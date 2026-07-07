"""Local execution engine — the CLI-invoked entry point for local-first scans.

Unlike `standalone.py` (fully offline, ephemeral graph, CI-only, no cloud
sync), this module optionally *pulls* existing graph context for the diff's
touched nodes from the cloud (read-only — pointers and short semantic labels
only, never source) so the local SAST agent sees callers/labels that exist
outside the diff, then *pushes back* the graph delta and findings the local
scan produced. Source code and diffs are never sent anywhere; the local
scratch graph is a throwaway SQLite database, same as `standalone.py`.

This is the shared core behind the CLI's `source`, `scan`, and `plan`
commands (see cli/src) — the CLI shells out to this module (or the
`sentinel-local-scan` console script built on top of it) instead of POSTing
diffs to the cloud API.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: F401 — re-exported for type hints in callers

from .agent import SentinelLLMClient
from .construction import SourceFile, build_source_graph
from .db import create_engine, create_sessionmaker
from .migrations import apply_migrations
from .models import Edge, Finding, Node
from .pentest import PentestRequestContext, run_pentest
from .scan import bootstrap_repo, get_or_create_graph, parse_unified_diff, review_plan, scan_diff
from .security import is_env_var_file
from .standalone import ScanFinding, ScanResult, _severity_rank
from .vm import LocalSubprocessSandboxExecutor, PentestSandboxConfig

_NODE_UPSERT_FIELDS = (
    "id", "kind", "name", "file", "line_start", "line_end", "language",
    "trust_level", "auth_required", "privilege", "is_entry_point", "is_sink",
    "taint_uncertain", "parse_error", "label", "intent", "commit_hash", "is_new",
)
_EDGE_UPSERT_FIELDS = (
    "src", "dst", "kind", "tainted", "sanitized", "taint_uncertain", "call_uncertainty", "order_index",
)


@dataclass
class GraphDelta:
    """A graph change set in the exact shape POST /graph/upsert expects — pointers and short metadata only."""

    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)


@dataclass
class LocalScanResult:
    scan: ScanResult
    delta: GraphDelta
    local_run_id: str | None = None
    local_trace_path: str | None = None


def _save_local_trace(run_id: str, trace: str) -> str:
    """Persist a run's full trace (prompts, tool calls, findings) to a local
    file. This is the durable copy — the cloud only ever gets a redacted run
    summary via /findings/ingest's trace_event, never the full trace, so
    nothing here is sent anywhere. See non-code/README.md's run-trace model."""
    trace_dir = Path.home() / ".sentinel" / "runs"
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_path = trace_dir / f"{run_id}.jsonl"
    trace_path.write_text(trace)
    return str(trace_path)


def _node_to_dict(node: Node) -> dict:
    return {field_name: getattr(node, field_name) for field_name in _NODE_UPSERT_FIELDS}


def _edge_to_dict(edge: Edge) -> dict:
    return {field_name: getattr(edge, field_name) for field_name in _EDGE_UPSERT_FIELDS}


def fetch_cloud_subgraph(*, api_url: str, token: str | None, repo_name: str, seeds: list[str]) -> GraphDelta:
    """Best-effort pull of existing graph context for `seeds` from the cloud.

    Any failure (unreachable, unauthenticated, cloud sync not configured)
    degrades to an empty delta — a local scan must work fully offline.
    """
    if not seeds:
        return GraphDelta()
    import httpx

    try:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        resp = httpx.get(
            api_url.rstrip("/") + "/graph/subgraph",
            params={"repo_name": repo_name, "seeds": seeds, "max_hops": 2},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        body = resp.json()
        return GraphDelta(nodes=body.get("nodes", []), edges=body.get("edges", []))
    except Exception:
        return GraphDelta()


def push_results_to_cloud(
    *,
    api_url: str,
    token: str | None,
    repo_name: str,
    run_context: str,
    commit_sha: str | None,
    base_ref: str | None,
    scan: ScanResult,
    delta: GraphDelta,
) -> dict:
    """Push the graph delta and findings a local scan produced.

    Only pointers/metadata (graph) and finding records (no source, no diff)
    ever appear in these request bodies — see payload_guard for the
    server-side check enforcing the same invariant on /graph/upsert.
    """
    import httpx

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    graph_response: dict = {}
    if delta.nodes or delta.edges:
        resp = httpx.post(
            api_url.rstrip("/") + "/graph/upsert",
            json={"repo_name": repo_name, "graph_kind": "main", "nodes": delta.nodes, "edges": delta.edges},
            headers=headers,
            timeout=60,
        )
        resp.raise_for_status()
        graph_response = resp.json()

    findings_payload = {
        "repo_name": repo_name,
        "run_context": run_context,
        "commit_sha": commit_sha,
        "base_ref": base_ref,
        "findings": [
            {
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
                "node_id": f.node_id,
                "file": f.file,
                "line": f.line,
                "evidence": f.evidence,
            }
            for f in scan.findings
        ],
    }
    findings_resp = httpx.post(api_url.rstrip("/") + "/findings/ingest", json=findings_payload, headers=headers, timeout=60)
    findings_resp.raise_for_status()
    return {"graph": graph_response, "findings": findings_resp.json()}


async def _merge_cloud_context(session: AsyncSession, *, graph_id: str, context: GraphDelta) -> None:
    for incoming in context.nodes:
        if await session.get(Node, incoming["id"]) is None:
            session.add(Node(graph_id=graph_id, **{k: v for k, v in incoming.items() if k != "id"}, id=incoming["id"]))
    await session.flush()
    for incoming in context.edges:
        exists = await session.scalar(
            select(Edge)
            .where(Edge.graph_id == graph_id)
            .where(Edge.src == incoming["src"])
            .where(Edge.dst == incoming["dst"])
            .where(Edge.kind == incoming["kind"])
        )
        if exists is None:
            session.add(Edge(graph_id=graph_id, **{k: v for k, v in incoming.items() if k != "id"}))
    await session.flush()


async def run_local_source_scan(
    *,
    repo_name: str,
    repo_dir: str,
    diff: str,
    llm: SentinelLLMClient,
    run_context: str = "local",
    base_ref: str | None = None,
    commit_sha: str | None = None,
    api_url: str | None = None,
    api_token: str | None = None,
) -> LocalScanResult:
    """Run a full source scan (graph build + SCA + secrets + SAST) locally.

    `repo_dir` is read directly by the SAST agent's read_file/grep_source
    tools — source never leaves this process. When `api_url` is set, existing
    graph context for the diff's touched nodes is pulled from the cloud first
    (read-only) to enrich the SAST bootstrap; the delta this scan produces is
    returned for the caller to push back via `push_results_to_cloud`.
    """
    tmpdir = tempfile.mkdtemp(prefix="sentinel-local-")
    db_path = Path(tmpdir) / "scan.db"
    engine = create_engine(f"sqlite+aiosqlite:///{db_path}")
    try:
        await apply_migrations(engine)
        sessionmaker = create_sessionmaker(engine)
        async with sessionmaker() as session:
            async with session.begin():
                graph = await get_or_create_graph(session, repo_name)

                if api_url:
                    files = parse_unified_diff(diff)
                    sources = [SourceFile(path=f.path, content=f.content, is_new=True) for f in files]
                    seed_nodes = await build_source_graph(session, graph.id, sources)
                    cloud_context = fetch_cloud_subgraph(
                        api_url=api_url, token=api_token, repo_name=repo_name, seeds=[n.id for n in seed_nodes]
                    )
                    await _merge_cloud_context(session, graph_id=graph.id, context=cloud_context)

                run = await scan_diff(
                    session,
                    repo_name,
                    diff,
                    run_context=run_context,
                    base_ref=base_ref,
                    repo_dir=repo_dir,
                    _llm=llm,
                )

                finding_rows = list(await session.scalars(select(Finding).where(Finding.run_id == run.id)))
                scan_findings: list[ScanFinding] = []
                for f in finding_rows:
                    file_path: str | None = None
                    line: int | None = None
                    if f.node_id:
                        node = await session.get(Node, f.node_id)
                        if node is not None:
                            file_path, line = node.file, node.line_start
                        elif f.node_id.startswith("file:"):
                            file_path = f.node_id.removeprefix("file:")
                    scan_findings.append(
                        ScanFinding(
                            vuln_type=f.vuln_type,
                            severity=f.severity,
                            title=f.title,
                            description=f.description,
                            remediation=f.remediation,
                            fingerprint=f.fingerprint,
                            node_id=f.node_id,
                            file=file_path,
                            line=line,
                            evidence=f.evidence,
                        )
                    )

                new_nodes = list(
                    await session.scalars(select(Node).where(Node.graph_id == graph.id).where(Node.is_new.is_(True)))
                )
                new_edges: list[Edge] = []
                if new_nodes:
                    new_node_ids = [n.id for n in new_nodes]
                    new_edges = list(
                        await session.scalars(
                            select(Edge).where(Edge.graph_id == graph.id).where(Edge.src.in_(new_node_ids))
                        )
                    )
                local_run_id, local_trace = run.id, run.trace

        trace_path = _save_local_trace(local_run_id, local_trace)
        scan_result = ScanResult(
            repo_name=repo_name, findings=scan_findings, base_ref=base_ref, commit_sha=commit_sha, run_context=run_context
        )
        scan_result.findings.sort(key=lambda x: (-_severity_rank(x.severity), x.file or "", x.title))
        delta = GraphDelta(nodes=[_node_to_dict(n) for n in new_nodes], edges=[_edge_to_dict(e) for e in new_edges])
        return LocalScanResult(scan=scan_result, delta=delta, local_run_id=local_run_id, local_trace_path=trace_path)
    finally:
        await engine.dispose()
        try:
            db_path.unlink(missing_ok=True)
            Path(tmpdir).rmdir()
        except OSError:
            pass


def _list_tracked_files(repo_dir: str) -> list[str]:
    proc = subprocess.run(["git", "ls-files"], cwd=repo_dir, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-files failed in {repo_dir}: {proc.stderr.strip()}")
    return [line for line in proc.stdout.splitlines() if line]


async def run_local_init(*, repo_name: str, repo_dir: str, llm: SentinelLLMClient) -> tuple[GraphDelta, str, str]:
    """Build the full graph locally (all 5 passes) from every tracked file and
    return the delta to push. File contents are read from disk and used only
    to build node/edge pointers and short semantic labels — never sent
    anywhere as-is; only the resulting metadata leaves this function.
    Returns (delta, local_run_id, local_trace_path).
    """
    files: dict[str, str] = {}
    for rel_path in _list_tracked_files(repo_dir):
        if rel_path == "sentinel.config.json" or is_env_var_file(rel_path):
            continue
        try:
            files[rel_path] = (Path(repo_dir) / rel_path).read_text()
        except (UnicodeDecodeError, OSError):
            continue  # binary or unreadable tracked files are skipped, same as the CLI's old upload path

    tmpdir = tempfile.mkdtemp(prefix="sentinel-local-init-")
    db_path = Path(tmpdir) / "init.db"
    engine = create_engine(f"sqlite+aiosqlite:///{db_path}")
    try:
        await apply_migrations(engine)
        sessionmaker = create_sessionmaker(engine)
        async with sessionmaker() as session:
            async with session.begin():
                graph = await get_or_create_graph(session, repo_name)
                init_run = await bootstrap_repo(session, repo_name, files, _llm=llm)
                all_nodes = list(await session.scalars(select(Node).where(Node.graph_id == graph.id)))
                all_edges = list(await session.scalars(select(Edge).where(Edge.graph_id == graph.id)))
                local_run_id, local_trace = init_run.id, init_run.trace
        trace_path = _save_local_trace(local_run_id, local_trace)
        delta = GraphDelta(nodes=[_node_to_dict(n) for n in all_nodes], edges=[_edge_to_dict(e) for e in all_edges])
        return delta, local_run_id, trace_path
    finally:
        await engine.dispose()
        try:
            db_path.unlink(missing_ok=True)
            Path(tmpdir).rmdir()
        except OSError:
            pass


async def run_local_plan_review(
    *,
    repo_name: str,
    repo_dir: str,
    content: str,
    llm: SentinelLLMClient,
    with_retry: bool = False,
) -> tuple[ScanResult, str, str]:
    """Run a plan/design-doc review locally. Only findings are produced (no
    graph delta). Returns (result, local_run_id, local_trace_path)."""
    tmpdir = tempfile.mkdtemp(prefix="sentinel-local-plan-")
    db_path = Path(tmpdir) / "plan.db"
    engine = create_engine(f"sqlite+aiosqlite:///{db_path}")
    try:
        await apply_migrations(engine)
        sessionmaker = create_sessionmaker(engine)
        async with sessionmaker() as session:
            async with session.begin():
                plan_run, findings = await review_plan(
                    session, repo_name, content, with_retry=with_retry, repo_dir=repo_dir, _llm=llm
                )
                scan_findings = [
                    ScanFinding(
                        vuln_type=f.vuln_type,
                        severity=f.severity,
                        title=f.title,
                        description=f.description,
                        remediation=f.remediation,
                        fingerprint=f.fingerprint,
                        node_id=f.node_id,
                        evidence=f.evidence,
                    )
                    for f in findings
                ]
                local_run_id, local_trace = plan_run.id, plan_run.trace
        trace_path = _save_local_trace(local_run_id, local_trace)
        result = ScanResult(repo_name=repo_name, findings=scan_findings, run_context="plan")
        result.findings.sort(key=lambda x: (-_severity_rank(x.severity), x.title))
        return result, local_run_id, trace_path
    finally:
        await engine.dispose()
        try:
            db_path.unlink(missing_ok=True)
            Path(tmpdir).rmdir()
        except OSError:
            pass


@dataclass
class LocalPentestResult:
    finding_id: str
    confirmed: bool
    status: str
    evidence: str | None
    entry_node_id: str | None
    sink_node_id: str | None
    payloads: list[str] = field(default_factory=list)
    local_run_id: str | None = None
    local_trace_path: str | None = None


def fetch_cloud_finding(*, api_url: str, token: str | None, finding_id: str) -> dict:
    """Fetch the target finding's metadata (no source) from the cloud."""
    import httpx

    headers = {"Authorization": f"Bearer {token}"} if token else {}
    resp = httpx.get(f"{api_url.rstrip('/')}/findings/{finding_id}", headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.json()


def push_pentest_result(*, api_url: str, token: str | None, result: LocalPentestResult) -> dict:
    """Report a local pentest run's outcome. Only the confirmation
    status/evidence text and node pointers cross to the cloud — the app
    booted, the payloads sent, and any secrets from .env.sentinel all stayed
    on this machine (see PentestSandboxConfig / LocalSubprocessSandboxExecutor)."""
    import httpx

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = httpx.post(
        f"{api_url.rstrip('/')}/findings/{result.finding_id}/confirm",
        json={
            "confirmed": result.confirmed,
            "status": result.status,
            "evidence": result.evidence,
            "entry_node_id": result.entry_node_id,
            "sink_node_id": result.sink_node_id,
        },
        headers=headers,
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


async def run_local_pentest(
    *,
    repo_name: str,
    repo_dir: str,
    finding_id: str,
    llm: SentinelLLMClient,
    api_url: str,
    api_token: str | None,
    sanitizer_output: str = "",
    behavioral_proof: str | None = None,
    proof_detail: str = "",
    boot: str | None = None,
    healthcheck: str | None = None,
    egress_allowlist: list[str] | None = None,
) -> LocalPentestResult:
    """Confirm a finding by attacking the app booted on this machine.

    Pulls the finding + its graph context from the cloud (read-only,
    pointers/metadata only), runs the pentest agent locally — source read
    from `repo_dir`, payloads generated and sent by this process, sandbox
    execution via `LocalSubprocessSandboxExecutor` (no Firecracker microVM
    required; the app is already running on the developer's own machine, not
    a shared multi-tenant host) — and returns the outcome for the caller to
    push back via `push_pentest_result`. `.env.sentinel` secrets used to boot
    the app are read locally by the boot command itself and never enter the
    LLM's context or leave this process.
    """
    finding_data = fetch_cloud_finding(api_url=api_url, token=api_token, finding_id=finding_id)
    seeds = [finding_data["node_id"]] if finding_data.get("node_id") else []
    context = fetch_cloud_subgraph(api_url=api_url, token=api_token, repo_name=repo_name, seeds=seeds) if seeds else GraphDelta()

    tmpdir = tempfile.mkdtemp(prefix="sentinel-local-pentest-")
    db_path = Path(tmpdir) / "pentest.db"
    engine = create_engine(f"sqlite+aiosqlite:///{db_path}")
    try:
        await apply_migrations(engine)
        sessionmaker = create_sessionmaker(engine)
        async with sessionmaker() as session:
            async with session.begin():
                graph = await get_or_create_graph(session, repo_name)
                await _merge_cloud_context(session, graph_id=graph.id, context=context)

                local_finding = Finding(
                    id=finding_data["id"],
                    graph_id=graph.id,
                    node_id=finding_data.get("node_id"),
                    vuln_type=finding_data["vuln_type"],
                    severity=finding_data["severity"],
                    title=finding_data["title"],
                    description=finding_data["description"],
                    remediation=finding_data["remediation"],
                    status=finding_data["status"],
                    fingerprint=finding_data["fingerprint"],
                )
                session.add(local_finding)
                await session.flush()

                request = PentestRequestContext(
                    sanitizer_output=sanitizer_output,
                    behavioral_proof=behavioral_proof,
                    proof_detail=proof_detail,
                    sandbox=PentestSandboxConfig(boot=boot, healthcheck=healthcheck, egress_allowlist=egress_allowlist or []),
                    executor=LocalSubprocessSandboxExecutor(),
                )
                outcome = await run_pentest(session, local_finding, request, llm=llm, repo_dir=repo_dir)
                local_run_id, local_trace = outcome.run.id, outcome.run.trace

        trace_path = _save_local_trace(local_run_id, local_trace)
        return LocalPentestResult(
            finding_id=finding_id,
            confirmed=outcome.oracle_result.confirmed,
            status=outcome.finding.status,
            evidence=outcome.finding.evidence,
            entry_node_id=outcome.entry_node_id,
            sink_node_id=local_finding.node_id,
            payloads=outcome.payloads,
            local_run_id=local_run_id,
            local_trace_path=trace_path,
        )
    finally:
        await engine.dispose()
        try:
            db_path.unlink(missing_ok=True)
            Path(tmpdir).rmdir()
        except OSError:
            pass
