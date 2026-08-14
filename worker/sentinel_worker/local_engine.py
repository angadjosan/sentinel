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

import json
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
from .scan import bootstrap_repo, get_or_create_graph, parse_unified_diff, review_plan, scan_diff
from .security import is_secret_file
from .standalone import ScanFinding, ScanResult, _severity_rank

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
    # Changed files that no framework adapter matched (AUDIT.md §6 W4 P5.4).
    # Extracted from the scan's `adapter.coverage` trace event; surfaced to the
    # user on stderr by the CLI so they know why route coverage may be thin.
    adapter_unmatched_files: list[str] = field(default_factory=list)


def _unmatched_adapter_files_from_trace(trace: str | None) -> list[str]:
    """Pull the `adapter.coverage` event's `unmatched_files` out of a run trace.

    The trace is NDJSON; one line is the adapter-coverage event emitted by
    scan.py. Best-effort: any parse problem yields an empty list (a warning is
    a nicety, never load-bearing)."""
    if not trace:
        return []
    import json as _json

    for line in trace.splitlines():
        line = line.strip()
        if not line or '"adapter.coverage"' not in line:
            continue
        try:
            event = _json.loads(line)
        except ValueError:
            continue
        unmatched = event.get("unmatched_files")
        if isinstance(unmatched, list):
            return [str(f) for f in unmatched]
    return []


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
        if await session.get(Node, {"graph_id": graph_id, "id": incoming["id"]}) is None:
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
                        node = await session.get(Node, {"graph_id": f.graph_id, "id": f.node_id})
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
        return LocalScanResult(
            scan=scan_result,
            delta=delta,
            local_run_id=local_run_id,
            local_trace_path=trace_path,
            adapter_unmatched_files=_unmatched_adapter_files_from_trace(local_trace),
        )
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
        if rel_path == "sentinel.config.json" or is_secret_file(rel_path):
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


# ---------------------------------------------------------------------------
# Local pentest execution (refactor plan W2).
#
# Pentest runs entirely on the developer's machine using the FULL hardened
# sandbox stack — gVisor, token-scoped egress proxy, canary tokens, credential
# broker, attack-safety budget, agentic payload generation, and the
# confirmation oracle — via the transport-agnostic driver W1 extracted into
# `pentest_exec.execute_full_pentest`. The cloud is only a results store: we
# run against a throwaway SQLite DB, then POST the outcome (confirmed / status /
# evidence + node pointers) back. Source, diffs, payloads, the live target, and
# all secrets stay on the machine.
# ---------------------------------------------------------------------------


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


def fetch_pentest_config(*, api_url: str, token: str | None, repo_id: str) -> dict:
    """Best-effort fetch of the repo's structured pentest config so the local
    run honors canary/broker/attack-safety/egress exactly as the cloud worker
    would.

    Reads `GET /repos/{repo_id}/pentest-config` (see
    `api/sentinel_api/routers/repos.py` → `RepoPentestConfigResponse`) and
    returns the parsed fields:
    ``pentest_mode``, ``staging_base_url``, ``healthcheck_path``, ``boot``,
    ``healthcheck``, ``egress_allowlist`` (list), and the structured
    ``pentest_config`` blob (dict of sandbox/egress/secrets/canary/attack_safety).

    Any failure (unreachable, unauthenticated, config absent) degrades to an
    empty dict so an explicitly-passed boot/healthcheck still drives the run.
    """
    import httpx

    try:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        resp = httpx.get(f"{api_url.rstrip('/')}/repos/{repo_id}/pentest-config", headers=headers, timeout=15)
        resp.raise_for_status()
        body = resp.json()
        return body if isinstance(body, dict) else {}
    except Exception:
        return {}


def push_pentest_result(*, api_url: str, token: str | None, result: LocalPentestResult) -> dict:
    """Report a local pentest run's outcome. Only the confirmation
    status/evidence text and node pointers cross to the cloud — the app booted,
    the payloads sent, and any secrets from the boot env all stayed on this
    machine. Posts to `POST /findings/{id}/confirm` (PentestConfirmRequest)."""
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
    repo_id: str | None = None,
    sanitizer_output: str = "",
    behavioral_proof: str | None = None,
    proof_detail: str = "",
    boot: str | None = None,
    healthcheck: str | None = None,
    egress_allowlist: list[str] | None = None,
    pentest_config_json: str | None = None,
    pentest_mode: str | None = None,
    staging_base_url: str | None = None,
    healthcheck_path: str | None = None,
) -> LocalPentestResult:
    """Confirm a finding by attacking the app booted on this machine, using the
    FULL hardened sandbox stack.

    Pulls the finding + its structured pentest config + graph context from the
    cloud (read-only, pointers/metadata only), seeds a throwaway SQLite DB, then
    hands off to `pentest_exec.execute_full_pentest` — the identical
    gVisor + egress-proxy + canary + broker + attack-safety + oracle pipeline the
    cloud worker ran. Source is read locally from `repo_dir`; payloads, the live
    target, and any boot secrets never leave this process. Returns the outcome
    for the caller to push back via `push_pentest_result`.

    Explicitly-passed args (boot/healthcheck/egress/mode/urls/config) win over
    values fetched from the repo's pentest config. `repo_id`, when provided,
    enables the config fetch and is used only for stable seed/container naming.

    Docker/gVisor sandbox is ON by default and auto-degrades: for a
    `local_worker` run the preflight prefers gVisor, falls back to plain Docker
    (runc), and — when Docker is absent — boots the target directly as a
    subprocess (reduced isolation), logging each downgrade to stderr rather than
    failing. Pass `--no-sandbox` (or `SENTINEL_SANDBOX_RUNTIME=off`) to force the
    subprocess rung; only an explicit `SENTINEL_SANDBOX_RUNTIME=gvisor|runc`
    hard-fails when unmet. See `sandbox_preflight`'s ladder.
    """
    from .pentest_exec import PentestExecConfig, _decode_egress_allowlist, execute_full_pentest

    finding_data = fetch_cloud_finding(api_url=api_url, token=api_token, finding_id=finding_id)

    # Fetch the structured repo config so canary/broker/attack-safety/egress are
    # honored; explicit args override anything fetched. Best-effort (empty dict
    # on any failure), so an explicitly-passed boot/healthcheck still works.
    fetched: dict = {}
    if repo_id:
        fetched = fetch_pentest_config(api_url=api_url, token=api_token, repo_id=repo_id)

    resolved_mode = pentest_mode if pentest_mode is not None else fetched.get("pentest_mode")
    resolved_staging_url = staging_base_url if staging_base_url is not None else fetched.get("staging_base_url")
    resolved_hc_path = healthcheck_path if healthcheck_path is not None else fetched.get("healthcheck_path")
    resolved_boot = boot if boot is not None else fetched.get("boot")
    resolved_healthcheck = healthcheck if healthcheck is not None else fetched.get("healthcheck")

    if egress_allowlist is not None:
        resolved_egress = egress_allowlist
    else:
        fetched_egress = fetched.get("egress_allowlist")
        resolved_egress = list(fetched_egress) if isinstance(fetched_egress, list) else _decode_egress_allowlist(fetched_egress)

    if pentest_config_json is not None:
        resolved_config_json = pentest_config_json
    else:
        blob = fetched.get("pentest_config")
        resolved_config_json = json.dumps(blob) if isinstance(blob, dict) else None

    seeds = [finding_data["node_id"]] if finding_data.get("node_id") else []
    context = (
        fetch_cloud_subgraph(api_url=api_url, token=api_token, repo_name=repo_name, seeds=seeds)
        if seeds
        else GraphDelta()
    )

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

                cfg = PentestExecConfig(
                    repo_id=repo_id or repo_name,
                    finding_id=finding_id,
                    pentest_mode=resolved_mode,
                    staging_base_url=resolved_staging_url,
                    healthcheck_path=resolved_hc_path,
                    boot=resolved_boot,
                    healthcheck=resolved_healthcheck,
                    egress_allowlist=list(resolved_egress),
                    pentest_config_json=resolved_config_json,
                    sanitizer_output=sanitizer_output,
                    behavioral_proof=behavioral_proof,
                    proof_detail=proof_detail,
                )

                # THE full gVisor + proxy + canary + broker + attack-safety stack.
                # If docker/gVisor is unavailable in local_worker mode, the
                # preflight inside this call raises — let it propagate.
                outcome = await execute_full_pentest(
                    session, local_finding, config=cfg, llm=llm, repo_dir=repo_dir
                )
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
