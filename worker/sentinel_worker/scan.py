from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .construction import SourceFile, build_source_graph
from .enrichment import enrich_graph_nodes
from .graph_query import GraphQuery
from .models import Edge, Finding, Graph, Node, Repo, Run, now
from .sca import scan_dependencies
from .security import compute_fingerprint, find_secret_candidates, scrub_secrets
from .source_store import enforce_source_retention_for_account, store_source_snapshot
from .trace_store import offload_trace_if_large

log = structlog.get_logger(__name__)

# Used only by secret scanning (§12), not by SAST.
LOG_SINK_RE = re.compile(r"\b(console\.log|logger\.|logging\.|print)\s*\(", re.IGNORECASE)
HTTP_SINK_RE = re.compile(r"\b(fetch|axios\.|requests\.|httpx\.|http\.request)\s*\(", re.IGNORECASE)


@dataclass(frozen=True)
class DiffFile:
    path: str
    content: str


def parse_unified_diff(diff: str) -> list[DiffFile]:
    files: list[DiffFile] = []
    current_path: str | None = None
    added: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            if current_path is not None:
                files.append(DiffFile(current_path, "\n".join(added)))
            current_path = line.removeprefix("+++ b/")
            added = []
        elif current_path and line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
    if current_path is not None:
        files.append(DiffFile(current_path, "\n".join(added)))
    return files


def trace_event(kind: str, **fields: object) -> str:
    payload = _scrub_trace_value({"ts": datetime.now(UTC).isoformat(), "kind": kind, **fields})
    return json.dumps(payload, sort_keys=True)


def _scrub_trace_value(value: object) -> object:
    if isinstance(value, str):
        return scrub_secrets(value)
    if isinstance(value, list):
        return [_scrub_trace_value(item) for item in value]
    if isinstance(value, tuple):
        return [_scrub_trace_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _scrub_trace_value(item) for key, item in value.items()}
    return value


async def get_or_create_graph(db: AsyncSession, repo_name: str, account_name: str = "dev", account_id: str | None = None) -> Graph:
    account = None
    repo = None
    from .models import Account

    if account_id is not None:
        account = await db.get(Account, account_id)
    else:
        account = await db.scalar(select(Account).where(Account.name == account_name))
    if account is None:
        account = Account(id=account_id, name=account_name if account_id is None else account_id) if account_id else Account(name=account_name)
        db.add(account)
        await db.flush()
    repo = await db.scalar(select(Repo).where(Repo.account_id == account.id).where(Repo.name == repo_name))
    if repo is None:
        repo = Repo(account_id=account.id, name=repo_name)
        db.add(repo)
        await db.flush()
    graph = await db.scalar(select(Graph).where(Graph.repo_id == repo.id).where(Graph.kind == "main"))
    if graph is None:
        graph = Graph(account_id=account.id, repo_id=repo.id, kind="main")
        db.add(graph)
        await db.flush()
    return graph


async def bootstrap_repo(db: AsyncSession, repo_name: str, files: dict[str, str], *, account_id: str | None = None, _llm=None) -> Run:
    from .sast import get_llm_for_graph
    from .enrichment import validate_enrichment_labels
    graph = await get_or_create_graph(db, repo_name, account_id=account_id)
    run = Run(graph_id=graph.id, kind="init", status="running")
    db.add(run)
    await db.flush()
    repo = await db.scalar(select(Repo).where(Repo.id == graph.repo_id))
    if repo is None:
        raise ValueError(f"repo not found for graph {graph.id}")
    sources: list[SourceFile] = []
    for path, content in files.items():
        await store_source_snapshot(db, repo_id=repo.id, commit_hash="bootstrap", file_path=path, content=content)
        sources.append(SourceFile(path=path, content=content, is_new=False))
    await build_source_graph(db, graph.id, sources)
    llm = _llm
    if llm is None:
        llm = await get_llm_for_graph(graph.id, db)
    await enrich_graph_nodes(db, graph_id=graph.id, run_id=run.id, source_by_file=files, only_new=False, llm=llm)
    await validate_enrichment_labels(db, graph_id=graph.id, run_id=run.id, source_by_file=files, llm=llm)
    await enforce_source_retention_for_account(db, graph.account_id)
    run.status = "completed"
    run.completed_at = now()
    run.trace = "\n".join(part for part in [run.trace, trace_event("init.completed", file_count=len(files))] if part)
    await offload_trace_if_large(db, run)
    return run


async def scan_diff(
    db: AsyncSession,
    repo_name: str,
    diff: str,
    *,
    run_context: str = "local",
    account_id: str | None = None,
    base_ref: str | None = None,
    paths: list[str] | None = None,
    _llm=None,
) -> Run:
    graph = await get_or_create_graph(db, repo_name, account_id=account_id)
    run = Run(graph_id=graph.id, kind="source", status="running", trace=trace_event("scan.started", run_context=run_context, base_ref=base_ref, paths=paths or []))
    db.add(run)
    await db.flush()
    repo = await db.scalar(select(Repo).where(Repo.id == graph.repo_id))
    if repo is None:
        raise ValueError(f"repo not found for graph {graph.id}")
    await execute_source_scan(db, graph=graph, repo=repo, run=run, diff=diff, run_context=run_context, base_ref=base_ref, paths=paths or [], _llm=_llm)
    return run


async def execute_source_scan(
    db: AsyncSession,
    *,
    graph: Graph,
    repo: Repo,
    run: Run,
    diff: str,
    run_context: str = "local",
    base_ref: str | None = None,
    paths: list[str] | None = None,
    _llm=None,  # injectable for tests; production resolves from account config
) -> int:
    from .sast import run_sast, get_llm_for_graph

    if run.status != "running":
        run.status = "running"
    started = trace_event("scan.started", run_context=run_context, base_ref=base_ref, paths=paths or [])
    if not run.trace:
        run.trace = started
    elif '"kind": "scan.started"' not in run.trace:
        run.trace = "\n".join([run.trace, started])

    files = parse_unified_diff(diff)
    changed_paths = [file.path for file in files]
    log.info("scan.started", run_id=run.id, changed_file_count=len(changed_paths))

    blast_radius = await _blast_radius_files(db, graph.id, changed_paths)
    log.info("scan.blast_radius", run_id=run.id, blast_radius_file_count=len(blast_radius))

    matched_adapter_files: list[str] = []
    unmatched_adapter_files: list[str] = []
    sources = [SourceFile(path=file.path, content=file.content, is_new=True) for file in files]
    nodes_by_path: dict[str, list] = {s.path: [] for s in sources}

    for file in files:
        await store_source_snapshot(db, repo_id=repo.id, commit_hash=run.id, file_path=file.path, content=file.content)
    if sources:
        nodes = await build_source_graph(db, graph.id, sources)
        for node in nodes:
            if node.file in nodes_by_path:
                nodes_by_path[node.file].append(node)

    log.info("scan.graph_update.completed", run_id=run.id, changed_files=len(changed_paths))

    # Adapter coverage tracking
    for file in files:
        if not _is_manifest(file.path):
            if any(n.kind == "ROUTE" for n in nodes_by_path[file.path]):
                matched_adapter_files.append(file.path)
            else:
                unmatched_adapter_files.append(file.path)

    # Bootstrap serialisation for SAST
    changed_node_ids = [n.id for nodes in nodes_by_path.values() for n in nodes]
    graph_query = GraphQuery(db=db, graph_id=graph.id)
    bootstrap_context = await sast_bootstrap(changed_node_ids, graph_query)

    # Suppressed fingerprints
    suppressed_fps = list(await db.scalars(
        select(Finding.fingerprint).where(
            Finding.graph_id == graph.id,
            Finding.suppressed.is_(True),
        )
    ))

    findings = 0

    # ── SCA (feed-based, not LLM) ──────────────────────────────────────────
    sca_count = 0
    for f in files:
        sca_count += await scan_dependencies(db, graph.id, repo.id, run.id, f.path, f.content)
    findings += sca_count
    log.info("scan.sca.completed", run_id=run.id, sca_finding_count=sca_count)

    # ── Secret scan (entropy + regex, not LLM) ────────────────────────────
    secret_count = 0
    for f in files:
        secret_count += await _run_secret_scan(db, graph.id, repo.id, run.id, f, suppressed_fps)
    findings += secret_count
    log.info("scan.secrets.completed", run_id=run.id, secret_finding_count=secret_count)

    # ── SAST (LLM-only) ───────────────────────────────────────────────────
    llm = _llm
    if llm is None:
        llm = await get_llm_for_graph(graph.id, db)  # raises LLMNotConfiguredError if unconfigured

    try:
        sast_findings = await asyncio.wait_for(
            run_sast(
                diff=diff,
                bootstrap_context=bootstrap_context,
                run_id=run.id,
                suppressed_fps=suppressed_fps,
                graph=graph,
                repo_id=str(repo.id),
                db=db,
                llm=llm,
            ),
            timeout=15.0,
        )
    except asyncio.TimeoutError:
        log.warning("sast_timeout", run_id=run.id)
        sast_findings = []
    findings += len(sast_findings)
    log.info("scan.sast.completed", run_id=run.id, sast_finding_count=len(sast_findings))

    # Graph enrichment runs only on the async worker path (run_context != "local"),
    # not inline on synchronous /source requests, to keep response latency bounded.
    if run_context != "local":
        await enrich_graph_nodes(db, graph_id=graph.id, run_id=run.id, source_by_file={f.path: f.content for f in files}, only_new=True, llm=llm)
        from .enrichment import validate_enrichment_labels
        await validate_enrichment_labels(db, graph_id=graph.id, run_id=run.id, llm=llm, source_by_file={f.path: f.content for f in files})
    await enforce_source_retention_for_account(db, graph.account_id)
    run.status = "completed"
    run.completed_at = now()
    run.trace = "\n".join([
        run.trace,
        trace_event("graph_update.completed", changed_files=len(changed_paths), blast_radius_files=len(blast_radius), files=blast_radius[:50]),
        trace_event("adapter.coverage", matched_files=matched_adapter_files, unmatched_files=unmatched_adapter_files),
        trace_event("scan.completed", finding_count=findings),
    ])
    await offload_trace_if_large(db, run)
    return findings


async def review_plan(
    db: AsyncSession,
    repo_name: str,
    content: str,
    *,
    with_retry: bool = False,
    account_id: str | None = None,
    _llm=None,
    max_passes: int | None = None,
) -> tuple[Run, list[Finding]]:
    from .sast import run_sast, get_llm_for_graph

    graph = await get_or_create_graph(db, repo_name, account_id=account_id)
    run = Run(graph_id=graph.id, kind="plan", status="running", trace=trace_event("plan.started", with_retry=with_retry))
    db.add(run)
    await db.flush()
    repo = await db.scalar(select(Repo).where(Repo.id == graph.repo_id))
    if repo is None:
        raise ValueError(f"repo not found for graph {graph.id}")

    llm = _llm
    if llm is None:
        llm = await get_llm_for_graph(graph.id, db)

    graph_query = GraphQuery(db=db, graph_id=graph.id)
    bootstrap_context = await sast_bootstrap([], graph_query)

    suppressed_fps = list(await db.scalars(
        select(Finding.fingerprint).where(Finding.graph_id == graph.id, Finding.suppressed.is_(True))
    ))

    # Default to 1 pass on the synchronous path; caller can override via max_passes
    # (worker uses 3 passes when with_retry=True to find more issues asynchronously)
    max_passes = max_passes if max_passes is not None else (3 if with_retry else 1)
    seen_fps: set[str] = set()
    trace_lines = [run.trace]

    for pass_index in range(1, max_passes + 1):
        sast_findings = await run_sast(
            diff=f"+++ b/plan.txt\n+{content}",
            bootstrap_context=bootstrap_context,
            run_id=run.id,
            suppressed_fps=suppressed_fps + list(seen_fps),
            graph=graph,
            repo_id=str(repo.id),
            db=db,
            llm=llm,
        )
        new_fps = {f.fingerprint for f in sast_findings} - seen_fps
        trace_lines.append(trace_event(
            "plan.pass.completed",
            pass_index=pass_index,
            issue_count=len(sast_findings),
            new_issue_count=len(new_fps),
        ))
        seen_fps.update(new_fps)
        if not with_retry or not new_fps:
            break
        if pass_index > 1 and not new_fps:
            trace_lines.append(trace_event("plan.retry.stabilized", pass_index=pass_index))
            break

    findings = list(await db.scalars(select(Finding).where(Finding.run_id == run.id)))
    run.status = "completed"
    run.completed_at = now()
    trace_lines.append(trace_event("plan.completed", finding_count=len(findings)))
    run.trace = "\n".join(trace_lines)
    await offload_trace_if_large(db, run)
    return run, findings


async def _run_secret_scan(
    db: AsyncSession,
    graph_id: str,
    repo_id: str,
    run_id: str,
    file: DiffFile,
    suppressed_fps: list[str],
) -> int:
    """Secret scanning pass — entropy analysis + regex patterns (§12). No LLM."""
    count = 0
    for secret_kind, secret in find_secret_candidates(file.content):
        severity = _secret_severity(file.content)
        fp = compute_fingerprint(repo_id, file.path, "secret_leak")
        if fp in suppressed_fps:
            log.debug("scan.secrets.finding_suppressed", fingerprint=fp, run_id=run_id)
            continue
        existing = await db.scalar(select(Finding).where(Finding.fingerprint == fp))
        if existing is not None and existing.suppressed:
            continue
        if existing is None:
            db.add(Finding(
                graph_id=graph_id,
                node_id=f"file:{file.path}",
                run_id=run_id,
                vuln_type="secret_leak",
                severity=severity,
                title=f"Hardcoded {secret_kind}",
                description=f"Changed code includes a credential-shaped value: {scrub_secrets(secret)}.",
                remediation="Remove the secret, rotate it, and load credentials from a managed secret store.",
                fingerprint=fp,
            ))
            count += 1
            log.info("scan.secrets.finding_emitted", secret_kind=secret_kind, severity=severity, run_id=run_id)
        else:
            existing.run_id = run_id
            existing.status = "open" if not existing.confirmed else existing.status
            existing.updated_at = now()
            count += 1
    return count


def _secret_severity(content: str) -> str:
    if HTTP_SINK_RE.search(content):
        return "critical"
    if LOG_SINK_RE.search(content):
        return "high"
    return "medium"


async def _blast_radius_files(db: AsyncSession, graph_id: str, changed_paths: list[str]) -> list[str]:
    changed = set(changed_paths)
    nodes = list(await db.scalars(select(Node).where(Node.graph_id == graph_id)))
    by_id = {node.id: node for node in nodes}
    seed_ids = {node.id for node in nodes if node.file in changed}
    affected = set(changed)
    if not seed_ids:
        return sorted(affected)
    edges = await db.scalars(select(Edge).where(Edge.graph_id == graph_id).where(Edge.kind.in_(["CALLS", "FLOWS_TO", "GUARDED_BY"])))
    for edge in edges:
        if edge.src in seed_ids or edge.dst in seed_ids:
            for node_id in (edge.src, edge.dst):
                node_obj = by_id.get(node_id)
                file = node_obj.file if node_obj is not None else None
                if file:
                    affected.add(file)
    return sorted(affected)


async def sast_bootstrap(changed_node_ids: list[str], graph_query: GraphQuery) -> str:
    seed_nodes: set[str] = set()
    for node_id in changed_node_ids:
        neighbors = await graph_query.neighbors(node_id,
            edge_kinds=['CALLS', 'FLOWS_TO', 'GUARDED_BY'], max_hops=3)
        for n in neighbors:
            seed_nodes.add(n.node.id)
    taint = await graph_query.taint_paths(include_uncertain=True)
    all_node_ids = list(seed_nodes | set(changed_node_ids) | {n.id for path in taint for n in path})
    return await graph_query.serialize_for_prompt(all_node_ids)


def _is_manifest(path: str) -> bool:
    return path.endswith((
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "requirements.txt", "pyproject.toml", "Gemfile.lock", "Pipfile.lock",
        "poetry.lock", "go.mod", "go.sum", "Cargo.toml", "Cargo.lock",
        "pom.xml", "build.gradle", "build.gradle.kts",
    ))
