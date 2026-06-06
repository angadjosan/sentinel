from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .construction import SourceFile, build_file_graph
from .languages import language_for
from .models import Edge, Finding, Graph, Node, Repo, Run, now
from .sca import scan_dependencies
from .security import compute_fingerprint, find_secret_candidates, scrub_secrets
from .source_store import store_source_snapshot
from .trace_store import offload_trace_if_large


SQLI_RE = re.compile(r"(query|execute)\s*\([^)]*(\+|\$\{|format\(|f['\"])", re.IGNORECASE)
CMDI_RE = re.compile(r"(exec|spawn|system|popen)\s*\([^)]*(\+|\$\{|format\(|f['\"])", re.IGNORECASE)
PATH_TRAVERSAL_RE = re.compile(r"(readFile|open|send_file|FileResponse)\s*\([^)]*(req\.|request\.|params|query)", re.IGNORECASE)
ROUTE_RE = re.compile(r"(app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)")
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
    payload = {"ts": datetime.now(UTC).isoformat(), "kind": kind, **fields}
    return json.dumps(payload, sort_keys=True)


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


async def bootstrap_repo(db: AsyncSession, repo_name: str, files: dict[str, str], *, account_id: str | None = None) -> Run:
    graph = await get_or_create_graph(db, repo_name, account_id=account_id)
    run = Run(graph_id=graph.id, kind="init", status="running")
    db.add(run)
    await db.flush()
    repo = await db.scalar(select(Repo).where(Repo.id == graph.repo_id))
    assert repo is not None
    for path, content in files.items():
        await store_source_snapshot(db, repo_id=repo.id, commit_hash="bootstrap", file_path=path, content=content)
        await build_file_graph(db, graph.id, SourceFile(path=path, content=content, is_new=False))
    run.status = "completed"
    run.completed_at = now()
    run.trace = trace_event("init.completed", file_count=len(files))
    await offload_trace_if_large(db, run)
    return run


async def scan_diff(db: AsyncSession, repo_name: str, diff: str, *, run_context: str = "local", account_id: str | None = None) -> Run:
    graph = await get_or_create_graph(db, repo_name, account_id=account_id)
    run = Run(graph_id=graph.id, kind="source", status="running", trace=trace_event("scan.started", run_context=run_context))
    db.add(run)
    await db.flush()
    repo = await db.scalar(select(Repo).where(Repo.id == graph.repo_id))
    assert repo is not None
    await execute_source_scan(db, graph=graph, repo=repo, run=run, diff=diff, run_context=run_context)
    return run


async def execute_source_scan(db: AsyncSession, *, graph: Graph, repo: Repo, run: Run, diff: str, run_context: str = "local") -> int:
    if run.status != "running":
        run.status = "running"
    if not run.trace:
        run.trace = trace_event("scan.started", run_context=run_context)
    findings = 0
    files = parse_unified_diff(diff)
    changed_paths = [file.path for file in files]
    blast_radius = await _blast_radius_files(db, graph.id, changed_paths)
    matched_adapter_files: list[str] = []
    unmatched_adapter_files: list[str] = []
    for file in files:
        await store_source_snapshot(db, repo_id=repo.id, commit_hash=run.id, file_path=file.path, content=file.content)
        nodes = await build_file_graph(db, graph.id, SourceFile(path=file.path, content=file.content, is_new=True))
        if not _is_manifest(file.path):
            if any(node.kind == "ROUTE" for node in nodes):
                matched_adapter_files.append(file.path)
            else:
                unmatched_adapter_files.append(file.path)
        findings += await scan_dependencies(db, graph.id, repo.id, run.id, file.path, file.content)
        findings += await _emit_pattern_findings(db, graph.id, repo.id, run.id, file)
    run.status = "completed"
    run.completed_at = now()
    run.trace = "\n".join(
        [
            run.trace,
            trace_event("graph_update.completed", changed_files=len(changed_paths), blast_radius_files=len(blast_radius), files=blast_radius[:50]),
            trace_event("adapter.coverage", matched_files=matched_adapter_files, unmatched_files=unmatched_adapter_files),
            trace_event("scan.completed", finding_count=findings),
        ]
    )
    await offload_trace_if_large(db, run)
    return findings


async def review_plan(db: AsyncSession, repo_name: str, content: str, *, with_retry: bool = False, account_id: str | None = None) -> tuple[Run, list[Finding]]:
    graph = await get_or_create_graph(db, repo_name, account_id=account_id)
    run = Run(graph_id=graph.id, kind="plan", status="running", trace=trace_event("plan.started", with_retry=with_retry))
    db.add(run)
    await db.flush()
    repo = await db.scalar(select(Repo).where(Repo.id == graph.repo_id))
    assert repo is not None
    pseudo_file = DiffFile("plan.txt", content)
    await _emit_pattern_findings(db, graph.id, repo.id, run.id, pseudo_file)
    findings = list(await db.scalars(select(Finding).where(Finding.run_id == run.id)))
    run.status = "completed"
    run.completed_at = now()
    run.trace = "\n".join([run.trace, trace_event("plan.completed", finding_count=len(findings))])
    await offload_trace_if_large(db, run)
    return run, findings


async def _emit_pattern_findings(db: AsyncSession, graph_id: str, repo_id: str, run_id: str, file: DiffFile) -> int:
    specs: list[tuple[str, str, str, str, str]] = []
    if SQLI_RE.search(file.content):
        specs.append(("sqli", "high", "Possible SQL injection", "Changed code appears to build a database query from interpolated input.", "Use parameterized queries and validate untrusted input."))
    if CMDI_RE.search(file.content):
        specs.append(("cmdi", "critical", "Possible command injection", "Changed code appears to pass interpolated input to process execution.", "Avoid shell execution; pass arguments as an array and validate allowlisted values."))
    if PATH_TRAVERSAL_RE.search(file.content):
        specs.append(("path_traversal", "high", "Possible path traversal", "Changed code appears to pass request-controlled data to a file access sink.", "Normalize paths and restrict access to an allowlisted base directory."))
    for secret_kind, secret in find_secret_candidates(file.content):
        severity = _secret_severity(file.content)
        specs.append(("secret_leak", severity, f"Hardcoded {secret_kind}", f"Changed code includes a credential-shaped value: {scrub_secrets(secret)}.", "Remove the secret, rotate it, and load credentials from a managed secret store."))
    count = 0
    for vuln_type, severity, title, description, remediation in specs:
        fingerprint = compute_fingerprint(repo_id, file.path, vuln_type)
        existing = await db.scalar(select(Finding).where(Finding.fingerprint == fingerprint))
        if existing is not None and existing.suppressed:
            continue
        if existing is None:
            db.add(
                Finding(
                    graph_id=graph_id,
                    node_id=f"file:{file.path}",
                    run_id=run_id,
                    vuln_type=vuln_type,
                    severity=severity,
                    title=title,
                    description=description,
                    remediation=remediation,
                    fingerprint=fingerprint,
                )
            )
            count += 1
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
                file = by_id.get(node_id).file if node_id in by_id else None
                if file:
                    affected.add(file)
    return sorted(affected)


def _is_manifest(path: str) -> bool:
    return path.endswith(("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "pyproject.toml", "Gemfile.lock"))
