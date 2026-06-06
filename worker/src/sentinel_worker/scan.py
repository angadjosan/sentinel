from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Finding, Graph, Node, Repo, Run, now
from .security import compute_fingerprint, find_secret_candidates, scrub_secrets


SQLI_RE = re.compile(r"(query|execute)\s*\([^)]*(\+|\$\{|format\(|f['\"])", re.IGNORECASE)
CMDI_RE = re.compile(r"(exec|spawn|system|popen)\s*\([^)]*(\+|\$\{|format\(|f['\"])", re.IGNORECASE)
PATH_TRAVERSAL_RE = re.compile(r"(readFile|open|send_file|FileResponse)\s*\([^)]*(req\.|request\.|params|query)", re.IGNORECASE)
ROUTE_RE = re.compile(r"(app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)")


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


def language_for(path: str) -> str | None:
    suffix = path.rsplit(".", 1)[-1] if "." in path else ""
    return {
        "ts": "typescript",
        "tsx": "typescript",
        "js": "javascript",
        "jsx": "javascript",
        "py": "python",
        "rb": "ruby",
        "java": "java",
        "go": "go",
        "rs": "rust",
        "c": "c",
        "cpp": "cpp",
        "h": "c",
    }.get(suffix)


def trace_event(kind: str, **fields: object) -> str:
    payload = {"ts": datetime.now(UTC).isoformat(), "kind": kind, **fields}
    return json.dumps(payload, sort_keys=True)


async def get_or_create_graph(db: AsyncSession, repo_name: str, account_name: str = "dev") -> Graph:
    account = None
    repo = None
    from .models import Account

    account = await db.scalar(select(Account).where(Account.name == account_name))
    if account is None:
        account = Account(name=account_name)
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


async def bootstrap_repo(db: AsyncSession, repo_name: str, files: dict[str, str]) -> Run:
    graph = await get_or_create_graph(db, repo_name)
    run = Run(graph_id=graph.id, kind="init", status="running")
    db.add(run)
    await db.flush()
    for path, content in files.items():
        node = Node(
            id=f"file:{path}",
            graph_id=graph.id,
            kind="FILE",
            name=path,
            file=path,
            line_start=1,
            line_end=max(1, len(content.splitlines())),
            language=language_for(path),
            is_new=False,
            label=f"{path} source file",
            intent="Repository source snapshot indexed during bootstrap.",
        )
        await db.merge(node)
    run.status = "completed"
    run.completed_at = now()
    run.trace = trace_event("init.completed", file_count=len(files))
    return run


async def scan_diff(db: AsyncSession, repo_name: str, diff: str, *, run_context: str = "local") -> Run:
    graph = await get_or_create_graph(db, repo_name)
    run = Run(graph_id=graph.id, kind="source", status="running", trace=trace_event("scan.started", run_context=run_context))
    db.add(run)
    await db.flush()
    repo = await db.scalar(select(Repo).where(Repo.id == graph.repo_id))
    assert repo is not None
    findings = 0
    for file in parse_unified_diff(diff):
        file_node = Node(
            id=f"file:{file.path}",
            graph_id=graph.id,
            kind="FILE",
            name=file.path,
            file=file.path,
            line_start=1,
            line_end=max(1, len(file.content.splitlines())),
            language=language_for(file.path),
            is_new=True,
            label=f"Changed {file.path}",
            intent="File changed in the submitted diff.",
        )
        await db.merge(file_node)
        for match in ROUTE_RE.finditer(file.content):
            route_node = Node(
                id=f"route:{file.path}:{match.group(2).upper()} {match.group(3)}",
                graph_id=graph.id,
                kind="ROUTE",
                name=f"{match.group(2).upper()} {match.group(3)}",
                file=file.path,
                line_start=file.content[: match.start()].count("\n") + 1,
                line_end=file.content[: match.start()].count("\n") + 1,
                language=language_for(file.path),
                is_entry_point=True,
                auth_required="auth" in file.content[max(0, match.start() - 250) : match.start()].lower(),
                privilege="user",
                is_new=True,
            )
            await db.merge(route_node)
        findings += await _emit_pattern_findings(db, graph.id, repo.id, run.id, file)
    run.status = "completed"
    run.completed_at = now()
    run.trace = "\n".join([run.trace, trace_event("scan.completed", finding_count=findings)])
    return run


async def _emit_pattern_findings(db: AsyncSession, graph_id: str, repo_id: str, run_id: str, file: DiffFile) -> int:
    specs: list[tuple[str, str, str, str, str]] = []
    if SQLI_RE.search(file.content):
        specs.append(("sqli", "high", "Possible SQL injection", "Changed code appears to build a database query from interpolated input.", "Use parameterized queries and validate untrusted input."))
    if CMDI_RE.search(file.content):
        specs.append(("cmdi", "critical", "Possible command injection", "Changed code appears to pass interpolated input to process execution.", "Avoid shell execution; pass arguments as an array and validate allowlisted values."))
    if PATH_TRAVERSAL_RE.search(file.content):
        specs.append(("path_traversal", "high", "Possible path traversal", "Changed code appears to pass request-controlled data to a file access sink.", "Normalize paths and restrict access to an allowlisted base directory."))
    for secret_kind, secret in find_secret_candidates(file.content):
        specs.append(("secret_leak", "critical", f"Hardcoded {secret_kind}", f"Changed code includes a credential-shaped value: {scrub_secrets(secret)}.", "Remove the secret, rotate it, and load credentials from a managed secret store."))
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
    return count
