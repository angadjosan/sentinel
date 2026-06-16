# sast.py - SAST agent loop
from __future__ import annotations
import json
import structlog
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from .agent import SentinelLLMClient
from .tools import TOOLS, dispatch_tool
from .models import Finding, Account, Graph
from .security import compute_fingerprint
from .graph_query import GraphQuery
from .scan import trace_event

log = structlog.get_logger(__name__)

_PROMPTS_DIR = Path(__file__).parent / "prompts"


class LLMNotConfiguredError(RuntimeError):
    """Raised when a scan is attempted without a configured LLM provider."""


async def run_sast(
    diff: str,
    bootstrap_context: str,
    run_id: str,
    suppressed_fps: list[str],
    graph,  # Graph ORM model
    repo_id: str,
    db: AsyncSession,
    llm: SentinelLLMClient | None = None,
) -> list[Finding]:
    if llm is None:
        llm = await get_llm_for_graph(graph.id, db)

    system = (_PROMPTS_DIR / "sast.txt").read_text()

    user_content = (
        f"<suppressed_fingerprints>\n{json.dumps(suppressed_fps)}\n</suppressed_fingerprints>\n\n"
        f"<graph_context>\n{bootstrap_context}\n</graph_context>\n\n"
        f"<diff>\n{diff}\n</diff>"
    )

    findings = []
    graph_query = GraphQuery(db=db, graph_id=graph.id)
    _empty_rounds = 0

    async def tool_dispatcher(tool_name: str, tool_input: dict) -> dict:
        return await dispatch_tool(
            tool_name=tool_name,
            tool_input=tool_input,
            graph=graph_query,
            run_id=run_id,
            db=db,
            repo_id=repo_id,
        )

    log.info("scan.sast.started", run_id=run_id)

    async for event in llm.call_with_tools(
        system=system,
        user=user_content,
        tools=TOOLS,
        max_iterations=12,
        tool_dispatcher=tool_dispatcher,
        run_id=run_id,
        component="sast",
        db=db,
    ):
        if event.type == "tool_call":
            log.debug("scan.sast.tool_call", tool=event.tool_name, run_id=run_id)
            if event.tool_name == "emit_finding" and isinstance(event.result, dict):
                finding_data = event.result.get("data", event.result)
                vuln_type = finding_data.get("vuln_type") or finding_data.get("type") or finding_data.get("vulnerability_type") or finding_data.get("category") or _infer_vuln_type(finding_data.get("description", "") + " " + finding_data.get("title", ""))
                node_id = finding_data.get("node_id") or finding_data.get("file_path") or finding_data.get("file") or "unknown"
                if not node_id.startswith("file:") and "/" in str(node_id):
                    node_id = f"file:{node_id}"
                finding_data["vuln_type"] = vuln_type
                finding_data["node_id"] = node_id
                fp = compute_fingerprint(repo_id, node_id, vuln_type)
                if fp not in suppressed_fps:
                    existing = await db.scalar(select(Finding).where(Finding.fingerprint == fp))
                    if existing is not None:
                        existing.run_id = run_id
                        existing.severity = finding_data.get("severity", existing.severity)
                        existing.title = finding_data.get("title", existing.title)
                        existing.description = finding_data.get("description", existing.description)
                        existing.remediation = finding_data.get("remediation", existing.remediation)
                        findings.append(existing)
                    else:
                        f = Finding(
                            graph_id=graph.id,
                            node_id=node_id,
                            run_id=run_id,
                            vuln_type=vuln_type,
                            severity=finding_data.get("severity", "medium"),
                            title=finding_data.get("title") or _VULN_TYPE_TITLES.get(vuln_type, "Security Issue"),
                            description=finding_data.get("description", ""),
                            remediation=finding_data.get("remediation", ""),
                            fingerprint=fp,
                        )
                        db.add(f)
                        await db.flush()
                        findings.append(f)
                    log.info("scan.sast.finding_emitted", vuln_type=f.vuln_type, severity=f.severity, run_id=run_id)
                else:
                    log.debug("scan.sast.finding_suppressed", fingerprint=fp, run_id=run_id)

    log.info("scan.sast.completed", finding_count=len(findings), run_id=run_id)
    return findings


_VULN_TYPE_KEYWORDS = {
    "sqli": ["sql injection", "sql query", "db.query", "sql statement"],
    "cmdi": ["command injection", "shell command", "child_process", "exec(", "os.system", "subprocess"],
    "xss": ["cross-site scripting", "xss", "innerHTML", "document.write"],
    "ssrf": ["ssrf", "server-side request", "fetch(", "url injection"],
    "path_traversal": ["path traversal", "directory traversal", "../", "file path"],
    "auth_bypass": ["auth bypass", "authentication bypass", "authorization"],
    "secret_leak": ["secret", "api key", "password", "credential", "token leak"],
    "idor": ["idor", "insecure direct object"],
    "open_redirect": ["open redirect", "redirect"],
}


def _infer_vuln_type(text: str) -> str:
    lower = text.lower()
    for vuln_type, keywords in _VULN_TYPE_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return vuln_type
    return "unknown"


_VULN_TYPE_TITLES = {
    "sqli": "SQL Injection",
    "cmdi": "Command Injection",
    "xss": "Cross-Site Scripting",
    "ssrf": "Server-Side Request Forgery",
    "path_traversal": "Path Traversal",
    "auth_bypass": "Authentication Bypass",
    "secret_leak": "Secret Leak",
    "idor": "Insecure Direct Object Reference",
    "open_redirect": "Open Redirect",
}


async def get_llm_for_graph(graph_id: str, db: AsyncSession) -> SentinelLLMClient:
    graph = await db.get(Graph, graph_id)
    if graph is None:
        raise LLMNotConfiguredError(f"Graph {graph_id!r} not found")
    account = await db.get(Account, graph.account_id)
    if account is None or not account.provider or not account.model:
        raise LLMNotConfiguredError(
            f"Account for graph {graph_id!r} has no provider/model configured. "
            "Run `sentinel config set provider <anthropic|openai|local>` and `sentinel config set model <name>`."
        )
    api_key = getattr(account, "api_key", None)
    if not api_key and account.provider != "local":
        raise LLMNotConfiguredError(
            f"Account for graph {graph_id!r} has no API key. "
            "Run `sentinel config set api-key <key>`."
        )
    return SentinelLLMClient(provider=account.provider, model=account.model, api_key=api_key or "")
