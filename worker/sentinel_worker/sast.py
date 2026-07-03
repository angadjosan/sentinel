# sast.py - SAST agent loop
from __future__ import annotations
import json
import structlog
from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession
from .agent import SentinelLLMClient, ModelNotFoundError  # noqa: F401 — re-export for API handler
from .tools import TOOLS, dispatch_tool
from .models import Finding, Account, Graph
from .security import compute_fingerprint
from .graph_query import GraphQuery

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
        max_iterations=5,
        tool_dispatcher=tool_dispatcher,
        run_id=run_id,
        component="sast",
        db=db,
    ):
        if event.type == "tool_call":
            log.debug("scan.sast.tool_call", tool=event.tool_name, run_id=run_id)
            if event.tool_name == "emit_finding" and isinstance(event.result, dict):
                finding_data = event.result.get("data", event.result)
                fp = compute_fingerprint(
                    repo_id,
                    finding_data.get("node_id", "unknown"),
                    finding_data.get("vuln_type", "unknown"),
                )
                if fp not in suppressed_fps:
                    f = Finding(
                        graph_id=graph.id,
                        node_id=finding_data.get("node_id"),
                        run_id=run_id,
                        vuln_type=finding_data.get("vuln_type", "unknown"),
                        severity=finding_data.get("severity", "medium"),
                        title=finding_data.get("title", "Security Issue"),
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


async def get_llm_for_graph(graph_id: str, db: AsyncSession) -> SentinelLLMClient:
    import os as _os
    graph = await db.get(Graph, graph_id)
    if graph is None:
        raise LLMNotConfiguredError(f"Graph {graph_id!r} not found")
    account = await db.get(Account, graph.account_id)
    if account is None or not account.provider or not account.model:
        raise LLMNotConfiguredError(
            f"Account for graph {graph_id!r} has no provider/model configured. "
            "Run `sentinel config set provider <anthropic|openai|local>` and `sentinel config set model <name>`."
        )
    api_key = getattr(account, "api_key", None) or ""
    # Fall back to standard provider env vars so the key doesn't have to live in the DB.
    if not api_key and account.provider == "anthropic":
        api_key = _os.getenv("ANTHROPIC_API_KEY", "")
    elif not api_key and account.provider == "openai":
        api_key = _os.getenv("OPENAI_API_KEY", "")
    if not api_key and account.provider not in ("local", "mock"):
        raise LLMNotConfiguredError(
            f"Account for graph {graph_id!r} has no API key. "
            "Run `sentinel config set api-key <key>` or set the ANTHROPIC_API_KEY / OPENAI_API_KEY env var."
        )
    return SentinelLLMClient(provider=account.provider, model=account.model, api_key=api_key)
