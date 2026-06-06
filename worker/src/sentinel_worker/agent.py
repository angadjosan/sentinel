from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from .models import Run, TokenSpendByComponent
from .security import scrub_secrets


class ChannelViolationError(ValueError):
    pass


class LLMProvider(Protocol):
    async def complete(self, *, system: str, data: str, model: str) -> "LLMCallResult":
        ...


@dataclass(frozen=True)
class LLMCallResult:
    content: str
    input_tokens: int
    output_tokens: int
    model: str
    provider: str


class MockLLMProvider:
    provider = "local"

    async def complete(self, *, system: str, data: str, model: str) -> LLMCallResult:
        words_in = len(system.split()) + len(data.split())
        if "annotate a security context graph" in system.lower():
            content = _mock_enrichment_response(data)
        else:
            content = "No issues found." if not data.strip() else f"Reviewed {len(data)} bytes."
        return LLMCallResult(content=content, input_tokens=words_in, output_tokens=len(content.split()), model=model, provider=self.provider)


class SentinelLLMClient:
    def __init__(self, provider: LLMProvider | None = None, model: str = "ollama"):
        self.provider = provider or MockLLMProvider()
        self.model = model

    async def call(
        self,
        *,
        system: str,
        data: str,
        component: str,
        db: AsyncSession | None = None,
        run_id: str | None = None,
        iteration: int | None = None,
    ) -> LLMCallResult:
        self._assert_no_repo_content_in_system(system)
        result = await self.provider.complete(system=system, data=data, model=self.model)
        if db is not None and run_id is not None:
            await self.record_token_event(db, run_id, component, result, iteration=iteration)
        return result

    async def record_token_event(
        self,
        db: AsyncSession,
        run_id: str,
        component: str,
        result: LLMCallResult,
        *,
        iteration: int | None = None,
    ) -> None:
        run = await db.get(Run, run_id)
        if run is None:
            raise ValueError("run not found")
        event = {
            "ts": datetime.now(UTC).isoformat(),
            "kind": "token_event",
            "component": component,
            "model": result.model,
            "provider": result.provider,
            "input_tokens": result.input_tokens,
            "output_tokens": result.output_tokens,
            "iteration": iteration,
        }
        run.token_spend += result.input_tokens + result.output_tokens
        aggregate = await db.get(TokenSpendByComponent, (run_id, component, result.model))
        if aggregate is None:
            db.add(
                TokenSpendByComponent(
                    run_id=run_id,
                    component=component,
                    model=result.model,
                    provider=result.provider,
                    input_tokens=result.input_tokens,
                    output_tokens=result.output_tokens,
                )
            )
        else:
            aggregate.input_tokens += result.input_tokens
            aggregate.output_tokens += result.output_tokens
        line = json.dumps(event, sort_keys=True)
        run.trace = "\n".join(part for part in [run.trace, scrub_secrets(line)] if part)

    def _assert_no_repo_content_in_system(self, system: str) -> None:
        forbidden_markers = [
            "+++ b/",
            "--- a/",
            "diff --git",
            "AKIA",
            "req.query",
            "request.GET",
            "db.query(",
            "subprocess.",
            "child_process",
        ]
        for marker in forbidden_markers:
            if marker in system:
                raise ChannelViolationError(f"repository content marker found in system prompt: {marker}")


def _mock_enrichment_response(data: str) -> str:
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        return json.dumps({"annotations": []})
    annotations = []
    for node in payload.get("nodes", []):
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            continue
        kind = str(node.get("kind", "node")).lower()
        name = str(node.get("name", node["id"]))
        label = f"{name} {kind}".strip()
        intent = f"{name} is a {kind} node discovered from structural graph context."
        trust_level = "untrusted" if kind == "parameter" else ("trusted" if node.get("auth_required") else None)
        annotations.append({"node_id": node["id"], "label": label[:80], "intent": intent, "trust_level": trust_level})
    return json.dumps({"annotations": annotations}, sort_keys=True)
