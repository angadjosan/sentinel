from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import AsyncIterator

import httpx
import structlog

from sqlalchemy.ext.asyncio import AsyncSession

from .models import Run, TokenSpendByComponent
from .security import scrub_secrets

log = structlog.get_logger(__name__)


class ChannelViolationError(ValueError):
    pass


@dataclass(frozen=True)
class LLMCallResult:
    content: str
    input_tokens: int
    output_tokens: int
    model: str
    provider: str


@dataclass
class ToolCallEvent:
    type: str
    tool_name: str
    tool_input: dict
    result: dict


def _assert_no_repo_content_in_system(system: str) -> None:
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
            raise ChannelViolationError(
                f"repository content marker found in system prompt: {marker}"
            )


async def record_token_event(
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


class SentinelLLMClient:
    def __init__(
        self,
        provider: object | str | None = None,
        model: str = "ollama",
        api_key: str = "",
        api_endpoint: str | None = None,
    ) -> None:
        # Support legacy protocol-based provider (used by enrichment tests)
        if provider is not None and not isinstance(provider, str):
            self._legacy_provider = provider
            self.provider_name = getattr(provider, "provider", "fixture")
            self.model = model
            self.api_key = api_key
            self.api_endpoint = api_endpoint
            self._client = None
        else:
            self._legacy_provider = None
            self.provider_name = provider or "local"
            self.model = model
            self.api_key = api_key
            self.api_endpoint = api_endpoint
            self._client = self._init_client()

    def _init_client(self) -> object:
        if self.provider_name == "anthropic":
            try:
                from anthropic import AsyncAnthropic
                return AsyncAnthropic(api_key=self.api_key or None)
            except ImportError:
                return None
        elif self.provider_name == "openai":
            try:
                from openai import AsyncOpenAI
                return AsyncOpenAI(api_key=self.api_key or None)
            except ImportError:
                return None
        # "local" / Ollama — no persistent client object needed
        return None

    def _is_mock_mode(self) -> bool:
        """Return True only when provider is explicitly 'mock' (test fixtures)."""
        return self._legacy_provider is None and self.provider_name == "mock"

    async def call(
        self,
        *,
        system: str,
        user: str | None = None,
        data: str | None = None,
        tools: list[dict] | None = None,
        schema: type | None = None,
        run_id: str | None = None,
        component: str = "unknown",
        db: AsyncSession | None = None,
        iteration: int | None = None,
    ) -> LLMCallResult:
        # Support legacy 'data' kwarg used by enrichment
        effective_user = user if user is not None else (data or "")
        _assert_no_repo_content_in_system(system)

        # Use legacy protocol provider if set
        if self._legacy_provider is not None:
            result = await self._legacy_provider.complete(
                system=system, data=effective_user, model=self.model
            )
            if db is not None and run_id is not None:
                await record_token_event(db, run_id, component, result, iteration=iteration)
            log.debug(
                "llm.call",
                provider=result.provider,
                model=result.model,
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
            )
            return result

        result = await self._call_provider(system=system, user=effective_user, tools=tools)
        if db is not None and run_id is not None:
            await record_token_event(db, run_id, component, result, iteration=iteration)
        log.debug(
            "llm.call",
            provider=self.provider_name,
            model=self.model,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
        )
        return result

    async def _call_provider(
        self,
        *,
        system: str,
        user: str,
        tools: list[dict] | None = None,
    ) -> LLMCallResult:
        if self._is_mock_mode():
            return self._mock_call(system=system, user=user)
        if self.provider_name == "anthropic":
            return await self._call_anthropic(system=system, user=user, tools=tools)
        elif self.provider_name == "openai":
            return await self._call_openai(system=system, user=user, tools=tools)
        else:
            return await self._call_local(system=system, user=user, tools=tools)

    def _mock_call(self, *, system: str, user: str) -> LLMCallResult:
        words_in = len(system.split()) + len(user.split())
        if "annotate a security context graph" in system.lower():
            content = _mock_enrichment_response(user)
        else:
            content = "No issues found." if not user.strip() else f"Reviewed {len(user)} bytes."
        return LLMCallResult(
            content=content,
            input_tokens=words_in,
            output_tokens=len(content.split()),
            model=self.model,
            provider=self.provider_name,
        )

    async def _call_anthropic(
        self,
        *,
        system: str,
        user: str,
        tools: list[dict] | None = None,
    ) -> LLMCallResult:
        from anthropic import AsyncAnthropic

        client: AsyncAnthropic = self._client  # type: ignore[assignment]
        kwargs: dict = {
            "model": self.model,
            "max_tokens": 8192,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if tools:
            kwargs["tools"] = tools
        response = await client.messages.create(**kwargs)
        content = ""
        for block in response.content:
            if hasattr(block, "text"):
                content = block.text
                break
        return LLMCallResult(
            content=content,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            model=self.model,
            provider="anthropic",
        )

    async def _call_openai(
        self,
        *,
        system: str,
        user: str,
        tools: list[dict] | None = None,
    ) -> LLMCallResult:
        from openai import AsyncOpenAI

        client: AsyncOpenAI = self._client  # type: ignore[assignment]
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        kwargs: dict = {
            "model": self.model,
            "messages": messages,
        }
        if tools:
            openai_tools = [
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t.get("description", ""),
                        "parameters": t.get("input_schema", {}),
                    },
                }
                for t in tools
            ]
            kwargs["tools"] = openai_tools
            kwargs["tool_choice"] = "auto"
        response = await client.chat.completions.create(**kwargs)
        choice = response.choices[0]
        content = choice.message.content or ""
        usage = response.usage
        return LLMCallResult(
            content=content,
            input_tokens=usage.prompt_tokens if usage else 0,
            output_tokens=usage.completion_tokens if usage else 0,
            model=self.model,
            provider="openai",
        )

    async def _call_local(
        self,
        *,
        system: str,
        user: str,
        tools: list[dict] | None = None,
    ) -> LLMCallResult:
        endpoint = self.api_endpoint or "http://localhost:11434"
        url = f"{endpoint}/api/chat"
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        payload: dict = {
            "model": self.model,
            "messages": messages,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
        async with httpx.AsyncClient() as http:
            try:
                resp = await http.post(url, json=payload, timeout=120)
                resp.raise_for_status()
                data = resp.json()
                msg = data.get("message", {})
                content = msg.get("content", "")
                usage = data.get("usage", {}) or {}
                return LLMCallResult(
                    content=content,
                    input_tokens=usage.get("prompt_tokens", 0),
                    output_tokens=usage.get("completion_tokens", 0),
                    model=self.model,
                    provider="local",
                )
            except (httpx.ConnectError, httpx.ConnectTimeout):
                raise RuntimeError(
                    f"Cannot connect to Ollama at {endpoint}. "
                    "Either start Ollama or configure a cloud provider: "
                    "`sentinel config set provider anthropic` then `sentinel config set api-key <key>`"
                )
            except httpx.HTTPStatusError as exc:
                # Fall back to non-tool JSON-mode if the model doesn't support tool calling
                if tools and exc.response.status_code in (400, 422):
                    payload.pop("tools", None)
                    resp = await http.post(url, json=payload, timeout=120)
                    resp.raise_for_status()
                    data = resp.json()
                    msg = data.get("message", {})
                    content = msg.get("content", "")
                    usage = data.get("usage", {}) or {}
                    return LLMCallResult(
                        content=content,
                        input_tokens=usage.get("prompt_tokens", 0),
                        output_tokens=usage.get("completion_tokens", 0),
                        model=self.model,
                        provider="local",
                    )
                raise

    async def call_with_tools(
        self,
        *,
        system: str,
        user: str,
        tools: list[dict],
        max_iterations: int = 50,
        tool_dispatcher,
        run_id: str | None = None,
        component: str = "sast",
        db: AsyncSession | None = None,
    ) -> AsyncIterator[ToolCallEvent]:
        _assert_no_repo_content_in_system(system)

        if self.provider_name == "anthropic":
            async for event in self._anthropic_agentic_loop(
                system=system,
                user=user,
                tools=tools,
                max_iterations=max_iterations,
                tool_dispatcher=tool_dispatcher,
                run_id=run_id,
                component=component,
                db=db,
            ):
                yield event
        elif self.provider_name == "openai":
            async for event in self._openai_agentic_loop(
                system=system,
                user=user,
                tools=tools,
                max_iterations=max_iterations,
                tool_dispatcher=tool_dispatcher,
                run_id=run_id,
                component=component,
                db=db,
            ):
                yield event
        else:
            async for event in self._local_agentic_loop(
                system=system,
                user=user,
                tools=tools,
                max_iterations=max_iterations,
                tool_dispatcher=tool_dispatcher,
                run_id=run_id,
                component=component,
                db=db,
            ):
                yield event

    async def _anthropic_agentic_loop(
        self,
        *,
        system: str,
        user: str,
        tools: list[dict],
        max_iterations: int,
        tool_dispatcher,
        run_id: str | None,
        component: str,
        db: AsyncSession | None,
    ) -> AsyncIterator[ToolCallEvent]:
        from anthropic import AsyncAnthropic

        client: AsyncAnthropic = self._client  # type: ignore[assignment]
        messages = [{"role": "user", "content": user}]
        total_input = 0
        total_output = 0

        for _ in range(max_iterations):
            response = await client.messages.create(
                model=self.model,
                max_tokens=8192,
                system=system,
                messages=messages,
                tools=tools,
            )
            total_input += response.usage.input_tokens
            total_output += response.usage.output_tokens

            if response.stop_reason == "end_turn":
                break

            if response.stop_reason == "tool_use":
                # Append assistant message
                messages.append({"role": "assistant", "content": response.content})
                tool_results = []
                for block in response.content:
                    if block.type == "tool_use":
                        tool_input = block.input or {}
                        result = await tool_dispatcher(block.name, tool_input)
                        yield ToolCallEvent(
                            type="tool_call",
                            tool_name=block.name,
                            tool_input=tool_input,
                            result=result,
                        )
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": json.dumps(result),
                        })
                messages.append({"role": "user", "content": tool_results})
            else:
                break

        if db is not None and run_id is not None:
            result = LLMCallResult(
                content="",
                input_tokens=total_input,
                output_tokens=total_output,
                model=self.model,
                provider="anthropic",
            )
            await record_token_event(db, run_id, component, result)
            log.debug(
                "llm.call",
                provider="anthropic",
                model=self.model,
                input_tokens=total_input,
                output_tokens=total_output,
            )

    async def _openai_agentic_loop(
        self,
        *,
        system: str,
        user: str,
        tools: list[dict],
        max_iterations: int,
        tool_dispatcher,
        run_id: str | None,
        component: str,
        db: AsyncSession | None,
    ) -> AsyncIterator[ToolCallEvent]:
        from openai import AsyncOpenAI

        client: AsyncOpenAI = self._client  # type: ignore[assignment]
        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {}),
                },
            }
            for t in tools
        ]
        messages: list[dict] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        total_input = 0
        total_output = 0

        for _ in range(max_iterations):
            response = await client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=openai_tools,
                tool_choice="auto",
            )
            usage = response.usage
            if usage:
                total_input += usage.prompt_tokens
                total_output += usage.completion_tokens

            choice = response.choices[0]
            msg = choice.message

            if choice.finish_reason == "stop" or not msg.tool_calls:
                break

            messages.append(msg.model_dump())

            for tc in msg.tool_calls or []:
                tool_input = json.loads(tc.function.arguments or "{}")
                result = await tool_dispatcher(tc.function.name, tool_input)
                yield ToolCallEvent(
                    type="tool_call",
                    tool_name=tc.function.name,
                    tool_input=tool_input,
                    result=result,
                )
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result),
                })

        if db is not None and run_id is not None:
            result_obj = LLMCallResult(
                content="",
                input_tokens=total_input,
                output_tokens=total_output,
                model=self.model,
                provider="openai",
            )
            await record_token_event(db, run_id, component, result_obj)
            log.debug(
                "llm.call",
                provider="openai",
                model=self.model,
                input_tokens=total_input,
                output_tokens=total_output,
            )

    async def _local_agentic_loop(
        self,
        *,
        system: str,
        user: str,
        tools: list[dict],
        max_iterations: int,
        tool_dispatcher,
        run_id: str | None,
        component: str,
        db: AsyncSession | None,
    ) -> AsyncIterator[ToolCallEvent]:
        # Ollama: attempt tool calling, fall back to single-shot JSON-mode
        endpoint = self.api_endpoint or "http://localhost:11434"
        url = f"{endpoint}/api/chat"
        messages: list[dict] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]

        async with httpx.AsyncClient() as http:
            for _ in range(max_iterations):
                payload = {
                    "model": self.model,
                    "messages": messages,
                    "tools": tools,
                    "stream": False,
                }
                try:
                    resp = await http.post(url, json=payload, timeout=120)
                    resp.raise_for_status()
                    data = resp.json()
                except (httpx.ConnectError, httpx.ConnectTimeout):
                    raise RuntimeError(
                        f"Cannot connect to Ollama at {endpoint}. "
                        "Either start Ollama or configure a cloud provider: "
                        "`sentinel config set provider anthropic` then `sentinel config set api-key <key>`"
                    )
                except Exception:
                    break

                msg = data.get("message", {})
                tool_calls = msg.get("tool_calls") or []
                if not tool_calls:
                    break

                messages.append({"role": "assistant", "content": msg.get("content", ""), "tool_calls": tool_calls})
                for tc in tool_calls:
                    fn = tc.get("function", {})
                    name = fn.get("name", "")
                    args = fn.get("arguments", {})
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except Exception:
                            args = {}
                    result = await tool_dispatcher(name, args)
                    yield ToolCallEvent(
                        type="tool_call",
                        tool_name=name,
                        tool_input=args,
                        result=result,
                    )
                    messages.append({
                        "role": "tool",
                        "content": json.dumps(result),
                    })

        if db is not None and run_id is not None:
            result_obj = LLMCallResult(
                content="",
                input_tokens=0,
                output_tokens=0,
                model=self.model,
                provider="local",
            )
            await record_token_event(db, run_id, component, result_obj)


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


def get_llm_client(account_config: dict) -> SentinelLLMClient:
    provider = account_config.get("provider", "local")
    model = account_config.get("model", "llama3.1")
    api_key = account_config.get("api_key", "")
    api_endpoint = account_config.get("api_endpoint", None)
    return SentinelLLMClient(
        provider=provider,
        model=model,
        api_key=api_key,
        api_endpoint=api_endpoint,
    )
