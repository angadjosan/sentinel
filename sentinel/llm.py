"""Anthropic Claude API wrapper for code security review."""
from __future__ import annotations

import json
import logging
from typing import Any

import anthropic

from sentinel.models import CodeSecurityFinding

logger = logging.getLogger(__name__)

# Maximum characters to send for the diff/files content (~32k chars ≈ 8k tokens)
_MAX_DIFF_CHARS = 32_000
# When truncating, keep this many chars from the start and end of the diff
_TRUNCATE_HEAD = 20_000
_TRUNCATE_TAIL = 10_000

# Maximum characters per context file to include
_MAX_CONTEXT_FILE_CHARS = 2_000

SYSTEM_PROMPT = """You are a senior security engineer reviewing code for vulnerabilities.
Your job is to find REAL security issues, not style problems or minor inefficiencies.
Focus on: broken access control, IDOR, injection sinks (SQL/command/template),
hardcoded secrets/credentials, SSRF-shaped network calls, unsafe deserialization,
weak crypto defaults, missing auth middleware on sensitive routes.

Return ONLY valid JSON — a list of findings. Each finding:
{
  "file": "path/to/file.py",
  "line": 42,  // optional, null if unknown
  "category": "access_control|injection|secrets|ssrf|crypto|idor|other",
  "severity": "critical|high|medium|low|info",
  "cwe_id": "CWE-89",  // optional
  "explanation": "Concise 1-2 sentence explanation of the issue",
  "fix_suggestion": "Short actionable fix"
}

If no issues found, return [].
DO NOT return markdown. Return raw JSON array only."""


def _truncate_diff(diff: str) -> str:
    """
    Truncate diff to _MAX_DIFF_CHARS by keeping the first _TRUNCATE_HEAD chars
    and the last _TRUNCATE_TAIL chars, with a notice in the middle.
    """
    if len(diff) <= _MAX_DIFF_CHARS:
        return diff

    head = diff[:_TRUNCATE_HEAD]
    tail = diff[-_TRUNCATE_TAIL:]
    omitted = len(diff) - _TRUNCATE_HEAD - _TRUNCATE_TAIL
    notice = f"\n\n... [{omitted} characters omitted for length] ...\n\n"
    return head + notice + tail


def _build_context_block(context_files: dict[str, str]) -> str:
    """Format context files into a readable block, truncating each file."""
    if not context_files:
        return ""

    parts = ["# Context files (auth/middleware patterns)"]
    for path, content in context_files.items():
        if len(content) > _MAX_CONTEXT_FILE_CHARS:
            content = content[:_MAX_CONTEXT_FILE_CHARS] + "\n... (truncated)"
        parts.append(f"\n## {path}\n```\n{content}\n```")

    return "\n".join(parts)


def _parse_findings(raw: str) -> list[CodeSecurityFinding]:
    """
    Parse raw JSON string into a list of CodeSecurityFinding.
    Handles both a bare JSON array and a JSON array wrapped in markdown fences.
    Returns [] on any parse error.
    """
    text = raw.strip()

    # Strip markdown code fences if present (model sometimes ignores instructions)
    if text.startswith("```"):
        lines = text.splitlines()
        # Drop first line (```json or ```) and last line (```)
        inner_lines = lines[1:]
        if inner_lines and inner_lines[-1].strip() == "```":
            inner_lines = inner_lines[:-1]
        text = "\n".join(inner_lines).strip()

    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        logger.warning(
            "Failed to parse LLM security review response as JSON (%s). Raw: %.500s",
            exc, raw,
        )
        return []

    if not isinstance(data, list):
        logger.warning(
            "LLM response was JSON but not a list (got %s). Raw: %.500s",
            type(data).__name__, raw,
        )
        return []

    findings: list[CodeSecurityFinding] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            logger.debug("Skipping non-dict finding at index %d: %r", i, item)
            continue
        try:
            findings.append(CodeSecurityFinding(**item))
        except Exception as exc:  # pydantic validation errors
            logger.debug("Skipping invalid finding at index %d (%s): %r", i, exc, item)

    return findings


async def review_code_security(
    diff_or_files: str,
    context_files: dict[str, str],
    api_key: str,
    model: str = "claude-sonnet-4-6",
) -> list[CodeSecurityFinding]:
    """
    Send diff + context to Claude for security review.

    Prompt structure:
    1. System prompt (with prompt caching)
    2. If context_files: context file block
    3. Code to review (truncated)
    4. Instruction to return JSON
    """
    client = anthropic.AsyncAnthropic(api_key=api_key)

    # Build the user message
    user_parts: list[str] = []

    context_block = _build_context_block(context_files)
    if context_block:
        user_parts.append(context_block)

    truncated_diff = _truncate_diff(diff_or_files)
    user_parts.append(f"# Code to review\n{truncated_diff}")
    user_parts.append("Return JSON array of findings:")

    user_content = "\n\n".join(user_parts)

    try:
        response = await client.messages.create(
            model=model,
            max_tokens=4096,
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[
                {"role": "user", "content": user_content},
            ],
        )
    except anthropic.APIError as exc:
        logger.warning(
            "Anthropic API error during code security review: %s", exc
        )
        return []

    # Extract text from response
    raw_text = ""
    for block in response.content:
        if hasattr(block, "text"):
            raw_text += block.text

    if not raw_text.strip():
        logger.warning("LLM returned empty response for security review")
        return []

    return _parse_findings(raw_text)
