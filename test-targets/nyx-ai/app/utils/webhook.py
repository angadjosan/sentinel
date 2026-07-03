"""Outbound webhook delivery for Nyx AI events (usage alerts, run completions, etc.)."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from ..config import get_settings

log = structlog.get_logger(__name__)
settings = get_settings()

# Hosts that must never receive outbound webhooks — prevents SSRF to internal services.
_BLOCKED_HOST_RE = re.compile(
    r"^("
    r"localhost"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.169\.254"
    r"|0\.0\.0\.0"
    r")$",
    re.IGNORECASE,
)


def _is_safe_webhook_url(url: str) -> bool:
    """Return True only if *url* points to a routable public host."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    if parsed.scheme not in ("http", "https"):
        return False

    hostname = parsed.hostname or ""
    if _BLOCKED_HOST_RE.match(hostname):
        return False

    return True


async def deliver_webhook(url: str, event: str, payload: dict[str, Any]) -> bool:
    """POST *payload* to *url*.  Returns True on 2xx, False otherwise."""
    if not _is_safe_webhook_url(url):
        log.warning("webhook.blocked", url=url, reason="unsafe host")
        return False

    body = {"event": event, "data": payload}
    try:
        async with httpx.AsyncClient(timeout=settings.webhook_timeout_seconds) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            log.info("webhook.delivered", url=url, event=event, status=resp.status_code)
            return True
    except httpx.HTTPStatusError as exc:
        log.warning("webhook.http_error", url=url, status=exc.response.status_code)
    except Exception as exc:
        log.warning("webhook.error", url=url, error=str(exc))
    return False
