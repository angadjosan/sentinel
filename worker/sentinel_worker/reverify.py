from __future__ import annotations

import json
from dataclasses import dataclass

import httpx
import structlog

from .pentest import _http_body_proves_exploit
from .security import scrub_secrets

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ReverifyResult:
    """Outcome of replaying a confirmed finding's stored proof artifact."""

    replayed: bool  # did we successfully re-send the request?
    still_vulnerable: bool  # did the same proof still fire?
    status: int | None
    evidence: str | None


async def reverify_replay(
    artifact_json: str,
    *,
    vuln_type: str,
    http_client: httpx.AsyncClient | None = None,
) -> ReverifyResult:
    """Replay the exact request captured at confirmation time and check whether
    the deterministic proof still fires. A fix is verified when a previously
    confirmed finding replays to ``still_vulnerable=False`` — the same
    re-execution contract OSS-Fuzz uses to auto-close fixed crashes.
    """
    try:
        artifact = json.loads(artifact_json)
    except (ValueError, TypeError):
        return ReverifyResult(replayed=False, still_vulnerable=False, status=None, evidence=None)
    url = artifact.get("url")
    if not isinstance(url, str) or not url:
        return ReverifyResult(replayed=False, still_vulnerable=False, status=None, evidence=None)

    method = str(artifact.get("method") or "POST").upper()
    params = artifact.get("params") or {}
    json_body = artifact.get("json")
    payload = str(params.get("q") or (json_body or {}).get("input") or "")

    client = http_client or httpx.AsyncClient(timeout=15.0)
    owns_client = http_client is None
    try:
        resp = await client.request(method, url, params=params, json=json_body)
    except httpx.HTTPError as exc:
        log.warning("reverify.request_failed", url=url, error=str(exc))
        return ReverifyResult(replayed=False, still_vulnerable=False, status=None, evidence=None)
    finally:
        if owns_client:
            await client.aclose()

    evidence = _http_body_proves_exploit(vuln_type, payload, resp.status_code, resp.text or "")
    return ReverifyResult(
        replayed=True,
        still_vulnerable=evidence is not None,
        status=resp.status_code,
        evidence=scrub_secrets(evidence) if evidence else None,
    )
