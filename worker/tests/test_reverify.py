"""Replay re-verification: a stored proof artifact replays to confirm a fix."""
import json

import httpx
import pytest

from sentinel_worker.reverify import reverify_replay

_ARTIFACT = json.dumps(
    {"method": "POST", "url": "http://staging.test/", "params": {"q": "' OR '1'='1", "id": "x"}, "json": {"input": "' OR '1'='1"}},
    sort_keys=True,
)


def _client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=5.0)


@pytest.mark.asyncio
async def test_still_vulnerable_when_proof_marker_persists():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="psycopg2.errors.SyntaxError: unclosed quotation mark")

    result = await reverify_replay(_ARTIFACT, vuln_type="sqli", http_client=_client(handler))
    assert result.replayed is True
    assert result.still_vulnerable is True
    assert result.status == 500
    assert result.evidence is not None


@pytest.mark.asyncio
async def test_fix_verified_when_proof_no_longer_fires():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="0 results")  # parameterized query -> no SQL error

    result = await reverify_replay(_ARTIFACT, vuln_type="sqli", http_client=_client(handler))
    assert result.replayed is True
    assert result.still_vulnerable is False  # fix confirmed
    assert result.evidence is None


@pytest.mark.asyncio
async def test_malformed_artifact_is_not_replayed():
    result = await reverify_replay("not json", vuln_type="sqli")
    assert result.replayed is False
    assert result.still_vulnerable is False
