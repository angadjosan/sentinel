"""CanarytokensClient: real HTTP minting against a Canarytokens-style service."""
import httpx

from sentinel_worker.canary import CanarytokensClient, CanarytokensProvider


class _SyncMock:
    """Minimal sync httpx-like client backed by a MockTransport handler."""

    def __init__(self, handler):
        self._t = httpx.MockTransport(handler)

    def post(self, url, data=None, headers=None, timeout=None):
        request = httpx.Request("POST", url, data=data, headers=headers)
        response = self._t.handle_request(request)
        response.request = request  # bind so raise_for_status() works
        return response


def test_client_mints_from_generate_endpoint():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/generate"
        assert b"sentinel-pentest" in request.content
        return httpx.Response(200, json={"token": "abc123", "hostname": "abc123.canary.test"})

    client = CanarytokensClient(_SyncMock(handler), alert_email="sec@example.com")
    provider = CanarytokensProvider(base_url="https://canarytokens.org", api_token="t", client=client)
    token = provider.mint("url", 0)
    assert token.id == "abc123"
    assert token.value == "abc123.canary.test"
    assert token.kind == "url"


def test_client_falls_back_to_value_field():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": "tok9", "value": "https://tok9.canary.test"})

    client = CanarytokensClient(_SyncMock(handler))
    result = client.create_token(base_url="https://c.test", api_token="", kind="generic", index=1)
    assert result == {"id": "tok9", "value": "https://tok9.canary.test"}
