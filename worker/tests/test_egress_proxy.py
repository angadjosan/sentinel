"""Egress proxy: default-deny + token-scoping, broker injection, canary scan,
plus a real CONNECT tunnel over an ephemeral port."""
import asyncio

import pytest

from sentinel_worker.canary import CanaryToken
from sentinel_worker.credential_broker import BrokerConfig, CredentialBroker, Upstream
from sentinel_worker.egress_proxy import EgressProxy, SANDBOX_TOKEN_HEADER, parse_connect_target, parse_headers
from sentinel_worker.vm import EgressProxyPolicy


def _proxy(**kw):
    policy = EgressProxyPolicy(allow_hosts=("api.example.com",), sandbox_token="tok-123")
    return EgressProxy(policy, **kw)


def test_parse_connect_target():
    assert parse_connect_target("CONNECT api.example.com:443 HTTP/1.1") == ("api.example.com", 443)
    assert parse_connect_target("CONNECT host HTTP/1.1") == ("host", 443)  # default port
    assert parse_connect_target("GET / HTTP/1.1") is None


def test_parse_headers_lowercases():
    hdrs = parse_headers("Host: x\r\nX-Sentinel-Token: tok-123")
    assert hdrs["host"] == "x"
    assert hdrs[SANDBOX_TOKEN_HEADER] == "tok-123"


def test_authorize_requires_host_and_token():
    p = _proxy()
    assert p.authorize("api.example.com", "tok-123") == (True, None)
    assert p.authorize("api.example.com", "attacker") == (False, "token_mismatch")
    assert p.authorize("evil.test", "tok-123") == (False, "host_not_allowlisted")


def test_apply_request_headers_injects_broker_cred_and_strips_agent_auth():
    broker = CredentialBroker(
        BrokerConfig(enabled=True, upstreams=(Upstream(host="api.example.com", credential_ref="k"),)),
        {"k": "real-secret"},
    )
    p = _proxy(broker=broker)
    out = p.apply_request_headers("api.example.com", {"Authorization": "Bearer agent-supplied"})
    assert out["Authorization"] == "Bearer real-secret"  # agent value replaced by real one


def test_scan_for_leaks_flags_canary():
    canary = CanaryToken(id="canary-generic-0", value="abc123" * 6, kind="generic")
    p = _proxy(canary_tokens=(canary,))
    assert p.scan_for_leaks(f"...{canary.value}...")[0].id == "canary-generic-0"
    assert p.scan_for_leaks("nothing here") == []


@pytest.mark.asyncio
async def test_denied_connect_returns_403_over_a_real_socket():
    proxy = _proxy()
    server = await proxy.serve()
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # allowlisted host but no token -> denied
        writer.write(b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com\r\n\r\n")
        await writer.drain()
        status_line = await asyncio.wait_for(reader.readline(), timeout=2)
        assert b"403" in status_line
        writer.close()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_allowed_connect_tunnels_to_a_backend():
    # A tiny echo backend playing the role of an allowlisted upstream.
    async def echo(reader, writer):
        data = await reader.read(64)
        writer.write(b"PONG:" + data)
        await writer.drain()
        writer.close()

    backend = await asyncio.start_server(echo, "127.0.0.1", 0)
    backend_port = backend.sockets[0].getsockname()[1]

    policy = EgressProxyPolicy(allow_hosts=("127.0.0.1",), sandbox_token="tok-123")
    proxy = EgressProxy(policy)
    server = await proxy.serve()
    proxy_port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            f"CONNECT 127.0.0.1:{backend_port} HTTP/1.1\r\n{SANDBOX_TOKEN_HEADER}: tok-123\r\n\r\n".encode()
        )
        await writer.drain()
        established = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
        assert b"200" in established  # tunnel established
        writer.write(b"PING")
        await writer.drain()
        tunneled = await asyncio.wait_for(reader.read(16), timeout=2)
        assert tunneled == b"PONG:PING"  # bytes flowed through the tunnel to the backend
        writer.close()
    finally:
        server.close()
        backend.close()
        await server.wait_closed()
        await backend.wait_closed()
