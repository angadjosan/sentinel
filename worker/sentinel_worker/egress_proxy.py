from __future__ import annotations

import asyncio
import contextlib

import structlog

from .canary import CanaryToken, detect_canaries
from .credential_broker import CredentialBroker
from .vm import EgressProxyPolicy, proxy_allows

log = structlog.get_logger(__name__)

# Header the sandbox attaches to outbound requests so the proxy can bind traffic
# to this run's provisioned token. An attacker who reaches an allowlisted host
# but cannot present this token is rejected (allowlist alone is not sufficient).
SANDBOX_TOKEN_HEADER = "x-sentinel-token"


def build_egress_proxy(
    *,
    allow_hosts: tuple[str, ...] | list[str],
    sandbox_token: str,
    broker: CredentialBroker | None = None,
    canary_tokens: tuple[CanaryToken, ...] = (),
    token_scoped: bool = True,
) -> EgressProxy:
    """Construct the run's egress proxy from resolved config primitives."""
    policy = EgressProxyPolicy(
        allow_hosts=tuple(dict.fromkeys(h for h in allow_hosts if h)),
        sandbox_token=sandbox_token,
        token_scoped=token_scoped,
    )
    return EgressProxy(policy, broker=broker, canary_tokens=tuple(canary_tokens))


def parse_connect_target(request_line: str) -> tuple[str, int] | None:
    """Parse an HTTP CONNECT request line: ``CONNECT host:port HTTP/1.1``."""
    parts = request_line.split()
    if len(parts) < 2 or parts[0].upper() != "CONNECT":
        return None
    host, _, port = parts[1].partition(":")
    if not host:
        return None
    try:
        return host, int(port) if port else 443
    except ValueError:
        return None


def parse_headers(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
    return headers


class EgressProxy:
    """The single egress path for the sandbox — the real enforcement point that
    composes default-deny + token-scoping (rec #7) with per-request credential
    brokering (rec #4) and canary leak detection (rec #4/G).

    The decision/transform methods are pure and fully tested; ``serve`` is the
    asyncio server that runs on the worker host outside the sandbox.
    """

    def __init__(
        self,
        policy: EgressProxyPolicy,
        *,
        broker: CredentialBroker | None = None,
        canary_tokens: tuple[CanaryToken, ...] = (),
    ) -> None:
        self.policy = policy
        self.broker = broker
        self.canary_tokens = list(canary_tokens)

    def authorize(self, host: str, presented_token: str | None) -> tuple[bool, str | None]:
        """Default-deny: a request is permitted only if the host is allowlisted
        AND it carries this run's token (when token-scoping is on)."""
        return proxy_allows(self.policy, host, presented_token)

    def apply_request_headers(self, host: str, headers: dict[str, str]) -> dict[str, str]:
        """Strip any agent-supplied auth and inject the real upstream credential
        (broker) — so the agent/sandbox never holds real third-party creds."""
        if self.broker is None:
            return dict(headers)
        return self.broker.inject_headers(host, headers)

    def scan_for_leaks(self, text: str) -> list[CanaryToken]:
        """Any canary decoy seen in outbound/return traffic is a real leak."""
        if not self.canary_tokens:
            return []
        leaked = detect_canaries(text, self.canary_tokens)
        if leaked:
            log.warning("egress.canary_leak", tokens=[t.id for t in leaked])
        return leaked

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Minimal HTTP CONNECT proxy: authorize, then tunnel bytes both ways.

        Reads the CONNECT preamble, enforces the policy, and on success opens the
        upstream socket and pipes traffic. Denied requests get a 403 and close.
        """
        try:
            preamble = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            writer.close()
            return
        lines = preamble.decode("latin-1").split("\r\n")
        target = parse_connect_target(lines[0]) if lines else None
        headers = parse_headers("\r\n".join(lines[1:]))
        token = headers.get(SANDBOX_TOKEN_HEADER)

        if target is None:
            await self._respond(writer, 400, "Bad Request")
            return
        host, port = target
        allowed, reason = self.authorize(host, token)
        if not allowed:
            log.warning("egress.denied", host=host, reason=reason)
            await self._respond(writer, 403, f"Forbidden ({reason})")
            return

        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
        except OSError as exc:
            log.warning("egress.upstream_unreachable", host=host, error=str(exc))
            await self._respond(writer, 502, "Bad Gateway")
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await asyncio.gather(
            self._pipe(reader, upstream_writer),
            self._pipe(upstream_reader, writer),
            return_exceptions=True,
        )

    @staticmethod
    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while not src.at_eof():
                chunk = await src.read(65536)
                if not chunk:
                    break
                dst.write(chunk)
                await dst.drain()
        finally:
            with contextlib.suppress(Exception):
                dst.close()

    @staticmethod
    async def _respond(writer: asyncio.StreamWriter, status: int, message: str) -> None:
        writer.write(f"HTTP/1.1 {status} {message}\r\n\r\n".encode("latin-1"))
        with contextlib.suppress(Exception):
            await writer.drain()
        writer.close()

    async def serve(self, host: str = "127.0.0.1", port: int = 0) -> asyncio.Server:
        """Start the proxy server. Port 0 binds an ephemeral port (returned on the
        server object). The sandbox is pointed here via build_egress_proxy_env."""
        return await asyncio.start_server(self.handle_client, host, port)
