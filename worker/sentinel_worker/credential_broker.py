from __future__ import annotations

from dataclasses import dataclass

# Agent-supplied auth headers are always stripped before any upstream injection so the
# AI agent can never smuggle its own credentials through the broker (case-insensitive match).
AGENT_AUTH_HEADERS = frozenset({"authorization", "x-api-key", "proxy-authorization"})

REDACTION_PLACEHOLDER = "[REDACTED:broker_credential]"


@dataclass(frozen=True)
class Upstream:
    host: str
    credential_ref: str
    header: str = "Authorization"
    scheme: str = "Bearer"


@dataclass(frozen=True)
class BrokerConfig:
    enabled: bool = False
    upstreams: tuple[Upstream, ...] = ()


def parse_broker_config(raw: dict | None) -> BrokerConfig:
    if not raw:
        return BrokerConfig()
    upstreams: list[Upstream] = []
    for entry in raw.get("upstreams") or []:
        host = entry.get("host")
        credential_ref = entry.get("credential_ref")
        if not host or not credential_ref:
            continue
        upstreams.append(
            Upstream(
                host=host,
                credential_ref=credential_ref,
                header=entry.get("header") or "Authorization",
                scheme=entry.get("scheme", "Bearer") or "",
            )
        )
    return BrokerConfig(enabled=bool(raw.get("enabled", False)), upstreams=tuple(upstreams))


class CredentialBroker:
    def __init__(self, config: BrokerConfig, secret_store: dict[str, str]) -> None:
        self._config = config
        # Real secrets live only inside the broker and are never returned in cleartext
        # except when injected onto a request bound for an allowlisted upstream host.
        self._secret_store = dict(secret_store)
        self._by_host = {upstream.host: upstream for upstream in config.upstreams}

    def strip_agent_credentials(self, headers: dict[str, str]) -> dict[str, str]:
        return {key: value for key, value in headers.items() if key.lower() not in AGENT_AUTH_HEADERS}

    def is_upstream(self, request_host: str) -> bool:
        return self._config.enabled and request_host in self._by_host

    def inject_headers(self, request_host: str, headers: dict[str, str]) -> dict[str, str]:
        stripped = self.strip_agent_credentials(headers)
        if not self.is_upstream(request_host):
            return stripped
        upstream = self._by_host[request_host]
        secret = self._secret_store.get(upstream.credential_ref)
        if secret is None:
            return stripped
        stripped[upstream.header] = f"{upstream.scheme} {secret}".strip()
        return stripped

    def redact(self, text: str) -> str:
        redacted = text
        # Longest-first so a secret that is a substring of another is fully masked.
        for secret in sorted(self._secret_store.values(), key=len, reverse=True):
            if secret:
                redacted = redacted.replace(secret, REDACTION_PLACEHOLDER)
        return redacted
