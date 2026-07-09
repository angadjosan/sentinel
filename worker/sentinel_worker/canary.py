from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Protocol

import structlog

logger = structlog.get_logger(__name__)

_KINDS = ("generic", "aws_key", "url")
_KIND_CYCLE = ("generic", "aws_key", "url")


@dataclass(frozen=True)
class CanaryToken:
    id: str
    value: str
    kind: str


@dataclass(frozen=True)
class CanaryConfig:
    enabled: bool = False
    provider: str = "deterministic"
    count: int = 3
    seed_into: tuple[str, ...] = ("env",)


def parse_canary_config(raw: dict | None) -> CanaryConfig:
    """Tolerant parser: accepts None, missing keys, or partial dicts and fills defaults."""
    if not raw:
        return CanaryConfig()

    defaults = CanaryConfig()

    enabled = bool(raw.get("enabled", defaults.enabled))

    provider = raw.get("provider", defaults.provider)
    if not isinstance(provider, str) or not provider:
        provider = defaults.provider

    try:
        count = int(raw.get("count", defaults.count))
    except (TypeError, ValueError):
        count = defaults.count
    if count < 0:
        count = 0

    raw_seed_into = raw.get("seed_into", defaults.seed_into)
    if isinstance(raw_seed_into, (list, tuple)):
        seed_into = tuple(str(item) for item in raw_seed_into)
    elif isinstance(raw_seed_into, str):
        seed_into = (raw_seed_into,)
    else:
        seed_into = defaults.seed_into

    return CanaryConfig(enabled=enabled, provider=provider, count=count, seed_into=seed_into)


class CanaryProvider(Protocol):
    def mint(self, kind: str, index: int) -> CanaryToken: ...


@dataclass(frozen=True)
class DeterministicCanaryProvider:
    """Offline provider that derives reproducible high-entropy token values from a seed.

    Values are derived via hashlib (never random/uuid) so tests are fully reproducible.
    """

    seed: str

    def _digest(self, kind: str, index: int) -> str:
        return hashlib.sha256(f"{self.seed}:{kind}:{index}".encode()).hexdigest()

    def mint(self, kind: str, index: int) -> CanaryToken:
        digest = self._digest(kind, index)
        token_id = f"canary-{kind}-{index}"

        if kind == "aws_key":
            # AKIA + 16 uppercase alphanumerics -> matches security.AWS_ACCESS_KEY_RE (20 chars).
            suffix = "".join(_to_upper_alnum(char) for char in digest)[:16]
            value = f"AKIA{suffix}"
        elif kind == "url":
            value = f"https://canary.example/{digest[:40]}"
        else:  # generic
            value = digest[:40]

        return CanaryToken(id=token_id, value=value, kind=kind)


def _to_upper_alnum(char: str) -> str:
    """Map a hex char to an uppercase [0-9A-Z] alphanumeric for AWS-key-shaped suffixes."""
    # Hex chars are already in [0-9a-f]; uppercasing keeps them within [0-9A-Z].
    return char.upper()


@dataclass(frozen=True)
class CanarytokensProvider:
    """Skeleton seam for a REAL external canary service (e.g. Canarytokens/Thinkst).

    Inject a sync or async HTTP ``client`` exposing the service API, the service
    ``base_url``, and an ``api_token``. This is intentionally minimal; the
    ``DeterministicCanaryProvider`` is what tests exercise. When a real client is
    wired in, ``mint`` should call the service to provision a live canary token and
    map the response onto :class:`CanaryToken`.
    """

    base_url: str
    api_token: str
    client: Any | None = None

    def mint(self, kind: str, index: int) -> CanaryToken:
        if self.client is None:
            raise NotImplementedError(
                "CanarytokensProvider requires an injected HTTP client to mint real canary tokens"
            )
        # Real seam: the injected client provisions a live canary at self.base_url and
        # returns its identifier + tripwire value, which we map onto CanaryToken.
        response = self.client.create_token(
            base_url=self.base_url,
            api_token=self.api_token,
            kind=kind,
            index=index,
        )
        return CanaryToken(id=str(response["id"]), value=str(response["value"]), kind=kind)


def mint_canaries(config: CanaryConfig, provider: CanaryProvider) -> list[CanaryToken]:
    """Mint ``config.count`` tokens, cycling through kinds generic/aws_key/url."""
    tokens: list[CanaryToken] = []
    for index in range(config.count):
        kind = _KIND_CYCLE[index % len(_KIND_CYCLE)]
        tokens.append(provider.mint(kind, index))
    logger.debug("minted_canaries", count=len(tokens), provider=config.provider)
    return tokens


def seed_env(tokens: list[CanaryToken], base_env: dict[str, str] | None = None) -> dict[str, str]:
    """Return an env dict seeded with canary values under realistic decoy names.

    Each token is exposed as ``SENTINEL_CANARY_<i>`` and, additionally, a couple of
    convincing decoy names (e.g. ``AWS_SECRET_ACCESS_KEY``, ``INTERNAL_API_TOKEN``)
    are set to canary values so they read as genuine secrets to an attacker.
    """
    env: dict[str, str] = dict(base_env or {})

    for index, token in enumerate(tokens):
        env[f"SENTINEL_CANARY_{index}"] = token.value

    if tokens:
        aws_token = next((tok for tok in tokens if tok.kind == "aws_key"), tokens[0])
        env["AWS_SECRET_ACCESS_KEY"] = aws_token.value
        env["INTERNAL_API_TOKEN"] = tokens[0].value

    return env


def detect_canaries(text: str, tokens: list[CanaryToken]) -> list[CanaryToken]:
    """Return tokens whose ``value`` literally appears in ``text`` (a real leak)."""
    if not text:
        return []
    return [token for token in tokens if token.value and token.value in text]
