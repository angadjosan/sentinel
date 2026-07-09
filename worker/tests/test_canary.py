from __future__ import annotations

from sentinel_worker.canary import (
    CanaryConfig,
    CanaryToken,
    CanarytokensProvider,
    DeterministicCanaryProvider,
    detect_canaries,
    mint_canaries,
    parse_canary_config,
    seed_env,
)
from sentinel_worker.security import AWS_ACCESS_KEY_RE


def test_deterministic_provider_reproducible_distinct_high_entropy():
    provider_a = DeterministicCanaryProvider(seed="s3cr3t-seed")
    provider_b = DeterministicCanaryProvider(seed="s3cr3t-seed")

    values = [provider_a.mint("generic", i).value for i in range(8)]

    # Reproducible: same seed + index -> identical value.
    for i in range(8):
        assert provider_b.mint("generic", i).value == values[i]

    # Distinct across indices.
    assert len(set(values)) == len(values)

    # High entropy: 40 hex chars.
    for value in values:
        assert len(value) == 40
        assert all(char in "0123456789abcdef" for char in value)


def test_aws_key_kind_matches_aws_access_key_shape():
    provider = DeterministicCanaryProvider(seed="seed")
    for index in range(5):
        token = provider.mint("aws_key", index)
        assert token.kind == "aws_key"
        assert len(token.value) == 20
        assert token.value.startswith("AKIA")
        assert AWS_ACCESS_KEY_RE.fullmatch(token.value)
        assert AWS_ACCESS_KEY_RE.search(f"leaked key = {token.value} in logs")


def test_url_kind_shape():
    provider = DeterministicCanaryProvider(seed="seed")
    token = provider.mint("url", 0)
    assert token.value.startswith("https://canary.example/")


def test_seed_env_injects_canaries_under_decoy_names():
    provider = DeterministicCanaryProvider(seed="seed")
    tokens = mint_canaries(CanaryConfig(count=3), provider)

    env = seed_env(tokens, base_env={"PATH": "/usr/bin"})

    # Base env preserved.
    assert env["PATH"] == "/usr/bin"

    # Indexed canary vars present.
    for index, token in enumerate(tokens):
        assert env[f"SENTINEL_CANARY_{index}"] == token.value

    # Realistic decoy names carry canary values.
    canary_values = {token.value for token in tokens}
    assert env["AWS_SECRET_ACCESS_KEY"] in canary_values
    assert env["INTERNAL_API_TOKEN"] in canary_values

    # The AWS decoy uses an aws_key-kind value.
    aws_values = {token.value for token in tokens if token.kind == "aws_key"}
    assert env["AWS_SECRET_ACCESS_KEY"] in aws_values


def test_seed_env_without_base_env():
    provider = DeterministicCanaryProvider(seed="seed")
    tokens = mint_canaries(CanaryConfig(count=2), provider)
    env = seed_env(tokens)
    assert "SENTINEL_CANARY_0" in env


def test_detect_canaries_finds_seeded_value_and_empty_when_absent():
    provider = DeterministicCanaryProvider(seed="seed")
    tokens = mint_canaries(CanaryConfig(count=3), provider)

    leaked = tokens[1].value
    blob = f"agent output ...\nfound credential {leaked} while scanning\n... more text"

    detected = detect_canaries(blob, tokens)
    assert detected == [tokens[1]]

    # No leak -> empty list.
    assert detect_canaries("nothing sensitive here", tokens) == []
    assert detect_canaries("", tokens) == []


def test_detect_canaries_multiple_leaks():
    provider = DeterministicCanaryProvider(seed="seed")
    tokens = mint_canaries(CanaryConfig(count=3), provider)
    blob = f"{tokens[0].value} and also {tokens[2].value}"
    detected = detect_canaries(blob, tokens)
    assert set(detected) == {tokens[0], tokens[2]}


def test_mint_canaries_cycles_kinds():
    provider = DeterministicCanaryProvider(seed="seed")
    tokens = mint_canaries(CanaryConfig(count=4), provider)
    assert [t.kind for t in tokens] == ["generic", "aws_key", "url", "generic"]
    assert [t.id for t in tokens] == [
        "canary-generic-0",
        "canary-aws_key-1",
        "canary-url-2",
        "canary-generic-3",
    ]


def test_parse_canary_config_tolerates_none():
    config = parse_canary_config(None)
    assert config == CanaryConfig()
    assert config.enabled is False
    assert config.provider == "deterministic"
    assert config.count == 3
    assert config.seed_into == ("env",)


def test_parse_canary_config_partial_and_garbage():
    config = parse_canary_config({"enabled": True, "count": "5"})
    assert config.enabled is True
    assert config.count == 5

    # Garbage count falls back to default.
    config = parse_canary_config({"count": "abc"})
    assert config.count == 3

    # String seed_into normalized to tuple.
    config = parse_canary_config({"seed_into": "env"})
    assert config.seed_into == ("env",)

    config = parse_canary_config({"seed_into": ["env", "file"]})
    assert config.seed_into == ("env", "file")

    # Empty dict -> defaults.
    assert parse_canary_config({}) == CanaryConfig()


def test_canarytokens_provider_requires_client():
    provider = CanarytokensProvider(base_url="https://canary.svc", api_token="tok")
    try:
        provider.mint("generic", 0)
        raise AssertionError("expected NotImplementedError")
    except NotImplementedError:
        pass


def test_canarytokens_provider_uses_injected_client():
    class FakeClient:
        def create_token(self, base_url, api_token, kind, index):
            return {"id": f"real-{index}", "value": f"tripwire-{index}"}

    provider = CanarytokensProvider(
        base_url="https://canary.svc", api_token="tok", client=FakeClient()
    )
    token = provider.mint("generic", 7)
    assert token == CanaryToken(id="real-7", value="tripwire-7", kind="generic")
