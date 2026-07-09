from sentinel_worker.credential_broker import (
    REDACTION_PLACEHOLDER,
    BrokerConfig,
    CredentialBroker,
    Upstream,
    parse_broker_config,
)


def _broker() -> CredentialBroker:
    config = BrokerConfig(
        enabled=True,
        upstreams=(
            Upstream(host="api.github.com", credential_ref="gh_token"),
            Upstream(host="api.stripe.com", credential_ref="stripe_key", header="X-Api-Key", scheme=""),
            Upstream(host="api.missing.com", credential_ref="absent_ref"),
        ),
    )
    return CredentialBroker(config, {"gh_token": "ghp_realsecretvalue123", "stripe_key": "sk_live_abc"})


def test_agent_authorization_header_stripped_before_injection():
    broker = _broker()
    headers = broker.inject_headers("api.github.com", {"Authorization": "Bearer agent-smuggled-token", "Accept": "application/json"})
    assert headers["Authorization"] == "Bearer ghp_realsecretvalue123"
    assert "agent-smuggled-token" not in headers["Authorization"]
    assert headers["Accept"] == "application/json"


def test_strip_agent_credentials_case_insensitive():
    broker = _broker()
    stripped = broker.strip_agent_credentials(
        {"authorization": "x", "X-Api-Key": "y", "Proxy-Authorization": "z", "Content-Type": "application/json"}
    )
    assert stripped == {"Content-Type": "application/json"}


def test_credential_injected_only_for_configured_upstream_with_scheme_and_header():
    broker = _broker()
    gh = broker.inject_headers("api.github.com", {})
    assert gh == {"Authorization": "Bearer ghp_realsecretvalue123"}

    stripe = broker.inject_headers("api.stripe.com", {})
    # Empty scheme -> no leading space, custom header name honored.
    assert stripe == {"X-Api-Key": "sk_live_abc"}


def test_unconfigured_host_receives_no_authorization():
    broker = _broker()
    headers = broker.inject_headers("evil.example.com", {"Authorization": "Bearer agent-token", "X-Trace": "1"})
    assert "Authorization" not in headers
    assert headers == {"X-Trace": "1"}
    assert broker.is_upstream("evil.example.com") is False


def test_missing_credential_ref_injects_nothing():
    broker = _broker()
    headers = broker.inject_headers("api.missing.com", {"Authorization": "Bearer agent-token"})
    assert "Authorization" not in headers
    assert headers == {}


def test_redact_masks_real_secret_value():
    broker = _broker()
    text = "trace: sent Authorization Bearer ghp_realsecretvalue123 and key sk_live_abc to upstream"
    redacted = broker.redact(text)
    assert "ghp_realsecretvalue123" not in redacted
    assert "sk_live_abc" not in redacted
    assert redacted.count(REDACTION_PLACEHOLDER) == 2


def test_parse_broker_config_tolerates_none_and_missing_keys():
    assert parse_broker_config(None) == BrokerConfig(enabled=False, upstreams=())
    assert parse_broker_config({}) == BrokerConfig(enabled=False, upstreams=())

    config = parse_broker_config(
        {
            "enabled": True,
            "upstreams": [
                {"host": "api.github.com", "credential_ref": "gh_token"},
                {"host": "api.stripe.com", "credential_ref": "stripe_key", "header": "X-Api-Key", "scheme": "Token"},
                {"host": "no-ref.com"},  # missing credential_ref -> skipped
            ],
        }
    )
    assert config.enabled is True
    assert len(config.upstreams) == 2
    assert config.upstreams[0] == Upstream(host="api.github.com", credential_ref="gh_token")
    assert config.upstreams[1] == Upstream(host="api.stripe.com", credential_ref="stripe_key", header="X-Api-Key", scheme="Token")
