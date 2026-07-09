"""Oracle hardening tests (AUDIT.md §6 W1 P0.4, §1 invariant 5).

The confirmation oracle must never confirm a finding on the pentest agent's
self-assertion alone. Behavioral confirmation requires external proof — either
sanitizer output or an HTTP response captured from the target.
"""
from sentinel_worker.oracle import ConfirmationOracle


def test_sanitizer_output_confirms():
    result = ConfirmationOracle().evaluate(sanitizer_output="ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...")
    assert result.confirmed is True
    assert result.kind == "memory_safety"
    assert "heap buffer overflow" in (result.evidence or "").lower()


def test_agent_only_behavioral_proof_is_rejected():
    """Agent claims `auth_bypassed` with only a free-text detail — no external
    evidence. The oracle must NOT confirm (AUDIT.md §1 invariant 5)."""
    result = ConfirmationOracle().evaluate(
        sanitizer_output="",
        behavioral_proof="auth_bypassed",
        proof_detail="the agent is confident the auth was bypassed",
    )
    assert result.confirmed is False
    assert result.kind is None
    assert result.evidence is None


def test_behavioral_proof_confirms_with_http_evidence():
    result = ConfirmationOracle().evaluate(
        sanitizer_output="",
        behavioral_proof="data_exfiltrated",
        proof_detail="SQLi",
        http_evidence="payload=\"' OR '1'='1\" status=500 matched marker 'sql syntax'",
    )
    assert result.confirmed is True
    assert result.kind == "behavioral"
    assert "data_exfiltrated" in (result.evidence or "")


def test_behavioral_proof_confirms_with_sanitizer_backing():
    result = ConfirmationOracle().evaluate(
        sanitizer_output="ThreadSanitizer: data race detected",
        behavioral_proof="command_executed",
        proof_detail="cmdi",
    )
    # Sanitizer pattern short-circuits to memory_safety before behavioral check.
    assert result.confirmed is True


def test_unknown_behavioral_proof_kind_rejected_even_with_evidence():
    result = ConfirmationOracle().evaluate(
        sanitizer_output="",
        behavioral_proof="totally_made_up_kind",
        proof_detail="x",
        http_evidence="some http body",
    )
    assert result.confirmed is False


def test_empty_inputs_do_not_confirm():
    result = ConfirmationOracle().evaluate()
    assert result.confirmed is False
