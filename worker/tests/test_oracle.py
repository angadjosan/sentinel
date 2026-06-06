from sentinel_worker.oracle import ConfirmationOracle


def test_oracle_confirms_sanitizer_crash_and_scrubs_evidence():
    result = ConfirmationOracle().evaluate("==1==ERROR: AddressSanitizer: heap-buffer-overflow AKIA1234567890ABCDEF")
    assert result.confirmed is True
    assert result.kind == "memory_safety"
    assert "AKIA1234567890ABCDEF" not in (result.evidence or "")


def test_oracle_rejects_agent_judgment_without_proof():
    result = ConfirmationOracle().evaluate("", "agent_says_confirmed", "looks bad")
    assert result.confirmed is False
    assert result.evidence is None
