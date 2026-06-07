"""Tests for ConfirmationOracle matching TECHNICAL_DESIGN.md §23.6."""
from sentinel_worker.oracle import ConfirmationOracle, SANITIZER_PATTERNS, BEHAVIORAL_PROOFS


def test_oracle_confirms_sanitizer_crash_and_scrubs_evidence():
    result = ConfirmationOracle().evaluate("==1==ERROR: AddressSanitizer: heap-buffer-overflow AKIA1234567890ABCDEF")
    assert result.confirmed is True
    assert result.kind == "memory_safety"
    assert "AKIA1234567890ABCDEF" not in (result.evidence or "")


def test_oracle_rejects_agent_judgment_without_proof():
    result = ConfirmationOracle().evaluate("", "agent_says_confirmed", "looks bad")
    assert result.confirmed is False
    assert result.evidence is None


# ---------------------------------------------------------------------------
# G5: Additional oracle tests per §23.6
# ---------------------------------------------------------------------------


def test_all_asan_patterns_confirm_memory_safety():
    """Each ASan pattern → confirmed=True, kind='memory_safety'."""
    asan_patterns = [
        "heap-buffer-overflow",
        "use-after-free",
        "stack-buffer-overflow",
        "global-buffer-overflow",
    ]
    for pattern in asan_patterns:
        output = f"==ERROR: AddressSanitizer: {pattern} on address 0x..."
        result = ConfirmationOracle().evaluate(output)
        assert result.confirmed is True, f"Expected confirmed for ASan pattern: {pattern}"
        assert result.kind == "memory_safety", f"Expected memory_safety kind for: {pattern}"


def test_tsan_data_race_confirms_memory_safety():
    """TSan race → confirmed=True, kind='memory_safety'."""
    output = "WARNING: ThreadSanitizer: data race (pid=1234)"
    result = ConfirmationOracle().evaluate(output)
    assert result.confirmed is True
    assert result.kind == "memory_safety"


def test_ubsan_runtime_error_confirms_memory_safety():
    """UBSan runtime error → confirmed=True, kind='memory_safety'."""
    output = "app.c:10:5: runtime error: signed integer overflow"
    result = ConfirmationOracle().evaluate(output)
    assert result.confirmed is True
    assert result.kind == "memory_safety"


def test_behavioral_proof_data_exfiltrated_confirms():
    """Behavioral proof with data_exfiltrated → confirmed=True."""
    result = ConfirmationOracle().evaluate("", "data_exfiltrated", "sent to attacker.com")
    assert result.confirmed is True
    assert result.kind == "behavioral"


def test_behavioral_proof_auth_bypassed_confirms():
    """Behavioral proof auth_bypassed → confirmed=True."""
    result = ConfirmationOracle().evaluate("", "auth_bypassed", "accessed admin without login")
    assert result.confirmed is True
    assert result.kind == "behavioral"


def test_behavioral_proof_command_executed_confirms():
    """Behavioral proof command_executed → confirmed=True."""
    result = ConfirmationOracle().evaluate("", "command_executed", "ran id; whoami")
    assert result.confirmed is True
    assert result.kind == "behavioral"


def test_behavioral_proof_privilege_escalated_confirms():
    """Behavioral proof privilege_escalated → confirmed=True."""
    result = ConfirmationOracle().evaluate("", "privilege_escalated", "gained root via suid")
    assert result.confirmed is True
    assert result.kind == "behavioral"


def test_unrecognized_behavioral_proof_kind_not_confirmed():
    """Unrecognized behavioral proof kind → confirmed=False."""
    result = ConfirmationOracle().evaluate("", "agent_assertion", "i think it's bad")
    assert result.confirmed is False


def test_no_sanitizer_no_proof_not_confirmed():
    """No sanitizer output + no proof → confirmed=False."""
    result = ConfirmationOracle().evaluate("", None, "")
    assert result.confirmed is False
    assert result.evidence is None


def test_empty_inputs_not_confirmed():
    """Empty sanitizer + empty behavioral → confirmed=False."""
    result = ConfirmationOracle().evaluate()
    assert result.confirmed is False


def test_evidence_scrubs_aws_key_in_asan_output():
    """Evidence passes through scrub_secrets → no raw AWS keys in evidence."""
    secret = "AKIA1234567890ABCDEF"
    output = f"heap-buffer-overflow reading 4 bytes, token={secret}"
    result = ConfirmationOracle().evaluate(output)
    assert result.confirmed is True
    assert secret not in (result.evidence or "")
    assert "[REDACTED" in (result.evidence or "")


def test_evidence_scrubs_secrets_in_behavioral_proof():
    """Evidence from behavioral proof also passes through scrub_secrets."""
    secret = "AKIA1234567890ABCDEF"
    result = ConfirmationOracle().evaluate("", "data_exfiltrated", f"sent token {secret} to evil.com")
    assert result.confirmed is True
    assert secret not in (result.evidence or "")


def test_sanitizer_patterns_dict_has_expected_keys():
    """Verify SANITIZER_PATTERNS includes both ASan and TSan patterns."""
    assert any("heap-buffer-overflow" in k for k in SANITIZER_PATTERNS)
    assert any("ThreadSanitizer" in k for k in SANITIZER_PATTERNS)
    assert any("runtime error" in k for k in SANITIZER_PATTERNS)


def test_behavioral_proofs_set_has_expected_members():
    """BEHAVIORAL_PROOFS set matches §23.6 spec."""
    assert "data_exfiltrated" in BEHAVIORAL_PROOFS
    assert "auth_bypassed" in BEHAVIORAL_PROOFS
    assert "command_executed" in BEHAVIORAL_PROOFS
    assert "privilege_escalated" in BEHAVIORAL_PROOFS
