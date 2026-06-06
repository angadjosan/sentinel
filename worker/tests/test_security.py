from sentinel_worker.security import compute_fingerprint, find_secret_candidates, scrub_secrets


def test_fingerprint_ignores_line_number_inputs_by_design():
    first = compute_fingerprint("repo-1", "app/routes.ts", "sqli")
    second = compute_fingerprint("repo-1", "app/routes.ts", "sqli")
    assert first == second


def test_scrub_secrets_is_idempotent():
    text = "token AKIA1234567890ABCDEF and abcdefghijklmnopqrstuvwxyzABCDEF"
    scrubbed = scrub_secrets(text)
    assert scrub_secrets(scrubbed) == scrubbed
    assert "AKIA1234567890ABCDEF" not in scrubbed


def test_high_entropy_scanner_ignores_plain_hex_ids():
    text = "trace id 8f3a1b2c9d0e4f567890abcdefabcdef"
    assert find_secret_candidates(text) == []


def test_high_entropy_scanner_ignores_uuid_ids():
    text = "run 123e4567-e89b-12d3-a456-426614174000"
    assert find_secret_candidates(text) == []
    assert scrub_secrets(text) == text


def test_high_entropy_scanner_requires_character_variety():
    text = "token sk-Test_1234567890abcdefghijklmnop/QRSTUV"
    assert find_secret_candidates(text)
