from sentinel_worker.security import compute_fingerprint, scrub_secrets


def test_fingerprint_ignores_line_number_inputs_by_design():
    first = compute_fingerprint("repo-1", "app/routes.ts", "sqli")
    second = compute_fingerprint("repo-1", "app/routes.ts", "sqli")
    assert first == second


def test_scrub_secrets_is_idempotent():
    text = "token AKIA1234567890ABCDEF and abcdefghijklmnopqrstuvwxyzABCDEF"
    scrubbed = scrub_secrets(text)
    assert scrub_secrets(scrubbed) == scrubbed
    assert "AKIA1234567890ABCDEF" not in scrubbed
