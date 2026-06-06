from __future__ import annotations

import hashlib
import re

AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
HIGH_ENTROPY_RE = re.compile(r"\b[A-Za-z0-9_/\-+=]{32,}\b")

SAFE_SECRET_EXAMPLES = {"AKIAIOSFODNN7EXAMPLE"}


def compute_fingerprint(repo_id: str, file_path: str, vuln_type: str) -> str:
    return hashlib.sha256(f"{repo_id}:{file_path}:{vuln_type}".encode()).hexdigest()


def scrub_secrets(text: str) -> str:
    scrubbed = AWS_ACCESS_KEY_RE.sub("[REDACTED:aws_access_key_id]", text)
    return HIGH_ENTROPY_RE.sub(lambda match: "[REDACTED:high_entropy]" if not match.group(0).startswith("[REDACTED:") else match.group(0), scrubbed)


def find_secret_candidates(text: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for value in AWS_ACCESS_KEY_RE.findall(text):
        if value not in SAFE_SECRET_EXAMPLES:
            findings.append(("aws_access_key_id", value))
    for value in HIGH_ENTROPY_RE.findall(text):
        if value not in SAFE_SECRET_EXAMPLES and not AWS_ACCESS_KEY_RE.fullmatch(value):
            findings.append(("high_entropy", value))
    return findings
