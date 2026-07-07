from __future__ import annotations

import hashlib
import re

AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
HIGH_ENTROPY_RE = re.compile(r"\b[A-Za-z0-9_/\-+=]{32,}\b")
HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
UUID_RE = re.compile(r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$")
ENV_FILE_RE = re.compile(r"(^|/)\.env(\..+)?$", re.IGNORECASE)

SAFE_SECRET_EXAMPLES = {"AKIAIOSFODNN7EXAMPLE"}


def is_env_var_file(path: str) -> bool:
    """True for .env-style files (.env, .env.local, .env.example, nested), which the SAST LLM must never see."""
    return bool(ENV_FILE_RE.search(path))


def compute_fingerprint(repo_id: str, file_path: str, vuln_type: str) -> str:
    return hashlib.sha256(f"{repo_id}:{file_path}:{vuln_type}".encode()).hexdigest()


def scrub_secrets(text: str) -> str:
    scrubbed = AWS_ACCESS_KEY_RE.sub("[REDACTED:aws_access_key_id]", text)
    return HIGH_ENTROPY_RE.sub(lambda match: "[REDACTED:high_entropy]" if _should_scrub_high_entropy(match.group(0)) else match.group(0), scrubbed)


def find_secret_candidates(text: str) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    for value in AWS_ACCESS_KEY_RE.findall(text):
        if value not in SAFE_SECRET_EXAMPLES:
            findings.append(("aws_access_key_id", value))
    for value in HIGH_ENTROPY_RE.findall(text):
        if value not in SAFE_SECRET_EXAMPLES and not AWS_ACCESS_KEY_RE.fullmatch(value) and _looks_like_secret(value):
            findings.append(("high_entropy", value))
    return findings


def _looks_like_secret(value: str) -> bool:
    if UUID_RE.fullmatch(value):
        return False
    if HEX_RE.fullmatch(value):
        return False
    classes = [
        any(char.islower() for char in value),
        any(char.isupper() for char in value),
        any(char.isdigit() for char in value),
        any(char in "_/-+=" for char in value),
    ]
    return sum(classes) >= 3


def _should_scrub_high_entropy(value: str) -> bool:
    return not value.startswith("[REDACTED:") and value not in SAFE_SECRET_EXAMPLES and not AWS_ACCESS_KEY_RE.fullmatch(value) and _looks_like_secret(value)
