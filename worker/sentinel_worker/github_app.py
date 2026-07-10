from __future__ import annotations

import hashlib
import hmac
import os
import time

import httpx
import structlog
from jose import jwt as jose_jwt

log = structlog.get_logger(__name__)

GITHUB_API = "https://api.github.com"


class GitHubAppNotConfiguredError(RuntimeError):
    """Raised when a required GitHub App env var is missing."""


def webhook_secret() -> str:
    secret = os.environ.get("GITHUB_APP_WEBHOOK_SECRET")
    if not secret:
        raise GitHubAppNotConfiguredError("GITHUB_APP_WEBHOOK_SECRET is not set")
    return secret


def verify_webhook_signature(secret: str, signature_header: str | None, body: bytes) -> bool:
    if not signature_header:
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature_header, expected)


def _app_jwt() -> str:
    app_id = os.environ.get("GITHUB_APP_ID")
    private_key = os.environ.get("GITHUB_APP_PRIVATE_KEY")
    if not app_id or not private_key:
        raise GitHubAppNotConfiguredError("GITHUB_APP_ID / GITHUB_APP_PRIVATE_KEY are not set")
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 600, "iss": app_id}
    return jose_jwt.encode(payload, private_key, algorithm="RS256")


async def get_installation_token(installation_id: int) -> str:
    """Exchange an installation ID for a short-lived token using a JWT signed with the App's private key."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{GITHUB_API}/app/installations/{installation_id}/access_tokens",
            headers={"Authorization": f"Bearer {_app_jwt()}", "Accept": "application/vnd.github+json"},
        )
        resp.raise_for_status()
        return resp.json()["token"]


async def create_check_run(token: str, repo: str, sha: str) -> int:
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{GITHUB_API}/repos/{repo}/check-runs",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            json={"name": "Sentinel Security Scan", "head_sha": sha, "status": "in_progress"},
        )
        resp.raise_for_status()
        return resp.json()["id"]


async def fetch_pr_diff(token: str, repo: str, pr_number: int) -> str:
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(
            f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3.diff"},
        )
        resp.raise_for_status()
        return resp.text


async def complete_check_run(token: str, repo: str, check_run_id: int, findings: list[dict]) -> None:
    conclusion = "failure" if findings else "success"
    summary = f"{len(findings)} finding(s)" if findings else "No issues found"
    lines = [f"**{f['severity'].upper()}** {f['vuln_type']}: {f['title']}" for f in findings]
    # GitHub caps check-run output.text at 65535 characters.
    text = "\n".join(lines)[:65000]
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.patch(
            f"{GITHUB_API}/repos/{repo}/check-runs/{check_run_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            json={
                "status": "completed",
                "conclusion": conclusion,
                "output": {"title": "Sentinel Security Scan", "summary": summary, "text": text},
            },
        )
        resp.raise_for_status()
