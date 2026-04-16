"""GitHub webhook handler for Sentinel."""
from __future__ import annotations

import fnmatch
import hashlib
import hmac
import logging
import os
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request, status

from sentinel.api.tasks import (
    enqueue_baseline_scan,
    enqueue_dep_scan,
    enqueue_pr_review,
    enqueue_surface_scan,
)

logger = logging.getLogger(__name__)

router = APIRouter()

DEP_FILE_PATTERNS = {
    "requirements.txt",
    "requirements*.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "setup.py",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.toml",
    "go.mod",
    "go.sum",
}


def _verify_signature(body: bytes, signature_header: str | None, secret: str) -> bool:
    """Verify X-Hub-Signature-256 HMAC header against request body."""
    if not signature_header:
        return False
    if not signature_header.startswith("sha256="):
        return False
    expected_sig = signature_header[len("sha256="):]
    mac = hmac.new(secret.encode(), body, hashlib.sha256)
    computed = mac.hexdigest()
    return hmac.compare_digest(computed, expected_sig)


def targets_default_branch(payload: dict[str, Any]) -> bool:
    """Return True if the push targets the repository's default branch."""
    ref = payload.get("ref", "")
    default_branch = payload.get("repository", {}).get("default_branch", "")
    return ref == f"refs/heads/{default_branch}"


def dep_files_changed(payload: dict[str, Any]) -> bool:
    """Return True if any commit in the push modified a dependency file."""
    commits = payload.get("commits", [])
    for commit in commits:
        changed_files = (
            commit.get("added", [])
            + commit.get("modified", [])
        )
        for filepath in changed_files:
            # Use just the basename for matching
            filename = filepath.split("/")[-1]
            for pattern in DEP_FILE_PATTERNS:
                if fnmatch.fnmatch(filename, pattern):
                    return True
    return False


@router.post("/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
) -> dict[str, str]:
    """Receive GitHub App webhook events and enqueue Celery tasks."""
    body = await request.body()

    # Validate HMAC signature
    webhook_secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    if not webhook_secret:
        # Also try loading from config
        try:
            from sentinel.config import load_config
            config = load_config()
            webhook_secret = config.github_webhook_secret or ""
        except Exception:
            pass

    if not webhook_secret:
        logger.error("GITHUB_WEBHOOK_SECRET is not configured")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Webhook secret not configured",
        )

    if not _verify_signature(body, x_hub_signature_256, webhook_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Hub-Signature-256",
        )

    # Parse JSON body
    try:
        payload: dict[str, Any] = await request.json()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON body: {exc}",
        )

    event_type = x_github_event or "unknown"
    logger.info("Received GitHub event: %s", event_type)

    # Route to appropriate Celery task
    match event_type:
        case "installation" | "installation_repositories":
            enqueue_baseline_scan.delay(payload)
        case "push":
            if targets_default_branch(payload):
                enqueue_surface_scan.delay(payload)
            if dep_files_changed(payload):
                enqueue_dep_scan.delay(payload)
        case "pull_request":
            if payload.get("action") in ("opened", "synchronize"):
                enqueue_pr_review.delay(payload)
        case _:
            pass  # ignore unknown events

    return {"status": "accepted"}
