"""Celery task definitions for Sentinel security scans."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from celery import Celery

from sentinel.config import load_config

logger = logging.getLogger(__name__)


def make_celery() -> Celery:
    config = load_config()
    broker = config.redis_url
    app = Celery("sentinel", broker=broker, backend=broker)
    app.conf.task_routes = {
        "sentinel.api.tasks.enqueue_pr_review": {"queue": "high_priority"},
        "sentinel.api.tasks.enqueue_dep_scan": {"queue": "default"},
        "sentinel.api.tasks.enqueue_surface_scan": {"queue": "low_priority"},
        "sentinel.api.tasks.enqueue_baseline_scan": {"queue": "low_priority"},
    }
    return app


celery_app = make_celery()


def _repo_url_from_payload(payload: dict[str, Any]) -> str:
    """Extract repository clone URL from a GitHub webhook payload."""
    repo = payload.get("repository", {})
    # Prefer html_url (https), fall back to clone_url
    return repo.get("html_url") or repo.get("clone_url") or ""


def _installation_id_from_payload(payload: dict[str, Any]) -> int | None:
    """Extract installation ID from a GitHub App webhook payload."""
    installation = payload.get("installation")
    if isinstance(installation, dict):
        return installation.get("id")
    return None


@celery_app.task(
    name="sentinel.api.tasks.enqueue_pr_review",
    bind=True,
    max_retries=3,
)
def enqueue_pr_review(self, payload: dict[str, Any]) -> dict[str, Any]:
    """Run PR security review (code + deps on diff), then post GitHub Check Run."""
    from sentinel.scan import run_scan
    from sentinel.github.auth import get_installation_token
    from sentinel.github.checks import post_check_run, post_pr_comment

    config = load_config()
    repo_url = _repo_url_from_payload(payload)
    installation_id = _installation_id_from_payload(payload)

    pr_data = payload.get("pull_request", {})
    pr_number: int | None = pr_data.get("number") if isinstance(pr_data, dict) else None
    head_sha: str | None = pr_data.get("head", {}).get("sha") if isinstance(pr_data, dict) else None

    # repo slug for Check Run API (owner/repo)
    repo_slug = payload.get("repository", {}).get("full_name", "")

    logger.info("PR review scan: repo=%s pr=%s installation=%s", repo_url, pr_number, installation_id)

    try:
        report = asyncio.run(
            run_scan(
                repo=repo_url,
                modules=["code", "deps"],
                config=config,
                pr_number=pr_number,
            )
        )

        # Post results back to GitHub if we have an installation token
        if installation_id and head_sha and repo_slug:
            async def _post_results() -> None:
                token = await get_installation_token(installation_id)
                await post_check_run(repo_slug, head_sha, report, token)
                if pr_number:
                    await post_pr_comment(repo_slug, pr_number, report, token)

            asyncio.run(_post_results())

    except Exception as exc:
        logger.error("PR review scan failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc, countdown=2 ** self.request.retries * 30)

    findings_count = len(report.dep_findings) + len(report.code_security_findings)
    return {"status": "complete", "findings": findings_count}


@celery_app.task(
    name="sentinel.api.tasks.enqueue_dep_scan",
    bind=True,
    max_retries=3,
)
def enqueue_dep_scan(self, payload: dict[str, Any]) -> dict[str, Any]:
    """Run dependency scan on push."""
    from sentinel.scan import run_scan

    config = load_config()
    repo_url = _repo_url_from_payload(payload)
    installation_id = _installation_id_from_payload(payload)

    logger.info(
        "Dependency scan: repo=%s installation=%s",
        repo_url,
        installation_id,
    )

    try:
        report = asyncio.run(
            run_scan(
                repo=repo_url,
                modules=["deps"],
                config=config,
            )
        )
    except Exception as exc:
        logger.error("Dependency scan failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc, countdown=2 ** self.request.retries * 30)

    return {"status": "complete", "findings": len(report.dep_findings)}


@celery_app.task(
    name="sentinel.api.tasks.enqueue_surface_scan",
    bind=True,
    max_retries=3,
)
def enqueue_surface_scan(self, payload: dict[str, Any]) -> dict[str, Any]:
    """Run attack surface scan."""
    from sentinel.scan import run_scan

    config = load_config()
    repo_url = _repo_url_from_payload(payload)
    installation_id = _installation_id_from_payload(payload)

    logger.info(
        "Surface scan: repo=%s installation=%s",
        repo_url,
        installation_id,
    )

    try:
        report = asyncio.run(
            run_scan(
                repo=repo_url,
                modules=["surface"],
                config=config,
            )
        )
    except Exception as exc:
        logger.error("Surface scan failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc, countdown=2 ** self.request.retries * 30)

    return {"status": "complete", "findings": len(report.attack_surface_findings)}


@celery_app.task(
    name="sentinel.api.tasks.enqueue_baseline_scan",
    bind=True,
    max_retries=3,
)
def enqueue_baseline_scan(self, payload: dict[str, Any]) -> dict[str, Any]:
    """Full baseline scan on new GitHub App install."""
    from sentinel.scan import run_scan

    config = load_config()
    installation_id = _installation_id_from_payload(payload)

    # For installation events the repository list may be in "repositories" or
    # "repositories_added"; fall back to the single "repository" key.
    repositories: list[dict[str, Any]] = (
        payload.get("repositories")
        or payload.get("repositories_added")
        or []
    )
    if not repositories:
        single = payload.get("repository")
        if single:
            repositories = [single]

    logger.info(
        "Baseline scan: installation=%s repos=%d",
        installation_id,
        len(repositories),
    )

    total_findings = 0
    errors: list[str] = []

    for repo_info in repositories:
        # GitHub App installation payloads use a trimmed repo object that
        # may only contain id/name/full_name.  Build the html_url if missing.
        repo_url = (
            repo_info.get("html_url")
            or repo_info.get("clone_url")
            or f"https://github.com/{repo_info.get('full_name', '')}"
        )
        if not repo_url.strip("/"):
            logger.warning("Skipping repo with no resolvable URL: %s", repo_info)
            continue

        try:
            report = asyncio.run(
                run_scan(
                    repo=repo_url,
                    modules=["deps", "code", "surface"],
                    config=config,
                )
            )
            total_findings += report.total_findings
        except Exception as exc:
            logger.error(
                "Baseline scan failed for %s: %s", repo_url, exc, exc_info=True
            )
            errors.append(str(exc))

    if errors:
        exc = RuntimeError(f"Baseline scan had {len(errors)} error(s): {errors[0]}")
        raise self.retry(exc=exc, countdown=2 ** self.request.retries * 30)

    return {"status": "complete", "findings": total_findings}
