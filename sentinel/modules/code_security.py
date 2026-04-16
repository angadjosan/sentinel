"""Main code security scanner module for Sentinel."""
from __future__ import annotations

import logging
from typing import Optional

from sentinel.github_helper import (
    clone_repo,
    extract_repo_files,
    get_pr_diff,
    get_recent_diff,
    normalize_repo_url,
)
from sentinel.llm import review_code_security
from sentinel.models import CodeSecurityFinding

logger = logging.getLogger(__name__)

# Severity ordering for sorting findings (lower index = higher priority)
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sort_findings(findings: list[CodeSecurityFinding]) -> list[CodeSecurityFinding]:
    """Sort findings by severity: critical first, info last."""
    return sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(f.severity, 99),
    )


async def run_code_security_scan(
    repo: str,
    repo_path: str,
    api_key: str,
    pr_number: Optional[int] = None,
    token: Optional[str] = None,
    model: str = "claude-sonnet-4-6",
) -> list[CodeSecurityFinding]:
    """
    Run an LLM-based code security scan on a repository.

    Steps:
    1. Obtain a diff:
       - If pr_number is given, fetch the PR diff from the GitHub API.
       - Otherwise, get the recent diff (last 3 commits) from the local clone.
       - If neither yields content (e.g. a new/empty repo), extract key source
         files and review those instead.
    2. Extract context files (auth, middleware, route definitions) from the
       local clone to help the LLM understand the security boundaries.
    3. Send diff (or files) + context to review_code_security().
    4. Return findings sorted by severity (critical first).

    Args:
        repo:       Repository identifier — URL or "owner/repo" shorthand.
        repo_path:  Local path to the already-cloned repository.
        api_key:    Anthropic API key.
        pr_number:  If set, fetch and review the specified pull request diff.
        token:      Optional GitHub personal access token for private repos / higher rate limits.
        model:      Claude model ID to use.

    Returns:
        List of CodeSecurityFinding, sorted critical → info.
    """
    repo_url = normalize_repo_url(repo)

    # ------------------------------------------------------------------ #
    # Step 1: Obtain a diff (or fall back to key source files)
    # ------------------------------------------------------------------ #
    diff: str = ""

    if pr_number is not None:
        logger.info("Fetching PR #%d diff for %s", pr_number, repo_url)
        try:
            diff = get_pr_diff(repo_url, pr_number, token=token)
        except Exception as exc:
            logger.warning(
                "Failed to fetch PR #%d diff (%s); falling back to recent diff",
                pr_number, exc,
            )

    if not diff:
        logger.info("Getting recent diff from local clone at %s", repo_path)
        diff = get_recent_diff(repo_path, n_commits=3)

    # If still no diff, fall back to reviewing key source files directly
    use_files_fallback = not diff.strip()
    if use_files_fallback:
        logger.info(
            "No diff available for %s; falling back to key file extraction",
            repo_url,
        )

    # ------------------------------------------------------------------ #
    # Step 2: Extract context files
    # ------------------------------------------------------------------ #
    logger.debug("Extracting context files from %s", repo_path)
    context_files = extract_repo_files(
        repo_path,
        extensions=[".py", ".js", ".ts", ".go"],
        max_files=20,
        max_lines_per_file=200,
    )

    # ------------------------------------------------------------------ #
    # Step 3: Build the content to review and call the LLM
    # ------------------------------------------------------------------ #
    if use_files_fallback:
        # Format extracted files as pseudo-diff for the LLM
        if not context_files:
            logger.warning(
                "No source files found in %s — nothing to review", repo_path
            )
            return []

        file_blocks = []
        for rel_path, content in context_files.items():
            file_blocks.append(f"### {rel_path}\n```\n{content}\n```")

        review_content = (
            "# Repository source files (no diff available — new or empty repo)\n\n"
            + "\n\n".join(file_blocks)
        )
        # When we're already sending files as the main content, pass an empty
        # context_files dict to avoid duplicating everything.
        llm_context: dict[str, str] = {}
    else:
        review_content = diff
        llm_context = context_files

    logger.info(
        "Sending %d chars to LLM for security review (model=%s)",
        len(review_content), model,
    )

    findings = await review_code_security(
        diff_or_files=review_content,
        context_files=llm_context,
        api_key=api_key,
        model=model,
    )

    # ------------------------------------------------------------------ #
    # Step 4: Sort and return
    # ------------------------------------------------------------------ #
    sorted_findings = _sort_findings(findings)

    logger.info(
        "Code security scan complete: %d finding(s) for %s",
        len(sorted_findings), repo_url,
    )
    return sorted_findings
