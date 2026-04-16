"""Repo cloning and diff extraction utilities for Sentinel."""
from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Files/dirs to always skip when extracting source files
_SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "vendor",
    "migrations", "tests", "test", "__pycache__", ".venv",
    "venv", "env", ".tox", "coverage", ".pytest_cache",
}

# Security-relevant filename fragments — prioritized when selecting files
_SECURITY_PRIORITY_NAMES = {
    "auth", "middleware", "routes", "api", "handler", "handlers",
    "router", "permission", "permissions", "acl", "token", "jwt",
    "oauth", "session", "secret", "crypto", "hash", "password",
    "login", "logout", "register", "signup", "user", "users",
    "admin", "role", "roles", "guard", "verify", "validate",
}


def normalize_repo_url(repo: str) -> str:
    """
    Accept: 'owner/repo', 'https://github.com/owner/repo', 'git@github.com:owner/repo.git'
    Always return: 'https://github.com/owner/repo'
    """
    repo = repo.strip()

    # Already a clean https URL (with or without trailing .git)
    https_match = re.match(
        r"https?://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$", repo
    )
    if https_match:
        return f"https://github.com/{https_match.group(1)}"

    # SSH format: git@github.com:owner/repo.git
    ssh_match = re.match(r"git@github\.com:([^/]+/[^/]+?)(?:\.git)?$", repo)
    if ssh_match:
        return f"https://github.com/{ssh_match.group(1)}"

    # Bare owner/repo
    bare_match = re.match(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)$", repo)
    if bare_match:
        return f"https://github.com/{bare_match.group(1)}"

    raise ValueError(f"Cannot parse repository identifier: {repo!r}")


def clone_repo(repo_url: str, token: Optional[str] = None) -> str:
    """
    Shallow clone (--depth=1) the repo into a temp directory.
    If token provided, inject into URL: https://<token>@github.com/owner/repo
    Returns local path to cloned repo.
    Raises RuntimeError with clear message on failure.
    """
    url = normalize_repo_url(repo_url)

    if token:
        # Inject token: https://TOKEN@github.com/owner/repo
        url = url.replace("https://", f"https://{token}@", 1)

    tmp_dir = tempfile.mkdtemp(prefix="sentinel_clone_")

    cmd = ["git", "clone", "--depth=1", "--single-branch", url, tmp_dir]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"git clone timed out for {repo_url}") from exc
    except FileNotFoundError as exc:
        raise RuntimeError("git is not installed or not on PATH") from exc

    if result.returncode != 0:
        stderr = result.stderr.strip()
        # Redact token from error message before raising
        if token:
            stderr = stderr.replace(token, "***")
        raise RuntimeError(
            f"git clone failed for {repo_url} (exit {result.returncode}): {stderr}"
        )

    logger.debug("Cloned %s -> %s", repo_url, tmp_dir)
    return tmp_dir


def get_pr_diff(repo_url: str, pr_number: int, token: Optional[str] = None) -> str:
    """
    Fetch PR diff via GitHub API: GET /repos/{owner}/{repo}/pulls/{pr_number}/files
    Returns unified diff string (concatenated patch fields from response).
    Uses httpx (sync). Raises on non-200.
    """
    url = normalize_repo_url(repo_url)

    # Extract owner/repo from normalized URL
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)$", url)
    if not match:
        raise ValueError(f"Cannot extract owner/repo from URL: {url!r}")
    owner, repo = match.group(1), match.group(2)

    api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files"

    headers = {
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    with httpx.Client(timeout=30) as client:
        response = client.get(api_url, headers=headers)

    if response.status_code != 200:
        raise RuntimeError(
            f"GitHub API returned {response.status_code} for PR #{pr_number}: "
            f"{response.text[:500]}"
        )

    files = response.json()
    patches: list[str] = []
    for f in files:
        filename = f.get("filename", "")
        patch = f.get("patch", "")
        if patch:
            patches.append(f"--- a/{filename}\n+++ b/{filename}\n{patch}")

    return "\n".join(patches)


def get_recent_diff(repo_path: str, n_commits: int = 3) -> str:
    """
    Get diff of last n_commits from a local cloned repo.
    Uses: git diff HEAD~{n}..HEAD
    Returns unified diff string. Falls back to full HEAD diff if not enough history.
    """
    def _run_git(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", repo_path, *args],
            capture_output=True,
            text=True,
            timeout=60,
        )

    # Try the requested range first
    result = _run_git("diff", f"HEAD~{n_commits}..HEAD")
    if result.returncode == 0 and result.stdout.strip():
        logger.debug("Got diff HEAD~%d..HEAD from %s", n_commits, repo_path)
        return result.stdout

    # Not enough history — try progressively smaller ranges
    for n in range(n_commits - 1, 0, -1):
        result = _run_git("diff", f"HEAD~{n}..HEAD")
        if result.returncode == 0 and result.stdout.strip():
            logger.debug("Fell back to HEAD~%d..HEAD from %s", n, repo_path)
            return result.stdout

    # Single commit or initial commit — diff against empty tree
    result = _run_git(
        "diff-tree", "--no-commit-id", "-r", "--patch", "HEAD"
    )
    if result.returncode == 0 and result.stdout.strip():
        logger.debug("Used diff-tree HEAD from %s", repo_path)
        return result.stdout

    logger.warning("Could not get any diff from %s", repo_path)
    return ""


def _is_security_relevant(name: str) -> bool:
    """Return True if filename contains a security-priority keyword."""
    name_lower = name.lower()
    return any(kw in name_lower for kw in _SECURITY_PRIORITY_NAMES)


def extract_repo_files(
    repo_path: str,
    extensions: list[str] = [".py", ".js", ".ts", ".go"],
    max_files: int = 20,
    max_lines_per_file: int = 200,
) -> dict[str, str]:
    """
    Extract representative source files for context.
    Skip: node_modules, .git, dist, build, vendor, migrations, tests.
    Return dict of {relative_path: content_truncated_to_max_lines}.
    Prioritize files with security-relevant names: auth, middleware, routes, api, handlers.
    """
    root = Path(repo_path)
    ext_set = {e.lower() for e in extensions}

    priority_files: list[Path] = []
    normal_files: list[Path] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        # Skip any path that contains a skip-dir component
        parts = path.relative_to(root).parts
        if any(part in _SKIP_DIRS for part in parts):
            continue

        # Check extension
        if path.suffix.lower() not in ext_set:
            continue

        if _is_security_relevant(path.stem):
            priority_files.append(path)
        else:
            normal_files.append(path)

    # Sort each group for determinism
    priority_files.sort()
    normal_files.sort()

    # Fill up to max_files, priority first
    selected = (priority_files + normal_files)[:max_files]

    result: dict[str, str] = {}
    for path in selected:
        rel = str(path.relative_to(root))
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError as exc:
            logger.debug("Could not read %s: %s", path, exc)
            continue

        if len(lines) > max_lines_per_file:
            truncated = lines[:max_lines_per_file]
            content = "\n".join(truncated) + f"\n... (truncated, {len(lines)} total lines)"
        else:
            content = "\n".join(lines)

        result[rel] = content

    logger.debug(
        "Extracted %d files (%d priority) from %s",
        len(result), min(len(priority_files), max_files), repo_path,
    )
    return result
