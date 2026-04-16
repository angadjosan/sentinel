"""Scan orchestrator — clones repo, runs enabled modules, returns UnifiedReport."""
from __future__ import annotations

import logging
import tempfile
import shutil
from typing import Optional

from sentinel.config import SentinelConfig
from sentinel.models import UnifiedReport

logger = logging.getLogger(__name__)

_DEFAULT_MODULES = ["deps", "code"]


async def run_scan(
    repo: str,
    modules: list[str] | None = None,
    config: SentinelConfig | None = None,
    quiet: bool = False,
    pr_number: Optional[int] = None,
) -> UnifiedReport:
    """Clone repo and run all enabled modules. Returns a UnifiedReport."""
    if modules is None:
        modules = list(_DEFAULT_MODULES)
    if config is None:
        from sentinel.config import load_config
        config = load_config()

    from sentinel.github_helper import clone_repo, normalize_repo_url
    repo_url = normalize_repo_url(repo)
    report = UnifiedReport(repo=repo_url)

    repo_path: Optional[str] = None
    try:
        if not quiet:
            logger.info("Cloning %s ...", repo_url)
        repo_path = clone_repo(repo_url, token=config.github_token)

        if "deps" in modules:
            try:
                from sentinel.modules.deps import run_dep_scan
                if not quiet:
                    logger.info("Running dependency scan...")
                dep_findings = await run_dep_scan(repo_path)
                report.dep_findings.extend(dep_findings)
            except ImportError:
                logger.warning("sentinel.modules.deps unavailable — skipping.")
            except Exception as exc:
                logger.error("Dependency scan failed: %s", exc, exc_info=True)

        if "code" in modules:
            try:
                from sentinel.modules.code_security import run_code_security_scan
                config.require_anthropic_key()
                if not quiet:
                    logger.info("Running code security scan...")
                code_findings = await run_code_security_scan(
                    repo=repo_url,
                    repo_path=repo_path,
                    api_key=config.anthropic_api_key,  # type: ignore[arg-type]
                    pr_number=pr_number,
                    token=config.github_token,
                )
                report.code_security_findings.extend(code_findings)
            except ImportError:
                logger.warning("sentinel.modules.code_security unavailable — skipping.")
            except Exception as exc:
                logger.error("Code security scan failed: %s", exc, exc_info=True)

        if "surface" in modules:
            try:
                from sentinel.modules.surface import run_surface_scan
                if not quiet:
                    logger.info("Running attack surface scan...")
                surface_findings = await run_surface_scan(repo_path=repo_path)
                report.attack_surface_findings.extend(surface_findings)
            except ImportError:
                logger.warning("sentinel.modules.surface unavailable — skipping.")
            except Exception as exc:
                logger.error("Attack surface scan failed: %s", exc, exc_info=True)

        unknown = set(modules) - {"deps", "code", "surface"}
        for mod in unknown:
            logger.warning("Unknown module %r — skipping.", mod)

    finally:
        if repo_path:
            shutil.rmtree(repo_path, ignore_errors=True)

    return report
