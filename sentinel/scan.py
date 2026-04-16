"""Scan orchestrator — runs enabled modules and returns a UnifiedReport."""
from __future__ import annotations

import logging
from typing import Optional

from sentinel.config import SentinelConfig
from sentinel.models import UnifiedReport

logger = logging.getLogger(__name__)

# Default modules when caller doesn't specify
_DEFAULT_MODULES = ["deps", "code"]


async def run_scan(
    repo: str,
    modules: list[str] | None = None,
    config: SentinelConfig | None = None,
    quiet: bool = False,
    pr_number: Optional[int] = None,
) -> UnifiedReport:
    """
    Orchestrate all enabled modules. Returns a UnifiedReport.

    Imports scanner modules lazily so that missing optional dependencies don't
    crash the whole CLI.  Per-module exceptions are caught, logged, and the scan
    continues with partial results.
    """
    if modules is None:
        modules = list(_DEFAULT_MODULES)
    if config is None:
        from sentinel.config import load_config
        config = load_config()

    report = UnifiedReport(repo=repo)

    if "deps" in modules:
        try:
            from sentinel.modules.deps import run_dep_scan  # type: ignore[import]
            if not quiet:
                logger.info("Running dependency scan...")
            dep_findings = await run_dep_scan(repo=repo, config=config)
            report.dep_findings.extend(dep_findings)
        except ImportError:
            logger.warning(
                "sentinel.modules.deps is not available — skipping dependency scan. "
                "Install optional dependencies to enable it."
            )
        except Exception as exc:
            logger.error("Dependency scan failed: %s", exc, exc_info=True)

    if "code" in modules:
        try:
            from sentinel.modules.code_security import run_code_security_scan  # type: ignore[import]
            if not quiet:
                logger.info("Running code security scan...")
            # Ensure we have an Anthropic key before attempting the scan
            config.require_anthropic_key()
            code_findings = await run_code_security_scan(
                repo=repo,
                config=config,
                pr_number=pr_number,
            )
            report.code_security_findings.extend(code_findings)
        except ImportError:
            logger.warning(
                "sentinel.modules.code_security is not available — skipping code security scan. "
                "Install optional dependencies to enable it."
            )
        except Exception as exc:
            logger.error("Code security scan failed: %s", exc, exc_info=True)

    if "surface" in modules:
        try:
            from sentinel.modules.surface import run_surface_scan  # type: ignore[import]
            if not quiet:
                logger.info("Running attack surface scan...")
            surface_findings = await run_surface_scan(repo=repo, config=config)
            report.attack_surface_findings.extend(surface_findings)
        except ImportError:
            logger.warning(
                "sentinel.modules.surface is not available — skipping attack surface scan. "
                "Install optional dependencies to enable it."
            )
        except Exception as exc:
            logger.error("Attack surface scan failed: %s", exc, exc_info=True)

    unknown = set(modules) - {"deps", "code", "surface"}
    for mod in unknown:
        logger.warning("Unknown module %r — skipping.", mod)

    return report
