"""Sentinel CLI entrypoint."""
from __future__ import annotations

import asyncio
import logging
import sys
from typing import Optional

import click

from sentinel.config import SentinelConfigError, load_config
from sentinel.display import (
    print_banner,
    print_code_security_findings_table,
    print_dep_findings_table,
    print_summary,
)
from sentinel.models import UnifiedReport
from sentinel.report import write_report
from sentinel.scan import run_scan

# Map severity label → numeric threshold for exit-code logic
_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "never": -1,
}


def _should_fail(report: UnifiedReport, fail_on: str) -> bool:
    """Return True if the report contains findings at or above *fail_on* severity."""
    if fail_on == "never":
        return False
    threshold = _SEVERITY_RANK.get(fail_on, 3)
    all_severities = (
        [f.severity for f in report.dep_findings]
        + [f.severity for f in report.code_security_findings]
        + [f.severity for f in report.attack_surface_findings]
    )
    for sev in all_severities:
        if _SEVERITY_RANK.get(sev, 0) >= threshold:
            return True
    return False


@click.group()
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
def cli(debug: bool) -> None:
    """Sentinel — security scanning for your repositories."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        format="%(levelname)s  %(name)s  %(message)s",
        level=level,
    )


@cli.command()
@click.option("--repo", required=True, help="GitHub repo URL or owner/repo slug.")
@click.option(
    "--module",
    "module",
    multiple=True,
    default=["deps", "code"],
    show_default=True,
    help="Modules to run. Repeat to enable multiple (deps, code, surface).",
)
@click.option("--output", "output", default=None, help="Output directory for report files.")
@click.option("--quiet", is_flag=True, default=False, help="Suppress Rich output (CI mode).")
@click.option(
    "--fail-on",
    "fail_on",
    default="high",
    show_default=True,
    type=click.Choice(["critical", "high", "medium", "low", "never"]),
    help="Exit with code 1 if any finding meets this severity threshold.",
)
@click.option("--pr", "pr", default=None, type=int, help="Pull-request number to review.")
def scan(
    repo: str,
    module: tuple[str, ...],
    output: Optional[str],
    quiet: bool,
    fail_on: str,
    pr: Optional[int],
) -> None:
    """Run a security scan against a GitHub repository."""
    # 1. Load config, override with CLI flags
    try:
        config = load_config(
            output_dir=output,
            fail_on=fail_on,
        )
    except SentinelConfigError as exc:
        click.echo(f"Configuration error: {exc}", err=True)
        sys.exit(2)

    # Override output_dir / fail_on from CLI even if load_config already set them
    if output:
        config.output_dir = output  # type: ignore[assignment]
    if fail_on:
        config.fail_on = fail_on  # type: ignore[assignment]

    # 2. Print banner
    if not quiet:
        print_banner()

    # 3. Run the scan
    modules_list = list(module) if module else ["deps", "code"]
    try:
        report: UnifiedReport = asyncio.run(
            run_scan(
                repo=repo,
                modules=modules_list,
                config=config,
                quiet=quiet,
                pr_number=pr,
            )
        )
    except SentinelConfigError as exc:
        click.echo(f"Configuration error: {exc}", err=True)
        sys.exit(2)
    except Exception as exc:
        click.echo(f"Scan failed: {exc}", err=True)
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            raise
        sys.exit(2)

    # 4. Write report
    report_path = write_report(report, config.output_dir)

    # 5. Print findings + summary
    if not quiet:
        if report.dep_findings:
            print_dep_findings_table(report.dep_findings)
        if report.code_security_findings:
            print_code_security_findings_table(report.code_security_findings)
        print_summary(report)
        click.echo(f"\nReport written to: {report_path}")

    # 6. Exit 1 if findings breach threshold
    if _should_fail(report, config.fail_on):
        sys.exit(1)


@cli.command("show")
@click.argument("path", default="./sentinel-report/findings.json")
def show(path: str) -> None:
    """Display a previously written findings.json report."""
    from sentinel.report import load_report

    try:
        report = load_report(path)
    except FileNotFoundError:
        click.echo(f"Report not found: {path}", err=True)
        sys.exit(2)
    except Exception as exc:
        click.echo(f"Failed to load report: {exc}", err=True)
        sys.exit(2)

    print_banner()
    if report.dep_findings:
        print_dep_findings_table(report.dep_findings)
    if report.code_security_findings:
        print_code_security_findings_table(report.code_security_findings)
    print_summary(report)
