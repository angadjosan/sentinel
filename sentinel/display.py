"""Rich terminal output helpers for Sentinel."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Generator

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from sentinel.models import CodeSecurityFinding, DepFinding, UnifiedReport

console = Console(stderr=False)

_VERSION = "0.1.0"

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "red",
    "high": "orange1",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}

_BANNER = r"""
   ___           _   _             _
  / __| ___ _ _ | |_(_)_ _   ___| |
  \__ \/ -_) ' \|  _| | ' \ / -_) |
  |___/\___|_||_|\__|_|_||_|\___|_|
"""


def print_banner() -> None:
    """Print Sentinel ASCII banner with version."""
    banner_text = Text(_BANNER, style="bold cyan")
    version_line = Text(f"  Security Scanner  v{_VERSION}", style="dim")
    console.print(banner_text, end="")
    console.print(version_line)
    console.print()


def print_stage_start(stage: str) -> None:
    """Print a stage start line with a spinner."""
    console.print(f":mag: Scanning: [bold]{stage}[/bold]...")


@contextmanager
def stage_spinner(stage: str) -> Generator[None, None, None]:
    """Context manager that shows a spinner while the body executes."""
    with console.status(f":mag: Scanning: [bold]{stage}[/bold]...", spinner="dots"):
        yield


class SentinelProgress:
    """Context manager wrapping rich.progress.Progress for multi-stage scans."""

    def __init__(self) -> None:
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
        )

    def __enter__(self) -> "SentinelProgress":
        self._progress.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._progress.stop()

    def start_stage(self, name: str, total: int) -> TaskID:
        """Add a new stage task and return its TaskID."""
        return self._progress.add_task(f"[cyan]{name}[/cyan]", total=total)

    def advance(self, task_id: TaskID, amount: int = 1) -> None:
        """Advance a task by *amount* steps."""
        self._progress.advance(task_id, amount)

    def complete_stage(self, task_id: TaskID, msg: str) -> None:
        """Mark a stage complete and update its description."""
        self._progress.update(task_id, completed=self._progress.tasks[task_id].total)
        self._progress.update(task_id, description=f"[green]{msg}[/green]")


def _severity_cell(severity: str) -> Text:
    color = _SEVERITY_COLORS.get(severity, "white")
    return Text(severity.upper(), style=f"bold {color}")


def print_dep_findings_table(findings: list[DepFinding]) -> None:
    """Print a Rich table of dependency findings."""
    if not findings:
        console.print("[dim]No dependency findings.[/dim]")
        return

    table = Table(
        title="Dependency Vulnerabilities",
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
    )
    table.add_column("Package", style="bold")
    table.add_column("Version")
    table.add_column("CVE")
    table.add_column("CVSS", justify="right")
    table.add_column("Severity")
    table.add_column("Fix")

    for f in sorted(findings, key=lambda x: -x.cvss_score):
        table.add_row(
            f.package,
            f.version,
            f.cve_id,
            f"{f.cvss_score:.1f}",
            _severity_cell(f.severity),
            f.fix_version or "[dim]none[/dim]",
        )

    console.print(table)


def print_code_security_findings_table(findings: list[CodeSecurityFinding]) -> None:
    """Print a Rich table of code security findings."""
    if not findings:
        console.print("[dim]No code security findings.[/dim]")
        return

    table = Table(
        title="Code Security Findings",
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
    )
    table.add_column("File:Line", style="bold")
    table.add_column("Category")
    table.add_column("Severity")
    table.add_column("CWE")
    table.add_column("Explanation")

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(findings, key=lambda x: severity_order.get(x.severity, 99)):
        location = f"{f.file}:{f.line}" if f.line is not None else f.file
        explanation = f.explanation
        if len(explanation) > 80:
            explanation = explanation[:77] + "..."
        table.add_row(
            location,
            f.category,
            _severity_cell(f.severity),
            f.cwe_id or "[dim]—[/dim]",
            explanation,
        )

    console.print(table)


def print_summary(report: UnifiedReport) -> None:
    """Print final summary: risk score, total findings by severity, output path."""
    all_severities: list[str] = (
        [f.severity for f in report.dep_findings]
        + [f.severity for f in report.code_security_findings]
        + [f.severity for f in report.attack_surface_findings]
    )

    counts: dict[str, int] = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
    for s in all_severities:
        if s in counts:
            counts[s] += 1

    score = report.risk_score
    if score >= 75:
        score_color = "red"
    elif score >= 40:
        score_color = "orange1"
    elif score >= 15:
        score_color = "yellow"
    else:
        score_color = "green"

    lines: list[str] = [
        f"[bold]Scan ID:[/bold] {report.scan_id}",
        f"[bold]Repo:[/bold]    {report.repo}",
        f"[bold]Risk Score:[/bold] [{score_color}]{score}/100[/{score_color}]",
        "",
        "[bold]Findings by severity:[/bold]",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        color = _SEVERITY_COLORS[sev]
        n = counts[sev]
        lines.append(f"  [{color}]{sev.upper():8s}[/{color}]  {n}")

    lines.append("")
    lines.append(f"[bold]Total findings:[/bold] {report.total_findings}")

    body = "\n".join(lines)
    panel = Panel(body, title="[bold cyan]Sentinel Scan Summary[/bold cyan]", border_style="cyan")
    console.print(panel)
