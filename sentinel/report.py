"""Report persistence — write and load UnifiedReport JSON files."""
from __future__ import annotations

import json
from pathlib import Path

from sentinel.models import UnifiedReport


def write_report(report: UnifiedReport, output_dir: str) -> str:
    """Write findings.json to *output_dir*. Returns the full path written."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dest = out / "findings.json"
    dest.write_text(
        json.dumps(report.model_dump(), indent=2, default=str),
        encoding="utf-8",
    )
    return str(dest.resolve())


def load_report(path: str) -> UnifiedReport:
    """Load and validate a findings.json file."""
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    return UnifiedReport.model_validate(data)
