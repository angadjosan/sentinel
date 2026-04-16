"""Smoke tests for parsers, models, and report I/O. No network calls."""
from __future__ import annotations

import os

import pytest

from sentinel.models import CodeSecurityFinding, DepFinding, UnifiedReport
from sentinel.parsers.package_json import parse_package_json
from sentinel.parsers.requirements import parse_requirements_txt
from sentinel.report import load_report, write_report


# ---------------------------------------------------------------------------
# 1. requirements.txt parsing
# ---------------------------------------------------------------------------

_REQUIREMENTS_TXT = """\
# Production dependencies
requests==2.31.0          # HTTP library
flask>=2.3,<4.0           # web framework
numpy==1.26.4
scipy>=1.11               # scientific computing; python_requires>="3.9"
celery[redis]==5.3.6      # task queue with extras
urllib3!=2.0.0,>=1.25.4   # version exclusion

# Dev dependencies
-r requirements-dev.txt   # include file (should be skipped)
pytest==8.0.0
black>=23.0

# VCS / URL (should be skipped)
git+https://github.com/example/repo.git#egg=mylib
https://example.com/mypackage.tar.gz
"""


def test_requirements_parsing():
    packages = parse_requirements_txt(_REQUIREMENTS_TXT)
    names = {name for name, _ in packages}

    # Core packages must be present
    assert "requests" in names
    assert "flask" in names
    assert "numpy" in names
    assert "scipy" in names
    assert "celery" in names  # extras stripped → celery
    assert "urllib3" in names
    assert "pytest" in names
    assert "black" in names

    # VCS and URL entries must be skipped
    assert "mylib" not in names

    # Version specs preserved correctly
    pkg_map = dict(packages)
    assert pkg_map["requests"] == "==2.31.0"
    assert pkg_map["numpy"] == "==1.26.4"
    # Flask has a range; both operators must be in the spec
    assert ">=" in pkg_map["flask"] and "<" in pkg_map["flask"]


# ---------------------------------------------------------------------------
# 2. package.json parsing
# ---------------------------------------------------------------------------

_PACKAGE_JSON = """\
{
  "name": "my-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "axios": "~1.6.0",
    "lodash": "4.17.21",
    "react": ">=18.0.0"
  },
  "devDependencies": {
    "jest": "^29.7.0",
    "eslint": "~8.56.0",
    "typescript": "5.3.3"
  }
}
"""


def test_package_json_parsing():
    packages = parse_package_json(_PACKAGE_JSON)
    pkg_map = dict(packages)

    # express: "^4.18.2" → "4.18.2"
    assert "express" in pkg_map
    assert pkg_map["express"] == "4.18.2"

    # jest: "^29.7.0" → "29.7.0"
    assert "jest" in pkg_map
    assert pkg_map["jest"] == "29.7.0"

    # lodash: bare version unchanged
    assert pkg_map["lodash"] == "4.17.21"

    # tilde stripped: axios "~1.6.0" → "1.6.0"
    assert pkg_map["axios"] == "1.6.0"

    # No leading ^ or ~ in any version
    for name, version in packages:
        assert not version.startswith("^"), f"{name} version still has ^ prefix"
        assert not version.startswith("~"), f"{name} version still has ~ prefix"


# ---------------------------------------------------------------------------
# 3. UnifiedReport risk score and total_findings
# ---------------------------------------------------------------------------

def test_unified_report_risk_score():
    code_finding = CodeSecurityFinding(
        file="app/auth.py",
        line=42,
        category="injection",
        severity="critical",
        explanation="SQL injection via unsanitised user input.",
    )
    dep_finding_1 = DepFinding(
        package="requests",
        version="2.20.0",
        ecosystem="pypi",
        cve_id="CVE-2023-32681",
        cvss_score=7.5,
        severity="high",
        summary="Proxy-Authorization header leak.",
    )
    dep_finding_2 = DepFinding(
        package="flask",
        version="2.2.0",
        ecosystem="pypi",
        cve_id="CVE-2023-30861",
        cvss_score=7.5,
        severity="high",
        summary="Session cookie leak via proxy response.",
    )

    report = UnifiedReport(
        repo="https://github.com/example/app",
        code_security_findings=[code_finding],
        dep_findings=[dep_finding_1, dep_finding_2],
    )

    assert report.total_findings == 3
    # critical code finding: 25 * 2 = 50; two high dep findings: 10 + 10 = 20 → total 70
    assert report.risk_score > 0
    assert report.risk_score == 70


# ---------------------------------------------------------------------------
# 4. Report round-trip: write → load
# ---------------------------------------------------------------------------

def test_report_roundtrip(tmp_path):
    dep_finding = DepFinding(
        package="django",
        version="3.2.0",
        ecosystem="pypi",
        cve_id="CVE-2021-35042",
        cvss_score=9.8,
        severity="critical",
        summary="RCE via QuerySet.order_by().",
    )
    original = UnifiedReport(
        repo="https://github.com/example/myrepo",
        dep_findings=[dep_finding],
    )

    written_path = write_report(original, str(tmp_path))
    loaded = load_report(written_path)

    assert loaded.repo == original.repo
    assert loaded.total_findings == original.total_findings
    assert loaded.dep_findings[0].cve_id == "CVE-2021-35042"


# ---------------------------------------------------------------------------
# 5. SentinelConfig defaults (no env vars, no YAML key overrides)
# ---------------------------------------------------------------------------

def test_config_defaults(monkeypatch, tmp_path):
    # Clear env vars that could supply API keys or override defaults
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    # Point YAML lookup away from the real sentinel.yml so we get pure defaults
    monkeypatch.chdir(tmp_path)

    # Import here so the monkeypatched env is in effect when the module resolves
    from sentinel.config import SentinelConfig  # noqa: PLC0415

    config = SentinelConfig()

    assert config.fail_on == "high"
    assert config.dashboard_port == 4000
    assert config.anthropic_api_key is None
    assert config.github_token is None


# ---------------------------------------------------------------------------
# 6. SentinelConfig env override
# ---------------------------------------------------------------------------

def test_config_env_override(monkeypatch, tmp_path):
    test_key = "sk-ant-test-0000000000000000"
    monkeypatch.setenv("ANTHROPIC_API_KEY", test_key)
    # Isolate from the project sentinel.yml
    monkeypatch.chdir(tmp_path)

    from sentinel.config import SentinelConfig  # noqa: PLC0415

    config = SentinelConfig()

    assert config.anthropic_api_key == test_key
