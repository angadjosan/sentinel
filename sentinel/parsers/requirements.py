"""Parsers for Python dependency files."""
from __future__ import annotations

import re
import sys
import tomllib

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EXTRAS_RE = re.compile(r"\[.*?\]")  # strip extras like pkg[extra]


def _normalize_name(name: str) -> str:
    """Lowercase, replace underscores/dots with hyphens (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _split_name_version(raw: str) -> tuple[str, str]:
    """
    Given a raw requirement string (no extras, no env markers, no comments),
    split into (normalized_name, version_spec).
    version_spec is whatever follows the name, e.g. ">=1.0,<2.0" or "==1.2.3".
    Returns ("", "") for empty / URL / VCS requirements.
    """
    raw = raw.strip()
    if not raw:
        return "", ""
    # Skip URL / VCS dependencies (bare or PEP 440 direct references `pkg @ url`)
    if raw.startswith(("http://", "https://", "git+", "svn+", "hg+", "bzr+")):
        return "", ""
    # PEP 440 direct reference: pkg @ <url>
    if " @ " in raw or raw.count("@") and re.search(r"\s*@\s*(https?|git\+)", raw):
        return "", ""
    # Match: name followed by optional version spec
    m = re.match(r"^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)(.*)", raw)
    if not m:
        return "", ""
    name = _normalize_name(m.group(1))
    version_spec = m.group(3).strip()
    return name, version_spec


# ---------------------------------------------------------------------------
# requirements.txt
# ---------------------------------------------------------------------------

def parse_requirements_txt(content: str) -> list[tuple[str, str]]:
    """Parse requirements.txt. Returns list of (package_name, version_spec).

    Handles:
    - Pinned (==), ranges (>=,<=,!=,~=), bare names
    - Inline comments (#)
    - -r / --requirement includes (ignored — file not available here)
    - -c / --constraint, -e / --editable (ignored)
    - Extras: pkg[extra] → pkg
    - Blank lines
    - Environment markers (;) — stripped, version spec retained
    - Normalized names: lowercase, hyphens
    """
    results: list[tuple[str, str]] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        # Skip empty and comment-only lines
        if not line or line.startswith("#"):
            continue
        # Skip pip options
        if line.startswith(("-r", "--requirement", "-c", "--constraint", "-e", "--editable")):
            continue
        # Strip inline comment
        comment_pos = line.find(" #")
        if comment_pos != -1:
            line = line[:comment_pos].strip()
        # Strip environment markers
        marker_pos = line.find(";")
        if marker_pos != -1:
            line = line[:marker_pos].strip()
        # Strip extras
        line = _EXTRAS_RE.sub("", line)
        name, version_spec = _split_name_version(line)
        if name:
            results.append((name, version_spec))
    return results


# ---------------------------------------------------------------------------
# pyproject.toml
# ---------------------------------------------------------------------------

def parse_pyproject_toml(content: str) -> list[tuple[str, str]]:
    """Parse [project].dependencies from pyproject.toml.

    Returns list of (package_name, version_spec) in the same format as
    parse_requirements_txt.  Only PEP 621 [project] dependencies are parsed;
    build-system extras are ignored.
    """
    try:
        data = tomllib.loads(content)
    except Exception:
        return []

    raw_deps: list[str] = []

    # PEP 621 — [project].dependencies
    project = data.get("project", {})
    raw_deps.extend(project.get("dependencies", []))

    # Also collect optional-dependencies if present (flatten all groups)
    for group_deps in project.get("optional-dependencies", {}).values():
        if isinstance(group_deps, list):
            raw_deps.extend(group_deps)

    results: list[tuple[str, str]] = []
    for dep in raw_deps:
        if not isinstance(dep, str):
            continue
        # Strip extras and env markers then reuse the same split logic
        dep = _EXTRAS_RE.sub("", dep)
        marker_pos = dep.find(";")
        if marker_pos != -1:
            dep = dep[:marker_pos].strip()
        name, version_spec = _split_name_version(dep)
        if name:
            results.append((name, version_spec))
    return results


# ---------------------------------------------------------------------------
# Pipfile
# ---------------------------------------------------------------------------

def parse_pipfile(content: str) -> list[tuple[str, str]]:
    """Parse Pipfile [packages] section.

    Pipfile is TOML-like but uses a custom format. We handle:
    - pkg = "*"  → version_spec = ""
    - pkg = "==1.2.3" or pkg = ">=1.0"  → version_spec taken verbatim
    - pkg = {version = "==1.0", ...}  → version_spec taken from version key
    - [dev-packages] section is also included
    Normalized names: lowercase, hyphens.
    """
    try:
        # Pipfile is valid TOML
        data = tomllib.loads(content)
    except Exception:
        # Fall back to manual line-by-line parsing
        return _parse_pipfile_manual(content)

    results: list[tuple[str, str]] = []
    for section in ("packages", "dev-packages"):
        section_data = data.get(section, {})
        if not isinstance(section_data, dict):
            continue
        for pkg_name, spec in section_data.items():
            name = _normalize_name(pkg_name)
            if isinstance(spec, str):
                version_spec = "" if spec.strip() == "*" else spec.strip()
            elif isinstance(spec, dict):
                raw = spec.get("version", "") or ""
                version_spec = "" if raw.strip() == "*" else raw.strip()
            else:
                version_spec = ""
            if name:
                results.append((name, version_spec))
    return results


def _parse_pipfile_manual(content: str) -> list[tuple[str, str]]:
    """Manual fallback parser for Pipfile when tomllib cannot parse it."""
    results: list[tuple[str, str]] = []
    in_section = False
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Detect section headers
        if line.startswith("["):
            section_name = line.strip("[]").strip().lower()
            in_section = section_name in ("packages", "dev-packages")
            continue
        if not in_section:
            continue
        # pkg = "spec" or pkg = {version = "spec", ...}
        if "=" not in line:
            continue
        pkg_part, _, spec_part = line.partition("=")
        pkg_name = _normalize_name(pkg_part.strip())
        spec_part = spec_part.strip().strip('"\'')
        # Handle inline table {version = "==1.0"}
        if spec_part.startswith("{"):
            vm = re.search(r'version\s*=\s*["\']([^"\']*)["\']', spec_part)
            spec_part = vm.group(1).strip() if vm else ""
        version_spec = "" if spec_part == "*" else spec_part
        if pkg_name:
            results.append((pkg_name, version_spec))
    return results
