"""Dependency vulnerability scanner using OSV.dev."""
from __future__ import annotations

import logging
import os
import re
from packaging.version import Version, InvalidVersion

import httpx

from sentinel.models import DepFinding, Severity
from sentinel.parsers.requirements import (
    parse_pipfile,
    parse_pyproject_toml,
    parse_requirements_txt,
)
from sentinel.parsers.package_json import parse_package_json

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"

# ---------------------------------------------------------------------------
# OSV query helpers
# ---------------------------------------------------------------------------

_BATCH_SIZE = 100
_DETAIL_CONCURRENCY = 20  # max parallel vuln detail fetches


async def query_osv_batch(packages: list[dict]) -> list[dict]:
    """Query OSV.dev batch endpoint.

    ``packages`` is a list of dicts::

        {"name": str, "version": str, "ecosystem": "PyPI" | "npm"}

    Returns the raw ``results`` list from the OSV response — one element per
    input package (each element is a dict with a ``"vulns"`` key containing
    full vulnerability details, or ``{}`` if no vulnerabilities were found).

    Note: The batch endpoint only returns {id, modified} per vuln. We fetch
    full details for each unique vuln ID in parallel.
    """
    if not packages:
        return []

    queries = [
        {
            "package": {
                "name": pkg["name"],
                "ecosystem": pkg["ecosystem"],
            },
            "version": pkg["version"],
        }
        for pkg in packages
    ]

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(OSV_BATCH_URL, json={"queries": queries})
            response.raise_for_status()
            data = response.json()
            raw_results = data.get("results", [])

            # Collect unique vuln IDs across all results
            all_ids: set[str] = set()
            for result in raw_results:
                for vuln in result.get("vulns", []):
                    if vuln.get("id"):
                        all_ids.add(vuln["id"])

            if not all_ids:
                return [{} for _ in raw_results]

            # Fetch full details for each unique ID in parallel
            full_vulns = await _fetch_vuln_details(list(all_ids), client)
            vuln_map: dict[str, dict] = {v["id"]: v for v in full_vulns if v.get("id")}

            # Re-assemble results with full vuln objects
            enriched = []
            for result in raw_results:
                ids = [v["id"] for v in result.get("vulns", []) if v.get("id")]
                full = [vuln_map[i] for i in ids if i in vuln_map]
                enriched.append({"vulns": full} if full else {})
            return enriched

    except httpx.TimeoutException:
        logger.warning("OSV.dev query timed out — skipping batch of %d packages", len(packages))
        return []
    except httpx.HTTPStatusError as exc:
        logger.warning("OSV.dev HTTP error %s — skipping batch", exc.response.status_code)
        return []
    except Exception as exc:  # noqa: BLE001
        logger.warning("OSV.dev query failed: %s — skipping batch", exc)
        return []


async def _fetch_vuln_details(vuln_ids: list[str], client: httpx.AsyncClient) -> list[dict]:
    """Fetch full vuln details for a list of OSV IDs in parallel."""
    import asyncio
    semaphore = asyncio.Semaphore(_DETAIL_CONCURRENCY)

    async def fetch_one(vuln_id: str) -> dict:
        async with semaphore:
            try:
                resp = await client.get(OSV_VULN_URL.format(vuln_id), timeout=15.0)
                resp.raise_for_status()
                return resp.json()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Failed to fetch vuln %s: %s", vuln_id, exc)
                return {"id": vuln_id}  # return stub so we still have the ID

    results = await asyncio.gather(*[fetch_one(vid) for vid in vuln_ids])
    return list(results)


# ---------------------------------------------------------------------------
# CVSS helpers
# ---------------------------------------------------------------------------

# Mapping of CVSS v3 metric values used to compute the base score.
# We use the standard AV/AC/PR/UI/S/C/I/A weights to derive a numeric score
# from a CVSS vector string without needing the `cvss` package.

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED    = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

_QUALITATIVE_TO_SCORE: dict[str, float] = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "MODERATE": 5.0,
    "LOW": 2.0,
    "NONE": 0.0,
}


def _parse_cvss_vector(vector: str) -> float | None:
    """Compute a CVSS v3 base score from a vector string.

    Accepts strings like ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H``.
    Returns ``None`` if the string cannot be parsed.
    """
    # Strip the "CVSS:3.x/" prefix
    m = re.match(r"^CVSS:3\.[01]/(.+)$", vector)
    if not m:
        return None
    parts = dict(item.split(":") for item in m.group(1).split("/") if ":" in item)
    try:
        av  = _AV[parts["AV"]]
        ac  = _AC[parts["AC"]]
        s   = parts["S"]
        pr  = (_PR_CHANGED if s == "C" else _PR_UNCHANGED)[parts["PR"]]
        ui  = _UI[parts["UI"]]
        c   = _CIA[parts["C"]]
        i   = _CIA[parts["I"]]
        a   = _CIA[parts["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if s == "U":
        base = min(impact + exploitability, 10)
    else:
        base = min(1.08 * (impact + exploitability), 10)

    # Round up to one decimal place (CVSS spec uses ceiling at 1 dp)
    import math
    return math.ceil(base * 10) / 10


def _extract_cvss_score(vuln: dict) -> float:
    """Try multiple locations in an OSV vuln dict to find a numeric score."""
    # 1. severity[] list with CVSS_V3 vectors
    for sev in vuln.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V2"):
            score = _parse_cvss_vector(sev.get("score", ""))
            if score is not None:
                return score

    # 2. database_specific.severity qualitative string
    db_sev = (
        vuln.get("database_specific", {}).get("severity", "")
        or vuln.get("database_specific", {}).get("cvss_score", "")
    )
    if isinstance(db_sev, str) and db_sev.upper() in _QUALITATIVE_TO_SCORE:
        return _QUALITATIVE_TO_SCORE[db_sev.upper()]
    if isinstance(db_sev, (int, float)):
        return float(db_sev)

    # 3. github_reviewed_at / ecosystem_specific sometimes has cvss_score
    for key in ("ecosystem_specific",):
        nested = vuln.get(key, {})
        if isinstance(nested, dict):
            score_val = nested.get("cvss_score") or nested.get("severity")
            if isinstance(score_val, (int, float)):
                return float(score_val)
            if isinstance(score_val, str) and score_val.upper() in _QUALITATIVE_TO_SCORE:
                return _QUALITATIVE_TO_SCORE[score_val.upper()]

    return 0.0


def _score_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# OSV → DepFinding conversion
# ---------------------------------------------------------------------------

def _extract_cve_id(vuln: dict) -> str:
    """Prefer CVE-xxxx-xxxx aliases; fall back to OSV ID."""
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "UNKNOWN")


def _extract_fix_version(vuln: dict, ecosystem: str) -> str | None:
    """Walk affected[].ranges[].events to find the first 'fixed' entry."""
    for affected in vuln.get("affected", []):
        # Filter to the right ecosystem if specified in the affected block
        pkg_eco = affected.get("package", {}).get("ecosystem", "")
        if pkg_eco and ecosystem.lower() not in pkg_eco.lower():
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    return fixed
    return None


def osv_to_finding(
    pkg_name: str,
    pkg_version: str,
    ecosystem: str,
    vuln: dict,
) -> DepFinding:
    """Convert a single OSV vulnerability dict to a ``DepFinding``.

    - CVE ID: prefers ``CVE-`` aliases, falls back to OSV ID.
    - CVSS score: parsed from severity CVSS vector, then qualitative mapping.
    - Severity: derived from CVSS score (>=9=critical, >=7=high, >=4=medium, else low).
    - Fix version: first ``fixed`` event found in affected ranges.
    - Summary: ``vuln["summary"]`` or ``vuln["details"]`` (truncated).
    """
    cvss_score = _extract_cvss_score(vuln)
    severity = _score_to_severity(cvss_score)
    cve_id = _extract_cve_id(vuln)
    fix_version = _extract_fix_version(vuln, ecosystem)

    summary = vuln.get("summary", "") or ""
    if not summary:
        details = vuln.get("details", "") or ""
        summary = details[:200].strip()

    aliases = [a for a in vuln.get("aliases", []) if a != cve_id]

    return DepFinding(
        package=pkg_name,
        version=pkg_version,
        ecosystem=ecosystem.lower(),
        cve_id=cve_id,
        cvss_score=cvss_score,
        severity=severity,
        summary=summary,
        fix_version=fix_version,
        aliases=aliases,
    )


# ---------------------------------------------------------------------------
# Repo walker
# ---------------------------------------------------------------------------

def _find_dep_files(repo_path: str) -> dict[str, str]:
    """Walk ``repo_path`` and return ``{filepath: file_type}`` for all
    recognised dependency manifests.

    Recognised file types: ``requirements_txt``, ``pyproject_toml``,
    ``pipfile``, ``package_json``.
    """
    dep_files: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(repo_path):
        # Skip hidden directories and common non-project directories
        dirnames[:] = [
            d for d in dirnames
            if not d.startswith(".")
            and d not in ("node_modules", "__pycache__", ".git", "venv", ".venv", "env")
        ]
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            lower = filename.lower()
            if re.match(r"^requirements.*\.txt$", lower):
                dep_files[filepath] = "requirements_txt"
            elif lower == "pyproject.toml":
                dep_files[filepath] = "pyproject_toml"
            elif lower == "pipfile" and "." not in filename:
                dep_files[filepath] = "pipfile"
            elif lower == "package.json":
                dep_files[filepath] = "package_json"
    return dep_files


def _parse_file(filepath: str, file_type: str) -> tuple[list[tuple[str, str]], str]:
    """Parse a single dep file. Returns ``(packages, ecosystem)``."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError as exc:
        logger.warning("Could not read %s: %s", filepath, exc)
        return [], ""

    if file_type == "requirements_txt":
        return parse_requirements_txt(content), "PyPI"
    if file_type == "pyproject_toml":
        return parse_pyproject_toml(content), "PyPI"
    if file_type == "pipfile":
        return parse_pipfile(content), "PyPI"
    if file_type == "package_json":
        return parse_package_json(content), "npm"
    return [], ""


# ---------------------------------------------------------------------------
# Version deduplication
# ---------------------------------------------------------------------------

def _keep_highest_version(
    packages: list[tuple[str, str, str]]
) -> list[tuple[str, str, str]]:
    """Given list of (name, version, ecosystem), keep the highest version per
    (name, ecosystem) pair.

    If a version string cannot be parsed by ``packaging.version.Version`` the
    package is kept as-is (first occurrence wins).
    """
    best: dict[tuple[str, str], tuple[str, str, str]] = {}
    for name, version, ecosystem in packages:
        key = (name, ecosystem)
        if key not in best:
            best[key] = (name, version, ecosystem)
        else:
            existing_version = best[key][1]
            try:
                if Version(version) > Version(existing_version):
                    best[key] = (name, version, ecosystem)
            except InvalidVersion:
                pass  # Keep existing entry
    return list(best.values())


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def run_dep_scan(
    repo_path: str,
    ecosystem_filter: list[str] | None = None,
) -> list[DepFinding]:
    """Scan a local repository for vulnerable dependencies.

    Steps:

    1. Walk ``repo_path`` for dependency manifests.
    2. Parse each file using the appropriate parser.
    3. Deduplicate packages, keeping the highest version.
    4. Query OSV.dev in batches of 100.
    5. Convert results to ``DepFinding`` objects, deduplicating by
       ``(package, cve_id)``.
    6. Sort by severity (critical first), then CVSS score descending.

    Parameters
    ----------
    repo_path:
        Absolute path to the cloned repository root.
    ecosystem_filter:
        Optional list of ecosystems to scan (e.g. ``["PyPI"]``).
        ``None`` means scan all recognised ecosystems.
    """
    # Normalise filter values
    if ecosystem_filter is not None:
        ecosystem_filter = [e.lower() for e in ecosystem_filter]

    # Step 1 & 2 — discover and parse dep files
    dep_files = _find_dep_files(repo_path)
    logger.debug("Found %d dependency files in %s", len(dep_files), repo_path)

    raw_packages: list[tuple[str, str, str]] = []  # (name, version, ecosystem)
    for filepath, file_type in dep_files.items():
        parsed, ecosystem = _parse_file(filepath, file_type)
        if not parsed:
            continue
        if ecosystem_filter is not None and ecosystem.lower() not in ecosystem_filter:
            continue
        for name, version_spec in parsed:
            if not name:
                continue
            # Extract a concrete version from the spec (e.g. "==1.2.3" → "1.2.3")
            version = _extract_pinned_version(version_spec)
            if not version:
                # Skip packages with no concrete version — OSV needs a version
                logger.debug("Skipping %s (no pinned version: %r)", name, version_spec)
                continue
            raw_packages.append((name, version, ecosystem))

    if not raw_packages:
        logger.info("No versioned packages found in %s", repo_path)
        return []

    # Step 3 — deduplicate
    unique_packages = _keep_highest_version(raw_packages)
    logger.info("Querying OSV for %d unique packages", len(unique_packages))

    # Step 4 — query OSV in batches
    all_results: list[tuple[tuple[str, str, str], list[dict]]] = []
    for i in range(0, len(unique_packages), _BATCH_SIZE):
        batch = unique_packages[i : i + _BATCH_SIZE]
        osv_queries = [
            {"name": name, "version": version, "ecosystem": ecosystem}
            for name, version, ecosystem in batch
        ]
        results = await query_osv_batch(osv_queries)
        for pkg, result in zip(batch, results):
            vulns = result.get("vulns", []) if isinstance(result, dict) else []
            if vulns:
                all_results.append((pkg, vulns))

    # Step 5 — convert to DepFinding, deduplicate by (package, cve_id)
    seen: set[tuple[str, str]] = set()
    findings: list[DepFinding] = []
    for (name, version, ecosystem), vulns in all_results:
        for vuln in vulns:
            finding = osv_to_finding(name, version, ecosystem, vuln)
            key = (finding.package, finding.cve_id)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)

    # Step 6 — sort by severity then CVSS desc
    findings.sort(
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), -f.cvss_score)
    )

    logger.info("Dep scan complete: %d findings", len(findings))
    return findings


# ---------------------------------------------------------------------------
# Version extraction helper
# ---------------------------------------------------------------------------

_PINNED_VERSION_RE = re.compile(
    r"==\s*([^\s,;]+)"  # exact pin: ==1.2.3
)
_SINGLE_VERSION_RE = re.compile(
    r"^(\d[\w.\-+]*)$"  # bare version string with no operator
)


def _extract_pinned_version(version_spec: str) -> str:
    """Extract a single concrete version string from a version spec.

    - ``==1.2.3`` → ``1.2.3``
    - ``>=1.2.3`` → ``1.2.3``   (best effort: take the lower bound)
    - ``1.2.3`` (bare) → ``1.2.3``
    - ``*``, ``latest``, empty → ``""``
    """
    if not version_spec:
        return ""
    vs = version_spec.strip()

    if vs in ("*", "latest", "x", ""):
        return ""

    # Exact pin
    m = _PINNED_VERSION_RE.search(vs)
    if m:
        return m.group(1).strip()

    # Bare version (no operator)
    m = _SINGLE_VERSION_RE.match(vs)
    if m:
        return m.group(1)

    # Range — extract the first version number as a best-effort lower bound
    range_m = re.search(r"[\^~><=!]+\s*(\d[\w.\-]*)", vs)
    if range_m:
        return range_m.group(1).strip()

    return ""
