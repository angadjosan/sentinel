"""Parser for JavaScript / TypeScript dependency files."""
from __future__ import annotations

import json
import re

# Prefix characters that indicate a version range/constraint rather than a
# concrete version.  We strip leading occurrences of these so that e.g.
# "^1.2.3", "~1.2.3", ">=1.2.3", "<=1.2.3" all become "1.2.3".
_VERSION_PREFIX_RE = re.compile(r"^[\^~>=<\s]+")


def _clean_version(raw: str) -> str:
    """Strip range prefixes (^, ~, >=, <=) to get a concrete version string.

    If the result would be empty (e.g. "*" or "latest") we return the original
    value unchanged so callers can still see what was specified.
    """
    cleaned = _VERSION_PREFIX_RE.sub("", raw).strip()
    return cleaned if cleaned else raw.strip()


def parse_package_json(content: str) -> list[tuple[str, str]]:
    """Parse package.json dependencies + devDependencies.

    Returns list of (package_name, version) where version has had leading
    range prefixes (^, ~, >=, <=) stripped.

    Both ``dependencies`` and ``devDependencies`` are included.
    Scoped packages (``@scope/name``) are preserved as-is.
    Non-semver specifiers such as ``file:``, ``link:``, ``workspace:``,
    ``git+``, ``http://``, and ``https://`` are skipped.
    """
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    if not isinstance(data, dict):
        return []

    results: list[tuple[str, str]] = []

    for section in ("dependencies", "devDependencies", "peerDependencies"):
        section_data = data.get(section)
        if not isinstance(section_data, dict):
            continue
        for pkg_name, raw_version in section_data.items():
            if not isinstance(raw_version, str):
                continue
            version = raw_version.strip()
            # Skip non-registry specifiers
            if any(
                version.startswith(prefix)
                for prefix in ("file:", "link:", "workspace:", "git+", "git:", "http://", "https://", "github:")
            ):
                continue
            # Skip "latest", "*", "" — no concrete version to look up
            if version in ("", "*", "latest", "x"):
                results.append((pkg_name, version))
                continue
            results.append((pkg_name, _clean_version(version)))

    return results
