from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AdvisoryCache, Edge, Finding, Node
from .security import compute_fingerprint

log = structlog.get_logger(__name__)


REQUIREMENT_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)==([^\s#]+)", re.MULTILINE)
IMPORT_RE = re.compile(r"\b(?:import|require\()\s*['\"]?(@?[A-Za-z0-9_.\-\/]+)")
PYPROJECT_DEP_RE = re.compile(r"['\"]([A-Za-z0-9_.\-]+)==([^'\"]+)['\"]")
GEM_LOCK_RE = re.compile(r"^\s{4}([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)", re.MULTILINE)
YARN_ENTRY_RE = re.compile(r"^\"?((?:@[^/\s@]+/)?[^@\s\"]+)@[^:\n]+\"?:\n(?:  .+\n)*?  version \"([^\"]+)\"", re.MULTILINE)
PNPM_PACKAGE_RE = re.compile(r"^\s{2}/?((?:@[^/\s@]+/)?[^@\s/]+)@([^:\n]+):", re.MULTILINE)


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    manifest_path: str


@dataclass(frozen=True)
class Advisory:
    package: str
    ecosystem: str
    affected_version: str
    vuln_id: str
    severity: str
    summary: str


@dataclass(frozen=True)
class Reachability:
    reachable: bool
    evidence: str
    imported_by: list[str]


class AdvisorySource:
    async def lookup(self, dependency: Dependency) -> list[Advisory]:
        raise NotImplementedError



class OSVAdvisorySource(AdvisorySource):
    def __init__(self, base_url: str = "https://api.osv.dev/v1/query"):
        self.base_url = base_url

    async def lookup(self, dependency: Dependency) -> list[Advisory]:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(
                self.base_url,
                json={"package": {"name": dependency.name, "ecosystem": dependency.ecosystem}, "version": dependency.version},
            )
            response.raise_for_status()
            payload = response.json()
        advisories: list[Advisory] = []
        for vuln in payload.get("vulns", []):
            advisories.append(
                Advisory(
                    package=dependency.name,
                    ecosystem=dependency.ecosystem,
                    affected_version=dependency.version,
                    vuln_id=vuln.get("id", "OSV"),
                    severity=_severity_from_osv(vuln),
                    summary=vuln.get("summary") or vuln.get("details", "Dependency advisory"),
                )
            )
        return advisories


class NVDAdvisorySource(AdvisorySource):
    def __init__(self, base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0", api_key: str | None = None):
        self.base_url = base_url
        self.api_key = api_key

    async def lookup(self, dependency: Dependency) -> list[Advisory]:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                self.base_url,
                params={"keywordSearch": dependency.name, "keywordExactMatch": "", "noRejected": "", "resultsPerPage": 50},
                headers=headers,
            )
            response.raise_for_status()
            payload = response.json()
        return parse_nvd_advisories(payload, dependency)


def parse_nvd_advisories(payload: dict, dependency: Dependency) -> list[Advisory]:
    advisories: list[Advisory] = []
    seen: set[str] = set()
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        vuln_id = cve.get("id")
        if not vuln_id or vuln_id in seen:
            continue
        if not _nvd_mentions_affected_dependency(cve, dependency):
            continue
        seen.add(vuln_id)
        advisories.append(
            Advisory(
                package=dependency.name,
                ecosystem=dependency.ecosystem,
                affected_version=dependency.version,
                vuln_id=vuln_id,
                severity=_severity_from_nvd(cve),
                summary=_english_description(cve) or "NVD dependency advisory",
            )
        )
    return advisories


def _parse_pipfile_lock(content: str) -> list[tuple[str, str, str]]:
    data = json.loads(content)
    deps: list[tuple[str, str, str]] = []
    for section in ["default", "develop"]:
        for name, info in data.get(section, {}).items():
            version = info.get("version", "").lstrip("==")
            deps.append((name, version, "PyPI"))
    return deps


def _parse_poetry_lock(content: str) -> list[tuple[str, str, str]]:
    deps: list[tuple[str, str, str]] = []
    current_name: str | None = None
    current_version: str | None = None
    for line in content.splitlines():
        if line.startswith("name = "):
            current_name = line.split('"')[1] if '"' in line else line.split("=")[1].strip().strip('"')
        elif line.startswith("version = ") and current_name:
            current_version = line.split('"')[1] if '"' in line else line.split("=")[1].strip().strip('"')
            deps.append((current_name, current_version, "PyPI"))
            current_name = current_version = None
    return deps


def _parse_go_mod(content: str) -> list[tuple[str, str, str]]:
    deps: list[tuple[str, str, str]] = []
    in_require = False
    for line in content.splitlines():
        line = line.strip()
        if line == "require (":
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if in_require or line.startswith("require "):
            line = line.removeprefix("require ").strip()
            parts = line.split()
            if len(parts) >= 2 and not parts[0].startswith("//"):
                deps.append((parts[0], parts[1].lstrip("v"), "Go"))
    return deps


def _parse_cargo_lock(content: str) -> list[tuple[str, str, str]]:
    deps: list[tuple[str, str, str]] = []
    current: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if line == "[[package]]":
            if current.get("name") and current.get("version"):
                deps.append((current["name"], current["version"], "crates.io"))
            current = {}
        elif " = " in line:
            key, _, val = line.partition(" = ")
            current[key.strip()] = val.strip().strip('"')
    if current.get("name") and current.get("version"):
        deps.append((current["name"], current["version"], "crates.io"))
    return deps


def _parse_cargo_toml(content: str) -> list[tuple[str, str, str]]:
    deps: list[tuple[str, str, str]] = []
    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped in ("[dependencies]", "[dev-dependencies]", "[build-dependencies]"):
            in_deps = True
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_deps = False
            continue
        if not in_deps:
            continue
        if "=" not in stripped or stripped.startswith("#"):
            continue
        name, _, rest = stripped.partition("=")
        name = name.strip()
        rest = rest.strip().strip('"').strip("'")
        # handle: name = "1.2.3" or name = { version = "1.2.3", ... }
        if rest.startswith("{"):
            m = re.search(r'version\s*=\s*["\']?([^"\'}\s,]+)', rest)
            version = m.group(1).lstrip("^~>=") if m else ""
        else:
            version = rest.lstrip("^~>=").split()[0] if rest else ""
        if name and version:
            deps.append((name, version, "crates.io"))
    return deps


def _parse_build_gradle(content: str) -> list[tuple[str, str, str]]:
    deps: list[tuple[str, str, str]] = []
    # Groovy DSL: implementation 'group:artifact:version' or implementation "group:artifact:version"
    # Kotlin DSL: implementation("group:artifact:version")
    pattern1 = re.compile(
        r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\(?\s*['"]([^'"]+):([^'"]+):([^'"]+)['"]""",
        re.IGNORECASE,
    )
    # Named args: implementation(group = "...", name = "...", version = "...")
    pattern2 = re.compile(
        r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*\([^)]*name\s*=\s*['"]([^'"]+)['"][^)]*version\s*=\s*['"]([^'"]+)['"]""",
        re.IGNORECASE,
    )
    for m in pattern1.finditer(content):
        artifact = m.group(2)
        version = m.group(3)
        deps.append((artifact, version, "Maven"))
    for m in pattern2.finditer(content):
        artifact = m.group(1)
        version = m.group(2)
        deps.append((artifact, version, "Maven"))
    return deps


def _parse_pom_xml(content: str) -> list[tuple[str, str, str]]:
    deps: list[tuple[str, str, str]] = []
    dep_blocks = re.findall(r"<dependency>(.*?)</dependency>", content, re.DOTALL)
    for block in dep_blocks:
        artifact = re.search(r"<artifactId>(.*?)</artifactId>", block)
        version = re.search(r"<version>(.*?)</version>", block)
        if artifact and version:
            deps.append((artifact.group(1), version.group(1), "Maven"))
    return deps


def parse_dependencies(path: str, content: str) -> list[Dependency]:
    if path.endswith("package-lock.json"):
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            return []
        deps: list[Dependency] = []
        packages = payload.get("packages")
        if isinstance(packages, dict):
            for package_path, package in packages.items():
                if not package_path.startswith("node_modules/") or not isinstance(package, dict):
                    continue
                version = package.get("version")
                if version:
                    deps.append(Dependency(name=package_path.removeprefix("node_modules/"), version=str(version), ecosystem="npm", manifest_path=path))
            return deps
        for name, package in payload.get("dependencies", {}).items():
            if isinstance(package, dict) and package.get("version"):
                deps.append(Dependency(name=name, version=str(package["version"]), ecosystem="npm", manifest_path=path))
        return deps
    if path.endswith("yarn.lock"):
        return [Dependency(name=match.group(1), version=match.group(2), ecosystem="npm", manifest_path=path) for match in YARN_ENTRY_RE.finditer(content)]
    if path.endswith("pnpm-lock.yaml"):
        return [Dependency(name=match.group(1), version=match.group(2), ecosystem="npm", manifest_path=path) for match in PNPM_PACKAGE_RE.finditer(content)]
    if path.endswith("package.json"):
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            return [
                Dependency(name=match.group(1), version=match.group(2), ecosystem="npm", manifest_path=path)
                for match in re.finditer(r'"(@?[^"]+)"\s*:\s*"[\^~]?([^"]+)"', content)
            ]
        pkg_deps: list[Dependency] = []
        for section in ("dependencies", "devDependencies"):
            for name, version in payload.get(section, {}).items():
                pkg_deps.append(Dependency(name=name, version=str(version).lstrip("^~"), ecosystem="npm", manifest_path=path))
        return pkg_deps
    if path.endswith("requirements.txt"):
        return [Dependency(name=match.group(1), version=match.group(2), ecosystem="pypi", manifest_path=path) for match in REQUIREMENT_RE.finditer(content)]
    if path.endswith("Pipfile.lock"):
        try:
            return [Dependency(name=n, version=v, ecosystem=e, manifest_path=path) for n, v, e in _parse_pipfile_lock(content)]
        except (json.JSONDecodeError, KeyError):
            return []
    if path.endswith("pyproject.toml"):
        return [Dependency(name=match.group(1), version=match.group(2), ecosystem="pypi", manifest_path=path) for match in PYPROJECT_DEP_RE.finditer(content)]
    if path.endswith("poetry.lock"):
        return [Dependency(name=n, version=v, ecosystem=e, manifest_path=path) for n, v, e in _parse_poetry_lock(content)]
    if path.endswith("go.mod"):
        return [Dependency(name=n, version=v, ecosystem=e, manifest_path=path) for n, v, e in _parse_go_mod(content)]
    if path.endswith("Cargo.lock"):
        return [Dependency(name=n, version=v, ecosystem=e, manifest_path=path) for n, v, e in _parse_cargo_lock(content)]
    if path.endswith("Cargo.toml"):
        return [Dependency(name=n, version=v, ecosystem=e, manifest_path=path) for n, v, e in _parse_cargo_toml(content)]
    if path.endswith("build.gradle") or path.endswith("build.gradle.kts"):
        return [Dependency(name=n, version=v, ecosystem=e, manifest_path=path) for n, v, e in _parse_build_gradle(content)]
    if path.endswith("pom.xml"):
        return [Dependency(name=n, version=v, ecosystem=e, manifest_path=path) for n, v, e in _parse_pom_xml(content)]
    if path.endswith("Gemfile.lock"):
        return [Dependency(name=match.group(1), version=match.group(2), ecosystem="rubygems", manifest_path=path) for match in GEM_LOCK_RE.finditer(content)]
    return []


async def scan_dependencies(
    db: AsyncSession,
    graph_id: str,
    repo_id: str,
    run_id: str,
    path: str,
    content: str,
    source: AdvisorySource | None = None,
) -> int:
    advisory_source = source or OSVAdvisorySource()
    count = 0
    for dependency in parse_dependencies(path, content):
        dep_node = Node(
            id=f"dep:{path}:{dependency.name}@{dependency.version}",
            graph_id=graph_id,
            kind="DEPENDENCY",
            name=f"{dependency.name}@{dependency.version}",
            file=path,
            language=dependency.ecosystem,
            label=f"{dependency.name} dependency",
            intent=f"{dependency.ecosystem} dependency declared in {path}.",
        )
        await db.merge(dep_node)
        reachable = await _dependency_reachability(db, graph_id, dependency, dep_node.id)
        for advisory in await _lookup_with_cache(db, dependency, advisory_source):
            vuln_type = "sca_reachable" if reachable.reachable else "sca_unreachable"
            fingerprint = compute_fingerprint(repo_id, path, f"{vuln_type}:{dependency.name}:{advisory.vuln_id}")
            existing = await db.scalar(select(Finding).where(Finding.fingerprint == fingerprint))
            if existing is not None and existing.suppressed:
                continue
            if existing is None:
                db.add(
                    Finding(
                        graph_id=graph_id,
                        node_id=dep_node.id,
                        run_id=run_id,
                        vuln_type=vuln_type,
                        severity=advisory.severity,
                        title=f"{advisory.vuln_id} affects {dependency.name}@{dependency.version}",
                        description=f"{advisory.summary}. Reachability: {reachable.evidence}.",
                        remediation=f"Upgrade {dependency.name} to a non-vulnerable version.",
                        fingerprint=fingerprint,
                    )
                )
            else:
                existing.run_id = run_id
            count += 1
    return count


async def _lookup_with_cache(db: AsyncSession, dependency: Dependency, source: AdvisorySource) -> list[Advisory]:
    cached = await db.get(AdvisoryCache, (dependency.name, dependency.ecosystem, dependency.version))
    now_utc = datetime.now(UTC)
    if cached is not None and _as_utc(cached.expires_at) > now_utc:
        return [_advisory_from_json(row) for row in json.loads(cached.advisories_json)]

    advisories = await source.lookup(dependency)
    payload = json.dumps(
        [
            {
                "package": advisory.package,
                "ecosystem": advisory.ecosystem,
                "affected_version": advisory.affected_version,
                "vuln_id": advisory.vuln_id,
                "severity": advisory.severity,
                "summary": advisory.summary,
            }
            for advisory in advisories
        ],
        sort_keys=True,
    )
    record = AdvisoryCache(
        package=dependency.name,
        ecosystem=dependency.ecosystem,
        version=dependency.version,
        advisories_json=payload,
        fetched_at=now_utc,
        expires_at=now_utc + timedelta(hours=24),
    )
    await db.merge(record)
    return advisories


async def _dependency_reachability(db: AsyncSession, graph_id: str, dependency: Dependency, version_node_id: str) -> Reachability:
    package_node_id = f"dep:{dependency.name}"
    package_node = await db.get(Node, {"graph_id": graph_id, "id": package_node_id})
    if package_node is None:
        package_node = Node(
            id=package_node_id,
            graph_id=graph_id,
            kind="DEPENDENCY",
            name=dependency.name,
            language=dependency.ecosystem,
            label=f"{dependency.name} dependency",
            intent="Imported package referenced by repository source.",
        )
        await db.merge(package_node)
    await _add_edge(db, graph_id, package_node_id, version_node_id, "DEPENDS_ON", call_uncertainty="resolved_import")
    import_edges = list(await db.scalars(select(Edge).where(Edge.graph_id == graph_id).where(Edge.kind == "IMPORTS").where(Edge.dst == package_node_id)))
    imported_by = sorted(edge.src for edge in import_edges)
    if imported_by:
        return Reachability(True, f"reachable via IMPORTS edge(s) from {', '.join(imported_by[:5])}", imported_by)
    nodes = await db.scalars(select(Node).where(Node.graph_id == graph_id).where(Node.kind.in_(["FILE", "FUNCTION"])))
    fallback = sorted(node.id for node in nodes if node.intent and dependency.name in node.intent)
    if fallback:
        return Reachability(True, f"reachable via unresolved textual import evidence in {', '.join(fallback[:5])}", fallback)
    return Reachability(False, "not proven reachable from any source import edge", [])


async def _add_edge(db: AsyncSession, graph_id: str, src: str, dst: str, kind: str, **kwargs: object) -> None:
    existing = await db.scalar(select(Edge).where(Edge.graph_id == graph_id).where(Edge.src == src).where(Edge.dst == dst).where(Edge.kind == kind))
    if existing is None:
        db.add(Edge(graph_id=graph_id, src=src, dst=dst, kind=kind, **kwargs))


def _severity_from_osv(vuln: dict) -> str:
    severities = vuln.get("severity") or []
    for item in severities:
        score = item.get("score", "")
        if score.startswith("CVSS:"):
            if "/C:H" in score or "/I:H" in score or "/A:H" in score:
                return "high"
    return "medium"


def _severity_from_nvd(cve: dict) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for item in metrics.get(key, []):
            severity = item.get("cvssData", {}).get("baseSeverity") or item.get("baseSeverity")
            if severity:
                return str(severity).lower()
    return "medium"


def _english_description(cve: dict) -> str | None:
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en" and description.get("value"):
            return str(description["value"])
    return None


def _nvd_mentions_affected_dependency(cve: dict, dependency: Dependency) -> bool:
    package = _normalize_package_name(dependency.name)
    for match in _iter_cpe_matches(cve.get("configurations", [])):
        if not match.get("vulnerable", True):
            continue
        criteria = str(match.get("criteria", "")).lower()
        if package not in _normalize_package_name(criteria):
            continue
        if _nvd_version_matches(match, dependency.version):
            return True
    return False


def _iter_cpe_matches(configurations: list[dict]):
    for configuration in configurations:
        yield from _iter_cpe_node(configuration)


def _iter_cpe_node(node: dict):
    for match in node.get("cpeMatch", []):
        yield match
    for child in node.get("nodes", []):
        yield from _iter_cpe_node(child)


def _nvd_version_matches(match: dict, version: str) -> bool:
    cpe_version = _version_from_cpe(str(match.get("criteria", "")))
    if cpe_version not in ("", "*", "-") and _compare_versions(version, cpe_version) == 0:
        return True
    if start := match.get("versionStartIncluding"):
        if _compare_versions(version, str(start)) < 0:
            return False
    if start := match.get("versionStartExcluding"):
        if _compare_versions(version, str(start)) <= 0:
            return False
    if end := match.get("versionEndIncluding"):
        if _compare_versions(version, str(end)) > 0:
            return False
    if end := match.get("versionEndExcluding"):
        if _compare_versions(version, str(end)) >= 0:
            return False
    return any(match.get(key) for key in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"))


def _version_from_cpe(criteria: str) -> str:
    parts = criteria.split(":")
    return parts[5] if len(parts) > 5 else ""


def _compare_versions(left: str, right: str) -> int:
    left_parts = _version_parts(left)
    right_parts = _version_parts(right)
    width = max(len(left_parts), len(right_parts))
    left_parts.extend([0] * (width - len(left_parts)))
    right_parts.extend([0] * (width - len(right_parts)))
    if left_parts == right_parts:
        return 0
    return -1 if left_parts < right_parts else 1


def _version_parts(version: str) -> list[int]:
    parts: list[int] = []
    for part in re.split(r"[.\-+_]", version):
        match = re.match(r"(\d+)", part)
        parts.append(int(match.group(1)) if match else 0)
    return parts or [0]


def _normalize_package_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _advisory_from_json(row: dict) -> Advisory:
    return Advisory(
        package=row["package"],
        ecosystem=row["ecosystem"],
        affected_version=row["affected_version"],
        vuln_id=row["vuln_id"],
        severity=row["severity"],
        summary=row["summary"],
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)
