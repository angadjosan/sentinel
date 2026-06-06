from __future__ import annotations

import json
import re
from dataclasses import dataclass

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Edge, Finding, Node
from .security import compute_fingerprint


REQUIREMENT_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)==([^\s#]+)", re.MULTILINE)
IMPORT_RE = re.compile(r"\b(?:import|require\()\s*['\"]?(@?[A-Za-z0-9_.\-\/]+)")
PYPROJECT_DEP_RE = re.compile(r"['\"]([A-Za-z0-9_.\-]+)==([^'\"]+)['\"]")
GEM_LOCK_RE = re.compile(r"^\s{4}([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)", re.MULTILINE)


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


class AdvisorySource:
    async def lookup(self, dependency: Dependency) -> list[Advisory]:
        raise NotImplementedError


class BuiltinAdvisorySource(AdvisorySource):
    advisories = [
        Advisory("lodash", "npm", "4.17.21", "CVE-2021-23337", "high", "lodash command injection in template handling"),
        Advisory("django", "pypi", "3.2.0", "CVE-2021-33203", "medium", "Django potential directory traversal issue"),
        Advisory("express", "npm", "4.17.0", "GHSA-example-express", "medium", "Express vulnerable version example advisory"),
        Advisory("rails", "rubygems", "6.1.0", "CVE-2021-22885", "high", "Rails vulnerable version example advisory"),
    ]

    async def lookup(self, dependency: Dependency) -> list[Advisory]:
        return [
            advisory
            for advisory in self.advisories
            if advisory.package == dependency.name and advisory.ecosystem == dependency.ecosystem and advisory.affected_version == dependency.version
        ]


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


def parse_dependencies(path: str, content: str) -> list[Dependency]:
    if path.endswith("package.json"):
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            return [
                Dependency(name=match.group(1), version=match.group(2), ecosystem="npm", manifest_path=path)
                for match in re.finditer(r'"(@?[^"]+)"\s*:\s*"[\^~]?([^"]+)"', content)
            ]
        deps: list[Dependency] = []
        for section in ("dependencies", "devDependencies"):
            for name, version in payload.get(section, {}).items():
                deps.append(Dependency(name=name, version=str(version).lstrip("^~"), ecosystem="npm", manifest_path=path))
        return deps
    if path.endswith("requirements.txt"):
        return [Dependency(name=match.group(1), version=match.group(2), ecosystem="pypi", manifest_path=path) for match in REQUIREMENT_RE.finditer(content)]
    if path.endswith("pyproject.toml"):
        return [Dependency(name=match.group(1), version=match.group(2), ecosystem="pypi", manifest_path=path) for match in PYPROJECT_DEP_RE.finditer(content)]
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
    advisory_source = source or BuiltinAdvisorySource()
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
        reachable = await _has_import_reference(db, graph_id, dependency.name)
        for advisory in await advisory_source.lookup(dependency):
            vuln_type = "sca_reachable" if reachable else "sca_unreachable"
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
                        description=f"{advisory.summary}. Reachability: {'reachable' if reachable else 'not proven reachable'}.",
                        remediation=f"Upgrade {dependency.name} to a non-vulnerable version.",
                        fingerprint=fingerprint,
                    )
                )
            else:
                existing.run_id = run_id
            count += 1
    return count


async def _has_import_reference(db: AsyncSession, graph_id: str, package_name: str) -> bool:
    nodes = await db.scalars(select(Node).where(Node.graph_id == graph_id).where(Node.kind.in_(["FILE", "FUNCTION"])))
    return any(node.intent and package_name in node.intent for node in nodes)


def _severity_from_osv(vuln: dict) -> str:
    severities = vuln.get("severity") or []
    for item in severities:
        score = item.get("score", "")
        if score.startswith("CVSS:"):
            if "/C:H" in score or "/I:H" in score or "/A:H" in score:
                return "high"
    return "medium"
