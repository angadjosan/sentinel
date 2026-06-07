from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import httpx
import structlog

log = structlog.get_logger(__name__)

try:
    from packaging.version import InvalidVersion, Version as _PackagingVersion

    def _parse_version(v: str):
        return _PackagingVersion(v)

    _InvalidVersion = InvalidVersion
except ImportError:  # packaging not installed — fall back to no-op sentinel
    _parse_version = None  # type: ignore[assignment]
    _InvalidVersion = Exception  # type: ignore[assignment,misc]


@dataclass
class CVERecord:
    id: str
    description: str
    cvss_score: float | None
    affected_versions: list[str]
    references: list[str]


@dataclass
class _TokenBucket:
    """Rate limiter: 50 requests per 30 seconds with API key, 5 without."""

    capacity: int
    refill_per_second: float
    _tokens: float = field(init=False)
    _last_refill: float = field(init=False)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False)

    def __post_init__(self) -> None:
        self._tokens = float(self.capacity)
        self._last_refill = time.monotonic()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_per_second)
            self._last_refill = now
            if self._tokens < 1:
                wait_time = (1 - self._tokens) / self.refill_per_second
                await asyncio.sleep(wait_time)
                self._tokens = 0
            else:
                self._tokens -= 1


class NVDClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key
        # 50 req/30s with key, 5 req/30s without
        rate = 50 / 30 if api_key else 5 / 30
        self._rate_limiter = _TokenBucket(capacity=int(rate * 30), refill_per_second=rate)
        self.http = httpx.AsyncClient(timeout=30.0)

    async def get_cves_for_package(self, package_name: str, version: str, ecosystem: str) -> list[CVERecord]:
        params: dict[str, str] = {"keywordSearch": package_name, "keywordExactMatch": ""}
        if self.api_key:
            params["apiKey"] = self.api_key

        await self._rate_limiter.acquire()
        try:
            resp = await self.http.get(self.BASE_URL, params=params)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            log.warning("nvd.request_failed", error=str(e), package=package_name)
            return []

        data = resp.json()
        cves: list[CVERecord] = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln["cve"]
            if self._version_affected(cve, version):
                cves.append(
                    CVERecord(
                        id=cve["id"],
                        description=next(
                            (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                            "",
                        ),
                        cvss_score=self._extract_cvss(cve),
                        affected_versions=self._extract_version_range(cve),
                        references=[r["url"] for r in cve.get("references", [])[:5]],
                    )
                )
        return cves

    def _version_affected(self, cve: dict, version: str) -> bool:
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue
                    v_start = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                    v_end = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                    try:
                        if _parse_version is None:
                            raise _InvalidVersion("packaging not available")
                        v = _parse_version(version)
                        if v_start and _parse_version(v_start) > v:
                            continue
                        if v_end and v > _parse_version(v_end):
                            continue
                        return True
                    except (_InvalidVersion, TypeError):
                        return True  # conservative: assume affected if can't parse
        return False  # configs present but none matched → not affected

    def _extract_cvss(self, cve: dict) -> float | None:
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metrics = cve.get("metrics", {}).get(metric_key, [])
            if metrics:
                return metrics[0].get("cvssData", {}).get("baseScore")
        return None

    def _extract_version_range(self, cve: dict) -> list[str]:
        ranges: list[str] = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    v_start = match.get("versionStartIncluding", "")
                    v_end = match.get("versionEndIncluding", match.get("versionEndExcluding", ""))
                    if v_start or v_end:
                        ranges.append(f"{v_start}..{v_end}")
        return ranges[:5]

    async def close(self) -> None:
        await self.http.aclose()
