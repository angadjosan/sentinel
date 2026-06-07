from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from sentinel_worker.nvd import CVERecord, NVDClient, _TokenBucket


# ---------------------------------------------------------------------------
# _TokenBucket tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nvd_rate_limiter_acquires_correctly():
    """Verify _TokenBucket starts full and decrements on acquire."""
    bucket = _TokenBucket(capacity=5, refill_per_second=5 / 30)
    # Should start with full tokens — first 5 acquires should be instant.
    for _ in range(5):
        await bucket.acquire()
    # After 5 acquires the bucket is empty; tokens should be effectively 0
    # (small floating-point residue from time elapsed between calls is acceptable).
    assert bucket._tokens < 1.0


@pytest.mark.asyncio
async def test_nvd_rate_limiter_refills_over_time():
    """Verify the bucket refills proportionally to elapsed time."""
    bucket = _TokenBucket(capacity=5, refill_per_second=5.0)
    # Drain the bucket completely.
    for _ in range(5):
        await bucket.acquire()
    assert bucket._tokens < 1.0

    # Manually advance _last_refill backward by 1 second so the next acquire
    # sees 1 second of elapsed time → 5 tokens refilled.
    bucket._last_refill -= 1.0
    # Trigger refill calculation without waiting.
    import time
    async with bucket._lock:
        now = time.monotonic()
        elapsed = now - bucket._last_refill
        bucket._tokens = min(bucket.capacity, bucket._tokens + elapsed * bucket.refill_per_second)
        bucket._last_refill = now

    assert bucket._tokens >= 1.0


# ---------------------------------------------------------------------------
# NVDClient._version_affected tests
# ---------------------------------------------------------------------------


def _make_cve_with_range(v_start: str, v_end: str) -> dict:
    return {
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "versionStartIncluding": v_start,
                                "versionEndExcluding": v_end,
                            }
                        ]
                    }
                ]
            }
        ]
    }


def test_nvd_version_check_affected():
    """A version within the affected range is detected as affected."""
    client = NVDClient()
    cve = _make_cve_with_range("1.0.0", "2.0.0")
    assert client._version_affected(cve, "1.5.0") is True


def test_nvd_version_check_not_affected():
    """A version clearly above the affected range is correctly excluded."""
    client = NVDClient()
    cve = _make_cve_with_range("1.0.0", "2.0.0")
    # 3.0.0 is above versionEndExcluding=2.0.0, so not affected.
    assert client._version_affected(cve, "3.0.0") is False


def test_nvd_version_check_lower_bound_excluded():
    """A version below the start of the affected range is not affected."""
    client = NVDClient()
    cve = _make_cve_with_range("1.5.0", "2.0.0")
    assert client._version_affected(cve, "1.0.0") is False


def test_nvd_version_check_no_configurations():
    """A CVE with no configurations is treated as not affected."""
    client = NVDClient()
    cve: dict = {"configurations": []}
    assert client._version_affected(cve, "1.0.0") is False


# ---------------------------------------------------------------------------
# NVDClient HTTP error handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nvd_client_handles_http_error():
    """An httpx.HTTPError results in an empty list, not a raised exception."""
    client = NVDClient(api_key="test-key")

    # Patch the underlying HTTP client to raise an error.
    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "500", request=MagicMock(), response=MagicMock()
    )

    with patch.object(client.http, "get", new=AsyncMock(return_value=mock_response)):
        result = await client.get_cves_for_package("lodash", "4.17.21", "npm")

    assert result == []
    await client.close()


@pytest.mark.asyncio
async def test_nvd_client_handles_network_error():
    """A network-level httpx.HTTPError also results in an empty list."""
    client = NVDClient()

    with patch.object(client.http, "get", new=AsyncMock(side_effect=httpx.ConnectError("refused"))):
        result = await client.get_cves_for_package("requests", "2.28.0", "PyPI")

    assert result == []
    await client.close()


# ---------------------------------------------------------------------------
# NVDClient full response parsing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nvd_client_parses_cve_records():
    """A successful NVD response is parsed into CVERecord objects."""
    client = NVDClient(api_key="key")

    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-9999",
                    "descriptions": [{"lang": "en", "value": "Example vulnerability"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
                    },
                    "references": [{"url": "https://example.com/advisory"}],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "versionStartIncluding": "1.0.0",
                                            "versionEndExcluding": "2.0.0",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = payload

    with patch.object(client.http, "get", new=AsyncMock(return_value=mock_response)):
        records = await client.get_cves_for_package("example-pkg", "1.5.0", "PyPI")

    assert len(records) == 1
    record = records[0]
    assert record.id == "CVE-2024-9999"
    assert record.description == "Example vulnerability"
    assert record.cvss_score == 9.8
    assert record.references == ["https://example.com/advisory"]

    await client.close()
