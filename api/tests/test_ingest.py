"""Tests for the CI-native POST /findings/ingest endpoint.

The endpoint accepts pre-computed findings (no source/diff) and deduplicates
them by canonical fingerprint across re-ingests.
"""
from uuid import uuid4

from fastapi.testclient import TestClient

from sentinel_api.auth import create_token
from sentinel_api.main import app

_FINDINGS = [
    {
        "vuln_type": "sqli",
        "severity": "high",
        "title": "SQL Injection",
        "description": "User input flows into a raw SQL query.",
        "remediation": "Use parameterized queries.",
        "file": "app/db.py",
        "line": 42,
        "evidence": "db.query(f'select * from u where id={req.id}')",
    },
    {
        "vuln_type": "cmdi",
        "severity": "critical",
        "title": "Command Injection",
        "description": "User input flows into an os.system call.",
        "remediation": "Avoid shell; use argument lists.",
        "node_id": "fn:app/run.py:exec",
        "evidence": "os.system('run ' + req.cmd)",
    },
]


def test_ingest_creates_run_and_findings(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    token = create_token("ingest-user", f"ingest-account-{uuid4().hex}", "admin")
    headers = {"Authorization": f"Bearer {token}"}
    repo = f"ingest-repo-{uuid4().hex}"
    with TestClient(app) as client:
        resp = client.post(
            "/findings/ingest",
            headers=headers,
            json={"repo_name": repo, "run_context": "ci", "commit_sha": "abc123", "findings": _FINDINGS},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["created"] == 2
        assert body["updated"] == 0
        assert body["total"] == 2
        assert body["run_id"]

        listed = client.get(f"/findings?repo_name={repo}", headers=headers)
        assert listed.status_code == 200
        rows = listed.json()
        assert {row["vuln_type"] for row in rows} == {"sqli", "cmdi"}
        assert all(row["status"] == "open" for row in rows)


def test_ingest_dedups_on_reingest(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    token = create_token("ingest-user", f"ingest-account-{uuid4().hex}", "admin")
    headers = {"Authorization": f"Bearer {token}"}
    repo = f"ingest-repo-{uuid4().hex}"
    payload = {"repo_name": repo, "run_context": "ci", "findings": _FINDINGS}
    with TestClient(app) as client:
        first = client.post("/findings/ingest", headers=headers, json=payload)
        assert first.status_code == 200, first.text
        assert first.json()["created"] == 2

        second = client.post("/findings/ingest", headers=headers, json=payload)
        assert second.status_code == 200, second.text
        body = second.json()
        assert body["created"] == 0
        assert body["updated"] == 2
        assert body["total"] == 2

        listed = client.get(f"/findings?repo_name={repo}", headers=headers)
        assert listed.status_code == 200
        # No duplicate rows created on re-ingest.
        assert len(listed.json()) == 2


def test_ingest_does_not_reopen_suppressed_finding(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    token = create_token("ingest-user", f"ingest-account-{uuid4().hex}", "admin")
    headers = {"Authorization": f"Bearer {token}"}
    repo = f"ingest-repo-{uuid4().hex}"
    payload = {"repo_name": repo, "run_context": "ci", "findings": _FINDINGS}
    with TestClient(app) as client:
        first = client.post("/findings/ingest", headers=headers, json=payload)
        assert first.status_code == 200, first.text
        finding_id = client.get(f"/findings?repo_name={repo}", headers=headers).json()[0]["id"]

        suppressed = client.patch(
            f"/findings/{finding_id}/suppress",
            headers=headers,
            json={"reason": "accepted risk"},
        )
        assert suppressed.status_code == 200
        assert suppressed.json()["status"] == "suppressed"

        # Re-ingest the same findings — the suppressed one must stay suppressed.
        second = client.post("/findings/ingest", headers=headers, json=payload)
        assert second.status_code == 200, second.text
        assert second.json()["updated"] == 2

        detail = client.get(f"/findings/{finding_id}", headers=headers)
        assert detail.status_code == 200
        assert detail.json()["status"] == "suppressed"


def test_ingest_requires_auth(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    with TestClient(app) as client:
        missing = client.post(
            "/findings/ingest",
            json={"repo_name": "no-auth-repo", "findings": _FINDINGS},
        )
        invalid = client.post(
            "/findings/ingest",
            headers={"Authorization": "Bearer not-a-real-token"},
            json={"repo_name": "no-auth-repo", "findings": _FINDINGS},
        )
    assert missing.status_code == 401
    assert invalid.status_code == 401
