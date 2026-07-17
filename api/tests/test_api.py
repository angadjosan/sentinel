from fastapi.testclient import TestClient
from uuid import uuid4

from sentinel_api.main import app

from .conftest import seed_finding


def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ingest_creates_completed_run_and_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'sentinel.db'}")
    with TestClient(app) as client:
        ingested = seed_finding(client, repo_name="repo", vuln_type="sqli", file="app.js")
        run_id = ingested["run_id"]

        run_detail = client.get(f"/runs/{run_id}")
        assert run_detail.status_code == 200
        run = run_detail.json()
        assert run["status"] == "completed"
        assert run["finding_count"] == 1
        assert run["created_at"]
        assert run["completed_at"]

        findings = client.get("/findings")
        assert findings.status_code == 200
        findings_body = findings.json()
        assert findings_body[0]["vuln_type"] == "sqli"
        assert findings_body[0]["file"] == "app.js"
        assert findings_body[0]["created_at"]
        assert findings_body[0]["updated_at"]


def test_runs_include_listing_metadata():
    repo = f"run-metadata-{uuid4().hex}"
    with TestClient(app) as client:
        ingested = seed_finding(client, repo_name=repo, vuln_type="sqli", file="app.js")
        run_id = ingested["run_id"]

        listed = client.get("/runs")
        detail = client.get(f"/runs/{run_id}")

    assert listed.status_code == 200
    row = next(run for run in listed.json() if run["id"] == run_id)
    assert row["finding_count"] == 1
    assert row["created_at"]
    assert row["completed_at"]
    assert detail.status_code == 200
    assert detail.json()["finding_count"] == 1


def test_pull_graph_and_cancel_flow():
    repo = f"pull-graph-{uuid4().hex}"
    with TestClient(app) as client:
        ingested = seed_finding(
            client, repo_name=repo, vuln_type="cmdi",
            description="Add handler that calls exec(`convert ${req.query.file}`)",
        )
        run_id = ingested["run_id"]
        finding_id = ingested["finding_ids"][0]

        pull = client.get(f"/findings/{finding_id}/pull")
        assert pull.status_code == 200
        assert pull.json()["remediation_plan"]

        graph = client.get("/graph")
        assert graph.status_code == 200
        assert "nodes" in graph.json()

        finding_graph = client.get(f"/findings/{finding_id}/graph")
        assert finding_graph.status_code == 200
        assert "nodes" in finding_graph.json()
        assert "edges" in finding_graph.json()

        # The ingest run already completed; cancelling it is a no-op that
        # reports its (terminal) status rather than erroring.
        cancel = client.delete(f"/runs/{run_id}")
        assert cancel.status_code == 200
        assert cancel.json()["status"] == "completed"


def test_findings_can_filter_by_repo_name():
    suffix = uuid4().hex
    repo_a = f"filter-a-{suffix}"
    repo_b = f"filter-b-{suffix}"
    with TestClient(app) as client:
        # Distinct node ids: different repos producing the same deterministic
        # node id is a real (if narrower) collision case too — see graph_upsert.
        seed_finding(client, repo_name=repo_a, vuln_type="cmdi", node_id=f"fn:{repo_a}/app.js:sink")
        seed_finding(client, repo_name=repo_b, vuln_type="sqli", node_id=f"fn:{repo_b}/app.js:sink")

        response = client.get(f"/findings?repo_name={repo_b}")
    assert response.status_code == 200
    body = response.json()
    assert body
    assert all(finding["vuln_type"] == "sqli" for finding in body)


def test_findings_can_filter_by_status_and_severity():
    repo = f"finding-filters-{uuid4().hex}"
    with TestClient(app) as client:
        ingested = seed_finding(client, repo_name=repo, vuln_type="sqli", severity="high")
        finding_id = ingested["finding_ids"][0]

        suppressed = client.patch(f"/findings/{finding_id}/suppress", json={"reason": "filter regression"})
        assert suppressed.status_code == 200

        suppressed_rows = client.get(f"/findings?repo_name={repo}&status=suppressed")
        high_rows = client.get(f"/findings?repo_name={repo}&severity=high")
        critical_rows = client.get(f"/findings?repo_name={repo}&severity=critical")

    assert suppressed_rows.status_code == 200
    assert [finding["id"] for finding in suppressed_rows.json()] == [finding_id]
    assert high_rows.status_code == 200
    assert [finding["id"] for finding in high_rows.json()] == [finding_id]
    assert critical_rows.status_code == 200
    assert critical_rows.json() == []


# NOTE (W4): test_pentest_task_claim_complete_and_cancel was removed. It drove the
# generic task-queue lifecycle (/tasks/claim|complete|cancel) via the now-deleted
# POST /pentest enqueue. Pentest runs entirely on the developer's machine and the
# backend no longer enqueues any task, so there is no API path to seed the queue.
# The /tasks/* endpoints are dead cloud-worker surface removed with the daemon in W5.


def test_analytics_endpoints_return_operational_metrics():
    repo = f"analytics-{uuid4().hex}"
    with TestClient(app) as client:
        seed_finding(client, repo_name=repo, vuln_type="sqli", severity="high")

        trends = client.get("/analytics/finding-trends")
        latency = client.get("/analytics/scan-latency")
        fp = client.get("/analytics/false-positive-rate")
        confirmation = client.get("/analytics/confirmation-rate")

    assert trends.status_code == 200
    assert any(row["severity"] == "high" for row in trends.json())
    assert latency.status_code == 200
    assert isinstance(latency.json(), list)
    assert fp.status_code == 200
    assert "rate" in fp.json()
    assert confirmation.status_code == 200
    assert "confirmed" in confirmation.json()


# NOTE (W4): the cloud-enqueue and cloud-worker E2E pentest tests were removed:
#   - test_pentest_enqueue_returns_queued_run_and_task
#   - test_pentest_e2e_confirms_finding_and_writes_exploit_edge
#   - test_pentest_e2e_clean_target_marks_not_reproducible
#   - test_pentest_description_selects_matching_open_target
# plus their _set_repo_staging_url / _patch_httpx_transport helpers.
# They all drove POST /pentest -> cloud worker, which no longer exists: pentest
# runs entirely on the developer's machine (full gVisor stack) and pushes its
# outcome to POST /findings/{id}/confirm (covered by test_pentest_confirm.py).
# Natural-language target resolution moved client-side to the CLI, ranking over
# GET /findings — test_findings_exposes_fields_for_client_target_resolution below
# pins the fields that resolution depends on.


def test_findings_exposes_fields_for_client_target_resolution():
    """GET /findings must expose the fields the CLI ranks over to resolve a
    natural-language pentest target client-side (vuln_type/title/severity/status/
    id/file) — the server no longer selects a target."""
    repo = f"pentest-resolve-{uuid4().hex}"
    with TestClient(app) as client:
        seed_finding(
            client, repo_name=repo, vuln_type="sqli", title="SQL Injection", severity="high",
            description="Taint path confirmed from user-controlled input to sqli sink.",
        )
        seed_finding(
            client, repo_name=repo, vuln_type="cmdi", title="Command Injection", severity="critical",
            file="convert.js",
            description="Command injection via the convert endpoint using unsanitized input.",
        )

        all_findings = client.get(f"/findings?repo_name={repo}")
        assert all_findings.status_code == 200
        findings_list = all_findings.json()
        assert len(findings_list) == 2
        for finding in findings_list:
            for field in ("id", "vuln_type", "title", "severity", "status", "file"):
                assert field in finding, f"{field} missing from GET /findings response"

        cmdi = next(f for f in findings_list if f["vuln_type"] == "cmdi")
        assert cmdi["title"] == "Command Injection"
        assert cmdi["severity"] == "critical"
        assert cmdi["status"] == "open"
        assert cmdi["file"] == "convert.js"


def test_run_events_streams_trace_and_completion():
    repo = f"events-{uuid4().hex}"
    with TestClient(app) as client:
        ingested = seed_finding(client, repo_name=repo, vuln_type="sqli")
        run_id = ingested["run_id"]

        with client.stream("GET", f"/runs/{run_id}/events") as response:
            body = "".join(response.iter_text())
    assert "ingest.completed" in body
    assert '"kind": "complete"' in body


def test_run_trace_access_is_audited():
    repo = f"trace-audit-{uuid4().hex}"
    with TestClient(app) as client:
        ingested = seed_finding(client, repo_name=repo, vuln_type="sqli")
        run_id = ingested["run_id"]

        trace = client.get(f"/runs/{run_id}/trace")
        assert trace.status_code == 200
        assert trace.headers["content-type"].startswith("application/x-ndjson")
        access_log = client.get(f"/runs/{run_id}/trace-access")
        assert access_log.status_code == 200
        assert any(row["run_id"] == run_id for row in access_log.json())
