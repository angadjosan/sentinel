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


def test_pentest_task_claim_complete_and_cancel():
    """Generic task-queue lifecycle (claim/complete/fail/cancel), exercised via
    /pentest enqueue now that /source/enqueue is gone — the task machinery
    itself is not scan-specific."""
    repo = f"queue-{uuid4().hex}"
    with TestClient(app) as client:
        ingested = seed_finding(client, repo_name=repo, vuln_type="sqli")
        finding_id = ingested["finding_ids"][0]

        enqueued = client.post("/pentest", json={"repo_name": repo, "finding_id": finding_id})
        assert enqueued.status_code == 200
        task_id = enqueued.json()["task_id"]
        run_id = enqueued.json()["run"]["id"]

        claimed = client.post("/tasks/claim?worker_id=test-worker")
        assert claimed.status_code == 200
        assert claimed.json()["id"] == task_id
        assert claimed.json()["status"] == "claimed"

        completed = client.post(f"/tasks/{task_id}/complete", json={"trace": "worker done"})
        assert completed.status_code == 200
        assert completed.json()["status"] == "completed"
        run = client.get(f"/runs/{run_id}")
        assert run.status_code == 200
        assert run.json()["status"] == "completed"

        second = client.post("/pentest", json={"repo_name": repo, "finding_id": finding_id})
        second_task = second.json()["task_id"]
        cancelled = client.post(f"/tasks/{second_task}/cancel")
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"

        third = client.post("/pentest", json={"repo_name": repo, "finding_id": finding_id})
        third_task = third.json()["task_id"]
        third_run = third.json()["run"]["id"]
        cancelled_run = client.delete(f"/runs/{third_run}")
        assert cancelled_run.status_code == 200
        assert cancelled_run.json()["status"] == "cancelled"
        claimed_after_cancel = client.post("/tasks/claim?worker_id=test-worker")
        assert claimed_after_cancel.status_code == 200
        assert claimed_after_cancel.json() is None
        cancelled_task = client.post(f"/tasks/{third_task}/complete", json={"trace": "late completion"})
        assert cancelled_task.status_code == 200
        assert cancelled_task.json()["status"] == "cancelled"
        cancelled_trace = client.get(f"/runs/{third_run}/trace")
        assert "run.cancelled" in cancelled_trace.text
        assert "late completion" not in cancelled_trace.text

        fourth = client.post("/pentest", json={"repo_name": repo, "finding_id": finding_id})
        fourth_run = fourth.json()["run"]["id"]
        delete_cancelled = client.delete(f"/runs/{fourth_run}")
        assert delete_cancelled.status_code == 200
        assert delete_cancelled.json()["status"] == "cancelled"


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


def test_pentest_enqueue_returns_queued_run_and_task():
    """Enqueue-only contract: POST /pentest returns a *queued* pentest run + task.

    Renamed from the former ``*writes_confirmed_edge`` (AUDIT.md §6 W4 P3.2 /
    Gate 3): that name lied — the body only ever asserted ``status == queued``
    and never confirmed anything. Confirmation is proven end-to-end (through the
    worker + a mock staging app) in
    ``test_pentest_e2e_confirms_finding_and_writes_exploit_edge`` below.
    """
    repo = f"pentest-{uuid4().hex}"
    with TestClient(app) as client:
        seed_finding(client, repo_name=repo, vuln_type="sqli", severity="high")

        enqueued = client.post(
            "/pentest",
            json={"repo_name": repo},
        )
        assert enqueued.status_code == 200
        body = enqueued.json()
        assert body["run"]["status"] == "queued"
        assert body["run"]["kind"] == "pentest"
        assert body["task_id"]

        runs = client.get("/runs")
    pentest_runs = [run for run in runs.json() if run["kind"] == "pentest"]
    assert pentest_runs


def _set_repo_staging_url(repo_name: str, base_url: str, healthcheck_path: str = "/health") -> None:
    """Set staging pentest config on the repo directly in the test DB.

    The runner reads `repo.staging_base_url` to decide where to dispatch HTTP
    payloads; the /pentest enqueue payload doesn't carry it. Uses the same
    patched SessionLocal the inline task runner uses."""
    import asyncio
    from sqlalchemy import select
    from sentinel_api.deps import SessionLocal
    from sentinel_worker.models import Repo

    async def _run() -> None:
        async with SessionLocal() as session:
            async with session.begin():
                repo = await session.scalar(select(Repo).where(Repo.name == repo_name))
                assert repo is not None, f"repo {repo_name} should exist after seed_finding"
                repo.pentest_mode = "staging"
                repo.staging_base_url = base_url
                repo.healthcheck_path = healthcheck_path

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_run())
    finally:
        loop.close()


def _patch_httpx_transport(monkeypatch, handler):
    """Route httpx.AsyncClients created without an explicit transport through a
    MockTransport so the worker's real HTTP dispatch hits our fake staging app."""
    import httpx

    real_init = httpx.AsyncClient.__init__

    def patched_init(self, *args, **kwargs):
        kwargs.setdefault("transport", httpx.MockTransport(handler))
        real_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", patched_init)


def test_pentest_e2e_confirms_finding_and_writes_exploit_edge(monkeypatch):
    """True end-to-end (AUDIT.md §6 W4 P3.1/P3.2, Gate 3):

    POST /pentest -> worker claims the task -> real HTTP dispatch hits a mock
    staging app that leaks a SQL error on the injection payload -> the oracle
    confirms on the *target's own response* (not the agent's word, §1 inv. 5) ->
    finding is marked confirmed and a CONFIRMED_EXPLOIT edge is written.

    This is the test that FAILS if the runner's `pentest` handler is deleted:
    the unknown kind would mark the task failed, the finding would stay open, and
    both the status and the edge assertions below would blow up.
    """
    import httpx
    from .conftest import process_tasks, NoFindingLLM

    def staging_app(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":  # healthcheck
            return httpx.Response(200, text="ok")
        body = request.content.decode(errors="replace")
        if "OR '1'='1" in body or "OR '1'='1" in str(request.url):
            # Target leaks a DB error the oracle recognizes as a SQLi proof marker.
            return httpx.Response(500, text="psycopg2.errors.SyntaxError: unclosed quotation mark near ''")
        return httpx.Response(200, text="no results")

    _patch_httpx_transport(monkeypatch, staging_app)

    repo = f"pentest-e2e-{uuid4().hex}"
    sink_id = "fn:app/db.py:query_user"
    entry = {"id": "route:search", "kind": "ROUTE", "name": "search", "file": "app/routes.py", "is_entry_point": True}
    with TestClient(app) as client:
        client.post(
            "/graph/upsert",
            json={
                "repo_name": repo,
                "graph_kind": "main",
                "nodes": [entry, {"id": sink_id, "kind": "FUNCTION", "name": "query_user", "file": "app/db.py", "is_sink": True}],
                "edges": [],
            },
        )
        ingested = seed_finding(client, repo_name=repo, vuln_type="sqli", node_id=sink_id, file="app/db.py")
        finding_id = ingested["finding_ids"][0]

        _set_repo_staging_url(repo, "http://staging.example.test", "/health")

        enqueued = client.post("/pentest", json={"repo_name": repo, "finding_id": finding_id})
        assert enqueued.status_code == 200
        assert enqueued.json()["run"]["status"] == "queued"

        # Run the worker inline: real handler + real HTTP dispatch (mocked target).
        process_tasks(1, llm=NoFindingLLM())

        detail = client.get(f"/findings/{finding_id}")
        assert detail.status_code == 200, detail.text
        assert detail.json()["status"] == "confirmed", detail.json()
        assert detail.json()["confirmed"] is True

        graph = client.get(f"/findings/{finding_id}/graph")
        assert graph.status_code == 200
        edge_kinds = {e["kind"] for e in graph.json()["edges"]}
        assert "CONFIRMED_EXPLOIT" in edge_kinds, graph.json()

        # A completed pentest run with an HTTP-dispatch trace must exist.
        runs = client.get("/runs")
        pentest_runs = [r for r in runs.json() if r["kind"] == "pentest"]
        assert pentest_runs
        assert any(r["status"] == "completed" for r in pentest_runs)


def test_pentest_e2e_clean_target_marks_not_reproducible(monkeypatch):
    """Negative half of the E2E: a staging app that never leaks proof must leave
    the finding NOT reproducible — the oracle refuses to confirm without the
    target's own evidence (AUDIT.md §1 invariant 5)."""
    import httpx
    from .conftest import process_tasks, NoFindingLLM

    def clean_app(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, text="ok")
        return httpx.Response(200, text="0 results found")

    _patch_httpx_transport(monkeypatch, clean_app)

    repo = f"pentest-clean-{uuid4().hex}"
    with TestClient(app) as client:
        ingested = seed_finding(client, repo_name=repo, vuln_type="sqli")
        finding_id = ingested["finding_ids"][0]
        _set_repo_staging_url(repo, "http://staging.example.test", "/health")

        client.post("/pentest", json={"repo_name": repo, "finding_id": finding_id})
        process_tasks(1, llm=NoFindingLLM())

        detail = client.get(f"/findings/{finding_id}")
        assert detail.status_code == 200
        assert detail.json()["status"] == "not_reproducible", detail.json()
        assert detail.json()["confirmed"] is False


def test_pentest_description_selects_matching_open_target():
    repo = f"pentest-description-{uuid4().hex}"
    with TestClient(app) as client:
        seed_finding(
            client, repo_name=repo, vuln_type="sqli", title="SQL Injection",
            description="Taint path confirmed from user-controlled input to sqli sink.",
        )
        seed_finding(
            client, repo_name=repo, vuln_type="cmdi", title="Command Injection",
            description="Command injection via the convert endpoint using unsanitized input.",
        )

        all_findings = client.get(f"/findings?repo_name={repo}")
        assert all_findings.status_code == 200
        findings_list = all_findings.json()
        cmdi_findings = [f for f in findings_list if f["vuln_type"] == "cmdi"]
        sqli_findings = [f for f in findings_list if f["vuln_type"] == "sqli"]
        assert cmdi_findings
        assert sqli_findings

        selected = client.post(
            "/pentest",
            json={
                "repo_name": repo,
                "description": "confirm the command injection convert endpoint",
                "behavioral_proof": "command_executed",
                "proof_detail": "wrote marker file through convert payload",
            },
        )

    assert selected.status_code == 200
    assert selected.json()["run"]["status"] == "queued"
    assert selected.json()["task_id"]


# NOTE (AUDIT.md §6 W4 P3.2): the former `test_pentest_rejects_incomplete_firecracker_config`
# was deleted. It was named "rejects ... config" but only asserted a 200 on
# enqueue — a fake-green test for a `firecracker` field that is not part of the
# target pentest config (§3 D1 supports `staging` and `local_worker` modes only).
# Config validation now lives in PATCH /repos/{id}/pentest-config (see
# api/tests/test_repos_pentest_config.py / W1) and in the worker, both of which
# assert real reject behavior.


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
