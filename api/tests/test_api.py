from fastapi.testclient import TestClient
from uuid import uuid4

from sentinel_api.main import app
from sentinel_api.deps import SessionLocal
from sentinel_worker.models import TraceAccessLog


def test_health_endpoint():
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_source_endpoint_emits_finding(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'sentinel.db'}")
    with TestClient(app) as client:
        response = client.post(
            "/source",
            json={
                "repo_name": "repo",
                "diff": "+++ b/app.js\n+app.get('/u', (req,res)=> db.query(`select * from users where id=${req.query.id}`))",
                "run_context": "local",
            },
        )
    assert response.status_code == 200
    body = response.json()
    assert body["run"]["status"] == "completed"
    assert body["findings"][0]["vuln_type"] == "sqli"
    assert body["run"]["finding_count"] == 1
    assert body["run"]["created_at"]
    assert body["run"]["completed_at"]


def test_runs_include_listing_metadata():
    repo = f"run-metadata-{uuid4().hex}"
    with TestClient(app) as client:
        source = client.post(
            "/source",
            json={
                "repo_name": repo,
                "diff": "+++ b/app.js\n+db.query(`select * from users where id=${req.query.id}`)",
                "run_context": "local",
            },
        )
        assert source.status_code == 200
        run_id = source.json()["run"]["id"]
        listed = client.get("/runs")
        detail = client.get(f"/runs/{run_id}")

    assert listed.status_code == 200
    row = next(run for run in listed.json() if run["id"] == run_id)
    assert row["finding_count"] == 1
    assert row["created_at"]
    assert row["completed_at"]
    assert detail.status_code == 200
    assert detail.json()["finding_count"] == 1


def test_plan_pull_graph_and_cancel_flow():
    with TestClient(app) as client:
        plan = client.post(
            "/plan",
            json={
                "repo_name": "repo",
                "content": "Add handler that calls exec(`convert ${req.query.file}`)",
                "with_retry": True,
            },
        )
        assert plan.status_code == 200
        body = plan.json()
        finding_id = body["findings"][0]["id"]
        run_id = body["run"]["id"]

        pull = client.get(f"/findings/{finding_id}/pull")
        assert pull.status_code == 200
        assert pull.json()["remediation_plan"]

        graph = client.get("/graph")
        assert graph.status_code == 200
        assert "nodes" in graph.json()

        cancel = client.post(f"/runs/{run_id}/cancel")
        assert cancel.status_code == 200
        assert cancel.json()["status"] == "completed"


def test_findings_can_filter_by_repo_name():
    suffix = uuid4().hex
    repo_a = f"filter-a-{suffix}"
    repo_b = f"filter-b-{suffix}"
    with TestClient(app) as client:
        first = client.post(
            "/plan",
            json={"repo_name": repo_a, "content": "exec(`run ${req.query.x}`)", "with_retry": False},
        )
        second = client.post(
            "/plan",
            json={"repo_name": repo_b, "content": "db.query(`select ${req.query.x}`)", "with_retry": False},
        )
        assert first.status_code == 200
        assert second.status_code == 200
        response = client.get(f"/findings?repo_name={repo_b}")
    assert response.status_code == 200
    body = response.json()
    assert body
    assert all(finding["vuln_type"] == "sqli" for finding in body)


def test_source_enqueue_claim_complete_and_cancel():
    with TestClient(app) as client:
        enqueued = client.post(
            "/source/enqueue",
            json={"repo_name": f"queue-{uuid4().hex}", "diff": "+++ b/app.js\n+console.log('x')", "run_context": "local"},
        )
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

        second = client.post(
            "/source/enqueue",
            json={"repo_name": f"queue-{uuid4().hex}", "diff": "+++ b/app.js\n+console.log('y')", "run_context": "local"},
        )
        second_task = second.json()["task_id"]
        cancelled = client.post(f"/tasks/{second_task}/cancel")
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"

        third = client.post(
            "/source/enqueue",
            json={"repo_name": f"queue-{uuid4().hex}", "diff": "+++ b/app.js\n+console.log('z')", "run_context": "local"},
        )
        third_task = third.json()["task_id"]
        third_run = third.json()["run"]["id"]
        cancelled_run = client.post(f"/runs/{third_run}/cancel")
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


def test_analytics_endpoints_return_operational_metrics():
    repo = f"analytics-{uuid4().hex}"
    with TestClient(app) as client:
        plan = client.post(
            "/plan",
            json={"repo_name": repo, "content": "db.query(`select ${req.query.x}`)", "with_retry": False},
        )
        assert plan.status_code == 200

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


def test_pentest_selects_open_target_and_writes_confirmed_edge():
    repo = f"pentest-{uuid4().hex}"
    with TestClient(app) as client:
        source = client.post(
            "/source",
            json={
                "repo_name": repo,
                "diff": "+++ b/app.js\n+db.query(`select * from users where id=${req.query.id}`)",
                "run_context": "local",
            },
        )
        assert source.status_code == 200
        finding_id = source.json()["findings"][0]["id"]
        confirmed = client.post(
            "/pentest",
            json={
                "repo_name": repo,
                "behavioral_proof": "data_exfiltrated",
                "proof_detail": "dumped user row through SQLi payload",
            },
        )
        assert confirmed.status_code == 200
        assert confirmed.json()["id"] == finding_id
        assert confirmed.json()["confirmed"] is True
        graph = client.get("/graph")
        runs = client.get("/runs")
    assert any(edge["kind"] == "CONFIRMED_EXPLOIT" for edge in graph.json()["edges"])
    pentest_runs = [run for run in runs.json() if run["kind"] == "pentest"]
    assert pentest_runs
    assert "pentest.payloads.generated" in pentest_runs[0]["trace"]
    assert "pentest.oracle.evaluated" in pentest_runs[0]["trace"]


def test_pentest_description_selects_matching_open_target():
    repo = f"pentest-description-{uuid4().hex}"
    with TestClient(app) as client:
        sqli = client.post(
            "/plan",
            json={"repo_name": repo, "content": "db.query(`select ${req.query.id}`)", "with_retry": False},
        )
        cmdi = client.post(
            "/plan",
            json={"repo_name": repo, "content": "exec(`convert ${req.query.file}`)", "with_retry": False},
        )
        assert sqli.status_code == 200
        assert cmdi.status_code == 200

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
    assert selected.json()["id"] == cmdi.json()["findings"][0]["id"]
    assert selected.json()["id"] != sqli.json()["findings"][0]["id"]
    assert selected.json()["confirmed"] is True


def test_pentest_rejects_incomplete_firecracker_config():
    repo = f"pentest-firecracker-{uuid4().hex}"
    with TestClient(app) as client:
        source = client.post(
            "/source",
            json={
                "repo_name": repo,
                "diff": "+++ b/app.js\n+db.query(`select * from users where id=${req.query.id}`)",
                "run_context": "local",
            },
        )
        assert source.status_code == 200
        rejected = client.post(
            "/pentest",
            json={
                "repo_name": repo,
                "finding_id": source.json()["findings"][0]["id"],
                "firecracker": {"enabled": True, "kernel_image": "/var/lib/sentinel/vmlinux"},
            },
        )

    assert rejected.status_code == 422
    assert "rootfs_image" in rejected.text


def test_run_events_streams_trace_and_completion():
    repo = f"events-{uuid4().hex}"
    with TestClient(app) as client:
        plan = client.post(
            "/plan",
            json={"repo_name": repo, "content": "db.query(`select ${req.query.id}`)", "with_retry": False},
        )
        assert plan.status_code == 200
        run_id = plan.json()["run"]["id"]
        with client.stream("GET", f"/runs/{run_id}/events") as response:
            body = "".join(response.iter_text())
    assert "plan.completed" in body
    assert '"kind": "complete"' in body


def test_run_trace_access_is_audited():
    import anyio

    repo = f"trace-audit-{uuid4().hex}"
    with TestClient(app) as client:
        plan = client.post(
            "/plan",
            json={"repo_name": repo, "content": "db.query(`select ${req.query.id}`)", "with_retry": False},
        )
        assert plan.status_code == 200
        run_id = plan.json()["run"]["id"]
        trace = client.get(f"/runs/{run_id}/trace")
        assert trace.status_code == 200

    async def read_log_count() -> int:
        async with SessionLocal() as session:
            rows = await session.get(TraceAccessLog, 1)
            all_rows = await session.execute(TraceAccessLog.__table__.select().where(TraceAccessLog.run_id == run_id))
            return len(list(all_rows))

    assert anyio.run(read_log_count) >= 1


def test_source_file_endpoint_reads_encrypted_snapshot():
    repo = f"source-read-{uuid4().hex}"
    with TestClient(app) as client:
        init = client.post("/init", json={"repo_name": repo, "files": {"app.js": "const x = 1;"}})
        assert init.status_code == 200
        response = client.get(f"/source-files/{repo}/bootstrap/app.js")
    assert response.status_code == 200
    assert response.json()["content"] == "const x = 1;"
