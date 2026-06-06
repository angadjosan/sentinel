from fastapi.testclient import TestClient

from sentinel_api.main import app


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
