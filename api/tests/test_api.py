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
