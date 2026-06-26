"""Verify that /source, /init, /plan, /pentest enqueue tasks rather than running inline."""
from fastapi.testclient import TestClient
from sentinel_api.main import app


def test_source_endpoint_enqueues_not_runs(monkeypatch):
    import sentinel_worker.scan as scan
    def _raise(*a, **k):
        raise AssertionError("scan_diff ran inline — should have been enqueued")
    monkeypatch.setattr(scan, "scan_diff", _raise)

    with TestClient(app) as client:
        resp = client.post("/source", json={
            "repo_name": "demo",
            "diff": "diff --git a/app.py b/app.py\n+print('hi')",
        })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["run"]["status"] in ("queued", "running", "claimed")


def test_init_endpoint_enqueues_not_runs(monkeypatch):
    import sentinel_worker.scan as scan
    def _raise(*a, **k):
        raise AssertionError("bootstrap_repo ran inline — should have been enqueued")
    monkeypatch.setattr(scan, "bootstrap_repo", _raise)

    with TestClient(app) as client:
        resp = client.post("/init", json={
            "repo_name": "demo",
            "files": {},
        })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["run"]["status"] in ("queued", "running", "claimed")


def test_plan_endpoint_enqueues_not_runs(monkeypatch):
    import sentinel_worker.scan as scan
    def _raise(*a, **k):
        raise AssertionError("review_plan ran inline — should have been enqueued")
    monkeypatch.setattr(scan, "review_plan", _raise)

    with TestClient(app) as client:
        resp = client.post("/plan", json={
            "repo_name": "demo",
            "content": "users can reset passwords via a link",
            "with_retry": False,
        })
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["run"]["status"] in ("queued", "running", "claimed")
