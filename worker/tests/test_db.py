from pathlib import Path

from sentinel_worker.db import database_url


def test_database_url_uses_stable_dev_db(monkeypatch, tmp_path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SENTINEL_DEV_DB", str(tmp_path / "sentinel.dev.db"))
    assert database_url() == f"sqlite+aiosqlite:///{tmp_path / 'sentinel.dev.db'}"
    assert Path(tmp_path).exists()
