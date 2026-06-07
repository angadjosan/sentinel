from pathlib import Path

from sentinel_worker.db import _schema_name, database_url, reset_account_context, set_account_context


def test_database_url_uses_stable_dev_db(monkeypatch, tmp_path):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("SENTINEL_DEV_DB", str(tmp_path / "sentinel.dev.db"))
    assert database_url() == f"sqlite+aiosqlite:///{tmp_path / 'sentinel.dev.db'}"
    assert Path(tmp_path).exists()


def test_schema_name_valid_uuid():
    schema = _schema_name("550e8400-e29b-41d4-a716-446655440000")
    assert schema == "tenant_550e8400_e29b_41d4_a716_446655440000"


def test_schema_name_rejects_invalid():
    assert _schema_name("' OR 1=1--") is None
    assert _schema_name("../../etc/passwd") is None
    assert _schema_name("") is None


def test_account_context_is_thread_local():
    import asyncio

    async def inner(account_id: str) -> str | None:
        from sentinel_worker.db import _current_account_id
        token = set_account_context(account_id)
        val = _current_account_id.get()
        reset_account_context(token)
        return val

    result = asyncio.run(inner("550e8400-e29b-41d4-a716-446655440000"))
    assert result == "550e8400-e29b-41d4-a716-446655440000"


def test_account_context_resets_after_token():
    from sentinel_worker.db import _current_account_id

    assert _current_account_id.get() is None
    token = set_account_context("550e8400-e29b-41d4-a716-446655440000")
    assert _current_account_id.get() == "550e8400-e29b-41d4-a716-446655440000"
    reset_account_context(token)
    assert _current_account_id.get() is None
