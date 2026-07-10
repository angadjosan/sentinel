import sys
import os

# Local dev fallback: if sentinel_worker isn't pip-installed, add worker/ to path.
# On Vercel both packages are installed via `file:api` and `file:worker` in requirements.txt.
_worker_dev = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "worker")
if os.path.isdir(os.path.join(_worker_dev, "sentinel_worker")):
    try:
        import sentinel_worker  # noqa: F401 — already installed, nothing to do
    except ImportError:
        sys.path.insert(0, os.path.normpath(_worker_dev))

app = None  # placeholder so the builder statically detects a top-level `app`

try:
    from sentinel_api.main import app  # noqa: F401,F811
except Exception:
    import traceback

    _tb = traceback.format_exc()

    async def _diagnostic_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 500, "headers": [[b"content-type", b"text/plain"]]})
        await send({"type": "http.response.body", "body": _tb.encode()})

    app = _diagnostic_app
