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

from sentinel_api.main import app  # noqa: F401
