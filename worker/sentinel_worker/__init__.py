import sys

import structlog

__all__ = ["__version__"]

__version__ = "0.1.0"

# Logs go to stderr, never stdout: local_cli.py (and standalone.py) print a
# single machine-readable JSON result line to stdout, and structlog's default
# PrintLoggerFactory targets stdout — without this, log lines interleave with
# and corrupt that JSON. Standard containers (Docker, etc.) capture stderr
# alongside stdout, so this doesn't lose any log output for the cloud worker.
structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=sys.stderr))
