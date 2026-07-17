"""Frozen entry point for the Sentinel engine.

PyInstaller freezes the entry script as `__main__`, so freezing
`sentinel_worker/local_cli.py` directly breaks its `from .local_engine import ...`
relative imports ("attempted relative import with no known parent package").
Freezing this wrapper instead keeps `sentinel_worker` a real, importable package.
"""

from sentinel_worker.local_cli import main

if __name__ == "__main__":
    main()
