# PyInstaller spec — freeze the Sentinel local analysis engine into a onedir
# bundle named `sentinel-local`. This is what the npm CLI runs when the bundled
# engine optionalDependency (@sentineldev/engine-<os>-<cpu>) is installed, so no
# system Python / `pip install` is needed.
#
# onedir (NOT onefile): onefile self-extracts to a tmp dir on every invocation
# (~1-2s startup penalty + awkward with our subprocess model). onedir keeps a
# stable extracted tree the launcher points at.
#
# Build:  pyinstaller worker/pyinstaller/sentinel-engine.spec --noconfirm
#         (run from the repo root or worker/ — see build.sh which sets paths)
#
# What must be bundled beyond code:
#   * data:  sentinel_worker/prompts/*.txt   (loaded via Path(__file__).parent/"prompts")
#   * data:  worker/alembic/versions/*.py    (alembic migration path; create_all is the
#            runtime default but we ship these so `alembic upgrade` also works frozen)
#   * tree-sitter grammar shared libs — loaded dynamically via importlib in
#     construction.py, so PyInstaller can't see them: --collect-all each grammar.

import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

# The spec runs with CWD = wherever pyinstaller was invoked. SPECPATH is the dir
# containing this spec (worker/pyinstaller), so worker/ is its parent.
WORKER_DIR = Path(SPECPATH).parent  # noqa: F821 — SPECPATH injected by PyInstaller
PKG_DIR = WORKER_DIR / "sentinel_worker"

datas = [
    (str(PKG_DIR / "prompts"), "sentinel_worker/prompts"),
    (str(WORKER_DIR / "alembic"), "alembic"),
]
binaries = []
hiddenimports = [
    # SQLAlchemy async + drivers (imported by string/dialect name at runtime).
    "aiosqlite",
    "asyncpg",
    "greenlet",
    "sqlalchemy.dialects.sqlite.aiosqlite",
    "sqlalchemy.dialects.postgresql.asyncpg",
    # LLM SDKs are imported lazily inside functions (agent.py) — pin them so the
    # frozen binary can still talk to a real provider, not just --provider mock.
    "anthropic",
    "openai",
    # tree-sitter core + the three grammars construction.py imports by name.
    "tree_sitter",
    "tree_sitter_python",
    "tree_sitter_javascript",
    "tree_sitter_typescript",
    # sentinel_worker submodules that are only reached via string dialect names
    # or otherwise not statically visible from the entry wrapper.
    "sentinel_worker.local_cli",
]

# --collect-all equivalents: pull in the compiled grammar shared libs + any
# package data. tree_sitter itself ships a compiled core extension.
for mod in (
    "tree_sitter",
    "tree_sitter_python",
    "tree_sitter_javascript",
    "tree_sitter_typescript",
):
    d, b, h = collect_all(mod)
    datas += d
    binaries += b
    hiddenimports += h

a = Analysis(
    # Freeze the wrapper (entry.py), NOT local_cli.py directly: PyInstaller runs
    # the entry as __main__, and local_cli.py uses package-relative imports.
    [str(Path(SPECPATH) / "entry.py")],  # noqa: F821 — SPECPATH injected by PyInstaller
    pathex=[str(WORKER_DIR)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Trim: the engine never renders plots / notebooks / GUI.
        "tkinter",
        "matplotlib",
        "PIL",
        "IPython",
        "pytest",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="sentinel-local",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,  # macOS signing done post-build in CI (see build-engine.yml).
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="sentinel-local",
)
