#!/usr/bin/env bash
# Build the frozen Sentinel engine (onedir) with PyInstaller.
#
# Produces:  worker/pyinstaller/dist/sentinel-local/sentinel-local  (the launcher)
# which is what @sentineldev/engine-<os>-<cpu>/bin/sentinel-local points at.
#
# Usage:
#   worker/pyinstaller/build.sh            # build into a throwaway venv
#   PY=python3.12 worker/pyinstaller/build.sh
#
# Local prerequisites: a Python >=3.12 on PATH (or set $PY). This script creates
# an ISOLATED venv so the frozen bundle only contains the worker's real deps
# (avoid a shared/conda env leaking unrelated packages into the binary).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKER_DIR="$(cd "$HERE/.." && pwd)"
PY="${PY:-python3}"

BUILD_VENV="$HERE/.build-venv"
echo "==> Creating isolated build venv at $BUILD_VENV"
"$PY" -m venv "$BUILD_VENV"
# shellcheck disable=SC1091
source "$BUILD_VENV/bin/activate"

python -m pip install --upgrade pip wheel >/dev/null
echo "==> Installing worker + pyinstaller"
pip install "$WORKER_DIR" pyinstaller

echo "==> Freezing engine"
cd "$HERE"
pyinstaller sentinel-engine.spec --noconfirm --clean

BIN="$HERE/dist/sentinel-local/sentinel-local"
echo "==> Built: $BIN"
"$BIN" --help >/dev/null 2>&1 || true
echo "==> Done. Package the dist/sentinel-local/ dir as @sentineldev/engine-<os>-<cpu>."
