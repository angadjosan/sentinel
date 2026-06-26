#!/usr/bin/env bash
set -euo pipefail

REPO="sentineldev/sentinel"
INSTALL_DIR="${SENTINEL_INSTALL_DIR:-$HOME/.local/bin}"
BIN="$INSTALL_DIR/sentinel"

detect_platform() {
  local uname_out="${SENTINEL_FAKE_UNAME:-$(uname -s) $(uname -m)}"
  local os arch
  case "$uname_out" in
    Darwin*) os="darwin" ;;
    Linux*)  os="linux" ;;
    *) echo "Unsupported OS: $uname_out" >&2; exit 1 ;;
  esac
  case "$uname_out" in
    *arm64*|*aarch64*) arch="arm64" ;;
    *x86_64*|*x64*)    arch="x64" ;;
    *) echo "Unsupported arch: $uname_out" >&2; exit 1 ;;
  esac
  echo "sentinel-${os}-${arch}"
}

main() {
  local asset url
  asset="$(detect_platform)"
  url="https://github.com/${REPO}/releases/latest/download/${asset}"
  echo "Installing Sentinel ($asset)..."
  echo "  from: $url"

  if [ "${SENTINEL_NO_DOWNLOAD:-0}" = "1" ]; then
    echo "[dry-run] would download $asset to $BIN"
    return 0
  fi

  mkdir -p "$INSTALL_DIR"
  curl -fsSL "$url" -o "$BIN.tmp"
  curl -fsSL "$url.sha256" -o "$BIN.sha256" 2>/dev/null || true
  if [ -f "$BIN.sha256" ]; then
    (cd "$INSTALL_DIR" && shasum -a 256 -c "$(basename "$BIN").sha256" 2>/dev/null) \
      || { echo "Checksum verification failed" >&2; exit 1; }
    rm -f "$BIN.sha256"
  fi
  mv "$BIN.tmp" "$BIN"
  chmod +x "$BIN"
  echo "Installed to $BIN"

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo; echo "Add to PATH:  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
  esac
  echo "Run: sentinel --help"
}

main "$@"
