#!/bin/sh
# Stoffel CLI installer.
#
#   curl -fsSL https://get.stoffelmpc.com | sh
#   curl -fsSL https://get.stoffelmpc.com | sh -s -- --version 0.1.0
#
# Env overrides:
#   STOFFEL_VERSION       pin a version (same as --version)
#   STOFFEL_INSTALL_DIR   install location (default: ~/.local/bin)
set -eu

REPO="Stoffel-Labs/stoffel"
BIN="stoffel"
INSTALL_DIR="${STOFFEL_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${STOFFEL_VERSION:-}"

err()  { echo "stoffel-install: error: $*" >&2; exit 1; }
info() { echo "stoffel-install: $*"; }

# --- args (only --version) ---
while [ $# -gt 0 ]; do
  case "$1" in
    --version)   VERSION="${2:-}"; shift 2 ;;
    --version=*) VERSION="${1#--version=}"; shift ;;
    *) err "unknown argument: $1" ;;
  esac
done

# --- downloader (curl or wget) ---
if command -v curl >/dev/null 2>&1; then
  dl()    { curl -fsSL "$1" -o "$2"; }
  dlout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  dl()    { wget -qO "$2" "$1"; }
  dlout() { wget -qO- "$1"; }
else
  err "need curl or wget installed"
fi

# --- platform detection ---
os="$(uname -s)"; arch="$(uname -m)"
case "$os" in
  Linux)  os_part="unknown-linux-gnu" ;;
  Darwin) os_part="apple-darwin" ;;
  *)      err "unsupported OS '$os' (Linux and macOS are supported)" ;;
esac
case "$arch" in
  x86_64|amd64)  arch_part="x86_64" ;;
  arm64|aarch64) arch_part="aarch64" ;;
  *)             err "unsupported architecture '$arch'" ;;
esac
TARGET="${arch_part}-${os_part}"

# --- resolve release tag/version ---
if [ -n "$VERSION" ]; then
  TAG="cli-v${VERSION}"
else
  info "resolving latest CLI release..."
  TAG="$(dlout "https://api.github.com/repos/${REPO}/releases" 2>/dev/null \
    | grep '"tag_name"' \
    | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/' \
    | grep '^cli-v' | head -n 1 || true)"
  [ -n "$TAG" ] || err "no cli-v* release found for ${REPO} (has a CLI release been cut yet?)"
  VERSION="${TAG#cli-v}"
fi

TARBALL="stoffel-${VERSION}-${TARGET}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${TAG}"
info "installing ${BIN} ${VERSION} (${TARGET})"

# --- temp workspace ---
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
cd "$tmp"

# --- download ---
dl "${BASE}/${TARBALL}" "$TARBALL" \
  || err "no prebuilt binary for ${TARGET} in ${TAG} (your platform may not be built yet — try building from source)"
dl "${BASE}/SHA256SUMS" "SHA256SUMS" || err "could not download SHA256SUMS"

# --- checksum verification ---
if command -v sha256sum >/dev/null 2>&1; then sha="sha256sum"
elif command -v shasum >/dev/null 2>&1; then sha="shasum -a 256"
else err "need sha256sum or shasum to verify the download"
fi
expected="$(grep " ${TARBALL}\$" SHA256SUMS | awk '{print $1}' | head -n 1)"
[ -n "$expected" ] || err "no checksum listed for ${TARBALL}"
actual="$($sha "$TARBALL" | awk '{print $1}')"
[ "$expected" = "$actual" ] || err "checksum mismatch for ${TARBALL}"
info "checksum verified"

# --- extract & install ---
tar xzf "$TARBALL"
src="stoffel-${VERSION}-${TARGET}/${BIN}"
[ -f "$src" ] || src="$(find . -type f -name "$BIN" | head -n 1)"
[ -n "${src:-}" ] && [ -f "$src" ] || err "binary '${BIN}' not found in archive"

mkdir -p "$INSTALL_DIR"
install -m 0755 "$src" "$INSTALL_DIR/${BIN}" 2>/dev/null \
  || { cp "$src" "$INSTALL_DIR/${BIN}" && chmod 0755 "$INSTALL_DIR/${BIN}"; }
info "installed to ${INSTALL_DIR}/${BIN}"

# --- PATH hint ---
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) : ;;
  *)
    echo ""
    echo "  ${INSTALL_DIR} is not on your PATH. Add it with:"
    echo "    echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.profile && . ~/.profile"
    echo ""
    ;;
esac

# --- confirm ---
if "$INSTALL_DIR/${BIN}" --version >/dev/null 2>&1; then
  info "$("$INSTALL_DIR/${BIN}" --version)"
fi
info "done — run '${BIN} --help' to get started"
