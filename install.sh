#!/usr/bin/env bash
# clavis installer — macOS & Linux.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/armtch-dev/clavis/main/install.sh | bash
# or from a checkout:
#   ./install.sh
set -euo pipefail

REPO="https://github.com/armtch-dev/clavis.git"
BIN="clavis"

say()  { printf '\033[36m▸ %s\033[0m\n' "$*"; }
fail() { printf '\033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

case "$(uname -s)" in
  Darwin|Linux) ;;
  *) fail "unsupported OS: $(uname -s) (clavis supports macOS and Linux)" ;;
esac

command -v git >/dev/null 2>&1 || fail "git is required"
command -v go  >/dev/null 2>&1 || fail "Go is required (https://go.dev/dl — 1.26+)"
command -v ssh >/dev/null 2>&1 || fail "OpenSSH client (ssh) is required"

# Build from the current checkout if we're inside one; otherwise clone.
SRC=""
CLEANUP=""
if [ -f "go.mod" ] && grep -q "armtch-dev/clavis" go.mod 2>/dev/null; then
  SRC="$PWD"
  say "building from local checkout: $SRC"
else
  SRC="$(mktemp -d "${TMPDIR:-/tmp}/clavis-install.XXXXXX")"
  CLEANUP="$SRC"
  say "cloning $REPO"
  git clone --quiet --depth 1 "$REPO" "$SRC"
fi

say "compiling"
( cd "$SRC" && go build -trimpath -ldflags="-s -w" -o "$BIN" . )

# Pick an install dir: /usr/local/bin if writable, else ~/.local/bin.
DEST="/usr/local/bin"
if [ ! -w "$DEST" ]; then
  DEST="$HOME/.local/bin"
  mkdir -p "$DEST"
fi
install -m 0755 "$SRC/$BIN" "$DEST/$BIN"
[ -n "$CLEANUP" ] && rm -rf "$CLEANUP"

say "installed: $DEST/$BIN ($("$DEST/$BIN" version))"
case ":$PATH:" in
  *":$DEST:"*) ;;
  *) printf '\033[33m⚠ %s is not on your PATH — add: export PATH="%s:$PATH"\033[0m\n' "$DEST" "$DEST" ;;
esac
say "run '$BIN' to set up your vault (your master key is shown once — store it safely)"
