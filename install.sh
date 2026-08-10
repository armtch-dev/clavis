#!/usr/bin/env bash
# clavis installer — macOS & Linux.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/armtch-dev/clavis/main/install.sh | bash
# or from a checkout:
#   ./install.sh
set -euo pipefail

REPO="https://github.com/armtch-dev/clavis.git"
BIN="clavis"

# Colours only on a TTY, and never when NO_COLOR is set.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_ACC=$'\033[36m' C_DIM=$'\033[90m' C_OK=$'\033[32m'
  C_ERR=$'\033[31m' C_WRN=$'\033[33m' C_BLD=$'\033[1m' C_OFF=$'\033[0m'
else
  C_ACC="" C_DIM="" C_OK="" C_ERR="" C_WRN="" C_BLD="" C_OFF=""
fi

say()  { printf '%s▸ %s%s\n' "$C_ACC" "$*" "$C_OFF"; }
ok()   { printf '  %s✓%s %s\n' "$C_OK" "$C_OFF" "$*"; }
dim()  { printf '    %s%s%s\n' "$C_DIM" "$*" "$C_OFF"; }
warn() { printf '%s⚠ %s%s\n' "$C_WRN" "$*" "$C_OFF"; }
fail() { printf '  %s✗ %s%s\n' "$C_ERR" "$*" "$C_OFF" >&2; exit 1; }
rule() { printf '%s──────────────────────────────────────────────────────────%s\n' "$C_DIM" "$C_OFF"; }

printf '\n%s⚷ clavis%s %s— SSH connection manager with an encrypted vault%s\n' \
  "$C_BLD$C_ACC" "$C_OFF" "$C_DIM" "$C_OFF"
rule

# confirm asks on the terminal directly: under `curl | bash` stdin is the
# script itself, so /dev/tty is the only place a real answer can come from.
# No terminal (CI) → no prompt, caller falls back to the manual-install hint.
confirm() {
  [ -r /dev/tty ] && [ -w /dev/tty ] || return 1
  printf '  %s? %s [y/N] %s' "$C_WRN" "$1" "$C_OFF" > /dev/tty
  local ans=""
  IFS= read -r ans < /dev/tty || return 1
  case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# require <cmd> <desc> <brew-pkg> <apt-pkg> <dnf-pkg> <pacman-pkg>
# Offers to install a missing prerequisite via the platform's package
# manager — always with confirmation, never silently.
require() {
  local cmd=$1 desc=$2 brew=$3 apt=$4 dnf=$5 pac=$6 install=""
  command -v "$cmd" >/dev/null 2>&1 && return 0
  if [ "$(uname -s)" = Darwin ]; then
    command -v brew >/dev/null 2>&1 && install="brew install $brew"
  elif command -v apt-get >/dev/null 2>&1; then install="sudo apt-get install -y $apt"
  elif command -v dnf >/dev/null 2>&1; then install="sudo dnf install -y $dnf"
  elif command -v pacman >/dev/null 2>&1; then install="sudo pacman -S --noconfirm $pac"
  fi
  if [ -n "$install" ] && confirm "$desc is missing — install it now with '$install'"; then
    say "installing $desc"
    $install
    command -v "$cmd" >/dev/null 2>&1 && return 0
  fi
  return 1
}

say "checking prerequisites"
case "$(uname -s)" in
  Darwin) ok "macOS $(sw_vers -productVersion 2>/dev/null || echo '')" ;;
  Linux)  ok "Linux $(uname -r)" ;;
  *) fail "unsupported OS: $(uname -s) (clavis supports macOS and Linux)" ;;
esac
require git "git" git git git git || fail "git is required (macOS: install Homebrew or the Xcode CLT first)"
ok "git $(git --version 2>/dev/null | awk '{print $3}')"
require go "Go" go golang-go golang go || fail "Go is required (https://go.dev/dl — 1.26+)"
ok "$(go version | cut -d' ' -f3-)"
require ssh "OpenSSH client" openssh openssh-client openssh-clients openssh || fail "OpenSSH client (ssh) is required"
ok "$(ssh -V 2>&1 | cut -d, -f1)"

# Build from a local checkout when possible: the dir this script lives in,
# or the current dir. Otherwise clone (needs repo access if private).
say "locating source"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-/nonexistent}")" 2>/dev/null && pwd || true)"
SRC=""
CLEANUP=""
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/go.mod" ] && grep -q "armtch-dev/clavis" "$SCRIPT_DIR/go.mod" 2>/dev/null; then
  SRC="$SCRIPT_DIR"
  ok "local checkout: $SRC"
elif [ -f "go.mod" ] && grep -q "armtch-dev/clavis" go.mod 2>/dev/null; then
  SRC="$PWD"
  ok "local checkout: $SRC"
else
  SRC="$(mktemp -d "${TMPDIR:-/tmp}/clavis-install.XXXXXX")"
  CLEANUP="$SRC"
  git clone --quiet --depth 1 "$REPO" "$SRC"
  ok "cloned $REPO"
  dim "commit $(cd "$SRC" && git rev-parse --short HEAD)"
fi

say "compiling"
dim "first install fetches Go dependencies — may take a minute"
START=$(date +%s)
( cd "$SRC" && go build -trimpath -ldflags="-s -w" -o "$BIN" . )
SIZE="$(du -h "$SRC/$BIN" | cut -f1 | tr -d ' ')"
ok "built in $(( $(date +%s) - START ))s (${SIZE} binary)"

# Pick an install dir: /usr/local/bin if writable, else ~/.local/bin.
say "installing"
DEST="/usr/local/bin"
if [ ! -w "$DEST" ]; then
  dim "$DEST is not writable — using ~/.local/bin instead"
  DEST="$HOME/.local/bin"
  mkdir -p "$DEST"
fi
install -m 0755 "$SRC/$BIN" "$DEST/$BIN"
[ -n "$CLEANUP" ] && rm -rf "$CLEANUP"
ok "$DEST/$BIN ($("$DEST/$BIN" version))"

rule
printf '%s✓ done.%s next steps:\n' "$C_OK$C_BLD" "$C_OFF"
printf '  %s%-16s%s %sfirst run: create a new vault, or restore from your clavis git repo%s\n' \
  "$C_ACC" "$BIN" "$C_OFF" "$C_DIM" "$C_OFF"
printf '  %s%-16s%s %shealth check: key, vault, git, ssh%s\n' \
  "$C_ACC" "$BIN doctor" "$C_OFF" "$C_DIM" "$C_OFF"
printf '  %s%-16s%s %simport your existing hosts%s\n' \
  "$C_ACC" "$BIN import" "$C_OFF" "$C_DIM" "$C_OFF"
printf '%syour master key is shown exactly once — store it somewhere safe, off this machine.%s\n' \
  "$C_DIM" "$C_OFF"
case ":$PATH:" in
  *":$DEST:"*) ;;
  *) warn "$DEST is not on your PATH — add: export PATH=\"$DEST:\$PATH\"" ;;
esac
