#!/bin/bash
# Tests scripts/lin-smoke.sh without a VM: its arguments, and (LINVPN_REMOTE_PRINT=1, which scripts/lin-remote.sh
# honours) the remote scripts it would run, in order.
set -euo pipefail
cd "$(dirname "$0")/.."
SCRIPT="$PWD/scripts/lin-smoke.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   - $1"; }
nok() { FAIL=$((FAIL+1)); echo "FAIL - $1"; }
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else nok "$desc"; fi; }
has() { grep -qF -- "$2" <<<"$1"; }
lacks() { ! grep -qF -- "$2" <<<"$1"; }
before() { local a b; a=$(grep -nF -- "$2" <<<"$1" | head -1 | cut -d: -f1); b=$(grep -nF -- "$3" <<<"$1" | head -1 | cut -d: -f1); [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; }

check "bash -n" bash -n "$SCRIPT"
if command -v shellcheck >/dev/null 2>&1; then check "shellcheck" shellcheck "$SCRIPT" "$0"; else echo "skip - shellcheck is not installed"; fi

print() { LINVPN_SSH=linvpn-dev@example.invalid LINVPN_REMOTE_DIR=linvpn-work-slot9 LINVPN_REMOTE_PRINT=1 "$SCRIPT" "$@" 2>&1; }

for bad in de 'en;rm'; do
  OUT="$(print "$bad" || true)"
  check "refuses '$bad' with the usage line" has "$OUT" "usage: scripts/lin-smoke.sh [en|hu]"
  check "refuses '$bad' before any remote command" lacks "$OUT" "smoke-manage.sh"
done
check "needs LINVPN_SSH" bash -c "! env -u LINVPN_SSH LINVPN_REMOTE_PRINT=1 '$SCRIPT' en 2>&1 | grep -q smoke-manage"

EN="$(print)"
HU="$(print hu)"
check "default language en" has "$EN" "SMOKE_LANG=en scripts/smoke-manage.sh"
check "hu" has "$HU" "SMOKE_LANG=hu scripts/smoke-manage.sh"
check "builds the debug app with the embedded UI" has "$EN" "cargo build --locked -p macvpn-app --features custom-protocol"
check "builds the UI first" has "$EN" "(cd app/ui && npm ci && npm run build) &&"
check "never a release build" lacks "$EN" "--release"
check "the run is a desktop job" has "$EN" "systemd-run --user"
check "the desktop session is checked" has "$EN" "loginctl show-user"
check "the build comes before the run" before "$EN" "cargo build" "systemd-run --user"
JOBS="$(CARGO_BUILD_JOBS=4 print)"
check "passes CARGO_BUILD_JOBS on to the build" has "$JOBS" "&& CARGO_BUILD_JOBS=4 cargo build --locked"
check "refuses a CARGO_BUILD_JOBS that is not a number" bash -c "! CARGO_BUILD_JOBS='4;x' LINVPN_SSH=x@example.invalid LINVPN_REMOTE_PRINT=1 '$SCRIPT' en 2>&1 | grep -q smoke-manage"
nowhere() { ! grep -qE -- "$2" <<<"$1"; }
check "never sudo, never the installed app" nowhere "$EN" 'sudo|/usr/bin/linvpn'

# The NetworkManager step (L-b Task 25): its script is shipped with the run, the run expects its verdict, and the
# driver reaches NetworkManager and PackageKit only through stand-ins.
MANAGE="$(cat scripts/smoke-manage.sh)"
DRIVER="$(cat app/src-tauri/src/platform/smoke/linux.rs)"
check "the step's script is there" test -f scripts/smoke/nm.js
check "the run expects the step's verdict" has "$MANAGE" "MacVPN smoke: nm: ok"
check "the run checks no smoke plan record is in the real data folder" has "$MANAGE" 'LinVPN/nm"'
check "the driver asks neither NetworkManager nor PackageKit" nowhere "$DRIVER" 'lin_for_tests|packagekit|nm_client|zbus'

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
