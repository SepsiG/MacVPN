#!/bin/bash
# Tests scripts/win-smoke.sh without a Windows machine: its argument handling, and (WINVPN_REMOTE_PRINT=1, which
# scripts/win-remote.sh honours) the remote commands it would run, in order, without waiting for a result.
set -euo pipefail
cd "$(dirname "$0")/.."
SCRIPT="$PWD/scripts/win-smoke.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   - $1"; }
nok() { FAIL=$((FAIL+1)); echo "FAIL - $1"; }
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else nok "$desc"; fi; }
has() { grep -qF -- "$2" <<<"$1"; }
lacks() { ! grep -qF -- "$2" <<<"$1"; }
before() { local a b; a=$(grep -nF -- "$2" <<<"$1" | head -1 | cut -d: -f1); b=$(grep -nF -- "$3" <<<"$1" | head -1 | cut -d: -f1); [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; }

check "bash -n" bash -n "$SCRIPT"
if command -v shellcheck >/dev/null 2>&1; then
  check "shellcheck" shellcheck "$SCRIPT" "$0"
else
  echo "skip - shellcheck is not installed"
fi

print() { WINVPN_SSH=winvpn-dev@example.invalid WINVPN_REMOTE_DIR=winvpn-work-slot9 WINVPN_REMOTE_PRINT=1 "$SCRIPT" "$@" 2>&1; }

# Arguments: en (default) or hu, nothing else; no remote command for a refused one.
for bad in de 'en;rm' '' 'en hu'; do
  # shellcheck disable=SC2086 # 'en hu' is two arguments on purpose
  OUT="$(print $bad || true)"
  if [ -z "$bad" ]; then continue; fi
  check "refuses '$bad' with the usage line" has "$OUT" "usage: scripts/win-smoke.sh [en|hu]"
  check "refuses '$bad' before any remote command" lacks "$OUT" "schtasks"
done
check "exit 1 for a bad language" bash -c "! WINVPN_SSH=a@b WINVPN_REMOTE_PRINT=1 '$SCRIPT' de >/dev/null 2>&1"
check "needs WINVPN_SSH" bash -c "! env -u WINVPN_SSH WINVPN_REMOTE_PRINT=1 '$SCRIPT' en 2>&1 | grep -q schtasks"
check "refuses WINVPN_SSH without a user" bash -c "! WINVPN_SSH=example.invalid WINVPN_REMOTE_PRINT=1 '$SCRIPT' en 2>&1 | grep -q schtasks"
check "refuses a bad WINVPN_REMOTE_DIR" bash -c "! WINVPN_SSH=a@b WINVPN_REMOTE_DIR='x;rm' WINVPN_REMOTE_PRINT=1 '$SCRIPT' en 2>&1 | grep -q schtasks"

EN="$(print)"
HU="$(print hu)"
check "default language en" has "$EN" "SMOKE_LANG=en scripts/smoke-manage.sh"
check "hu" has "$HU" "SMOKE_LANG=hu scripts/smoke-manage.sh"
check "the session check lists the sessions with query.exe" has "$EN" "{ query.exe user 2>/dev/null || true; } | grep -qiE '^[ >]winvpn-dev[[:space:]]'"
check "the session check's message" has "$EN" "no interactive session of winvpn-dev: log on as winvpn-dev at the VM console"
check "builds the debug app with the embedded UI" has "$EN" "cargo build --locked --target x86_64-pc-windows-msvc -p macvpn-app --features custom-protocol"
check "builds the UI first" has "$EN" "(cd app/ui && npm ci && npm run build) &&"
check "never a release build" lacks "$EN" "--release"
check "the session check comes before the build" before "$EN" "query.exe user" "cargo build"
check "the build comes before the task" before "$EN" "cargo build" "schtasks /Create"
check "the task: one-shot, interactive only, as the SSH user" has "$EN" "schtasks /Create /F /SC ONCE /ST 00:00 /IT /RU winvpn-dev /TN WinVPN-smoke-"
check "the task: no stored password" lacks "$EN" "/RP"
check "the task runs smoke-manage.sh in the remote checkout" has "$EN" "cd ~/winvpn-work-slot9 && SMOKE_LANG=en scripts/smoke-manage.sh > target/smoke.log 2>&1"
check "the task records the run's own exit code" has "$EN" "echo \$? > target/smoke.result"
check "the task's exit code is not escaped" lacks "$EN" "echo \\\$?"
check "the task through Git Bash" has "$EN" "\"C:\\Program Files\\Git\\bin\\bash.exe\" -lc"
check "no MSYS path conversion of /Create" has "$EN" "MSYS_NO_PATHCONV=1 schtasks /Create"
check "the task is started" has "$EN" "schtasks /Run /TN WinVPN-smoke-"
check "the task is deleted" has "$EN" "schtasks /Delete /F /TN WinVPN-smoke-"
check "the log is printed" has "$EN" "cat target/smoke.log"
check "the exit code is the run's" has "$EN" "exit \$(cat target/smoke.result 2>/dev/null || echo 1)"
check "one name for the task" test "$(grep -oE 'WinVPN-smoke-[0-9]+' <<<"$EN" | sort -u | wc -l | tr -d ' ')" = 1
check "only the build syncs" test "$(grep -cF 'print only: nothing is synced' <<<"$EN")" = 1
check "print mode does not poll" lacks "$EN" "test -f target/smoke.result"
check "the installed service is never touched" lacks "$EN" "sc "

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
