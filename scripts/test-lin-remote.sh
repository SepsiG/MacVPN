#!/bin/bash
# Tests scripts/lin-remote.sh without a VM: LINVPN_REMOTE_PRINT=1 prints each remote script instead of running it
# over SSH (nothing is copied, nothing waits). Checks the job wrapper (detached, logged, exit code recorded), that
# `test` runs the CI linux job's set under dbus-run-session with CI=1, that `desktop` goes through systemd-run --user
# after the desktop-session check, and the argument checks.
set -euo pipefail
cd "$(dirname "$0")/.."
SCRIPT="$PWD/scripts/lin-remote.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   - $1"; }
nok() { FAIL=$((FAIL+1)); echo "FAIL - $1"; }
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else nok "$desc"; fi; }
has() { grep -qF -- "$2" <<<"$1"; }
lacks() { ! grep -qF -- "$2" <<<"$1"; }
line() { grep -qxF -- "$2" <<<"$1"; }
before() { local a b; a=$(grep -nF -- "$2" <<<"$1" | head -1 | cut -d: -f1); b=$(grep -nF -- "$3" <<<"$1" | head -1 | cut -d: -f1); [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; }

check "bash -n" bash -n "$SCRIPT"
if command -v shellcheck >/dev/null 2>&1; then
  check "shellcheck" shellcheck "$SCRIPT" "$0"
else
  echo "skip - shellcheck is not installed"
fi

print() { LINVPN_SSH=linvpn-dev@example.invalid LINVPN_REMOTE_DIR=linvpn-work-slot9 LINVPN_REMOTE_PRINT=1 "$SCRIPT" "$@" 2>&1; }

check "usage without arguments" bash -c "! '$SCRIPT' >/dev/null 2>&1"
check "needs LINVPN_SSH" bash -c "! env -u LINVPN_SSH LINVPN_REMOTE_PRINT=1 '$SCRIPT' sync 2>&1 | grep -q 'git fetch'"
check "refuses a bad LINVPN_REMOTE_DIR" bash -c "! LINVPN_SSH=a@b LINVPN_REMOTE_DIR='x;rm' LINVPN_REMOTE_PRINT=1 '$SCRIPT' sync >/dev/null 2>&1"
# LA-4: one folder name in the home, never a path that leaves it or a hidden folder (git clean -fdx runs there).
for bad in "" "." ".." "/tmp/x" "/" "a/b" "a/.." "../x" "./x" ".ssh" "a b" "x;rm" "a\$b" "~" "a/"; do
  check "refuses LINVPN_REMOTE_DIR='$bad'" bash -c "! LINVPN_SSH=a@b LINVPN_REMOTE_DIR='$bad' LINVPN_REMOTE_PRINT=1 '$SCRIPT' sync >/dev/null 2>&1"
done
for good in linvpn-work linvpn-work-slot9 linvpn-work-lafix a.b_c-1; do
  check "accepts LINVPN_REMOTE_DIR=$good" bash -c "LINVPN_SSH=a@b LINVPN_REMOTE_DIR='$good' LINVPN_REMOTE_PRINT=1 '$SCRIPT' sync >/dev/null 2>&1"
done
check "refuses an unknown command" bash -c "! LINVPN_SSH=a@b LINVPN_REMOTE_PRINT=1 '$SCRIPT' frobnicate >/dev/null 2>&1"

SYNC="$(print sync)"
check "sync: says print mode copies nothing" has "$SYNC" "print only: nothing is synced"

TEST="$(print test)"
check "test: syncs first" has "$TEST" "print only: nothing is synced"
check "test: the CI linux job's set" has "$TEST" "cargo test --locked -p macvpn-core -p macvpn-app-core -p macvpn-platform-api"
check "test: under a private session bus" has "$TEST" "dbus-run-session -- cargo test"
check "test: CI=1" has "$TEST" "export CI=1"
check "test: detached, not in the SSH session" has "$TEST" "setsid --fork"
check "test: the job's log" has "$TEST" ".lin-jobs/"
check "test: the exit code is recorded" has "$TEST" '.rc.tmp'
check "test: never --target (the VM's own architecture)" lacks "$TEST" "--target"

RUN="$(print run 'cargo build --locked -p macvpn-platform-linux')"
check "run: syncs first" has "$RUN" "print only: nothing is synced"
check "run: the command in the job script" has "$RUN" "cargo build --locked -p macvpn-platform-linux"
NOSYNC="$(print run-nosync 'echo polled')"
check "run-nosync: does not sync" lacks "$NOSYNC" "nothing is synced"
check "run-nosync: runs the command" has "$NOSYNC" "echo polled"
check "job: the command runs in a subshell (an exit in it still records the exit code)" line "$NOSYNC" "("

DESK="$(print desktop 'cargo test --locked -p macvpn-platform-linux -- --ignored')"
check "desktop: checks the graphical session first" has "$DESK" "loginctl show-user"
check "desktop: through the user manager" has "$DESK" "systemd-run --user"
check "desktop: the unit is collected" has "$DESK" "--collect"
check "desktop: its output into the job log" has "$DESK" "StandardOutput=append:"
check "desktop: session check before the start" before "$DESK" "loginctl show-user" "systemd-run --user"
check "desktop: never sudo" lacks "$DESK" "sudo"

check "put: refuses a name with .." bash -c "! LINVPN_SSH=a@b LINVPN_REMOTE_PRINT=1 '$SCRIPT' put /tmp ../x >/dev/null 2>&1"
check "fetch: refuses a path with .." bash -c "! LINVPN_SSH=a@b LINVPN_REMOTE_PRINT=1 '$SCRIPT' fetch ../etc /tmp/x >/dev/null 2>&1"
check "attach: refuses a bad job id" bash -c "! LINVPN_SSH=a@b LINVPN_REMOTE_PRINT=1 '$SCRIPT' attach 'j1;rm' >/dev/null 2>&1"

# LA-5: no forwarding to the VM, whatever ~/.ssh/config says (every ssh and scp call uses SSH_OPTS).
for opt in "-o ForwardAgent=no" "-o ForwardX11=no" "-o ClearAllForwardings=yes"; do
  check "ssh options: $opt" grep -qF -- "$opt" "$SCRIPT"
done
check "every ssh and scp call uses SSH_OPTS" bash -c "! grep -En '^[^#]*\\b(ssh|scp) ' '$SCRIPT' | grep -v 'SSH_OPTS\\[@\\]' | grep -Ev 'echo \"scp'"

check "no address in the script" bash -c "! grep -En '([0-9]{1,3}\.){3}[0-9]{1,3}' '$SCRIPT'"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
