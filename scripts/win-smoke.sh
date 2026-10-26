#!/bin/bash
# The Windows smoke run in the SSH user's desktop session (2b plan, Task 20), started from the Mac: checks that the
# user (winvpn-dev) has an interactive session on the Windows machine, builds the debug app there (the embedded UI,
# `custom-protocol`), then runs scripts/smoke-manage.sh through a one-shot scheduled task that runs only in that
# logged-on desktop session (/IT: no password is stored; a standard user may create it for itself), waits for its
# result, prints its log and deletes the task. The user must be logged on at the machine's console (the session may
# be locked or disconnected). The run uses the debug app's sandbox and fakes only: never the installed WinVPN
# Service, the vault in Credential Manager or a real connection.
#
#   scripts/win-smoke.sh [en|hu]
#
# Environment: WINVPN_SSH and WINVPN_REMOTE_DIR as for scripts/win-remote.sh; WINVPN_REMOTE_PRINT=1 prints the remote
# commands instead of running them (scripts/test-win-smoke.sh) and does not wait. WINVPN_SMOKE_WAIT: seconds to wait
# for the result (default 1500).
set -euo pipefail
cd "$(dirname "$0")/.."

usage() { echo "usage: scripts/win-smoke.sh [en|hu]" >&2; exit 1; }
[ $# -le 1 ] || usage
LANG_ARG="${1:-en}"
[[ "$LANG_ARG" =~ ^(en|hu)$ ]] || usage
SSH_DEST="${WINVPN_SSH:-}"
[ -n "$SSH_DEST" ] || { echo "error: set WINVPN_SSH=user@host of the Windows test machine" >&2; exit 1; }
# The task runs as the SSH user, in that user's own desktop session.
RUN_AS="${SSH_DEST%%@*}"
[[ "$SSH_DEST" == *@* && "$RUN_AS" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "error: WINVPN_SSH: user@host" >&2; exit 1; }
REMOTE_DIR="${WINVPN_REMOTE_DIR:-winvpn-work}"
[[ "$REMOTE_DIR" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] || { echo "error: WINVPN_REMOTE_DIR: letters, digits, . _ - and /" >&2; exit 1; }
WAIT="${WINVPN_SMOKE_WAIT:-1500}"
[[ "$WAIT" =~ ^[0-9]+$ ]] || { echo "error: WINVPN_SMOKE_WAIT: seconds" >&2; exit 1; }
TASK="WinVPN-smoke-$$"
PRINT="${WINVPN_REMOTE_PRINT:-}"

# 1. A desktop session first (no build without one). `query.exe user` lists the console and RDP sessions (not SSH),
# active or disconnected; its exit code is 1 even when it lists them (and the remote shell has pipefail), so only its
# lines count. `.exe` explicitly: Git
# Bash would run a file named `query` before `query.exe`.
scripts/win-remote.sh run-nosync "{ query.exe user 2>/dev/null || true; } | grep -qiE '^[ >]${RUN_AS}[[:space:]]' || { echo 'no interactive session of $RUN_AS: log on as $RUN_AS at the VM console (it may then be locked or disconnected), then run again'; exit 3; }"

# 2. The debug app with the embedded UI, for the CI target (the checkout's warm build directory).
scripts/win-remote.sh run '(cd app/ui && npm ci && npm run build) && cargo build --locked --target x86_64-pc-windows-msvc -p macvpn-app --features custom-protocol'

# 3. The one-shot task in that session: Git Bash runs the smoke run in the checkout; `$?` is the task shell's.
RUNNER="\"C:\\Program Files\\Git\\bin\\bash.exe\" -lc \"cd ~/$REMOTE_DIR && SMOKE_LANG=$LANG_ARG scripts/smoke-manage.sh > target/smoke.log 2>&1; echo \$? > target/smoke.result\""
scripts/win-remote.sh run-nosync "rm -f target/smoke.result target/smoke.log && MSYS_NO_PATHCONV=1 schtasks /Create /F /SC ONCE /ST 00:00 /IT /RU $RUN_AS /TN $TASK /TR '$RUNNER' && MSYS_NO_PATHCONV=1 schtasks /Run /TN $TASK"

# 4. Its result, then the log; the task is deleted either way.
if [ -z "$PRINT" ]; then
  waited=0
  until scripts/win-remote.sh run-nosync 'test -f target/smoke.result' >/dev/null 2>&1; do
    if [ "$waited" -ge "$WAIT" ]; then
      echo "no result after ${WAIT} s; the task's state:" >&2
      scripts/win-remote.sh run-nosync "MSYS_NO_PATHCONV=1 schtasks /Query /TN $TASK /V /FO LIST; MSYS_NO_PATHCONV=1 schtasks /Delete /F /TN $TASK >/dev/null" >&2 || true
      exit 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
fi
scripts/win-remote.sh run-nosync "cat target/smoke.log; MSYS_NO_PATHCONV=1 schtasks /Delete /F /TN $TASK >/dev/null; exit \$(cat target/smoke.result 2>/dev/null || echo 1)"
