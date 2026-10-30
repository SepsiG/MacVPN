#!/bin/bash
# The Linux smoke run in linvpn-dev's desktop session (LinVPN plan, Task 23), started from the Mac: builds the debug
# app with the embedded UI on the VM (a plain job), then runs scripts/smoke-manage.sh as a `desktop` job of
# scripts/lin-remote.sh (systemd-run --user in the logged-in desktop session, which may be locked) and prints its log;
# the exit code is the run's. The run uses the debug app's sandbox and fakes only: never the real keyring, the
# installed LinVPN or a real connection.
#
#   scripts/lin-smoke.sh [en|hu]
#
# Environment: LINVPN_SSH and LINVPN_REMOTE_DIR as for scripts/lin-remote.sh; LINVPN_REMOTE_PRINT=1 prints the remote
# scripts instead of running them (scripts/test-lin-smoke.sh); LINVPN_SMOKE_WAIT: seconds for the run (default 1800);
# CARGO_BUILD_JOBS: passed on to the VM's build (a VM shared with other runs).
set -euo pipefail
cd "$(dirname "$0")/.."

usage() { echo "usage: scripts/lin-smoke.sh [en|hu]" >&2; exit 1; }
[ $# -le 1 ] || usage
LANG_ARG="${1:-en}"
[[ "$LANG_ARG" =~ ^(en|hu)$ ]] || usage
[ -n "${LINVPN_SSH:-}" ] || { echo "error: set LINVPN_SSH=linvpn-dev@<VM address>" >&2; exit 1; }
WAIT="${LINVPN_SMOKE_WAIT:-1800}"
[[ "$WAIT" =~ ^[0-9]+$ ]] || { echo "error: LINVPN_SMOKE_WAIT: seconds" >&2; exit 1; }
JOBS="${CARGO_BUILD_JOBS:-}"
[[ "$JOBS" =~ ^[0-9]*$ ]] || { echo "error: CARGO_BUILD_JOBS: a number" >&2; exit 1; }

scripts/lin-remote.sh run "(cd app/ui && npm ci && npm run build) && ${JOBS:+CARGO_BUILD_JOBS=$JOBS }cargo build --locked -p macvpn-app --features custom-protocol"
LINVPN_JOB_WAIT="$WAIT" scripts/lin-remote.sh desktop "SMOKE_LANG=$LANG_ARG scripts/smoke-manage.sh"
