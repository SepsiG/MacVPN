#!/bin/bash
# Tests scripts/win-remote.sh without a Windows machine: WINVPN_REMOTE_PRINT=1 prints each remote command instead of
# running it over SSH (nothing is copied). Checks that `test` runs with CI=1 (as the CI job) and that `msi` runs
# scripts/build-msi.sh without CI and with WINVPN_WIX_NO_ICE=1 (build-msi.sh refuses that pair, so CI stays strict).
set -euo pipefail
cd "$(dirname "$0")/.."
SCRIPT="$PWD/scripts/win-remote.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   - $1"; }
nok() { FAIL=$((FAIL+1)); echo "FAIL - $1"; }
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else nok "$desc"; fi; }
has() { grep -qF -- "$2" <<<"$1"; }
lacks() { ! grep -qF -- "$2" <<<"$1"; }

check "bash -n" bash -n "$SCRIPT"
if command -v shellcheck >/dev/null 2>&1; then
  check "shellcheck" shellcheck "$SCRIPT" "$0"
else
  echo "skip - shellcheck is not installed"
fi

print() { WINVPN_SSH=nobody@example.invalid WINVPN_REMOTE_PRINT=1 "$SCRIPT" "$@"; }

# LA-4: one folder name in the home, never a path that leaves it or a hidden folder (git clean -fdx runs there).
for bad in "" "." ".." "/tmp/x" "/" "a/b" "a/.." "../x" "./x" ".ssh" "a b" "x;rm" "a\$b" "~" "a/"; do
  check "refuses WINVPN_REMOTE_DIR='$bad'" bash -c "! WINVPN_SSH=a@b WINVPN_REMOTE_DIR='$bad' WINVPN_REMOTE_PRINT=1 '$SCRIPT' sync >/dev/null 2>&1"
done
for good in winvpn-work winvpn-work-slot1 a.b_c-1; do
  check "accepts WINVPN_REMOTE_DIR=$good" bash -c "WINVPN_SSH=a@b WINVPN_REMOTE_DIR='$good' WINVPN_REMOTE_PRINT=1 '$SCRIPT' sync >/dev/null 2>&1"
done

# LA-5: no forwarding to the machine, whatever ~/.ssh/config says (every ssh and scp call uses SSH_OPTS).
for opt in "-o ForwardAgent=no" "-o ForwardX11=no" "-o ClearAllForwardings=yes"; do
  check "ssh options: $opt" grep -qF -- "$opt" "$SCRIPT"
done

TEST="$(print test)"
LAST="$(tail -n 1 <<<"$TEST")"
check "test: the CI windows job's set" has "$LAST" "cargo test --locked --target x86_64-pc-windows-msvc"
check "test: runs with CI=1" has "$LAST" "CI=1"

NOSYNC="$(print run-nosync 'echo polled')"
check "run-nosync: does not sync" lacks "$NOSYNC" "nothing is synced"
check "run-nosync: runs the command in the checkout" has "$(tail -n 1 <<<"$NOSYNC")" "echo polled"
check "run-nosync: with CI=1" has "$(tail -n 1 <<<"$NOSYNC")" "CI=1"
RUN="$(print run 'echo built')"
check "run: syncs first" has "$RUN" "nothing is synced"

MSI="$(print msi --arch x64)"
LAST="$(tail -n 1 <<<"$MSI")"
check "msi: runs build-msi.sh with its arguments" has "$LAST" "scripts/build-msi.sh --arch x64"
check "msi: with WINVPN_WIX_NO_ICE=1" has "$LAST" "WINVPN_WIX_NO_ICE=1"
check "msi: without CI" lacks "$LAST" "CI=1"
check "msi: says that ICE validation is skipped" has "$MSI" "ICE validation is skipped"
# shellcheck disable=SC2016 # the script path is expanded by this shell on purpose; the rest is literal
check "msi: no command for a bad argument" bash -c "! WINVPN_SSH=x@y WINVPN_REMOTE_PRINT=1 '$SCRIPT' msi --arch 'x64;rm' >/dev/null 2>&1"

# build-msi.sh keeps refusing the pair in CI.
# shellcheck disable=SC2016 # the literal line of build-msi.sh
check "build-msi.sh refuses WINVPN_WIX_NO_ICE under CI" grep -qF 'if [ -n "${CI:-}" ] && [ -n "$NO_ICE" ]; then' scripts/build-msi.sh

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
