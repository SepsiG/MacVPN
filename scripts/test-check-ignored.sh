#!/bin/bash
# Tests the source scan of scripts/check-ignored.sh (--scan): every form of an OS-specific test ignore is found
# (windows, unix, target_os, target_family, inside not/any/all, over several lines), an ignore on every OS and an
# OS cfg without ignore are not, and the repository's sources have none.
set -euo pipefail
cd "$(dirname "$0")/.."
SCRIPT="$PWD/scripts/check-ignored.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   - $1"; }
nok() { FAIL=$((FAIL+1)); echo "FAIL - $1"; }
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else nok "$desc"; fi; }

check "bash -n" bash -n "$SCRIPT"
if command -v shellcheck >/dev/null 2>&1; then
  check "shellcheck" shellcheck "$SCRIPT" "$0"
else
  echo "skip - shellcheck is not installed"
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/test-check-ignored.XXXXXXXX")"
trap 'rm -rf "${WORK:?}"' EXIT
found() { printf '%s\n' "$1" >"$WORK/t.rs"; ! "$SCRIPT" --scan "$WORK" >/dev/null; }
clean() { printf '%s\n' "$1" >"$WORK/t.rs"; "$SCRIPT" --scan "$WORK" >/dev/null; }

check "windows" found '#[cfg_attr(windows, ignore = "x")]'
check "unix" found '#[cfg_attr(unix, ignore)]'
check "not(unix)" found '#[cfg_attr(not(unix), ignore = "x")]'
check "target_os" found '#[cfg_attr(target_os = "windows", ignore = "x")]'
check "not(target_os)" found '#[cfg_attr(not(target_os = "macos"), ignore = "x")]'
check "target_family" found '#[cfg_attr(target_family = "windows", ignore)]'
check "any(...)" found '#[cfg_attr(any(windows, target_os = "linux"), ignore = "x")]'
check "over several lines" found $'#[cfg_attr(\n    windows,\n    ignore = "phase 2"\n)]'
check "an ignore everywhere is fine" clean '#[ignore = "fixture writer"]'
check "an OS cfg without ignore is fine" clean $'#[cfg_attr(windows, allow(dead_code))]\n#[ignore = "x"]'
check "the sources have none" "$SCRIPT" --scan crates app examples

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
