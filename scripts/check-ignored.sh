#!/bin/bash
# No test may be ignored on one OS only: the ignored tests of the workspace's test set must be exactly the entries of
# scripts/ignored-everywhere.txt that exist on this OS (the tests ignored on every OS they are built for, e.g. the
# fixture writers, or a Windows-only manual test). An entry whose test is not built on this OS is skipped here and
# checked on the other one.
#
#   scripts/check-ignored.sh [CARGO ARGS...]            compare (e.g. --target x86_64-pc-windows-msvc)
#   scripts/check-ignored.sh --write [CARGO ARGS...]    rewrite the list from this OS (only when a test is ignored
#                                                       everywhere; entries of tests not built here are kept)
#   scripts/check-ignored.sh --scan PATH...             only the source scan for OS-specific ignores
#                                                       (scripts/test-check-ignored.sh)
set -euo pipefail
cd "$(dirname "$0")/.."

# Files under PATH... with an ignore that depends on the OS: a `cfg_attr` whose condition names `windows`, `unix`,
# `target_os` or `target_family` (also inside not/any/all, also over several lines) and ignores the test.
os_ignores() {
  # shellcheck disable=SC2016 # a Perl program: $ARGV is Perl's
  find "$@" -name '*.rs' -not -path '*/target/*' -not -path '*/node_modules/*' -print0 \
    | xargs -0 perl -0777 -ne 'while (/cfg_attr\(\s*(?:(?:not|any|all)\(\s*)*(?:windows|unix|target_os\s*=\s*"[^"]*"|target_family\s*=\s*"[^"]*")[^\]]*?\bignore\b/gs) { print "$ARGV\n" }' \
    | { grep -v 'crates/app-core/tests/cfg_rule.rs' || true; } | LC_ALL=C sort -u
}
if [ "${1:-}" = --scan ]; then
  shift
  found="$(os_ignores "$@")"
  [ -z "$found" ] || { printf '%s\n' "$found"; exit 1; }
  exit 0
fi

WRITE=0
if [ "${1:-}" = --write ]; then WRITE=1; shift; fi
LIST_FILE=scripts/ignored-everywhere.txt
# The CI windows job's test set (and the release's), the app included.
PACKAGES=(-p macvpn-core -p macvpn-app-core -p macvpn-platform-api -p macvpn-platform-win -p macvpn-helper -p macvpn-winsys -p macvpn-control-client -p macvpn-app)
# tests all|ignored [CARGO ARGS...]: the test names (without their module path's binary), sorted, once each.
tests() {
  local which=$1
  shift
  local only=()
  [ "$which" = ignored ] && only=(--ignored)
  CI=1 cargo test --locked "$@" "${PACKAGES[@]}" --lib --tests -- --list ${only[@]+"${only[@]}"} </dev/null 2>/dev/null \
    | sed -n 's/: test$//p' | LC_ALL=C sort -u
}
ALL="$(tests all "$@")"
IGNORED="$(tests ignored "$@")"
[ -n "$ALL" ] || { echo "FAIL: no tests listed (did the build fail?)"; exit 1; }
KNOWN="$(LC_ALL=C sort -u "$LIST_FILE")"
# The entries of the list whose tests exist on this OS, and those that do not.
HERE="$(LC_ALL=C comm -12 <(printf '%s\n' "$KNOWN") <(printf '%s\n' "$ALL"))"
ELSEWHERE="$(LC_ALL=C comm -23 <(printf '%s\n' "$KNOWN") <(printf '%s\n' "$ALL"))"
if [ "$WRITE" = 1 ]; then
  printf '%s\n' "$IGNORED" "$ELSEWHERE" | grep . | LC_ALL=C sort -u >"$LIST_FILE"
  echo "wrote $LIST_FILE ($(grep -c . "$LIST_FILE") tests)"
  exit 0
fi
if ! diff -u <(printf '%s\n' "$HERE" | grep . || true) <(printf '%s\n' "$IGNORED" | grep . || true); then
  echo "FAIL: the ignored tests differ from $LIST_FILE (a test is ignored on this OS only, or the list is stale)"
  exit 1
fi
FOUND="$(os_ignores crates app examples)"
if [ -n "$FOUND" ]; then
  printf '%s\n' "$FOUND"
  echo "FAIL: an OS-specific ignore is left in the sources"
  exit 1
fi
echo "OK: $(printf '%s\n' "$IGNORED" | grep -c . || true) ignored tests here, all in $LIST_FILE ($(printf '%s\n' "$ELSEWHERE" | grep -c . || true) more are not built on this OS)"
