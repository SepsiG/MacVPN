#!/bin/bash
# Regenerates the Swift-written compatibility fixtures with the real MacVPNCore (0.4.0) encoders.
# Never touches ~/Library/Application Support: everything is written under a fresh mktemp directory and
# then copied here. Usage: crates/core/tests/fixtures/swift/generate.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../../../../.." && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/macvpn-fixtures.XXXXXX")"
trap 'rm -rf "$work"' EXIT
swiftc -O -module-name FixtureGen "$repo"/legacy/swift/Sources/MacVPNCore/*.swift "$here/generator/main.swift" -o "$work/gen"
# The list() order depends on the process locale (localizedCaseInsensitiveCompare): pin it.
"$work/gen" "$here" "$work/scratch" -AppleLocale en_US -AppleLanguages '(en)'
"$work/gen" "$here" "$work/scratch" -AppleLocale hu_HU -AppleLanguages '(hu)'
