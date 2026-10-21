#!/bin/bash
# The bundle baseline (platform-neutral refactor, Task 1): what a built MacVPN.app looks like from the outside,
# frozen on 1.4.0, so a later build can be compared with it (Task 19).
#
#   scripts/bundle-baseline.sh [--write] <path/to/MacVPN.app>
#
# Without --write it compares the bundle with scripts/bundle-baseline/1.4.0/ and exits 1 on any difference (a
# unified diff per file); --write (re)writes the baseline from the bundle. Use a scripts/build-dmg.sh build
# (dist/MacVPN.app). BUNDLE_BASELINE_DIR overrides the baseline directory.
#
# The files:
#   Info.plist.xml      plutil -convert xml1 of Contents/Info.plist, every value equal to the bundle's version
#                       (CFBundleShortVersionString, CFBundleVersion) replaced by @VERSION@
#   bundle-files.txt    every file and symlink in the bundle (find . -type f -o -type l | sort), with its size (a
#                       symlink with its target). The sizes of the two Mach-O binaries (Contents/MacOS/MacVPN,
#                       Contents/Resources/root/mvpn) are recorded, but a compare only reports their change: code
#                       changes move them; what they link and what they are entitled to is checked below.
#   otool-L.txt         otool -L of Contents/MacOS/MacVPN and Contents/Resources/root/mvpn, per architecture
#                       (lipo -thin)
#   entitlements.txt    codesign -d --entitlements of both (none: the bundle is signed without entitlements)
#   tauri-config.json   the Tauri config the bundler used for macOS: app/src-tauri/tauri.conf.json with
#                       tauri.macos.conf.json merged over it when present (JSON merge patch, RFC 7386), the version
#                       replaced by @VERSION@. A compare sorts the object keys on both sides first: the merge appends
#                       the keys that moved to tauri.macos.conf.json (Task 10), and key order means nothing to Tauri.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
export PATH="/opt/homebrew/bin:$PATH"

die() { echo "error: $*" >&2; exit 2; }

WRITE=0
APP=""
for arg in "$@"; do
  case "$arg" in
    --write) WRITE=1 ;;
    -*) die "unknown option $arg" ;;
    *) [ -z "$APP" ] || die "one bundle only"; APP="$arg" ;;
  esac
done
[ -n "$APP" ] || die "usage: scripts/bundle-baseline.sh [--write] <MacVPN.app>"
[ -d "$APP/Contents" ] || die "not an app bundle: $APP"
APP=$(cd "$APP" && pwd -P)
BASELINE="${BUNDLE_BASELINE_DIR:-$ROOT/scripts/bundle-baseline/1.4.0}"
BINARIES=(Contents/MacOS/MacVPN Contents/Resources/root/mvpn)

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$APP/Contents/Info.plist")
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid CFBundleShortVersionString: $VERSION"

# --- Info.plist -------------------------------------------------------------------------------------------------
/usr/bin/plutil -convert xml1 -o - "$APP/Contents/Info.plist" \
  | sed "s|<string>${VERSION//./\\.}</string>|<string>@VERSION@</string>|g" >"$OUT/Info.plist.xml"
grep -qF "$VERSION" "$OUT/Info.plist.xml" && die "Info.plist has the version $VERSION in a value not normalized"

# --- files ------------------------------------------------------------------------------------------------------
(
  cd "$APP"
  find . -type f -o -type l | LC_ALL=C sort | while IFS= read -r path; do
    if [ -L "$path" ]; then
      printf '%s -> %s\n' "$path" "$(readlink "$path")"
    else
      printf '%s %s\n' "$path" "$(stat -f %z "$path")"
    fi
  done
) >"$OUT/bundle-files.txt"

# --- otool -L ---------------------------------------------------------------------------------------------------
for bin in "${BINARIES[@]}"; do
  [ -f "$APP/$bin" ] || die "missing $bin"
  for arch in $(lipo -archs "$APP/$bin" | tr ' ' '\n' | LC_ALL=C sort); do
    lipo -thin "$arch" -output "$OUT/thin" "$APP/$bin"
    echo "$bin ($arch):"
    otool -L "$OUT/thin" | tail -n +2
    rm -f "$OUT/thin"
  done
done >"$OUT/otool-L.txt"

# --- entitlements -----------------------------------------------------------------------------------------------
for bin in "${BINARIES[@]}"; do
  echo "$bin:"
  # stdout only: stderr names the local path ("Executable=…").
  codesign -d --entitlements - --xml "$APP/$bin" 2>/dev/null || echo "(codesign failed)"
  echo
done >"$OUT/entitlements.txt"

# --- the merged Tauri config ------------------------------------------------------------------------------------
node -e '
const fs = require("fs");
const [base, overlay] = process.argv.slice(1);
// RFC 7386: objects merge, null removes, anything else replaces.
const merge = (target, patch) => {
  if (patch === null || typeof patch !== "object" || Array.isArray(patch)) return patch;
  const out = target !== null && typeof target === "object" && !Array.isArray(target) ? { ...target } : {};
  for (const [k, v] of Object.entries(patch)) {
    if (v === null) delete out[k];
    else out[k] = merge(out[k], v);
  }
  return out;
};
let config = JSON.parse(fs.readFileSync(base, "utf8"));
if (fs.existsSync(overlay)) config = merge(config, JSON.parse(fs.readFileSync(overlay, "utf8")));
if (typeof config.version === "string") config.version = "@VERSION@";
process.stdout.write(JSON.stringify(config, null, 2) + "\n");
' "$ROOT/app/src-tauri/tauri.conf.json" "$ROOT/app/src-tauri/tauri.macos.conf.json" >"$OUT/tauri-config.json"

FILES=(Info.plist.xml bundle-files.txt otool-L.txt entitlements.txt tauri-config.json)

if [ "$WRITE" = 1 ]; then
  mkdir -p "$BASELINE"
  for f in "${FILES[@]}"; do cp "$OUT/$f" "$BASELINE/$f"; done
  echo "wrote the bundle baseline of $VERSION to ${BASELINE#"$ROOT"/}"
  exit 0
fi

# The Mach-O binaries' sizes are reported, not compared.
mask_sizes() {
  local pattern
  pattern=$(printf '%s|' "${BINARIES[@]}"); pattern="${pattern%|}"
  sed -E "s#^(\./(${pattern//./\\.})) [0-9]+\$#\1 <size>#" "$1"
}
# Objects with their keys sorted (recursively), arrays in order.
canonical_json() {
  node -e '
const fs = require("fs");
const sort = (v) => Array.isArray(v) ? v.map(sort)
  : v !== null && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sort(v[k])])) : v;
process.stdout.write(JSON.stringify(sort(JSON.parse(fs.readFileSync(process.argv[1], "utf8"))), null, 2) + "\n");
' "$1"
}
FAILED=0
for f in "${FILES[@]}"; do
  [ -f "$BASELINE/$f" ] || die "missing baseline file $BASELINE/$f (run with --write on a 1.4.0 build)"
  if [ "$f" = bundle-files.txt ]; then
    if ! diff -u --label "baseline/$f" --label "bundle/$f" <(mask_sizes "$BASELINE/$f") <(mask_sizes "$OUT/$f"); then
      FAILED=1
    fi
    for bin in "${BINARIES[@]}"; do
      was=$(sed -n "s#^\./${bin//./\\.} \([0-9]*\)\$#\1#p" "$BASELINE/$f")
      now=$(sed -n "s#^\./${bin//./\\.} \([0-9]*\)\$#\1#p" "$OUT/$f")
      [ "$was" = "$now" ] || echo "note: $bin size $was -> $now bytes"
    done
  elif [ "$f" = tauri-config.json ]; then
    if ! diff -u --label "baseline/$f" --label "bundle/$f" <(canonical_json "$BASELINE/$f") <(canonical_json "$OUT/$f"); then
      FAILED=1
    fi
  elif ! diff -u --label "baseline/$f" --label "bundle/$f" "$BASELINE/$f" "$OUT/$f"; then
    FAILED=1
  fi
done
if [ "$FAILED" = 1 ]; then
  echo "the bundle differs from the baseline in ${BASELINE#"$ROOT"/}" >&2
  exit 1
fi
echo "bundle baseline: identical (${BASELINE#"$ROOT"/})"
