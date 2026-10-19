#!/bin/bash
# Builds MacVPN.app (Tauri 2, universal: arm64 + x86_64) and packs it into dist/MacVPN-<version>.dmg.
# Ad-hoc signature, no Developer ID (the v0.4.0 updater checks the bundle ID, the version, the symlinks and
# `codesign --verify --strict`; see docs/superpowers/specs/2026-10-18-rust-port-design.md, section 4).
#
#   1. UI: npm ci && npm run build (app/ui/dist, embedded by the custom-protocol feature)
#   2. app: tauri build --target universal-apple-darwin (cargo for both architectures, lipo, the bundle with
#      app/src-tauri/Info.plist merged into its Info.plist)
#   3. root layer: mvpn for both architectures, lipo, into Contents/Resources/root with VERSION (crates/mvpn)
#      release gate: the app binary must not contain setInspectable, developerExtrasEnabled, MACVPN_SANDBOX_HOME
#      or MACVPN_SMOKE (Web Inspector, the sandbox and the smoke driver are debug-only)
#   4. icon (Resources/AppIcon.icns), Info.plist checked key by key
#   5. signing: mvpn, then the bundle, both ad-hoc with the hardened runtime (dyld ignores DYLD_* and loads no
#      foreign library) and no entitlements; codesign --verify --strict; no symlink pointing out of the bundle
#   6. DMG: the app and an /Applications symlink (hdiutil, at most 3 attempts)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
export PATH="$HOME/.cargo/bin:$PATH"

die() { echo "error: $*" >&2; exit 1; }
step() { echo "==> $*"; }

TAURI_CONF=app/src-tauri/tauri.conf.json
PLIST_SRC=app/src-tauri/Info.plist
EXPECTED_REPO="SepsiG/MacVPN"
EXPECTED_REPO_ID=1422472799
ARCHS=(arm64 x86_64)
RUST_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)

# --- Versions: one value everywhere ---------------------------------------------------------------------------
json_version() { /usr/bin/plutil -extract version raw -o - "$1"; }
VERSION=$(json_version "$TAURI_CONF")
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid version in ${TAURI_CONF}: $VERSION"
CARGO_VERSION=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)
UI_VERSION=$(json_version app/ui/package.json)
[ "$CARGO_VERSION" = "$VERSION" ] || die "Cargo.toml workspace version $CARGO_VERSION != $TAURI_CONF $VERSION"
[ "$UI_VERSION" = "$VERSION" ] || die "app/ui/package.json version $UI_VERSION != $TAURI_CONF $VERSION"
# The updater only follows the pinned numeric repository ID (against repo-jacking); without it the app would
# never update.
REPO_ID=$(/usr/libexec/PlistBuddy -c "Print :MacVPNUpdateRepoID" "$PLIST_SRC" 2>/dev/null || true)
[ "$REPO_ID" = "$EXPECTED_REPO_ID" ] || die "MacVPNUpdateRepoID in $PLIST_SRC is '$REPO_ID', expected $EXPECTED_REPO_ID"
ROOT_VERSION=$(tr -d '[:space:]' < crates/mvpn/VERSION)
[[ "$ROOT_VERSION" =~ ^[1-9][0-9]*$ ]] || die "invalid root layer version in crates/mvpn/VERSION"
step "MacVPN $VERSION (root layer $ROOT_VERSION), universal: ${ARCHS[*]}"

for t in "${RUST_TARGETS[@]}"; do
  rustup target list --installed | grep -qx "$t" || die "missing Rust target $t (rustup target add $t)"
done

# --- 1. UI ------------------------------------------------------------------------------------------------------
step "UI (npm ci, npm run build)"
(cd app/ui && npm ci --no-audit --no-fund && npm run build)
[ -s app/ui/dist/index.html ] || die "app/ui/dist/index.html is missing"

# --- 2. App -----------------------------------------------------------------------------------------------------
step "app (tauri build, universal-apple-darwin, custom-protocol)"
# The UI is built above; the Tauri CLI must not build it again.
(cd app/ui && npm run tauri -- build --ci --target universal-apple-darwin --bundles app --features custom-protocol \
  --config '{"build":{"beforeBuildCommand":""}}')
TAURI_APP="target/universal-apple-darwin/release/bundle/macos/MacVPN.app"
[ -d "$TAURI_APP" ] || die "not found: $TAURI_APP"
EXECUTABLE=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$TAURI_APP/Contents/Info.plist")
[ "$EXECUTABLE" = MacVPN ] || die "CFBundleExecutable is '$EXECUTABLE', expected MacVPN (mainBinaryName)"

# --- 3. Root layer ----------------------------------------------------------------------------------------------
step "root layer (mvpn)"
for t in "${RUST_TARGETS[@]}"; do
  cargo build --release --locked -p mvpn --target "$t"
done
MVPN_UNIVERSAL="target/universal-apple-darwin/release/mvpn"
mkdir -p "$(dirname "$MVPN_UNIVERSAL")"
lipo -create -output "$MVPN_UNIVERSAL" "target/${RUST_TARGETS[0]}/release/mvpn" "target/${RUST_TARGETS[1]}/release/mvpn"

step "architectures"
check_archs() { # $1 = binary
  local archs a
  archs=$(lipo -archs "$1")
  for a in "${ARCHS[@]}"; do
    case " $archs " in *" $a "*) ;; *) die "missing architecture ($a) in $1 (has: $archs)" ;; esac
  done
  echo "  $1: $archs"
}
check_archs "$TAURI_APP/Contents/MacOS/MacVPN"
check_archs "$MVPN_UNIVERSAL"

# Release gate: nothing of the debug-only paths may reach the release binary (Web Inspector, the sandbox and the
# smoke driver are compiled in only with debug_assertions). grep -a scans both slices of the universal binary.
step "release gate (no debug-only code in the app binary)"
for marker in setInspectable developerExtrasEnabled MACVPN_SANDBOX_HOME MACVPN_SMOKE; do
  if LC_ALL=C grep -a -q -F "$marker" "$TAURI_APP/Contents/MacOS/MacVPN"; then
    die "the release binary contains '$marker' (a debug-only path reached the release build)"
  fi
done

# --- 4. Bundle --------------------------------------------------------------------------------------------------
step "bundle"
APP="dist/MacVPN.app"
rm -rf dist
mkdir -p dist
/usr/bin/ditto "$TAURI_APP" "$APP"
RES="$APP/Contents/Resources"
mkdir -p "$RES/root"
install -m 755 "$MVPN_UNIVERSAL" "$RES/root/mvpn"
install -m 644 crates/mvpn/VERSION "$RES/root/VERSION"
# The icon under the Swift app's name (Resources/AppIcon.icns, CFBundleIconFile AppIcon) instead of Tauri's copy.
rm -f "$RES/icon.icns"
install -m 644 Resources/AppIcon.icns "$RES/AppIcon.icns"
PLIST="$APP/Contents/Info.plist"
pb() { /usr/libexec/PlistBuddy -c "$1" "$PLIST"; }
pb "Set :CFBundleIconFile AppIcon"
# Tauri's defaults that the app does not need (no Carbon; the Swift app's plist did not have them).
pb "Delete :LSRequiresCarbon" 2>/dev/null || true

step "Info.plist"
expect() { # key, expected value (plutil's raw output: true/false for booleans)
  local got
  got=$(/usr/bin/plutil -extract "$1" raw -o - "$PLIST" 2>/dev/null) || die "Info.plist: missing $1"
  [ "$got" = "$2" ] || die "Info.plist: $1 is '$got', expected '$2'"
}
expect CFBundleIdentifier local.macvpn
expect CFBundleName MacVPN
expect CFBundleDisplayName MacVPN
expect CFBundleExecutable MacVPN
expect CFBundlePackageType APPL
expect CFBundleShortVersionString "$VERSION"
expect CFBundleVersion "$VERSION"
expect LSMinimumSystemVersion 14.0
expect LSUIElement true
expect CFBundleDevelopmentRegion en
expect CFBundleLocalizations.0 en
expect CFBundleLocalizations.1 hu
[ "$(/usr/bin/plutil -extract CFBundleLocalizations raw -o - "$PLIST")" = 2 ] || die "Info.plist: CFBundleLocalizations is not [en, hu]"
expect MacVPNUpdateRepo "$EXPECTED_REPO"
expect MacVPNUpdateRepoID "$EXPECTED_REPO_ID"
[ "$(/usr/bin/plutil -type MacVPNUpdateRepoID "$PLIST")" = string ] || die "Info.plist: MacVPNUpdateRepoID must be a string"
expect CFBundleIconFile AppIcon
[ -x "$APP/Contents/MacOS/MacVPN" ] || die "the executable is missing"
[ -s "$RES/AppIcon.icns" ] || die "the icon is missing"
# Contents/Resources/root holds exactly mvpn and VERSION (what the root installer installs).
ROOT_FILES=$(find "$RES/root" -mindepth 1 -maxdepth 1 -exec basename {} \; | LC_ALL=C sort | tr '\n' ' ')
[ "$ROOT_FILES" = "VERSION mvpn " ] || die "unexpected files in Resources/root: $ROOT_FILES"
[ "$(tr -d '[:space:]' < "$RES/root/VERSION")" = "$ROOT_VERSION" ] || die "Resources/root/VERSION"

# --- 5. Signing -------------------------------------------------------------------------------------------------
step "signing (ad-hoc, hardened runtime, no entitlements)"
# The app is signed with the hardened runtime too: the Keychain items' ACL trusts this signature, so no process of
# the same user may inject a library into it (DYLD_INSERT_LIBRARIES) or attach to it. It needs no entitlement: no
# JIT or unsigned memory in this process (WKWebView's JIT runs in Apple's WebContent process), no library
# validation exception (nothing is loaded from outside the bundle and the system), no Apple Events (osascript is
# a separate process), and NSWorkspace, UNUserNotificationCenter and SMAppService need none.
codesign --force --sign - --options runtime --identifier local.macvpn.mvpn "$RES/root/mvpn"
codesign --force --sign - --options runtime --identifier local.macvpn "$APP"
codesign --verify --strict --verbose=2 "$APP"
codesign --verify --strict --deep --verbose=2 "$APP"
codesign --verify --strict --verbose=2 "$RES/root/mvpn"
runtime_flags() { codesign -dv "$1" 2>&1 | sed -n 's/^CodeDirectory .*flags=\([^ ]*\).*/\1/p'; }
for signed in "$APP" "$RES/root/mvpn"; do
  FLAGS=$(runtime_flags "$signed")
  case "$FLAGS" in *runtime*) ;; *) die "$signed is not signed with the hardened runtime (flags: $FLAGS)" ;; esac
  echo "  $signed: flags=$FLAGS"
  ENTITLEMENTS=$(codesign -d --entitlements - --xml "$signed" 2>/dev/null || true)
  [ -z "$ENTITLEMENTS" ] || die "$signed has entitlements (none are needed): $ENTITLEMENTS"
done
"$RES/root/mvpn" version >/dev/null || die "the signed mvpn does not run"

# No symlink may point out of the bundle (the updater refuses such a bundle).
BUNDLE_REAL=$(cd "$APP" && pwd -P)
while IFS= read -r -d '' link; do
  target=$(/bin/realpath "$link" 2>/dev/null) || die "dangling symlink in the bundle: $link"
  case "$target" in "$BUNDLE_REAL"/*) ;; *) die "symlink pointing out of the bundle: $link -> $target" ;; esac
done < <(find "$APP" -type l -print0)

# --- 6. DMG -----------------------------------------------------------------------------------------------------
step "DMG"
# The version comes from the finished bundle's Info.plist (as the updater sees it).
DMG_VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$PLIST")
DMG="dist/MacVPN-$DMG_VERSION.dmg"
STAGE="dist/dmg"
mkdir -p "$STAGE"
/usr/bin/ditto "$APP" "$STAGE/MacVPN.app"
ln -s /Applications "$STAGE/Applications"
# hdiutil create sometimes fails transiently ("Resource busy"): at most 3 attempts.
for attempt in 1 2 3; do
  if hdiutil create -volname "MacVPN" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null; then
    break
  fi
  [ "$attempt" = 3 ] && die "hdiutil create failed 3 times"
  echo "hdiutil create failed (attempt ${attempt}), retrying in 5 s" >&2
  sleep 5
done
rm -rf "$STAGE"
hdiutil verify -quiet "$DMG" || die "hdiutil verify failed"
echo "Done: $ROOT/$DMG ($(du -h "$DMG" | cut -f1 | tr -d ' '))"
