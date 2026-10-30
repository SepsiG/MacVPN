#!/bin/bash
# Builds MacVPN.app (Tauri 2, universal: arm64 + x86_64) and packs it into dist/MacVPN-<version>.dmg.
# Ad-hoc signature, no Developer ID (the v0.4.0 updater checks the bundle ID, the version, the symlinks and
# `codesign --verify --strict`; see docs/superpowers/specs/2026-10-18-rust-port-design.md, section 4).
#
#   1. UI: npm ci && npm run build (app/ui/dist, embedded by the custom-protocol feature)
#   2. app: tauri build --target universal-apple-darwin (cargo for both architectures, lipo, the bundle with
#      app/src-tauri/Info.plist merged into its Info.plist)
#   3. root layer: mvpn for both architectures, lipo, into Contents/Resources/root with VERSION (crates/helper)
#      release gate: the app binary must not contain setInspectable, developerExtrasEnabled, MACVPN_SANDBOX_HOME
#      or MACVPN_SMOKE (Web Inspector, the sandbox and the smoke driver are debug-only); the vault's SQLCipher
#      must use CommonCrypto (no libcrypto/libssl linked, no OpenSSL inside); mvpn must contain no SQLite/SQLCipher
#   4. icon (Resources/AppIcon.icns), THIRD-PARTY-NOTICES.txt (checked against its generator), Info.plist checked
#      key by key, the Resources listing
#   5. signing: mvpn, then the bundle, both ad-hoc with the hardened runtime (dyld ignores DYLD_* and loads no
#      foreign library) and no entitlements; codesign --verify --strict; no symlink pointing out of the bundle
#   6. DMG: the app and an /Applications symlink (hdiutil, at most 3 attempts)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
export PATH="$HOME/.cargo/bin:$PATH"
# The vault's SQLCipher (libsqlite3-sys, bundled-sqlcipher) uses CommonCrypto only when no OpenSSL location is set;
# with one, it silently links that libcrypto dylib (e.g. Homebrew's). The build script does not track these
# variables for rebuilds, so none may leak in from the environment (spike report A.1/A.5). The gate after the app
# build checks the result.
for v in OPENSSL_DIR OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR OPENSSL_STATIC OPENSSL_LIBS; do
  unset "$v" "AARCH64_APPLE_DARWIN_$v" "X86_64_APPLE_DARWIN_$v"
done

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
ROOT_VERSION=$(tr -d '[:space:]' < crates/helper/VERSION)
[[ "$ROOT_VERSION" =~ ^[1-9][0-9]*$ ]] || die "invalid root layer version in crates/helper/VERSION"
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
  cargo build --release --locked -p macvpn-helper --target "$t"
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

# The vault database: SQLCipher must use CommonCrypto in both slices (spike report A.5). "SQLite format" marks the
# linked SQLite; SQLCipher's provider name is compiled in only for the provider it was built with: "commoncrypto"
# (SQLCIPHER_CRYPTO_CC) or "openssl". The lower-case "openssl" is matched case-sensitively: the app's own texts
# mention "Homebrew's OpenSSL".
step "release gate (SQLCipher with CommonCrypto, no OpenSSL; no SQLite in mvpn)"
APP_BIN="$TAURI_APP/Contents/MacOS/MacVPN"
if otool -L "$APP_BIN" | grep -Eiq 'libcrypto|libssl|openssl'; then
  die "the app binary links OpenSSL: $(otool -L "$APP_BIN" | grep -Ei 'libcrypto|libssl|openssl' | tr -s ' \t' ' ')"
fi
SLICES=$(mktemp -d)
trap 'rm -rf "$SLICES"' EXIT
for a in "${ARCHS[@]}"; do
  lipo -thin "$a" -output "$SLICES/MacVPN-$a" "$APP_BIN"
  # libcrypto's own texts (its OPENSSLDIR line, the openssl.cnf name), not the word "openssl": the app's texts name the
  # openssl package (LinVPN's PKCS#12 import).
  if LC_ALL=C grep -a -q -F -e OPENSSLDIR -e openssl.cnf -e libcrypto "$SLICES/MacVPN-$a"; then
    die "the app binary ($a) contains OpenSSL (an OPENSSL_* variable reached the SQLCipher build?)"
  fi
  if LC_ALL=C grep -a -q -F 'SQLite format' "$SLICES/MacVPN-$a"; then
    LC_ALL=C grep -a -q -F commoncrypto "$SLICES/MacVPN-$a" \
      || die "the app binary ($a) contains SQLCipher without the CommonCrypto provider"
    echo "  MacVPN ($a): SQLCipher with CommonCrypto, no OpenSSL"
  else
    # The app opens the vault on both architectures: each slice must carry SQLCipher (with CommonCrypto).
    die "the app binary ($a) contains no SQLCipher"
  fi
done
rm -rf "$SLICES"
trap - EXIT
for marker in sqlcipher 'SQLite format'; do
  if LC_ALL=C grep -a -i -q -F "$marker" "$MVPN_UNIVERSAL"; then
    die "mvpn contains '$marker' (the vault code must not reach the root layer)"
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
install -m 644 crates/helper/VERSION "$RES/root/VERSION"
# The icon under the Swift app's name (Resources/AppIcon.icns, CFBundleIconFile AppIcon) instead of Tauri's copy.
rm -f "$RES/icon.icns"
install -m 644 Resources/AppIcon.icns "$RES/AppIcon.icns"
# The licences of what the bundle contains (SQLCipher, SQLite, the Rust crates, the web view's JS packages):
# generated by scripts/third-party-notices.mjs and committed; it must match what the generator writes now.
[ -s THIRD-PARTY-NOTICES.txt ] || die "THIRD-PARTY-NOTICES.txt is missing (node scripts/third-party-notices.mjs)"
node scripts/third-party-notices.mjs --check || die "THIRD-PARTY-NOTICES.txt is out of date"
install -m 644 THIRD-PARTY-NOTICES.txt "$RES/THIRD-PARTY-NOTICES.txt"
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
# Finder's document types (open-to-import): .ovpn and .sstp (Default) through their imported types,
# .macvpncatalog (Owner) through its exported type, .conf only under "Open With" (Alternate, by the extension).
# Admin key files, backups and .mobileconfig profiles are never claimed.
pbexpect() { # PlistBuddy key path (':'-separated; keys may contain dots), expected value
  local got
  got=$(/usr/libexec/PlistBuddy -c "Print :$1" "$PLIST" 2>/dev/null) || die "Info.plist: missing $1"
  [ "$got" = "$2" ] || die "Info.plist: $1 is '$got', expected '$2'"
}
pbcount() { # array key path, expected count
  local got
  got=$(/usr/bin/plutil -extract "$1" raw -o - "$PLIST" 2>/dev/null) || die "Info.plist: missing $1"
  [ "$got" = "$2" ] || die "Info.plist: $1 has $got entries, expected $2"
}
pbcount CFBundleDocumentTypes 4
DOC_TYPES=("local.macvpn.ovpn Default" "local.macvpn.sstp Default" "local.macvpn.catalog Owner")
for i in "${!DOC_TYPES[@]}"; do
  read -r uti rank <<< "${DOC_TYPES[$i]}"
  pbexpect "CFBundleDocumentTypes:$i:LSItemContentTypes:0" "$uti"
  pbcount "CFBundleDocumentTypes.$i.LSItemContentTypes" 1
  pbexpect "CFBundleDocumentTypes:$i:LSHandlerRank" "$rank"
  pbexpect "CFBundleDocumentTypes:$i:CFBundleTypeRole" Viewer
done
pbexpect "CFBundleDocumentTypes:3:CFBundleTypeExtensions:0" conf
pbcount CFBundleDocumentTypes.3.CFBundleTypeExtensions 1
pbexpect "CFBundleDocumentTypes:3:LSHandlerRank" Alternate
pbexpect "CFBundleDocumentTypes:3:CFBundleTypeRole" Viewer
/usr/libexec/PlistBuddy -c "Print :CFBundleDocumentTypes:3:LSItemContentTypes" "$PLIST" >/dev/null 2>&1 \
  && die "Info.plist: the .conf document type must not name a content type (it would claim other apps' .conf type)"
pbcount UTImportedTypeDeclarations 2
pbexpect "UTImportedTypeDeclarations:0:UTTypeIdentifier" local.macvpn.ovpn
pbexpect "UTImportedTypeDeclarations:0:UTTypeTagSpecification:public.filename-extension:0" ovpn
pbexpect "UTImportedTypeDeclarations:1:UTTypeIdentifier" local.macvpn.sstp
pbexpect "UTImportedTypeDeclarations:1:UTTypeTagSpecification:public.filename-extension:0" sstp
# Data, not text: plain text is a "safe" download type that Safari may open by itself (a drive-by import).
for i in 0 1; do
  pbcount "UTImportedTypeDeclarations.$i.UTTypeConformsTo" 2
  pbexpect "UTImportedTypeDeclarations:$i:UTTypeConformsTo:0" public.data
  pbexpect "UTImportedTypeDeclarations:$i:UTTypeConformsTo:1" public.item
done
if /usr/bin/plutil -convert xml1 -o - "$PLIST" | grep -Eq 'public\.(plain-text|text|utf8-plain-text|source-code)<'; then
  die "Info.plist: a declared type conforms to a text type (a safe download type)"
fi
pbcount UTExportedTypeDeclarations 1
pbexpect "UTExportedTypeDeclarations:0:UTTypeIdentifier" local.macvpn.catalog
pbexpect "UTExportedTypeDeclarations:0:UTTypeTagSpecification:public.filename-extension:0" macvpncatalog
if /usr/bin/plutil -convert xml1 -o - "$PLIST" | grep -Eiq 'macvpnadminkey|macvpnbackup|mobileconfig'; then
  die "Info.plist claims an admin key file, a backup or a .mobileconfig profile (they open from their panels only)"
fi
[ -x "$APP/Contents/MacOS/MacVPN" ] || die "the executable is missing"
[ -s "$RES/AppIcon.icns" ] || die "the icon is missing"
# Contents/Resources/root holds exactly mvpn and VERSION (what the root installer installs).
ROOT_FILES=$(find "$RES/root" -mindepth 1 -maxdepth 1 -exec basename {} \; | LC_ALL=C sort | tr '\n' ' ')
[ "$ROOT_FILES" = "VERSION mvpn " ] || die "unexpected files in Resources/root: $ROOT_FILES"
[ "$(tr -d '[:space:]' < "$RES/root/VERSION")" = "$ROOT_VERSION" ] || die "Resources/root/VERSION"
# Contents/Resources holds exactly the icon, the notices and root/ (the updater checks the bundle's identity, version,
# symlinks and signature, not this list; nothing else may slip in unnoticed).
RES_FILES=$(find "$RES" -mindepth 1 -maxdepth 1 -exec basename {} \; | LC_ALL=C sort | tr '\n' ' ')
[ "$RES_FILES" = "AppIcon.icns THIRD-PARTY-NOTICES.txt root " ] || die "unexpected files in Resources: $RES_FILES"
[ -s "$RES/THIRD-PARTY-NOTICES.txt" ] || die "Resources/THIRD-PARTY-NOTICES.txt is missing"

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
