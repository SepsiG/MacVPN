#!/bin/bash
# MacVPN.app összeállítása és DMG csomagolás (ad-hoc aláírás, Developer ID nélkül).
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" Resources/Info.plist)
# Az updater a rögzített numerikus repo ID-ről frissít (repo-jacking ellen); nélküle a kész app nem frissítene.
REPO_ID=$(/usr/libexec/PlistBuddy -c "Print :MacVPNUpdateRepoID" Resources/Info.plist 2>/dev/null || true)
[[ "$REPO_ID" =~ ^[1-9][0-9]*$ ]] || { echo "Hiányzó vagy érvénytelen MacVPNUpdateRepoID az Info.plist-ben" >&2; exit 1; }
echo "▶ build $VERSION (universal)"
ARCHS=(--arch arm64 --arch x86_64)
swift build -c release "${ARCHS[@]}"
BIN_DIR=$(swift build -c release "${ARCHS[@]}" --show-bin-path)
BIN="$BIN_DIR/MacVPN"
VALIDATE="$BIN_DIR/mvpn-validate"
MGMT="$BIN_DIR/mvpn-mgmt"
[ -x "$BIN" ] || { echo "Nem található: $BIN" >&2; exit 1; }
[ -x "$VALIDATE" ] || { echo "Nem található: $VALIDATE" >&2; exit 1; }
[ -x "$MGMT" ] || { echo "Nem található: $MGMT" >&2; exit 1; }
echo "▶ architektúrák ellenőrzése"
for b in "$BIN" "$VALIDATE" "$MGMT"; do
  archs=$(lipo -archs "$b")
  for a in arm64 x86_64; do
    case " $archs " in *" $a "*) ;; *) echo "Hiányzó architektúra ($a) itt: $b (van: $archs)" >&2; exit 1 ;; esac
  done
  echo "  $(basename "$b"): $archs"
done

APP="dist/MacVPN.app"
rm -rf dist
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/root"
cp "$BIN" "$APP/Contents/MacOS/MacVPN"
cp Resources/Info.plist "$APP/Contents/Info.plist"
cp Resources/root/mvpn Resources/root/ovpn-dns Resources/root/VERSION "$APP/Contents/Resources/root/"
cp "$VALIDATE" "$APP/Contents/Resources/root/mvpn-validate"
cp "$MGMT" "$APP/Contents/Resources/root/mvpn-mgmt"
# Lokalizáció: az app String Catalogja közvetlenül a Contents/Resources/<nyelv>.lproj-ba fordul (a kulcs az angol
# szöveg, ezért angolra nem kell fájl). Az app a Bundle.main-ből olvas (SwiftUI Text, String(localized:)); a nyelvet
# a macOS választja az Info.plist CFBundleLocalizations (en, hu) és a preferált nyelvek alapján, tartalék: en.
echo "▶ lokalizáció"
xcrun xcstringstool compile Sources/MacVPN/Resources/Localizable.xcstrings --output-directory "$APP/Contents/Resources"
[ -s "$APP/Contents/Resources/hu.lproj/Localizable.strings" ] || { echo "Hiányzik a magyar fordítás (hu.lproj)" >&2; exit 1; }
chmod 755 "$APP/Contents/Resources/root/mvpn" "$APP/Contents/Resources/root/ovpn-dns" "$APP/Contents/Resources/root/mvpn-validate" \
  "$APP/Contents/Resources/root/mvpn-mgmt"
if [ -f Resources/AppIcon.icns ]; then
  cp Resources/AppIcon.icns "$APP/Contents/Resources/"
  if /usr/libexec/PlistBuddy -c "Print :CFBundleIconFile" "$APP/Contents/Info.plist" >/dev/null 2>&1; then
    /usr/libexec/PlistBuddy -c "Set :CFBundleIconFile AppIcon" "$APP/Contents/Info.plist"
  else
    /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string AppIcon" "$APP/Contents/Info.plist"
  fi
fi

echo "▶ ad-hoc aláírás"
codesign --force --deep --sign - "$APP"
codesign --verify --verbose "$APP"

echo "▶ DMG"
STAGE="dist/dmg"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
# A hdiutil create néha átmenetileg hibázik (pl. „Resource busy”): legfeljebb 3 próbálkozás.
for attempt in 1 2 3; do
  if hdiutil create -volname "MacVPN" -srcfolder "$STAGE" -ov -format UDZO "dist/MacVPN-$VERSION.dmg" >/dev/null; then
    break
  fi
  [ "$attempt" = 3 ] && { echo "A hdiutil create 3 próbálkozás után is sikertelen" >&2; exit 1; }
  echo "hdiutil create sikertelen ($attempt. próbálkozás), újra 5 mp múlva…" >&2
  sleep 5
done
rm -rf "$STAGE"
echo "Kész: dist/MacVPN-$VERSION.dmg"
