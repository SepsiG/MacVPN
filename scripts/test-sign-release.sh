#!/bin/bash
# A scripts/sign-release.sh tesztje --dry-run módban: eldobható kulccsal, hálózat, GitHub és Keychain nélkül.
# OpenSSL 3 nélkül kihagyja a futtató részt (0-val lép ki).
set -euo pipefail
cd "$(dirname "$0")/.."
SCRIPT="$PWD/scripts/sign-release.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   - $1"; }
nok() { FAIL=$((FAIL+1)); echo "FAIL - $1"; }
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else nok "$desc"; fi; }

check "bash -n" bash -n "$SCRIPT"
if command -v shellcheck >/dev/null 2>&1; then
  check "shellcheck" shellcheck "$SCRIPT" "$0"
else
  echo "skip - shellcheck nincs telepítve"
fi

# A script a Rust core forrásából olvassa a kulcsokat: ugyanazok, mint a konstansok.
KEYS="$("$SCRIPT" --print-public-keys)"
PRIMARY="$(echo "$KEYS" | awk '$1=="primary"{print $2}')"
BACKUP="$(echo "$KEYS" | awk '$1=="backup"{print $2}')"
RUST="crates/core/src/update.rs"
check "két kulcs, elsődleges és tartalék" test "$(echo "$KEYS" | awk '{print $1}' | tr '\n' ' ')" = "primary backup "
check "elsődleges kulcs = Rust konstans" grep -q "PRIMARY_PUBLIC_KEY_BASE64: &'static str = \"$PRIMARY\";" "$RUST"
check "tartalék kulcs = Rust konstans" grep -q "BACKUP_PUBLIC_KEY_BASE64: &'static str = \"$BACKUP\";" "$RUST"
# A kiadott (Swift) appok ugyanezeket a kulcsokat ellenőrzik: a v0.4.0 forrása (git tag), ha elérhető.
if V040="$(git show v0.4.0:Sources/MacVPNCore/UpdateSignature.swift 2>/dev/null)"; then
  check "elsődleges kulcs = v0.4.0" grep -q "primaryPublicKeyBase64 = \"$PRIMARY\"" <<<"$V040"
  check "tartalék kulcs = v0.4.0" grep -q "backupPublicKeyBase64 = \"$BACKUP\"" <<<"$V040"
else
  echo "skip - a v0.4.0 tag nem érhető el (sekély klón)"
fi

# Build provenance (P2-L5): a release.yml minden draft-fájlhoz attesztációt készít (a GitHub saját, SHA-ra rögzített
# actionjével, csak a release jobban), és a script aláírás előtt minden assetre ellenőrzi (repó, workflow, tag,
# commit, GitHub-hostolt runner); hiba esetén nem ír alá.
WF=".github/workflows/release.yml"
check "release.yml: attest-build-provenance SHA-ra rögzítve" \
  grep -Eq '^ +uses: actions/attest-build-provenance@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+$' "$WF"
check "release.yml: a DMG és az MSI is attesztált" bash -c \
  "grep -A3 'uses: actions/attest-build-provenance@' '$WF' | grep -q 'dist/MacVPN-\*\.dmg$' && grep -A3 'uses: actions/attest-build-provenance@' '$WF' | grep -q 'dist/WinVPN-\*\.msi$'"
check "release.yml: id-token és attestations írás csak a release jobban" bash -c \
  "[ \"\$(grep -c 'id-token: write' '$WF')\" = 1 ] && [ \"\$(grep -c 'attestations: write' '$WF')\" = 1 ] && sed -n '/^  release:/,\$p' '$WF' | grep -q 'id-token: write'"
check "sign-release.sh: gh attestation verify a repóra, a workflow-ra, a tagre és a commitra" bash -c \
  "grep -q 'gh attestation verify' '$SCRIPT' && grep -q -- '--signer-workflow \"\$FULL_NAME/.github/workflows/release.yml\"' '$SCRIPT' \
   && grep -q -- '--source-ref \"refs/tags/\$TAG\"' '$SCRIPT' && grep -q -- '--source-digest \"\$TAG_SHA\"' '$SCRIPT' \
   && grep -q -- '--deny-self-hosted-runners' '$SCRIPT' && grep -q '^  verify_provenance \"\$name\"$' '$SCRIPT'"

OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl
if [ ! -x "$OPENSSL" ] && command -v brew >/dev/null 2>&1; then OPENSSL="$(brew --prefix openssl@3 2>/dev/null)/bin/openssl"; fi
if [ ! -x "$OPENSSL" ] || ! "$OPENSSL" version | grep -q '^OpenSSL 3\.'; then
  echo "skip - OpenSSL 3 nincs telepítve, a dry-run teszt kimarad"
  echo "# $PASS ok, $FAIL hiba"
  [ "$FAIL" = 0 ]
  exit
fi

T="$(mktemp -d "${TMPDIR:-/tmp}/macvpn-sign-test.XXXXXXXX")"
trap 'rm -rf "${T:?}"' EXIT
"$OPENSSL" genpkey -algorithm ed25519 -out "$T/throwaway.pem" 2>/dev/null
"$OPENSSL" pkey -in "$T/throwaway.pem" -pubout -out "$T/throwaway.pub.pem"
head -c 100000 /dev/urandom >"$T/MacVPN-9.8.7.dmg"
HASH="$(shasum -a 256 "$T/MacVPN-9.8.7.dmg" | awk '{print $1}')"

# Hálózat nélkül: egy nem létező proxy minden curl hívást elrontana, és a git credential sem kérdezhet.
export HTTPS_PROXY="http://127.0.0.1:9" https_proxy="http://127.0.0.1:9" GIT_TERMINAL_PROMPT=0
if OUT="$("$SCRIPT" --dry-run --dmg "$T/MacVPN-9.8.7.dmg" --backup-key "$T/throwaway.pem" v9.8.7 </dev/null 2>&1)"; then
  ok "dry-run lefut"
else
  nok "dry-run lefut"; echo "$OUT"
fi
check "kiírja a hash-t" grep -q "$HASH" <<<"$OUT"
check "jelzi, hogy nem beágyazott kulcs" grep -q "not an embedded key" <<<"$OUT"
check "semmit nem tölt fel" grep -q "nothing was uploaded" <<<"$OUT"
SIG="$(sed -n 's/^signature: //p' <<<"$OUT")"
check "az aláírás 88 karakteres base64" grep -Eq '^[A-Za-z0-9+/]{86}==$' <<<"$SIG"

# Független ellenőrzés: a pontos üzenet, a throwaway nyilvános kulccsal.
printf 'macvpn-update-v1\n9.8.7\n%s\n' "$HASH" >"$T/message"
printf %s "$SIG" | base64 -d >"$T/sig.bin"
check "az aláírás érvényes a pontos üzenetre" \
  "$OPENSSL" pkeyutl -verify -pubin -inkey "$T/throwaway.pub.pem" -rawin -in "$T/message" -sigfile "$T/sig.bin" -out /dev/null
printf 'macvpn-update-v1\n9.8.8\n%s\n' "$HASH" >"$T/message2"
if "$OPENSSL" pkeyutl -verify -pubin -inkey "$T/throwaway.pub.pem" -rawin -in "$T/message2" -sigfile "$T/sig.bin" >/dev/null 2>&1; then
  nok "más verzióra nem érvényes"
else
  ok "más verzióra nem érvényes"
fi

# WinVPN: az MSI aláírása a WinVPN-üzenetre (a fájlnévvel együtt), és csak a saját architektúrájára érvényes.
head -c 100000 /dev/urandom >"$T/winvpn.msi"
MHASH="$(shasum -a 256 "$T/winvpn.msi" | awk '{print $1}')"
if OUT="$("$SCRIPT" --dry-run --msi "$T/winvpn.msi" --arch arm64 --backup-key "$T/throwaway.pem" v9.8.7 </dev/null 2>&1)"; then
  ok "msi dry-run lefut"
else
  nok "msi dry-run lefut"; echo "$OUT"
fi
check "msi: kiírja a hash-t és az asset nevét" grep -q "as WinVPN-9.8.7-arm64.msi): $MHASH" <<<"$OUT"
MSIG="$(sed -n 's/^signature: //p' <<<"$OUT")"
printf 'winvpn-update-v1\nWinVPN-9.8.7-arm64.msi\n9.8.7\n%s\n' "$MHASH" >"$T/mmessage"
printf %s "$MSIG" | base64 -d >"$T/msig.bin"
check "az msi aláírása a WinVPN-üzenetre érvényes" \
  "$OPENSSL" pkeyutl -verify -pubin -inkey "$T/throwaway.pub.pem" -rawin -in "$T/mmessage" -sigfile "$T/msig.bin" -out /dev/null
printf 'winvpn-update-v1\nWinVPN-9.8.7-x64.msi\n9.8.7\n%s\n' "$MHASH" >"$T/mmessage2"
if "$OPENSSL" pkeyutl -verify -pubin -inkey "$T/throwaway.pub.pem" -rawin -in "$T/mmessage2" -sigfile "$T/msig.bin" >/dev/null 2>&1; then
  nok "az arm64 aláírás az x64 fájlra nem érvényes"
else
  ok "az arm64 aláírás az x64 fájlra nem érvényes"
fi
printf 'macvpn-update-v1\n9.8.7\n%s\n' "$MHASH" >"$T/mmessage3"
if "$OPENSSL" pkeyutl -verify -pubin -inkey "$T/throwaway.pub.pem" -rawin -in "$T/mmessage3" -sigfile "$T/msig.bin" >/dev/null 2>&1; then
  nok "az msi aláírása a MacVPN-üzenetre nem érvényes"
else
  ok "az msi aláírása a MacVPN-üzenetre nem érvényes"
fi

# Hibás használat.
expect_fail() { local desc="$1"; shift; if "$@" </dev/null >/dev/null 2>&1; then nok "$desc"; else ok "$desc"; fi; }
expect_fail "rossz tag (v nélkül)" "$SCRIPT" --dry-run --dmg "$T/MacVPN-9.8.7.dmg" --backup-key "$T/throwaway.pem" 9.8.7
expect_fail "rossz tag (két elem)" "$SCRIPT" --dry-run --dmg "$T/MacVPN-9.8.7.dmg" --backup-key "$T/throwaway.pem" v9.8
expect_fail "rossz tag (utótag)" "$SCRIPT" --dry-run --dmg "$T/MacVPN-9.8.7.dmg" --backup-key "$T/throwaway.pem" v9.8.7-beta
expect_fail "dry-run --dmg nélkül" "$SCRIPT" --dry-run --backup-key "$T/throwaway.pem" v9.8.7
expect_fail "--dmg dry-run nélkül" "$SCRIPT" --dmg "$T/MacVPN-9.8.7.dmg" --backup-key "$T/throwaway.pem" v9.8.7
expect_fail "nem létező kulcsfájl" "$SCRIPT" --dry-run --dmg "$T/MacVPN-9.8.7.dmg" --backup-key "$T/nincs.pem" v9.8.7
expect_fail "--msi --arch nélkül" "$SCRIPT" --dry-run --msi "$T/winvpn.msi" --backup-key "$T/throwaway.pem" v9.8.7
expect_fail "--msi rossz arch" "$SCRIPT" --dry-run --msi "$T/winvpn.msi" --arch x86 --backup-key "$T/throwaway.pem" v9.8.7
expect_fail "--dmg és --msi együtt" "$SCRIPT" --dry-run --dmg "$T/MacVPN-9.8.7.dmg" --msi "$T/winvpn.msi" --arch x64 --backup-key "$T/throwaway.pem" v9.8.7
expect_fail "--dmg --arch-csal" "$SCRIPT" --dry-run --dmg "$T/MacVPN-9.8.7.dmg" --arch x64 --backup-key "$T/throwaway.pem" v9.8.7
expect_fail "--msi dry-run nélkül" "$SCRIPT" --msi "$T/winvpn.msi" --arch x64 --backup-key "$T/throwaway.pem" v9.8.7
expect_fail "ismeretlen opció" "$SCRIPT" --force v9.8.7

echo "# $PASS ok, $FAIL hiba"
[ "$FAIL" = 0 ]
