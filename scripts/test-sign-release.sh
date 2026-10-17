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

# A script a Swift forrásból olvassa a kulcsokat: ugyanazok, mint a konstansok.
KEYS="$("$SCRIPT" --print-public-keys)"
SWIFT="Sources/MacVPNCore/UpdateSignature.swift"
check "elsődleges kulcs = Swift konstans" grep -q "primaryPublicKeyBase64 = \"$(echo "$KEYS" | awk '$1=="primary"{print $2}')\"" "$SWIFT"
check "tartalék kulcs = Swift konstans" grep -q "backupPublicKeyBase64 = \"$(echo "$KEYS" | awk '$1=="backup"{print $2}')\"" "$SWIFT"

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

# Hibás használat.
expect_fail() { local desc="$1"; shift; if "$@" </dev/null >/dev/null 2>&1; then nok "$desc"; else ok "$desc"; fi; }
expect_fail "rossz tag (v nélkül)" "$SCRIPT" --dry-run --dmg "$T/MacVPN-9.8.7.dmg" --backup-key "$T/throwaway.pem" 9.8.7
expect_fail "rossz tag (két elem)" "$SCRIPT" --dry-run --dmg "$T/MacVPN-9.8.7.dmg" --backup-key "$T/throwaway.pem" v9.8
expect_fail "rossz tag (utótag)" "$SCRIPT" --dry-run --dmg "$T/MacVPN-9.8.7.dmg" --backup-key "$T/throwaway.pem" v9.8.7-beta
expect_fail "dry-run --dmg nélkül" "$SCRIPT" --dry-run --backup-key "$T/throwaway.pem" v9.8.7
expect_fail "--dmg dry-run nélkül" "$SCRIPT" --dmg "$T/MacVPN-9.8.7.dmg" --backup-key "$T/throwaway.pem" v9.8.7
expect_fail "nem létező kulcsfájl" "$SCRIPT" --dry-run --dmg "$T/MacVPN-9.8.7.dmg" --backup-key "$T/nincs.pem" v9.8.7
expect_fail "ismeretlen opció" "$SCRIPT" --force v9.8.7

echo "# $PASS ok, $FAIL hiba"
[ "$FAIL" = 0 ]
