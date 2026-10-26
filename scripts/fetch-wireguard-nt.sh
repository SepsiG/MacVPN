#!/bin/bash
# Fetches the pinned wireguard-nt SDK (scripts/pins/wireguard-nt.txt) into target/wireguard-nt/ and checks it:
# the zip's SHA-256, each bundled DLL's SHA-256 (amd64, arm64) and, on Windows, each DLL's Authenticode status
# (Valid) and signer. Used by scripts/build-msi.sh, the tests and CI; runs on Windows (Git Bash), macOS and Linux.
# A zip already in target/wireguard-nt.zip is reused only if its hash is the pin. Exit 1 with the reason on any
# mismatch (and nothing is left in target/wireguard-nt/ then).
set -euo pipefail
cd "$(dirname "$0")/.."

PINS=scripts/pins/wireguard-nt.txt
ZIP=target/wireguard-nt.zip
OUT=target/wireguard-nt

die() { echo "error: $*" >&2; rm -rf "${OUT:?}"; exit 1; }

pin() {
    local v
    v="$(awk -F'\t' -v k="$1" '$1 == k { print $2; n++ } END { if (n != 1) exit 1 }' "$PINS")" ||
        die "$PINS: $1 must be there exactly once"
    [ -n "$v" ] || die "$PINS: $1 is empty"
    printf '%s' "$v"
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

URL="$(pin zip_url)"
ZIP_SHA="$(pin zip_sha256)"
SIGNER="$(pin signer)"
[[ "$URL" == https://download.wireguard.com/wireguard-nt/* ]] || die "zip_url is not on download.wireguard.com"

mkdir -p target
if [ -f "$ZIP" ] && [ "$(sha256 "$ZIP")" != "$ZIP_SHA" ]; then
    rm -f "$ZIP"
fi
if [ ! -f "$ZIP" ]; then
    curl -fsSL --proto '=https' --tlsv1.2 --max-time 300 -o "$ZIP.part" "$URL" || die "cannot download $URL"
    mv "$ZIP.part" "$ZIP"
fi
got="$(sha256 "$ZIP")"
[ "$got" = "$ZIP_SHA" ] || { rm -f "$ZIP"; die "$ZIP has SHA-256 $got, the pin is $ZIP_SHA"; }

rm -rf "$OUT" "$OUT.tmp"
mkdir -p "$OUT.tmp"
if command -v unzip >/dev/null 2>&1; then
    unzip -q "$ZIP" -d "$OUT.tmp" || die "cannot unzip $ZIP"
else
    powershell.exe -NoProfile -NonInteractive -Command \
        "Expand-Archive -LiteralPath '$(cygpath -w "$ZIP")' -DestinationPath '$(cygpath -w "$OUT.tmp")'" ||
        die "cannot unzip $ZIP"
fi
[ -d "$OUT.tmp/wireguard-nt" ] || die "$ZIP has no wireguard-nt folder"
mv "$OUT.tmp/wireguard-nt" "$OUT"
rm -rf "$OUT.tmp"

for arch in amd64 arm64; do
    dll="$OUT/bin/$arch/wireguard.dll"
    want="$(pin "dll_${arch}_sha256")"
    [ -f "$dll" ] || die "$dll is missing"
    got="$(sha256 "$dll")"
    [ "$got" = "$want" ] || die "$dll has SHA-256 $got, the pin is $want"
    case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*)
        # Status, then the signer's simple name, one per line (CR stripped).
        sig="$(powershell.exe -NoProfile -NonInteractive -Command \
            "\$s = Get-AuthenticodeSignature -LiteralPath '$(cygpath -w "$dll")'; \$s.Status; \$s.SignerCertificate.GetNameInfo('SimpleName', \$false)" |
            tr -d '\r')" || die "cannot read the signature of $dll"
        [ "$(sed -n 1p <<<"$sig")" = "Valid" ] || die "$dll: the Authenticode signature is not valid ($(sed -n 1p <<<"$sig"))"
        [ "$(sed -n 2p <<<"$sig")" = "$SIGNER" ] || die "$dll is signed by '$(sed -n 2p <<<"$sig")', the pin is '$SIGNER'"
        ;;
    esac
done
echo "OK: wireguard-nt $(pin version) in $OUT (zip and DLLs match the pins)"
