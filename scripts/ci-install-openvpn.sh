#!/bin/bash
# Installs the pinned OpenVPN Community x64 MSI (scripts/pins/openvpn.txt) with the plan's features (decision 4:
# openvpn.exe, DCO, TAP-Windows6) on a CI runner, for the windows-admin job of .github/workflows/ci.yml:
#
#   scripts/ci-install-openvpn.sh             download, verify, install, check (only when CI is set: it changes the machine)
#   scripts/ci-install-openvpn.sh --dry-run   print what it would do from the pins (any OS, no network, no change)
#
# Download over HTTPS only, then the pinned SHA-256 and a valid Authenticode signature by the pinned signer before
# msiexec runs it (`/qn /norestart ADDLOCAL=<features>`, as an administrator). Afterwards: HKLM\SOFTWARE\OpenVPN
# exe_path names an openvpn.exe of the pinned version, and the driver services ovpn-dco and tap0901 exist, are not
# disabled and their .sys files have the versions recorded with the pin (Task 10, below). OpenVPN's Interactive
# Service is left as the MSI set it: this install is not WinVPN's (WinVPN disables it only after its own installs).
set -euo pipefail
cd "$(dirname "$0")/.."

PINS=scripts/pins/openvpn.txt
# The driver files of the pinned 2.7.8-I001 MSI (scripts/pins/openvpn.txt's comments; FileVersionRaw as Windows
# reports it). Change them together with the pin.
DRIVERS=("ovpn-dco 2.8.13.0" "tap0901 9.27.0.0")

die() { echo "error: $*" >&2; exit 1; }

pin() {
  local v
  v="$(awk -F'\t' -v k="$1" '$1 == k { print $2; n++ } END { if (n != 1) exit 1 }' "$PINS")" ||
    die "$PINS: $1 must be there exactly once"
  [ -n "$v" ] || die "$PINS: $1 is empty"
  printf '%s' "$v"
}

DRY=0
case "${1:-}" in
--dry-run) DRY=1; shift ;;
"") ;;
*) die "usage: $0 [--dry-run]" ;;
esac
[ $# -eq 0 ] || die "usage: $0 [--dry-run]"

VERSION="$(pin version)"
URL="$(pin msi_x64_url)"
SHA="$(pin msi_x64_sha256)"
FEATURES="$(pin msi_x64_features)"
SIGNER="$(pin signer)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version is not X.Y.Z: $VERSION"
[[ "$URL" =~ ^https://swupdate\.openvpn\.org/community/releases/OpenVPN-[0-9A-Za-z.-]+-amd64\.msi$ ]] ||
  die "msi_x64_url is not an OpenVPN MSI on swupdate.openvpn.org: $URL"
[[ "$SHA" =~ ^[0-9a-f]{64}$ ]] || die "msi_x64_sha256 is not 64 lower-case hex digits"
[[ "$FEATURES" =~ ^[A-Za-z0-9.]+(,[A-Za-z0-9.]+)*$ ]] || die "msi_x64_features is not a feature list: $FEATURES"

if [ "$DRY" = 1 ]; then
  echo "OpenVPN Community $VERSION (x64)"
  echo "  download: $URL"
  echo "  SHA-256:  $SHA"
  echo "  signer:   $SIGNER (Authenticode Valid)"
  echo "  install:  msiexec /i <msi> /qn /norestart ADDLOCAL=$FEATURES"
  for d in "${DRIVERS[@]}"; do echo "  driver:   ${d% *} ${d#* }"; done
  exit 0
fi

[ -n "${CI:-}" ] || die "refusing to run without CI set: it installs OpenVPN Community and its drivers on this machine"
case "$(uname -s)" in
MINGW* | MSYS* | CYGWIN*) ;;
*) die "runs on Windows (Git Bash) only" ;;
esac

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK:?}"' EXIT
MSI="$WORK/${URL##*/}"
LOG="${RUNNER_TEMP:-$WORK}/openvpn-install.log"

echo "Downloading $URL"
curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --max-redirs 5 --max-time 600 -o "$MSI" "$URL" ||
  die "cannot download $URL"
got="$(sha256sum "$MSI" | cut -d' ' -f1)"
[ "$got" = "$SHA" ] || die "$MSI has SHA-256 $got, the pin is $SHA"
# Status, then the signer's simple name, one per line (CR stripped).
sig="$(powershell.exe -NoProfile -NonInteractive -Command \
  "\$s = Get-AuthenticodeSignature -LiteralPath '$(cygpath -w "$MSI")'; \$s.Status; \$s.SignerCertificate.GetNameInfo('SimpleName', \$false)" |
  tr -d '\r')" || die "cannot read the signature of $MSI"
[ "$(sed -n 1p <<<"$sig")" = Valid ] || die "$MSI: the Authenticode signature is not valid ($(sed -n 1p <<<"$sig"))"
[ "$(sed -n 2p <<<"$sig")" = "$SIGNER" ] || die "$MSI is signed by '$(sed -n 2p <<<"$sig")', the pin is '$SIGNER'"
echo "  SHA-256 $got (pinned), Authenticode Valid, $SIGNER"

echo "Installing with ADDLOCAL=$FEATURES"
rc=0
MSYS_NO_PATHCONV=1 msiexec.exe /i "$(cygpath -w "$MSI")" /qn /norestart "ADDLOCAL=$FEATURES" \
  /l*v "$(cygpath -w "$LOG")" || rc=$?
[ "$rc" = 0 ] || [ "$rc" = 3010 ] || { tr -d '\000' <"$LOG" | tail -100 || true; die "msiexec failed ($rc), log: $LOG"; }

# openvpn.exe where the service looks for it, of the pinned version.
cat >"$WORK/facts.ps1" <<'PS'
param([string]$Driver)
$ErrorActionPreference = 'Stop'
if ($Driver -eq '') {
  $exe = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\OpenVPN').exe_path
  $exe
  (Get-Item -LiteralPath $exe).VersionInfo.FileVersionRaw.ToString()
  exit 0
}
$k = Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\' + $Driver)
$p = [Environment]::ExpandEnvironmentVariables([string]$k.ImagePath)
if ($p -match '^\\SystemRoot\\') { $p = $env:SystemRoot + $p.Substring(11) }
elseif ($p -match '^\\\?\?\\') { $p = $p.Substring(4) }
elseif ($p -match '^(?i)system32\\') { $p = Join-Path $env:SystemRoot $p }
[string]$k.Start
(Get-Item -LiteralPath $p).VersionInfo.FileVersionRaw.ToString()
PS
facts() {
  powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$(cygpath -w "$WORK/facts.ps1")" "$@" |
    tr -d '\r'
}
exe="$(facts)" || die "OpenVPN's exe_path or its version cannot be read"
[[ "$(sed -n 2p <<<"$exe")" == "$VERSION".* ]] ||
  die "$(sed -n 1p <<<"$exe") has version $(sed -n 2p <<<"$exe"), the pin is $VERSION"
echo "  openvpn.exe: $(sed -n 1p <<<"$exe") $(sed -n 2p <<<"$exe")"
for d in "${DRIVERS[@]}"; do
  name="${d% *}" want="${d#* }"
  got="$(facts "$name")" || die "the driver service $name is not installed"
  [ "$(sed -n 1p <<<"$got")" != 4 ] || die "the driver service $name is disabled"
  [ "$(sed -n 2p <<<"$got")" = "$want" ] || die "$name has version $(sed -n 2p <<<"$got"), expected $want"
  echo "  driver $name: $want (start type $(sed -n 1p <<<"$got"))"
done
echo "OK: OpenVPN Community $VERSION with DCO and TAP-Windows6"
