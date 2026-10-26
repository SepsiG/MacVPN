#!/bin/bash
# Offline signing of a MacVPN release, run by the maintainer on their own Mac.
#
#   scripts/sign-release.sh vX.Y.Z                      sign the CI-built draft release and publish it
#   scripts/sign-release.sh --backup-key FILE vX.Y.Z    sign with the backup PEM instead of the Keychain key
#   scripts/sign-release.sh --republish-sig vX.Y.Z      replace the .sig of an already published release
#   scripts/sign-release.sh --dry-run (--dmg FILE | --msi FILE --arch x64|arm64) [--backup-key FILE] vX.Y.Z
#                                                       sign a local file and verify it; no network, no GitHub
#   scripts/sign-release.sh --print-public-keys         print the public keys embedded in the app
#
# CI (release.yml) only creates a *draft* release with MacVPN-X.Y.Z.dmg (and, when WinVPN is released,
# WinVPN-X.Y.Z-x64.msi and WinVPN-X.Y.Z-arm64.msi), each with its .sha256 and a build provenance attestation
# (actions/attest-build-provenance); it never holds the signing key. This script downloads them, checks each SHA-256
# locally, verifies each asset's build provenance with `gh attestation verify` (made by this repository's
# .github/workflows/release.yml, for this tag and its commit, on a GitHub-hosted runner) and refuses to sign an
# asset without it (a draft whose files were replaced after the build), then signs each asset with its product's
# message:
#   MacVPN-X.Y.Z.dmg           "macvpn-update-v1\n" + X.Y.Z + "\n" + sha256hex + "\n"
#   WinVPN-X.Y.Z-<arch>.msi    "winvpn-update-v1\n" + asset name + "\n" + X.Y.Z + "\n" + sha256hex + "\n"
# with Ed25519 (OpenSSL 3, pkeyutl -rawin), verifies each signature against the public keys embedded in the app
# (parsed from the Rust core, crates/core/src/update.rs, UpdateSignature::PRIMARY_/BACKUP_PUBLIC_KEY_BASE64; the same
# keys as in every app since 0.2.2), uploads the .sig files and publishes the release.
#
# The primary private key is read from the login Keychain (generic password, service "MacVPN release signing",
# account "primary", value = base64 of the PEM) through a process substitution: it never touches the disk and is
# never printed. The GitHub token comes from `git credential fill` and is only used in curl Authorization headers
# (passed through a process substitution) and in the environment of `gh attestation verify` (GH_TOKEN), so it is
# not in any command line.
set -euo pipefail

REPO_ID=1422472799
EXPECTED_REPO="SepsiG/MacVPN"
KEYCHAIN_SERVICE="MacVPN release signing"
KEYCHAIN_ACCOUNT="primary"
SIG_DOMAIN="macvpn-update-v1"
WIN_SIG_DOMAIN="winvpn-update-v1"
# DER prefix of an Ed25519 SubjectPublicKeyInfo; followed by the raw 32-byte key.
ED25519_SPKI_PREFIX='\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEYS_SOURCE="$ROOT/crates/core/src/update.rs"

die() { echo "error: $*" >&2; exit 1; }
usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

DRY_RUN=0
REPUBLISH=0
BACKUP_KEY=""
DRY_DMG=""
DRY_MSI=""
DRY_ARCH=""
PRINT_KEYS=0
TAG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --republish-sig) REPUBLISH=1 ;;
    --backup-key) [ $# -ge 2 ] || die "--backup-key needs a file"; BACKUP_KEY="$2"; shift ;;
    --dmg) [ $# -ge 2 ] || die "--dmg needs a file"; DRY_DMG="$2"; shift ;;
    --msi) [ $# -ge 2 ] || die "--msi needs a file"; DRY_MSI="$2"; shift ;;
    --arch) [ $# -ge 2 ] || die "--arch needs x64 or arm64"; DRY_ARCH="$2"; shift ;;
    --print-public-keys) PRINT_KEYS=1 ;;
    -h|--help) usage 0 ;;
    -*) die "unknown option: $1" ;;
    *) [ -z "$TAG" ] || die "only one tag can be given"; TAG="$1" ;;
  esac
  shift
done

# --- Embedded public keys (the single source of truth is the Rust core source) ---------------------------------
embedded_keys() {
  [ -f "$KEYS_SOURCE" ] || die "not found: $KEYS_SOURCE"
  sed -nE "s/^[[:space:]]*pub const (PRIMARY|BACKUP)_PUBLIC_KEY_BASE64: &'static str = \"([A-Za-z0-9+\/]{43}=)\";\$/\1 \2/p" \
    "$KEYS_SOURCE" | sed -e 's/^PRIMARY /primary /' -e 's/^BACKUP /backup /'
}
KEYS="$(embedded_keys)"
[ "$(printf '%s\n' "$KEYS" | grep -c .)" = 2 ] || die "cannot parse exactly two public keys from $KEYS_SOURCE"
[ "$(printf '%s\n' "$KEYS" | awk '{print $1}' | tr '\n' ' ')" = "primary backup " ] || die "unexpected key order in $KEYS_SOURCE"
while read -r _ b64; do
  [ "$(printf %s "$b64" | base64 -d | wc -c | tr -d ' ')" = 32 ] || die "embedded public key is not 32 bytes: $b64"
done <<<"$KEYS"
if [ "$PRINT_KEYS" = 1 ]; then
  printf '%s\n' "$KEYS"
  exit 0
fi

# --- Arguments --------------------------------------------------------------------------------------------------
[ -n "$TAG" ] || usage 1
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid tag (expected vX.Y.Z): $TAG"
VERSION="${TAG#v}"
DMG_NAME="MacVPN-$VERSION.dmg"
MSI_NAMES=("WinVPN-$VERSION-x64.msi" "WinVPN-$VERSION-arm64.msi")
if [ "$DRY_RUN" = 1 ]; then
  [ "$REPUBLISH" = 0 ] || die "--republish-sig cannot be combined with --dry-run"
  if [ -n "$DRY_DMG" ]; then
    [ -z "$DRY_MSI" ] || die "--dmg and --msi cannot be combined"
    [ -z "$DRY_ARCH" ] || die "--arch is only for --msi"
    [ -f "$DRY_DMG" ] || die "not a file: $DRY_DMG"
    DRY_FILE="$DRY_DMG"; DRY_ASSET="$DMG_NAME"
  elif [ -n "$DRY_MSI" ]; then
    [ -f "$DRY_MSI" ] || die "not a file: $DRY_MSI"
    [[ "$DRY_ARCH" =~ ^(x64|arm64)$ ]] || die "--msi needs --arch x64 or --arch arm64"
    DRY_FILE="$DRY_MSI"; DRY_ASSET="WinVPN-$VERSION-$DRY_ARCH.msi"
  else
    die "--dry-run needs --dmg FILE or --msi FILE --arch ARCH"
  fi
else
  [ -z "$DRY_DMG$DRY_MSI$DRY_ARCH" ] || die "--dmg, --msi and --arch are only for --dry-run"
fi
if [ -n "$BACKUP_KEY" ]; then
  [ -f "$BACKUP_KEY" ] && [ -r "$BACKUP_KEY" ] || die "cannot read the key file: $BACKUP_KEY"
fi

# --- Tools ------------------------------------------------------------------------------------------------------
OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl
if [ ! -x "$OPENSSL" ] && command -v brew >/dev/null 2>&1; then
  OPENSSL="$(brew --prefix openssl@3 2>/dev/null)/bin/openssl"
fi
[ -x "$OPENSSL" ] || die "OpenSSL 3 not found (brew install openssl@3)"
"$OPENSSL" version | grep -q '^OpenSSL 3\.' || die "OpenSSL 3 is required, found: $("$OPENSSL" version)"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/macvpn-sign.XXXXXXXX")"
trap 'rm -rf "${WORK:?}"' EXIT

# --- Helpers ----------------------------------------------------------------------------------------------------
# Writes the DER public key for a raw base64 key to $2.
spki_der() { { printf '%b' "$ED25519_SPKI_PREFIX"; printf %s "$1" | base64 -d; } >"$2"; }

# Verifies $WORK/signature.bin over $WORK/message with the base64 raw key $1.
verify_with() {
  spki_der "$1" "$WORK/pub.der"
  "$OPENSSL" pkeyutl -verify -pubin -keyform DER -inkey "$WORK/pub.der" -rawin \
    -in "$WORK/message" -sigfile "$WORK/signature.bin" >/dev/null 2>&1
}

sign_message() { # $1 = asset name; writes $WORK/$1.sig
  local sig_name="$1.sig"
  rm -f "${WORK:?}/signature.bin"
  if [ -n "$BACKUP_KEY" ]; then
    echo "Signing with the key file $BACKUP_KEY"
    "$OPENSSL" pkeyutl -sign -rawin -inkey "$BACKUP_KEY" -in "$WORK/message" -out "$WORK/signature.bin"
  else
    echo "Signing with the primary key from the login Keychain (\"$KEYCHAIN_SERVICE\" / $KEYCHAIN_ACCOUNT)"
    security find-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" >/dev/null 2>&1 \
      || die "Keychain item not found: service \"$KEYCHAIN_SERVICE\", account \"$KEYCHAIN_ACCOUNT\""
    "$OPENSSL" pkeyutl -sign -rawin -keyform PEM \
      -inkey <(security find-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" -w | base64 -d) \
      -in "$WORK/message" -out "$WORK/signature.bin"
  fi
  [ "$(wc -c <"$WORK/signature.bin" | tr -d ' ')" = 64 ] || die "the signature is not 64 bytes"
  printf '%s\n' "$(base64 <"$WORK/signature.bin" | tr -d '\n')" >"$WORK/$sig_name"
  [ "$(wc -c <"$WORK/$sig_name" | tr -d ' ')" -le 1024 ] || die "the .sig file is larger than 1 KB"
}

# Accepts the signature if an embedded key verifies it. In --dry-run the public key of --backup-key also counts
# (so a throwaway key can be tested), but then it is reported that the app would reject it.
verify_signature() {
  local role b64
  while read -r role b64; do
    if verify_with "$b64"; then
      echo "Signature verified with the embedded $role public key ($b64)"
      return 0
    fi
  done <<<"$KEYS"
  if [ "$DRY_RUN" = 1 ] && [ -n "$BACKUP_KEY" ]; then
    b64="$("$OPENSSL" pkey -in "$BACKUP_KEY" -pubout -outform DER | tail -c 32 | base64)"
    if verify_with "$b64"; then
      echo "Signature verified with the public key of $BACKUP_KEY ($b64)"
      echo "NOTE: this is not an embedded key; the app would reject this signature."
      return 0
    fi
  fi
  die "the signature does not verify with any embedded public key; nothing was uploaded"
}

# Writes the signed message of asset $1 with hash $2 to $WORK/message.
write_message() {
  case "$1" in
    "$DMG_NAME") printf '%s\n%s\n%s\n' "$SIG_DOMAIN" "$VERSION" "$2" ;;
    "WinVPN-$VERSION-x64.msi"|"WinVPN-$VERSION-arm64.msi") printf '%s\n%s\n%s\n%s\n' "$WIN_SIG_DOMAIN" "$1" "$VERSION" "$2" ;;
    *) die "no signature domain for the asset $1" ;;
  esac >"$WORK/message"
}

local_sha256() { shasum -a 256 "$1" | awk '{print $1}'; }

# --- Dry run: sign a local file, verify, no network -------------------------------------------------------------
if [ "$DRY_RUN" = 1 ]; then
  HASH="$(local_sha256 "$DRY_FILE")"
  echo "SHA-256 ($DRY_FILE as $DRY_ASSET): $HASH"
  write_message "$DRY_ASSET" "$HASH"
  sign_message "$DRY_ASSET"
  verify_signature
  echo "signature: $(cat "$WORK/$DRY_ASSET.sig")"
  echo "Dry run: nothing was uploaded or published."
  exit 0
fi

# --- GitHub -----------------------------------------------------------------------------------------------------
command -v jq >/dev/null 2>&1 || die "jq is required"
command -v gh >/dev/null 2>&1 || die "the GitHub CLI (gh) is required to verify the build provenance (brew install gh)"
TOKEN="$(printf 'protocol=https\nhost=github.com\n\n' | GIT_TERMINAL_PROMPT=0 git credential fill 2>/dev/null \
  | sed -n 's/^password=//p' | head -n 1)" || true
[ -n "$TOKEN" ] || die "no GitHub credential for github.com from 'git credential fill'"

# The token only ever goes into a header file read through a process substitution.
api() {
  curl -fsS --proto =https --tlsv1.2 \
    -H @<(printf 'Authorization: Bearer %s\n' "$TOKEN") \
    -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28" "$@"
}

# Fájl (asset) letöltése: pontosan EGY Accept fejléc (octet-stream). Két Accept fejléc mellett a GitHub
# a JSON-leírást adja vissza a fájl helyett. A -L átirányításnál a curl nem viszi tovább az Authorization
# fejlécet más hosztra.
api_download() {
  curl -fsS --proto =https --tlsv1.2 -L \
    -H @<(printf 'Authorization: Bearer %s\n' "$TOKEN") \
    -H "Accept: application/octet-stream" -H "X-GitHub-Api-Version: 2022-11-28" "$@"
}

FULL_NAME="$(api "https://api.github.com/repositories/$REPO_ID" | jq -r '.full_name')"
[ "$(printf %s "$FULL_NAME" | tr '[:upper:]' '[:lower:]')" = "$(printf %s "$EXPECTED_REPO" | tr '[:upper:]' '[:lower:]')" ] \
  || die "repository $REPO_ID is $FULL_NAME, expected $EXPECTED_REPO"
REPO_API="https://api.github.com/repos/$FULL_NAME"

# Drafts are not returned by /releases/tags/<tag>; search the list.
api "$REPO_API/releases?per_page=100" >"$WORK/releases.json"
jq --arg t "$TAG" '[.[] | select(.tag_name == $t)]' "$WORK/releases.json" >"$WORK/matching.json"
[ "$(jq 'length' "$WORK/matching.json")" = 1 ] || die "expected exactly one release for $TAG, found $(jq 'length' "$WORK/matching.json")"
jq '.[0]' "$WORK/matching.json" >"$WORK/release.json"
RELEASE_ID="$(jq -r '.id' "$WORK/release.json")"
IS_DRAFT="$(jq -r '.draft' "$WORK/release.json")"
[[ "$RELEASE_ID" =~ ^[0-9]+$ ]] || die "unexpected release id: $RELEASE_ID"
if [ "$IS_DRAFT" != true ] && [ "$REPUBLISH" != 1 ]; then
  die "the release $TAG is not a draft (use --republish-sig to replace the signature of a published release)"
fi
echo "Release $TAG (id $RELEASE_ID, draft: $IS_DRAFT)"

asset_field() { # $1 = asset name, $2 = field
  jq -r --arg n "$1" --arg f "$2" '[.assets[] | select(.name == $n)] | if length == 1 then .[0][$f] | tostring else "" end' \
    "$WORK/release.json"
}
download_asset() { # $1 = asset name → $WORK/$1
  local url
  url="$(asset_field "$1" url)"
  [ -n "$url" ] || die "the release has no asset $1"
  [[ "$url" == "$REPO_API/releases/assets/"* ]] || die "unexpected asset URL: $url"
  api_download -o "$WORK/$1" "$url"
}

# The commit the tag names: the build provenance must be for exactly this commit (a moved tag is refused).
TAG_SHA="$(api "$REPO_API/commits/tags/$TAG" | jq -r '.sha')"
[[ "$TAG_SHA" =~ ^[0-9a-f]{40}$ ]] || die "cannot resolve the commit of $TAG: $TAG_SHA"
echo "Tag $TAG is commit $TAG_SHA"

# The build provenance of a downloaded asset ($WORK/$1): signed (Sigstore) for this repository's release workflow,
# at this tag and its commit, on a GitHub-hosted runner, for exactly these bytes. Anything else refuses to sign.
verify_provenance() {
  local out
  if ! out="$(GH_TOKEN="$TOKEN" GH_HOST=github.com gh attestation verify "$WORK/$1" \
    --repo "$FULL_NAME" \
    --signer-workflow "$FULL_NAME/.github/workflows/release.yml" \
    --source-ref "refs/tags/$TAG" \
    --source-digest "$TAG_SHA" \
    --deny-self-hosted-runners \
    --format json 2>&1)"; then
    printf '%s\n' "$out" | tail -n 20 >&2
    die "$1 has no valid build provenance from $FULL_NAME's release.yml for $TAG ($TAG_SHA); nothing was signed"
  fi
  echo "Build provenance verified: $1 (release.yml, $TAG, $TAG_SHA)"
}

ASSETS=("$DMG_NAME")
MSI_COUNT=0
for name in "${MSI_NAMES[@]}"; do
  if [ -n "$(asset_field "$name" url)" ]; then MSI_COUNT=$((MSI_COUNT + 1)); fi
done
case "$MSI_COUNT" in
  0) ;;
  2) ASSETS+=("${MSI_NAMES[@]}") ;;
  *) die "the release has only one of ${MSI_NAMES[*]}: both or neither" ;;
esac

# Parallel arrays, not `declare -A`: the maintainer runs this with macOS' /bin/bash 3.2.
HASH_LIST=()
for name in "${ASSETS[@]}"; do
  echo "Downloading $name and $name.sha256…"
  download_asset "$name"
  download_asset "$name.sha256"
  HASH="$(local_sha256 "$WORK/$name")"
  EXPECTED="$(awk -v n="$name" '$2 == n || $2 == "*" n {print tolower($1)}' "$WORK/$name.sha256" | head -n 1)"
  [[ "$EXPECTED" =~ ^[0-9a-f]{64}$ ]] || die "cannot parse $name.sha256"
  [ "$HASH" = "$EXPECTED" ] || die "SHA-256 mismatch for $name: local $HASH, $name.sha256 says $EXPECTED"
  verify_provenance "$name"
  HASH_LIST+=("$HASH")
done
echo
echo "SHA-256 (computed locally, matches the .sha256 assets and the build provenance):"
for i in "${!ASSETS[@]}"; do
  echo "  ${ASSETS[$i]}: ${HASH_LIST[$i]}"
done
echo "Compare these with the 'SHA-256' steps of the release workflow log before signing (a second check)."
echo

read -r -p "Sign and publish $TAG (${#ASSETS[@]} assets)? [y/N] " ANSWER
[[ "$ANSWER" =~ ^[yY]$ ]] || die "cancelled"

for i in "${!ASSETS[@]}"; do
  write_message "${ASSETS[$i]}" "${HASH_LIST[$i]}"
  sign_message "${ASSETS[$i]}"
  verify_signature
done

# Replace an existing .sig (only possible with --republish-sig, or a leftover on the draft).
for name in "${ASSETS[@]}"; do
  SIG_NAME="$name.sig"
  OLD_SIG_ID="$(asset_field "$SIG_NAME" id)"
  if [ -n "$OLD_SIG_ID" ]; then
    [[ "$OLD_SIG_ID" =~ ^[0-9]+$ ]] || die "unexpected asset id: $OLD_SIG_ID"
    echo "Deleting the existing $SIG_NAME (asset $OLD_SIG_ID)"
    api -X DELETE "$REPO_API/releases/assets/$OLD_SIG_ID" >/dev/null
  fi
  echo "Uploading ${SIG_NAME}…"
  UPLOAD_URL="https://uploads.github.com/repos/$FULL_NAME/releases/$RELEASE_ID/assets?name=$SIG_NAME"
  api -X POST -H "Content-Type: application/octet-stream" --data-binary @"$WORK/$SIG_NAME" "$UPLOAD_URL" >"$WORK/upload.json"
  [ "$(jq -r '.size' "$WORK/upload.json")" = "$(wc -c <"$WORK/$SIG_NAME" | tr -d ' ')" ] || die "upload size mismatch: $SIG_NAME"
done

if [ "$IS_DRAFT" = true ]; then
  echo "Publishing ${TAG}…"
  api -X PATCH "$REPO_API/releases/$RELEASE_ID" -d '{"draft":false,"make_latest":"true"}' >"$WORK/published.json"
  [ "$(jq -r '.draft' "$WORK/published.json")" = false ] || die "the release is still a draft"
  URL="$(jq -r '.html_url' "$WORK/published.json")"
else
  URL="$(jq -r '.html_url' "$WORK/release.json")"
fi
echo
echo "Done: $URL"
