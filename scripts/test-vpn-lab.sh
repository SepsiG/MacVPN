#!/bin/bash
# Tests the VPN test lab (scripts/vpn-lab) without Docker: the scripts are shellcheck-clean, profiles.sh generates
# a complete state with throwaway values (a lab PKI the clients accept, name-constrained to the lab's names and
# limited to the TLS server / client and IKE usages, its CA key deleted; the CRL; WireGuard keys that pair; credentials kept across re-runs and renewed with --renew), the client profiles pass
# MacVPN's import and validators for macOS, Windows and Linux (crates/core/tests/vpn_lab_profiles.rs) and pick their
# Windows OpenVPN driver (crates/helper/tests/vpn_lab_driver.rs), the compose files are valid and publish every port
# on LAB_BIND only, the --dry-run modes of up.sh / down.sh / check.sh run nothing, and down.sh deletes only the
# lab's own state folder. Needs OpenSSL 3+.
#
# Usage: scripts/test-vpn-lab.sh [--no-cargo]
set -euo pipefail
cd "$(dirname "$0")/.."
LAB="$PWD/scripts/vpn-lab"
CARGO=1; [ "${1:-}" = "--no-cargo" ] && CARGO=0

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   - $1"; }
nok() { FAIL=$((FAIL+1)); echo "FAIL - $1"; }
check() { local desc="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else nok "$desc"; fi; }

HOST_SCRIPTS=("$LAB/lib.sh" "$LAB/up.sh" "$LAB/down.sh" "$LAB/profiles.sh" "$LAB/check.sh" "$LAB/selftest.sh"
  "$LAB/selftest/run.sh" "$0")
SH_SCRIPTS=("$LAB"/server/*.sh "$LAB/server/index.cgi" "$LAB/selftest/l2tp.sh")
for f in "${HOST_SCRIPTS[@]}"; do check "bash -n ${f#"$PWD"/}" bash -n "$f"; done
for f in "${SH_SCRIPTS[@]}"; do check "sh -n ${f#"$PWD"/}" sh -n "$f"; done
if command -v shellcheck >/dev/null 2>&1; then
  check "shellcheck (host scripts, bash)" shellcheck -x -P "$PWD" "${HOST_SCRIPTS[@]}"
  check "shellcheck (container scripts, sh)" shellcheck -s sh -x "${SH_SCRIPTS[@]}"
else
  echo "skip - shellcheck is not installed"
fi
check "no company name in the lab" bash -c "! grep -rniE 'alpha.?vet' '$LAB' '$0'"
check ".state is git-ignored" git check-ignore -q scripts/vpn-lab/.state/secrets.env

# shellcheck source=scripts/vpn-lab/lib.sh
. "$LAB/lib.sh"
OSSL="$(find_openssl)" || { echo "FAIL - OpenSSL 3+ is needed"; exit 1; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/test-vpn-lab.XXXXXXXX")"
trap 'rm -rf "${WORK:?}"' EXIT
export LAB_STATE="$WORK/state"
HOST=192.0.2.10   # TEST-NET-1: never a real server

check "profiles.sh refuses a missing server name" bash -c "! LAB_HOST= LAB_BIND= '$LAB/profiles.sh'"
check "profiles.sh refuses a bad --bind" bash -c "! '$LAB/profiles.sh' --bind 300.1.2.3"
check "profiles.sh generates the state" "$LAB/profiles.sh" --bind "$HOST"
S="$LAB_STATE"
for f in secrets.env .vpn-lab-state pki/ca.pem pki/server.pem pki/server.key pki/client.p12 pki/ca.crl crl/ca.crl \
         server/swanctl.conf server/chap-secrets server/openvpn-tun.conf server/openvpn-tap.conf server/wg0.conf \
         server/accel-ppp.conf server/openvpn-users.env client/CREDENTIALS.txt \
         client/macos/swanctl/x509ca/lab-ca.pem client/macos/swanctl/x509/lab-client.pem \
         client/macos/swanctl/private/lab-client.key client/windows/lab-ca.cer client/windows/lab-client.p12 \
         client/windows/l2tp.txt client/windows/cisco-ipsec.txt client/selftest/secrets.env; do
  check "generated: $f" test -s "$S/$f"
done
perm() { stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1"; }
check "secrets.env is private (600)" test "$(perm "$S/secrets.env")" = 600
check "the state folder is private (700)" test "$(perm "$S")" = 700
# shellcheck source=/dev/null
. "$S/secrets.env"
check "credentials are letters and digits" bash -c "[[ '$LAB_PASSWORD$LAB_PSK$LAB_P12_PASSWORD' =~ ^[A-Za-z0-9]+$ ]]"
check "password 20, PSK 24 characters, a 6-digit code" \
  bash -c "[ ${#LAB_PASSWORD} = 20 ] && [ ${#LAB_PSK} = 24 ] && [[ '$LAB_OTP_CODE' =~ ^[0-9]{6}$ ]]"

# The PKI as the clients see it.
check "server certificate: issued by the lab CA, valid for $HOST" \
  "$OSSL" verify -CAfile "$S/pki/ca.pem" -verify_ip "$HOST" -purpose sslserver "$S/pki/server.pem"
check "server certificate: IKE intermediate EKU (Windows IKEv2)" \
  bash -c "'$OSSL' x509 -in '$S/pki/server.pem' -noout -ext extendedKeyUsage | grep -qE '1\.3\.6\.1\.5\.5\.8\.2\.2|IPSec End|ipsecIKE'"
check "server certificate: the CRL distribution point on $HOST:${LAB_CRL_PORT}" \
  bash -c "'$OSSL' x509 -in '$S/pki/server.pem' -noout -ext crlDistributionPoints | grep -q 'http://$HOST:$LAB_CRL_PORT/ca.crl'"
check "client certificate: issued by the lab CA, client EKU" \
  "$OSSL" verify -CAfile "$S/pki/ca.pem" -purpose sslclient "$S/pki/client.pem"
# The CA key is gone (nothing can be signed with it), so its limits are read from the certificate: exactly the lab's
# names, and exactly the TLS server, TLS client and IKE intermediate usages (never code signing).
check "the CA's name constraints permit only the lab's names" bash -c "
  [ \"\$('$OSSL' x509 -in '$S/pki/ca.pem' -noout -ext nameConstraints | sed 's/^ *//' | sed 1d)\" = \"\$(printf 'Permitted:\nDNS:lab.test\nIP:$HOST/255.255.255.255')\" ]"
check "the CA's extended key usages: TLS server, TLS client, IKE intermediate only" bash -c "
  [ \"\$('$OSSL' x509 -in '$S/pki/ca.pem' -noout -ext extendedKeyUsage | sed 1d | sed 's/^ *//')\" = \
    'TLS Web Server Authentication, TLS Web Client Authentication, 1.3.6.1.5.5.8.2.2' ]"
check "the CA's private key, serial and CRL database are deleted" bash -c \
  "[ ! -e '$S/pki/ca.key' ] && [ ! -e '$S/pki/ca.srl' ] && [ ! -e '$S/pki/ca-db' ] && ! grep -rlq 'PRIVATE KEY' '$S/pki/ca.pem' '$S/client'/*/lab-ca.*"
check "the CRL is signed by the lab CA" \
  bash -c "'$OSSL' crl -inform DER -in '$S/crl/ca.crl' -noout -CAfile '$S/pki/ca.pem' 2>&1 | grep -q 'verify OK'"
check "lab-client.p12 opens with its password" \
  "$OSSL" pkcs12 -in "$S/client/windows/lab-client.p12" -passin "pass:$LAB_P12_PASSWORD" -noout
check "lab-ca.cer is the CA in DER" bash -c "cmp -s <('$OSSL' x509 -inform DER -in '$S/client/windows/lab-ca.cer') <('$OSSL' x509 -in '$S/pki/ca.pem')"

# LinVPN's imports (client/linux): the macOS set with its own WireGuard peer, and the user labfull, whose OpenVPN
# session gets a pushed redirect-gateway (LinVPN's "Server decides" routing test).
STATE="$S"
L="$STATE/client/linux"
check "linux: openvpn profiles"        test -f "$L/openvpn-tun-dco.ovpn" -a -f "$L/openvpn-static-challenge.ovpn" -a -f "$L/openvpn-tun-cbc.ovpn"
check "linux: own wireguard peer"      grep -q '^Address = 10.99.13.5/' "$L/wireguard-linux.conf"
check "linux: wireguard key differs"   test "$(grep PrivateKey "$L/wireguard-linux.conf")" != "$(grep PrivateKey "$STATE/client/macos/wireguard-macos.conf")"
check "server knows the linux peer"    grep -q "$(sed -n 's/^PublicKey = //p' "$STATE/client/linux/wireguard-linux.pub" 2>/dev/null || echo none)" "$STATE/server/wg0.conf"
check "linux: ikev2 alt port"          grep -q 'remote_port = 4510' "$L/ikev2-eap.swanctl.conf"
check "linux: swanctl folder"          test -f "$L/swanctl/x509ca/lab-ca.pem" -a -f "$L/swanctl/x509/lab-client.pem" -a -f "$L/swanctl/private/lab-client.key"
check "linux: forms"                   test -f "$L/l2tp.txt" -a -f "$L/cisco-ipsec.txt"
check "labfull gets redirect-gateway"  grep -q 'push "redirect-gateway def1"' "$STATE/server/ccd/labfull"
check "labfull in credentials"         grep -q 'labfull' "$STATE/client/CREDENTIALS.txt"

# WireGuard: each client's private key pairs with the public key the server lists for it, and the client knows the
# server's public key.
wg_pub() { # raw base64 private key -> base64 public key
  { printf '302e020100300506032b656e04220420' | xxd -r -p; printf '%s' "$1" | base64 -d; } >"$WORK/wgk.der"
  "$OSSL" pkey -inform DER -in "$WORK/wgk.der" -pubout -outform DER | tail -c 32 | base64
}
wg_pair() { # client-file peer-comment
  local priv pub
  priv="$(sed -n 's/^PrivateKey = //p' "$1")"
  pub="$(wg_pub "$priv")"
  grep -A1 "^# $2\$" "$S/server/wg0.conf" | grep -q "PublicKey = $pub" \
    && grep -q "PublicKey = $(wg_pub "$(sed -n 's/^PrivateKey = //p' "$S/server/wg0.conf")")" "$1"
}
check "WireGuard keys pair (macOS)" wg_pair "$S/client/macos/wireguard-macos.conf" macos
check "WireGuard keys pair (Windows)" wg_pair "$S/client/windows/wireguard-windows.conf" windows
check "WireGuard keys pair (selftest)" wg_pair "$S/client/selftest/wireguard.conf" selftest
check "WireGuard keys pair (Linux)" wg_pair "$S/client/linux/wireguard-linux.conf" linux

# The profiles route only the lab, and carry no secret.
check "no profile sends all traffic (no 0.0.0.0/0, route_all=no, no redirect-gateway)" bash -c \
  "! grep -rlE '0\.0\.0\.0/0|route_all=yes|redirect-gateway' '$S/client/macos' '$S/client/windows' '$S/client/linux'"
check "no profile contains the password or the PSK" bash -c \
  "! grep -rlE '$LAB_PASSWORD|$LAB_PSK' '$S/client/macos' '$S/client/windows' '$S/client/linux' --include='*.ovpn' --include='*.conf' --include='*.sstp'"
check "macOS IKEv2 profiles use the alternative IKE port, Windows' none" bash -c \
  "[ \"\$(grep -l 'remote_port = $LAB_IKE_ALT_PORT' '$S'/client/macos/*.swanctl.conf | wc -l)\" -eq 3 ] && ! grep -q remote_port '$S'/client/windows/*.swanctl.conf"

# Re-runs keep the credentials and the CA; --renew replaces both; another server name makes a new PKI.
ca1="$("$OSSL" x509 -in "$S/pki/ca.pem" -noout -fingerprint -sha256)"
"$LAB/profiles.sh" >/dev/null 2>&1
check "a re-run keeps the credentials and the CA" bash -c \
  "grep -q 'LAB_PASSWORD=$LAB_PASSWORD' '$S/secrets.env' && [ \"\$('$OSSL' x509 -in '$S/pki/ca.pem' -noout -fingerprint -sha256)\" = '$ca1' ]"
check "a re-run without the CA key keeps the CRL and the certificates valid" bash -c \
  "[ ! -e '$S/pki/ca.key' ] && '$OSSL' crl -inform DER -in '$S/crl/ca.crl' -noout -CAfile '$S/pki/ca.pem' 2>&1 | grep -q 'verify OK' \
   && '$OSSL' verify -CAfile '$S/pki/ca.pem' -purpose sslserver '$S/pki/server.pem'"
# A state made before the linux peer existed (no wg-linux key) gains it on a re-run; the other keys stay.
mac_wg="$(cat "$S/pki/wg-macos.key")"
rm -f "$S/pki/wg-linux.pem" "$S/pki/wg-linux.key" "$S/pki/wg-linux.pub"
"$LAB/profiles.sh" >/dev/null 2>&1
check "a re-run adds a missing linux WireGuard key and keeps the others" bash -c \
  "test -s '$S/pki/wg-linux.key' && [ \"\$(cat '$S/pki/wg-macos.key')\" = '$mac_wg' ]"
check "WireGuard keys pair (Linux, added later)" wg_pair "$S/client/linux/wireguard-linux.conf" linux
"$LAB/profiles.sh" --renew >/dev/null 2>&1
check "--renew makes new credentials and a new CA" bash -c \
  "! grep -q 'LAB_PASSWORD=$LAB_PASSWORD' '$S/secrets.env' && [ \"\$('$OSSL' x509 -in '$S/pki/ca.pem' -noout -fingerprint -sha256)\" != '$ca1' ]"
LAB_STATE="$WORK/named" "$LAB/profiles.sh" --host vpn-lab.example.test --bind "$HOST" >/dev/null 2>&1
check "a DNS server name: the certificate names both" \
  "$OSSL" verify -CAfile "$WORK/named/pki/ca.pem" -verify_hostname vpn-lab.example.test -verify_ip "$HOST" "$WORK/named/pki/server.pem"

# Compose: valid, and every published port is bound to LAB_BIND only.
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  cfg() { LAB_BIND="$HOST" docker compose -p macvpn-lab -f "$LAB/compose.yaml" -f "$LAB/compose.ike-standard-ports.yaml" \
    --profile selftest config --format json; }
  check "compose files are valid" cfg
  check "every published port is bound to LAB_BIND" bash -c "
    [ \"\$(LAB_BIND=$HOST LAB_STATE='$S' docker compose -p macvpn-lab -f '$LAB/compose.yaml' -f '$LAB/compose.ike-standard-ports.yaml' \
      --profile selftest config --format json | python3 -c '
import json, sys
c = json.load(sys.stdin)
ports = [p for s in c[\"services\"].values() for p in s.get(\"ports\", [])]
bad = [p for p in ports if p.get(\"host_ip\") != \"$HOST\"]
print(\"ok\" if ports and not bad else bad)')\" = ok ]"
  check "the services network is internal" bash -c "
    LAB_BIND=$HOST LAB_STATE='$S' docker compose -p macvpn-lab -f '$LAB/compose.yaml' config --format json \
      | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)[\"networks\"][\"labnet\"].get(\"internal\") else 1)'"
  check "compose refuses to start without LAB_BIND" bash -c \
    "! env -u LAB_BIND LAB_STATE='$S' docker compose -p macvpn-lab -f '$LAB/compose.yaml' config -q"
else
  echo "skip - docker compose is not installed (compose checks)"
fi

# --dry-run: the docker commands are printed, not run (PATH holds a docker that fails if called).
mkdir -p "$WORK/bin"
printf '#!/bin/sh\necho "docker was called" >&2\nexit 99\n' >"$WORK/bin/docker"; chmod +x "$WORK/bin/docker"
check "up.sh --dry-run prints the compose commands, runs no docker" bash -c \
  "PATH='$WORK/bin:$PATH' '$LAB/up.sh' --bind $HOST --dry-run 2>/dev/null | grep -q '^+ docker compose -p macvpn-lab .* up -d --force-recreate'"
check "up.sh --no-ike-standard-ports leaves out UDP 500/4500" bash -c \
  "PATH='$WORK/bin:$PATH' '$LAB/up.sh' --bind $HOST --no-ike-standard-ports --dry-run 2>/dev/null | grep '^+ docker compose' | grep -vq ike-standard-ports"
check "up.sh refuses --bind 0.0.0.0" bash -c "! PATH='$WORK/bin:$PATH' '$LAB/up.sh' --bind 0.0.0.0 --dry-run"
check "up.sh refuses a missing --bind" bash -c "! env -u LAB_BIND PATH='$WORK/bin:$PATH' '$LAB/up.sh' --dry-run"
check "check.sh --dry-run runs no docker" bash -c "PATH='$WORK/bin:$PATH' '$LAB/check.sh' --dry-run | grep -q '^+ docker exec'"
check "down.sh --dry-run runs no docker and keeps the state" bash -c \
  "PATH='$WORK/bin:$PATH' '$LAB/down.sh' --keep-state --dry-run | grep -q '^+ docker compose .* down' && test -s '$S/secrets.env'"

# down.sh deletes only the lab's own state: a folder inside scripts/vpn-lab/ (resolved) with profiles.sh's marker.
# The in-lab test folders are git-ignored (.state*) and removed on exit.
INLAB="$(mktemp -d "$LAB/.state-test.XXXXXXXX")"
trap 'rm -rf "${WORK:?}" "${INLAB:?}"' EXIT
check "down.sh refuses a LAB_STATE outside scripts/vpn-lab (and removes nothing)" bash -c \
  "! LAB_STATE='$S' PATH='$WORK/bin:$PATH' '$LAB/down.sh' 2>/dev/null && ! LAB_STATE='$S' PATH='$WORK/bin:$PATH' '$LAB/down.sh' --dry-run 2>/dev/null && test -s '$S/secrets.env'"
mkdir -p "$INLAB/nomarker"; : >"$INLAB/nomarker/keep"
check "down.sh refuses a folder inside scripts/vpn-lab without the marker" bash -c \
  "! LAB_STATE='$INLAB/nomarker' PATH='$WORK/bin:$PATH' '$LAB/down.sh' 2>/dev/null && test -e '$INLAB/nomarker/keep'"
ln -s "$S" "$INLAB/link"
check "down.sh refuses a symbolic link to a state elsewhere" bash -c \
  "! LAB_STATE='$INLAB/link' PATH='$WORK/bin:$PATH' '$LAB/down.sh' 2>/dev/null && test -s '$S/secrets.env'"
check "down.sh refuses scripts/vpn-lab itself" bash -c \
  "! LAB_STATE='$LAB/.' PATH='$WORK/bin:$PATH' '$LAB/down.sh' 2>/dev/null && test -s '$LAB/up.sh'"
LAB_STATE="$INLAB/state" "$LAB/profiles.sh" --bind "$HOST" >/dev/null 2>&1
check "down.sh deletes the lab's own state (marker written by profiles.sh)" bash -c \
  "test -f '$INLAB/state/.vpn-lab-state' && LAB_STATE='$INLAB/state/../state' PATH='$WORK/bin:$PATH' '$LAB/down.sh' >/dev/null 2>&1 && test ! -e '$INLAB/state'"

# The client profiles through MacVPN's own import and validators, and the Windows OpenVPN driver choice.
if [ "$CARGO" = 1 ]; then
  export MVPN_LAB_CLIENT_DIR="$S/client"
  check "macvpn-core: the profiles import and validate for macOS, Windows and Linux" \
    cargo test -q --locked -p macvpn-core --test vpn_lab_profiles
  check "macvpn-helper: the OpenVPN profiles choose DCO / TAP-Windows6 as named" \
    cargo test -q --locked -p macvpn-helper --test vpn_lab_driver
else
  echo "skip - cargo tests (--no-cargo)"
fi

echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
