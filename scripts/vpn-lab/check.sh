#!/bin/bash
# Server-side health of the running lab: every container runs, each server has its configuration loaded, the test
# page and the lab DNS answer, the services network cannot reach outside, and the ports published on LAB_BIND
# deliver traffic (a TLS handshake with the lab CA on the SSTP ports; one probe datagram per UDP port, counted by
# the server's firewall). Changes nothing on the host: it only opens ordinary client sockets to LAB_BIND.
# Prints the exact package versions of the images. With --selftest it also runs selftest.sh.
#
# Usage: check.sh [--selftest] [--dry-run]
set -euo pipefail
# shellcheck source=scripts/vpn-lab/lib.sh
. "$(dirname "$0")/lib.sh"

SELFTEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --selftest) SELFTEST=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
load_state
export LAB_BIND LAB_SSTP_PORT LAB_SSTP_ALT_PORT LAB_IKE_ALT_PORT LAB_CRL_PORT

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   - $1"; }
nok() { FAIL=$((FAIL+1)); echo "FAIL - $1"; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else nok "$d"; fi; }
in_c() { local c="$1"; shift; run docker exec "$COMPOSE_PROJECT-$c-1" "$@"; }

if [ "$DRY_RUN" = 1 ]; then
  in_c ipsec swanctl --list-conns
  in_c ipsec iptables -nvxL INPUT
  echo "+ openssl s_client -connect $LAB_BIND:$LAB_SSTP_PORT -CAfile $LAB_STATE/pki/ca.pem …"
  exit 0
fi
docker_ready || die "the Docker daemon does not answer"

# --- containers ----------------------------------------------------------------------------------------------------
for c in ipsec openvpn wireguard sstp crl web dns; do
  check "container $c runs" test "$(docker inspect -f '{{.State.Running}}' "$COMPOSE_PROJECT-$c-1" 2>/dev/null)" = true
done

# --- servers -------------------------------------------------------------------------------------------------------
conns="$(in_c ipsec swanctl --list-conns 2>/dev/null || true)"
for n in ikev2-eap ikev2-cert ikev2-psk cisco-xauth l2tp-psk; do
  check "strongSwan: connection $n loaded" grep -q "^$n:" <<<"$conns"
done
# shellcheck disable=SC2329 # count and pools run through check
count() { local want="$1"; shift; [ "$("$@" 2>/dev/null | wc -l | tr -d ' ')" = "$want" ]; }
# shellcheck disable=SC2329
pools() { in_c ipsec swanctl --list-pools | grep -E '^(ikev2|cisco) '; }
check "strongSwan: pools ikev2 and cisco" count 2 pools
check "xl2tpd runs" in_c ipsec pgrep -x xl2tpd
check "OpenVPN: two servers (tun 1194, tap 1195)" count 2 in_c openvpn pgrep -x openvpn
check "WireGuard: wg0 with 3 peers" count 3 in_c wireguard wg show wg0 peers
check "accel-ppp (SSTP) runs" in_c sstp pgrep -x accel-pppd
check "test page answers (from the ipsec container)" in_c ipsec wget -qO- -T 5 http://10.99.0.10/cgi-bin/index.cgi
check "lab DNS answers whoami.lab.test" bash -c "docker exec $COMPOSE_PROJECT-ipsec-1 nslookup -type=a whoami.lab.test 10.99.0.53 | grep -q 10.99.0.10"
for c in ipsec openvpn wireguard sstp; do
  check "$c: FORWARD policy is DROP" bash -c "docker exec $COMPOSE_PROJECT-$c-1 iptables -S FORWARD | grep -qx -- '-P FORWARD DROP'"
done
check "the services network has no way out (web cannot reach 1.1.1.1)" \
  bash -c "! docker exec $COMPOSE_PROJECT-web-1 wget -qO- -T 3 http://1.1.1.1/"

# --- the published ports, from this host ---------------------------------------------------------------------------
OSSL="$(find_openssl || echo openssl)"
for port in "$LAB_SSTP_PORT" "$LAB_SSTP_ALT_PORT"; do
  verify=(-verify_hostname "$LAB_HOST"); is_ipv4 "$LAB_HOST" && verify=(-verify_ip "$LAB_HOST")
  check "SSTP TLS on $LAB_BIND:$port (lab CA, name $LAB_HOST)" bash -c \
    "echo | '$OSSL' s_client -connect '$LAB_BIND:$port' -CAfile '$LAB_STATE/pki/ca.pem' ${verify[*]} -verify_return_error 2>&1 | grep -q 'Verify return code: 0 (ok)'"
done
check "CRL served on $LAB_BIND:$LAB_CRL_PORT (the server certificate's distribution point)" bash -c \
  "curl -s --max-time 5 'http://$LAB_BIND:$LAB_CRL_PORT/ca.crl' | '$OSSL' crl -inform DER -noout -CAfile '$LAB_STATE/pki/ca.pem' 2>&1 | grep -q 'verify OK'"
counter() { # container proto port
  docker exec "$COMPOSE_PROJECT-$1-1" iptables -nvxL INPUT 2>/dev/null | awk -v c="lab-probe $2/$3" 'index($0, c) {print $1; exit}'
}
probe_udp() { # host-port container counted-port
  local before after
  before="$(counter "$2" udp "$3")"
  printf 'macvpn-lab-probe' | nc -u -w 1 "$LAB_BIND" "$1" >/dev/null 2>&1 || true
  sleep 1
  after="$(counter "$2" udp "$3")"
  [ -n "$before" ] && [ -n "$after" ] && [ "$after" -gt "$before" ]
}
UDP_PORTS=("$LAB_IKE_ALT_PORT:ipsec:4500" "1194:openvpn:1194" "1195:openvpn:1195" "51820:wireguard:51820")
if docker port "$COMPOSE_PROJECT-ipsec-1" 500/udp >/dev/null 2>&1; then
  UDP_PORTS=("500:ipsec:500" "4500:ipsec:4500" "${UDP_PORTS[@]}")
else
  echo "info - UDP 500/4500 not published (--no-ike-standard-ports)"
fi
for spec in "${UDP_PORTS[@]}"; do
  IFS=: read -r hp c cp <<<"$spec"
  if [ "$hp" = 500 ] && [ "$(uname -s)" = Darwin ]; then
    # A datagram from the Mac to its own address' UDP 500 was not always delivered to Docker's listener (README,
    # "What works through Docker Desktop"); it does not concern clients on the LAN. Reported, not counted.
    if probe_udp "$hp" "$c" "$cp"; then echo "ok   - UDP $LAB_BIND:500 reaches the ipsec server"
    else echo "info - UDP $LAB_BIND:500 from this Mac itself was not delivered (seen at times on macOS); check from the VM (README)"; fi
    continue
  fi
  check "UDP $LAB_BIND:$hp reaches the $c server" probe_udp "$hp" "$c" "$cp"
done

# --- versions ------------------------------------------------------------------------------------------------------
echo "--- versions (server image: Alpine; selftest image: Debian)"
docker exec "$COMPOSE_PROJECT-dns-1" sh -c 'head -n1 /etc/alpine-release; grep -E "^(strongswan|xl2tpd|ppp|openvpn|wireguard-tools-wg|accel-ppp|dnsmasq|libssl3)-[0-9]" /lab-packages.txt' \
  | tr '\n' ' '; echo
docker run --rm "macvpn-lab-client:local" sh -c 'grep -E "^(strongswan-charon|xl2tpd|ppp|openvpn|wireguard-tools|sstp-client) " /lab-packages.txt' 2>/dev/null \
  | tr '\n' ' '; echo

echo "$PASS passed, $FAIL failed"
status=0; [ "$FAIL" = 0 ] || status=1
if [ "$SELFTEST" = 1 ]; then "$LAB_DIR/selftest.sh" || status=1; fi
exit "$status"
