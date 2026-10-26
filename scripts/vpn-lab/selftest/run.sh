#!/bin/bash
# Runs inside the selftest container (Debian's clients): connects to every lab server through the ports published on
# the host (LAB_HOST), with the generated client profiles where a client can read them as they are, and checks the
# test page (it names the server the request came through) and the lab DNS through each tunnel. Nothing here runs
# on the host's network: the container has its own network namespace inside Docker.
#
# Usage (selftest.sh runs it): run.sh [kind...]   kinds: wireguard openvpn ikev2 cisco sstp (default: all)
# L2TP runs in the second selftest container (l2tp.sh): Debian 13's xl2tpd 1.3.18 does not bring PPP up with
# ppp 2.5 (its pppd exits at once in kernel mode, and hangs up in userspace mode), Alpine's xl2tpd 1.3.20 does.
set -uo pipefail
P=/profiles
# shellcheck source=/dev/null
. "$P/secrets.env"
H="$LAB_HOST"
WORK=/tmp/selftest
rm -rf "$WORK"; mkdir -p "$WORK"; chmod 700 "$WORK"
# Docker Desktop does not forward a container's packets to the host's published ports (hairpin), so the profiles'
# server address is rewritten here to the servers' edge addresses (same ports; IPsec still sees a NAT: the server's
# own address differs from the one the client dials, so NAT-T is used). check.sh probes the published ports from the
# host itself.
iptables -t nat -F OUTPUT
dnat() { iptables -t nat -A OUTPUT -d "$H" -p "$1" --dport "$2" -j DNAT --to-destination "$3:${4:-$2}"; }
dnat udp 500 172.31.99.20; dnat udp 4500 172.31.99.20; dnat udp "$LAB_IKE_ALT_PORT" 172.31.99.20 4510
dnat udp 1194 172.31.99.21; dnat udp 1195 172.31.99.21; dnat udp 51820 172.31.99.22
dnat tcp "$LAB_SSTP_PORT" 172.31.99.23 443; dnat tcp "$LAB_SSTP_ALT_PORT" 172.31.99.23 8443
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   - $1"; }
nok() { FAIL=$((FAIL+1)); echo "FAIL - $1"; [ -z "${2:-}" ] || { echo "--- $2 (last lines)"; tail -n 25 "$2"; echo "---"; }; }

# page VIA [URL]: the test page answers through the tunnel and names the expected server.
page() {
  local out
  out="$(curl -s --max-time 8 "${2:-http://10.99.0.10/cgi-bin/index.cgi}" 2>/dev/null)"
  [[ "$out" == *"MacVPN lab: OK"* && "$out" == *"via: $1"* ]]
}
# dns [SERVER]: the lab DNS answers the test name through the tunnel.
dns() { [ "$(dig +short +time=3 +tries=2 "@${1:-10.99.0.53}" whoami.lab.test 2>/dev/null)" = "10.99.0.10" ]; }
# wait_for SECONDS COMMAND...: polls until the command succeeds.
wait_for() {
  local n=$(( $1 * 2 )); shift
  while [ "$n" -gt 0 ]; do "$@" && return 0; sleep 0.5; n=$((n-1)); done
  return 1
}
have_if() { ip link show "$1" >/dev/null 2>&1; }

# --- WireGuard -----------------------------------------------------------------------------------------------------
t_wireguard() {
  grep -vE '^(Address|DNS) *=' "$P/wireguard.conf" >"$WORK/wg.conf"
  ip link add wg0 type wireguard && wg setconf wg0 "$WORK/wg.conf" && ip address add 10.99.13.4/32 dev wg0 \
    && ip link set wg0 up && ip route add 10.99.0.0/24 dev wg0 && ip route add 10.99.13.1/32 dev wg0
  if wait_for 10 page wireguard; then ok "wireguard: test page through the tunnel"; else nok "wireguard: test page"; fi
  if dns; then ok "wireguard: lab DNS"; else nok "wireguard: lab DNS"; fi
  if page wireguard http://10.99.13.1/cgi-bin/index.cgi; then ok "wireguard: gateway page"; else nok "wireguard: gateway page"; fi
  ip link del wg0 2>/dev/null
}

# --- OpenVPN -------------------------------------------------------------------------------------------------------
# ovpn NAME PROFILE USER PASSWORD [EXPECT]: EXPECT "up" (default), "crv1" (the server answers with a CRV1
# challenge), "refused" (AUTH_FAILED without a challenge) or "isolation" (nothing outside the lab is reachable)
ovpn() {
  local name="$1" profile="$2" log="$WORK/ovpn-$1.log"
  printf '%s\n%s\n' "$3" "$4" >"$WORK/ovpn-auth"
  openvpn --config "$P/$profile" --auth-user-pass "$WORK/ovpn-auth" --auth-nocache --verb 3 \
    --connect-retry-max 1 --writepid "$WORK/ovpn.pid" >"$log" 2>&1 &
  local pid=$!
  if [ "${5:-up}" = crv1 ]; then
    if wait_for 25 grep -q 'AUTH_FAILED,CRV1:' "$log"; then ok "openvpn $name: server sent a CRV1 challenge"
    else nok "openvpn $name: CRV1 challenge" "$log"; fi
  elif [ "${5:-up}" = isolation ]; then
    # Routes through the tunnel to the internet and to the servers' edge gateway: the server must drop both.
    if wait_for 25 grep -q 'Initialization Sequence Completed' "$log"; then
      ip route add 1.1.1.1/32 dev tun0 2>/dev/null; ip route add 172.31.99.1/32 dev tun0 2>/dev/null
      if ! curl -s --max-time 4 -o /dev/null http://1.1.1.1/ && ! curl -s --max-time 4 -o /dev/null http://172.31.99.1/; then
        ok "openvpn: the tunnel reaches nothing outside the lab (internet, Docker's edge network)"
      else nok "openvpn: isolation"; fi
      ip route del 1.1.1.1/32 2>/dev/null; ip route del 172.31.99.1/32 2>/dev/null
    else nok "openvpn isolation: connect" "$log"; fi
  elif [ "${5:-up}" = refused ]; then
    if wait_for 25 grep -q 'AUTH_FAILED' "$log" && ! grep -q 'CRV1' "$log"; then ok "openvpn $name: refused"
    else nok "openvpn $name: refused" "$log"; fi
  elif wait_for 25 grep -q 'Initialization Sequence Completed' "$log"; then
    if wait_for 5 page openvpn; then ok "openvpn $name: connected, test page"; else nok "openvpn $name: test page" "$log"; fi
    if dns; then ok "openvpn $name: lab DNS"; else nok "openvpn $name: lab DNS"; fi
  else
    nok "openvpn $name: connect" "$log"
  fi
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
}
t_openvpn() {
  ovpn tun-dco openvpn-tun-dco.ovpn "$LAB_USER" "$LAB_PASSWORD"
  ovpn isolation openvpn-tun-dco.ovpn "$LAB_USER" "$LAB_PASSWORD" isolation
  ovpn tun-cbc openvpn-tun-cbc.ovpn "$LAB_USER" "$LAB_PASSWORD"
  if grep -q 'AES-256-CBC' "$WORK/ovpn-tun-cbc.log"; then ok "openvpn tun-cbc: AES-256-CBC negotiated"
  else nok "openvpn tun-cbc: cipher" "$WORK/ovpn-tun-cbc.log"; fi
  ovpn tap-l2 openvpn-tap-l2.ovpn "$LAB_USER" "$LAB_PASSWORD"
  ovpn otp-appended openvpn-tun-dco.ovpn "$LAB_OTP_USER" "$LAB_PASSWORD,$LAB_OTP_CODE"
  ovpn otp-static openvpn-tun-dco.ovpn "$LAB_OTP_USER" \
    "SCRV1:$(printf '%s' "$LAB_PASSWORD" | base64):$(printf '%s' "$LAB_OTP_CODE" | base64)"
  ovpn otp-dynamic openvpn-tun-dco.ovpn "$LAB_OTP_USER" "$LAB_PASSWORD" crv1
  local state
  state="$(grep -o 'AUTH_FAILED,CRV1:[^:]*:[^:]*' "$WORK/ovpn-otp-dynamic.log" | head -n1 | cut -d: -f3)"
  if [ -n "$state" ]; then
    ovpn otp-dynamic-answer openvpn-tun-dco.ovpn "$LAB_OTP_USER" "CRV1::$state::$LAB_OTP_CODE"
  fi
  ovpn wrong-password openvpn-tun-dco.ovpn "$LAB_USER" "wrong-$LAB_PASSWORD" refused
}

# --- strongSwan client (IKEv2, Cisco IPsec, L2TP's IPsec) ----------------------------------------------------------
charon_start() {
  # `swanctl --load-all --file <config>` reads x509ca/, x509/ and private/ next to <config> (not /etc/swanctl) and
  # unloads private keys it does not find there, so the lab CA and the client certificate go next to the config.
  mkdir -p "$WORK/x509ca" "$WORK/x509" "$WORK/private"
  cp "$P/lab-ca.pem" "$WORK/x509ca/lab-ca.pem"
  cp "$P/lab-client.pem" "$WORK/x509/lab-client.pem"
  cp "$P/lab-client.key" "$WORK/private/lab-client.key"
  # bypass-lan would exempt the container's own subnet (the servers' edge network) from IPsec.
  printf 'charon {\n  plugins {\n    bypass-lan {\n      load = no\n    }\n  }\n}\n' >/etc/strongswan.d/zz-selftest.conf
  /usr/lib/ipsec/charon >"$WORK/charon.log" 2>&1 &
  wait_for 10 swanctl --stats >/dev/null 2>&1
}
charon_stop() { pkill -x charon 2>/dev/null; sleep 1; ip xfrm state flush; ip xfrm policy flush; }
# swan NAME CONFIG CHILD VIA: MacVPN's helper flow: the profile plus a `secrets` block, --load-all --file, initiate.
swan() {
  local name="$1" log="$WORK/swan-$1.log"
  cp "$2" "$WORK/swan.conf"
  { echo "secrets {"
    echo "  ike-macvpn {"; echo "    secret = \"$LAB_PSK\""; echo "  }"
    echo "  eap-macvpn {"; echo "    id = \"$LAB_USER\""; echo "    secret = \"$LAB_PASSWORD\""; echo "  }"
    echo "  xauth-macvpn {"; echo "    id = \"$LAB_USER\""; echo "    secret = \"$LAB_PASSWORD\""; echo "  }"
    echo "}"; } >>"$WORK/swan.conf"
  if swanctl --load-all --file "$WORK/swan.conf" >"$log" 2>&1 \
     && swanctl --initiate --child "$3" --timeout 30 >>"$log" 2>&1; then
    if wait_for 5 page "$4"; then ok "$name: connected, test page"; else nok "$name: test page" "$log"; fi
    if dns; then ok "$name: lab DNS"; else nok "$name: lab DNS"; fi
  else
    nok "$name: connect" "$log"
  fi
  swanctl --terminate --ike "$3" --timeout 5 >/dev/null 2>&1
  swanctl --load-all --file /dev/null >/dev/null 2>&1 || true
}
t_ikev2() {
  charon_start
  swan "ikev2 eap (Windows form, UDP 500)" "$P/windows-ikev2-eap.swanctl.conf" lab-eap ipsec
  swan "ikev2 psk (Windows form, UDP 500)" "$P/windows-ikev2-psk.swanctl.conf" lab-psk ipsec
  swan "ikev2 eap (macOS form, alt port)" "$P/macos-ikev2-eap.swanctl.conf" lab-eap ipsec
  swan "ikev2 psk (macOS form, alt port)" "$P/macos-ikev2-psk.swanctl.conf" lab-psk ipsec
  swan "ikev2 cert (macOS form, alt port)" "$P/macos-ikev2-cert.swanctl.conf" lab-cert ipsec
  charon_stop
}
t_cisco() {
  charon_start
  cat >"$WORK/cisco.conf" <<EOF
connections {
  lab-cisco {
    version = 1
    aggressive = yes
    remote_addrs = $H
    vips = 0.0.0.0
    proposals = aes256-sha256-modp2048
    local {
      auth = psk
      id = keyid:$LAB_GROUP
    }
    local-xauth {
      auth = xauth
      xauth_id = $LAB_USER
    }
    remote {
      auth = psk
    }
    children {
      lab-cisco {
        remote_ts = 10.99.0.0/24
        esp_proposals = aes256-sha256
      }
    }
  }
}
EOF
  swan "cisco ipsec (IKEv1 aggressive, PSK + XAUTH)" "$WORK/cisco.conf" lab-cisco ipsec
  charon_stop
}
# --- SSTP ----------------------------------------------------------------------------------------------------------
sstp() { # NAME PORT
  local log="$WORK/sstp-$1.log"
  sstpc --log-stdout --log-level 2 --ca-cert "$P/lab-ca.pem" --user "$LAB_USER" --password "$LAB_PASSWORD" \
    "$H:$2" require-mschap-v2 noauth nodefaultroute refuse-pap refuse-chap refuse-eap refuse-mschap noccp >"$log" 2>&1 &
  local pid=$!
  if wait_for 20 have_if ppp0 && wait_for 10 ip -4 address show ppp0 | grep -q 'inet 10.99.17.'; then
    ip route add 10.99.0.0/24 dev ppp0 2>/dev/null
    if wait_for 5 page "sstp"; then ok "sstp $1: MS-CHAPv2 over TLS, test page"; else nok "sstp $1: test page" "$log"; fi
    if dns 10.99.17.1; then ok "sstp $1: lab DNS through the gateway (10.99.17.1)"; else nok "sstp $1: gateway DNS"; fi
  else
    nok "sstp $1: connect" "$log"
  fi
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; sleep 1
}
t_sstp() {
  sstp "port $LAB_SSTP_PORT" "$LAB_SSTP_PORT"
  sstp "port $LAB_SSTP_ALT_PORT" "$LAB_SSTP_ALT_PORT"
}

KINDS=("$@"); [ "${#KINDS[@]}" -gt 0 ] || KINDS=(wireguard openvpn ikev2 cisco sstp)
for k in "${KINDS[@]}"; do
  case "$k" in
    wireguard|openvpn|ikev2|cisco|sstp) "t_$k" ;;
    *) nok "unknown kind: $k" ;;
  esac
done
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
