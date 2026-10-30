#!/bin/bash
# Tests LinVPN's NetworkManager dispatcher script (packaging/linux/nm-dispatcher/90-linvpn-route) on any OS: a copy
# whose PATH starts with fakes of `ip` and `logger` and whose interface folder is a temporary one, run with the
# environment NetworkManager's dispatcher builds (nm-dispatcher-utils.c: CONNECTION_USER_<KEY>, VPN_IP_IFACE,
# VPN_IP4_ADDRESS_0 = "address/prefix gateway"). Runs it with /bin/sh and, when installed, dash (Ubuntu's sh).
set -euo pipefail
cd "$(dirname "$0")/.."
SCRIPT="$PWD/packaging/linux/nm-dispatcher/90-linvpn-route"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   - $1"; }
nok() { FAIL=$((FAIL+1)); echo "FAIL - $1"; }
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else nok "$desc"; fi; }

T="$(mktemp -d "${TMPDIR:-/tmp}/linvpn-route.XXXXXXXX")"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/net/ppp0" "$T/net/ppp12" "$T/net/eth0"
cat > "$T/bin/ip" <<'FAKE'
#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_DIR/ip.log"
case "$*" in
  "-4 route show table main exact "*) printf '%s' "${FAKE_EXACT-}" ;;
  "-4 route show table main default") printf '%s' "${FAKE_DEFAULT-}" ;;
  "-4 route replace "*) exit "${FAKE_REPLACE_RC:-0}" ;;
esac
exit 0
FAKE
cat > "$T/bin/logger" <<'FAKE'
#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_DIR/log"
FAKE
chmod 0755 "$T/bin/ip" "$T/bin/logger"
COPY="$T/90-linvpn-route"
sed -e "s|^PATH=/usr/sbin:/usr/bin:/sbin:/bin\$|PATH=$T/bin:/usr/bin:/bin|" -e "s|^SYS_NET=/sys/class/net\$|SYS_NET=$T/net|" \
  "$SCRIPT" > "$COPY"
chmod 0755 "$COPY"
check "the copy uses the fakes" bash -c "grep -qx 'PATH=$T/bin:/usr/bin:/bin' '$COPY' && grep -qx 'SYS_NET=$T/net' '$COPY'"

check "sh -n" sh -n "$SCRIPT"
if command -v shellcheck >/dev/null 2>&1; then
  check "shellcheck (POSIX sh)" shellcheck -s sh "$SCRIPT"
  check "shellcheck" shellcheck "$0"
else
  echo "skip - shellcheck is not installed"
fi
check "the script is executable" test -x "$SCRIPT"
check "PATH is fixed first" bash -c "grep -m1 -v '^#' '$SCRIPT' | grep -qx 'PATH=/usr/sbin:/usr/bin:/sbin:/bin'"
check "no eval" bash -c "! grep -v '^ *#' '$SCRIPT' | grep -Eq '(^|[^a-z])eval([^a-z]|\$)'"

SHELLS=(/bin/sh)
if command -v dash >/dev/null 2>&1; then SHELLS+=("$(command -v dash)"); else echo "skip - dash is not installed"; fi

# run SHELL ACTION [VAR=VALUE…]: the script's run with exactly these variables; the fakes' logs are reset.
run() {
  local shell="$1" action="$2"; shift 2
  rm -f "$T/ip.log" "$T/log"; : > "$T/ip.log"; : > "$T/log"
  env -i FAKE_DIR="$T" "$@" "$shell" "$COPY" "${IFACE_ARG:-ppp0}" "$action"
}
added() { grep -qx -- "-4 route replace $1 dev $2 metric 50" "$T/ip.log"; }
no_change() { ! grep -q -- "route replace" "$T/ip.log"; }
logged() { grep -qF -- "$1" "$T/log"; }

for sh in "${SHELLS[@]}"; do
  M=(CONNECTION_USER_LINVPN__CLASSFUL=1 VPN_IP_IFACE=ppp0)
  run "$sh" vpn-up "${M[@]}" "VPN_IP4_ADDRESS_0=100.64.30.6/32 100.64.30.1"
  check "$sh: class A → /8 through the PPP interface" added 100.0.0.0/8 ppp0
  check "$sh: one log line" bash -c "logged() { grep -qF -- \"\$1\" '$T/log'; }; logged 'ppp0: added 100.0.0.0/8 (the class of 100.64.30.6)' && [ \$(wc -l < '$T/log') -eq 1 ]"
  check "$sh: the tag" logged "-t linvpn-route --"
  run "$sh" vpn-up "${M[@]}" "VPN_IP4_ADDRESS_0=172.16.5.9/32 0.0.0.0"
  check "$sh: class B → /16 (Windows: 172.16.0.0/16, not /12)" added 172.16.0.0/16 ppp0
  run "$sh" vpn-up "${M[@]}" "VPN_IP4_ADDRESS_0=198.51.100.20/32 0.0.0.0"
  check "$sh: class C → /24" added 198.51.100.0/24 ppp0
  run "$sh" vpn-up CONNECTION_USER_LINVPN__CLASSFUL=1 VPN_IP_IFACE=ppp12 "VPN_IP4_ADDRESS_0=100.64.3.4/32 0.0.0.0"
  check "$sh: another PPP interface" added 100.0.0.0/8 ppp12
  for a in 127.0.0.5 0.1.2.3 224.0.0.9 239.1.1.1 240.0.0.1 255.255.255.255; do
    run "$sh" vpn-up "${M[@]}" "VPN_IP4_ADDRESS_0=$a/32 0.0.0.0"
    check "$sh: $a has no class route" no_change
  done

  # Only vpn-up of a marked connection.
  for action in up down vpn-down pre-up dhcp4-change connectivity-change ""; do
    run "$sh" "$action" "${M[@]}" "VPN_IP4_ADDRESS_0=100.64.30.6/32 0.0.0.0"
    check "$sh: action '$action' does nothing" bash -c "[ ! -s '$T/ip.log' ] && [ ! -s '$T/log' ]"
  done
  for mark in "" CONNECTION_USER_LINVPN__CLASSFUL=0 CONNECTION_USER_LINVPN__CLASSFUL=yes "CONNECTION_USER_LINVPN__CLASSFUL=1 " CONNECTION_USER_OTHER=1; do
    run "$sh" vpn-up VPN_IP_IFACE=ppp0 "VPN_IP4_ADDRESS_0=100.64.30.6/32 0.0.0.0" ${mark:+"$mark"}
    check "$sh: not marked ('$mark') does nothing" bash -c "[ ! -s '$T/ip.log' ] && [ ! -s '$T/log' ]"
  done

  # The interface: pppN only, and it exists.
  for i in eth0 ppp ppp12345 "ppp0;touch $T/pwned" "ppp0 " ../ppp0 nm-xfrm-1 tun0 PPP0 ppp7; do
    run "$sh" vpn-up CONNECTION_USER_LINVPN__CLASSFUL=1 "VPN_IP_IFACE=$i" "VPN_IP4_ADDRESS_0=100.64.30.6/32 0.0.0.0"
    check "$sh: interface '$i' gets no route" no_change
  done
  check "$sh: nothing ran from an interface name" test ! -e "$T/pwned"

  # The address: a plain dotted quad only.
  # shellcheck disable=SC2016  # the command substitution must reach the script unexpanded
  for a in "" 100.64.0 100.64.0.256 0100.64.1.1 1.2.3.4.5 ".1.2.3" "1..2.3" "a.b.c.d" '$(touch '"$T"'/pwned2)' "100.64.0.1;x" "*.*.*.*" "100.64.0.1 " 1000.1.1.1; do
    run "$sh" vpn-up "${M[@]}" "VPN_IP4_ADDRESS_0=$a/32 0.0.0.0"
    check "$sh: address '$a' gets no route" no_change
  done
  run "$sh" vpn-up "${M[@]}"
  check "$sh: no address at all gets no route" no_change
  check "$sh: nothing ran from an address" test ! -e "$T/pwned2"

  # Conflicts.
  run "$sh" vpn-up "${M[@]}" "VPN_IP4_ADDRESS_0=198.51.100.20/32 0.0.0.0" \
    "FAKE_EXACT=198.51.100.0/24 dev eth0 proto kernel scope link src 198.51.100.5 metric 100"
  check "$sh: the same network on another interface stays" no_change
  check "$sh: … and says so" logged "198.51.100.0/24 is already routed elsewhere"
  run "$sh" vpn-up "${M[@]}" "VPN_IP4_ADDRESS_0=198.51.100.20/32 0.0.0.0" "FAKE_EXACT=198.51.100.0/24 dev ppp0 scope link metric 50"
  check "$sh: our own earlier route is replaced" added 198.51.100.0/24 ppp0
  run "$sh" vpn-up "${M[@]}" "VPN_IP4_ADDRESS_0=100.64.30.6/32 0.0.0.0" \
    "FAKE_EXACT=100.0.0.0/8 dev ppp00 scope link"
  check "$sh: another interface whose name starts like ours is another" no_change
  run "$sh" vpn-up "${M[@]}" "VPN_IP4_ADDRESS_0=100.64.30.6/32 0.0.0.0" \
    "FAKE_DEFAULT=default via 100.64.0.1 dev eth0 proto dhcp src 100.64.0.20 metric 100"
  check "$sh: the default gateway inside the network: no route" no_change
  check "$sh: … and says so" logged "the default gateway 100.64.0.1 is in 100.0.0.0/8"
  run "$sh" vpn-up "${M[@]}" "VPN_IP4_ADDRESS_0=100.64.30.6/32 0.0.0.0" \
    "$(printf 'FAKE_DEFAULT=default via 203.0.113.1 dev eth0 metric 100\ndefault via 198.51.100.1 dev wlan0 metric 600\n')"
  check "$sh: default gateways outside: the route" added 100.0.0.0/8 ppp0
  run "$sh" vpn-up "${M[@]}" "VPN_IP4_ADDRESS_0=172.16.5.9/32 0.0.0.0" \
    "FAKE_DEFAULT=default via 172.17.0.1 dev eth0 metric 100"
  check "$sh: a gateway in the next class B network is outside" added 172.16.0.0/16 ppp0
  run "$sh" vpn-up "${M[@]}" "VPN_IP4_ADDRESS_0=100.64.30.6/32 0.0.0.0" FAKE_REPLACE_RC=2
  check "$sh: a failed add is logged" logged "ppp0: could not add 100.0.0.0/8"
  check "$sh: always exit 0" bash -c "env -i FAKE_DIR='$T' FAKE_REPLACE_RC=2 CONNECTION_USER_LINVPN__CLASSFUL=1 VPN_IP_IFACE=ppp0 'VPN_IP4_ADDRESS_0=100.64.1.1/32 0.0.0.0' '$sh' '$COPY' ppp0 vpn-up; env -i '$sh' '$COPY'"
done

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
