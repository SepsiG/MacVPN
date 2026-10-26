#!/bin/sh
# L2TP/IPsec selftest (runs inside the selftest-l2tp container: the lab's Alpine image, whose xl2tpd 1.3.20 works
# with ppp 2.5): IKEv1 main mode with the PSK, ESP transport mode for UDP 1701, then L2TP + PPP with MS-CHAPv2,
# exactly the settings MacVPN's and Windows' L2TP clients use. Same address rewrite as run.sh (no hairpin in Docker
# Desktop).
set -u
# shellcheck source=/dev/null
. /profiles/secrets.env
H="$LAB_HOST"
W=/tmp/selftest-l2tp
rm -rf "$W"; mkdir -p "$W" /etc/xl2tpd /var/run/xl2tpd; chmod 700 "$W"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   - $1"; }
nok() { FAIL=$((FAIL+1)); echo "FAIL - $1"; [ -z "${2:-}" ] || { echo "--- $2 (last lines)"; tail -n 25 "$2"; echo "---"; }; }
wait_for() { n=$(( $1 * 2 )); shift; while [ "$n" -gt 0 ]; do "$@" && return 0; sleep 0.5; n=$((n-1)); done; return 1; }
ppp_up() { ip -4 address show ppp0 2>/dev/null | grep -q 'inet 10\.99\.16\.'; }
page() { wget -qO- -T 8 "${1:-http://10.99.0.10/cgi-bin/index.cgi}" 2>/dev/null | grep -q 'via: ipsec'; }

iptables -t nat -F OUTPUT
iptables -t nat -A OUTPUT -d "$H" -p udp --dport 500 -j DNAT --to-destination 172.31.99.20:500
iptables -t nat -A OUTPUT -d "$H" -p udp --dport 4500 -j DNAT --to-destination 172.31.99.20:4500

# bypass-lan would exempt the edge network (where the server is) from IPsec.
printf 'charon {\n  plugins {\n    bypass-lan {\n      load = no\n    }\n  }\n}\n' >/etc/strongswan.d/zz-selftest.conf
cat >/etc/swanctl/swanctl.conf <<EOC
connections {
  lab-l2tp {
    version = 1
    remote_addrs = $H
    proposals = aes256-sha256-modp2048
    local {
      auth = psk
    }
    remote {
      auth = psk
    }
    children {
      lab-l2tp {
        mode = transport
        local_ts = dynamic[udp/1701]
        # The server is behind NAT (Docker): its selector is its own address, not the dialled one.
        remote_ts = 0.0.0.0/0[udp/1701]
        esp_proposals = aes256-sha256
      }
    }
  }
}
secrets {
  ike-lab {
    secret = "$LAB_PSK"
  }
}
EOC
chmod 600 /etc/swanctl/swanctl.conf
/usr/lib/strongswan/charon >"$W/charon.log" 2>&1 &
wait_for 10 swanctl --stats >/dev/null 2>&1
log="$W/l2tp.log"
if swanctl --load-all >"$log" 2>&1 && swanctl --initiate --child lab-l2tp --timeout 30 >>"$log" 2>&1; then
  ok "l2tp: IPsec transport SA (IKEv1 main mode, PSK)"
  printf '[lac lab]\nlns = %s\npppoptfile = %s\nlength bit = yes\n' "$H" "$W/options" >/etc/xl2tpd/xl2tpd.conf
  printf 'name %s\npassword %s\nnoauth\nrefuse-pap\nrefuse-chap\nrefuse-eap\nrefuse-mschap\nnodefaultroute\nnoccp\nmtu 1280\nmru 1280\nlogfile %s\n' \
    "$LAB_USER" "$LAB_PASSWORD" "$W/pppd.log" >"$W/options"
  chmod 600 "$W/options"
  xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf >>"$log" 2>&1 &
  xpid=$!
  sleep 1; echo "c lab" >/var/run/xl2tpd/l2tp-control
  if wait_for 20 ppp_up; then
    ip route add 10.99.0.0/24 dev ppp0 2>/dev/null
    if wait_for 5 page; then ok "l2tp: PPP (MS-CHAPv2) up, test page"; else nok "l2tp: test page" "$W/pppd.log"; fi
    if page http://10.99.16.1/cgi-bin/index.cgi; then ok "l2tp: gateway page (10.99.16.1)"; else nok "l2tp: gateway page"; fi
    if nslookup -type=a whoami.lab.test 10.99.16.1 2>/dev/null | grep -q '10\.99\.0\.10'; then
      ok "l2tp: lab DNS through the gateway (10.99.16.1)"
    else nok "l2tp: gateway DNS"; fi
  else
    nok "l2tp: PPP" "$W/pppd.log"
  fi
  echo "d lab" >/var/run/xl2tpd/l2tp-control 2>/dev/null; sleep 1; kill "$xpid" 2>/dev/null
else
  nok "l2tp: IPsec" "$log"
fi
swanctl --terminate --ike lab-l2tp --timeout 5 >/dev/null 2>&1
pkill -x charon 2>/dev/null
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
