#!/bin/sh
# The lab's test page. REMOTE_ADDR is the VPN server's labnet address (the servers masquerade their clients).
addr="${REMOTE_ADDR:-}"
addr="${addr#[}"; addr="${addr%]}"; addr="${addr#::ffff:}"
case "$addr" in
  10.99.0.20) via="ipsec (strongSwan: IKEv2, Cisco IPsec, L2TP/IPsec)" ;;
  10.99.0.21) via="openvpn" ;;
  10.99.0.22) via="wireguard" ;;
  10.99.0.23) via="sstp (accel-ppp)" ;;
  *) via="unknown (${addr:-?})" ;;
esac
printf 'Content-Type: text/plain\r\n\r\n'
printf 'MacVPN lab: OK\nvia: %s\n' "$via"
