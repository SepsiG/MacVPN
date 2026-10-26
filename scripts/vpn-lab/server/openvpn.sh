#!/bin/sh
# The OpenVPN container: "tun" (UDP 1194, routed, DCO-compatible ciphers and AES-256-CBC for the TAP-driver test)
# and "tap" (UDP 1195, layer 2: WinVPN's TAP-Windows6 path).
# shellcheck source=scripts/vpn-lab/server/common.sh
. /lab/server/common.sh

fw_base
probe udp 1194
probe udp 1195
fw_pool 10.99.11.0/24 10.99.11.1
fw_pool 10.99.12.0/24 10.99.12.1
openvpn --config /state/server/openvpn-tun.conf &
openvpn --config /state/server/openvpn-tap.conf &
log "ready"
wait_forever
