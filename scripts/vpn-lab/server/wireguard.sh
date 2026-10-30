#!/bin/sh
# The WireGuard container: kernel WireGuard (Docker Desktop's VM kernel has it), UDP 51820, peers 10.99.13.2-5.
# shellcheck source=scripts/vpn-lab/server/common.sh
. /lab/server/common.sh

fw_base
probe udp 51820
fw_pool 10.99.13.0/24 10.99.13.1
ip link add wg0 type wireguard
wg setconf wg0 /state/server/wg0.conf
ip address add 10.99.13.1/24 dev wg0
ip link set wg0 up
log "ready"
wait_forever
