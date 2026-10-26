#!/bin/sh
# The SSTP container: accel-ppp (MS-CHAPv2, the lab certificate), PPP addresses 10.99.17.0/24.
# shellcheck source=scripts/vpn-lab/server/common.sh
. /lab/server/common.sh

fw_base
probe tcp 443 # also the alternative port (redirected to 443 before INPUT)
fw_pool 10.99.17.0/24 10.99.17.1
# The alternative SSTP port (a non-443 port test) is redirected to accel-ppp's 443 (Docker Desktop cannot publish
# two host ports onto one container port).
iptables -t nat -A PREROUTING -p tcp --dport 8443 -j REDIRECT --to-ports 443
accel-pppd -c /state/server/accel-ppp.conf &
log "ready"
wait_forever
