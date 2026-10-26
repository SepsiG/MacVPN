# The lab's server image: official Alpine 3.24 packages only (strongSwan, xl2tpd + pppd, OpenVPN, wireguard-tools,
# accel-ppp for SSTP, dnsmasq, busybox httpd). The base is pinned by digest (the multi-arch index of
# alpine:3.24.2); packages are pinned to their minor series with `~`, and the exact versions are recorded in
# /lab-packages.txt (check.sh prints them). Configs are mounted at run time, never baked in.
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache \
      'strongswan~6.0' 'xl2tpd~1.3' 'ppp~2.5' 'openvpn~2.7' 'wireguard-tools-wg~1.0' 'accel-ppp~1.14' \
      'dnsmasq~2.92' 'iptables~1.8' iproute2 busybox-extras \
 && apk info -v 2>/dev/null | sort >/lab-packages.txt
