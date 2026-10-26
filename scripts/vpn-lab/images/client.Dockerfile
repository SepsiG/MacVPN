# The selftest client image: Debian 13's clients (an independent build of each protocol's client, and sstp-client,
# which Alpine does not package). The base is pinned by digest (debian:trixie-slim); the exact package versions are
# recorded in /lab-packages.txt. Only selftest.sh uses it, inside Docker: nothing runs on the host's network.
FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      strongswan-swanctl strongswan-charon libcharon-extauth-plugins libcharon-extra-plugins \
      libstrongswan-extra-plugins \
      xl2tpd ppp openvpn wireguard-tools sstp-client curl iproute2 iptables bind9-dnsutils ca-certificates procps \
 && rm -rf /var/lib/apt/lists/* \
 && dpkg-query -W -f '${Package} ${Version}\n' | sort >/lab-packages.txt
