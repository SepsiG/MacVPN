#!/bin/sh
# The IPsec container: charon (IKEv2, IKEv1 XAUTH, L2TP's IPsec) and xl2tpd + pppd for L2TP.
# shellcheck source=scripts/vpn-lab/server/common.sh
. /lab/server/common.sh

fw_base
probe udp 500
probe udp 4500 # also the alternative port (redirected to 4500 before INPUT)
fw_pool 10.99.14.0/24            # IKEv2 virtual IPs
fw_pool 10.99.15.0/24            # Cisco IPsec (IKEv1 XAUTH) virtual IPs
fw_pool 10.99.16.0/24 10.99.16.1 # L2TP PPP addresses
# L2TP only inside IPsec: a plain L2TP packet (no ESP) never reaches xl2tpd.
iptables -A INPUT -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
iptables -A INPUT -p udp --dport 1701 -j DROP
# The alternative IKE port (published for the lab host's own IKE client, README) is charon's NAT-T port. Docker
# Desktop cannot publish two host ports onto one container port, so the container redirects it.
iptables -t nat -A PREROUTING -p udp --dport 4510 -j REDIRECT --to-ports 4500

cp /lab/server/strongswan.conf /etc/strongswan.conf
cp /state/server/swanctl.conf /etc/swanctl/swanctl.conf
cp /state/pki/ca.pem /etc/swanctl/x509ca/ca.pem
cp /state/pki/server.pem /etc/swanctl/x509/server.pem
cp /state/pki/server.key /etc/swanctl/private/server.key
chmod 600 /etc/swanctl/swanctl.conf /etc/swanctl/private/server.key

mkdir -p /etc/xl2tpd /etc/ppp /var/run/xl2tpd
cp /lab/server/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf
cp /lab/server/options.xl2tpd /etc/ppp/options.xl2tpd
cp /state/server/chap-secrets /etc/ppp/chap-secrets
chmod 600 /etc/ppp/chap-secrets

/usr/lib/strongswan/charon &
i=0
until swanctl --stats >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 50 ] || { log "charon did not start"; exit 1; }
  sleep 0.2
done
swanctl --load-all
xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf &
log "ready"
wait_forever
