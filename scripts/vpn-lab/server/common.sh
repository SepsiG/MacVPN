# shellcheck shell=sh
# Shared by the VPN server containers: the forwarding rules that keep VPN clients inside the lab.
# A client pool may reach only the lab services network (10.99.0.0/24): FORWARD drops everything else (the edge
# network, the host's LAN, the internet), and the forwarded traffic is masqueraded to the container's labnet address
# (the test page names the server it came through). The pool's gateway address (the server's own tunnel address)
# answers HTTP and DNS by DNAT to the test page and the DNS server, so a client that routes only its peer address
# (PPP without "send all traffic") can still check both.
set -eu
LAB_SERVICES_NET=10.99.0.0/24
LAB_WEB_IP=10.99.0.10
LAB_DNS_IP=10.99.0.53

log() { echo "[$(hostname)] $*"; }

fw_base() {
  iptables -P FORWARD DROP
  iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
}

# fw_pool POOL [GATEWAY]
fw_pool() {
  iptables -A FORWARD -s "$1" -d "$LAB_SERVICES_NET" -j ACCEPT
  iptables -t nat -A POSTROUTING -s "$1" -d "$LAB_SERVICES_NET" -j MASQUERADE
  if [ -n "${2:-}" ]; then
    iptables -t nat -A PREROUTING -s "$1" -d "$2" -p tcp --dport 80 -j DNAT --to-destination "$LAB_WEB_IP:80"
    iptables -t nat -A PREROUTING -s "$1" -d "$2" -p udp --dport 53 -j DNAT --to-destination "$LAB_DNS_IP:53"
    iptables -t nat -A PREROUTING -s "$1" -d "$2" -p tcp --dport 53 -j DNAT --to-destination "$LAB_DNS_IP:53"
  fi
}

# probe PROTO PORT: a counting rule (no target) on a published port; check.sh reads its packet counter after sending
# a probe datagram from the host, to see that Docker's port forwarding delivers it.
probe() {
  iptables -A INPUT -p "$1" --dport "$2" -m comment --comment "lab-probe $1/$2"
}

# Runs until the container is stopped: waits on the background daemons, ends them on SIGTERM.
wait_forever() {
  trap 'log "stopping"; kill $(jobs -p) 2>/dev/null; exit 0' TERM INT
  while :; do sleep 3600 & wait $!; done
}
