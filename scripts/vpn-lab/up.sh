#!/bin/bash
# Starts the VPN lab: generates the state (profiles.sh) when needed, builds the two images and starts the servers,
# with every port published on LAB_BIND only.
#
# Usage: up.sh --bind IPV4 [--host NAME] [--no-ike-standard-ports] [--renew] [--dry-run]
#   --bind IPV4                the host address to publish on (the Mac's LAN IPv4; or LAB_BIND)
#   --host NAME                the server name in certificates and profiles (default: the --bind address)
#   --no-ike-standard-ports    do not publish UDP 500/4500 (only the alternative IKE port): for MacVPN's IKEv2 on
#                              the lab host itself (README)
#   --renew                    new credentials and PKI
#   --dry-run                  print the docker commands, run nothing (the state is still generated)
set -euo pipefail
# shellcheck source=scripts/vpn-lab/lib.sh
. "$(dirname "$0")/lib.sh"

usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
PROFILE_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --bind) LAB_BIND="${2:?--bind needs a value}"; shift 2 ;;
    --host) PROFILE_ARGS+=(--host "${2:?--host needs a value}"); shift 2 ;;
    --no-ike-standard-ports) LAB_IKE_STANDARD_PORTS=0; shift ;;
    --renew) PROFILE_ARGS+=(--renew); shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 2 ;;
  esac
done
[ -n "${LAB_BIND:-}" ] || die "give the host address to publish on: --bind IPV4 (or LAB_BIND)"
is_ipv4 "$LAB_BIND" || die "--bind must be an IPv4 address: $LAB_BIND"
[ "$LAB_BIND" != "0.0.0.0" ] || die "--bind 0.0.0.0 would publish the lab on every interface; give the LAN address"
# Read-only check that the address is this host's (ifconfig / ip only list addresses).
if command -v ifconfig >/dev/null 2>&1; then
  ifconfig 2>/dev/null | grep -q "inet $LAB_BIND " || note "warning: $LAB_BIND is not an address of this host"
elif command -v ip >/dev/null 2>&1; then
  ip -4 -o address 2>/dev/null | grep -q " $LAB_BIND/" || note "warning: $LAB_BIND is not an address of this host"
fi
export LAB_BIND LAB_IKE_STANDARD_PORTS="${LAB_IKE_STANDARD_PORTS:-1}"

"$LAB_DIR/profiles.sh" --bind "$LAB_BIND" ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"}
load_state
export LAB_SSTP_PORT LAB_SSTP_ALT_PORT LAB_IKE_ALT_PORT LAB_CRL_PORT

if [ "$DRY_RUN" != 1 ]; then
  docker_ready || die "the Docker daemon does not answer (start Docker Desktop), or use --dry-run"
fi
compose --profile selftest build
compose up -d --force-recreate --remove-orphans ipsec openvpn wireguard sstp crl web dns
note "lab up on $LAB_BIND (server name $LAB_HOST); check with check.sh, profiles in $LAB_STATE/client"
