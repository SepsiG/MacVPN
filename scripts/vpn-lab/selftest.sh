#!/bin/bash
# End-to-end check of the running lab from a client container inside Docker (never from the host's network): every
# kind connects through the ports published on LAB_BIND with the generated profiles (selftest/run.sh).
#
# Usage: selftest.sh [--dry-run] [kind...]   kinds: wireguard openvpn ikev2 cisco l2tp sstp (default: all)
set -euo pipefail
# shellcheck source=scripts/vpn-lab/lib.sh
. "$(dirname "$0")/lib.sh"

KINDS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,5p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) KINDS+=("$1"); shift ;;
  esac
done
load_state
export LAB_BIND LAB_SSTP_PORT LAB_SSTP_ALT_PORT LAB_IKE_ALT_PORT LAB_CRL_PORT
if [ "$DRY_RUN" != 1 ]; then docker_ready || die "the Docker daemon does not answer"; fi
# L2TP runs in its own container (selftest/l2tp.sh says why); everything else in the Debian one.
L2TP=0; OTHERS=()
if [ "${#KINDS[@]}" = 0 ]; then
  L2TP=1; OTHERS=(wireguard openvpn ikev2 cisco sstp)
else
  for k in "${KINDS[@]}"; do if [ "$k" = l2tp ]; then L2TP=1; else OTHERS+=("$k"); fi; done
fi
compose --profile selftest up -d selftest selftest-l2tp
status=0
if [ "${#OTHERS[@]}" -gt 0 ]; then
  compose exec -T selftest /lab/selftest/run.sh "${OTHERS[@]}" || status=1
fi
if [ "$L2TP" = 1 ]; then
  compose exec -T selftest-l2tp /lab/selftest/l2tp.sh || status=1
fi
compose --profile selftest rm -sf selftest selftest-l2tp >/dev/null 2>&1 || true
exit "$status"
