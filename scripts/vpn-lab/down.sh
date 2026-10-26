#!/bin/bash
# Removes the VPN lab: containers, networks, the two lab images, and the generated state (credentials, PKI,
# profiles) unless --keep-state is given. The state is deleted only when LAB_STATE resolves to a folder inside
# scripts/vpn-lab/ holding the marker profiles.sh writes (otherwise nothing is removed).
#
# Usage: down.sh [--keep-state] [--dry-run]
set -euo pipefail
# shellcheck source=scripts/vpn-lab/lib.sh
. "$(dirname "$0")/lib.sh"

usage() { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --keep-state) KEEP=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage 2 ;;
  esac
done
# The state is deleted only when it is the lab's own (lib.sh: lab_state_check): checked before anything is removed.
STATE_REAL=""
if [ "$KEEP" = 0 ]; then
  if [ ! -e "$LAB_STATE" ] && [ ! -L "$LAB_STATE" ]; then
    note "no state in $LAB_STATE"
  else
    STATE_REAL="$(lab_state_check "$LAB_STATE")" \
      || die "not deleting LAB_STATE=$LAB_STATE (see above); delete it yourself, or run down.sh --keep-state"
  fi
fi
# compose needs the variables to parse the files; their values do not matter for `down`.
export LAB_BIND="${LAB_BIND:-127.0.0.1}" LAB_STATE
if [ "$DRY_RUN" = 1 ] || docker_ready; then
  compose --profile selftest down --volumes --remove-orphans --rmi all --timeout 5
else
  note "the Docker daemon does not answer: no containers removed"
fi
if [ -n "$STATE_REAL" ]; then
  if [ "$DRY_RUN" = 1 ]; then
    echo "+ rm -rf $STATE_REAL"
  else
    rm -rf -- "${STATE_REAL:?}"
  fi
fi
note "lab removed"
