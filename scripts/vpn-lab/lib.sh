# shellcheck shell=bash
# Shared helpers of the VPN lab's host scripts (up.sh, down.sh, profiles.sh, check.sh, selftest.sh). Sourced, never
# run. Settings come from the environment or from the scripts' arguments; nothing about the user's network (the
# Mac's or the VM's LAN address) is stored in the repository.
#
#   LAB_BIND      the host address the lab's ports are published on (required by up.sh; e.g. the Mac's LAN IPv4)
#   LAB_HOST      the server name in the certificates and client profiles (default: LAB_BIND)
#   LAB_STATE     the generated state (secrets, PKI, server configs, client profiles); default scripts/vpn-lab/.state
#                 (git-ignored)
#   OPENSSL       an OpenSSL 3 (or newer) binary; default: the first `openssl` of version 3+ found
#   DRY_RUN=1     print the docker commands instead of running them (the --dry-run flag sets it)

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LAB_DIR
LAB_STATE="${LAB_STATE:-$LAB_DIR/.state}"
export LAB_STATE
DRY_RUN="${DRY_RUN:-0}"
COMPOSE_PROJECT="macvpn-lab"

die() { echo "vpn-lab: $*" >&2; exit 1; }
note() { echo "vpn-lab: $*" >&2; }

# The ranges the lab uses (documented in README.md; none of them is pushed as a default route). Exported for the
# scripts that source this file.
export LAB_SERVICES_NET="10.99.0.0/24" LAB_WEB_IP="10.99.0.10" LAB_DNS_IP="10.99.0.53" LAB_DNS_NAME="whoami.lab.test"

# Runs a command, or prints it with DRY_RUN=1.
run() {
  if [ "$DRY_RUN" = 1 ]; then
    printf '+'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}

is_ipv4() {
  local ip="$1" part
  [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  IFS=. read -r -a parts <<<"$ip"
  for part in "${parts[@]}"; do [ "$part" -le 255 ] || return 1; done
}

is_hostname() {
  [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]
}

# An OpenSSL of major version 3 or newer (LibreSSL lacks X25519 key export in the form used here).
find_openssl() {
  local c v
  for c in "${OPENSSL:-}" openssl /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
    [ -n "$c" ] || continue
    command -v "$c" >/dev/null 2>&1 || continue
    v="$("$c" version 2>/dev/null || true)"
    if [[ "$v" =~ ^OpenSSL\ ([0-9]+)\. ]] && [ "${BASH_REMATCH[1]}" -ge 3 ]; then
      command -v "$c"
      return 0
    fi
  done
  return 1
}

# The docker compose command line of the lab (project name and the compose files).
compose() {
  local files=(-f "$LAB_DIR/compose.yaml")
  if [ "${LAB_IKE_STANDARD_PORTS:-1}" = 1 ]; then
    files+=(-f "$LAB_DIR/compose.ike-standard-ports.yaml")
  fi
  run docker compose -p "$COMPOSE_PROJECT" "${files[@]}" "$@"
}

# Whether the Docker daemon answers.
docker_ready() {
  command -v docker >/dev/null 2>&1 && docker version --format '{{.Server.Version}}' >/dev/null 2>&1
}

# The marker profiles.sh writes into the state folder: down.sh deletes only a folder that holds it.
LAB_STATE_MARKER=".vpn-lab-state"

# Whether $1 is a lab state folder down.sh may delete: a directory (not a symbolic link) that resolves to a folder
# inside scripts/vpn-lab/ (never scripts/vpn-lab itself) and holds the marker profiles.sh writes. Prints the
# resolved path; otherwise says why not (stderr) and returns 1.
lab_state_check() {
  local path="$1" real lab
  [ -n "$path" ] || { note "LAB_STATE is empty"; return 1; }
  [ ! -L "$path" ] || { note "$path is a symbolic link"; return 1; }
  [ -d "$path" ] || { note "$path is not a folder"; return 1; }
  real="$(cd -P -- "$path" && pwd -P)" || { note "cannot resolve $path"; return 1; }
  lab="$(cd -P -- "$LAB_DIR" && pwd -P)" || { note "cannot resolve $LAB_DIR"; return 1; }
  case "$real/" in
    "$lab"/?*/) ;;
    *) note "$real is not a folder inside $lab"; return 1 ;;
  esac
  if [ -L "$real/$LAB_STATE_MARKER" ] || [ ! -f "$real/$LAB_STATE_MARKER" ]; then
    note "$real has no $LAB_STATE_MARKER (written by profiles.sh)"
    return 1
  fi
  printf '%s\n' "$real"
}

# Loads the recorded settings of the generated state (LAB_HOST, LAB_BIND, the throwaway credentials).
load_state() {
  [ -f "$LAB_STATE/secrets.env" ] || die "no lab state in $LAB_STATE: run profiles.sh (or up.sh) first"
  # shellcheck source=/dev/null
  . "$LAB_STATE/secrets.env"
}
