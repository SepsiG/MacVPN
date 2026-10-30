#!/bin/bash
# Tests scripts/build-nm-linvpn-openvpn.sh without building (NM_LINVPN_PRINT=1: it prints its commands, runs nothing;
# runs on any OS), and the files it packages (the pin, the patch, the .name file, the D-Bus policy).
#
# Usage: scripts/test-build-nm-linvpn-openvpn.sh [BUILT_OUT_DIR]
#   BUILT_OUT_DIR: the output of a real build (Linux); its file list is checked too.
set -euo pipefail
export LC_ALL=C   # sort order and messages as on CI
cd "$(dirname "$0")/.."
SCRIPT="$PWD/scripts/build-nm-linvpn-openvpn.sh"
PKG="$PWD/packaging/linux/nm-linvpn-openvpn"
NAME=NetworkManager-openvpn-1.12.5

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   - $1"; }
nok() { FAIL=$((FAIL+1)); echo "FAIL - $1"; }
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else nok "$desc"; fi; }
has() { grep -qF -- "$2" <<<"$1"; }
lacks() { ! grep -qF -- "$2" <<<"$1"; }
# The first line number of $2 in $1 (0 when absent).
line_of() { local n; n="$(grep -nF -- "$2" <<<"$1" | head -n 1 | cut -d: -f1)"; echo "${n:-0}"; }
before() { local a b; a="$(line_of "$1" "$2")"; b="$(line_of "$1" "$3")"; [ "$a" -gt 0 ] && [ "$b" -gt 0 ] && [ "$a" -lt "$b" ]; }

# The seven files of the output tree, relative to OUT.
EXPECTED="usr/lib/NetworkManager/VPN/nm-linvpn-openvpn-service.name
usr/lib/linvpn/nm-openvpn-service
usr/lib/linvpn/nm-openvpn-service-openvpn-helper
usr/share/dbus-1/system.d/nm-linvpn-openvpn-service.conf
usr/share/linvpn/source/$NAME.tar.xz
usr/share/linvpn/source/README.md
usr/share/linvpn/source/linvpn-nm-openvpn.patch"

check "bash -n" bash -n "$SCRIPT"
if command -v shellcheck >/dev/null 2>&1; then check "shellcheck" shellcheck "$SCRIPT" "$0"; else echo "skip - shellcheck is not installed"; fi

OUT="/nonexistent/linvpn-test-out"
P="$(NM_LINVPN_PRINT=1 "$SCRIPT" "$OUT")"
PT="$(NM_LINVPN_PRINT=1 "$SCRIPT" "$OUT" /nonexistent/$NAME.tar.xz)"

# Download and pin
check "download: upstream's URL over https only" has "$P" "curl -fL --proto =https -o"
check "download: the GNOME tarball" has "$P" "https://download.gnome.org/sources/NetworkManager-openvpn/1.12/$NAME.tar.xz"
check "given tarball: copied, not downloaded" bash -c "grep -qF 'cp /nonexistent/$NAME.tar.xz' <<<\"\$1\" && ! grep -qF 'curl' <<<\"\$1\"" _ "$PT"
check "the SHA-256 is verified" has "$P" "sha256sum -c $PWD/scripts/pins/nm-openvpn.sha256"
check "the SHA-256 is verified before extracting" before "$P" "sha256sum -c" "tar -xJf"
check "the given tarball is verified too" before "$PT" "sha256sum -c" "tar -xJf"
check "pin: one line in shasum -c format" grep -qxE "[0-9a-f]{64}  $NAME\.tar\.xz" scripts/pins/nm-openvpn.sha256
check "pin: nothing else" test "$(wc -l <scripts/pins/nm-openvpn.sha256 | tr -d ' ')" = 1

# Patch and build
check "the patch is applied with patch -p1 --forward --batch" has "$P" "-p1 --forward --batch -i $PKG/linvpn-nm-openvpn.patch"
check "patched after extracting" before "$P" "tar -xJf" "patch -d"
check "patched before configuring" before "$P" "patch -d" "./configure"
check "libexecdir is /usr/lib/linvpn" has "$P" "--libexecdir=/usr/lib/linvpn"
check "prefix is /usr" has "$P" "--prefix=/usr"
# The service's run directory and OpenVPN's chroot come from localstatedir: the default (PREFIX/var) gave
# /usr/var/run/NetworkManager, which the read-only /usr cannot hold (every connect failed; L-b lab, 2026-10-30).
check "localstatedir is /var (run dir /var/run/NetworkManager, chroot /var/lib/openvpn/chroot)" has "$P" "--localstatedir=/var"
check "sysconfdir is /etc" has "$P" "--sysconfdir=/etc"
check "the GNOME editor is disabled" has "$P" "--without-gnome"
check "no GTK 4 editor" lacks "$P" "--with-gtk4"
check "make -j2 (R4)" has "$P" "make -j2"
check "only the service and its helper are built" has "$P" "src/nm-openvpn-service src/nm-openvpn-service-openvpn-helper"
check "never make install (DESTDIR-free: every file is placed under OUT)" lacks "$P" "make install"
check "no sudo" lacks "$P" "sudo"

# Install: exactly the seven files, all under OUT, with their modes
TARGETS="$(grep -E '^install ' <<<"$P" | awk '{print $NF}' | sed "s|^$OUT/||" | sort)"
check "install: exactly the seven files" test "$TARGETS" = "$EXPECTED"
check "install: every target under OUT" bash -c "! grep -E '^install ' <<<\"\$1\" | awk '{print \$NF}' | grep -vqE '^$OUT/'" _ "$P"
check "install: the service is 0755" has "$P" "install -D -m 0755 "
check "install: binaries 0755, data 0644" bash -c "[ \"\$(grep -cE '^install -D -m 0755 .*/usr/lib/linvpn/nm-openvpn-service(-openvpn-helper)?$' <<<\"\$1\")\" = 2 ] && [ \"\$(grep -cE '^install -D -m 0644 ' <<<\"\$1\")\" = 5 ]" _ "$P"
check "install: the pinned tarball, unmodified" has "$P" "/$NAME.tar.xz $OUT/usr/share/linvpn/source/$NAME.tar.xz"
check "refuses a missing OUT_DIR" bash -c "! NM_LINVPN_PRINT=1 '$SCRIPT' >/dev/null 2>&1"

# The patch: exactly the three files, every hunk marked
PATCH="$(cat "$PKG/linvpn-nm-openvpn.patch")"
check "patch: exactly the three files" test "$(grep -E '^\+\+\+ ' <<<"$PATCH" | awk '{print $2}' | sort | tr '\n' ' ')" \
  = "b/shared/nm-service-defines.h b/src/nm-openvpn-service-openvpn-helper.c b/src/nm-openvpn-service.c "
check "patch: every hunk has a LinVPN: comment" bash -c "awk '/^@@/{if(h&&!m)bad=1;h=1;m=0} /^\+.*LinVPN:/{m=1} END{if(h&&!m)bad=1; exit bad}' <<<\"\$1\"" _ "$PATCH"
check "patch: only adds the four keys" bash -c "[ \"\$(grep -cE '^\+#define NM_OPENVPN_KEY_LINVPN_' <<<\"\$1\")\" = 4 ]" _ "$PATCH"
for key in linvpn-redirect-gateway linvpn-pull-filter linvpn-route-nopull linvpn-verb; do
  check "patch: key $key" has "$PATCH" "\"$key\""
done
check "patch: the helper sends NEVER_DEFAULT for IPv4 and IPv6" bash -c "grep -qF 'NM_VPN_PLUGIN_IP4_CONFIG_NEVER_DEFAULT' <<<\"\$1\" && grep -qF 'NM_VPN_PLUGIN_IP6_CONFIG_NEVER_DEFAULT' <<<\"\$1\"" _ "$PATCH"
check "patch: from OpenVPN 2.7's variables" bash -c "grep -qF 'route_redirect_gateway_ipv4' <<<\"\$1\" && grep -qF 'route_redirect_gateway_ipv6' <<<\"\$1\"" _ "$PATCH"
check "patch: --redirect-info only with OpenVPN >= 2.7" has "$PATCH" "nmovpn_version_encode (2, 7, 0)"
check "patch: the per-connection syslog identifier" has "$PATCH" '"linvpn-ovpn-"'
check "patch: the redirect-gateway flags allowed" has "$PATCH" '"def1", "ipv6", "!ipv4", "bypass-dhcp", "bypass-dns",'
check "patch: the existing error path" has "$PATCH" 'property “%s” invalid or not supported'
check "patch: the bus name stays upstream's" lacks "$PATCH" "NM_DBUS_SERVICE_OPENVPN    "
check "patch: under ~250 lines" test "$(wc -l <<<"$PATCH")" -le 250

# The .name file and the D-Bus policy
NAMEF="$(cat "$PKG/nm-linvpn-openvpn-service.name")"
check ".name: the service" has "$NAMEF" "service=org.freedesktop.NetworkManager.linvpn-openvpn"
check ".name: the program" has "$NAMEF" "program=/usr/lib/linvpn/nm-openvpn-service"
check ".name: name=linvpn-openvpn" has "$NAMEF" "name=linvpn-openvpn"
check ".name: no editor or auth dialog" bash -c "! grep -qE '^\[(GNOME|libnm)\]' <<<\"\$1\"" _ "$NAMEF"
CONF="$(cat "$PKG/nm-linvpn-openvpn-service.conf")"
check ".conf: only the LinVPN service name" bash -c "[ \"\$(grep -c 'org.freedesktop.NetworkManager.linvpn-openvpn\"' <<<\"\$1\")\" = 4 ] && ! grep -q 'NetworkManager\.openvpn' <<<\"\$1\"" _ "$CONF"
check "README: GPL-2.0-or-later" grep -qF "GPL-2.0-or-later" "$PKG/README.md"

# A real build's output (optional)
if [ $# -ge 1 ]; then
  BUILT="$(cd "$1" && find . -type f | sed 's|^\./||' | sort)"
  check "built: exactly the seven files" test "$BUILT" = "$EXPECTED"
  check "built: the service is executable" test -x "$1/usr/lib/linvpn/nm-openvpn-service"
  check "built: the helper is executable" test -x "$1/usr/lib/linvpn/nm-openvpn-service-openvpn-helper"
  check "built: the service knows the LinVPN keys" bash -c "strings '$1/usr/lib/linvpn/nm-openvpn-service' | grep -q 'linvpn-redirect-gateway'"
  check "built: the helper knows --redirect-info" bash -c "strings '$1/usr/lib/linvpn/nm-openvpn-service-openvpn-helper' | grep -q -- '--redirect-info'"
  check "built: the helper runs from /usr/lib/linvpn" bash -c "strings '$1/usr/lib/linvpn/nm-openvpn-service' | grep -qF '/usr/lib/linvpn/nm-openvpn-service-openvpn-helper'"
  check "built: no path under /usr/var" bash -c "! strings '$1/usr/lib/linvpn/nm-openvpn-service' | grep -qF '/usr/var/'"
  check "built: the run directory is /var/run/NetworkManager" bash -c "strings '$1/usr/lib/linvpn/nm-openvpn-service' | grep -qxF '/var/run/NetworkManager'"
  check "built: the tarball matches the pin" bash -c "cd '$1/usr/share/linvpn/source' && sha256sum -c '$PWD/scripts/pins/nm-openvpn.sha256' >/dev/null"
fi

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
