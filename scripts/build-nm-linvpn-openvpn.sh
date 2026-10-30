#!/bin/bash
# Builds LinVPN's NetworkManager OpenVPN service (decision 8): upstream NetworkManager-openvpn 1.12.5, SHA-256 pinned
# (scripts/pins/nm-openvpn.sha256), with packaging/linux/nm-linvpn-openvpn/linvpn-nm-openvpn.patch, installed into
# OUT (a staging tree for scripts/build-deb.sh), never into the system. Linux only.
#
# Usage: scripts/build-nm-linvpn-openvpn.sh OUT_DIR [TARBALL]   (TARBALL: a downloaded copy; default: download)
# Env: NM_LINVPN_PRINT=1 prints the commands instead of running them (scripts/test-build-nm-linvpn-openvpn.sh).
#
# Build dependencies (Ubuntu): build-essential pkg-config gettext libnm-dev libglib2.0-dev. The release tarball ships
# its generated configure script (autotools; upstream has no meson build in 1.12.5), so autoconf is not needed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:?usage: $0 OUT_DIR [TARBALL]}"; TARBALL="${2:-}"
NAME=NetworkManager-openvpn-1.12.5
URL="https://download.gnome.org/sources/NetworkManager-openvpn/1.12/$NAME.tar.xz"
PKG="$ROOT/packaging/linux/nm-linvpn-openvpn"
PRINT="${NM_LINVPN_PRINT:-}"
run() { if [ "$PRINT" = 1 ]; then printf '%s\n' "$*"; else "$@"; fi; }
run_in() { local dir="$1"; shift; if [ "$PRINT" = 1 ]; then printf 'cd %s && %s\n' "$dir" "$*"; else (cd "$dir" && "$@"); fi; }

[ "$PRINT" = 1 ] || [ "$(uname -s)" = Linux ] || { echo "error: builds on Linux only" >&2; exit 1; }
case "$OUT" in /*) ;; *) OUT="$PWD/$OUT" ;; esac

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
if [ -z "$TARBALL" ]; then
  run curl -fL --proto '=https' -o "$WORK/$NAME.tar.xz" "$URL"
else
  run cp "$TARBALL" "$WORK/$NAME.tar.xz"
fi
run_in "$WORK" sha256sum -c "$ROOT/scripts/pins/nm-openvpn.sha256"
run tar -xJf "$WORK/$NAME.tar.xz" -C "$WORK"
run patch -d "$WORK/$NAME" -p1 --forward --batch -i "$PKG/linvpn-nm-openvpn.patch"
# autotools (the 1.12.5 tarball has no meson.build). --disable-nls: the service's messages stay in English, which is
# what LinVPN's log reads; nothing else of the tree (editor, auth dialog, translations) is built. --localstatedir=/var
# and --sysconfdir=/etc as Debian's own build: the service's run directory (/var/run/NetworkManager) and OpenVPN's
# chroot (/var/lib/openvpn/chroot) derive from localstatedir; its default (/usr/var) is on the read-only /usr.
run_in "$WORK/$NAME" ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --libexecdir=/usr/lib/linvpn \
  --without-gnome --disable-static --disable-nls
run make -j2 -C "$WORK/$NAME" src/nm-openvpn-service src/nm-openvpn-service-openvpn-helper
run install -D -m 0755 "$WORK/$NAME/src/nm-openvpn-service" "$OUT/usr/lib/linvpn/nm-openvpn-service"
run install -D -m 0755 "$WORK/$NAME/src/nm-openvpn-service-openvpn-helper" "$OUT/usr/lib/linvpn/nm-openvpn-service-openvpn-helper"
run install -D -m 0644 "$PKG/nm-linvpn-openvpn-service.name" "$OUT/usr/lib/NetworkManager/VPN/nm-linvpn-openvpn-service.name"
run install -D -m 0644 "$PKG/nm-linvpn-openvpn-service.conf" "$OUT/usr/share/dbus-1/system.d/nm-linvpn-openvpn-service.conf"
run install -D -m 0644 "$WORK/$NAME.tar.xz" "$OUT/usr/share/linvpn/source/$NAME.tar.xz"
run install -D -m 0644 "$PKG/linvpn-nm-openvpn.patch" "$OUT/usr/share/linvpn/source/linvpn-nm-openvpn.patch"
run install -D -m 0644 "$PKG/README.md" "$OUT/usr/share/linvpn/source/README.md"
