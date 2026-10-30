#!/bin/bash
# Builds LinVPN's .deb on Linux, the counterpart of build-dmg.sh and build-msi.sh (LinVPN plan, Task 21; L-b Task 20
# added LinVPN's NetworkManager OpenVPN service, linvpn-logd and the GPL source). One architecture per run, this
# machine's (`dpkg --print-architecture`: amd64 or arm64); CI runs it on an amd64 and an arm64 runner (ubuntu-24.04,
# so the package runs on Ubuntu 24.04+ and Debian 13).
#   1. the three version numbers agree; no build-changing variable leaks in; the NM service's build dependencies are
#      there; the UI's packages (npm ci) and the crate sources (cargo fetch); THIRD-PARTY-NOTICES.linux.txt current
#   2. the UI, the release app (`tauri build --no-bundle`: custom-protocol, tauri.linux.conf.json → target/release/
#      linvpn), the helper crate's root update step (linvpn-install-update), log reader (linvpn-logd) and IKEv2 traffic
#      counter reader (linvpn-xfrmd), and LinVPN's
#      NM OpenVPN service (scripts/build-nm-linvpn-openvpn.sh: the SHA-256-pinned upstream tarball plus the patch,
#      into a staging tree that scripts/test-build-nm-linvpn-openvpn.sh checks)
#   3. release gates on the binaries: the ELF machine; no debug-only code (MACVPN_SANDBOX_HOME, MACVPN_SMOKE);
#      SQLCipher on the vendored OpenSSL 3, statically linked (no libssl, libcrypto or libsqlite3 among the NEEDED
#      libraries; OpenSSL 3's version string inside); the root step and the two readers need only libc, libm, libgcc_s
#      and the loader; the NM service and its helper only libnm, GLib (glib, gobject, gio) and libc, and are stripped
#      (upstream's build keeps debug info and build paths)
#   4. the staged tree, DEBIAN/control (Package linvpn exactly, Version, Architecture, Depends from dpkg-shlibdeps over
#      all six programs plus the fixed list, Recommends: the NM plugins), md5sums and exactly two maintainer scripts,
#      postinst and prerm, copied byte for byte from packaging/linux/deb/ (they enable and disable
#      linvpn-logd.socket and linvpn-xfrmd.socket, and record and drop the installed version in /run/linvpn/package-version, which a running
#      LinVPN restarts into; everything else comes from dpkg triggers); dpkg-deb --root-owner-group
#   5. the built .deb read back: its three fields and Depends, the control files exactly control, md5sums, postinst
#      and prerm (the two byte for byte the repository's, 0755), every file root:root, the file list (path and mode)
#      equal to scripts/bundle-baseline/linvpn-deb-files.txt, the six programs byte for byte the gated ones, the GPL
#      source's tarball matching scripts/pins/nm-openvpn.sha256, the GPL-2+ stanza in copyright; .sha256 beside it
#
#   scripts/build-deb.sh [--write-baseline]
#   scripts/build-deb.sh --control VERSION ARCH SHLIBS   only print DEBIAN/control for these values, then exit
#                                                        (scripts/test-build-deb.sh; runs on any OS)
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "error: $*" >&2; exit 1; }

# network-manager-openvpn: LinVPN's own OpenVPN service runs OpenVPN as its nm-openvpn user in its chroot, which the
# stock plugin's package creates; systemd: linvpn-logd and linvpn-xfrmd are socket-activated.
DEPENDS_FIXED="network-manager, network-manager-openvpn (>= 1.10), openvpn, systemd, curl, openssl, pkexec | policykit-1, gnome-shell-extension-appindicator | plasma-workspace"
# libcharon-extauth-plugins (EAP-MSCHAPv2) and libcharon-extra-plugins (EAP-Identity): IKEv2 with a user name and
# password, the default IKEv2 sign-in (resolved point 17).
RECOMMENDS="network-manager-openvpn-gnome | network-manager-openvpn, network-manager-l2tp-gnome | network-manager-l2tp, network-manager-strongswan, libcharon-extauth-plugins, libcharon-extra-plugins, network-manager-sstp-gnome | network-manager-sstp, network-manager-vpnc-gnome | network-manager-vpnc"

control() { # VERSION ARCH SHLIBS
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "bad version: $1"
  [[ "$2" =~ ^(amd64|arm64)$ ]] || die "bad architecture: $2"
  local depends="$DEPENDS_FIXED"
  [ -z "$3" ] || depends="$3, $depends"
  cat <<CONTROL
Package: linvpn
Version: $1
Architecture: $2
Maintainer: SepsiG <SepsiG@users.noreply.github.com>
Section: net
Priority: optional
Homepage: https://github.com/SepsiG/MacVPN
Depends: $depends
Recommends: $RECOMMENDS
Description: VPN connections in the top bar
 LinVPN keeps VPN connections (OpenVPN, WireGuard, L2TP/IPsec, IKEv2, Cisco IPsec
 and SSTP) in an encrypted vault and connects them through NetworkManager. The
 Linux sibling of MacVPN and WinVPN.
CONTROL
}

if [ "${1:-}" = --control ]; then
  [ $# -eq 4 ] || die "--control VERSION ARCH SHLIBS"
  control "$2" "$3" "$4"
  exit 0
fi

WRITE_BASELINE=0
case "${1:-}" in
  "") ;;
  --write-baseline) WRITE_BASELINE=1 ;;
  *) die "unknown option: $1" ;;
esac
[ "$(uname -s)" = Linux ] || die "build the .deb on Linux"
ARCH="$(dpkg --print-architecture)"
case "$ARCH" in
  amd64) ELF_MACHINE="X86-64" ;;
  arm64) ELF_MACHINE="AArch64" ;;
  *) die "unsupported architecture: $ARCH" ;;
esac
for tool in dpkg-deb dpkg-shlibdeps readelf strip md5sum sha256sum node npm cargo; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is missing (build-essential, dpkg-dev, binutils, nodejs)"
done
# LinVPN's NM OpenVPN service (scripts/build-nm-linvpn-openvpn.sh) builds against the system's libnm and GLib.
NM_BUILD_DEPS="build-essential pkg-config gettext libnm-dev libglib2.0-dev"
if ! command -v pkg-config >/dev/null 2>&1 || ! pkg-config --exists libnm glib-2.0; then
  die "the NM OpenVPN service's build dependencies are missing (apt-get install --no-install-recommends $NM_BUILD_DEPS)"
fi

echo "==> 1. versions, environment, notices"
V_CARGO="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)"
V_CONF="$(node -p "require('./app/src-tauri/tauri.conf.json').version")"
V_UI="$(node -p "require('./app/ui/package.json').version")"
[ "$V_CARGO" = "$V_CONF" ] && [ "$V_CONF" = "$V_UI" ] || die "versions differ: Cargo $V_CARGO, tauri.conf.json $V_CONF, package.json $V_UI"
VERSION="$V_CARGO"
for v in MACVPN_SANDBOX_HOME MACVPN_SMOKE_DIR RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_TARGET OPENSSL_DIR \
  OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR OPENSSL_STATIC OPENSSL_NO_VENDOR SQLCIPHER_LIB_DIR LIBSQLITE3_SYS_USE_PKG_CONFIG; do
  [ -z "${!v:-}" ] || die "$v must not be set for a release build"
done
# The notices are read from the UI's node_modules and the crate sources: both first.
(cd app/ui && npm ci --no-audit --no-fund)
cargo fetch --locked >/dev/null
node scripts/third-party-notices.mjs --os linux --check \
  || die "THIRD-PARTY-NOTICES.linux.txt is not current (node scripts/third-party-notices.mjs --os linux)"

echo "==> 2. the UI, the app, the root update step, the two readers and the NM OpenVPN service"
(cd app/ui && npm run build)
# The Tauri CLI reads CI as its --ci flag and takes only true or false (lin-remote.sh sets CI=1); this build never
# asks anything anyway.
(cd app/ui && CI=true npm run tauri -- build --no-bundle)
cargo build --release --locked -p macvpn-helper --bin linvpn-install-update --bin linvpn-logd --bin linvpn-xfrmd
APP=target/release/linvpn
STEP=target/release/linvpn-install-update
LOGD=target/release/linvpn-logd
XFRMD=target/release/linvpn-xfrmd
[ -x "$APP" ] || die "no $APP (tauri.linux.conf.json's mainBinaryName must be linvpn)"
[ -x "$STEP" ] || die "no $STEP"
[ -x "$LOGD" ] || die "no $LOGD"
[ -x "$XFRMD" ] || die "no $XFRMD"
STAGE="target/linvpn-deb/$ARCH"
rm -rf "$STAGE"
NM_OUT="$STAGE/nm-linvpn-openvpn"
scripts/build-nm-linvpn-openvpn.sh "$NM_OUT"
scripts/test-build-nm-linvpn-openvpn.sh "$NM_OUT" >/dev/null \
  || die "the NM OpenVPN service's build output failed its checks (scripts/test-build-nm-linvpn-openvpn.sh $NM_OUT)"
# Upstream's build keeps the symbols, debug info and build paths: strip them as dh_strip does.
NM_BIN="$STAGE/nm-bin"
mkdir -p "$NM_BIN"
for prog in nm-openvpn-service nm-openvpn-service-openvpn-helper; do
  strip --remove-section=.comment --remove-section=.note -o "$NM_BIN/$prog" "$NM_OUT/usr/lib/linvpn/$prog"
done
SERVICE="$NM_BIN/nm-openvpn-service"
SERVICE_HELPER="$NM_BIN/nm-openvpn-service-openvpn-helper"

echo "==> 3. release gates on the binaries"
needed() { readelf -d "$1" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | sort; }
for bin in "$APP" "$STEP" "$LOGD" "$XFRMD" "$SERVICE" "$SERVICE_HELPER"; do
  readelf -h "$bin" | grep -q "Machine:.*$ELF_MACHINE" || die "$bin is not $ELF_MACHINE"
  for marker in MACVPN_SANDBOX_HOME MACVPN_SMOKE; do
    if grep -aq "$marker" "$bin"; then die "$bin contains the debug-only $marker"; fi
  done
done
if needed "$APP" | grep -Eq '^lib(ssl|crypto|sqlite3)\.so'; then die "the app links a system libssl, libcrypto or libsqlite3"; fi
grep -aq 'OpenSSL 3\.' "$APP" || die "no vendored OpenSSL 3 in the app (SQLCipher's crypto provider)"
for bin in "$STEP" "$LOGD" "$XFRMD"; do
  for lib in $(needed "$bin"); do
    case "$lib" in
      libc.so.6|libm.so.6|libgcc_s.so.1|ld-linux-*.so.*) ;;
      *) die "$bin links $lib" ;;
    esac
  done
done
for bin in "$SERVICE" "$SERVICE_HELPER"; do
  for lib in $(needed "$bin"); do
    case "$lib" in
      libnm.so.0|libgio-2.0.so.0|libgobject-2.0.so.0|libglib-2.0.so.0|libc.so.6|ld-linux-*.so.*) ;;
      *) die "$bin links $lib (only libnm, GLib and libc)" ;;
    esac
  done
  if readelf -S --wide "$bin" | grep -Eq '[[:space:]]\.(debug_[a-z_]+|symtab)[[:space:]]'; then
    die "$bin is not stripped"
  fi
done
needed "$SERVICE" | grep -qx 'libnm.so.0' || die "$SERVICE does not link libnm (not the NM service?)"

echo "==> 4. the package tree"
ROOT="$STAGE/root"
install -D -m 0755 "$APP" "$ROOT/usr/bin/linvpn"
install -D -m 0755 "$STEP" "$ROOT/usr/libexec/linvpn/linvpn-install-update"
install -D -m 0755 "$LOGD" "$ROOT/usr/libexec/linvpn/linvpn-logd"
install -D -m 0644 packaging/linux/systemd/linvpn-logd.socket "$ROOT/usr/lib/systemd/system/linvpn-logd.socket"
install -D -m 0644 packaging/linux/systemd/linvpn-logd@.service "$ROOT/usr/lib/systemd/system/linvpn-logd@.service"
install -D -m 0755 "$XFRMD" "$ROOT/usr/libexec/linvpn/linvpn-xfrmd"
install -D -m 0644 packaging/linux/systemd/linvpn-xfrmd.socket "$ROOT/usr/lib/systemd/system/linvpn-xfrmd.socket"
install -D -m 0644 packaging/linux/systemd/linvpn-xfrmd@.service "$ROOT/usr/lib/systemd/system/linvpn-xfrmd@.service"
# The class-based route of SSTP/L2TP split tunnels (NM's packaged dispatcher folder; NM runs only root-owned scripts
# that group and others cannot write).
install -D -m 0755 packaging/linux/nm-dispatcher/90-linvpn-route "$ROOT/usr/lib/NetworkManager/dispatcher.d/90-linvpn-route"
install -D -m 0755 "$SERVICE" "$ROOT/usr/lib/linvpn/nm-openvpn-service"
install -D -m 0755 "$SERVICE_HELPER" "$ROOT/usr/lib/linvpn/nm-openvpn-service-openvpn-helper"
for f in usr/lib/NetworkManager/VPN/nm-linvpn-openvpn-service.name \
  usr/share/dbus-1/system.d/nm-linvpn-openvpn-service.conf \
  usr/share/linvpn/source/NetworkManager-openvpn-1.12.5.tar.xz \
  usr/share/linvpn/source/linvpn-nm-openvpn.patch \
  usr/share/linvpn/source/README.md; do
  install -D -m 0644 "$NM_OUT/$f" "$ROOT/$f"
done
install -D -m 0644 packaging/linux/linvpn.desktop "$ROOT/usr/share/applications/linvpn.desktop"
install -D -m 0644 packaging/linux/linvpn-mime.xml "$ROOT/usr/share/mime/packages/linvpn.xml"
install -D -m 0644 packaging/linux/local.linvpn.update.policy "$ROOT/usr/share/polkit-1/actions/local.linvpn.update.policy"
install -D -m 0644 app/src-tauri/icons/32x32.png "$ROOT/usr/share/icons/hicolor/32x32/apps/linvpn.png"
install -D -m 0644 app/src-tauri/icons/128x128.png "$ROOT/usr/share/icons/hicolor/128x128/apps/linvpn.png"
install -D -m 0644 "app/src-tauri/icons/128x128@2x.png" "$ROOT/usr/share/icons/hicolor/256x256/apps/linvpn.png"
install -D -m 0644 packaging/linux/copyright "$ROOT/usr/share/doc/linvpn/copyright"
install -D -m 0644 THIRD-PARTY-NOTICES.linux.txt "$ROOT/usr/share/doc/linvpn/THIRD-PARTY-NOTICES.txt"
if command -v desktop-file-validate >/dev/null 2>&1; then
  desktop-file-validate "$ROOT/usr/share/applications/linvpn.desktop" || die "the desktop entry is invalid"
fi
mkdir -p "$STAGE/shlibs/debian"
printf 'Source: linvpn\n\nPackage: linvpn\nArchitecture: any\n' > "$STAGE/shlibs/debian/control"
ABS_ROOT="$(cd "$ROOT" && pwd)"
SHLIBS="$(cd "$STAGE/shlibs" && dpkg-shlibdeps -O "$ABS_ROOT/usr/bin/linvpn" "$ABS_ROOT/usr/libexec/linvpn/linvpn-install-update" \
  "$ABS_ROOT/usr/libexec/linvpn/linvpn-logd" "$ABS_ROOT/usr/libexec/linvpn/linvpn-xfrmd" \
  "$ABS_ROOT/usr/lib/linvpn/nm-openvpn-service" \
  "$ABS_ROOT/usr/lib/linvpn/nm-openvpn-service-openvpn-helper" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')"
[ -n "$SHLIBS" ] || die "dpkg-shlibdeps found no library dependencies"
for pkg in libnm0 libglib2.0-0; do
  grep -Eq "(^|, )${pkg}[a-z0-9]*( |,|$)" <<<"$SHLIBS" || die "dpkg-shlibdeps did not name $pkg (the NM service's libraries): $SHLIBS"
done
mkdir -p "$ROOT/DEBIAN"
control "$VERSION" "$ARCH" "$SHLIBS" > "$ROOT/DEBIAN/control"
(cd "$ROOT" && find usr -type f -print0 | sort -z | xargs -0 md5sum) > "$ROOT/DEBIAN/md5sums"
chmod 0644 "$ROOT/DEBIAN/control" "$ROOT/DEBIAN/md5sums"
# Exactly two maintainer scripts (L-b resolved point 12): the two readers' sockets, nothing else.
install -m 0755 packaging/linux/deb/postinst "$ROOT/DEBIAN/postinst"
install -m 0755 packaging/linux/deb/prerm "$ROOT/DEBIAN/prerm"
find "$ROOT" -type d -exec chmod 0755 {} +
OUT=dist/linux
mkdir -p "$OUT"
DEB="$OUT/linvpn_${VERSION}_${ARCH}.deb"
rm -f "$DEB" "$DEB.sha256"
dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$DEB" >/dev/null

echo "==> 5. the built package"
[ "$(dpkg-deb --field "$DEB" Package)" = linvpn ] || die "Package is not linvpn"
[ "$(dpkg-deb --field "$DEB" Version)" = "$VERSION" ] || die "Version is not $VERSION"
[ "$(dpkg-deb --field "$DEB" Architecture)" = "$ARCH" ] || die "Architecture is not $ARCH"
DEPENDS="$(dpkg-deb --field "$DEB" Depends)"
for pkg in network-manager network-manager-openvpn openvpn systemd libnm0 openssl; do
  grep -Eq "(^|, )$pkg( |,|$)" <<<"$DEPENDS" || die "Depends lacks $pkg: $DEPENDS"
done
CTRL="$(dpkg-deb --ctrl-tarfile "$DEB" | tar -t | LC_ALL=C sort | tr '\n' ' ')"
[ "$CTRL" = "./ ./control ./md5sums ./postinst ./prerm " ] \
  || die "unexpected control files (exactly postinst and prerm as maintainer scripts): $CTRL"
CTRL_MODES="$(dpkg-deb --ctrl-tarfile "$DEB" | tar -tv | awk '$NF == "./postinst" || $NF == "./prerm" {print $1}' | sort -u)"
[ "$CTRL_MODES" = "-rwxr-xr-x" ] || die "the maintainer scripts are not 0755: $CTRL_MODES"
LIST="$(dpkg-deb --fsys-tarfile "$DEB" | tar -tv | awk '{print $1, $2, $6}' | LC_ALL=C sort -k3)"
if awk '$2 != "root/root"' <<<"$LIST" | grep -q .; then die "a file is not owned by root:root"; fi
FILES="$(awk '{print $1, $3}' <<<"$LIST")"
BASELINE=scripts/bundle-baseline/linvpn-deb-files.txt
if [ "$WRITE_BASELINE" = 1 ]; then
  printf '%s\n' "$FILES" > "$BASELINE"
  echo "wrote $BASELINE"
fi
diff -u "$BASELINE" <(printf '%s\n' "$FILES") || die "the package's files differ from $BASELINE (--write-baseline after a deliberate change)"
X="$STAGE/extract"
dpkg-deb -x "$DEB" "$X"
dpkg-deb -e "$DEB" "$X/DEBIAN"
cmp -s "$X/usr/bin/linvpn" "$APP" || die "the packaged linvpn is not the gated one"
cmp -s "$X/usr/lib/NetworkManager/dispatcher.d/90-linvpn-route" packaging/linux/nm-dispatcher/90-linvpn-route \
  || die "the packaged dispatcher script is not the repository's"
cmp -s "$X/usr/libexec/linvpn/linvpn-install-update" "$STEP" || die "the packaged root step is not the gated one"
cmp -s "$X/usr/libexec/linvpn/linvpn-logd" "$LOGD" || die "the packaged linvpn-logd is not the gated one"
cmp -s "$X/usr/libexec/linvpn/linvpn-xfrmd" "$XFRMD" || die "the packaged linvpn-xfrmd is not the gated one"
cmp -s "$X/usr/lib/linvpn/nm-openvpn-service" "$SERVICE" || die "the packaged NM OpenVPN service is not the gated one"
cmp -s "$X/usr/lib/linvpn/nm-openvpn-service-openvpn-helper" "$SERVICE_HELPER" \
  || die "the packaged NM OpenVPN helper is not the gated one"
for unit in linvpn-logd.socket linvpn-logd@.service linvpn-xfrmd.socket linvpn-xfrmd@.service; do
  cmp -s "$X/usr/lib/systemd/system/$unit" "packaging/linux/systemd/$unit" || die "the packaged $unit is not the repository's"
done
for script in postinst prerm; do
  cmp -s "$X/DEBIAN/$script" "packaging/linux/deb/$script" || die "the packaged $script is not packaging/linux/deb/$script byte for byte"
done
PIN="$PWD/scripts/pins/nm-openvpn.sha256"
(cd "$X/usr/share/linvpn/source" && sha256sum -c "$PIN" >/dev/null) \
  || die "the packaged NetworkManager-openvpn source does not match scripts/pins/nm-openvpn.sha256"
cmp -s "$X/usr/share/linvpn/source/linvpn-nm-openvpn.patch" packaging/linux/nm-linvpn-openvpn/linvpn-nm-openvpn.patch \
  || die "the packaged patch is not the repository's"
awk '/^Files: usr\/lib\/linvpn\/nm-openvpn-service\*$/ {s=1; next} /^Files:/ {s=0} s && /^License: GPL-2\+$/ {ok=1} END {exit !ok}' \
  "$X/usr/share/doc/linvpn/copyright" || die "copyright has no GPL-2+ stanza for usr/lib/linvpn/nm-openvpn-service*"
(cd "$OUT" && sha256sum "$(basename "$DEB")" > "$(basename "$DEB").sha256")
echo "OK: $DEB"
cat "$DEB.sha256"
