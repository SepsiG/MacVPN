#!/bin/bash
# Tests scripts/build-deb.sh without building: its syntax, --control (DEBIAN/control for given values; runs on any
# OS), what it stages (the pinned file list, the two maintainer scripts byte for byte, the GPL stanza) and which gates
# it has. The real build and its gates run on Linux (CI's deb jobs, the VM).
# shellcheck disable=SC2016  # the expected texts are build-deb.sh's own lines, $VAR and all: never expanded here
set -euo pipefail
cd "$(dirname "$0")/.."
SCRIPT="$PWD/scripts/build-deb.sh"

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "ok   - $1"; }
nok() { FAIL=$((FAIL+1)); echo "FAIL - $1"; }
check() { local desc="$1"; shift; if "$@"; then ok "$desc"; else nok "$desc"; fi; }
has() { grep -qF -- "$2" <<<"$1"; }
lacks() { ! grep -qF -- "$2" <<<"$1"; }

check "bash -n" bash -n "$SCRIPT"
if command -v shellcheck >/dev/null 2>&1; then check "shellcheck" shellcheck "$SCRIPT" "$0"; else echo "skip - shellcheck is not installed"; fi

C="$("$SCRIPT" --control 2.1.0 arm64 'libc6 (>= 2.39), libwebkit2gtk-4.1-0 (>= 2.44)')"
check "control: the package name exactly" has "$C" $'\nPackage: linvpn\n'
check "control: starts with Package" test "$(head -n 1 <<<"$C")" = "Package: linvpn"
check "control: version" has "$C" "Version: 2.1.0"
check "control: architecture" has "$C" "Architecture: arm64"
check "control: shlibs first" has "$C" "Depends: libc6 (>= 2.39), libwebkit2gtk-4.1-0 (>= 2.44), network-manager, "
check "control: the stock OpenVPN plugin, OpenVPN, systemd and openssl (PKCS#12 import)" has "$C" "network-manager, network-manager-openvpn (>= 1.10), openvpn, systemd, curl, openssl, pkexec | policykit-1"
check "control: a StatusNotifierItem host" has "$C" "gnome-shell-extension-appindicator | plasma-workspace"
check "control: the NM plugins recommended" has "$C" "Recommends: network-manager-openvpn-gnome | network-manager-openvpn"
check "control: strongSwan and vpnc too" bash -c "grep -q 'network-manager-strongswan' <<<'$C' && grep -q 'network-manager-vpnc-gnome | network-manager-vpnc' <<<'$C'"
check "control: the strongSwan EAP plugins (EAP-MSCHAPv2, EAP-Identity) recommended" bash -c "grep -q 'network-manager-strongswan, libcharon-extauth-plugins, libcharon-extra-plugins,' <<<'$C'"
check "control: refuses a bad version" bash -c "! '$SCRIPT' --control 2.1 amd64 '' >/dev/null 2>&1"
check "control: refuses an unknown architecture" bash -c "! '$SCRIPT' --control 2.1.0 i386 '' >/dev/null 2>&1"
# The maintainer scripts (L-b resolved point 12): exactly postinst and prerm, byte for byte these texts (postinst also
# records the installed version in /run/linvpn/package-version for a running LinVPN's restart; prerm drops it).
POSTINST='#!/bin/sh
# LinVPN: starts the log reader'"'"'s and the IKEv2 traffic counter reader'"'"'s sockets (linvpn-logd, linvpn-xfrmd) and
# records the installed version for a running LinVPN, which restarts into it (/run/linvpn/package-version). Nothing
# else: dpkg triggers do the rest.
set -e
if [ "$1" = "configure" ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable --now linvpn-logd.socket >/dev/null 2>&1 || true
    systemctl enable --now linvpn-xfrmd.socket >/dev/null 2>&1 || true
fi
if [ "$1" = "configure" ]; then
    v="$(dpkg-query -W -f='"'"'${Version}'"'"' linvpn 2>/dev/null || true)"
    if [ -n "$v" ] && mkdir -p /run/linvpn 2>/dev/null && chmod 0755 /run/linvpn 2>/dev/null; then
        { printf '"'"'%s\n'"'"' "$v" > /run/linvpn/package-version.tmp \
            && chmod 0644 /run/linvpn/package-version.tmp \
            && mv -f /run/linvpn/package-version.tmp /run/linvpn/package-version; } 2>/dev/null \
            || rm -f /run/linvpn/package-version.tmp 2>/dev/null || true
    fi
fi
exit 0
'
PRERM='#!/bin/sh
# LinVPN: stops the log reader'"'"'s and the IKEv2 traffic counter reader'"'"'s sockets before their files go, and drops the
# installed version'"'"'s record.
set -e
if [ "$1" = "remove" ] && [ -d /run/systemd/system ]; then
    systemctl disable --now linvpn-logd.socket >/dev/null 2>&1 || true
    systemctl disable --now linvpn-xfrmd.socket >/dev/null 2>&1 || true
fi
if [ "$1" = "remove" ]; then
    rm -f /run/linvpn/package-version /run/linvpn/package-version.tmp 2>/dev/null || true
    rmdir /run/linvpn 2>/dev/null || true
fi
exit 0
'
check "postinst: byte for byte" cmp -s packaging/linux/deb/postinst <(printf '%s' "$POSTINST")
check "prerm: byte for byte" cmp -s packaging/linux/deb/prerm <(printf '%s' "$PRERM")
# The version record, run on a copy whose /run paths point into a temp dir (a fake dpkg-query; no systemd there).
T="$(mktemp -d)"
mkdir "$T/bin" "$T/run"
mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
fake_query() { printf '#!/bin/sh\n%s\n' "$1" > "$T/bin/dpkg-query"; chmod 0755 "$T/bin/dpkg-query"; }
for script in postinst prerm; do
  sed -e "s#/run/linvpn#$T/run/linvpn#g" -e "s#/run/systemd/system#$T/no-systemd#g" "packaging/linux/deb/$script" > "$T/$script"
done
fake_query "printf '%s' 2.2.0"
check "postinst configure: the version recorded" bash -c "PATH='$T/bin':\"\$PATH\" sh '$T/postinst' configure 2.1.0 && [ \"\$(cat '$T/run/linvpn/package-version')\" = 2.2.0 ] && [ ! -e '$T/run/linvpn/package-version.tmp' ]"
check "postinst: the record 0644 in a 0755 folder" test "$(mode "$T/run/linvpn"):$(mode "$T/run/linvpn/package-version" 2>/dev/null)" = "755:644"
check "postinst upgrade: nothing recorded for another action" bash -c "PATH='$T/bin':\"\$PATH\" sh '$T/postinst' abort-upgrade 2.1.0 && [ \"\$(cat '$T/run/linvpn/package-version')\" = 2.2.0 ]"
fake_query "exit 1"
check "postinst: a failing dpkg-query keeps the old record and still succeeds" bash -c "PATH='$T/bin':\"\$PATH\" sh '$T/postinst' configure 2.1.0 && [ \"\$(cat '$T/run/linvpn/package-version')\" = 2.2.0 ]"
fake_query "printf '%s' 2.3.0"
chmod 0555 "$T/run/linvpn"
if [ -w "$T/run/linvpn" ]; then echo "skip - an unwritable folder (running as root)"; else
  check "postinst: an unwritable /run/linvpn never fails the install" bash -c "PATH='$T/bin':\"\$PATH\" sh '$T/postinst' configure 2.1.0"
fi
chmod 0755 "$T/run/linvpn"
check "prerm upgrade: the record stays" bash -c "sh '$T/prerm' upgrade 2.3.0 && [ -f '$T/run/linvpn/package-version' ]"
check "prerm remove: the record and its folder go" bash -c "sh '$T/prerm' remove && [ ! -e '$T/run/linvpn' ]"
check "prerm remove: nothing there is fine" sh "$T/prerm" remove
rm -rf "$T"
check "packaging/linux/deb holds only postinst and prerm" test "$(cd packaging/linux/deb && find . -mindepth 1 | LC_ALL=C sort | tr '\n' ' ')" = "./postinst ./prerm "
check "the maintainer scripts are executable" test -x packaging/linux/deb/postinst -a -x packaging/linux/deb/prerm
STAGED="$(grep -oE 'DEBIAN/[a-z0-9]+' "$SCRIPT" | sort -u | tr '\n' ' ')"
check "only control, md5sums, postinst and prerm are staged" test "$STAGED" = "DEBIAN/control DEBIAN/md5sums DEBIAN/postinst DEBIAN/prerm "
check "the scripts are staged 0755 from packaging/linux/deb" bash -c "grep -qF 'install -m 0755 packaging/linux/deb/postinst \"\$ROOT/DEBIAN/postinst\"' '$SCRIPT' && grep -qF 'install -m 0755 packaging/linux/deb/prerm \"\$ROOT/DEBIAN/prerm\"' '$SCRIPT'"
check "the gate allows exactly the two scripts" has "$(cat "$SCRIPT")" '[ "$CTRL" = "./ ./control ./md5sums ./postinst ./prerm " ]'
check "the gate compares them byte for byte" has "$(cat "$SCRIPT")" 'cmp -s "$X/DEBIAN/$script" "packaging/linux/deb/$script"'

# The pinned file list: the new paths with their modes.
BASELINE="$(cat scripts/bundle-baseline/linvpn-deb-files.txt)"
for entry in \
  "-rwxr-xr-x ./usr/lib/linvpn/nm-openvpn-service" \
  "-rwxr-xr-x ./usr/lib/linvpn/nm-openvpn-service-openvpn-helper" \
  "-rw-r--r-- ./usr/lib/NetworkManager/VPN/nm-linvpn-openvpn-service.name" \
  "-rw-r--r-- ./usr/share/dbus-1/system.d/nm-linvpn-openvpn-service.conf" \
  "-rwxr-xr-x ./usr/libexec/linvpn/linvpn-logd" \
  "-rw-r--r-- ./usr/lib/systemd/system/linvpn-logd.socket" \
  "-rw-r--r-- ./usr/lib/systemd/system/linvpn-logd@.service" \
  "-rwxr-xr-x ./usr/libexec/linvpn/linvpn-xfrmd" \
  "-rw-r--r-- ./usr/lib/systemd/system/linvpn-xfrmd.socket" \
  "-rw-r--r-- ./usr/lib/systemd/system/linvpn-xfrmd@.service" \
  "-rw-r--r-- ./usr/share/linvpn/source/NetworkManager-openvpn-1.12.5.tar.xz" \
  "-rw-r--r-- ./usr/share/linvpn/source/linvpn-nm-openvpn.patch" \
  "-rw-r--r-- ./usr/share/linvpn/source/README.md" \
  "-rwxr-xr-x ./usr/lib/NetworkManager/dispatcher.d/90-linvpn-route"; do
  check "baseline: $entry" grep -qxF -- "$entry" <<<"$BASELINE"
done
check "baseline: 24 files" test "$(grep -c '^-' <<<"$BASELINE")" = 24
check "baseline: nothing setuid, setgid or world-writable" bash -c "! grep -E '^.{3}[sS]|^.{6}[sS]|^.{8}w' <<<\"\$1\"" _ "$BASELINE"

# What build-deb.sh builds and installs.
S="$(cat "$SCRIPT")"
check "builds the NM OpenVPN service into the stage" has "$S" 'scripts/build-nm-linvpn-openvpn.sh "$NM_OUT"'
check "checks the service's build output" has "$S" 'scripts/test-build-nm-linvpn-openvpn.sh "$NM_OUT"'
check "strips the service and its helper" has "$S" 'strip --remove-section=.comment --remove-section=.note -o'
check "refuses an unstripped service" has "$S" 'is not stripped'
check "installs the dispatcher script 0755 into NM's packaged folder" has "$S" 'install -D -m 0755 packaging/linux/nm-dispatcher/90-linvpn-route "$ROOT/usr/lib/NetworkManager/dispatcher.d/90-linvpn-route"'
check "checks the packaged dispatcher script byte for byte" has "$S" 'cmp -s "$X/usr/lib/NetworkManager/dispatcher.d/90-linvpn-route" packaging/linux/nm-dispatcher/90-linvpn-route'
check "the dispatcher script is executable in the repository (100755)" bash -c "git ls-files -s packaging/linux/nm-dispatcher/90-linvpn-route | grep -q '^100755 '"
check "builds linvpn-logd and linvpn-xfrmd" has "$S" '--bin linvpn-install-update --bin linvpn-logd --bin linvpn-xfrmd'
check "installs linvpn-logd 0755" has "$S" 'install -D -m 0755 "$LOGD" "$ROOT/usr/libexec/linvpn/linvpn-logd"'
check "installs linvpn-xfrmd 0755" has "$S" 'install -D -m 0755 "$XFRMD" "$ROOT/usr/libexec/linvpn/linvpn-xfrmd"'
for unit in linvpn-logd.socket linvpn-logd@.service linvpn-xfrmd.socket linvpn-xfrmd@.service; do
  check "installs $unit from packaging/linux/systemd" has "$S" "install -D -m 0644 packaging/linux/systemd/$unit \"\$ROOT/usr/lib/systemd/system/$unit\""
  check "$unit exists" test -f "packaging/linux/systemd/$unit"
  check "the packaged $unit is compared with the repository's" bash -c "grep -F 'for unit in ' '$SCRIPT' | grep -qF '$unit'"
done
check "dpkg-shlibdeps reads all six programs" bash -c "grep -A3 'dpkg-shlibdeps -O' '$SCRIPT' | grep -qF 'linvpn-logd' && grep -A3 'dpkg-shlibdeps -O' '$SCRIPT' | grep -qF 'linvpn-xfrmd' && grep -A3 'dpkg-shlibdeps -O' '$SCRIPT' | grep -qF 'nm-openvpn-service-openvpn-helper'"
check "linvpn-xfrmd needs only libc and the loader" has "$S" 'for bin in "$STEP" "$LOGD" "$XFRMD"; do'
check "the packaged linvpn-xfrmd is the gated one" has "$S" 'cmp -s "$X/usr/libexec/linvpn/linvpn-xfrmd" "$XFRMD"'
# linvpn-xfrmd's unit (the IKEv2 counters): CAP_NET_ADMIN and nothing else, the host's network namespace for XFRM
# but no IP, AF_UNIX and AF_NETLINK only, never root.
U="$(cat packaging/linux/systemd/linvpn-xfrmd@.service)"
for line in DynamicUser=yes AmbientCapabilities=CAP_NET_ADMIN CapabilityBoundingSet=CAP_NET_ADMIN NoNewPrivileges=yes \
  ProtectSystem=strict ProtectHome=yes IPAddressDeny=any "RestrictAddressFamilies=AF_UNIX AF_NETLINK" RestrictNamespaces=yes \
  "SystemCallFilter=~@privileged @resources" RuntimeMaxSec=20 StandardInput=socket ProtectProc=invisible ProcSubset=pid \
  MemoryMax=64M TasksMax=4; do
  check "xfrmd unit: $line" grep -qxF -- "$line" <<<"$U"
done
for absent in User= Group= SupplementaryGroups= PrivateUsers= PrivateNetwork= "ExecStart=+" "ExecStart=!"; do
  check "xfrmd unit: no $absent" bash -c "! grep -q -- '^$absent' <<<\"\$1\"" _ "$U"
done
check "xfrmd unit: exactly one capability line each" test "$(grep -c 'Capabilit' <<<"$U")" = 2
# linvpn-logd's unit: a dynamic user in systemd-journal, no network, only its own processes in /proc, bounded.
L="$(cat packaging/linux/systemd/linvpn-logd@.service)"
for line in DynamicUser=yes SupplementaryGroups=systemd-journal NoNewPrivileges=yes CapabilityBoundingSet= \
  ProtectSystem=strict ProtectHome=yes PrivateNetwork=yes RestrictAddressFamilies=AF_UNIX ProtectProc=invisible \
  ProcSubset=pid MemoryMax=384M TasksMax=16 RuntimeMaxSec=20 StandardInput=socket; do
  check "logd unit: $line" grep -qxF -- "$line" <<<"$L"
done
check "xfrmd socket: per-connection instances" grep -qxF Accept=yes packaging/linux/systemd/linvpn-xfrmd.socket
check "xfrmd socket: /run/linvpn-xfrmd.sock" grep -qxF ListenStream=/run/linvpn-xfrmd.sock packaging/linux/systemd/linvpn-xfrmd.socket
check "the NM service links only libnm, GLib and libc" has "$S" 'libnm.so.0|libgio-2.0.so.0|libgobject-2.0.so.0|libglib-2.0.so.0|libc.so.6|ld-linux-*.so.*) ;;'
check "the packaged tarball is checked against the pin" has "$S" 'sha256sum -c "$PIN"'
check "Depends is read back" has "$S" 'for pkg in network-manager network-manager-openvpn openvpn systemd libnm0 openssl; do'

# copyright: MIT for LinVPN, GPL-2+ for the NM service and its source.
CR="$(cat packaging/linux/copyright)"
check "copyright: the GPL-2+ stanza for the NM service" bash -c "awk '/^Files: usr\/lib\/linvpn\/nm-openvpn-service\*\$/ {s=1; next} /^Files:/ {s=0} s && /^License: GPL-2\+\$/ {ok=1} END {exit !ok}' <<<\"\$1\"" _ "$CR"
check "copyright: the stanza covers the source" has "$CR" " usr/share/linvpn/source/NetworkManager-openvpn-1.12.5.tar.xz"
check "copyright: the GPL text's place" has "$CR" "/usr/share/common-licenses/GPL-2"
check "copyright: LinVPN stays MIT" bash -c "grep -A2 -xF 'Files: *' <<<\"\$1\" | grep -qxF 'License: MIT'" _ "$CR"

echo "$PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
