# LinVPN's NetworkManager OpenVPN service

LinVPN runs its own OpenVPN connections through NetworkManager with **its own build of the NetworkManager OpenVPN
service**: upstream [NetworkManager-openvpn](https://gitlab.gnome.org/GNOME/NetworkManager-openvpn) **1.12.5** (the
version Ubuntu 26.04 ships), unmodified except for `linvpn-nm-openvpn.patch`. It is installed next to the stock
plugin, which stays untouched and keeps serving every other OpenVPN connection on the machine:

| File | What |
|---|---|
| `/usr/lib/linvpn/nm-openvpn-service` | the service (NetworkManager starts it for `org.freedesktop.NetworkManager.linvpn-openvpn`) |
| `/usr/lib/linvpn/nm-openvpn-service-openvpn-helper` | its `--up` helper |
| `/usr/lib/NetworkManager/VPN/nm-linvpn-openvpn-service.name` | the VPN service registration (no editor, no auth dialog) |
| `/usr/share/dbus-1/system.d/nm-linvpn-openvpn-service.conf` | upstream's D-Bus policy for the new service name |

## Why

Stock NetworkManager ignores a `redirect-gateway` that the OpenVPN server pushes: the `--up` helper never tells
NetworkManager whether the VPN should get the default route, so only the connection's `never-default` setting
decides. OpenVPN 2.7 exports the effective state (profile, push and `pull-filter` together) to the `--up` script as
`route_redirect_gateway_ipv4` / `route_redirect_gateway_ipv6`, for exactly this purpose. With the patch, LinVPN's
OpenVPN connections follow the server's push from the first IP configuration, as on macOS. (LinVPN design,
decision 8; research: `docs/superpowers/spikes/2026-10-29-linvpn-redirect-gateway.md` and
`…-linvpn-nm-openvpn.md` in the LinVPN source.)

## What the patch changes

1. **The helper** (`src/nm-openvpn-service-openvpn-helper.c`) gets the option `--redirect-info`. With it, the IPv4
   configuration carries `NEVER_DEFAULT = false` exactly when `route_redirect_gateway_ipv4` is `1` or `2`, and the
   IPv6 configuration (when there is one) the same from `route_redirect_gateway_ipv6`. `2` (`block-local`) has no
   NetworkManager equivalent: it routes as a plain full tunnel and logs a warning.
2. **The service** (`src/nm-openvpn-service.c`, keys in `shared/nm-service-defines.h`):
   - passes `--redirect-info` to the helper when `openvpn --version` is 2.7 or later;
   - accepts four more `vpn.data` keys and passes them to OpenVPN, each value checked strictly (anything else fails
     the connection with "property … invalid or not supported"):

     | Key | Value | OpenVPN option |
     |---|---|---|
     | `linvpn-redirect-gateway` | space-separated flags from `def1 ipv6 !ipv4 bypass-dhcp bypass-dns local autolocal block-local` (at most 8) | `--redirect-gateway <flags>` |
     | `linvpn-pull-filter` | lines `ignore\|accept\|reject <text>` (at most 16; the text optionally in double quotes, `[A-Za-z0-9 _.:/-]{1,64}`) | `--pull-filter <action> <text>` per line |
     | `linvpn-route-nopull` | `yes` | `--route-nopull` |
     | `linvpn-verb` | `0` … `4` | raises `--verb` (never lowers it) |

   - starts OpenVPN with `--syslog linvpn-ovpn-<NetworkManager connection UUID>` instead of `--syslog nm-openvpn`,
     so LinVPN's log service can tell one connection's OpenVPN lines from another's;
   - nothing else: the D-Bus service name constant, the hardening (`--user nm-openvpn`, the chroot), the
     management interface and the secrets handling are upstream's. No editor, auth dialog or translation is built.

## Building

`scripts/build-nm-linvpn-openvpn.sh OUT_DIR` (Linux) downloads the tarball, checks it against
`scripts/pins/nm-openvpn.sha256` (the same SHA-256 as GNOME's published `.sha256sum` and Ubuntu's
`network-manager-openvpn_1.12.5.orig.tar.xz`), applies the patch and builds with upstream's own autotools build:

```bash
./configure --prefix=/usr --libexecdir=/usr/lib/linvpn --without-gnome --disable-static --disable-nls
make src/nm-openvpn-service src/nm-openvpn-service-openvpn-helper
```

Build dependencies on Ubuntu: `build-essential pkg-config gettext libnm-dev libglib2.0-dev`.

## Licence and source

NetworkManager-openvpn is licensed under the **GNU General Public License, version 2 or (at your option) any later
version** (GPL-2.0-or-later); so are the patch and the two programs built from them. The `.deb` ships the
corresponding source in `/usr/share/linvpn/source/`: the unmodified upstream tarball
`NetworkManager-openvpn-1.12.5.tar.xz`, `linvpn-nm-openvpn.patch` and this README. LinVPN itself is MIT licensed;
it only starts these programs through NetworkManager (aggregation).

The helper part of the patch is what OpenVPN 2.7's variables were added for; it is offered upstream to
NetworkManager-openvpn. When a distribution ships it, LinVPN can return to the stock plugin.
