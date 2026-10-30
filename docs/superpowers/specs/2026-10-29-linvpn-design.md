# LinVPN (Linux) — design

**Date:** 2026-10-29
**Status:** agreed with the maintainer in conversation (2026-10-29); this written spec awaits their review.
**Base:** MacVPN / WinVPN 2.0.5 (`develop`). Every rule of the earlier specs still applies on Linux: the vault, the control API, team catalogs, the validators, the untrusted-input rules and the update signing. See also [the cross-platform design](2026-10-20-cross-platform-winvpn-design.md), section 7 item 4.

## 1. Goals

- **LinVPN**, the third product from the same codebase: MacVPN (macOS), WinVPN (Windows), LinVPN (Linux).
- **Target:** Debian and Ubuntu based desktops. Test system: Ubuntu 26.04 desktop (GNOME, Wayland) in a VM.
- **Full feature parity with MacVPN.** Everything MacVPN does works in LinVPN:
  - vault, folders, shared credentials, backup and restore;
  - team catalogs and publishing;
  - control API with paired apps;
  - MFA and credential prompts;
  - auto-reconnect, network loss, network switch, dead tunnels and slow retries;
  - live traffic, the Log tab with clear and time filter;
  - notifications, appearance, missing engines, signed self-update;
  - EN/HU.
- **NetworkManager is the VPN backend.** LinVPN drives NM; it does not run VPN engines itself.

**Not goals:**
- Distributions other than Debian/Ubuntu.
- Flatpak, Snap, AppImage.
- Official support for desktops other than GNOME on Ubuntu. KDE and others will probably work but are not tested.
- An apt repository. A later option.

## 2. Decisions (maintainer, 2026-10-29)

| # | Decision |
|---|---|
| 1 | Product name **LinVPN**; package `linvpn`. |
| 2 | Test VM: like Windows. A non-admin `linvpn-dev` user reached over SSH (key `~/.ssh/linvpn_dev` on the Mac) and logged on at the desktop for the smoke. Admin steps (apt installs, installing the `.deb`) are the maintainer's. |
| 3 | **Backend A: everything through NetworkManager.** No root helper for VPNs. LinVPN is an NM secret agent. OpenVPN accepts what NM's OpenVPN plugin can express. Spike L0-1 measures the gap; if it is large, OpenVPN falls back to its own helper (option B). |
| 4 | Tray: the **card panel** as on macOS/Windows, opened near the top-right corner. Spike L0-2 checks a direct left click; fallback is a short menu whose first item opens the panel. |
| 5 | Packaging: signed **`.deb`** (amd64, arm64) in the GitHub release, with **self-update**: the same Ed25519 check as the other products, then installed with the system's password prompt (pkexec). |
| 6 | Logs: a small read-only system service **`linvpn-logd`** that returns only the calling user's own VPN connections' NetworkManager journal lines. |
| 7 | (After spike L0-1) OpenVPN without `redirect-gateway` in the profile defaults to a **split tunnel** on Linux when the server's push cannot be seen, with a per-connection "Send all traffic over VPN" setting. |
| 8 | (After the redirect-gateway research) A **server-pushed `redirect-gateway` is honored automatically**, as on macOS: LinVPN ships its own patched NM OpenVPN service (section 4); the setting's default is "Server decides". |

*Note (L0, 2026-10-29), decision 4:* spike L0-2 ([findings](../spikes/2026-10-29-linvpn-tray.md)) found that Tauri's Linux tray (libayatana-appindicator) delivers no click at all, and that Ubuntu's AppIndicators extension never sends `Activate` on a single left click: a single left click opens the item's menu (after the 400 ms double-click wait), a double click sends `Activate(x, y)`, a middle click `SecondaryActivate(x, y)`. GNOME on Wayland centres every positioned toplevel and has no layer shell. The maintainer decided (CP-L0, 2026-10-29): the tray is **LinVPN's own StatusNotifierItem over `ksni`** (0.3.7); a single left or right click shows a short menu whose first item is **"Open LinVPN"**; a double click (`Activate`) or a middle click (`SecondaryActivate`) **toggles the panel** directly. The panel on Wayland is a **transparent maximized overlay window** whose input region is the card (re-applied on every `size-allocate`, because GTK resets it), with the card drawn at the top-right under the top bar; a click outside passes through and hides it. LinVPN stays on native Wayland (**no forced X11 backend**); Xwayland (`GDK_BACKEND=x11` with an explicit position) is only the fallback if the overlay fails. The maintainer checked the variant on screen (double click → the card at the top-right under the top bar; a click outside hides it) and accepts the single-click menu delay. Decision 4 stands: the "short menu whose first item opens the panel" is the main path for a single click on Ubuntu GNOME.

## 3. Architecture

### 3.1 Crates

- **`platform-linux`** (new): implements the `platform-api` traits for Linux.
  - **NetworkManager client** over D-Bus (`zbus`):
    - add and activate connections, deactivate them;
    - active-connection and device state signals;
    - `Ip4Config` (address);
    - the primary connection and connectivity for the network watcher, which feeds network loss, network switch and the wake fingerprint.
  - **Secret agent** (`org.freedesktop.NetworkManager.SecretAgent`): NM asks LinVPN for passwords, PSKs and MFA codes. They come from the vault or the LinVPN prompts; nothing is stored in GNOME Keyring or NM's system store.
  - **Vault auto-unlock key** in the Secret Service (`org.freedesktop.secrets`, gnome-keyring), like the Keychain and Credential Manager.
  - **Tray:** StatusNotifierItem; the card panel opens near the top-right corner and closes on focus loss. (Since L0: an own SNI over `ksni`, the menu's first item "Open LinVPN", a double or middle click toggles the panel, the panel a transparent overlay window on Wayland; see the note under decision 4.)
  - **Desktop integration:**
    - notifications: `org.freedesktop.Notifications`;
    - autostart: `~/.config/autostart/linvpn.desktop`;
    - appearance: `org.freedesktop.portal.Settings` `color-scheme`;
    - file associations: `.desktop` MIME types for `.ovpn`, `.conf`, `.sstp`, `.macvpnbackup`, `.macvpncatalog` and the others MacVPN opens;
    - control API: Unix socket in `$XDG_RUNTIME_DIR`, same protocol as macOS.
  - **Missing engines:** System Status installs the needed NM plugin through the PackageKit D-Bus API (system password prompt).
  - **Live traffic:** `/sys/class/net/<iface>/statistics` (user-readable).
- **`linvpn-logd`** (new, a binary in the `helper` crate or its own small crate; decided in the plan):
  - **How it runs:** a socket-activated systemd service, the only root component. It identifies the caller by `SO_PEERCRED`.
  - **What it returns:** only journal lines of NetworkManager and its VPN plugins for connections the caller owns. Ownership means the NM connection's `permissions` holds `user:<caller>`, and the connection UUID is one LinVPN created for that user.
  - **What it never does:** writes, other users' lines, arbitrary journal queries. Its strictness follows the WinVPN Service's owner check.
- **`core`:**
  - `nm_plan`: a pure, tested translation of a LinVPN connection into NM settings, per kind.
  - The OpenVPN validator gets a **Linux tier** (`TargetOs::Linux`): what NM's OpenVPN plugin can express.
- **`app-core`, the Svelte UI:** unchanged except platform branches behind the existing traits and product names. LinVPN-specific texts go into `strings.json` with `only`/`variants`, as WinVPN's do.

### 3.2 Data

- **Locations:** app data in `~/.local/share/LinVPN`, settings in `~/.config/LinVPN`, run files in `$XDG_RUNTIME_DIR/linvpn`.
- **Formats:** vault, full backup, per-connection export and team catalog are the same as on macOS and Windows. A MacVPN or WinVPN backup restores on LinVPN.
- **Connections Linux cannot run:** they keep their data and get a per-connection Linux reason (greyed row, editor note, refused start), as WinVPN does.

## 4. VPN kinds

| Kind | NM backend | Notes |
|---|---|---|
| WireGuard | NM built-in `wireguard` | no plugin |
| OpenVPN | `network-manager-openvpn` | Linux tier; inline certs and keys written to `$XDG_RUNTIME_DIR/linvpn/<id>/` (0700 dir, 0600 files), removed after disconnect |
| L2TP/IPsec | `network-manager-l2tp` | PSK + user/password |
| IKEv2 | `network-manager-strongswan` | EAP, certificate and PSK |
| Cisco IPsec (IKEv1 XAuth) | `network-manager-vpnc` | works on Linux, unlike Windows |
| SSTP | `network-manager-sstp` | |

**Connecting:**
- LinVPN adds and activates a connection for each connect with `AddAndActivateConnection2` and the option `persist = volatile`. NM deletes the profile when it is deactivated. *(2026-10-30: no `bind-activation = dbus-client` any more. The binding took every LinVPN tunnel down when the process ended, also after "Quit, Keep Them Running"; macOS and Windows keep them up. Now a "Keep Them Running" quit and a crash leave the tunnel up, the next launch adopts it (found by its derived UUID among NM's active connections, only when its profile is volatile and private to the user), and a normal quit disconnects through app-core's quit flow. The user can still disconnect it from GNOME's network menu while LinVPN is not running; the profile vanishes then.)* Settings: `permissions = user:<name>` (set before adding; a connection without it is a system-wide change that asks for the admin password), `autoconnect = false`, NM's own VPN persistence and retries off. LinVPN never uses `nmcli connection import`: even `--temporary` asks for the admin password (spike L0-1).
- Secrets carry `agent-owned` flags, so NM asks the LinVPN secret agent.
- The LinVPN planner alone decides reconnects (wake, network loss, network switch, dead tunnel, slow retry), with the same user-visible rules as macOS.

**MFA:** OpenVPN static challenge, dynamic challenge (CRV1) and the code appended to the password all go through the secret agent and the LinVPN code prompt. The dynamic challenge is spike L0-4.

*Note (L0, 2026-10-29):* spike L0-4 (the static and the CRV1 challenge through the secret agent) stays deferred until the maintainer starts the VPN lab; no L-a work depends on it. It must run before L-b's secret agent is designed.

**OpenVPN full or split tunnel (decisions 7 and 8):** stock NM ignores a `redirect-gateway` pushed by the server (research: `docs/superpowers/spikes/2026-10-29-linvpn-redirect-gateway.md`). LinVPN therefore ships its **own NM OpenVPN service**: upstream network-manager-openvpn (the version Ubuntu ships) with a small helper patch that sends `NEVER_DEFAULT` for IPv4/IPv6 unless OpenVPN 2.7+ reports `route_redirect_gateway_ipv4/6`, installed under its own service name (`org.freedesktop.NetworkManager.linvpn-openvpn`) next to the stock plugin, which stays untouched. `nm_plan` sets `never-default = no`, so the default route follows the server's push from the first IP config (no leak window, no reconnect, no prompt). Every OpenVPN connection has a **Send all traffic over VPN** setting with three values: **Server decides** (default; matches macOS), **Always**, **Never**. With OpenVPN older than 2.7 the push cannot be seen; then "Server decides" acts as decision 7: the profile's own `redirect-gateway` decides, otherwise a split tunnel, and the editor says so.

**System VPNs:** the user's own NM VPN and WireGuard profiles appear as system VPNs (connect, disconnect, state, address, traffic), as on macOS.

**DNS:** NM and systemd-resolved apply and restore it. Split tunnels use the connection's DNS only for its search domains. LinVPN has no DNS manager of its own.

**Liveness (dead tunnel):**
- OpenVPN uses the NM VPN state: reconnecting is shown as "Reconnecting…", stopped means dead.
- WireGuard: the last handshake is not readable without root (spike L0-3: NM's D-Bus has no handshake, `wg` and netlink get EPERM). LinVPN uses the counter rule on `/sys/class/net/<iface>/statistics`: dead when tx grows while rx stays still for about 200 s (past WireGuard's 180 s session expiry).

**Logs:** the Log tab shows `linvpn-logd`'s NM lines for the connection plus LinVPN's own lines. **Clear Log…** clears LinVPN's copy and the view; the system journal is not touched. The time filter works on journal timestamps.

## 5. Phases

1. **L0 — spikes on the VM:**
   1. Import the existing OpenVPN fixtures (lab, MikroTik, UniFi, pfSense, OPNsense) into NM's OpenVPN plugin; list what it refuses or drops.
   2. Tray left click opens the panel (StatusNotifierItem `Activate` with the Ubuntu AppIndicators extension).
   3. WireGuard last-handshake without root.
   4. OpenVPN CRV1 through the secret agent.
   
   Results may change section 4 and decisions 3 and 4; the maintainer is told.
2. **L-a — foundations:**
   - `platform-linux` skeleton, builds and tests on the VM;
   - tray and panel;
   - Secret Service vault key;
   - notifications, autostart, appearance, file associations;
   - control API socket;
   - `.deb` (amd64, arm64) with dependencies, and the signed self-update;
   - CI Linux job;
   - Linux smoke in the VM's desktop session.
3. **L-b — VPNs through NM:**
   - `nm_plan`, the NM client, the secret agent;
   - all six kinds;
   - system VPNs;
   - status, traffic, liveness;
   - `linvpn-logd`;
   - PackageKit installs;
   - the OpenVPN Linux tier.
4. **L-c — parity and closing:**
   - a feature-by-feature audit against MacVPN, with its gaps fixed;
   - LinVPN user guide and how-to (EN/HU);
   - manual checklist;
   - independent security review.
5. **Release 2.1.0:** MacVPN + WinVPN + LinVPN together.

Each phase gets its own implementation plan.

## 6. Testing

- **Pure logic** (`nm_plan`, the Linux tier, logd's filter) is tested on macOS and in CI.
- **`scripts/lin-remote.sh`**, like `win-remote.sh`: sync, build, test and smoke on the VM as `linvpn-dev`. One remote dir per concurrent agent.
- **Live end-to-end against the VPN lab** for every kind. On Linux this needs no admin, because the desktop user may activate NM connections. The lab runs in Docker on the Mac and is reachable from the VM over the LAN. The maintainer starts the lab.
- **CI:** an Ubuntu job (build, clippy, tests, `.deb`) plus an arm64 build.

## 7. Release and updates

- The GitHub release adds `linvpn_<ver>_amd64.deb` and `linvpn_<ver>_arm64.deb` with `.sha256` and build provenance.
- `sign-release.sh` signs them. The message is `linvpn-update-v1\n<asset>\n<ver>\n<sha256>\n`, verified with the same primary key.
- **Self-update:** download, then check the signature, the version (no downgrade) and the package name/architecture. Then `pkexec apt-get install ./<file>.deb` from a private, user-only directory.
- **Dependencies:** `network-manager`, `libwebkit2gtk-4.1-0`, a StatusNotifierItem host, and the NM plugins as `Recommends`. Missing plugins are installed on demand from System Status.

## 8. Security notes

- **Root components:** `linvpn-logd` (read-only, socket-activated, filters by the caller's UID and owned connections), the update step `linvpn-install-update` (pkexec, re-checks the signed package), and LinVPN's NM OpenVPN service (started by NM as root and dropping to `nm-openvpn` like the stock plugin; a scoped patch of upstream GPL-2+ code whose source ships with the `.deb`; upstream security fixes are tracked, and the patch is offered upstream).
- **NM connections** are in-memory, user-restricted and volatile. Secrets never go into NM's system storage; the secret agent answers only NM (it checks the D-Bus sender is NetworkManager's unique name).
- **OpenVPN** keeps the directive policy; the Linux tier can only be stricter than what NM itself allows.
- **Credential files** written for NM (certificates, keys) live in the 0700 runtime dir and are removed after use.
- **The self-update** installs only a signed `.deb` of package `linvpn`, never downgrades, and uses pkexec with the system prompt.
