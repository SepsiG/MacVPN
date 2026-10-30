# Spike L0-3: WireGuard last handshake without root

**Date:** 2026-10-29
**Spec:** [LinVPN design](../specs/2026-10-29-linvpn-design.md), section 4 ("Liveness"), section 5 (L0-3).
**System:** Ubuntu 26.04.1 VM (x86_64), kernel 7.0.0-42, NetworkManager 1.54.3, wireguard-tools 1.0.20250521.
User `linvpn-dev` (not an admin).

## Answer

**An unprivileged user cannot read the last handshake.** LinVPN must use the counter rule from the spec: dead when
`tx_bytes` grows while `rx_bytes` stays still for longer than the WireGuard timers.

| Source | Last handshake | rx / tx | Result as `linvpn-dev` |
|---|---|---|---|
| NM D-Bus `org.freedesktop.NetworkManager.Device.WireGuard` | no | no | Only `PublicKey`, `ListenPort`, `FwMark`. NM 1.54 exposes no peer data |
| NM D-Bus `org.freedesktop.NetworkManager.Device.Statistics` | no | **yes** | `TxBytes`/`RxBytes`, once `RefreshRateMs` is set (polkit `enable-disable-statistics`: yes in the desktop session) |
| `/sys/class/net/<if>/statistics/*` (and `ip -s link`, RTM_GETLINK) | no | **yes** | Readable, no polkit. **Use this** (the spec's live-traffic source anyway) |
| `wg show <if>` / `latest-handshakes` / `transfer` | — | — | `Unable to access interface: Operation not permitted` |
| generic netlink `WG_CMD_GET_DEVICE` | — | — | `NLMSG_ERROR -1 (EPERM)`, even for a non-WireGuard name. The family is `GENL_UNS_ADMIN_PERM`, so it needs CAP_NET_ADMIN |

**What the counters showed with a dead peer:** within about 11 s, the interface counted
`tx_packets=3, tx_bytes=444, rx=0`. That is 3 × 148 bytes, the size of a WireGuard handshake initiation. This is
**inferred** from the sizes: the 5 pings stayed queued and were not counted, while the kernel retried the handshake
every 5 s (REKEY_TIMEOUT). So a dead peer shows exactly the pattern the counter rule looks for: tx grows, rx stays 0.

**The rule for LinVPN, to tune in L-b:**
- Sample `rx_bytes`/`tx_bytes` from sysfs.
- The tunnel is dead if `tx_bytes` increased and `rx_bytes` did not, over a window longer than REJECT_AFTER_TIME
  (180 s), for example 200 s.
- A live peer answers a rekey at least every REKEY_AFTER_TIME (120 s) while we send anything, and a handshake
  response is 92 bytes. Persistent keepalive counts as sending.
- If both counters stay still, the tunnel is only idle, not dead. That matches the macOS rule.

## What was run

Everything ran as `linvpn-dev` inside the user's systemd manager:
```
ssh $LINVPN_SSH 'cd ~/l0-a/spike3 && systemd-run --user --unit=l0a-wg -E LC_ALL=C \
  --working-directory=$HOME/l0-a/spike3 /bin/bash -c "python3 -I wg_liveness.py > wg.log 2>&1"'
```
The user manager counts as the desktop user's session for polkit, so it has the same rights the LinVPN app will have.

[wg_liveness.py](2026-10-29-linvpn-l0-a/wg_liveness.py):
1. **Asks polkit first, non-interactively.** It calls `CheckAuthorization` with flags 0, which never shows a dialog,
   for `settings.modify.own`, `network-control` and `enable-disable-statistics`. It stops unless the first two are
   authorized. A dry run over plain SSH stopped here, as expected.
2. **Adds and activates one connection** with `AddAndActivateConnection2`, options
   `{"persist": "volatile", "bind-activation": "dbus-client"}`, and no interactive-authorization flag on the call:
   - `connection.permissions = user:linvpn-dev`, `autoconnect = false`, interface `l0awg0`;
   - a random private key and a random peer public key, the peer endpoint at `192.0.2.1:51820` (TEST-NET-1),
     `AllowedIPs 10.99.250.0/24`, persistent keepalive 5;
   - `ipv4` manual `10.99.250.2/32`, `never-default`, `ignore-auto-dns`; `ipv6` disabled.
3. Pings `10.99.250.1` 5 times and reads every source in the table.
4. Deactivates the connection and checks that it is gone.

[wg_genl.py](2026-10-29-linvpn-l0-a/wg_genl.py) repeats the netlink test from a plain SSH shell. No NM was
involved in that run.

### Evidence (`wg.log`, abridged)

```
polkit org.freedesktop.NetworkManager.settings.modify.own: authorized=True challenge=False
polkit org.freedesktop.NetworkManager.network-control: authorized=True challenge=False
polkit org.freedesktop.NetworkManager.enable-disable-statistics: authorized=True challenge=False
added+activating: /org/freedesktop/NetworkManager/Settings/3 /org/freedesktop/NetworkManager/ActiveConnection/3 {}
settings flags (1=unsaved 2=nm-generated 4=volatile 8=external): 5 unsaved: True
active state: 2 (2=activated) device: /org/freedesktop/NetworkManager/Devices/3
interface: l0awg0 ip4config: /org/freedesktop/NetworkManager/IP4Config/3
$ ping -c 5 -i 1 -W 1 10.99.250.1
  5 packets transmitted, 0 received, 100% packet loss, time 4131ms

[A] NM D-Bus org.freedesktop.NetworkManager.Device.WireGuard:
  properties: {'PublicKey': '<32 bytes>', 'ListenPort': 43819, 'FwMark': 0}
  introspection: <property type="ay" name="PublicKey" access="read"/> <property type="q" name="ListenPort" access="read"/> <property type="u" name="FwMark" access="read"/>

[B] NM D-Bus org.freedesktop.NetworkManager.Device.Statistics:
  before: {'RefreshRateMs': 0, 'TxBytes': 0, 'RxBytes': 0}
  RefreshRateMs=1000 set; after: {'RefreshRateMs': 1000, 'TxBytes': 444, 'RxBytes': 0}

[C] sysfs /sys/class/net/l0awg0/statistics:
  rx_bytes = 0
  tx_bytes = 444
  rx_packets = 0
  tx_packets = 3
  tx_errors = 0
  tx_dropped = 0

[D] wg (wireguard-tools) as the user:
$ wg show l0awg0
  rc=1  stderr='Unable to access interface: Operation not permitted'
$ wg show l0awg0 latest-handshakes
  rc=1  stderr='Unable to access interface: Operation not permitted'
$ wg show l0awg0 transfer
  rc=1  stderr='Unable to access interface: Operation not permitted'

[cleanup]
  deactivated
  delete: … Object does not exist at path “/org/freedesktop/NetworkManager/Settings/3” (volatile: NM already removed it)
  connection still listed: False
  interface still present: False
```
```
$ python3 -I wg_genl.py l0awg0 lo        # plain SSH shell, uid 1001
uid 1001 wireguard family id 41
ifname='l0awg0': NLMSG_ERROR -1 (EPERM: Operation not permitted)
ifname='lo': NLMSG_ERROR -1 (EPERM: Operation not permitted)
```
(The in-script netlink check printed `NLMSG_ERROR 0`. That was the ACK of its own family lookup, read by mistake.
`wg_genl.py` reads replies by sequence number and gives the real answer above.)

## Side findings for the design

**Connect flow.** `AddAndActivateConnection2` with `persist: volatile` and `bind-activation: dbus-client` works for
a user-owned connection without any prompt:
- Settings `Flags = 5` means UNSAVED | VOLATILE.
- NM deleted the profile itself on deactivation.
- If the LinVPN process dies, `dbus-client` binding takes the tunnel down.

This is better than the spec's `AddConnection2` + flags. That call has no VOLATILE flag; volatility is only
available through `Update2` or this `persist` option. Proposed change to section 4: use
`AddAndActivateConnection2(…, {"persist": "volatile", "bind-activation": "dbus-client"})`.

**Polkit, measured with `nmcli general permissions` and `CheckAuthorization`, as `linvpn-dev` (not an admin):**

| Operation | polkit action | From an SSH shell | In the desktop session / user manager |
|---|---|---|---|
| Add a connection **without** `permissions` (`nmcli connection import`, even `--temporary`; `nmcli connection add` without `connection.permissions`) | `settings.modify.system` | auth | **auth_admin: admin-password dialog on the desktop** |
| Add or delete a connection with `permissions = user:<me>` | `settings.modify.own` | auth (challenge) | yes, no prompt |
| Activate or deactivate | `network-control` | auth (challenge) | yes, no prompt |
| Set `Device.Statistics.RefreshRateMs` | `enable-disable-statistics` | no | yes, no prompt |

**Rules:**
- LinVPN must always set `connection.permissions = user:<name>` **before** adding, and never use `nmcli connection
  import`.
- Test tooling over SSH must run NM writes through `systemd-run --user`, and only after a non-interactive
  `CheckAuthorization`.

**The approval dialogs the maintainer saw:**
1. **"Authentication required … modification of network settings for all users"** (admin password, several times
   from about 16:06): this spike's first OpenVPN attempt, `nmcli connection import --temporary` in a loop. See the
   [OpenVPN spike](2026-10-29-linvpn-nm-openvpn.md#do-not-use-nmcli-connection-import-not-even-with---temporary).
   It was stopped, and no connection was added.
2. **The earlier "connection attempt" dialog** (about 16:04) was **not** NetworkManager. At that time this spike had
   run only read-only commands: `id`, `nmcli --version`, `nmcli general permissions`, `loginctl`. The user journal
   shows the desktop portal and Mutter's screen-cast and remote-desktop API at that moment:
   ```
   16:04:27 gnome-shell[44993]: D-Bus client with active sessions vanished
   16:04:36 xdg-desktop-portal-gnome[45439]: Failed to associate portal window with parent window
   16:04:58 xdg-desktop-portal-gnome[45439]: Failed to associate portal window with parent window ''
   16:04:58 xdg-desktop-portal-gnome[45439]: Failed to get screenshot: … There is an ongoing operation for this sender
   ```
   This is a portal permission dialog (screenshot or screen cast "Allow"). Another client asked for it, most likely
   the parallel tray spike (L0-2): the journal shows `gnome-extensions list --enabled` at 16:02 and 16:03, which this
   spike never ran.
3. **The WireGuard run** (16:14:12) produced no prompt. The user journal from 16:14 has only the `systemd-run` line,
   and polkit had already said "authorized, no challenge".

**Cleanup:** `nmcli connection show` on the VM lists only `netplan-ens18` and `lo`. `ip -br link` shows no
`l0awg0`. No `nmcli` or spike process is left running.
