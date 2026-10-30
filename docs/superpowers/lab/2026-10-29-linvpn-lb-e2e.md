# LinVPN L-b end-to-end lab notes

## Security review of LinVPN (develop eacb482) and its fixes (branch lb-sec)

An independent security review of LinVPN at develop eacb482 found one medium, three low and six informational
items. Each fix is one commit on `lb-sec` (on develop 19dd312), with its tests. The tests ran on the Linux test VM
(non-admin `linvpn-dev`, private session buses, fake NetworkManager / PackageKit / logd) and on the Mac for the
pure crates. Nothing was run against the real NetworkManager, journal, keyring or PackageKit.

| Finding | Fix | Tests |
|---|---|---|
| **M1** (medium): linvpn-logd could give one user another user's VPN plugin lines (a tunnel that was up before the caller's window and stayed up after it wrote no VPN-domain line inside the window) | `fix(logd): plugin lines only while NetworkManager's history shows no other VPN up` | core `tests/logd.rs` (the attack, the normal single-user case, a tunnel that ended before, name and quoted-text spoofing, forged start or end lines, an NM restart, no history), helper `tests/logd.rs` (two fixed queries, the history whole or not at all) |
| **L1** (low): the secret agent released stored secrets by UUID alone | `fix(linux): the secret agent answers only the run's own profile path, permission and plugin` | `nm_agent.rs` (wrong path, waits for the bind, permissions or plugin wrong), `nm_engine.rs` (wrong path, wrong permissions, wrong plugin, NM's `user:<name>:` form, secrets gone after Failed) |
| **L2** (low): another user can squat a derived UUID | `fix(linux): a connection whose derived UUID another user holds gets a clear error` | `nm_engine.rs` (a hidden and a visible profile of someone else: the new message, nothing deleted), `texts.rs` (EN+HU) |
| **L3** (low): a timed-out clipboard write could leave the secret there with no clear | `fix(linux): a timed-out clipboard write never puts the secret there later` | `clipboard.rs` unit tests (an abandoned call never runs later; a call in time returns) |
| **I1**: the update step's open of the caller's files could block on a FIFO | `fix(helper): the update step opens the caller's files with O_NONBLOCK\|O_NOCTTY` | `install_update.rs` (a FIFO in place of the package is refused without blocking) |
| **I2**: logd/xfrmd unit hardening | `fix(linux): bound linvpn-logd and linvpn-xfrmd instances; logd sees only its own /proc` | `scripts/test-build-deb.sh` (the logd unit's lines, the new xfrmd lines) |
| **I3**: xfrmd could mix the system charon's and charon-nm's SAs | `fix(xfrmd): IKEv2 counters match the SA's outer source and selector, refuse ambiguous SAs` | core `tests/xfrmd.rs` (outer source, an SA's own selector, two daemons with the same reqid: `N`, the parser reads the new fields) |
| **I4**: the PKCS#12 password pipe could land on fd 0-2 | `fix(linux): the PKCS#12 password pipe is moved above stdio before openssl starts` | `pkcs12.rs` unit test (a pipe end at fd 0 is moved, stays close-on-exec, is the same pipe) |
| **I5**: PackageKit's wait had no limit | `fix(linux): PackageKit installs time out (30 min, 5 min to resolve) and are cancelled` | `packagekit_bus.rs` (a never-finishing install times out, `Cancel` is sent, the message) |
| **I6**: verb-4 OpenVPN output goes to the system journal | no code change (decision below) | — |
| Extra (coordinator): an adopted run's log masked nothing | `fix(linux): an adopted tunnel's log masks its secrets once the vault is unlocked` | `nm_connlog.rs`, `nm_engine.rs`, app-core `state_listeners.rs` |

### M1: how plugin lines are attributed now

`_PID` attribution was checked first and is not usable: NetworkManager 1.54.3 logs `starting: VPN service has PID
<n>` only for the plugins it spawns itself (`supports-multiple-connections=true`: openvpn, sstp, vpnc, pptp), while
charon-nm and nm-l2tp-service are D-Bus activated (no PID line; charon-nm serves every connection from one
process), and the services' children (openvpn, pppd, xl2tpd, sstpc, vpnc) have PIDs NM never logs.

So logd now runs a second, fixed `journalctl` query: NetworkManager's `NM_LOG_DOMAINS=VPN` lines and its
`CODE_FUNC=main` lines (its `NetworkManager (version …) is starting...` line), the newest 5000, no `-b` (the unit's
`ProcSubset=pid` hides `/proc/sys`, which `-b` reads). It must be read whole (a cut fails it). From NM's last start it
replays each connection's state from trusted NM lines only: `starting <plugin>` activates, `set state:
disconnected|failed (was …)` and `dbus: state changed: stopped (6)` end, any other line of a connection that has not
ended counts as active. Only the text after the first `"]: ` of the `vpn[0x…,<uuid>,"<name>"]: ` prefix is read and
it must be the whole known message, so neither a connection name (chosen by its owner) nor a quoted plugin or agent
error at the end of a message can fake an end. A plugin line passes only when the caller's connection was active
then (after its own activation) and no other connection was; otherwise `W`. Without NM's start line (rotated away,
more than 5000 VPN lines since, a failed read) no plugin line passes. The caller's own NM and `linvpn-ovpn-<UUID>`
lines are unchanged.

Residual: a VPN plugin that outlives an NM restart is not tracked (NM tears its VPNs down when it stops; not
verified on a live system). journald rate limiting that drops NM's activation line would hide that connection.

### M1 reworked after lab run 2 (branch lb-logd)

Lab run 2 showed NetworkManager 1.54.3 at its default level (`INFO`) logs no end of a VPN connection: `set state:
…` and `dbus: state changed: …` are `_LOGD`, so every earlier connection stayed "active" and every later plugin line
was withheld. NM's source (`src/core/vpn/nm-vpn-connection.c`, tag 1.54.3) writes at `INFO`/`WARN` in the `VPN`
domain only `starting <plugin>` (`nm_vpn_connection_activate`, `_LOGI`) and warnings; the warnings that end a
connection (each followed by `_set_vpn_state(…, STATE_FAILED, …)` or `nm_vpn_connection_disconnect`) are now ends,
matched as whole messages after the `vpn[0x…,<uuid>,"<name>"[,if:<n>][,dev:<n>][:(<iface>)]]: ` prefix
(`__LOG_create_prefix`; the iface tail was not handled before):

| Message | NM function |
|---|---|
| `dbus: failure: <reason> (<n>)` | `_dbus_signal_failure_cb` (the plugin's `Failure`; it then stops) |
| `failed to connect: '<error>'` | `connect_cb` |
| `connect: failed to connect interactively: '<error>'` | `connect_interactive_cb` |
| `did not receive valid IP config information` | `_check_complete` (also after `config: …` / `invalid IP… config received: …`) |
| `connect timeout exceeded` | `_connect_timeout_cb` |
| `plugin NeedSecrets request #<n> failed: <error>`, `final secrets request failed to provide sufficient secrets` | `_secrets_dbus_need_secrets_cb` |
| `sending new secrets to the plugin failed: <error>` | `_secrets_dbus_new_secrets_cb` |
| `secrets: failed to request VPN secrets #<n>: <error>` | `_secrets_get_secrets_cb` |
| `starting: timed out waiting for the service to start` / `… for the VPN to activate` | `_start_timeout_cb` |
| `starting: failure to start VPN service: <error>` | `_name_owner_changed` |

A normally finished VPN still writes nothing. So logd now reads NetworkManager's active connections over the system
bus at every request (`ActiveConnections`, each `Vpn`, `State` != deactivated, `Uuid`; strict: any property error or
more than 256 connections means no reading) between two clock readings, and records a reading that says something
new (first since NM's start, another set, or an activation since the newest recorded one began) in its own journal:
`<5>linvpn-logd-vpns-v1 <before µs> <after µs> <uuid,…|->` on stderr (priority notice, so a third fixed query
`SYSLOG_IDENTIFIER=linvpn-logd PRIORITY=5` gets only readings, the newest 2000), trusted only with
`_SYSTEMD_UNIT=linvpn-logd@….service`. The engine sends logd one request right before each activation
(`logd_client::mark`, at most 3 s), so earlier connections that are gone are recorded as gone before the new one's
first plugin line. Per connection, sessions are rebuilt from the lines and the readings:

- `starting <plugin>` opens a session; an end line closes it, unless a later reading still lists the connection with
  no activation line in between (the end is void: a plugin's `Failure` that did not end it);
- a reading that does not list the connection closes its session at the reading's end, if the session is known to
  have existed before the reading began (its activation line, or the reading that saw it, is older); one that
  began before the activation line cannot end it (the connection may have started during the reading);
- a reading that lists a connection with no open session opens one back to its last known inactive moment (NM's
  start, an end, a reading without it): its activation line was lost (journald's rate limit), formerly a residual;
- anything else stays active, so without readings the old fail-closed behaviour holds.

The M1 attack stays closed: B's tunnel is either listed by every reading during A's window (active) or, if no
reading happened, active from its activation line on until the first reading without it, which is after the
window. A can ask as often as it likes; a reading can only end B after B really is gone.

Residual risk (documented in `docs/architecture.md`): (1) plugin lines journald stamps after NM already dropped a
connection (a dying pppd's last lines, journald's receipt delay) can reach a caller whose connection is the only one
active then, as before with the debug-level end lines; (2) a plugin that reports `Failure` but keeps its connection
up, and ends it before any reading, would have the lines in between attributed the same way (no plugin does this;
NM itself treats the failure as the reason of the coming stop); (3) the readings' clock is the system's realtime
clock, as journald's (a clock step backwards between a reading and later lines could misplace them; only root can
step it). A stopped logd, a bus failure, a cut or lost reading only withhold more.

### Journal pump: lines after the first answer (branch lb-logd)

The run-2 finding "only OpenVPN's first lines reach the log" was logd's cursor handling: the pump's second and
later queries carry `--after-cursor` and logd also passed `--since`, which journalctl 259 refuses ("Please specify
only one of --since=, --cursor=, --cursor-file=, and --after-cursor="), so every follow-up query failed and the pump
retried the same cursor forever. With a cursor logd now passes only `--after-cursor` (the time bound stays in
`select`); `-n` then counts from the cursor (checked on the VM). Test: the real journalctl accepts a follow-up
query with a real cursor (`crates/helper/tests/logd.rs`).

### L1: the agent's binding

Each expectation is bound to the settings object path: `AddAndActivateConnection2`'s first result (the run), the
system profile's path (a system VPN), the adopted run's own volatile profile. A `GetSecrets` must name that path, its
settings must keep `connection.permissions == ["user:<self>"]` (also NM's `user:<self>:` form) for LinVPN's runs and
the planned `vpn.service-type`. The engine still announces before the add (NM may ask right after it returns); a
request that comes before the path is bound waits for it (at most 10 s), which makes the reconnect path's order safe:
the old profile's request never matches the new path. A run's expectation is dropped as soon as NM reports it Failed
or Disconnected (and, as before, when the run goes).

### L2: decisions

- The specific error replaces the misleading "not authorized" one (NM refuses `GetConnectionByUuid` of a profile
  hidden from the user with `PermissionDenied`, which used to surface as a polkit refusal). Such a profile is never
  deleted.
- **No per-user salt** in the UUID derivation. linvpn-logd and linvpn-xfrmd prove ownership by deriving the UUID
  from `SO_PEERCRED` and the connection id; a salt only the user knows would have to be sent by the caller (a
  caller-chosen UUID: no proof left) or stored somewhere the root services read (new state to secure), and it would
  change every existing connection's UUID (re-adoption of running tunnels, upgrades). A squatter can only deny the
  connect (now explained) and expose its own lines.
- **logd's NM and `linvpn-ovpn-<UUID>` lines are not gated on "an activation by the caller"**: an activation line
  cannot be tied to a uid without NM's `audit:` lines, whose exact 1.54 form could not be checked here (the VM's
  journal is not readable as `linvpn-dev`), and gating on a format guess could silence every user's log. A squatted
  UUID's lines are the squatter's own. Plugin lines do require the caller's own activation (M1).

### I6: OpenVPN verb 4 — decision: keep the cap at 4

OpenVPN 2.7 (release/2.7, v2.7.8; unchanged since 2.4): the pushed `auth-token` value is removed from the `PUSH:
Received control message` line unless `--verb` ≥ 7 (`misc.c`, `sanitize_control_message`, `D_SHOW_KEYS`); that line
is `D_PUSH`, verb 3. `auth-token-user` (the base64 user name) is not redacted, from verb 3 on (the user name is not a
secret in LinVPN). What verb 4 adds is the start-up options dump (`D_SHOW_PARMS`): it prints file paths for
`auth-user-pass` and keys, but `auth_file_up` (the `--http-proxy` credentials argument) and `--http-proxy-option`
custom headers in clear. Under LinVPN neither reaches OpenVPN: an inline `<http-proxy-user-pass>` becomes NM's
`http-proxy-username` plus an agent secret, which nm-openvpn-service answers over the management interface (its
`--http-proxy` gets no credentials), and `http-proxy-option` is a directive NetworkManager drops (the validator's
RISKY "Ignored by NetworkManager on Linux"). The management interface gets the raw token, but that is
nm-openvpn-service's own socket. So `linvpn-verb` stays capped at 4.

### Extra: an adopted run's log masking

A run adopted from an earlier process started its journal pump with an empty masker. Now `HelperClient` has
`wants_log_secrets` / `set_log_secrets` (default: nothing); the Linux engine marks adopted runs, and app-core's
refresh hands such a run its connection's secrets once the vault is open (never while it is locked). The pump's
masker is shared, so later lines are masked from then on; lines written before the vault was unlocked are not
rewritten.

### Needs a live system

- M1: NetworkManager 1.54.3's real VPN messages (`starting <plugin>`, `set state: …`, `dbus: state changed: stopped
  (6)`), `NM_LOG_DOMAINS=VPN` and `CODE_FUNC=main` on the start line, the history query's speed on a large journal;
  a two-user run (B's IKEv2 tunnel up, A connects twice: A's log shows A's plugin lines only when B is down, the
  "withheld" note otherwise).
- I2: linvpn-logd with `ProtectProc=invisible`, `ProcSubset=pid`, `MemoryMax=384M`, `TasksMax=16` still runs
  journalctl (installed .deb, a real request); linvpn-xfrmd within `MemoryMax=64M`, `TasksMax=4`.
- L1: a real NM's `GetSecrets` path and settings for LinVPN's runs, system L2TP/Cisco VPNs and an adopted run;
  CRV1 through the bound expectation; a reconnect.
- L2: NM's real error for a duplicate UUID and `GetConnectionByUuid`'s `PermissionDenied` for another user's
  private profile (two local users).
- I3: an IKEv2 tunnel's counters with the system's charon running a tunnel too.
- I5: a real PackageKit install still finishes (and a stuck one is cancelled).
- Extra: an adopted OpenVPN run's log masks the password after the unlock.

## Lab end to end (L-b Tasks 26–28, branch lb-lab)

The VPN lab ran in Docker on the Linux test VM itself (not on the Mac): the server address is a host bridge address
DNAT'd to the containers, the IKE standard ports moved off (the VM's own strongSwan), and the lab's services network is
reachable only through a tunnel. The client profiles were the lab's `client/linux` folder; the credentials came from
its `l2tp.txt` / `cisco-ipsec.txt` sheets, read by the test process only. System: Ubuntu 26.04, NetworkManager 1.54.3,
network-manager-openvpn 1.12.5 (+ LinVPN's service), -strongswan 1.6.4 (strongSwan 6.0.4), -l2tp 1.52.0,
-vpnc 1.4.0 (vpnc 0.5.3), -sstp 1.3.2, OpenVPN 2.7. The tests are `crates/platform-linux/tests/lab_e2e.rs` (the real
`Engine` on the system bus, one per process as in the app, run with `scripts/lin-remote.sh desktop`; every case
checks that no lab secret reached the connection log or linvpn-logd's answer). Run 1: develop db699aa + lb-lab, the
installed 2.0.7 `.deb` (built before the fixes below).

### Bugs found and fixed (lb-lab)

| Bug | Fix commit | Test |
|---|---|---|
| LinVPN's NM OpenVPN service was configured without `--localstatedir`: run dir `/usr/var/run/NetworkManager` and chroot `/usr/var/lib/openvpn/chroot` on the read-only `/usr`. **Every OpenVPN connect failed** ("Cannot create run-dir … read-only file system") | `fix(linux): LinVPN's NM OpenVPN service uses /var/run/NetworkManager, not /usr/var` | `scripts/test-build-nm-linvpn-openvpn.sh` (flags; a real build has no `/usr/var` path) |
| linvpn-xfrmd refused every IKEv2 connection: charon-nm installs the virtual IP on `lo`, NM 1.54 shows it on its `loopback` active connection too, and the "no other holder" rule took that for a second holder → no IKEv2 traffic or liveness | `fix(linux): linvpn-xfrmd counts an IKEv2 connection whose virtual IP NM also shows on lo` | `crates/core/tests/xfrmd.rs` |
| sstpc's "Verification of server certificate failed" was classified Unknown (a reconnect was tried, no plain reason) | `fix(app): an SSTP server certificate sstpc refuses is a certificate problem` | `crates/app-core/tests/failure_reason.rs` |
| A refused password (or one-time code) looped: the agent re-sent the stored secrets each time NM asked again, until NM's 60 s timeout → "server could not be reached" and a reconnect | `fix(linux): a refused password fails at once instead of looping until NM's timeout` (fix 5) | `nm_agent.rs`, `nm_engine.rs`; live: wrong password / static / appended / CRV1 code → `AuthFailed` in 16–19 s |
| The engine tests' logs read the host's real linvpn-logd (failing while a lab VPN was up) | `test(linux): the engine tests' logs never read the host's linvpn-logd` | `nm_engine`, `nm_native`, `nm_system_vpns` |
| A WireGuard tunnel taken down outside LinVPN (`nmcli connection down`, GNOME's menu) was logged as a plain drop, so app-core would reconnect it (WireGuard has no VPN state reason) | `fix(linux): a WireGuard tunnel stopped outside LinVPN is the user's stop, not a drop` | `nm_engine.rs`, `nm_client.rs`; live: `lab_external_disconnect` (WireGuard) passes |

### Run 2: the lb-lab `.deb` (develop 8e6754d with lb-sec, plus the fixes above), 2026-10-30

| Case | Result | What was seen |
|---|---|---|
| `lab_openvpn_tun` (dco, cbc; plain user; Server decides) | pass | LinVPN's service (`…linvpn-openvpn`), interface `lvo…`, connected in < 1 s; the lab through the tunnel, 1.1.1.1 not; counters liveness and traffic grow with the page |
| `lab_openvpn_pushed_full_tunnel` (`labfull`, Server decides) | pass | 1.1.1.1 goes through `lvo…`: the pushed `redirect-gateway def1` reaches NM through the patched helper (decision 8 proven live) |
| `lab_openvpn_never_ignores_the_push` (`labfull`, Never) | pass | `pull-filter ignore "redirect-gateway"`: 1.1.1.1 stays on the LAN |
| `lab_openvpn_key_without_password` | pass | `cert-pass-flags = 4` (not required): no key password asked, connects |
| `lab_openvpn_wrong_password` | pass (after fix 5) | before: the agent re-sent the refused password each time NM-openvpn asked again, until NM's 60 s timeout → "server could not be reached", reconnected. Now: failed after 19 s, `AUTH_FAILED: no secrets were given (NetworkManager)` → `AuthFailed`, not retried |
| MFA 1: `lab_openvpn_static_challenge` (SCRV1) | pass | the code packed as `SCRV1:…` by app-core's `apply_static_challenge`, answered by the agent: connected in 0.4 s, no dynamic challenge. A wrong code: failed after 19 s as `AuthFailed`, no retry (fix 5) |
| MFA 2: `lab_openvpn_crv1` | pass | the dynamic challenge reaches LinVPN's agent for the new service type 2.3 s after the start (`AuthStateReader`: method crv1, the server's text, echo on, deadline 110 s); `respond`: connected 0.3 s later (also when answered after 105 s), state `Done`. A wrong code: failed after 16 s as `AuthFailed`, no new challenge, no retry (fix 5) |
| MFA 3: `lab_openvpn_append_code` (`,` `""` `:`) | pass | app-core's `apply_code` with each separator: connected, no challenge. A wrong appended code: failed after 19 s as `AuthFailed`, no retry (fix 5) |
| MFA: a stored TOTP secret generating the code | n/a | the app has no TOTP generator (codes are typed); the lab's code is a fixed number |
| `lab_wireguard` | pass | `lvw…`, keepalive 25, counters |
| `lab_external_disconnect` (WireGuard, OpenVPN) | pass | `nmcli connection down` → "disconnected by the user" → `StoppedByUser`, no reconnect (WireGuard after fix 4) |
| `lab_ikev2_psk`, `lab_ikev2_cert` (folder, imported PEM, imported PKCS#12; wrong p12 password refused before NM) | pass (connect) / **fail** (traffic) | connects in < 1 s. linvpn-xfrmd still answers `N` with lb-sec's I3 matching (traffic and liveness `None`). charon-nm 6.0.4 makes an XFRM interface `nm-xfrm-<n>` per connection whose sysfs counters grow with the traffic (436/411 bytes per page): the source lb-fix2 switches to |
| `lab_ikev2_eap` | blocked (package) | charon-nm has no eap-identity plugin ("EAP_IDENTITY not supported, sending EAP_NAK"); the lab server asks for the EAP identity. `libcharon-extra-plugins` is added to the IKEv2 packages on lb-fix2 |
| `lab_sstp` (ca, ca-alt-port, no-verification; system-ca) | pass | connects in < 1 s; split PPP: only the peer is routed (the services network is not), the gateway's page answers via sstp — the class-based route comes with lb-fix2; system-ca fails with sstpc's certificate error (now "A certificate was not accepted.") |
| `lab_l2tp` | **fail (lab config)** | charon (Main Mode PSK) refuses the server: `IDir '<server container address>' does not match to '<gateway address>'`: on this VM the lab is reached through a DNAT, so the server identifies with its container address. Not a LinVPN bug (recorded; a lab with published ports on another host, or the server's `leftid` set to its public address, avoids it) |
| `lab_cisco` | **fail (lab interop)** | IKEv1 Aggressive Mode and XAuth succeed; vpnc 0.5.3 then rejects the lab strongSwan's mode-config reply (two `UNITY_SPLIT_INCLUDE` attributes): "configuration response rejected: (ISAKMP_N_PAYLOAD_MALFORMED)". A vpnc/strongSwan-unity interop limit of the lab server, not a LinVPN bug (recorded) |
| `lab_dns_split_and_full` | pass | split: the tunnel link has `-DefaultRoute`, DNS domain `lab.test`, `whoami.lab.test` answers through it, example.com through the LAN; full (`labfull`): `+DefaultRoute` |
| `lab_liveness_dead_peer` (WireGuard, container stopped) | pass | rx stopped, tx grew; `Dead` 215 s after the stop (`COUNTER_SILENCE` 200 s + one poll) |
| `lab_openvpn_server_restart` (container restarted) | pass | NM's VPN state stayed activated throughout (`Liveness::OpenVpn { reconnecting_since }` never fired): OpenVPN restarted itself after its ping timeout and carried traffic again after 60 s. **For Task 29: the counter rule alone carries OpenVPN** |
| `lab_system_vpn` (the user's own NM WireGuard profile, in memory, `permissions = user:<me>`) | pass | listed read-only as `WireGuard (app)`, started and stopped through `NativeController`, traffic shown, never deleted by LinVPN (the test removed it). `NativeController::address` is `None` for it |
| `lab_logd_lines` (SSTP) | **fail** | linvpn-logd returns only NM's start line and `withheld`: every plugin line is withheld as "another VPN was active". NM 1.54.3 at its default log level writes no end line for a VPN (no `set state: …`, no `dbus: state changed: stopped (6)`; a failure writes only `dbus: failure: …`), so M1's history keeps every earlier connection active forever. Also OpenVPN's own lines after its privilege drop and chroot do not reach the log. Diagnosis needs the journal (maintainer) |
| no secret in any log or logd answer | pass | every case |

Minor: caps are cached 60 s, so a CA copied into the swanctl folder counts only up to a minute later (seen when a test
copied one right after another case had read the folder).

### Open after run 2

- **Fixed on lb-logd (see "M1 reworked after lab run 2"); needs the lab rerun.** **linvpn-logd withholds every
  plugin line (security review M1's history, a LinVPN bug):** NetworkManager 1.54.3 at its
  default log level writes no end line for a VPN (no `set state: …`, no `dbus: state changed: stopped (6)`; a failure
  writes only `dbus: failure: …` / `failed to connect: …`), so the history keeps every earlier VPN connection active and
  each later connection's plugin lines are withheld ("another VPN was active"). Effect: the Log tab of SSTP, L2TP,
  Cisco and IKEv2 has no plugin lines, and a plugin's own failure text (e.g. sstpc's certificate error) does not reach
  `failure_reason` (`sstp-system-ca` is classified Unknown again). Needs a design decision (e.g. logd asking NM over
  D-Bus which VPNs are active now, or treating `dbus: failure` / `failed to connect` and a later activation of the same
  device as ends).
- **Fixed on lb-logd (journalctl refused `--since` with `--after-cursor`); needs the lab rerun.** **OpenVPN's own
  lines:** only OpenVPN's first lines (before it drops privileges and chroots) reach the log; whether
  the later ones are missing from the journal or filtered by logd needs the journal (maintainer).
- IKEv2 traffic and liveness: linvpn-xfrmd answered `N` also with lb-sec's I3 matching; lb-fix2 reads charon-nm's
  `nm-xfrm-*` sysfs counters instead (to be confirmed live on its `.deb`).
- Deferred to the manual checklist (release speed): CRV1 answered after 60 s (105 s passed), the alternative SSTP port
  (passed in run 1), cosmetic log lines.

### Run 3: the lb-lab `.deb` with lb-fix2 (0b24171), after the maintainer's checkpoint

- **CP-engines / CP-screen** (maintainer): SSTP removed and installed again through System Status' **Install**; the
  real app's OpenVPN, WireGuard, SSTP and IKEv2 EAP connections, the CRV1 code window, a wrong code, the network
  off/on and the supervisor: "everything was fine".
- **Second LinVPN agent** (lb-fix2): with the installed LinVPN running, the test's engine is refused with "Another
  LinVPN (or a LinVPN test) is already registered with NetworkManager for this user. Quit it and try again." — pass
  (it was "NetworkManager is not running.").
- **IKEv2 EAP-Identity:** after the IKEv2 row's Install, `libcharon-extra-plugins` is still **not installed**
  (`dpkg -s`: not installed; no `libstrongswan-eap-identity.so`). Open: whether the row offered the package or the
  install failed; EAP against the lab stays blocked until the package is there.
- **OpenVPN's own lines (journal dump of run 2):** the journal has all of OpenVPN's lines under
  `linvpn-ovpn-<NM UUID>` with `_COMM=openvpn`, as root (`_UID=0`) before and as `nm-openvpn` after the privilege drop
  (`Peer Connection Initiated`, `Initialization Sequence Completed`, `AUTH: Received control message: AUTH_FAILED`,
  …). LinVPN's log got only the first five lines of each run. So the lines are not missing from the journal and the
  sender rule holds: they are lost between linvpn-logd's answers and the journal pump (the continuation after the
  first answer). Recorded for lb-logd; not fixed here.
- Not run (LinVPN was running again after the CP-screen, and the tests' engine cannot register beside it): the
  `nm-xfrm` counters versus the page bytes, the SSTP class-based route, the address log line.

### Run 3b: the lb-fix2 live checks (LinVPN quit)

| Check | Result | What was seen |
|---|---|---|
| IKEv2 traffic and liveness from charon-nm's `nm-xfrm-*` sysfs counters (`lab_ikev2_psk`) | pass | traffic `(0, 0)` → `(872, 822)` with the first page; 20 pages of 1420 body bytes: rx +8720, tx +8220 (about 436 bytes per request and answer with the IP and TCP overhead); liveness `Counters` |
| The address log line (`lab_wireguard`, `lab_ikev2_psk`) | pass | "Connected, IPv4 10.99.x.x" (was "Connected, IPv4 -") |
| SSTP class-based route (`lab_sstp_classful_route`) | pass (skip rule) | `/usr/lib/NetworkManager/dispatcher.d/90-linvpn-route` is root:root 0755. This VM's LAN and default gateway are inside 10.0.0.0/8, the class network of the lab's 10.99.x.x addresses, so the script correctly adds no class route (it keeps the default gateway reachable); the peer route and NM's server route are there; nothing is left after the disconnect; none with `route_all=yes`. The positive case (class route on pppN, metric 50) needs a LAN outside the class network: manual checklist |
| System Status' IKEv2 row on this machine (`desktop_nm_plugins_on_this_system`) | pass | `eap_identity: false` → the row says "EAP needs libcharon-extra-plugins", action `install`, packages `libcharon-extra-plugins`: the row does offer the package. The maintainer's Install did not install it (still not installed): the PackageKit side or the click is to be checked by hand; IKEv2 EAP stays blocked here |
