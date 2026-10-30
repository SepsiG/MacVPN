# Spike L0-1: NetworkManager's OpenVPN plugin versus our OpenVPN profiles

**Date:** 2026-10-29
**Spec:** [LinVPN design](../specs/2026-10-29-linvpn-design.md), sections 2 (decision 3), 4 and 5 (L0-1).
**System:** Ubuntu 26.04.1 VM (x86_64), NetworkManager 1.54.3, `network-manager-openvpn` 1.12.5-1, OpenVPN 2.7.0.
User `linvpn-dev` (not an admin). All commands ran as that user. Nothing was installed, and no VPN was activated.
**Source read:** GNOME `NetworkManager-openvpn`, tag `1.12.5`: `properties/import-export.c` (the importer),
`src/nm-openvpn-service.c` (builds OpenVPN's command line and handles the management socket),
`src/nm-openvpn-service-openvpn-helper.c` (the `--up` helper that hands IP, routes and DNS to NM) and
`shared/nm-service-defines.h`.

## Verdict

**Option A works: run OpenVPN through NetworkManager.** The gap is small. Most of it can be expressed if
LinVPN's `nm_plan` writes the NM settings itself instead of using NM's importer. One behaviour differs by design
(see the note below the numbers).

The 19 OpenVPN fixtures are: 4 lab profiles, 6 MikroTik, 2 OPNsense, 4 pfSense (one of them from `pfsense/archive`),
2 UniFi, and the 1.4.0 compatibility export.

| Path | Same behaviour | Changed without warning | Refused |
|---|---|---|---|
| NM's own importer (`nmcli connection import` / the plugin's `import`) | 13 | 4 | 2 |
| LinVPN `nm_plan` (vpn.data + ipv4/ipv6 settings + secret agent) | **17 of the 18 real profiles** (3 of them depend on L0-4) | 1 (wiki-extras: one `net_gateway` route) | 0 (the CA-less 1.4.0 stub fails as OpenVPN itself would) |

- **Changed without warning by the importer (4):**
  - 3 profiles use `static-challenge` (lab, OPNsense file-only, pfSense connect-tls-crypt). The importer drops it.
  - OPNsense tls-crypt-v2 has `pull-filter ignore "redirect-gateway"`. The importer drops it, so this **split
    tunnel becomes a full tunnel**.
- **Refused by the importer (2):**
  - `compat-1.4.0/export-openvpn.ovpn` has no CA.
  - `routeros-wiki-extras.ovpn` has `route … vpn_gateway`.
- **What `nm_plan` can do that the importer cannot:**
  - It maps `pull-filter ignore "redirect-gateway"` to `ipv4.never-default=yes`.
  - It maps `route … vpn_gateway` to an `ipv4.routes` entry without a next hop.
  - It maps `ncp-ciphers` to `data-ciphers`.
  - It sends the static-challenge answer through the secret agent (see "MFA" below).
  - The only thing left in the 18 real profiles is wiki-extras' `route 203.0.113.0 255.255.255.0 net_gateway`.
    This route bypasses the tunnel, and NM has no way to express it.

**The one behaviour that differs from macOS: NM ignores a pushed `redirect-gateway`.** The `--up` helper never
reads it. The source has no `redirect` or `NEVER_DEFAULT` anywhere in `src/`. So `ipv4.never-default` in the
connection alone decides full or split tunnel, and NM's default is a full tunnel.
- 6 of the 19 profiles state full or split themselves (`redirect-gateway`, `route-nopull` or `pull-filter`).
- **13 leave it to the server.** On Linux those need a per-connection decision.
- The VPN lab is one of them. Its server pushes only `route 10.99.10.0/24` and DNS. Under NM's default, the lab
  profiles would route everything into the tunnel and lose the internet.

**Proposal for the maintainer:** give OpenVPN connections on Linux a "Send all traffic over VPN" switch (LinVPN
already has `send_all_traffic` for the native kinds).
- When the profile says it: `redirect-gateway` means on; `route-nopull` or `pull-filter ignore "redirect-gateway"`
  means off.
- When the profile is silent, the default is on. That is the NM and GNOME behaviour, and nothing leaks.
- When the server pushes its own routes, show a hint after the first connect.

Option B (our own root helper running `openvpn`) would get server-decided routing back. But it reintroduces the root
VPN helper, our own DNS handling through resolved, and our own route handling: everything decision 3 removed. One
bit of configuration does not justify that.

## Method

1. **Fixtures**, staged on the VM in `~/l0-a/spike1/fx`:
   - every `*.ovpn` under `Tests/Fixtures` (MikroTik, OPNsense, pfSense including `archive/` with its `tls.key`,
     UniFi);
   - `crates/app-core/tests/fixtures/compat-1.4.0/export-openvpn.ovpn`;
   - the lab profiles from `scripts/vpn-lab/profiles.sh --host lab.example.test --bind 192.0.2.10` (`LAB_STATE` in a
     scratch directory, no Docker): `openvpn-tun-dco`, `-tun-cbc`, `-static-challenge`, `-tap-l2`.
2. **Probes:** 45 single-directive profiles ([probes.sh](2026-10-29-linvpn-l0-a/probes.sh)). Each is the lab's
   `openvpn-tun-dco.ovpn` plus one directive, so an import diff against the base shows exactly what NM does with
   that directive.
3. **Import offline** with the plugin's own parser: [offline_import.py](2026-10-29-linvpn-l0-a/offline_import.py)
   calls `NM.VpnPluginInfo` → `load_editor_plugin()` → `import_(path)` through python3-gi.
   - It talks to no NM daemon, so it needs no polkit. Inline blobs went to a scratch `$XDG_DATA_HOME`, deleted
     afterwards.
   - It is the same code `nmcli connection import` runs before it calls `AddConnection`.

   ```
   ssh $LINVPN_SSH 'cd ~/l0-a/spike1 && XDG_DATA_HOME=$PWD/xdg LC_ALL=C python3 -I offline_import.py fx/*.ovpn probe/*.ovpn > offline.log'
   ```
4. **Read the NM-openvpn 1.12.5 source** for what the service accepts and passes to `openvpn`.

### Do not use `nmcli connection import`, not even with `--temporary`

The first attempt ran `nmcli connection import --temporary type openvpn file X` in a loop, inside the user's systemd
manager (`systemd-run --user`). Each import adds the connection **without `connection.permissions`**. That makes it
a system-wide connection, which needs `org.freedesktop.NetworkManager.settings.modify.system`, and for a non-admin
user that is **auth_admin**. So the desktop showed "Authentication required … modification of network settings for
all users" (admin password) once per import. The maintainer cancelled them. The loop was stopped, and nothing was
added:
```
=== fx/lab_openvpn-tap-l2.ovpn
out: Error: Failed to add 'lab_openvpn-tap-l2' connection: Timeout was reached
=== fx/lab_openvpn-tun-cbc.ovpn
out: Error: Failed to add 'lab_openvpn-tun-cbc' connection: Insufficient privileges
```
Even so, the importer had already written the inline blobs to `~/.local/share/networkmanagement/certificates/nm-openvpn/`
(files 0600, directory 0755). They were deleted. **LinVPN must never use `nmcli connection import`.** It adds
connections itself through `AddAndActivateConnection2` with `connection.permissions = user:<name>` (see the
WireGuard spike for the polkit table).

## What NM keeps, drops and refuses

### Importer: refused (the whole file fails)

| Input | Message |
|---|---|
| no `<ca>` / `ca` (and no `pkcs12`) | `The file to import wasn’t a valid OpenVPN configuration (missing --ca)` |
| `route N M vpn_gateway` / `net_gateway` (any non-IP gateway word) | `configuration error: unsupported 3th argument vpn_gateway to “route” (line 34)` |
| `<auth-user-pass>`, `<connection>`, `<peer-fingerprint>`, `<http-proxy-user-pass>`, `<verify-hash>`, `<dh>` | `configuration error: unsupported blob/xml element (line 11)` |
| `compress stub` / `stub-v2` / `migrate` | `configuration error: unsupported compress argument (line 11)` |

### Importer: kept (directive → `vpn.data` key)

These go into `vpn.data`. `route` goes into `ipv4.routes`.
- **Mode and type:** `client`/`tls-client` (required) → `connection-type`, which is `tls`, `password`,
  `password-tls` or `static-key`, depending on `auth-user-pass` and the certificates.
- **Transport:** `remote` (all of them, joined as `host:port:proto, …`), `proto` (→ `proto-tcp`), `port`/`rport`,
  `dev`, `dev-type`, `tun-ipv6`, `float`, `remote-random`, `remote-random-hostname`, `connect-timeout`,
  `server-poll-timeout`.
- **Crypto:** `ca`, `cert`, `key`, `pkcs12`, `extra-certs`, `crl-verify`, `tls-auth` + `key-direction` (→ `ta`,
  `ta-dir`), `tls-crypt`, `tls-crypt-v2`, `secret`, `auth`, `cipher`, `data-ciphers`, `data-ciphers-fallback`,
  `keysize`, `tls-cipher`, `tls-version-min` (with `or-highest`), `tls-version-max`, `remote-cert-tls`,
  `ns-cert-type`, `verify-x509-name`, `tls-remote`, `reneg-sec`.
- **Link:** `tun-mtu` (→ `tunnel-mtu`), `fragment`, `mssfix`, `mtu-disc`, `keepalive` (→ `ping` + `ping-restart`),
  `ping`, `ping-exit`, `ping-restart`, `max-routes`.
- **Compression:** `comp-lzo` (bare = `adaptive`), `compress` `lzo`/`lz4`/`lz4-v2`, `allow-compression`.
- **Proxies:** `http-proxy`/`socks-proxy` (+ `*-retry`; the user name and password from an auth file go to
  `http-proxy-username` and the `http-proxy-password` secret).
- **Other:** `allow-pull-fqdn`, `push-peer-info`, `ifconfig` (static-key mode).
- **`route`** with an IPv4 gateway or none → `ipv4.routes`. `route 0.0.0.0 0.0.0.0` only sets
  `never-default=false`, which is already the default.
- **Inline blobs** become files under `$XDG_DATA_HOME/networkmanagement/certificates/nm-openvpn/<name>-<tag>.pem`.

Probe evidence. Each line is what the probe added over the base import:
```
keepalive          data: ping = 10, ping-restart = 60
tun-mtu            data: tunnel-mtu = 1400, mssfix = 1360
tls-version-min    data: tls-version-min = 1.2, tls-version-min-or-highest = yes
verify-x509        data: verify-x509-name = name:server
compress-lz4v2     data: compress = lz4-v2
comp-lzo           data: comp-lzo = yes
allow-compression  data: allow-compression = asym
data-ciphers       data: data-ciphers = AES-256-GCM:CHACHA20-POLY1305, data-ciphers-fallback = AES-256-CBC
http-proxy         data: proxy-type = http, proxy-server = proxy.example.test, proxy-port = 3128
tls-auth-file      data: ta = …/probe/ta.key, ta-dir = 1
route-plain        ipv4: routes=['10.99.20.0/24 via None metric -1']
```

### Importer: dropped without warning

The importer skips every other directive: `/* TODO: currently we ignore any unknown options and skip over them. */`
(`import-export.c`). The probes confirmed it. These directives produced **no change** over the base import:

`route-nopull`, `pull-filter`, `static-challenge`, `script-security`, `up`, `down`, `management`, `verb`,
`auth-retry`, `auth-nocache`, `resolv-retry`, `dhcp-option`, `dns` (2.6+ form), `block-outside-dns`,
`redirect-gateway` (all flag forms), `route-ipv6`, `ifconfig-ipv6`, `topology`, `tls-groups`, `remote-cert-eku`,
`peer-fingerprint` (argument form), `explicit-exit-notify`, `setenv`, `ignore-unknown-option`, `pkcs11-id`,
`auth-user-pass <file>`.

The fixtures also showed these dropped: `ncp-ciphers` (the old name of `data-ciphers`), `askpass`, `connect-retry`,
`route-delay`, `route-method`, `mute`, `ping-timer-rem`, `lport`.

### Service: the hard limit

`nm-openvpn-service` accepts only the `vpn.data` keys in `valid_properties[]`. Any other key fails the connection
with `property “%s” invalid or not supported`. So even `nm_plan` cannot pass a directive NM has no key for.

The service always adds these itself:
- `--client` (TLS modes), `--nobind`, `--auth-nocache`, `--persist-key`, `--persist-tun`;
- `--explicit-exit-notify` (UDP), `--reneg-sec 0` (when not set);
- `--script-security 2`, `--up <nm helper>`, `--up-restart`;
- `--management <socket> unix`, `--management-query-passwords`, `--auth-retry interact`;
- `--route-noexec`, `--ifconfig-noexec` (NM applies addresses, routes and DNS);
- `--user nm-openvpn`, `--group nm-openvpn`, `--chroot /var/lib/openvpn/chroot`;
- `--verb` from NM's log level (default 1);
- `--syslog nm-openvpn`.

The `--up` helper hands NM these values from OpenVPN's environment:
- `ifconfig_*`, `route_network_*`, `route_ipv6_*`, `tun_mtu`, `trusted_ip(6)`;
- from `foreign_option_*`, only `dhcp-option DNS`, `WINS`, `DOMAIN`, `DOMAIN-SEARCH`.

It never reads anything about `redirect-gateway` (see the verdict). Whether OpenVPN 2.7 also exports pushed
`dns …` options as `foreign_option_*` for this helper was **not verified**. It needs a live test with a server
that pushes `dns`.

**Private connections** (`permissions = user:X`): `access_file()` copies every certificate or key file "as the
user" (`nm_utils_copy_cert_as_user`) to a root-only temp file before `openvpn` starts. So the spec's plan works:
files in `$XDG_RUNTIME_DIR/linvpn/<id>/` (0700/0600, owned by the user).

## Proposed Linux tier

Our tier list has SAFE, RISKY, FORBIDDEN and the platform table, as `TargetOs::Linux`. The proposal changes it as
follows. It starts from the SAFE table (158 names in `ARGUMENT_SPECS`) plus the ones only `nm_plan` can express.

**Legend:**
- **NM:** an NM key exists.
- **plan:** `nm_plan` re-expresses it through `ipv4.*`/`ipv6.*` or LinVPN itself.
- **implicit:** the service already does it.
- **no-op:** no effect on Linux.
- **lost:** nothing can express it.

| Directive(s) | NM import | NM can express | Linux decision |
|---|---|---|---|
| `client`, `tls-client`, `pull` | yes | implicit | SAFE |
| `remote` (several), `proto`, `port`, `rport`, `float`, `remote-random(-hostname)`, `connect-timeout`, `server-poll-timeout` | yes | NM | SAFE |
| `<connection>` blocks | refuses | plan: only `remote`/`proto`/`port`/`nobind` flatten into the `remote` list | SAFE when flattenable, otherwise **Not supported on Linux** |
| `nobind`, `lport 0`, `persist-key`, `persist-tun`, `auth-nocache`, `explicit-exit-notify`, `auth-retry`, `resolv-retry` | dropped | implicit / OpenVPN default | SAFE (`nm_plan` drops them) |
| `dev`, `dev-type`, `tun-ipv6` | yes | NM | SAFE |
| `ca`, `cert`, `key`, `pkcs12`, `extra-certs`, `crl-verify`, `tls-auth`, `key-direction`, `tls-crypt`, `tls-crypt-v2`, `secret` | yes | NM (files in `$XDG_RUNTIME_DIR`) | SAFE |
| `auth`, `cipher`, `data-ciphers`, `data-ciphers-fallback`, `tls-cipher`, `tls-version-min/max`, `keysize`, `reneg-sec` | yes | NM | SAFE (`nm_plan` sets `reneg-seconds` explicitly; NM's default is 0, not 3600) |
| `ncp-ciphers`, `ncp-disable` | dropped | plan → `data-ciphers` / `ncp-disable` key | SAFE |
| `remote-cert-tls`, `ns-cert-type`, `verify-x509-name` | yes | NM | SAFE |
| `peer-fingerprint`, `verify-hash`, `remote-cert-ku`, `remote-cert-eku` | dropped / refused | **lost** | **Not supported on Linux**: dropping a server check would quietly weaken authentication |
| `tls-groups`, `ecdh-curve`, `tls-ciphersuites`, `tls-cert-profile`, `x509-track`, `x509-username-field` | dropped | lost | RISKY, "ignored on Linux: OpenVPN's default applies" |
| `auth-user-pass` (bare, file, inline block) | bare yes; file dropped; block refuses | agent: user name in `username`, password from the vault | SAFE |
| `askpass`, `<http-proxy-user-pass>` | dropped / refuses | agent (`cert-pass`, `http-proxy-password`) | SAFE |
| `static-challenge` | dropped | agent: answered as the password (see "MFA") | SAFE, depends on L0-4 |
| `auth-token`, `auth-token-user` | dropped | lost (normally pushed) | RISKY (ignored) |
| `comp-lzo`, `compress lzo/lz4/lz4-v2`, `allow-compression` | yes | NM | SAFE |
| `compress stub/stub-v2/migrate`, `comp-noadapt` | refuses / dropped | lost | RISKY (ignored); compression framing then comes only from the server's push |
| `tun-mtu`, `fragment`, `mssfix`, `mtu-disc`, `keepalive`, `ping*`, `max-routes` | yes | NM | SAFE |
| `link-mtu`, `udp-mtu`, `tun-mtu-extra`, `tun-mtu-max`, `max-packet-size`, `mtu-test`, `sndbuf`, `rcvbuf`, `txqueuelen`, `fast-io`, `tcp-nodelay`, `socket-flags`, `mark`, `bind`, `bind-dev`, `local`, `lport N`, `passtos`, `nice`, `mlock`, `shaper`, `replay-window`, `hand-window`, `tran-window`, `tls-timeout`, `reneg-bytes`, `reneg-pkts`, `inactive`, `session-timeout`, `connect-retry(-max)`, `proto-force`, `persist-local-ip`, `persist-remote-ip`, `multihome`, `preresolve`, `remap-usr1`, `up-delay`, `tls-exit`, `prng`, `keying-material-exporter`, `force-tls-key-material-export`, `use-prediction-resistance`, `http-proxy-option`, `http-proxy-timeout`, `tcp-queue-limit`, `ping-timer-rem` | dropped | lost | RISKY, "ignored by NetworkManager on Linux" (tuning; `connect-retry` is replaced by LinVPN's planner) |
| `http-proxy`, `socks-proxy`, `*-proxy-retry` | yes | NM | SAFE |
| `route` with an IP gateway or none | yes | NM `ipv4.routes` | SAFE |
| `route … vpn_gateway` | refuses | plan: `ipv4.routes` without a next hop | SAFE |
| `route … net_gateway` / `remote_host` | refuses | **lost** | **Not supported on Linux** |
| `route-metric`, `route-ipv6` | dropped | plan: `ipv4.route-metric`, `ipv6.routes` | SAFE |
| `route-gateway`, `route-ipv6-gateway`, `route-table`, `ifconfig-ipv6`, `block-ipv6` | dropped | lost | RISKY (ignored) |
| `redirect-gateway` (`def1`, `ipv6`, `!ipv4`, `bypass-*`, `local`, `autolocal`), `redirect-private` | dropped | plan: `ipv4/ipv6.never-default` (NM always routes the server itself outside the tunnel) | SAFE, except `block-local`: RISKY (ignored) |
| `route-nopull` | dropped | plan: `ipv4/ipv6.ignore-auto-routes` + `ignore-auto-dns` + `never-default` | SAFE |
| `pull-filter` | dropped | plan, only for `redirect-gateway` (never-default), `route`/`route-ipv6` (ignore-auto-routes), `dhcp-option`/`dns` (ignore-auto-dns); harmless Windows-only targets are ignored | SAFE for those prefixes; any other pattern **Not supported on Linux** |
| `dhcp-option DNS/DNS6/DOMAIN/DOMAIN-SEARCH`, `dns server … address/resolve-domains`, `dns search-domains` | dropped | plan: `ipv4/ipv6.dns`, `dns-search` (`~domain` for resolve-domains) | SAFE |
| `dns server … dnssec/transport/sni` | dropped | lost | RISKY (ignored) |
| `dhcp-option WINS/NBDD/NTP/NBT/NBS/DISABLE-NBT/PROXY_*/ADAPTER_DOMAIN_SUFFIX`, `block-outside-dns`, `register-dns`, `dhcp-renew/release/pre-release`, `ip-win32`, `route-method`, `windows-driver`, `tap-sleep`, `pause-exit` | dropped | no-op (Windows only) | SAFE (dropped) |
| `topology`, `route-delay`, `verb`, `mute`, `mute-replay-warnings`, `suppress-timestamps`, `machine-readable-output`, `errors-to-stderr`, `ifconfig-nowarn`, `status-version`, `disable-occ`, `opt-verify`, `single-session`, `setenv-safe`, `setenv NAME …`, `ignore-unknown-option`, `allow-pull-fqdn`, `push-peer-info`, `disable-dco` | mostly dropped | no-op, or NM for the last three | SAFE |
| `user`, `group` (RISKY today) | dropped | implicit: NM always drops to `nm-openvpn` | SAFE (no-op) on Linux |
| `script-security 0/1` | dropped | NM forces 2 for its own `--up` | SAFE (no-op) |
| FORBIDDEN today (`up`, `down`, `script-security 2+`, `management*`, `plugin`, `pkcs11-*`, `chroot`, `log*`, `status`, …) | dropped | NM owns them | FORBIDDEN (unchanged) |
| `setcon` (platform table today) | dropped | lost | RISKY (ignored) |

In short, the Linux tier adds one new reason, **"Not supported on Linux (NetworkManager)"**, a refusal. It has 8
entries:
1. `peer-fingerprint`
2. `verify-hash`
3. `remote-cert-ku`
4. `remote-cert-eku`
5. `route … net_gateway`/`remote_host`
6. `<connection>` that cannot be flattened
7. `pull-filter` with an unmapped pattern
8. `compress stub*`, if we decide to refuse it rather than ignore it

Roughly 60 SAFE names become **"ignored on Linux"** RISKY (tuning or Windows-only), and the rest stay SAFE through NM
keys, `nm_plan` or the secret agent.

## Features lost or changed versus macOS

| Feature | Linux (NM 1.54 / NM-openvpn 1.12.5) |
|---|---|
| `route-nopull`, `pull-filter` | Not passed to OpenVPN. `nm_plan` emulates the common cases with `ignore-auto-routes`/`ignore-auto-dns`/`never-default`; other patterns are refused |
| Server-pushed `redirect-gateway` | **Ignored**: `ipv4.never-default` decides (see the verdict) |
| `script-security`, `up`/`down` | Already FORBIDDEN on every OS; NM runs its own `--up` helper |
| `static-challenge` | No NM key and no `SC:` handling in the service, but it can be done through the secret agent (below) |
| `auth-user-pass` inline | The importer refuses it; with `nm_plan` the credentials come from the vault through the agent (same result) |
| `tls-crypt-v2` | Supported (`tls-crypt-v2` key) |
| `data-ciphers` | Supported, with `data-ciphers-fallback`; `ncp-ciphers` must be renamed by `nm_plan` |
| client-side `dhcp-option` / `dns` | Re-expressed as `ipv4/ipv6.dns` and `dns-search`; pushed DNS still works through the helper |
| `block-outside-dns` | Windows-only; no-op |
| `route` / `route-ipv6` | `ipv4/ipv6.routes`; `vpn_gateway` → no next hop; **`net_gateway` lost** |
| `management` | NM uses the socket itself; we get no bytecount (live traffic comes from `/sys/class/net/<if>/statistics`) |
| `verb` | NM controls it (default `--verb 1`): the Log tab shows fewer OpenVPN lines than macOS at `verb 3` unless NM's log level is raised (root) |
| `compress` | `lzo`/`lz4`/`lz4-v2`/`comp-lzo` yes; `stub`/`stub-v2`/`migrate` no |
| `peer-fingerprint` (CA-less profiles) | Lost: such profiles cannot run on Linux |
| Reconnects | `--auth-retry interact` and `ping-restart` happen inside NM's plugin; NM's own VPN retries must be off (`vpn.persistent=no`, `connection.autoconnect-retries`), as the spec says |

## MFA and secrets (from the source)

**Secret keys** (`vpn.secrets`):
- `password`, `cert-pass`, `http-proxy-password`, `challenge-response`.
- Each has a `*-flags` item in `vpn.data`.
- The importer sets `password-flags=1` (AGENT_OWNED) and `challenge-response-flags=2` (NOT_SAVED). So NM asks the
  secret agents.

**The flow:**
1. NM asks the plugin `NeedSecrets`, then asks the agents (`GetSecrets`, setting `vpn`), then calls `Connect`
   with the secrets.
2. OpenVPN's management socket sends `>PASSWORD:Need 'Auth'`, `'Private Key'` or `'HTTP Proxy'`.
3. `handle_auth()` answers from what it has. If something is missing and the connection was started
   interactively, it calls `nm_vpn_service_plugin_secrets_required(message, hints)`. NM forwards that to the agent
   with those hints and the message, and the plugin receives the answer as `NewSecrets`.

**CRV1 (dynamic challenge) is supported:**
1. `>PASSWORD:Verification Failed: 'Auth' ['CRV1:flags:state:user:text']` is parsed by `parse_challenge()`. The
   cached password is cleared.
2. OpenVPN restarts and asks `Need 'Auth'` again. The plugin requests the secret `challenge-response`, with the
   hint `x-dynamic-challenge-echo:challenge-response` (flag `E`) or `x-dynamic-challenge:challenge-response`. The
   challenge text is the message.
3. It answers `CRV1::<state>::<response>` with the connection's user name. The CRV1 user field is not used.
4. The response is cleared after one use, so a wrong code does not loop.

**Static challenge is not supported by NM-openvpn 1.12.5:**
- No `static-challenge` key exists, and the service never passes `--static-challenge`.
- `get_detail(">PASSWORD:Need '")` reads only up to the quote, so an `SC:` suffix would be ignored anyway.
- Because NM does not pass `--static-challenge`, OpenVPN forwards the management password **verbatim**. So
  LinVPN's agent can answer the `password` secret with exactly what a static-challenge client sends:
  - `SCRV1:base64(password):base64(code)` (the scrv1 format, the default);
  - or `password+code` (the `concat` format).
- The prompt text and echo flag come from the profile, which LinVPN keeps.
- The lab server (`scripts/vpn-lab/server/openvpn-auth.sh`) accepts exactly these forms.
- Caveat from the source: NM caches the password in `io_data->password` for in-process restarts (`ping-restart`),
  so a soft restart resends a used code. The server rejects it, NM clears it, and the agent is asked again
  (interactive only). That makes **spike L0-4** the place to confirm SCRV1-through-agent and CRV1 end to end on
  the lab.

**Risk to check in L0-4** (NM core, not read in this spike): GNOME Shell is also a secret agent of the same user,
with VPN hints capability. Which agent NM asks first for `vpn` secrets of a `user:`-owned connection decides whether
LinVPN's prompt or GNOME's dialog appears. Putting the static password into the in-memory connection's secrets
(flags 0) avoids the question for plain logins. It does not avoid it for CRV1 and static-challenge.

## Housekeeping

- The VM has no NM connections left: `nmcli connection show` lists only `netplan-ens18` and `lo`.
- `~/.local/share/networkmanagement`, created by the cancelled imports, was deleted, and so was the scratch
  `XDG_DATA_HOME`.
- The files stay in `~/l0-a/spike1` on the VM.
