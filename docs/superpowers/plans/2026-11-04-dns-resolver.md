# DNS resolver redesign (root layer 15) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On macOS, put the VPN's DNS into effect through the **SystemConfiguration dynamic store** instead of the services' persistent preferences, and add per-connection DNS modes. The modes are **Automatic** (default: full DNS, with a fallback when the VPN's DNS cannot resolve `apple.com`), **Strict**, **Full** and **Targeted**. A connection can also have its own DNS servers and domains, and the local network's own names keep working while connected. The whole design rests on one principle: a bad VPN DNS setting must never break the internet. A disconnect, a crash or a reboot leaves nothing behind. WireGuard, OpenVPN and SSTP behave the same way. Linux and Windows keep their behaviour.

**Architecture:**
- **Pure decision core.** The pure logic lives in `macvpn_core` and is tested on every OS:
  - `dns_settings` holds the model, the validation and the `up` frame lines.
  - `dns_wire` builds and parses one DNS query.
  - `dns_zones` produces the reverse zones and handles domain overlap.
  - In the helper, `macos/dns_plan.rs` holds the mode decision table and the dynamic-store entries.
- **Dynamic-store writer.** `macos/sc_store.rs` is a thin FFI over `SCDynamicStore`. It sits behind a `Store` trait, with an in-memory fake for unit tests and a file-backed fake for test mode (`MVPN_DYNSTORE`).
- **Manager rewrite.** `macos/dns.rs` becomes the dynamic-store manager:
  - The owners record (the "ledger") lives in the dynamic store, so it is volatile like everything it describes.
  - `acquire` / `release` / `reconcile` / `check` work on that record.
  - The persistent root-layer-14 ledger keeps a restore-only path in `macos/dns_legacy.rs`.
- **Probe.** The probe (one UDP A query for `apple.com`) runs after the tunnel is up: in `updown::up`, then again on demand. The app asks for it about every 5 minutes and after a network change, through a new query-daemon request `dns-check <id>`.
- **Settings travel and notices.**
  - The app sends the per-connection settings as new optional lines of the `up` frame, and the root helper validates them.
  - `mvpn status` gets an optional `dns` field.
  - The app turns changes of that field into notices and row hints.

**Tech Stack:** Rust 2024 (`crates/core`, `crates/helper`, `crates/app-core`, `crates/platform-mac`, `crates/platform-api`). Hand-written SystemConfiguration FFI over `core-foundation` 0.10 / `core-foundation-sys` 0.8 (already dependencies, same pattern as `sc_prefs.rs`). `std::net::UdpSocket` for the probe; no new crate. Tauri 2 + Svelte/TS (`app/ui`). Bash root tests (`scripts/test-root.sh`). Homebrew OpenVPN 2.7.8, wireguard-tools, sstp-client.

---

## Research findings

### R1. The current DNS manager (root layer 14)

**`crates/helper/src/macos/dns.rs`**
- `Manager { dir, net: Box<dyn Net> }` keeps a **persistent** ledger `/var/db/macvpn/dns/ledger`: `HEADER = "macvpn-dns-ledger 1"`, then `orig\t<service>\t<servers>\t<domains>` and `owner\t<uuid>\t<servers>\t<domains>` lines. It is serialized by an `flock` on `<dir>/lock` (`Manager::lock`, 300 × 100 ms).
- `acquire(id, dns, log)`:
  - refuses lists outside `Dns::within_limits` (`MAX_SERVERS = 16`, `MAX_DOMAINS = 32`);
  - captures the originals of **every** service, but only when there are none yet;
  - pushes the owner;
  - persists the ledger, then `apply(owner_targets(..))`.
- `release(id)` and `reconcile(alive, log_for, wait)` call `settle`. `settle` restores the originals when no owner is left, and re-applies the newest owner when the one in effect leaves.
- `restore_legacy(backup)` restores a pre-ledger `<run>/dns-backup`.
- `apply` writes, reads back (`mismatched`), retries once (`Net::retry_many`) and logs `"DNS set and verified on %@ network service(s)"`.
- `Ledger::parse` / `salvage` handle damaged ledgers (`ledger.bad`).
- `reconcile(s, wait)` uses `owner_alive` (run dir + kind + `status::one(..).state != "failed"`) and `log_of`.
- Validation helpers that the new code reuses: `is_search_domain`, `is_valid`, `Dns::within_limits`, `log_over_limits`.

**`Net` trait.** Its methods are `services`, `get`, `set`, `get_many`, `set_many` and `retry_many`. There are three implementations: `NetworkSetup` (`/usr/sbin/networksetup`), `dns_sc::ScNet` (root layer 14), and `tests::FakeNet` (in-memory).

**`crates/helper/src/macos/dns_sc.rs` + `sc_prefs.rs` (root layer 14).**
- They read and write the `ServerAddresses` / `SearchDomains` of each service's DNS protocol entity in the **persistent** preferences, through one locked `SCPreferences` session with one `SCPreferencesCommitChanges` + `SCPreferencesApplyChanges`.
- Anything they cannot do with certainty falls back to `networksetup`.
- `sc_prefs.rs` is the FFI pattern to copy: `#[link(name = "SystemConfiguration", kind = "framework")]`, create/get rule wrappers, and `error(what)` with `SCError` / `SCErrorString`.

**`crates/helper/src/macos/hook_dns.rs` (`mvpn hook ovpn-dns <run> <log>`, OpenVPN `--up`/`--down`, also SSTP).**
- `HookEnv::from_lookup` reads **only** `script_type`, `dev`, `ifconfig_local` and `foreign_option_1..N`. The test `only_allowlisted_names_are_read` pins this.
- `HookEnv::options()` accepts `dhcp-option DNS <ip>` (`is_dns`) and `dhcp-option DOMAIN <d>` (`is_search_domain`). It does **not** accept `DNS6` or `DOMAIN-SEARCH` (see R3: OpenVPN 2.7 hands IPv6 servers pushed with `--dns` to `--up` as `dhcp-option DNS6`, so these are lost today).
- `up()` writes `<run>/iface` and `<run>/ip`, then calls `Manager::acquire`.
- `down()` calls `release` and restores a legacy `dns-backup`.
- `hook_manager()` returns a manager only as root, so a privilege-dropped OpenVPN (`user`/`group`, a risky-acknowledged directive) never changes DNS in `down`. `ctx.dns_restore()` at cleanup handles that case.
- `crates/helper/src/macos/mod.rs::hook_paths_ok` accepts the hook only for a root-private `/var/run/macvpn/<uuid>` whose `kind` is `openvpn` or `sstp`, and only with its own log path.

**WireGuard (`crates/helper/src/macos/wireguard.rs`).**
- `strip_dns(conf) -> (String, Dns)` takes the `[Interface] DNS =` lines out of the conf that `wg-quick` sees. Addresses become servers, everything else becomes search domains.
- `up()` calls `ctx.dns_set(&dns)` (= `Manager::acquire`) after `wg-quick up`, and only if `within_limits`.
- `down()` calls `ctx.dns_restore()` after `wg-quick down`.

**SSTP (`crates/helper/src/macos/sstp.rs` ~l.374).** Only when `SstpParams.peer_dns == "yes"`, it runs `mvpn hook ovpn-dns` with `script_type=up` and `foreign_option_N=dhcp-option DNS <ip>` built from the pppd log (`pppd_log_fields(&run, "dns")`). Without `usepeerdns` the DNS manager is never called, so own DNS for SSTP needs that call in every case.

**`Ctx` helpers (`crates/helper/src/macos/ctx.rs` l.264–296).**
- `dns_restore()`: legacy `dns-backup` through the hook, then `Manager::release`.
- `dns_set(dns)`: `Manager::acquire`.

**Reconcile call sites.**
- `status::answer` (`crates/helper/src/macos/status.rs` l.171) runs `dns::reconcile(s, false)` on every `mvpn status`, so also from the query daemon.
- `updown::up` (before anything new is set, `wait=true`), `updown::body` after `down`, and `mvpn dns-reconcile` (`mod.rs`).

**How per-connection settings reach the root helper.**
- **Command line.** `crates/core/src/helper_args.rs::up_arguments` gives `up <kind> <ID> [--debug] [--accept-risky a,b]` (parsed by `crates/helper/src/shared/cli.rs::Args::parse`).
- **The framed stdin.** `helper_args::up_stdin` writes `config <len>\n<config><secret lines>`. It is parsed by `crates/helper/src/shared/framing.rs::parse_framed` → `Secrets::parse_lines`, which accepts only `username=`, `password=`, `psk=`, `keypass=`, `otp=`, `challenge=packed`, `x509=`, `private=` and `pkcs12=`, each at most once (`seen: [bool; 9]`). Any other line is `FrameError::Invalid`.
- **SSTP parameters** travel inside the config body (`SstpParams::from_lines` via `validate::sstp_params`).
- **Client side.** `crates/platform-mac/src/mvpn_client.rs::MvpnClient::up(kind, id, config, secrets, debug, accept_risky)` is called through `crates/platform-api/src/helper.rs::HelperClient::up` from `crates/app-core/src/manager.rs` ~l.1899.
- **Decision.** The new DNS settings travel as **new optional lines of the same frame** (validated in `framing.rs`, re-checked in `macos/`). An older root layer refuses unknown lines (`Invalid input`), so the app sends them only to root layer ≥ 15 (Task 7).
- **Shared with WinVPN.** The framing parser is shared with WinVPN's service client, which simply ignores the lines.

### R2. App side

**Model.**
- `crates/core/src/models.rs::Connection` (l.295) has `acknowledged_risky_directives` and `otp: OTPSetting`. `otp` is decoded leniently: `match obj.get("otp") { None|Null => default, Some(v) => OTPSetting::from_json(v).unwrap_or_default() }`. That is the pattern for a new `dns` object.
- `to_json` (l.369) writes camelCase keys.
- Storage is the vault column `connections.meta_json` (`crates/core/src/vault/repo_connections.rs`; trait `ConnectionRepository` in `crates/app-core/src/deps.rs:26`).
- The backup carries `Connection::to_json()` whole (`crates/core/src/vault/backup.rs` l.832/1083).
- The export (`exporter.rs`, `ExportMeta` in `importer.rs:112`) does not carry `otp`, and will not carry DNS.
- The team catalog copies `otp` (`catalog/payload.rs` allowlist l.608, `catalog/planner.rs:183` hash, `vault/catalog_apply.rs` l.256/294/643). Whether DNS is catalog-owned is an open point (O5).

**Editor.**
- Tauri: `app/src-tauri/src/manage.rs` (`editor_open` / `editor_update` / `editor_save(state, id, fields: EditorFields)`).
- app-core:
  - `crates/app-core/src/connections.rs::save_editor` (l.863).
  - `crates/app-core/src/editor.rs`: `OtpFields`, `TextFields`, `NativeFields`, `SstpFields` and `SystemFields` are all `#[serde(rename_all = "camelCase", deny_unknown_fields)]`.
  - `save_otp(deps, c, otp)` (l.415) saves the meta only. It is the model for `save_dns`.
  - `Draft::save` (l.905).
- UI: `app/ui/src/lib/api.ts` (`TextFields` / `SstpFields` … with `otp: Otp`, `editorSave` l.728). The reusable sub-form `app/ui/src/lib/manage/OtpFields.svelte` is used in `TextEditor.svelte:193`, `SstpForm.svelte:107`, `NativeForm.svelte:80` and `SystemDetail.svelte:123`. The connection detail is `manage/Detail.svelte`.

**l10n.**
- One table, `crates/core/l10n/strings.json`: `{"<English>": {"hu": "…", "scope": "app|core|mvpn|platform", "only": ["macos"]}}`.
- Rust: `macvpn_core::l10n::tr`. UI: `tr()` from `app/ui/src/lib/l10n.svelte.ts`.
- Coverage checks: `crates/app-core/tests/l10n_coverage.rs` and `app/ui/src/lib/l10n.test.ts`. Fragments go in `crates/core/l10n/<dir>/*.json`, merged with `scripts/l10n-merge.mjs`.

**Notices.**
- `crates/app-core/src/connection_notices.rs`: `enum Notice` (11 variants `{key, name, …}`). `NoticeTracker::on_state` raises notices on state transitions. Texts are lock-screen safe (no server, address or log text).
- `app/src-tauri/src/notifications.rs::notice(state, &Notice)` checks the switch `connection_notices::ENABLED_KEY` and posts.

**Row hints.** `crates/app-core/src/view_model.rs::RowView` (l.130) has optional fields such as `certificate_warning: Option<String>` with `skip_serializing_if`. They are set by `vm.set_…` from `app/src-tauri/src/state.rs` l.139–180 and shown in `Detail.svelte:101` (`row.certificateWarning`, `api.ts:60`).

**Split vs full tunnel, as the app knows it (static, from the config).**
- `crates/core/src/openvpn_routing.rs::read(text) -> Routing { ServerDecides, Always, Never }`.
- WireGuard: `AllowedIPs` containing `0.0.0.0/0` / `::/0` (as in `crates/core/src/nm_plan/wireguard.rs` l.88).
- SSTP: `route_all` (`SSTPConfig`).
- `crates/core/src/vpn_networks.rs::VpnNetworks` deliberately drops default routes (`IpPrefix::is_default_route`), so it cannot tell "full".
- A **pushed** `redirect-gateway` is not knowable statically (`Routing::ServerDecides`), so the helper decides at runtime (R4).

**Status and polling.**
- `crates/core/src/status.rs::RootStatus { id, kind, state, iface, ip, since }`. Unknown JSON keys are ignored.
- `crates/helper/src/shared/status_json.rs` renders `status` byte-exactly against the golden `GOLDEN_1_4`. A new key is emitted only when set.
- Status poll (`crates/app-core/src/app.rs`): 3 s active, 10 s connected without a window, 30 s idle.
- Liveness (`crates/app-core/src/liveness.rs`): `POLL = 30 s`, `SWITCH_POLL = 10 s` for `SWITCH_WINDOW = 120 s` after a network switch. It is gated by `liveness_due` (`crates/app-core/src/reconnect.rs:936`: not asleep, online, no pending network check) and driven by `app/src-tauri/src/reconnect.rs:303`.

**Query daemon (`crates/helper/src/macos/serve.rs`, root layer 13).**
- `enum Request { Status, Liveness(String), Traffic(String) }`, with `Request::parse` as the allowlist (`REQUEST_MAX = 128`).
- The answer is `<exit code>\n<stdout>`.
- The client is `MvpnClient::read_only` (socket first, then `sudo`).
- The doc comment promises "No request reaches anything that changes state beyond what `mvpn status` already does". `status` already reconciles DNS, so `dns-check` would be the same class of change (open point O4).

### R3. The dynamic-store technique and OpenVPN 2.7

**OpenVPN 2.7.8's own script.** Homebrew installs `/opt/homebrew/Cellar/openvpn/2.7.8_1/libexec/openvpn/dns-updown`. It takes `dns_*` variables (directly, or from `dns_vars_file`) and works through `scutil`.

- **Split DNS** (the server profile has `resolve-domains`):
  - It writes its own service entry `State:/Network/Service/openvpn-<dev>/DNS`:
    ```
    d.init
    d.add ServerAddresses * <addresses>
    d.add SupplementalMatchDomains * <resolve-domains>
    d.add SupplementalMatchDomainsNoSearch # 1
    add State:/Network/Service/openvpn-<dev>/DNS
    ```
  - For search domains it prepends to the **primary service's** `Setup:/Network/Service/<PrimaryService>/DNS` `SearchDomains`. The primary comes from `State:/Network/Global/IPv4` `PrimaryService`. It also keeps a copy in `State:/Network/Service/openvpn-<dev>/DnsBackup` when another tunnel holds the backup.
  - Restore: `remove` the entry, and strip the domains back out of `SearchDomains`.
- **Full DNS** (no `resolve-domains`):
  - It copies the primary service's `Setup:/Network/Service/<primary>/DNS` (as it is **in the dynamic store**) into `State:/Network/Service/openvpn-<dev>/DnsBackup`.
  - It then **replaces** that `Setup:` key in the dynamic store with `{ServerAddresses, SearchDomains, SearchOrder = 5000}`.
  - It refuses when another tunnel already holds a backup ("already redirecting to another tunnel").
  - Restore: copy the backup back, but only if the current `ServerAddresses` still equal its own ("not restoring global DNS configuration, server addresses have changed"), then `remove` the backup.
- Both paths finish with `/usr/bin/dscacheutil -flushcache`.
- The script **never writes `State:/Network/Global/DNS`**. That key is configd's (IPMonitor's) merged output and is rewritten by it.
- The reason the full technique works: configd's IPMonitor builds a service's DNS from `State:/Network/Service/<id>/DNS` (DHCP and other dynamic sources) overlaid by `Setup:/Network/Service/<id>/DNS` (the preferences as PreferencesMonitor publishes them). `Setup:` wins per key. Writing the `Setup:` key **in the dynamic store** therefore overrides the service's resolver without touching the persistent preferences, and it is gone at reboot.

**This Mac's live dynamic store** (read-only `scutil`, 2026-11-04):
- `State:/Network/Global/IPv4` = `{PrimaryInterface: en0, PrimaryService: D27D8913-…, Router: 192.168.50.1}`.
- `Setup:/Network/Global/IPv4` `ServiceOrder` lists 10 service IDs.
- `list State:/Network/Service/.*/DNS` → only `State:/Network/Service/D27D8913-…/DNS` = `{ServerAddresses: [192.168.50.5]}` (DHCP). There is no `DomainName` and no `SearchDomains` (Wi-Fi has no search domains).
- `list Setup:/Network/Service/.*/DNS` → **no keys**: no service has manual DNS, so `Setup:…/DNS` keys exist only for manually configured services.
- `State:/Network/Service/<primary>/IPv4` has `Addresses: [192.168.50.58]` and `SubnetMasks: [255.255.255.0]`, which gives the local reverse zone `50.168.192.in-addr.arpa`.
- `State:/Network/Global/DNS` = `{ServerAddresses: [192.168.50.5], __CONFIGURATION_ID__: "Default: D27D…", __FLAGS__, __IF_INDEX__: 13, __ORDER__}`. This is the merged result.
- `scutil --dns`: resolver #1 is `192.168.50.5` on `en0`, followed by mDNS resolvers for `local`, `254.169.in-addr.arpa`, `8.e.f.ip6.arpa` … `b.e.f.ip6.arpa`.

**What OpenVPN 2.7 does with `--dns` / `dhcp-option` when we pass our own `--up`** (sources `release/2.7`: `options.c::dhcp_options_postprocess_dns`, `dns.c::run_up_down_command`, `options.c` `dns-updown` parsing):
1. The default `dns-updown` **does not run** when an `--up` script is set, unless `--dns-updown` is user-set or `force` (`if (!dns->updown || (o->up_script && !dns_updown_user_set(dns) && !dns_updown_forced(dns))) return;`). We pass `--up`/`--down` (`crates/helper/src/macos/openvpn.rs` l.145–157).
   - The validator forbids `dns-updown` in configs (`crates/core/src/validators/openvpn.rs` l.194).
   - `dns-updown` is `OPT_P_SCRIPT`, so it cannot be pushed.
   - **Two DNS managers never fight today, and passing `--dns-updown disable` is not required.**
   - `disable` would be harmless on 2.7 (it keeps the `foreign_option` compatibility). OpenVPN 2.6 does not know the option and would refuse to start, so it must not be passed blindly.
2. **Compatibility env for `--up`.**
   - When `--dns` servers exist (pushed `dns server …` or converted), OpenVPN removes the `dhcp-option DNS|DNS6|DOMAIN|DOMAIN-SEARCH|ADAPTER-DOMAIN-SUFFIX` foreign options and re-creates them from `--dns`:
     - `dhcp-option DOMAIN <d>` for each `--dns search-domains` entry;
     - `dhcp-option DNS <v4>` / `dhcp-option DNS6 <v6>` for the addresses of the **first** server profile with plain transport, no DNSSEC and port 53.
   - **`resolve-domains` are not passed to `--up`.**
   - Without `--dns` servers, the pushed `dhcp-option …` lines stay as pushed, including `DNS6` and `DOMAIN-SEARCH`.
3. **The richer path.** A user-set `--dns-updown <cmd>` gets `script_type=dns-up|dns-down`, `dev`, and `dns_search_domain_{n}`, `dns_server_{n}_address_{m}`, `dns_server_{n}_port_{m}`, `dns_server_{n}_resolve_domain_{m}`, `dns_server_{n}_dnssec`, `dns_server_{n}_transport` and `dns_server_{n}_sni`.
   - When OpenVPN dropped privileges (`user`/`group`), the variables come instead as a file named by `dns_vars_file`: `NAME=value` lines (`env_set_write_file`), written by OpenVPN and unlinked after the command. The command runs in a privileged runner child, i.e. as **root**, even after the drop.
   - In this mode the DNS foreign options are removed from `--up`'s environment.
   - Order: `dns-up` runs **before** `--up`, after the TUN open. `dns-down` runs before `--down`.
4. **Routes come after `--up`.** `--up` and `dns-up` run before the routes are added. `mvpn up` itself waits for `Initialization Sequence Completed` (`openvpn::wait_connected`), when the routes are in place. **The probe and the split/full decision therefore run in `mvpn up` after `wait_connected`, not in the hook.**
5. 2.7 also exports `route_redirect_gateway_ipv4/6` to `--up` (measured in the LinVPN L0 spike, `docs/superpowers/plans/2026-10-29-linvpn-lb.md` fact 5). The helper still uses the route-table check (R4), because it is the same for every kind.

**The decision for 15.**
- Keep `--up`/`--down` as the baseline on every OpenVPN version, and extend the parser with `DNS6` and `DOMAIN-SEARCH`.
- On OpenVPN ≥ 2.7, additionally pass `--dns-updown "<libexec>/mvpn hook ovpn-dns <run> <log>"`, so the hook gets `resolve-domains` (needed by the Targeted mode and the fallback). The hook then handles `script_type=dns-up|dns-down` and strictly parses `dns_vars_file` (never sources it).
- That path is its own task (Task 9b) and can be dropped without affecting the rest (open point O3).

**macOS resolver semantics relevant to the fallback.**
- **Default resolver.** The default resolver (resolver #1) comes from the primary service's merged DNS. Every name not matched by a supplemental resolver goes there.
- **Supplemental resolvers.**
  - Every `State:/Network/Service/<any id>/DNS` with `SupplementalMatchDomains` becomes a supplemental resolver (the service does not need to be in the `ServiceOrder`; this is how OpenVPN's and Tunnelblick's entries work).
  - The longest matching domain wins.
  - `SearchOrder` orders resolvers with equal match.
  - Without `SupplementalMatchDomainsNoSearch = 1`, the match domains are also appended to the search list.
- **NXDOMAIN and timeouts are final.** NXDOMAIN or a timeout from the chosen resolver is **final**: there is no fall-through to another resolver.
  - This is why a VPN DNS without recursion breaks browsing on a full DNS layout.
  - It is also why the fallback must take the VPN DNS **out of the default role** instead of adding the original DNS "after" it.
  - And it is why an overlap between the local domain and a VPN domain must be decided by us (the VPN wins).
- **The default resolver is interface-scoped.** `scutil --dns` shows `if_index : 13 (en0)` on resolver #1. Whether mDNSResponder sends the fallback default resolver's queries out of `en0` on a full tunnel (outside the tunnel) or by the routing table (into the tunnel when the original DNS is not on the local subnet) is open point O2, settled on the live test.
- **The entry model for 15.** These facts settle the model below (R3a).

### R3a. The dynamic-store entries of root layer 15 (exact keys and values)

`<id>` is the connection UUID, upper-case as the CLI accepts it. `<sid>` is a network service ID. Every entry written by MacVPN carries `MacVPNOwner = "<id>"` so drift and foreign changes can be recognised.

| Key | Written in | Value |
|---|---|---|
| `State:/Network/Service/macvpn-<id>/DNS` | every layout with VPN servers and VPN search domains | `ServerAddresses = [vpn servers]`, `SupplementalMatchDomains = [vpn search domains (+ own domains)]`, `SearchOrder = 100`, `SupplementalMatchDomainsNoSearch = 1` in the `Vpn` layout (the search list comes from the override) and absent in `Split`/`Fallback` (the VPN's search domains are appended to the search list), `MacVPNOwner` |
| `State:/Network/Service/macvpn-<id>-match/DNS` | when there are resolve-only domains or routed private reverse zones | `ServerAddresses = [vpn servers]`, `SupplementalMatchDomains = [resolve-domains + reverse zones of the routed private networks]`, `SupplementalMatchDomainsNoSearch = 1`, `SearchOrder = 101`, `MacVPNOwner` |
| `State:/Network/Service/macvpn-<id>-local/DNS` | `Vpn{local:true}` (Automatic / Full) only | `ServerAddresses = [original servers of the primary service]`, `SupplementalMatchDomains = [local domain(s)] + [local reverse zones]` minus anything a VPN domain or zone covers, `SupplementalMatchDomainsNoSearch = 1`, `SearchOrder = 200`, `MacVPNOwner` |
| `Setup:/Network/Service/<sid>/DNS` (override) | `Vpn` layout of the **newest** `Vpn`-layout owner, for every `<sid>` in `Setup:/Network/Global/IPv4` `ServiceOrder` except VPN-like services (interface `utun*`/`ppp*`/`ipsec*`, and our own) | the service's original `Setup:` DNS dict (or `{}`), with `ServerAddresses = [vpn servers]`, `SearchDomains = dedup(vpn search domains ++ (Vpn{local:true} ? original search of that service : []))`, `MacVPNOwner = "<id>"` |
| `State:/Network/MacVPN/DNS` (the volatile ledger) | while any owner exists | `Version = 15`, `Owners = [<id>…]` (oldest first), `Originals = { <sid>: {Present: 0/1, Value: <original Setup DNS dict>} }`, captured when the first override is written and dropped when the last override is restored |

Notes on the table:
- **Original search domains.** The "original search" of a service is its `Setup:` `SearchDomains`, else its `State:` `SearchDomains`, else `[State: DomainName]`.
- **The original primary DNS.** "Original servers of the primary" are taken from `Originals[primary]` (`Setup:` `ServerAddresses` if present), else from `State:/Network/Service/<primary>/DNS` `ServerAddresses`. `State:` is never overridden by us, so it stays readable.
- **Restore.** For each `<sid>` in `Originals`, if the current `Setup:` value still has our `MacVPNOwner`, put back `Value` (or remove the key when `Present = 0`). Otherwise leave it and log "changed by the system meanwhile". This is OpenVPN's server-address guard, made exact by the marker.
- **Why every service, not only the primary.** A Wi-Fi → Ethernet switch makes another service primary. Overriding every ordered service keeps full DNS in effect at once, with no window. Services that appear later, and PreferencesMonitor rewriting `Setup:` keys after a preferences change, are repaired by the drift check in `reconcile` (every `status`, Task 8).
- **Nothing persistent.** Nothing is written to the persistent preferences any more. A reboot clears everything. A helper crash leaves the entries until the next `reconcile` (≤ 10 s with the app running), which removes the dead owner's entries and restores the overrides from `Originals`.

### R4. The probe

- **Wire format.** A minimal query in `macvpn_core::dns_wire` (Task 2): ID, RD flag, one question `apple.com` / `A` / `IN`.
- **Validation of the answer:**
  - the ID matches, `QR = 1`, opcode 0, `QDCOUNT = 1`, and the question section byte-equal to ours;
  - `RCODE`, then the answer section, with compression pointers handled and the loop bounded;
  - at least one `A` record of `rdlength` 4. `TC = 1` with `RCODE = 0` also counts as resolving.
- **Socket.** `std::net::UdpSocket`, bound to the unspecified address of the server's family and `connect()`ed to `<server>:53`, so only that peer's datagrams are read. 1.5 s read timeout, at most 2 sends, mismatched IDs ignored until the deadline. No crate is added.
- **Which servers.** At most the first 3 VPN servers. The first `Resolved` wins. The routing table decides the path, exactly as the resolver's own queries do.
- **When.**
  - **At connect:** in `updown::up`, after `up_kind` returned (OpenVPN after `wait_connected`, WireGuard after `wg-quick up`, SSTP after the hook). One call, `dns::after_connect(ctx)`, does the tunnel detection, the probe, the decision and the re-publish.
  - **During the session:** the app sends `dns-check <id>` through the query daemon:
    - every **5 minutes** while connected, when the session's mode probes (Automatic, Full, Strict) and the connection has VPN DNS servers;
    - **15 s after a network change** (the app's existing network-switch signal, `liveness::SWITCH_WINDOW` machinery);
    - never while asleep or offline (the `liveness_due` gate).
  - One UDP query per check, so the energy cost is negligible. `dscacheutil -flushcache` runs only when the layout actually changes.
- **Failure rule.** "Lookups through it start failing" is approximated by the periodic re-probe. Fallback happens after **two consecutive** failed checks (each check already retries once), to avoid flapping. Full DNS returns after **one** successful check.
- **Split vs full tunnel** is decided by the helper after connect, the same way for every kind: `route -n get -inet 1.0.0.1` and `route -n get -inet 129.0.0.1` (one in each `def1` half). If both resolve to the tunnel's interface (`<run>/iface`, or the `utun` behind WireGuard's `mv…` name), the tunnel is full. The `-inet6 2000::1` result also counts, as full when it goes into the tunnel. That is 2–3 `route` processes, once per connect, through `ctx.s.route`, which is fakeable in test mode.

### R5. Root layer 15 and migration

- **Disconnect before upgrade.** `crates/platform-mac/src/root_installer.rs::install` (l.325) embeds `down_loop(user)` (l.355). It runs `mvpn down <kind> <id>` for every `$RUN_BASE/<uuid>/kind` **before** replacing the binary, and aborts with `disconnect_failure_marker()` ("Could not disconnect:") on a failure. The UI warns first with `upgrade_disconnect_notice()` ("Updating the system component will disconnect active VPN connections."; `crates/app-core/src/setup.rs:288/303`, `Setup.svelte:208`). **So no connection made under 14 is alive under 15.**
- **Leftover 14 ledger.** A 14 ledger can still be left by a crash or a reboot under 14: the originals sit in `/var/db/macvpn/dns/ledger` and the VPN DNS in the persistent preferences.
  - 15 keeps the 14 restore path verbatim in `macos/dns_legacy.rs`: `Ledger`, `parse` / `salvage`, `Manager::{release, reconcile, settle, apply, lock, load, save}`, `restore_legacy`, `dns_sc`, `sc_prefs`, `NetworkSetup`. The only change is that `acquire` is gone.
  - `dns::reconcile` first runs the legacy reconcile when `/var/db/macvpn/dns/ledger` exists. Owners are dead (no 14 run dir survives the installer's `down`), so the originals are restored and the ledger is removed.
  - The new code never creates the legacy ledger.
- **The lock.** The `flock` stays at `/var/db/macvpn/dns/lock` (`Manager::lock`'s directory rules) and serializes both the legacy path and the dynamic-store manager.
- **Version number.** `crates/helper/VERSION` goes `14` → `15`. Change `mod.rs::tests::version_is_14` accordingly. `scripts/build-dmg.sh` reads the file. Add the user guide's root-layer history line.

### R6. Linux and Windows

- **This redesign is macOS-only.**
- **LinVPN.** DNS goes through NetworkManager / systemd-resolved, already with split DNS: `crates/core/src/nm_plan/dns.rs::section_extras(full, domains)`, `~.` with priority `-50` on a full tunnel and `~domain` with priority `50` on a split one.
- **WinVPN.**
  - WireGuard sets per-adapter DNS (`crates/helper/src/windows/wg_plan.rs`, `wg_nt.rs`).
  - OpenVPN's `openvpn.exe` sets DNS itself (`sys/openvpn.rs`).
  - RAS kinds are Windows' own.
- **What applies there.**
  - The `Connection.dns` field is stored and round-trips on every OS (vault and backup are shared formats), and is ignored off macOS.
  - The DNS section of the editor is shown only when `i18n.platform.os === 'macos'` and the kind is OpenVPN, WireGuard or SSTP. strongSwan (charon's own `osx-attr` dynamic-store DNS) and native VPNs are not touched by the DNS manager.
  - `HelperClient::up` gets the new parameter on every platform; the Linux and Windows implementations ignore it.
  - `HelperClient::dns_check` defaults to `None`.
  - A later LinVPN mapping (Targeted → no `~.`; Strict/Full → `~.`) is possible but out of scope.

---

## File structure

**Create**

| File | Responsibility |
|---|---|
| `crates/core/src/dns_settings.rs` | `DnsMode`, `DnsSetting` (model and JSON), `DnsRequest` (what goes to root), validation, frame lines (render/parse), `full_tunnel_hint(kind, config)` |
| `crates/core/src/dns_wire.rs` | `PROBE_NAME`, `query()`, `parse_answer()`, `Answer` (pure) |
| `crates/core/src/dns_zones.rs` | `reverse_zones(prefix)`, `is_private(prefix)`, `covered_by(domain, domains)` (pure) |
| `crates/core/tests/dns_settings.rs`, `dns_wire.rs`, `dns_zones.rs` | unit tests |
| `crates/helper/src/macos/sc_store.rs` | SCDynamicStore FFI: `open`, `copy_value`, `set_value`, `remove_value`, `copy_key_list(pattern)`; a `Value` tree ⇄ CFPropertyList |
| `crates/helper/src/macos/dns_store.rs` | `trait Store`, `ScStore` (as root), `MemStore` (unit tests), `FileStore` (test mode, `MVPN_DYNSTORE=<dir>`) |
| `crates/helper/src/macos/dns_plan.rs` | the pure decision table `decide()`, `Inputs`, `Layout`, `Warn`, `entries()` → the exact dictionaries of R3a |
| `crates/helper/src/macos/dns_probe.rs` | the UDP probe over `dns_wire` (and `MVPN_DNS_PROBE` in test mode) |
| `crates/helper/src/macos/dns_session.rs` | `<run>/dns-request` and `<run>/dns-session` files (root 0600, strict key=value) |
| `crates/helper/src/macos/dns_legacy.rs` | root layer 14's ledger manager, restore-only (moved from `dns.rs`) |
| `crates/helper/tests/dns_probe.rs` | the probe against a local fake UDP DNS server |
| `app/ui/src/lib/manage/DnsFields.svelte` | the per-connection DNS sub-form |
| `app/ui/src/lib/manage/dnsFields.ts` (+ `.test.ts`) | visibility and validation helpers for the form |

**Modify**

| File | Change |
|---|---|
| `crates/core/src/lib.rs` | `pub mod dns_settings; pub mod dns_wire; pub mod dns_zones;` |
| `crates/core/src/models.rs` | `Connection.dns: DnsSetting` (lenient decode, written only when not default) |
| `crates/core/src/helper_args.rs` | `up_stdin(config, secrets, dns: Option<&DnsRequest>)` |
| `crates/core/src/status.rs` | `RootStatus.dns: Option<DnsState>` |
| `crates/helper/src/shared/framing.rs` | parse the `dns-*` lines into `Secrets.dns: DnsRequest` (not masked, not secret) |
| `crates/helper/src/shared/status_json.rs` | optional `"dns"` key |
| `crates/helper/src/macos/dns.rs` | rewritten: the dynamic-store manager |
| `crates/helper/src/macos/dns_sc.rs`, `sc_prefs.rs` | used only by `dns_legacy` (doc comments) |
| `crates/helper/src/macos/hook_dns.rs` | `DNS6`, `DOMAIN-SEARCH`, `dns-up`/`dns-down` + `dns_*`/`dns_vars_file`, `route_*` env; the new manager calls |
| `crates/helper/src/macos/openvpn.rs` | `--dns-updown <hook>` on OpenVPN ≥ 2.7; `after_connect` |
| `crates/helper/src/macos/wireguard.rs` | use the request; `after_connect` |
| `crates/helper/src/macos/sstp.rs` | call the DNS step also without `usepeerdns` (own DNS) |
| `crates/helper/src/macos/ctx.rs` | `dns_set` / `dns_restore` over the new manager; `ctx.dns_request` |
| `crates/helper/src/macos/updown.rs` | write `<run>/dns-request`; `dns::after_connect` after `up_kind` |
| `crates/helper/src/macos/status.rs` | `dns` field from `<run>/dns-session` |
| `crates/helper/src/macos/serve.rs`, `mod.rs` | `dns-check <uuid>` (query daemon and CLI) |
| `crates/helper/src/macos/paths.rs` | `dynstore` and `dns_probe` test settings (`MVPN_DYNSTORE`, `MVPN_DNS_PROBE`) |
| `crates/helper/VERSION`, `crates/helper/src/macos/mod.rs` (test) | 15 |
| `crates/platform-api/src/helper.rs` | `up(..., dns: Option<&DnsRequest>)`, `fn dns_check(&self, id) -> Option<DnsState> { None }` |
| `crates/platform-mac/src/mvpn_client.rs`, `src/api/adapters.rs` | pass the request (only to root ≥ 15), `dns_check` |
| `crates/platform-linux/src/lin/nm/helper_impl.rs`, `crates/platform-win/src/win/service_client.rs`, `ras_engine.rs`, the test fakes (`app/src-tauri/src/control.rs:1055`, `catalog.rs:1626`, `platform/smoke/mod.rs:232`) | the new parameter (ignored) |
| `crates/app-core/src/manager.rs` | build the `DnsRequest` from `c.dns` and pass it |
| `crates/app-core/src/editor.rs`, `connections.rs`, `app/src-tauri/src/manage.rs` | `DnsFields` in `TextFields` / `SstpFields`, `save_dns` |
| `crates/app-core/src/connection_notices.rs` | `Notice::{DnsFallback, DnsFailing, DnsRestored}` and `NoticeTracker::on_dns` |
| `crates/app-core/src/view_model.rs`, `app/src-tauri/src/state.rs` | `RowView.dns_note` |
| `crates/app-core/src/liveness.rs` (or a new `dns_check.rs`), `app/src-tauri/src/reconnect.rs` | the `dns-check` schedule and driver |
| `app/ui/src/lib/api.ts`, `manage/TextEditor.svelte`, `manage/SstpForm.svelte`, `manage/Detail.svelte` | form and hint |
| `crates/core/l10n/strings.json` | new strings EN/HU |
| `docs/user-guide.en.md`, `docs/user-guide.hu.md` (§5.6, root-layer history), `docs/architecture.md` ("macOS DNS manager"), `docs/manual-test-checklist.md`, `docs/release-notes/<next>.md` | docs |
| `scripts/test-root.sh` | DNS section rewritten for the fake dynamic store |

---

## Rules for every task

- TDD: the failing test first. Run targeted tests per task: `cargo test -p <crate> <filter>`. Run the full gate once at the end (Task 16).
- No `sudo`, no change to this Mac's network or DNS settings by an agent. `#[ignore]` root-only tests are run by the maintainer (as `dns_sc` does today).
- Formats: `meta.json` and status JSON stay byte-identical for connections without DNS settings. New keys are omitted when default or absent.
- One commit per task, message trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never push.
- Server-sent values are validated, never evaluated. Every new environment variable read by the hook is allowlisted and pinned by a test.

---

## Task 1: Core DNS settings model, validation and frame lines

**Files:** create `crates/core/src/dns_settings.rs` and `crates/core/tests/dns_settings.rs`; modify `crates/core/src/lib.rs` and `crates/core/src/models.rs`.

- [x] **Step 1: tests first** (`crates/core/tests/dns_settings.rs`):
  - `default_is_automatic_without_own_dns`;
  - `json_round_trip_and_default_omitted`: `Connection::to_json` has no `dns` key for the default, and has `{"mode":"targeted","servers":["10.0.0.53"],"domains":["corp.example"],"override":true}` otherwise;
  - `lenient_decode`: a bad `dns` value means the default, as with `otp`;
  - `validation`:
    - servers must pass `is_dns` and be at most 16;
    - domains must pass `is_search_domain` and be at most 32, stored lower-case without a trailing dot;
    - `override` without servers is invalid;
  - `frame_lines_round_trip`: the request renders to lines and parses back equal;
  - `frame_lines_refuse_garbage`: unknown mode, a bad server, a bad domain or a duplicate key are refused;
  - `full_tunnel_hint`:
    - OpenVPN `redirect-gateway def1` gives `Some(true)`; `route-nopull` gives `Some(false)`; neither gives `None` (server decides);
    - WireGuard `AllowedIPs = 0.0.0.0/0` gives `Some(true)`;
    - SSTP `route_all` gives `Some(true)`.
- [x] **Step 2: implement:**

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsMode { #[default] Automatic, Strict, Full, Targeted }
impl DnsMode { pub fn raw(self) -> &'static str; pub fn from_raw(s: &str) -> Option<DnsMode> }

/// The connection's own setting (stored in `meta.json` under `dns`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsSetting { pub mode: DnsMode, pub servers: Vec<String>, pub domains: Vec<String>, pub override_vpn: bool }
impl DnsSetting {
    pub fn is_default(&self) -> bool;
    pub fn from_json(v: &Value) -> Option<DnsSetting>;   // None → caller uses default
    pub fn to_json(&self) -> Value;
    pub fn validate(&self) -> Result<(), String>;         // l10n message
    pub fn request(&self) -> Option<DnsRequest>;          // None when default (nothing is sent)
}

/// What the root layer gets (frame lines, root layer 15).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsRequest { pub mode: DnsMode, pub servers: Vec<String>, pub domains: Vec<String>, pub override_vpn: bool }
pub const FRAME_KEYS: [&str; 4] = ["dns-mode", "dns-servers", "dns-domains", "dns-override"];
impl DnsRequest {
    /// `dns-mode=<m>\n` always; `dns-servers=a,b\n` / `dns-domains=a,b\n` when not empty; `dns-override=1\n` when set.
    pub fn frame_lines(&self) -> String;
    /// One line's key and value; `false` if invalid (the frame is then refused whole).
    pub fn accept(&mut self, key: &str, value: &str) -> bool;
    pub fn valid(&self) -> bool;
}
pub fn is_dns_server(s: &str) -> bool;   // IPv4/IPv6 literal, parsed by std (stricter than the hook's shape check)
pub fn is_dns_domain(s: &str) -> bool;   // same rule as helper::dns::is_search_domain, ≤ 253 bytes
/// Some(true) full tunnel, Some(false) split, None: the server decides (OpenVPN without a local choice).
pub fn full_tunnel_hint(kind: VPNKind, config: &str) -> Option<bool>;
```

  - `Connection` gets `pub dns: DnsSetting`. In `from_json`: `match obj.get("dns") { None | Some(Value::Null) => default, Some(v) => DnsSetting::from_json(v).unwrap_or_default() }`. In `to_json`: insert only when `!is_default()`.
  - Move `is_search_domain`'s rule to core and let `helper::macos::dns::is_search_domain` call it, so there is one rule.
- [x] **Step 3:** `cargo test -p macvpn-core --test dns_settings --test models --test compat_swift --test vault_connections --test vault_backup` must pass. The existing golden JSONs must stay unchanged.
- [x] **Step 4:** commit `core: per-connection DNS settings model and the up frame's DNS lines`.

## Task 2: DNS query encoding and answer parsing (pure)

**Files:** create `crates/core/src/dns_wire.rs` and `crates/core/tests/dns_wire.rs`.

- [x] **Step 1: tests:**
  - `query_bytes_for_apple_com`: exact bytes, `[id, 0x01,0x00, 0,1, 0,0, 0,0, 0,0, 5 a p p l e 3 c o m 0, 0,1, 0,1]`;
  - `resolved_with_a_record`;
  - `resolved_through_cname_compression`: a CNAME, then an A, with `0xC0 0x0C` pointers;
  - `truncated_noerror_counts_as_resolved`;
  - `nxdomain`, `servfail`, `refused`;
  - `noerror_without_answer_and_ra0_is_no_recursion`;
  - `wrong_id_is_mismatch`, `not_a_response_is_malformed`, `question_must_echo`;
  - `pointer_loop_is_malformed`: a self-pointing name stops after 128 steps;
  - `short_and_overlong_rdata_are_malformed`.
- [x] **Step 2: implement:**

```rust
pub const PROBE_NAME: &str = "apple.com";
pub const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer { Resolved, NoRecursion, Empty, NxDomain, ServFail, Refused, OtherRcode(u8), Mismatch, Malformed }
impl Answer { pub fn ok(self) -> bool { self == Answer::Resolved } }

pub fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(18 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // RD
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QDCOUNT 1
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    q
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> { Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?])) }

/// The index after a (possibly compressed) name; bounded, no pointer is followed (only skipped).
fn skip_name(b: &[u8], mut i: usize) -> Option<usize> {
    for _ in 0..128 {
        let len = *b.get(i)? as usize;
        match len & 0xC0 {
            0x00 if len == 0 => return Some(i + 1),
            0x00 => i += 1 + len,
            0xC0 => { b.get(i + 1)?; return Some(i + 2); }
            _ => return None,
        }
    }
    None
}

pub fn parse_answer(resp: &[u8], query: &[u8]) -> Answer {
    if resp.len() < 12 || query.len() < 12 { return Answer::Malformed; }
    if resp[0..2] != query[0..2] { return Answer::Mismatch; }
    let (f1, f2) = (resp[2], resp[3]);
    if f1 & 0x80 == 0 || (f1 >> 3) & 0x0F != 0 { return Answer::Malformed; }   // QR, opcode QUERY
    if u16_at(resp, 4) != Some(1) { return Answer::Malformed; }
    let qend = 12 + (query.len() - 12);
    if resp.get(12..qend) != Some(&query[12..]) { return Answer::Mismatch; }
    let tc = f1 & 0x02 != 0;
    let ra = f2 & 0x80 != 0;
    match f2 & 0x0F {
        0 => {}
        2 => return Answer::ServFail,
        3 => return Answer::NxDomain,
        5 => return Answer::Refused,
        r => return Answer::OtherRcode(r),
    }
    if tc { return Answer::Resolved; }
    let Some(ancount) = u16_at(resp, 6) else { return Answer::Malformed };
    let mut i = qend;
    let mut a = 0;
    for _ in 0..ancount {
        let Some(j) = skip_name(resp, i) else { return Answer::Malformed };
        let (Some(t), Some(c), Some(len)) = (u16_at(resp, j), u16_at(resp, j + 2), u16_at(resp, j + 8)) else {
            return Answer::Malformed;
        };
        let end = j + 10 + len as usize;
        if end > resp.len() { return Answer::Malformed; }
        if t == TYPE_A && c == CLASS_IN {
            if len != 4 { return Answer::Malformed; }
            a += 1;
        }
        i = end;
    }
    if a > 0 { Answer::Resolved } else if !ra { Answer::NoRecursion } else { Answer::Empty }
}
```

- [x] **Step 3:** `cargo test -p macvpn-core --test dns_wire`. Commit `core: minimal DNS query and answer parser for the probe`.

## Task 3: Reverse zones and domain overlap (pure)

**Files:** create `crates/core/src/dns_zones.rs` and `crates/core/tests/dns_zones.rs`.

- [x] **Step 1: tests:**
  - `v4_octet_boundaries`: `10.0.0.0/8` → `["10.in-addr.arpa"]`, `192.168.50.0/24` → `["50.168.192.in-addr.arpa"]`;
  - `v4_small_expansion`: `10.1.2.0/23` → `["2.1.10.in-addr.arpa","3.1.10.in-addr.arpa"]` (up to 4 expanded);
  - `v4_large_rounds_down`: `172.16.0.0/12` → `["172.in-addr.arpa"]`. Expanding a `/12` would take 16 `/16` zones, more than 4, so the prefix rounds down to its `/8` zone;
  - `host_routes_give_the_24`: a `/32` → its `/24` zone;
  - `v6_nibbles`: `fd00:1234::/32` → `4.3.2.1.0.0.d.f.ip6.arpa`;
  - `default_and_public_are_skipped`: `is_private` allows `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, `fc00::/7`, `169.254/16` (not added; mDNS owns it);
  - `covered_by`: `lan` is covered by `lan`; `x.corp.example` by `corp.example`; `example` is **not** covered by `corp.example`. The overlap rule: a local domain or zone is dropped when it equals, or lies under, a VPN domain or zone; a local **parent** of a VPN domain stays (longest match already gives the VPN its names).
- [x] **Step 2: implement:**

```rust
pub fn is_private(p: &IpPrefix) -> bool;
/// The reverse zones covering `p`: octet (IPv4) or nibble (IPv6) boundaries; up to 4 zones by expansion, else the
/// zone rounded down; none for a prefix shorter than /8 (IPv4) or /16 (IPv6).
pub fn reverse_zones(p: &IpPrefix) -> Vec<String>;
pub fn covered_by(domain: &str, by: &[String]) -> bool;  // case-insensitive, trailing dot ignored, label-wise
pub const MAX_ZONES: usize = 32;                          // per entry, the rest dropped (logged by the caller)
```

- [x] **Step 3:** `cargo test -p macvpn-core --test dns_zones`. Commit `core: reverse zones and domain overlap for split DNS`.

## Task 4: The mode decision table and the entries (pure, helper)

**Files:** create `crates/helper/src/macos/dns_plan.rs` (with a `#[cfg(test)] mod tests`); modify `crates/helper/src/macos/mod.rs` (`mod dns_plan;`).

- [x] **Step 1: tests (names and assertions):**
  - `no_servers_is_none_with_hint`: every mode with no effective servers gives `Layout::None` and `Warn::NoDns`.
  - `automatic_ok_or_not_yet_is_vpn_with_local`.
  - `automatic_failed_is_fallback_on_split_and_full`: `Warn::Fallback { full_tunnel }` carries the tunnel.
  - `strict_never_falls_back`: a failed probe gives `Vpn{local:false}` + `Warn::Failing`.
  - `full_failed_keeps_vpn_with_local_and_warns`.
  - `targeted_split_is_split_and_needs_no_probe`.
  - `targeted_on_full_tunnel_acts_as_automatic`: logged with `Warn::TargetedOnFullTunnel`.
  - `targeted_without_domains_warns`.
  - `effective_dns_merge`:
    - the VPN's servers win, unless there are none or `override`;
    - own domains are always match domains;
    - own domains become search domains only when the VPN sent none or with `override`.
  - Entries:
    - `entries_vpn_layout`: exact dictionaries per R3a, with `NoSearch = 1` on all three entries and the override list `vpn ++ original search`;
    - `entries_split_layout_has_no_override_and_search_entry_without_nosearch`;
    - `local_entry_drops_overlaps`: home `corp.example` when the VPN has `corp.example` → dropped; local reverse zone inside a routed VPN prefix → dropped;
    - `strict_has_no_local_entry`;
    - `override_skips_vpn_like_services`;
    - `entries_are_capped`.
- [x] **Step 2: implement the table:**

```rust
use macvpn_core::dns_settings::DnsMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Tunnel { Full, Split, Unknown }
#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum Probe { NotRun, Ok, Failed }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout { None, Vpn { local: bool }, Split, Fallback }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warn { NoDns, Fallback { full_tunnel: bool }, Failing, TargetedOnFullTunnel, TargetedNoDomains }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision { pub layout: Layout, pub warn: Option<Warn>, pub probes: bool }

/// The whole mode logic. `Tunnel::Unknown` (before the routes are in, i.e. in the hook) counts as split for
/// Targeted and is otherwise irrelevant; the after-connect pass decides again with the real tunnel.
pub fn decide(mode: DnsMode, tunnel: Tunnel, has_servers: bool, has_match: bool, probe: Probe) -> Decision {
    use {DnsMode::*, Layout::*};
    if !has_servers {
        return Decision { layout: None, warn: Some(Warn::NoDns), probes: false };
    }
    let full = tunnel == Tunnel::Full;
    let (mode, note) = match mode {
        Targeted if full => (Automatic, Some(Warn::TargetedOnFullTunnel)),
        m => (m, Option::None),
    };
    let d = |layout, warn: Option<Warn>, probes| Decision { layout, warn: warn.or(note), probes };
    match (mode, probe) {
        (Targeted, _) => d(Split, (!has_match).then_some(Warn::TargetedNoDomains), false),
        (Automatic, Probe::Failed) => d(Fallback, Some(Warn::Fallback { full_tunnel: full }), true),
        (Automatic, _) => d(Vpn { local: true }, Option::None, true),
        (Full, Probe::Failed) => d(Vpn { local: true }, Some(Warn::Failing), true),
        (Full, _) => d(Vpn { local: true }, Option::None, true),
        (Strict, Probe::Failed) => d(Vpn { local: false }, Some(Warn::Failing), true),
        (Strict, _) => d(Vpn { local: false }, Option::None, true),
    }
}
```

The same table in words:

| VPN servers | Mode | Tunnel | Probe | Layout | Warning | Probes later |
|---|---|---|---|---|---|---|
| none | any | any | – | None | NoDns (hint in log, status `none`) | no |
| yes | Automatic | any | ok / not run | Vpn{local} | – | yes |
| yes | Automatic | any | failed | Fallback (VPN domains on VPN DNS, rest on original) | Fallback{full_tunnel} (notice) | yes (recovery) |
| yes | Full | any | ok / not run | Vpn{local} | – | yes |
| yes | Full | any | failed | Vpn{local} | Failing (notice) | yes |
| yes | Strict | any | ok / not run | Vpn (no local entry) | – | yes |
| yes | Strict | any | failed | Vpn (no local entry) | Failing (notice) | yes |
| yes | Targeted | split/unknown | – | Split | TargetedNoDomains if no match domains | no |
| yes | Targeted | full | as Automatic | as Automatic | + TargetedOnFullTunnel (log) | yes |

- [x] **Step 3: the inputs and entries:**

```rust
pub struct Effective { pub servers: Vec<String>, pub search: Vec<String>, pub resolve: Vec<String>, pub zones: Vec<String> }
/// VPN-sent (pushed / WireGuard `DNS =` / pppd) merged with the connection's own request (Task 1 semantics).
pub fn effective(pushed: &Pushed, req: &DnsRequest, routed: &[IpPrefix]) -> Effective;

pub struct Original { pub sid: String, pub present: bool, pub dict: Dict }   // Setup: value before us
pub struct Primary { pub sid: String, pub servers: Vec<String>, pub search: Vec<String>, pub local_domains: Vec<String>, pub local_zones: Vec<String> }

pub enum Op { Set(String, Dict), Remove(String) }   // key, value
/// The dynamic-store operations that bring this connection's entries to `layout` (R3a), without the overrides.
pub fn own_entries(id: &str, layout: Layout, e: &Effective, primary: Option<&Primary>) -> Vec<Op>;
/// The override of every service for the newest Vpn-layout owner (or the restore when `owner` is None).
pub fn overrides(owner: Option<(&str, &Effective, bool /*local*/)>, originals: &[Original], current: &[(String, Option<Dict>)]) -> Vec<Op>;
```

`Dict` is the small value tree of `dns_store` (Task 5): `enum Value { Str(String), Int(i64), Array(Vec<Value>), Dict(BTreeMap<String, Value>) }`. The VPN search entry in code:

```rust
fn vpn_entry(id: &str, servers: &[String], domains: &[String], no_search: bool, order: i64) -> Dict {
    let mut d = Dict::new();
    d.insert("ServerAddresses".into(), strings(servers));
    d.insert("SupplementalMatchDomains".into(), strings(domains));
    d.insert("SearchOrder".into(), Value::Int(order));
    if no_search { d.insert("SupplementalMatchDomainsNoSearch".into(), Value::Int(1)); }
    d.insert("MacVPNOwner".into(), Value::Str(id.into()));
    d
}
// key: format!("State:/Network/Service/macvpn-{id}/DNS"), "-match", "-local" as in R3a
fn override_of(id: &str, original: &Dict, servers: &[String], search: &[String]) -> Dict {
    let mut d = original.clone();
    d.insert("ServerAddresses".into(), strings(servers));
    d.insert("SearchDomains".into(), strings(search));   // empty → key removed
    d.insert("MacVPNOwner".into(), Value::Str(id.into()));
    d
}
```

- [x] **Step 4:** `cargo test -p macvpn-helper macos::dns_plan`. Commit `helper: DNS mode decision table and dynamic-store entries (pure)`.

## Task 5: The dynamic-store layer behind a trait, with fakes

**Files:** create `crates/helper/src/macos/sc_store.rs` and `crates/helper/src/macos/dns_store.rs`; modify `crates/helper/src/macos/paths.rs` (`Settings.dynstore: Option<PathBuf>` from `MVPN_DYNSTORE`, test mode only) and `mod.rs`.

- [x] **Step 1: `sc_store.rs` FFI** (same audit-note style and create/get-rule wrappers as `sc_prefs.rs`):
  - `SCDynamicStoreCreate(NULL, CFSTR("mvpn"), NULL, NULL)`;
  - `SCDynamicStoreCopyValue`, `SCDynamicStoreSetValue`, `SCDynamicStoreRemoveValue`, `SCDynamicStoreCopyKeyList(store, pattern)` (regex pattern);
  - optionally `SCDynamicStoreSetMultiple(store, set, remove, NULL)` for one atomic batch per change (preferred: IPMonitor then recomputes once).
  - Conversion `Value` ⇄ CF (`CFString`, `CFNumber` (i64), `CFArray`, `CFDictionary`). Anything else read back is `None` (strict).
- [x] **Step 2: `dns_store.rs`:**

```rust
pub trait Store {
    fn get(&self, key: &str) -> Option<Value>;
    fn keys(&self, pattern: &str) -> Vec<String>;
    /// One batch: all sets and removes together (SCDynamicStoreSetMultiple); false on failure (logged by caller).
    fn apply(&self, ops: &[Op]) -> bool;
}
pub struct ScStore(sc_store::Session);   // as root
pub struct MemStore(RefCell<BTreeMap<String, Value>>);   // unit tests; `seed_primary(sid, servers, domain)` helper
pub struct FileStore { dir: PathBuf }    // test mode: one file per key (key percent-encoded), value as JSON
pub fn store(s: &Settings) -> Option<Box<dyn Store>>;   // root: ScStore; test mode: FileStore only with MVPN_DYNSTORE
```

  - `FileStore` also lets `scripts/test-root.sh` seed `State:/Network/Global/IPv4`, `Setup:/Network/Global/IPv4` and the primary's `State:` DNS / IPv4, and assert the results with `cat`.
  - **Facts the manager reads**, through a helper `fn network(store) -> NetFacts { primary_sid, service_order, per-service Setup:/State: DNS, primary IPv4 Addresses/SubnetMasks, IPv6 Addresses/PrefixLength }`:
    - `State:/Network/Global/IPv4` (`PrimaryService`);
    - `Setup:/Network/Global/IPv4` (`ServiceOrder`);
    - `Setup:/Network/Service/<sid>/DNS`, `State:/Network/Service/<sid>/DNS` (`ServerAddresses`, `SearchDomains`, `DomainName`);
    - `State:/Network/Service/<sid>/IPv4` (`Addresses`, `SubnetMasks`, `InterfaceName`), `State:/Network/Service/<sid>/IPv6`.
    - `State:/Network/Global/DNS` (verification only).
- [x] **Step 3: tests:**
  - `mem_store_batches_and_patterns`;
  - `file_store_round_trips_values_and_escapes_keys`;
  - `value_cf_round_trip`: CF conversion without root (CF objects need no daemon);
  - an `#[ignore = "reads the live dynamic store: cargo test -p macvpn-helper sc_store -- --ignored"]` test `reads_this_macs_primary_dns`, which is **read-only** and asserts that the `PrimaryService` from `State:/Network/Global/IPv4` has a `State:` DNS key or none (no panic). Writing to the real store is tested only live (Task 16).
- [x] **Step 4:** `cargo test -p macvpn-helper macos::dns_store macos::sc_store`. Commit `helper: SCDynamicStore access behind a Store trait with fakes`.

## Task 6: The UDP probe

**Files:** create `crates/helper/src/macos/dns_probe.rs` and `crates/helper/tests/dns_probe.rs`; modify `paths.rs` (`Settings.dns_probe: Option<String>` from `MVPN_DNS_PROBE=ok|fail`, test mode only).

- [x] **Step 1: tests** (integration, with a fake server on `127.0.0.1:<port>`, so the port is a parameter of the inner function):
  - `resolves_against_a_fake_recursive_server`;
  - `refused_server_fails`;
  - `silent_server_times_out_within_bound`: ≤ 2 × timeout + slack;
  - `wrong_id_is_ignored_then_right_answer_counts`;
  - `first_good_server_wins_and_at_most_three_are_asked`.
- [x] **Step 2: implement:**

```rust
pub const TIMEOUT: Duration = Duration::from_millis(1500);
pub const MAX_SERVERS: usize = 3;
pub fn probe_server(addr: SocketAddr, timeout: Duration) -> Answer;   // 2 sends, ID from uuid::Uuid::new_v4() bytes
pub fn probe(s: &Settings, servers: &[String]) -> (Probe, String /*log detail: per-server Answer*/);
```

  In test mode, `probe()` returns what `MVPN_DNS_PROBE` says and never opens a socket to a real server. Without it, the result is `Probe::NotRun`.
- [x] **Step 3:** `cargo test -p macvpn-helper --test dns_probe`. Commit `helper: the DNS probe (one A query for apple.com, bounded)`.

## Task 7: The `up` frame's DNS lines and their path from the app

**Files:**
- modify `crates/helper/src/shared/framing.rs` and `crates/core/src/helper_args.rs`;
- modify `crates/platform-api/src/helper.rs`, `crates/platform-mac/src/mvpn_client.rs` and `src/api/adapters.rs`;
- modify the Linux and Windows `HelperClient` implementations and the fakes (R6 list);
- modify `crates/app-core/src/manager.rs`;
- modify `crates/helper/src/macos/updown.rs` and create `crates/helper/src/macos/dns_session.rs`.

- [x] **Step 1: tests:**
  - framing:
    - `dns_lines_are_parsed_once_each`;
    - `dns_lines_invalid_refuse_the_frame`;
    - `dns_lines_are_not_masked`: they are not in `Secrets::masker`;
    - `validate_still_takes_no_tail`.
  - helper_args:
    - `up_stdin_appends_dns_lines_after_the_secrets`;
    - `no_request_no_lines`: frames byte-identical to today's.
  - mvpn_client: `dns_lines_only_for_root_15_or_newer`. The installed root version comes from the cached `mvpn version` (the client asks once per app run, using the same call as `setup_checker`); unknown counts as < 15. When not sent, the app logs the hint "Update the system component to use this connection's DNS settings."
  - dns_session:
    - `request_file_round_trip`;
    - `request_file_must_be_root_private`: in test mode, the owner check is skipped and the mode check stays;
    - `session_file_round_trip`.
- [x] **Step 2: implement.**
  - `Secrets.dns: DnsRequest` (`parse_lines` gains four slots, `seen: [bool; 13]`).
  - `HelperClient::up(&self, kind, id, config, secrets, debug, accept_risky, dns: Option<&DnsRequest>)`.
  - `manager.rs` passes `c.dns.request().as_ref()` for OpenVPN, WireGuard and SSTP, and `None` for everything else.
  - In `updown::up`, after `run_dir::prepare`, `dns_session::write_request(run, &ctx.secrets.dns)` writes `<run>/dns-request` (0600, `mode=…\nservers=…\ndomains=…\noverride=0|1\n`). The hook and `after_connect` read it back with the same strict parser.
  - `dns-session` (written by the manager, Task 8) holds `mode, tunnel, layout, probe, fails, warn, servers, search, resolve, zones, since`.
- [x] **Step 3:** `cargo test -p macvpn-helper shared::framing macos::dns_session && cargo test -p macvpn-core --test helper_args && cargo test -p macvpn-platform-mac mvpn_client && cargo test -p macvpn-app-core manager`. Then `scripts/check-windows.sh`, because the trait is shared. Commit `DNS settings travel to the root layer in the up frame (root layer 15)`.

## Task 8: The dynamic-store DNS manager and the legacy restore

**Files:** move the 14 ledger code to `crates/helper/src/macos/dns_legacy.rs`; rewrite `crates/helper/src/macos/dns.rs`; modify `ctx.rs` and `status.rs`.

- [x] **Step 1: move, no behaviour change.**
  - `git mv` the ledger manager into `dns_legacy.rs` (`Ledger`, `Manager` without `acquire`, `NetworkSetup`, `restore_legacy`, `owner_targets`, `same`, and the whole test module).
  - `dns_sc.rs` / `sc_prefs.rs` now serve only `dns_legacy`.
  - `cargo test -p macvpn-helper macos::dns_legacy` must stay green. Drop only the `acquire` tests that now belong to the new manager.
  - Add `legacy_ledger_is_restored_without_owners_alive` (the upgrade case).
- [x] **Step 2: tests for the new manager** (`dns.rs` tests over `MemStore` + a temp lock dir):
  - `acquire_vpn_layout_writes_entries_overrides_and_ledger`;
  - `release_last_owner_restores_every_override_and_removes_all_keys`;
  - `release_restores_only_values_still_ours`: a foreign rewrite is left alone and logged;
  - `stacking_newest_vpn_owner_holds_the_override_older_split_entries_stay`;
  - `stacking_newest_leaves_previous_vpn_owner_takes_override_again`;
  - `two_split_owners_coexist`;
  - `reconcile_drops_dead_owner_keys_by_pattern`: no run dir is needed for the cleanup;
  - `reconcile_repairs_drift_after_preferences_rewrite`: our `Setup:` value replaced by a value without `MacVPNOwner` is re-applied, and `Originals` takes the new value as the original;
  - `reconcile_overrides_a_newly_listed_service`;
  - `reconcile_without_ledger_reads_one_key_and_returns`: counts `Store::get` calls, which is the energy guard;
  - `reconcile_runs_the_legacy_restore_first`;
  - `check_failed_twice_falls_back_and_ok_once_returns`;
  - `check_on_strict_never_changes_layout`;
  - `fallback_keeps_vpn_domains_on_vpn_dns`;
  - `no_servers_writes_nothing_and_records_none`;
  - `verification_reads_global_dns`: after the batch, `State:/Network/Global/DNS` `ServerAddresses` is polled (≤ 10 × 100 ms) and the result logged. With `MemStore` the test simulates IPMonitor by copying.
- [x] **Step 3: implement the API:**

```rust
pub struct Manager { pub lock_dir: PathBuf, pub store: Box<dyn Store>, pub flush: Box<dyn Fn()> /* dscacheutil -flushcache; no-op in tests */ }
pub fn manager(s: &Settings) -> Option<Manager>;          // root: ScStore + /var/db/macvpn/dns; test: FileStore only with MVPN_DYNSTORE
impl Manager {
    /// From the hook / WireGuard / SSTP: VPN-sent DNS + the connection's request; tunnel Unknown; probe NotRun.
    pub fn acquire(&self, id: &str, run: &Path, pushed: &Pushed, log: &Log);
    /// After connect (updown::up): tunnel detection, probe, decision, re-publish; writes <run>/dns-session.
    pub fn after_connect(&self, s: &Settings, id: &str, run: &Path, iface: &str, log: &Log) -> DnsState;
    /// `dns-check <id>`: probe again when the session probes; apply the 2-fail / 1-ok rule; re-publish on change.
    pub fn check(&self, s: &Settings, id: &str, run: &Path, log: &Log) -> DnsState;
    pub fn release(&self, id: &str, log: &Log) -> bool;
    /// Legacy restore first; then dead owners dropped; then drift / new services repaired (cheap when nothing to do).
    pub fn reconcile(&self, alive: &dyn Fn(&str) -> bool, log_for: &dyn Fn(&str) -> Log, wait: bool);
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DnsState { Vpn, Targeted, Fallback, FallbackFullTunnel, Failing, None }   // raw: vpn|targeted|fallback|fallback-full|failing|none
```

  - `acquire` reads the request from `<run>/dns-request`. A missing file means `DnsRequest::default()`, i.e. Automatic: this is the case for an `up` from an older app.
  - **Limits.** An over-limit VPN list (`Dns::within_limits`) is refused whole as today (`log_over_limits`). In Automatic mode the connection then has no VPN DNS, and the own DNS applies when it is set.
  - **Log lines (EN keys, Task 14):**
    - "DNS mode: %@";
    - "the VPN's DNS is in effect (%@ servers, %@ domains), verified";
    - "the VPN's DNS does not resolve internet names (%@): only the VPN's domains use it now";
    - "the VPN's DNS answers again: it is in effect for every name";
    - "Strict DNS: the VPN's DNS does not answer (%@); DNS stays in the tunnel";
    - "the VPN sent no DNS; internal names will not resolve";
    - "the local network's names stay on its DNS: %@";
    - "full tunnel: the Targeted mode acts as Automatic";
    - "a DNS setting was changed by the system meanwhile and is left as it is".
  - `ctx.dns_set` → `acquire`; `ctx.dns_restore` → `release` + legacy `dns-backup` as today.
  - `status::render` adds `dns` from `<run>/dns-session` (Task 10).
- [x] **Step 4:** `cargo test -p macvpn-helper macos::dns macos::dns_legacy macos::hook_dns`. Commit `helper: DNS through the dynamic store, root layer 14 ledger restore-only`.

## Task 9: Hook, OpenVPN, WireGuard and SSTP integration; after-connect

**Files:** modify `hook_dns.rs`, `openvpn.rs`, `wireguard.rs`, `sstp.rs`, `updown.rs` and `mod.rs` (`hook_paths_ok` unchanged).

- [x] **9a. `--up` compatibility (every OpenVPN version):**
  - `HookEnv::options()` also accepts `dhcp-option DNS6 <v6>` and `dhcp-option DOMAIN-SEARCH <d>`.
  - Reads `route_network_{n}` / `route_netmask_{n}` / `route_ipv6_network_{n}`. These are the routed private networks used for the reverse zones. They are added to the allowlist and to the `only_allowlisted_names_are_read` test.
  - `up()` writes `<run>/iface`, `<run>/ip` and `<run>/routes`, then calls `Manager::acquire`. The message "the server sent no DNS" stays; the own DNS may still apply.
  - Tests:
    - `dns6_and_domain_search_are_accepted`;
    - `routes_are_read_strictly`: a bad network or mask is dropped;
    - `up_without_pushed_dns_uses_own_servers`;
    - `up_with_override_ignores_pushed`.
- [x] **9b. OpenVPN ≥ 2.7: `--dns-updown <hook>` (for `resolve-domains`):**
  - `openvpn::up` runs `<openvpn> --version` once (minimal env, 1 MB cap) and parses `^OpenVPN (\d+)\.(\d+)`. When the version is ≥ 2.7, it appends `--dns-updown "<hook>"` (the same string as `--up`).
  - The hook handles `script_type=dns-up` / `dns-down`:
    - it reads `dns_search_domain_{n}`, `dns_server_{n}_address_{m}`, `_port_{m}`, `_resolve_domain_{m}`, `_dnssec`, `_transport` (allowlisted);
    - or `dns_vars_file`: a regular file, not a symlink, ≤ 64 KiB, `NAME=value` lines, names restricted to the same allowlist, never sourced.
  - It picks the first profile with plain transport, no DNSSEC and port 53, as OpenVPN's own `find_compat_profile` does.
  - `dns-up` → `acquire`; `dns-down` → nothing (the `--down` hook releases), so the order stays the same as on 2.6.
  - `--up` then only records iface/ip/routes. A marker `<run>/dns-updown` tells it not to say "no DNS".
  - Tests:
    - `version_parse`;
    - `dns_updown_only_from_2_7`;
    - `dns_vars_file_strict`: symlink, oversize, unknown name and `$(…)` value are each refused or kept literal;
    - `first_compatible_profile`;
    - `resolve_domains_reach_the_match_entry`.
- [x] **9c. WireGuard:**
  - `wireguard::up` keeps `strip_dns`, then calls `ctx.dns_set_pushed(&Pushed { servers, search, routes: AllowedIPs })`. The private `AllowedIPs` go to the reverse zones.
  - Test: `allowed_ips_feed_the_reverse_zones`.
- [x] **9d. SSTP:**
  - The DNS hook is called also when `peer_dns == "no"` (no `foreign_option`), so the own DNS applies.
  - Test: `sstp_without_peer_dns_still_calls_the_dns_step` (`test-root.sh`, Task 16).
- [x] **9e. After connect:**
  - In `updown::up`, right after `up_kind(ctx)?` and before `connection established`, when not a dry run: `dns::after_connect(ctx)`.
  - It reads `<run>/iface` (WireGuard: the `utun` from `/var/run/wireguard/<iface>.name`) and runs the tunnel detection through `ctx.s.route` (R4).
  - It runs the probe when `decide(..).probes` holds, then applies and logs.
  - A probe failure **never** fails `up`.
- [x] **Step:** `cargo test -p macvpn-helper macos::hook_dns macos::openvpn macos::wireguard macos::sstp macos::updown`. Commit `helper: OpenVPN/WireGuard/SSTP DNS through the new manager; probe after connect`.

## Task 10: `status` field and the `dns-check` request

**Files:**
- modify `crates/helper/src/shared/status_json.rs`, `crates/helper/src/macos/status.rs`, `serve.rs` and `mod.rs`;
- modify `crates/core/src/status.rs`;
- modify `crates/platform-mac/src/mvpn_client.rs` and `crates/platform-api/src/helper.rs`;
- modify `crates/helper/tests/query_daemon.rs`.

- [x] **Step 1: tests:**
  - `golden_unchanged_without_dns`: `GOLDEN_1_4` stays identical;
  - `dns_key_rendered_when_set`;
  - `root_status_parses_dns_and_ignores_unknown_values`: an unknown value counts as absent;
  - serve:
    - `only_the_four_questions_are_understood`: rename `only_the_three_questions_are_understood`, plus `dns-check <uuid>`;
    - `dns_check_answers_the_state_line`;
  - `query_daemon.rs`: `dns_check_over_the_socket`.
- [x] **Step 2: implement.**
  - `"dns": "vpn|targeted|fallback|fallback-full|failing|none"`, present only when `<run>/dns-session` exists.
  - `Request::DnsCheck(String)`, `const DNS_CHECK: &str = "dns-check"` in `macvpn_core::status`. The answer is `0\n<state>\n`, or `1\n` when the connection is not running.
  - The CLI arm is `"dns-check" => …` in `mod.rs`, under the same `is_uuid` check.
  - Update the `serve.rs` doc comment: `dns-check` may re-publish **this connection's own** DNS layout, the same class of change as the reconcile `status` already does (open point O4).
  - Client: `MvpnClient::dns_check(id) -> Option<DnsState>` via `read_only`; `HelperClient::dns_check` on macOS.
- [x] **Step 3:** `cargo test -p macvpn-helper shared::status_json macos::serve && cargo test -p macvpn-helper --test query_daemon && cargo test -p macvpn-core --test status`. Commit `helper: dns state in status and the dns-check question`.

## Task 11: App model and editor UI

**Files:**
- modify `crates/app-core/src/editor.rs` and `connections.rs`;
- modify `app/src-tauri/src/manage.rs` (and its `EditorFields` strictness tests);
- modify `app/ui/src/lib/api.ts`, `manage/TextEditor.svelte` and `manage/SstpForm.svelte`;
- create `manage/DnsFields.svelte`, `manage/dnsFields.ts` and `dnsFields.test.ts`.

- [x] **Step 1: tests:**
  - app-core:
    - `dns_fields_deserialize_strictly`;
    - `save_dns_saves_meta_only`: the config is untouched, as `save_otp`;
    - `invalid_dns_fields_are_refused_with_message`.
  - Tauri: `editor_fields_with_dns_round_trip`.
  - UI (`dnsFields.test.ts`):
    - `visible only on macOS for openvpn/wireguard/sstp`;
    - `targeted hidden when full_tunnel_hint is true`;
    - `override needs servers`;
    - `servers and domains split on commas/spaces/newlines`.
- [x] **Step 2: implement.**
  - `DnsFields { mode: String, servers: Vec<String>, domains: Vec<String>, override_vpn: bool }` with `#[serde(rename_all = "camelCase", deny_unknown_fields)]`, inside `TextFields` and `SstpFields` as `dns: Option<DnsFields>`. It is optional so the Linux and Windows UIs send nothing.
  - `EditorPlatformView` gets `dns_visible: bool` (macOS and a supported kind) and `full_tunnel: Option<bool>` (from `full_tunnel_hint`).
  - `DnsFields.svelte`:
    - **Mode:** a radio group: Automatic (recommended) / Full / Targeted / Strict, each with a one-line explanation.
    - **"Own DNS servers"** and **"Own domains"**: text areas.
    - **"Use these instead of the VPN's DNS"**: a check box (override).
    - A grey note when Targeted is chosen and `full_tunnel` is `None` ("If the server sends all traffic through the VPN, Targeted works like Automatic.").
- [x] **Step 3:** `cargo test -p macvpn-app-core editor connections && cargo test -p macvpn-app manage && (cd app/ui && npm test -- dnsFields)`. Commit `app: per-connection DNS mode and own DNS in the editor (macOS)`.

## Task 12: Notices, row hints and the dns-check schedule

**Files:**
- modify `crates/app-core/src/connection_notices.rs`, `view_model.rs` and `liveness.rs` (or create `dns_check.rs`);
- modify `app/src-tauri/src/notifications.rs`, `state.rs` and `reconnect.rs`;
- modify `app/ui/src/lib/manage/Detail.svelte` and `api.ts`.

- [x] **Step 1: tests:**
  - notices:
    - `fallback_notice_on_entering_fallback_only_once`;
    - `full_tunnel_fallback_text_mentions_outside_the_tunnel`;
    - `failing_notice_for_strict_and_full`;
    - `restored_notice_only_after_a_fallback_notice`;
    - `no_notice_for_none_but_row_hint`;
    - `texts_are_lock_screen_safe`: no address or server name in them.
  - schedule (pure):
    - `due_every_5_minutes_when_probing_state`;
    - `due_15s_after_network_switch`;
    - `never_when_asleep_offline_or_targeted_or_none`;
    - `one_check_in_flight_per_connection`.
- [x] **Step 2: implement.**
  - `Notice::DnsFallback { key, name, full_tunnel: bool }`, `Notice::DnsFailing { key, name }`, `Notice::DnsRestored { key, name }`, raised by `NoticeTracker::on_dns(key, name, old: Option<DnsState>, new: Option<DnsState>)` from the status poll.
  - `RowView.dns_note: Option<String>` (`skip_serializing_if`):
    - `none` → "The VPN sent no DNS; internal names will not resolve."
    - `fallback` / `fallback-full` → the notice body;
    - `failing` → "The VPN's DNS does not answer."
  - The `DNS_CHECK_INTERVAL = 300 s` / `DNS_SWITCH_DELAY = 15 s` schedule rides on the existing liveness tick and gate (`liveness_due`). No new timer and no extra wake-ups.
- [x] **Step 3:** `cargo test -p macvpn-app-core connection_notices view_model liveness && cargo test -p macvpn-app notifications reconnect`. Commit `app: DNS fallback notices, hints and the periodic dns-check`.

## Task 13: Catalog, backup and export decisions (small)

**Files:** `crates/core/src/vault/backup.rs` (restore keeps `dns`), and **only if O5 is decided "catalog-owned"**: `catalog/payload.rs` allowlist + `planner.rs` hash + `vault/catalog_apply.rs`.

- [x] Test `backup_restore_keeps_dns`. The export does not carry DNS (`exporter_does_not_export_dns`, the same as `otp`). Commit `core: DNS settings in backup restore`.

## Task 14: l10n EN/HU

**Files:** `crates/core/l10n/strings.json` (or a fragment `crates/core/l10n/dns/*.json` + `node scripts/l10n-merge.mjs`).

- [x] Add every new key with `hu`. Use `scope: "mvpn"` for the helper's log lines, `"app"` for the UI and notices, and `only: ["macos"]` for all of them. The main user-facing texts:

| EN | HU |
|---|---|
| DNS | DNS |
| Automatic (recommended) | Automatikus (ajánlott) |
| Every name through the VPN's DNS; if it cannot resolve internet names, only the VPN's domains use it. | Minden név a VPN DNS-én át; ha az internetes neveket nem oldja fel, csak a VPN tartományai használják. |
| Full | Teljes |
| Every name through the VPN's DNS, also when it does not work. The local network's own names stay local. | Minden név a VPN DNS-én át, akkor is, ha nem működik. A helyi hálózat saját nevei helyben maradnak. |
| Targeted | Célzott |
| Only the VPN's domains use the VPN's DNS. | Csak a VPN tartományai használják a VPN DNS-ét. |
| Strict | Szigorú |
| DNS never leaves the tunnel, even if the VPN's DNS does not work. | A DNS soha nem hagyja el az alagutat, akkor sem, ha a VPN DNS-e nem működik. |
| Own DNS servers | Saját DNS-kiszolgálók |
| Own domains | Saját tartományok |
| Use these instead of the VPN's DNS | Ezeket használja a VPN DNS-e helyett |
| If the server sends all traffic through the VPN, Targeted works like Automatic. | Ha a kiszolgáló minden forgalmat a VPN-en át küld, a Célzott mód Automatikusként működik. |
| The VPN's DNS does not resolve internet names; only the VPN's domains use it now. | A VPN DNS-e nem oldja fel az internetes neveket; most csak a VPN tartományai használják. |
| Internet names are resolved outside the tunnel meanwhile. | Az internetes neveket addig az alagúton kívül oldja fel a gép. |
| The VPN's DNS works again; every name uses it. | A VPN DNS-e újra működik; minden név azt használja. |
| The VPN's DNS does not answer. | A VPN DNS-e nem válaszol. |
| The VPN sent no DNS; internal names will not resolve. | A VPN nem küldött DNS-t; a belső nevek nem oldódnak fel. |
| Update the system component to use this connection's DNS settings. | Frissítse a rendszerösszetevőt, hogy a kapcsolat DNS-beállításai érvényesüljenek. |

  The helper log lines of Task 8 get HU translations in the same style as the existing `mvpn` entries (`"a szerver nem küldött DNS-t"`).
- [x] `cargo test -p macvpn-app-core --test l10n_coverage && (cd app/ui && npm test -- l10n)`. Commit `l10n: DNS modes and notices (EN/HU)`.

## Task 15: Docs

**Files:**
- `docs/user-guide.en.md` / `docs/user-guide.hu.md`:
  - rewrite §5.6 "DNS while connected": the modes, the fallback, local names, own DNS, what Strict means, and the no-DNS hint;
  - add the root-layer history line "root layer 15 from <version>";
  - update the highlights bullet.
- `docs/architecture.md`: replace "macOS DNS manager (root layer)" with the dynamic-store design. Cover:
  - R3a's table;
  - the volatile ledger;
  - the drift check;
  - legacy restore;
  - the probe and `dns-check`;
  - the OpenVPN 2.7 `--dns-updown` interaction (R3);
  - an update to the query-daemon section (`dns-check`).
- `docs/manual-test-checklist.md`: the live checklist of Task 16.
- `docs/release-notes/<next>.md`: an EN + HU paragraph.

- [x] Commit `docs: DNS modes and the dynamic-store DNS manager (root layer 15)`.

## Task 16: Root layer 15, root tests, full gate and the live checklist

**Files:** `crates/helper/VERSION` (`15`), `crates/helper/src/macos/mod.rs` (`version_is_15`), `scripts/test-root.sh` (the DNS section l.~606–680 rewritten), `docs/manual-test-checklist.md`.

- [x] **test-root.sh** (test mode, `MVPN_DYNSTORE="$T/dyn"` seeded with `State:/Network/Global/IPv4` `{PrimaryService: S1}`, `Setup:/Network/Global/IPv4` `{ServiceOrder: [S1, S2]}`, `State:/Network/Service/S1/DNS` `{ServerAddresses: [192.168.1.1], DomainName: lan}`, `State:/Network/Service/S1/IPv4` `{Addresses: [192.168.1.20], SubnetMasks: [255.255.255.0]}`):
  1. `hook ovpn-dns` up with `dhcp-option DNS 10.8.0.1` + `DOMAIN corp.example` and `MVPN_DNS_PROBE=ok`, then `after_connect` through a fake `route` (`MVPN_ROUTE`):
     - the `Setup:/Network/Service/S1/DNS` and `S2/DNS` overrides carry `MacVPNOwner`;
     - the `macvpn-<id>-local` entry has `lan` + `1.168.192.in-addr.arpa`;
     - `State:/Network/MacVPN/DNS` lists the owner;
     - `status` prints `"dns":"vpn"`.
  2. `MVPN_DNS_PROBE=fail` and `dns-check` twice → the overrides are restored and the `macvpn-<id>` entry has no NoSearch; `"dns":"fallback"`. Then `ok` → `"vpn"`.
  3. Strict + fail → overrides remain, `"failing"`.
  4. Targeted on a split tunnel → no override.
  5. down → every `macvpn-*` key and the ledger key are gone, and S1/S2 `Setup:` are back to absent.
  6. A dead owner (run dir removed) → `status` cleans up.
  7. A legacy 14 ledger with the fake `networksetup` → restored by `status`, and the legacy ledger is removed (keep today's `dns_ledger` helper).
  8. Frame: the `dns-*` lines accepted; a bad one → `Invalid input`.
  9. The hook's environment allowlist (`check-env`) including the new names.
  10. SSTP without `usepeerdns` still calls the DNS step.
- [x] **Full gate:** `scripts/test-all.sh` (or the repo's gate: `cargo test --workspace --locked`, `scripts/test-root.sh`, `scripts/check-windows.sh`, `(cd app/ui && npm test)`), plus `cargo test -p macvpn-helper sc_store -- --ignored` (read-only).
- [x] **The live checklist for the maintainer's Mac** (`docs/manual-test-checklist.md`, root layer 15; each item states what to look at: `scutil --dns`, `scutil` `show`, the connection log, the notice):
  1. Install root layer 15 with a connection up: it is disconnected first, and the 14 ledger (if any) is restored.
  2. OpenVPN split tunnel (lab), Automatic:
     - `scutil --dns` resolver #1 = VPN DNS;
     - a `macvpn-<id>-local` supplemental resolver exists for the home domain / reverse zone;
     - `nas.lan` / the router name resolve;
     - `dig apple.com` works.
  3. A VPN DNS without recursion (lab: a test resolver answering only `lab.example.test`):
     - Automatic falls back within the connect, with a notice;
     - internal names resolve, and internet names resolve through the home DNS.
     - Full tunnel variant: the notice mentions outside the tunnel, and `tcpdump -i en0 port 53` shows where the queries go (settles O2).
  4. Recovery: start the test resolver's recursion → within 5 min (or after a Wi-Fi toggle), full DNS returns and the notice appears.
  5. Strict: the same broken DNS → no fallback, a warning; `tcpdump -i en0 port 53` stays empty.
  6. Targeted with a split-horizon own domain (`portal.<lab domain>`) → only that goes to the VPN DNS.
  7. A VPN without DNS: the hint in the log and in the details. With own servers set, they are used.
  8. Network switch Wi-Fi → Ethernet while connected: resolver #1 stays the VPN DNS immediately, and the new service has the override.
  9. IPv6-only and dual-stack primary network (iPhone USB hotspot), full tunnel: no AAAA or A query leaves on the physical interface in Strict.
  10. Crash: `kill -9` the openvpn → within 10 s with the app open, every `macvpn-*` key is gone and the original DNS is back. Reboot while connected → nothing left (`list State:/Network/Service/macvpn-.*`).
  11. Changing a network setting in System Settings while connected (PreferencesMonitor rewrite) → within one status poll the override is back (drift repair).
  12. WireGuard and SSTP: items 2 and 3 once each.
  13. OpenVPN 2.7 with a server pushing `dns server 1 resolve-domains corp.lab` → the `-match` entry carries it (9b).
- [x] Commit `helper: root layer 15`.

---

## Risks and open points

- **O1 – The `Setup:` override in the dynamic store vs PreferencesMonitor.** configd republishes `Setup:` keys when the preferences change. Our override can then be replaced until the next `reconcile` (status poll ≤ 10 s with the app running; none while the app is quit). This is the same exposure as OpenVPN's own script, and the marker makes the drift check exact. If live tests show a worse effect (e.g. PreferencesMonitor removing a `Setup:…/DNS` key we created for a service without manual DNS), the alternative is to override only the primary and re-apply on `State:/Network/Global/IPv4` change. Settle on the live checklist (item 11).
- **O2 – "Outside the tunnel" in the full-tunnel fallback.** On a `0/1 + 128/1` full tunnel, queries to an original DNS that is not on the local subnet (e.g. `8.8.8.8` from DHCP) may still be routed into the tunnel, unless mDNSResponder scopes the default resolver to `en0` (`if_index 13` on resolver #1 suggests it does). The notice text "resolved outside the tunnel" may be inaccurate either way; it is measured in the live test (item 3). The maintainer may prefer the neutral wording "resolved by the local network's DNS".
- **O3 – `--dns-updown` on OpenVPN 2.7 (Task 9b)** brings `resolve-domains` (and ports/DNSSEC filtering), at the price of one `openvpn --version` per connect and a stricter hook. Without 9b, Targeted uses only the search domains, the own domain list and the reverse zones. Decide whether 9b ships in 15.
- **O4 – `dns-check` through the query daemon.** The daemon is documented as answering only the questions whose effects `status` already has. `dns-check` probes the network (one UDP packet) and may re-publish this connection's own DNS layout. The alternative is `sudo -n mvpn dns-check` every 5 minutes (a sudo process each time, the energy cost the daemon was built to avoid). The recommendation is the daemon; it needs the maintainer's yes.
- **O5 – Catalog ownership of DNS settings.** Team catalog connections: should `dns` be publisher-owned (like `otp`: an admin knows the VPN's DNS) or the user's own (like the colour)? Task 13 implements only the backup unless decided.
- **O6 – Root < 15 with non-default DNS settings.** The app sends the lines only to root ≥ 15 (otherwise `Invalid input`). Until the update, such a connection connects with the old behaviour, and the log says so. Alternatively the app could refuse to connect. Recommended: connect and warn.
- **O7 – Stacking.** Two full-DNS connections: the newest holds the override (as today), and the older one's supplemental entries stay. Two split connections now coexist, which is new. Accept as the new rule?
- **O8 – Fallback threshold and intervals** (2 failures to fall back, 1 success to return, 5 min, 15 s after a network change). The defaults balance flapping, energy and responsiveness; tune after the live test.
- **O9 – Interface scoping of our entries.** Like OpenVPN's script, our entries carry no `InterfaceName`. If queries to a VPN DNS that is not routed into the tunnel (a public resolver pushed on a split tunnel) should be forced into the tunnel, that needs a route, not a resolver setting. Out of scope.
- **O10 – `SupplementalMatchDomains = [""]` (a default-matching supplemental resolver, as NetworkExtension uses)** could make full DNS work without touching any `Setup:` key. It is undocumented for plain dynamic-store entries and was not verified. It is not used; it could be explored as a follow-up spike if O1 bites.
- **Not in scope:** strongSwan (charon `osx-attr`) and native VPNs keep their own DNS handling. On Linux and Windows the model field is stored and the UI is hidden.

## Maintainer decisions (2026-11-04)

- **O2:** neutral notice wording ("internet names are resolved by the local network's DNS"), no claim about the tunnel.
- **O3:** yes — Task 9b (`--dns-updown` / `resolve-domains`) ships in root layer 15.
- **O4:** yes — `dns-check` goes through the query daemon (`mvpn serve`); its documented rule is extended by this one read-only DNS probe.
- **O5:** the publisher (admin) owns a catalog connection's DNS settings (like `otp`).
- **O6:** root < 15 with non-default DNS settings: connect with the old behaviour and warn (log + System Status).
- **O7:** accepted: the newest full-DNS connection holds the override; split entries coexist.
- **O8:** the proposed defaults (2 failures → fallback, 1 success → back, 5 min, 15 s after a network change); tuned after the live test.
- **O1, O9, O10:** settled on the live checklist.
