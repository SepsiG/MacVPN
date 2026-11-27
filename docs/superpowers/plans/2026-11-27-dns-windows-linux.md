# Per-connection DNS on Windows and Linux Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** WinVPN and LinVPN apply the connection's DNS mode (Automatic, Strict, Full, Targeted), its own DNS servers and domains, and the probe with Automatic's fallback, as MacVPN does since 2.1.8. All three apps ship it in 2.1.15.

**Architecture:**
- **Shared core:** the pure mode logic moves from the macOS root helper into `macvpn-core::dns_policy` and is shared by all three. On macOS this is a move only, so MacVPN gets root layer 20.
- **Windows:** the WinVPN Service applies the result as local NRPT rules in the registry.
  - OpenVPN and WireGuard are applied directly; SSTP is applied when the app asks.
  - The probe is rerun on the app's 5-minute `dns-check`, which can rewrite the rules.
- **Linux:** the app writes the mode into the NetworkManager profile.
  - Automatic's fallback lowers the physical link's DNS priority at runtime (spec D1 = A).

**Tech Stack:**
- Rust workspace: `macvpn-core`, `macvpn-helper` (`macos` and `windows` modules), `macvpn-winsys`, `macvpn-platform-win`, `macvpn-platform-linux`, `macvpn-app-core`.
- `windows-sys` 0.61 (`Win32_System_Registry` and `Win32_System_Services` are already enabled).
- zbus (NM D-Bus) on Linux.
- Svelte UI.

**Spec:** `docs/superpowers/specs/2026-11-27-dns-windows-linux-design.md`. The macOS original is
`docs/superpowers/specs/2026-11-04-dns-resolver-design.md`; its code lives in `crates/helper/src/macos/dns*.rs`.

**Conventions (all tasks):**
- `export PATH=$HOME/.cargo/bin:$PATH` before cargo.
- `cargo fmt --all`; `cargo clippy --workspace --all-targets -- -D warnings`.
- OS `cfg`s only in platform modules.
- No `unwrap()` in production code.
- User-facing strings go through `tr("literal key")`, with the Hungarian in `crates/core/l10n/strings.json`.
- Commit messages are written normally and end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Per task, run only the touched crates' tests. Task 9 runs the full suite.
- Windows code is checked on the Mac with `scripts/check-windows.sh` (core, helper, winsys).
  - platform-win and app-core on Windows are checked only by CI.
- Linux code (`#[cfg(target_os = "linux")]`) is tested on the Linux VM with `scripts/lin-remote.sh` (not the
  `desktop` subcommand), or by CI.

**Order:**
- Task 1 first.
- Then two independent streams in separate worktrees: Linux (Tasks 2–3) and Windows (Tasks 4–7).
- Then Task 8 (UI and docs), then Task 9 (merge, full gates, release).

---

## File structure

| File | Responsibility |
|---|---|
| `crates/core/src/dns_policy/mod.rs` (new) | `Tunnel`, `Probe`, `Layout`, `Warn`, `Decision`, `decide`, `Pushed`, `Effective`, `effective`, `dedup`, `next_probe`, `state_of`, `FAILS_TO_FALL_BACK` (moved from `helper/src/macos/dns_plan.rs`, `dns.rs` and `dns_session.rs`) |
| `crates/core/src/dns_policy/probe.rs` (new) | `probe_server`, `probe` (moved from `helper/src/macos/dns_probe.rs`; the test-mode env switch stays in the macOS wrapper) |
| `crates/core/src/dns_policy/push_reply.rs` (new) | `parse_push_reply(line) -> Option<Pushed>` (OpenVPN's `PUSH_REPLY` text) |
| `crates/core/src/dns_policy/nrpt.rs` (new) | pure NRPT rule set per layout (`NrptRule`) |
| `crates/helper/src/macos/dns_plan.rs`, `dns_probe.rs`, `dns.rs`, `dns_session.rs` | re-export or use the moved items; macOS-only store logic stays |
| `crates/core/src/nm_plan/dns.rs` | NM DNS keys per mode (`section_extras` gains the `DnsSetting`) |
| `crates/platform-linux/src/lin/nm/dns_runtime.rs` (new) | Linux probe, `dns-check`, the physical-link fallback and its ledger |
| `crates/winsys/src/nrpt.rs` (new) | registry I/O for NRPT rules and the policy refresh |
| `crates/helper/src/windows/dns.rs` (new) | the service's DNS manager: facts, decide, apply, check, release, reconcile |
| `crates/helper/src/windows/service.rs` | `dns-check`, `dns-apply`, `dns-release` requests; `status` fills `dns` |
| `crates/core/src/service_proto.rs` | `SERVICE_VERSION` 1 → 2; request names |
| `crates/platform-win/src/win/service_client.rs`, `ras_engine.rs` | `up_with_dns`, `dns_supported`, `dns_check`; SSTP asks the service |
| `app/ui/src/lib/manage/dnsFields.ts` | DNS section on all OSes |

---

### Task 1: Move the pure DNS logic into `macvpn-core::dns_policy` (macOS root 20)

**Files:**
- Create: `crates/core/src/dns_policy/mod.rs`, `crates/core/src/dns_policy/probe.rs`
- Modify: `crates/core/src/lib.rs` (add `pub mod dns_policy;`)
- Modify: `crates/helper/src/macos/dns_plan.rs`, `dns_probe.rs`, `dns.rs`, `dns_session.rs`
- Modify (root bump):
  - `crates/helper/VERSION` (19 → 20);
  - the `version_is_19` test in `crates/helper/src/macos/mod.rs` (rename it to `version_is_20`, expect 20);
  - `scripts/test-root.sh` (`EXPECT_VERSION=20`);
  - `docs/user-guide.en.md` and `docs/user-guide.hu.md`: the root-layer list near line 164, "Installed (version 20)" and "Update required (19 → 20)";
  - `docs/release-notes/2.1.15.md` (new, "Not released yet", root 20 line as in `2.1.14.md`).
- Test: `crates/core/tests/dns_policy.rs` (new). The moved unit tests go with the code.

- [ ] **Step 1: Move the types and `decide`/`effective` verbatim.** Move from `crates/helper/src/macos/dns_plan.rs` into `crates/core/src/dns_policy/mod.rs`:
  - `Tunnel`, `Probe`, `Layout`, `Warn` (with the `raw_enum!` macro and its `raw`/`from_raw`);
  - `Decision`, `decide`, `Pushed`, `Effective` (with `has_match`; make `all_matches` `pub`), `dedup` (`pub`) and `effective`.

  Keep the doc comments, but drop the dynamic-store wording from the module doc. In `dns_plan.rs` replace the moved
  items with `pub use macvpn_core::dns_policy::{Decision, Effective, Layout, Probe, Pushed, Tunnel, Warn, decide, effective};`.
  Keep everything store-specific (`entry_key`, `Original`, `Primary`, `own_entries`, `override_ops`, …) where it is.
- [ ] **Step 2: Move the probe-count rule** out of `Manager::check` (`crates/helper/src/macos/dns.rs` ~line 630) and the session→state mapping out of `dns_session.rs::Session::state`:

```rust
/// Consecutive failed checks before the Automatic mode falls back (each check already sends twice).
pub const FAILS_TO_FALL_BACK: u32 = 2;

/// A check's probe result folded into the session: one failure keeps the current layout (no flapping), the
/// second in a row decides; one success returns. `NotRun` changes nothing.
pub fn next_probe(prev: Probe, prev_fails: u32, result: Probe) -> (Probe, u32) {
    match result {
        Probe::NotRun => (prev, prev_fails),
        Probe::Ok => (Probe::Ok, 0),
        Probe::Failed => {
            let fails = prev_fails.saturating_add(1);
            let keep = if prev == Probe::Failed { Probe::Failed } else { Probe::Ok };
            (if fails >= FAILS_TO_FALL_BACK { Probe::Failed } else { keep }, fails)
        }
    }
}

/// The state the app shows for a layout and its warning.
pub fn state_of(layout: Layout, warn: Option<Warn>) -> crate::status::DnsState {
    use crate::status::DnsState;
    match (layout, warn) {
        (Layout::None, _) => DnsState::None,
        (Layout::Split, _) => DnsState::Targeted,
        (Layout::Fallback, Some(Warn::Fallback { full_tunnel: true })) => DnsState::FallbackFullTunnel,
        (Layout::Fallback, _) => DnsState::Fallback,
        (Layout::Vpn { .. }, Some(Warn::Failing)) => DnsState::Failing,
        (Layout::Vpn { .. }, _) => DnsState::Vpn,
    }
}
```

  `Manager::check` calls `next_probe(prev.probe, prev.fails, p)`, keeping its early return for `NotRun`.
  `Session::state` calls `state_of(self.layout, self.warn)`. `dns.rs` re-exports
  `pub use macvpn_core::dns_policy::FAILS_TO_FALL_BACK;` in place of its own constant.
- [ ] **Step 3: Move the probe.** `probe_server(addr, timeout)` moves verbatim to `crates/core/src/dns_policy/probe.rs`, together with `TIMEOUT`, `MAX_SERVERS`, `SENDS`, the log `word` helper and the servers loop.
  - In core, the loop is `pub fn probe(servers: &[String]) -> (Probe, String)`, which never reads env.
  - The macOS wrapper in `dns_probe.rs` keeps the `MVPN_DNS_PROBE=ok|fail` test switch, then calls the core `probe`.
  - `uuid` is already a core dependency (check `crates/core/Cargo.toml`; add `features = ["v4"]` if it is missing).
- [ ] **Step 4: Write `crates/core/tests/dns_policy.rs`** with the moved `decide`/`effective` tests (they currently sit in `dns_plan.rs`'s `mod tests`; move the ones that test only the moved functions) plus:

```rust
use macvpn_core::dns_policy::*;
use macvpn_core::status::DnsState;

#[test]
fn one_failure_keeps_the_layout_two_fall_back_one_success_returns() {
    assert_eq!(next_probe(Probe::Ok, 0, Probe::Failed), (Probe::Ok, 1));
    assert_eq!(next_probe(Probe::Ok, 1, Probe::Failed), (Probe::Failed, 2));
    assert_eq!(next_probe(Probe::Failed, 2, Probe::Failed), (Probe::Failed, 3));
    assert_eq!(next_probe(Probe::Failed, 3, Probe::Ok), (Probe::Ok, 0));
    assert_eq!(next_probe(Probe::Failed, 3, Probe::NotRun), (Probe::Failed, 3));
}

#[test]
fn states_follow_the_layout() {
    assert_eq!(state_of(Layout::None, Some(Warn::NoDns)), DnsState::None);
    assert_eq!(state_of(Layout::Split, None), DnsState::Targeted);
    assert_eq!(state_of(Layout::Fallback, Some(Warn::Fallback { full_tunnel: true })), DnsState::FallbackFullTunnel);
    assert_eq!(state_of(Layout::Fallback, Some(Warn::Fallback { full_tunnel: false })), DnsState::Fallback);
    assert_eq!(state_of(Layout::Vpn { local: true }, Some(Warn::Failing)), DnsState::Failing);
    assert_eq!(state_of(Layout::Vpn { local: false }, None), DnsState::Vpn);
}

#[test]
fn probe_of_no_servers_is_not_run() {
    assert_eq!(probe(&[]).0, Probe::NotRun);
}
```

- [ ] **Step 5: Run.**

```bash
cargo test -p macvpn-core --test dns_policy
cargo test -p macvpn-helper
scripts/test-root.sh
scripts/check-windows.sh
```

  Expected: all pass; `test-root.sh` reports `fail: 0` with `EXPECT_VERSION=20`.
- [ ] **Step 6: Bump the root layer** (the files listed above) and add `docs/release-notes/2.1.15.md` with a one-line "Not released yet. On top of [2.1.14](2.1.14.md). **MacVPN: root layer 20** …" header and empty English/Magyar sections, in the same format as `2.1.14.md`.
- [ ] **Step 7: Commit:** `helper, core: the DNS mode logic is shared (root layer 20)`.

---

### Task 2: Linux – NM DNS keys per mode (plan time)

**Files:**
- Modify: `crates/core/src/nm_plan/dns.rs`, plus the callers in `openvpn.rs:767`, `wireguard.rs:175`, `sstp.rs:71`, `l2tp.rs:91` and `strongswan.rs:354`.
- Test: `crates/core/tests/nm_plan_dns.rs` (new); update the expectations in `crates/core/tests/nm_plan_openvpn.rs` and the other `nm_plan_*` tests that assert `dns-priority` or `dns-search`.

**Rule (spec, Linux table).** It applies to OpenVPN, WireGuard and SSTP. L2TP, Cisco and IKEv2 keep today's
behavior and pass `None`.

| Mode (`DnsSetting.mode`) | `dns-search` | `dns-priority` |
|---|---|---|
| Automatic, Full | VPN domains (plain) + own domains as `~d` + `~.` | `50` (`DEFAULT_PRIORITY`) |
| Strict | VPN domains (plain) + own domains as `~d` + `~.` | `-50` (`STRICT_PRIORITY`) |
| Targeted (split tunnel) | `~d` for each VPN domain and own domain | `50` |
| Targeted on a full tunnel | as Automatic (the macOS rule `TargetedOnFullTunnel`) | `50` |

Own servers go to the address family's `dns-data` (IPv4 literals to `ipv4`, IPv6 to `ipv6`):
- when the VPN sends none, the VPN's pushed servers come first (NM merges them);
- with `override_vpn`, `ignore-auto-dns = true` is also set and only the own servers apply.

- [ ] **Step 1: Write the failing test** `crates/core/tests/nm_plan_dns.rs`:

```rust
use macvpn_core::dns_settings::{DnsMode, DnsSetting};
use macvpn_core::nm_plan::NmValue;
use macvpn_core::nm_plan::dns::{DEFAULT_PRIORITY, STRICT_PRIORITY, section_extras};

fn setting(mode: DnsMode, servers: &[&str], domains: &[&str], override_vpn: bool) -> DnsSetting {
    DnsSetting {
        mode,
        servers: servers.iter().map(|s| s.to_string()).collect(),
        domains: domains.iter().map(|s| s.to_string()).collect(),
        override_vpn,
    }
}
fn search(m: &std::collections::BTreeMap<String, NmValue>) -> Vec<String> {
    match m.get("dns-search") { Some(NmValue::StrList(v)) => v.clone(), _ => vec![] }
}
fn prio(m: &std::collections::BTreeMap<String, NmValue>) -> i32 {
    match m.get("dns-priority") { Some(NmValue::I32(p)) => *p, other => panic!("{other:?}") }
}
const V4: bool = true;

#[test]
fn automatic_and_full_take_every_name_but_keep_local_names() {
    for mode in [DnsMode::Automatic, DnsMode::Full] {
        let m = section_extras(false, &["corp.example".into()], Some(&setting(mode, &[], &["intra.example"], false)), V4);
        assert_eq!(search(&m), ["corp.example", "~intra.example", "~."]);
        assert_eq!(prio(&m), DEFAULT_PRIORITY);
    }
}

#[test]
fn strict_is_exclusive() {
    let m = section_extras(true, &["corp.example".into()], Some(&setting(DnsMode::Strict, &[], &[], false)), V4);
    assert_eq!(search(&m), ["corp.example", "~."]);
    assert_eq!(prio(&m), STRICT_PRIORITY);
}

#[test]
fn targeted_routes_only_the_vpn_domains_on_a_split_tunnel() {
    let m = section_extras(false, &["corp.example".into()], Some(&setting(DnsMode::Targeted, &[], &["portal.example"], false)), V4);
    assert_eq!(search(&m), ["~corp.example", "~portal.example"]);
    assert_eq!(prio(&m), DEFAULT_PRIORITY);
}

#[test]
fn targeted_on_a_full_tunnel_acts_as_automatic() {
    let m = section_extras(true, &[], Some(&setting(DnsMode::Targeted, &[], &[], false)), V4);
    assert_eq!(search(&m), ["~."]);
}

#[test]
fn own_servers_per_family_and_override() {
    let s = setting(DnsMode::Automatic, &["10.0.0.53", "fd00::53"], &[], true);
    let v4 = section_extras(false, &[], Some(&s), true);
    assert_eq!(v4.get("dns-data"), Some(&NmValue::StrList(vec!["10.0.0.53".into()])));
    assert_eq!(v4.get("ignore-auto-dns"), Some(&NmValue::Bool(true)));
    let v6 = section_extras(false, &[], Some(&s), false);
    assert_eq!(v6.get("dns-data"), Some(&NmValue::StrList(vec!["fd00::53".into()])));
}

#[test]
fn kinds_without_dns_settings_keep_todays_keys() {
    let m = section_extras(true, &[], None, V4);
    assert_eq!(search(&m), ["~."]);
    assert_eq!(prio(&m), STRICT_PRIORITY);
    let m = section_extras(false, &["a.example".into()], None, V4);
    assert_eq!(search(&m), ["~a.example"]);
    assert_eq!(prio(&m), DEFAULT_PRIORITY);
}
```

  Check the `NmValue` variant names in `crates/core/src/nm_plan/mod.rs` (`StrList`, `I32`, `Bool`) and adapt
  them if they differ. If `dns-data` is not the key the plan already uses for WireGuard's servers
  (`wireguard.rs:228`), use the same key that code uses.
- [ ] **Step 2: Run it:** `cargo test -p macvpn-core --test nm_plan_dns`. Expected: compile FAIL (new signature).
- [ ] **Step 3: Implement.** Implement `section_extras(full: bool, domains: &[String], dns: Option<&DnsSetting>, v4: bool)` per the table.
  - Rename `SPLIT_PRIORITY` to `DEFAULT_PRIORITY` (50) and `FULL_PRIORITY` to `STRICT_PRIORITY` (−50).
  - `None` keeps today's behavior exactly: full gives `~.` at −50; split gives `~d` at 50.
  - Dedup domains case-insensitively with `macvpn_core::dns_policy::dedup` (cap `MAX_DOMAINS`).
  - Update the module doc: the mode now decides the keys; Automatic's runtime fallback is in `platform-linux`'s `dns_runtime`.
- [ ] **Step 4: Callers.**
  - OpenVPN, WireGuard and SSTP pass `Some(&input.connection.dns)`. `Input` already carries `connection`; see `nm_plan/mod.rs:177`.
  - OpenVPN today writes `dns-search` on ipv4 only: keep that, and call it with `v4 = false` for ipv6 only to get `dns-data` and `dns-priority`.
  - L2TP, vpnc and strongSwan pass `None`.
- [ ] **Step 5: Run** `cargo test -p macvpn-core` and fix the old expectations. They change only where the default (Automatic) now gives `~.` at 50 on split tunnels, or 50 instead of −50 on full ones. Expected: all pass.
- [ ] **Step 6: Commit:** `core: the NM plan writes the connection's DNS mode (LinVPN)`.

---

### Task 3: Linux – probe, `dns-check`, Automatic's fallback through the physical link

**Files:**
- Create: `crates/platform-linux/src/lin/nm/dns_runtime.rs`, registered in `crates/platform-linux/src/lin/nm/mod.rs`.
- Modify: `crates/platform-linux/src/lin/nm/helper_impl.rs` (`impl HelperClient for Engine`: `dns_supported` → `true`, `dns_check`, the run's `dns` in `status`, which is now `None` at ~line 285) and `crates/platform-linux/src/lin/nm/engine.rs` (after activation: first decision; at deactivate and engine start: restore).
- Test: `#[cfg(test)] mod tests` in `dns_runtime.rs` (they run on Linux CI and the VM).

**Design:**
- A trait `NmDns` hides D-Bus. The real implementation uses the engine's zbus `client.rs`; tests use a fake.
  - `vpn_servers(active_path) -> Vec<String>`: the active VPN connection's `Ip4Config`/`Ip6Config` `NameserverData` addresses.
  - `default_links() -> Vec<Link>`, where `Link { iface: String, device_path: String }`: devices other than the VPN with an IPv4 or IPv6 default route.
  - `dns_priority(device_path, v4: bool) -> Option<i32>`: from `Device.GetAppliedConnection`.
  - `set_dns_priority(device_path, v4: bool, prio: i32) -> Result<(), String>`: `GetAppliedConnection`, change `ipv4|ipv6.dns-priority`, then `Device.Reapply(conn, version_id, 0)`.
- **Fallback:** the physical links get `FALLBACK_PRIORITY = 40`, below the VPN's 50 and above 0, so no shadowing.
  - Return restores each link's recorded original priority.
- **Ledger:** `<data>/dns-fallback.json`, holding `{ "<connection id>": [{ "iface", "v4": orig, "v6": orig }] }`.
  - It is written before changing anything and removed after the restore.
  - At engine start, every entry is restored (best effort) and the file removed. A leftover is harmless: NM drops a runtime priority at the link's next reconnect.
- **Session (in memory, per connection id):** `mode`, `tunnel`, `Effective`, `probe`, `fails`, `layout`, `warn`.
  - Built after activation:
    - `Pushed.servers` come from `vpn_servers`;
    - `Pushed.search` from the active connection's domains (`Ip4Config` `Domains`/`Searches`);
    - routes from `Ip4Config` `RouteData`;
    - `tunnel` = Full when the active connection is the default (`ActiveConnection.Default`/`Default6`).
  - Then `effective`, `probe`, `decide` (all from `macvpn_core::dns_policy`).
  - `Layout::Fallback` → fallback on; anything else → off.
- **`dns_check(id)`:** at most once per 20 s per connection; runs `probe`, `next_probe`, `decide`, applies on a change, and returns `state_of`.
- **Log lines:** the same keys as macOS, so the l10n already has them. Search `crates/core/l10n/strings.json` for "DNS" and reuse the macOS `tr` keys (the fallback and return lines).

- [ ] **Step 1: Write the failing tests** (fake `NmDns` recording calls):

```rust
#[test]
fn fallback_lowers_every_default_link_and_records_it_first() { /* fake with eth0 (v4 prio 0→100 effective, record raw), wlan0; session Automatic + probe Failed twice → set_dns_priority(eth0,v4,40), (wlan0,v4,40); ledger file holds the originals before the first set call */ }
#[test]
fn recovery_restores_the_recorded_priorities_and_removes_the_ledger() { /* after fallback, probe Ok → set back to originals, ledger gone */ }
#[test]
fn strict_and_full_never_touch_the_links() { /* two failures → no set calls; state Failing */ }
#[test]
fn targeted_never_probes() { /* dns_check returns Targeted, no probe call (inject a probe fn that panics) */ }
#[test]
fn start_restores_a_leftover_ledger() { /* ledger present at start → set calls with recorded values, file removed */ }
#[test]
fn deactivate_restores() { /* fallback on, deactivate → originals back */ }
```

  Write each test body fully. Inject the probe as `Box<dyn Fn(&[String]) -> Probe + Send + Sync>` so tests do not
  open sockets; the real one is `|s| dns_policy::probe(s).0`.
- [ ] **Step 2: Run on the Linux VM.** Read `scripts/lin-remote.sh` for usage; use `LINVPN_SSH=linvpn-dev@<VM>` from your environment (never write the IP into the repo):

```bash
scripts/lin-remote.sh run 'cargo test --locked -p macvpn-platform-linux dns_runtime'
```

  Expected: FAIL (module not there).
- [ ] **Step 3: Implement** `dns_runtime.rs`: the trait, the real zbus implementation (follow the patterns in `crates/platform-linux/src/lin/nm/client.rs`), the session map behind a `Mutex`, and the ledger.
  - Write the ledger with the app's atomic file helper; search `crates/platform-linux/src/lin` for an existing "write atomically" function and reuse it.
- [ ] **Step 4: Wire it in.**
  - `engine.rs`: after an activation reaches Activated, build the session and apply.
  - `engine.rs`: on `deactivate` and when the NM connection leaves, restore.
  - `engine.rs`: at `Engine::new`, run the start restore.
  - `helper_impl.rs`: `dns_check` delegates to the session; the status run's `dns` = `Some(state)`.
- [ ] **Step 5: Run** the module tests and `cargo test -p macvpn-platform-linux` on the VM, and `cargo clippy -p macvpn-platform-linux --all-targets -- -D warnings` there. Expected: pass.
- [ ] **Step 6: Commit:** `linux: DNS probe, dns-check and Automatic's fallback through the physical link`.

---

### Task 4: Windows – pure pieces in core: `PUSH_REPLY` parser and NRPT rule set

**Files:**
- Create: `crates/core/src/dns_policy/push_reply.rs`, `crates/core/src/dns_policy/nrpt.rs`.
- Test: `crates/core/tests/dns_policy_windows.rs` (new; runs on every OS).

- [ ] **Step 1: Write the failing tests:**

```rust
use macvpn_core::dns_policy::nrpt::{NrptRule, rules};
use macvpn_core::dns_policy::push_reply::parse_push_reply;
use macvpn_core::dns_policy::{Effective, Layout};

#[test]
fn push_reply_gives_servers_domains_and_routes() {
    let line = "PUSH: Received control message: 'PUSH_REPLY,route 10.99.0.0 255.255.255.0,dhcp-option DNS 10.99.0.53,dhcp-option DOMAIN lab.test,dhcp-option DOMAIN-SEARCH corp.example,dhcp-option DNS6 fd00::53,dns server 0 resolve-domains internal.example,route-gateway 10.99.11.1,ping 10,peer-id 0'";
    let p = parse_push_reply(line).unwrap();
    assert_eq!(p.servers, ["10.99.0.53", "fd00::53"]);
    assert_eq!(p.search, ["lab.test", "corp.example"]);
    assert_eq!(p.resolve, ["internal.example"]);
    assert_eq!(p.routes.len(), 1);
    assert!(parse_push_reply("some other line").is_none());
}

#[test]
fn push_reply_takes_dns_server_addresses_of_openvpn_2_6() {
    let p = parse_push_reply("PUSH: Received control message: 'PUSH_REPLY,dns server 0 address 10.0.0.1 10.0.0.2,dns search-domains a.example b.example'").unwrap();
    assert_eq!(p.servers, ["10.0.0.1", "10.0.0.2"]);
    assert_eq!(p.search, ["a.example", "b.example"]);
}

fn eff() -> Effective {
    Effective {
        servers: vec!["10.99.0.53".into()],
        search: vec!["lab.test".into()],
        resolve: vec!["internal.example".into()],
        zones: vec!["0.99.10.in-addr.arpa".into()],
    }
}

#[test]
fn vpn_layout_catches_every_name_and_keeps_local_names_local() {
    let r = rules("ID", Layout::Vpn { local: true }, &eff(), Some((&["home.lan".to_string()], &["192.168.1.1".to_string()])));
    assert_eq!(r[0], NrptRule { key: "WinVPN-ID-0".into(), names: vec![".".into()], servers: vec!["10.99.0.53".into()] });
    assert_eq!(r[1], NrptRule { key: "WinVPN-ID-1".into(), names: vec![".home.lan".into()], servers: vec!["192.168.1.1".into()] });
    assert_eq!(r.len(), 2);
}

#[test]
fn strict_has_only_the_catch_all() {
    let r = rules("ID", Layout::Vpn { local: false }, &eff(), Some((&["home.lan".to_string()], &["192.168.1.1".to_string()])));
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].names, ["."]);
}

#[test]
fn split_and_fallback_route_only_the_vpn_names() {
    for layout in [Layout::Split, Layout::Fallback] {
        let r = rules("ID", layout, &eff(), None);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].names, [".lab.test", ".internal.example", ".0.99.10.in-addr.arpa"]);
        assert_eq!(r[0].servers, ["10.99.0.53"]);
    }
}

#[test]
fn a_local_domain_the_vpn_also_has_stays_with_the_vpn() {
    let r = rules("ID", Layout::Vpn { local: true }, &eff(), Some((&["lab.test".to_string()], &["192.168.1.1".to_string()])));
    assert_eq!(r.len(), 1);
}

#[test]
fn no_layout_no_rules() {
    assert!(rules("ID", Layout::None, &eff(), None).is_empty());
}
```

- [ ] **Step 2: Run** `cargo test -p macvpn-core --test dns_policy_windows`. Expected: compile FAIL.
- [ ] **Step 3: Implement `push_reply.rs`.**
  - Find the quoted text after `PUSH_REPLY,` and split it on `,`.
  - `dhcp-option DNS|DNS6 <ip>`: a server (validated with `dns_settings::is_dns_server`).
  - `dhcp-option DOMAIN|DOMAIN-SEARCH <d>`: a search domain (`is_dns_domain`, lower-cased through `dns_settings::normalize_domain`).
  - `dns server <n> address <ip>…`: servers.
  - `dns server <n> resolve-domains <d>…`: resolve domains.
  - `dns search-domains <d>…`: search domains.
  - `route <net> <mask>`: `IpPrefix` (use `macvpn_core::netaddr` to build it from a netmask; search it for an existing parser).
  - Ignore everything else.
  - Apply the caps (`MAX_SERVERS`, `MAX_DOMAINS`) via `dedup`.
- [ ] **Step 4: Implement `nrpt.rs`.**

```rust
//! The local NRPT rules (Windows' Name Resolution Policy Table) a DNS layout needs. Pure: the WinVPN Service writes
//! them under `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\<key>`.

use super::{Effective, Layout};
use crate::dns_zones::covered_by;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrptRule {
    /// The registry key name: `WinVPN-<id>-<n>` (the prefix marks ours for cleanup).
    pub key: String,
    /// NRPT names: `.` for every name, `.<suffix>` for a domain.
    pub names: Vec<String>,
    pub servers: Vec<String>,
}

pub fn key_prefix(id: &str) -> String { format!("WinVPN-{id}-") }

/// `local`: the physical network's own domains and their DNS servers (Automatic and Full keep those names local).
pub fn rules(id: &str, layout: Layout, e: &Effective, local: Option<(&[String], &[String])>) -> Vec<NrptRule> { … }
```

  The rules, by layout:
  - `Vpn { local }`: a rule `["."]` to `e.servers`. When `local` is true and `local` is `Some`, a second rule holds
    the local domains not `covered_by` the VPN's `all_matches()`, as `.<d>`, to the local servers. Skip it when no
    domains remain or the local servers are empty.
  - `Split` and `Fallback`: one rule for `search + resolve + zones` as `.<d>`. Skip it if empty.
  - `None`: no rules.
- [ ] **Step 5: Run** the tests, then `scripts/check-windows.sh`. Expected: pass.
- [ ] **Step 6: Commit:** `core: PUSH_REPLY DNS parser and NRPT rule set (WinVPN)`.

---

### Task 5: Windows – registry I/O for NRPT (`winsys::nrpt`)

**Files:**
- Create: `crates/winsys/src/nrpt.rs` (`#[cfg(windows)]`, registered in `crates/winsys/src/lib.rs` next to the other modules).
- Test: the `#[cfg(test)]` module in the same file (runs in CI's windows jobs; uses a test-only key path).

**API:**

```rust
pub const POLICY_PATH: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

/// Writes one rule as OpenVPN's interactive service does: `Name` (REG_MULTI_SZ), `GenericDNSServers` (REG_SZ,
/// `;`-joined), `ConfigOptions` (DWORD 8), `Version` (DWORD 2), `IPSECCARestriction` (REG_SZ ""), `Comment` (REG_SZ
/// "WinVPN").
pub fn write_rule(base: &str, key: &str, names: &[String], servers: &[String]) -> std::io::Result<()>;
/// Deletes every rule whose key starts with `prefix`; returns how many went.
pub fn delete_rules(base: &str, prefix: &str) -> std::io::Result<usize>;
/// The key names under `base` (for the reconcile).
pub fn rule_keys(base: &str) -> std::io::Result<Vec<String>>;
/// Makes the DNS client re-read the policy and drop its cache: `SERVICE_CONTROL_PARAMCHANGE` to `Dnscache` (as
/// openvpnserv's `ApplyDnsSettings`), then `DnsFlushResolverCache` (dnsapi.dll, loaded through the crate's existing
/// `dll` module, since windows-sys does not export it).
pub fn apply() -> std::io::Result<()>;
```

- [ ] **Step 1: Write the tests.**
  - `write_rule`, `rule_keys` and `delete_rules` round-trip under `HKLM\SOFTWARE\WinVPN-test-<uuid>`, deleted at the end. CI's `windows-admin` job runs elevated; mark the test `#[ignore]` only if `scripts/check-ignored.sh` lists `windows-admin` as the place for elevated tests (read that script and `scripts/ignored-everywhere.txt` to follow the existing convention).
  - A REG_MULTI_SZ encoding test (pure: a `names` list → the UTF-16 double-NUL buffer), runnable everywhere: put the encoder in a non-cfg helper inside `winsys` only if the crate already has such a pattern; otherwise inside the cfg module.
- [ ] **Step 2: Implement** with `windows-sys` `Win32_System_Registry` (`RegCreateKeyExW`, `RegSetValueExW`, `RegDeleteTreeW`, `RegEnumKeyExW`) and `Win32_System_Services` (`OpenSCManagerW`, `OpenServiceW` with `SERVICE_PAUSE_CONTINUE`, `ControlService(…, SERVICE_CONTROL_PARAMCHANGE, …)`).
  - Follow `crates/winsys/src/scm.rs` and `util.rs` for handle wrappers and wide strings.
  - `apply` does not fail the caller when the PARAMCHANGE is refused: it returns an error and the caller logs it.
- [ ] **Step 3: Run** `scripts/check-windows.sh`. Expected: pass. The real run happens in CI.
- [ ] **Step 4: Commit:** `winsys: NRPT rules in the registry and the DNS policy refresh`.

---

### Task 6: Windows – the service's DNS manager

**Files:**
- Create: `crates/helper/src/windows/dns.rs` (registered in `crates/helper/src/windows/mod.rs`).
- Modify:
  - `crates/helper/src/windows/service.rs`: `dispatch` gets `"dns-check"`, `"dns-apply"` and `"dns-release"`. `status` fills `dns` (now `None` at ~line 342). `up` hands `req.secrets.dns` to the engine. `down` releases. Service start reconciles.
  - `crates/helper/src/windows/sys/openvpn.rs`: the stdout reader passes `PUSH_REPLY` lines to the session; after "Initialization Sequence Completed" (find the existing connected detection) it triggers the after-connect pass.
  - `crates/helper/src/windows/sys/wireguard.rs`: WireGuard's servers and domains come from the plan. In the `Split`/`Fallback` layouts the adapter's own DNS is not set: `set_dns` with empty lists (~line 589).
  - `crates/core/src/service_proto.rs`: `SERVICE_VERSION = 2`; constants `DNS_CHECK`, `DNS_APPLY`, `DNS_RELEASE`.
- Test: the `#[cfg(test)]` module in `dns.rs`, compiled on Windows (CI). Put the decision flow behind a trait so it is testable.

**Design:**
- `trait Nrpt { fn write(&self, rules: &[NrptRule]) -> Result<(), String>; fn delete(&self, prefix: &str) -> Result<(), String>; fn keys(&self) -> Vec<String>; fn apply(&self); }`. The real one uses `winsys::nrpt`; the fake one is in-memory.
- `trait AdapterDns { fn get(&self, luid: u64) -> (Vec<String>, Vec<String>); fn clear(&self, luid: u64); fn physical(&self) -> Option<(Vec<String>, Vec<String>)>; }`.
  - `get` returns servers and suffixes.
  - `physical` returns the domains and servers of the adapter that holds the default route, excluding VPN adapters.
  - Real implementation: `winsys::net::adapters_with_dns` and `iphlp::set_dns`.
- A `Manager` with `sessions: Mutex<HashMap<String, Session>>`, where `Session { mode, tunnel, eff, probe, fails, layout, warn, luid }`, and these methods:
  - `after_connect(id, req: DnsRequest, pushed: Pushed, luid, tunnel)`: `effective`, `probe` (`dns_policy::probe`), `decide`, apply.
  - `check(id) -> Option<DnsState>`: same flow as Linux Task 3, with a 20 s minimum interval.
  - `release(id)`: `delete(prefix)` + `apply`.
  - `reconcile(running: &[String])`: deletes every `WinVPN-*` rule whose id is not running.
- **Applying a layout:**
  1. `delete(prefix)`, then `write(rules(..))`.
  2. For `Split`/`Fallback`, also `AdapterDns::clear(luid)`.
  3. Then `apply()`.
  4. Log the change with the macOS `tr` keys.
- **Tunnel:** Full when the config or the push redirects the gateway (`dns_settings::full_tunnel_hint` for the config; `redirect-gateway` in the `PUSH_REPLY` for the server push) or WireGuard's AllowedIPs hold a default route.
- **Pushed DNS:** OpenVPN's `PUSH_REPLY` via `parse_push_reply`; if none arrived, the adapter's DNS via `AdapterDns::get`. WireGuard's comes from the plan. SSTP's comes from `dns-apply`'s body.
- **`dns-apply <id>`** (SSTP, from the app; the body is the DNS frame lines plus `luid=<n>`):
  - The caller must own the RAS connection; follow `service.rs`'s owner check for `up` (`o.sid != caller.sid`). Since the service does not run RAS, record the owner SID at `dns-apply` and require the same SID for `dns-check` and `dns-release`.
  - Pushed = the RAS adapter's DNS.

- [ ] **Step 1: Write the tests** with the fakes:
  - Automatic, probe ok: one `.` rule plus the local rule; state `Vpn`.
  - Automatic, two failed checks: `Fallback` rules, adapter cleared, state `Fallback`; one ok: back to `Vpn`.
  - Full failing: still the `.` rule, state `Failing`.
  - Strict: only the `.` rule.
  - Targeted on a split tunnel: domain rule only, adapter cleared.
  - No servers: no rules, state `None`.
  - `release` deletes only that id's rules.
  - `reconcile` deletes stale ids and keeps running ones.
  - `dns-apply` from another SID is refused.

  Write each with concrete ids, servers (`10.99.0.53`) and domains (`lab.test`). Inject the probe as a closure.
- [ ] **Step 2: Implement** `dns.rs` and the dispatch, status, up, down and start wiring.
- [ ] **Step 3: Run** `scripts/check-windows.sh` and `cargo test -p macvpn-helper` (Mac: the shared parts). Expected: pass. The Windows test module runs in CI.
- [ ] **Step 4: Commit:** `winvpn service: per-connection DNS through NRPT, dns-check, SSTP dns-apply (service 2)`.

---

### Task 7: Windows – the app side (`ServiceClient`, `RasHelper`)

**Files:**
- Modify: `crates/platform-win/src/win/service_client.rs`, `crates/platform-win/src/win/ras_engine.rs`.
- Test: the existing test modules of those files (look for `#[cfg(test)]` and the fake service used there).

- [ ] **Step 1: Write the failing tests.**
  - `ServiceClient::up_with_dns` puts `DnsRequest::frame_lines()` after the secrets in the `up` stdin (compare with `helper_args::up_stdin`). `None` sends `dns-mode=automatic\n`, because on Windows the default must still be applied.
  - `dns_supported()` is true when the service reports version ≥ 2.
  - `dns_check(id)` sends `dns-check <id>` and parses `DnsState::from_raw`.
  - For SSTP, `RasHelper` sends `dns-apply <id>` with the request and the RAS adapter LUID once RAS reports connected, and `dns-release <id>` after hang-up. `dns_check` for an SSTP id goes to the service too.
- [ ] **Step 2: Implement.**
  - Override `up_with_dns`, `dns_supported` and `dns_check` in `ServiceClient`, and forward them in `RasHelper` (`ras_engine.rs:910-924` routes per kind).
  - Get the RAS adapter's LUID with `RasGetProjectionInfoEx` (check whether `crates/winsys/src/ras` already exposes it; otherwise add it there, `Win32_NetworkManagement_Rras`).
- [ ] **Step 3: Run** `scripts/check-windows.sh`. platform-win is checked by CI only, so push nothing; the coordinator runs CI at Task 9.
- [ ] **Step 4: Commit:** `winvpn app: the DNS settings reach the service; SSTP's DNS through dns-apply`.

---

### Task 8: UI, notices, docs

**Files:**
- Modify:
  - `app/ui/src/lib/manage/dnsFields.ts` (drop `os === "macos"`), `dnsFields.test.ts`;
  - `app/ui/src/lib/api.ts` (comments at lines 62, 310 and 338);
  - `app/src-tauri/src/state.rs:170-178`: `dns_update_needed` stays macOS-meaningful; the Windows service is installed with the app, so the trait default `false` is right.
- Modify docs:
  - `docs/winvpn-user-guide.en.md` and `.hu.md` §5.6 (DNS): the modes, NRPT, the probe, SSTP.
  - `docs/linvpn-user-guide.en.md` and `.hu.md` §5.5: the modes as NM keys; Automatic's fallback lowers the Wi-Fi/Ethernet DNS priority while it lasts; check with `resolvectl status`.
  - `docs/architecture.md`: lines 1166–1169 (the Linux DNS rule) and 1460–1462 ("store and ignore").
  - `docs/release-notes/2.1.15.md` EN/HU: the feature, and the static-challenge regression test (no behavior change).
  - `crates/core/src/dns_settings.rs` module doc: "Linux and Windows … never use it" is no longer true.

- [ ] **Step 1:** Update `dnsFields.test.ts` so the section is visible on linux and windows for openvpn, wireguard and sstp, and hidden for the other kinds. Run `cd app/ui && npm test`. Expected: FAIL.
- [ ] **Step 2:** Change `visible()`. Run `npm test` and `npx svelte-check`. Expected: pass, 0 errors.
- [ ] **Step 3:** Write the docs in the style of the macOS sections (`docs/user-guide.en.md`, search for "DNS mode"). No new l10n keys are needed unless a help text in the editor names macOS; check with `grep -n -i macos app/ui/src/lib/manage/*.svelte`.
- [ ] **Step 4:** Run `scripts/check-l10n.sh`. Expected: OK.
- [ ] **Step 5: Commit:** `app, docs: DNS settings on Windows and Linux`.

---

### Task 9: Merge, full gates, review, release 2.1.15

- [ ] Merge the Linux and Windows branches into `dns-winlin`, resolving conflicts in `dns_policy` and `service_proto`.
- [ ] Full gates:
  - `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`;
  - `scripts/test-root.sh` (expect 20), `scripts/check-windows.sh`, `scripts/check-l10n.sh`, `scripts/check-ignored.sh`;
  - `cd app/ui && npm test && npx svelte-check`;
  - `cargo test -p macvpn-platform-linux` on the Linux VM.
- [ ] Energy review: no new timers (the 5-minute `dns-check` already exists). The probe runs only on connect and on checks. The Linux D-Bus reads happen only at those moments, with no polling.
- [ ] crit review of the diff with the maintainer (CLAUDE.md: a larger change). Apply their comments.
- [ ] Merge `dns-winlin` into `develop`, then run the release flow for 2.1.15. MacVPN root 19 → 20, so the user presses Authorize. WinVPN service 2 ships inside the MSI.
