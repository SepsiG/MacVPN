//! The helper's DNS manager from root layer 15: the one place that puts a VPN's DNS into effect, for every kind
//! that sets DNS (OpenVPN and SSTP through the `ovpn-dns` hook, WireGuard after `wg-quick up`), through the
//! SystemConfiguration **dynamic store** (as Tunnelblick, Viscosity and OpenVPN 2.7's own `dns-updown` do) instead
//! of the services' persistent preferences. The dynamic store is volatile: a reboot leaves nothing behind.
//!
//! - **Entries.** The connection's own supplemental resolvers and, in the `Vpn` layout, the `Setup:` DNS override
//!   of every ordered network service (`dns_plan`, R3a of the plan). Every value written carries `MacVPNOwner`.
//! - **The volatile ledger** `State:/Network/MacVPN/DNS`: the owners (oldest first, each with its layout, servers
//!   and search domains) and the originals of the overridden services, captured when the first override is
//!   written and given back when the last one goes. It lives in the dynamic store too, so it disappears with
//!   everything it describes.
//! - **Stacking.** The newest `Vpn`-layout owner holds the override; split entries of several connections
//!   coexist; when the owner in effect leaves, the next newest `Vpn` owner takes the override again.
//! - **Restore.** Only values that still carry the marker are put back; a value the system changed meanwhile is
//!   left as it is (logged).
//! - **Reconcile** (every `up`, `down`, `status` and `dns-reconcile`): root layer 14's leftover ledger first
//!   (`dns_legacy`), then the dead owners' entries are removed, and drift is repaired (configd's PreferencesMonitor
//!   rewriting a `Setup:` key after a preferences change, a newly listed service). Without a ledger it reads one key
//!   and returns.
//! - **Modes and the probe.** `acquire` (the hook / WireGuard / SSTP) decides without knowing the tunnel;
//!   `after_connect` (once the routes are in) detects the tunnel, probes the VPN's DNS (`dns_probe`) and decides
//!   again; `check` (`dns-check`, the app about every 5 minutes) probes again: two failed checks in a row fall
//!   back (Automatic), one good one returns. The decision is `dns_plan::decide`; the session is
//!   `<run>/dns-session` (`dns_session`).
//!
//! One `flock` (`dns_legacy::lock_dir`, `/var/db/macvpn/dns/lock`) serializes every change across processes.

use crate::macos::dns_legacy::lock_dir;
pub use crate::macos::dns_legacy::{Dns, is_search_domain, log_over_limits};
use crate::macos::dns_plan::{
    self as plan, Effective, Layout, Original, Primary, Probe, Pushed, Service, Tunnel, Warn,
};
use crate::macos::dns_session::{self, Session};
use crate::macos::dns_store::{self, Dict, Op, Store, Value, list_of, strings};
use crate::macos::exec::{Cmd, EnvMode};
use crate::macos::fsx;
use crate::macos::log::Log;
use crate::macos::paths::{Settings, is_dir, is_file, is_symlink};
use crate::shared::cli::is_uuid;
use crate::shared::l10n::tr;
use macvpn_core::dns_settings::{DnsMode, is_dns_domain, is_dns_server};
use macvpn_core::status::DnsState;
use std::path::{Path, PathBuf};

/// The volatile ledger's key.
pub const LEDGER_KEY: &str = "State:/Network/MacVPN/DNS";
const LEDGER_VERSION: i64 = 15;
const GLOBAL_IPV4: &str = "State:/Network/Global/IPv4";
const SETUP_IPV4: &str = "Setup:/Network/Global/IPv4";
const GLOBAL_DNS: &str = "State:/Network/Global/DNS";
/// Consecutive failed `dns-check`s before the Automatic mode falls back (each check already sends twice).
pub const FAILS_TO_FALL_BACK: u32 = 2;
/// At most this many network services are handled (a Mac lists about ten).
const MAX_SERVICES: usize = 64;
/// At most this many owners are kept in the ledger.
const MAX_OWNERS: usize = 32;
/// A connection's DNS is probed by `dns-check` at most once in this many seconds (the app's own interval is 300 s;
/// this guards against a repeated or concurrent question counting one broken DNS twice).
pub const MIN_CHECK_SECS: i64 = 20;
/// Waiting for configd to merge the change: at most 10 × 100 ms.
const VERIFY_TRIES: u32 = 10;

/// A network service ID as configd lists them (a UUID; letters, digits and `-`).
fn is_service_id(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// One connection holding DNS.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnerRec {
    id: String,
    layout: Layout,
    servers: Vec<String>,
    search: Vec<String>,
    /// Match-only domains and reverse zones (the local entry's overlap rule needs them on a network change).
    resolve: Vec<String>,
    zones: Vec<String>,
}

impl OwnerRec {
    fn new(id: &str, layout: Layout, e: &Effective) -> OwnerRec {
        OwnerRec {
            id: id.into(),
            layout,
            servers: e.servers.clone(),
            search: e.search.clone(),
            resolve: e.resolve.clone(),
            zones: e.zones.clone(),
        }
    }

    fn effective(&self) -> Effective {
        Effective {
            servers: self.servers.clone(),
            search: self.search.clone(),
            resolve: self.resolve.clone(),
            zones: self.zones.clone(),
        }
    }
}

/// The volatile ledger (`State:/Network/MacVPN/DNS`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Ledger {
    /// Oldest first.
    owners: Vec<OwnerRec>,
    /// The `Setup:` DNS of every overridden service before MacVPN.
    originals: Vec<Original>,
    /// Services never overridden (another VPN's interface).
    skipped: Vec<String>,
}

impl Ledger {
    /// Lenient: entries that do not pass the checks are dropped (the store is root's, but read strictly anyway).
    fn from_value(v: Option<Value>) -> Ledger {
        let Some(Value::Dict(d)) = v else { return Ledger::default() };
        let owners = match d.get("Owners") {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|o| {
                    let o = o.as_dict()?;
                    let id = o.get("Id")?.as_str().filter(|i| is_uuid(i))?.to_string();
                    let layout = Layout::from_raw(o.get("Layout")?.as_str()?)?;
                    let servers = list_of(o, "ServerAddresses");
                    let search = list_of(o, "SearchDomains");
                    let resolve = list_of(o, "MatchDomains");
                    let zones = list_of(o, "Zones");
                    (servers.iter().all(|s| is_dns_server(s))
                        && [&search, &resolve, &zones].iter().all(|l| l.iter().all(|s| is_dns_domain(s))))
                    .then_some(OwnerRec { id, layout, servers, search, resolve, zones })
                })
                .take(MAX_OWNERS)
                .collect(),
            _ => Vec::new(),
        };
        let originals = match d.get("Originals") {
            Some(Value::Dict(o)) => o
                .iter()
                .filter(|(sid, _)| is_service_id(sid))
                .filter_map(|(sid, v)| {
                    let v = v.as_dict()?;
                    let present = v.get("Present")?.as_int()? == 1;
                    let dict = v.get("Value").and_then(Value::as_dict).cloned().unwrap_or_default();
                    Some(Original { sid: sid.clone(), present, dict })
                })
                .take(MAX_SERVICES)
                .collect(),
            _ => Vec::new(),
        };
        let skipped = d
            .get("Skipped")
            .and_then(Value::as_strings)
            .unwrap_or_default()
            .into_iter()
            .filter(|s| is_service_id(s))
            .take(MAX_SERVICES)
            .collect();
        Ledger { owners, originals, skipped }
    }

    fn to_dict(&self) -> Dict {
        let owners = self
            .owners
            .iter()
            .map(|o| {
                Value::Dict(Dict::from([
                    ("Id".to_string(), Value::Str(o.id.clone())),
                    ("Layout".to_string(), Value::Str(o.layout.raw().into())),
                    ("ServerAddresses".to_string(), strings(&o.servers)),
                    ("SearchDomains".to_string(), strings(&o.search)),
                    ("MatchDomains".to_string(), strings(&o.resolve)),
                    ("Zones".to_string(), strings(&o.zones)),
                ]))
            })
            .collect();
        let originals = self
            .originals
            .iter()
            .map(|o| {
                let v = Dict::from([
                    ("Present".to_string(), Value::Int(i64::from(o.present))),
                    ("Value".to_string(), Value::Dict(o.dict.clone())),
                ]);
                (o.sid.clone(), Value::Dict(v))
            })
            .collect();
        Dict::from([
            ("Version".to_string(), Value::Int(LEDGER_VERSION)),
            ("Owners".to_string(), Value::Array(owners)),
            ("Originals".to_string(), Value::Dict(originals)),
            ("Skipped".to_string(), strings(&self.skipped)),
        ])
    }

    fn is_empty(&self) -> bool {
        self.owners.is_empty() && self.originals.is_empty()
    }

    /// The newest `Vpn`-layout owner: it holds the override.
    fn override_owner(&self) -> Option<&OwnerRec> {
        self.owners.iter().rev().find(|o| matches!(o.layout, Layout::Vpn { .. }))
    }
}

/// A service on another VPN's interface (`Setup:/Network/Service/<sid>/Interface`: type PPP / IPSec / VPN, or a
/// `utun` / `ppp` / `ipsec` device) is never overridden.
fn vpn_like(iface: Option<&Dict>) -> bool {
    let Some(i) = iface else { return false };
    let t = i.get("Type").and_then(Value::as_str).unwrap_or_default();
    let dev = i.get("DeviceName").and_then(Value::as_str).unwrap_or_default();
    matches!(t, "PPP" | "IPSec" | "VPN") || ["utun", "ppp", "ipsec"].iter().any(|p| dev.starts_with(p))
}

/// The keys of `id`'s own entries.
fn own_pattern(id: &str) -> String {
    format!("^State:/Network/Service/macvpn-{id}(-match|-local)?/DNS$")
}

/// Equal server lists up to the address notation.
fn same_servers(a: &[String], b: &[String]) -> bool {
    let ip = |v: &[String]| -> Vec<String> {
        v.iter().map(|s| s.parse::<std::net::IpAddr>().map(|i| i.to_string()).unwrap_or_else(|_| s.clone())).collect()
    };
    ip(a) == ip(b)
}

/// The DNS manager over a dynamic store (`dns_store::Store`) and the lock directory.
pub struct Manager {
    pub lock_dir: PathBuf,
    pub store: Box<dyn Store>,
    /// `dscacheutil -flushcache` after a resolver change; a no-op in the tests.
    pub flush: Box<dyn Fn()>,
    /// Wait for configd's merged result after an override (the real store only).
    pub verify: bool,
    /// Test mode: the run directory's files are not root's.
    pub test_mode: bool,
    /// `dns-check` probes a connection at most once in this many seconds ([`MIN_CHECK_SECS`]; 0 in test mode).
    pub min_check_secs: i64,
}

/// The manager of this invocation: as root the real dynamic store and `/var/db/macvpn/dns`; in test mode only with
/// `MVPN_DYNSTORE` (the file store), never the real store.
pub fn manager(s: &Settings) -> Option<Manager> {
    let store = dns_store::store(s)?;
    let flush: Box<dyn Fn()> = if s.test_mode {
        Box::new(|| {})
    } else {
        Box::new(|| {
            crate::macos::exec::quiet(&Cmd::system("/usr/bin/dscacheutil").arg("-flushcache"), EnvMode::Minimal);
        })
    };
    Some(Manager {
        lock_dir: s.dns_base.clone(),
        store,
        flush,
        verify: !s.test_mode,
        test_mode: s.test_mode,
        min_check_secs: if s.test_mode { 0 } else { MIN_CHECK_SECS },
    })
}

/// An owner is alive while its run directory has a valid kind and its engine is not `failed` (as `status` sees it).
pub fn owner_alive(s: &Settings, id: &str) -> bool {
    let d = s.run_dir(id);
    is_uuid(id)
        && is_dir(&d)
        && !is_symlink(&d)
        && crate::shared::cli::is_kind(&fsx::cat(&d.join("kind")))
        && crate::macos::status::one(s, &d).state != "failed"
}

/// The connection log of `id` for the reconcile's messages (only an existing regular file).
pub fn log_of(s: &Settings, id: &str) -> Log {
    let p = s.log_file(id);
    if is_uuid(id) && is_file(&p) && !is_symlink(&p) { Log::at(p) } else { Log::none() }
}

/// Root layer 14's leftover ledger first (always restored: nothing of this layer keeps it, and an owner id alive
/// again under this layer must not keep the old persistent override, which would become this layer's "original"),
/// then [`Manager::reconcile`], with the run directories as the liveness source.
pub fn reconcile(s: &Settings, wait: bool) {
    if let Some(legacy) = crate::macos::dns_legacy::manager(s) {
        legacy.reconcile(&|_| false, &|id| log_of(s, id), wait);
    }
    if let Some(m) = manager(s) {
        m.reconcile(&|id| owner_alive(s, id), &|id| log_of(s, id), wait);
    }
}

impl Manager {
    fn dict(&self, key: &str) -> Option<Dict> {
        self.store.dict(key)
    }

    fn ledger(&self) -> Ledger {
        Ledger::from_value(self.store.get(LEDGER_KEY))
    }

    /// The primary service's ID and the ordered services with their current `Setup:` / `State:` DNS.
    fn network(&self, l: &Ledger) -> (Option<String>, Vec<Service>) {
        let primary = self
            .dict(GLOBAL_IPV4)
            .and_then(|d| d.get("PrimaryService").and_then(Value::as_str).map(str::to_string))
            .filter(|s| is_service_id(s));
        let order: Vec<String> = self
            .dict(SETUP_IPV4)
            .map(|d| list_of(&d, "ServiceOrder"))
            .unwrap_or_default()
            .into_iter()
            .filter(|s| is_service_id(s))
            .take(MAX_SERVICES)
            .collect();
        let services = order
            .into_iter()
            .map(|sid| {
                let vpn_like = if l.skipped.contains(&sid) {
                    true
                } else if l.originals.iter().any(|o| o.sid == sid) {
                    false
                } else {
                    vpn_like(self.dict(&format!("Setup:/Network/Service/{sid}/Interface")).as_ref())
                };
                Service {
                    setup: self.dict(&plan::setup_key(&sid)),
                    state: self.dict(&format!("State:/Network/Service/{sid}/DNS")),
                    vpn_like,
                    sid,
                }
            })
            .collect();
        (primary, services)
    }

    /// The primary service's facts for the local entry.
    fn primary(&self, sid: &str, l: &Ledger) -> Primary {
        let state = |what: &str| self.dict(&format!("State:/Network/Service/{sid}/{what}"));
        plan::primary(
            sid,
            l.originals.iter().find(|o| o.sid == sid),
            state("DNS").as_ref(),
            state("IPv4").as_ref(),
            state("IPv6").as_ref(),
        )
    }

    /// Only the operations that change something.
    fn changing(&self, ops: Vec<Op>) -> Vec<Op> {
        ops.into_iter()
            .filter(|op| match op {
                Op::Set(k, d) => self.dict(k).as_ref() != Some(d),
                Op::Remove(k) => self.store.get(k).is_some(),
            })
            .collect()
    }

    /// The override of the newest `Vpn` owner (capturing the originals of services seen for the first time), or,
    /// without one, the restore of every override (the originals then leave the ledger).
    fn overrides(&self, l: &mut Ledger, services: &[Service], log: &Log) -> Vec<Op> {
        match l.override_owner().cloned() {
            Some(o) => {
                for s in services {
                    if s.vpn_like {
                        if !l.skipped.contains(&s.sid) {
                            l.skipped.push(s.sid.clone());
                        }
                    } else if !l.originals.iter().any(|x| x.sid == s.sid) {
                        // A value already ours without an original cannot be told apart: treated as none.
                        let ours = plan::is_ours(s.setup.as_ref());
                        l.originals.push(Original {
                            sid: s.sid.clone(),
                            present: s.setup.is_some() && !ours,
                            dict: if ours { Dict::new() } else { s.setup.clone().unwrap_or_default() },
                        });
                    }
                }
                let e = Effective { servers: o.servers.clone(), search: o.search.clone(), ..Default::default() };
                let local = o.layout == Layout::Vpn { local: true };
                plan::override_ops(&o.id, &e, local, &l.originals, services)
            }
            None if l.originals.is_empty() => Vec::new(),
            None => {
                let (ops, changed) = plan::restore_ops(&l.originals, &|sid| self.dict(&plan::setup_key(sid)));
                if !changed.is_empty() {
                    log.step(&tr("a DNS setting was changed by the system meanwhile and is left as it is", &[]));
                }
                l.originals.clear();
                l.skipped.clear();
                ops
            }
        }
    }

    /// One batch: `ops` and the ledger. `true` when it was applied (or nothing had to change). The resolver cache
    /// is flushed when a resolver entry changed.
    fn commit(&self, l: &Ledger, mut ops: Vec<Op>, log: &Log) -> bool {
        let resolver = !ops.is_empty();
        if l.is_empty() {
            if self.store.get(LEDGER_KEY).is_some() {
                ops.push(Op::Remove(LEDGER_KEY.into()));
            }
        } else if self.dict(LEDGER_KEY) != Some(l.to_dict()) {
            ops.push(Op::Set(LEDGER_KEY.into(), l.to_dict()));
        }
        if ops.is_empty() {
            return true;
        }
        if let Err(e) = self.store.apply(&ops) {
            log.step(&tr("DNS could not be changed: %@", &[&e]));
            return false;
        }
        if resolver {
            (self.flush)();
        }
        true
    }

    /// The ledger holds `id` exactly as `layout` with `e`'s lists (`Layout::None`: not at all).
    fn holds(&self, id: &str, layout: Layout, e: &Effective) -> bool {
        match self.ledger().owners.iter().find(|o| o.id == id) {
            None => layout == Layout::None,
            Some(o) => *o == OwnerRec::new(id, layout, e),
        }
    }

    /// Puts `id`'s entries in `layout` and settles the override (the caller holds the lock). `false`: not applied.
    fn publish_locked(&self, id: &str, layout: Layout, e: &Effective, log: &Log) -> bool {
        let mut l = self.ledger();
        l.owners.retain(|o| o.id != id);
        if layout != Layout::None {
            l.owners.push(OwnerRec::new(id, layout, e));
            if l.owners.len() > MAX_OWNERS {
                l.owners.remove(0);
            }
        }
        let (primary, services) = self.network(&l);
        let primary = primary.map(|sid| self.primary(&sid, &l));
        let mut ops = self.changing(plan::own_entries(id, layout, e, primary.as_ref()));
        if let Layout::Vpn { local: true } = layout
            && let Some(p) = &primary
        {
            let names = plan::local_matches(e, p);
            if !names.is_empty() && !p.servers.is_empty() {
                log.step(&tr("the local network's names stay on its DNS: %@", &[&names.join(", ")]));
            }
        }
        ops.extend(self.overrides(&mut l, &services, log));
        self.commit(&l, ops, log)
    }

    /// configd's merged result shows `servers` as the default resolver's (at most 10 × 100 ms).
    fn verified(&self, servers: &[String]) -> bool {
        if !self.verify {
            return true;
        }
        for i in 0..VERIFY_TRIES {
            let now = self.dict(GLOBAL_DNS).map(|d| list_of(&d, "ServerAddresses")).unwrap_or_default();
            if same_servers(&now, servers) {
                return true;
            }
            if i + 1 < VERIFY_TRIES {
                crate::macos::exec::sleep_ms(100, false);
            }
        }
        false
    }

    /// Applies `d` for `id` under the lock (publishing when the layout or the lists changed, or the ledger does not
    /// hold them), writes the session and logs the change. `continuing` (after connect, `dns-check`): only while
    /// the connection still has its session (it may have gone down during the probe); `None` otherwise. A publish
    /// that failed keeps the previous session, so the next check (or the ledger comparison) tries again.
    #[allow(clippy::too_many_arguments)]
    fn apply_decision(
        &self,
        id: &str,
        run: &Path,
        mode: DnsMode,
        tunnel: Tunnel,
        probe: (Probe, &str),
        fails: u32,
        d: plan::Decision,
        e: Effective,
        prev: Option<&Session>,
        continuing: bool,
        log: &Log,
    ) -> Option<Session> {
        let guard = lock_dir(&self.lock_dir, true);
        if guard.is_none() {
            log.step(&tr("the DNS ledger cannot be used, DNS not changed", &[]));
        }
        if continuing && dns_session::read_session(run, self.test_mode).is_none() {
            return None;
        }
        let changed = prev.is_none_or(|p| p.layout != d.layout || p.eff != e) || !self.holds(id, d.layout, &e);
        let applied = !changed || (guard.is_some() && self.publish_locked(id, d.layout, &e, log));
        if !applied && let Some(p) = prev {
            return Some(p.clone());
        }
        let since = match prev {
            Some(p) if p.layout == d.layout => p.since,
            _ => crate::macos::exec::now(),
        };
        let s = Session { mode, tunnel, layout: d.layout, probe: probe.0, fails, warn: d.warn, eff: e, since };
        let _ = dns_session::write_session(run, &s);
        drop(guard);
        let was = prev.map(|p| (p.layout, p.warn));
        if applied && was != Some((d.layout, d.warn)) {
            self.log_change(was, &d, &s.eff, probe.1, log);
        }
        Some(s)
    }

    fn log_change(
        &self,
        was: Option<(Layout, Option<Warn>)>,
        d: &plan::Decision,
        e: &Effective,
        detail: &str,
        log: &Log,
    ) {
        if d.warn == Some(Warn::TargetedOnFullTunnel) {
            log.step(&tr("full tunnel: the Targeted mode acts as Automatic", &[]));
        }
        match (d.layout, d.warn) {
            (Layout::None, _) => log.step(&tr("the VPN sent no DNS; internal names will not resolve", &[])),
            (Layout::Fallback, _) => log.step(&tr(
                "the VPN's DNS does not resolve internet names (%@): only the VPN's domains use it now",
                &[detail],
            )),
            (Layout::Vpn { local: false }, Some(Warn::Failing)) => {
                log.step(&tr("Strict DNS: the VPN's DNS does not answer (%@); DNS stays in the tunnel", &[detail]))
            }
            (Layout::Vpn { .. }, Some(Warn::Failing)) => {
                log.step(&tr("the VPN's DNS does not answer (%@); it stays in effect", &[detail]))
            }
            (Layout::Vpn { .. }, _) => {
                if matches!(was, Some((Layout::Fallback, _))) {
                    log.step(&tr("the VPN's DNS answers again: it is in effect for every name", &[]));
                } else if self.verified(&e.servers) {
                    log.step(&tr(
                        "the VPN's DNS is in effect (%@ servers, %@ domains), verified",
                        &[&e.servers.len().to_string(), &e.search.len().to_string()],
                    ));
                } else {
                    log.step(&tr("the VPN's DNS is set; the system has not confirmed it yet", &[]));
                }
            }
            (Layout::Split, Some(Warn::TargetedNoDomains)) => {
                log.step(&tr("Targeted DNS: no domain uses the VPN's DNS (the VPN sent none, none is set)", &[]))
            }
            (Layout::Split, _) => log.step(&tr(
                "only the VPN's domains use the VPN's DNS (%@ servers, %@ domains)",
                &[&e.servers.len().to_string(), &(e.search.len() + e.resolve.len()).to_string()],
            )),
        }
    }

    /// From the hook / WireGuard / SSTP: the VPN-sent DNS and the connection's request (`<run>/dns-request`); no
    /// probe runs. The same connection's DNS step again (a live session, or the one its `down` released: OpenVPN's
    /// restart) keeps the tunnel it knew and, for the same DNS, a failed probe: the safe layout stays until a probe
    /// says the VPN's DNS answers.
    pub fn acquire(&self, id: &str, run: &Path, pushed: &Pushed, log: &Log) -> DnsState {
        let req = dns_session::read_request(run, self.test_mode);
        log.step(&tr("DNS mode: %@", &[req.mode.raw()]));
        let e = plan::effective(pushed, &req);
        let prev = dns_session::read_session(run, self.test_mode);
        let memory = prev.clone().or_else(|| dns_session::read_released(run, self.test_mode));
        let tunnel = memory.as_ref().map_or(Tunnel::Unknown, |m| m.tunnel);
        let (probe, fails) = match &memory {
            Some(m) if m.probe == Probe::Failed && m.mode == req.mode && m.eff == e => (Probe::Failed, m.fails),
            _ => (Probe::NotRun, 0),
        };
        let d = plan::decide(req.mode, tunnel, !e.servers.is_empty(), e.has_match(), probe);
        let s = self.apply_decision(id, run, req.mode, tunnel, (probe, ""), fails, d, e, prev.as_ref(), false, log);
        dns_session::remove_released(run);
        s.map_or(DnsState::None, |s| s.state())
    }

    /// After connect (the routes are in): the tunnel, the probe, the decision and the re-publish. A connection
    /// whose DNS step never ran (WireGuard without `DNS =`) gets its request applied here.
    pub fn after_connect(&self, s: &Settings, id: &str, run: &Path, tunnel: Tunnel, log: &Log) -> DnsState {
        let prev = match dns_session::read_session(run, self.test_mode) {
            Some(p) => p,
            None => {
                self.acquire(id, run, &Pushed::default(), log);
                match dns_session::read_session(run, self.test_mode) {
                    Some(p) => p,
                    None => return DnsState::None,
                }
            }
        };
        let has = (!prev.eff.servers.is_empty(), prev.eff.has_match());
        let probes = plan::decide(prev.mode, tunnel, has.0, has.1, Probe::NotRun).probes;
        let (probe, detail) =
            if probes { crate::macos::dns_probe::probe(s, &prev.eff.servers) } else { (Probe::NotRun, String::new()) };
        let d = plan::decide(prev.mode, tunnel, has.0, has.1, probe);
        let fails = u32::from(probe == Probe::Failed);
        let e = prev.eff.clone();
        self.apply_decision(id, run, prev.mode, tunnel, (probe, &detail), fails, d, e, Some(&prev), true, log)
            .map_or(DnsState::None, |s| s.state())
    }

    /// `dns-check <id>`: probes again when the session probes; two failures in a row fall back (or warn), one
    /// success returns. One check of a connection at a time and at most one probe in [`Manager::min_check_secs`]:
    /// otherwise the current state, unprobed. `None`: no session (not running, no DNS step yet, or released during
    /// the probe).
    pub fn check(&self, s: &Settings, id: &str, run: &Path, log: &Log) -> Option<DnsState> {
        let prev = dns_session::read_session(run, self.test_mode)?;
        let has = (!prev.eff.servers.is_empty(), prev.eff.has_match());
        if !plan::decide(prev.mode, prev.tunnel, has.0, has.1, Probe::NotRun).probes {
            return Some(prev.state());
        }
        let Some(mut lock) = dns_session::check_lock(run) else { return Some(prev.state()) };
        let now = crate::macos::exec::now();
        if lock.last().is_some_and(|t| (0..self.min_check_secs).contains(&(now - t))) {
            return Some(prev.state());
        }
        // Read again under the check lock: the session of a check that just finished.
        let prev = dns_session::read_session(run, self.test_mode)?;
        let (p, detail) = crate::macos::dns_probe::probe(s, &prev.eff.servers);
        lock.stamp(crate::macos::exec::now());
        let (probe, fails) = match p {
            Probe::NotRun => return Some(prev.state()),
            Probe::Ok => (Probe::Ok, 0),
            Probe::Failed => {
                let fails = prev.fails.saturating_add(1);
                // A single failure keeps the current layout (no flapping); the second one decides.
                let keep = if prev.probe == Probe::Failed { Probe::Failed } else { Probe::Ok };
                (if fails >= FAILS_TO_FALL_BACK { Probe::Failed } else { keep }, fails)
            }
        };
        let d = plan::decide(prev.mode, prev.tunnel, has.0, has.1, probe);
        let e = prev.eff.clone();
        self.apply_decision(id, run, prev.mode, prev.tunnel, (probe, &detail), fails, d, e, Some(&prev), true, log)
            .map(|s| s.state())
    }

    /// `id` leaves: its entries go, the override is handed to the next newest `Vpn` owner or restored, and its
    /// session is retired (`dns_session::retire_session`, under the lock: a `dns-check` still probing finds no
    /// session and changes nothing). `true` if it held anything.
    pub fn release(&self, id: &str, run: &Path, log: &Log) -> bool {
        let has_session = std::fs::symlink_metadata(dns_session::session_path(run)).is_ok();
        let held = self.store.get(LEDGER_KEY).is_some() || !self.store.keys(&own_pattern(id)).is_empty();
        if !held && !has_session {
            return false;
        }
        let Some(_g) = lock_dir(&self.lock_dir, true) else {
            log.step(&tr("the DNS ledger cannot be used, DNS not changed", &[]));
            dns_session::retire_session(run);
            return false;
        };
        dns_session::retire_session(run);
        if !held {
            return false;
        }
        let mut l = self.ledger();
        let held_override = l.override_owner().is_some_and(|o| o.id == id);
        l.owners.retain(|o| o.id != id);
        let mut ops: Vec<Op> = self.store.keys(&own_pattern(id)).into_iter().map(Op::Remove).collect();
        let (_, services) = self.network(&l);
        let restoring = l.override_owner().is_none() && !l.originals.is_empty();
        ops.extend(self.overrides(&mut l, &services, log));
        if !l.owners.is_empty() {
            log.step(&tr(
                if held_override && l.override_owner().is_some() {
                    "another MacVPN connection still holds DNS: the newest one's DNS settings are applied"
                } else {
                    "another MacVPN connection still holds DNS; the original DNS comes back when the last one disconnects"
                },
                &[],
            ));
        }
        if self.commit(&l, ops, log) && restoring {
            log.step(&tr("the original DNS is back", &[]));
        }
        true
    }

    /// Drops the owners for which `alive` is false (their entries go by key pattern, no run directory needed) and
    /// repairs drift: a `Setup:` value that lost the marker (rewritten by configd) becomes the new original and is
    /// overridden again; a newly listed service is overridden. Without a ledger it reads one key and returns.
    /// `wait`: wait for the lock (otherwise skip when it is busy).
    pub fn reconcile(&self, alive: &dyn Fn(&str) -> bool, log_for: &dyn Fn(&str) -> Log, wait: bool) {
        if self.store.get(LEDGER_KEY).is_none() {
            return;
        }
        let Some(_g) = lock_dir(&self.lock_dir, wait) else { return };
        let mut l = self.ledger();
        let before = l.clone();
        let dead: Vec<String> = l.owners.iter().filter(|o| !alive(&o.id)).map(|o| o.id.clone()).collect();
        let mut ops = Vec::new();
        for id in &dead {
            log_for(id).step(&tr("the connection is no longer running: its DNS settings are released", &[]));
            ops.extend(self.store.keys(&own_pattern(id)).into_iter().map(Op::Remove));
        }
        l.owners.retain(|o| !dead.contains(&o.id));
        let (primary, services) = self.network(&l);
        // The local entries follow the network (another Wi-Fi, a wired network, offline): the primary service's
        // DNS, domains and subnets as they are now.
        let primary = primary.map(|sid| self.primary(&sid, &l));
        for o in l.owners.iter().filter(|o| o.layout == Layout::Vpn { local: true }) {
            let local = plan::entry_key(&o.id, "-local");
            let entries = plan::own_entries(&o.id, o.layout, &o.effective(), primary.as_ref());
            ops.extend(self.changing(
                entries.into_iter().filter(|op| matches!(op, Op::Set(k, _) | Op::Remove(k) if *k == local)).collect(),
            ));
        }
        if l.override_owner().is_some() {
            for s in &services {
                if let Some(cur) = s.setup.as_ref().filter(|c| !plan::is_ours(Some(c)))
                    && let Some(o) = l.originals.iter_mut().find(|o| o.sid == s.sid)
                {
                    o.present = true;
                    o.dict = cur.clone();
                }
            }
        }
        let log = dead.last().map(|id| log_for(id)).unwrap_or_default();
        ops.extend(self.overrides(&mut l, &services, &log));
        if ops.is_empty() && l == before {
            return;
        }
        self.commit(&l, ops, &log);
    }
}

/// The routing table's answer for `dest` (`route -n get [-inet6] <dest>`): the interface, if any.
fn route_iface(s: &Settings, family: &str, dest: &str) -> Option<String> {
    let mode = if s.test_mode { EnvMode::Inherit } else { EnvMode::Minimal };
    let (ok, out) =
        crate::macos::exec::capture(&Cmd::new(&s.route).args(["-n", "get", family, dest]), mode, 64 * 1024)?;
    if !ok {
        return None;
    }
    String::from_utf8_lossy(&out)
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface:").map(|i| i.trim().to_string()))
        .filter(|i| !i.is_empty() && i.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// Full or split, the same way for every kind: `1.0.0.1` and `129.0.0.1` (one in each `def1` half) both through
/// `iface` is a full tunnel. IPv6 alone through it is not (a VPN that routes `::/0` only to blackhole IPv6 against
/// leaks would otherwise turn the Targeted mode into Automatic). `Unknown` without an interface.
pub fn detect_tunnel(s: &Settings, iface: &str) -> Tunnel {
    if iface.is_empty() {
        return Tunnel::Unknown;
    }
    let via = |family: &str, dest: &str| route_iface(s, family, dest).as_deref() == Some(iface);
    if via("-inet", "1.0.0.1") && via("-inet", "129.0.0.1") { Tunnel::Full } else { Tunnel::Split }
}

/// What `mvpn dns-check <id>` prints, with its exit code (shared by the command line and `mvpn serve`): the
/// connection's DNS state after probing again (`0`, `<state>\n`), or `1` with nothing when it is not running or
/// has no DNS session. Changes at most this connection's own DNS layout (the fallback and its return).
pub fn check_answer(ctx: &crate::macos::ctx::Ctx) -> (i32, String) {
    let Some(id) = crate::macos::liveness::canonical_id(&ctx.kind) else {
        return (ctx.die(tr("Invalid ID", &[])).0, String::new());
    };
    let s = &ctx.s;
    let run = s.run_dir(&id);
    if !is_dir(&run) || is_symlink(&run) || !crate::shared::cli::is_kind(&fsx::cat(&run.join("kind"))) {
        return (1, String::new());
    }
    let state = match manager(s) {
        Some(m) => m.check(s, &id, &run, &log_of(s, &id)),
        None => dns_session::read_session(&run, s.test_mode).map(|x| x.state()),
    };
    state.map_or((1, String::new()), |st| (0, format!("{}\n", st.raw())))
}

/// `mvpn dns-check <id>`.
pub fn check_main(ctx: &crate::macos::ctx::Ctx) -> i32 {
    let (code, out) = check_answer(ctx);
    crate::macos::out_raw(&out);
    code
}

/// `mvpn up`, right after the tunnel came up (the routes are in): the tunnel detection, the probe and the
/// decision for the kinds the DNS manager handles. Never fails `up`: a broken VPN DNS only changes the layout.
pub fn after_connect(ctx: &crate::macos::ctx::Ctx) {
    if !matches!(ctx.kind.as_str(), "openvpn" | "wireguard" | "sstp") {
        return;
    }
    let Some(m) = manager(&ctx.s) else { return };
    let run = ctx.run();
    let mut iface = fsx::cat(&run.join("iface"));
    if ctx.kind == "wireguard" && !iface.is_empty() {
        iface = fsx::cat(&ctx.s.wg_run.join(format!("{iface}.name")));
    }
    let tunnel = detect_tunnel(&ctx.s, &iface);
    m.after_connect(&ctx.s, &ctx.id, run, tunnel, &ctx.log);
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::macos::dns_store::MemStore;

    /// A manager over a shared in-memory store with one primary service `S1` (`192.168.1.1`, domain `lan`), for
    /// the hook's tests.
    pub fn mem_manager(lock_dir: PathBuf) -> (Manager, Rc<MemStore>) {
        let store = Rc::new(MemStore { ipmonitor: true, ..Default::default() });
        store.seed_primary("S1", &["192.168.1.1"], Some("lan"), "192.168.1.20");
        let m = Manager {
            lock_dir,
            store: Box::new(Shared(store.clone())),
            flush: Box::new(|| {}),
            verify: true,
            test_mode: true,
            min_check_secs: 0,
        };
        (m, store)
    }
    use macvpn_core::dns_settings::DnsRequest;
    use std::cell::Cell;
    use std::rc::Rc;

    const A: &str = "0A1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
    const B: &str = "0B1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";

    /// The store shared between the manager and the test.
    struct Shared(Rc<MemStore>);

    impl Store for Shared {
        fn get(&self, key: &str) -> Option<Value> {
            self.0.get(key)
        }
        fn keys(&self, pattern: &str) -> Vec<String> {
            self.0.keys(pattern)
        }
        fn apply(&self, ops: &[Op]) -> Result<(), String> {
            self.0.apply(ops)
        }
    }

    struct T {
        base: PathBuf,
        store: Rc<MemStore>,
        m: Manager,
        flushes: Rc<Cell<u32>>,
        log: Log,
        s: Settings,
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    impl T {
        fn new() -> T {
            let base = std::env::temp_dir().join(format!("mvpn-dyn-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(base.join("run")).unwrap();
            let store = Rc::new(MemStore { ipmonitor: true, ..Default::default() });
            store.seed_primary("S1", &["192.168.1.1"], Some("lan"), "192.168.1.20");
            // A second ordered service (Ethernet, not connected) and another VPN's service.
            store.set(
                "Setup:/Network/Global/IPv4",
                Dict::from([("ServiceOrder".to_string(), strings(&strs(&["S1", "S2", "T1"])))]),
            );
            store.set(
                "Setup:/Network/Service/T1/Interface",
                Dict::from([("Type".to_string(), Value::Str("PPP".into()))]),
            );
            let flushes = Rc::new(Cell::new(0));
            let f = flushes.clone();
            let m = Manager {
                lock_dir: base.join("db/dns"),
                store: Box::new(Shared(store.clone())),
                flush: Box::new(move || f.set(f.get() + 1)),
                verify: true,
                test_mode: true,
                min_check_secs: 0,
            };
            let mut s = Settings::resolve(true, Default::default(), String::new());
            s.dns_probe = Some("ok".into());
            let log = Log::at(base.join("conn.log"));
            T { base, store, m, flushes, log, s }
        }

        fn run(&self, id: &str) -> PathBuf {
            let r = self.base.join("run").join(id);
            std::fs::create_dir_all(&r).unwrap();
            r
        }

        fn request(&self, id: &str, r: &DnsRequest) -> PathBuf {
            let run = self.run(id);
            dns_session::write_request(&run, r).unwrap();
            run
        }

        fn d(&self, key: &str) -> Option<Dict> {
            self.store.dict(key)
        }

        fn setup(&self, sid: &str) -> Option<Dict> {
            self.d(&plan::setup_key(sid))
        }

        fn log_text(&self) -> String {
            std::fs::read_to_string(self.base.join("conn.log")).unwrap_or_default()
        }

        fn ours(&self) -> Vec<String> {
            self.store.keys("^State:/Network/Service/macvpn-")
        }
    }

    impl Drop for T {
        fn drop(&mut self) {
            fsx::remove_rf(&self.base);
        }
    }

    fn pushed(servers: &[&str], search: &[&str]) -> Pushed {
        Pushed { servers: strs(servers), search: strs(search), ..Default::default() }
    }

    fn servers_of(d: &Option<Dict>) -> Vec<String> {
        d.as_ref().map(|d| list_of(d, "ServerAddresses")).unwrap_or_default()
    }

    #[test]
    fn acquire_vpn_layout_writes_entries_overrides_and_ledger() {
        let t = T::new();
        let run = t.run(A);
        assert_eq!(t.m.acquire(A, &run, &pushed(&["10.8.0.1"], &["corp.example"]), &t.log), DnsState::Vpn);
        assert_eq!(servers_of(&t.setup("S1")), ["10.8.0.1"]);
        assert_eq!(servers_of(&t.setup("S2")), ["10.8.0.1"]);
        assert!(t.setup("T1").is_none(), "another VPN's service is never overridden");
        assert_eq!(list_of(&t.setup("S1").unwrap(), "SearchDomains"), ["corp.example", "lan"]);
        let local = t.d(&plan::entry_key(A, "-local")).unwrap();
        assert_eq!(list_of(&local, "SupplementalMatchDomains"), ["lan", "1.168.192.in-addr.arpa"]);
        assert!(t.d(&plan::entry_key(A, "")).is_some());
        let l = t.m.ledger();
        assert_eq!(l.owners.len(), 1);
        assert_eq!(l.originals.len(), 2);
        assert_eq!(l.skipped, ["T1"]);
        assert_eq!(servers_of(&t.d(GLOBAL_DNS)), ["10.8.0.1"]);
        assert!(t.log_text().contains("verified"), "{}", t.log_text());
        assert!(t.flushes.get() >= 1);
        let s = dns_session::read_session(&run, true).unwrap();
        assert_eq!(s.layout, Layout::Vpn { local: true });
    }

    #[test]
    fn release_last_owner_restores_every_override_and_removes_all_keys() {
        let t = T::new();
        let manual = Dict::from([("ServerAddresses".to_string(), strings(&strs(&["1.1.1.1"])))]);
        t.store.set(&plan::setup_key("S2"), manual.clone());
        t.m.acquire(A, &t.run(A), &pushed(&["10.8.0.1"], &[]), &t.log);
        assert!(t.m.release(A, &t.run(A), &t.log));
        assert!(t.setup("S1").is_none(), "absent before: removed");
        assert_eq!(t.setup("S2"), Some(manual), "manual DNS back");
        assert!(t.ours().is_empty());
        assert!(t.store.get(LEDGER_KEY).is_none());
        assert_eq!(servers_of(&t.d(GLOBAL_DNS)), ["192.168.1.1"]);
        assert!(!t.m.release(A, &t.run(A), &t.log), "nothing held any more");
    }

    #[test]
    fn release_restores_only_values_still_ours() {
        let t = T::new();
        t.m.acquire(A, &t.run(A), &pushed(&["10.8.0.1"], &[]), &t.log);
        let foreign = Dict::from([("ServerAddresses".to_string(), strings(&strs(&["9.9.9.9"])))]);
        t.store.set(&plan::setup_key("S2"), foreign.clone());
        t.m.release(A, &t.run(A), &t.log);
        assert_eq!(t.setup("S2"), Some(foreign));
        assert!(t.setup("S1").is_none());
        assert!(t.log_text().contains("changed by the system meanwhile"));
    }

    #[test]
    fn stacking_newest_vpn_owner_holds_the_override_older_split_entries_stay() {
        let t = T::new();
        let rb = t.request(B, &DnsRequest { mode: DnsMode::Targeted, ..Default::default() });
        t.m.acquire(B, &rb, &pushed(&["10.9.0.1"], &["b.example"]), &t.log);
        assert!(t.setup("S1").is_none(), "Targeted writes no override");
        t.m.acquire(A, &t.run(A), &pushed(&["10.8.0.1"], &["a.example"]), &t.log);
        assert_eq!(servers_of(&t.setup("S1")), ["10.8.0.1"]);
        let b = t.d(&plan::entry_key(B, "")).unwrap();
        assert_eq!(list_of(&b, "SupplementalMatchDomains"), ["b.example"]);
    }

    #[test]
    fn stacking_newest_leaves_previous_vpn_owner_takes_override_again() {
        let t = T::new();
        t.m.acquire(A, &t.run(A), &pushed(&["10.8.0.1"], &[]), &t.log);
        t.m.acquire(B, &t.run(B), &pushed(&["10.9.0.1"], &[]), &t.log);
        assert_eq!(servers_of(&t.setup("S1")), ["10.9.0.1"]);
        t.m.release(B, &t.run(B), &t.log);
        assert_eq!(servers_of(&t.setup("S1")), ["10.8.0.1"]);
        assert_eq!(t.m.ledger().originals.len(), 2, "the true originals are kept");
        t.m.release(A, &t.run(A), &t.log);
        assert!(t.setup("S1").is_none());
    }

    #[test]
    fn two_split_owners_coexist() {
        let t = T::new();
        let targeted = DnsRequest { mode: DnsMode::Targeted, ..Default::default() };
        t.m.acquire(A, &t.request(A, &targeted), &pushed(&["10.8.0.1"], &["a.example"]), &t.log);
        t.m.acquire(B, &t.request(B, &targeted), &pushed(&["10.9.0.1"], &["b.example"]), &t.log);
        assert!(t.d(&plan::entry_key(A, "")).is_some() && t.d(&plan::entry_key(B, "")).is_some());
        assert!(t.setup("S1").is_none());
        t.m.release(A, &t.run(A), &t.log);
        assert!(t.d(&plan::entry_key(B, "")).is_some());
        t.m.release(B, &t.run(B), &t.log);
        assert!(t.ours().is_empty() && t.store.get(LEDGER_KEY).is_none());
    }

    #[test]
    fn reconcile_drops_dead_owner_keys_by_pattern() {
        let t = T::new();
        t.m.acquire(A, &t.run(A), &pushed(&["10.8.0.1"], &["corp.example"]), &t.log);
        fsx::remove_rf(&t.base.join("run"));
        t.m.reconcile(&|_| false, &|_| Log::none(), true);
        assert!(t.ours().is_empty());
        assert!(t.setup("S1").is_none() && t.setup("S2").is_none());
        assert!(t.store.get(LEDGER_KEY).is_none());
    }

    #[test]
    fn reconcile_repairs_drift_after_preferences_rewrite() {
        let t = T::new();
        t.m.acquire(A, &t.run(A), &pushed(&["10.8.0.1"], &[]), &t.log);
        let rewritten = Dict::from([("ServerAddresses".to_string(), strings(&strs(&["8.8.8.8"])))]);
        t.store.set(&plan::setup_key("S1"), rewritten.clone());
        t.m.reconcile(&|_| true, &|_| Log::none(), true);
        assert_eq!(servers_of(&t.setup("S1")), ["10.8.0.1"], "overridden again");
        let o = t.m.ledger().originals.into_iter().find(|o| o.sid == "S1").unwrap();
        assert!(o.present);
        assert_eq!(o.dict, rewritten, "the new value is the original now");
        t.m.release(A, &t.run(A), &t.log);
        assert_eq!(t.setup("S1"), Some(rewritten));
    }

    #[test]
    fn reconcile_overrides_a_newly_listed_service() {
        let t = T::new();
        t.m.acquire(A, &t.run(A), &pushed(&["10.8.0.1"], &[]), &t.log);
        t.store.set(
            "Setup:/Network/Global/IPv4",
            Dict::from([("ServiceOrder".to_string(), strings(&strs(&["S1", "S2", "T1", "S3"])))]),
        );
        t.m.reconcile(&|_| true, &|_| Log::none(), true);
        assert_eq!(servers_of(&t.setup("S3")), ["10.8.0.1"]);
        t.m.release(A, &t.run(A), &t.log);
        assert!(t.setup("S3").is_none());
    }

    #[test]
    fn reconcile_refreshes_the_local_entry_after_a_network_switch() {
        let t = T::new();
        let run = t.run(A);
        let routes = vec![macvpn_core::netaddr::IpPrefix::parse("10.0.0.0/8").unwrap()];
        let p = Pushed { routes, ..pushed(&["10.8.0.1"], &["corp.example"]) };
        t.m.acquire(A, &run, &p, &t.log);
        let local = t.d(&plan::entry_key(A, "-local")).unwrap();
        assert_eq!(list_of(&local, "ServerAddresses"), ["192.168.1.1"]);
        // Another network on the same service: its DHCP DNS, domain and subnet.
        t.store.seed_primary("S1", &["172.16.0.1"], Some("office"), "10.0.5.20");
        t.store.set(
            "Setup:/Network/Global/IPv4",
            Dict::from([("ServiceOrder".to_string(), strings(&strs(&["S1", "S2", "T1"])))]),
        );
        t.m.reconcile(&|_| true, &|_| Log::none(), true);
        let local = t.d(&plan::entry_key(A, "-local")).unwrap();
        assert_eq!(list_of(&local, "ServerAddresses"), ["172.16.0.1"]);
        // The new subnet's reverse zone is inside the VPN's routed 10/8: it stays on the VPN's DNS.
        assert_eq!(list_of(&local, "SupplementalMatchDomains"), ["office"]);
        // Offline (no primary service): no local entry until a network is back.
        t.store.apply(&[Op::Remove("State:/Network/Global/IPv4".into())]).unwrap();
        t.m.reconcile(&|_| true, &|_| Log::none(), true);
        assert!(t.d(&plan::entry_key(A, "-local")).is_none());
        t.m.release(A, &run, &t.log);
        assert!(t.ours().is_empty());
    }

    #[test]
    fn reconcile_without_ledger_reads_one_key_and_returns() {
        let t = T::new();
        t.store.gets.set(0);
        t.m.reconcile(&|_| false, &|_| Log::none(), true);
        assert_eq!(t.store.gets.get(), 1);
        assert!(!t.m.lock_dir.exists(), "not even the lock");
    }

    #[test]
    fn reconcile_runs_the_legacy_restore_first() {
        // The legacy path is `dns_legacy`'s own (its tests); here: the wrapper calls it before the new manager,
        // and test mode without fakes changes nothing.
        let s = Settings::resolve(true, Default::default(), String::new());
        assert!(crate::macos::dns_legacy::manager(&s).is_none());
        assert!(manager(&s).is_none());
        reconcile(&s, false);
    }

    #[test]
    fn check_failed_twice_falls_back_and_ok_once_returns() {
        let mut t = T::new();
        let run = t.run(A);
        t.m.acquire(A, &run, &pushed(&["10.8.0.1"], &["corp.example"]), &t.log);
        assert_eq!(t.m.after_connect(&t.s, A, &run, Tunnel::Split, &t.log), DnsState::Vpn);
        t.s.dns_probe = Some("fail".into());
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), Some(DnsState::Vpn), "one failure keeps it");
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), Some(DnsState::Fallback));
        assert!(t.setup("S1").is_none(), "the override is gone");
        let main = t.d(&plan::entry_key(A, "")).unwrap();
        assert!(!main.contains_key("SupplementalMatchDomainsNoSearch"));
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), Some(DnsState::Fallback));
        t.s.dns_probe = Some("ok".into());
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), Some(DnsState::Vpn));
        assert_eq!(servers_of(&t.setup("S1")), ["10.8.0.1"]);
        let log = t.log_text();
        assert!(log.contains("only the VPN's domains use it now") && log.contains("answers again"), "{log}");
    }

    #[test]
    fn a_failed_probe_at_connect_falls_back_at_once_on_a_full_tunnel() {
        let mut t = T::new();
        t.s.dns_probe = Some("fail".into());
        let run = t.run(A);
        t.m.acquire(A, &run, &pushed(&["10.8.0.1"], &["corp.example"]), &t.log);
        assert_eq!(t.m.after_connect(&t.s, A, &run, Tunnel::Full, &t.log), DnsState::FallbackFullTunnel);
        assert!(t.setup("S1").is_none());
    }

    #[test]
    fn check_on_strict_never_changes_layout() {
        let mut t = T::new();
        let run = t.request(A, &DnsRequest { mode: DnsMode::Strict, ..Default::default() });
        t.m.acquire(A, &run, &pushed(&["10.8.0.1"], &[]), &t.log);
        t.m.after_connect(&t.s, A, &run, Tunnel::Full, &t.log);
        assert!(t.d(&plan::entry_key(A, "-local")).is_none(), "Strict keeps nothing local");
        t.s.dns_probe = Some("fail".into());
        t.m.check(&t.s, A, &run, &t.log);
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), Some(DnsState::Failing));
        assert_eq!(servers_of(&t.setup("S1")), ["10.8.0.1"], "still in the tunnel");
        assert!(t.log_text().contains("DNS stays in the tunnel"));
    }

    #[test]
    fn fallback_keeps_vpn_domains_on_vpn_dns() {
        let mut t = T::new();
        t.s.dns_probe = Some("fail".into());
        let run = t.run(A);
        t.m.acquire(A, &run, &pushed(&["10.8.0.1"], &["corp.example"]), &t.log);
        t.m.after_connect(&t.s, A, &run, Tunnel::Split, &t.log);
        let main = t.d(&plan::entry_key(A, "")).unwrap();
        assert_eq!(list_of(&main, "ServerAddresses"), ["10.8.0.1"]);
        assert_eq!(list_of(&main, "SupplementalMatchDomains"), ["corp.example"]);
        assert_eq!(servers_of(&t.d(GLOBAL_DNS)), ["192.168.1.1"], "every other name: the original DNS");
    }

    #[test]
    fn no_servers_writes_nothing_and_records_none() {
        let t = T::new();
        let run = t.run(A);
        assert_eq!(t.m.acquire(A, &run, &Pushed::default(), &t.log), DnsState::None);
        assert!(t.ours().is_empty() && t.store.get(LEDGER_KEY).is_none());
        assert!(t.log_text().contains("the VPN sent no DNS"));
        assert_eq!(dns_session::read_session(&run, true).unwrap().state(), DnsState::None);
        // Own servers apply when the VPN sends none.
        let run = t.request(B, &DnsRequest { servers: strs(&["10.0.0.53"]), ..Default::default() });
        assert_eq!(t.m.acquire(B, &run, &Pushed::default(), &t.log), DnsState::Vpn);
        assert_eq!(servers_of(&t.setup("S1")), ["10.0.0.53"]);
    }

    #[test]
    fn verification_reads_global_dns() {
        let t = T::new();
        assert!(!t.m.verified(&strs(&["10.8.0.1"])), "not merged yet");
        t.m.acquire(A, &t.run(A), &pushed(&["10.8.0.1"], &[]), &t.log);
        assert!(t.m.verified(&strs(&["10.8.0.1"])));
    }

    #[test]
    fn a_failed_batch_is_logged() {
        let t = T::new();
        t.store.fail.set(true);
        t.m.acquire(A, &t.run(A), &pushed(&["10.8.0.1"], &[]), &t.log);
        assert!(t.log_text().contains("DNS could not be changed"));
    }

    #[test]
    fn release_then_acquire_again_republishes_the_vpn_dns() {
        // OpenVPN's ping-restart without persist-tun: the down hook releases, the up hook acquires again.
        for mode in [DnsMode::Automatic, DnsMode::Strict] {
            let t = T::new();
            let run = t.request(A, &DnsRequest { mode, ..Default::default() });
            t.m.acquire(A, &run, &pushed(&["10.8.0.1"], &["corp.example"]), &t.log);
            t.m.after_connect(&t.s, A, &run, Tunnel::Full, &t.log);
            assert!(t.m.release(A, &run, &t.log));
            assert!(t.setup("S1").is_none() && t.ours().is_empty());
            assert!(dns_session::read_session(&run, true).is_none(), "released: no session");
            assert_eq!(t.m.acquire(A, &run, &pushed(&["10.8.0.1"], &["corp.example"]), &t.log), DnsState::Vpn);
            assert_eq!(servers_of(&t.setup("S1")), ["10.8.0.1"], "{mode:?}: the VPN's DNS is in effect again");
            assert!(t.d(&plan::entry_key(A, "")).is_some());
        }
    }

    #[test]
    fn acquire_again_keeps_a_fallback_until_a_probe_says_ok() {
        let mut t = T::new();
        t.s.dns_probe = Some("fail".into());
        let run = t.run(A);
        t.m.acquire(A, &run, &pushed(&["10.8.0.1"], &["corp.example"]), &t.log);
        assert_eq!(t.m.after_connect(&t.s, A, &run, Tunnel::Split, &t.log), DnsState::Fallback);
        // The same connection's DNS step again without a release (the session is live) …
        assert_eq!(t.m.acquire(A, &run, &pushed(&["10.8.0.1"], &["corp.example"]), &t.log), DnsState::Fallback);
        assert!(t.setup("S1").is_none(), "the known-broken DNS is not put back");
        // … and after a release (ping-restart).
        t.m.release(A, &run, &t.log);
        assert_eq!(t.m.acquire(A, &run, &pushed(&["10.8.0.1"], &["corp.example"]), &t.log), DnsState::Fallback);
        assert!(t.setup("S1").is_none());
        assert!(t.d(&plan::entry_key(A, "")).is_some(), "the VPN's domains still use the VPN's DNS");
        // One good probe returns.
        t.s.dns_probe = Some("ok".into());
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), Some(DnsState::Vpn));
        assert_eq!(servers_of(&t.setup("S1")), ["10.8.0.1"]);
        // Other DNS from the VPN after a failed probe: decided afresh.
        t.s.dns_probe = Some("fail".into());
        t.m.check(&t.s, A, &run, &t.log);
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), Some(DnsState::Fallback));
        t.m.release(A, &run, &t.log);
        assert_eq!(t.m.acquire(A, &run, &pushed(&["10.9.0.1"], &["corp.example"]), &t.log), DnsState::Vpn);
    }

    #[test]
    fn a_failed_publish_is_retried_by_the_next_check() {
        let mut t = T::new();
        let run = t.run(A);
        t.m.acquire(A, &run, &pushed(&["10.8.0.1"], &["corp.example"]), &t.log);
        t.m.after_connect(&t.s, A, &run, Tunnel::Split, &t.log);
        t.s.dns_probe = Some("fail".into());
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), Some(DnsState::Vpn));
        t.store.fail.set(true);
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), Some(DnsState::Vpn), "not changed: the old layout is reported");
        assert_eq!(dns_session::read_session(&run, true).unwrap().layout, Layout::Vpn { local: true });
        t.store.fail.set(false);
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), Some(DnsState::Fallback));
        assert!(t.setup("S1").is_none(), "the fallback is in effect now");
    }

    #[test]
    fn a_failed_first_publish_is_retried_after_connect() {
        let t = T::new();
        let run = t.run(A);
        t.store.fail.set(true);
        t.m.acquire(A, &run, &pushed(&["10.8.0.1"], &[]), &t.log);
        assert!(t.setup("S1").is_none());
        t.store.fail.set(false);
        assert_eq!(t.m.after_connect(&t.s, A, &run, Tunnel::Split, &t.log), DnsState::Vpn);
        assert_eq!(servers_of(&t.setup("S1")), ["10.8.0.1"], "the ledger did not hold it: published now");
    }

    #[test]
    fn a_decision_for_a_released_connection_changes_nothing() {
        // dns-check probes for up to 9 s without the lock; the connection may go down meanwhile.
        let t = T::new();
        let run = t.run(A);
        t.m.acquire(A, &run, &pushed(&["10.8.0.1"], &[]), &t.log);
        let prev = dns_session::read_session(&run, true).unwrap();
        t.m.release(A, &run, &t.log);
        let d = plan::decide(DnsMode::Automatic, Tunnel::Split, true, false, Probe::Ok);
        let e = prev.eff.clone();
        let r = t.m.apply_decision(
            A,
            &run,
            DnsMode::Automatic,
            Tunnel::Split,
            (Probe::Ok, ""),
            0,
            d,
            e,
            Some(&prev),
            true,
            &t.log,
        );
        assert!(r.is_none());
        assert!(t.setup("S1").is_none() && t.ours().is_empty() && t.store.get(LEDGER_KEY).is_none());
        assert!(dns_session::read_session(&run, true).is_none());
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), None);
    }

    #[test]
    fn a_check_soon_after_another_or_during_one_does_not_probe_again() {
        let mut t = T::new();
        t.m.min_check_secs = 60;
        let run = t.run(A);
        t.m.acquire(A, &run, &pushed(&["10.8.0.1"], &["corp.example"]), &t.log);
        t.m.after_connect(&t.s, A, &run, Tunnel::Split, &t.log);
        t.s.dns_probe = Some("fail".into());
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), Some(DnsState::Vpn));
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), Some(DnsState::Vpn), "within the interval: not probed");
        assert_eq!(dns_session::read_session(&run, true).unwrap().fails, 1, "not counted twice");
        // While another check probes (the app's retry, a second query): the current state, no probe.
        t.m.min_check_secs = 0;
        let busy = dns_session::check_lock(&run).unwrap();
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), Some(DnsState::Vpn));
        assert_eq!(dns_session::read_session(&run, true).unwrap().fails, 1);
        drop(busy);
        assert_eq!(t.m.check(&t.s, A, &run, &t.log), Some(DnsState::Fallback));
    }

    #[test]
    fn ledger_round_trip_and_strict_read() {
        let l = Ledger {
            owners: vec![OwnerRec {
                id: A.into(),
                layout: Layout::Vpn { local: true },
                servers: strs(&["10.8.0.1"]),
                search: strs(&["corp.example"]),
                resolve: strs(&["svc.example"]),
                zones: strs(&["10.in-addr.arpa"]),
            }],
            originals: vec![Original { sid: "S1".into(), present: false, dict: Dict::new() }],
            skipped: strs(&["T1"]),
        };
        assert_eq!(Ledger::from_value(Some(Value::Dict(l.to_dict()))), l);
        let mut bad = l.to_dict();
        bad.insert(
            "Owners".into(),
            Value::Array(vec![Value::Dict(Dict::from([("Id".to_string(), Value::Str("x; rm".into()))]))]),
        );
        assert!(Ledger::from_value(Some(Value::Dict(bad))).owners.is_empty());
    }

    /// IPv6 into the tunnel alone (a VPN that only blackholes IPv6 against leaks) is not a full tunnel: the
    /// Targeted mode stays targeted.
    #[test]
    fn a_full_tunnel_is_the_ipv4_default_through_the_tunnel() {
        let t = T::new();
        let route = t.base.join("route");
        let fake = |v4: &str, v6: &str| {
            let script = format!(
                "#!/bin/sh\ncase \"$3\" in -inet6) echo \"  interface: {v6}\" ;; *) echo \"  interface: {v4}\" ;; esac\n"
            );
            std::fs::write(&route, script).unwrap();
            std::fs::set_permissions(&route, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        };
        let mut s = t.s.clone();
        s.route = route.clone();
        fake("en0", "utun9");
        assert_eq!(detect_tunnel(&s, "utun9"), Tunnel::Split);
        fake("utun9", "utun9");
        assert_eq!(detect_tunnel(&s, "utun9"), Tunnel::Full);
        fake("utun9", "en0");
        assert_eq!(detect_tunnel(&s, "utun9"), Tunnel::Full);
        assert_eq!(detect_tunnel(&s, ""), Tunnel::Unknown);
    }

    #[test]
    fn vpn_like_services() {
        let d = |k: &str, v: &str| Dict::from([(k.to_string(), Value::Str(v.into()))]);
        assert!(vpn_like(Some(&d("Type", "IPSec"))));
        assert!(vpn_like(Some(&d("DeviceName", "utun4"))));
        assert!(!vpn_like(Some(&d("DeviceName", "en0"))));
        assert!(!vpn_like(None));
    }
}
