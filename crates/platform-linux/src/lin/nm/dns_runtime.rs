//! LinVPN's per-connection DNS at runtime (spec "Linux", D1 = A). The profile already carries the mode's keys
//! (`macvpn_core::nm_plan::dns`); NM and systemd-resolved apply them. What is left here:
//!
//! - **The probe** (`macvpn_core::dns_policy::probe`, plain UDP as the user) after the connection is up and at the
//!   app's `dns-check` (at most once per [`MIN_CHECK_INTERVAL`]); the decision is `dns_policy::decide`.
//! - **Automatic's fallback.** A plugin VPN's DNS cannot be re-applied at runtime, so the physical links (every
//!   non-VPN link with a default route) get [`FALLBACK_PRIORITY`] at runtime (`Device.Reapply`, never saved): below
//!   the VPN's 50, they take the default DNS role back, while the VPN keeps its `~domain`s (positive priorities
//!   shadow nothing). Recovery restores each link's recorded priority.
//! - **The ledger** `<data>/dns-fallback.json`, `{ "<connection id>": [{ "iface", "v4", "v6" }] }`: the links'
//!   original priorities, written before anything changes and removed once restored. A leftover (a crash) is
//!   restored when the engine starts; it is harmless meanwhile, as NM drops a runtime priority at the link's next
//!   activation. A link is restored only while it still has the fallback priority.
//!
//! D-Bus is read only at connect, at `dns-check` (only when the layout changes) and at disconnect: no polling.

use crate::lin::nm::client::NmClient;
use macvpn_core::dns_policy::{self, Effective, Layout, Probe, Pushed, Tunnel, Warn};
use macvpn_core::dns_settings::{DnsMode, DnsRequest};
use macvpn_core::fsx::{self, Access};
use macvpn_core::l10n::{self, Arg};
use macvpn_core::status::DnsState;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// The physical links' DNS priority while Automatic falls back: below the VPN's 50
/// (`nm_plan::dns::DEFAULT_PRIORITY`) and above 0, so it shadows none of the VPN's domains.
pub const FALLBACK_PRIORITY: i32 = 40;
/// `dns-check` probes a connection at most once in this interval (the macOS `MIN_CHECK_SECS`).
pub const MIN_CHECK_INTERVAL: Duration = Duration::from_secs(20);
/// The ledger's file name in LinVPN's data folder.
pub const LEDGER_FILE: &str = "dns-fallback.json";
/// What NM uses for a non-VPN link whose priority is 0 (unset).
const NM_LINK_DEFAULT: i32 = 100;
/// The largest ledger read.
const MAX_LEDGER: u64 = 64 * 1024;

/// A device's applied `ipv4.dns-priority` and `ipv6.dns-priority` (0: NM's default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Priorities {
    pub v4: i32,
    pub v6: i32,
}

impl Priorities {
    /// The fallback's priorities: each family above [`FALLBACK_PRIORITY`] comes down to it, a lower one stays.
    fn lowered(self) -> Priorities {
        let lower =
            |p: i32| if (if p == 0 { NM_LINK_DEFAULT } else { p }) > FALLBACK_PRIORITY { FALLBACK_PRIORITY } else { p };
        Priorities { v4: lower(self.v4), v6: lower(self.v6) }
    }

    /// `self` (now) with every family still at [`FALLBACK_PRIORITY`] back at `original`'s.
    fn restored(self, original: Priorities) -> Priorities {
        let back = |now: i32, orig: i32| if now == FALLBACK_PRIORITY { orig } else { now };
        Priorities { v4: back(self.v4, original.v4), v6: back(self.v6, original.v6) }
    }
}

/// A non-VPN link with a default route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub iface: String,
    pub device_path: String,
}

/// What the VPN put into effect: its DNS and routes, and the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnFacts {
    pub pushed: Pushed,
    pub tunnel: Tunnel,
}

/// NetworkManager as the DNS runtime needs it ([`NmClient`] in production, a fake in the tests).
pub trait NmDns {
    /// The active VPN connection's DNS, routes and tunnel.
    fn vpn_facts(&self, active_path: &str) -> Result<VpnFacts, String>;
    /// The non-VPN links with a default route, other than the VPN's.
    fn default_links(&self, vpn_active_path: &str) -> Vec<Link>;
    /// The device of an interface, `None` when NM has none.
    fn device_of(&self, iface: &str) -> Option<String>;
    /// The device's applied DNS priorities.
    fn dns_priority(&self, device_path: &str) -> Option<Priorities>;
    /// Changes the device's DNS priorities at runtime only.
    fn set_dns_priority(&self, device_path: &str, p: Priorities) -> Result<(), String>;
}

impl NmDns for NmClient {
    fn vpn_facts(&self, active_path: &str) -> Result<VpnFacts, String> {
        let d = self.vpn_dns(active_path).map_err(|e| e.message())?;
        let tunnel = if d.full { Tunnel::Full } else { Tunnel::Split };
        Ok(VpnFacts {
            pushed: Pushed { servers: d.servers, search: d.domains, resolve: Vec::new(), routes: d.routes },
            tunnel,
        })
    }

    fn default_links(&self, vpn_active_path: &str) -> Vec<Link> {
        NmClient::default_links(self, vpn_active_path)
            .unwrap_or_default()
            .into_iter()
            .map(|l| Link { iface: l.iface, device_path: l.device_path })
            .collect()
    }

    fn device_of(&self, iface: &str) -> Option<String> {
        self.device_by_iface(iface)
    }

    fn dns_priority(&self, device_path: &str) -> Option<Priorities> {
        self.applied_dns_priority(device_path).ok().map(|(v4, v6)| Priorities { v4, v6 })
    }

    fn set_dns_priority(&self, device_path: &str, p: Priorities) -> Result<(), String> {
        self.reapply_dns_priority(device_path, p.v4, p.v6).map_err(|e| e.message())
    }
}

/// The probe: `(result, detail for the log)`; `dns_policy::probe` in production.
pub type ProbeFn = Box<dyn Fn(&[String]) -> (Probe, String) + Send + Sync>;
/// The clock of the minimum check interval; `Instant::now` in production.
pub type Clock = Box<dyn Fn() -> Instant + Send + Sync>;

/// One link's original priorities in the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    iface: String,
    original: Priorities,
}

/// The ledger: connection id → the links its fallback lowered.
type Ledger = BTreeMap<String, Vec<Held>>;

/// A connection's DNS while it is up.
#[derive(Debug, Clone, PartialEq)]
struct Session {
    /// The VPN's active connection.
    active_path: String,
    mode: DnsMode,
    tunnel: Tunnel,
    eff: Effective,
    probe: Probe,
    fails: u32,
    layout: Layout,
    warn: Option<Warn>,
    /// The last probe (connect or check).
    probed_at: Option<Instant>,
}

impl Session {
    fn decide(&self, probe: Probe) -> dns_policy::Decision {
        dns_policy::decide(self.mode, self.tunnel, !self.eff.servers.is_empty(), self.eff.has_match(), probe)
    }

    fn state(&self) -> DnsState {
        dns_policy::state_of(self.layout, self.warn)
    }
}

/// The connections' DNS sessions and Automatic's fallback (one per engine).
pub struct DnsRuntime {
    ledger: PathBuf,
    probe: ProbeFn,
    now: Clock,
    /// Serializes the changes: the commit of a connect or check, a release and the start restore (never held
    /// during a probe).
    apply: Mutex<()>,
    sessions: Mutex<HashMap<Uuid, Session>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn dns_error(e: &str) -> String {
    l10n::tr("DNS could not be changed: %@", &[Arg::Str(e)])
}

impl DnsRuntime {
    /// The runtime of the engine whose data folder is `data` (the real probe and clock).
    pub fn new(data: &Path) -> DnsRuntime {
        DnsRuntime::with_parts(data, Box::new(dns_policy::probe), Box::new(Instant::now))
    }

    fn with_parts(data: &Path, probe: ProbeFn, now: Clock) -> DnsRuntime {
        DnsRuntime {
            ledger: data.join(LEDGER_FILE),
            probe,
            now,
            apply: Mutex::new(()),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// The connection's DNS state, `None` without a session.
    pub fn state(&self, id: &Uuid) -> Option<DnsState> {
        lock(&self.sessions).get(id).map(Session::state)
    }

    /// Whether a ledger is left (an earlier process's fallback, or a restore that failed): then
    /// [`DnsRuntime::restore_leftovers`] has work, and only then is NM asked.
    pub fn has_leftovers(&self) -> bool {
        self.ledger.exists()
    }

    /// The connection is up (first time or after a reconnect): its facts, the probe, the decision and, for
    /// Automatic's fallback, the links. The probe runs outside the runtime's lock (a release never waits for it);
    /// `still_running` is asked under the lock after it: a connection that went down meanwhile changes nothing.
    pub fn connected(
        &self,
        nm: &dyn NmDns,
        id: Uuid,
        active_path: &str,
        req: &DnsRequest,
        log: &dyn Fn(&str),
        still_running: &dyn Fn() -> bool,
    ) {
        let facts = match nm.vpn_facts(active_path) {
            Ok(f) => f,
            Err(e) => return log(&dns_error(&e)),
        };
        log(&l10n::tr("DNS mode: %@", &[Arg::Str(req.mode.raw())]));
        let mut s = Session {
            active_path: active_path.to_string(),
            mode: req.mode,
            tunnel: facts.tunnel,
            eff: dns_policy::effective(&facts.pushed, req),
            probe: Probe::NotRun,
            fails: 0,
            layout: Layout::None,
            warn: None,
            probed_at: None,
        };
        let (probe, detail) = if s.decide(Probe::NotRun).probes {
            s.probed_at = Some((self.now)());
            (self.probe)(&s.eff.servers)
        } else {
            (Probe::NotRun, String::new())
        };
        let _apply = lock(&self.apply);
        if !still_running() {
            return;
        }
        let prev = lock(&self.sessions).get(&id).cloned();
        let d = s.decide(probe);
        (s.probe, s.fails, s.layout, s.warn) = (probe, u32::from(probe == Probe::Failed), d.layout, d.warn);
        self.commit(nm, id, prev.as_ref(), s, &detail, log);
    }

    /// `dns-check`: probes again when the session probes and the last probe is older than
    /// [`MIN_CHECK_INTERVAL`]; two failures in a row fall back (Automatic) or warn, one success returns. The probe
    /// runs outside the lock; a session that changed or went meanwhile is left as it is. `None`: no session.
    pub fn check(&self, nm: &dyn NmDns, id: &Uuid, log: &dyn Fn(&str)) -> Option<DnsState> {
        let prev = lock(&self.sessions).get(id).cloned()?;
        let now = (self.now)();
        let recent = prev.probed_at.is_some_and(|t| now.saturating_duration_since(t) < MIN_CHECK_INTERVAL);
        if !prev.decide(Probe::NotRun).probes || recent {
            return Some(prev.state());
        }
        let (result, detail) = (self.probe)(&prev.eff.servers);
        let _apply = lock(&self.apply);
        let current = lock(&self.sessions).get(id).cloned();
        if current.as_ref() != Some(&prev) {
            return current.map(|c| c.state());
        }
        let mut s = Session { probed_at: Some(now), ..prev.clone() };
        if result != Probe::NotRun {
            (s.probe, s.fails) = dns_policy::next_probe(prev.probe, prev.fails, result);
            let d = s.decide(s.probe);
            (s.layout, s.warn) = (d.layout, d.warn);
        }
        Some(self.commit(nm, *id, Some(&prev), s, &detail, log))
    }

    /// The activation at `active_path` ended: its session goes and the links its fallback lowered come back. A
    /// session of another activation of the same connection (a quick reconnect) is left alone. A link that cannot
    /// be restored stays in the ledger for the next start.
    pub fn release(&self, nm: &dyn NmDns, id: &Uuid, active_path: &str, log: &dyn Fn(&str)) {
        let _apply = lock(&self.apply);
        {
            let mut sessions = lock(&self.sessions);
            if sessions.get(id).is_none_or(|s| s.active_path != active_path) {
                return;
            }
            sessions.remove(id);
        }
        if let Err(e) = self.fallback_off(nm, id) {
            log(&dns_error(&e));
        }
    }

    /// At the engine's start: every link a leftover ledger names comes back (best effort); only the links that
    /// still cannot be restored stay in the ledger.
    pub fn restore_leftovers(&self, nm: &dyn NmDns) {
        let _apply = lock(&self.apply);
        let ledger = self.read_ledger().unwrap_or_default();
        let mut done: Vec<&str> = Vec::new();
        let mut left = Ledger::new();
        for (id, held) in &ledger {
            for h in held {
                if done.contains(&h.iface.as_str()) {
                    continue;
                }
                done.push(&h.iface);
                if restore(nm, h).is_err() {
                    left.entry(id.clone()).or_default().push(h.clone());
                }
            }
        }
        let _ = self.write_ledger(&left);
    }

    /// Applies `s`'s layout to the links (when it changed), logs a changed layout or warning and keeps the session.
    /// The session always says what the links are:
    /// - a fallback that failed is rolled back and the previous layout stays (a new session: the VPN's DNS,
    ///   failing); if even the rollback fails, the lowered links stay recorded and the session falls back;
    /// - a return that failed keeps the session falling back, with the unrestored links recorded.
    ///
    /// Either way the next check tries again.
    fn commit(
        &self,
        nm: &dyn NmDns,
        id: Uuid,
        prev: Option<&Session>,
        mut s: Session,
        detail: &str,
        log: &dyn Fn(&str),
    ) -> DnsState {
        let was = prev.map(|p| (p.layout, p.warn));
        let falls_back = s.layout == Layout::Fallback;
        let fell_back = prev.is_some_and(|p| p.layout == Layout::Fallback);
        let fallback = (Layout::Fallback, Some(Warn::Fallback { full_tunnel: s.tunnel == Tunnel::Full }));
        if prev.is_none() || fell_back != falls_back {
            if falls_back {
                if let Err(e) = self.fallback_on(nm, &id, &s.active_path) {
                    log(&dns_error(&e));
                    match self.fallback_off(nm, &id) {
                        Ok(()) => {
                            (s.layout, s.warn) =
                                prev.map_or((Layout::Vpn { local: true }, Some(Warn::Failing)), |p| (p.layout, p.warn))
                        }
                        Err(e) => log(&dns_error(&e)),
                    }
                }
            } else if let Err(e) = self.fallback_off(nm, &id) {
                log(&dns_error(&e));
                (s.layout, s.warn) = fallback;
            }
        }
        if was != Some((s.layout, s.warn)) {
            log_change(was, &s, detail, log);
        }
        let state = s.state();
        lock(&self.sessions).insert(id, s);
        state
    }

    /// Lowers every default-route link, after recording its original priorities (a link another connection's
    /// fallback already lowered keeps that record's original).
    fn fallback_on(&self, nm: &dyn NmDns, id: &Uuid, active_path: &str) -> Result<(), String> {
        let mut ledger = self.read_ledger()?;
        let mut held = Vec::new();
        let mut changes = Vec::new();
        for link in nm.default_links(active_path) {
            let Some(now) = nm.dns_priority(&link.device_path) else { continue };
            let recorded = ledger.values().flatten().find(|h| h.iface == link.iface).map(|h| h.original);
            held.push(Held { iface: link.iface, original: recorded.unwrap_or(now) });
            if now.lowered() != now {
                changes.push((link.device_path, now.lowered()));
            }
        }
        ledger.insert(id.to_string(), held);
        self.write_ledger(&ledger)?;
        let errors: Vec<String> =
            changes.into_iter().filter_map(|(device, p)| nm.set_dns_priority(&device, p).err()).collect();
        if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
    }

    /// Restores the links `id`'s fallback lowered, except those another connection's fallback still holds. A link
    /// whose restore failed stays recorded under `id`.
    fn fallback_off(&self, nm: &dyn NmDns, id: &Uuid) -> Result<(), String> {
        let mut ledger = self.read_ledger()?;
        let Some(held) = ledger.remove(&id.to_string()) else { return Ok(()) };
        let mut kept = Vec::new();
        let mut errors = Vec::new();
        for h in held {
            if ledger.values().flatten().any(|o| o.iface == h.iface) {
                continue;
            }
            if let Err(e) = restore(nm, &h) {
                errors.push(e);
                kept.push(h);
            }
        }
        if !kept.is_empty() {
            ledger.insert(id.to_string(), kept);
        }
        self.write_ledger(&ledger)?;
        if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
    }

    /// The ledger; none (or an unreadable one) is empty.
    fn read_ledger(&self) -> Result<Ledger, String> {
        let text = match std::fs::metadata(&self.ledger) {
            Ok(m) if m.len() > MAX_LEDGER => return Ok(Ledger::new()),
            Ok(_) => std::fs::read_to_string(&self.ledger).map_err(|e| e.to_string())?,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Ledger::new()),
            Err(e) => return Err(e.to_string()),
        };
        Ok(parse_ledger(&text))
    }

    /// Writes the ledger atomically (0600), or removes it when it is empty.
    fn write_ledger(&self, ledger: &Ledger) -> Result<(), String> {
        if ledger.is_empty() {
            return match std::fs::remove_file(&self.ledger) {
                Err(e) if e.kind() != ErrorKind::NotFound => Err(e.to_string()),
                _ => Ok(()),
            };
        }
        if let Some(dir) = self.ledger.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        fsx::atomic_write(&self.ledger, render_ledger(ledger).as_bytes(), Access::Private).map_err(|e| e.to_string())
    }
}

/// Puts a link's recorded priorities back, for the families that still have the fallback's (NM dropped a runtime
/// change when the link reconnected; a gone link has nothing to restore).
fn restore(nm: &dyn NmDns, held: &Held) -> Result<(), String> {
    let Some(device) = nm.device_of(&held.iface) else { return Ok(()) };
    let Some(now) = nm.dns_priority(&device) else { return Ok(()) };
    let back = now.restored(held.original);
    if back == now { Ok(()) } else { nm.set_dns_priority(&device, back) }
}

fn parse_ledger(text: &str) -> Ledger {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(text) else { return Ledger::new() };
    let int = |v: &Value, k: &str| v.get(k).and_then(Value::as_i64).and_then(|n| i32::try_from(n).ok());
    map.into_iter()
        .filter(|(id, _)| Uuid::parse_str(id).is_ok())
        .map(|(id, links)| {
            let held = links
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|l| {
                    let iface = l.get("iface")?.as_str()?.to_string();
                    Some(Held { iface, original: Priorities { v4: int(l, "v4")?, v6: int(l, "v6")? } })
                })
                .collect();
            (id, held)
        })
        .collect()
}

fn render_ledger(ledger: &Ledger) -> String {
    let map: Map<String, Value> = ledger
        .iter()
        .map(|(id, held)| {
            let links =
                held.iter().map(|h| json!({ "iface": h.iface, "v4": h.original.v4, "v6": h.original.v6 })).collect();
            (id.clone(), Value::Array(links))
        })
        .collect();
    Value::Object(map).to_string()
}

/// The log line of a changed layout or warning (the macOS lines).
fn log_change(was: Option<(Layout, Option<Warn>)>, s: &Session, detail: &str, log: &dyn Fn(&str)) {
    let count = |n: usize| n.to_string();
    if s.warn == Some(Warn::TargetedOnFullTunnel) {
        log(&l10n::tr("full tunnel: the Targeted mode acts as Automatic", &[]));
    }
    let line = match (s.layout, s.warn) {
        (Layout::None, _) => l10n::tr("the VPN sent no DNS; internal names will not resolve", &[]),
        (Layout::Fallback, _) => l10n::tr(
            "the VPN's DNS does not resolve internet names (%@): only the VPN's domains use it now",
            &[Arg::Str(detail)],
        ),
        (Layout::Vpn { local: false }, Some(Warn::Failing)) => {
            l10n::tr("Strict DNS: the VPN's DNS does not answer (%@); DNS stays in the tunnel", &[Arg::Str(detail)])
        }
        (Layout::Vpn { .. }, Some(Warn::Failing)) => {
            l10n::tr("the VPN's DNS does not answer (%@); it stays in effect", &[Arg::Str(detail)])
        }
        (Layout::Vpn { .. }, _) if matches!(was, Some((Layout::Fallback, _))) => {
            l10n::tr("the VPN's DNS answers again: it is in effect for every name", &[])
        }
        (Layout::Vpn { .. }, _) => l10n::tr(
            "the VPN's DNS is in effect (%@ servers, %@ domains)",
            &[Arg::Str(&count(s.eff.servers.len())), Arg::Str(&count(s.eff.search.len()))],
        ),
        (Layout::Split, Some(Warn::TargetedNoDomains)) => {
            l10n::tr("Targeted DNS: no domain uses the VPN's DNS (the VPN sent none, none is set)", &[])
        }
        (Layout::Split, _) => l10n::tr(
            "only the VPN's domains use the VPN's DNS (%@ servers, %@ domains)",
            &[Arg::Str(&count(s.eff.servers.len())), Arg::Str(&count(s.eff.search.len() + s.eff.resolve.len()))],
        ),
    };
    log(&line);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;

    const ETH: &str = "/org/freedesktop/NetworkManager/Devices/2";
    const WLAN: &str = "/org/freedesktop/NetworkManager/Devices/3";
    const VPN: &str = "/org/freedesktop/NetworkManager/ActiveConnection/7";

    /// NM without D-Bus: two physical links with a default route (eth0, wlan0), each `set_dns_priority` recorded
    /// with the ledger's text at that moment.
    struct Fake {
        facts: VpnFacts,
        links: Vec<Link>,
        prios: Mutex<HashMap<String, Priorities>>,
        sets: Mutex<Vec<(String, Priorities, Option<String>)>>,
        /// Devices whose `set_dns_priority` fails (nothing changes there).
        failing: Mutex<Vec<String>>,
        ledger: PathBuf,
    }

    impl Fake {
        fn new(dir: &Path, tunnel: Tunnel) -> Fake {
            let link = |iface: &str, path: &str| Link { iface: iface.into(), device_path: path.into() };
            Fake {
                facts: VpnFacts {
                    pushed: Pushed {
                        servers: vec!["10.8.0.53".into()],
                        search: vec!["corp.example".into()],
                        ..Pushed::default()
                    },
                    tunnel,
                },
                links: vec![link("eth0", ETH), link("wlan0", WLAN)],
                prios: Mutex::new(HashMap::from([
                    (ETH.to_string(), Priorities { v4: 0, v6: 0 }),
                    (WLAN.to_string(), Priorities { v4: 0, v6: 0 }),
                ])),
                sets: Mutex::new(Vec::new()),
                failing: Mutex::new(Vec::new()),
                ledger: dir.join(LEDGER_FILE),
            }
        }

        fn sets(&self) -> Vec<(String, Priorities)> {
            self.sets.lock().unwrap().iter().map(|(d, p, _)| (d.clone(), *p)).collect()
        }

        fn prio(&self, device: &str) -> Priorities {
            self.prios.lock().unwrap()[device]
        }
    }

    impl NmDns for Fake {
        fn vpn_facts(&self, active_path: &str) -> Result<VpnFacts, String> {
            assert_eq!(active_path, VPN);
            Ok(self.facts.clone())
        }
        fn default_links(&self, vpn_active_path: &str) -> Vec<Link> {
            assert_eq!(vpn_active_path, VPN);
            self.links.clone()
        }
        fn device_of(&self, iface: &str) -> Option<String> {
            self.links.iter().find(|l| l.iface == iface).map(|l| l.device_path.clone())
        }
        fn dns_priority(&self, device_path: &str) -> Option<Priorities> {
            self.prios.lock().unwrap().get(device_path).copied()
        }
        fn set_dns_priority(&self, device_path: &str, p: Priorities) -> Result<(), String> {
            if self.failing.lock().unwrap().iter().any(|d| d == device_path) {
                return Err(format!("{device_path}: refused"));
            }
            let ledger = std::fs::read_to_string(&self.ledger).ok();
            self.sets.lock().unwrap().push((device_path.to_string(), p, ledger));
            self.prios.lock().unwrap().insert(device_path.to_string(), p);
            Ok(())
        }
    }

    /// A temporary data folder, removed at the end.
    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Dir {
            let d = std::env::temp_dir().join(format!("linvpn-dns-{}", Uuid::new_v4()));
            std::fs::create_dir_all(&d).unwrap();
            Dir(d)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The runtime with queued probe results (a probe with none queued fails the test) and a hand-moved clock.
    struct Harness {
        rt: DnsRuntime,
        probes: Arc<Mutex<VecDeque<Probe>>>,
        clock: Arc<Mutex<Instant>>,
        lines: Mutex<Vec<String>>,
    }

    impl Harness {
        fn new(dir: &Path) -> Harness {
            let probes: Arc<Mutex<VecDeque<Probe>>> = Arc::default();
            let clock = Arc::new(Mutex::new(Instant::now()));
            let (p, c) = (probes.clone(), clock.clone());
            let rt = DnsRuntime::with_parts(
                dir,
                Box::new(move |servers: &[String]| {
                    assert_eq!(servers, ["10.8.0.53"]);
                    let next = p.lock().unwrap().pop_front().expect("an unexpected probe");
                    (next, "timeout".to_string())
                }),
                Box::new(move || *c.lock().unwrap()),
            );
            Harness { rt, probes, clock, lines: Mutex::new(Vec::new()) }
        }

        fn queue(&self, results: &[Probe]) {
            self.probes.lock().unwrap().extend(results);
        }

        fn later(&self) {
            *self.clock.lock().unwrap() += MIN_CHECK_INTERVAL + Duration::from_secs(1);
        }

        fn log(&self) -> impl Fn(&str) + '_ {
            |line: &str| self.lines.lock().unwrap().push(line.to_string())
        }

        fn connect(&self, nm: &Fake, id: Uuid, mode: DnsMode) -> Option<DnsState> {
            let req = DnsRequest { mode, ..DnsRequest::default() };
            self.rt.connected(nm, id, VPN, &req, &self.log(), &|| true);
            self.rt.state(&id)
        }

        fn check(&self, nm: &Fake, id: Uuid) -> Option<DnsState> {
            self.later();
            self.rt.check(nm, &id, &self.log())
        }

        fn logged(&self, text: &str) -> bool {
            self.lines.lock().unwrap().iter().any(|l| l.contains(text))
        }
    }

    const ORIGINAL: Priorities = Priorities { v4: 0, v6: 0 };
    const LOWERED: Priorities = Priorities { v4: FALLBACK_PRIORITY, v6: FALLBACK_PRIORITY };

    #[test]
    fn fallback_lowers_every_default_link_and_records_it_first() {
        let dir = Dir::new();
        let nm = Fake::new(&dir.0, Tunnel::Split);
        let h = Harness::new(&dir.0);
        let id = Uuid::new_v4();
        h.queue(&[Probe::Ok]);
        assert_eq!(h.connect(&nm, id, DnsMode::Automatic), Some(DnsState::Vpn));
        assert!(nm.sets().is_empty());

        h.queue(&[Probe::Failed]);
        assert_eq!(h.check(&nm, id), Some(DnsState::Vpn), "one failure keeps the layout");
        assert!(nm.sets().is_empty());

        h.queue(&[Probe::Failed]);
        assert_eq!(h.check(&nm, id), Some(DnsState::Fallback));
        assert_eq!(nm.sets(), [(ETH.to_string(), LOWERED), (WLAN.to_string(), LOWERED)]);
        let first = nm.sets.lock().unwrap()[0].2.clone().expect("the ledger is written before the first change");
        let ledger: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert_eq!(
            ledger,
            serde_json::json!({ id.to_string(): [
                { "iface": "eth0", "v4": 0, "v6": 0 },
                { "iface": "wlan0", "v4": 0, "v6": 0 },
            ]})
        );
        assert!(h.logged("only the VPN's domains use it now"));
    }

    #[test]
    fn recovery_restores_the_recorded_priorities_and_removes_the_ledger() {
        let dir = Dir::new();
        let nm = Fake::new(&dir.0, Tunnel::Split);
        let h = Harness::new(&dir.0);
        let id = Uuid::new_v4();
        h.queue(&[Probe::Failed]);
        assert_eq!(h.connect(&nm, id, DnsMode::Automatic), Some(DnsState::Fallback));
        assert_eq!(nm.prio(ETH), LOWERED);

        h.queue(&[Probe::Ok]);
        assert_eq!(h.check(&nm, id), Some(DnsState::Vpn));
        assert_eq!(nm.prio(ETH), ORIGINAL);
        assert_eq!(nm.prio(WLAN), ORIGINAL);
        assert!(!dir.0.join(LEDGER_FILE).exists());
        assert!(h.logged("the VPN's DNS answers again"));
    }

    #[test]
    fn a_full_tunnels_fallback_is_reported_as_such() {
        let dir = Dir::new();
        let nm = Fake::new(&dir.0, Tunnel::Full);
        let h = Harness::new(&dir.0);
        h.queue(&[Probe::Failed]);
        assert_eq!(h.connect(&nm, Uuid::new_v4(), DnsMode::Automatic), Some(DnsState::FallbackFullTunnel));
    }

    #[test]
    fn strict_and_full_never_touch_the_links() {
        for mode in [DnsMode::Strict, DnsMode::Full] {
            let dir = Dir::new();
            let nm = Fake::new(&dir.0, Tunnel::Split);
            let h = Harness::new(&dir.0);
            let id = Uuid::new_v4();
            h.queue(&[Probe::Ok, Probe::Failed, Probe::Failed]);
            assert_eq!(h.connect(&nm, id, mode), Some(DnsState::Vpn));
            assert_eq!(h.check(&nm, id), Some(DnsState::Vpn));
            assert_eq!(h.check(&nm, id), Some(DnsState::Failing));
            assert!(nm.sets().is_empty(), "{mode:?}");
            assert!(!dir.0.join(LEDGER_FILE).exists());
        }
    }

    #[test]
    fn targeted_never_probes() {
        let dir = Dir::new();
        let nm = Fake::new(&dir.0, Tunnel::Split);
        let h = Harness::new(&dir.0);
        let id = Uuid::new_v4();
        // Nothing queued: any probe fails the test.
        assert_eq!(h.connect(&nm, id, DnsMode::Targeted), Some(DnsState::Targeted));
        assert_eq!(h.check(&nm, id), Some(DnsState::Targeted));
        assert!(nm.sets().is_empty());
    }

    #[test]
    fn a_check_within_the_minimum_interval_does_not_probe() {
        let dir = Dir::new();
        let nm = Fake::new(&dir.0, Tunnel::Split);
        let h = Harness::new(&dir.0);
        let id = Uuid::new_v4();
        h.queue(&[Probe::Ok]);
        h.connect(&nm, id, DnsMode::Automatic);
        // The connect probed just now; nothing is queued, so a probe would fail the test.
        assert_eq!(h.rt.check(&nm, &id, &h.log()), Some(DnsState::Vpn));
        h.queue(&[Probe::Ok]);
        assert_eq!(h.check(&nm, id), Some(DnsState::Vpn));
        assert!(h.probes.lock().unwrap().is_empty());
    }

    #[test]
    fn start_restores_a_leftover_ledger() {
        let dir = Dir::new();
        let nm = Fake::new(&dir.0, Tunnel::Split);
        nm.prios.lock().unwrap().insert(ETH.into(), LOWERED);
        let left = serde_json::json!({ Uuid::new_v4().to_string(): [{ "iface": "eth0", "v4": 0, "v6": 0 }] });
        std::fs::write(dir.0.join(LEDGER_FILE), left.to_string()).unwrap();
        let h = Harness::new(&dir.0);
        h.rt.restore_leftovers(&nm);
        assert_eq!(nm.sets(), [(ETH.to_string(), ORIGINAL)]);
        assert!(!dir.0.join(LEDGER_FILE).exists());
    }

    #[test]
    fn a_link_changed_since_is_left_alone() {
        let dir = Dir::new();
        let nm = Fake::new(&dir.0, Tunnel::Split);
        // NM dropped the runtime priority (the link reconnected): nothing to restore.
        let left = serde_json::json!({ Uuid::new_v4().to_string(): [{ "iface": "eth0", "v4": 0, "v6": 0 }] });
        std::fs::write(dir.0.join(LEDGER_FILE), left.to_string()).unwrap();
        Harness::new(&dir.0).rt.restore_leftovers(&nm);
        assert!(nm.sets().is_empty());
        assert!(!dir.0.join(LEDGER_FILE).exists());
    }

    #[test]
    fn deactivate_restores() {
        let dir = Dir::new();
        let nm = Fake::new(&dir.0, Tunnel::Split);
        let h = Harness::new(&dir.0);
        let id = Uuid::new_v4();
        h.queue(&[Probe::Failed]);
        h.connect(&nm, id, DnsMode::Automatic);
        assert_eq!(nm.prio(WLAN), LOWERED);
        h.rt.release(&nm, &id, VPN, &h.log());
        assert_eq!(nm.prio(ETH), ORIGINAL);
        assert_eq!(nm.prio(WLAN), ORIGINAL);
        assert_eq!(h.rt.state(&id), None);
        assert!(!dir.0.join(LEDGER_FILE).exists());
    }

    #[test]
    fn a_link_shared_by_two_fallbacks_returns_when_the_last_one_ends() {
        let dir = Dir::new();
        let nm = Fake::new(&dir.0, Tunnel::Split);
        let h = Harness::new(&dir.0);
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        h.queue(&[Probe::Failed, Probe::Failed]);
        h.connect(&nm, a, DnsMode::Automatic);
        h.connect(&nm, b, DnsMode::Automatic);
        h.rt.release(&nm, &a, VPN, &h.log());
        assert_eq!(nm.prio(ETH), LOWERED, "b still falls back");
        h.rt.release(&nm, &b, VPN, &h.log());
        assert_eq!(nm.prio(ETH), ORIGINAL, "b's record holds the original, not a's lowered value");
    }

    #[test]
    fn a_connection_gone_during_the_probe_changes_nothing() {
        let dir = Dir::new();
        let nm = Fake::new(&dir.0, Tunnel::Split);
        let h = Harness::new(&dir.0);
        let id = Uuid::new_v4();
        h.queue(&[Probe::Failed]);
        let req = DnsRequest::default();
        h.rt.connected(&nm, id, VPN, &req, &h.log(), &|| false);
        assert_eq!(h.rt.state(&id), None);
        assert!(nm.sets().is_empty());
    }

    fn ledger_ifaces(dir: &Path) -> Vec<String> {
        let Ok(text) = std::fs::read_to_string(dir.join(LEDGER_FILE)) else { return Vec::new() };
        parse_ledger(&text).values().flatten().map(|h| h.iface.clone()).collect()
    }

    #[test]
    fn a_failed_restore_stays_recorded_and_the_next_check_retries_it() {
        let dir = Dir::new();
        let nm = Fake::new(&dir.0, Tunnel::Split);
        let h = Harness::new(&dir.0);
        let id = Uuid::new_v4();
        h.queue(&[Probe::Failed]);
        h.connect(&nm, id, DnsMode::Automatic);
        nm.failing.lock().unwrap().push(ETH.into());

        h.queue(&[Probe::Ok]);
        assert_eq!(h.check(&nm, id), Some(DnsState::Fallback), "eth0 is still lowered");
        assert_eq!(nm.prio(WLAN), ORIGINAL);
        assert_eq!(nm.prio(ETH), LOWERED);
        assert_eq!(ledger_ifaces(&dir.0), ["eth0"]);

        nm.failing.lock().unwrap().clear();
        h.queue(&[Probe::Ok]);
        assert_eq!(h.check(&nm, id), Some(DnsState::Vpn));
        assert_eq!(nm.prio(ETH), ORIGINAL);
        assert!(!dir.0.join(LEDGER_FILE).exists());
    }

    #[test]
    fn a_failed_release_keeps_the_record_for_the_start_restore() {
        let dir = Dir::new();
        let nm = Fake::new(&dir.0, Tunnel::Split);
        let h = Harness::new(&dir.0);
        let id = Uuid::new_v4();
        h.queue(&[Probe::Failed]);
        h.connect(&nm, id, DnsMode::Automatic);
        nm.failing.lock().unwrap().push(ETH.into());
        h.rt.release(&nm, &id, VPN, &h.log());
        assert_eq!(ledger_ifaces(&dir.0), ["eth0"]);
        nm.failing.lock().unwrap().clear();
        h.rt.restore_leftovers(&nm);
        assert_eq!(nm.prio(ETH), ORIGINAL);
        assert!(!dir.0.join(LEDGER_FILE).exists());
    }

    #[test]
    fn a_partly_failed_fallback_is_rolled_back() {
        let dir = Dir::new();
        let nm = Fake::new(&dir.0, Tunnel::Split);
        nm.failing.lock().unwrap().push(WLAN.into());
        let h = Harness::new(&dir.0);
        let id = Uuid::new_v4();
        h.queue(&[Probe::Ok, Probe::Failed, Probe::Failed]);
        h.connect(&nm, id, DnsMode::Automatic);
        h.check(&nm, id);
        assert_eq!(h.check(&nm, id), Some(DnsState::Vpn), "the previous layout stays");
        assert_eq!(nm.prio(ETH), ORIGINAL, "eth0 was lowered, then put back");
        assert!(!dir.0.join(LEDGER_FILE).exists());
        assert!(h.logged("DNS could not be changed"));
    }

    #[test]
    fn a_stale_end_leaves_the_new_session_alone() {
        let dir = Dir::new();
        let nm = Fake::new(&dir.0, Tunnel::Split);
        let h = Harness::new(&dir.0);
        let id = Uuid::new_v4();
        h.queue(&[Probe::Failed]);
        h.connect(&nm, id, DnsMode::Automatic);
        h.rt.release(&nm, &id, "/org/freedesktop/NetworkManager/ActiveConnection/6", &h.log());
        assert_eq!(h.rt.state(&id), Some(DnsState::Fallback));
        assert_eq!(nm.prio(ETH), LOWERED);
        h.rt.release(&nm, &id, VPN, &h.log());
        assert_eq!(h.rt.state(&id), None);
        assert_eq!(nm.prio(ETH), ORIGINAL);
    }

    #[test]
    fn a_release_during_the_probe_does_not_wait_and_the_check_then_changes_nothing() {
        let dir = Dir::new();
        let nm = Arc::new(Fake::new(&dir.0, Tunnel::Split));
        let id = Uuid::new_v4();
        let rt_cell: Arc<std::sync::OnceLock<Arc<DnsRuntime>>> = Arc::default();
        let results: Arc<Mutex<VecDeque<Probe>>> = Arc::new(Mutex::new(VecDeque::from([Probe::Failed, Probe::Failed])));
        let clock = Arc::new(Mutex::new(Instant::now()));
        let (cell, fake, res, c) = (rt_cell.clone(), nm.clone(), results.clone(), clock.clone());
        let rt = Arc::new(DnsRuntime::with_parts(
            &dir.0,
            Box::new(move |_: &[String]| {
                let r = res.lock().unwrap().pop_front().expect("an unexpected probe");
                if res.lock().unwrap().is_empty()
                    && let Some(rt) = cell.get()
                {
                    // The connection ends while the check's probe runs (the old code deadlocked here).
                    rt.release(fake.as_ref(), &id, VPN, &|_| {});
                }
                (r, "timeout".into())
            }),
            Box::new(move || *c.lock().unwrap()),
        ));
        let _ = rt_cell.set(rt.clone());
        let req = DnsRequest::default();
        rt.connected(nm.as_ref(), id, VPN, &req, &|_| {}, &|| true);
        assert_eq!(rt.state(&id), Some(DnsState::Fallback));
        *clock.lock().unwrap() += MIN_CHECK_INTERVAL + Duration::from_secs(1);
        assert_eq!(rt.check(nm.as_ref(), &id, &|_| {}), None);
        assert_eq!(rt.state(&id), None);
        assert_eq!(nm.prio(ETH), ORIGINAL);
    }
}
