//! The WinVPN Service's DNS manager (spec 2026-11-27, "Windows"): a connection's DNS mode becomes local NRPT rules
//! (`macvpn_core::dns_policy::nrpt`), the layout the shared mode logic decides (`macvpn_core::dns_policy::decide`).
//!
//! - **After connect** ([`Manager::after_connect`]): the VPN-sent DNS (OpenVPN's push, WireGuard's plan, else the
//!   VPN adapter's own), merged with the connection's request; the probe; the rules. OpenVPN and WireGuard come from
//!   the service's own `up`; SSTP (dialled by the app) from `dns-apply`.
//! - **`dns-check`** ([`Manager::check`]): the probe again (at most once in [`MIN_CHECK_SECS`], one at a time per
//!   connection); two failures in a row make Automatic fall back, one success returns. The rules are rewritten only
//!   when they change (another layout, another local network).
//! - **Split and Fallback** also clear the VPN adapter's own DNS, so Windows' parallel lookup does not send every
//!   name to it; OpenVPN and RAS restore it when they stop, WireGuard's adapter goes with the connection.
//! - **Release** ([`Manager::release`]) at `down`, when the engine's process ends on its own, `dns-release`, logoff
//!   and stop, and from the status poll for a connection that no longer runs (an SSTP whose RAS adapter is gone); a
//!   failed release is retried. **Reconcile** ([`Manager::reconcile`]) at service start removes the rules of
//!   connections that no longer run (a crash, a reboot).
//! - **Rewrites** write the new rules over the same keys first and delete the surplus after: there is no moment
//!   without a rule. Registry, IP Helper and policy-refresh steps run outside the sessions' lock, one at a time.
//!
//! Portable (no `cfg`): the registry, the adapters and the probe are behind [`Nrpt`], [`AdapterDns`] and
//! [`ProbeFn`] (the real ones are in `sys::dns`). Nothing here polls: the probe runs only after connect and on
//! `dns-check`. A refused policy refresh is logged and the connect goes on (Windows reads the rules at its own next
//! refresh).

use crate::shared::l10n::tr;
use crate::windows::service::LogSink;
use crate::windows::wg_plan::Plan;
use macvpn_core::dns_policy::nrpt::{self, NrptRule};
use macvpn_core::dns_policy::{
    Decision, Effective, Layout, Probe, Pushed, Tunnel, Warn, decide, dedup, effective, next_probe, state_of,
};
use macvpn_core::dns_settings::{
    DnsMode, DnsRequest, MAX_DOMAINS, MAX_SERVERS, full_tunnel_hint, is_dns_domain, is_dns_server, normalize_domain,
};
use macvpn_core::dns_zones::{MAX_ZONES, is_private, reverse_zones};
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::models::VPNKind;
use macvpn_core::netaddr::IpPrefix;
use macvpn_core::status::DnsState;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// `dns-check` probes a connection at most once in this many seconds (as macOS).
pub const MIN_CHECK_SECS: u64 = 20;
/// Every rule key the service writes starts with this (`WinVPN-<id>-<n>`).
const KEY_FAMILY: &str = "WinVPN-";
/// The status poll looks at a SID's RAS adapters at most once in this many seconds ([`Manager::release_gone`]).
pub const GONE_CHECK_SECS: u64 = 30;

/// The local NRPT rules (production: `macvpn_winsys::nrpt` under `DnsPolicyConfig`). Errors are the text for the
/// connection's log.
pub trait Nrpt: Send + Sync {
    /// Writes (or overwrites) each rule.
    fn write(&self, rules: &[NrptRule]) -> Result<(), String>;
    /// Deletes every rule whose key starts with `prefix`; how many went.
    fn delete(&self, prefix: &str) -> Result<usize, String>;
    /// Every rule key (the service's and other programs').
    fn keys(&self) -> Result<Vec<String>, String>;
    /// Makes the DNS client re-read the policy and drop its cache.
    fn apply(&self) -> Result<(), String>;
}

/// One adapter's DNS as Windows reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdapterNet {
    /// The DNS servers (IP literals; see [`usable_server`]).
    pub servers: Vec<String>,
    /// The connection-specific DNS suffix (at most one).
    pub domains: Vec<String>,
    /// The adapter's own subnets.
    pub subnets: Vec<IpPrefix>,
}

/// The network adapters (production: IP Helper).
pub trait AdapterDns: Send + Sync {
    /// The DNS of the adapter `luid`; `None`: no such adapter.
    fn get(&self, luid: u64) -> Option<AdapterNet>;
    /// Clears the adapter's own DNS servers and search list.
    fn clear(&self, luid: u64) -> Result<(), String>;
    /// Sets the adapter's own DNS servers and search list.
    fn set(&self, luid: u64, servers: &[String], domains: &[String]) -> Result<(), String>;
    /// The physical network: the adapter with the best default route that is no VPN's or virtual one.
    fn physical(&self) -> Option<AdapterNet>;
    /// `luid` is a RAS (PPP) adapter that is up: the only kind `dns-apply` may name, and while it is, its DNS
    /// session lasts.
    fn is_ppp(&self, luid: u64) -> bool;
}

/// The probe of the VPN's servers (production: `macvpn_core::dns_policy::probe`).
pub type ProbeFn = Box<dyn Fn(&[String]) -> (Probe, String) + Send + Sync>;

/// What an engine knows of its running connection's DNS after connect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VpnDns {
    /// The VPN-sent DNS: OpenVPN's push, WireGuard's plan. `None` or without servers: the adapter's own.
    pub pushed: Option<Pushed>,
    /// The server pushed `redirect-gateway` (OpenVPN; used when the config leaves routing to the server).
    pub pushed_full_tunnel: bool,
    /// The VPN adapter's interface LUID, if found.
    pub luid: Option<u64>,
    /// The engine's run (one process of the connection): its own end releases only the DNS it applied
    /// ([`Manager::release_run`]). `None`: the engine has no such runs.
    pub run: Option<u64>,
}

/// One connection's DNS step after connect.
pub struct Connect<'a> {
    /// The canonical (upper-case) UUID.
    pub id: &'a str,
    pub request: &'a DnsRequest,
    pub vpn: VpnDns,
    pub tunnel: Tunnel,
    /// `dns-apply` (SSTP): the SID that applied it, who alone may check and release it. `None`: a connection of
    /// the service's own engines (its ownership is the service's).
    pub owner: Option<&'a str>,
    /// The connection's log; `None`: the caller's sink of each call.
    pub log: Option<Arc<dyn LogSink>>,
    /// Asked under the sessions' lock right before the session is recorded (`dns-apply`: the ID is no connection
    /// of the service's engines); `false` changes nothing.
    pub admit: &'a dyn Fn() -> bool,
    /// The language of the step's log lines (a restart's step runs on the engine's thread: the connection's);
    /// `None`: the calling request's.
    pub language: Option<AppLanguage>,
}

/// The log lines of one request, for a connection whose log the service does not keep (SSTP: the app writes them
/// into its own log).
#[derive(Default)]
pub struct Lines(Mutex<Vec<String>>);

impl Lines {
    /// The lines, each with a line end.
    pub fn text(&self) -> String {
        lock(&self.0).iter().map(|l| format!("{l}\n")).collect()
    }
}

impl LogSink for Lines {
    fn line(&self, text: &str) {
        lock(&self.0).push(text.to_string());
    }
}

struct Session {
    /// Which `after_connect` made it (a later step of an earlier one must not record for it).
    epoch: u64,
    mode: DnsMode,
    tunnel: Tunnel,
    eff: Effective,
    probe: Probe,
    fails: u32,
    layout: Layout,
    warn: Option<Warn>,
    /// The rules written last (compared before every rewrite).
    rules: Vec<NrptRule>,
    /// A layout is in place (false while the first probe runs, or when the first write failed).
    applied: bool,
    /// The last write failed: the next step writes again.
    dirty: bool,
    luid: Option<u64>,
    /// The engine run that applied it ([`VpnDns::run`]).
    run: Option<u64>,
    /// The VPN adapter's own DNS was cleared (Split, Fallback); a return to `Vpn` sets it again.
    cleared: bool,
    owner: Option<String>,
    log: Option<Arc<dyn LogSink>>,
    /// The last probe's time (Unix seconds).
    probed_at: u64,
    checking: bool,
}

impl Session {
    fn state(&self) -> DnsState {
        state_of(self.layout, self.warn)
    }

    fn probes(&self) -> bool {
        decide(self.mode, self.tunnel, !self.eff.servers.is_empty(), self.eff.has_match(), Probe::NotRun).probes
    }

    fn decide(&self, probe: Probe) -> Decision {
        decide(self.mode, self.tunnel, !self.eff.servers.is_empty(), self.eff.has_match(), probe)
    }

    /// The state a step answers: the layout's, or `None` while none is in place.
    fn answer(&self) -> DnsState {
        if self.applied { self.state() } else { DnsState::None }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The DNS manager of the service: one session per connection with DNS.
pub struct Manager {
    nrpt: Box<dyn Nrpt>,
    adapters: Box<dyn AdapterDns>,
    probe: ProbeFn,
    /// The sessions; held only for short reads and records, never across I/O.
    sessions: Mutex<HashMap<String, Session>>,
    /// Held across every registry, IP Helper and policy-refresh step, so they run one at a time and a release
    /// never interleaves with a write. Lock order: `io`, then `sessions`. The service's own locks are never held
    /// while calling in.
    io: Mutex<()>,
    /// Connections whose rules could not be deleted: retried by [`Manager::retry`].
    unreleased: Mutex<HashSet<String>>,
    /// When each SID's RAS adapters were last looked at ([`Manager::release_gone`]).
    gone_checked: Mutex<HashMap<String, u64>>,
    epochs: AtomicU64,
}

/// What one step writes, planned under the sessions' lock.
struct StepPlan {
    eff: Effective,
    luid: Option<u64>,
    cleared: bool,
    log: Option<Arc<dyn LogSink>>,
}

impl Manager {
    pub fn new(nrpt: Box<dyn Nrpt>, adapters: Box<dyn AdapterDns>, probe: ProbeFn) -> Manager {
        Manager {
            nrpt,
            adapters,
            probe,
            sessions: Mutex::default(),
            io: Mutex::default(),
            unreleased: Mutex::default(),
            gone_checked: Mutex::default(),
            epochs: AtomicU64::new(1),
        }
    }

    /// After connect (also after OpenVPN restarted itself): the effective DNS, the probe (when the mode probes) and
    /// the rules. `now`: Unix seconds (the probe's time). The state the connection reports; `None` when another
    /// owner holds `c.id` (an SSTP session of another SID, or of `dns-apply` for an engine's connection, or the
    /// other way round) or `c.admit` refuses (nothing changed), or when `c.id` was released while the probe ran
    /// (nothing written).
    pub fn after_connect(&self, c: Connect<'_>, now: u64, spill: &dyn LogSink) -> Option<DnsState> {
        match c.language {
            Some(language) => with_language(language, || self.connect_step(c, now, spill)),
            None => self.connect_step(c, now, spill),
        }
    }

    /// [`Manager::after_connect`] in the step's language.
    fn connect_step(&self, c: Connect<'_>, now: u64, spill: &dyn LogSink) -> Option<DnsState> {
        let log_arc = c.log.clone();
        let log: &dyn LogSink = log_arc.as_deref().unwrap_or(spill);
        let mode = c.request.mode;
        let pushed = self.pushed(c.vpn.pushed, c.vpn.luid);
        let e = effective(&pushed, c.request);
        let epoch = self.epochs.fetch_add(1, Ordering::SeqCst);
        {
            let mut sessions = lock(&self.sessions);
            // The owner check and the insert under one lock: no other SID takes the ID in between.
            if sessions.get(c.id).is_some_and(|s| s.owner.as_deref() != c.owner) || !(c.admit)() {
                return None;
            }
            let session = Session {
                epoch,
                mode,
                tunnel: c.tunnel,
                eff: e.clone(),
                probe: Probe::NotRun,
                fails: 0,
                layout: Layout::None,
                warn: None,
                rules: Vec::new(),
                applied: false,
                dirty: false,
                luid: c.vpn.luid,
                run: c.vpn.run,
                cleared: false,
                owner: c.owner.map(str::to_string),
                log: c.log,
                probed_at: now,
                checking: true,
            };
            // An earlier run's rules of this ID stay until this one overwrites them (they share the key prefix).
            sessions.insert(c.id.to_string(), session);
        }
        log.line(&tr("DNS mode: %@", &[mode.raw()]));
        let (has_servers, has_match) = (!e.servers.is_empty(), e.has_match());
        let probes = decide(mode, c.tunnel, has_servers, has_match, Probe::NotRun).probes;
        let (probe, detail) = if probes { (self.probe)(&e.servers) } else { (Probe::NotRun, String::new()) };
        let d = decide(mode, c.tunnel, has_servers, has_match, probe);
        if let Some(s) = lock(&self.sessions).get_mut(c.id).filter(|s| s.epoch == epoch) {
            s.checking = false;
        }
        self.settle(c.id, epoch, d, (probe, u32::from(probe == Probe::Failed)), &detail, spill)
    }

    /// `dns-check`: the probe again, the decision and, when they changed, the rules. Without a probe when the
    /// mode does not probe, a step of it runs, or the last probe was less than [`MIN_CHECK_SECS`] ago (a layout
    /// whose write failed is written again then). `None`: no session (or released during the probe); the state is
    /// `None` while no layout is in place.
    pub fn check(&self, id: &str, now: u64, spill: &dyn LogSink) -> Option<DnsState> {
        self.retry(spill);
        let (epoch, servers) = {
            let mut sessions = lock(&self.sessions);
            let s = sessions.get_mut(id)?;
            if s.checking {
                return Some(s.answer());
            }
            let recent = now >= s.probed_at && now - s.probed_at < MIN_CHECK_SECS;
            if !s.probes() || recent {
                if s.applied && !s.dirty {
                    return Some(s.state());
                }
                let (epoch, d, probe, fails) = (s.epoch, s.decide(s.probe), s.probe, s.fails);
                drop(sessions);
                return self.settle(id, epoch, d, (probe, fails), "", spill);
            }
            s.checking = true;
            s.probed_at = now;
            (s.epoch, s.eff.servers.clone())
        };
        let (result, detail) = (self.probe)(&servers);
        let (d, probe, fails) = {
            let mut sessions = lock(&self.sessions);
            let s = sessions.get_mut(id).filter(|s| s.epoch == epoch)?;
            s.checking = false;
            let (probe, fails) = next_probe(s.probe, s.fails, result);
            (s.decide(probe), probe, fails)
        };
        self.settle(id, epoch, d, (probe, fails), &detail, spill)
    }

    /// The state `status` reports (`None`: no layout in place).
    pub fn state(&self, id: &str) -> Option<DnsState> {
        lock(&self.sessions).get(id).filter(|s| s.applied).map(Session::state)
    }

    /// Whether `id` has a session, and the SID that holds it (`dns-apply`); `None`: no session.
    pub fn owner(&self, id: &str) -> Option<Option<String>> {
        lock(&self.sessions).get(id).map(|s| s.owner.clone())
    }

    /// The sessions `sid` holds through `dns-apply`, and all sessions.
    pub fn counts(&self, sid: &str) -> (usize, usize) {
        let sessions = lock(&self.sessions);
        (sessions.values().filter(|s| s.owner.as_deref() == Some(sid)).count(), sessions.len())
    }

    /// `luid` may be named by `dns-apply` (a RAS adapter that is up).
    pub fn is_ras_adapter(&self, luid: u64) -> bool {
        self.adapters.is_ppp(luid)
    }

    /// `id` leaves: its session ends and its rules go. Only the holder may release it: `owner` must be the
    /// session's (`None`: a connection of the service's engines). Nothing is read or written without a session or a
    /// release still owed. A delete that fails is retried by [`Manager::retry`]. `true` if any rule went.
    pub fn release(&self, id: &str, owner: Option<&str>, spill: &dyn LogSink) -> bool {
        self.release_where(id, &|s| s.owner.as_deref() == owner, true, spill)
    }

    /// The engine's run `run` of `id` ended on its own: the DNS it applied goes, but never a later run's session
    /// (a new `up` of the same connection may already hold it).
    pub fn release_run(&self, id: &str, run: u64, spill: &dyn LogSink) -> bool {
        self.release_where(id, &|s| s.owner.is_none() && s.run == Some(run), false, spill)
    }

    /// The release of `id` when its session passes `holds`; `owed`: also a release owed without a session.
    fn release_where(&self, id: &str, holds: &dyn Fn(&Session) -> bool, owed: bool, spill: &dyn LogSink) -> bool {
        let is_owed = || owed && lock(&self.unreleased).contains(id);
        // The status poll asks for every ended connection: without anything to release, no lock is waited for.
        if !lock(&self.sessions).contains_key(id) && !is_owed() {
            return false;
        }
        let _io = lock(&self.io);
        let session = {
            let mut sessions = lock(&self.sessions);
            match sessions.get(id) {
                Some(s) if !holds(s) => return false,
                Some(_) => sessions.remove(id),
                None if !is_owed() => return false,
                None => None,
            }
        };
        let log_arc = session.and_then(|s| s.log);
        self.delete_rules(id, log_arc.as_deref().unwrap_or(spill))
    }

    /// The releases that failed before, tried again (the status poll and `dns-check`).
    pub fn retry(&self, spill: &dyn LogSink) {
        let owed: Vec<String> = lock(&self.unreleased).iter().cloned().collect();
        if owed.is_empty() {
            return;
        }
        let _io = lock(&self.io);
        for id in owed {
            self.delete_rules(&id, spill);
        }
    }

    /// Every rule of `id` goes (the caller holds `io`); a failure is owed.
    fn delete_rules(&self, id: &str, log: &dyn LogSink) -> bool {
        match self.nrpt.delete(&nrpt::key_prefix(id)) {
            Ok(n) => {
                lock(&self.unreleased).remove(id);
                if n > 0 {
                    self.refresh(log);
                    log.line(&tr("the original DNS is back", &[]));
                }
                n > 0
            }
            Err(e) => {
                log.line(&tr("DNS could not be changed: %@", &[&e]));
                lock(&self.unreleased).insert(id.to_string());
                false
            }
        }
    }

    /// The sessions `sid` holds through `dns-apply` whose RAS adapter is gone (hung up, or dropped by the server
    /// while the app did not run) are released. The adapters are read only when `sid` holds such a session, and at
    /// most once in [`GONE_CHECK_SECS`] per SID (the status poll calls this).
    pub fn release_gone(&self, sid: &str, now: u64, spill: &dyn LogSink) {
        let held: Vec<(String, u64)> = lock(&self.sessions)
            .iter()
            .filter(|(_, s)| s.owner.as_deref() == Some(sid))
            .filter_map(|(id, s)| s.luid.map(|l| (id.clone(), l)))
            .collect();
        if held.is_empty() {
            return;
        }
        {
            let mut checked = lock(&self.gone_checked);
            if checked.get(sid).is_some_and(|t| now >= *t && now - t < GONE_CHECK_SECS) {
                return;
            }
            checked.insert(sid.to_string(), now);
        }
        for (id, luid) in held {
            if !self.adapters.is_ppp(luid) {
                self.release(&id, Some(sid), spill);
            }
        }
    }

    /// The user's session ended: every session `sid` holds through `dns-apply` is released.
    pub fn release_owned_by(&self, sid: &str, spill: &dyn LogSink) {
        let ids: Vec<String> = lock(&self.sessions)
            .iter()
            .filter(|(_, s)| s.owner.as_deref() == Some(sid))
            .map(|(id, _)| id.clone())
            .collect();
        for id in ids {
            self.release(&id, Some(sid), spill);
        }
        lock(&self.gone_checked).remove(sid);
    }

    /// The service stops: every session is released.
    pub fn release_all(&self, spill: &dyn LogSink) {
        let held: Vec<(String, Option<String>)> =
            lock(&self.sessions).iter().map(|(id, s)| (id.clone(), s.owner.clone())).collect();
        for (id, owner) in held {
            self.release(&id, owner.as_deref(), spill);
        }
        self.retry(spill);
    }

    /// Removes the rules of every connection that has no session and for which `running` is false (service start:
    /// a crash or a reboot left them). How many rules went; `Err`: the rules could not be listed or deleted.
    pub fn reconcile(&self, running: &dyn Fn(&str) -> bool, spill: &dyn LogSink) -> Result<usize, String> {
        let _io = lock(&self.io);
        let keys = self.nrpt.keys()?;
        let stale: HashSet<String> = {
            let sessions = lock(&self.sessions);
            keys.iter()
                .filter_map(|k| rule_key(k).map(|(id, _)| id))
                .filter(|id| !sessions.contains_key(*id) && !running(id))
                .map(str::to_string)
                .collect()
        };
        let mut removed = 0;
        for id in &stale {
            removed += self.nrpt.delete(&nrpt::key_prefix(id))?;
        }
        if removed > 0 {
            self.refresh(spill);
        }
        Ok(removed)
    }

    /// The VPN-sent DNS; without servers, the VPN adapter's own (and its suffix when nothing else names a domain).
    fn pushed(&self, pushed: Option<Pushed>, luid: Option<u64>) -> Pushed {
        let mut p = pushed.unwrap_or_default();
        if p.servers.is_empty()
            && let Some(own) = luid.and_then(|l| self.adapters.get(l))
        {
            p.servers = dedup(own.servers.into_iter().filter(|s| is_dns_server(s)), MAX_SERVERS);
            if p.search.is_empty() {
                p.search = clean_domains(&own.domains);
            }
        }
        p
    }

    /// Puts decision `d` in place for session `epoch` of `id` and logs a change of layout or warning. Planned under
    /// the sessions' lock, written outside it (under `io`), recorded only while the session is still that epoch's.
    /// A write that failed keeps the previous layout and marks the session dirty: the next step writes again.
    /// `None`: no such session any more.
    fn settle(
        &self,
        id: &str,
        epoch: u64,
        d: Decision,
        (probe, fails): (Probe, u32),
        detail: &str,
        spill: &dyn LogSink,
    ) -> Option<DnsState> {
        let _io = lock(&self.io);
        let (plan, layout_was) = {
            let sessions = lock(&self.sessions);
            let s = sessions.get(id).filter(|s| s.epoch == epoch)?;
            let plan = StepPlan { eff: s.eff.clone(), luid: s.luid, cleared: s.cleared, log: s.log.clone() };
            (plan, (s.applied, s.dirty, s.layout, s.rules.clone()))
        };
        let log: &dyn LogSink = plan.log.as_deref().unwrap_or(spill);
        let local = (d.layout == Layout::Vpn { local: true })
            .then(|| self.adapters.physical())
            .flatten()
            .map(|p| (local_names(&p), dedup(p.servers.into_iter().filter(|v| is_dns_server(v)), MAX_SERVERS)));
        let rules = nrpt::rules(id, d.layout, &plan.eff, local.as_ref().map(|(n, v)| (n.as_slice(), v.as_slice())));
        let (applied, dirty, layout, written) = layout_was;
        let write = !applied || dirty || layout != d.layout || written != rules;
        let ok = !write || self.write_rules(id, &rules, log);
        let cleared = if ok { self.adapter_dns(d.layout, &plan, log) } else { plan.cleared };
        let mut sessions = lock(&self.sessions);
        let s = sessions.get_mut(id).filter(|s| s.epoch == epoch)?;
        s.probe = probe;
        s.fails = fails;
        s.cleared = cleared;
        if !ok {
            s.dirty = true;
            return Some(s.answer());
        }
        let was = s.applied.then_some((s.layout, s.warn));
        s.layout = d.layout;
        s.warn = d.warn;
        s.rules = rules;
        s.applied = true;
        s.dirty = false;
        if was != Some((d.layout, d.warn)) {
            log_change(was, &d, &s.eff, detail, log);
        }
        Some(s.state())
    }

    /// Writes `rules` over the same keys first, then deletes only this connection's keys numbered beyond them: no
    /// moment without a rule (Strict never leaks a name). Refreshes the policy when anything changed. `false`: a
    /// write or delete failed (logged).
    fn write_rules(&self, id: &str, rules: &[NrptRule], log: &dyn LogSink) -> bool {
        let written = self.nrpt.write(rules).and_then(|()| {
            let stale: Vec<String> = self
                .nrpt
                .keys()?
                .into_iter()
                .filter(|k| rule_key(k).is_some_and(|(of, n)| of == id && n >= rules.len()))
                .collect();
            stale.iter().try_fold(0, |sum, k| Ok::<usize, String>(sum + self.nrpt.delete(k)?))
        });
        match written {
            Ok(removed) => {
                if removed > 0 || !rules.is_empty() {
                    self.refresh(log);
                }
                if let Some(own) = rules.get(1) {
                    let names: Vec<&str> = own.names.iter().map(|n| n.trim_start_matches('.')).collect();
                    log.line(&tr("the local network's names stay on its DNS: %@", &[&names.join(", ")]));
                }
                true
            }
            Err(e) => {
                log.line(&tr("DNS could not be changed: %@", &[&e]));
                false
            }
        }
    }

    /// The VPN adapter's own DNS for `layout`: cleared for Split and Fallback (so Windows' parallel lookup does not
    /// send every name to it), set again to the effective VPN DNS on the way back to `Vpn` (the spec's "kept").
    /// Whether it is cleared now.
    fn adapter_dns(&self, layout: Layout, plan: &StepPlan, log: &dyn LogSink) -> bool {
        let Some(luid) = plan.luid else { return plan.cleared };
        match layout {
            Layout::Split | Layout::Fallback if !plan.cleared => match self.adapters.clear(luid) {
                Ok(()) => true,
                Err(e) => {
                    log.line(&tr("the VPN adapter's own DNS could not be cleared (%@)", &[&e]));
                    false
                }
            },
            Layout::Vpn { .. } if plan.cleared => {
                if let Err(e) = self.adapters.set(luid, &plan.eff.servers, &plan.eff.search) {
                    log.line(&tr("DNS could not be changed: %@", &[&e]));
                }
                false
            }
            _ => plan.cleared,
        }
    }

    /// The policy refresh; refused, Windows reads the rules at its own next refresh (logged, never an error).
    fn refresh(&self, log: &dyn LogSink) {
        if let Err(e) = self.nrpt.apply() {
            log.line(&tr("Windows applies the DNS rules at its next policy refresh (%@)", &[&e]));
        }
    }
}

/// The connection id and number of one of the service's rule keys (`WinVPN-<id>-<n>`); `None` for any other key.
fn rule_key(key: &str) -> Option<(&str, usize)> {
    let (id, n) = key.strip_prefix(KEY_FAMILY)?.rsplit_once('-')?;
    let n = n.parse::<usize>().ok().filter(|_| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))?;
    (!id.is_empty()).then_some((id, n))
}

/// Valid domains, lower-case, each once, capped.
fn clean_domains(domains: &[String]) -> Vec<String> {
    dedup(domains.iter().map(|d| normalize_domain(d)).filter(|d| is_dns_domain(d)), MAX_DOMAINS)
}

/// The physical network's own names: its DNS suffix and the reverse zones of its private subnets (they stay on its
/// DNS in the Automatic and Full modes).
fn local_names(p: &AdapterNet) -> Vec<String> {
    let zones = p.subnets.iter().filter(|s| is_private(s)).flat_map(reverse_zones);
    dedup(clean_domains(&p.domains).into_iter().chain(zones), MAX_ZONES)
}

/// A DNS server address worth a rule: not link-local (its zone is lost in text) and not one of the deprecated
/// site-local defaults Windows lists for an adapter without IPv6 DNS (`fec0:0:0:ffff::1`–`3`).
pub fn usable_server(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => !a.is_unspecified() && !a.is_link_local(),
        IpAddr::V6(a) => !a.is_unspecified() && !matches!(a.segments()[0] & 0xffc0, 0xfe80 | 0xfec0),
    }
}

/// The tunnel of an OpenVPN or WireGuard connection: the config's own routing choice, else (OpenVPN leaving it to
/// the server) whether the server pushed `redirect-gateway`.
pub fn tunnel_of(kind: VPNKind, config: &str, pushed_full_tunnel: bool) -> Tunnel {
    tunnel_from(full_tunnel_hint(kind, config), pushed_full_tunnel)
}

/// [`tunnel_of`] from the config's choice already read (`macvpn_core::dns_settings::full_tunnel_hint`).
pub fn tunnel_from(config_full_tunnel: Option<bool>, pushed_full_tunnel: bool) -> Tunnel {
    if config_full_tunnel.unwrap_or(pushed_full_tunnel) { Tunnel::Full } else { Tunnel::Split }
}

/// WireGuard's VPN-sent DNS: the config's `DNS =` servers and domains, and the AllowedIPs (for the reverse zones).
pub fn wireguard_pushed(plan: &Plan) -> Pushed {
    Pushed {
        servers: dedup(plan.dns_servers.iter().map(ToString::to_string), MAX_SERVERS),
        search: clean_domains(&plan.dns_search),
        resolve: Vec::new(),
        routes: plan.routes().iter().filter_map(|p| IpPrefix::new(p.addr(), p.prefix_len())).collect(),
    }
}

/// The log line of a new layout or warning (the macOS texts; Windows has no "verified" step).
fn log_change(was: Option<(Layout, Option<Warn>)>, d: &Decision, e: &Effective, detail: &str, log: &dyn LogSink) {
    if d.warn == Some(Warn::TargetedOnFullTunnel) {
        log.line(&tr("full tunnel: the Targeted mode acts as Automatic", &[]));
    }
    let line = match (d.layout, d.warn) {
        (Layout::None, _) => tr("the VPN sent no DNS; internal names will not resolve", &[]),
        (Layout::Fallback, _) => {
            tr("the VPN's DNS does not resolve internet names (%@): only the VPN's domains use it now", &[detail])
        }
        (Layout::Vpn { local: false }, Some(Warn::Failing)) => {
            tr("Strict DNS: the VPN's DNS does not answer (%@); DNS stays in the tunnel", &[detail])
        }
        (Layout::Vpn { .. }, Some(Warn::Failing)) => {
            tr("the VPN's DNS does not answer (%@); it stays in effect", &[detail])
        }
        (Layout::Vpn { .. }, _) if matches!(was, Some((Layout::Fallback, _))) => {
            tr("the VPN's DNS answers again: it is in effect for every name", &[])
        }
        (Layout::Vpn { .. }, _) => tr(
            "the VPN's DNS is in effect for every name (%@ servers, %@ domains)",
            &[&e.servers.len().to_string(), &e.search.len().to_string()],
        ),
        (Layout::Split, Some(Warn::TargetedNoDomains)) => {
            tr("Targeted DNS: no domain uses the VPN's DNS (the VPN sent none, none is set)", &[])
        }
        (Layout::Split, _) => tr(
            "only the VPN's domains use the VPN's DNS (%@ servers, %@ domains)",
            &[&e.servers.len().to_string(), &(e.search.len() + e.resolve.len()).to_string()],
        ),
    };
    log.line(&line);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::OnceLock;
    use std::sync::atomic::AtomicBool;

    const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
    const OTHER: &str = "11111111-2222-3333-4444-555555555555";
    const LUID: u64 = 0x0017_0000_0100_0000;

    #[derive(Default)]
    struct FakeNrpt {
        rules: Mutex<BTreeMap<String, NrptRule>>,
        writes: Mutex<u32>,
        applies: Mutex<u32>,
        /// Every write and delete, in order (`write <key>`, `delete <prefix>`).
        ops: Mutex<Vec<String>>,
        fail_write: AtomicBool,
        fail_delete: AtomicBool,
        fail_apply: bool,
    }

    impl FakeNrpt {
        fn names(&self) -> Vec<(String, Vec<String>, Vec<String>)> {
            lock(&self.rules).values().map(|r| (r.key.clone(), r.names.clone(), r.servers.clone())).collect()
        }
    }

    impl Nrpt for Arc<FakeNrpt> {
        fn write(&self, rules: &[NrptRule]) -> Result<(), String> {
            if self.fail_write.load(Ordering::SeqCst) {
                return Err("access denied".into());
            }
            *lock(&self.writes) += 1;
            for r in rules {
                lock(&self.ops).push(format!("write {}", r.key));
                lock(&self.rules).insert(r.key.clone(), r.clone());
            }
            Ok(())
        }
        fn delete(&self, prefix: &str) -> Result<usize, String> {
            if self.fail_delete.load(Ordering::SeqCst) {
                return Err("access denied".into());
            }
            lock(&self.ops).push(format!("delete {prefix}"));
            let mut rules = lock(&self.rules);
            let before = rules.len();
            rules.retain(|k, _| !k.starts_with(prefix));
            Ok(before - rules.len())
        }
        fn keys(&self) -> Result<Vec<String>, String> {
            Ok(lock(&self.rules).keys().cloned().collect())
        }
        fn apply(&self) -> Result<(), String> {
            *lock(&self.applies) += 1;
            if self.fail_apply { Err("Dnscache refused".into()) } else { Ok(()) }
        }
    }

    /// One `AdapterDns::set`: the adapter, its servers and its domains.
    type SetCall = (u64, Vec<String>, Vec<String>);

    #[derive(Default)]
    struct FakeAdapters {
        vpn: Option<AdapterNet>,
        physical: Mutex<Option<AdapterNet>>,
        cleared: Mutex<Vec<u64>>,
        set: Mutex<Vec<SetCall>>,
        /// How often `is_ppp` was asked, and its answer.
        ppp_asked: Mutex<u32>,
        ppp_up: AtomicBool,
    }

    impl AdapterDns for Arc<FakeAdapters> {
        fn get(&self, luid: u64) -> Option<AdapterNet> {
            (luid == LUID).then(|| self.vpn.clone()).flatten()
        }
        fn clear(&self, luid: u64) -> Result<(), String> {
            lock(&self.cleared).push(luid);
            Ok(())
        }
        fn set(&self, luid: u64, servers: &[String], domains: &[String]) -> Result<(), String> {
            lock(&self.set).push((luid, servers.to_vec(), domains.to_vec()));
            Ok(())
        }
        fn physical(&self) -> Option<AdapterNet> {
            lock(&self.physical).clone()
        }
        fn is_ppp(&self, luid: u64) -> bool {
            *lock(&self.ppp_asked) += 1;
            luid == LUID && self.ppp_up.load(Ordering::SeqCst)
        }
    }

    fn home() -> AdapterNet {
        AdapterNet {
            servers: vec!["192.168.1.1".into()],
            domains: vec!["home.lan".into()],
            subnets: vec![IpPrefix::parse("192.168.1.0/24").unwrap()],
        }
    }

    /// The probe's answers in order (the last one repeats), and how often it ran.
    struct Probes {
        answers: Mutex<Vec<Probe>>,
        runs: Mutex<u32>,
        /// Runs during the probe (a `down` while it waits).
        during: OnceLock<Box<dyn Fn() + Send + Sync>>,
    }

    struct T {
        m: Arc<Manager>,
        nrpt: Arc<FakeNrpt>,
        adapters: Arc<FakeAdapters>,
        probes: Arc<Probes>,
        log: Arc<Lines>,
    }

    fn t_with(nrpt: FakeNrpt, adapters: FakeAdapters, answers: &[Probe]) -> T {
        let (nrpt, adapters) = (Arc::new(nrpt), Arc::new(adapters));
        let probes =
            Arc::new(Probes { answers: Mutex::new(answers.to_vec()), runs: Mutex::default(), during: OnceLock::new() });
        let p = probes.clone();
        let probe: ProbeFn = Box::new(move |servers| {
            assert!(!servers.is_empty());
            *lock(&p.runs) += 1;
            if let Some(f) = p.during.get() {
                f();
            }
            let mut a = lock(&p.answers);
            let r = if a.len() > 1 { a.remove(0) } else { a[0] };
            (r, format!("{}: {}", servers[0], if r == Probe::Ok { "resolved" } else { "REFUSED" }))
        });
        let m = Arc::new(Manager::new(Box::new(nrpt.clone()), Box::new(adapters.clone()), probe));
        T { m, nrpt, adapters, probes, log: Arc::new(Lines::default()) }
    }

    fn t(answers: &[Probe]) -> T {
        t_with(FakeNrpt::default(), FakeAdapters { physical: Mutex::new(Some(home())), ..Default::default() }, answers)
    }

    fn pushed() -> VpnDns {
        VpnDns {
            pushed: Some(Pushed {
                servers: vec!["10.99.0.53".into()],
                search: vec!["lab.test".into()],
                ..Pushed::default()
            }),
            pushed_full_tunnel: false,
            luid: Some(LUID),
            run: None,
        }
    }

    fn request(mode: DnsMode) -> DnsRequest {
        DnsRequest { mode, ..DnsRequest::default() }
    }

    impl T {
        fn connect_as(
            &self,
            id: &str,
            mode: DnsMode,
            vpn: VpnDns,
            tunnel: Tunnel,
            owner: Option<&str>,
        ) -> Option<DnsState> {
            let log: Arc<dyn LogSink> = self.log.clone();
            let req = request(mode);
            let c = Connect { id, request: &req, vpn, tunnel, owner, log: Some(log), admit: &|| true, language: None };
            with_language(AppLanguage::En, || self.m.after_connect(c, 1000, &Lines::default()))
        }
        fn connect(&self, mode: DnsMode, tunnel: Tunnel) -> Option<DnsState> {
            self.connect_as(ID, mode, pushed(), tunnel, None)
        }
        fn check(&self, now: u64) -> Option<DnsState> {
            with_language(AppLanguage::En, || self.m.check(ID, now, &Lines::default()))
        }
        fn rules(&self) -> Vec<(String, Vec<String>, Vec<String>)> {
            self.nrpt.names()
        }
        fn runs(&self) -> u32 {
            *lock(&self.probes.runs)
        }
    }

    fn rule(n: u32, names: &[&str], servers: &[&str]) -> (String, Vec<String>, Vec<String>) {
        (
            format!("WinVPN-{ID}-{n}"),
            names.iter().map(|s| s.to_string()).collect(),
            servers.iter().map(|s| s.to_string()).collect(),
        )
    }

    fn catch_all_and_local() -> Vec<(String, Vec<String>, Vec<String>)> {
        vec![rule(0, &["."], &["10.99.0.53"]), rule(1, &[".home.lan", ".1.168.192.in-addr.arpa"], &["192.168.1.1"])]
    }

    #[test]
    fn automatic_with_a_good_probe_catches_every_name_and_keeps_the_local_names_local() {
        let t = t(&[Probe::Ok]);
        assert_eq!(t.connect(DnsMode::Automatic, Tunnel::Split), Some(DnsState::Vpn));
        assert_eq!(t.rules(), catch_all_and_local());
        assert_eq!(*lock(&t.nrpt.applies), 1);
        assert!(lock(&t.adapters.cleared).is_empty(), "the adapter keeps its DNS");
        assert_eq!(t.m.state(ID), Some(DnsState::Vpn));
        let log = t.log.text();
        assert!(log.contains("DNS mode: automatic"), "{log}");
        assert!(log.contains("the local network's names stay on its DNS: home.lan, 1.168.192.in-addr.arpa"), "{log}");
        assert!(log.contains("the VPN's DNS is in effect for every name (1 servers, 1 domains)"), "{log}");
    }

    #[test]
    fn automatic_falls_back_after_two_failed_checks_and_returns_after_one_good_one() {
        let t = t(&[Probe::Ok, Probe::Failed, Probe::Failed, Probe::Ok]);
        assert_eq!(t.connect(DnsMode::Automatic, Tunnel::Split), Some(DnsState::Vpn));
        assert_eq!(t.check(1300), Some(DnsState::Vpn), "one failure keeps the layout");
        assert_eq!(*lock(&t.nrpt.writes), 1, "nothing rewritten");
        assert_eq!(t.check(1600), Some(DnsState::Fallback));
        assert_eq!(t.rules(), [rule(0, &[".lab.test"], &["10.99.0.53"])]);
        assert_eq!(*lock(&t.adapters.cleared), [LUID]);
        assert!(t.log.text().contains("the VPN's DNS does not resolve internet names (10.99.0.53: REFUSED)"));
        assert_eq!(t.check(1900), Some(DnsState::Vpn));
        assert_eq!(t.rules(), catch_all_and_local());
        assert!(t.log.text().contains("the VPN's DNS answers again: it is in effect for every name"));
        assert_eq!(t.runs(), 4);
    }

    #[test]
    fn a_failed_probe_at_connect_falls_back_at_once() {
        let t = t(&[Probe::Failed]);
        assert_eq!(t.connect(DnsMode::Automatic, Tunnel::Full), Some(DnsState::FallbackFullTunnel));
        assert_eq!(t.rules(), [rule(0, &[".lab.test"], &["10.99.0.53"])]);
    }

    #[test]
    fn full_failing_keeps_the_catch_all() {
        let t = t(&[Probe::Failed]);
        assert_eq!(t.connect(DnsMode::Full, Tunnel::Split), Some(DnsState::Failing));
        assert_eq!(t.rules(), catch_all_and_local());
        assert!(t.log.text().contains("the VPN's DNS does not answer (10.99.0.53: REFUSED); it stays in effect"));
    }

    #[test]
    fn strict_has_only_the_catch_all() {
        let t = t(&[Probe::Ok]);
        assert_eq!(t.connect(DnsMode::Strict, Tunnel::Split), Some(DnsState::Vpn));
        assert_eq!(t.rules(), [rule(0, &["."], &["10.99.0.53"])]);
    }

    #[test]
    fn targeted_on_a_split_tunnel_routes_only_the_domains_and_clears_the_adapter() {
        let t = t(&[Probe::Ok]);
        assert_eq!(t.connect(DnsMode::Targeted, Tunnel::Split), Some(DnsState::Targeted));
        assert_eq!(t.rules(), [rule(0, &[".lab.test"], &["10.99.0.53"])]);
        assert_eq!(*lock(&t.adapters.cleared), [LUID]);
        assert_eq!(t.runs(), 0, "Targeted never probes");
        assert_eq!(t.check(5000), Some(DnsState::Targeted));
        assert_eq!(t.runs(), 0);
    }

    #[test]
    fn targeted_on_a_full_tunnel_acts_as_automatic() {
        let t = t(&[Probe::Ok]);
        assert_eq!(t.connect(DnsMode::Targeted, Tunnel::Full), Some(DnsState::Vpn));
        assert!(t.log.text().contains("full tunnel: the Targeted mode acts as Automatic"));
    }

    #[test]
    fn no_servers_no_rules() {
        let t = t(&[Probe::Ok]);
        let vpn = VpnDns { pushed: None, pushed_full_tunnel: false, luid: None, run: None };
        assert_eq!(t.connect_as(ID, DnsMode::Automatic, vpn, Tunnel::Split, None), Some(DnsState::None));
        assert!(t.rules().is_empty());
        assert_eq!(*lock(&t.nrpt.applies), 0, "nothing to refresh");
        assert!(t.log.text().contains("the VPN sent no DNS; internal names will not resolve"));
    }

    #[test]
    fn without_a_push_the_vpn_adapters_own_dns_is_used() {
        let vpn_adapter =
            AdapterNet { servers: vec!["10.8.0.1".into()], domains: vec!["Corp.Example".into()], subnets: vec![] };
        let t =
            t_with(FakeNrpt::default(), FakeAdapters { vpn: Some(vpn_adapter), ..Default::default() }, &[Probe::Ok]);
        let vpn = VpnDns { pushed: None, pushed_full_tunnel: false, luid: Some(LUID), run: None };
        assert_eq!(t.connect_as(ID, DnsMode::Targeted, vpn, Tunnel::Split, None), Some(DnsState::Targeted));
        assert_eq!(t.rules(), [rule(0, &[".corp.example"], &["10.8.0.1"])]);
    }

    #[test]
    fn release_deletes_only_that_connections_rules() {
        let t = t(&[Probe::Ok]);
        t.connect(DnsMode::Strict, Tunnel::Split);
        t.connect_as(OTHER, DnsMode::Strict, pushed(), Tunnel::Split, None);
        assert_eq!(t.rules().len(), 2);
        assert!(with_language(AppLanguage::En, || t.m.release(ID, None, &Lines::default())));
        assert_eq!(t.rules().len(), 1);
        assert!(t.rules()[0].0.starts_with(&format!("WinVPN-{OTHER}-")));
        assert!(t.log.text().contains("the original DNS is back"));
        assert_eq!(t.m.state(ID), None);
        assert_eq!(t.check(5000), None);
        assert!(!t.m.release(ID, None, &Lines::default()), "nothing left");
    }

    #[test]
    fn reconcile_deletes_stale_rules_and_keeps_running_and_foreign_ones() {
        let nrpt = FakeNrpt::default();
        for key in [format!("WinVPN-{ID}-0"), format!("WinVPN-{ID}-1"), format!("WinVPN-{OTHER}-0"), "OpenVPN-1".into()]
        {
            lock(&nrpt.rules).insert(key.clone(), NrptRule { key, names: vec![".".into()], servers: vec![] });
        }
        let t = t_with(nrpt, FakeAdapters::default(), &[Probe::Ok]);
        assert_eq!(t.m.reconcile(&|id| id == OTHER, &Lines::default()), Ok(2));
        let keys: Vec<String> = t.rules().into_iter().map(|r| r.0).collect();
        assert_eq!(keys, ["OpenVPN-1".to_string(), format!("WinVPN-{OTHER}-0")]);
        assert_eq!(*lock(&t.nrpt.applies), 1);
        assert_eq!(t.m.reconcile(&|_| false, &Lines::default()), Ok(1));
        assert_eq!(t.m.reconcile(&|_| false, &Lines::default()), Ok(0));
        assert_eq!(*lock(&t.nrpt.applies), 2, "no refresh without a change");
    }

    #[test]
    fn a_session_of_another_sid_is_not_taken_over() {
        let t = t(&[Probe::Ok]);
        let alice = Some("S-1-5-21-1-2-3-1001");
        assert_eq!(t.connect_as(ID, DnsMode::Strict, pushed(), Tunnel::Split, alice), Some(DnsState::Vpn));
        let bob = Some("S-1-5-21-1-2-3-1002");
        assert_eq!(t.connect_as(ID, DnsMode::Targeted, pushed(), Tunnel::Split, bob), None);
        assert_eq!(t.connect_as(ID, DnsMode::Targeted, pushed(), Tunnel::Split, None), None, "nor an engine's up");
        assert!(!t.m.release(ID, None, &Lines::default()), "nor its down");
        assert!(!t.m.release(ID, bob, &Lines::default()));
        assert_eq!(t.rules(), [rule(0, &["."], &["10.99.0.53"])]);
        assert_eq!(t.m.owner(ID), Some(alice.map(str::to_string)));
        assert_eq!(t.m.counts("S-1-5-21-1-2-3-1001"), (1, 1));
        t.m.release_owned_by("S-1-5-21-1-2-3-1001", &Lines::default());
        assert!(t.rules().is_empty());
    }

    #[test]
    fn a_check_soon_after_another_does_not_probe_again() {
        let t = t(&[Probe::Ok]);
        t.connect(DnsMode::Automatic, Tunnel::Split);
        assert_eq!(t.check(1000 + MIN_CHECK_SECS - 1), Some(DnsState::Vpn));
        assert_eq!(t.runs(), 1, "only the connect's probe");
        t.check(1000 + MIN_CHECK_SECS);
        assert_eq!(t.runs(), 2);
    }

    #[test]
    fn a_release_during_the_probe_leaves_no_rule() {
        let t = t(&[Probe::Ok]);
        let m = Arc::downgrade(&t.m);
        let _ = t.probes.during.set(Box::new(move || {
            if let Some(m) = m.upgrade() {
                m.release(ID, None, &Lines::default());
            }
        }));
        assert_eq!(t.connect(DnsMode::Automatic, Tunnel::Split), None);
        assert!(t.rules().is_empty());
        assert_eq!(t.m.state(ID), None);
    }

    #[test]
    fn a_refused_policy_refresh_is_logged_and_the_rules_stay() {
        let nrpt = FakeNrpt { fail_apply: true, ..FakeNrpt::default() };
        let t = t_with(nrpt, FakeAdapters::default(), &[Probe::Ok]);
        assert_eq!(t.connect(DnsMode::Strict, Tunnel::Split), Some(DnsState::Vpn));
        assert_eq!(t.rules().len(), 1);
        assert!(t.log.text().contains("Windows applies the DNS rules at its next policy refresh (Dnscache refused)"));
    }

    #[test]
    fn a_failed_write_is_retried_by_the_next_check() {
        let nrpt = FakeNrpt::default();
        nrpt.fail_write.store(true, Ordering::SeqCst);
        let t = t_with(nrpt, FakeAdapters::default(), &[Probe::Ok]);
        assert_eq!(t.connect(DnsMode::Targeted, Tunnel::Split), Some(DnsState::None));
        assert!(t.log.text().contains("DNS could not be changed: access denied"));
        assert_eq!(t.m.state(ID), None);
        t.nrpt.fail_write.store(false, Ordering::SeqCst);
        assert_eq!(t.check(1001), Some(DnsState::Targeted));
        assert_eq!(t.rules(), [rule(0, &[".lab.test"], &["10.99.0.53"])]);
    }

    #[test]
    fn a_new_local_network_rewrites_the_local_rule_at_the_next_check() {
        let t = t(&[Probe::Ok]);
        t.connect(DnsMode::Automatic, Tunnel::Split);
        t.check(2000);
        assert_eq!(*lock(&t.nrpt.writes), 1, "the same network: nothing written");
        *lock(&t.adapters.physical) = Some(AdapterNet {
            servers: vec!["10.20.0.1".into()],
            domains: vec!["office.example".into()],
            subnets: vec![IpPrefix::parse("10.20.0.0/16").unwrap()],
        });
        t.check(3000);
        assert_eq!(*lock(&t.nrpt.writes), 2);
        assert_eq!(t.rules()[1], rule(1, &[".office.example", ".20.10.in-addr.arpa"], &["10.20.0.1"]));
    }

    #[test]
    fn rule_ids_are_read_only_from_the_services_keys() {
        assert_eq!(rule_key(&format!("WinVPN-{ID}-12")), Some((ID, 12)));
        assert_eq!(rule_key("WinVPN-x"), None);
        assert_eq!(rule_key("WinVPN--0"), None);
        assert_eq!(rule_key(&format!("WinVPN-{ID}-a")), None);
        assert_eq!(rule_key(&format!("WinVPN-{ID}-+1")), None);
        assert_eq!(rule_key("OpenVPN-1-0"), None);
    }

    #[test]
    fn link_local_and_site_local_servers_are_not_usable() {
        for bad in ["fe80::1", "fec0:0:0:ffff::1", "169.254.1.1", "0.0.0.0", "::"] {
            assert!(!usable_server(&bad.parse().unwrap()), "{bad}");
        }
        for good in ["192.168.1.1", "fd00::53", "2001:db8::1"] {
            assert!(usable_server(&good.parse().unwrap()), "{good}");
        }
    }

    #[test]
    fn the_tunnel_comes_from_the_config_else_from_the_push() {
        assert_eq!(tunnel_of(VPNKind::Openvpn, "client\n", true), Tunnel::Full);
        assert_eq!(tunnel_of(VPNKind::Openvpn, "client\n", false), Tunnel::Split);
        assert_eq!(tunnel_of(VPNKind::Openvpn, "client\nroute-nopull\n", true), Tunnel::Split);
        assert_eq!(tunnel_of(VPNKind::Openvpn, "client\nredirect-gateway def1\n", false), Tunnel::Full);
        let wg = |allowed: &str| format!("[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nAllowedIPs = {allowed}\n");
        assert_eq!(tunnel_of(VPNKind::Wireguard, &wg("0.0.0.0/0"), false), Tunnel::Full);
        assert_eq!(tunnel_of(VPNKind::Wireguard, &wg("10.0.0.0/8"), true), Tunnel::Split);
    }

    #[test]
    fn wireguards_dns_comes_from_its_plan() {
        let plan = crate::windows::wg_plan::parse(
            "[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.0.0.2/32\nDNS = 10.0.0.53, Lab.Test\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 10.0.0.0/8\nEndpoint = 192.0.2.1:51820\n",
        )
        .unwrap();
        let p = wireguard_pushed(&plan);
        assert_eq!(p.servers, ["10.0.0.53"]);
        assert_eq!(p.search, ["lab.test"]);
        assert_eq!(p.routes, [IpPrefix::parse("10.0.0.0/8").unwrap()]);
    }

    #[test]
    fn an_engines_session_is_not_taken_over_by_dns_apply_and_admit_can_refuse() {
        let t = t(&[Probe::Ok]);
        t.connect(DnsMode::Strict, Tunnel::Split);
        assert_eq!(t.connect_as(ID, DnsMode::Targeted, pushed(), Tunnel::Split, Some("S-1")), None);
        let req = request(DnsMode::Targeted);
        let c = Connect {
            id: OTHER,
            request: &req,
            vpn: pushed(),
            tunnel: Tunnel::Split,
            owner: Some("S-1"),
            log: None,
            admit: &|| false,
            language: None,
        };
        assert_eq!(t.m.after_connect(c, 1000, &Lines::default()), None);
        assert_eq!(t.m.owner(OTHER), None);
        assert_eq!(t.rules(), [rule(0, &["."], &["10.99.0.53"])]);
    }

    #[test]
    fn a_failed_rewrite_is_retried_by_the_next_check_without_a_new_probe() {
        let t = t(&[Probe::Ok, Probe::Failed, Probe::Failed]);
        t.connect(DnsMode::Automatic, Tunnel::Split);
        assert_eq!(t.check(1300), Some(DnsState::Vpn));
        t.nrpt.fail_write.store(true, Ordering::SeqCst);
        assert_eq!(t.check(1600), Some(DnsState::Vpn), "the fallback could not be written");
        t.nrpt.fail_write.store(false, Ordering::SeqCst);
        assert_eq!(t.check(1605), Some(DnsState::Fallback), "written again within the probe interval");
        assert_eq!(t.runs(), 3);
        assert_eq!(t.rules(), [rule(0, &[".lab.test"], &["10.99.0.53"])]);
    }

    #[test]
    fn a_rewrite_writes_first_and_deletes_only_the_surplus() {
        let t = t(&[Probe::Ok, Probe::Failed, Probe::Failed]);
        t.connect(DnsMode::Automatic, Tunnel::Split);
        t.check(1300);
        lock(&t.nrpt.ops).clear();
        t.check(1600);
        assert_eq!(*lock(&t.nrpt.ops), [format!("write WinVPN-{ID}-0"), format!("delete WinVPN-{ID}-1")]);
    }

    #[test]
    fn a_return_to_the_vpn_layout_sets_the_adapters_dns_again() {
        let t = t(&[Probe::Failed, Probe::Ok]);
        assert_eq!(t.connect(DnsMode::Automatic, Tunnel::Split), Some(DnsState::Fallback));
        assert_eq!(*lock(&t.adapters.cleared), [LUID]);
        assert_eq!(t.check(1300), Some(DnsState::Vpn));
        assert_eq!(*lock(&t.adapters.set), [(LUID, vec!["10.99.0.53".to_string()], vec!["lab.test".to_string()])]);
        assert_eq!(lock(&t.adapters.cleared).len(), 1, "not cleared again");
    }

    #[test]
    fn a_restart_applies_the_new_push_and_clears_the_new_adapter_again() {
        let t = t(&[Probe::Ok]);
        t.connect(DnsMode::Targeted, Tunnel::Split);
        let mut vpn = pushed();
        if let Some(p) = vpn.pushed.as_mut() {
            p.search = vec!["other.test".into()];
        }
        assert_eq!(t.connect_as(ID, DnsMode::Targeted, vpn, Tunnel::Split, None), Some(DnsState::Targeted));
        assert_eq!(t.rules(), [rule(0, &[".other.test"], &["10.99.0.53"])]);
        assert_eq!(*lock(&t.adapters.cleared), [LUID, LUID]);
    }

    #[test]
    fn a_failed_release_is_owed_and_retried() {
        let t = t(&[Probe::Ok]);
        t.connect(DnsMode::Strict, Tunnel::Split);
        t.nrpt.fail_delete.store(true, Ordering::SeqCst);
        assert!(!t.m.release(ID, None, &Lines::default()));
        assert_eq!(t.rules().len(), 1);
        t.m.retry(&Lines::default());
        t.nrpt.fail_delete.store(false, Ordering::SeqCst);
        assert_eq!(t.check(5000), None, "no session; the retry ran");
        assert!(t.rules().is_empty());
        t.m.retry(&Lines::default());
        assert_eq!(*lock(&t.nrpt.writes), 1);
    }

    #[test]
    fn gone_ras_adapters_are_looked_at_at_most_every_30_seconds() {
        let t = t(&[Probe::Ok]);
        t.adapters.ppp_up.store(true, Ordering::SeqCst);
        let sid = Some("S-1");
        t.connect_as(ID, DnsMode::Strict, pushed(), Tunnel::Split, sid);
        t.m.release_gone("S-2", 1000, &Lines::default());
        assert_eq!(*lock(&t.adapters.ppp_asked), 0, "Bob holds nothing: no read");
        t.m.release_gone("S-1", 1000, &Lines::default());
        t.adapters.ppp_up.store(false, Ordering::SeqCst);
        t.m.release_gone("S-1", 1000 + GONE_CHECK_SECS - 1, &Lines::default());
        assert_eq!(*lock(&t.adapters.ppp_asked), 1);
        assert_eq!(t.rules().len(), 1);
        t.m.release_gone("S-1", 1000 + GONE_CHECK_SECS, &Lines::default());
        assert!(t.rules().is_empty());
    }

    #[test]
    fn an_old_runs_end_never_releases_a_new_runs_dns() {
        let t = t(&[Probe::Ok]);
        let run = |n| VpnDns { run: Some(n), ..pushed() };
        t.connect_as(ID, DnsMode::Strict, run(1), Tunnel::Split, None);
        t.connect_as(ID, DnsMode::Strict, run(2), Tunnel::Split, None);
        assert!(!t.m.release_run(ID, 1, &Lines::default()), "the end of run 1 arrives late");
        assert_eq!(t.rules(), [rule(0, &["."], &["10.99.0.53"])]);
        assert!(t.m.release_run(ID, 2, &Lines::default()));
        assert!(t.rules().is_empty());
    }

    #[test]
    fn a_restarts_lines_are_in_the_connections_language() {
        let t = t(&[Probe::Ok]);
        let req = request(DnsMode::Strict);
        let log: Arc<dyn LogSink> = t.log.clone();
        let c = Connect {
            id: ID,
            request: &req,
            vpn: pushed(),
            tunnel: Tunnel::Split,
            owner: None,
            log: Some(log),
            admit: &|| true,
            language: Some(AppLanguage::Hu),
        };
        with_language(AppLanguage::En, || t.m.after_connect(c, 1000, &Lines::default()));
        let text = t.log.text();
        assert!(text.contains("DNS-mód: strict"), "{text}");
    }
}
