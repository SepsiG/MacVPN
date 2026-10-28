//! Automatic reconnect after sleep and network loss (maintainer decision 4, 2026-10-24): the pure decision, the
//! per-connection opt-out and (below) the planner. A connection reconnects only on the physical network it started
//! on (gateway IP + MAC, the SSID when both sides know it) and only when none of its routed networks or DNS servers
//! is directly connected there. Everything fails closed: an unidentified network is not reconnected.
//!
//! Network loss under a running tunnel (maintainer report, 2026-10-28): most engines never notice it themselves
//! (WireGuard has no connection state, OpenVPN keeps its process and interface through `ping-restart`, a strongSwan
//! SA stays `ESTABLISHED` without DPD), so the app would keep saying "connected". The planner checks the physical
//! network (debounced) after every change: without one, the connections that are up or connecting "wait for
//! network" (a view state only: the tunnel is left alone, it may survive a short outage). When the network is back,
//! a surviving tunnel is treated as after a wake ([`surviving_check`]); after [`OFFLINE_GRACE`] without a network
//! it is disconnected (so DNS and routes no longer point at a dead tunnel) and, with "Reconnect Automatically" on,
//! becomes a candidate that [`decide`] reconnects once the network is back.
//!
//! Dead tunnels (maintainer decision 2026-10-28): a tunnel can also die while the network is there (a WireGuard
//! server gone, OpenVPN stuck in its own `ping-restart`). While a network is present and nothing waits for one, the
//! planner asks the connected tunnels every [`crate::liveness::POLL`] (the driver polls the helper, the
//! [`crate::liveness::Monitor`] decides). OpenVPN restarting itself shows as reconnecting; a dead tunnel is
//! disconnected (DNS and routes restored) and, with "Reconnect Automatically" on and not a lease's, reconnected
//! through the usual candidate path, at most [`MAX_DEAD_RECONNECTS`] times before the planner gives up with a notice.
//! A live network switch (Wi-Fi A → B, Wi-Fi → cable, also back from "waiting for network" on another network)
//! moves the connection to the new network: it is checked soon and closely ([`crate::liveness::SWITCH_WINDOW`]), a
//! dead one is reconnected there, and one whose VPN network is directly reachable there is disconnected as after a
//! wake. A wake keeps its same-network rule: the switch check never counts a network change around a wake.

use crate::connection_notices::DeadOutcome;
use crate::connection_notices::Notice;
use crate::failure_reason::{FailureKind, plain};
use crate::liveness::{Health, Monitor, POLL, SWITCH_FIRST, SWITCH_POLL, SWITCH_WINDOW};
use macvpn_core::date::Date;
use macvpn_core::liveness::Liveness;
use macvpn_core::netaddr::IpPrefix;
use macvpn_core::vpn_networks::VpnNetworks;
use macvpn_platform_api::{NetworkSnapshot, PreferenceStore};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use uuid::Uuid;

/// The preference: the connections switched off (sorted UUIDs, comma-separated). Default on.
pub const OFF_KEY: &str = "autoReconnectOff";

/// The preference: the connections a lease started that are still up (sorted UUIDs, comma-separated), so that
/// after a relaunch ("Quit, Keep Them Running" leaves them up without their leases) they still count as the leases'
/// and are never reconnected. A mark goes when the connection goes down or the user connects it.
pub const LEASED_KEY: &str = "leaseStartedConnections";

fn uuid_set(prefs: &dyn PreferenceStore, key: &str) -> BTreeSet<String> {
    prefs.string(key).unwrap_or_default().split(',').filter(|s| !s.is_empty()).map(str::to_string).collect()
}

/// The persisted lease marks (only well-formed UUIDs).
pub fn lease_marks(prefs: &dyn PreferenceStore) -> Vec<String> {
    uuid_set(prefs, LEASED_KEY)
        .into_iter()
        .filter_map(|k| macvpn_core::models::parse_uuid(&k).map(|u| macvpn_core::models::uuid_string(&u)))
        .collect()
}

/// Sets or clears the lease mark of `key` (a connection's UUID string; anything else is ignored).
pub fn set_lease_mark(prefs: &dyn PreferenceStore, key: &str, on: bool) {
    let Some(id) = macvpn_core::models::parse_uuid(key).map(|u| macvpn_core::models::uuid_string(&u)) else { return };
    let mut set = uuid_set(prefs, LEASED_KEY);
    let changed = if on { set.insert(id) } else { set.remove(&id) };
    if changed {
        prefs.set_string(LEASED_KEY, &set.into_iter().collect::<Vec<_>>().join(","));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    pub gateway: IpAddr,
    pub gateway_mac: [u8; 6],
    pub ssid: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    DifferentNetwork,
    Unidentified,
    DirectlyReachable(IpPrefix),
    DnsDirectlyReachable(IpAddr),
    VaultLocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Reconnect,
    /// No network yet: evaluate again on the next change.
    Wait,
    Skip(Skip),
}

/// `None` without a gateway MAC (it cannot identify the network).
pub fn fingerprint(s: &NetworkSnapshot) -> Option<Fingerprint> {
    let g = s.gateway.as_ref()?;
    Some(Fingerprint { gateway: g.ip, gateway_mac: g.mac?, ssid: g.ssid.clone() })
}

pub fn decide(before: Option<&Fingerprint>, now: &NetworkSnapshot, networks: &VpnNetworks) -> Decision {
    if !now.has_network() {
        return Decision::Wait;
    }
    // The VPN's own network reachable here (e.g. at the office) is the more telling reason, also on a new router.
    if let Some(skip) = surviving_check(now, networks) {
        return Decision::Skip(skip);
    }
    let (Some(before), Some(current)) = (before, fingerprint(now)) else {
        return Decision::Skip(Skip::Unidentified);
    };
    let ssid_differs = matches!((&before.ssid, &current.ssid), (Some(a), Some(b)) if a != b);
    if before.gateway != current.gateway || before.gateway_mac != current.gateway_mac || ssid_differs {
        return Decision::Skip(Skip::DifferentNetwork);
    }
    Decision::Reconnect
}

/// A tunnel that survived the sleep (still connected after wake): `Some` when the VPN's network or DNS server is
/// directly reachable on the physical network now (it must be disconnected). The fingerprint does not matter: on
/// any other network the tunnel stays. No network → `None`.
pub fn surviving_check(now: &NetworkSnapshot, networks: &VpnNetworks) -> Option<Skip> {
    if !now.has_network() {
        return None;
    }
    if let Some(p) =
        networks.prefixes.iter().filter(|p| !p.is_default_route()).find(|p| now.connected.iter().any(|c| c.overlaps(p)))
    {
        return Some(Skip::DirectlyReachable(*p));
    }
    networks
        .dns
        .iter()
        .find(|ip| now.connected.iter().any(|c| c.contains(ip)))
        .map(|ip| Skip::DnsDirectlyReachable(*ip))
}

fn off_set(prefs: &dyn PreferenceStore) -> BTreeSet<String> {
    uuid_set(prefs, OFF_KEY)
}

pub fn is_enabled(prefs: &dyn PreferenceStore, id: &Uuid) -> bool {
    !off_set(prefs).contains(&macvpn_core::models::uuid_string(id))
}

pub fn set_enabled(prefs: &dyn PreferenceStore, id: &Uuid, on: bool) {
    let mut set = off_set(prefs);
    let key = macvpn_core::models::uuid_string(id);
    if on {
        set.remove(&key);
    } else {
        set.insert(key);
    }
    prefs.set_string(OFF_KEY, &set.into_iter().collect::<Vec<_>>().join(","));
}

// The planner: which connections are candidates, when they are evaluated, the attempts and the notices, and the
// once-per-wake check of tunnels that survived the sleep. No threads, no clock, no OS calls: the app (its driver
// thread) feeds it the events with their time and executes its actions.

/// Drops within this many seconds after a wake count for connections that were up before the sleep; the
/// surviving-tunnel check waits this long at most for a network after a wake.
pub const WAKE_WINDOW: f64 = 180.0;
/// Drops within this many seconds after a network change count as caused by it.
pub const NETWORK_WINDOW: f64 = 60.0;
/// Wait this long after a wake, a change or a drop before probing (DHCP, ARP).
pub const SETTLE: f64 = 3.0;
/// The delays before the second and the third attempt (after the previous attempt failed).
pub const RETRY_DELAYS: [f64; 2] = [10.0, 30.0];
/// The network is checked this long after the last change (a short Wi-Fi blip never shows) …
pub const NETWORK_DEBOUNCE: f64 = SETTLE;
/// … but at most this long after the first of a stream of changes.
pub const NETWORK_DEBOUNCE_MAX: f64 = 10.0;
/// While connections wait for network it is checked again this often (a missed change is not fatal).
pub const OFFLINE_RECHECK: f64 = 10.0;
/// A connection waiting for network this long is disconnected (the notice says "2 minutes"). Longer than OpenVPN's
/// usual `ping-restart` (60 s) and the network window, short enough that DNS does not point at a dead tunnel for long.
pub const OFFLINE_GRACE: f64 = 120.0;
/// A tunnel found dead is reconnected at most this many times (each one disconnects and connects again) …
pub const MAX_DEAD_RECONNECTS: usize = 3;
/// … until it has worked for this long since the last time it was found dead (then the count starts over).
pub const DEAD_STABLE: f64 = 600.0;
/// After the fast attempts gave up (the [`RETRY_DELAYS`] or [`MAX_DEAD_RECONNECTS`]), a connection that should be up
/// is tried again this often …
pub const SLOW_RETRY: f64 = 300.0;
/// … for this long (then one final notice).
pub const SLOW_FOR: f64 = 3600.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Connect it (the app marks the connect as the planner's: `connect_started(…, true)`, a "reconnected" notice).
    Connect(String),
    /// A surviving tunnel on its own network: the app disconnects it (`DisconnectCause::User`).
    Disconnect(String),
    /// No network for [`OFFLINE_GRACE`]: the app disconnects it (`DisconnectCause::NoNetwork`, not the user's: it
    /// may be reconnected when the network is back).
    DisconnectNoNetwork(String),
    /// A dead tunnel: the app disconnects it (`DisconnectCause::NotResponding`, not the user's), then tells the
    /// planner [`Planner::dead_down`] (a reconnect waits for that).
    DisconnectNotResponding(String),
    Notify(Notice),
}

#[derive(Debug, Clone)]
struct Candidate {
    name: String,
    attempts: usize,
    /// `None`: waits for a network change.
    next: Option<Date>,
    attempting: bool,
    /// A dead tunnel's: waits for the app's disconnect ([`Planner::dead_down`]) before it is evaluated.
    held: bool,
    /// A drop while awake (not after a wake): until then a live switch moves it to the new network, and "another
    /// network" waits while a network change is being checked (the switch may be under way).
    moves_until: Option<Date>,
}

impl Candidate {
    fn new(name: &str, next: Option<Date>) -> Candidate {
        Candidate { name: name.to_string(), attempts: 0, next, attempting: false, held: false, moves_until: None }
    }
}

/// The slow tier of a connection that should be up: since when, and the next attempt (`None`: an attempt is a
/// candidate now, or it is up again); `ended`: the hour is over, nothing more until the user acts.
#[derive(Debug, Clone)]
struct Slow {
    name: String,
    started: Date,
    next: Option<Date>,
    ended: bool,
}

/// What [`Planner::go_slow`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlowStep {
    Started,
    Continued,
    Ended,
    /// The hour ended earlier: nothing (no notice).
    Over,
}

/// How often a tunnel was found dead lately.
#[derive(Debug, Clone, Copy)]
struct Strikes {
    count: usize,
    last: Date,
}

#[derive(Debug, Default)]
pub struct Planner {
    fingerprints: HashMap<String, Fingerprint>,
    networks: HashMap<String, VpnNetworks>,
    user_off: HashSet<String>,
    /// A lease's connect is running (between [`Planner::lease_connect_began`] and [`Planner::lease_connect_ended`]).
    lease_connecting: HashSet<String>,
    /// Started by the control API under a lease: they belong to their leases and are never reconnected (a drop
    /// ends the leases, and the controlling app may be gone), until the user connects them again.
    leased: HashSet<String>,
    up_at_sleep: HashSet<String>,
    slept: bool,
    woke_at: Option<Date>,
    changed_at: Option<Date>,
    /// The last evaluation found no network.
    network_down: bool,
    candidates: HashMap<String, Candidate>,
    /// When the surviving-tunnel check of this wake is due (`None`: done, or waiting for a network change).
    survivors_at: Option<Date>,
    /// The check still has to run.
    survivors_pending: bool,
    /// The connections waiting for network: their names and since when.
    offline: HashMap<String, Offline>,
    /// When the network is checked next (debounced after a change; `None`: no check pending).
    check_at: Option<Date>,
    /// The first change of the pending check (its debounce is capped at [`NETWORK_DEBOUNCE_MAX`]).
    check_first: Option<Date>,
    /// Between a sleep announcement and the wake: the network going away is the sleep, not a loss.
    asleep: bool,
    // Dead tunnels.
    monitor: Monitor,
    /// When the connected tunnels are asked next (`None`: at the next chance).
    liveness_at: Option<Date>,
    /// OpenVPN restarting itself (the rows show "Reconnecting…").
    reconnecting: BTreeSet<String>,
    /// Found dead and disconnected (the rows show "Not responding" until the user acts or it is up again).
    not_responding: BTreeSet<String>,
    strikes: HashMap<String, Strikes>,
    /// The physical network each active connection was last seen on (a live switch is a change of it). Cleared at
    /// a wake: the network after a wake is never a switch.
    seen_on: HashMap<String, Option<Fingerprint>>,
    /// The connections that went through a live switch, and when (closer checks for [`SWITCH_WINDOW`]).
    switched: HashMap<String, Date>,
    /// The slow tier ([`SLOW_RETRY`] for [`SLOW_FOR`]).
    slow: HashMap<String, Slow>,
    /// Actions the planner decided outside a call that returns them ([`Self::dropped`]); the driver takes them.
    queued: Vec<Action>,
    /// The last physical network seen, `None` after a change until it is seen again (the overlap rule and the
    /// reconnect promise for a dead tunnel).
    last_snapshot: Option<NetworkSnapshot>,
}

#[derive(Debug, Clone)]
struct Offline {
    name: String,
    since: Date,
}

/// `b` when it is later than `a`, else `a`.
fn later(a: Date, b: Option<Date>) -> Date {
    match b {
        Some(b) if b.time_interval_since(a) > 0.0 => b,
        _ => a,
    }
}

fn reached(now: Date, at: Option<Date>) -> bool {
    at.is_some_and(|t| now.time_interval_since(t) >= 0.0)
}

impl Planner {
    /// The control API starts `key` for a lease (the app calls this before the lease's connect and
    /// [`Self::lease_connect_ended`] after it returned): a [`Self::connect_started`] in between is the lease's.
    pub fn lease_connect_began(&mut self, key: &str) {
        self.lease_connecting.insert(key.to_string());
    }

    /// The lease's connect returned (started or refused).
    pub fn lease_connect_ended(&mut self, key: &str) {
        self.lease_connecting.remove(key);
    }

    /// Connections a lease started before the app was restarted (the persisted marks, [`lease_marks`]): never
    /// reconnected, as if their leases had started them now.
    pub fn restore_leased(&mut self, keys: &[String]) {
        self.leased.extend(keys.iter().cloned());
    }

    /// A lease started `key` (the app keeps the mark while it is up).
    pub fn is_leased(&self, key: &str) -> bool {
        self.leased.contains(key)
    }

    /// The connection left `disconnected`/`failed` for `connecting`; `fp` is the physical network now.
    /// `by_planner`: our own attempt (nothing changes then). A user's connect cancels a candidate and arms the
    /// connection again after a user disconnect. A lease's connect (see [`Self::lease_connect_began`]) marks the
    /// connection as the lease's: it is never reconnected until the user connects it.
    pub fn connect_started(&mut self, key: &str, fp: Option<Fingerprint>, by_planner: bool) {
        if by_planner {
            return;
        }
        if self.lease_connecting.contains(key) {
            self.leased.insert(key.to_string());
        } else {
            self.leased.remove(key);
        }
        self.user_off.remove(key);
        self.candidates.remove(key);
        self.strikes.remove(key);
        self.slow.remove(key);
        self.not_responding.remove(key);
        self.seen_on.remove(key);
        match fp {
            Some(fp) => {
                self.seen_on.insert(key.to_string(), Some(fp.clone()));
                self.fingerprints.insert(key.to_string(), fp)
            }
            None => self.fingerprints.remove(key),
        };
    }

    /// Connected: its networks (config + pushed) for the next decision; any candidate is done.
    pub fn connected(&mut self, key: &str, networks: VpnNetworks) {
        self.networks.insert(key.to_string(), networks);
        self.candidates.remove(key);
        // Up again: no slow attempt is pending (the hour still counts until it has worked for a while).
        if let Some(s) = self.slow.get_mut(key) {
            s.next = None;
        }
        // A new session: watched from now; "Not responding" is over.
        self.monitor.forget(key);
        self.not_responding.remove(key);
    }

    /// The user disconnected it (also quitting with "Disconnect and Quit", a cancelled sign-in of our attempt, or a
    /// surviving tunnel on its own network): never reconnected until the user connects it again. A lease end
    /// (`DisconnectCause::Lease`) does not come here; a connection a lease started is never reconnected anyway.
    pub fn user_disconnected(&mut self, key: &str) {
        self.user_off.insert(key.to_string());
        self.candidates.remove(key);
        self.offline.remove(key);
        self.forget_liveness(key);
        self.strikes.remove(key);
        self.slow.remove(key);
    }

    fn forget_liveness(&mut self, key: &str) {
        self.monitor.forget(key);
        self.reconnecting.remove(key);
        self.not_responding.remove(key);
        self.switched.remove(key);
    }

    /// A deleted connection.
    pub fn forget(&mut self, key: &str) {
        self.fingerprints.remove(key);
        self.networks.remove(key);
        self.user_off.remove(key);
        self.lease_connecting.remove(key);
        self.leased.remove(key);
        self.up_at_sleep.remove(key);
        self.candidates.remove(key);
        self.offline.remove(key);
        self.forget_liveness(key);
        self.strikes.remove(key);
        self.slow.remove(key);
        self.seen_on.remove(key);
    }

    /// The system is about to sleep: `connected` are the connected keys; `fp` the physical network now (it
    /// replaces theirs when known).
    pub fn sleep(&mut self, connected: &[String], fp: Option<Fingerprint>) {
        self.slept = true;
        self.asleep = true;
        self.offline.clear();
        self.monitor.restart();
        self.reconnecting.clear();
        self.switched.clear();
        self.check_at = None;
        self.check_first = None;
        self.up_at_sleep = connected.iter().cloned().collect();
        if let Some(fp) = fp {
            for key in connected {
                self.fingerprints.insert(key.clone(), fp.clone());
            }
        }
    }

    /// The system woke. Without a sleep announcement, `connected` (the states before the first refresh) stands in.
    pub fn wake(&mut self, now: Date, connected: &[String]) {
        if !self.slept {
            self.up_at_sleep = connected.iter().cloned().collect();
        }
        self.slept = false;
        self.asleep = false;
        self.woke_at = Some(now);
        // The tunnels are watched afresh; the network after the wake is never a live switch (the wake keeps its
        // same-network rule).
        self.monitor.restart();
        self.reconnecting.clear();
        self.switched.clear();
        self.seen_on.clear();
        self.liveness_at = None;
        // A wake without a sleep announcement: the outage timers restart (the clock jumped over the sleep).
        for o in self.offline.values_mut() {
            o.since = now;
        }
        self.check_first = None;
        self.check_at = Some(now.adding(SETTLE));
        self.survivors_pending = true;
        self.survivors_at = Some(now.adding(SETTLE));
        for c in self.candidates.values_mut().filter(|c| !c.held) {
            c.next = Some(later(now.adding(SETTLE), c.next));
        }
    }

    /// The physical network changed (a gateway or address came or went).
    pub fn network_changed(&mut self, now: Date) {
        self.changed_at = Some(now);
        // The last network seen is no longer known to be current (a check with nothing active probes nothing).
        self.last_snapshot = None;
        let in_window = self.woke_at.is_some_and(|w| now.time_interval_since(w) <= WAKE_WINDOW);
        if self.survivors_pending && in_window {
            self.survivors_at = Some(now.adding(SETTLE));
        }
        for c in self.candidates.values_mut().filter(|c| !c.attempting && !c.held) {
            c.next = Some(now.adding(SETTLE));
        }
        self.check_network_soon(now);
    }

    /// Schedules the debounced network check ([`NETWORK_DEBOUNCE`] after this call, at most [`NETWORK_DEBOUNCE_MAX`]
    /// after the first call since the last check): after a change, or a connect that started without a network.
    pub fn check_network_soon(&mut self, now: Date) {
        if self.asleep {
            return;
        }
        let first = *self.check_first.get_or_insert(now);
        let capped = first.adding(NETWORK_DEBOUNCE_MAX);
        let debounced = now.adding(NETWORK_DEBOUNCE);
        self.check_at = Some(if debounced.time_interval_since(capped) > 0.0 { capped } else { debounced });
    }

    /// A connected connection was found down (`ConnectionEvent::Dropped`), with its log's category. One a lease
    /// started is not a candidate: the drop ended its leases (the control API's rule), so nothing brings it back;
    /// neither is a refused sign-in or certificate. A drop after a wake or around a network loss or change is
    /// decided by those rules; any other drop counts as a dead tunnel (at most [`MAX_DEAD_RECONNECTS`] reconnects
    /// per [`DEAD_STABLE`]).
    pub fn dropped(&mut self, key: &str, name: &str, now: Date, kind: FailureKind) {
        self.offline.remove(key);
        if self.user_off.contains(key)
            || self.leased.contains(key)
            || !kind.worth_retrying()
            || self.candidates.contains_key(key)
        {
            return;
        }
        let within = |at: Option<Date>, window: f64| at.is_some_and(|t| now.time_interval_since(t) <= window);
        let after_wake = self.up_at_sleep.contains(key) && within(self.woke_at, WAKE_WINDOW);
        let network = self.network_down || within(self.changed_at, NETWORK_WINDOW);
        // Any other drop while the network is there (the engine exited or crashed, OpenVPN's `--ping-exit`,
        // strongSwan's DPD, the server ended the session) is a tunnel that died under a connection that should be up:
        // reconnected like a dead tunnel, within the same limit ([`MAX_DEAD_RECONNECTS`] per [`DEAD_STABLE`]).
        let died = !after_wake && !network && self.strike(key, now) <= MAX_DEAD_RECONNECTS;
        if !after_wake && !network && !died {
            // Dropped again and again: the slow tier (its notice comes with the driver's next turn).
            let step = self.go_slow(key, name, now);
            if let Some(n) = slow_notice(step, key, name, None) {
                self.queued.push(Action::Notify(n));
            }
            return;
        }
        if after_wake || network || died {
            let mut c = Candidate::new(name, Some(now.adding(SETTLE)));
            // A drop while awake may be the start of a live switch (or a short outage): it moves with it.
            if !after_wake {
                c.moves_until = Some(now.adding(OFFLINE_GRACE));
            }
            self.candidates.insert(key.to_string(), c);
        }
    }

    /// The planner has the network `key` was last up on (a connection already up when the app started has none
    /// until [`Self::adopt`]).
    pub fn knows_network(&self, key: &str) -> bool {
        self.fingerprints.contains_key(key)
    }

    /// A connection found up without a connect of ours (the app started while it was up): the physical network now
    /// is the one it is up on (`None`: unknown, nothing changes). Never replaces a known one.
    pub fn adopt(&mut self, key: &str, fp: Option<Fingerprint>) {
        if let Some(fp) = fp
            && !self.fingerprints.contains_key(key)
        {
            self.seen_on.entry(key.to_string()).or_insert_with(|| Some(fp.clone()));
            self.fingerprints.insert(key.to_string(), fp);
        }
    }

    /// Our attempt failed (`ConnectionEvent::Failed` while [`Self::is_attempting`]): another attempt after
    /// [`RETRY_DELAYS`], or after the last one (or a refused sign-in or certificate) one "could not reconnect".
    pub fn failed(&mut self, key: &str, now: Date, kind: FailureKind) -> Vec<Action> {
        let Some(c) = self.candidates.get_mut(key).filter(|c| c.attempting) else { return Vec::new() };
        c.attempting = false;
        if kind.worth_retrying() && c.attempts <= RETRY_DELAYS.len() {
            c.next = Some(now.adding(RETRY_DELAYS[c.attempts - 1]));
            return Vec::new();
        }
        let Some(c) = self.candidates.remove(key) else { return Vec::new() };
        if !kind.worth_retrying() {
            self.slow.remove(key);
            return vec![Action::Notify(Notice::ReconnectFailed {
                key: key.to_string(),
                name: c.name,
                reason: plain(kind),
            })];
        }
        // The fast attempts are over: every [`SLOW_RETRY`] for [`SLOW_FOR`].
        let step = self.go_slow(key, &c.name, now);
        slow_notice(step, key, &c.name, plain(kind)).map(Action::Notify).into_iter().collect()
    }

    /// Moves `key` to the slow tier (or on within it): the next attempt in [`SLOW_RETRY`]; once [`SLOW_FOR`] has
    /// passed since it started, it ends.
    fn go_slow(&mut self, key: &str, name: &str, now: Date) -> SlowStep {
        match self.slow.get_mut(key) {
            Some(s) if s.ended => SlowStep::Over,
            Some(s) if now.time_interval_since(s.started) >= SLOW_FOR => {
                s.ended = true;
                s.next = None;
                SlowStep::Ended
            }
            Some(s) => {
                s.next = Some(now.adding(SLOW_RETRY));
                SlowStep::Continued
            }
            None => {
                let next = Some(now.adding(SLOW_RETRY));
                self.slow.insert(key.to_string(), Slow { name: name.to_string(), started: now, next, ended: false });
                SlowStep::Started
            }
        }
    }

    /// The actions decided outside a returning call (a drop that started the slow tier), for the driver.
    pub fn take_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.queued)
    }

    /// The connections in the slow tier waiting for their next attempt, sorted, with its time (the rows show
    /// "Retrying in … min").
    pub fn slow_retries(&self) -> Vec<(String, Date)> {
        let mut v: Vec<(String, Date)> = self
            .slow
            .iter()
            .filter(|(k, s)| !s.ended && !self.candidates.contains_key(*k))
            .filter_map(|(k, s)| s.next.map(|n| (k.clone(), n)))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    /// The surviving-tunnel check of this wake is due (the driver then probes and calls [`Self::survivors`]).
    pub fn survivors_due(&self, now: Date) -> bool {
        self.survivors_pending && reached(now, self.survivors_at)
    }

    /// Once per wake: the connections up before the sleep and still connected (`connected`) whose network is
    /// directly reachable now are disconnected, with a notice; the others stay. No network: wait for a change (at
    /// most [`WAKE_WINDOW`] after the wake). It runs whatever the per-connection switch says.
    pub fn survivors(&mut self, now: Date, snapshot: &NetworkSnapshot, connected: &[String]) -> Vec<Action> {
        let _ = now;
        self.survivors_at = None;
        if !snapshot.has_network() {
            return Vec::new();
        }
        self.survivors_pending = false;
        let mut actions = Vec::new();
        let empty = VpnNetworks::default();
        for key in connected.iter().filter(|k| self.up_at_sleep.contains(*k)) {
            if let Some(why) = surviving_check(snapshot, self.networks.get(key).unwrap_or(&empty)) {
                self.user_off.insert(key.clone());
                self.candidates.remove(key);
                actions.push(Action::Disconnect(key.clone()));
                actions.push(Action::Notify(Notice::DisconnectedHere { key: key.clone(), why }));
            }
        }
        actions
    }

    /// Our own connect of `key` is in flight (its `Failed` goes to [`Self::failed`]).
    pub fn is_attempting(&self, key: &str) -> bool {
        self.candidates.get(key).is_some_and(|c| c.attempting)
    }

    /// Something is due to be evaluated (the driver then probes the network and calls [`Self::evaluate`]).
    pub fn due(&self, now: Date) -> bool {
        self.candidates.values().any(|c| !c.attempting && !c.held && reached(now, c.next))
            || self.slow.iter().any(|(k, s)| !s.ended && !self.candidates.contains_key(k) && reached(now, s.next))
    }

    /// Decides every due candidate on a fresh snapshot. `enabled`: the connection's "Reconnect Automatically"
    /// switch; `locked`: the vault is locked (its secrets are needed).
    pub fn evaluate(
        &mut self,
        now: Date,
        snapshot: &NetworkSnapshot,
        enabled: &dyn Fn(&str) -> bool,
        locked: bool,
    ) -> Vec<Action> {
        self.network_down = !snapshot.has_network();
        if snapshot.has_network() {
            self.last_snapshot = Some(snapshot.clone());
        }
        // A slow attempt that is due becomes a one-shot candidate (its failure goes back to the slow tier).
        let slow_due: Vec<(String, String)> = self
            .slow
            .iter()
            .filter(|(k, s)| !s.ended && !self.candidates.contains_key(*k) && reached(now, s.next))
            .map(|(k, s)| (k.clone(), s.name.clone()))
            .collect();
        for (key, name) in slow_due {
            if let Some(s) = self.slow.get_mut(&key) {
                s.next = None;
            }
            let mut c = Candidate::new(&name, Some(now));
            c.attempts = RETRY_DELAYS.len();
            self.candidates.insert(key, c);
        }
        let mut due: Vec<String> = self
            .candidates
            .iter()
            .filter(|(_, c)| !c.attempting && !c.held && reached(now, c.next))
            .map(|(k, _)| k.clone())
            .collect();
        due.sort();
        let mut actions = Vec::new();
        let empty = VpnNetworks::default();
        for key in due {
            if !enabled(&key) {
                self.candidates.remove(&key);
                self.slow.remove(&key);
                continue;
            }
            let decision = if locked && self.network_down {
                Decision::Wait
            } else if locked {
                Decision::Skip(Skip::VaultLocked)
            } else {
                decide(self.fingerprints.get(&key), snapshot, self.networks.get(&key).unwrap_or(&empty))
            };
            let checking = self.check_first.is_some();
            let Some(c) = self.candidates.get_mut(&key) else { continue };
            // Another network while a change is still being checked: a live switch may be under way (its check moves
            // the candidate to the new network); decided again right after that check.
            let moving = c.moves_until.is_some_and(|t| now.time_interval_since(t) <= 0.0);
            if decision == Decision::Skip(Skip::DifferentNetwork) && moving && checking {
                c.next = None;
                continue;
            }
            match decision {
                Decision::Reconnect => {
                    c.attempts += 1;
                    c.attempting = true;
                    actions.push(Action::Connect(key));
                }
                Decision::Wait => c.next = None,
                // A slow attempt with the vault locked: the next one in [`SLOW_RETRY`], silently.
                Decision::Skip(Skip::VaultLocked) if self.slow.get(&key).is_some_and(|s| !s.ended) => {
                    self.candidates.remove(&key);
                    if let Some(s) = self.slow.get_mut(&key) {
                        s.next = Some(now.adding(SLOW_RETRY));
                    }
                }
                Decision::Skip(why) => {
                    let name = c.name.clone();
                    self.candidates.remove(&key);
                    // Another network, the office: the slow tier is over too.
                    self.slow.remove(&key);
                    actions.push(Action::Notify(Notice::NotReconnected { key, name, why }));
                }
            }
        }
        actions
    }

    // Network loss under a running tunnel.

    /// The network is to be checked (the driver then probes, unless nothing is active, and calls
    /// [`Self::network_checked`]).
    pub fn network_check_due(&self, now: Date) -> bool {
        !self.asleep && reached(now, self.check_at)
    }

    /// The result of a check. `snapshot`: the physical network now (`None`: it could not be read, or nothing is
    /// active so it was not probed); `active`: the managed connections up, connecting or waiting for
    /// authentication now (key, display name). Without a network they wait for it (a view state; nothing is torn
    /// down yet); with one, those that waited are back, except a tunnel whose VPN network is directly reachable here
    /// (disconnected with a notice, as after a wake).
    pub fn network_checked(
        &mut self,
        now: Date,
        snapshot: Option<&NetworkSnapshot>,
        active: &[(String, String)],
    ) -> Vec<Action> {
        self.check_at = None;
        self.check_first = None;
        self.offline.retain(|k, _| active.iter().any(|(a, _)| a == k));
        let Some(snapshot) = snapshot else {
            if !self.offline.is_empty() {
                self.check_at = Some(now.adding(OFFLINE_RECHECK));
            }
            return Vec::new();
        };
        if !snapshot.has_network() {
            self.network_down = true;
            for (key, name) in active {
                self.offline.entry(key.clone()).or_insert_with(|| Offline { name: name.clone(), since: now });
            }
            if !self.offline.is_empty() {
                self.check_at = Some(now.adding(OFFLINE_RECHECK));
            }
            // The tunnels are not asked without a network; their watch starts over when it is back.
            self.monitor.restart();
            self.reconnecting.clear();
            return Vec::new();
        }
        self.network_down = false;
        self.last_snapshot = Some(snapshot.clone());
        // Candidates that waited for the network (one disconnected after the grace just before this check).
        for c in self.candidates.values_mut().filter(|c| !c.attempting && !c.held && c.next.is_none()) {
            c.next = Some(now);
        }
        let mut back: Vec<String> = self.offline.drain().map(|(k, _)| k).collect();
        // A live switch: an active connection now on another physical network than it was last seen on. It moves
        // there (its fingerprint is the new network's, so a reconnect of it happens here).
        let fp = fingerprint(snapshot);
        // A connection that dropped while awake moves with a switch too (reconnected on the new network).
        let moving: Vec<String> = self
            .candidates
            .iter()
            .filter(|(_, c)| c.moves_until.is_some_and(|t| now.time_interval_since(t) <= 0.0))
            .map(|(k, _)| k.clone())
            .collect();
        self.seen_on.retain(|k, _| active.iter().any(|(a, _)| a == k) || moving.contains(k));
        for key in &moving {
            if let Some(before) = self.seen_on.insert(key.clone(), fp.clone())
                && before != fp
            {
                match &fp {
                    Some(f) => self.fingerprints.insert(key.clone(), f.clone()),
                    None => self.fingerprints.remove(key),
                };
            }
        }
        let mut switched = Vec::new();
        for (key, _) in active {
            if let Some(before) = self.seen_on.insert(key.clone(), fp.clone())
                && before != fp
            {
                match &fp {
                    Some(f) => self.fingerprints.insert(key.clone(), f.clone()),
                    None => self.fingerprints.remove(key),
                };
                switched.push(key.clone());
            }
        }
        back.extend(switched.iter().cloned());
        back.sort();
        back.dedup();
        let mut actions = Vec::new();
        let empty = VpnNetworks::default();
        for key in back {
            if let Some(why) = surviving_check(snapshot, self.networks.get(&key).unwrap_or(&empty)) {
                self.user_off.insert(key.clone());
                self.candidates.remove(&key);
                self.forget_liveness(&key);
                actions.push(Action::Disconnect(key.clone()));
                actions.push(Action::Notify(Notice::DisconnectedHere { key, why }));
            } else if switched.contains(&key) {
                // Checked soon and closely on the new network.
                self.monitor.switched(&key, now.time_interval_since_1970());
                self.switched.insert(key.clone(), now);
                let soon = now.adding(SWITCH_FIRST);
                self.liveness_at =
                    Some(self.liveness_at.map_or(soon, |t| if t.time_interval_since(soon) > 0.0 { soon } else { t }));
            } else {
                // Back on the same network: the watch starts over.
                self.monitor.forget(&key);
            }
        }
        actions
    }

    /// The connections waiting for network, sorted (the rows and the tray show "Waiting for network…").
    pub fn waiting_for_network(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.offline.keys().cloned().collect();
        keys.sort();
        keys
    }

    /// A connection has waited for network for [`OFFLINE_GRACE`].
    pub fn offline_due(&self, now: Date) -> bool {
        !self.asleep && self.offline.values().any(|o| now.time_interval_since(o.since) >= OFFLINE_GRACE)
    }

    /// Disconnects the connections that waited for network for [`OFFLINE_GRACE`], each with a notice. With
    /// "Reconnect Automatically" on (`enabled`), and not started by a lease, each becomes a candidate that waits for
    /// the network; [`decide`] then reconnects it on the network it started on.
    pub fn offline_expired(&mut self, now: Date, enabled: &dyn Fn(&str) -> bool) -> Vec<Action> {
        if self.asleep {
            return Vec::new();
        }
        let mut expired: Vec<String> = self
            .offline
            .iter()
            .filter(|(_, o)| now.time_interval_since(o.since) >= OFFLINE_GRACE)
            .map(|(k, _)| k.clone())
            .collect();
        expired.sort();
        let mut actions = Vec::new();
        for key in expired {
            let Some(o) = self.offline.remove(&key) else { continue };
            self.forget_liveness(&key);
            let reconnects = enabled(&key) && !self.leased.contains(&key) && !self.user_off.contains(&key);
            if reconnects {
                let c = self.candidates.entry(key.clone()).or_insert_with(|| Candidate::new(&o.name, None));
                c.attempting = false;
                c.held = false;
                c.next = None;
            } else {
                self.candidates.remove(&key);
            }
            actions.push(Action::DisconnectNoNetwork(key.clone()));
            actions.push(Action::Notify(Notice::DisconnectedNoNetwork { key, name: o.name, reconnects }));
        }
        actions
    }
    // Dead tunnels.

    /// One more time `key` was found dead (or dropped because its server stopped answering); the count since it
    /// last worked for [`DEAD_STABLE`].
    fn strike(&mut self, key: &str, now: Date) -> usize {
        let s = self.strikes.entry(key.to_string()).or_insert(Strikes { count: 0, last: now });
        if now.time_interval_since(s.last) >= DEAD_STABLE {
            s.count = 0;
        }
        s.count += 1;
        s.last = now;
        s.count
    }

    /// The connected tunnels are to be asked (the driver then polls the helper and calls [`Self::liveness_checked`]):
    /// never asleep, without a network, while a connection waits for one or while a network change is being
    /// checked (the network rules come first).
    pub fn liveness_due(&self, now: Date) -> bool {
        !self.asleep
            && !self.network_down
            && self.offline.is_empty()
            && self.check_at.is_none()
            && self.liveness_at.is_none_or(|t| reached(now, Some(t)))
    }

    /// One poll's answers: `polled` are the managed connections connected now whose engine reports liveness (key,
    /// display name, its facts; `None`: no answer, e.g. an older root layer or service: nothing is decided).
    /// `enabled`: the connection's "Reconnect Automatically". A dead tunnel is disconnected with a notice; with the
    /// switch on (not a lease's, at most [`MAX_DEAD_RECONNECTS`] times) it becomes a candidate that waits for the
    /// disconnect ([`Self::dead_down`]) and is then decided as usual: its network (where it was last up, see the
    /// live switch) and the overlap rule. A tunnel whose VPN network is directly reachable here is disconnected as
    /// after a wake instead.
    pub fn liveness_checked(
        &mut self,
        now: Date,
        polled: &[(String, String, Option<Liveness>)],
        enabled: &dyn Fn(&str) -> bool,
    ) -> Vec<Action> {
        self.switched.retain(|_, at| now.time_interval_since(*at) <= SWITCH_WINDOW);
        let closely = polled.iter().any(|(k, _, _)| self.switched.contains_key(k));
        self.liveness_at = Some(now.adding(if closely { SWITCH_POLL } else { POLL }));
        let keys: Vec<&str> = polled.iter().map(|(k, _, _)| k.as_str()).collect();
        self.monitor.retain(&keys);
        self.reconnecting.retain(|k| keys.contains(&k.as_str()));
        if self.asleep || self.network_down || !self.offline.is_empty() {
            return Vec::new();
        }
        let mut actions = Vec::new();
        let empty = VpnNetworks::default();
        for (key, name, facts) in polled {
            let Some(facts) = facts else { continue };
            // Our own reconnect is on its way.
            if self.candidates.contains_key(key) {
                continue;
            }
            match self.monitor.observe(key, now.time_interval_since_1970(), facts) {
                Health::Alive { proven } => {
                    self.reconnecting.remove(key);
                    if proven && self.strikes.get(key).is_some_and(|s| now.time_interval_since(s.last) >= DEAD_STABLE) {
                        self.strikes.remove(key);
                        self.slow.remove(key);
                    }
                }
                Health::Reconnecting => {
                    self.reconnecting.insert(key.clone());
                }
                Health::Dead => {
                    self.forget_liveness(key);
                    let here = self
                        .last_snapshot
                        .as_ref()
                        .and_then(|s| surviving_check(s, self.networks.get(key).unwrap_or(&empty)));
                    if let Some(why) = here {
                        self.user_off.insert(key.clone());
                        actions.push(Action::Disconnect(key.clone()));
                        actions.push(Action::Notify(Notice::DisconnectedHere { key: key.clone(), why }));
                        continue;
                    }
                    // Where it would not be reconnected anyway (woken on another network): no promise to.
                    let elsewhere = self.last_snapshot.as_ref().is_some_and(|s| {
                        decide(self.fingerprints.get(key), s, self.networks.get(key).unwrap_or(&empty))
                            != Decision::Reconnect
                    });
                    let wanted = enabled(key) && !self.leased.contains(key) && !elsewhere;
                    let outcome = if !wanted {
                        DeadOutcome::Disconnected
                    } else if self.strike(key, now) <= MAX_DEAD_RECONNECTS {
                        let mut c = Candidate::new(name, None);
                        c.held = true;
                        self.candidates.insert(key.clone(), c);
                        DeadOutcome::Reconnects
                    } else {
                        DeadOutcome::KeepsTrying
                    };
                    self.not_responding.insert(key.clone());
                    actions.push(Action::DisconnectNotResponding(key.clone()));
                    // Dead too often: the slow tier; one notice when it starts and one when it ends.
                    let notice = if outcome == DeadOutcome::KeepsTrying {
                        match self.go_slow(key, name, now) {
                            SlowStep::Started => {
                                Some(Notice::NotResponding { key: key.clone(), name: name.clone(), outcome })
                            }
                            step => slow_notice(step, key, name, None),
                        }
                    } else {
                        Some(Notice::NotResponding { key: key.clone(), name: name.clone(), outcome })
                    };
                    actions.extend(notice.map(Action::Notify));
                }
            }
        }
        actions
    }

    /// Ask the tunnels at the next chance (a smoke run).
    pub fn liveness_soon(&mut self) {
        self.liveness_at = None;
    }

    /// The app's disconnect of a dead tunnel returned: its reconnect (if any) is decided after [`SETTLE`].
    pub fn dead_down(&mut self, key: &str, now: Date) {
        if let Some(c) = self.candidates.get_mut(key).filter(|c| c.held) {
            c.held = false;
            c.next = Some(now.adding(SETTLE));
        }
    }

    /// OpenVPN restarting itself, sorted (the rows show "Reconnecting…", the tray the half-filled shield).
    pub fn reconnecting(&self) -> Vec<String> {
        self.reconnecting.iter().cloned().collect()
    }

    /// The tunnels found dead and disconnected, sorted (the rows show "Not responding", the tray the failure).
    pub fn not_responding(&self) -> Vec<String> {
        self.not_responding.iter().cloned().collect()
    }
}

/// The notice of a step of the slow tier: when it starts (with the last failure's reason) and when the hour is over.
fn slow_notice(step: SlowStep, key: &str, name: &str, reason: Option<String>) -> Option<Notice> {
    let (key, name) = (key.to_string(), name.to_string());
    match step {
        SlowStep::Started => Some(Notice::KeepsTrying { key, name, reason }),
        SlowStep::Ended => Some(Notice::RetriesEnded { key, name }),
        SlowStep::Continued | SlowStep::Over => None,
    }
}
