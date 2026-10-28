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

use crate::connection_notices::Notice;
use crate::failure_reason::{FailureKind, plain};
use macvpn_core::date::Date;
use macvpn_core::netaddr::IpPrefix;
use macvpn_core::vpn_networks::VpnNetworks;
use macvpn_platform_api::{NetworkSnapshot, PreferenceStore};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use uuid::Uuid;

/// The preference: the connections switched off (sorted UUIDs, comma-separated). Default on.
pub const OFF_KEY: &str = "autoReconnectOff";

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
    prefs.string(OFF_KEY).unwrap_or_default().split(',').filter(|s| !s.is_empty()).map(str::to_string).collect()
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Connect it (the app marks the connect as the planner's: `connect_started(…, true)`, a "reconnected" notice).
    Connect(String),
    /// A surviving tunnel on its own network: the app disconnects it (`DisconnectCause::User`).
    Disconnect(String),
    /// No network for [`OFFLINE_GRACE`]: the app disconnects it (`DisconnectCause::NoNetwork`, not the user's: it
    /// may be reconnected when the network is back).
    DisconnectNoNetwork(String),
    Notify(Notice),
}

#[derive(Debug, Clone)]
struct Candidate {
    name: String,
    attempts: usize,
    /// `None`: waits for a network change.
    next: Option<Date>,
    attempting: bool,
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
        match fp {
            Some(fp) => self.fingerprints.insert(key.to_string(), fp),
            None => self.fingerprints.remove(key),
        };
    }

    /// Connected: its networks (config + pushed) for the next decision; any candidate is done.
    pub fn connected(&mut self, key: &str, networks: VpnNetworks) {
        self.networks.insert(key.to_string(), networks);
        self.candidates.remove(key);
    }

    /// The user disconnected it (also quitting with "Disconnect and Quit", a cancelled sign-in of our attempt, or a
    /// surviving tunnel on its own network): never reconnected until the user connects it again. A lease end
    /// (`DisconnectCause::Lease`) does not come here; a connection a lease started is never reconnected anyway.
    pub fn user_disconnected(&mut self, key: &str) {
        self.user_off.insert(key.to_string());
        self.candidates.remove(key);
        self.offline.remove(key);
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
    }

    /// The system is about to sleep: `connected` are the connected keys; `fp` the physical network now (it
    /// replaces theirs when known).
    pub fn sleep(&mut self, connected: &[String], fp: Option<Fingerprint>) {
        self.slept = true;
        self.asleep = true;
        self.offline.clear();
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
        // A wake without a sleep announcement: the outage timers restart (the clock jumped over the sleep).
        for o in self.offline.values_mut() {
            o.since = now;
        }
        self.check_first = None;
        self.check_at = Some(now.adding(SETTLE));
        self.survivors_pending = true;
        self.survivors_at = Some(now.adding(SETTLE));
        for c in self.candidates.values_mut() {
            c.next = Some(later(now.adding(SETTLE), c.next));
        }
    }

    /// The physical network changed (a gateway or address came or went).
    pub fn network_changed(&mut self, now: Date) {
        self.changed_at = Some(now);
        let in_window = self.woke_at.is_some_and(|w| now.time_interval_since(w) <= WAKE_WINDOW);
        if self.survivors_pending && in_window {
            self.survivors_at = Some(now.adding(SETTLE));
        }
        for c in self.candidates.values_mut().filter(|c| !c.attempting) {
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
    /// started is not a candidate: the drop ended its leases (the control API's rule), so nothing brings it back.
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
        if after_wake || network {
            self.candidates.insert(
                key.to_string(),
                Candidate { name: name.to_string(), attempts: 0, next: Some(now.adding(SETTLE)), attempting: false },
            );
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
        vec![Action::Notify(Notice::ReconnectFailed { key: key.to_string(), name: c.name, reason: plain(kind) })]
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
        self.candidates.values().any(|c| !c.attempting && reached(now, c.next))
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
        let mut due: Vec<String> = self
            .candidates
            .iter()
            .filter(|(_, c)| !c.attempting && reached(now, c.next))
            .map(|(k, _)| k.clone())
            .collect();
        due.sort();
        let mut actions = Vec::new();
        let empty = VpnNetworks::default();
        for key in due {
            if !enabled(&key) {
                self.candidates.remove(&key);
                continue;
            }
            let decision = if locked && self.network_down {
                Decision::Wait
            } else if locked {
                Decision::Skip(Skip::VaultLocked)
            } else {
                decide(self.fingerprints.get(&key), snapshot, self.networks.get(&key).unwrap_or(&empty))
            };
            let Some(c) = self.candidates.get_mut(&key) else { continue };
            match decision {
                Decision::Reconnect => {
                    c.attempts += 1;
                    c.attempting = true;
                    actions.push(Action::Connect(key));
                }
                Decision::Wait => c.next = None,
                Decision::Skip(why) => {
                    let name = c.name.clone();
                    self.candidates.remove(&key);
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
            return Vec::new();
        }
        self.network_down = false;
        // Candidates that waited for the network (one disconnected after the grace just before this check).
        for c in self.candidates.values_mut().filter(|c| !c.attempting && c.next.is_none()) {
            c.next = Some(now);
        }
        let mut back: Vec<String> = self.offline.drain().map(|(k, _)| k).collect();
        back.sort();
        let mut actions = Vec::new();
        let empty = VpnNetworks::default();
        for key in back {
            if let Some(why) = surviving_check(snapshot, self.networks.get(&key).unwrap_or(&empty)) {
                self.user_off.insert(key.clone());
                self.candidates.remove(&key);
                actions.push(Action::Disconnect(key.clone()));
                actions.push(Action::Notify(Notice::DisconnectedHere { key, why }));
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
            let reconnects = enabled(&key) && !self.leased.contains(&key) && !self.user_off.contains(&key);
            if reconnects {
                let c = self.candidates.entry(key.clone()).or_insert_with(|| Candidate {
                    name: o.name.clone(),
                    attempts: 0,
                    next: None,
                    attempting: false,
                });
                c.attempting = false;
                c.next = None;
            } else {
                self.candidates.remove(&key);
            }
            actions.push(Action::DisconnectNoNetwork(key.clone()));
            actions.push(Action::Notify(Notice::DisconnectedNoNetwork { key, name: o.name, reconnects }));
        }
        actions
    }
}
