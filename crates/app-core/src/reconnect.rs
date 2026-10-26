//! Automatic reconnect after sleep and network loss (maintainer decision 4, 2026-10-24): the pure decision, the
//! per-connection opt-out and (below) the planner. A connection reconnects only on the physical network it started
//! on (gateway IP + MAC, the SSID when both sides know it) and only when none of its routed networks or DNS servers
//! is directly connected there. Everything fails closed: an unidentified network is not reconnected.

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Connect it (the app marks the connect as the planner's: `connect_started(…, true)`, a "reconnected" notice).
    Connect(String),
    /// A surviving tunnel on its own network: the app disconnects it (`DisconnectCause::User`).
    Disconnect(String),
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
    /// The connection left `disconnected`/`failed` for `connecting`; `fp` is the physical network now.
    /// `by_planner`: our own attempt (nothing changes then). A user's connect cancels a candidate and arms the
    /// connection again after a user disconnect.
    pub fn connect_started(&mut self, key: &str, fp: Option<Fingerprint>, by_planner: bool) {
        if by_planner {
            return;
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

    /// The user (or a lease end, or quitting) disconnected it: never reconnected until the user connects it again.
    pub fn user_disconnected(&mut self, key: &str) {
        self.user_off.insert(key.to_string());
        self.candidates.remove(key);
    }

    /// A deleted connection.
    pub fn forget(&mut self, key: &str) {
        self.fingerprints.remove(key);
        self.networks.remove(key);
        self.user_off.remove(key);
        self.up_at_sleep.remove(key);
        self.candidates.remove(key);
    }

    /// The system is about to sleep: `connected` are the connected keys; `fp` the physical network now (it
    /// replaces theirs when known).
    pub fn sleep(&mut self, connected: &[String], fp: Option<Fingerprint>) {
        self.slept = true;
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
        self.woke_at = Some(now);
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
    }

    /// A connected connection was found down (`ConnectionEvent::Dropped`), with its log's category.
    pub fn dropped(&mut self, key: &str, name: &str, now: Date, kind: FailureKind) {
        if self.user_off.contains(key) || !kind.worth_retrying() || self.candidates.contains_key(key) {
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
}
