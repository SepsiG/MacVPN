//! When the app asks the root layer to probe a connection's DNS again (`dns-check`, macOS root layer 15): about
//! every [`DNS_CHECK_INTERVAL`] while connected, and [`DNS_SWITCH_DELAY`] after a live network switch, for the
//! connections whose DNS state probes (the VPN's DNS in effect, the fallback, a failing VPN DNS). Never for the
//! Targeted mode, a connection without VPN DNS or an unknown state (an older root layer), and never while asleep or
//! offline (the caller passes the reconnect planner's gate). The schedule rides on the reconnect loop's existing
//! wake-ups (the liveness poll): no timer of its own, at most one check in flight per connection. Pure.

use macvpn_core::status::DnsState;
use std::collections::{HashMap, HashSet};

/// Seconds between two checks of a connection.
pub const DNS_CHECK_INTERVAL: f64 = 300.0;
/// Seconds after a live network switch before the check.
pub const DNS_SWITCH_DELAY: f64 = 15.0;

/// The states whose DNS is probed again.
pub fn probes(state: Option<DnsState>) -> bool {
    matches!(state, Some(DnsState::Vpn | DnsState::Fallback | DnsState::FallbackFullTunnel | DnsState::Failing))
}

/// One connected connection as the schedule sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Connected {
    pub key: String,
    pub state: Option<DnsState>,
    /// The last live network switch of the connection (Unix seconds), if any.
    pub switched_at: Option<f64>,
}

#[derive(Debug, Default)]
pub struct DnsSchedule {
    /// When each connection is due next (Unix seconds).
    next: HashMap<String, f64>,
    /// The switch each connection was last checked for (so one switch gives one check).
    switch_seen: HashMap<String, f64>,
    in_flight: HashSet<String>,
}

impl DnsSchedule {
    /// The connections to check now; they are in flight until [`Self::done`]. `allowed`: the planner's gate (awake,
    /// online, no pending network check). A connection seen for the first time is due an interval later (its probe
    /// just ran at connect). Connections no longer listed are forgotten.
    pub fn due(&mut self, now: f64, allowed: bool, connected: &[Connected]) -> Vec<String> {
        let keys: HashSet<&str> = connected.iter().map(|c| c.key.as_str()).collect();
        self.next.retain(|k, _| keys.contains(k.as_str()));
        self.switch_seen.retain(|k, _| keys.contains(k.as_str()));
        self.in_flight.retain(|k| keys.contains(k.as_str()));
        let mut out = Vec::new();
        for c in connected {
            let next = *self.next.entry(c.key.clone()).or_insert(now + DNS_CHECK_INTERVAL);
            if !allowed || !probes(c.state) || self.in_flight.contains(&c.key) {
                continue;
            }
            let switch = c.switched_at.filter(|at| self.switch_seen.get(&c.key) != Some(at));
            let switch_due = switch.is_some_and(|at| now >= at + DNS_SWITCH_DELAY);
            if now >= next || switch_due {
                if let Some(at) = switch.filter(|_| switch_due) {
                    self.switch_seen.insert(c.key.clone(), at);
                }
                self.in_flight.insert(c.key.clone());
                out.push(c.key.clone());
            }
        }
        out
    }

    /// The check of `key` answered (or failed): the next one an interval later.
    pub fn done(&mut self, key: &str, now: f64) {
        self.in_flight.remove(key);
        self.next.insert(key.to_string(), now + DNS_CHECK_INTERVAL);
    }
}
