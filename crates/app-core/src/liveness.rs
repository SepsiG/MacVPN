//! Dead-tunnel detection (maintainer decision 2026-10-28): is a connected tunnel still alive while the physical
//! network is there? Pure: the reconnect planner feeds each poll's facts ([`macvpn_core::liveness::Liveness`], from
//! the root layer or the WinVPN Service) with the poll's time and gets a [`Health`] back. No clock, no I/O.
//!
//! **WireGuard** has no connection state, so the rule follows its protocol timers (the WireGuard paper, 6.1–6.5):
//! a session is renewed `REKEY_AFTER_TIME` (120 s) after its handshake when data is sent, its keys are refused after
//! [`REJECT_AFTER_TIME`] (180 s), and a handshake that gets no answer is retried for [`REKEY_ATTEMPT_TIME`] (90 s).
//! The age of the latest handshake alone says nothing: an idle tunnel without `PersistentKeepalive` sends nothing and
//! so legitimately has no handshake for hours. A peer (with an endpoint: only those start handshakes from here) is
//! dead when
//!
//! - it has `PersistentKeepalive`: it sends at least every few seconds, so a live server keeps the session younger
//!   than `REJECT_AFTER_TIME`; a handshake older than [`STALE_AFTER`] (180 s + one poll of margin) means none of the
//!   keepalives got through;
//! - it has none: its session expired (handshake older than `REJECT_AFTER_TIME`), then the sent bytes grew (data or
//!   a handshake initiation went out: WireGuard tries a new handshake at once), and [`REKEY_ATTEMPT_TIME`] after the
//!   growth was seen there is still no new handshake (and nothing was received). An idle tunnel sends nothing:
//!   never dead.
//!
//! The tunnel is dead when every peer with an endpoint is (one live peer keeps it). Ages count from the handshake or
//! from the start of watching, whichever is later: after a wake or a network change the watch restarts, so an old
//! handshake from before is not held against the tunnel.
//!
//! **After a live network switch** ([`Monitor::switched`]: Wi-Fi A → B, Wi-Fi → cable) a tunnel is checked
//! closely for [`SWITCH_WINDOW`]: WireGuard roams without a new handshake, but a live server answers every data
//! packet within `KEEPALIVE_TIMEOUT` (10 s), with data or its passive keepalive. So a peer is dead when, after the
//! switch, more was sent than its own `PersistentKeepalive` explains ([`KEEPALIVE_BYTES`] per keepalive) and
//! [`SWITCH_SILENCE`] after that growth was seen nothing was received and no new handshake came. Nothing is sent
//! into the tunnel to provoke an answer: a tunnel with no traffic of its own stays undecided here (the rule above
//! catches it once something is sent), and an idle dead tunnel hurts nobody. OpenVPN restarting itself after a
//! switch is dead after [`SWITCH_OPENVPN_LIMIT`].
//!
//! **OpenVPN** reports its own restart through the management interface (`>STATE:…,RECONNECTING`, e.g.
//! `ping-restart`): the tunnel is [`Health::Reconnecting`] (shown as connecting, never connected) and dead when it
//! has not come back within [`OPENVPN_RECONNECT_LIMIT`]. `--ping-exit` ends OpenVPN itself: that is a drop, handled
//! as one.

use macvpn_core::liveness::{Liveness, WgPeer};
use std::collections::HashMap;

/// How often a connected tunnel is asked (only while the physical network is there and nothing waits for it).
pub const POLL: f64 = 30.0;
/// WireGuard's `REJECT_AFTER_TIME`: a session older than this is unusable.
pub const REJECT_AFTER_TIME: f64 = 180.0;
/// WireGuard's `REKEY_ATTEMPT_TIME`: how long it retries a handshake that gets no answer.
pub const REKEY_ATTEMPT_TIME: f64 = 90.0;
/// A WireGuard peer with `PersistentKeepalive` whose latest handshake is older than this is dead
/// ([`REJECT_AFTER_TIME`] plus one [`POLL`] of margin).
pub const STALE_AFTER: f64 = REJECT_AFTER_TIME + POLL;
/// An OpenVPN tunnel restarting itself for longer than this is dead (its own `ping-restart` retries go on forever).
pub const OPENVPN_RECONNECT_LIMIT: f64 = 120.0;
/// After a live switch the first close check comes this long after the planner saw the new network (itself
/// [`crate::reconnect::NETWORK_DEBOUNCE`] after the change) …
pub const SWITCH_FIRST: f64 = 5.0;
/// … then one every this often …
pub const SWITCH_POLL: f64 = 10.0;
/// … for this long after the switch.
pub const SWITCH_WINDOW: f64 = 120.0;
/// After a switch: sent data and nothing received for this long since the growth was seen is a dead WireGuard
/// peer (a live server answers within `KEEPALIVE_TIMEOUT`, 10 s, plus the round trip).
pub const SWITCH_SILENCE: f64 = 20.0;
/// What one of our own keepalives may add to the sent bytes (a keepalive is 32 bytes on the wire; generous).
pub const KEEPALIVE_BYTES: u64 = 96;
/// After a switch, OpenVPN restarting itself for this long is dead.
pub const SWITCH_OPENVPN_LIMIT: f64 = 60.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// `proven`: there is fresh evidence of life (a WireGuard handshake since the watch began, OpenVPN up).
    Alive {
        proven: bool,
    },
    /// OpenVPN restarts the tunnel itself (shown as connecting).
    Reconnecting,
    Dead,
}

#[derive(Debug, Clone, Default)]
struct PeerTrack {
    /// The sent bytes when the session was first seen expired (`None`: not expired).
    tx_mark: Option<u64>,
    /// When the sent bytes were first seen above the mark.
    grew_at: Option<f64>,
    rx: u64,
    /// After a switch: the first close check's counters (tx, rx, handshake, time).
    sw_base: Option<(u64, u64, Option<u64>, f64)>,
    /// When the sent bytes were first seen above what the keepalives explain.
    sw_grew: Option<f64>,
    /// Answered after the switch: no more close checks.
    sw_ok: bool,
}

#[derive(Debug, Clone)]
struct Track {
    /// When this watch began (Unix seconds).
    since: f64,
    peers: Vec<PeerTrack>,
    /// A live switch at this time: the close checks of [`SWITCH_WINDOW`].
    switch: Option<f64>,
}

/// The per-connection state of the rule above.
#[derive(Debug, Default)]
pub struct Monitor {
    tracks: HashMap<String, Track>,
}

impl Monitor {
    /// One poll of `key` at `now` (Unix seconds).
    pub fn observe(&mut self, key: &str, now: f64, facts: &Liveness) -> Health {
        let track =
            self.tracks.entry(key.to_string()).or_insert_with(|| Track { since: now, peers: Vec::new(), switch: None });
        match facts {
            Liveness::OpenVpn { reconnecting_since: None } => Health::Alive { proven: true },
            Liveness::OpenVpn { reconnecting_since: Some(t) } => {
                let since = (*t as f64).max(track.since);
                let after_switch = track.switch.is_some_and(|s| since <= s + SWITCH_WINDOW);
                let limit = if after_switch { SWITCH_OPENVPN_LIMIT } else { OPENVPN_RECONNECT_LIMIT };
                if now - since >= limit { Health::Dead } else { Health::Reconnecting }
            }
            Liveness::WireGuard(peers) => wireguard(track, now, peers),
        }
    }

    /// The connection is no longer watched (down, deleted, or just found dead).
    pub fn forget(&mut self, key: &str) {
        self.tracks.remove(key);
    }

    /// `key` went through a live network switch at `at` (Unix seconds): its watch starts over, with the close
    /// checks of [`SWITCH_WINDOW`].
    pub fn switched(&mut self, key: &str, at: f64) {
        self.tracks.insert(key.to_string(), Track { since: at, peers: Vec::new(), switch: Some(at) });
    }

    /// Every watch starts over (sleep, wake, a network change or outage): ages count from the next poll.
    pub fn restart(&mut self) {
        self.tracks.clear();
    }

    /// Keeps only the watches of `keys`.
    pub fn retain(&mut self, keys: &[&str]) {
        self.tracks.retain(|k, _| keys.contains(&k.as_str()));
    }
}

fn wireguard(track: &mut Track, now: f64, peers: &[WgPeer]) -> Health {
    if track.peers.len() != peers.len() {
        track.peers = vec![PeerTrack::default(); peers.len()];
    }
    let switch_active = track.switch.is_some_and(|s| now - s <= SWITCH_WINDOW);
    let mut watched = 0;
    let mut dead = 0;
    let mut proven = false;
    for (p, t) in peers.iter().zip(track.peers.iter_mut()) {
        let received = p.rx > t.rx;
        t.rx = p.rx;
        let fresh_handshake = p.last_handshake.is_some_and(|h| h as f64 >= track.since);
        proven |= fresh_handshake;
        if !p.endpoint {
            continue;
        }
        watched += 1;
        if switch_active && !t.sw_ok && switch_dead(t, p, now) {
            dead += 1;
            continue;
        }
        proven |= t.sw_ok;
        let age = now - p.last_handshake.map_or(track.since, |h| (h as f64).max(track.since));
        if age <= REJECT_AFTER_TIME || received {
            t.tx_mark = None;
            t.grew_at = None;
            continue;
        }
        if p.keepalive > 0 {
            if age > STALE_AFTER {
                dead += 1;
            }
            continue;
        }
        match t.tx_mark {
            None => t.tx_mark = Some(p.tx),
            Some(mark) if p.tx > mark => {
                let grew_at = *t.grew_at.get_or_insert(now);
                if now - grew_at >= REKEY_ATTEMPT_TIME {
                    dead += 1;
                }
            }
            Some(_) => {}
        }
    }
    if watched > 0 && dead == watched { Health::Dead } else { Health::Alive { proven } }
}

/// The close check after a switch (see the module docs); `true`: dead. Marks the peer answered once it is.
fn switch_dead(t: &mut PeerTrack, p: &WgPeer, now: f64) -> bool {
    let Some((tx0, rx0, hs0, t0)) = t.sw_base else {
        t.sw_base = Some((p.tx, p.rx, p.last_handshake, now));
        return false;
    };
    if p.rx > rx0 || p.last_handshake > hs0 {
        t.sw_ok = true;
        return false;
    }
    let keepalives = if p.keepalive > 0 { ((now - t0) / f64::from(p.keepalive)).floor() as u64 + 2 } else { 0 };
    if p.tx.saturating_sub(tx0) <= keepalives * KEEPALIVE_BYTES {
        return false;
    }
    let grew = *t.sw_grew.get_or_insert(now);
    now - grew >= SWITCH_SILENCE
}
