//! Dead-tunnel detection's rule (maintainer decision 2026-10-28): WireGuard by its protocol timers (an idle tunnel
//! is never dead), OpenVPN by its own restart.

use macvpn_app_core::liveness::{
    COUNTER_SILENCE, Health, Monitor, OPENVPN_RECONNECT_LIMIT, POLL, REJECT_AFTER_TIME, REKEY_ATTEMPT_TIME,
    STALE_AFTER, SWITCH_SILENCE,
};
use macvpn_core::liveness::{Liveness, WgPeer};

const T0: f64 = 1_800_000_000.0;

fn wg(handshake: f64, rx: u64, tx: u64, keepalive: u16) -> Liveness {
    Liveness::WireGuard(vec![WgPeer {
        last_handshake: (handshake > 0.0).then_some(handshake as u64),
        rx,
        tx,
        keepalive,
        endpoint: true,
    }])
}

fn alive(h: Health) -> bool {
    matches!(h, Health::Alive { .. })
}

/// Polls every [`POLL`] from `from` to `to` (inclusive) with the facts of `f(t)`; the healths in order.
fn polls(m: &mut Monitor, from: f64, to: f64, f: impl Fn(f64) -> Liveness) -> Vec<(f64, Health)> {
    let mut out = Vec::new();
    let mut t = from;
    while t <= to {
        out.push((t, m.observe("k", t, &f(t))));
        t += POLL;
    }
    out
}

fn first_dead(v: &[(f64, Health)]) -> Option<f64> {
    v.iter().find(|(_, h)| *h == Health::Dead).map(|(t, _)| *t)
}

#[test]
fn an_idle_wireguard_tunnel_without_keepalive_is_never_dead() {
    let mut m = Monitor::default();
    // The last handshake an hour ago, nothing sent or received since.
    let v = polls(&mut m, T0, T0 + 3600.0, |_| wg(T0 - 3600.0, 5000, 7000, 0));
    assert!(v.iter().all(|(_, h)| alive(*h)), "{v:?}");
    // Never a handshake at all (nothing was ever sent): not dead either.
    let mut m = Monitor::default();
    assert!(polls(&mut m, T0, T0 + 3600.0, |_| wg(0.0, 0, 0, 0)).iter().all(|(_, h)| alive(*h)));
}

#[test]
fn a_busy_wireguard_tunnel_with_regular_handshakes_is_alive() {
    let mut m = Monitor::default();
    // Traffic both ways, a new handshake every 2 minutes.
    let v = polls(&mut m, T0, T0 + 1800.0, |t| {
        let h = T0 + ((t - T0) / 120.0).floor() * 120.0;
        wg(h, (t - T0) as u64 * 100, (t - T0) as u64 * 100, 0)
    });
    assert!(v.iter().all(|(_, h)| alive(*h)), "{v:?}");
    assert_eq!(v.last().unwrap().1, Health::Alive { proven: true });
}

#[test]
fn wireguard_without_keepalive_is_dead_once_sending_gets_no_handshake() {
    let mut m = Monitor::default();
    // The server went away: the last handshake at T0, data keeps being sent, nothing comes back.
    let v = polls(&mut m, T0, T0 + 900.0, |t| wg(T0, 1000, 1000 + (t - T0) as u64 * 10, 0));
    let dead = first_dead(&v).expect("dead");
    // The session expired (180 s), the growth was seen, then WireGuard's 90 s of retries passed.
    assert!(dead - T0 > REJECT_AFTER_TIME + REKEY_ATTEMPT_TIME, "{dead}");
    assert!(dead - T0 <= REJECT_AFTER_TIME + REKEY_ATTEMPT_TIME + 3.0 * POLL, "{dead}");
}

#[test]
fn wireguard_without_keepalive_that_sent_before_going_idle_is_not_dead() {
    let mut m = Monitor::default();
    // Data sent right after the handshake, then idle for an hour: "tx grew since the handshake", but not since the
    // session expired.
    let v = polls(&mut m, T0, T0 + 3600.0, |t| wg(T0, 500, if t < T0 + 60.0 { 100 } else { 900 }, 0));
    assert!(v.iter().all(|(_, h)| alive(*h)), "{v:?}");
}

#[test]
fn a_new_handshake_or_received_data_clears_the_suspicion() {
    let mut m = Monitor::default();
    // Expired, then sending: the handshake succeeds 60 s after the growth.
    let v = polls(&mut m, T0, T0 + 900.0, |t| {
        let tx = if t >= T0 + 240.0 { 5000 } else { 1000 };
        let h = if t >= T0 + 300.0 { T0 + 290.0 } else { T0 };
        wg(h, 1000, tx, 0)
    });
    assert_eq!(first_dead(&v), None, "{v:?}");
    // Received bytes are proof of life too.
    let mut m = Monitor::default();
    let v = polls(&mut m, T0, T0 + 900.0, |t| wg(T0, 1000 + (t - T0) as u64, 1000 + (t - T0) as u64, 0));
    assert_eq!(first_dead(&v), None, "{v:?}");
}

#[test]
fn wireguard_with_keepalive_is_dead_when_the_handshake_is_stale() {
    let mut m = Monitor::default();
    let v = polls(&mut m, T0, T0 + 600.0, |t| wg(T0, 1000, 1000 + (t - T0) as u64, 25));
    let dead = first_dead(&v).expect("dead");
    assert!(dead - T0 > STALE_AFTER && dead - T0 <= STALE_AFTER + POLL, "{dead}");
    // Never a handshake since the connect: counted from the start of the watch.
    let mut m = Monitor::default();
    let v = polls(&mut m, T0, T0 + 600.0, |_| wg(0.0, 0, 148, 25));
    let dead = first_dead(&v).expect("dead");
    assert!(dead - T0 > STALE_AFTER && dead - T0 <= STALE_AFTER + POLL, "{dead}");
    // Regular handshakes: alive.
    let mut m = Monitor::default();
    let v = polls(&mut m, T0, T0 + 1800.0, |t| wg(T0 + ((t - T0) / 120.0).floor() * 120.0, 100, 100, 25));
    assert_eq!(first_dead(&v), None);
}

#[test]
fn an_old_handshake_counts_from_the_start_of_the_watch() {
    // After a wake (the watch restarts) the handshake from before the sleep is an hour old: WireGuard gets its
    // usual time to renew it.
    let mut m = Monitor::default();
    m.observe("k", T0 - 600.0, &wg(T0 - 3600.0, 1, 1, 25));
    m.restart();
    let v = polls(&mut m, T0, T0 + 600.0, |_| wg(T0 - 3600.0, 1, 1, 25));
    let dead = first_dead(&v).expect("dead");
    assert!(dead - T0 > STALE_AFTER, "{dead}");
    assert!(alive(v[0].1));
}

#[test]
fn one_live_peer_keeps_the_tunnel_and_peers_without_an_endpoint_do_not_count() {
    let dead_peer = WgPeer { last_handshake: Some(T0 as u64), rx: 1, tx: 1, keepalive: 25, endpoint: true };
    let mut m = Monitor::default();
    let v = polls(&mut m, T0, T0 + 900.0, |t| {
        let live = WgPeer { last_handshake: Some((t - 10.0) as u64), ..dead_peer };
        Liveness::WireGuard(vec![dead_peer, live])
    });
    assert_eq!(first_dead(&v), None);
    // A peer without an endpoint (it cannot start a handshake from here) is not watched.
    let roaming = WgPeer { endpoint: false, keepalive: 0, ..dead_peer };
    let mut m = Monitor::default();
    let v = polls(&mut m, T0, T0 + 900.0, |_| Liveness::WireGuard(vec![roaming]));
    assert_eq!(first_dead(&v), None);
    let mut m = Monitor::default();
    let v = polls(&mut m, T0, T0 + 900.0, |_| Liveness::WireGuard(vec![dead_peer, roaming]));
    assert!(first_dead(&v).is_some());
    let mut m = Monitor::default();
    assert!(alive(m.observe("k", T0, &Liveness::WireGuard(vec![]))));
}

#[test]
fn openvpn_restarting_itself_is_reconnecting_then_dead_after_the_limit() {
    let mut m = Monitor::default();
    assert_eq!(m.observe("k", T0, &Liveness::OpenVpn { reconnecting_since: None }), Health::Alive { proven: true });
    let r = Liveness::OpenVpn { reconnecting_since: Some(T0 as u64 + 10) };
    assert_eq!(m.observe("k", T0 + 30.0, &r), Health::Reconnecting);
    assert_eq!(m.observe("k", T0 + 10.0 + OPENVPN_RECONNECT_LIMIT - 1.0, &r), Health::Reconnecting);
    assert_eq!(m.observe("k", T0 + 10.0 + OPENVPN_RECONNECT_LIMIT, &r), Health::Dead);
    // Back up in time: alive.
    assert_eq!(
        m.observe("k", T0 + 200.0, &Liveness::OpenVpn { reconnecting_since: None }),
        Health::Alive { proven: true }
    );
    // A restart that began before the watch (a sleep in between) counts from the watch.
    let mut m = Monitor::default();
    let old = Liveness::OpenVpn { reconnecting_since: Some(T0 as u64 - 3600) };
    assert_eq!(m.observe("k", T0, &old), Health::Reconnecting);
    assert_eq!(m.observe("k", T0 + OPENVPN_RECONNECT_LIMIT, &old), Health::Dead);
}

#[test]
fn forget_and_retain_drop_the_watch() {
    let mut m = Monitor::default();
    let r = Liveness::OpenVpn { reconnecting_since: Some(T0 as u64 - 3600) };
    m.observe("k", T0, &r);
    m.observe("j", T0, &r);
    m.forget("k");
    m.retain(&["x"]);
    assert_eq!(m.observe("k", T0 + 100.0, &r), Health::Reconnecting);
    assert_eq!(m.observe("j", T0 + 100.0, &r), Health::Reconnecting);
}

fn c(rx: u64, tx: u64) -> Liveness {
    Liveness::Counters { rx, tx, keepalive: 0 }
}

#[test]
fn sending_without_receiving_for_the_silence_is_dead() {
    let mut m = Monitor::default();
    assert_eq!(m.observe("k", 0.0, &c(100, 100)), Health::Alive { proven: false });
    assert_eq!(m.observe("k", 30.0, &c(100, 400)), Health::Alive { proven: false }, "grew: the clock starts");
    assert_eq!(m.observe("k", 30.0 + COUNTER_SILENCE - 1.0, &c(100, 900)), Health::Alive { proven: false });
    assert_eq!(m.observe("k", 30.0 + COUNTER_SILENCE, &c(100, 950)), Health::Dead);
}

#[test]
fn any_received_byte_resets_and_proves_life() {
    let mut m = Monitor::default();
    m.observe("k", 0.0, &c(100, 100));
    m.observe("k", 30.0, &c(100, 400));
    assert_eq!(m.observe("k", 150.0, &c(160, 500)), Health::Alive { proven: true });
    assert_eq!(m.observe("k", 30.0 + COUNTER_SILENCE + 10.0, &c(160, 600)), Health::Alive { proven: false });
}

#[test]
fn an_idle_tunnel_is_never_dead() {
    let mut m = Monitor::default();
    for t in 0..20 {
        assert_ne!(m.observe("k", f64::from(t) * 30.0, &c(5, 5)), Health::Dead);
    }
}

#[test]
fn after_a_switch_silence_beyond_the_keepalives_is_dead_sooner() {
    let mut m = Monitor::default();
    m.switched("k", 0.0);
    let k = |rx, tx| Liveness::Counters { rx, tx, keepalive: 10 };
    m.observe("k", 5.0, &k(0, 0));
    m.observe("k", 15.0, &k(0, 2000));
    assert_eq!(m.observe("k", 15.0 + SWITCH_SILENCE, &k(0, 2100)), Health::Dead);
}
