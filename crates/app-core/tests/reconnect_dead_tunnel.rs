//! Dead-tunnel detection in the planner (maintainer decision 2026-10-28, and the live network switch amendment of the
//! same day): the connected tunnels are polled only while a network is there and nothing waits for it; OpenVPN
//! restarting itself shows as reconnecting; a dead tunnel is disconnected cleanly, reconnected with "Reconnect
//! Automatically" on (never a lease's, at most `MAX_DEAD_RECONNECTS` times), and a live switch moves the connection
//! to the new network (a dead one is reconnected there; on the VPN's own network it is disconnected).

use macvpn_app_core::connection_notices::{DeadOutcome, Notice};
use macvpn_app_core::failure_reason::FailureKind;
use macvpn_app_core::liveness::{
    OPENVPN_RECONNECT_LIMIT, POLL, STALE_AFTER, SWITCH_FIRST, SWITCH_OPENVPN_LIMIT, SWITCH_POLL, SWITCH_SILENCE,
};
use macvpn_app_core::reconnect::{
    Action, DEAD_STABLE, MAX_DEAD_RECONNECTS, NETWORK_DEBOUNCE, Planner, SETTLE, SLOW_FOR, SLOW_RETRY, Skip,
    fingerprint,
};
use macvpn_core::date::Date;
use macvpn_core::liveness::{Liveness, WgPeer};
use macvpn_core::netaddr::IpPrefix;
use macvpn_core::vpn_networks::VpnNetworks;
use macvpn_platform_api::{Gateway, NetworkSnapshot};

fn net(gw: &str, mac: [u8; 6], subnet: &str) -> NetworkSnapshot {
    NetworkSnapshot {
        gateway: Some(Gateway { ip: gw.parse().unwrap(), mac: Some(mac), interface: "en0".into(), ssid: None }),
        connected: vec![IpPrefix::parse(subnet).unwrap()],
    }
}

fn home() -> NetworkSnapshot {
    net("192.168.1.1", [0xa4, 0x2b, 0xb0, 0, 0, 1], "192.168.1.0/24")
}

fn office() -> NetworkSnapshot {
    net("10.20.30.1", [2, 0, 0, 0, 0, 7], "10.20.30.0/24")
}

fn cafe() -> NetworkSnapshot {
    net("10.0.0.1", [2, 0, 0, 0, 0, 9], "10.0.0.0/24")
}

fn t0() -> Date {
    Date::from_time_interval_since_1970(1_800_000_000.0)
}

fn at(s: f64) -> Date {
    t0().adding(s)
}

fn on(_: &str) -> bool {
    true
}

fn off(_: &str) -> bool {
    false
}

fn active() -> Vec<(String, String)> {
    vec![("k".to_string(), "Office VPN".to_string())]
}

/// A WireGuard peer with keepalive whose latest handshake was at `h` (seconds after t0).
fn wg(h: f64, rx: u64, tx: u64) -> Option<Liveness> {
    Some(Liveness::WireGuard(vec![WgPeer {
        last_handshake: Some(at(h).time_interval_since_1970() as u64),
        rx,
        tx,
        keepalive: 25,
        endpoint: true,
    }]))
}

fn polled(facts: Option<Liveness>) -> Vec<(String, String, Option<Liveness>)> {
    vec![("k".to_string(), "Office VPN".to_string(), facts)]
}

fn dead_notice(outcome: DeadOutcome) -> Action {
    Action::Notify(Notice::NotResponding { key: "k".into(), name: "Office VPN".into(), outcome })
}

/// "k" came up at home (its VPN routes the office network) and the planner has seen the home network.
fn up_at_home() -> Planner {
    let mut p = Planner::default();
    p.connect_started("k", fingerprint(&home()), false);
    p.connected(
        "k",
        VpnNetworks::from_config(macvpn_core::models::VPNKind::Openvpn, "route 10.20.30.0 255.255.255.0\n"),
    );
    p.network_changed(t0());
    assert!(p.network_checked(at(NETWORK_DEBOUNCE), Some(&home()), &active()).is_empty());
    p
}

/// Polls `facts` at `t` (when due) and returns the actions.
fn poll(p: &mut Planner, t: f64, facts: Option<Liveness>, enabled: &dyn Fn(&str) -> bool) -> Vec<Action> {
    assert!(p.liveness_due(at(t)), "due at {t}");
    p.liveness_checked(at(t), &polled(facts), enabled)
}

/// Polls a dead keepalive tunnel (handshake at 0) whenever due from `from` until it is found dead; the actions.
fn until_dead(p: &mut Planner, from: f64, enabled: &dyn Fn(&str) -> bool) -> (f64, Vec<Action>) {
    let mut t = from;
    loop {
        assert!(t < from + 3600.0, "never dead");
        if !p.liveness_due(at(t)) {
            t += 1.0;
            continue;
        }
        let actions = poll(p, t, wg(0.0, 100, 100), enabled);
        if !actions.is_empty() {
            return (t, actions);
        }
        t += 1.0;
    }
}

#[test]
fn a_dead_tunnel_is_disconnected_and_reconnected_on_its_network() {
    let mut p = up_at_home();
    let (t, actions) = until_dead(&mut p, 10.0, &on);
    assert!(t - 10.0 > STALE_AFTER, "{t}");
    assert_eq!(actions, vec![Action::DisconnectNotResponding("k".into()), dead_notice(DeadOutcome::Reconnects)]);
    assert_eq!(p.not_responding(), vec!["k".to_string()]);
    // Nothing happens before the app's disconnect returned (no connect while it goes down).
    assert!(!p.due(at(t + 60.0)));
    p.network_changed(at(t + 1.0));
    assert!(!p.due(at(t + 60.0)), "a network change does not release it either");
    p.dead_down("k", at(t + 2.0));
    assert!(!p.due(at(t + 2.0 + SETTLE - 0.5)));
    assert_eq!(p.evaluate(at(t + 2.0 + SETTLE), &home(), &on, false), vec![Action::Connect("k".into())]);
    // Up again: "Not responding" is over.
    p.connect_started("k", None, true);
    p.connected("k", VpnNetworks::default());
    assert!(p.not_responding().is_empty());
}

#[test]
fn without_auto_reconnect_a_dead_tunnel_is_only_disconnected() {
    let mut p = up_at_home();
    let (t, actions) = until_dead(&mut p, 10.0, &off);
    assert_eq!(actions, vec![Action::DisconnectNotResponding("k".into()), dead_notice(DeadOutcome::Disconnected)]);
    p.dead_down("k", at(t + 1.0));
    assert!(!p.due(at(t + 100.0)));
    // "Not responding" stays until the user acts.
    assert_eq!(p.not_responding(), vec!["k".to_string()]);
    p.connect_started("k", fingerprint(&home()), false);
    assert!(p.not_responding().is_empty());
    let mut q = up_at_home();
    until_dead(&mut q, 10.0, &off);
    q.user_disconnected("k");
    assert!(q.not_responding().is_empty());
}

#[test]
fn a_lease_started_tunnel_is_never_reconnected() {
    let mut p = Planner::default();
    p.lease_connect_began("k");
    p.connect_started("k", fingerprint(&home()), false);
    p.lease_connect_ended("k");
    p.connected("k", VpnNetworks::default());
    let (t, actions) = until_dead(&mut p, 10.0, &on);
    assert_eq!(actions, vec![Action::DisconnectNotResponding("k".into()), dead_notice(DeadOutcome::Disconnected)]);
    p.dead_down("k", at(t + 1.0));
    assert!(!p.due(at(t + 100.0)));
}

#[test]
fn a_tunnel_dead_again_and_again_is_given_up() {
    let mut p = up_at_home();
    let mut from = 10.0;
    for n in 1..=MAX_DEAD_RECONNECTS {
        let (t, actions) = until_dead(&mut p, from, &on);
        assert_eq!(actions[1], dead_notice(DeadOutcome::Reconnects), "{n}");
        p.dead_down("k", at(t + 1.0));
        assert_eq!(p.evaluate(at(t + 1.0 + SETTLE), &home(), &on, false), vec![Action::Connect("k".into())]);
        p.connect_started("k", None, true);
        p.connected("k", VpnNetworks::default());
        from = t + 10.0;
    }
    let (t, actions) = until_dead(&mut p, from, &on);
    assert_eq!(actions, vec![Action::DisconnectNotResponding("k".into()), dead_notice(DeadOutcome::KeepsTrying)]);
    p.dead_down("k", at(t + 1.0));
    assert!(!p.due(at(t + 100.0)));
    // The slow tier: tried again in 5 minutes.
    assert_eq!(p.slow_retries(), vec![("k".to_string(), at(t + SLOW_RETRY))]);
    assert!(p.due(at(t + SLOW_RETRY)));
    assert_eq!(p.not_responding(), vec!["k".to_string()]);
    // The user connects it again: a fresh count.
    p.connect_started("k", fingerprint(&home()), false);
    p.connected("k", VpnNetworks::default());
    let (_, actions) = until_dead(&mut p, t + 20.0, &on);
    assert_eq!(actions[1], dead_notice(DeadOutcome::Reconnects));
}

#[test]
fn the_count_starts_over_after_the_tunnel_worked_for_a_while() {
    let mut p = up_at_home();
    let mut from = 10.0;
    for _ in 1..=MAX_DEAD_RECONNECTS {
        let (t, _) = until_dead(&mut p, from, &on);
        p.dead_down("k", at(t + 1.0));
        p.evaluate(at(t + 1.0 + SETTLE), &home(), &on, false);
        p.connect_started("k", None, true);
        p.connected("k", VpnNetworks::default());
        from = t + 10.0;
    }
    // Now it works: fresh handshakes for DEAD_STABLE.
    let mut t = from;
    while t < from + DEAD_STABLE + POLL {
        assert!(p.liveness_checked(at(t), &polled(wg(t - 5.0, 100, 100)), &on).is_empty());
        t += POLL;
    }
    let (_, actions) = until_dead(&mut p, t, &on);
    assert_eq!(actions[1], dead_notice(DeadOutcome::Reconnects));
}

#[test]
fn openvpn_restarting_itself_is_reconnecting_then_dead() {
    let mut p = up_at_home();
    let since = Some(Liveness::OpenVpn { reconnecting_since: Some(at(5.0).time_interval_since_1970() as u64) });
    assert!(poll(&mut p, 10.0, since.clone(), &on).is_empty());
    assert_eq!(p.reconnecting(), vec!["k".to_string()]);
    let mut t = 10.0 + POLL;
    while t < 10.0 + OPENVPN_RECONNECT_LIMIT {
        assert!(poll(&mut p, t, since.clone(), &on).is_empty(), "{t}");
        t += POLL;
    }
    assert_eq!(
        poll(&mut p, t, since, &on),
        vec![Action::DisconnectNotResponding("k".into()), dead_notice(DeadOutcome::Reconnects)]
    );
    assert!(p.reconnecting().is_empty());
    // Back up in time instead: no longer reconnecting.
    let mut q = up_at_home();
    let since = Some(Liveness::OpenVpn { reconnecting_since: Some(at(5.0).time_interval_since_1970() as u64) });
    poll(&mut q, 10.0, since, &on);
    assert!(poll(&mut q, 10.0 + POLL, Some(Liveness::OpenVpn { reconnecting_since: None }), &on).is_empty());
    assert!(q.reconnecting().is_empty());
}

#[test]
fn nothing_is_polled_without_a_network_asleep_or_while_a_change_is_checked() {
    let mut p = up_at_home();
    assert!(p.liveness_due(at(10.0)));
    p.liveness_checked(at(10.0), &polled(wg(0.0, 1, 1)), &on);
    assert!(!p.liveness_due(at(10.0 + POLL - 1.0)));
    assert!(p.liveness_due(at(10.0 + POLL)));
    // A change being debounced: the network rules come first.
    p.network_changed(at(50.0));
    assert!(!p.liveness_due(at(51.0)));
    // No network: waiting for it, never polled (so never both a network loss and a dead tunnel).
    p.network_checked(at(50.0 + NETWORK_DEBOUNCE), Some(&NetworkSnapshot::default()), &active());
    assert!(!p.liveness_due(at(500.0)));
    assert!(p.liveness_checked(at(500.0), &polled(wg(0.0, 1, 1)), &on).is_empty());
    // Asleep: neither.
    let mut q = up_at_home();
    q.sleep(&["k".to_string()], fingerprint(&home()));
    assert!(!q.liveness_due(at(500.0)));
}

#[test]
fn the_network_back_restarts_the_watch() {
    // A tunnel whose handshake aged during an outage is not dead the moment the network is back.
    let mut p = up_at_home();
    poll(&mut p, 10.0, wg(0.0, 1, 1), &on);
    p.network_changed(at(20.0));
    p.network_checked(at(20.0 + NETWORK_DEBOUNCE), Some(&NetworkSnapshot::default()), &active());
    p.network_changed(at(400.0));
    assert!(p.network_checked(at(400.0 + NETWORK_DEBOUNCE), Some(&home()), &active()).is_empty());
    assert!(poll(&mut p, 410.0, wg(0.0, 1, 1), &on).is_empty());
    let (t, _) = until_dead(&mut p, 410.0 + POLL, &on);
    assert!(t - 410.0 > STALE_AFTER, "{t}");
}

#[test]
fn no_answer_decides_nothing() {
    let mut p = up_at_home();
    let mut t = 10.0;
    while t < 3600.0 {
        assert!(poll(&mut p, t, None, &on).is_empty());
        t += POLL;
    }
}

#[test]
fn a_dead_tunnel_on_its_own_network_is_disconnected_as_after_a_wake() {
    // The planner last saw the office network (the VPN's own) without a live switch (the tunnel came up there).
    let mut p = Planner::default();
    p.connect_started("k", fingerprint(&office()), false);
    p.connected(
        "k",
        VpnNetworks::from_config(macvpn_core::models::VPNKind::Openvpn, "route 10.20.30.0 255.255.255.0\n"),
    );
    p.network_changed(t0());
    // Its own network directly reachable: the switch's overlap rule disconnects it at once.
    let actions = p.network_checked(at(NETWORK_DEBOUNCE), Some(&office()), &active());
    assert!(actions.is_empty(), "no switch: the tunnel came up here");
    let (_, actions) = until_dead(&mut p, 10.0, &on);
    let why = Skip::DirectlyReachable(IpPrefix::parse("10.20.30.0/24").unwrap());
    assert_eq!(
        actions,
        vec![Action::Disconnect("k".into()), Action::Notify(Notice::DisconnectedHere { key: "k".into(), why })]
    );
}

#[test]
fn a_dead_tunnel_after_waking_on_another_network_is_not_promised_a_reconnect() {
    let mut p = up_at_home();
    p.sleep(&["k".to_string()], fingerprint(&home()));
    p.wake(at(1000.0), &["k".to_string()]);
    // The first check after the wake sees the café: never a live switch.
    assert!(p.network_checked(at(1000.0 + SETTLE), Some(&cafe()), &active()).is_empty());
    let (t, actions) = until_dead(&mut p, 1010.0, &on);
    assert_eq!(actions, vec![Action::DisconnectNotResponding("k".into()), dead_notice(DeadOutcome::Disconnected)]);
    p.dead_down("k", at(t + 1.0));
    assert!(!p.due(at(t + 100.0)), "the wake keeps its same-network rule");
}

#[test]
fn a_drop_while_the_network_is_there_is_reconnected_like_a_dead_tunnel() {
    let mut p = up_at_home();
    // OpenVPN's `--ping-exit`, long after any network change.
    p.dropped("k", "Office VPN", at(900.0), FailureKind::ServerNotResponding);
    assert_eq!(p.evaluate(at(900.0 + SETTLE), &home(), &on, false), vec![Action::Connect("k".into())]);
}

// The live network switch.

/// `up_at_home`, then a live switch to `to` (debounced check at `NETWORK_DEBOUNCE` after `t`): its actions.
fn switch(p: &mut Planner, t: f64, to: &NetworkSnapshot) -> Vec<Action> {
    p.network_changed(at(t));
    assert!(p.network_check_due(at(t + NETWORK_DEBOUNCE)));
    p.network_checked(at(t + NETWORK_DEBOUNCE), Some(to), &active())
}

/// A WireGuard peer without keepalive after a switch: its handshake at `h`, the counters.
fn roaming(h: f64, rx: u64, tx: u64) -> Option<Liveness> {
    Some(Liveness::WireGuard(vec![WgPeer {
        last_handshake: Some(at(h).time_interval_since_1970() as u64),
        rx,
        tx,
        keepalive: 0,
        endpoint: true,
    }]))
}

#[test]
fn a_switch_is_checked_soon_and_closely() {
    let mut p = up_at_home();
    poll(&mut p, 10.0, roaming(0.0, 1000, 1000), &on);
    poll(&mut p, 10.0 + POLL, roaming(0.0, 1000, 1000), &on);
    assert!(switch(&mut p, 50.0, &cafe()).is_empty());
    let checked = 50.0 + NETWORK_DEBOUNCE;
    assert!(!p.liveness_due(at(checked + SWITCH_FIRST - 0.5)));
    assert!(p.liveness_due(at(checked + SWITCH_FIRST)));
    p.liveness_checked(at(checked + SWITCH_FIRST), &polled(roaming(0.0, 1000, 1000)), &on);
    assert!(p.liveness_due(at(checked + SWITCH_FIRST + SWITCH_POLL)));
}

#[test]
fn a_switch_then_a_dead_tunnel_is_reconnected_on_the_new_network() {
    let mut p = up_at_home();
    poll(&mut p, 10.0, roaming(0.0, 1000, 1000), &on);
    assert!(switch(&mut p, 50.0, &cafe()).is_empty());
    // Data goes out after the switch, nothing comes back.
    let mut t = 50.0 + NETWORK_DEBOUNCE + SWITCH_FIRST;
    let mut tx = 1000;
    let actions = loop {
        let a = poll(&mut p, t, roaming(0.0, 1000, tx), &on);
        if !a.is_empty() {
            break a;
        }
        tx += 500;
        t += SWITCH_POLL;
        assert!(t < 200.0, "never dead");
    };
    // Well within a minute of the switch.
    assert!(t - 50.0 <= NETWORK_DEBOUNCE + SWITCH_FIRST + SWITCH_POLL + SWITCH_SILENCE + SWITCH_POLL, "{t}");
    assert_eq!(actions, vec![Action::DisconnectNotResponding("k".into()), dead_notice(DeadOutcome::Reconnects)]);
    p.dead_down("k", at(t + 1.0));
    // Reconnected at the café although it came up at home: the user had it up here.
    assert_eq!(p.evaluate(at(t + 1.0 + SETTLE), &cafe(), &on, false), vec![Action::Connect("k".into())]);
}

#[test]
fn a_switch_with_a_working_tunnel_leaves_it_alone() {
    let mut p = up_at_home();
    poll(&mut p, 10.0, roaming(0.0, 1000, 1000), &on);
    assert!(switch(&mut p, 50.0, &cafe()).is_empty());
    // Sent and received: WireGuard roamed without a new handshake.
    let mut t = 50.0 + NETWORK_DEBOUNCE + SWITCH_FIRST;
    let mut n = 1000;
    while t < 400.0 {
        assert!(p.liveness_checked(at(t), &polled(roaming(0.0, n, n)), &on).is_empty(), "{t}");
        n += 500;
        t += SWITCH_POLL;
    }
    // Idle after the switch (nothing sent): undecided, never dead.
    let mut q = up_at_home();
    poll(&mut q, 10.0, roaming(0.0, 1000, 1000), &on);
    switch(&mut q, 50.0, &cafe());
    let mut t = 50.0 + NETWORK_DEBOUNCE + SWITCH_FIRST;
    while t < 3600.0 {
        assert!(q.liveness_checked(at(t), &polled(roaming(0.0, 1000, 1000)), &on).is_empty(), "{t}");
        t += SWITCH_POLL;
    }
}

#[test]
fn openvpn_stuck_restarting_after_a_switch_is_dead_after_a_minute() {
    let mut p = up_at_home();
    poll(&mut p, 10.0, Some(Liveness::OpenVpn { reconnecting_since: None }), &on);
    switch(&mut p, 50.0, &cafe());
    let since = Some(Liveness::OpenVpn { reconnecting_since: Some(at(60.0).time_interval_since_1970() as u64) });
    let mut t = 50.0 + NETWORK_DEBOUNCE + SWITCH_FIRST;
    let actions = loop {
        let a = poll(&mut p, t, since.clone(), &on);
        if !a.is_empty() {
            break a;
        }
        t += SWITCH_POLL;
    };
    assert!(t - 60.0 >= SWITCH_OPENVPN_LIMIT && t - 60.0 < SWITCH_OPENVPN_LIMIT + SWITCH_POLL, "{t}");
    assert_eq!(actions[1], dead_notice(DeadOutcome::Reconnects));
}

#[test]
fn a_switch_to_the_vpns_own_network_disconnects() {
    let mut p = up_at_home();
    let why = Skip::DirectlyReachable(IpPrefix::parse("10.20.30.0/24").unwrap());
    assert_eq!(
        switch(&mut p, 50.0, &office()),
        vec![Action::Disconnect("k".into()), Action::Notify(Notice::DisconnectedHere { key: "k".into(), why })]
    );
}

#[test]
fn a_switch_does_not_reconnect_a_lease_or_with_the_setting_off() {
    let run = |lease: bool, enabled: &dyn Fn(&str) -> bool| {
        let mut p = Planner::default();
        if lease {
            p.lease_connect_began("k");
        }
        p.connect_started("k", fingerprint(&home()), false);
        p.lease_connect_ended("k");
        p.connected("k", VpnNetworks::default());
        p.network_changed(t0());
        p.network_checked(at(NETWORK_DEBOUNCE), Some(&home()), &active());
        poll(&mut p, 10.0, roaming(0.0, 1000, 1000), enabled);
        switch(&mut p, 50.0, &cafe());
        let mut t = 50.0 + NETWORK_DEBOUNCE + SWITCH_FIRST;
        let mut tx = 1000;
        let actions = loop {
            let a = poll(&mut p, t, roaming(0.0, 1000, tx), enabled);
            if !a.is_empty() {
                break a;
            }
            tx += 500;
            t += SWITCH_POLL;
        };
        assert_eq!(actions, vec![Action::DisconnectNotResponding("k".into()), dead_notice(DeadOutcome::Disconnected)]);
        p.dead_down("k", at(t + 1.0));
        assert!(!p.due(at(t + 100.0)));
    };
    run(true, &on);
    run(false, &off);
}

#[test]
fn back_from_waiting_for_network_on_another_network_is_a_switch() {
    let mut p = up_at_home();
    poll(&mut p, 10.0, roaming(0.0, 1000, 1000), &on);
    p.network_changed(at(50.0));
    p.network_checked(at(50.0 + NETWORK_DEBOUNCE), Some(&NetworkSnapshot::default()), &active());
    assert_eq!(p.waiting_for_network(), vec!["k".to_string()]);
    p.network_changed(at(80.0));
    assert!(p.network_checked(at(80.0 + NETWORK_DEBOUNCE), Some(&cafe()), &active()).is_empty());
    let first = 80.0 + NETWORK_DEBOUNCE + SWITCH_FIRST;
    poll(&mut p, first, roaming(0.0, 1000, 1000), &on);
    assert!(p.liveness_due(at(first + SWITCH_POLL)), "closely after the switch");
    // Back on the same network instead: no switch, the usual pace.
    let mut q = up_at_home();
    poll(&mut q, 10.0, roaming(0.0, 1000, 1000), &on);
    q.network_changed(at(50.0));
    q.network_checked(at(50.0 + NETWORK_DEBOUNCE), Some(&NetworkSnapshot::default()), &active());
    q.network_changed(at(80.0));
    q.network_checked(at(80.0 + NETWORK_DEBOUNCE), Some(&home()), &active());
    poll(&mut q, first, roaming(0.0, 1000, 1000), &on);
    assert!(!q.liveness_due(at(first + SWITCH_POLL)));
    assert!(q.liveness_due(at(first + POLL)));
}

// The resilience audit (maintainer goal 2026-10-28: "stable in every situation while it should be up").

/// The app started while the connection was up (no connect of ours): it is adopted on the network it is up on, so
/// a later drop or dead tunnel is reconnected there instead of "the network could not be identified".
#[test]
fn a_connection_up_when_the_app_started_is_reconnected_on_its_network() {
    let mut p = Planner::default();
    assert!(!p.knows_network("k"));
    p.adopt("k", fingerprint(&home()));
    p.connected("k", VpnNetworks::default());
    assert!(p.knows_network("k"));
    // A known network is never replaced by a later adoption.
    p.adopt("k", fingerprint(&cafe()));
    p.dropped("k", "Office VPN", at(900.0), FailureKind::Unknown);
    assert_eq!(p.evaluate(at(900.0 + SETTLE), &home(), &on, false), vec![Action::Connect("k".into())]);
    // Without the adoption: not identified.
    let mut q = Planner::default();
    q.connected("k", VpnNetworks::default());
    q.dropped("k", "Office VPN", at(900.0), FailureKind::Unknown);
    assert_eq!(
        q.evaluate(at(900.0 + SETTLE), &home(), &on, false),
        vec![Action::Notify(Notice::NotReconnected {
            key: "k".into(),
            name: "Office VPN".into(),
            why: Skip::Unidentified
        })]
    );
}

/// A tunnel that drops right at a live switch (an IPsec or native VPN bound to the old address) is reconnected on
/// the new network like one that survived and died; its decision waits for the switch's network check.
#[test]
fn a_drop_at_a_live_switch_is_reconnected_on_the_new_network() {
    let mut p = up_at_home();
    p.network_changed(at(50.0));
    p.dropped("k", "Office VPN", at(50.5), FailureKind::NetworkLost);
    // Due after settling on another network, but the change is still being checked: it waits for the check.
    assert!(p.evaluate(at(50.5 + SETTLE + 1.0), &cafe(), &on, false).is_empty());
    assert!(!p.due(at(55.0)));
    assert!(p.network_checked(at(50.0 + NETWORK_DEBOUNCE + 2.0), Some(&cafe()), &[]).is_empty());
    assert!(p.due(at(56.0)));
    assert_eq!(p.evaluate(at(56.0), &cafe(), &on, false), vec![Action::Connect("k".into())]);
    // On the VPN's own network it is not.
    let mut q = up_at_home();
    q.network_changed(at(50.0));
    q.dropped("k", "Office VPN", at(50.5), FailureKind::NetworkLost);
    q.network_checked(at(50.0 + NETWORK_DEBOUNCE + 2.0), Some(&office()), &[]);
    let why = Skip::DirectlyReachable(IpPrefix::parse("10.20.30.0/24").unwrap());
    assert_eq!(
        q.evaluate(at(56.0), &office(), &on, false),
        vec![Action::Notify(Notice::NotReconnected { key: "k".into(), name: "Office VPN".into(), why })]
    );
}

/// After a wake a drop keeps the same-network rule (maintainer decision 4), also when the network changes later.
#[test]
fn a_drop_after_a_wake_never_moves_to_another_network() {
    let mut p = up_at_home();
    p.sleep(&["k".to_string()], fingerprint(&home()));
    p.wake(at(1000.0), &["k".to_string()]);
    p.dropped("k", "Office VPN", at(1001.0), FailureKind::NetworkLost);
    p.network_changed(at(1002.0));
    p.network_checked(at(1002.0 + NETWORK_DEBOUNCE), Some(&cafe()), &[]);
    assert_eq!(
        p.evaluate(at(1002.0 + NETWORK_DEBOUNCE + SETTLE), &cafe(), &on, false),
        vec![Action::Notify(Notice::NotReconnected {
            key: "k".into(),
            name: "Office VPN".into(),
            why: Skip::DifferentNetwork
        })]
    );
}

/// A network change checked with nothing active probes no network: the last one seen is then unknown, not stale (a
/// dead tunnel connected after it is promised its reconnect; `evaluate` decides on a fresh snapshot).
#[test]
fn a_change_with_nothing_active_does_not_leave_a_stale_network() {
    let mut p = Planner::default();
    p.network_changed(t0());
    p.network_checked(at(NETWORK_DEBOUNCE), Some(&cafe()), &[]);
    // Back home with nothing up: the driver does not probe.
    p.network_changed(at(50.0));
    p.network_checked(at(50.0 + NETWORK_DEBOUNCE), None, &[]);
    p.connect_started("k", fingerprint(&home()), false);
    p.connected("k", VpnNetworks::default());
    let (t, actions) = until_dead(&mut p, 60.0, &on);
    assert_eq!(actions[1], dead_notice(DeadOutcome::Reconnects));
    p.dead_down("k", at(t + 1.0));
    assert_eq!(p.evaluate(at(t + 1.0 + SETTLE), &home(), &on, false), vec![Action::Connect("k".into())]);
}

// Lease marks across a relaunch (2026-10-28 follow-up).

/// The marks are stored as sorted UUIDs; anything else is ignored; set / clear are idempotent.
#[test]
fn lease_marks_round_trip_in_the_preferences() {
    use macvpn_app_core::reconnect::{LEASED_KEY, lease_marks, set_lease_mark};
    use macvpn_platform_api::{MemoryPreferences, PreferenceStore};
    let prefs = MemoryPreferences::default();
    let a = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
    let b = "1F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
    set_lease_mark(&prefs, b, true);
    set_lease_mark(&prefs, &a.to_ascii_lowercase(), true);
    set_lease_mark(&prefs, a, true);
    set_lease_mark(&prefs, "not-a-uuid", true);
    assert_eq!(lease_marks(&prefs), vec![a.to_string(), b.to_string()]);
    set_lease_mark(&prefs, b, false);
    assert_eq!(lease_marks(&prefs), vec![a.to_string()]);
    prefs.set_string(LEASED_KEY, &format!("{a},../x,,{b}"));
    assert_eq!(lease_marks(&prefs), vec![a.to_string(), b.to_string()]);
}

/// A connection a lease started and left up by "Quit, Keep Them Running" is restored as the lease's: never
/// reconnected after a drop or as a dead tunnel; the user's own connect takes it over.
#[test]
fn a_restored_lease_mark_is_never_reconnected_until_the_user_connects() {
    let mut p = Planner::default();
    p.restore_leased(&["k".to_string()]);
    assert!(p.is_leased("k"));
    p.adopt("k", fingerprint(&home()));
    p.connected("k", VpnNetworks::default());
    p.dropped("k", "Office VPN", at(900.0), FailureKind::Unknown);
    assert!(!p.due(at(900.0 + SETTLE)));
    let mut q = Planner::default();
    q.restore_leased(&["k".to_string()]);
    q.adopt("k", fingerprint(&home()));
    q.connected("k", VpnNetworks::default());
    let (_, actions) = until_dead(&mut q, 10.0, &on);
    assert_eq!(actions[1], dead_notice(DeadOutcome::Disconnected));
    // The user connects it: it is theirs now.
    q.connect_started("k", fingerprint(&home()), false);
    assert!(!q.is_leased("k"));
}

// The slow tier (2026-10-28 follow-up): after the fast attempts, every 5 minutes for up to an hour.

/// `up_at_home`, dropped by itself, and the three fast attempts failed: the slow tier started at `t`.
fn slow() -> (Planner, f64) {
    let mut p = up_at_home();
    p.dropped("k", "Office VPN", at(900.0), FailureKind::ServerUnreachable);
    let mut t = 900.0 + SETTLE;
    for _ in 0..3 {
        assert_eq!(p.evaluate(at(t), &home(), &on, false), vec![Action::Connect("k".into())]);
        let a = p.failed("k", at(t + 1.0), FailureKind::ServerUnreachable);
        t += 1.0;
        if !a.is_empty() {
            assert!(matches!(a[0], Action::Notify(Notice::KeepsTrying { .. })));
            return (p, t);
        }
        t += 40.0;
    }
    panic!("no slow tier");
}

#[test]
fn the_slow_tier_tries_every_five_minutes_and_gives_up_after_an_hour_with_two_notices() {
    let (mut p, start) = slow();
    let mut t = start;
    let mut notices = Vec::new();
    loop {
        t += SLOW_RETRY;
        assert!(p.due(at(t)), "{t}");
        let a = p.evaluate(at(t), &home(), &on, false);
        if a.is_empty() {
            break;
        }
        assert_eq!(a, vec![Action::Connect("k".into())]);
        t += 1.0;
        let a = p.failed("k", at(t), FailureKind::ServerUnreachable);
        notices.extend(a);
        if p.slow_retries().is_empty() {
            break;
        }
        assert!(t - start < SLOW_FOR + SLOW_RETRY + 10.0, "never ends");
    }
    // Silent attempts, then exactly one final notice once the hour is over.
    assert_eq!(notices, vec![Action::Notify(Notice::RetriesEnded { key: "k".into(), name: "Office VPN".into() })]);
    assert!(t - start >= SLOW_FOR - SLOW_RETRY);
    assert!(!p.due(at(t + 10_000.0)));
}

#[test]
fn a_slow_attempt_that_works_ends_it_and_the_row_shows_the_next_attempt() {
    let (mut p, start) = slow();
    assert_eq!(p.slow_retries(), vec![("k".to_string(), at(start + SLOW_RETRY))]);
    assert_eq!(p.evaluate(at(start + SLOW_RETRY), &home(), &on, false), vec![Action::Connect("k".into())]);
    assert!(p.slow_retries().is_empty(), "attempting: no countdown");
    p.connect_started("k", None, true);
    p.connected("k", VpnNetworks::default());
    assert!(p.slow_retries().is_empty());
    assert!(!p.due(at(start + 2.0 * SLOW_RETRY)));
}

#[test]
fn the_slow_tier_stops_when_the_user_acts_or_the_switch_is_off() {
    let (mut p, start) = slow();
    p.user_disconnected("k");
    assert!(p.slow_retries().is_empty() && !p.due(at(start + SLOW_RETRY)));
    let (mut p, start) = slow();
    p.connect_started("k", fingerprint(&home()), false);
    assert!(p.slow_retries().is_empty() && !p.due(at(start + SLOW_RETRY)));
    let (mut p, start) = slow();
    assert!(p.evaluate(at(start + SLOW_RETRY), &home(), &off, false).is_empty());
    assert!(p.slow_retries().is_empty() && !p.due(at(start + 2.0 * SLOW_RETRY)));
}

#[test]
fn the_slow_tier_waits_for_a_network_and_stops_on_the_office_network() {
    let (mut p, start) = slow();
    // No network: it waits (no attempt), and tries once the network is back.
    assert!(p.evaluate(at(start + SLOW_RETRY), &NetworkSnapshot::default(), &on, false).is_empty());
    assert!(!p.due(at(start + SLOW_RETRY + 60.0)));
    p.network_changed(at(start + 400.0));
    p.network_checked(at(start + 400.0 + NETWORK_DEBOUNCE), Some(&home()), &[]);
    assert_eq!(
        p.evaluate(at(start + 400.0 + NETWORK_DEBOUNCE), &home(), &on, false),
        vec![Action::Connect("k".into())]
    );
    // On the VPN's own network: not reconnected, and the slow tier is over.
    let (mut p, start) = slow();
    let why = Skip::DirectlyReachable(IpPrefix::parse("10.20.30.0/24").unwrap());
    assert_eq!(
        p.evaluate(at(start + SLOW_RETRY), &office(), &on, false),
        vec![Action::Notify(Notice::NotReconnected { key: "k".into(), name: "Office VPN".into(), why })]
    );
    assert!(p.slow_retries().is_empty() && !p.due(at(start + 2.0 * SLOW_RETRY)));
    // With the vault locked: silently the next time.
    let (mut p, start) = slow();
    assert!(p.evaluate(at(start + SLOW_RETRY), &home(), &on, true).is_empty());
    assert_eq!(p.slow_retries(), vec![("k".to_string(), at(start + 2.0 * SLOW_RETRY))]);
}

#[test]
fn a_refused_sign_in_or_a_lease_never_reaches_the_slow_tier() {
    let mut p = up_at_home();
    p.dropped("k", "Office VPN", at(900.0), FailureKind::ServerUnreachable);
    p.evaluate(at(900.0 + SETTLE), &home(), &on, false);
    assert!(matches!(
        p.failed("k", at(905.0), FailureKind::AuthFailed)[..],
        [Action::Notify(Notice::ReconnectFailed { .. })]
    ));
    assert!(p.slow_retries().is_empty());
    let mut q = Planner::default();
    q.restore_leased(&["k".to_string()]);
    q.adopt("k", fingerprint(&home()));
    q.connected("k", VpnNetworks::default());
    for i in 0..6 {
        q.dropped("k", "Office VPN", at(900.0 + 100.0 * f64::from(i)), FailureKind::Unknown);
    }
    assert!(q.take_actions().is_empty() && q.slow_retries().is_empty());
}

#[test]
fn a_connection_that_keeps_dropping_reaches_the_slow_tier_with_one_notice() {
    let mut p = up_at_home();
    let mut t = 900.0;
    for _ in 0..MAX_DEAD_RECONNECTS {
        p.dropped("k", "Office VPN", at(t), FailureKind::Unknown);
        assert_eq!(p.evaluate(at(t + SETTLE), &home(), &on, false), vec![Action::Connect("k".into())]);
        p.connect_started("k", None, true);
        p.connected("k", VpnNetworks::default());
        t += 60.0;
    }
    assert!(p.take_actions().is_empty());
    p.dropped("k", "Office VPN", at(t), FailureKind::Unknown);
    assert!(matches!(p.take_actions()[..], [Action::Notify(Notice::KeepsTrying { .. })]));
    assert_eq!(p.slow_retries(), vec![("k".to_string(), at(t + SLOW_RETRY))]);
    // Up again by a slow attempt, dropped again within the hour: no second notice.
    p.evaluate(at(t + SLOW_RETRY), &home(), &on, false);
    p.connect_started("k", None, true);
    p.connected("k", VpnNetworks::default());
    p.dropped("k", "Office VPN", at(t + SLOW_RETRY + 60.0), FailureKind::Unknown);
    assert!(p.take_actions().is_empty());
    assert_eq!(p.slow_retries().len(), 1);
}
