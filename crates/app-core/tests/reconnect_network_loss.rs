//! Network loss under a running VPN (maintainer report, 2026-10-28): a connection that is up or connecting while the
//! physical network is gone "waits for network" (debounced), a tunnel that survived stays when the network comes
//! back (unless the VPN's own network is directly reachable there), and after a long outage the connection is
//! disconnected cleanly and, with "Reconnect Automatically" on, reconnected through the usual decision.

use macvpn_app_core::connection_notices::Notice;
use macvpn_app_core::failure_reason::FailureKind;
use macvpn_app_core::reconnect::{
    Action, NETWORK_DEBOUNCE, NETWORK_DEBOUNCE_MAX, OFFLINE_GRACE, OFFLINE_RECHECK, Planner, SETTLE, Skip, fingerprint,
};
use macvpn_core::date::Date;
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

fn none() -> NetworkSnapshot {
    NetworkSnapshot::default()
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

/// "k" came up at home; its VPN routes the office network.
fn up_at_home() -> Planner {
    let mut p = Planner::default();
    p.connect_started("k", fingerprint(&home()), false);
    p.connected(
        "k",
        VpnNetworks::from_config(macvpn_core::models::VPNKind::Openvpn, "route 10.20.30.0 255.255.255.0\n"),
    );
    p
}

/// `up_at_home`, then the network went away at t0 and the debounced check saw no network.
fn waiting() -> Planner {
    let mut p = up_at_home();
    p.network_changed(t0());
    assert!(p.network_check_due(at(NETWORK_DEBOUNCE)));
    assert!(p.network_checked(at(NETWORK_DEBOUNCE), Some(&none()), &active()).is_empty());
    assert_eq!(p.waiting_for_network(), vec!["k".to_string()]);
    p
}

#[test]
fn the_check_is_debounced_after_a_change() {
    let mut p = up_at_home();
    assert!(!p.network_check_due(t0()), "nothing changed yet");
    p.network_changed(t0());
    assert!(!p.network_check_due(at(NETWORK_DEBOUNCE - 0.5)));
    // Another change restarts the wait …
    p.network_changed(at(2.0));
    assert!(!p.network_check_due(at(NETWORK_DEBOUNCE)));
    assert!(p.network_check_due(at(2.0 + NETWORK_DEBOUNCE)));
}

#[test]
fn a_stream_of_changes_is_checked_at_most_after_the_debounce_cap() {
    let mut p = up_at_home();
    let mut t = 0.0;
    while t < NETWORK_DEBOUNCE_MAX + 5.0 {
        p.network_changed(at(t));
        t += 1.0;
    }
    assert!(p.network_check_due(at(NETWORK_DEBOUNCE_MAX)));
}

#[test]
fn no_network_makes_the_active_connections_wait() {
    let p = waiting();
    assert!(!p.network_check_due(at(NETWORK_DEBOUNCE + 1.0)));
    assert!(p.network_check_due(at(NETWORK_DEBOUNCE + OFFLINE_RECHECK)), "rechecked while waiting");
}

#[test]
fn a_short_blip_never_shows() {
    let mut p = up_at_home();
    p.network_changed(t0());
    // Back before the debounced check.
    p.network_changed(at(1.0));
    assert!(p.network_checked(at(1.0 + NETWORK_DEBOUNCE), Some(&home()), &active()).is_empty());
    assert!(p.waiting_for_network().is_empty());
}

#[test]
fn the_network_back_restores_a_surviving_tunnel() {
    let mut p = waiting();
    p.network_changed(at(30.0));
    assert!(p.network_checked(at(30.0 + NETWORK_DEBOUNCE), Some(&home()), &active()).is_empty());
    assert!(p.waiting_for_network().is_empty());
    assert!(!p.offline_due(at(OFFLINE_GRACE + 100.0)), "no disconnect after the network came back");
}

#[test]
fn a_surviving_tunnel_on_another_network_stays_as_after_a_wake() {
    let mut p = waiting();
    assert!(p.network_checked(at(30.0), Some(&cafe()), &active()).is_empty());
    assert!(p.waiting_for_network().is_empty());
}

#[test]
fn a_surviving_tunnel_on_the_vpns_own_network_is_disconnected() {
    let mut p = waiting();
    let actions = p.network_checked(at(30.0), Some(&office()), &active());
    let why = Skip::DirectlyReachable(IpPrefix::parse("10.20.30.0/24").unwrap());
    assert_eq!(
        actions,
        vec![Action::Disconnect("k".into()), Action::Notify(Notice::DisconnectedHere { key: "k".into(), why })]
    );
    assert!(p.waiting_for_network().is_empty());
}

#[test]
fn a_connection_that_went_down_is_no_longer_waiting() {
    let mut p = waiting();
    assert!(p.network_checked(at(20.0), Some(&none()), &[]).is_empty());
    assert!(p.waiting_for_network().is_empty());
    let mut q = waiting();
    q.dropped("k", "Office VPN", at(20.0), FailureKind::NetworkLost);
    assert!(q.waiting_for_network().is_empty());
    let mut r = waiting();
    r.user_disconnected("k");
    assert!(r.waiting_for_network().is_empty());
}

#[test]
fn a_long_outage_disconnects_and_reconnects_on_the_same_network() {
    let mut p = waiting();
    let since = NETWORK_DEBOUNCE;
    assert!(!p.offline_due(at(since + OFFLINE_GRACE - 1.0)));
    assert!(p.offline_due(at(since + OFFLINE_GRACE)));
    let actions = p.offline_expired(at(since + OFFLINE_GRACE), &on);
    assert_eq!(
        actions,
        vec![
            Action::DisconnectNoNetwork("k".into()),
            Action::Notify(Notice::DisconnectedNoNetwork {
                key: "k".into(),
                name: "Office VPN".into(),
                reconnects: true
            }),
        ]
    );
    assert!(p.waiting_for_network().is_empty());
    assert!(!p.due(at(500.0)), "waits for the network");
    // The network comes back: the usual decision on a fresh snapshot.
    p.network_changed(at(600.0));
    assert!(p.network_checked(at(600.0 + NETWORK_DEBOUNCE), Some(&home()), &[]).is_empty());
    assert!(p.due(at(600.0 + SETTLE)));
    assert_eq!(p.evaluate(at(600.0 + SETTLE), &home(), &on, false), vec![Action::Connect("k".into())]);
}

#[test]
fn a_long_outage_then_another_network_is_not_reconnected() {
    let mut p = waiting();
    p.offline_expired(at(NETWORK_DEBOUNCE + OFFLINE_GRACE), &on);
    p.network_changed(at(600.0));
    assert_eq!(
        p.evaluate(at(600.0 + SETTLE), &cafe(), &on, false),
        vec![Action::Notify(Notice::NotReconnected {
            key: "k".into(),
            name: "Office VPN".into(),
            why: Skip::DifferentNetwork
        })]
    );
}

#[test]
fn the_network_back_just_before_the_check_still_reconnects() {
    let mut p = waiting();
    // Back at 120 s, the grace ends before the debounced check.
    p.network_changed(at(NETWORK_DEBOUNCE + OFFLINE_GRACE - 1.0));
    p.offline_expired(at(NETWORK_DEBOUNCE + OFFLINE_GRACE), &on);
    let check = at(NETWORK_DEBOUNCE + OFFLINE_GRACE - 1.0 + NETWORK_DEBOUNCE);
    assert!(p.network_checked(check, Some(&home()), &[]).is_empty());
    assert!(p.due(check));
    assert_eq!(p.evaluate(check, &home(), &on, false), vec![Action::Connect("k".into())]);
}

#[test]
fn a_long_outage_without_auto_reconnect_only_disconnects() {
    let mut p = waiting();
    let actions = p.offline_expired(at(NETWORK_DEBOUNCE + OFFLINE_GRACE), &off);
    assert_eq!(
        actions,
        vec![
            Action::DisconnectNoNetwork("k".into()),
            Action::Notify(Notice::DisconnectedNoNetwork {
                key: "k".into(),
                name: "Office VPN".into(),
                reconnects: false
            }),
        ]
    );
    p.network_changed(at(600.0));
    p.network_checked(at(600.0 + NETWORK_DEBOUNCE), Some(&home()), &[]);
    assert!(!p.due(at(700.0)));
}

#[test]
fn a_lease_started_connection_is_disconnected_but_never_reconnected() {
    let mut p = Planner::default();
    p.lease_connect_began("k");
    p.connect_started("k", fingerprint(&home()), false);
    p.lease_connect_ended("k");
    p.connected("k", VpnNetworks::default());
    p.network_changed(t0());
    p.network_checked(at(NETWORK_DEBOUNCE), Some(&none()), &active());
    let actions = p.offline_expired(at(NETWORK_DEBOUNCE + OFFLINE_GRACE), &on);
    assert_eq!(actions[0], Action::DisconnectNoNetwork("k".into()));
    assert_eq!(
        actions[1],
        Action::Notify(Notice::DisconnectedNoNetwork { key: "k".into(), name: "Office VPN".into(), reconnects: false })
    );
    p.network_changed(at(600.0));
    assert!(!p.due(at(700.0)));
}

#[test]
fn a_drop_during_the_outage_waits_for_the_network_and_reconnects() {
    let mut p = waiting();
    // Long after the change (outside the network window), the engine gives up.
    p.dropped("k", "Office VPN", at(90.0), FailureKind::NetworkLost);
    assert!(p.due(at(90.0 + SETTLE)));
    assert!(p.evaluate(at(90.0 + SETTLE), &none(), &on, false).is_empty());
    p.network_changed(at(200.0));
    assert_eq!(p.evaluate(at(200.0 + SETTLE), &home(), &on, false), vec![Action::Connect("k".into())]);
}

#[test]
fn sleep_is_not_a_network_loss() {
    let mut p = waiting();
    p.sleep(&["k".to_string()], None);
    assert!(p.waiting_for_network().is_empty());
    p.network_changed(at(10.0));
    assert!(!p.network_check_due(at(100.0)), "nothing is checked while asleep");
    // Hours later: the outage timer starts again after the wake.
    p.wake(at(36_000.0), &["k".to_string()]);
    assert!(p.network_check_due(at(36_000.0 + SETTLE)));
    p.network_checked(at(36_000.0 + SETTLE), Some(&none()), &active());
    assert_eq!(p.waiting_for_network(), vec!["k".to_string()]);
    assert!(!p.offline_due(at(36_000.0 + SETTLE + 1.0)));
    assert!(p.offline_due(at(36_000.0 + SETTLE + OFFLINE_GRACE)));
}

#[test]
fn an_unreadable_network_changes_nothing() {
    let mut p = waiting();
    assert!(p.network_checked(at(20.0), None, &active()).is_empty());
    assert_eq!(p.waiting_for_network(), vec!["k".to_string()]);
    assert!(p.network_check_due(at(20.0 + OFFLINE_RECHECK)));
    let mut q = up_at_home();
    q.network_changed(t0());
    assert!(q.network_checked(at(NETWORK_DEBOUNCE), None, &active()).is_empty());
    assert!(q.waiting_for_network().is_empty());
    assert!(!q.network_check_due(at(100.0)));
}

#[test]
fn several_connections_wait_and_expire_in_key_order() {
    let mut p = up_at_home();
    p.connect_started("j", fingerprint(&home()), false);
    p.connected("j", VpnNetworks::default());
    let both = vec![("k".to_string(), "Office VPN".to_string()), ("j".to_string(), "Lab".to_string())];
    p.network_changed(t0());
    p.network_checked(at(NETWORK_DEBOUNCE), Some(&none()), &both);
    assert_eq!(p.waiting_for_network(), vec!["j".to_string(), "k".to_string()]);
    let actions = p.offline_expired(at(NETWORK_DEBOUNCE + OFFLINE_GRACE), &on);
    let disconnects: Vec<&Action> = actions.iter().filter(|a| matches!(a, Action::DisconnectNoNetwork(_))).collect();
    assert_eq!(disconnects, vec![&Action::DisconnectNoNetwork("j".into()), &Action::DisconnectNoNetwork("k".into())]);
}

#[test]
fn the_outage_limit_is_the_two_minutes_the_notice_names() {
    assert_eq!(OFFLINE_GRACE, 120.0);
    assert!((2.0..=3.0).contains(&NETWORK_DEBOUNCE));
}
