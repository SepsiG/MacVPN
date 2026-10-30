//! The auto-reconnect planner (features 2.0, maintainer decision 4 and the 2026-10-25 amendment): candidates after
//! a wake or a network change, settling, retries and give-up, the notices, and the once-per-wake check of tunnels
//! that survived the sleep on the VPN's own network.

use macvpn_app_core::connection_notices::Notice;
use macvpn_app_core::failure_reason::FailureKind;
use macvpn_app_core::reconnect::{
    Action, DEAD_STABLE, Fingerprint, MAX_DEAD_RECONNECTS, Planner, SETTLE, SLOW_RETRY, Skip, WAKE_WINDOW, fingerprint,
};
use macvpn_core::date::Date;
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::netaddr::IpPrefix;
use macvpn_core::vpn_networks::VpnNetworks;
use macvpn_platform_api::{Gateway, NetworkSnapshot};

const MAC: [u8; 6] = [0xa4, 0x2b, 0xb0, 0, 0, 1];

fn net(gw: &str, mac: [u8; 6], subnet: &str) -> NetworkSnapshot {
    NetworkSnapshot {
        gateway: Some(Gateway { ip: gw.parse().unwrap(), mac: Some(mac), interface: "en0".into(), ssid: None }),
        connected: vec![IpPrefix::parse(subnet).unwrap()],
    }
}

fn home() -> NetworkSnapshot {
    net("192.168.1.1", MAC, "192.168.1.0/24")
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

fn on(_: &str) -> bool {
    true
}

/// A connection "k" that came up at home and was up when the system slept.
fn slept_planner() -> Planner {
    let mut p = Planner::default();
    p.connect_started("k", fingerprint(&home()), false);
    p.connected(
        "k",
        VpnNetworks::from_config(macvpn_core::models::VPNKind::Openvpn, "route 10.20.30.0 255.255.255.0\n"),
    );
    p.sleep(&["k".to_string()], fingerprint(&home()));
    p.wake(t0(), &["k".to_string()]);
    p
}

#[test]
fn a_drop_after_wake_on_the_same_network_reconnects_after_settling() {
    let mut p = slept_planner();
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::ServerNotResponding);
    assert!(!p.due(t0().adding(1.0)));
    assert!(p.due(t0().adding(1.0 + SETTLE)));
    let actions = p.evaluate(t0().adding(5.0), &home(), &on, false);
    assert_eq!(actions, vec![Action::Connect("k".into())]);
    assert!(p.is_attempting("k"));
    assert!(!p.due(t0().adding(100.0)), "an attempt in flight is not evaluated again");
    p.connected("k", VpnNetworks::default());
    assert!(!p.is_attempting("k") && !p.due(t0().adding(100.0)));
}

#[test]
fn another_network_is_reported_once_and_forgotten() {
    let mut p = slept_planner();
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
    let actions = p.evaluate(t0().adding(5.0), &cafe(), &on, false);
    assert_eq!(
        actions,
        vec![Action::Notify(Notice::NotReconnected {
            key: "k".into(),
            name: "Office VPN".into(),
            why: Skip::DifferentNetwork
        })]
    );
    assert!(p.evaluate(t0().adding(60.0), &cafe(), &on, false).is_empty());
}

#[test]
fn the_vpns_own_network_is_not_reconnected() {
    let mut p = Planner::default();
    p.connect_started("k", fingerprint(&office()), false);
    p.connected(
        "k",
        VpnNetworks::from_config(macvpn_core::models::VPNKind::Openvpn, "route 10.20.30.0 255.255.255.0\n"),
    );
    p.network_changed(t0());
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
    assert_eq!(
        p.evaluate(t0().adding(5.0), &office(), &on, false),
        vec![Action::Notify(Notice::NotReconnected {
            key: "k".into(),
            name: "Office VPN".into(),
            why: Skip::DirectlyReachable(IpPrefix::parse("10.20.30.0/24").unwrap())
        })]
    );
}

#[test]
fn no_network_waits_for_a_change() {
    let mut p = slept_planner();
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
    assert!(p.evaluate(t0().adding(5.0), &NetworkSnapshot::default(), &on, false).is_empty());
    assert!(!p.due(t0().adding(500.0)), "waits for a network change, not a timer");
    p.network_changed(t0().adding(600.0));
    assert!(p.due(t0().adding(600.0 + SETTLE)));
    assert_eq!(p.evaluate(t0().adding(605.0), &home(), &on, false), vec![Action::Connect("k".into())]);
}

#[test]
fn a_drop_while_the_network_is_down_is_a_candidate() {
    let mut p = Planner::default();
    p.connect_started("k", fingerprint(&home()), false);
    p.connected("k", VpnNetworks::default());
    // Another candidate's evaluation saw no network.
    p.connect_started("j", fingerprint(&home()), false);
    p.connected("j", VpnNetworks::default());
    p.network_changed(t0());
    p.dropped("j", "Other VPN", t0().adding(1.0), FailureKind::NetworkLost);
    assert!(p.evaluate(t0().adding(5.0), &NetworkSnapshot::default(), &on, false).is_empty());
    // Long after the change, but the network is still down.
    p.dropped("k", "Office VPN", t0().adding(500.0), FailureKind::NetworkLost);
    assert!(p.due(t0().adding(500.0 + SETTLE)));
}

/// A drop long after a wake on a stable network is a tunnel that died under a connection that should be up (the
/// engine exited, `--ping-exit`, DPD; maintainer goal 2026-10-28): reconnected, at most `MAX_DEAD_RECONNECTS` times
/// until it has worked for `DEAD_STABLE`. A refused sign-in never.
#[test]
fn a_drop_long_after_wake_on_a_stable_network_is_reconnected_up_to_the_limit() {
    let mut p = slept_planner();
    let mut t = WAKE_WINDOW + 1.0;
    for attempt in 1..=MAX_DEAD_RECONNECTS {
        p.dropped("k", "Office VPN", t0().adding(t), FailureKind::ServerNotResponding);
        assert!(p.due(t0().adding(t + SETTLE)), "drop {attempt}");
        assert_eq!(p.evaluate(t0().adding(t + SETTLE), &home(), &on, false), [Action::Connect("k".into())]);
        p.connected("k", VpnNetworks::default());
        t += 60.0;
    }
    p.dropped("k", "Office VPN", t0().adding(t), FailureKind::Unknown);
    assert!(!p.due(t0().adding(t + 100.0)), "the limit");
    // Working for DEAD_STABLE since the last one: the count starts over.
    p.dropped("k", "Office VPN", t0().adding(t + DEAD_STABLE), FailureKind::Unknown);
    assert!(p.due(t0().adding(t + DEAD_STABLE + SETTLE)));
    let mut q = slept_planner();
    q.dropped("k", "Office VPN", t0().adding(WAKE_WINDOW + 1.0), FailureKind::AuthFailed);
    assert!(!q.due(t0().adding(WAKE_WINDOW + 100.0)));
}

#[test]
fn a_drop_soon_after_a_network_change_is_a_candidate_without_sleep() {
    let mut p = Planner::default();
    p.connect_started("k", fingerprint(&home()), false);
    p.connected("k", VpnNetworks::default());
    p.network_changed(t0());
    p.dropped("k", "Office VPN", t0().adding(20.0), FailureKind::NetworkLost);
    assert!(p.due(t0().adding(20.0 + SETTLE)));
}

#[test]
fn the_user_wins() {
    let mut p = slept_planner();
    p.user_disconnected("k");
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
    assert!(!p.due(t0().adding(10.0)));
    // A new connect by the user arms it again.
    p.connect_started("k", fingerprint(&home()), false);
    p.connected("k", VpnNetworks::default());
    p.network_changed(t0().adding(100.0));
    p.dropped("k", "Office VPN", t0().adding(101.0), FailureKind::NetworkLost);
    assert!(p.due(t0().adding(101.0 + SETTLE)));
    // A user connect while it is a candidate cancels the candidate; so does deleting it.
    p.connect_started("k", fingerprint(&home()), false);
    assert!(!p.due(t0().adding(200.0)));
    p.connected("k", VpnNetworks::default());
    p.network_changed(t0().adding(300.0));
    p.dropped("k", "Office VPN", t0().adding(301.0), FailureKind::NetworkLost);
    p.forget("k");
    assert!(!p.due(t0().adding(400.0)));
}

#[test]
fn the_planners_own_connect_keeps_the_candidate() {
    let mut p = slept_planner();
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
    assert_eq!(p.evaluate(t0().adding(5.0), &home(), &on, false), vec![Action::Connect("k".into())]);
    p.connect_started("k", fingerprint(&home()), true);
    assert!(p.is_attempting("k"));
}

#[test]
fn switched_off_and_refused_credentials_are_not_retried() {
    let mut p = slept_planner();
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
    assert!(p.evaluate(t0().adding(5.0), &home(), &|_| false, false).is_empty());
    assert!(!p.due(t0().adding(60.0)));
    let mut p = slept_planner();
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::AuthFailed);
    assert!(!p.due(t0().adding(10.0)));
    let mut p = slept_planner();
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::CertificateProblem);
    assert!(!p.due(t0().adding(10.0)));
}

#[test]
fn three_attempts_then_the_slow_tier_with_one_notice() {
    with_language(AppLanguage::En, || {
        let mut p = slept_planner();
        p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
        let mut now = t0().adding(5.0);
        for attempt in 1..=3 {
            assert_eq!(p.evaluate(now, &home(), &on, false), vec![Action::Connect("k".into())], "attempt {attempt}");
            let actions = p.failed("k", now.adding(2.0), FailureKind::ServerUnreachable);
            if attempt < 3 {
                assert!(actions.is_empty());
                assert!(!p.due(now.adding(3.0)));
                now = now.adding(if attempt == 1 { 12.0 } else { 32.0 });
                assert!(p.due(now));
            } else {
                // The fast attempts are over: the slow tier (every 5 minutes for an hour), one notice.
                assert_eq!(
                    actions,
                    vec![Action::Notify(Notice::KeepsTrying {
                        key: "k".into(),
                        name: "Office VPN".into(),
                        reason: Some("The server could not be reached.".into())
                    })]
                );
            }
        }
        assert!(!p.due(now.adding(2.0 + SLOW_RETRY - 1.0)));
        assert!(p.due(now.adding(2.0 + SLOW_RETRY)));
    });
}

#[test]
fn a_refused_sign_in_ends_the_attempts_at_once() {
    with_language(AppLanguage::En, || {
        let mut p = slept_planner();
        p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
        assert_eq!(p.evaluate(t0().adding(5.0), &home(), &on, false), vec![Action::Connect("k".into())]);
        assert_eq!(
            p.failed("k", t0().adding(7.0), FailureKind::AuthFailed),
            vec![Action::Notify(Notice::ReconnectFailed {
                key: "k".into(),
                name: "Office VPN".into(),
                reason: Some("The server refused the sign-in.".into())
            })]
        );
        assert!(!p.due(t0().adding(100.0)));
    });
}

#[test]
fn a_failure_not_of_our_attempt_is_ignored() {
    let mut p = slept_planner();
    assert!(p.failed("k", t0().adding(5.0), FailureKind::ServerUnreachable).is_empty());
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
    assert!(p.failed("k", t0().adding(5.0), FailureKind::ServerUnreachable).is_empty(), "not attempting yet");
    assert!(p.due(t0().adding(5.0)));
}

#[test]
fn a_locked_vault_is_reported() {
    let mut p = slept_planner();
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
    let actions = p.evaluate(t0().adding(5.0), &home(), &on, true);
    assert_eq!(
        actions,
        vec![Action::Notify(Notice::NotReconnected {
            key: "k".into(),
            name: "Office VPN".into(),
            why: Skip::VaultLocked
        })]
    );
}

#[test]
fn a_locked_vault_without_a_network_waits_for_the_network() {
    let mut p = slept_planner();
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
    assert!(p.evaluate(t0().adding(5.0), &NetworkSnapshot::default(), &on, true).is_empty());
    p.network_changed(t0().adding(50.0));
    // Unlocked in the meantime.
    assert_eq!(p.evaluate(t0().adding(55.0), &home(), &on, false), vec![Action::Connect("k".into())]);
}

#[test]
fn without_a_sleep_announcement_the_wake_uses_the_states_it_sees() {
    let mut p = Planner::default();
    p.connect_started("k", fingerprint(&home()), false);
    p.connected("k", VpnNetworks::default());
    p.wake(t0(), &["k".to_string()]);
    p.dropped("k", "Office VPN", t0().adding(30.0), FailureKind::ServerNotResponding);
    assert!(p.due(t0().adding(30.0 + SETTLE)));
}

#[test]
fn a_surviving_tunnel_on_the_vpns_own_network_is_disconnected_once() {
    let mut p = slept_planner(); // "k" routes 10.20.30.0/24, up before the sleep, woke at t0
    assert!(!p.survivors_due(t0().adding(1.0)));
    assert!(p.survivors_due(t0().adding(SETTLE)));
    let actions = p.survivors(t0().adding(SETTLE), &office(), &["k".to_string()]);
    assert_eq!(
        actions,
        vec![
            Action::Disconnect("k".into()),
            Action::Notify(Notice::DisconnectedHere {
                key: "k".into(),
                why: Skip::DirectlyReachable(IpPrefix::parse("10.20.30.0/24").unwrap())
            }),
        ]
    );
    assert!(!p.survivors_due(t0().adding(60.0)), "once per wake");
    // The app's disconnect is a user disconnect: no reconnect afterwards.
    p.dropped("k", "Office VPN", t0().adding(10.0), FailureKind::Unknown);
    assert!(!p.due(t0().adding(20.0)));
}

#[test]
fn a_surviving_tunnel_whose_dns_server_is_here_is_disconnected() {
    let mut p = Planner::default();
    p.connect_started("k", fingerprint(&home()), false);
    p.connected("k", VpnNetworks::from_config(macvpn_core::models::VPNKind::Openvpn, "dhcp-option DNS 10.20.30.53\n"));
    p.sleep(&["k".to_string()], fingerprint(&home()));
    p.wake(t0(), &["k".to_string()]);
    assert_eq!(
        p.survivors(t0().adding(SETTLE), &office(), &["k".to_string()]),
        vec![
            Action::Disconnect("k".into()),
            Action::Notify(Notice::DisconnectedHere {
                key: "k".into(),
                why: Skip::DnsDirectlyReachable("10.20.30.53".parse().unwrap())
            }),
        ]
    );
}

#[test]
fn a_surviving_tunnel_elsewhere_is_left_alone() {
    let mut p = slept_planner();
    assert!(p.survivors(t0().adding(SETTLE), &cafe(), &["k".to_string()]).is_empty());
    assert!(!p.survivors_due(t0().adding(60.0)));
}

#[test]
fn only_connections_still_up_and_up_before_sleep_are_checked() {
    let mut p = slept_planner();
    // "k" is no longer connected (it dropped: the reconnect rules apply), "other" was not up before the sleep.
    assert!(p.survivors(t0().adding(SETTLE), &office(), &["other".to_string()]).is_empty());
}

#[test]
fn without_a_network_the_survivor_check_waits_for_a_change() {
    let mut p = slept_planner();
    assert!(p.survivors(t0().adding(SETTLE), &NetworkSnapshot::default(), &["k".to_string()]).is_empty());
    assert!(!p.survivors_due(t0().adding(30.0)));
    p.network_changed(t0().adding(40.0));
    assert!(p.survivors_due(t0().adding(40.0 + SETTLE)));
    assert_eq!(p.survivors(t0().adding(45.0), &office(), &["k".to_string()]).len(), 2);
    // After WAKE_WINDOW a network change no longer triggers it.
    let mut late = slept_planner();
    late.survivors(t0().adding(SETTLE), &NetworkSnapshot::default(), &["k".to_string()]);
    late.network_changed(t0().adding(WAKE_WINDOW + 1.0));
    assert!(!late.survivors_due(t0().adding(WAKE_WINDOW + 10.0)));
}

#[test]
fn a_network_change_while_connected_does_not_check_survivors_without_a_wake() {
    let mut p = Planner::default();
    p.connect_started("k", fingerprint(&home()), false);
    p.connected(
        "k",
        VpnNetworks::from_config(macvpn_core::models::VPNKind::Openvpn, "route 10.20.30.0 255.255.255.0\n"),
    );
    p.network_changed(t0());
    assert!(!p.survivors_due(t0().adding(SETTLE)));
}

#[test]
fn the_fingerprint_is_refreshed_at_sleep() {
    let mut p = Planner::default();
    p.connect_started("k", None, false); // the probe failed when it started
    p.connected("k", VpnNetworks::default());
    p.sleep(&["k".to_string()], fingerprint(&home()));
    p.wake(t0(), &["k".to_string()]);
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
    assert_eq!(p.evaluate(t0().adding(5.0), &home(), &on, false), vec![Action::Connect("k".into())]);
    let _ = Fingerprint { gateway: "192.168.1.1".parse().unwrap(), gateway_mac: MAC, ssid: None };
}

#[test]
fn an_unidentified_start_is_not_reconnected() {
    let mut p = Planner::default();
    p.connect_started("k", None, false);
    p.connected("k", VpnNetworks::default());
    p.network_changed(t0());
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
    assert_eq!(
        p.evaluate(t0().adding(5.0), &home(), &on, false),
        vec![Action::Notify(Notice::NotReconnected {
            key: "k".into(),
            name: "Office VPN".into(),
            why: Skip::Unidentified
        })]
    );
}

/// "k" started by the control API under a lease (the app brackets the lease's connect), up at home when the
/// system slept.
fn lease_slept_planner() -> Planner {
    let mut p = Planner::default();
    p.lease_connect_began("k");
    p.connect_started("k", fingerprint(&home()), false);
    p.lease_connect_ended("k");
    p.connected("k", VpnNetworks::default());
    p.sleep(&["k".to_string()], fingerprint(&home()));
    p.wake(t0(), &["k".to_string()]);
    p
}

#[test]
fn a_connection_a_lease_started_is_not_reconnected_after_a_drop_at_wake() {
    // The drop ends its leases; the controlling app may be gone after the wake: nothing brings it back.
    let mut p = lease_slept_planner();
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::ServerNotResponding);
    assert!(!p.due(t0().adding(10.0)));
    assert!(p.evaluate(t0().adding(10.0), &home(), &on, false).is_empty());
}

#[test]
fn a_connection_a_lease_started_is_not_reconnected_after_a_network_change() {
    let mut p = Planner::default();
    p.lease_connect_began("k");
    p.connect_started("k", fingerprint(&home()), false);
    p.connected("k", VpnNetworks::default());
    p.lease_connect_ended("k");
    p.network_changed(t0());
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
    assert!(!p.due(t0().adding(10.0)));
}

#[test]
fn the_users_own_connect_after_a_lease_makes_it_reconnectable_again() {
    let mut p = lease_slept_planner();
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::ServerNotResponding);
    // The user connects it from the menu: it is the user's connection now.
    p.connect_started("k", fingerprint(&home()), false);
    p.connected("k", VpnNetworks::default());
    p.network_changed(t0().adding(20.0));
    p.dropped("k", "Office VPN", t0().adding(21.0), FailureKind::NetworkLost);
    assert_eq!(p.evaluate(t0().adding(25.0), &home(), &on, false), vec![Action::Connect("k".into())]);
}

#[test]
fn a_refused_lease_connect_leaves_no_mark() {
    // The lease's connect never started (setup required, locked): the user's later connect is the user's.
    let mut p = Planner::default();
    p.lease_connect_began("k");
    p.lease_connect_ended("k");
    p.connect_started("k", fingerprint(&home()), false);
    p.connected("k", VpnNetworks::default());
    p.network_changed(t0());
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
    assert_eq!(p.evaluate(t0().adding(5.0), &home(), &on, false), vec![Action::Connect("k".into())]);
}

/// LinVPN (audit C1): stopped outside the app (GNOME's menu, `nmcli connection down`) is the user's stop: never
/// reconnected (also not after a later drop of the planner's knowledge), no notice; a connect of the user's own
/// starts over.
#[test]
fn a_stop_outside_the_app_is_a_user_disconnect() {
    let mut p = slept_planner();
    p.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::StoppedByUser);
    assert!(!p.due(t0().adding(100.0)));
    assert!(p.evaluate(t0().adding(100.0), &home(), &on, false).is_empty());
    assert!(p.take_actions().is_empty(), "no notice");
    // Our own attempt cancelled from GNOME's menu: no "could not reconnect", no further attempts.
    let mut q = slept_planner();
    q.dropped("k", "Office VPN", t0().adding(1.0), FailureKind::NetworkLost);
    assert_eq!(q.evaluate(t0().adding(5.0), &home(), &on, false), vec![Action::Connect("k".into())]);
    assert!(q.failed("k", t0().adding(7.0), FailureKind::StoppedByUser).is_empty());
    assert!(!q.due(t0().adding(1000.0)));
    // Off as after a disconnect in the app: a wake does not bring it back.
    q.sleep(&[], fingerprint(&home()));
    q.wake(t0().adding(2000.0), &[]);
    assert!(q.evaluate(t0().adding(2100.0), &home(), &on, false).is_empty());
}
