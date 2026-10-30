//! NetworkManager's state numbers, the tunnel's root state and the reason lines (pure; every OS).
use macvpn_platform_linux::pure::nm::state::{ActiveState, STOPPED_LINE, VpnState, reason_line, root_state};

#[test]
fn numbers_map_to_states() {
    assert_eq!(ActiveState::from_u32(1), ActiveState::Activating);
    assert_eq!(ActiveState::from_u32(2), ActiveState::Activated);
    assert_eq!(ActiveState::from_u32(3), ActiveState::Deactivating);
    assert_eq!(ActiveState::from_u32(4), ActiveState::Deactivated);
    assert_eq!(ActiveState::from_u32(99), ActiveState::Unknown);
    assert_eq!(VpnState::from_u32(1), VpnState::Prepare);
    assert_eq!(VpnState::from_u32(2), VpnState::NeedAuth);
    assert_eq!(VpnState::from_u32(3), VpnState::Connect);
    assert_eq!(VpnState::from_u32(4), VpnState::IpConfigGet);
    assert_eq!(VpnState::from_u32(5), VpnState::Activated);
    assert_eq!(VpnState::from_u32(6), VpnState::Failed);
    assert_eq!(VpnState::from_u32(7), VpnState::Disconnected);
    assert_eq!(VpnState::from_u32(99), VpnState::Unknown);
}

#[test]
fn root_states() {
    assert_eq!(root_state(ActiveState::Activated, Some(VpnState::Activated)), Some("connected"));
    assert_eq!(root_state(ActiveState::Activated, None), Some("connected"), "WireGuard has no VPN state");
    assert_eq!(root_state(ActiveState::Activating, Some(VpnState::NeedAuth)), Some("connecting"));
    assert_eq!(root_state(ActiveState::Activating, None), Some("connecting"));
    assert_eq!(root_state(ActiveState::Activated, Some(VpnState::IpConfigGet)), Some("connecting"));
    assert_eq!(root_state(ActiveState::Deactivated, Some(VpnState::Failed)), None);
    assert_eq!(root_state(ActiveState::Activating, Some(VpnState::Failed)), None, "a failed VPN is down");
    assert_eq!(root_state(ActiveState::Deactivating, Some(VpnState::Activated)), None);
    assert_eq!(root_state(ActiveState::Unknown, None), None);
}

// The numbers are NM 1.54.3's `NMVpnConnectionStateReason` (= the first 12 of `NMActiveConnectionStateReason`),
// read on Ubuntu 26.04 through libnm's introspection data.
#[test]
fn failure_reasons_use_the_words_app_core_matches() {
    assert!(reason_line(10).contains("AUTH_FAILED"), "login failed");
    assert!(reason_line(9).contains("AUTH_FAILED"), "no secrets");
    assert!(reason_line(6).contains("Connection timed out"), "connect timeout");
    assert_eq!(reason_line(4), "NetworkManager: the VPN plugin did not start (service-stopped)");
    assert_eq!(reason_line(7), "NetworkManager: the VPN plugin did not start (service-start-timeout)");
    assert_eq!(reason_line(8), "NetworkManager: the VPN plugin did not start (service-start-failed)");
    // USER_DISCONNECTED: stopped outside LinVPN (GNOME's menu, `nmcli connection down`), the user's stop (C1).
    assert_eq!(reason_line(2), "NetworkManager: disconnected by the user");
    assert_eq!(reason_line(2), macvpn_app_core::failure_reason::USER_STOP_LINE);
    assert_eq!(reason_line(11), "NetworkManager: disconnected");
    assert_eq!(reason_line(11), STOPPED_LINE);
    let lines = |l: &str| vec![format!("2026-10-30 10:00:00 {l}")];
    assert!(macvpn_app_core::failure_reason::stopped_by_user(&lines(reason_line(2))));
    assert!(!macvpn_app_core::failure_reason::stopped_by_user(&lines(STOPPED_LINE)));
    assert_eq!(reason_line(5), "NetworkManager: the VPN failed (reason 5)");
    assert_eq!(reason_line(14), "NetworkManager: the VPN failed (reason 14)");
    assert_eq!(reason_line(99), "NetworkManager: the VPN failed (unknown reason)", "a static line for any number");
}
