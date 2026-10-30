//! L-b Task 22, the pure parts (every OS): which NetworkManager profiles are system VPNs and how they are labelled,
//! and `NativeSupport`'s Linux reasons and editor notes over `nm_plan`. On Linux the engine's `NativeSupport` is
//! checked too (built without a bus: it reads only `nm_plan` and the cached caps).
use macvpn_core::models::{Connection, NativeSettings, VPNKind};
use macvpn_core::nm_plan::{Caps, Input};
use macvpn_platform_linux::pure::nm::state::{ActiveState, VpnState};
use macvpn_platform_linux::pure::nm::support::{editor_notes, unsupported_reason};
use macvpn_platform_linux::pure::nm::system_vpn::{
    is_linvpn_made, is_listed, remote_address, secret_keys, status, type_label,
};
use std::collections::BTreeMap;
use std::path::Path;

#[test]
fn labels_follow_the_plugin() {
    assert_eq!(type_label("vpn", Some("org.freedesktop.NetworkManager.l2tp")), "L2TP");
    assert_eq!(type_label("vpn", Some("org.freedesktop.NetworkManager.vpnc")), "Cisco IPsec");
    assert_eq!(type_label("vpn", Some("org.freedesktop.NetworkManager.strongswan")), "IKEv2");
    assert_eq!(type_label("vpn", Some("org.freedesktop.NetworkManager.openvpn")), "OpenVPN (app)");
    assert_eq!(type_label("wireguard", None), "WireGuard (app)");
    assert_eq!(type_label("vpn", Some("org.freedesktop.NetworkManager.sstp")), "VPN");
    assert_eq!(type_label("vpn", None), "VPN");
}

#[test]
fn only_visible_non_linvpn_profiles_are_system_vpns() {
    assert!(is_listed("vpn", &["user:linvpn-dev".into()], 0, "linvpn-dev", false));
    assert!(is_listed("vpn", &["user:linvpn-dev:".into()], 0, "linvpn-dev", false), "NM's reserved third field");
    assert!(is_listed("wireguard", &[], 0, "linvpn-dev", false), "all users");
    assert!(!is_listed("vpn", &["user:other".into()], 0, "linvpn-dev", false));
    assert!(!is_listed("vpn", &["user:linvpn-dev-2".into()], 0, "linvpn-dev", false));
    assert!(!is_listed("vpn", &[], 4, "linvpn-dev", false), "volatile: LinVPN's or another app's in-memory one");
    assert!(!is_listed("wireguard", &[], 8, "linvpn-dev", false), "external (wg-quick)");
    assert!(!is_listed("vpn", &[], 0, "linvpn-dev", true), "a LinVPN-derived UUID");
    assert!(!is_listed("802-3-ethernet", &[], 0, "linvpn-dev", false));
}

#[test]
fn linvpns_own_connections_are_recognized() {
    let derived = macvpn_core::nm_plan::names::nm_uuid(1001, &uuid::Uuid::new_v4()).to_string();
    assert!(is_linvpn_made(&derived, "Office"));
    assert!(is_linvpn_made("6f1c0a52-3b7e-4c1d-9a2f-0e8d7c6b5a49", "linvpn-6F1C0A52-3B7E-4C1D-9A2F-0E8D7C6B5A49"));
    assert!(!is_linvpn_made("6f1c0a52-3b7e-4c1d-9a2f-0e8d7c6b5a49", "Office VPN"));
}

#[test]
fn the_server_address_per_plugin() {
    let d = |k: &str, v: &str| BTreeMap::from([(k.to_string(), v.to_string())]);
    assert_eq!(
        remote_address(Some("org.freedesktop.NetworkManager.l2tp"), &d("gateway", "vpn.example.com")),
        Some("vpn.example.com".into())
    );
    assert_eq!(
        remote_address(Some("org.freedesktop.NetworkManager.vpnc"), &d("IPSec gateway", "198.51.100.7")),
        Some("198.51.100.7".into())
    );
    assert_eq!(
        remote_address(
            Some("org.freedesktop.NetworkManager.openvpn"),
            &d("remote", "a.example.com:1194:udp, b.example.com")
        ),
        Some("a.example.com".into())
    );
    assert_eq!(
        remote_address(Some("org.freedesktop.NetworkManager.strongswan"), &d("address", "vpn.example.com")),
        Some("vpn.example.com".into())
    );
    assert_eq!(remote_address(None, &d("endpoint", "vpn.example.com:51820")), Some("vpn.example.com".into()));
    assert_eq!(remote_address(None, &d("endpoint", "[2001:db8::1]:51820")), Some("2001:db8::1".into()));
    assert_eq!(remote_address(Some("org.freedesktop.NetworkManager.l2tp"), &BTreeMap::new()), None);
    assert_eq!(remote_address(Some("org.example.unknown"), &d("gateway", "vpn.example.com")), None);
}

#[test]
fn states_and_secret_keys() {
    assert_eq!(status(ActiveState::Activated, Some(VpnState::Activated)), "Connected");
    assert_eq!(status(ActiveState::Activated, None), "Connected");
    assert_eq!(status(ActiveState::Activated, Some(VpnState::Connect)), "Connecting");
    assert_eq!(status(ActiveState::Activating, Some(VpnState::Prepare)), "Connecting");
    assert_eq!(status(ActiveState::Deactivating, Some(VpnState::Activated)), "Disconnecting");
    assert_eq!(status(ActiveState::Activated, Some(VpnState::Failed)), "Disconnected");
    assert_eq!(status(ActiveState::Deactivated, None), "Disconnected");
    assert_eq!(secret_keys(Some("org.freedesktop.NetworkManager.l2tp")), Some(("password", "ipsec-psk")));
    assert_eq!(secret_keys(Some("org.freedesktop.NetworkManager.vpnc")), Some(("Xauth password", "IPSec secret")));
    assert_eq!(secret_keys(Some("org.freedesktop.NetworkManager.openvpn")), None);
    assert_eq!(secret_keys(None), None);
}

// ---- NativeSupport over nm_plan ----

const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";

fn ovpn(extra: &str) -> String {
    format!(
        "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nauth-user-pass\nremote-cert-tls server\ndata-ciphers AES-256-GCM:CHACHA20-POLY1305\n<ca>\n{CA}\n</ca>\n{extra}"
    )
}

fn swan_split() -> String {
    "connections {\n  lab {\n    remote_addrs = vpn.example.com\n    vips = 0.0.0.0\n    local {\n      auth = eap-mschapv2\n      eap_id = alice\n    }\n    remote {\n      auth = pubkey\n      id = vpn.example.com\n    }\n    children {\n      lab {\n        remote_ts = 10.99.0.0/24\n      }\n    }\n  }\n}\n".into()
}

fn caps() -> Caps {
    Caps { openvpn_push_visible: true, strongswan_remote_ts: true, ..Caps::default() }
}

fn input<'a>(c: &'a Connection, config: &'a str, caps: &'a Caps) -> Input<'a> {
    Input {
        connection: c,
        config: config.as_bytes(),
        user: "linvpn-dev",
        uid: 1001,
        runtime_dir: Path::new("/run/user/1001/linvpn/nm/x"),
        caps,
        client_cert: macvpn_core::nm_plan::ImportedCert::None,
    }
}

fn l2tp() -> Connection {
    let mut c = Connection::new("Office", VPNKind::L2tp);
    c.native = Some(NativeSettings {
        server: "vpn.example.com".into(),
        account: "alice".into(),
        group_name: String::new(),
        send_all_traffic: true,
    });
    c
}

#[test]
fn a_linux_refusal_is_the_reason_a_valid_or_invalid_config_is_none() {
    let c = Connection::new("Office", VPNKind::Openvpn);
    let caps = caps();
    let config = ovpn("peer-fingerprint AB:CD\n");
    let reason = unsupported_reason(&input(&c, &config, &caps)).expect("a Linux reason");
    assert!(reason.contains("peer-fingerprint"), "{reason}");
    let config = ovpn("");
    assert_eq!(unsupported_reason(&input(&c, &config, &caps)), None);
    let config = ovpn("up /bin/sh\n");
    assert_eq!(unsupported_reason(&input(&c, &config, &caps)), None, "the validator's issue");

    let notes = editor_notes(&input(&c, &ovpn("peer-fingerprint AB:CD\n"), &caps));
    assert!(notes.reasons.iter().any(|r| r.contains("peer-fingerprint")), "{notes:?}");
    assert!(!notes.no_install_step);
}

#[test]
fn ikev2_split_without_remote_ts_support_is_a_reason() {
    let c = Connection::new("IKE", VPNKind::Strongswan);
    let config = swan_split();
    let without = Caps { strongswan_remote_ts: false, ..caps() };
    let reason = unsupported_reason(&input(&c, &config, &without)).expect("a Linux reason");
    assert!(reason.contains("remote_ts"), "{reason}");
    assert_eq!(unsupported_reason(&input(&c, &config, &caps())), None);
}

#[test]
fn the_editor_notes_carry_the_summary_and_warnings() {
    // `sndbuf` is the validator's RISKY finding on Linux (Task 6), not a plan warning; an argument NM cannot express
    // is the plan's warning.
    let c = Connection::new("Office", VPNKind::Openvpn);
    let caps = caps();
    let config = ovpn("redirect-gateway def1 block-local\n");
    let notes = editor_notes(&input(&c, &config, &caps));
    assert!(notes.reasons.is_empty(), "{notes:?}");
    assert!(notes.warnings.iter().any(|w| w.contains("block-local")), "{notes:?}");
    assert!(notes.summary.is_some());

    let c = l2tp();
    let notes = editor_notes(&input(&c, "", &caps));
    assert!(notes.no_install_step);
    assert!(notes.reasons.is_empty());
    assert!(notes.summary.as_deref().is_some_and(|s| s.contains("L2TP")), "{notes:?}");
    // A draft without a server: still saved without an install step, the validator speaks.
    let mut draft = l2tp();
    draft.native.as_mut().unwrap().server.clear();
    let notes = editor_notes(&input(&draft, "", &caps));
    assert!(notes.no_install_step && notes.reasons.is_empty());
    assert_eq!(unsupported_reason(&input(&draft, "", &caps)), None);
}

#[cfg(target_os = "linux")]
mod engine {
    use super::*;
    use macvpn_platform_api::NativeSupport;
    use macvpn_platform_linux::lin_for_tests::nm::engine::Engine;

    fn no_bus() -> zbus::Result<zbus::blocking::Connection> {
        Err(zbus::Error::Failure("no bus in this test".into()))
    }

    #[test]
    fn the_engine_answers_without_a_bus() {
        let tmp = std::env::temp_dir().join(format!("linvpn-nm-support-{}", uuid::Uuid::new_v4()));
        let e = Engine::new(no_bus, false, "linvpn-dev".into(), 1001, None, tmp.clone());
        let c = Connection::new("Office", VPNKind::Openvpn);
        let reason = e.unsupported_reason(&c, ovpn("peer-fingerprint AB:CD\n").as_bytes()).expect("a reason");
        assert!(reason.contains("peer-fingerprint"), "{reason}");
        assert_eq!(e.unsupported_reason(&c, ovpn("").as_bytes()), None);
        assert_eq!(e.unsupported_reason(&c, ovpn("up /bin/sh\n").as_bytes()), None);
        assert!(e.editor_notes(&l2tp(), b"").no_install_step);
        assert_eq!(e.system_psk_note(), None);
        let _ = std::fs::remove_dir_all(tmp);
    }
}
