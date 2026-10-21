//! Port of `NativeVPNTests.swift` (the start-option tests are in the core: `native::start_options`; the
//! controller-level ones are here).
#![cfg(target_os = "macos")]

use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::models::{ConnectionState, Secrets, parse_uuid};
use macvpn_core::native::NativeKind;
use macvpn_platform_mac::command::CommandResult;
use macvpn_platform_mac::native_vpn::{NativeDriverError, NativeVPNController, ScutilParser, SystemVPNService};
use macvpn_platform_mac::testing::{MockCommandRunner, MockNativeDriver, NativeStart};
use std::collections::BTreeMap;

const SAMPLE: &str = r#"Available network connection services in the current set (*=enabled):
* (Disconnected)   BB566669-2725-4F23-9181-0AC6F242F1CF PPP --> XR21B1411  "XR21B1411"                      [PPP:Modem]
* (Disconnected)   38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4 PPP --> L2TP       "Office L2TP"                        [PPP:L2TP]
* (Connected)      052ED352-624D-4F75-BD84-D3E278CFD84F VPN (com.wireguard.macos) "Home"                           [VPN:com.wireguard.macos]
  (Connecting)     AAAAAAAA-624D-4F75-BD84-D3E278CFD84F IPSec              "Partner Cisco"                  [IPSec]"#;

#[test]
fn parse_remote_address() {
    assert_eq!(
        ScutilParser::remote_address(
            "PPP <dictionary> {\n  AuthName : bob\n  CommRemoteAddress : vpn.example.com\n}\n"
        )
        .as_deref(),
        Some("vpn.example.com")
    );
    assert_eq!(
        ScutilParser::remote_address("IPSec <dictionary> {\n  LocalIdentifier : g\n  RemoteAddress : 1.2.3.4 \n}\n")
            .as_deref(),
        Some("1.2.3.4")
    );
    assert_eq!(ScutilParser::remote_address("PPP <dictionary> {\n  AuthName : bob\n}\n"), None);
    // An empty value is skipped; an IPv6 address keeps its colons (one split only).
    assert_eq!(
        ScutilParser::remote_address("  RemoteAddress :\n  CommRemoteAddress : fd00::1\n").as_deref(),
        Some("fd00::1")
    );
}

#[test]
fn parse_list_filters_vpns() {
    let list = ScutilParser::parse_list(SAMPLE);
    assert_eq!(list.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["Office L2TP", "Home", "Partner Cisco"]);
    assert_eq!(list[0].id, "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4");
    assert_eq!(list[0].type_label, "L2TP");
    assert_eq!(list[1].type_label, "WireGuard (app)");
    assert_eq!(list[2].type_label, "Cisco IPsec");
    assert_eq!(list[0].connection_state(), ConnectionState::Disconnected);
    assert_eq!(list[1].connection_state(), ConnectionState::Connected { ip: None, since: None });
    assert_eq!(list[2].connection_state(), ConnectionState::Connecting);
}

#[test]
fn type_labels() {
    assert_eq!(ScutilParser::type_label("IKEv2"), Some("IKEv2"));
    assert_eq!(ScutilParser::type_label("VPN:net.tunnelblick.tunnelblick"), Some("OpenVPN (app)"));
    assert_eq!(ScutilParser::type_label("VPN:com.example"), Some("VPN"));
    assert_eq!(ScutilParser::type_label("PPP:Modem"), None);
    let s = |status: &str| SystemVPNService {
        id: "x".into(),
        name: "n".into(),
        type_label: "L2TP".into(),
        status: status.into(),
    };
    assert_eq!(s("Disconnecting").connection_state(), ConnectionState::Disconnecting);
    assert_eq!(s("Invalid").connection_state(), ConnectionState::Disconnected);
}

#[test]
fn start_stop_go_through_driver_not_scutil() {
    let c = NativeVPNController::new(MockCommandRunner::new(), MockNativeDriver::new());
    c.start("38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4", None, &Secrets::default()).unwrap();
    c.stop("38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4").unwrap();
    assert!(c.runner().calls().is_empty(), "no scutil start/stop (secrets must never reach argv)");
    assert_eq!(
        c.driver().starts(),
        [NativeStart { service_id: "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4".into(), options: None, linger: true }]
    );
    assert_eq!(c.driver().stops(), ["38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4"]);
}

#[test]
fn start_lingers() {
    // The VPN must survive a MacVPN quit ("keep running"), so the in-process start lingers.
    const { assert!(NativeVPNController::<MockCommandRunner, MockNativeDriver>::LINGER) };
}

#[test]
fn start_passes_options_for_kind() {
    let c = NativeVPNController::new(MockCommandRunner::new(), MockNativeDriver::new());
    let secrets = Secrets { password: Some("pw".into()), psk: Some("k".into()), ..Secrets::default() };
    c.start("S", Some(NativeKind::L2tp), &secrets).unwrap();
    let start = &c.driver().starts()[0];
    let mut expected = BTreeMap::new();
    expected.insert("IPSec", BTreeMap::from([("SharedSecret", "k".to_string())]));
    expected.insert("PPP", BTreeMap::from([("AuthPassword", "pw".to_string())]));
    assert_eq!(start.options.as_ref(), Some(&expected));
    assert!(start.linger);
    // Without a kind no options, even with secrets.
    c.start("S", None, &secrets).unwrap();
    assert_eq!(c.driver().starts()[1].options, None);
}

#[test]
fn start_error_propagates() {
    let driver = MockNativeDriver::new();
    *driver.start_error.lock().unwrap() = Some("nem indul".into());
    let c = NativeVPNController::new(MockCommandRunner::new(), driver);
    let error = c.start("S", None, &Secrets::default()).unwrap_err();
    assert_eq!(error.to_string(), "nem indul");
}

#[test]
fn driver_error_message_is_localized() {
    with_language(AppLanguage::Hu, || {
        assert_eq!(
            NativeDriverError::Start("No service".into()).to_string(),
            "A VPN szolgáltatás nem indítható: No service"
        );
        assert_eq!(
            NativeDriverError::Stop("No service".into()).to_string(),
            "A VPN szolgáltatás nem állítható le: No service"
        );
        assert_eq!(
            NativeDriverError::Open("No service".into()).to_string(),
            "A VPN szolgáltatás nem nyitható meg: No service"
        );
    });
}

#[test]
fn native_kind_mapping() {
    use macvpn_core::models::VPNKind;
    assert_eq!(NativeKind::from_kind(VPNKind::L2tp), Some(NativeKind::L2tp));
    assert_eq!(NativeKind::from_kind(VPNKind::Cisco), Some(NativeKind::CiscoIPSec));
    assert_eq!(NativeKind::from_kind(VPNKind::Openvpn), None);
    assert_eq!(NativeKind::from_type_label("L2TP"), Some(NativeKind::L2tp));
    assert_eq!(NativeKind::from_type_label("Cisco IPsec"), Some(NativeKind::CiscoIPSec));
    assert_eq!(NativeKind::from_type_label("IKEv2"), None);
    assert_eq!(NativeKind::from_type_label("WireGuard (app)"), None);
}

#[test]
fn system_service_secret_support() {
    let l2tp = SystemVPNService {
        id: "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4".into(),
        name: "Office".into(),
        type_label: "L2TP".into(),
        status: "Disconnected".into(),
    };
    assert_eq!(l2tp.secret_id(), parse_uuid("38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4"));
    assert!(l2tp.supports_stored_secrets());
    let bad = SystemVPNService {
        id: "not-a-uuid".into(),
        name: "X".into(),
        type_label: "L2TP".into(),
        status: "Disconnected".into(),
    };
    assert_eq!(bad.secret_id(), None);
    assert!(!bad.supports_stored_secrets());
    let wg = SystemVPNService {
        id: "052ED352-624D-4F75-BD84-D3E278CFD84F".into(),
        name: "Home".into(),
        type_label: "WireGuard (app)".into(),
        status: "Connected".into(),
    };
    assert!(!wg.supports_stored_secrets());
}

#[test]
fn name_with_quotes_and_apostrophe() {
    let line =
        r#"* (Disconnected)   38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4 PPP --> L2TP       "Bob's "work" VPN"   [PPP:L2TP]"#;
    assert_eq!(
        ScutilParser::parse_list(line).iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
        [r#"Bob's "work" VPN"#]
    );
}

#[test]
fn list_throws_on_non_zero_exit() {
    with_language(AppLanguage::Hu, || {
        let mock = MockCommandRunner::new();
        mock.respond("/usr/sbin/scutil --nc list", CommandResult::exit(1));
        let error = NativeVPNController::new(mock, MockNativeDriver::new()).list().unwrap_err();
        assert_eq!(error.to_string(), "scutil hiba (kilépési kód: 1)");
        // stderr + stdout is the message when present.
        let mock = MockCommandRunner::new();
        mock.respond("/usr/sbin/scutil --nc list", CommandResult::new(2, "out\n", "err "));
        assert_eq!(NativeVPNController::new(mock, MockNativeDriver::new()).list().unwrap_err().to_string(), "err out");
    });
}

#[test]
fn list_and_remote_address_use_scutil() {
    let mock = MockCommandRunner::new();
    mock.respond("/usr/sbin/scutil --nc list", CommandResult::stdout(SAMPLE));
    mock.respond("/usr/sbin/scutil --nc show S", CommandResult::stdout("  CommRemoteAddress : vpn.example.com\n"));
    mock.respond("/usr/sbin/scutil --nc show F", CommandResult::new(1, "  RemoteAddress : x\n", ""));
    let c = NativeVPNController::new(mock, MockNativeDriver::new());
    assert_eq!(c.list().unwrap().len(), 3);
    assert_eq!(c.remote_address("S").as_deref(), Some("vpn.example.com"));
    assert_eq!(c.remote_address("F"), None);
}
