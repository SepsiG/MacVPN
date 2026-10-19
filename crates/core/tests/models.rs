//! Port of `ModelsTests.swift` and the model parts of `OpenVPNTierTests` / `MFATests`.

use macvpn_core::date::Date;
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::models::*;
use macvpn_core::swift_json;

fn round_trip(c: &Connection) -> Connection {
    let text = swift_json::to_pretty_sorted(&c.to_json()).unwrap();
    Connection::from_json(&swift_json::parse(text.as_bytes()).unwrap()).unwrap()
}

#[test]
fn kind_display_names_and_native_flag() {
    assert_eq!(VPNKind::Openvpn.display_name(), "OpenVPN");
    assert_eq!(VPNKind::Wireguard.display_name(), "WireGuard");
    assert_eq!(VPNKind::Strongswan.display_name(), "IKEv2");
    assert_eq!(VPNKind::L2tp.display_name(), "L2TP");
    assert_eq!(VPNKind::Cisco.display_name(), "Cisco IPsec");
    assert!(VPNKind::L2tp.is_native());
    assert!(VPNKind::Cisco.is_native());
    assert!(!VPNKind::Openvpn.is_native());
    assert_eq!(VPNKind::Strongswan.raw_value(), "strongswan");
}

#[test]
fn connection_codable_round_trip() {
    let mut c = Connection::new("Iroda", VPNKind::Cisco);
    c.native = Some(NativeSettings {
        server: "vpn.example.com".into(),
        account: "bob".into(),
        group_name: "staff".into(),
        send_all_traffic: false,
    });
    let back = round_trip(&c);
    assert_eq!(back.id, c.id);
    assert_eq!(back.native.as_ref().unwrap().group_name, "staff");
    assert_eq!(back.kind, VPNKind::Cisco);
}

#[test]
fn connection_state_active() {
    assert!(ConnectionState::Connecting.is_active());
    assert!(ConnectionState::Connected { ip: None, since: None }.is_active());
    assert!(ConnectionState::Disconnecting.is_active());
    assert!(ConnectionState::AwaitingAuth(AuthWait { kind: AuthWaitKind::Code, deadline: None }).is_active());
    assert!(!ConnectionState::Disconnected.is_active());
    assert!(!ConnectionState::Failed("x".into()).is_active());
    assert!(ConnectionState::Connected { ip: Some("10.0.0.2".into()), since: Some(Date::now()) }.is_connected());
    assert!(!ConnectionState::Connecting.is_connected());
}

#[test]
fn secrets_stdin_payload_skips_empty_and_strips_newlines() {
    let s = Secrets {
        username: Some("bob".into()),
        password: Some("p\nw".into()),
        psk: Some(String::new()),
        ..Default::default()
    };
    assert_eq!(s.stdin_payload(), "username=bob\npassword=pw\n");
    assert_eq!(Secrets::default().stdin_payload(), "");
    let crlf = Secrets { password: Some("a\r\nb".into()), ..Default::default() };
    assert_eq!(crlf.stdin_payload(), "password=ab\n");
    // Stricter than Swift (whose replacingOccurrences keeps a line break a combining mark follows): every line
    // break goes, so a value cannot add a `key=value` line.
    let marked = Secrets { password: Some("pw\n\u{301}keypass=x".into()), ..Default::default() };
    assert_eq!(marked.stdin_payload(), "password=pw\u{301}keypass=x\n");
    let zwj = Secrets { password: Some("a\r\u{200D}\n\u{903}b\r\u{301}".into()), ..Default::default() };
    assert_eq!(zwj.stdin_payload(), "password=a\u{200D}\u{903}b\u{301}\n");
}

#[test]
fn secrets_input_error_rejects_control_characters() {
    let ok = Secrets {
        username: Some("bob@x.hu".into()),
        password: Some("pä ss\"\\w0rd".into()),
        psk: Some("k!".into()),
        ..Default::default()
    };
    assert_eq!(ok.input_error(), None);
    assert_eq!(Secrets::default().input_error(), None);
    for bad in ["a\nb", "a\rb", "a\tb", "a\u{0}b", "a\u{7F}b", "a\u{85}b", "a\u{2028}b"] {
        assert!(Secrets { username: Some(bad.into()), ..Default::default() }.input_error().is_some(), "{bad:?}");
        assert!(Secrets { password: Some(bad.into()), ..Default::default() }.input_error().is_some(), "{bad:?}");
        assert!(Secrets { psk: Some(bad.into()), ..Default::default() }.input_error().is_some(), "{bad:?}");
    }
    with_language(AppLanguage::Hu, || {
        assert_eq!(
            Secrets { psk: Some("a\nb".into()), ..Default::default() }.input_error().as_deref(),
            Some("A felhasználónév, a jelszó és a PSK nem tartalmazhat sortörést vagy vezérlőkaraktert")
        );
    });
}

/// `OpenVPNTierTests.testConnectionDecodesWithoutAcknowledgements`. (The Swift test decodes `createdAt: 0` with the
/// default `deferredToDate` strategy; `meta.json` always uses `.iso8601`, so the date is written that way here.)
#[test]
fn connection_decodes_without_acknowledgements() {
    let json = r#"{"id":"11111111-2222-3333-4444-555555555555","name":"x","kind":"openvpn","createdAt":"2001-01-01T00:00:00Z"}"#;
    let c = Connection::from_json(&swift_json::parse(json.as_bytes()).unwrap()).unwrap();
    assert!(c.acknowledged_risky_directives.is_empty());
    assert_eq!(c.created_at.time_interval_since_reference_date(), 0.0);
    let mut d = c.clone();
    d.acknowledged_risky_directives = vec!["group".into(), "user".into()];
    assert_eq!(round_trip(&d), d);
}

/// `OpenVPNTierTests.testKeyPasswordSecret` (model part; the Keychain part belongs to platform-mac).
#[test]
fn key_password_secret() {
    let s = Secrets {
        username: Some("u".into()),
        password: Some("p".into()),
        key_password: Some("k".into()),
        ..Default::default()
    };
    assert_eq!(s.stdin_payload(), "username=u\npassword=p\nkeypass=k\n");
    assert!(Secrets { key_password: Some("a\nb".into()), ..Default::default() }.input_error().is_some());
    assert!(Secrets { key_password: Some("a\u{7F}b".into()), ..Default::default() }.input_error().is_some());
    assert!(Secrets { key_password: Some("ok pass".into()), ..Default::default() }.input_error().is_none());
}

#[test]
fn otp_and_challenge_in_payload() {
    let s = Secrets {
        username: Some("bob".into()),
        password: Some("SCRV1:U3RhdFBhc3M=:MjQ2ODEw".into()),
        one_time_code: Some("246810".into()),
        challenge_packed: true,
        ..Default::default()
    };
    assert_eq!(s.stdin_payload(), "username=bob\npassword=SCRV1:U3RhdFBhc3M=:MjQ2ODEw\notp=246810\nchallenge=packed\n");
}

/// `MFATests.testOTPSettingBackwardCompatible`.
#[test]
fn otp_setting_backward_compatible() {
    let c = Connection::new("x", VPNKind::Openvpn);
    let mut dict = c.to_json();
    assert!(dict.get("otp").is_some());
    dict.as_object_mut().unwrap().remove("otp");
    let old = Connection::from_json(&dict).unwrap();
    assert_eq!(old.otp, OTPSetting::default());
    let mut on = c.clone();
    on.otp = OTPSetting::new(true, OTPSeparator::Colon);
    assert_eq!(round_trip(&on).otp, OTPSetting::new(true, OTPSeparator::Colon));
    let future =
        OTPSetting::from_json(&swift_json::parse(br#"{"enabled":true,"separator":"slash"}"#).unwrap()).unwrap();
    assert_eq!(future, OTPSetting::new(true, OTPSeparator::None));
    assert_eq!(OTPSeparator::None.string(), "");
    assert_eq!(OTPSeparator::Comma.string(), ",");
    assert_eq!(OTPSeparator::Colon.string(), ":");
}

#[test]
fn validation_issue_display_follows_language() {
    let issue = ValidationIssue::new(3, "x");
    assert_eq!(with_language(AppLanguage::En, || issue.display()), "Line 3: x");
    assert_eq!(with_language(AppLanguage::Hu, || issue.display()), "3. sor: x");
    assert_eq!(with_language(AppLanguage::Hu, || ValidationIssue::new(0, "y").display()), "y");
}

#[test]
fn uuid_strings_like_foundation() {
    let id = parse_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
    assert_eq!(uuid_string(&id), "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE");
    for bad in [
        "AAAAAAAABBBBCCCCDDDDEEEEEEEEEEEE",
        "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
        "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEEX",
        "AAAAAAAA-BBBB-CCCC-DDDDEEEEEEEEEEEE-",
        "gAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
        "urn:uuid:AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEE",
    ] {
        assert!(parse_uuid(bad).is_none(), "{bad}");
    }
}
