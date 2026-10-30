//! What the editors show about Windows (WinVPN 2c Task 11, pure, every OS): the reasons, the IKEv2 summary and
//! warnings, the SSTP certificate modes, the offered buttons, the system VPN's PSK note and the administrator step
//! an error text offers.

use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::models::{Connection, NativeSettings, VPNKind};
use macvpn_platform_api::PlatformNotes;
use macvpn_platform_win::pure::ras_editor::{editor_notes, offered_action, system_psk_note};
use macvpn_platform_win::pure::ras_errors::{self, AdminAction, ErrorContext, codes};

fn en<T>(f: impl FnOnce() -> T) -> T {
    with_language(AppLanguage::En, f)
}

fn hu<T>(f: impl FnOnce() -> T) -> T {
    with_language(AppLanguage::Hu, f)
}

fn native(kind: VPNKind) -> Connection {
    let mut c = Connection::new("Office VPN", kind);
    c.native = Some(NativeSettings {
        server: "vpn.example.com".into(),
        account: "alice".into(),
        group_name: "staff".into(),
        send_all_traffic: true,
    });
    c
}

const EAP: &str = "connections {\n  office {\n    remote_addrs = vpn.example.com\n    local {\n      auth = eap-mschapv2\n      eap_id = alice\n    }\n    remote {\n      auth = pubkey\n      id = vpn.example.com\n    }\n    children {\n      net {\n        remote_ts = 10.0.0.0/8\n      }\n    }\n  }\n}\n";

fn sstp(cert: &str) -> Vec<u8> {
    format!("server=vpn.example.com\nport=443\nuser=alice\ncert={cert}\nroute_all=yes\npeer_dns=yes\n").into_bytes()
}

#[test]
fn l2tp_saves_without_an_install_step_and_has_no_reason() {
    en(|| {
        let notes = editor_notes(&native(VPNKind::L2tp), b"");
        assert_eq!(notes, PlatformNotes { no_install_step: true, ..PlatformNotes::default() });
    });
}

#[test]
fn cisco_gets_the_option_a_text_and_the_copy_button() {
    en(|| {
        let notes = editor_notes(&native(VPNKind::Cisco), b"");
        assert_eq!(notes.reasons.len(), 1);
        assert!(notes.reasons[0].starts_with("Cisco IPsec is not supported by Windows."), "{notes:?}");
        assert!(notes.l2tp_copy && notes.no_install_step && !notes.trust_ca);
        assert_eq!(notes.summary, None);
    });
}

#[test]
fn ikev2_shows_the_windows_summary_and_offers_the_ca() {
    en(|| {
        let c = Connection::new("Office VPN", VPNKind::Strongswan);
        let notes = editor_notes(&c, EAP.as_bytes());
        assert!(notes.reasons.is_empty(), "{notes:?}");
        assert_eq!(
            notes.summary.as_deref(),
            Some("On Windows: EAP-MSCHAPv2 · AES-256, SHA-256, DH group 14; ESP AES-256, SHA-256 · split tunnel")
        );
        assert!(notes.trust_ca && !notes.l2tp_copy && !notes.no_install_step);
        assert!(notes.warnings.is_empty());

        // A full tunnel and a computer certificate.
        let cert = EAP
            .replace("auth = eap-mschapv2\n      eap_id = alice", "auth = pubkey\n      certs = client.pem")
            .replace("remote_ts = 10.0.0.0/8", "remote_ts = 0.0.0.0/0");
        let notes = editor_notes(&c, cert.as_bytes());
        let summary = notes.summary.unwrap();
        assert!(summary.starts_with("On Windows: computer certificate · "), "{summary}");
        assert!(summary.ends_with(" · all traffic"), "{summary}");
        // G2/G4: the client's key and its password belong in Windows' store (the note says how).
        assert_eq!(notes.warnings.len(), 1);
        assert!(notes.warnings[0].contains("Local Computer › Personal"), "{:?}", notes.warnings);
    });
    hu(|| {
        let c = Connection::new("Office VPN", VPNKind::Strongswan);
        let summary = editor_notes(&c, EAP.as_bytes()).summary.unwrap();
        assert!(summary.starts_with("Windowson: EAP-MSCHAPv2 · "), "{summary}");
        assert!(summary.ends_with(" · osztott alagút"), "{summary}");
    });
}

#[test]
fn ikev2_warnings_and_every_reason_are_listed() {
    en(|| {
        let c = Connection::new("Office VPN", VPNKind::Strongswan);
        let restart = EAP.replace("remote_ts = 10.0.0.0/8", "remote_ts = 10.0.0.0/8\n        dpd_action = restart");
        let notes = editor_notes(&c, restart.as_bytes());
        assert_eq!(
            notes.warnings,
            ["Ignored on Windows: dpd_action = restart (Windows itself redials a dropped connection)"]
        );
        assert!(notes.summary.is_some() && notes.reasons.is_empty());

        // Two settings Windows lacks: both reasons (not only the first, as the row shows), no summary.
        let two = EAP
            .replace("auth = eap-mschapv2", "auth = eap-tls")
            .replace("remote_addrs", "version = 1\n    remote_addrs");
        let notes = editor_notes(&c, two.as_bytes());
        assert!(notes.reasons.len() >= 2, "{notes:?}");
        assert!(notes.reasons.iter().all(|r| r.starts_with("Not supported on Windows: ")), "{notes:?}");
        assert_eq!(notes.summary, None);
        assert!(notes.trust_ca, "the button stays: the CA may be needed once the settings are fixed");

        // An invalid config is the validator's (shown as on macOS), not a Windows reason.
        let notes = editor_notes(&c, b"connections {");
        assert!(notes.reasons.is_empty() && notes.summary.is_none(), "{notes:?}");
    });
}

#[test]
fn sstp_cannot_skip_the_certificate_check() {
    en(|| {
        let c = Connection::new("Office VPN", VPNKind::Sstp);
        let reason = "Windows always checks the SSTP server's certificate. Choose System CA or Custom CA file.";
        let ok = editor_notes(&c, &sstp("system"));
        assert_eq!(ok.insecure_cert.as_deref(), Some(reason));
        assert!(ok.reasons.is_empty() && ok.trust_ca && ok.summary.is_none());
        let insecure = editor_notes(&c, &sstp("insecure"));
        assert_eq!(insecure.reasons, [reason]);
        assert_eq!(insecure.insecure_cert.as_deref(), Some(reason));
    });
}

#[test]
fn openvpn_and_wireguard_have_no_notes() {
    for kind in [VPNKind::Openvpn, VPNKind::Wireguard] {
        assert!(editor_notes(&Connection::new("Office VPN", kind), b"client\n").is_empty());
    }
}

#[test]
fn the_system_vpn_psk_note() {
    en(|| {
        assert_eq!(
            system_psk_note(),
            "Windows uses its own PSK for this VPN if it has one; otherwise WinVPN stores this one there."
        )
    });
    hu(|| assert!(system_psk_note().starts_with("A Windows a saját PSK-ját használja"), "{}", system_psk_note()));
}

/// The error banner's button: the step whose label the error text names (809 for L2TP, the untrusted CA of an
/// SSTP custom CA), in EN and HU; any other error offers none.
#[test]
fn an_error_offers_the_step_it_names() {
    for lang in [AppLanguage::En, AppLanguage::Hu] {
        with_language(lang, || {
            let c = native(VPNKind::L2tp);
            let plan = macvpn_core::ras::plan_for(&c, b"").unwrap().unwrap();
            let nat = ras_errors::explain(codes::VPN_TIMEOUT, &ErrorContext::for_plan(&plan, false));
            assert_eq!(nat.action, Some(AdminAction::AllowL2tpBehindNat));
            assert_eq!(offered_action(&nat.text), Some(AdminAction::AllowL2tpBehindNat), "{}", nat.text);

            let sstp_plan = macvpn_core::ras::plan_sstp(&sstp("system")).unwrap();
            let ca = ras_errors::explain(codes::CERT_E_UNTRUSTEDROOT, &ErrorContext::for_plan(&sstp_plan, true));
            assert_eq!(offered_action(&ca.text), Some(AdminAction::TrustCaInWindows), "{}", ca.text);

            let auth = ras_errors::explain(691, &ErrorContext::for_plan(&plan, false));
            assert_eq!(offered_action(&auth.text), None);
            assert_eq!(offered_action(""), None);
        });
    }
}
