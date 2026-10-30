//! The RAS dial state machine, its log lines and the error texts (WinVPN 2c Task 7), Cisco IPsec on Windows and the
//! administrator steps' pure parts (Task 12): pure, tested on every OS.

use macvpn_app_core::failure_reason::{FailureKind, classify};
use macvpn_core::credentials::is_sign_in_failure;
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::models::{Connection, NativeSettings, Secrets, VPNKind};
use macvpn_core::ras::policy::WINDOWS_DEFAULT_FOR_STRONGSWAN;
use macvpn_core::ras::{Auth, DefaultRoute, Needs, RasEntryPlan, Strategy};
use macvpn_platform_api::NativeSupport;
use macvpn_platform_win::pure::admin_steps;
use macvpn_platform_win::pure::ca_trust;
use macvpn_platform_win::pure::cisco;
use macvpn_platform_win::pure::ras_errors::{self, AdminAction, ErrorContext, codes};
use macvpn_platform_win::pure::ras_log::{self, LogMasker};
use macvpn_platform_win::pure::ras_state::{self, Dial, DialEvent, DialState, rascs};
use std::path::Path;
use uuid::Uuid;

fn en<T>(f: impl FnOnce() -> T) -> T {
    with_language(AppLanguage::En, f)
}

fn l2tp() -> ErrorContext {
    ErrorContext { strategy: Strategy::L2tp, auth: Auth::MsChapV2 { psk: true }, sstp_custom_ca: false, policy: None }
}

fn sstp(custom_ca: bool) -> ErrorContext {
    ErrorContext {
        strategy: Strategy::Sstp,
        auth: Auth::MsChapV2 { psk: false },
        sstp_custom_ca: custom_ca,
        policy: None,
    }
}

fn ikev2(auth: Auth) -> ErrorContext {
    ErrorContext {
        strategy: Strategy::Ikev2,
        auth,
        sstp_custom_ca: false,
        policy: Some(WINDOWS_DEFAULT_FOR_STRONGSWAN),
    }
}

fn plan() -> RasEntryPlan {
    RasEntryPlan {
        strategy: Strategy::Ikev2,
        server: "vpn.example.com".into(),
        auth: Auth::EapMsChapV2,
        default_route: DefaultRoute::None,
        ts_as_routes: true,
        ike_fragmentation: true,
        interface_metric: None,
        policy: Some(WINDOWS_DEFAULT_FOR_STRONGSWAN),
        user: "alice".into(),
        needs: Needs { user: true, password: true, psk: false },
        warnings: Vec::new(),
    }
}

#[test]
fn states_map_to_root_status() {
    let id = Uuid::new_v4();
    let kind = VPNKind::Strongswan;
    assert_eq!(DialState::Idle.root_status(id, kind), None);
    assert_eq!(DialState::Idle.system_status(), "Disconnected");

    let s = DialState::Dialling { step: rascs::AUTHENTICATE }.root_status(id, kind).unwrap();
    assert_eq!((s.id, s.kind.as_str(), s.state.as_str(), s.ip.as_deref()), (id, "strongswan", "connecting", None));
    assert_eq!(DialState::Dialling { step: rascs::OPEN_PORT }.system_status(), "Connecting");

    let c = DialState::Connected { ipv4: Some("10.8.0.6".into()), since: 1_760_000_000.0 };
    let s = c.root_status(id, VPNKind::Sstp).unwrap();
    assert_eq!(
        (s.kind.as_str(), s.state.as_str(), s.ip.as_deref(), s.since),
        ("sstp", "connected", Some("10.8.0.6"), Some(1_760_000_000.0))
    );
    assert_eq!(c.system_status(), "Connected");

    assert_eq!(DialState::HangingUp.root_status(id, kind), None);
    assert_eq!(DialState::HangingUp.system_status(), "Disconnecting");

    let f = DialState::Failed { code: codes::AUTHENTICATION_FAILURE, at: 1.0 };
    assert_eq!(f.root_status(id, kind).unwrap().state, "failed");
    assert_eq!(f.system_status(), "Disconnected");

    // The failure's reason is the mapped text.
    let mut dial = Dial::new("vpn.example.com", ikev2(Auth::EapMsChapV2));
    dial.apply(DialEvent::Started);
    dial.apply(DialEvent::Error { code: codes::AUTHENTICATION_FAILURE, at: 2.0, windows_text: "Access denied".into() });
    assert!(matches!(dial.state(), DialState::Failed { code: 691, .. }));
    assert_eq!(en(|| dial.failure()).unwrap().text, "Authentication failed (wrong user name or password)");
}

#[test]
fn rasconnstate_names() {
    en(|| {
        for &state in rascs::ALL {
            let line = ras_state::state_line(state, "vpn.example.com");
            assert!(!line.starts_with("RAS state"), "{state:#x}: {line}");
            assert!(!line.is_empty());
        }
        assert_eq!(ras_state::state_line(rascs::OPEN_PORT, "x"), "Opening port…");
        assert_eq!(ras_state::state_line(rascs::CONNECT_DEVICE, "vpn.example.com"), "Connecting to vpn.example.com…");
        assert_eq!(ras_state::state_line(rascs::AUTHENTICATE, "x"), "Authenticating…");
        assert_eq!(ras_state::state_line(rascs::AUTHENTICATED, "x"), "Authenticated");
        assert_eq!(ras_state::state_line(rascs::AUTH_PROJECT, "x"), "Projecting (IP configuration)…");
        assert_eq!(ras_state::state_line(rascs::CONNECTED, "x"), "Connected");
        assert_eq!(ras_state::state_line(rascs::DISCONNECTED, "x"), "Disconnected");
        assert_eq!(ras_state::state_line(77, "x"), "RAS state 77");
        assert_eq!(ras_state::state_line(0x1005, "x"), "RAS state 0x1005");
    });
    // Microsoft's documented values (ras.h, RASCONNSTATE).
    assert_eq!((rascs::OPEN_PORT, rascs::AUTHENTICATED, rascs::APPLY_SETTINGS), (0, 14, 24));
    assert_eq!(
        (rascs::INTERACTIVE, rascs::INVOKE_EAP_UI, rascs::CONNECTED, rascs::DISCONNECTED),
        (0x1000, 0x1004, 0x2000, 0x2001)
    );
    assert_eq!(rascs::ALL.len(), 32);
    with_language(AppLanguage::Hu, || {
        assert_eq!(ras_state::state_line(rascs::AUTHENTICATE, "x"), "Hitelesítés…");
    });
}

#[test]
fn errors_map_to_texts() {
    en(|| {
        let text = |code: u32, ctx: &ErrorContext| ras_errors::explain(code, ctx).text;
        assert_eq!(text(691, &l2tp()), "Authentication failed (wrong user name or password)");
        let eap = text(13801, &ikev2(Auth::EapMsChapV2));
        assert!(eap.starts_with("Or Windows does not trust the server’s certificate"), "{eap}");
        assert!(macvpn_core::credentials::is_sign_in_failure(&eap), "still asks for the credentials once more");
        assert_eq!(text(13801, &ikev2(Auth::Ikev2Psk)), "Authentication failed");
        assert_eq!(
            text(13801, &ikev2(Auth::MachineCertificate)),
            "The server did not accept the computer certificate."
        );
        assert!(text(789, &l2tp()).starts_with("The IPsec negotiation with the server failed."));
        assert_eq!(
            text(13806, &ikev2(Auth::MachineCertificate)),
            "No computer certificate for IKEv2 was found. An administrator must import it (see the user guide)."
        );
        assert!(text(812, &l2tp()).starts_with("The server’s policy refused the connection"));
        assert!(text(868, &l2tp()).starts_with("The server’s name could not be resolved."));
        for code in [800, 815] {
            assert!(text(code, &l2tp()).starts_with("The server did not answer."), "{code}");
        }
        for code in [720, 734] {
            assert!(text(code, &sstp(false)).starts_with("The PPP negotiation with the server failed."), "{code}");
        }
        for code in [619, 628] {
            assert_eq!(text(code, &l2tp()), "The server closed the connection before it was complete.", "{code}");
        }
        assert_eq!(text(631, &l2tp()), "The connection was cancelled.");

        // 809: the NAT action only for L2TP.
        let e = ras_errors::explain(809, &l2tp());
        assert_eq!(e.action, Some(AdminAction::AllowL2tpBehindNat));
        assert_eq!(e.action.unwrap().id(), "allow-l2tp-behind-nat");
        assert!(e.text.contains("Allow L2TP Behind NAT…"), "{}", e.text);
        let e = ras_errors::explain(809, &ikev2(Auth::EapMsChapV2));
        assert_eq!(e.action, None);
        assert!(!e.text.contains("L2TP"), "{}", e.text);

        // 13868 names the offered policy.
        let e = ras_errors::explain(13868, &ikev2(Auth::EapMsChapV2));
        assert!(e.text.contains("AES-256, SHA-256, DH group 14; ESP AES-256, SHA-256"), "{}", e.text);
        assert!(!ras_errors::explain(13868, &l2tp()).text.contains("%@"));

        // SSTP certificates: Trust This CA only for a custom CA.
        let e = ras_errors::explain(codes::CERT_E_UNTRUSTEDROOT, &sstp(true));
        assert_eq!(e.action, Some(AdminAction::TrustCaInWindows));
        assert_eq!(e.action.unwrap().id(), "trust-ca-in-windows");
        assert_eq!(e.text, "The server’s CA is not trusted by Windows. Use Trust This CA in Windows… in the editor.");
        let e = ras_errors::explain(codes::CERT_E_UNTRUSTEDROOT, &sstp(false));
        assert_eq!(e.action, None);
        assert!(e.text.starts_with("The server’s certificate is not issued by a CA Windows trusts."));
        assert!(text(codes::CRYPT_E_REVOCATION_OFFLINE, &sstp(true)).contains("revoked"));
        assert_eq!(ras_errors::explain(codes::CRYPT_E_REVOCATION_OFFLINE, &sstp(true)).action, None);
        assert!(text(codes::CERT_E_CN_NO_MATCH, &sstp(false)).starts_with("The server’s certificate does not match"));

        // G-12: the codes a real dial returns (Task 2's spike).
        let silent_l2tp = text(789, &l2tp());
        assert!(silent_l2tp.contains("the server did not answer"), "{silent_l2tp}");
        assert!(silent_l2tp.contains("UDP 500/4500"), "{silent_l2tp}");
        assert_eq!(
            text(codes::SSTP_TIMEOUT, &sstp(false)),
            "The server did not answer on its port. Check the server address and your network connection."
        );
        assert_eq!(text(628, &ikev2(Auth::EapMsChapV2)), "The server did not answer or closed the connection.");
        assert_eq!(text(628, &l2tp()), "The server closed the connection before it was complete.");
        assert_eq!(text(628, &sstp(false)), "The server closed the connection before it was complete.");
        for ctx in [l2tp(), sstp(false), ikev2(Auth::EapMsChapV2)] {
            assert_eq!(text(633, &ctx), "Windows is still closing the previous connection. Try again in a moment.");
            assert_eq!(text(756, &ctx), "This connection is already being dialled.");
        }
        assert_eq!(
            text(766, &l2tp()),
            "Windows has no pre-shared key for this connection. Save it again and reconnect."
        );
        // 766 means "no stored PSK" only for an L2TP PSK entry.
        let l2tp_no_psk = ErrorContext { strategy: Strategy::L2tp, auth: Auth::MsChapV2 { psk: false }, ..l2tp() };
        assert_eq!(text(766, &l2tp_no_psk), "Windows error 766 (see the log)");
        assert_eq!(text(766, &sstp(false)), "Windows error 766 (see the log)");
        assert_eq!(text(codes::E_FAIL, &sstp(false)), "Windows error 0x80004005 (see the log)");
        assert_eq!(ras_errors::explain(codes::E_FAIL, &l2tp()).action, None);

        // Anything else.
        assert_eq!(text(1234, &l2tp()), "Windows error 1234 (see the log)");
        assert_eq!(text(0x8009_0325, &sstp(false)), "Windows error 0x80090325 (see the log)");
    });
    // The codes are Microsoft's (raserror.h, winerror.h).
    assert_eq!(codes::CERT_E_UNTRUSTEDROOT, 0x800B_0109);
    assert_eq!(codes::CRYPT_E_REVOCATION_OFFLINE, 0x8009_2013);
    assert_eq!(codes::CERT_E_CN_NO_MATCH, 0x800B_010F);
    assert_eq!((codes::IKE_AUTH_FAIL, codes::IKE_NO_CERT, codes::IKE_POLICY_MATCH), (13801, 13806, 13868));
    assert_eq!(
        (codes::PORT_NOT_OPEN, codes::GEN_FAILURE, codes::INVALID_PARAMETER, codes::PORT_NOT_AVAILABLE),
        (618, 31, 87, 633)
    );
    assert_eq!((codes::DIAL_ALREADY_IN_PROGRESS, codes::NO_CERTIFICATE), (756, 766));
    assert_eq!((codes::SSTP_TIMEOUT, codes::E_FAIL), (0x8007_274C, 0x8000_4005));
    // Every mapped code has a Hungarian text (and its own, not the generic one).
    for &code in ras_errors::MAPPED {
        let ctx = match code {
            13800.. if code < 0x8000_0000 => ikev2(Auth::EapMsChapV2),
            codes::NO_CERTIFICATE => l2tp(),
            _ => sstp(true),
        };
        let generic =
            with_language(AppLanguage::En, || ras_errors::explain(code, &ctx).text.starts_with("Windows error "));
        assert!(!generic, "{code}");
        let en = with_language(AppLanguage::En, || ras_errors::explain(code, &ctx).text);
        let hu = with_language(AppLanguage::Hu, || ras_errors::explain(code, &ctx).text);
        assert_ne!(en, hu, "{code}");
    }
}

#[test]
fn auth_errors_are_sign_in_failures() {
    for lang in [AppLanguage::En, AppLanguage::Hu] {
        with_language(lang, || {
            for (code, ctx) in [
                (691, l2tp()),
                (691, sstp(false)),
                (691, ikev2(Auth::EapMsChapV2)),
                (13801, ikev2(Auth::EapMsChapV2)),
                (13801, ikev2(Auth::Ikev2Psk)),
            ] {
                let text = ras_errors::explain(code, &ctx).text;
                assert!(is_sign_in_failure(&text), "{lang:?} {code}: {text}");
            }
        });
    }
}

#[test]
fn other_errors_are_not() {
    for lang in [AppLanguage::En, AppLanguage::Hu] {
        with_language(lang, || {
            for (code, ctx) in [
                (809, l2tp()),
                (868, l2tp()),
                (13868, ikev2(Auth::EapMsChapV2)),
                (13801, ikev2(Auth::MachineCertificate)),
                (789, l2tp()),
                (1234, l2tp()),
            ] {
                let text = ras_errors::explain(code, &ctx).text;
                assert!(!is_sign_in_failure(&text), "{lang:?} {code}: {text}");
            }
        });
    }
}

#[test]
fn ras_errors_have_a_failure_kind() {
    let kind = |code: u32| classify(&[ras_errors::log_line(code, "Windows' own text")]);
    for (code, expected) in [
        (691, FailureKind::AuthFailed),
        (13801, FailureKind::AuthFailed),
        (13806, FailureKind::CertificateProblem),
        (codes::CERT_E_UNTRUSTEDROOT, FailureKind::CertificateProblem),
        (codes::CRYPT_E_REVOCATION_OFFLINE, FailureKind::CertificateProblem),
        (codes::CERT_E_CN_NO_MATCH, FailureKind::CertificateProblem),
        (868, FailureKind::NameNotResolved),
        (800, FailureKind::ServerUnreachable),
        (809, FailureKind::ServerUnreachable),
        (815, FailureKind::ServerUnreachable),
        (619, FailureKind::Unknown),
        (628, FailureKind::Unknown),
        (631, FailureKind::Unknown),
        (720, FailureKind::Unknown),
        (734, FailureKind::Unknown),
        (789, FailureKind::Unknown),
        (812, FailureKind::Unknown),
        (13868, FailureKind::Unknown),
        (codes::SSTP_TIMEOUT, FailureKind::ServerUnreachable),
        (633, FailureKind::Unknown),
        (756, FailureKind::Unknown),
        (766, FailureKind::Unknown),
        (codes::E_FAIL, FailureKind::Unknown),
        (6910, FailureKind::Unknown),
        (8000, FailureKind::Unknown),
    ] {
        assert_eq!(kind(code), expected, "{code}");
    }
    // The whole log of a failed dial, in either language, classifies by its code line.
    for lang in [AppLanguage::En, AppLanguage::Hu] {
        let lines = with_language(lang, || {
            let mut dial = Dial::new("vpn.example.com", l2tp());
            let mut lines = dial.apply(DialEvent::Started);
            lines.extend(dial.apply(DialEvent::Step(rascs::AUTHENTICATE)));
            lines.extend(dial.apply(DialEvent::Error { code: 691, at: 1.0, windows_text: "x".into() }));
            lines
        });
        assert_eq!(classify(&lines), FailureKind::AuthFailed, "{lang:?}: {lines:?}");
    }
}

/// G-12: an HRESULT handed over as a negative `i32` is compared, explained and logged as its `u32`.
#[test]
fn hresults_compare_as_u32() {
    let code = ras_errors::code_from_i32(-2_147_014_836);
    assert_eq!(code, 0x8007_274C);
    assert_eq!(code, codes::SSTP_TIMEOUT);
    assert_eq!(ras_errors::code_label(code), "0x8007274C");
    assert_eq!(ras_errors::code_from_i32(-2_147_467_259), codes::E_FAIL);
    assert_eq!(ras_errors::code_from_i32(691), 691);
    let line = ras_errors::log_line(code, "A connection attempt failed");
    assert_eq!(line, "Windows error 0x8007274C: A connection attempt failed");
    assert_eq!(classify(&[line]), FailureKind::ServerUnreachable);
    let explained = en(|| ras_errors::explain(code, &sstp(false)).text);
    assert!(explained.starts_with("The server did not answer on its port."), "{explained}");
}

/// G-12: whatever code a dial ends with after WinVPN's own hang-up (618, 31, 87, 631: Task 2's spike), it is
/// cancelled, not a failure: no error line, no failure, "Disconnected" when it ends.
#[test]
fn a_code_after_our_hang_up_is_cancelled() {
    en(|| {
        for code in [codes::PORT_NOT_OPEN, codes::GEN_FAILURE, codes::INVALID_PARAMETER, codes::USER_DISCONNECTION] {
            for connected in [false, true] {
                let mut dial = Dial::new("vpn.example.com", l2tp());
                dial.apply(DialEvent::Started);
                dial.apply(DialEvent::Step(rascs::CONNECT_DEVICE));
                if connected {
                    dial.apply(DialEvent::Connected { ipv4: None, at: 1.0 });
                }
                assert_eq!(dial.apply(DialEvent::HangUp), ["Disconnecting…"]);
                let lines = dial.apply(DialEvent::Error { code, at: 2.0, windows_text: "x".into() });
                assert_eq!(lines, Vec::<String>::new(), "{code}");
                assert_eq!(dial.failure(), None, "{code}");
                assert_eq!(dial.apply(DialEvent::Ended), ["Disconnected"], "{code}");
                assert_eq!(dial.state(), &DialState::Idle, "{code}");
            }
        }
        // The same codes without our hang-up are failures.
        let mut dial = Dial::new("vpn.example.com", l2tp());
        dial.apply(DialEvent::Started);
        dial.apply(DialEvent::Error { code: codes::INVALID_PARAMETER, at: 1.0, windows_text: "x".into() });
        assert!(matches!(dial.state(), DialState::Failed { code: 87, .. }));
    });
}

#[test]
fn log_lines_are_masked() {
    let secrets = Secrets {
        username: Some("alice".into()),
        password: Some("Sup3rTitok".into()),
        psk: Some("sharedK3y".into()),
        one_time_code: Some("123456".into()),
        ..Secrets::default()
    };
    let masker = LogMasker::new(&secrets);
    let windows_text = "Server said: bad password Sup3rTitok123456 (psk sharedK3y) for alice";
    let line = masker.line(&ras_errors::log_line(691, windows_text));
    assert_eq!(line, "Windows error 691: Server said: bad password ****** (psk ***) for alice");
    for secret in ["Sup3rTitok", "sharedK3y", "123456"] {
        assert!(!line.contains(secret), "{line}");
    }
    // Short secrets only as whole tokens (the helper's rule).
    let short = LogMasker::new(&Secrets { password: Some("ab".into()), ..Secrets::default() });
    assert_eq!(short.line("ab cab ab. (ab)"), "*** cab ***. (***)");
    // A line is one line: Windows' text cannot add lines, and it is bounded.
    let line = ras_errors::log_line(868, "first\r\nsecond\u{7}");
    assert_eq!(line, "Windows error 868: first  second ");
    assert!(ras_errors::log_line(868, &"x".repeat(5000)).chars().count() < 600);

    // The debug dump of an entry: the effective settings, no secret and no password or PSK field.
    let dump = en(|| ras_log::entry_dump(&plan())).join("\n");
    assert!(dump.contains("vpn.example.com") && dump.contains("IKEv2") && dump.contains("EAP-MSCHAPv2"), "{dump}");
    assert!(dump.contains("AES-256, SHA-256, DH group 14"), "{dump}");
    let lower = dump.to_lowercase();
    for word in ["password", "psk", "pre-shared", "sup3rtitok", "sharedk3y"] {
        assert!(!lower.contains(word), "{word}: {dump}");
    }
    let masked = masker.lines(&ras_log::entry_dump(&plan()));
    assert_eq!(masked.len(), ras_log::entry_dump(&plan()).len());
}

#[test]
fn a_drop_after_connected_is_disconnected_not_failed() {
    en(|| {
        let mut dial = Dial::new("vpn.example.com", l2tp());
        let mut log = dial.apply(DialEvent::Started);
        log.extend(dial.apply(DialEvent::Step(rascs::CONNECT_DEVICE)));
        assert!(matches!(dial.state(), DialState::Dialling { step: 2 }));
        log.extend(dial.apply(DialEvent::Connected { ipv4: Some("10.8.0.6".into()), at: 5.0 }));
        assert_eq!(dial.state(), &DialState::Connected { ipv4: Some("10.8.0.6".into()), since: 5.0 });
        log.extend(dial.apply(DialEvent::Ended));
        assert_eq!(dial.state(), &DialState::Idle);
        assert_eq!(dial.failure(), None);
        assert_eq!(
            log,
            [
                "Connecting to vpn.example.com…",
                "Connected, IPv4 10.8.0.6",
                "The connection was closed (by the server or the network).",
            ]
        );

        // A hang-up we asked for: "Disconnected", and a late error (631) is not a failure.
        let mut dial = Dial::new("vpn.example.com", l2tp());
        dial.apply(DialEvent::Started);
        dial.apply(DialEvent::Connected { ipv4: None, at: 1.0 });
        assert_eq!(dial.apply(DialEvent::HangUp), ["Disconnecting…"]);
        assert_eq!(dial.state(), &DialState::HangingUp);
        assert_eq!(
            dial.apply(DialEvent::Error { code: 631, at: 2.0, windows_text: String::new() }),
            Vec::<String>::new()
        );
        assert_eq!(dial.apply(DialEvent::Ended), ["Disconnected"]);
        assert_eq!(dial.state(), &DialState::Idle);

        // A failure stays a failure when the connection then ends; a new dial starts afresh.
        let mut dial = Dial::new("vpn.example.com", l2tp());
        dial.apply(DialEvent::Started);
        let lines = dial.apply(DialEvent::Error { code: 809, at: 3.0, windows_text: "Timeout".into() });
        assert_eq!(lines[0], "Windows error 809: Timeout");
        assert!(lines[1].starts_with("The server did not answer on the VPN ports."), "{lines:?}");
        assert_eq!(dial.apply(DialEvent::Ended), Vec::<String>::new());
        assert!(matches!(dial.state(), DialState::Failed { code: 809, at } if *at == 3.0));
        assert_eq!(dial.failure().unwrap().action, Some(AdminAction::AllowL2tpBehindNat));
        dial.apply(DialEvent::Started);
        assert!(matches!(dial.state(), DialState::Dialling { step: 0 }));
        assert_eq!(dial.failure(), None);
        // `RASCS_Disconnected` from the dial callback ends it too.
        dial.apply(DialEvent::Connected { ipv4: None, at: 4.0 });
        assert_eq!(
            dial.apply(DialEvent::Step(rascs::DISCONNECTED)),
            ["The connection was closed (by the server or the network)."]
        );
        assert_eq!(dial.state(), &DialState::Idle);
    });
}

// MARK: - Task 12: Cisco IPsec on Windows (option A) and the administrator steps

const CA_PEM: &str = include_str!("fixtures/ca/ca.pem");
const LONG_CA_PEM: &str = include_str!("fixtures/ca/long-ca.pem");
const LEAF_PEM: &str = include_str!("fixtures/ca/leaf.pem");
/// `ca.pem`: notBefore 2026-10-25 17:33:38Z, notAfter 2046-10-20 17:33:38Z (`openssl x509 -dates`).
const CA_NOT_BEFORE: i64 = 1_792_949_618;
const CA_NOT_AFTER: i64 = 2_423_669_618;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_ca_summary_names_subject_validity_and_fingerprint() {
    let ca = ca_trust::read(CA_PEM, CA_NOT_BEFORE + 60).unwrap();
    assert_eq!(ca.summary.subject, "CN=WinVPN Test CA, O=Example, C=HU");
    assert_eq!((ca.summary.not_before, ca.summary.not_after), (CA_NOT_BEFORE, CA_NOT_AFTER));
    // `openssl x509 -fingerprint -sha256` / `-sha1` of the fixture.
    assert_eq!(
        ca.summary.sha256,
        "41:73:F8:BB:53:7C:2B:FC:BE:A1:3B:0C:07:60:12:BE:17:82:71:9B:38:DD:09:75:04:38:63:83:86:BB:BA:92"
    );
    assert_eq!(hex(&ca.sha1), "53cdc417ceda8000a2fcfd50eb98f4d80c9cde2f");
    assert_eq!(ca.der.first(), Some(&0x30));
    // GeneralizedTime (after 2049) and an OU.
    let long = ca_trust::read(LONG_CA_PEM, CA_NOT_BEFORE + 60).unwrap();
    assert_eq!(long.summary.subject, "CN=WinVPN Long CA, OU=Lab, O=Example");
    assert_eq!(long.summary.not_after, 2_656_949_627);
    assert_eq!(hex(&long.sha1), "d311d97bff251ccc94b40ffdeacd470f7b0e3b7c");
    // The first certificate of a bundle, text around it ignored.
    let bundle = format!("subject=CN=WinVPN Test CA\n{CA_PEM}\n{LEAF_PEM}");
    assert_eq!(ca_trust::read(&bundle, CA_NOT_BEFORE + 60).unwrap().sha1, ca.sha1);
    en(|| assert!(ca_trust::warning().contains("Every program on this PC")));
    // The elevated step reads the DER file WinVPN staged, with the same checks.
    assert_eq!(ca_trust::read_der(&ca.der, CA_NOT_BEFORE + 60).unwrap(), ca);
    assert!(ca_trust::read_der(&ca.der, CA_NOT_AFTER + 1).is_err());
    assert!(ca_trust::read_der(&ca.der[..ca.der.len() - 1], CA_NOT_BEFORE + 60).is_err());
}

#[test]
fn the_tls_only_usage_is_server_and_client_authentication() {
    // RFC 5280 ExtKeyUsageSyntax: SEQUENCE { id-kp-serverAuth 1.3.6.1.5.5.7.3.1, id-kp-clientAuth 1.3.6.1.5.5.7.3.2 }.
    assert_eq!(
        admin_steps::TLS_ONLY_EKU,
        [
            0x30, 0x14, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05,
            0x05, 0x07, 0x03, 0x02
        ]
    );
}

/// L-6 of the 2.0.0 security review: a subject whose CN carries bidi controls, zero-width characters, a BOM, a line
/// separator and a soft hyphen (`openssl req -utf8`) shows each of them escaped, never as an invisible character.
#[test]
fn invisible_format_characters_in_the_subject_are_shown_escaped() {
    const BIDI_CA_PEM: &str = include_str!("fixtures/ca/bidi-ca.pem");
    // notBefore 2026-10-25 21:19:19Z: an hour later.
    let ca = ca_trust::read(BIDI_CA_PEM, 1_792_970_000).unwrap();
    assert_eq!(ca.summary.subject, r"O=Example, CN=Example \u{202E}3pm.exe\u{200B} CA\u{FEFF}\u{2028}x\u{AD}");
}

#[test]
fn a_non_ca_or_expired_pem_is_refused() {
    en(|| {
        let now = CA_NOT_BEFORE + 60;
        assert_eq!(ca_trust::read(LEAF_PEM, now).unwrap_err(), "This certificate is not a CA certificate.");
        let expired = "This CA certificate has expired or is not valid yet.";
        assert_eq!(ca_trust::read(CA_PEM, CA_NOT_AFTER + 1).unwrap_err(), expired);
        assert_eq!(ca_trust::read(CA_PEM, CA_NOT_BEFORE - 1).unwrap_err(), expired);
        let none = "The text contains no readable certificate.";
        assert_eq!(ca_trust::read("", now).unwrap_err(), none);
        assert_eq!(
            ca_trust::read("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n", now).unwrap_err(),
            none
        );
        // A truncated or tampered DER (every cut of the certificate's base64 body) never panics and is refused.
        let body: String = CA_PEM.lines().filter(|l| !l.starts_with("-----")).collect();
        for cut in (4..body.len()).step_by(4) {
            let pem = format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", &body[..cut]);
            assert!(ca_trust::read(&pem, now).is_err(), "cut at {cut}");
        }
    });
}

#[test]
fn sha1_matches_the_standard_vectors() {
    assert_eq!(hex(&ca_trust::sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(hex(&ca_trust::sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(
        hex(&ca_trust::sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
    assert_eq!(hex(&ca_trust::sha1(&[b'a'; 1_000_000])), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
}

#[test]
fn the_trust_step_and_reg_argv_are_fixed() {
    let path = Path::new(r"C:\Users\Test User\AppData\Local\Temp\ca-0123456789abcdef.cer");
    let args = admin_steps::trust_step_args(path).unwrap();
    assert_eq!(args, ["--winvpn-trust-ca-step", r"C:\Users\Test User\AppData\Local\Temp\ca-0123456789abcdef.cer"]);
    assert_eq!(
        admin_steps::parameters(&args).unwrap(),
        r#"--winvpn-trust-ca-step "C:\Users\Test User\AppData\Local\Temp\ca-0123456789abcdef.cer""#
    );
    // The elevated WinVPN.exe takes exactly that back (and checks the path again); anything else is not the step.
    assert_eq!(admin_steps::parse_trust_step(&args), Some(Some(path.to_path_buf())));
    assert_eq!(admin_steps::parse_trust_step(&["--winvpn-openvpn-step".to_string()]), None);
    assert_eq!(admin_steps::parse_trust_step(&[]), None);
    for bad in [
        &args[..1],
        &[args[0].clone(), r"C:\Temp\other.cer".into()][..],
        &[args[0].clone(), args[1].clone(), "x".into()][..],
    ] {
        assert_eq!(admin_steps::parse_trust_step(bad), Some(None), "{bad:?}");
    }
    // A path WinVPN did not build that way is refused (it never can be: WinVPN names the file).
    for bad in [
        r#"C:\Temp\ca-"x.cer"#,
        r"relative\ca-0123.cer",
        r"C:\Temp\ca-0123.cer\",
        "C:\\Temp\\ca-01\n23.cer",
        r"C:\Temp\other.cer",
        r"C:\Temp\ca-0123.cer -f",
    ] {
        assert!(admin_steps::trust_step_args(Path::new(bad)).is_err(), "{bad:?}");
    }
    assert_eq!(
        admin_steps::reg_args(),
        [
            "add",
            r"HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent",
            "/v",
            "AssumeUDPEncapsulationContextOnSendRule",
            "/t",
            "REG_DWORD",
            "/d",
            "2",
            "/f",
        ]
    );
    assert_eq!(
        admin_steps::parameters(&admin_steps::reg_args()).unwrap(),
        r"add HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent /v AssumeUDPEncapsulationContextOnSendRule /t REG_DWORD /d 2 /f"
    );
    assert_eq!(admin_steps::parameters(&["a\"b".to_string()]), None);
    assert_eq!(admin_steps::parameters(&[String::new()]), None);
}

#[test]
fn the_admin_outcomes_say_what_happened() {
    en(|| {
        // Trust (M-1 of the 2.0.0 security review): the elevated step's code and the store read back afterwards,
        // whose CA must carry the TLS-only usage property.
        use admin_steps::{InRoot, TrustStep};
        let done = Ok("The CA is now trusted by Windows.".into());
        let absent = Err("Windows did not add the CA to its trusted root store.".into());
        let unlimited =
            Err("Windows could not limit the CA to server and client certificates, so it was not added.".into());
        let added = TrustStep::Added.code();
        assert_eq!(admin_steps::trust_outcome(Ok(added), Some(InRoot::TlsOnly)), done);
        assert_eq!(admin_steps::trust_outcome(Ok(added), None), done, "the store could not be read: the step's word");
        assert_eq!(admin_steps::trust_outcome(Ok(added), Some(InRoot::Absent)), absent);
        assert_eq!(admin_steps::trust_outcome(Ok(added), Some(InRoot::Unrestricted)), unlimited);
        // Already in the store (added before by an administrator): left as it is.
        let there = TrustStep::AlreadyThere.code();
        assert_eq!(admin_steps::trust_outcome(Ok(there), Some(InRoot::Unrestricted)), done);
        assert_eq!(admin_steps::trust_outcome(Ok(there), Some(InRoot::Absent)), absent);
        assert_eq!(admin_steps::trust_outcome(Ok(TrustStep::NotRestricted.code()), None), unlimited);
        assert_eq!(admin_steps::trust_outcome(Err(1223), None), Err("Cancelled".into()));
        assert_eq!(admin_steps::trust_outcome(Ok(5), None), Err("WinVPN.exe ended with error 5.".into()));
        assert_eq!(admin_steps::trust_outcome(Err(2), None), Err("WinVPN.exe could not be started.".into()));
        // The codes round-trip; 0 is success, the others have bit 29 set (not an HRESULT or Win32 error).
        for step in [
            TrustStep::Added,
            TrustStep::AlreadyThere,
            TrustStep::Arguments,
            TrustStep::Refused,
            TrustStep::StoreFailed,
            TrustStep::NotRestricted,
        ] {
            assert_eq!(TrustStep::from_code(step.code()), Some(step));
            assert!(step.code() == 0 || step.code() & 0x2000_0000 != 0, "{step:?}");
        }
        assert_eq!(TrustStep::from_code(5), None);
        // The usage property read back: exactly server and client authentication, else not restricted.
        assert_eq!(admin_steps::in_root(None), InRoot::Absent);
        assert_eq!(admin_steps::in_root(Some(Some(admin_steps::TLS_ONLY_EKU))), InRoot::TlsOnly);
        assert_eq!(admin_steps::in_root(Some(None)), InRoot::Unrestricted);
        assert_eq!(admin_steps::in_root(Some(Some(&admin_steps::TLS_ONLY_EKU[..12]))), InRoot::Unrestricted);
        // NAT: the value is read back; a restart is needed.
        let done = "L2TP/IPsec behind NAT is allowed. Restart Windows to apply it.";
        assert_eq!(admin_steps::nat_outcome(Ok(0), Some(2)), Ok(done.into()));
        assert_eq!(admin_steps::nat_outcome(Ok(0), None), Ok(done.into()));
        assert_eq!(admin_steps::nat_outcome(Ok(0), Some(0)), Err("The setting was not changed.".into()));
        assert_eq!(admin_steps::nat_outcome(Err(1223), None), Err("Cancelled".into()));
        assert_eq!(admin_steps::nat_outcome(Ok(1), None), Err("reg.exe ended with error 1.".into()));
    });
}

/// The buttons' labels are exactly the names the error texts tell the user to use (EN and HU).
#[test]
fn the_admin_action_labels_match_the_error_texts() {
    for language in [AppLanguage::En, AppLanguage::Hu] {
        with_language(language, || {
            let nat = ras_errors::explain(codes::VPN_TIMEOUT, &l2tp());
            assert_eq!(nat.action, Some(AdminAction::AllowL2tpBehindNat));
            assert!(nat.text.contains(&AdminAction::AllowL2tpBehindNat.label()), "{language:?}: {}", nat.text);
            let ca = ras_errors::explain(codes::CERT_E_UNTRUSTEDROOT, &sstp(true));
            assert_eq!(ca.action, Some(AdminAction::TrustCaInWindows));
            assert!(ca.text.contains(&AdminAction::TrustCaInWindows.label()), "{language:?}: {}", ca.text);
        });
    }
    en(|| {
        assert_eq!(AdminAction::AllowL2tpBehindNat.label(), "Allow L2TP Behind NAT…");
        assert_eq!(AdminAction::TrustCaInWindows.label(), "Trust This CA in Windows…");
    });
}

#[test]
fn cisco_ipsec_is_not_supported_on_windows() {
    en(|| {
        assert_eq!(cisco::unsupported(), macvpn_core::ras::CISCO_UNSUPPORTED);
        assert!(cisco::unsupported().contains("make an L2TP/IPsec copy"));
        assert_eq!(cisco::copy_label(), "Make an L2TP/IPsec Copy");
        let mut c = Connection::new("Office", VPNKind::Cisco);
        c.native =
            Some(NativeSettings { server: "vpn.example.com".into(), account: "bob".into(), ..Default::default() });
        assert_eq!(cisco::CiscoSupport.unsupported_reason(&c, b""), Some(cisco::unsupported()));
        c.kind = VPNKind::L2tp;
        assert_eq!(cisco::CiscoSupport.unsupported_reason(&c, b""), None);
        assert_eq!(cisco::unsupported_kinds(), vec![(VPNKind::Cisco, cisco::unsupported())]);
    });
    with_language(AppLanguage::Hu, || assert!(cisco::unsupported().starts_with("A Windows nem támogatja")));
}
