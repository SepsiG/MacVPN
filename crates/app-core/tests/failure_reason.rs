//! The last lines of a connection's log → a fixed, plain-words reason that names no server, address or user.

use macvpn_app_core::failure_reason::{FailureKind, classify, plain};
use macvpn_core::l10n::{AppLanguage, with_language};

fn kind(lines: &[&str]) -> FailureKind {
    classify(&lines.iter().map(|l| l.to_string()).collect::<Vec<_>>())
}

const ALL: [FailureKind; 7] = [
    FailureKind::ServerNotResponding,
    FailureKind::ServerUnreachable,
    FailureKind::NameNotResolved,
    FailureKind::AuthFailed,
    FailureKind::CertificateProblem,
    FailureKind::NetworkLost,
    FailureKind::Unknown,
];

#[test]
fn openvpn_lines_are_classified() {
    assert_eq!(
        kind(&["... [vpn.example.com] Inactivity timeout (--ping-restart), restarting"]),
        FailureKind::ServerNotResponding
    );
    assert_eq!(kind(&["... Inactivity timeout (--ping-exit), exiting"]), FailureKind::ServerNotResponding);
    assert_eq!(
        kind(&[
            "... TLS Error: TLS key negotiation failed to occur within 60 seconds (check your network connectivity)"
        ]),
        FailureKind::ServerUnreachable
    );
    assert_eq!(kind(&["... AUTH: Received control message: AUTH_FAILED"]), FailureKind::AuthFailed);
    assert_eq!(kind(&["... VERIFY ERROR: depth=0, error=certificate has expired"]), FailureKind::CertificateProblem);
    assert_eq!(
        kind(&["... RESOLVE: Cannot resolve host address: vpn.example.com:1194 (nodename nor servname provided)"]),
        FailureKind::NameNotResolved
    );
    assert_eq!(
        kind(&["... TCP: connect to [AF_INET]192.0.2.1:443 failed: Connection refused"]),
        FailureKind::ServerUnreachable
    );
    assert_eq!(kind(&["... write UDP: Network is unreachable (fd=5,code=51)"]), FailureKind::NetworkLost);
    assert_eq!(kind(&["... write UDP: No route to host (fd=5,code=65)"]), FailureKind::NetworkLost);
}

#[test]
fn strongswan_lines_are_classified() {
    assert_eq!(kind(&["giving up after 5 retransmits"]), FailureKind::ServerNotResponding);
    assert_eq!(kind(&["received AUTHENTICATION_FAILED notify error"]), FailureKind::AuthFailed);
}

#[test]
fn windows_ras_lines_are_classified() {
    assert_eq!(kind(&["Windows error 691: Access was denied."]), FailureKind::AuthFailed);
    assert_eq!(
        kind(&["Windows error 13801: IKE authentication credentials are unacceptable."]),
        FailureKind::AuthFailed
    );
    assert_eq!(
        kind(&["Windows error 13806: IKE failed to find valid machine certificate."]),
        FailureKind::CertificateProblem
    );
    for code in ["0x800B0109", "0x80092013", "0x800B010F"] {
        assert_eq!(kind(&[&format!("Windows error {code}: …")]), FailureKind::CertificateProblem, "{code}");
    }
    assert_eq!(kind(&["Windows error 868: The remote name did not resolve."]), FailureKind::NameNotResolved);
    for code in ["800", "809", "815", "0x8007274C"] {
        assert_eq!(kind(&[&format!("Windows error {code}: …")]), FailureKind::ServerUnreachable, "{code}");
    }
    for other in [
        "Windows error 6910: x",
        "Windows error 8000: x",
        "Windows error 13868: x",
        "Windows error 789: x",
        "Windows error 0x80004005: x",
    ] {
        assert_eq!(kind(&[other]), FailureKind::Unknown, "{other}");
    }
}

#[test]
fn the_last_classified_line_wins() {
    assert_eq!(
        kind(&["Network is unreachable", "Inactivity timeout (--ping-restart)"]),
        FailureKind::ServerNotResponding
    );
    assert_eq!(kind(&["Inactivity timeout (--ping-restart)", "AUTH_FAILED"]), FailureKind::AuthFailed);
    assert_eq!(kind(&["AUTH_FAILED", "Initialization Sequence Completed", "unrelated line"]), FailureKind::AuthFailed);
    assert_eq!(kind(&["Initialization Sequence Completed"]), FailureKind::Unknown);
    assert_eq!(kind(&[]), FailureKind::Unknown);
}

#[test]
fn texts_are_fixed_and_localized() {
    with_language(AppLanguage::En, || {
        assert_eq!(plain(FailureKind::ServerNotResponding).as_deref(), Some("The server stopped responding."));
        assert_eq!(plain(FailureKind::Unknown), None);
    });
    with_language(AppLanguage::Hu, || {
        assert_eq!(plain(FailureKind::ServerNotResponding).as_deref(), Some("A szerver nem válaszol."));
    });
}

#[test]
fn every_known_kind_has_a_hungarian_text() {
    for k in ALL.into_iter().filter(|k| *k != FailureKind::Unknown) {
        let en = with_language(AppLanguage::En, || plain(k)).expect("an English text");
        let hu = with_language(AppLanguage::Hu, || plain(k)).expect("a Hungarian text");
        assert_ne!(en, hu, "{k:?} has no Hungarian text");
    }
}

#[test]
fn texts_never_quote_the_log() {
    let line = "vpn.example.com 192.0.2.1 user alice AUTH_FAILED VERIFY ERROR Cannot resolve host address \
                Inactivity timeout (--ping-restart) Network is unreachable";
    for k in ALL {
        for lang in [AppLanguage::En, AppLanguage::Hu] {
            let text = with_language(lang, || plain(k)).unwrap_or_default();
            for word in ["vpn.example.com", "192.0.2.1", "alice", "AUTH_FAILED", "ping-restart"] {
                assert!(line.contains(word));
                assert!(!text.contains(word), "{k:?} quotes {word}");
            }
        }
    }
}

#[test]
fn retry_is_pointless_only_for_credentials_and_certificates() {
    assert!(!FailureKind::AuthFailed.worth_retrying());
    assert!(!FailureKind::CertificateProblem.worth_retrying());
    for k in ALL.into_iter().filter(|k| !matches!(k, FailureKind::AuthFailed | FailureKind::CertificateProblem)) {
        assert!(k.worth_retrying(), "{k:?}");
    }
}
