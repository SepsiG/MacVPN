//! The system VPNs' pure parts (`pure::system_vpn`), on every OS.

use macvpn_core::l10n::{self, AppLanguage};
use macvpn_core::models::VPNKind;
use macvpn_platform_api::{SetupReport, SystemVpn};
use macvpn_platform_win::pure::system_vpn::{
    EntryKind, SavedSignIn, Start, apply_ras_row, connection_status, how_to_start, is_connection_of, ras_row,
    same_phonebook, store_psk, system_id, type_label,
};

const GUID: [u8; 16] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const BOOK: &str = r"C:\Users\Test\AppData\Roaming\Microsoft\Network\Connections\Pbk\rasphone.pbk";

#[test]
fn start_without_secrets_or_saved_credentials_uses_the_dialog() {
    let none = SavedSignIn::default();
    let user = SavedSignIn { user: true, password: false };
    let both = SavedSignIn { user: true, password: true };
    assert_eq!(how_to_start(true, false, none), Start::Dialog);
    assert_eq!(how_to_start(true, false, user), Start::Dialog);
    // WinVPN's stored password, with the user name Windows saved.
    assert_eq!(how_to_start(true, true, user), Start::Params);
    assert_eq!(how_to_start(true, true, both), Start::Params);
    // A stored password without a user name to go with it: Windows' saved credentials, else its window.
    assert_eq!(how_to_start(true, true, none), Start::Dialog);
    assert_eq!(how_to_start(true, true, SavedSignIn { user: false, password: true }), Start::Saved);
    assert_eq!(how_to_start(true, false, both), Start::Saved);
    // A computer certificate needs nothing.
    assert_eq!(how_to_start(false, false, none), Start::Saved);
}

#[test]
fn labels_and_ids() {
    assert_eq!(type_label(EntryKind::L2tp), "L2TP");
    assert_eq!(type_label(EntryKind::Ikev2), "IKEv2");
    assert_eq!(type_label(EntryKind::Sstp), "SSTP");
    assert_eq!(type_label(EntryKind::Other), "VPN");
    let id = system_id(Some(GUID), "Office VPN");
    assert_eq!(id, "12345678-9ABC-DEF0-0123-456789ABCDEF");
    // Stored secrets only for L2TP (as on macOS), and only with a UUID ID.
    assert!(SystemVpn::new(&id, "Office VPN", "L2TP", "Disconnected").supports_stored_secrets());
    assert!(!SystemVpn::new(&id, "Office VPN", "SSTP", "Disconnected").supports_stored_secrets());
    assert!(!SystemVpn::new(&id, "Office VPN", "IKEv2", "Disconnected").supports_stored_secrets());
    let fallback = system_id(Some([0; 16]), "Office VPN");
    assert_eq!(fallback, "RAS:Office VPN");
    assert_eq!(system_id(None, "Office VPN"), fallback);
    assert!(!SystemVpn::new(&fallback, "Office VPN", "L2TP", "Disconnected").supports_stored_secrets());
}

#[test]
fn connection_states_map_to_the_system_status() {
    assert_eq!(connection_status(0x2000, 0), "Connected");
    assert_eq!(connection_status(0x2001, 0), "Disconnected");
    assert_eq!(connection_status(5, 0), "Connecting");
    assert_eq!(connection_status(0, 0), "Connecting");
    assert_eq!(connection_status(5, 691), "Disconnected");
    assert_eq!(connection_status(0x2000, 628), "Disconnected");
    use macvpn_core::models::ConnectionState;
    let state = |s: &str| SystemVpn::new("x", "x", "VPN", s).connection_state();
    assert_eq!(state("Connecting"), ConnectionState::Connecting);
    assert_eq!(state("Disconnected"), ConnectionState::Disconnected);
    assert!(matches!(state("Connected"), ConnectionState::Connected { .. }));
}

#[test]
fn phonebook_paths_compare_without_case() {
    assert!(same_phonebook(BOOK, &BOOK.to_uppercase()));
    assert!(same_phonebook(BOOK, &BOOK.replace('\\', "/")));
    assert!(same_phonebook(&format!(r"\\?\{BOOK}"), BOOK));
    assert!(same_phonebook(r"C:\Users\Gábor\x.pbk", r"C:\USERS\GÁBOR\X.PBK"));
    assert!(!same_phonebook(BOOK, &format!("{BOOK}.bak")));
    assert!(!same_phonebook("", ""));
}

#[test]
fn connections_match_their_entry() {
    // By GUID when both have one, whatever the name or path.
    assert!(is_connection_of(("Old name", "", GUID), ("Office VPN", BOOK, Some(GUID))));
    let mut other = GUID;
    other[0] = 0;
    assert!(!is_connection_of(("Office VPN", BOOK, other), ("Office VPN", BOOK, Some(GUID))));
    // Else by name and phonebook (case-insensitive), or by name when no phonebook is reported.
    assert!(is_connection_of(("Office VPN", &BOOK.to_lowercase(), [0; 16]), ("Office VPN", BOOK, Some(GUID))));
    assert!(is_connection_of(("Office VPN", "", [0; 16]), ("Office VPN", BOOK, None)));
    assert!(!is_connection_of(("Office VPN", r"C:\other.pbk", [0; 16]), ("Office VPN", BOOK, None)));
    assert!(!is_connection_of(("Office", BOOK, [0; 16]), ("Office VPN", BOOK, None)));
}

#[test]
fn the_windows_vpn_client_row() {
    l10n::with_language(AppLanguage::En, || {
        let (row, kinds) = ras_row(|_| false);
        assert!(row.ok && row.usable && row.action.is_none());
        assert_eq!(row.detail, "Built into Windows");
        assert!(kinds.is_empty());

        // SSTP's service disabled: only SSTP is unavailable, with the text.
        let (row, kinds) = ras_row(|s| s == "SstpSvc");
        assert!(!row.ok && row.usable);
        assert_eq!(
            row.detail,
            "The Windows service Secure Socket Tunneling Protocol Service (SstpSvc) is disabled. An administrator must set it to Manual (services.msc)."
        );
        assert_eq!(kinds, vec![(VPNKind::Sstp, row.detail.clone())]);
        let report = SetupReport { ras: Some(row), ras_unsupported_kinds: kinds, ..SetupReport::default() };
        assert!(report.is_available(VPNKind::L2tp) && report.is_available(VPNKind::Strongswan));
        assert!(!report.is_available(VPNKind::Sstp));
        assert!(report.unavailable_text(VPNKind::Sstp).unwrap().contains("SstpSvc"));
        assert!(!report.is_complete());

        // IKEEXT: L2TP and IKEv2.
        let (_, kinds) = ras_row(|s| s == "IKEEXT");
        let listed: Vec<VPNKind> = kinds.iter().map(|(k, _)| *k).collect();
        assert_eq!(listed, vec![VPNKind::L2tp, VPNKind::Strongswan]);

        // RasMan: nothing works; each kind once, with RasMan's text.
        let (row, kinds) = ras_row(|s| s == "RasMan" || s == "SstpSvc");
        assert!(!row.ok && !row.usable);
        assert_eq!(kinds.len(), 3);
        assert!(kinds.iter().all(|(_, t)| t.contains("(RasMan)")));
        assert!(row.detail.contains("(RasMan)") && row.detail.contains("(SstpSvc)"));
    });
}

#[test]
fn the_texts_are_translated() {
    l10n::with_language(AppLanguage::Hu, || {
        let (row, _) = ras_row(|_| false);
        assert_ne!(row.detail, "Built into Windows");
        let (row, _) = ras_row(|s| s == "PolicyAgent");
        assert!(row.detail.contains("PolicyAgent"));
        assert!(!row.detail.contains("is disabled"));
    });
}

#[test]
fn one_windows_vpn_client_row_next_to_cisco() {
    use macvpn_platform_win::pure::{cisco, ras_connect};
    l10n::with_language(AppLanguage::En, || {
        let mut report = SetupReport { ras_unsupported_kinds: cisco::unsupported_kinds(), ..SetupReport::default() };
        ras_connect::complete_report(&mut report);
        apply_ras_row(&mut report, |_| false);
        assert_eq!(report.ras.as_ref().unwrap().detail, "Built into Windows");
        assert_eq!(report.ras_unsupported_kinds, cisco::unsupported_kinds());
        assert!(report.is_available(VPNKind::Sstp) && report.ras.as_ref().unwrap().ok);

        let mut report = SetupReport { ras_unsupported_kinds: cisco::unsupported_kinds(), ..SetupReport::default() };
        ras_connect::complete_report(&mut report);
        apply_ras_row(&mut report, |s| s == "SstpSvc");
        let row = report.ras.clone().unwrap();
        assert!(!row.ok && row.usable && row.detail.contains("SstpSvc"));
        let kinds: Vec<VPNKind> = report.ras_unsupported_kinds.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, vec![VPNKind::Cisco, VPNKind::Sstp]);
        assert!(!report.is_available(VPNKind::Sstp) && report.is_available(VPNKind::L2tp));
        // Applied twice (a re-check of the same report): still each kind once.
        apply_ras_row(&mut report, |s| s == "SstpSvc");
        assert_eq!(report.ras_unsupported_kinds.len(), 2);
    });
}

#[test]
fn a_stored_psk_never_overwrites_the_one_windows_has() {
    assert!(store_psk(true, true, false));
    assert!(!store_psk(true, true, true));
    assert!(!store_psk(true, false, false));
    assert!(!store_psk(false, true, false));
}
