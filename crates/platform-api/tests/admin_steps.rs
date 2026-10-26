//! The administrator steps' defaults (WinVPN 2c Task 12): macOS has none, every step says so.

use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_platform_api::{AdminSteps, NoAdminSteps};

#[test]
fn macos_has_no_admin_steps() {
    with_language(AppLanguage::En, || {
        let steps = NoAdminSteps;
        let no = "Not available on this system";
        assert_eq!(steps.ca_summary("-----BEGIN CERTIFICATE-----").unwrap_err(), no);
        assert_eq!(steps.ca_trusted(""), None);
        assert_eq!(steps.trust_ca("").unwrap_err(), no);
        assert_eq!(steps.allow_l2tp_behind_nat().unwrap_err(), no);
    });
}

/// WinVPN 2c Task 11: macOS offers no administrator step on a connection's error, and its editors show no
/// platform notes (the view model stays as it was).
#[test]
fn macos_offers_no_action_and_no_editor_notes() {
    use macvpn_core::models::{Connection, VPNKind};
    use macvpn_platform_api::{NativeSupport, NoNativeSupport, PlatformNotes};
    with_language(AppLanguage::En, || {
        assert_eq!(NoAdminSteps.offered_action("Allow L2TP Behind NAT…"), None);
        let support = NoNativeSupport;
        for kind in VPNKind::ALL {
            let c = Connection::new("Office", kind);
            assert_eq!(support.editor_notes(&c, b"remote_addrs = vpn.example.com"), PlatformNotes::default());
        }
        assert_eq!(support.system_psk_note(), None);
        assert!(PlatformNotes::default().is_empty());
    });
}
