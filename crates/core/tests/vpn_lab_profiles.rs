//! The VPN test lab's client profiles (`scripts/vpn-lab/profiles.sh`) are what MacVPN and WinVPN import: each one
//! is detected as the right kind, passes the import and the validator of its kind for macOS and for Windows without
//! an issue or a risky finding, and the SSTP files are in the app's own (canonical) form.
//!
//! Runs only when `MVPN_LAB_CLIENT_DIR` names a generated `client` folder (`scripts/test-vpn-lab.sh` generates one
//! with throwaway values and sets it); without it the test returns at once.

mod common;

use common::lang;
use macvpn_core::TargetOs;
use macvpn_core::importer;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::VPNKind;
use macvpn_core::validators::{
    CertMode, ConfigValidator, OpenVPNValidator, SSTPConfig, SSTPValidator, StrongSwanValidator, WireGuardValidator,
};
use std::collections::HashSet;
use std::path::Path;

fn os_of(folder: &str) -> TargetOs {
    match folder {
        "macos" => TargetOs::MacOs,
        "windows" => TargetOs::Windows,
        _ => unreachable!(),
    }
}

/// Every profile of one OS folder: (file name, expected kind).
fn expected(folder: &str) -> Vec<(&'static str, VPNKind)> {
    let mut v = vec![
        ("openvpn-tun-dco.ovpn", VPNKind::Openvpn),
        ("openvpn-tun-cbc.ovpn", VPNKind::Openvpn),
        ("openvpn-static-challenge.ovpn", VPNKind::Openvpn),
        ("ikev2-eap.swanctl.conf", VPNKind::Strongswan),
        ("ikev2-psk.swanctl.conf", VPNKind::Strongswan),
        ("ikev2-cert.swanctl.conf", VPNKind::Strongswan),
        ("sstp-ca.sstp", VPNKind::Sstp),
        ("sstp-ca-alt-port.sstp", VPNKind::Sstp),
        ("sstp-system-ca.sstp", VPNKind::Sstp),
        ("sstp-no-verification.sstp", VPNKind::Sstp),
    ];
    if folder == "macos" {
        v.push(("wireguard-macos.conf", VPNKind::Wireguard));
    } else {
        v.push(("wireguard-windows.conf", VPNKind::Wireguard));
        v.push(("openvpn-tap-l2.ovpn", VPNKind::Openvpn));
    }
    v
}

#[test]
fn every_lab_profile_imports_and_validates_on_macos_and_windows() {
    let Some(dir) = std::env::var_os("MVPN_LAB_CLIENT_DIR") else {
        eprintln!("MVPN_LAB_CLIENT_DIR is not set: nothing to check (scripts/test-vpn-lab.sh sets it)");
        return;
    };
    lang(AppLanguage::En);
    let root = Path::new(&dir);
    for folder in ["macos", "windows"] {
        let os = os_of(folder);
        let base = root.join(folder);
        let expected = expected(folder);
        let present: HashSet<String> = std::fs::read_dir(&base)
            .unwrap_or_else(|e| panic!("{}: {e}", base.display()))
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.ends_with(".txt") && !n.ends_with(".pem") && !n.ends_with(".cer") && !n.ends_with(".p12"))
            .collect();
        let wanted: HashSet<String> = expected.iter().map(|(n, _)| n.to_string()).collect();
        assert_eq!(present, wanted, "{folder}: the profile set");

        for (name, kind) in expected {
            let path = base.join(name);
            let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let what = format!("{folder}/{name}");
            assert_eq!(importer::detect_kind(name, &text), Some(kind), "{what}: detected kind");
            let prepared = importer::prepare(name, &text, &base).unwrap_or_else(|e| panic!("{what}: import: {e}"));
            assert_eq!(prepared.kind, kind, "{what}: imported kind");
            assert!(prepared.inlined_files.is_empty(), "{what}: refers to no file");
            assert!(!prepared.has_encrypted_key, "{what}: no encrypted key");
            match kind {
                VPNKind::Openvpn => {
                    let v = OpenVPNValidator.validate_full_for(os, &text, &HashSet::new());
                    assert!(v.issues.is_empty(), "{what}: {:?}", v.issues);
                    assert!(v.risky.is_empty(), "{what}: risky {:?}", v.risky_names());
                }
                VPNKind::Wireguard => {
                    let issues = WireGuardValidator.validate_for(os, &text);
                    assert!(issues.is_empty(), "{what}: {issues:?}");
                }
                VPNKind::Strongswan => {
                    let issues = StrongSwanValidator.validate(&text);
                    assert!(issues.is_empty(), "{what}: {issues:?}");
                    assert!(StrongSwanValidator::names(&text).is_some(), "{what}: a connection and a child");
                }
                VPNKind::Sstp => {
                    let issues = SSTPValidator.validate(&text);
                    assert!(issues.is_empty(), "{what}: {issues:?}");
                    let config = SSTPConfig::parse(&text);
                    assert_eq!(config.serialized(), text, "{what}: the app's own form");
                    let want = match name {
                        "sstp-system-ca.sstp" => CertMode::System,
                        "sstp-no-verification.sstp" => CertMode::Insecure,
                        _ => CertMode::Ca,
                    };
                    assert_eq!(config.cert, want, "{what}: certificate mode");
                    assert_eq!(config.ca_pem.is_empty(), want != CertMode::Ca, "{what}: the CA block");
                }
                VPNKind::L2tp | VPNKind::Cisco => unreachable!(),
            }
            assert!(prepared.issues.is_empty(), "{what}: import issues {:?}", prepared.issues);
        }
    }
}

#[test]
fn the_ikev2_profiles_name_their_connection_and_child() {
    let Some(dir) = std::env::var_os("MVPN_LAB_CLIENT_DIR") else {
        return;
    };
    for folder in ["macos", "windows"] {
        for (name, conn) in [
            ("ikev2-eap.swanctl.conf", "lab-eap"),
            ("ikev2-psk.swanctl.conf", "lab-psk"),
            ("ikev2-cert.swanctl.conf", "lab-cert"),
        ] {
            let text = std::fs::read_to_string(Path::new(&dir).join(folder).join(name)).expect("profile");
            assert_eq!(
                StrongSwanValidator::names(&text),
                Some((conn.to_string(), conn.to_string())),
                "{folder}/{name}"
            );
        }
    }
}
