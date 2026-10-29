//! Client profiles of the firewalls and gateways people commonly run their VPN server on: Ubiquiti UniFi (the
//! WireGuard and OpenVPN servers of UniFi OS gateways), pfSense (OpenVPN Client Export package) and OPNsense
//! (OpenVPN client export). Each one imports cleanly and passes its kind's validator for macOS and for Windows
//! without an issue or a risky finding; what the policy refuses on purpose is pinned too. The IPsec files are the
//! `swanctl.conf` a user writes for these firewalls' mobile IPsec (they export no client file).
//!
//! Fixtures: `Tests/Fixtures/{unifi,pfsense,opnsense}/` (fake keys and certificates, documentation addresses).
//! Formats and sources: `docs/how-to.en.md` ("UniFi, pfSense and OPNsense") and `docs/openvpn-directives.md`.

mod common;

use common::{TempDir, lang, repo_root};
use macvpn_core::TargetOs;
use macvpn_core::importer;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::VPNKind;
use macvpn_core::ras::policy::{DhGroup, EspCipher, EspIntegrity, IkeCipher, IkeIntegrity};
use macvpn_core::ras::{self, Auth, DefaultRoute};
use macvpn_core::validators::{
    ConfigValidator, OpenVPNTier, OpenVPNValidator, StrongSwanValidator, WireGuardValidator,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const BOTH: [TargetOs; 2] = [TargetOs::MacOs, TargetOs::Windows];

fn fixtures() -> PathBuf {
    repo_root().join("Tests/Fixtures")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The OpenVPN and WireGuard profiles that import as they are (inline key material).
const PROFILES: &[(&str, VPNKind)] = &[
    ("unifi/wireguard-full-tunnel.conf", VPNKind::Wireguard),
    ("unifi/wireguard-split-tunnel.conf", VPNKind::Wireguard),
    ("unifi/openvpn-server.ovpn", VPNKind::Openvpn),
    ("unifi/openvpn-server-legacy-lzo.ovpn", VPNKind::Openvpn),
    ("pfsense/openvpn-inline-most-clients.ovpn", VPNKind::Openvpn),
    ("pfsense/openvpn-inline-connect-tls-crypt.ovpn", VPNKind::Openvpn),
    ("pfsense/openvpn-inline-android-user-auth.ovpn", VPNKind::Openvpn),
    ("pfsense/wireguard.conf", VPNKind::Wireguard),
    ("opnsense/openvpn-file-only.ovpn", VPNKind::Openvpn),
    ("opnsense/openvpn-tcp-tls-crypt-v2.ovpn", VPNKind::Openvpn),
    ("opnsense/wireguard.conf", VPNKind::Wireguard),
];

/// The import (detection, inlining, validation for this OS) and the validator for macOS and for Windows.
fn assert_imports_cleanly(what: &str, name: &str, text: &str, base: &Path, kind: VPNKind) -> importer::PreparedImport {
    assert_eq!(importer::detect_kind(name, text), Some(kind), "{what}: detected kind");
    let prepared = importer::prepare(name, text, base).unwrap_or_else(|e| panic!("{what}: import: {e}"));
    assert_eq!(prepared.kind, kind, "{what}: imported kind");
    assert!(prepared.issues.is_empty(), "{what}: import issues {:?}", prepared.issues);
    assert!(prepared.risky.is_empty(), "{what}: import risky {:?}", prepared.risky);
    assert!(!prepared.has_encrypted_key, "{what}: no encrypted key");
    for os in BOTH {
        match kind {
            VPNKind::Openvpn => {
                let v = OpenVPNValidator.validate_full_for(os, &prepared.config, &HashSet::new());
                assert!(v.issues.is_empty(), "{what} ({os:?}): {:?}", v.issues);
                assert!(v.risky.is_empty(), "{what} ({os:?}): risky {:?}", v.risky_names());
            }
            VPNKind::Wireguard => {
                let issues = WireGuardValidator.validate_for(os, &prepared.config);
                assert!(issues.is_empty(), "{what} ({os:?}): {issues:?}");
            }
            _ => unreachable!(),
        }
    }
    prepared
}

#[test]
fn every_vendor_profile_imports_cleanly_on_macos_and_windows() {
    lang(AppLanguage::En);
    for (path, kind) in PROFILES {
        let full = fixtures().join(path);
        let text = read(&full);
        let name = full.file_name().unwrap().to_str().unwrap();
        let prepared = assert_imports_cleanly(path, name, &text, full.parent().unwrap(), *kind);
        assert!(prepared.inlined_files.is_empty(), "{path}: refers to no file");
        assert_eq!(prepared.config, text, "{path}: imported unchanged");
    }
}

/// UniFi's WireGuard server: one client file per device, the server's own tunnel address in `AllowedIPs`, the
/// gateway as DNS; "Remote Client Networks" make it a split tunnel (no default route).
#[test]
fn unifi_wireguard_full_and_split_tunnel() {
    let allowed = |path: &str| -> Vec<String> {
        let text = read(&fixtures().join(path));
        let line = text.lines().find(|l| l.starts_with("AllowedIPs")).expect("AllowedIPs");
        line.split_once('=').unwrap().1.split(',').map(|s| s.trim().to_string()).collect()
    };
    assert!(allowed("unifi/wireguard-full-tunnel.conf").contains(&"0.0.0.0/0".to_string()));
    let split = allowed("unifi/wireguard-split-tunnel.conf");
    assert!(!split.iter().any(|a| a.ends_with("/0")), "{split:?}");
    assert!(split.contains(&"10.20.30.0/24".to_string()));
}

/// pfSense's "Archive" / "Config File Only" export refers to files next to the `.ovpn` (`pkcs12`, `tls-auth … 1`):
/// as written the validator refuses exactly those lines (root would read a file), and the import turns them into
/// inline blocks when the files sit next to it.
#[test]
fn pfsense_archive_export_is_inlined_on_import() {
    lang(AppLanguage::En);
    let src = fixtures().join("pfsense/archive");
    let name = "pfSense-UDP4-1194-alice.ovpn";
    let text = read(&src.join(name));

    let as_written = OpenVPNValidator.validate_full(&text, &HashSet::new());
    assert_eq!(as_written.issues.len(), 2, "{:?}", as_written.issues);
    for issue in &as_written.issues {
        assert!(issue.message.starts_with("External file reference, use an inline block: "), "{}", issue.display());
    }

    let dir = TempDir::new();
    std::fs::create_dir_all(dir.path()).unwrap();
    std::fs::write(dir.path().join(name), &text).unwrap();
    std::fs::copy(src.join("pfSense-UDP4-1194-alice-tls.key"), dir.path().join("pfSense-UDP4-1194-alice-tls.key"))
        .unwrap();
    // A PKCS#12-shaped stand-in (DER SEQUENCE + INTEGER 3): the import recognises the format, it never opens it.
    let mut p12 = vec![0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x03];
    p12.resize(256, 0xA5);
    std::fs::write(dir.path().join("pfSense-UDP4-1194-alice.p12"), &p12).unwrap();

    let prepared = assert_imports_cleanly("pfsense/archive", name, &text, dir.path(), VPNKind::Openvpn);
    assert_eq!(
        prepared.inlined_files,
        ["pfSense-UDP4-1194-alice.p12".to_string(), "pfSense-UDP4-1194-alice-tls.key".to_string()]
    );
    let lines: Vec<&str> = prepared.config.lines().collect();
    assert!(lines.contains(&"<pkcs12>") && lines.contains(&"<tls-auth>"), "{}", prepared.config);
    assert!(lines.contains(&"key-direction 1"), "{}", prepared.config);
    assert!(!prepared.config.contains("pkcs12 pfSense") && !prepared.config.contains("tls-auth pfSense"));
}

/// The export options that hand the key to something else are refused by the policy (docs: use the inline export
/// with the certificate in the file): the Windows certificate store (`cryptoapicert`, "Microsoft Certificate
/// Storage") and PKCS#11 tokens (`pkcs11-providers` / `pkcs11-id`, they load a library as root / SYSTEM).
#[test]
fn certificate_store_and_token_exports_are_refused() {
    lang(AppLanguage::En);
    let base = read(&fixtures().join("pfsense/openvpn-inline-android-user-auth.ovpn"));
    let with = |line: &str| format!("{line}\n{base}");

    let cryptoapi = with("cryptoapicert \"SUBJ:alice\"");
    let windows = OpenVPNValidator.validate_full_for(TargetOs::Windows, &cryptoapi, &HashSet::new());
    assert_eq!(windows.issues.len(), 1, "{:?}", windows.issues);
    assert_eq!(windows.issues[0].line, 1);
    assert_eq!(OpenVPNValidator::tier_for(TargetOs::Windows, "cryptoapicert"), OpenVPNTier::Forbidden);
    let mac = OpenVPNValidator.validate_full_for(TargetOs::MacOs, &cryptoapi, &HashSet::new());
    assert_eq!(mac.risky_names(), ["cryptoapicert".to_string()]);

    for os in BOTH {
        let token = with("pkcs11-providers '/usr/lib/opensc-pkcs11.so'\npkcs11-id 'alice'");
        let v = OpenVPNValidator.validate_full_for(os, &token, &HashSet::new());
        assert_eq!(v.issues.iter().map(|i| i.line).collect::<Vec<_>>(), [1, 2], "{os:?}: {:?}", v.issues);
    }
}

/// Some UniFi guides show a client file with `user nobody` / `group nogroup` (from OpenVPN's sample client.conf).
/// They stay RISKY (reconnects may fail after dropping root): the import lists them for acknowledgement.
#[test]
fn privilege_drop_lines_from_guides_stay_risky() {
    lang(AppLanguage::En);
    let text = format!("{}user nobody\ngroup nogroup\n", read(&fixtures().join("unifi/openvpn-server.ovpn")));
    for os in BOTH {
        let v = OpenVPNValidator.validate_full_for(os, &text, &HashSet::new());
        assert!(v.issues.is_empty(), "{os:?}: {:?}", v.issues);
        assert_eq!(v.risky_names(), ["group".to_string(), "user".to_string()], "{os:?}");
        let acknowledged: HashSet<String> = ["user", "group"].iter().map(|s| s.to_string()).collect();
        let v = OpenVPNValidator.validate_full_for(os, &text, &acknowledged);
        assert!(v.all_issues().is_empty(), "{os:?}: {:?}", v.all_issues());
    }
}

// --- IPsec (pfSense / OPNsense mobile IPsec, typed as swanctl.conf) -------------------------------------------

const SWAN: &[&str] = &[
    "pfsense/ikev2-eap-mschapv2.swanctl.conf",
    "pfsense/ikev2-eap-tls.swanctl.conf",
    "pfsense/ikev2-psk.swanctl.conf",
    "opnsense/ikev2-eap-mschapv2.swanctl.conf",
    "opnsense/ikev2-cert.swanctl.conf",
];

#[test]
fn firewall_ikev2_configs_pass_the_strongswan_validator() {
    lang(AppLanguage::En);
    for path in SWAN {
        let full = fixtures().join(path);
        let text = read(&full);
        let name = full.file_name().unwrap().to_str().unwrap();
        assert_eq!(importer::detect_kind(name, &text), Some(VPNKind::Strongswan), "{path}");
        let prepared = importer::prepare(name, &text, full.parent().unwrap()).unwrap();
        assert!(prepared.issues.is_empty(), "{path}: {:?}", prepared.issues);
        assert!(StrongSwanValidator.validate(&text).is_empty(), "{path}");
        assert!(StrongSwanValidator::names(&text).is_some(), "{path}: a connection and a child");
    }
}

fn plan(path: &str) -> Result<ras::RasEntryPlan, ras::Unsupported> {
    lang(AppLanguage::En);
    ras::plan_ikev2(read(&fixtures().join(path)).as_bytes())
}

/// The proposals of Netgate's mobile IKEv2 EAP-MSCHAPv2 recipe (AES-256-GCM / DH 16 first, which Windows lacks,
/// then AES-256 / SHA-256 / DH 14; ESP AES-GCM with PFS 14) map to the Windows IKEv2 client.
#[test]
fn pfsense_eap_mschapv2_maps_to_windows() {
    let p = plan("pfsense/ikev2-eap-mschapv2.swanctl.conf").unwrap();
    assert_eq!(p.auth, Auth::EapMsChapV2);
    assert_eq!(p.server, "vpn.example.com");
    assert_eq!(p.user, "alice");
    assert_eq!(p.default_route, DefaultRoute::None);
    assert!(p.ts_as_routes);
    let policy = p.policy.unwrap();
    assert_eq!(
        (policy.ike_cipher, policy.ike_integrity, policy.dh_group),
        (IkeCipher::Aes256, IkeIntegrity::Sha256, DhGroup::Group14)
    );
    assert_eq!(
        (policy.esp_cipher, policy.esp_integrity, policy.pfs),
        (EspCipher::Aes256Gcm16, EspIntegrity::Gcm256, Some(DhGroup::Group14))
    );
}

/// OPNsense's `default` proposals and a certificate profile with AES-GCM / ECP-256 first.
#[test]
fn opnsense_profiles_map_to_windows() {
    let p = plan("opnsense/ikev2-eap-mschapv2.swanctl.conf").unwrap();
    assert_eq!(p.auth, Auth::EapMsChapV2);
    assert_eq!(p.default_route, DefaultRoute::Both);
    let p = plan("opnsense/ikev2-cert.swanctl.conf").unwrap();
    assert_eq!(p.auth, Auth::MachineCertificate);
    let policy = p.policy.unwrap();
    assert_eq!(
        (policy.ike_cipher, policy.ike_integrity, policy.dh_group),
        (IkeCipher::Aes256Gcm16, IkeIntegrity::Sha256, DhGroup::Ecp256)
    );
    assert_eq!(
        (policy.esp_cipher, policy.esp_integrity, policy.pfs),
        (EspCipher::Aes256Gcm16, EspIntegrity::Gcm256, Some(DhGroup::Ecp256))
    );
}

/// What the Windows IKEv2 client cannot do (documented): a pre-shared key, and EAP-TLS (a user certificate over
/// EAP; Windows here uses the computer certificate with `auth = pubkey`). macOS (strongSwan) runs both.
#[test]
fn psk_and_eap_tls_are_not_supported_on_windows() {
    let e = plan("pfsense/ikev2-psk.swanctl.conf").unwrap_err();
    assert!(!e.invalid_config, "{e:?}");
    assert!(e.reasons.iter().any(|r| r.starts_with("Not supported on Windows: local auth = psk")), "{e:?}");
    let e = plan("pfsense/ikev2-eap-tls.swanctl.conf").unwrap_err();
    assert!(!e.invalid_config, "{e:?}");
    assert!(e.reasons.iter().any(|r| r.contains("eap-tls")), "{e:?}");
}
