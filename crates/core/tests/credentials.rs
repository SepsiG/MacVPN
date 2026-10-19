//! The credential prompt's pure logic: the required fields per kind, what is missing, merging the typed values,
//! checking them, and the sign-in failure classifier.

use macvpn_core::credentials::{
    self, CredentialField, CredentialValues, RequiredFields, apply, is_sign_in_failure, missing, required_fields,
    validate_values,
};
use macvpn_core::importer;
use macvpn_core::l10n::{self, AppLanguage};
use macvpn_core::models::{AuthWaitKind, Secrets, VPNKind};
use std::path::PathBuf;
use zeroize::Zeroizing;

use CredentialField::{KeyPassword, Password, Psk, Username};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(repo_root().join("Tests/Fixtures/mikrotik").join(name)).unwrap()
}

fn fields(r: &RequiredFields) -> Vec<CredentialField> {
    r.fields.iter().copied().collect()
}

fn required(kind: VPNKind, config: &str) -> Vec<CredentialField> {
    fields(&required_fields(kind, Some(config)))
}

fn value(s: &str) -> Option<Zeroizing<String>> {
    Some(Zeroizing::new(s.to_string()))
}

// MARK: - required fields

#[test]
fn openvpn_template_needs_user_name_and_password() {
    assert_eq!(required(VPNKind::Openvpn, &importer::template(VPNKind::Openvpn)), vec![Username, Password]);
}

#[test]
fn openvpn_inline_credentials_need_nothing() {
    let config = importer::template(VPNKind::Openvpn) + "<auth-user-pass>\nalice\nsecret\n</auth-user-pass>\n";
    assert_eq!(required(VPNKind::Openvpn, &config), vec![]);
}

#[test]
fn openvpn_commented_out_auth_user_pass_needs_nothing() {
    for comment in ["#", ";"] {
        let config =
            importer::template(VPNKind::Openvpn).replace("auth-user-pass", &format!("{comment}auth-user-pass"));
        assert_eq!(required(VPNKind::Openvpn, &config), vec![], "{comment}");
        let config =
            importer::template(VPNKind::Openvpn).replace("auth-user-pass", &format!("{comment} auth-user-pass"));
        assert_eq!(required(VPNKind::Openvpn, &config), vec![], "{comment} with a space");
    }
}

#[test]
fn openvpn_auth_user_pass_with_a_file_needs_nothing() {
    let config = importer::template(VPNKind::Openvpn).replace("auth-user-pass", "auth-user-pass auth.txt");
    assert_eq!(required(VPNKind::Openvpn, &config), vec![]);
}

#[test]
fn openvpn_auth_user_pass_inside_another_block_does_not_count() {
    let config = "client\nremote vpn.example.com 1194\n<ca>\nauth-user-pass\n</ca>\n";
    assert_eq!(required(VPNKind::Openvpn, config), vec![]);
}

#[test]
fn openvpn_encrypted_key_needs_the_key_password() {
    let config = "client\nremote vpn.example.com 1194\n<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n</key>\n";
    assert_eq!(required(VPNKind::Openvpn, config), vec![KeyPassword]);
    let legacy = "client\nremote vpn.example.com 1194\n<key>\n-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAAAA\n-----END RSA PRIVATE KEY-----\n</key>\n";
    assert_eq!(required(VPNKind::Openvpn, legacy), vec![KeyPassword]);
}

/// A PKCS#12 block is not flagged by `importer::contains_encrypted_key` (its password may be empty): no prompt,
/// the root layer decides.
#[test]
fn openvpn_pkcs12_is_not_asked_for() {
    let config = "client\nremote vpn.example.com 1194\n<pkcs12>\nMIIAAA==\n</pkcs12>\n";
    assert!(!importer::contains_encrypted_key(config));
    assert_eq!(required(VPNKind::Openvpn, config), vec![]);
}

#[test]
fn mikrotik_fixtures() {
    let expected: [(&str, Vec<CredentialField>); 6] = [
        ("routeros-v6-imported.ovpn", vec![Username, Password, KeyPassword]),
        // `auth-user-pass auth.cfg`: a file argument, the root layer refuses it anyway.
        ("routeros-v6-wiki.ovpn", vec![]),
        ("routeros-v7-export-tcp.ovpn", vec![Username, Password, KeyPassword]),
        ("routeros-v7-export-tls-crypt.ovpn", vec![Username, Password, KeyPassword]),
        ("routeros-v7-export-udp.ovpn", vec![Username, Password, KeyPassword]),
        ("routeros-wiki-extras.ovpn", vec![Username, Password, KeyPassword]),
    ];
    for (name, want) in expected {
        assert_eq!(required(VPNKind::Openvpn, &fixture(name)), want, "{name}");
    }
}

#[test]
fn ikev2_eap_needs_user_name_and_password() {
    let template = importer::template(VPNKind::Strongswan);
    assert!(template.contains("auth = eap-mschapv2"));
    assert_eq!(required(VPNKind::Strongswan, &template), vec![Username, Password]);
}

#[test]
fn ikev2_pubkey_needs_nothing() {
    let config = importer::template(VPNKind::Strongswan).replace("auth = eap-mschapv2", "auth = pubkey");
    assert_eq!(required(VPNKind::Strongswan, &config), vec![]);
}

#[test]
fn ikev2_eap_in_a_comment_or_the_remote_section_needs_nothing() {
    let config = importer::template(VPNKind::Strongswan).replace("auth = eap-mschapv2", "auth = pubkey # auth = eap");
    assert_eq!(required(VPNKind::Strongswan, &config), vec![]);
    let config = importer::template(VPNKind::Strongswan)
        .replace("auth = eap-mschapv2", "auth = pubkey")
        .replace("      auth = pubkey\n      id = vpn", "      auth = eap\n      id = vpn");
    assert_eq!(required(VPNKind::Strongswan, &config), vec![]);
}

#[test]
fn fixed_fields_of_the_other_kinds() {
    assert_eq!(fields(&required_fields(VPNKind::L2tp, None)), vec![Username, Password, Psk]);
    assert_eq!(fields(&required_fields(VPNKind::Cisco, None)), vec![Username, Password, Psk]);
    assert_eq!(required(VPNKind::Sstp, &importer::template(VPNKind::Sstp)), vec![Password]);
    assert_eq!(required(VPNKind::Wireguard, &importer::template(VPNKind::Wireguard)), vec![]);
}

#[test]
fn unreadable_config_leaves_it_to_the_root_layer() {
    assert_eq!(fields(&required_fields(VPNKind::Openvpn, None)), vec![]);
    assert_eq!(fields(&required_fields(VPNKind::Strongswan, None)), vec![]);
    assert_eq!(fields(&required_fields(VPNKind::Sstp, None)), vec![Password]);
}

// MARK: - missing, apply

#[test]
fn missing_fields_in_display_order() {
    let all = required_fields(VPNKind::L2tp, None);
    assert_eq!(missing(&all, &Secrets::default()), vec![Username, Password, Psk]);
    let stored = Secrets { username: Some("alice".into()), psk: Some(String::new()), ..Secrets::default() };
    assert_eq!(missing(&all, &stored), vec![Password, Psk]);
    let full = Secrets {
        username: Some("alice".into()),
        password: Some("pw".into()),
        psk: Some("k".into()),
        ..Secrets::default()
    };
    assert_eq!(missing(&all, &full), vec![]);
    let mut openvpn = RequiredFields::default();
    openvpn.fields.extend([KeyPassword, Password, Username]);
    assert_eq!(missing(&openvpn, &Secrets::default()), vec![Username, Password, KeyPassword]);
}

#[test]
fn apply_overrides_only_the_typed_fields() {
    let base = Secrets {
        username: Some("alice".into()),
        password: Some("old".into()),
        psk: Some("k".into()),
        challenge_packed: true,
        ..Secrets::default()
    };
    let values = CredentialValues { password: value("new"), ..CredentialValues::default() };
    let merged = apply(&values, &base);
    assert_eq!(merged.username.as_deref(), Some("alice"));
    assert_eq!(merged.password.as_deref(), Some("new"));
    assert_eq!(merged.psk.as_deref(), Some("k"));
    assert_eq!(merged.key_password, None);
    assert!(merged.challenge_packed);
}

// MARK: - validate

#[test]
fn values_are_checked() {
    let asked = [Username, Password];
    let ok = CredentialValues { username: value("alice"), password: value("pw"), ..CredentialValues::default() };
    assert_eq!(validate_values(&ok, &asked, VPNKind::Openvpn), Ok(()));
    let missing_one = CredentialValues { username: value("alice"), ..CredentialValues::default() };
    assert!(validate_values(&missing_one, &asked, VPNKind::Openvpn).is_err());
    for bad in ["", "a\nb", "a\u{2028}b", &"x".repeat(1025)] {
        let v = CredentialValues { username: value("alice"), password: value(bad), ..CredentialValues::default() };
        assert!(validate_values(&v, &asked, VPNKind::Openvpn).is_err(), "{:?}", bad.len());
    }
    let max = CredentialValues {
        username: value("alice"),
        password: value(&"x".repeat(1024)),
        ..CredentialValues::default()
    };
    assert_eq!(validate_values(&max, &asked, VPNKind::Openvpn), Ok(()));
}

#[test]
fn sstp_password_rule() {
    let v = CredentialValues { password: value("a\"b"), ..CredentialValues::default() };
    assert!(validate_values(&v, &[Password], VPNKind::Sstp).is_err());
    assert_eq!(validate_values(&v, &[Password], VPNKind::Openvpn), Ok(()));
}

// MARK: - sign-in failure

#[test]
fn sign_in_failures_in_both_languages() {
    for key in [
        "Authentication failed (AUTH_FAILED)",
        "Authentication failed",
        "Authentication failed (wrong user name or password)",
    ] {
        let hu = l10n::hungarian(key).unwrap();
        assert!(is_sign_in_failure(key), "{key}");
        assert!(is_sign_in_failure(hu), "{hu}");
        assert!(is_sign_in_failure(&format!("some earlier line\n{key}\n")), "{key} after a line");
        assert!(is_sign_in_failure(&format!("  {hu}  \n\n")), "{hu} trimmed");
    }
}

#[test]
fn other_failures_are_not_sign_in_failures() {
    for message in [
        "IKE negotiation failed (details in the log)",
        "Authentication cancelled",
        "x Authentication failed y",
        "Authentication failed\nsomething else",
        "",
    ] {
        assert!(!is_sign_in_failure(message), "{message}");
    }
}

#[test]
fn sign_in_failed_text_is_translated() {
    let en = l10n::with_language(AppLanguage::En, credentials::sign_in_failed_text);
    assert_eq!(en, "Sign-in failed — check the username and password");
    let hu = l10n::with_language(AppLanguage::Hu, credentials::sign_in_failed_text);
    assert_ne!(hu, en);
}

// MARK: - types

#[test]
fn debug_never_shows_a_value() {
    let v = CredentialValues {
        username: value("alice-user"),
        password: value("hunter2-secret"),
        psk: None,
        key_password: value("kp-secret"),
    };
    let text = format!("{v:?}");
    for secret in ["alice-user", "hunter2-secret", "kp-secret"] {
        assert!(!text.contains(secret), "{text}");
    }
    assert!(text.contains("password"), "{text}");
}

#[test]
fn field_names() {
    assert_eq!(Username.name(), "username");
    assert_eq!(Password.name(), "password");
    assert_eq!(Psk.name(), "psk");
    assert_eq!(KeyPassword.name(), "keyPassword");
    for f in [Username, Password, Psk, KeyPassword] {
        assert_eq!(CredentialField::from_name(f.name()), Some(f));
    }
    assert_eq!(CredentialField::from_name("code"), None);
}

#[test]
fn credentials_wait_kind_exists() {
    assert_ne!(AuthWaitKind::Credentials, AuthWaitKind::Code);
}

#[test]
fn only_the_key_block_counts_for_the_key_password() {
    let marker = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    let commented = format!("client\nremote vpn.example.com 1194\n# {marker}\n; Proc-Type: 4,ENCRYPTED\n");
    assert_eq!(required(VPNKind::Openvpn, &commented), vec![]);
    let in_cert = format!("client\nremote vpn.example.com 1194\n<cert>\n{marker}\n</cert>\n");
    assert_eq!(required(VPNKind::Openvpn, &in_cert), vec![]);
    let in_key = format!("client\nremote vpn.example.com 1194\n<key>\n{marker}\nAAAA\n</key>\n");
    assert_eq!(required(VPNKind::Openvpn, &in_key), vec![KeyPassword]);
}
