//! Client-credential audit G1 and G3: the certificates of a config (`x509`, `pkcs12`) and the config text with
//! its secrets masked (`config_secrets`). The fixtures in `fixtures/certs` were made with OpenSSL 4 (an EC P-256
//! CA, an RSA 2048 and an Ed25519 client certificate it signed, and PKCS#12 files of the RSA client with and
//! without a password); the expected values are `openssl x509 -noout -subject -issuer -serial -dates
//! -fingerprint` of each.

use base64::Engine;
use macvpn_core::config_secrets::{self, MASK};
use macvpn_core::models::VPNKind;
use macvpn_core::pkcs12::{self, Password};
use macvpn_core::x509::{self, Validity};

const CA: &str = include_str!("fixtures/certs/ca.pem");
const CLIENT_RSA: &str = include_str!("fixtures/certs/client-rsa.pem");
const CLIENT_ED: &str = include_str!("fixtures/certs/client-ed.pem");
const NOT_BEFORE: i64 = 1_793_314_120; // 2026-10-29 22:48:40Z (all three)
const CA_NOT_AFTER: i64 = 2_424_034_120; // 2046-10-24 22:48:40Z
const CLIENT_NOT_AFTER: i64 = 2_108_674_120; // 2036-10-26 22:48:40Z
const DAY: i64 = 86_400;

fn p12(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/certs/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

// MARK: - x509

#[test]
fn a_client_certificate_shows_subject_issuer_serial_validity_fingerprint_and_key() {
    let certs = x509::pem_certificates(CLIENT_RSA);
    assert_eq!(certs.len(), 1);
    let c = &certs[0];
    assert_eq!(c.subject, "CN=client one, OU=Lab, O=Example");
    assert_eq!(c.issuer, "CN=Cred Test CA, O=Example, C=HU");
    assert_eq!(c.serial, "12:34:AB:CD");
    assert_eq!((c.not_before, c.not_after), (NOT_BEFORE, CLIENT_NOT_AFTER));
    assert_eq!(
        c.sha256,
        "BF:09:5F:E2:24:AF:C2:13:09:47:3F:9D:37:C4:47:38:98:66:EA:E7:8B:78:11:B2:74:49:CE:CC:2D:EB:69:D6"
    );
    assert_eq!(x509::colon_hex(&c.sha1), "C6:98:F0:E6:62:C8:15:0B:A8:EC:92:16:6E:00:82:F7:E8:EE:AB:3B");
    assert_eq!(c.key_type, "RSA 2048");
    assert!(!c.ca);
    // The PEM written back for "Copy" is the same certificate.
    assert_eq!(x509::pem_certificates(&x509::to_pem(&c.der)), certs);
}

#[test]
fn ca_and_ed25519_certificates_and_bundles() {
    let ca = &x509::pem_certificates(CA)[0];
    assert_eq!(ca.subject, "CN=Cred Test CA, O=Example, C=HU");
    assert_eq!(ca.subject, ca.issuer);
    assert_eq!(ca.key_type, "ECDSA P-256");
    assert!(ca.ca);
    assert_eq!(ca.not_after, CA_NOT_AFTER);
    assert_eq!(ca.serial, "06:2D:3A:8B:4A:68:4A:04:53:8C:4E:51:08:62:D1:FA:37:B2:A1:40");
    let ed = &x509::pem_certificates(CLIENT_ED)[0];
    assert_eq!(ed.key_type, "Ed25519");
    assert_eq!(ed.serial, "07");
    assert_eq!(
        ed.sha256,
        "AF:D2:5A:98:D5:51:7C:15:83:40:F8:A2:A1:42:85:ED:CF:CA:2F:CC:A2:B3:A7:96:B8:57:CE:49:B8:D8:B3:9B"
    );
    // A bundle with text around and between the blocks, and an unreadable block left out.
    let bundle =
        format!("subject=x\n{CLIENT_RSA}junk\n-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n{CA}");
    let subjects: Vec<String> = x509::pem_certificates(&bundle).into_iter().map(|c| c.subject).collect();
    assert_eq!(subjects, ["CN=client one, OU=Lab, O=Example", "CN=Cred Test CA, O=Example, C=HU"]);
    assert!(x509::pem_certificates("").is_empty());
    assert!(x509::pem_certificates("-----BEGIN CERTIFICATE-----\nMIIB").is_empty());
}

#[test]
fn certificate_counts_and_sizes_are_bounded() {
    let many = CA.repeat(x509::MAX_CERTIFICATES + 5);
    assert_eq!(x509::pem_certificates(&many).len(), x509::MAX_CERTIFICATES);
    let huge = "x".repeat(x509::MAX_PEM_BYTES + 1) + CA;
    assert!(x509::pem_certificates(&huge).is_empty());
    assert!(x509::parse_der(&[]).is_none());
    assert!(x509::parse_der(&vec![0x30; x509::MAX_DER_BYTES + 1]).is_none());
}

#[test]
fn a_truncated_or_tampered_certificate_never_panics_and_is_refused() {
    let der = x509::first_pem_der(CLIENT_RSA).unwrap();
    for cut in 0..der.len() {
        assert!(x509::parse_der(&der[..cut]).is_none(), "cut at {cut}");
    }
    let mut trailing = der.clone();
    trailing.push(0);
    assert!(x509::parse_der(&trailing).is_none(), "nothing after the certificate");
    // Every single byte flipped: either refused or read, never a panic.
    for i in 0..der.len() {
        let mut bad = der.clone();
        bad[i] ^= 0xFF;
        let _ = x509::parse_der(&bad);
    }
}

#[test]
fn validity_warns_within_thirty_days_and_after_expiry() {
    let (from, to) = (NOT_BEFORE, CLIENT_NOT_AFTER);
    assert_eq!(x509::validity(from, to, from - 1), Validity::NotYetValid);
    assert_eq!(x509::validity(from, to, from), Validity::Valid);
    assert_eq!(x509::validity(from, to, to - 30 * DAY), Validity::Valid);
    assert_eq!(x509::validity(from, to, to - 30 * DAY + 1), Validity::ExpiresSoon { days: 29 });
    assert_eq!(x509::validity(from, to, to - DAY / 2), Validity::ExpiresSoon { days: 0 });
    assert_eq!(x509::validity(from, to, to), Validity::ExpiresSoon { days: 0 });
    assert_eq!(x509::validity(from, to, to + 1), Validity::Expired);
}

#[test]
fn names_with_control_and_invisible_characters_are_shown_safely() {
    assert_eq!(x509::shown("a\u{202E}b\u{0}c"), "a\\u{202E}b?c");
}

// MARK: - PKCS#12

#[test]
fn a_pkcs12_with_an_empty_password_opens_without_one() {
    for name in ["empty.p12", "empty-sha1.p12"] {
        let s = pkcs12::read(&p12(name)).unwrap();
        assert_eq!(s.password, Password::NotNeeded, "{name}");
        assert!(!s.needs_password());
        // OpenSSL encrypts the certificates too: they need the (empty) password to be read, so none is shown.
        assert!(s.certificates.is_empty(), "{name}");
        assert_eq!(s.encrypted_parts, 2, "{name}: the certificate part and the shrouded key");
    }
}

#[test]
fn a_pkcs12_with_a_password_asks_for_it() {
    for name in ["secret.p12", "secret-sha1.p12"] {
        let s = pkcs12::read(&p12(name)).unwrap();
        assert_eq!(s.password, Password::Needed, "{name}");
        assert!(s.needs_password());
    }
}

#[test]
fn an_unencrypted_pkcs12_shows_its_certificates() {
    let s = pkcs12::read(&p12("plain.p12")).unwrap();
    assert_eq!(s.password, Password::NotNeeded, "no MAC and nothing encrypted");
    let subjects: Vec<&str> = s.certificates.iter().map(|c| c.subject.as_str()).collect();
    assert_eq!(subjects, ["CN=client one, OU=Lab, O=Example", "CN=Cred Test CA, O=Example, C=HU"]);
    assert_eq!(s.encrypted_parts, 0);
    // As an OpenVPN `<pkcs12>` block: base64 with line breaks.
    let b64 = base64::engine::general_purpose::STANDARD.encode(p12("plain.p12"));
    let wrapped: String = b64.as_bytes().chunks(64).map(|c| format!("{}\n", std::str::from_utf8(c).unwrap())).collect();
    assert_eq!(pkcs12::read_base64(&wrapped).unwrap(), s);
}

#[test]
fn a_damaged_pkcs12_never_panics() {
    let der = p12("secret.p12");
    for cut in 0..der.len() {
        assert!(pkcs12::read(&der[..cut]).is_none(), "cut at {cut}");
    }
    for i in (0..der.len()).step_by(7) {
        let mut bad = der.clone();
        bad[i] ^= 0x55;
        let _ = pkcs12::read(&bad);
    }
    assert!(pkcs12::read_base64("not base64 !!").is_none());
    assert!(pkcs12::read(&x509::first_pem_der(CA).unwrap()).is_none(), "a certificate is not a PKCS#12");
}

// MARK: - Masked config text (G1)

#[test]
fn openvpn_key_blocks_are_masked_line_by_line() {
    let conf = "client\r\nremote a 1194\n<ca>\nCA-LINE\n</ca>\n<key>\n-----BEGIN PRIVATE KEY-----\nKEYDATA\n\n  -----END PRIVATE KEY-----\n</key>\n<TLS-CRYPT>\nTLSKEY\n</tls-crypt>\n<connection>\nremote b 1\n<http-proxy-user-pass>\nuser\nPROXYPASS\r\n</http-proxy-user-pass>\n</connection>\n<pkcs12>\nP12\n</pkcs12>\n<auth-user-pass>\nbob\nPASS\n</auth-user-pass>\n<tls-auth>\nA\n</tls-auth>\n<tls-crypt-v2>\nB\n</tls-crypt-v2>\n<secret>\nC\n</secret>\nverb 3\n";
    let masked = config_secrets::masked(VPNKind::Openvpn, conf).unwrap();
    let expected = format!(
        "client\r\nremote a 1194\n<ca>\nCA-LINE\n</ca>\n<key>\n{MASK}\n{MASK}\n\n  {MASK}\n</key>\n<TLS-CRYPT>\n{MASK}\n</tls-crypt>\n<connection>\nremote b 1\n<http-proxy-user-pass>\n{MASK}\n{MASK}\r\n</http-proxy-user-pass>\n</connection>\n<pkcs12>\n{MASK}\n</pkcs12>\n<auth-user-pass>\n{MASK}\n{MASK}\n</auth-user-pass>\n<tls-auth>\n{MASK}\n</tls-auth>\n<tls-crypt-v2>\n{MASK}\n</tls-crypt-v2>\n<secret>\n{MASK}\n</secret>\nverb 3\n"
    );
    assert_eq!(masked, expected);
    // The line count stays (the problems' line numbers still match).
    assert_eq!(masked.split('\n').count(), conf.split('\n').count());
    for secret in ["KEYDATA", "TLSKEY", "PROXYPASS", "P12", "PASS", "bob"] {
        assert!(!masked.contains(secret), "{secret}");
    }
    // An unclosed block is masked to the end.
    assert_eq!(
        config_secrets::masked(VPNKind::Openvpn, "a\n<key>\nK\nL").unwrap(),
        format!("a\n<key>\n{MASK}\n{MASK}")
    );
    // Nothing to mask.
    assert_eq!(config_secrets::masked(VPNKind::Openvpn, "client\n<ca>\nX\n</ca>\n<cert>\nY\n</cert>\n"), None);
    assert_eq!(config_secrets::masked(VPNKind::Openvpn, "client\n<key>\n</key>\n"), None);
    assert_eq!(config_secrets::masked(VPNKind::Openvpn, ""), None);
}

#[test]
fn wireguard_key_values_are_masked() {
    let conf = "[Interface]\nPrivateKey = abc=\r\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = pub=\npresharedkey=psk=\nPresharedKey =\n";
    assert_eq!(
        config_secrets::masked(VPNKind::Wireguard, conf).unwrap(),
        format!(
            "[Interface]\nPrivateKey = {MASK}\r\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = pub=\npresharedkey={MASK}\nPresharedKey =\n"
        )
    );
    assert_eq!(config_secrets::masked(VPNKind::Wireguard, "[Interface]\nPrivateKey =\n"), None);
}

#[test]
fn a_strongswan_secrets_section_is_masked_but_its_structure_stays() {
    let conf = "connections {\n  a {\n    local { auth = psk }\n  }\n}\nsecrets {\n  # the gateway's\n  ike-office {\n    id = gw.example.com\n    secret = \"p{w}\"\n  }\n}\nsecrets { ike-x { secret = inline } }\npools { }\n";
    assert_eq!(
        config_secrets::masked(VPNKind::Strongswan, conf).unwrap(),
        format!(
            "connections {{\n  a {{\n    local {{ auth = psk }}\n  }}\n}}\nsecrets {{\n  # the gateway's\n  ike-office {{\n    {MASK}\n    {MASK}\n  }}\n}}\nsecrets {{ {MASK}\npools {{ }}\n"
        )
    );
    assert_eq!(config_secrets::masked(VPNKind::Strongswan, "connections {\n}\n"), None);
}

#[test]
fn other_kinds_have_nothing_to_mask() {
    for kind in [VPNKind::Sstp, VPNKind::L2tp, VPNKind::Cisco] {
        assert_eq!(config_secrets::masked(kind, "server=x\n<key>\nK\n</key>\n"), None);
    }
}

// MARK: - A config's certificates and its key password

fn b64(name: &str) -> String {
    let b = base64::engine::general_purpose::STANDARD.encode(p12(name));
    b.as_bytes().chunks(64).map(|c| format!("{}\n", std::str::from_utf8(c).unwrap())).collect()
}

#[test]
fn an_openvpn_configs_certificates_client_first_then_cas() {
    use macvpn_core::certificates::{self, Role};
    let conf =
        format!("client\nremote a 1194\n<ca>\n{CA}</ca>\n<cert>\n{CLIENT_RSA}{CLIENT_ED}</cert>\n<key>\nK\n</key>\n");
    let found = certificates::of_config(VPNKind::Openvpn, &conf);
    let rows: Vec<(Role, &str, &str)> =
        found.certificates.iter().map(|c| (c.role, c.source.as_str(), c.certificate.subject.as_str())).collect();
    assert_eq!(
        rows,
        [
            (Role::Client, "<cert>", "CN=client one, OU=Lab, O=Example"),
            (Role::Chain, "<cert>", "CN=client ed"),
            (Role::Ca, "<ca>", "CN=Cred Test CA, O=Example, C=HU"),
        ]
    );
    assert_eq!(found.earliest_expiry(), Some(CLIENT_NOT_AFTER));
    assert!(!found.pkcs12_encrypted);
    // A PKCS#12 stored unencrypted shows its certificates; an encrypted one says its certificates are locked.
    let plain =
        certificates::of_config(VPNKind::Openvpn, &format!("client\n<pkcs12>\n{}</pkcs12>\n", b64("plain.p12")));
    let roles: Vec<(Role, &str)> = plain.certificates.iter().map(|c| (c.role, c.source.as_str())).collect();
    assert_eq!(roles, [(Role::Client, "<pkcs12>"), (Role::Ca, "<pkcs12>")]);
    let locked =
        certificates::of_config(VPNKind::Openvpn, &format!("client\n<pkcs12>\n{}</pkcs12>\n", b64("secret.p12")));
    assert!(locked.certificates.is_empty() && locked.pkcs12_encrypted);
    // SSTP: the custom CA. The other kinds: none in the config.
    let sstp = certificates::of_config(VPNKind::Sstp, &format!("server=vpn.example.com\ncert=ca\n{}", sstp_ca_lines()));
    assert_eq!(sstp.certificates.len(), 1);
    assert_eq!(sstp.certificates[0].role, Role::Ca);
    assert!(certificates::of_config(VPNKind::Wireguard, CA).certificates.is_empty());
}

/// The SSTP config's CA lines, as the SSTP form serializes a CA.
fn sstp_ca_lines() -> String {
    let config = macvpn_core::validators::SSTPConfig {
        server: "vpn.example.com".into(),
        port: 443,
        user: "u".into(),
        cert: macvpn_core::validators::sstp::CertMode::Ca,
        route_all: true,
        peer_dns: true,
        ca_pem: CA.into(),
    };
    config.serialized()
}

#[test]
fn the_key_password_is_needed_for_an_encrypted_key_or_a_protected_pkcs12() {
    use macvpn_core::certificates::{self, openvpn_key_needs_password};
    use macvpn_core::credentials::{CredentialField, required_fields};
    let needs = |conf: &str| {
        let asked = required_fields(VPNKind::Openvpn, Some(conf)).contains(CredentialField::KeyPassword);
        assert_eq!(asked, openvpn_key_needs_password(conf), "{conf}");
        asked
    };
    assert!(!needs("client\n<key>\n-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n</key>\n"));
    assert!(needs(
        "client\n<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nK\n-----END ENCRYPTED PRIVATE KEY-----\n</key>\n"
    ));
    // The connect prompt asks for a PKCS#12's password only when it does not open with an empty one.
    assert!(needs(&format!("client\n<pkcs12>\n{}</pkcs12>\n", b64("secret.p12"))));
    assert!(needs(&format!("client\n<pkcs12>\n{}</pkcs12>\n", b64("secret-sha1.p12"))));
    assert!(!needs(&format!("client\n<pkcs12>\n{}</pkcs12>\n", b64("empty.p12"))));
    assert!(!needs(&format!("client\n<pkcs12>\n{}</pkcs12>\n", b64("plain.p12"))));
    // Unreadable: asked (OpenVPN still tries an empty password first), but the import does not call it protected.
    assert!(needs("client\n<pkcs12>\nnot base64\n</pkcs12>\n"));
    assert!(!certificates::openvpn_pkcs12_protected("client\n<pkcs12>\nnot base64\n</pkcs12>\n"));
    assert!(certificates::openvpn_pkcs12_protected(&format!("client\n<pkcs12>\n{}</pkcs12>\n", b64("secret.p12"))));
    assert!(!certificates::openvpn_pkcs12_protected(&format!("client\n<pkcs12>\n{}</pkcs12>\n", b64("empty.p12"))));
    // A marker outside the key blocks asks nothing.
    assert!(!needs("client\n# -----BEGIN ENCRYPTED PRIVATE KEY-----\n<ca>\nProc-Type: 4,ENCRYPTED\n</ca>\n"));
}

#[test]
fn strongswan_names_its_certificate_files() {
    use macvpn_core::certificates::{self, Role};
    let conf = "connections {\n  office {\n    local {\n      auth = pubkey\n      certs = client.pem, \"second.der\"\n    }\n    remote {\n      cacerts = ca.pem # the CA\n      certs = ../etc/passwd\n    }\n  }\n}\n";
    assert_eq!(
        certificates::swanctl_files(conf),
        [(false, "client.pem".to_string()), (false, "second.der".to_string()), (true, "ca.pem".to_string())]
    );
    let der = x509::first_pem_der(CLIENT_ED).unwrap();
    let read = certificates::of_swanctl_files(&[
        (false, "client.pem".into(), CLIENT_RSA.as_bytes().to_vec()),
        (false, "second.der".into(), der),
        (true, "ca.pem".into(), CA.as_bytes().to_vec()),
        (true, "junk.pem".into(), b"junk".to_vec()),
    ]);
    let rows: Vec<(Role, &str)> = read.certificates.iter().map(|c| (c.role, c.source.as_str())).collect();
    assert_eq!(rows, [(Role::Client, "client.pem"), (Role::Client, "second.der"), (Role::Ca, "ca.pem")]);
}
