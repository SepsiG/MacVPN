//! Port of `SSTPTests.swift` (config, validator, password rule, messages; the import / export / template /
//! setup parts belong to Task 1.3 and 1.5) and of the validator-message cases of `LocalizationTests.swift`.

mod common;

use common::*;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::{VPNKind, ValidationIssue};
use macvpn_core::validators::{CertMode, ConfigValidator, OpenVPNValidator, SSTPConfig, SSTPValidator, validator};

const PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUQ2E+/=
-----END CERTIFICATE-----";

fn good() -> String {
    format!(
        "# office\nserver=vpn.example.com\nport=4443\nuser=alice@corp.example\ncert=ca\nroute_all=no\npeer_dns=yes\n<ca>\n{PEM}\n</ca>\n"
    )
}

fn validate(s: &str) -> Vec<ValidationIssue> {
    SSTPValidator.validate(s)
}

fn en() {
    lang(AppLanguage::En);
}

// MARK: Config

#[test]
fn parse_and_serialize_round_trip() {
    en();
    let c = SSTPConfig::parse(&good());
    assert_eq!(
        c,
        SSTPConfig {
            server: "vpn.example.com".into(),
            port: 4443,
            user: "alice@corp.example".into(),
            cert: CertMode::Ca,
            route_all: false,
            peer_dns: true,
            ca_pem: PEM.into()
        }
    );
    assert_eq!(SSTPConfig::parse(&c.serialized()), c);
    assert_eq!(validate(&c.serialized()), []);
    assert_eq!(SSTPConfig::certificate_count(&format!("{PEM}\n{PEM}")), 2);
    // Foundation's search: not after a Prepend character, not before a combining mark.
    assert_eq!(SSTPConfig::certificate_count(&format!("\u{600}{PEM}")), 0);
    assert_eq!(SSTPConfig::certificate_count("x-----BEGIN CERTIFICATE-----\u{301}y-----BEGIN CERTIFICATE-----"), 1);
}

#[test]
fn defaults_and_ca_dropped_outside_ca_mode() {
    en();
    let c = SSTPConfig::parse("server=a.example\nuser=bob\n");
    assert_eq!(c.port, 443);
    assert_eq!(c.cert, CertMode::System);
    assert!(c.route_all);
    assert!(c.peer_dns);
    let mut with_ca = c.clone();
    with_ca.ca_pem = PEM.into();
    assert!(!with_ca.serialized().contains("<ca>"));
    with_ca.cert = CertMode::Ca;
    assert!(with_ca.serialized().contains("<ca>\n-----BEGIN CERTIFICATE-----"));
}

#[test]
fn lenient_parse_like_swift() {
    // `Int(value) ?? 443`: a sign is accepted, anything else falls back.
    assert_eq!(SSTPConfig::parse("port=+8443\n").port, 8443);
    assert_eq!(SSTPConfig::parse("port=-1\n").port, -1);
    assert_eq!(SSTPConfig::parse("port= 44 3\n").port, 443);
    assert_eq!(SSTPConfig::parse("port=99999999999999999999\n").port, 443);
    assert_eq!(SSTPConfig::parse("PORT = 1\n").port, 1);
    assert_eq!(SSTPConfig::parse("cert=CA\n").cert, CertMode::System);
    assert!(!SSTPConfig::parse("route_all=no\n").route_all);
    assert!(SSTPConfig::parse("route_all=NO\n").route_all);
    assert_eq!(SSTPConfig::parse("<ca>\n\nA\n\n</ca>\n").ca_pem, "A");
}

#[test]
fn extract_certificates_from_bundle() {
    en();
    let bundle = format!("subject=CN=Corp\r\n{PEM}\nissuer=x\n{PEM}\n");
    assert_eq!(SSTPConfig::extract_certificates(&bundle), Some(format!("{PEM}\n{PEM}")));
    assert_eq!(SSTPConfig::extract_certificates("no cert here"), None);
    assert_eq!(
        SSTPConfig::extract_certificates("-----BEGIN CERTIFICATE-----\n$(id);\n-----END CERTIFICATE-----"),
        None
    );
    assert_eq!(SSTPConfig::extract_certificates("-----BEGIN CERTIFICATE-----\nAAAA\n"), None);
}

#[test]
fn serialized_has_no_password_key() {
    let c = SSTPConfig { server: "a".into(), user: "b".into(), ..Default::default() };
    assert!(!c.serialized().contains("password"));
}

// MARK: Validator

#[test]
fn accepts_good_config_and_minimal() {
    en();
    assert_eq!(validate(&good()), []);
    assert_eq!(validate("server=10.0.0.1\nuser=bob\n"), []);
    assert_eq!(validate("server=fd00::1\nuser=bob\ncert=insecure\n"), []);
    assert_eq!(validate("server=vpn.example.com.\r\nuser=a.b_c+d-e\r\n"), []);
}

#[test]
fn required_keys() {
    en();
    assert_eq!(messages(&validate("port=443\n")), ["Missing key: server", "Missing key: user"]);
}

#[test]
fn rejects_unknown_and_password_keys() {
    en();
    assert_eq!(lines(&validate("server=a\nuser=b\npassword=x\n")), [3]);
    assert_eq!(validate("server=a\nuser=b\npassword=x\n")[0].message, "Key not allowed: password");
    // Not an [a-z_] key: the message does not quote it.
    assert_eq!(validate("server=a\nuser=b\nX-Y=1\n")[0].message, "Key not allowed");
    assert_eq!(validate("server=a\nuser=b\nfoo bar\n")[0].message, "Invalid line");
    assert_eq!(lines(&validate("server=a\nuser=b\nuser=c\n")), [3]);
}

#[test]
fn strict_server() {
    en();
    let long = "a".repeat(254);
    for bad in [
        "vpn example.com",
        "\"vpn\"",
        "-vpn.example.com",
        "vpn.example.com:443",
        "[fd00::1]",
        "1.2.3",
        "999.1.1.1",
        "a..b",
        "a;b",
        "$(id)",
        "a/b",
        "ünnep.hu",
        &long,
    ] {
        let issues = validate(&format!("server={bad}\nuser=bob\n"));
        assert_eq!(lines(&issues), [1], "not rejected: {bad}");
        assert!(!issues[0].message.contains(bad), "the message quotes the value");
    }
    assert!(SSTPValidator::is_valid_server("2001:db8::8a2e:370:7334"));
    assert!(!SSTPValidator::is_valid_server("2001:db8:::1"));
}

#[test]
fn rejects_unspecified_and_loopback_servers() {
    en();
    for bad in
        ["0.0.0.0", "127.0.0.1", "127.8.9.10", "::", "::1", "0:0:0:0:0:0:0:1", "0:0::0", "localhost", "LOCALHOST."]
    {
        assert!(!SSTPValidator::is_valid_server(bad), "{bad}");
        assert_eq!(lines(&validate(&format!("server={bad}\nuser=bob\n"))), [1], "{bad}");
    }
    assert!(SSTPValidator::is_valid_server("128.0.0.1"));
    assert!(SSTPValidator::is_valid_server("::2"));
    assert!(SSTPValidator::is_valid_server("1.2.3.4"));
}

#[test]
fn password_rule() {
    en();
    for good in ["", "S3cret!pw", "pässwörd €", "a'b$c`d;e|f&g*h?i(j)k{l}m<n>o#p%q ~ space"] {
        assert!(SSTPConfig::is_acceptable_password(good), "{good}");
    }
    for bad in ["a\"b", "a\\b", "a\nb", "a\rb", "a\tb", "a\u{0}b", "a\u{7F}b", "a\u{85}b", "\"\nplugin /tmp/x.so\n\""] {
        assert!(!SSTPConfig::is_acceptable_password(bad), "{bad:?}");
    }
    assert_eq!(
        SSTPConfig::password_rule_message(),
        "The SSTP password must not contain quotation marks, backslashes or control characters"
    );
    lang(AppLanguage::Hu);
    assert_eq!(
        SSTPConfig::password_rule_message(),
        "Az SSTP jelszóban nem lehet idézőjel, fordított perjel és vezérlőkarakter"
    );
}

#[test]
fn strict_port() {
    en();
    for bad in ["0", "65536", "-1", "44 3", "abc", "443x", "999999"] {
        assert_eq!(lines(&validate(&format!("server=a\nport={bad}\nuser=b\n"))), [2], "not rejected: {bad}");
    }
    assert_eq!(validate("server=a\nport=65535\nuser=b\n"), []);
}

#[test]
fn user_charset() {
    en();
    let long = "a".repeat(129);
    for bad in
        ["bob smith", "\"bob\"", "bob'", "-bob", "b$ob", "b;ob", "", &long, ".", "..", "...", "bob.", "corp.example."]
    {
        assert_eq!(lines(&validate(&format!("server=a\nuser={bad}\n"))), [2], "not rejected: {bad}");
    }
    assert_eq!(validate("server=a\nuser=DOMAIN\\bob\n")[0].message, "Character not allowed: \\");
    assert!(SSTPValidator::is_valid_user(".bob"));
    assert!(SSTPValidator::is_valid_user("bob.smith@corp.example"));
}

#[test]
fn enums_and_control_characters() {
    en();
    assert_eq!(
        validate("server=a\nuser=b\ncert=none\n")[0].message,
        "Invalid value for cert: allowed: system, ca, insecure"
    );
    assert_eq!(lines(&validate("server=a\nuser=b\nroute_all=true\n")), [3]);
    assert_eq!(lines(&validate("server=a\nuser=b\npeer_dns=YES\n")), [3]);
    assert_eq!(validate("server=a\u{01}\nuser=b\n")[0].message, "Control character not allowed");
    assert_eq!(lines(&validate("server=a\nuser=b\u{7F}\n")), [2, 0]);
}

#[test]
fn ca_block_rules() {
    en();
    assert_eq!(
        messages(&validate("server=a\nuser=b\ncert=ca\n")),
        ["cert=ca requires a <ca> block with a PEM certificate"]
    );
    assert_eq!(messages(&validate(&format!("server=a\nuser=b\n<ca>\n{PEM}\n"))), ["Unclosed inline block: ca"]);
    assert_eq!(lines(&validate("server=a\nuser=b\n<ca>\nrm -rf /;\n</ca>\n")), [4]);
    assert_eq!(lines(&validate("server=a\nuser=b\n<ca>\n</ca>\n<ca>\n</ca>\n")), [5]);
    // The block without cert=ca is not an error (serialize drops it anyway), and "server=" inside it is no key.
    assert_eq!(validate(&format!("server=a\nuser=b\n<ca>\n{PEM}\n</ca>\n")), []);
}

#[test]
fn root_parameters() {
    en();
    assert_eq!(
        SSTPValidator::parameters(&good()),
        Some(
            vec!["vpn.example.com", "4443", "alice@corp.example", "ca", "no", "yes"]
                .into_iter()
                .map(String::from)
                .collect()
        )
    );
    assert_eq!(
        SSTPValidator::parameters("server=a.b\nuser=c\n"),
        Some(vec!["a.b", "443", "c", "system", "yes", "yes"].into_iter().map(String::from).collect())
    );
    assert_eq!(SSTPValidator::parameters("server=a b\nuser=c\n"), None);
    assert_eq!(SSTPValidator::ca_pem(&good()), Some(PEM.to_string()));
    assert_eq!(SSTPValidator::ca_pem("server=a.b\nuser=c\n"), None);
}

#[test]
fn hungarian_messages() {
    lang(AppLanguage::Hu);
    assert_eq!(validate("server=a\nport=0\nuser=b\n")[0].display(), "2. sor: Érvénytelen port: 1–65535");
}

#[test]
fn registered_validator() {
    assert!(validator(VPNKind::Sstp).is_some());
    assert_eq!(VPNKind::Sstp.display_name(), "SSTP");
    assert!(!VPNKind::Sstp.is_native());
}

/// `ConfigImporter.template(for: .sstp)` is `SSTPConfig(server: "vpn.example.com").serialized()`: the user name
/// is empty, so it must be filled in before saving.
#[test]
fn template_parses_and_needs_a_user() {
    en();
    let t = SSTPConfig { server: "vpn.example.com".into(), ..Default::default() }.serialized();
    assert_eq!(SSTPConfig::parse(&t).server, "vpn.example.com");
    assert_eq!(lines(&validate(&t)), [3]);
}

// MARK: LocalizationTests: validator messages

#[test]
fn validator_message_follows_language() {
    lang(AppLanguage::En);
    let en = OpenVPNValidator.validate("remote a 1\nup /x\n");
    assert_eq!(en[0].message, "Forbidden directive: up – delete the line or comment it out (#)");
    assert_eq!(en[0].display(), "Line 2: Forbidden directive: up – delete the line or comment it out (#)");

    lang(AppLanguage::Hu);
    let hu = OpenVPNValidator.validate("remote a 1\nup /x\n");
    assert_eq!(hu[0].message, "Tiltott direktíva: up – töröld vagy tedd megjegyzésbe (#) a sort");
    assert_eq!(hu[0].display(), "2. sor: Tiltott direktíva: up – töröld vagy tedd megjegyzésbe (#) a sort");
}
