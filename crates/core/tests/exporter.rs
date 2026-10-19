//! Port of `ConfigExporterTests.swift`, `MobileconfigGeneratorTests.swift`, the `NativeStartOptions` cases of
//! `NativeVPNTests.swift` and the SSTP export cases of `SSTPTests.swift`.

mod common;

use common::*;
use macvpn_core::date::Date;
use macvpn_core::exporter;
use macvpn_core::importer;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::mobileconfig::{self, MobileconfigError};
use macvpn_core::models::{Connection, NativeSettings, Secrets, VPNKind, parse_uuid, uuid_string};
use macvpn_core::native::{self, NativeKind};
use macvpn_core::store::ConnectionStore;
use plist::{Dictionary, Value};
use std::collections::BTreeMap;
use std::fs;

fn native_conn(name: &str, kind: VPNKind, server: &str, account: &str, group: &str, all: bool) -> Connection {
    let mut c = Connection::new(name, kind);
    c.native = Some(NativeSettings {
        server: server.into(),
        account: account.into(),
        group_name: group.into(),
        send_all_traffic: all,
    });
    c
}

fn root(data: &[u8]) -> Dictionary {
    Value::from_reader_xml(data).unwrap().into_dictionary().unwrap()
}

fn payload(data: &[u8]) -> Dictionary {
    let r = root(data);
    assert_eq!(r.get("PayloadType").and_then(Value::as_string), Some("Configuration"));
    r.get("PayloadContent").unwrap().as_array().unwrap()[0].as_dictionary().unwrap().clone()
}

fn sub<'a>(d: &'a Dictionary, key: &str) -> &'a Dictionary {
    d.get(key).unwrap().as_dictionary().unwrap()
}

// MARK: ConfigExporterTests

#[test]
fn file_names() {
    assert_eq!(exporter::file_name(&Connection::new("Iroda/VPN", VPNKind::Openvpn)), "Iroda-VPN.ovpn");
    assert_eq!(exporter::file_name(&Connection::new("Home", VPNKind::Wireguard)), "Home.conf");
    assert_eq!(exporter::file_name(&Connection::new("P", VPNKind::Strongswan)), "P.swanctl.conf");
    assert_eq!(exporter::file_name(&Connection::new("Ice", VPNKind::L2tp)), "Ice.mobileconfig");
    assert_eq!(exporter::file_name(&Connection::new("Iroda", VPNKind::Sstp)), "Iroda.sstp");
    assert_eq!(exporter::file_name(&Connection::new(" a:b ", VPNKind::Openvpn)), "a-b.ovpn");
    assert_eq!(exporter::file_name(&Connection::new(" / ", VPNKind::Openvpn)), "-.ovpn");
    assert_eq!(exporter::file_name(&Connection::new("  ", VPNKind::Openvpn)), "MacVPN.ovpn");
    // Stricter than Swift (whose search skips a `/` or `:` a combining mark follows): every one is replaced.
    assert_eq!(exporter::file_name(&Connection::new("a/\u{301}b", VPNKind::Openvpn)), "a-\u{301}b.ovpn");
    assert_eq!(
        exporter::file_name(&Connection::new("..:\u{301}/\u{E0041}x", VPNKind::Openvpn)),
        "..-\u{301}-\u{E0041}x.ovpn"
    );
}

#[test]
fn text_export_is_config_as_is() {
    let tmp = TempDir::new();
    let store = ConnectionStore::new(tmp.path());
    let c = Connection::new("Iroda", VPNKind::Openvpn);
    store.save(&c, Some("remote x\n")).unwrap();
    assert_eq!(exporter::export(&c, &store).unwrap(), b"remote x\n");
}

#[test]
fn native_export_has_no_secrets() {
    let tmp = TempDir::new();
    let store = ConnectionStore::new(tmp.path());
    let c = native_conn("Ice", VPNKind::L2tp, "s", "bob", "", true);
    let p = payload(&exporter::export(&c, &store).unwrap());
    // The generator leaves out the empty password (macOS then asks when connecting).
    assert!(sub(&p, "PPP").get("AuthPassword").is_none());
    assert_eq!(sub(&p, "PPP").get("AuthName").and_then(Value::as_string), Some(""));
    assert_eq!(sub(&p, "IPSec").get("SharedSecret").and_then(Value::as_data), Some(&[][..]));
}

#[test]
fn cisco_export_has_no_secrets() {
    let tmp = TempDir::new();
    let store = ConnectionStore::new(tmp.path());
    let c = native_conn("Cis", VPNKind::Cisco, "s", "bob", "g", true);
    let p = payload(&exporter::export(&c, &store).unwrap());
    let ipsec = sub(&p, "IPSec");
    assert!(ipsec.get("XAuthPassword").is_none());
    assert_eq!(ipsec.get("XAuthName").and_then(Value::as_string), Some(""));
    assert_eq!(ipsec.get("LocalIdentifier").and_then(Value::as_string), Some("g"));
    assert_eq!(ipsec.get("SharedSecret").and_then(Value::as_data), Some(&[][..]));
}

#[test]
fn round_trip_through_importer_detection() {
    let tmp = TempDir::new();
    let store = ConnectionStore::new(tmp.path());
    let c = Connection::new("WG", VPNKind::Wireguard);
    store.save(&c, Some("[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\n")).unwrap();
    let data = exporter::export(&c, &store).unwrap();
    assert_eq!(
        importer::detect_kind(&exporter::file_name(&c), &String::from_utf8(data).unwrap()),
        Some(VPNKind::Wireguard)
    );
}

const OVPN: &str = "client
remote a 1194
<ca>
-----BEGIN CERTIFICATE-----
MIIB
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIC
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
SECRET1
-----END PRIVATE KEY-----
</key>
<TLS-AUTH>
SECRET2
</TLS-AUTH>
key-direction 1
<tls-crypt>
SECRET3
</tls-crypt>
<tls-crypt-v2>
SECRET4
</tls-crypt-v2>
<secret>
SECRET5
</secret>
<pkcs12>
SECRET6
</pkcs12>
verb 3
";

#[test]
fn openvpn_secrets_are_detected_and_stripped() {
    assert_eq!(
        exporter::secret_material(OVPN, VPNKind::Openvpn),
        ["<key>", "<tls-auth>", "<tls-crypt>", "<tls-crypt-v2>", "<secret>", "<pkcs12>"]
    );
    let stripped = exporter::strip_secrets(OVPN, VPNKind::Openvpn);
    assert!(!stripped.contains("SECRET"));
    assert!(stripped.contains("<ca>\n-----BEGIN CERTIFICATE-----\nMIIB"));
    assert!(stripped.contains("<cert>"));
    assert!(stripped.ends_with("key-direction 1\nverb 3\n"));
    assert!(exporter::secret_material(&stripped, VPNKind::Openvpn).is_empty());
    assert!(exporter::secret_material("client\nremote a 1\n<ca>\nx\n</ca>\n", VPNKind::Openvpn).is_empty());
}

/// Inline credentials (`<auth-user-pass>`, `<http-proxy-user-pass>`, also inside `<connection>`) are flagged and stripped.
#[test]
fn openvpn_inline_credentials_are_detected_and_stripped() {
    let conf = "client\nremote vpn.example.com 1194\nauth-user-pass\n<auth-user-pass>\nbob\nCredPass1\n</auth-user-pass>\n<connection>\nremote alt.example.com 443 tcp\nhttp-proxy proxy.example.com 8080 [inline]\n<http-proxy-user-pass>\nproxyuser\nProxyPass2\n</http-proxy-user-pass>\n</connection>\n<ca>\nCA\n</ca>\nverb 3\n";
    assert_eq!(exporter::secret_material(conf, VPNKind::Openvpn), ["<auth-user-pass>", "<http-proxy-user-pass>"]);
    let stripped = exporter::strip_secrets(conf, VPNKind::Openvpn);
    assert!(!stripped.contains("CredPass1"));
    assert!(!stripped.contains("ProxyPass2"));
    assert!(!stripped.contains("proxyuser"));
    assert!(!stripped.contains("\nbob\n"));
    assert!(stripped.contains(
        "<connection>\nremote alt.example.com 443 tcp\nhttp-proxy proxy.example.com 8080 [inline]\n</connection>"
    ));
    assert!(stripped.contains("<ca>\nCA\n</ca>"));
    assert!(exporter::secret_material(&stripped, VPNKind::Openvpn).is_empty());
    // The plain directive alone (credentials from the Keychain) is not secret material.
    assert!(exporter::secret_material("remote a 1\nauth-user-pass\n", VPNKind::Openvpn).is_empty());
}

#[test]
fn openvpn_unclosed_secret_block_is_stripped_to_the_end() {
    assert_eq!(exporter::strip_secrets("remote a 1\n<key>\nSECRET\n", VPNKind::Openvpn), "remote a 1\n");
}

#[test]
fn wireguard_keys_are_blanked() {
    let conf = "[Interface]\nprivatekey = abc=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = pub=\nPresharedKey=psk=\n";
    assert_eq!(exporter::secret_material(conf, VPNKind::Wireguard), ["PrivateKey", "PresharedKey"]);
    let stripped = exporter::strip_secrets(conf, VPNKind::Wireguard);
    assert_eq!(
        stripped,
        "[Interface]\nPrivateKey =\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = pub=\nPresharedKey =\n"
    );
    assert!(exporter::secret_material(&stripped, VPNKind::Wireguard).is_empty());
    assert_eq!(importer::detect_kind("x.conf", &stripped), Some(VPNKind::Wireguard));
}

#[test]
fn strongswan_secrets_section_is_stripped() {
    let conf = "connections {\n  a {\n    children { a { } }\n  }\n}\nsecrets {\n  eap-1 {\n    id = bob\n    secret = \"p{w}\"\n  }\n}\npools { }\n";
    assert_eq!(exporter::secret_material(conf, VPNKind::Strongswan), ["secrets"]);
    assert_eq!(
        exporter::strip_secrets(conf, VPNKind::Strongswan),
        "connections {\n  a {\n    children { a { } }\n  }\n}\npools { }\n"
    );
    assert!(exporter::secret_material("connections {\n}\n", VPNKind::Strongswan).is_empty());
}

#[test]
fn other_kinds_have_no_secret_material() {
    assert!(exporter::secret_material("server=x\n", VPNKind::Sstp).is_empty());
    assert_eq!(exporter::strip_secrets("server=x\n", VPNKind::Sstp), "server=x\n");
}

#[test]
fn write_creates_private_file() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let path = tmp.path().join("x.conf");
    exporter::write(b"secret", &path).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"secret");
    assert_eq!(mode(&path), 0o600);
}

#[test]
fn write_replaces_existing_world_readable_file() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let path = tmp.path().join("x.conf");
    fs::write(&path, "old content that is longer").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    exporter::write(b"new", &path).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"new");
    assert_eq!(mode(&path), 0o600);
    let leftovers: Vec<_> = fs::read_dir(tmp.path()).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(leftovers, ["x.conf"]);
}

#[test]
fn write_errors_are_localized() {
    lang(AppLanguage::Hu);
    let err = exporter::write(b"x", std::path::Path::new("/nonexistent-dir/x.conf")).unwrap_err();
    assert_eq!(err.message, "Nem írható: /nonexistent-dir/x.conf");
}

/// SSTPTests: the export is the config without a password.
#[test]
fn sstp_export_is_config_without_password() {
    let good = "# office\nserver=vpn.example.com\nport=4443\nuser=alice@corp.example\ncert=ca\nroute_all=no\npeer_dns=yes\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ2E+/=\n-----END CERTIFICATE-----\n</ca>\n\n";
    let tmp = TempDir::new();
    let store = ConnectionStore::new(tmp.path());
    let c = Connection::new("S", VPNKind::Sstp);
    store.save(&c, Some(good)).unwrap();
    assert_eq!(exporter::export(&c, &store).unwrap(), good.as_bytes());
    assert_eq!(importer::detect_kind(&exporter::file_name(&c), good), Some(VPNKind::Sstp));
}

// MARK: MobileconfigGeneratorTests (Hungarian messages)

#[test]
fn l2tp_profile() {
    lang(AppLanguage::Hu);
    let c = native_conn("Office L2TP", VPNKind::L2tp, "vpn.ice.hu", "bob", "", true);
    let data = mobileconfig::generate(&c, "k").unwrap();
    assert_eq!(
        root(&data).get("PayloadIdentifier").and_then(Value::as_string),
        Some(format!("macvpn.{}", uuid_string(&c.id)).as_str())
    );
    let p = payload(&data);
    assert_eq!(p.get("PayloadType").and_then(Value::as_string), Some("com.apple.vpn.managed"));
    assert_eq!(p.get("VPNType").and_then(Value::as_string), Some("L2TP"));
    assert_eq!(p.get("UserDefinedName").and_then(Value::as_string), Some("Office L2TP"));
    let ppp = sub(&p, "PPP");
    assert_eq!(ppp.get("CommRemoteAddress").and_then(Value::as_string), Some("vpn.ice.hu"));
    assert_eq!(ppp.get("AuthName").and_then(Value::as_string), Some("bob"));
    assert!(
        ppp.get("AuthPassword").is_none(),
        "the password is passed in-process when connecting, never written to the profile"
    );
    assert_eq!(sub(&p, "IPSec").get("SharedSecret").and_then(Value::as_data), Some(&b"k"[..]));
    assert_eq!(sub(&p, "IPv4").get("OverridePrimary").and_then(Value::as_signed_integer), Some(1));
}

#[test]
fn cisco_profile() {
    lang(AppLanguage::Hu);
    let c = native_conn("Partner", VPNKind::Cisco, "1.2.3.4", "bob", "staff", false);
    let p = payload(&mobileconfig::generate(&c, "k").unwrap());
    assert_eq!(p.get("VPNType").and_then(Value::as_string), Some("IPSec"));
    let ipsec = sub(&p, "IPSec");
    assert_eq!(ipsec.get("RemoteAddress").and_then(Value::as_string), Some("1.2.3.4"));
    assert_eq!(ipsec.get("XAuthName").and_then(Value::as_string), Some("bob"));
    assert!(ipsec.get("XAuthPassword").is_none());
    assert_eq!(ipsec.get("SharedSecret").and_then(Value::as_data), Some(&b"k"[..]));
    assert_eq!(ipsec.get("LocalIdentifier").and_then(Value::as_string), Some("staff"));
    assert_eq!(ipsec.get("XAuthEnabled").and_then(Value::as_signed_integer), Some(1));
    assert!(p.get("PPP").is_none());
}

#[test]
fn rejects_non_native() {
    assert_eq!(mobileconfig::generate(&Connection::new("x", VPNKind::Openvpn), ""), Err(MobileconfigError::NotNative));
}

/// No password key anywhere in the profile (at any level).
#[test]
fn no_password_key_anywhere() {
    for c in
        [native_conn("A", VPNKind::L2tp, "s", "u", "", true), native_conn("B", VPNKind::Cisco, "s", "u", "g", true)]
    {
        let xml = String::from_utf8(mobileconfig::generate(&c, "k").unwrap()).unwrap();
        assert!(!xml.contains("Password"), "{xml}");
    }
}

/// Guards the plan B Task 12 decision (vault spike report D.2): until the manual test D.3 shows that a profile
/// without `SharedSecret` installs and still connects from System Settings, the PSK stays in the profile for both
/// native kinds (macOS owns those profiles and keeps it in the System keychain), next to
/// `AuthenticationMethod = SharedSecret`. The password never goes in. If D.3 passes, this test is replaced by its
/// opposite (no `SharedSecret`) together with the `generate` change.
#[test]
fn psk_stays_in_the_profile_until_spike_d3_passes() {
    for c in
        [native_conn("A", VPNKind::L2tp, "s", "u", "", true), native_conn("B", VPNKind::Cisco, "s", "u", "g", true)]
    {
        let data = mobileconfig::generate(&c, "vault psk").unwrap();
        let p = payload(&data);
        let ipsec = sub(&p, "IPSec");
        assert_eq!(ipsec.get("AuthenticationMethod").and_then(Value::as_string), Some("SharedSecret"), "{:?}", c.kind);
        assert_eq!(ipsec.get("SharedSecret").and_then(Value::as_data), Some(&b"vault psk"[..]), "{:?}", c.kind);
        let xml = String::from_utf8(data).unwrap();
        assert!(!xml.contains("Password"), "{xml}");
    }
}

#[test]
fn cisco_requires_group_name() {
    lang(AppLanguage::Hu);
    let c = native_conn("B", VPNKind::Cisco, "s", "u", "", true);
    assert_eq!(mobileconfig::generate(&c, "k").unwrap_err().message(), "Cisco IPsec-hez csoportnév szükséges");
}

#[test]
fn inner_payload_uuid_is_deterministic() {
    let c = native_conn("A", VPNKind::L2tp, "s", "u", "", true);
    let a = payload(&mobileconfig::generate(&c, "k").unwrap());
    let b = payload(&mobileconfig::generate(&c, "k").unwrap());
    assert_eq!(a.get("PayloadUUID"), b.get("PayloadUUID"));
    assert_ne!(a.get("PayloadUUID").and_then(Value::as_string), Some(uuid_string(&c.id).as_str()));
}

/// Byte-for-byte what Swift's `PropertyListSerialization` wrote (fixtures/swift/mobileconfig, generate.sh).
#[test]
fn profile_bytes_match_swift() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/swift/mobileconfig");
    let created = Date::parse_iso8601("2026-10-16T17:55:00Z").unwrap();
    let id = parse_uuid("55555555-6666-7777-8888-999999999999").unwrap();
    let name = "Office <L2TP> & \"q\" 'a' é \u{1}";
    for (file, kind, psk) in [
        ("cisco.mobileconfig", VPNKind::Cisco, "k".repeat(100)),
        ("l2tp.mobileconfig", VPNKind::L2tp, String::new()),
        ("l2tp-psk.mobileconfig", VPNKind::L2tp, "secret psk".to_string()),
    ] {
        let mut c = Connection::with_id(id, name, kind, created);
        c.native = Some(NativeSettings {
            server: "vpn.example.com".into(),
            account: "bob".into(),
            group_name: "staff".into(),
            send_all_traffic: kind == VPNKind::L2tp,
        });
        let expected = fs::read(dir.join(file)).unwrap();
        assert_eq!(
            String::from_utf8(mobileconfig::generate(&c, &psk).unwrap()).unwrap(),
            String::from_utf8(expected).unwrap(),
            "{file}"
        );
    }
}

// MARK: NativeStartOptions (NativeVPNTests.swift)

fn options(kind: NativeKind, secrets: Secrets) -> Option<BTreeMap<String, BTreeMap<String, String>>> {
    native::start_options(kind, &secrets).map(|o| {
        o.into_iter().map(|(k, v)| (k.to_string(), v.into_iter().map(|(a, b)| (a.to_string(), b)).collect())).collect()
    })
}

fn map(entries: &[(&str, &[(&str, &str)])]) -> Option<BTreeMap<String, BTreeMap<String, String>>> {
    Some(
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()))
            .collect(),
    )
}

fn secrets(username: Option<&str>, password: Option<&str>, psk: Option<&str>) -> Secrets {
    Secrets {
        username: username.map(String::from),
        password: password.map(String::from),
        psk: psk.map(String::from),
        ..Default::default()
    }
}

#[test]
fn l2tp_options_with_all_secrets() {
    assert_eq!(
        options(NativeKind::L2tp, secrets(Some("bob"), Some("pw"), Some("k"))),
        map(&[("IPSec", &[("SharedSecret", "k")]), ("PPP", &[("AuthName", "bob"), ("AuthPassword", "pw")])])
    );
}

#[test]
fn l2tp_options_psk_only() {
    assert_eq!(
        options(NativeKind::L2tp, secrets(Some(""), None, Some("k"))),
        map(&[("IPSec", &[("SharedSecret", "k")])])
    );
}

#[test]
fn l2tp_options_password_only() {
    assert_eq!(options(NativeKind::L2tp, secrets(None, Some("pw"), None)), map(&[("PPP", &[("AuthPassword", "pw")])]));
}

#[test]
fn cisco_options_with_all_secrets() {
    assert_eq!(
        options(NativeKind::CiscoIPSec, secrets(Some("bob"), Some("pw"), Some("k"))),
        map(&[("IPSec", &[("SharedSecret", "k"), ("XAuthName", "bob"), ("XAuthPassword", "pw")])])
    );
}

#[test]
fn cisco_options_psk_only() {
    assert_eq!(
        options(NativeKind::CiscoIPSec, secrets(None, None, Some("k"))),
        map(&[("IPSec", &[("SharedSecret", "k")])])
    );
}

#[test]
fn options_none_without_secrets() {
    assert_eq!(options(NativeKind::L2tp, Secrets::default()), None);
    assert_eq!(options(NativeKind::CiscoIPSec, secrets(Some(""), Some(""), Some(""))), None);
    assert_eq!(NativeKind::from_kind(VPNKind::L2tp), Some(NativeKind::L2tp));
    assert_eq!(NativeKind::from_kind(VPNKind::Cisco), Some(NativeKind::CiscoIPSec));
    assert_eq!(NativeKind::from_kind(VPNKind::Openvpn), None);
    assert_eq!(NativeKind::from_type_label("Cisco IPsec"), Some(NativeKind::CiscoIPSec));
    assert_eq!(NativeKind::from_type_label("WireGuard (app)"), None);
}
