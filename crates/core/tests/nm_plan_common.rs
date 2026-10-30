//! The shared parts of `nm_plan` (LinVPN L-b, Task 1): the derived NM UUID (logd's ownership proof), interface
//! names, the common sections, the DNS rule, and that a plan's `Debug` never shows a secret.

use macvpn_core::models::{Connection, VPNKind};
use macvpn_core::nm_plan::{self, Caps, Input, NmValue, RuntimeFile, SecretItem, SecretKey, SecretValue, names};
use std::path::Path;
use uuid::Uuid;
use zeroize::Zeroizing;

const ID: &str = "0b5f7c1e-2d3a-4b5c-8d6e-7f8091a2b3c4";

#[test]
fn the_nm_uuid_depends_on_uid_and_id_and_is_stable() {
    let id = Uuid::parse_str(ID).unwrap();
    let a = names::nm_uuid(1001, &id);
    assert_eq!(a, names::nm_uuid(1001, &id), "stable");
    assert_ne!(a, names::nm_uuid(1002, &id), "another uid, another UUID");
    assert_ne!(a, id, "never the LinVPN id itself");
    assert_eq!(a.get_version_num(), 8);
    assert_eq!(a.as_bytes()[8] & 0xC0, 0x80, "RFC 4122 variant");
    // Pinned: the derivation is a contract between the app and linvpn-logd (two binaries, maybe two versions).
    assert_eq!(names::nm_uuid(1001, &id).to_string(), names::nm_uuid_reference(1001, &id));
}

#[test]
fn interface_names_fit_ifnamsiz_and_differ_per_connection() {
    let a = names::iface(names::IFACE_WIREGUARD, &Uuid::parse_str(ID).unwrap());
    let b = names::iface(names::IFACE_OPENVPN, &Uuid::parse_str(ID).unwrap());
    assert!(a.len() <= 15 && b.len() <= 15);
    assert!(a.starts_with("lvw") && b.starts_with("lvo"));
    assert!(a.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    assert_ne!(a, names::iface(names::IFACE_WIREGUARD, &Uuid::new_v4()));
}

#[test]
fn the_connection_section_is_private_volatile_and_never_autoconnects() {
    let c = Connection::new("Office VPN", VPNKind::Wireguard);
    let s = nm_plan::connection_section(&c, 1001, "linvpn-dev", "wireguard", Some("lvw0123abcd"));
    assert_eq!(s["id"], NmValue::Str("Office VPN".into()));
    assert_eq!(s["type"], NmValue::Str("wireguard".into()));
    assert_eq!(s["autoconnect"], NmValue::Bool(false));
    assert_eq!(s["permissions"], NmValue::StrList(vec!["user:linvpn-dev".into()]));
    assert_eq!(s["uuid"], NmValue::Str(names::nm_uuid(1001, &c.id).to_string()));
    assert_eq!(s["interface-name"], NmValue::Str("lvw0123abcd".into()));
}

#[test]
fn split_tunnels_keep_dns_for_their_domains_and_full_tunnels_take_all() {
    let split = nm_plan::dns::section_extras(false, &["corp.example.com".into()]);
    assert_eq!(split.get("dns-search"), Some(&NmValue::StrList(vec!["~corp.example.com".into()])));
    assert_eq!(split.get("dns-priority"), Some(&NmValue::I32(nm_plan::dns::SPLIT_PRIORITY)));
    let full = nm_plan::dns::section_extras(true, &["corp.example.com".into()]);
    assert_eq!(full.get("dns-search"), Some(&NmValue::StrList(vec!["corp.example.com".into(), "~.".into()])));
    assert_eq!(full.get("dns-priority"), Some(&NmValue::I32(nm_plan::dns::FULL_PRIORITY)));
}

#[test]
fn secrets_and_files_never_show_in_debug() {
    let item = SecretItem {
        setting: "wireguard",
        key: SecretKey::Plain("private-key".into()),
        value: SecretValue::Literal(Zeroizing::new("c2VjcmV0LWtleQ==".into())),
    };
    let file = RuntimeFile { name: "key.pem".into(), data: Zeroizing::new(b"-----BEGIN PRIVATE KEY-----".to_vec()) };
    let shown = format!("{item:?} {file:?}");
    assert!(!shown.contains("c2VjcmV0") && !shown.contains("BEGIN"), "{shown}");
    assert!(shown.contains("private-key") && shown.contains("key.pem"));
}

#[test]
fn every_kind_has_a_plan_entry_point() {
    let caps = Caps::default();
    for kind in VPNKind::ALL {
        let c = Connection::new("x", kind);
        let input = Input {
            connection: &c,
            config: b"",
            user: "u",
            uid: 1000,
            runtime_dir: Path::new("/run/user/1000/linvpn/nm"),
            caps: &caps,
            client_cert: nm_plan::ImportedCert::None,
        };
        // Task 1's stubs answer "not yet"; the kind tasks replace them. Only the dispatch is checked here.
        let _ = nm_plan::plan(&input);
    }
}
