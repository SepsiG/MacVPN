//! The 1.1 Keychain items for the vault migration (plan B Task 13), over the in-memory Keychain backend only.
#![cfg(target_os = "macos")]

use macvpn_core::models::SecretField;
use macvpn_core::vault::{LegacyKeychain, LegacyRead};
use macvpn_platform_mac::legacy_store::KeychainLegacy;
use macvpn_platform_mac::secrets::{InMemoryKeychain, KeychainBackend, KeychainSecretStore};

const SERVICE: &str = "local.macvpn.secrets";
const OLD: &str = "macvpn";
const CONN: &str = "0A1B2C3D-4E5F-4061-8273-94A5B6C7D8E9";
const SYSTEM: &str = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";

fn legacy() -> KeychainLegacy<InMemoryKeychain> {
    let backend = InMemoryKeychain::new();
    backend.write(b"alice", SERVICE, &format!("{CONN}.username"));
    backend.write(b"pw-1", SERVICE, &format!("{CONN}.password"));
    backend.write(b"psk-1", SERVICE, &format!("{SYSTEM}.psk"));
    // Not ours: never listed or touched.
    backend.write(b"other", SERVICE, "something-else");
    backend.write(b"x", SERVICE, &format!("{CONN}.unknownfield"));
    KeychainLegacy::new(KeychainSecretStore::new(backend))
}

fn value(r: LegacyRead) -> Option<String> {
    match r {
        LegacyRead::Value(v) => Some(v.to_string()),
        _ => None,
    }
}

fn sorted(mut v: Vec<(String, SecretField)>) -> Vec<(String, &'static str)> {
    v.sort_by(|a, b| (&a.0, a.1.raw_value()).cmp(&(&b.0, b.1.raw_value())));
    v.into_iter().map(|(i, f)| (i, f.raw_value())).collect()
}

#[test]
fn lists_only_macvpn_items_with_their_item_ids() {
    let l = legacy();
    assert_eq!(
        sorted(l.items()),
        [(CONN.to_string(), "password"), (CONN.to_string(), "username"), (SYSTEM.to_string(), "psk"),]
    );
}

#[test]
fn reads_and_deletes_through_the_secret_store() {
    let l = legacy();
    assert_eq!(value(l.read(CONN, SecretField::Password)), Some("pw-1".into()));
    assert_eq!(value(l.read(SYSTEM, SecretField::Psk)), Some("psk-1".into()));
    assert!(matches!(l.read(SYSTEM, SecretField::Password), LegacyRead::Missing));
    assert!(matches!(l.read("not-a-uuid", SecretField::Password), LegacyRead::Missing));
    l.delete(CONN, SecretField::Password);
    assert!(matches!(l.read(CONN, SecretField::Password), LegacyRead::Missing));
    assert_eq!(sorted(l.items()), [(CONN.to_string(), "username"), (SYSTEM.to_string(), "psk")]);
    // Others' items stay.
    assert_eq!(l.store().backend().read(SERVICE, "something-else").as_deref(), Some(&b"other"[..]));
}

#[test]
fn prepare_moves_the_old_service_items_first() {
    let backend = InMemoryKeychain::new();
    backend.write(b"old-pw", OLD, &format!("{CONN}.password"));
    let l = KeychainLegacy::new(KeychainSecretStore::new(backend));
    assert!(l.items().is_empty());
    l.prepare();
    assert_eq!(sorted(l.items()), [(CONN.to_string(), "password")]);
    assert_eq!(value(l.read(CONN, SecretField::Password)), Some("old-pw".into()));
    assert!(l.store().backend().accounts(OLD).is_empty());
}

#[test]
fn a_refused_read_and_an_undecodable_value_are_told_apart() {
    let l = legacy();
    l.store().backend().write(b"\xFF\xFE", SERVICE, &format!("{SYSTEM}.password"));
    assert!(matches!(l.read(SYSTEM, SecretField::Password), LegacyRead::Undecodable));
    // errSecUserCanceled: the user clicked Deny / Cancel.
    l.store().backend().fail_read(&format!("{CONN}.username"), Some(-128));
    assert!(matches!(l.read(CONN, SecretField::Username), LegacyRead::Unavailable(-128)));
    l.store().backend().fail_read(&format!("{CONN}.username"), None);
    assert_eq!(value(l.read(CONN, SecretField::Username)), Some("alice".into()));
    // The Debug output of a value is redacted.
    assert!(!format!("{:?}", l.read(CONN, SecretField::Username)).contains("alice"));
}
