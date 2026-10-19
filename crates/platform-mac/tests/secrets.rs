//! Port of `SecretStoreTests.swift`.

use macvpn_core::models::{Secrets, uuid_string};
use macvpn_platform_mac::secrets::{
    InMemoryKeychain, InMemorySecretStore, KeychainBackend, KeychainSecretStore, SecretField, SecretStore,
    SystemKeychain,
};
use uuid::Uuid;

fn exercise(store: &dyn SecretStore) {
    let id = Uuid::new_v4();
    store.set("bob", &id, SecretField::Username);
    store.set("s3cret", &id, SecretField::Password);
    store.set("s3cret2", &id, SecretField::Password);
    assert_eq!(store.get(&id, SecretField::Username).as_deref(), Some("bob"));
    assert_eq!(
        store.secrets(&id),
        Secrets { username: Some("bob".into()), password: Some("s3cret2".into()), ..Secrets::default() }
    );
    store.set("", &id, SecretField::Username);
    assert_eq!(store.get(&id, SecretField::Username), None);
    store.delete_all(&id);
    assert_eq!(store.get(&id, SecretField::Password), None);

    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    store.set("x", &a, SecretField::Password);
    store.set("y", &b, SecretField::Psk);
    store.remove_all();
    assert_eq!(store.get(&a, SecretField::Password), None);
    assert_eq!(store.get(&b, SecretField::Psk), None);
    store.delete_all(&id);
}

#[test]
fn in_memory() {
    exercise(&InMemorySecretStore::new());
}

#[test]
fn keychain_store_over_in_memory_backend() {
    exercise(&KeychainSecretStore::new(InMemoryKeychain::new()));
}

#[test]
fn default_service_is_reverse_dns() {
    assert_eq!(KeychainSecretStore::<InMemoryKeychain>::DEFAULT_SERVICE, "local.macvpn.secrets");
    assert_eq!(KeychainSecretStore::<InMemoryKeychain>::LEGACY_SERVICE, "macvpn");
    let store = KeychainSecretStore::new(InMemoryKeychain::new());
    let id = Uuid::new_v4();
    store.set("pw", &id, SecretField::Password);
    assert_eq!(
        store.backend().read("local.macvpn.secrets", &format!("{}.password", uuid_string(&id))),
        Some(b"pw".to_vec())
    );
    // The account uses the upper-case UUID, as Swift's `uuidString`.
    assert!(store.backend().accounts("local.macvpn.secrets")[0].starts_with(&uuid_string(&id)));
    // The field names are the Swift raw values.
    assert_eq!(SecretField::ALL.map(SecretField::raw_value), ["username", "password", "psk", "keypass"]);
}

#[test]
fn migration_moves_legacy_items_and_is_idempotent() {
    let backend = InMemoryKeychain::new();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    backend.write(b"old-pw", "macvpn", &format!("{}.password", uuid_string(&a)));
    backend.write(b"old-psk", "macvpn", &format!("{}.psk", uuid_string(&b)));
    backend.write(b"x", "macvpn", "not-ours");
    let store = KeychainSecretStore::new(backend);
    assert_eq!(store.migrate_legacy_items(), 2);
    assert_eq!(store.get(&a, SecretField::Password).as_deref(), Some("old-pw"));
    assert_eq!(store.get(&b, SecretField::Psk).as_deref(), Some("old-psk"));
    assert_eq!(store.backend().accounts("macvpn"), ["not-ours"]);
    assert_eq!(store.migrate_legacy_items(), 0);
    assert_eq!(store.get(&a, SecretField::Password).as_deref(), Some("old-pw"));
}

/// An interrupted migration (the new item exists, the old one was not deleted yet): the new value wins, the old
/// one is deleted.
#[test]
fn interrupted_migration_keeps_the_new_value() {
    let backend = InMemoryKeychain::new();
    let a = Uuid::new_v4();
    backend.write(b"stale", "macvpn", &format!("{}.password", uuid_string(&a)));
    backend.write(b"current", "local.macvpn.secrets", &format!("{}.password", uuid_string(&a)));
    let store = KeychainSecretStore::new(backend);
    assert_eq!(store.migrate_legacy_items(), 1);
    assert_eq!(store.get(&a, SecretField::Password).as_deref(), Some("current"));
    assert!(store.backend().accounts("macvpn").is_empty());
}

#[test]
fn failed_write_keeps_the_legacy_item() {
    let backend = InMemoryKeychain::new();
    let a = Uuid::new_v4();
    let account = format!("{}.password", uuid_string(&a));
    backend.write(b"pw", "macvpn", &account);
    backend.set_fail_writes(true);
    let store = KeychainSecretStore::new(backend);
    assert_eq!(store.migrate_legacy_items(), 0);
    assert_eq!(store.backend().read("macvpn", &account), Some(b"pw".to_vec()));
    store.backend().set_fail_writes(false);
    assert_eq!(store.migrate_legacy_items(), 1);
    assert_eq!(store.get(&a, SecretField::Password).as_deref(), Some("pw"));
}

#[test]
fn remove_all_deletes_new_service_and_our_legacy_leftovers_only() {
    let backend = InMemoryKeychain::new();
    let (a, b) = (uuid_string(&Uuid::new_v4()), uuid_string(&Uuid::new_v4()));
    backend.write(b"1", "local.macvpn.secrets", &format!("{a}.password"));
    backend.write(b"2", "local.macvpn.secrets", "anything");
    backend.write(b"3", "macvpn", &format!("{b}.psk"));
    backend.write(b"4", "macvpn", "someone-else");
    backend.write(b"5", "macvpn", &format!("{b}.other"));
    backend.write(b"6", "other", &format!("{a}.password"));
    let store = KeychainSecretStore::new(backend);
    store.remove_all();
    assert!(store.backend().accounts("local.macvpn.secrets").is_empty());
    let mut legacy = store.backend().accounts("macvpn");
    legacy.sort();
    assert_eq!(legacy, [format!("{b}.other"), "someone-else".to_string()]);
    assert_eq!(store.backend().accounts("other").len(), 1);
}

#[test]
fn our_account_pattern() {
    let id = uuid_string(&Uuid::new_v4());
    type Store = KeychainSecretStore<InMemoryKeychain>;
    assert!(Store::is_our_account(&format!("{id}.username")));
    assert!(Store::is_our_account(&format!("{}.psk", id.to_lowercase())));
    assert!(Store::is_our_account(&format!("{id}.keypass")));
    assert!(!Store::is_our_account(&format!("{id}.token")));
    assert!(!Store::is_our_account(&format!("x{id}.psk")));
    assert!(!Store::is_our_account(&id));
}

fn on_ci() -> bool {
    std::env::var_os("CI").is_some()
}

/// The real Keychain, with throwaway service names. Skipped on CI (the runner's keychain may be locked).
#[test]
fn keychain() {
    if on_ci() {
        eprintln!("skipped on CI: the keychain is not reliably available");
        return;
    }
    exercise(&KeychainSecretStore::with_services("local.macvpn.tests", "macvpn.tests.legacy", SystemKeychain));
}

#[test]
fn keychain_migration() {
    if on_ci() {
        eprintln!("skipped on CI: the keychain is not reliably available");
        return;
    }
    let store = KeychainSecretStore::with_services("local.macvpn.tests.new", "macvpn.tests.old", SystemKeychain);
    let id = Uuid::new_v4();
    let account = format!("{}.password", uuid_string(&id));
    assert!(SystemKeychain.write(b"pw", "macvpn.tests.old", &account));
    assert_eq!(store.migrate_legacy_items(), 1);
    assert_eq!(store.get(&id, SecretField::Password).as_deref(), Some("pw"));
    assert_eq!(SystemKeychain.read("macvpn.tests.old", &account), None);
    assert_eq!(store.migrate_legacy_items(), 0);
    // Update-then-add: a second write updates the item in place.
    store.set("pw2", &id, SecretField::Password);
    assert_eq!(store.get(&id, SecretField::Password).as_deref(), Some("pw2"));
    store.remove_all();
    assert!(SystemKeychain.accounts("local.macvpn.tests.new").is_empty());
}
