//! Shared credentials (plan B Task 18, spec 3a): the `credentials` and `credential_links` tables, the restricted
//! delete, copy-into-connections, the link-aware secret resolution and the "Create from connection…" matching.

mod common;

use common::TempDir;
use macvpn_core::date::Date;
use macvpn_core::models::{Connection, SecretField, VPNKind, uuid_string};
use macvpn_core::vault::{CredentialInUse, Dek, FixedEntropy, Vault, VaultError};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

fn dek() -> Dek {
    Dek::generate(&FixedEntropy::new(7)).unwrap()
}

fn new_vault(tmp: &TempDir) -> (PathBuf, Vault) {
    fs::create_dir_all(tmp.path()).unwrap();
    let dir = tmp.path().join("MacVPN");
    let vault = Vault::create(&dir, &dek()).unwrap();
    (dir, vault)
}

/// A saved OpenVPN connection; its item key.
fn connection(vault: &mut Vault, name: &str) -> (Uuid, String) {
    let c = Connection::with_id(
        Uuid::new_v4(),
        name,
        VPNKind::Openvpn,
        Date::parse_iso8601("2026-10-19T08:00:00Z").unwrap(),
    );
    vault.save_connection(&c, Some("client\nauth-user-pass\n")).unwrap();
    (c.id, uuid_string(&c.id))
}

fn secret(vault: &Vault, item: &str, field: SecretField) -> Option<String> {
    vault.secret(item, field).unwrap().map(|s| s.as_str().to_owned())
}

fn resolved(vault: &Vault, item: &str, field: SecretField) -> Option<String> {
    vault.resolved_secret(item, field).unwrap().map(|s| s.as_str().to_owned())
}

fn count(vault: &Vault, sql: &str) -> i64 {
    vault.connection().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn create_list_update_and_read_the_password() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let b = vault.create_credential("Office L2TP user", "bob", None).unwrap();
    let a = vault.create_credential("  Office AD ", "alice", Some("s3cret")).unwrap();

    let list = vault.credentials().unwrap();
    assert_eq!(list.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["Office AD", "Office L2TP user"]);
    assert_eq!(list[0].id, a);
    assert_eq!(list[0].username, "alice");
    assert!(list[0].has_password);
    assert!(!list[1].has_password);
    assert_eq!(vault.credential_password(a).unwrap().unwrap().as_str(), "s3cret");
    assert_eq!(vault.credential_password(b).unwrap(), None);
    assert_eq!(vault.credential_by_name("Office AD").unwrap(), Some(a));
    assert_eq!(vault.credential_by_name("office ad").unwrap(), None, "exact names only");

    vault.update_credential(b, Some("Office L2TP"), Some("bobby"), Some(Some("pw"))).unwrap();
    let c = vault.credential(b).unwrap().unwrap();
    assert_eq!((c.name.as_str(), c.username.as_str(), c.has_password), ("Office L2TP", "bobby", true));
    assert!(c.updated.time_interval_since_1970() >= c.created.time_interval_since_1970());
    // `None` keeps a field; `Some(None)` clears the password.
    vault.update_credential(b, None, None, Some(None)).unwrap();
    let c = vault.credential(b).unwrap().unwrap();
    assert_eq!((c.name.as_str(), c.username.as_str(), c.has_password), ("Office L2TP", "bobby", false));
    // An empty password is no password.
    vault.update_credential(b, None, None, Some(Some(""))).unwrap();
    assert_eq!(vault.credential_password(b).unwrap(), None);

    assert!(matches!(vault.update_credential(Uuid::new_v4(), Some("x"), None, None), Err(VaultError::Constraint(_))));
}

#[test]
fn names_are_unique_and_validated() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let a = vault.create_credential("Office AD", "alice", None).unwrap();
    assert!(matches!(vault.create_credential("Office AD", "bob", None), Err(VaultError::Constraint(_))));
    assert!(matches!(vault.create_credential(" Office AD", "bob", None), Err(VaultError::Constraint(_))));
    let b = vault.create_credential("Other", "bob", None).unwrap();
    assert!(matches!(vault.update_credential(b, Some("Office AD"), None, None), Err(VaultError::Constraint(_))));
    // Renaming to its own name is fine.
    vault.update_credential(a, Some("Office AD"), None, None).unwrap();

    for bad in ["", "   ", "a\nb", "tab\there", &"x".repeat(65)] {
        assert!(
            matches!(vault.create_credential(bad, "u", None), Err(VaultError::Constraint(_))),
            "name {bad:?} must be refused"
        );
    }
    assert!(vault.create_credential(&"é".repeat(64), "u", None).is_ok(), "64 characters are allowed");
    for bad in ["a\nb", &"u".repeat(257)] {
        assert!(matches!(vault.create_credential("N1", bad, None), Err(VaultError::Constraint(_))));
    }
    assert!(matches!(vault.create_credential("N2", "u", Some("p\nw")), Err(VaultError::Constraint(_))));
    assert_eq!(vault.credentials().unwrap().len(), 3);
}

#[test]
fn link_replaces_the_items_own_username_and_password_and_keeps_the_rest() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (_, item) = connection(&mut vault, "Office");
    vault.set_secret(&item, SecretField::Username, "own-user").unwrap();
    vault.set_secret(&item, SecretField::Password, "own-pass").unwrap();
    vault.set_secret(&item, SecretField::Psk, "own-psk").unwrap();
    vault.set_secret(&item, SecretField::KeyPassword, "own-keypass").unwrap();
    let cred = vault.create_credential("Office AD", "alice", Some("shared")).unwrap();

    vault.link(&item, cred).unwrap();
    assert_eq!(vault.credential_of(&item).unwrap(), Some(cred));
    // The own username and password are gone (deleted in the same transaction), the PSK and key password stay.
    assert_eq!(secret(&vault, &item, SecretField::Username), None);
    assert_eq!(secret(&vault, &item, SecretField::Password), None);
    assert_eq!(secret(&vault, &item, SecretField::Psk).as_deref(), Some("own-psk"));
    // Resolution: the credential's username and password, the item's own other secrets.
    assert_eq!(resolved(&vault, &item, SecretField::Username).as_deref(), Some("alice"));
    assert_eq!(resolved(&vault, &item, SecretField::Password).as_deref(), Some("shared"));
    assert_eq!(resolved(&vault, &item, SecretField::Psk).as_deref(), Some("own-psk"));
    assert_eq!(resolved(&vault, &item, SecretField::KeyPassword).as_deref(), Some("own-keypass"));
    assert_eq!(vault.credential_usage().unwrap().get(&cred), Some(&1));

    // Unlink: its own values again, which are empty now.
    vault.unlink(&item).unwrap();
    assert_eq!(vault.credential_of(&item).unwrap(), None);
    assert_eq!(resolved(&vault, &item, SecretField::Username), None);
    assert_eq!(resolved(&vault, &item, SecretField::Password), None);
    assert_eq!(resolved(&vault, &item, SecretField::Psk).as_deref(), Some("own-psk"));
    assert_eq!(vault.credential_usage().unwrap().get(&cred), Some(&0));
    // Unlinking an unlinked item is not an error.
    vault.unlink(&item).unwrap();
}

#[test]
fn a_system_vpn_service_id_can_be_linked() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let service = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
    vault.set_secret(service, SecretField::Psk, "psk").unwrap();
    let cred = vault.create_credential("Office L2TP", "bob", Some("pw")).unwrap();
    vault.link(service, cred).unwrap();
    assert_eq!(resolved(&vault, service, SecretField::Username).as_deref(), Some("bob"));
    assert_eq!(resolved(&vault, service, SecretField::Psk).as_deref(), Some("psk"));
}

#[test]
fn linking_to_an_unknown_credential_or_an_empty_item_is_refused() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (_, item) = connection(&mut vault, "Office");
    vault.set_secret(&item, SecretField::Password, "own").unwrap();
    assert!(matches!(vault.link(&item, Uuid::new_v4()), Err(VaultError::Constraint(_))));
    // Nothing was deleted by the failed link.
    assert_eq!(secret(&vault, &item, SecretField::Password).as_deref(), Some("own"));
    let cred = vault.create_credential("C", "u", None).unwrap();
    assert!(matches!(vault.link("", cred), Err(VaultError::Constraint(_))));
}

#[test]
fn relinking_moves_the_item_to_the_other_credential() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (_, item) = connection(&mut vault, "Office");
    let a = vault.create_credential("A", "a", Some("pa")).unwrap();
    let b = vault.create_credential("B", "b", Some("pb")).unwrap();
    vault.link(&item, a).unwrap();
    vault.link(&item, b).unwrap();
    assert_eq!(vault.credential_of(&item).unwrap(), Some(b));
    assert_eq!(resolved(&vault, &item, SecretField::Username).as_deref(), Some("b"));
    let usage = vault.credential_usage().unwrap();
    assert_eq!((usage[&a], usage[&b]), (0, 1));
}

#[test]
fn prompted_writes_to_a_linked_item_go_to_the_credential() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (_, one) = connection(&mut vault, "One");
    let (_, two) = connection(&mut vault, "Two");
    let cred = vault.create_credential("Office AD", "alice", None).unwrap();
    vault.link(&one, cred).unwrap();
    vault.link(&two, cred).unwrap();
    assert_eq!(resolved(&vault, &two, SecretField::Password), None);

    // "Save" in the credential prompt of one connection sets the shared password …
    vault.save_prompted_secret(&one, SecretField::Password, "typed").unwrap();
    assert_eq!(vault.credential_password(cred).unwrap().unwrap().as_str(), "typed");
    // … so the other linked connection has it too, and neither item got an own copy.
    assert_eq!(resolved(&vault, &two, SecretField::Password).as_deref(), Some("typed"));
    assert_eq!(secret(&vault, &one, SecretField::Password), None);
    // A typed user name updates the credential too.
    vault.save_prompted_secret(&two, SecretField::Username, "alice2").unwrap();
    assert_eq!(vault.credential(cred).unwrap().unwrap().username, "alice2");
    // An empty value never clears the shared credential (the editors clear fields they do not show).
    vault.save_prompted_secret(&one, SecretField::Password, "").unwrap();
    vault.save_prompted_secret(&one, SecretField::Username, "").unwrap();
    let c = vault.credential(cred).unwrap().unwrap();
    assert_eq!((c.username.as_str(), c.has_password), ("alice2", true));
    // The other secrets stay per connection.
    vault.save_prompted_secret(&one, SecretField::Psk, "psk1").unwrap();
    assert_eq!(secret(&vault, &one, SecretField::Psk).as_deref(), Some("psk1"));
    assert_eq!(resolved(&vault, &two, SecretField::Psk), None);
    // An unlinked item writes its own secret.
    let (_, three) = connection(&mut vault, "Three");
    vault.save_prompted_secret(&three, SecretField::Password, "own").unwrap();
    assert_eq!(secret(&vault, &three, SecretField::Password).as_deref(), Some("own"));
}

/// Review M4: the editors' write (`set_item_secret`) never reaches the shared credential. Editing connection One
/// must not change the user name and password every other linked connection uses.
#[test]
fn editor_writes_to_a_linked_item_are_refused_and_change_nothing() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (_, one) = connection(&mut vault, "One");
    let (_, two) = connection(&mut vault, "Two");
    let cred = vault.create_credential("Office AD", "alice", Some("shared-pw")).unwrap();
    vault.link(&one, cred).unwrap();
    vault.link(&two, cred).unwrap();

    for field in [SecretField::Username, SecretField::Password] {
        assert!(matches!(vault.set_item_secret(&one, field, "typed"), Err(VaultError::LinkedToCredential)));
        // An empty value (a field the linked editor does not show) is a no-op, never a clear.
        vault.set_item_secret(&one, field, "").unwrap();
    }
    let c = vault.credential(cred).unwrap().unwrap();
    assert_eq!(c.username, "alice");
    assert_eq!(vault.credential_password(cred).unwrap().unwrap().as_str(), "shared-pw");
    assert_eq!(resolved(&vault, &two, SecretField::Password).as_deref(), Some("shared-pw"));
    assert_eq!(secret(&vault, &one, SecretField::Username), None);
    assert_eq!(secret(&vault, &one, SecretField::Password), None);
    // The other fields stay the item's own.
    vault.set_item_secret(&one, SecretField::Psk, "psk1").unwrap();
    assert_eq!(secret(&vault, &one, SecretField::Psk).as_deref(), Some("psk1"));
    vault.set_item_secret(&one, SecretField::Psk, "").unwrap();
    assert_eq!(secret(&vault, &one, SecretField::Psk), None);
    // An unlinked item writes (and clears) its own username and password.
    vault.unlink(&one).unwrap();
    vault.set_item_secret(&one, SecretField::Password, "own").unwrap();
    assert_eq!(secret(&vault, &one, SecretField::Password).as_deref(), Some("own"));
    assert_eq!(vault.credential_password(cred).unwrap().unwrap().as_str(), "shared-pw");
}

#[test]
fn deleting_all_secrets_and_credentials_is_one_transaction() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (_, one) = connection(&mut vault, "One");
    let (_, two) = connection(&mut vault, "Two");
    let cred = vault.create_credential("Office AD", "alice", Some("pw")).unwrap();
    vault.link(&one, cred).unwrap();
    vault.set_secret(&two, SecretField::Password, "own").unwrap();
    vault.delete_all_secrets_and_credentials().unwrap();
    assert_eq!(count(&vault, "SELECT count(*) FROM secrets"), 0);
    assert_eq!(count(&vault, "SELECT count(*) FROM credential_links"), 0);
    assert_eq!(count(&vault, "SELECT count(*) FROM credentials"), 0);
}

#[test]
fn delete_is_restricted_while_linked() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (_, one) = connection(&mut vault, "One");
    let (_, two) = connection(&mut vault, "Two");
    let cred = vault.create_credential("Office AD", "alice", Some("pw")).unwrap();
    vault.link(&one, cred).unwrap();
    vault.link(&two, cred).unwrap();

    let mut expected = vec![one.clone(), two.clone()];
    expected.sort();
    match vault.delete_credential(cred) {
        Err(Ok(CredentialInUse { items })) => assert_eq!(items, expected),
        other => panic!("expected CredentialInUse, got {other:?}"),
    }
    assert!(vault.credential(cred).unwrap().is_some());
    // The schema itself restricts it too (ON DELETE RESTRICT), whatever the code path.
    let raw = vault.transaction(|tx| {
        tx.execute("DELETE FROM credentials WHERE id = ?1", [uuid_string(&cred)])?;
        Ok(())
    });
    assert!(matches!(raw, Err(VaultError::Constraint(_))));

    vault.unlink(&one).unwrap();
    vault.unlink(&two).unwrap();
    vault.delete_credential(cred).unwrap();
    assert!(vault.credential(cred).unwrap().is_none());
    // Deleting an unknown credential is not an error.
    vault.delete_credential(Uuid::new_v4()).unwrap();
}

#[test]
fn copy_into_connections_gives_every_item_its_own_copy() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (_, one) = connection(&mut vault, "One");
    let service = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
    vault.set_secret(&one, SecretField::Psk, "psk").unwrap();
    let cred = vault.create_credential("Office AD", "alice", Some("pw")).unwrap();
    let other = vault.create_credential("Other", "o", None).unwrap();
    let (_, three) = connection(&mut vault, "Three");
    vault.link(&one, cred).unwrap();
    vault.link(service, cred).unwrap();
    vault.link(&three, other).unwrap();

    vault.copy_into_connections(cred).unwrap();
    for item in [one.as_str(), service] {
        assert_eq!(secret(&vault, item, SecretField::Username).as_deref(), Some("alice"));
        assert_eq!(secret(&vault, item, SecretField::Password).as_deref(), Some("pw"));
        assert_eq!(vault.credential_of(item).unwrap(), None);
    }
    assert_eq!(secret(&vault, &one, SecretField::Psk).as_deref(), Some("psk"));
    assert!(vault.credential(cred).unwrap().is_none());
    // Other credentials and links are untouched.
    assert_eq!(vault.credential_of(&three).unwrap(), Some(other));

    // A credential without a password copies only the user name.
    let (_, four) = connection(&mut vault, "Four");
    vault.link(&four, other).unwrap();
    vault.copy_into_connections(other).unwrap();
    assert_eq!(secret(&vault, &four, SecretField::Username).as_deref(), Some("o"));
    assert_eq!(secret(&vault, &four, SecretField::Password), None);
    assert_eq!(count(&vault, "SELECT count(*) FROM credentials"), 0);
    assert_eq!(count(&vault, "SELECT count(*) FROM credential_links"), 0);
}

#[test]
fn deleting_a_connection_removes_its_link_but_keeps_the_credential() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (id, item) = connection(&mut vault, "One");
    let cred = vault.create_credential("Office AD", "alice", None).unwrap();
    vault.link(&item, cred).unwrap();
    vault.delete_connection(&id).unwrap();
    assert_eq!(vault.credential_of(&item).unwrap(), None);
    vault.delete_credential(cred).unwrap();
}

#[test]
fn matching_items_finds_exact_username_and_password_matches_only() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (_, source) = connection(&mut vault, "Source");
    let (_, same) = connection(&mut vault, "Same");
    let (_, other_pass) = connection(&mut vault, "Other password");
    let (_, other_user) = connection(&mut vault, "Other user");
    let (_, no_pass) = connection(&mut vault, "No password");
    let (_, linked) = connection(&mut vault, "Linked");
    let service = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
    for (item, user, pass) in [
        (source.as_str(), Some("alice"), Some("pw")),
        (same.as_str(), Some("alice"), Some("pw")),
        (other_pass.as_str(), Some("alice"), Some("PW")),
        (other_user.as_str(), Some("Alice"), Some("pw")),
        (no_pass.as_str(), Some("alice"), None),
        (service, Some("alice"), Some("pw")),
    ] {
        if let Some(user) = user {
            vault.set_secret(item, SecretField::Username, user).unwrap();
        }
        if let Some(pass) = pass {
            vault.set_secret(item, SecretField::Password, pass).unwrap();
        }
    }
    let cred = vault.create_credential("X", "alice", Some("pw")).unwrap();
    vault.link(&linked, cred).unwrap();

    let mut expected = vec![same.clone(), service.to_string()];
    expected.sort();
    assert_eq!(vault.matching_items(&source).unwrap(), expected);
    // Without an own username and password there is nothing to match.
    assert!(vault.matching_items(&no_pass).unwrap().is_empty());
    assert!(vault.matching_items(&linked).unwrap().is_empty());
}

#[test]
fn create_from_connection_creates_and_links_in_one_go() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (_, source) = connection(&mut vault, "Source");
    let (_, same) = connection(&mut vault, "Same");
    let (_, same_unticked) = connection(&mut vault, "Same, not ticked");
    let (_, different) = connection(&mut vault, "Different");
    for item in [&source, &same, &same_unticked] {
        vault.set_secret(item, SecretField::Username, "alice").unwrap();
        vault.set_secret(item, SecretField::Password, "pw").unwrap();
    }
    vault.set_secret(&source, SecretField::Psk, "psk").unwrap();
    vault.set_secret(&different, SecretField::Username, "bob").unwrap();
    vault.set_secret(&different, SecretField::Password, "pw").unwrap();

    // A non-matching item in the list refuses the whole operation, and nothing changes.
    let refused = vault.create_credential_from(&source, "Office AD", &[same.clone(), different.clone()]);
    assert!(matches!(refused, Err(VaultError::Constraint(_))));
    assert!(vault.credentials().unwrap().is_empty());
    assert_eq!(secret(&vault, &source, SecretField::Password).as_deref(), Some("pw"));

    let cred = vault.create_credential_from(&source, "Office AD", std::slice::from_ref(&same)).unwrap();
    let c = vault.credential(cred).unwrap().unwrap();
    assert_eq!((c.name.as_str(), c.username.as_str(), c.has_password), ("Office AD", "alice", true));
    assert_eq!(vault.credential_password(cred).unwrap().unwrap().as_str(), "pw");
    for item in [&source, &same] {
        assert_eq!(vault.credential_of(item).unwrap(), Some(cred));
        assert_eq!(secret(&vault, item, SecretField::Password), None);
        assert_eq!(resolved(&vault, item, SecretField::Password).as_deref(), Some("pw"));
    }
    assert_eq!(secret(&vault, &source, SecretField::Psk).as_deref(), Some("psk"));
    assert_eq!(vault.credential_of(&same_unticked).unwrap(), None);
    assert_eq!(secret(&vault, &same_unticked, SecretField::Password).as_deref(), Some("pw"));

    // A duplicate name is refused, and so is a source without an own username (a linked one has none).
    assert!(matches!(vault.create_credential_from(&same_unticked, "Office AD", &[]), Err(VaultError::Constraint(_))));
    assert!(matches!(vault.create_credential_from(&source, "New", &[]), Err(VaultError::Constraint(_))));
    let (_, empty) = connection(&mut vault, "Empty");
    assert!(matches!(vault.create_credential_from(&empty, "New", &[]), Err(VaultError::Constraint(_))));
    // The source alone, without a password: the credential has none either.
    vault.set_secret(&different, SecretField::Password, "").unwrap();
    let bob = vault.create_credential_from(&different, "Bob", &[]).unwrap();
    assert_eq!(vault.credential_password(bob).unwrap(), None);
    assert_eq!(vault.credential_of(&different).unwrap(), Some(bob));
}

#[test]
fn credential_values_are_stored_as_blobs_and_errors_quote_nothing() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let cred = vault.create_credential("Office AD", "alice", Some("CanaryPassword")).unwrap();
    let kind: String = vault
        .connection()
        .query_row("SELECT typeof(password) FROM credentials WHERE id = ?1", [uuid_string(&cred)], |r| r.get(0))
        .unwrap();
    assert_eq!(kind, "blob");
    let err = vault.create_credential("Office AD", "alice", Some("CanaryPassword")).unwrap_err();
    assert!(!err.to_string().contains("CanaryPassword"));
    let debug = format!("{:?}", vault.credentials().unwrap());
    assert!(!debug.contains("CanaryPassword"));
}

#[test]
fn a_newer_database_refuses_credential_writes() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    let cred = vault.create_credential("Office AD", "alice", None).unwrap();
    vault
        .transaction(|tx| {
            tx.execute_batch(
                "UPDATE meta SET value = '99' WHERE key = 'schema_version';
                 UPDATE meta SET value = '99' WHERE key = 'min_app_schema';",
            )?;
            Ok(())
        })
        .unwrap();
    vault.close();
    let mut vault = Vault::open(&dir, &dek()).unwrap();
    assert_eq!(vault.credentials().unwrap().len(), 1);
    assert!(matches!(vault.create_credential("B", "b", None), Err(VaultError::NewerSchema { .. })));
    assert!(matches!(vault.link("A", cred), Err(VaultError::NewerSchema { .. })));
    assert!(matches!(vault.delete_credential(cred), Err(Err(VaultError::NewerSchema { .. }))));
}
