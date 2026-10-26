//! Vault schema v2: the team catalog repositories (plan Task 6): subscriptions with their secrets, namespaced ids,
//! the read-only guard on catalog-owned rows, admin keys and publications.

mod common;

use common::TempDir;
use macvpn_core::catalog::format::CatalogErrorKind;
use macvpn_core::catalog::ids::{CatalogItemKind, local_id, root_folder_id};
use macvpn_core::catalog::keys::{AdminKey, TeamKey};
use macvpn_core::catalog::selection::{InlineSecret, PublishSelection};
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl};
use macvpn_core::control::protocol::is_uuid_shaped;
use macvpn_core::date::Date;
use macvpn_core::models::{Connection, SecretField, VPNKind, uuid_string};
use macvpn_core::ranking::ConnectionRanking;
use macvpn_core::vault::{
    AdminKeyRole, Dek, DeleteMode, FixedEntropy, FolderColor, PublicationRecord, SourceValidators, SubscriptionRecord,
    SubscriptionStatus, Vault, VaultError,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

const TOKEN: &str = "c2VjcmV0LWJlYXJlci10b2tlbg.abc~+/-_=";

fn new_vault(tmp: &TempDir) -> Vault {
    fs::create_dir_all(tmp.path()).unwrap();
    Vault::create(&tmp.path().join("MacVPN"), &Dek::generate(&FixedEntropy::new(3)).unwrap()).unwrap()
}

fn date(s: &str) -> Date {
    Date::parse_iso8601(s).unwrap()
}

fn catalog_id(n: u128) -> Uuid {
    Uuid::from_u128(0xC000_0000_0000_4000_8000_0000_0000_0000 + n)
}

fn record(id: Uuid, name: &str) -> SubscriptionRecord {
    let admin = AdminKey::generate(&FixedEntropy::new(9)).unwrap();
    SubscriptionRecord {
        catalog_id: id,
        name: name.into(),
        source: CatalogSource::Https(HttpsUrl::parse("https://vpn.example.com/team.macvpncatalog?k=1").unwrap()),
        pinned: admin.public().fingerprint(),
        applied_version: None,
        reapply: false,
        status: SubscriptionStatus::Ok,
        validators: SourceValidators::default(),
        last_attempt: None,
        last_success: None,
        failures: 0,
        has_bearer: false,
        publisher_key: None,
        successor_key: None,
        added: date("2026-10-19T08:00:00Z"),
    }
}

fn team_key(seed: u64) -> TeamKey {
    TeamKey::generate(&FixedEntropy::new(seed)).unwrap()
}

fn subscribe(vault: &mut Vault, id: Uuid, name: &str) {
    vault.add_subscription(&record(id, name), &team_key(1), Some(TOKEN)).unwrap();
}

fn count(vault: &Vault, sql: &str) -> i64 {
    vault.connection().query_row(sql, [], |r| r.get(0)).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Every TEXT column of the catalog tables, concatenated (the JSON columns and the ids).
fn text_columns(vault: &Vault) -> String {
    let mut out = String::new();
    for sql in [
        "SELECT json FROM catalog_subscriptions",
        "SELECT json FROM catalog_publications",
        "SELECT key_id || role || created FROM catalog_admin_keys",
    ] {
        let mut stmt = vault.connection().prepare(sql).unwrap();
        for row in stmt.query_map([], |r| r.get::<_, String>(0)).unwrap() {
            out.push_str(&row.unwrap());
        }
    }
    out
}

/// A catalog-owned folder and connection under the root of `catalog`, written as the executor (Task 7) would.
fn owned_rows(vault: &mut Vault, catalog: Uuid) -> (Uuid, Uuid) {
    let folder = local_id(catalog, CatalogItemKind::Folder, Uuid::from_u128(1));
    let connection = local_id(catalog, CatalogItemKind::Connection, Uuid::from_u128(2));
    let c = Connection::with_id(connection, "Team VPN", VPNKind::L2tp, date("2026-10-19T08:00:00Z"));
    let meta = macvpn_core::swift_json::to_pretty_sorted(&c.to_json()).unwrap();
    let root = uuid_string(&root_folder_id(catalog));
    vault
        .transaction(|tx| {
            tx.execute(
                "INSERT INTO folders(id, parent_id, name, color, position) VALUES (?1, ?2, 'Offices', 'blue', 0)",
                (uuid_string(&folder), &root),
            )?;
            tx.execute(
                "INSERT INTO catalog_items(local_id, catalog_id, item_id, kind, meta_hash) VALUES (?1, ?2, ?3, 'folder', 'h')",
                (uuid_string(&folder), uuid_string(&catalog), uuid_string(&Uuid::from_u128(1))),
            )?;
            tx.execute(
                "INSERT INTO connections(id, kind, meta_json, config, folder_id, position) VALUES (?1, 'l2tp', ?2, x'', ?3, 0)",
                (uuid_string(&connection), &meta, uuid_string(&folder)),
            )?;
            tx.execute(
                "INSERT INTO catalog_items(local_id, catalog_id, item_id, kind, provided_secrets, meta_hash, config_hash)
                 VALUES (?1, ?2, ?3, 'connection', 'psk', 'h', 'c')",
                (uuid_string(&connection), uuid_string(&catalog), uuid_string(&Uuid::from_u128(2))),
            )?;
            tx.execute(
                "INSERT INTO secrets(connection_id, field, value) VALUES (?1, 'psk', x'7465616d')",
                [uuid_string(&connection)],
            )?;
            Ok(())
        })
        .unwrap();
    (folder, connection)
}

// MARK: - namespaced ids

#[test]
fn local_ids_are_deterministic_namespaced_and_uuid_shaped() {
    let a = catalog_id(1);
    let b = catalog_id(2);
    let item = Uuid::from_u128(42);
    let id = local_id(a, CatalogItemKind::Connection, item);
    assert_eq!(id, local_id(a, CatalogItemKind::Connection, item), "deterministic");
    assert_ne!(id, local_id(b, CatalogItemKind::Connection, item), "per catalog");
    assert_ne!(id, local_id(a, CatalogItemKind::Folder, item), "per kind");
    assert_ne!(id, local_id(a, CatalogItemKind::Connection, Uuid::from_u128(43)), "per item");
    assert_eq!(root_folder_id(a), local_id(a, CatalogItemKind::Root, a));
    assert_ne!(root_folder_id(a), root_folder_id(b));
    assert_eq!(id.get_version_num(), 8);
    assert!(is_uuid_shaped(&uuid_string(&id)));
    // Known answer: the derivation must never change (restores and re-subscribes rely on the same ids).
    // Known answer (computed independently): the derivation must never change, since restores and re-subscribes
    // rely on the same ids.
    assert_eq!(
        uuid_string(&local_id(Uuid::nil(), CatalogItemKind::Connection, Uuid::nil())),
        "190BD011-3B8E-8F56-AA6C-60D82C9678F2"
    );
}

// MARK: - subscriptions

#[test]
fn a_subscription_round_trips_and_creates_its_root_folder() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let id = catalog_id(1);
    let key = team_key(5);
    let mut r = record(id, "Acme VPN");
    r.validators = SourceValidators {
        etag: Some("\"abc\"".into()),
        last_modified: Some("Mon, 19 Oct 2026 08:00:00 GMT".into()),
        content_hash: Some([7u8; 32]),
    };
    vault.add_subscription(&r, &key, Some(TOKEN)).unwrap();

    let list = vault.subscriptions().unwrap();
    assert_eq!(list.len(), 1);
    let mut expected = r.clone();
    expected.has_bearer = true;
    assert_eq!(list[0], expected);
    let (stored_key, bearer) = vault.subscription_secrets(id).unwrap();
    assert_eq!(stored_key.as_bytes(), key.as_bytes());
    assert_eq!(bearer.as_deref().map(String::as_str), Some(TOKEN));

    // The root folder, named after the catalog, owned by it.
    let root = root_folder_id(id);
    let tree = vault.folder_tree().unwrap();
    assert_eq!(tree.get(root).map(|f| f.name.as_str()), Some("Acme VPN"));
    let owner = vault.catalog_owner(&uuid_string(&root)).unwrap().unwrap();
    assert_eq!(owner.kind, CatalogItemKind::Root);
    assert_eq!(owner.catalog_name, "Acme VPN");
    let local = vault.local_catalog(id).unwrap();
    assert_eq!(local.root_folder, root);
    assert!(local.items.is_empty() && local.slots.is_empty());

    // State updates, the trust keys, the status variants.
    let admin = AdminKey::generate(&FixedEntropy::new(11)).unwrap();
    for status in [
        SubscriptionStatus::NotModified,
        SubscriptionStatus::Unavailable,
        SubscriptionStatus::Failed(CatalogErrorKind::BadSignature),
        SubscriptionStatus::RollbackRefused { offered: 3 },
        SubscriptionStatus::TeamKeyChanged,
        SubscriptionStatus::Ok,
    ] {
        vault
            .update_subscription_state(id, |r| {
                r.status = status;
                r.applied_version = Some(4);
                r.failures = 2;
                r.publisher_key = Some(admin.public());
                r.last_attempt = Some(date("2026-10-19T09:00:00Z"));
            })
            .unwrap();
        let back = vault.subscription(id).unwrap().unwrap();
        assert_eq!(back.status, status);
        assert_eq!(back.applied_version, Some(4));
        assert_eq!(back.publisher_key, Some(admin.public()));
    }

    // Secrets change only through their own calls.
    let new_key = team_key(6);
    vault.set_subscription_team_key(id, &new_key).unwrap();
    assert_eq!(vault.subscription_secrets(id).unwrap().0.as_bytes(), new_key.as_bytes());
    vault.set_subscription_bearer(id, None).unwrap();
    assert!(vault.subscription_secrets(id).unwrap().1.is_none());
    assert!(!vault.subscription(id).unwrap().unwrap().has_bearer);
}

#[test]
fn team_key_and_token_are_only_in_their_blob_columns() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let key = team_key(5);
    vault.add_subscription(&record(catalog_id(1), "Acme VPN"), &key, Some(TOKEN)).unwrap();
    let text = text_columns(&vault);
    assert!(!text.contains(key.to_text().as_str()), "team key text in a JSON column");
    assert!(!text.contains(TOKEN), "token in a JSON column");
    let json: String =
        vault.connection().query_row("SELECT json FROM catalog_subscriptions", [], |r| r.get(0)).unwrap();
    assert!(!contains(json.as_bytes(), &key.as_bytes()[..8]));
    let debug = format!("{:?}", vault.subscriptions().unwrap());
    assert!(!debug.contains(TOKEN) && !debug.contains(key.to_text().as_str()), "{debug}");
}

#[test]
fn subscribing_twice_and_bad_input_are_refused() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let id = catalog_id(1);
    subscribe(&mut vault, id, "Acme VPN");
    assert!(matches!(
        vault.add_subscription(&record(id, "Acme VPN"), &team_key(1), None),
        Err(VaultError::Constraint(_))
    ));
    for bad in ["", "has space", "quote\"", "back\\slash", "=abc", &"a".repeat(4097)] {
        assert!(
            matches!(
                vault.add_subscription(&record(catalog_id(2), "Other"), &team_key(1), Some(bad)),
                Err(VaultError::Constraint(_))
            ),
            "{bad:?}"
        );
        assert!(matches!(vault.set_subscription_bearer(id, Some(bad)), Err(VaultError::Constraint(_))));
    }
    vault.set_subscription_bearer(id, Some(&"a".repeat(4096))).unwrap();
    assert!(matches!(
        vault.add_subscription(&record(catalog_id(3), "  padded "), &team_key(1), None),
        Err(VaultError::Constraint(_))
    ));
    assert_eq!(vault.subscriptions().unwrap().len(), 1, "nothing of the refused ones");
}

#[test]
fn deleting_a_subscription_cascades_items_and_slots() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let id = catalog_id(1);
    subscribe(&mut vault, id, "Acme VPN");
    owned_rows(&mut vault, id);
    vault
        .transaction(|tx| {
            tx.execute(
                "INSERT INTO catalog_slots(catalog_id, slot_id, name) VALUES (?1, ?2, 'Office AD')",
                (uuid_string(&id), uuid_string(&Uuid::from_u128(9))),
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(vault.local_catalog(id).unwrap().items.len(), 2);
    assert_eq!(vault.local_catalog(id).unwrap().slots.len(), 1);
    vault
        .transaction(|tx| {
            tx.execute("DELETE FROM catalog_subscriptions WHERE catalog_id = ?1", [uuid_string(&id)])?;
            Ok(())
        })
        .unwrap();
    assert_eq!(count(&vault, "SELECT count(*) FROM catalog_items"), 0);
    assert_eq!(count(&vault, "SELECT count(*) FROM catalog_slots"), 0);
    assert_eq!(count(&vault, "SELECT count(*) FROM connections"), 1, "the executor removes the rows, not the cascade");
}

// MARK: - the read-only guard

#[test]
fn every_guarded_write_on_a_catalog_row_is_refused() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let id = catalog_id(1);
    subscribe(&mut vault, id, "Acme VPN");
    let root = root_folder_id(id);
    let (folder, connection) = owned_rows(&mut vault, id);
    let key = uuid_string(&connection);
    let personal_folder = vault.create_folder(None, "Mine").unwrap();
    let personal = Connection::new("Personal", VPNKind::Wireguard);
    vault.save_connection(&personal, Some("[Interface]\n")).unwrap();
    let personal_key = uuid_string(&personal.id);

    let managed = |r: Result<(), VaultError>, what: &str| {
        assert!(matches!(r, Err(VaultError::CatalogManaged)), "{what}: {r:?}");
    };
    let mut c = Connection::with_id(connection, "Renamed", VPNKind::L2tp, Date::now());
    managed(vault.save_connection(&c, None), "save_connection");
    c.name = "Team VPN".into();
    managed(vault.save_connection(&c, Some("config")), "save_connection config");
    managed(vault.delete_connection(&connection), "delete_connection");
    managed(vault.set_item_folder(&key, None), "set_item_folder of a catalog connection");
    managed(vault.set_item_folder(&key, Some(personal_folder)), "set_item_folder to a personal folder");
    managed(vault.set_item_folder(&personal_key, Some(folder)), "a personal item into a catalog folder");
    managed(vault.set_item_folder(&personal_key, Some(root)), "a personal item into the catalog root");
    managed(vault.set_item_folder("SYSTEM-SERVICE", Some(folder)), "a system VPN into a catalog folder");
    managed(vault.create_folder(Some(folder), "Sub").map(|_| ()), "create_folder under a catalog folder");
    managed(vault.create_folder(Some(root), "Sub").map(|_| ()), "create_folder under the root");
    for f in [folder, root] {
        managed(vault.rename_folder(f, "Other"), "rename_folder");
        managed(vault.set_folder_color(f, Some(FolderColor::Red)), "set_folder_color");
        managed(vault.move_folder(f, Some(personal_folder), 0), "move_folder");
        managed(vault.delete_folder(f, DeleteMode::MoveContentsUp).map(|_| ()), "delete_folder");
        managed(vault.delete_folder(f, DeleteMode::DeleteContents).map(|_| ()), "delete_folder contents");
    }
    managed(vault.move_folder(personal_folder, Some(folder), 0), "move a personal folder into a catalog folder");
    managed(vault.set_item_secret(&key, SecretField::Psk, "mine"), "set_item_secret of a provided field");
    managed(vault.save_prompted_secret(&key, SecretField::Psk, "mine"), "save_prompted_secret of a provided field");
    managed(vault.set_secret(&key, SecretField::Psk, ""), "set_secret of a provided field");

    // Nothing changed.
    assert_eq!(vault.secret(&key, SecretField::Psk).unwrap().as_deref().map(String::as_str), Some("team"));
    assert_eq!(vault.folder_tree().unwrap().get(folder).unwrap().name, "Offices");
    assert_eq!(vault.connections().unwrap().iter().filter(|c| c.connection.id == connection).count(), 1);
}

#[test]
fn every_allowed_write_on_a_catalog_row_works() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let id = catalog_id(1);
    subscribe(&mut vault, id, "Acme VPN");
    let root = root_folder_id(id);
    let (folder, connection) = owned_rows(&mut vault, id);
    let key = uuid_string(&connection);

    vault.set_collapsed(folder, true).unwrap();
    vault.set_collapsed(root, true).unwrap();
    vault.set_item_color(&key, Some(FolderColor::Green)).unwrap();
    vault.save_ranking(&ConnectionRanking::new(vec![key.clone()], Default::default())).unwrap();
    // Own secrets the catalog does not provide; the prompt's username and password.
    vault.set_item_secret(&key, SecretField::Username, "alice").unwrap();
    vault.save_prompted_secret(&key, SecretField::Password, "pw").unwrap();
    vault.set_secret(&key, SecretField::KeyPassword, "kp").unwrap();
    // The credential link.
    let credential = vault.create_credential("Office AD", "", None).unwrap();
    vault.link(&key, credential).unwrap();
    vault.save_prompted_secret(&key, SecretField::Username, "bob").unwrap();
    assert_eq!(vault.credential(credential).unwrap().unwrap().username, "bob");
    vault.unlink(&key).unwrap();
    // The acknowledgement of risky directives.
    let seen = vault.config(&connection).unwrap();
    vault.set_acknowledged_risky(connection, &seen, &["up".to_string(), "script-security".to_string()]).unwrap();
    let stored = vault.connections().unwrap().into_iter().find(|c| c.connection.id == connection).unwrap();
    assert_eq!(stored.connection.acknowledged_risky_directives, ["script-security", "up"]);
    assert_eq!(stored.connection.name, "Team VPN", "nothing else changed");
    assert_eq!(stored.color, Some(FolderColor::Green));
    assert!(vault.folder_tree().unwrap().get(folder).unwrap().collapsed);
    assert_eq!(vault.ranking().unwrap().pinned(), std::slice::from_ref(&key));

    let owner = vault.catalog_owner(&key).unwrap().unwrap();
    assert_eq!(owner.catalog_id, id);
    assert_eq!(owner.kind, CatalogItemKind::Connection);
    assert_eq!(owner.provided_secrets, BTreeSet::from([SecretField::Psk]));
    assert!(vault.catalog_owner(&uuid_string(&Uuid::new_v4())).unwrap().is_none());
}

#[test]
fn personal_rows_are_not_guarded() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    subscribe(&mut vault, catalog_id(1), "Acme VPN");
    let a = vault.create_folder(None, "A").unwrap();
    let b = vault.create_folder(Some(a), "B").unwrap();
    vault.rename_folder(b, "C").unwrap();
    vault.move_folder(b, None, 0).unwrap();
    let c = Connection::new("Mine", VPNKind::Wireguard);
    vault.save_connection(&c, Some("[Interface]\n")).unwrap();
    vault.set_item_folder(&uuid_string(&c.id), Some(a)).unwrap();
    vault.set_item_secret(&uuid_string(&c.id), SecretField::Psk, "x").unwrap();
    vault.delete_connection(&c.id).unwrap();
    vault.delete_folder(a, DeleteMode::DeleteContents).unwrap();
}

// MARK: - admin keys

#[test]
fn admin_keys_save_list_load_promote_delete() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let primary = AdminKey::generate(&FixedEntropy::new(21)).unwrap();
    let backup = AdminKey::generate(&FixedEntropy::new(22)).unwrap();
    let created = date("2026-10-19T08:00:00Z");
    vault.save_admin_key(&primary, AdminKeyRole::Primary, created).unwrap();
    vault.save_admin_key(&primary, AdminKeyRole::Primary, created).unwrap();
    vault.save_admin_key(&backup, AdminKeyRole::Backup, created).unwrap();

    let list = vault.admin_keys().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!((list[0].role, list[0].public), (AdminKeyRole::Primary, primary.public()));
    assert_eq!(list[0].fingerprint, primary.public().fingerprint());
    assert_eq!((list[1].role, list[1].public), (AdminKeyRole::Backup, backup.public()));
    let debug = format!("{list:?}");
    let seed_hex: String = primary.seed().iter().map(|b| format!("{b:02x}")).collect();
    assert!(!debug.contains(&seed_hex));
    assert!(!text_columns(&vault).contains(&seed_hex));

    let loaded = vault.admin_key(AdminKeyRole::Primary).unwrap().unwrap();
    assert_eq!(loaded.public(), primary.public());
    assert_eq!(loaded.sign(b"m"), primary.sign(b"m"));

    // A role is never taken over silently.
    let other = AdminKey::generate(&FixedEntropy::new(23)).unwrap();
    assert!(matches!(vault.save_admin_key(&other, AdminKeyRole::Primary, created), Err(VaultError::Constraint(_))));
    assert!(matches!(vault.save_admin_key(&backup, AdminKeyRole::Primary, created), Err(VaultError::Constraint(_))));

    vault.promote_backup_key().unwrap();
    let list = vault.admin_keys().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!((list[0].role, list[0].public), (AdminKeyRole::Primary, backup.public()));
    assert!(matches!(vault.promote_backup_key(), Err(VaultError::Constraint(_))));
    assert!(vault.admin_key(AdminKeyRole::Backup).unwrap().is_none());

    vault.delete_admin_key(&backup.public().fingerprint()).unwrap();
    assert!(vault.admin_keys().unwrap().is_empty());
}

#[test]
fn a_backup_key_taken_offline_keeps_its_public_half_until_it_is_imported_again() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let primary = AdminKey::generate(&FixedEntropy::new(21)).unwrap();
    let backup = AdminKey::generate(&FixedEntropy::new(22)).unwrap();
    let created = date("2026-10-19T08:00:00Z");
    vault.save_admin_key(&primary, AdminKeyRole::Primary, created).unwrap();
    // Only the stored backup key can be taken offline.
    assert!(matches!(vault.take_backup_key_offline(&backup.public().fingerprint()), Err(VaultError::Constraint(_))));
    vault.save_admin_key(&backup, AdminKeyRole::Backup, created).unwrap();
    vault.take_backup_key_offline(&backup.public().fingerprint()).unwrap();

    assert!(vault.admin_key(AdminKeyRole::Backup).unwrap().is_none(), "the seed is gone");
    let list = vault.admin_keys().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!((list[1].role, list[1].public, list[1].offline), (AdminKeyRole::Backup, backup.public(), true));
    assert!(!list[0].offline);
    let seed_hex: String = backup.seed().iter().map(|b| format!("{b:02x}")).collect();
    assert!(!text_columns(&vault).contains(&seed_hex));
    // An offline key cannot be promoted, and holds its role.
    assert!(matches!(vault.promote_backup_key(), Err(VaultError::Constraint(_))));
    let other = AdminKey::generate(&FixedEntropy::new(23)).unwrap();
    assert!(matches!(vault.save_admin_key(&other, AdminKeyRole::Backup, created), Err(VaultError::Constraint(_))));
    assert!(matches!(vault.save_admin_key(&backup, AdminKeyRole::Primary, created), Err(VaultError::Constraint(_))));

    // Imported again: online, promotable.
    vault.save_admin_key(&backup, AdminKeyRole::Backup, created).unwrap();
    let list = vault.admin_keys().unwrap();
    assert_eq!(list.len(), 2);
    assert!(!list[1].offline);
    vault.promote_backup_key().unwrap();
    assert_eq!(vault.admin_keys().unwrap()[0].public, backup.public());

    // Deleting an offline key forgets its public half.
    vault.save_admin_key(&other, AdminKeyRole::Backup, created).unwrap();
    vault.take_backup_key_offline(&other.public().fingerprint()).unwrap();
    vault.delete_admin_key(&other.public().fingerprint()).unwrap();
    assert_eq!(vault.admin_keys().unwrap().len(), 1);
}

// MARK: - publications

#[test]
fn publications_round_trip_with_the_team_key_only_in_its_column() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let id = catalog_id(7);
    let key = team_key(8);
    let mut selection = PublishSelection::default();
    selection.folders.insert(Uuid::from_u128(1));
    selection.connections.insert(Uuid::from_u128(2));
    selection.secrets.insert((Uuid::from_u128(2), SecretField::Psk));
    selection.slots.insert(Uuid::from_u128(3));
    selection.inline_secrets.insert((Uuid::from_u128(2), InlineSecret::WireGuardPrivateKey));
    let p = PublicationRecord {
        catalog_id: id,
        name: "Acme VPN".into(),
        version: 3,
        selection,
        secret_ids: BTreeMap::from([((Uuid::from_u128(2), SecretField::Psk), Uuid::from_u128(4))]),
        item_hashes: BTreeMap::from([(Uuid::from_u128(2), "abc".to_string())]),
        last_path: Some(PathBuf::from("/Volumes/share/Acme VPN.macvpncatalog")),
        last_published: Some(date("2026-10-19T08:00:00Z")),
        announced_successor: None,
    };
    assert!(matches!(vault.save_publication(&p, None), Err(VaultError::Constraint(_))), "a new one needs its key");
    vault.save_publication(&p, Some(&key)).unwrap();
    assert_eq!(vault.publications().unwrap(), std::slice::from_ref(&p));
    assert_eq!(vault.publication_team_key(id).unwrap().as_bytes(), key.as_bytes());
    assert!(!text_columns(&vault).contains(key.to_text().as_str()));

    let mut next = p.clone();
    next.version = 4;
    next.last_path = None;
    vault.save_publication(&next, None).unwrap();
    assert_eq!(vault.publications().unwrap(), [next]);
    assert_eq!(vault.publication_team_key(id).unwrap().as_bytes(), key.as_bytes(), "kept");

    vault.delete_publication(id).unwrap();
    assert!(vault.publications().unwrap().is_empty());
    assert!(matches!(vault.publication_team_key(id), Err(VaultError::Constraint(_))));
}

#[test]
fn catalog_rows_make_the_vault_non_empty() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    assert!(vault.is_empty().unwrap());
    vault
        .save_admin_key(&AdminKey::generate(&FixedEntropy::new(1)).unwrap(), AdminKeyRole::Primary, Date::now())
        .unwrap();
    assert!(!vault.is_empty().unwrap());
}
