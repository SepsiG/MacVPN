//! The vault repositories for connections and secrets (plan B Task 7): `meta_json` is today's `meta.json`, the
//! config and the secrets are BLOBs, and every write goes through the vault's transaction API.

mod common;

use common::TempDir;
use macvpn_core::date::Date;
use macvpn_core::models::{Connection, SecretField, VPNKind, parse_uuid, uuid_string};
use macvpn_core::swift_json;
use macvpn_core::vault::{Dek, FixedEntropy, FolderColor, Vault, VaultError};
use std::fs;
use std::path::{Path, PathBuf};
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

fn connection(name: &str) -> Connection {
    Connection::with_id(Uuid::new_v4(), name, VPNKind::Openvpn, Date::parse_iso8601("2026-10-19T08:00:00Z").unwrap())
}

fn count(vault: &Vault, sql: &str, item: &str) -> i64 {
    vault.connection().query_row(sql, [item], |r| r.get(0)).unwrap()
}

/// Marks the database as written by a newer MacVPN and reopens it: read-only.
fn reopen_as_newer(dir: &Path, mut vault: Vault) -> Vault {
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
    let vault = Vault::open(dir, &dek()).unwrap();
    assert!(vault.is_read_only());
    vault
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/swift/decoded/meta")
}

/// The Swift-decoded `meta.json` fixtures that decode (the rest are `INVALID`), with their exact bytes.
fn decodable_fixtures() -> Vec<(String, String, Connection)> {
    let mut out = Vec::new();
    let mut paths: Vec<PathBuf> = fs::read_dir(fixtures()).unwrap().map(|e| e.unwrap().path()).collect();
    paths.sort();
    for path in paths {
        let text = fs::read_to_string(&path).unwrap();
        let Ok(value) = swift_json::parse(text.as_bytes()) else { continue };
        let Ok(c) = Connection::from_json(&value) else { continue };
        out.push((path.file_name().unwrap().to_string_lossy().into_owned(), text, c));
    }
    assert!(out.len() > 10, "too few decodable fixtures: {}", out.len());
    out
}

// --- Connections ------------------------------------------------------------------------------------------------

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn every_swift_fixture_round_trips_with_its_exact_meta_json() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    for (name, text, c) in decodable_fixtures() {
        let config = format!("# config of {name}\nremote vpn.example.com 1194\n");
        vault.save_connection(&c, Some(&config)).unwrap();
        let stored = vault.connections().unwrap();
        let s = stored.iter().find(|s| s.connection.id == c.id).unwrap_or_else(|| panic!("{name} missing"));
        assert_eq!(s.connection, c, "{name}");
        assert_eq!(*vault.config(&c.id).unwrap(), config, "{name}");
        let meta: String = vault
            .connection()
            .query_row("SELECT meta_json FROM connections WHERE id = ?1", [uuid_string(&c.id)], |r| r.get(0))
            .unwrap();
        assert_eq!(meta, text, "{name}: meta_json is the Swift-written meta.json");
        assert_eq!(meta, swift_json::to_pretty_sorted(&c.to_json()).unwrap(), "{name}");
        let kind: String = vault
            .connection()
            .query_row("SELECT kind FROM connections WHERE id = ?1", [uuid_string(&c.id)], |r| r.get(0))
            .unwrap();
        assert_eq!(kind, c.kind.raw_value(), "{name}");
    }
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn connections_survive_a_reopen_and_are_listed_by_name() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    let b = connection("beta");
    let a = connection("Alpha");
    vault.save_connection(&b, Some("b")).unwrap();
    vault.save_connection(&a, Some("a")).unwrap();
    vault.close();
    let vault = Vault::open(&dir, &dek()).unwrap();
    let names: Vec<String> = vault.connections().unwrap().into_iter().map(|s| s.connection.name).collect();
    assert_eq!(names, ["Alpha", "beta"]);
    assert_eq!(*vault.config(&a.id).unwrap(), "a");
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn the_row_columns_are_stored_as_specified() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let c = connection("Office");
    vault.save_connection(&c, Some("remote a 1")).unwrap();
    let (id, config_type): (String, String) = vault
        .connection()
        .query_row("SELECT id, typeof(config) FROM connections", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap();
    assert_eq!(id, uuid_string(&c.id), "the key is the upper-case UUID string, as in the Keychain and ranking");
    assert_eq!(config_type, "blob");
    let s = &vault.connections().unwrap()[0];
    assert_eq!((s.folder_id, s.color, s.position), (None, None, 0));
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn saving_without_a_config_keeps_the_stored_one() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let mut c = connection("Office");
    vault.save_connection(&c, Some("remote office.example.com 1194")).unwrap();
    c.name = "Office (renamed)".into();
    c.acknowledged_risky_directives = vec!["script-security".into()];
    vault.save_connection(&c, None).unwrap();
    assert_eq!(*vault.config(&c.id).unwrap(), "remote office.example.com 1194");
    assert_eq!(vault.connections().unwrap()[0].connection, c);
    // A replacement config replaces it.
    vault.save_connection(&c, Some("remote new.example.com 443")).unwrap();
    assert_eq!(*vault.config(&c.id).unwrap(), "remote new.example.com 443");
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_new_connection_saved_without_a_config_has_an_empty_one() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let c = connection("Native");
    vault.save_connection(&c, None).unwrap();
    assert_eq!(*vault.config(&c.id).unwrap(), "");
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn the_config_of_an_unknown_connection_is_an_error() {
    let tmp = TempDir::new();
    let (_dir, vault) = new_vault(&tmp);
    assert!(vault.config(&Uuid::new_v4()).is_err());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_one_megabyte_inline_block_round_trips() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let line = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3\n";
    let mut config = String::from("client\nremote vpn.example.com 1194\n<ca>\n");
    while config.len() < 1024 * 1024 {
        config.push_str(line);
    }
    config.push_str("</ca>\n");
    let c = connection("Big");
    vault.save_connection(&c, Some(&config)).unwrap();
    assert_eq!(*vault.config(&c.id).unwrap(), config);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn new_connections_are_appended_to_their_folder_and_keep_their_position() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (a, b, c) = (connection("a"), connection("b"), connection("c"));
    vault.save_connection(&a, Some("")).unwrap();
    vault.save_connection(&b, Some("")).unwrap();
    // `b` moves into a folder (Task 9 does this through its own API) with a higher position.
    vault
        .transaction(|tx| {
            tx.execute(
                "INSERT INTO folders(id, name, position) VALUES ('0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9', 'Office', 0)",
                (),
            )?;
            tx.execute(
                "UPDATE connections SET folder_id = '0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9', position = 7 WHERE id = ?1",
                [uuid_string(&b.id)],
            )?;
            Ok(())
        })
        .unwrap();
    vault.save_connection(&c, Some("")).unwrap();
    // Re-saving keeps the placement.
    vault.save_connection(&a, None).unwrap();
    vault.save_connection(&b, None).unwrap();
    let placement = |id: &Uuid| {
        let s = vault.connections().unwrap().into_iter().find(|s| s.connection.id == *id).unwrap();
        (s.folder_id.map(|f| uuid_string(&f)), s.position)
    };
    assert_eq!(placement(&a.id), (None, 0));
    assert_eq!(placement(&c.id), (None, 1), "max + 1 in the root, not across folders");
    assert_eq!(placement(&b.id), (Some("0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9".to_string()), 7));
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn delete_cascades_to_secrets_link_ranking_and_pin() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (gone, kept) = (connection("gone"), connection("kept"));
    vault.save_connection(&gone, Some("x")).unwrap();
    vault.save_connection(&kept, Some("y")).unwrap();
    for c in [&gone, &kept] {
        let key = uuid_string(&c.id);
        vault.set_secret(&key, SecretField::Password, "pw").unwrap();
        vault.set_secret(&key, SecretField::Username, "user").unwrap();
        vault
            .transaction(|tx| {
                let cred = format!("cred-{key}");
                tx.execute(
                    "INSERT INTO credentials(id, name, username, created, updated) VALUES (?1, ?1, 'u', 'd', 'd')",
                    [&cred],
                )?;
                tx.execute("INSERT INTO credential_links(item_id, credential_id) VALUES (?1, ?2)", [&key, &cred])?;
                tx.execute("INSERT INTO ranking(id, json) VALUES (?1, '{}')", [&key])?;
                tx.execute("INSERT INTO pins(id, position) VALUES (?1, 0)", [&key])?;
                Ok(())
            })
            .unwrap();
    }
    vault.delete_connection(&gone.id).unwrap();

    let ids: Vec<Uuid> = vault.connections().unwrap().into_iter().map(|s| s.connection.id).collect();
    assert_eq!(ids, [kept.id]);
    for (c, expected) in [(&gone, 0), (&kept, 1)] {
        let key = uuid_string(&c.id);
        assert_eq!(count(&vault, "SELECT count(*) FROM secrets WHERE connection_id = ?1", &key), expected * 2);
        assert_eq!(count(&vault, "SELECT count(*) FROM credential_links WHERE item_id = ?1", &key), expected);
        assert_eq!(count(&vault, "SELECT count(*) FROM ranking WHERE id = ?1", &key), expected);
        assert_eq!(count(&vault, "SELECT count(*) FROM pins WHERE id = ?1", &key), expected);
    }
    // The shared credential itself stays (it may be used by others).
    assert_eq!(count(&vault, "SELECT count(*) FROM credentials WHERE id LIKE ?1", "cred-%"), 2);
    assert!(vault.config(&gone.id).is_err());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn deleting_an_unknown_connection_is_fine() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    vault.delete_connection(&Uuid::new_v4()).unwrap();
}

// --- Secrets ----------------------------------------------------------------------------------------------------

#[test]
fn secret_fields_have_the_keychain_raw_values() {
    assert_eq!(SecretField::ALL.map(SecretField::raw_value), ["username", "password", "psk", "keypass"]);
    for field in SecretField::ALL {
        assert_eq!(SecretField::from_raw_value(field.raw_value()), Some(field));
    }
    assert_eq!(SecretField::from_raw_value("keyPassword"), None);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn secrets_round_trip_as_blobs() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    let id = uuid_string(&Uuid::new_v4());
    for (field, value) in SecretField::ALL.into_iter().zip(["bob", "s3cret ünïcode", "psk-value", "kp"]) {
        vault.set_secret(&id, field, value).unwrap();
    }
    vault.set_secret(&id, SecretField::Password, "s3cret2").unwrap();
    vault.close();
    let vault = Vault::open(&dir, &dek()).unwrap();
    assert_eq!(vault.secret(&id, SecretField::Username).unwrap().as_deref().map(|s| s.as_str()), Some("bob"));
    assert_eq!(vault.secret(&id, SecretField::Password).unwrap().as_deref().map(|s| s.as_str()), Some("s3cret2"));
    assert_eq!(vault.secret(&id, SecretField::Psk).unwrap().as_deref().map(|s| s.as_str()), Some("psk-value"));
    assert_eq!(vault.secret(&id, SecretField::KeyPassword).unwrap().as_deref().map(|s| s.as_str()), Some("kp"));
    let types: Vec<(String, String)> = {
        let mut stmt = vault.connection().prepare("SELECT field, typeof(value) FROM secrets ORDER BY field").unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
    };
    assert_eq!(
        types,
        [("keypass", "blob"), ("password", "blob"), ("psk", "blob"), ("username", "blob")]
            .map(|(a, b)| (a.to_string(), b.to_string()))
    );
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn an_empty_value_deletes_the_secret() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let id = uuid_string(&Uuid::new_v4());
    vault.set_secret(&id, SecretField::Password, "pw").unwrap();
    vault.set_secret(&id, SecretField::Password, "").unwrap();
    assert!(vault.secret(&id, SecretField::Password).unwrap().is_none());
    assert_eq!(count(&vault, "SELECT count(*) FROM secrets WHERE connection_id = ?1", &id), 0, "no empty row");
    // Deleting a missing secret is fine.
    vault.set_secret(&id, SecretField::Psk, "").unwrap();
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn secrets_keyed_by_a_system_vpn_service_id_work() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let service = "8C7B6A59-4F3E-2D1C-0B9A-887766554433-system";
    vault.set_secret(service, SecretField::Username, "alice").unwrap();
    vault.set_secret(service, SecretField::Password, "pw").unwrap();
    assert_eq!(vault.secret(service, SecretField::Username).unwrap().as_deref().map(|s| s.as_str()), Some("alice"));
    assert!(parse_uuid(service).is_none());
    vault.delete_secrets(service).unwrap();
    assert!(vault.secret(service, SecretField::Username).unwrap().is_none());
    assert!(vault.secret(service, SecretField::Password).unwrap().is_none());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn delete_secrets_only_touches_its_item_and_delete_all_clears_everything() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (a, b) = (uuid_string(&Uuid::new_v4()), "SERVICE-B".to_string());
    vault.set_secret(&a, SecretField::Password, "x").unwrap();
    vault.set_secret(&b, SecretField::Psk, "y").unwrap();
    vault.delete_secrets(&a).unwrap();
    assert!(vault.secret(&a, SecretField::Password).unwrap().is_none());
    assert_eq!(vault.secret(&b, SecretField::Psk).unwrap().as_deref().map(|s| s.as_str()), Some("y"));
    vault.delete_all_secrets().unwrap();
    assert!(vault.secret(&b, SecretField::Psk).unwrap().is_none());
    let total: i64 = vault.connection().query_row("SELECT count(*) FROM secrets", [], |r| r.get(0)).unwrap();
    assert_eq!(total, 0);
}

// --- Colours ----------------------------------------------------------------------------------------------------

#[test]
fn the_colour_palette_round_trips() {
    assert_eq!(FolderColor::ALL.len(), 12);
    let names: Vec<&str> = FolderColor::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(
        names,
        ["red", "orange", "amber", "yellow", "lime", "green", "teal", "cyan", "blue", "indigo", "purple", "pink"]
    );
    for c in FolderColor::ALL {
        assert_eq!(FolderColor::parse(c.as_str()), Some(c));
    }
    assert_eq!(FolderColor::parse("Red"), None);
    assert_eq!(FolderColor::parse(""), None);
    assert_eq!(FolderColor::parse("mauve"), None);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_stored_colour_is_read_and_an_unknown_one_is_none() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let (a, b) = (connection("a"), connection("b"));
    vault.save_connection(&a, Some("")).unwrap();
    vault.save_connection(&b, Some("")).unwrap();
    vault
        .transaction(|tx| {
            tx.execute("UPDATE connections SET color = 'teal' WHERE id = ?1", [uuid_string(&a.id)])?;
            tx.execute("UPDATE connections SET color = 'mauve' WHERE id = ?1", [uuid_string(&b.id)])?;
            Ok(())
        })
        .unwrap();
    // Re-saving keeps the colour.
    vault.save_connection(&a, None).unwrap();
    let stored = vault.connections().unwrap();
    assert_eq!(stored[0].color, Some(FolderColor::Teal));
    assert_eq!(stored[1].color, None, "a colour from a newer version reads as none");
}

// --- Newer database ---------------------------------------------------------------------------------------------

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn every_write_is_refused_on_a_newer_database() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    let c = connection("Office");
    let key = uuid_string(&c.id);
    vault.save_connection(&c, Some("remote a 1")).unwrap();
    vault.set_secret(&key, SecretField::Password, "pw").unwrap();
    let mut vault = reopen_as_newer(&dir, vault);

    // Reads still work.
    assert_eq!(vault.connections().unwrap().len(), 1);
    assert_eq!(*vault.config(&c.id).unwrap(), "remote a 1");
    assert_eq!(vault.secret(&key, SecretField::Password).unwrap().as_deref().map(|s| s.as_str()), Some("pw"));

    let newer =
        |r: Result<(), VaultError>| assert!(matches!(r, Err(VaultError::NewerSchema { db: 99, app: 2 })), "{r:?}");
    newer(vault.save_connection(&c, Some("changed")));
    newer(vault.save_connection(&connection("new"), None));
    newer(vault.delete_connection(&c.id));
    newer(vault.set_secret(&key, SecretField::Password, "other"));
    newer(vault.set_secret(&key, SecretField::Password, ""));
    newer(vault.delete_secrets(&key));
    newer(vault.delete_all_secrets());
    assert_eq!(*vault.config(&c.id).unwrap(), "remote a 1");
    assert_eq!(vault.secret(&key, SecretField::Password).unwrap().as_deref().map(|s| s.as_str()), Some("pw"));
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn debug_output_of_a_stored_connection_has_no_config() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let c = connection("Office");
    vault.save_connection(&c, Some("remote canary-config.example.com 1194")).unwrap();
    let debug = format!("{:?}", vault.connections().unwrap());
    assert!(debug.contains("Office") && !debug.contains("canary-config"), "{debug}");
}

// --- One transaction for many writes, raw records and counts (plan B Task 13: the migration) --------------------

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn writes_through_one_transaction_commit_together_or_not_at_all() {
    use macvpn_core::ranking::ConnectionRanking;
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    assert!(vault.is_empty().unwrap());
    let a = connection("A");
    let key = uuid_string(&a.id);

    // A failure at the end rolls back every write made before it.
    let result: Result<(), VaultError> = vault.transaction(|tx| {
        tx.save_connection(&a, Some("remote a\n"))?;
        tx.set_secret(&key, SecretField::Password, "pw")?;
        tx.save_ranking(&ConnectionRanking::new(vec![key.clone()], Default::default()))?;
        tx.save_control_clients(&[serde_json::json!({ "id": "c1" })])?;
        Err(VaultError::Constraint("injected".into()))
    });
    assert!(result.is_err());
    assert!(vault.is_empty().unwrap());
    assert_eq!(vault.connection_count().unwrap(), 0);

    vault
        .transaction(|tx| {
            tx.save_connection(&a, Some("remote a\n"))?;
            tx.set_secret(&key, SecretField::Password, "pw")?;
            tx.set_secret(&key, SecretField::Username, "")?;
            Ok(())
        })
        .unwrap();
    assert!(!vault.is_empty().unwrap());
    assert_eq!(vault.connection_count().unwrap(), 1);
    assert_eq!(vault.secret_count().unwrap(), 1);
    assert_eq!(vault.secret(&key, SecretField::Password).unwrap().as_deref().map(String::as_str), Some("pw"));
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn the_raw_record_is_the_stored_meta_json_and_config_bytes() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let a = connection("A");
    let config = "\u{FEFF}remote a\r\n";
    vault.save_connection(&a, Some(config)).unwrap();
    let (meta, bytes) = vault.connection_record(&a.id).unwrap().unwrap();
    assert_eq!(meta, swift_json::to_pretty_sorted(&a.to_json()).unwrap());
    assert_eq!(&bytes[..], config.as_bytes());
    assert!(vault.connection_record(&Uuid::new_v4()).unwrap().is_none());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn is_empty_sees_every_table() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    assert!(vault.is_empty().unwrap());
    vault.set_secret("SERVICE-ID", SecretField::Psk, "x").unwrap();
    assert!(!vault.is_empty().unwrap());
    vault.delete_all_secrets().unwrap();
    assert!(vault.is_empty().unwrap());
    vault.save_control_clients(&[serde_json::json!({ "id": "c1" })]).unwrap();
    assert!(!vault.is_empty().unwrap());
}
