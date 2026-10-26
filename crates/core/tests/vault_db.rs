//! The encrypted vault database (spec 2.1 and 2.4, plan B Task 6): SQLCipher with a raw key, the open sequence,
//! file modes, schema v1 and the migration runner.

mod common;

use common::TempDir;
#[cfg(unix)]
use common::mode;
use macvpn_core::vault::{CURRENT_SCHEMA, Dek, FixedEntropy, Migration, VAULT_FILE, Vault, VaultError};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

const CANARY_NAME: &str = "GrepCanaryName";
const CANARY_CONFIG: &str = "remote canary.example.com 1194";

fn dek(seed: u64) -> Dek {
    Dek::generate(&FixedEntropy::new(seed)).unwrap()
}

/// `<tmp>/MacVPN`, not created yet.
fn vault_dir(tmp: &TempDir) -> PathBuf {
    tmp.path().join("MacVPN")
}

fn new_vault(tmp: &TempDir) -> (PathBuf, Vault) {
    fs::create_dir_all(tmp.path()).unwrap();
    let dir = vault_dir(tmp);
    let vault = Vault::create(&dir, &dek(1)).unwrap();
    (dir, vault)
}

fn pragma_i64(vault: &Vault, name: &str) -> i64 {
    vault.connection().query_row(&format!("PRAGMA {name}"), [], |r| r.get(0)).unwrap()
}

fn pragma_text(vault: &Vault, name: &str) -> String {
    vault.connection().query_row(&format!("PRAGMA {name}"), [], |r| r.get(0)).unwrap()
}

fn tables(vault: &Vault) -> Vec<String> {
    let mut stmt =
        vault.connection().prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").unwrap();
    stmt.query_map([], |r| r.get::<_, String>(0)).unwrap().map(Result::unwrap).collect()
}

fn columns(vault: &Vault, table: &str) -> Vec<String> {
    let mut stmt = vault.connection().prepare(&format!("PRAGMA table_info({table})")).unwrap();
    stmt.query_map([], |r| r.get::<_, String>(1)).unwrap().map(Result::unwrap).collect()
}

fn insert_canary(vault: &mut Vault) {
    vault
        .transaction(|tx| {
            tx.execute(
                "INSERT INTO connections(id, kind, meta_json, config, position) VALUES (?1, 'openvpn', ?2, ?3, 0)",
                ("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", format!("{{\"name\":\"{CANARY_NAME}\"}}"), CANARY_CONFIG),
            )?;
            Ok(())
        })
        .unwrap();
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn assert_no_plaintext(path: &Path) {
    let Ok(bytes) = fs::read(path) else { return };
    for needle in [CANARY_NAME.as_bytes(), CANARY_CONFIG.as_bytes(), b"SQLite format 3", b"CREATE TABLE"] {
        assert!(!contains(&bytes, needle), "{} contains {:?}", path.display(), String::from_utf8_lossy(needle));
    }
}

fn sidecar(dir: &Path, suffix: &str) -> PathBuf {
    dir.join(format!("{VAULT_FILE}{suffix}"))
}

// --- Create and open --------------------------------------------------------------------------------------------

#[test]
fn create_then_open_with_the_same_key() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    insert_canary(&mut vault);
    vault.close();
    let vault = Vault::open(&dir, &dek(1)).unwrap();
    let name: String = vault.connection().query_row("SELECT meta_json FROM connections", [], |r| r.get(0)).unwrap();
    assert!(name.contains(CANARY_NAME));
}

/// A vault far larger than Windows' default working-set quota: SQLCipher's memory security locks every allocation,
/// `VirtualLock` starts failing after a few dozen pages, and the warning it logs to stderr by default allocated and
/// failed again until the stack overflowed (every vault write crashed the process on Windows). The memory security
/// stays on.
#[test]
fn a_large_vault_is_written_and_read_with_memory_security_on() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    assert_eq!(pragma_text(&vault, "cipher_memory_security"), "1");
    let config = "x".repeat(16 * 1024);
    vault
        .transaction(|tx| {
            for i in 0..256 {
                tx.execute(
                    "INSERT INTO connections(id, kind, meta_json, config, position) VALUES (?1, 'openvpn', '{}', ?2, ?3)",
                    (format!("id-{i}"), config.as_str(), i),
                )?;
            }
            Ok(())
        })
        .unwrap();
    vault.close();
    let vault = Vault::open(&dir, &dek(1)).unwrap();
    assert_eq!(pragma_text(&vault, "cipher_memory_security"), "1");
    let total: i64 =
        vault.connection().query_row("SELECT sum(length(config)) FROM connections", [], |r| r.get(0)).unwrap();
    assert_eq!(total, 256 * 16 * 1024);
}

#[test]
fn a_different_key_is_wrong_key() {
    let tmp = TempDir::new();
    let (dir, vault) = new_vault(&tmp);
    vault.close();
    assert!(matches!(Vault::open(&dir, &dek(2)), Err(VaultError::WrongKey)));
    // The right key still works afterwards (the failed open changed nothing).
    Vault::open(&dir, &dek(1)).unwrap();
}

#[test]
fn create_refuses_an_existing_vault_and_open_a_missing_one() {
    let tmp = TempDir::new();
    let (dir, vault) = new_vault(&tmp);
    vault.close();
    assert!(
        matches!(Vault::create(&dir, &dek(1)), Err(VaultError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists)
    );
    let other = TempDir::new();
    fs::create_dir_all(other.path()).unwrap();
    assert!(matches!(Vault::open(other.path(), &dek(1)), Err(VaultError::Io(_))));
}

// --- Modes and the directory ------------------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn directory_and_file_modes() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    insert_canary(&mut vault);
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&dir.join(VAULT_FILE)), 0o600);
    for suffix in ["-wal", "-shm"] {
        let path = sidecar(&dir, suffix);
        assert!(path.exists(), "{} (WAL mode)", path.display());
        assert_eq!(mode(&path), 0o600, "{}", path.display());
    }
}

#[cfg(unix)]
#[test]
fn an_existing_directory_is_tightened_to_0700() {
    let tmp = TempDir::new();
    let dir = vault_dir(&tmp);
    fs::DirBuilder::new().recursive(true).mode(0o755).create(&dir).unwrap();
    Vault::create(&dir, &dek(1)).unwrap().close();
    assert_eq!(mode(&dir), 0o700);
}

#[cfg(unix)]
#[test]
fn a_symlinked_directory_is_refused() {
    let tmp = TempDir::new();
    let real = tmp.path().join("real");
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&real).unwrap();
    let link = tmp.path().join("MacVPN");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(matches!(Vault::create(&link, &dek(1)), Err(VaultError::Io(_))));
    assert!(!real.join(VAULT_FILE).exists());

    // A vault behind a symlinked directory is not opened either.
    Vault::create(&real, &dek(1)).unwrap().close();
    assert!(matches!(Vault::open(&link, &dek(1)), Err(VaultError::Io(_))));
}

#[cfg(unix)]
#[test]
fn open_refuses_a_file_that_is_not_0600_or_a_symlink() {
    let tmp = TempDir::new();
    let (dir, vault) = new_vault(&tmp);
    vault.close();
    let file = dir.join(VAULT_FILE);
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(Vault::open(&dir, &dek(1)), Err(VaultError::Io(_))));
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    Vault::open(&dir, &dek(1)).unwrap().close();

    let moved = tmp.path().join("elsewhere.db");
    fs::rename(&file, &moved).unwrap();
    std::os::unix::fs::symlink(&moved, &file).unwrap();
    assert!(matches!(Vault::open(&dir, &dek(1)), Err(VaultError::Io(_))));
}

#[test]
fn no_stray_files_are_left_in_the_directory() {
    let tmp = TempDir::new();
    let (dir, vault) = new_vault(&tmp);
    vault.close();
    Vault::open(&dir, &dek(1)).unwrap().close();
    let names: Vec<String> =
        fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    assert_eq!(names, vec![VAULT_FILE.to_string()], "after a clean close only vault.db remains");
}

// --- No plaintext -----------------------------------------------------------------------------------------------

#[test]
fn the_files_contain_no_plaintext() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    insert_canary(&mut vault);
    // While open: the main file, the WAL (not checkpointed yet) and the shared memory file.
    for suffix in ["", "-wal", "-shm"] {
        assert_no_plaintext(&sidecar(&dir, suffix));
    }
    vault.close();
    for suffix in ["", "-wal", "-shm"] {
        assert_no_plaintext(&sidecar(&dir, suffix));
    }
}

/// The scan does find plaintext when it is there (a plain SQLite file with the same rows).
#[test]
fn the_plaintext_scan_detects_a_plain_database() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    // A canonical path (SQLite refuses symlinks such as /var in it) and an existing file (no SQLITE_OPEN_CREATE).
    let path = tmp.path().canonicalize().unwrap().join("plain.db");
    fs::write(&path, b"").unwrap();
    let (_, mut vault) = new_vault(&tmp);
    insert_canary(&mut vault);
    vault.connection().execute("ATTACH DATABASE ?1 AS plain KEY ''", [path.to_str().unwrap()]).unwrap();
    vault.connection().execute_batch("SELECT sqlcipher_export('plain'); DETACH DATABASE plain;").unwrap();
    vault.close();
    let bytes = fs::read(&path).unwrap();
    assert!(contains(&bytes, CANARY_NAME.as_bytes()));
    assert!(contains(&bytes, b"SQLite format 3"));
}

// --- Pragmas ------------------------------------------------------------------------------------------------------

#[test]
fn pragmas_of_the_open_sequence() {
    let tmp = TempDir::new();
    let (dir, vault) = new_vault(&tmp);
    let check = |vault: &Vault| {
        assert_eq!(pragma_i64(vault, "foreign_keys"), 1);
        assert_eq!(pragma_i64(vault, "secure_delete"), 1);
        assert_eq!(pragma_text(vault, "journal_mode"), "wal");
        assert_eq!(pragma_i64(vault, "temp_store"), 2, "MEMORY");
        assert_eq!(pragma_text(vault, "integrity_check"), "ok");
    };
    check(&vault);
    vault.close();
    let vault = Vault::open(&dir, &dek(1)).unwrap();
    check(&vault);
}

/// Catches an OpenSSL-linked SQLCipher in `cargo test` already (spike report A.1 and A.5).
#[cfg(target_os = "macos")]
#[test]
fn sqlcipher_uses_commoncrypto() {
    let tmp = TempDir::new();
    let (_, vault) = new_vault(&tmp);
    assert_eq!(pragma_text(&vault, "cipher_provider"), "commoncrypto");
    assert!(pragma_text(&vault, "cipher_version").starts_with("4."));
}

#[test]
fn foreign_keys_are_enforced() {
    let tmp = TempDir::new();
    let (_, mut vault) = new_vault(&tmp);
    let result = vault.transaction(|tx| {
        tx.execute("INSERT INTO credential_links(item_id, credential_id) VALUES ('x', 'missing')", ())?;
        Ok(())
    });
    assert!(matches!(result, Err(VaultError::Constraint(_))), "{result:?}");
}

#[test]
fn a_failed_transaction_rolls_back() {
    let tmp = TempDir::new();
    let (_, mut vault) = new_vault(&tmp);
    let result: Result<(), VaultError> = vault.transaction(|tx| {
        tx.execute("INSERT INTO pins(id, position) VALUES ('a', 0)", ())?;
        Err(VaultError::Corrupt("test".into()))
    });
    assert!(matches!(result, Err(VaultError::Corrupt(_))));
    let n: i64 = vault.connection().query_row("SELECT count(*) FROM pins", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 0);
}

// --- Schema ---------------------------------------------------------------------------------------------------

#[test]
fn schema_v2_has_the_spec_tables_and_columns() {
    let tmp = TempDir::new();
    let (_, vault) = new_vault(&tmp);
    assert_eq!(CURRENT_SCHEMA, 2);
    assert_eq!(Vault::migrations().iter().map(|m| m.version).max(), Some(CURRENT_SCHEMA));
    assert_eq!(
        tables(&vault),
        [
            "catalog_admin_keys",
            "catalog_items",
            "catalog_publications",
            "catalog_slots",
            "catalog_subscriptions",
            "connections",
            "control_clients",
            "credential_links",
            "credentials",
            "folders",
            "meta",
            "pins",
            "ranking",
            "secrets",
            "system_items",
            "system_otp",
        ]
    );
    let expect = |table: &str, cols: &[&str]| assert_eq!(columns(&vault, table), cols, "{table}");
    expect("meta", &["key", "value"]);
    expect("folders", &["id", "parent_id", "name", "color", "position", "collapsed"]);
    expect("connections", &["id", "kind", "meta_json", "config", "folder_id", "color", "position"]);
    expect("secrets", &["connection_id", "field", "value"]);
    expect("credentials", &["id", "name", "username", "password", "created", "updated"]);
    expect("credential_links", &["item_id", "credential_id"]);
    expect("system_items", &["service_id", "folder_id", "color", "position", "missing_since"]);
    expect("system_otp", &["service_id", "json"]);
    expect("ranking", &["id", "json"]);
    expect("pins", &["id", "position"]);
    expect("control_clients", &["id", "json"]);
    expect("catalog_subscriptions", &["catalog_id", "json", "team_key", "bearer", "publisher_key", "successor_key"]);
    expect(
        "catalog_items",
        &[
            "local_id",
            "catalog_id",
            "item_id",
            "kind",
            "color",
            "slot_id",
            "provided_secrets",
            "config_hash",
            "meta_hash",
            "pending_removal",
            "profile_outdated",
        ],
    );
    expect("catalog_slots", &["catalog_id", "slot_id", "name", "credential_id"]);
    expect("catalog_admin_keys", &["key_id", "role", "seed", "created"]);
    expect("catalog_publications", &["catalog_id", "json", "team_key"]);
}

#[test]
fn meta_rows() {
    let tmp = TempDir::new();
    let (_, vault) = new_vault(&tmp);
    let get = |key: &str| -> String {
        vault.connection().query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).unwrap()
    };
    assert_eq!(get("schema_version"), "2");
    // Schema v2 is additive: a 1.2 build (schema 1) may still write it.
    assert_eq!(get("min_app_schema"), "1");
    assert!(macvpn_core::date::Date::parse_iso8601(&get("created")).is_some(), "{}", get("created"));
}

#[test]
fn schema_cascades_and_restrictions() {
    let tmp = TempDir::new();
    let (_, mut vault) = new_vault(&tmp);
    vault
        .transaction(|tx| {
            tx.execute_batch(
                "INSERT INTO folders(id, parent_id, name, position) VALUES ('p', NULL, 'Parent', 0);
                 INSERT INTO folders(id, parent_id, name, position) VALUES ('c', 'p', 'Child', 0);
                 INSERT INTO connections(id, kind, meta_json, config, folder_id, position)
                     VALUES ('k', 'wireguard', '{}', x'00', 'c', 0);
                 INSERT INTO credentials(id, name, username, created, updated) VALUES ('cr', 'Office AD', 'u', 'x', 'x');
                 INSERT INTO credential_links(item_id, credential_id) VALUES ('k', 'cr');
                 DELETE FROM folders WHERE id = 'p';",
            )?;
            Ok(())
        })
        .unwrap();
    let c = vault.connection();
    let folders: i64 = c.query_row("SELECT count(*) FROM folders", [], |r| r.get(0)).unwrap();
    assert_eq!(folders, 0, "ON DELETE CASCADE removes the subfolder");
    let folder: Option<String> = c.query_row("SELECT folder_id FROM connections", [], |r| r.get(0)).unwrap();
    assert_eq!(folder, None, "ON DELETE SET NULL moves the connection to the root");
    let r = vault.transaction(|tx| {
        tx.execute("DELETE FROM credentials WHERE id = 'cr'", ())?;
        Ok(())
    });
    assert!(matches!(r, Err(VaultError::Constraint(_))), "ON DELETE RESTRICT");
    let r = vault.transaction(|tx| {
        tx.execute(
            "INSERT INTO credentials(id, name, username, created, updated) VALUES ('2', 'Office AD', 'v', 'x', 'x')",
            (),
        )?;
        Ok(())
    });
    assert!(matches!(r, Err(VaultError::Constraint(_))), "credentials.name is UNIQUE");
}

// --- Schema versioning and migrations ----------------------------------------------------------------------

const TEST_V2: Migration =
    Migration { version: 2, min_app_schema: 2, statements: &["CREATE TABLE test_v2(x INTEGER)"] };
const TEST_V3: Migration =
    Migration { version: 3, min_app_schema: 3, statements: &["CREATE TABLE test_v3(x INTEGER)"] };
const TEST_V4: Migration =
    Migration { version: 4, min_app_schema: 4, statements: &["CREATE TABLE test_v4(x INTEGER)"] };

/// The runner tests start from a schema-v1 database (a 1.2 vault) and add their own steps 2, 3, 4 (in place of
/// this build's real v2).
fn v1() -> Vec<Migration> {
    Vault::migrations()[..1].to_vec()
}

fn new_v1_vault(tmp: &TempDir) -> (PathBuf, Vault) {
    fs::create_dir_all(tmp.path()).unwrap();
    let dir = vault_dir(tmp);
    let vault = Vault::create_with_migrations(&dir, &dek(1), &v1()).unwrap();
    (dir, vault)
}

fn with(extra: &[Migration]) -> Vec<Migration> {
    let mut m = v1();
    m.extend_from_slice(extra);
    m
}

fn meta(vault: &Vault, key: &str) -> String {
    vault.connection().query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).unwrap()
}

fn backups(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("vault.db.bak-v"))
        .collect();
    names.sort();
    names
}

fn row_count(vault: &Vault, table: &str) -> i64 {
    vault.connection().query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0)).unwrap()
}

/// Opens a copy of a backup file (it is the still-encrypted v<old> database) and returns its schema version.
fn backup_version(dir: &Path, name: &str) -> String {
    let copy = TempDir::new();
    #[cfg(unix)]
    {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(copy.path()).unwrap();
        fs::copy(dir.join(name), copy.path().join(VAULT_FILE)).unwrap();
    }
    // A copied file gets the folder's inherited ACL on Windows (the vault refuses that): write it private, as the
    // backup itself is.
    #[cfg(not(unix))]
    {
        fs::create_dir_all(copy.path()).unwrap();
        let bytes = fs::read(dir.join(name)).unwrap();
        macvpn_core::fsx::atomic_write(&copy.path().join(VAULT_FILE), &bytes, macvpn_core::fsx::Access::Private)
            .unwrap();
    }
    let vault = Vault::open_with_migrations(copy.path(), &dek(1), &[]).unwrap_or_else(|e| panic!("{e}"));
    meta(&vault, "schema_version")
}

#[cfg(unix)]
#[test]
fn an_older_database_is_backed_up_and_migrated() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_v1_vault(&tmp);
    insert_canary(&mut vault);
    vault.close();
    let migrations = with(&[TEST_V2]);
    let vault = Vault::open_with_migrations(&dir, &dek(1), &migrations).unwrap();
    assert!(!vault.is_read_only());
    assert_eq!(vault.schema_version(), 2);
    assert!(tables(&vault).contains(&"test_v2".to_string()));
    assert_eq!(meta(&vault, "schema_version"), "2");
    assert_eq!(meta(&vault, "min_app_schema"), "2");
    assert_eq!(row_count(&vault, "connections"), 1, "the data survives");
    vault.close();

    // The backup is a byte copy of the encrypted v1 file: 0600, no plaintext, still opens as v1.
    assert_eq!(backups(&dir), ["vault.db.bak-v1"]);
    let backup = dir.join("vault.db.bak-v1");
    assert_eq!(mode(&backup), 0o600);
    assert_no_plaintext(&backup);
    assert_eq!(backup_version(&dir, "vault.db.bak-v1"), "1");

    // A second open does not migrate (or back up) again.
    Vault::open_with_migrations(&dir, &dek(1), &migrations).unwrap().close();
    assert_eq!(backups(&dir), ["vault.db.bak-v1"]);
}

#[test]
fn several_steps_run_in_order_in_one_atomic_migration() {
    let tmp = TempDir::new();
    let (dir, vault) = new_v1_vault(&tmp);
    vault.close();
    let vault = Vault::open_with_migrations(&dir, &dek(1), &with(&[TEST_V2, TEST_V3])).unwrap();
    assert_eq!(meta(&vault, "schema_version"), "3");
    assert!(tables(&vault).contains(&"test_v2".to_string()) && tables(&vault).contains(&"test_v3".to_string()));
    vault.close();
    assert_eq!(backups(&dir), ["vault.db.bak-v1"]);
}

#[test]
fn a_failing_step_leaves_the_old_version_and_the_backup() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_v1_vault(&tmp);
    insert_canary(&mut vault);
    vault.close();
    // Step 2 succeeds, step 3 fails: nothing of step 2 may stay either.
    let broken = Migration { version: 3, min_app_schema: 3, statements: &["CREATE TABLE half(x)", "THIS IS NOT SQL"] };
    let err = Vault::open_with_migrations(&dir, &dek(1), &with(&[TEST_V2, broken])).unwrap_err();
    assert!(matches!(err, VaultError::MigrationFailed { from: 1, to: 3, .. }), "{err:?}");
    assert!(err.to_string().contains("1") && err.to_string().contains("3"), "{err}");
    assert_eq!(backups(&dir), ["vault.db.bak-v1"]);

    let vault = Vault::open_with_migrations(&dir, &dek(1), &v1()).unwrap();
    assert_eq!(meta(&vault, "schema_version"), "1");
    let t = tables(&vault);
    assert!(!t.contains(&"test_v2".to_string()) && !t.contains(&"half".to_string()), "{t:?}");
    assert_eq!(row_count(&vault, "connections"), 1);
    assert_eq!(pragma_text(&vault, "integrity_check"), "ok");
}

#[test]
fn backup_rotation_keeps_the_last_two() {
    let tmp = TempDir::new();
    let (dir, vault) = new_v1_vault(&tmp);
    vault.close();
    Vault::open_with_migrations(&dir, &dek(1), &with(&[TEST_V2])).unwrap().close();
    Vault::open_with_migrations(&dir, &dek(1), &with(&[TEST_V2, TEST_V3])).unwrap().close();
    assert_eq!(backups(&dir), ["vault.db.bak-v1", "vault.db.bak-v2"]);
    Vault::open_with_migrations(&dir, &dek(1), &with(&[TEST_V2, TEST_V3, TEST_V4])).unwrap().close();
    assert_eq!(backups(&dir), ["vault.db.bak-v2", "vault.db.bak-v3"]);
    assert_eq!(backup_version(&dir, "vault.db.bak-v3"), "3");
}

/// The database written by a newer MacVPN: readable, but this build must not write to it.
#[test]
fn a_newer_database_opens_read_only_and_refuses_every_write() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_v1_vault(&tmp);
    insert_canary(&mut vault);
    vault.close();
    // A newer MacVPN migrated it to v2 (an additive change).
    Vault::open_with_migrations(&dir, &dek(1), &with(&[TEST_V2])).unwrap().close();
    let before = fs::read(dir.join(VAULT_FILE)).unwrap();

    let mut vault = Vault::open_with_migrations(&dir, &dek(1), &v1()).unwrap();
    assert!(vault.is_read_only());
    assert_eq!(vault.schema_version(), 2);
    // Reading works.
    assert_eq!(row_count(&vault, "connections"), 1);
    // The write API is refused with the typed error.
    let r = vault.transaction(|tx| {
        tx.execute("INSERT INTO pins(id, position) VALUES ('a', 0)", ())?;
        Ok(())
    });
    assert!(matches!(r, Err(VaultError::NewerSchema { db: 2, app: 1 })), "{r:?}");
    assert!(r.unwrap_err().to_string().contains("newer MacVPN"));
    // Even the raw connection cannot write (SQLITE_OPEN_READONLY + query_only).
    assert!(vault.connection().execute("INSERT INTO pins(id, position) VALUES ('b', 0)", ()).is_err());
    assert_eq!(pragma_i64(&vault, "query_only"), 1);
    vault.close();

    assert_eq!(fs::read(dir.join(VAULT_FILE)).unwrap(), before, "the file is untouched");
    assert_eq!(backups(&dir), ["vault.db.bak-v1"], "no backup or migration attempt");
    // The newer build still opens it normally.
    let vault = Vault::open_with_migrations(&dir, &dek(1), &with(&[TEST_V2])).unwrap();
    assert!(!vault.is_read_only());
}

#[test]
fn a_much_newer_but_readable_database_is_read_only() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
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
    let mut vault = Vault::open(&dir, &dek(1)).unwrap();
    assert!(vault.is_read_only());
    assert!(matches!(vault.transaction(|_| Ok(())), Err(VaultError::NewerSchema { db: 99, app: 2 })));
}

#[test]
fn an_unreadable_newer_database_is_refused() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    vault
        .transaction(|tx| {
            tx.execute_batch(
                "UPDATE meta SET value = '99' WHERE key = 'schema_version';
                 ALTER TABLE connections RENAME COLUMN meta_json TO meta_v99;",
            )?;
            Ok(())
        })
        .unwrap();
    vault.close();
    let r = Vault::open(&dir, &dek(1));
    assert!(matches!(r, Err(VaultError::NewerSchema { db: 99, app: 2 })), "{r:?}");
}

#[test]
fn a_missing_schema_version_is_corrupt() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    vault
        .transaction(|tx| {
            tx.execute("DELETE FROM meta WHERE key = 'schema_version'", ())?;
            Ok(())
        })
        .unwrap();
    vault.close();
    assert!(matches!(Vault::open(&dir, &dek(1)), Err(VaultError::Corrupt(_))));
}

// --- Crash in the middle of a transaction ---------------------------------------------------------------------

const CRASH_ENV: &str = "MACVPN_VAULT_TEST_CRASH_DIR";

/// The child half of `a_crash_mid_transaction_leaves_a_consistent_database`: does nothing unless started by it.
#[test]
fn crash_child() {
    let Some(dir) = std::env::var_os(CRASH_ENV) else { return };
    let mut vault = Vault::open(Path::new(&dir), &dek(1)).unwrap();
    let _: Result<(), VaultError> = vault.transaction(|tx| {
        for i in 0..1000 {
            tx.execute("INSERT INTO pins(id, position) VALUES (?1, ?2)", (format!("crash-{i}"), i))?;
        }
        std::process::abort();
    });
}

#[test]
fn a_crash_mid_transaction_leaves_a_consistent_database() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    insert_canary(&mut vault);
    vault.close();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_child", "--test-threads=1", "--nocapture"])
        .env(CRASH_ENV, &dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success(), "the child must have aborted");
    let vault = Vault::open(&dir, &dek(1)).unwrap();
    assert_eq!(pragma_text(&vault, "integrity_check"), "ok");
    let mut stmt = vault.connection().prepare("PRAGMA cipher_integrity_check").unwrap();
    let problems: Vec<String> = stmt.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    assert!(problems.is_empty(), "{problems:?}");
    let pins: i64 = vault.connection().query_row("SELECT count(*) FROM pins", [], |r| r.get(0)).unwrap();
    assert_eq!(pins, 0, "nothing of the aborted transaction");
    let n: i64 = vault.connection().query_row("SELECT count(*) FROM connections", [], |r| r.get(0)).unwrap();
    assert_eq!(n, 1, "the committed row survived");
}

// --- Opening a newer database must not write to it (security review M3) --------------------------------------

const HOT_WAL_ENV: &str = "MACVPN_VAULT_TEST_HOT_WAL_DIR";

/// The child half of `opening_a_newer_database_with_a_hot_wal_leaves_the_main_file_unchanged`: a v2 build commits
/// rows that stay in the WAL (no automatic checkpoint) and dies before it could checkpoint on close.
#[test]
fn hot_wal_child() {
    let Some(dir) = std::env::var_os(HOT_WAL_ENV) else { return };
    let mut vault = Vault::open_with_migrations(Path::new(&dir), &dek(1), &with(&[TEST_V2])).unwrap();
    vault.connection().execute_batch("PRAGMA wal_autocheckpoint = 0;").unwrap();
    vault
        .transaction(|tx| {
            for i in 0..50 {
                tx.execute("INSERT INTO pins(id, position) VALUES (?1, ?2)", (format!("hot-{i}"), i))?;
            }
            Ok(())
        })
        .unwrap();
    std::process::abort();
}

#[test]
fn opening_a_newer_database_with_a_hot_wal_leaves_the_main_file_unchanged() {
    let tmp = TempDir::new();
    let (dir, vault) = new_v1_vault(&tmp);
    vault.close();
    // A newer MacVPN migrated it to v2 and left committed rows in a hot WAL.
    Vault::open_with_migrations(&dir, &dek(1), &with(&[TEST_V2])).unwrap().close();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "hot_wal_child", "--test-threads=1", "--nocapture"])
        .env(HOT_WAL_ENV, &dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success(), "the child must have aborted");
    let wal = sidecar(&dir, "-wal");
    assert!(fs::metadata(&wal).map(|m| m.len() > 0).unwrap_or(false), "a hot WAL is left behind");
    let main_before = fs::read(dir.join(VAULT_FILE)).unwrap();

    // This (v1) build opens it read-only, sees the committed rows, and closes it.
    let vault = Vault::open_with_migrations(&dir, &dek(1), &v1()).unwrap();
    assert!(vault.is_read_only());
    assert_eq!(row_count(&vault, "pins"), 50);
    vault.close();

    assert!(fs::read(dir.join(VAULT_FILE)).unwrap() == main_before, "no checkpoint into the main file");
    // The newer build still finds its rows.
    let vault = Vault::open_with_migrations(&dir, &dek(1), &with(&[TEST_V2])).unwrap();
    assert_eq!(row_count(&vault, "pins"), 50);
}

// --- Raw key and page authentication (security review L6) -------------------------------------------------------

/// Closes the vault and returns a copy of its file at a canonical path (SQLite refuses symlinks such as /var).
fn copy_of_vault(tmp: &TempDir, dir: &Path) -> PathBuf {
    let copy = tmp.path().canonicalize().unwrap().join("copy.db");
    fs::copy(dir.join(VAULT_FILE), &copy).unwrap();
    copy
}

fn attach_works(vault: &Vault, path: &Path, key: &str) -> bool {
    let c = vault.connection();
    if c.execute("ATTACH DATABASE ?1 AS other KEY ?2", [path.to_str().unwrap(), key]).is_err() {
        return false;
    }
    let ok = c.query_row("SELECT count(*) FROM other.sqlite_master", [], |r| r.get::<_, i64>(0)).is_ok();
    c.execute_batch("DETACH DATABASE other").unwrap();
    ok
}

/// The DEK is a raw key (`x'…'`), not a passphrase run through SQLCipher's PBKDF2: the same hex text as a
/// passphrase does not open the file.
#[test]
fn the_dek_is_used_as_a_raw_key() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    insert_canary(&mut vault);
    vault.close();
    let copy = copy_of_vault(&tmp, &dir);
    let other = TempDir::new();
    let (_, probe) = new_vault(&other);
    let hex = dek(1).hex();
    assert!(attach_works(&probe, &copy, &format!("x'{}'", hex.as_str())), "the raw key opens it");
    assert!(!attach_works(&probe, &copy, hex.as_str()), "the hex as a passphrase must not");
    assert!(!attach_works(&probe, &copy, &format!("x'{}'", dek(2).hex().as_str())));
}

/// A flipped byte in page 2 is caught by the per-page HMAC.
#[test]
fn a_tampered_page_is_detected() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    insert_canary(&mut vault);
    vault.close();
    let path = dir.join(VAULT_FILE);
    let mut bytes = fs::read(&path).unwrap();
    assert!(bytes.len() >= 3 * 4096, "{} bytes", bytes.len());
    bytes[4096 + 200] ^= 0x01;
    fs::write(&path, &bytes).unwrap();
    let detected = match Vault::open(&dir, &dek(1)) {
        Err(_) => true,
        Ok(vault) => {
            let c = vault.connection();
            let mut stmt = c.prepare("PRAGMA cipher_integrity_check").unwrap();
            let problems: Vec<String> = stmt.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
            let full_read = ["connections", "folders", "secrets", "pins", "meta"]
                .iter()
                .all(|t| c.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get::<_, i64>(0)).is_ok());
            !problems.is_empty() || !full_read
        }
    };
    assert!(detected);
}

// --- Debug ------------------------------------------------------------------------------------------------------

#[test]
fn debug_and_errors_show_no_key() {
    let tmp = TempDir::new();
    let (dir, vault) = new_vault(&tmp);
    let hex = dek(1).hex();
    let text = format!("{vault:?}");
    assert!(!text.contains(&hex[..8]), "{text}");
    vault.close();
    let err = Vault::open(&dir, &dek(2)).unwrap_err();
    let text = format!("{err:?} {err}");
    assert!(!text.contains(&dek(2).hex()[..8]), "{text}");
}

// --- Schema v2 (1.3, team catalogs) ------------------------------------------------------------------------------

/// A 1.2 vault (schema v1) with data is backed up and migrated to v2: the catalog tables appear, the data stays,
/// and `min_app_schema` stays 1.
#[test]
fn migration_v1_to_v2_keeps_the_data_and_min_app_schema_1() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_v1_vault(&tmp);
    insert_canary(&mut vault);
    vault
        .transaction(|tx| {
            tx.execute_batch(
                "INSERT INTO folders(id, parent_id, name, position) VALUES ('F', NULL, 'Office', 0);
                 INSERT INTO credentials(id, name, username, created, updated) VALUES ('C', 'Office AD', 'u', 'x', 'x');
                 INSERT INTO pins(id, position) VALUES ('P', 0);",
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(vault.schema_version(), 1);
    vault.close();

    let vault = Vault::open(&dir, &dek(1)).unwrap();
    assert!(!vault.is_read_only());
    assert_eq!(vault.schema_version(), 2);
    assert_eq!(meta(&vault, "schema_version"), "2");
    assert_eq!(meta(&vault, "min_app_schema"), "1");
    let t = tables(&vault);
    for table in
        ["catalog_subscriptions", "catalog_items", "catalog_slots", "catalog_admin_keys", "catalog_publications"]
    {
        assert!(t.contains(&table.to_string()), "{table} missing: {t:?}");
    }
    for (table, n) in [("connections", 1), ("folders", 1), ("credentials", 1), ("pins", 1)] {
        assert_eq!(row_count(&vault, table), n, "{table}");
    }
    vault.close();
    assert_eq!(backups(&dir), ["vault.db.bak-v1"]);
    assert_eq!(backup_version(&dir, "vault.db.bak-v1"), "1");
}

/// The 1.2 code path: the v1 migration list opens a v2 database. It is readable (every v1 table and column is
/// still there, and `min_app_schema` is 1), and the open-time rule of 1.2 (`schema_version` above the app's schema
/// → read-only) applies, so 1.2 reads every v1 table without migrating or writing anything.
#[test]
fn a_v2_database_opens_in_a_1_2_build_and_reads_every_v1_table() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    insert_canary(&mut vault);
    assert_eq!(meta(&vault, "min_app_schema"), "1");
    vault.close();
    let before = fs::read(dir.join(VAULT_FILE)).unwrap();

    let vault = Vault::open_with_migrations(&dir, &dek(1), &v1()).expect("1.2 can open a v2 vault");
    assert_eq!(vault.schema_version(), 2);
    for table in [
        "meta",
        "folders",
        "connections",
        "secrets",
        "credentials",
        "credential_links",
        "system_items",
        "system_otp",
        "ranking",
        "pins",
        "control_clients",
    ] {
        let n: i64 = vault.connection().query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0)).unwrap();
        assert!(n >= 0);
    }
    assert_eq!(row_count(&vault, "connections"), 1);
    assert!(vault.is_read_only(), "1.2 treats a newer schema_version as read-only");
    vault.close();
    assert_eq!(fs::read(dir.join(VAULT_FILE)).unwrap(), before, "1.2 changes nothing");
    assert!(backups(&dir).is_empty(), "no migration attempt");
    // And this build still opens it normally.
    assert!(!Vault::open(&dir, &dek(1)).unwrap().is_read_only());
}
