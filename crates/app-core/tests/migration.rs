//! The migration of the 1.1 storage into the vault (plan B Task 13, spec 2.7): read everything, import it in one
//! transaction, verify it byte for byte, and only then shred the old files, delete the old Keychain items and
//! write the `migrated-to-vault` marker. A failure before the deletion leaves every old file and Keychain item
//! as it was, removes the new vault and puts the app into the legacy read-only mode; a failure during the
//! deletion keeps the (verified) vault and records the leftovers so the next run finishes the job.
//!
//! Fixtures: `tests/fixtures/migration/{swift-era,1.0}` are data directories as the Swift app and the Rust 1.0 app
//! wrote them (built from `crates/core/tests/fixtures/swift`); they are copied into a temp dir first. The Keychain
//! is a fake. Every value is made up.

mod common;

use common::TempDir;
use macvpn_app_core::migration::{
    self, LegacyKeychain, LegacyRead, LegacySources, MARKER, MigrationError, MigrationReport, MigrationStep,
};
use macvpn_app_core::vault::{VaultLifecycle, VaultState};
use macvpn_core::models::{Connection, OTPSetting, SecretField};
use macvpn_core::ranking::ConnectionRanking;
use macvpn_core::swift_json;
use macvpn_core::vault::{FixedEntropy, KEYS_FILE, KdfParams, KeyStore, MemoryKeyStore, VAULT_FILE, Vault};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use zeroize::Zeroizing;

const PASSWORD: &str = "correct horse battery";
const SYSTEM_SERVICE: &str = "0F9E8D7C-6B5A-4938-2716-05F4E3D2C1B0";
const OPENVPN: &str = "0A1B2C3D-4E5F-4061-8273-94A5B6C7D8E9";
const L2TP: &str = "55555555-6666-7777-8888-999999999999";
const V01: &str = "11111111-2222-3333-4444-555555555555";
const SSTP: &str = "44444444-5555-6666-7777-888888888888";

// --- The fake Keychain ------------------------------------------------------------------------------------------

#[derive(Default)]
struct FakeKeychain {
    items: Mutex<BTreeMap<(String, String), String>>,
    /// Items whose read is denied (the user clicked Deny).
    denied: Mutex<HashSet<(String, String)>>,
    /// Items that hold bytes that are not UTF-8.
    undecodable: Mutex<HashSet<(String, String)>>,
    /// Items that disappear between the listing and the read.
    vanishing: Mutex<HashSet<(String, String)>>,
    /// Deletes silently do nothing (a Keychain that refuses).
    refuse_deletes: AtomicBool,
    prepared: AtomicBool,
}

impl FakeKeychain {
    fn with(items: &[(&str, SecretField, &str)]) -> Arc<FakeKeychain> {
        let k = FakeKeychain::default();
        for (item, field, value) in items {
            k.items.lock().unwrap().insert((item.to_string(), field.raw_value().into()), value.to_string());
        }
        Arc::new(k)
    }

    fn snapshot(&self) -> BTreeMap<(String, String), String> {
        self.items.lock().unwrap().clone()
    }
}

impl LegacyKeychain for FakeKeychain {
    fn prepare(&self) {
        self.prepared.store(true, Ordering::SeqCst);
    }

    fn items(&self) -> Vec<(String, SecretField)> {
        self.items
            .lock()
            .unwrap()
            .keys()
            .map(|(item, field)| (item.clone(), SecretField::from_raw_value(field).unwrap()))
            .collect()
    }

    fn read(&self, item: &str, field: SecretField) -> LegacyRead {
        let key = (item.to_string(), field.raw_value().to_string());
        if self.denied.lock().unwrap().contains(&key) {
            return LegacyRead::Unavailable(-128);
        }
        if self.undecodable.lock().unwrap().contains(&key) {
            return LegacyRead::Undecodable;
        }
        if self.vanishing.lock().unwrap().contains(&key) {
            self.items.lock().unwrap().remove(&key);
            return LegacyRead::Missing;
        }
        match self.items.lock().unwrap().get(&key) {
            Some(v) => LegacyRead::Value(Zeroizing::new(v.clone())),
            None => LegacyRead::Missing,
        }
    }

    fn delete(&self, item: &str, field: SecretField) {
        if !self.refuse_deletes.load(Ordering::SeqCst) {
            self.items.lock().unwrap().remove(&(item.to_string(), field.raw_value().to_string()));
        }
    }
}

fn swift_era_items() -> Vec<(&'static str, SecretField, &'static str)> {
    vec![
        (OPENVPN, SecretField::Username, "fixture-user"),
        (OPENVPN, SecretField::Password, "fixture-pass-1"),
        (L2TP, SecretField::Password, "fixture-pass-2"),
        (L2TP, SecretField::Psk, "fixture-psk-2"),
        (V01, SecretField::KeyPassword, "fixture-keypass-3"),
        // A system VPN (scutil service ID), not a managed connection.
        (SYSTEM_SERVICE, SecretField::Password, "fixture-system-pass"),
    ]
}

fn one_point_zero_items() -> Vec<(&'static str, SecretField, &'static str)> {
    vec![
        (SSTP, SecretField::Username, "sstp-user"),
        (SSTP, SecretField::Password, "sstp-pass ő"),
        ("33333333-4444-5555-6666-777777777777", SecretField::Password, "ikev2-pass"),
        ("66666666-7777-8888-9999-AAAAAAAAAAAA", SecretField::Password, "cisco-pass"),
        ("66666666-7777-8888-9999-AAAAAAAAAAAA", SecretField::Psk, "cisco-psk"),
        ("38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4", SecretField::Psk, "system-psk"),
    ]
}

// --- The fixture ------------------------------------------------------------------------------------------------

struct Fixture {
    _tmp: TempDir,
    support: PathBuf,
    keychain: Arc<FakeKeychain>,
    keystore: Arc<MemoryKeyStore>,
    log: Arc<Mutex<Vec<String>>>,
    vault: VaultLifecycle,
}

fn fixture_dir(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/migration").join(name)
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    fs::set_permissions(to, fs::Permissions::from_mode(0o700)).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}

impl Fixture {
    /// `fixture`: a directory under `tests/fixtures/migration`, or `None` for an empty support directory.
    fn new(fixture: Option<&str>, items: &[(&str, SecretField, &str)]) -> Fixture {
        let tmp = TempDir::new();
        let support = tmp.path().join("MacVPN");
        match fixture {
            Some(name) => copy_tree(&fixture_dir(name), &support),
            None => fs::create_dir_all(&support).unwrap(),
        }
        let keystore = Arc::new(MemoryKeyStore::new());
        let vault = VaultLifecycle::new(
            support.clone(),
            keystore.clone(),
            Arc::new(FixedEntropy::new(3)),
            KdfParams::insecure_for_tests(),
        );
        let log: Arc<Mutex<Vec<String>>> = Arc::default();
        let sink = log.clone();
        vault.set_logger(move |line| sink.lock().unwrap().push(line.to_string()));
        Fixture { _tmp: tmp, support, keychain: FakeKeychain::with(items), keystore, log, vault }
    }

    fn sources(&self) -> LegacySources {
        LegacySources::new(self.support.clone(), self.keychain.clone())
    }

    fn create_vault(&self) {
        self.vault.create(Zeroizing::new(PASSWORD.to_string()), true).unwrap();
    }

    fn migrate(&self, fail_at: Option<MigrationStep>) -> Result<MigrationReport, MigrationError> {
        migration::migrate_for_tests(&self.vault, &self.sources(), fail_at, |_| {})
    }

    fn with<R>(&self, f: impl FnOnce(&mut Vault) -> R) -> R {
        self.vault.with(|v| Ok(f(v))).unwrap()
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

/// Every file below `dir` (relative path → bytes), the vault's own files excluded.
fn files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = fs::read_dir(dir) else { return };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                if !rel.starts_with("vault.") {
                    out.insert(rel, fs::read(&path).unwrap());
                }
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out);
    out
}

fn vault_files_exist(support: &Path) -> bool {
    fs::read_dir(support).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with("vault."))
}

fn decoded(path: &Path) -> Connection {
    Connection::from_json(&swift_json::parse(&fs::read(path).unwrap()).unwrap()).unwrap()
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn uuid(s: &str) -> Uuid {
    macvpn_core::models::parse_uuid(s).unwrap()
}

/// The source data of a fixture, read straight from its files: connections with their raw config bytes.
fn source_connections(support: &Path) -> Vec<(Connection, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(support.join("connections")).unwrap() {
        let dir = entry.unwrap().path();
        let c = decoded(&dir.join("meta.json"));
        let config = fs::read(dir.join("config")).unwrap_or_default();
        out.push((c, config));
    }
    out
}

fn assert_fully_migrated(f: &Fixture, before: &BTreeMap<String, Vec<u8>>, items: &[(&str, SecretField, &str)]) {
    // Every connection, with the exact meta and config bytes.
    let conns: Vec<(Connection, Vec<u8>)> = {
        let tmp = TempDir::new();
        for (rel, bytes) in before {
            let p = tmp.path().join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, bytes).unwrap();
        }
        source_connections(tmp.path())
    };
    f.with(|v| {
        assert_eq!(v.connection_count().unwrap(), conns.len());
        for (c, config) in &conns {
            let (meta, stored) = v.connection_record(&c.id).unwrap().expect("connection in the vault");
            assert_eq!(meta, swift_json::to_pretty_sorted(&c.to_json()).unwrap());
            assert_eq!(&stored[..], &config[..], "config bytes of {}", c.name);
        }
        let listed: HashMap<Uuid, Connection> =
            v.connections().unwrap().into_iter().map(|s| (s.connection.id, s.connection)).collect();
        for (c, _) in &conns {
            assert_eq!(listed.get(&c.id), Some(c));
        }
        // Every secret, the system-VPN one too.
        assert_eq!(v.secret_count().unwrap(), items.len());
        for (item, field, value) in items {
            assert_eq!(v.secret(item, *field).unwrap().as_deref().map(String::as_str), Some(*value));
        }
        // Ranking and OTP as decoded from the old files.
        let ranking =
            ConnectionRanking::from_json(&swift_json::parse(before.get("connection-order.json").unwrap()).unwrap())
                .unwrap();
        assert_eq!(v.ranking().unwrap(), ranking);
        let otp: HashMap<String, OTPSetting> = match swift_json::parse(before.get("system-otp.json").unwrap()).unwrap()
        {
            Value::Object(m) => m.into_iter().map(|(k, v)| (k, OTPSetting::from_json(&v).unwrap())).collect(),
            _ => unreachable!(),
        };
        assert_eq!(v.system_otp_map().unwrap(), otp);
    });
    // The old data is gone, the marker is there.
    assert!(files(&f.support).keys().all(|k| k == MARKER), "left: {:?}", files(&f.support).keys());
    assert!(!f.support.join("connections").exists());
    assert!(f.keychain.snapshot().is_empty());
    assert_eq!(mode(&f.support.join(MARKER)), 0o600);
    assert_eq!(f.vault.state(), VaultState::Unlocked);
    assert!(!migration::has_legacy_data(&f.sources()));
}

fn assert_no_secret_logged(f: &Fixture, items: &[(&str, SecretField, &str)]) {
    for line in f.log() {
        for (_, _, value) in items {
            assert!(!line.contains(value), "secret in the log: {line:?}");
        }
        for word in ["Office", "remote", "example", "Iroda"] {
            assert!(!line.contains(word), "data in the log: {line:?}");
        }
    }
}

// --- Full migrations --------------------------------------------------------------------------------------------

/// The create window pauses after the check (review 1.2.0 L4, spec 2.7 step 5): the old data is still there while
/// the window offers the backup; the next run deletes it.
#[test]
fn the_migration_can_pause_before_deleting_the_old_data() {
    let items = swift_era_items();
    let f = Fixture::new(Some("swift-era"), &items);
    let before = files(&f.support);
    f.create_vault();
    let report = migration::migrate_keeping_old_data(&f.vault, &f.sources()).unwrap();
    assert_eq!((report.connections, report.secrets, report.resumed), (3, 6, false));
    assert_eq!(f.vault.state(), macvpn_app_core::vault::VaultState::Unlocked, "the vault is in use");
    assert!(f.support.join("connections").exists(), "the old files are kept");
    assert_eq!(f.keychain.items().len(), items.len(), "the old Keychain items are kept");
    assert!(migration::has_legacy_data(&f.sources()));

    let finished = migration::migrate(&f.vault, &f.sources()).unwrap();
    assert!(finished.resumed);
    assert_fully_migrated(&f, &before, &items);
}

#[test]
fn the_swift_era_directory_migrates_fully() {
    let items = swift_era_items();
    let f = Fixture::new(Some("swift-era"), &items);
    assert!(migration::has_legacy_data(&f.sources()));
    assert_eq!(migration::keychain_item_count(&f.sources()), items.len());
    let before = files(&f.support);
    f.create_vault();

    let report = f.migrate(None).unwrap();

    assert_eq!(
        report,
        MigrationReport {
            connections: 3,
            secrets: 6,
            system_otp: 3,
            clients: 0,
            skipped: vec![],
            resumed: false,
            vault_had_data: false
        }
    );
    assert!(f.keychain.prepared.load(Ordering::SeqCst), "the old `macvpn` service is moved over first");
    assert_fully_migrated(&f, &before, &items);
    // The BOM and the CRLF line ends are kept byte for byte; the native connection has an empty config.
    f.with(|v| {
        let (_, config) = v.connection_record(&uuid(OPENVPN)).unwrap().unwrap();
        assert!(config.starts_with(b"\xEF\xBB\xBFclient\r\n"));
        let (_, config) = v.connection_record(&uuid(L2TP)).unwrap().unwrap();
        assert!(config.is_empty());
    });
    assert_no_secret_logged(&f, &items);
    assert!(f.log().iter().any(|l| l.contains("migrated") && l.contains("3 connections")), "{:?}", f.log());
}

#[test]
fn the_1_0_directory_with_paired_clients_migrates_fully() {
    let items = one_point_zero_items();
    let f = Fixture::new(Some("1.0"), &items);
    // The control API's registry as 1.1 writes it.
    let clients = vec![
        json!({
            "id": "C1A2B3C4-0000-4000-8000-000000000001",
            "name": "Script",
            "tokenSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "executable": "/usr/local/bin/example",
            "allowed": [SSTP],
            "created": "2026-10-19T08:00:00Z"
        }),
        json!({
            "id": "C1A2B3C4-0000-4000-8000-000000000002",
            "name": "Tool",
            "tokenSha256": "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752",
            "executable": "/Applications/Example.app/Contents/MacOS/Example",
            "allowed": [],
            "created": "2026-10-19T08:00:00Z",
            "lastUsed": "2026-10-19T09:00:00Z"
        }),
    ];
    let registry = swift_json::to_pretty_sorted(&json!({ "clients": clients })).unwrap();
    fs::write(f.support.join("control-clients.json"), registry).unwrap();
    let before = files(&f.support);
    f.create_vault();

    let report = f.migrate(None).unwrap();

    assert_eq!(
        report,
        MigrationReport {
            connections: 5,
            secrets: 6,
            system_otp: 1,
            clients: 2,
            skipped: vec![],
            resumed: false,
            vault_had_data: false
        }
    );
    assert_fully_migrated(&f, &before, &items);
    f.with(|v| assert_eq!(v.control_clients().unwrap(), clients));
    assert_no_secret_logged(&f, &items);
}

/// The file the 1.1 control API writes (`Registry::save` into the support directory) is the one the migration
/// reads, and its clients arrive in the vault as written.
#[test]
fn the_registry_the_control_api_saves_is_migrated() {
    use macvpn_core::control::registry::{PairedClient, Registry};
    let f = Fixture::new(None, &[]);
    let mut registry = Registry::new();
    let created = macvpn_core::date::Date::now();
    registry.add(PairedClient::new(
        uuid("C1A2B3C4-0000-4000-8000-000000000001"),
        "Script".into(),
        "token-1",
        "/usr/local/bin/script".into(),
        vec!["SERVICE-A".into()],
        created,
    ));
    registry.save(&f.support).unwrap();
    let legacy = LegacySources::new(f.support.clone(), f.keychain.clone());
    assert_eq!(legacy.registry_path, Registry::path(&f.support));
    let written: Value = serde_json::from_slice(&fs::read(Registry::path(&f.support)).unwrap()).unwrap();
    f.create_vault();

    let report = f.migrate(None).unwrap();

    assert_eq!(report.clients, 1);
    f.with(|v| assert_eq!(v.control_clients().unwrap(), written["clients"].as_array().unwrap().clone()));
    assert!(!Registry::path(&f.support).exists(), "the registry file is deleted once imported");
}

#[test]
fn shredded_files_are_zeroed_before_the_unlink() {
    let f = Fixture::new(Some("swift-era"), &swift_era_items());
    let config = f.support.join(format!("connections/{OPENVPN}/config"));
    let original = fs::read(&config).unwrap();
    // An fd opened before keeps the inode alive after the unlink, so the overwrite can be observed.
    let mut observer = fs::File::open(&config).unwrap();
    f.create_vault();
    f.migrate(None).unwrap();
    let mut after = Vec::new();
    std::io::Read::read_to_end(&mut observer, &mut after).unwrap();
    assert_eq!(after.len(), original.len());
    assert!(after.iter().all(|b| *b == 0));
    assert!(!config.exists());
}

// --- Failures before the deletion: nothing changes --------------------------------------------------------------

fn assert_untouched(
    f: &Fixture,
    files_before: &BTreeMap<String, Vec<u8>>,
    keychain_before: &BTreeMap<(String, String), String>,
) {
    assert_eq!(&files(&f.support), files_before, "every legacy file byte for byte");
    assert_eq!(&f.keychain.snapshot(), keychain_before, "every Keychain item");
    assert!(!vault_files_exist(&f.support), "no vault files remain");
    assert!(!f.support.join(MARKER).exists());
    assert!(matches!(f.vault.state(), VaultState::LegacyReadOnly { .. }), "{:?}", f.vault.state());
    // The auto-unlock item of the removed vault is gone too.
    assert!(f.keystore.get().unwrap().is_none());
}

#[test]
fn a_failure_before_the_deletion_leaves_the_old_data_intact_and_a_retry_works() {
    for step in [MigrationStep::Read, MigrationStep::Import, MigrationStep::Verify] {
        let items = swift_era_items();
        let f = Fixture::new(Some("swift-era"), &items);
        let files_before = files(&f.support);
        let keychain_before = f.keychain.snapshot();
        f.create_vault();

        let err = f.migrate(Some(step)).unwrap_err();

        assert!(matches!(&err, MigrationError::Failed { step: s, .. } if *s == step), "{err:?}");
        assert!(err.legacy_read_only(), "{step:?}");
        assert_untouched(&f, &files_before, &keychain_before);
        assert!(migration::has_legacy_data(&f.sources()));
        assert!(f.log().iter().any(|l| l.contains("migration failed")), "{:?}", f.log());

        // The user retries: a new vault, and this time it works.
        f.create_vault();
        f.migrate(None).unwrap();
        assert_fully_migrated(&f, &files_before, &items);
    }
}

#[test]
fn verification_catches_a_tampered_vault() {
    type Tamper = fn(&mut Vault);
    let tampers: [(&str, Tamper); 6] = [
        ("secret", |v| v.set_secret(L2TP, SecretField::Psk, "changed").unwrap()),
        ("extra secret", |v| v.set_secret("SOMETHING", SecretField::Psk, "extra").unwrap()),
        ("config", |v| {
            let c = v.connections().unwrap().into_iter().find(|c| c.connection.id == uuid(V01)).unwrap();
            v.save_connection(&c.connection, Some("client\n")).unwrap();
        }),
        ("meta", |v| {
            let mut c = v.connections().unwrap().into_iter().find(|c| c.connection.id == uuid(V01)).unwrap();
            c.connection.name = "renamed".into();
            v.save_connection(&c.connection, None).unwrap();
        }),
        ("ranking", |v| v.save_ranking(&ConnectionRanking::default()).unwrap()),
        ("system otp", |v| v.save_system_otp_map(&HashMap::new()).unwrap()),
    ];
    for (what, tamper) in tampers {
        let f = Fixture::new(Some("swift-era"), &swift_era_items());
        let files_before = files(&f.support);
        let keychain_before = f.keychain.snapshot();
        f.create_vault();

        let err = migration::migrate_for_tests(&f.vault, &f.sources(), None, tamper).unwrap_err();

        assert!(matches!(&err, MigrationError::Failed { step: MigrationStep::Verify, .. }), "{what}: {err:?}");
        assert_untouched(&f, &files_before, &keychain_before);
        // The message names what differs, never a value.
        assert!(!err.to_string().contains("changed") && !err.to_string().contains("fixture-"), "{err}");
    }
}

#[test]
fn verification_catches_tampered_clients() {
    let f = Fixture::new(Some("1.0"), &one_point_zero_items());
    fs::write(f.support.join("control-clients.json"), r#"{"clients":[{"id":"A","name":"x"}]}"#).unwrap();
    let files_before = files(&f.support);
    let keychain_before = f.keychain.snapshot();
    f.create_vault();
    let err = migration::migrate_for_tests(&f.vault, &f.sources(), None, |v| {
        v.save_control_clients(&[json!({ "id": "A", "name": "y" })]).unwrap()
    })
    .unwrap_err();
    assert!(matches!(&err, MigrationError::Failed { step: MigrationStep::Verify, .. }), "{err:?}");
    assert_untouched(&f, &files_before, &keychain_before);
}

#[test]
fn a_keychain_item_that_cannot_be_read_fails_the_read_step() {
    let f = Fixture::new(Some("swift-era"), &swift_era_items());
    f.keychain.denied.lock().unwrap().insert((L2TP.to_string(), "psk".to_string()));
    let files_before = files(&f.support);
    let keychain_before = f.keychain.snapshot();
    f.create_vault();
    let err = f.migrate(None).unwrap_err();
    assert!(matches!(&err, MigrationError::Failed { step: MigrationStep::Read, .. }), "{err:?}");
    assert_untouched(&f, &files_before, &keychain_before);
}

// --- Failures during the deletion: the vault stays, the next run finishes ---------------------------------------

#[test]
fn a_failure_while_deleting_files_is_finished_by_the_next_run() {
    let items = swift_era_items();
    let f = Fixture::new(Some("swift-era"), &items);
    let before = files(&f.support);
    let keychain_before = f.keychain.snapshot();
    f.create_vault();

    let err = f.migrate(Some(MigrationStep::DeleteFiles)).unwrap_err();

    assert!(matches!(&err, MigrationError::Failed { step: MigrationStep::DeleteFiles, .. }), "{err:?}");
    assert!(!err.legacy_read_only());
    assert_eq!(f.vault.state(), VaultState::Unlocked, "the verified vault stays in use");
    let mut left = files(&f.support);
    assert!(left.remove(migration::CLEANUP_FILE).is_some(), "the leftovers are recorded");
    assert!(left.len() < before.len() && !left.is_empty(), "some files were deleted: {:?}", left.keys());
    assert_eq!(f.keychain.snapshot(), keychain_before);
    assert!(!f.support.join(MARKER).exists());
    assert!(migration::has_legacy_data(&f.sources()));

    let report = f.migrate(None).unwrap();
    assert!(report.resumed);
    assert_fully_migrated(&f, &before, &items);
}

#[test]
fn a_failure_while_deleting_keychain_items_is_finished_by_the_next_run() {
    let items = swift_era_items();
    let f = Fixture::new(Some("swift-era"), &items);
    let before = files(&f.support);
    let keychain_before = f.keychain.snapshot();
    f.create_vault();

    let err = f.migrate(Some(MigrationStep::DeleteKeychain)).unwrap_err();

    assert!(matches!(&err, MigrationError::Failed { step: MigrationStep::DeleteKeychain, .. }), "{err:?}");
    assert!(!err.legacy_read_only());
    assert!(!f.support.join("connections").exists(), "the files are gone");
    assert!(!f.support.join("connection-order.json").exists());
    assert_eq!(f.keychain.snapshot(), keychain_before, "the Keychain items still exist");
    assert!(!f.support.join(MARKER).exists());
    assert_eq!(f.vault.state(), VaultState::Unlocked);

    let report = f.migrate(None).unwrap();
    assert!(report.resumed);
    assert_fully_migrated(&f, &before, &items);
}

#[test]
fn a_keychain_that_refuses_deletes_is_retried_later() {
    let items = swift_era_items();
    let f = Fixture::new(Some("swift-era"), &items);
    let before = files(&f.support);
    f.create_vault();
    f.keychain.refuse_deletes.store(true, Ordering::SeqCst);

    let err = f.migrate(None).unwrap_err();
    assert!(matches!(&err, MigrationError::Failed { step: MigrationStep::DeleteKeychain, .. }), "{err:?}");
    assert!(!f.support.join(MARKER).exists());

    f.keychain.refuse_deletes.store(false, Ordering::SeqCst);
    f.migrate(None).unwrap();
    assert_fully_migrated(&f, &before, &items);
}

#[test]
fn a_failure_writing_the_marker_is_finished_by_the_next_run() {
    let items = swift_era_items();
    let f = Fixture::new(Some("swift-era"), &items);
    let before = files(&f.support);
    f.create_vault();

    let err = f.migrate(Some(MigrationStep::Marker)).unwrap_err();
    assert!(matches!(&err, MigrationError::Failed { step: MigrationStep::Marker, .. }), "{err:?}");
    assert!(f.keychain.snapshot().is_empty());
    assert!(!f.support.join(MARKER).exists());
    assert!(migration::has_legacy_data(&f.sources()), "the cleanup is still pending");

    f.migrate(None).unwrap();
    assert_fully_migrated(&f, &before, &items);
}

#[test]
fn the_cleanup_is_refused_without_a_vault() {
    let f = Fixture::new(Some("swift-era"), &swift_era_items());
    f.create_vault();
    f.migrate(Some(MigrationStep::DeleteKeychain)).unwrap_err();
    let keychain_before = f.keychain.snapshot();
    // The vault disappears (deleted by hand) before the next launch.
    f.vault.lock();
    fs::remove_file(f.support.join(KEYS_FILE)).unwrap();
    fs::remove_file(f.support.join(VAULT_FILE)).unwrap();
    let err = f.migrate(None).unwrap_err();
    assert!(matches!(err, MigrationError::Refused(_)), "{err:?}");
    assert_eq!(f.keychain.snapshot(), keychain_before, "nothing is deleted without the vault");
}

// --- Skipped data -----------------------------------------------------------------------------------------------

#[test]
fn a_corrupt_meta_json_is_skipped_and_left_in_place_with_its_secrets() {
    let mut items = swift_era_items();
    let broken = "99999999-0000-4000-8000-000000000009";
    items.push((broken, SecretField::Password, "kept-pass"));
    let f = Fixture::new(Some("swift-era"), &items);
    let dir = f.support.join(format!("connections/{broken}"));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("meta.json"), b"{ not json").unwrap();
    fs::write(dir.join("config"), b"remote kept.example.com\n").unwrap();
    f.create_vault();

    let report = f.migrate(None).unwrap();

    assert_eq!(report.connections, 3);
    assert_eq!(report.secrets, 6);
    assert_eq!(report.skipped.len(), 2, "{:?}", report.skipped);
    assert!(report.skipped.iter().all(|s| s.contains(broken)), "{:?}", report.skipped);
    assert_eq!(fs::read(dir.join("meta.json")).unwrap(), b"{ not json");
    assert_eq!(fs::read(dir.join("config")).unwrap(), b"remote kept.example.com\n");
    assert_eq!(
        f.keychain.snapshot().into_iter().collect::<Vec<_>>(),
        [((broken.to_string(), "password".to_string()), "kept-pass".to_string())]
    );
    f.with(|v| assert_eq!(v.secret(broken, SecretField::Password).unwrap(), None));
    assert!(f.support.join(MARKER).exists());
}

#[test]
fn unreadable_ranking_otp_and_registry_files_are_skipped_and_left_in_place() {
    let f = Fixture::new(Some("1.0"), &one_point_zero_items());
    fs::write(f.support.join("connection-order.json"), b"[]").unwrap();
    fs::write(f.support.join("system-otp.json"), b"{\"X\": 1}").unwrap();
    fs::write(f.support.join("control-clients.json"), b"{\"clients\":[{\"id\":\"A\"},{\"id\":\"A\"}]}").unwrap();
    f.create_vault();
    let report = f.migrate(None).unwrap();
    assert_eq!(report.connections, 5);
    assert_eq!((report.system_otp, report.clients), (0, 0));
    assert_eq!(report.skipped.len(), 3, "{:?}", report.skipped);
    for name in ["connection-order.json", "system-otp.json", "control-clients.json"] {
        assert!(f.support.join(name).exists(), "{name} is kept");
    }
    f.with(|v| {
        assert_eq!(v.ranking().unwrap(), ConnectionRanking::default());
        assert!(v.system_otp_map().unwrap().is_empty());
    });
}

#[test]
fn duplicate_pins_are_imported_once() {
    let f = Fixture::new(Some("1.0"), &[]);
    let file = r#"{"pinned":["A","B","A"],"usage":{}}"#;
    fs::write(f.support.join("connection-order.json"), file).unwrap();
    f.create_vault();
    f.migrate(None).unwrap();
    f.with(|v| assert_eq!(v.ranking().unwrap().pinned(), ["A".to_string(), "B".to_string()]));
}

// --- Preconditions and the probes -------------------------------------------------------------------------------

#[test]
fn has_legacy_data_is_false_on_an_empty_or_missing_directory() {
    let f = Fixture::new(None, &[]);
    assert!(!migration::has_legacy_data(&f.sources()));
    assert_eq!(migration::keychain_item_count(&f.sources()), 0);
    let missing = LegacySources::new(f.support.join("nope"), f.keychain.clone());
    assert!(!migration::has_legacy_data(&missing));
    // An empty `connections` directory is no data either.
    fs::create_dir_all(f.support.join("connections")).unwrap();
    assert!(!migration::has_legacy_data(&f.sources()));
}

#[test]
fn has_legacy_data_sees_each_source_and_the_marker_ends_it() {
    let only_keychain = Fixture::new(None, &[(SYSTEM_SERVICE, SecretField::Password, "x")]);
    assert!(migration::has_legacy_data(&only_keychain.sources()));
    for name in ["connection-order.json", "system-otp.json", "control-clients.json"] {
        let f = Fixture::new(None, &[]);
        fs::write(f.support.join(name), b"{}").unwrap();
        assert!(migration::has_legacy_data(&f.sources()), "{name}");
        fs::write(f.support.join(MARKER), b"").unwrap();
        assert!(!migration::has_legacy_data(&f.sources()), "{name} after the marker");
    }
}

#[test]
fn an_empty_directory_migrates_to_just_the_marker() {
    let f = Fixture::new(None, &[]);
    f.create_vault();
    let report = f.migrate(None).unwrap();
    assert_eq!(report, MigrationReport::default());
    assert!(f.support.join(MARKER).exists());
    // Done: a second run changes nothing.
    assert_eq!(f.migrate(None).unwrap(), MigrationReport::default());
}

#[test]
fn a_locked_vault_is_refused_and_a_non_empty_one_left_alone() {
    let f = Fixture::new(Some("swift-era"), &swift_era_items());
    let files_before = files(&f.support);
    let keychain_before = f.keychain.snapshot();
    // No vault at all.
    assert!(matches!(f.migrate(None), Err(MigrationError::Refused(_))));
    f.create_vault();
    f.vault.lock();
    assert!(matches!(f.migrate(None), Err(MigrationError::Refused(_))));
    f.vault.unlock_with_password(Zeroizing::new(PASSWORD.to_string()), std::time::Instant::now()).unwrap();
    f.with(|v| v.set_secret(SYSTEM_SERVICE, SecretField::Psk, "already here").unwrap());
    // A vault with data: not a failure, nothing happens (final review 1.2.0, MEDIUM-1 b).
    let report = f.migrate(None).unwrap();
    assert!(report.vault_had_data);
    assert_eq!(files(&f.support), files_before);
    assert_eq!(f.keychain.snapshot(), keychain_before);
    assert!(vault_files_exist(&f.support), "a vault with data is never removed");
    assert_eq!(f.vault.state(), VaultState::Unlocked);
}

#[test]
fn a_successful_retry_leaves_the_legacy_read_only_mode() {
    let f = Fixture::new(Some("swift-era"), &swift_era_items());
    f.create_vault();
    f.migrate(Some(MigrationStep::Import)).unwrap_err();
    assert!(matches!(f.vault.state(), VaultState::LegacyReadOnly { .. }));
    f.create_vault();
    f.migrate(None).unwrap();
    assert_eq!(f.vault.state(), VaultState::Unlocked);
}

#[test]
fn the_step_names_are_stable() {
    let names: Vec<&str> = [
        MigrationStep::Read,
        MigrationStep::Import,
        MigrationStep::Verify,
        MigrationStep::DeleteFiles,
        MigrationStep::DeleteKeychain,
        MigrationStep::Marker,
    ]
    .iter()
    .map(|s| s.as_str())
    .collect();
    assert_eq!(names, ["read", "import", "verify", "delete files", "delete keychain", "marker"]);
}

// --- Review fixes ------------------------------------------------------------------------------------------------

#[test]
fn undecodable_and_vanished_keychain_items_are_skipped_and_not_deleted() {
    let mut items = swift_era_items();
    items.push((V01, SecretField::Password, "\u{FFFD}"));
    let f = Fixture::new(Some("swift-era"), &items);
    f.keychain.undecodable.lock().unwrap().insert((V01.to_string(), "password".to_string()));
    f.keychain.vanishing.lock().unwrap().insert((L2TP.to_string(), "psk".to_string()));
    f.create_vault();

    let report = f.migrate(None).unwrap();

    assert_eq!(report.secrets, 5, "the five readable ones");
    assert_eq!(report.skipped.len(), 2, "{:?}", report.skipped);
    assert!(report.skipped.iter().any(|s| s.contains(&format!("{V01}.password"))));
    assert!(report.skipped.iter().any(|s| s.contains(&format!("{L2TP}.psk"))));
    // The undecodable item is left in the Keychain; everything read was deleted.
    assert_eq!(f.keychain.snapshot().into_keys().collect::<Vec<_>>(), [(V01.to_string(), "password".to_string())]);
    assert!(f.support.join(MARKER).exists());
}

/// Puts a hand-written cleanup list in place after a verified import (as a damaged or planted file would be).
fn with_cleanup_list(text: &str) -> Fixture {
    let f = Fixture::new(Some("swift-era"), &swift_era_items());
    f.create_vault();
    f.migrate(Some(MigrationStep::DeleteFiles)).unwrap_err();
    fs::write(f.support.join(migration::CLEANUP_FILE), text).unwrap();
    f
}

#[test]
fn a_cleanup_list_naming_anything_else_is_refused() {
    for line in [
        "file vault.keys",
        "file vault.db",
        "file connections/../vault.db",
        "file /etc/hosts",
        &format!("file connections/{}/meta.json", OPENVPN.to_lowercase()),
        &format!("file connections/{OPENVPN}/other"),
        &format!("dir connections/{OPENVPN}/sub"),
        "dir .",
        "key SOMETHING password",
        &format!("key {OPENVPN} secret"),
        "rm -rf",
    ] {
        let f = with_cleanup_list(&format!("file connection-order.json\n{line}\n"));
        let before = files(&f.support);
        let err = f.migrate(None).unwrap_err();
        assert!(matches!(err, MigrationError::Refused(_)), "{line}: {err:?}");
        assert_eq!(files(&f.support), before, "{line}: nothing deleted");
        assert!(vault_files_exist(&f.support));
        assert!(f.support.join(KEYS_FILE).exists() && f.support.join(VAULT_FILE).exists());
    }
}

#[test]
fn a_symlinked_connection_directory_is_not_followed() {
    let f = Fixture::new(Some("swift-era"), &swift_era_items());
    // A connection directory that is a symlink to a directory elsewhere.
    let elsewhere = f._tmp.path().join("elsewhere");
    let id = "88888888-0000-4000-8000-000000000008";
    fs::create_dir_all(&elsewhere).unwrap();
    fs::copy(f.support.join(format!("connections/{V01}/meta.json")), elsewhere.join("meta.json")).unwrap();
    fs::write(elsewhere.join("config"), b"keep me\n").unwrap();
    std::os::unix::fs::symlink(&elsewhere, f.support.join(format!("connections/{id}"))).unwrap();
    f.create_vault();
    f.migrate(None).unwrap();
    f.with(|v| assert_eq!(v.connection_count().unwrap(), 3, "not imported"));
    assert_eq!(fs::read(elsewhere.join("config")).unwrap(), b"keep me\n");
    assert!(elsewhere.join("meta.json").exists());

    // Nor in a cleanup list: the directory was swapped for a symlink after the import.
    let f = with_cleanup_list(&format!("file connections/{V01}/config\nfile connections/{V01}/meta.json\n"));
    let dir = f.support.join(format!("connections/{V01}"));
    let target = f._tmp.path().join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join("config"), b"not ours\n").unwrap();
    fs::write(target.join("meta.json"), b"not ours either\n").unwrap();
    fs::remove_dir_all(&dir).unwrap();
    std::os::unix::fs::symlink(&target, &dir).unwrap();
    f.migrate(None).unwrap();
    assert_eq!(fs::read(target.join("config")).unwrap(), b"not ours\n");
    assert_eq!(fs::read(target.join("meta.json")).unwrap(), b"not ours either\n");
}

#[test]
fn resuming_into_an_empty_unlocked_vault_is_refused() {
    let f = Fixture::new(Some("swift-era"), &swift_era_items());
    f.create_vault();
    f.migrate(Some(MigrationStep::DeleteKeychain)).unwrap_err();
    let keychain_before = f.keychain.snapshot();
    // The vault was replaced by an empty one.
    f.vault.lock();
    fs::remove_file(f.support.join(KEYS_FILE)).unwrap();
    fs::remove_file(f.support.join(VAULT_FILE)).unwrap();
    f.create_vault();
    let err = f.migrate(None).unwrap_err();
    assert!(matches!(err, MigrationError::Refused(_)), "{err:?}");
    assert_eq!(f.keychain.snapshot(), keychain_before);
}

#[test]
fn an_empty_vault_from_an_earlier_session_is_rolled_back_too() {
    let f = Fixture::new(Some("swift-era"), &swift_era_items());
    let files_before = files(&f.support);
    let keychain_before = f.keychain.snapshot();
    f.create_vault();
    // The app quit before the migration; the next launch unlocks the (empty) vault.
    f.vault.lock();
    let next = VaultLifecycle::new(
        f.support.clone(),
        f.keystore.clone(),
        Arc::new(FixedEntropy::new(3)),
        KdfParams::insecure_for_tests(),
    );
    next.unlock_with_password(Zeroizing::new(PASSWORD.to_string()), std::time::Instant::now()).unwrap();
    assert!(!next.created_for_migration());
    let err = migration::migrate_for_tests(&next, &f.sources(), Some(MigrationStep::Import), |_| {}).unwrap_err();
    assert!(err.legacy_read_only());
    assert_eq!(files(&f.support), files_before);
    assert_eq!(f.keychain.snapshot(), keychain_before);
    assert!(!vault_files_exist(&f.support));
}

#[test]
fn a_successful_migration_ends_the_fresh_vault_mark() {
    let f = Fixture::new(Some("swift-era"), &swift_era_items());
    f.create_vault();
    assert!(f.vault.created_for_migration());
    f.migrate(None).unwrap();
    assert!(!f.vault.created_for_migration());
}
