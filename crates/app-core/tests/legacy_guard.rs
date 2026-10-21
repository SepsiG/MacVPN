//! The create window's migration window (review 1.2.0, H1 and M1): while the 1.1 data waits for the migration
//! (the legacy read-only mode), the new vault takes no write but the migration's own, so a folder or credential
//! edit made meanwhile cannot block the migration; and a quit between the import and the cleanup list is finished
//! at the next launch.

mod common;

use common::TempDir;
use macvpn_app_core::deps::{FolderOp, FolderStore};
use macvpn_app_core::folders::VaultFolders;
use macvpn_app_core::migration::{self, LegacyKeychain, LegacyRead, LegacySources};
use macvpn_app_core::shared_credentials::SharedCredentials;
use macvpn_app_core::vault::{VaultLifecycle, VaultState};
use macvpn_app_core::vault_setup::{LaunchDecision, launch_decision};
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::SecretField;
use macvpn_core::vault::{FixedEntropy, KdfParams, MemoryKeyStore};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

struct NoKeychain;
impl LegacyKeychain for NoKeychain {
    fn items(&self) -> Vec<(String, SecretField)> {
        Vec::new()
    }
    fn read(&self, _: &str, _: SecretField) -> LegacyRead {
        LegacyRead::Missing
    }
    fn delete(&self, _: &str, _: SecretField) {}
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn lifecycle(support: &Path, ks: Arc<MemoryKeyStore>) -> Arc<VaultLifecycle> {
    let v = Arc::new(VaultLifecycle::new(
        support.to_path_buf(),
        ks,
        Arc::new(FixedEntropy::new(3)),
        KdfParams::insecure_for_tests(),
    ));
    v.set_logger(|_| {});
    v
}

fn setup() -> (TempDir, PathBuf, Arc<VaultLifecycle>, Arc<MemoryKeyStore>) {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let tmp = TempDir::new();
    let support = tmp.path().join("MacVPN");
    copy_tree(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/migration/swift-era"), &support);
    let ks = Arc::new(MemoryKeyStore::new());
    let v = lifecycle(&support, ks.clone());
    (tmp, support, v, ks)
}

/// The create window in migration mode: the vault is created, the recovery key is shown and checked, and only then
/// the migration runs. A folder edit in between is refused, and the migration succeeds.
#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_folder_write_while_the_migration_waits_is_refused() {
    let (_tmp, support, v, _) = setup();
    let src = LegacySources::new(support.clone(), Arc::new(NoKeychain));
    assert_eq!(launch_decision(&v, || migration::has_legacy_data(&src)), LaunchDecision::Create { migrating: true });
    v.create(Zeroizing::new("correct horse battery".into()), true).unwrap();
    assert!(matches!(v.state(), VaultState::LegacyReadOnly { .. }), "still legacy mode while the key is shown");

    let folders = VaultFolders::new(v.clone());
    let refused = folders.apply(FolderOp::Create { parent: None, name: "Work".into() });
    assert_eq!(
        refused.unwrap_err().to_string(),
        "MacVPN is using the old storage in read-only mode until the migration succeeds"
    );
    // Nor directly through the lifecycle.
    assert!(v.with(|vault| vault.set_secret("A", SecretField::Psk, "x")).is_err());

    let report = migration::migrate(&v, &src).unwrap();
    assert!(report.connections > 0);
    assert!(!migration::has_legacy_data(&src));
    assert_eq!(v.state(), VaultState::Unlocked);
    // Afterwards the folders work.
    assert!(folders.apply(FolderOp::Create { parent: None, name: "Work".into() }).is_ok());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_shared_credential_write_while_the_migration_waits_is_refused() {
    let (_tmp, support, v, _) = setup();
    let src = LegacySources::new(support.clone(), Arc::new(NoKeychain));
    launch_decision(&v, || migration::has_legacy_data(&src));
    v.create(Zeroizing::new("correct horse battery".into()), true).unwrap();
    let creds = SharedCredentials::new(v.clone());
    assert!(creds.create("Office", "alice", None).is_err(), "no credential in legacy mode");
    assert!(!creds.view().available);
    migration::migrate(&v, &src).unwrap();
    assert!(creds.create("Office", "alice", None).is_ok());
}

/// The app quits (or crashes) after the import committed and before the cleanup list was written: the next launch
/// verifies the vault against the old data again and finishes the deletion.
#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_quit_between_the_import_and_the_cleanup_list_is_finished_at_the_next_launch() {
    let (_tmp, support, v, ks) = setup();
    let src = LegacySources::new(support.clone(), Arc::new(NoKeychain));
    launch_decision(&v, || migration::has_legacy_data(&src));
    v.create(Zeroizing::new("correct horse battery".into()), true).unwrap();
    let crash = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = migration::migrate_for_tests(&v, &src, None, |_| panic!("simulated quit after the import"));
    }));
    assert!(crash.is_err());
    drop(v);
    // The next launch: auto-unlock, then the pending migration.
    let v2 = lifecycle(&support, ks);
    assert_eq!(launch_decision(&v2, || migration::has_legacy_data(&src)), LaunchDecision::Unlocked);
    let report = migration::migrate(&v2, &src).unwrap();
    assert!(report.resumed);
    assert!(!migration::has_legacy_data(&src), "the old data is deleted");
    assert!(!support.join("connections").exists());
    assert!(v2.with_read(|vault| vault.is_empty()).map(|empty| !empty).unwrap());
}
