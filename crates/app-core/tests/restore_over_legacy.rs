//! A first-run restore over MacVPN 1.1 data (final review 1.2.0, MEDIUM-1): the backup becomes the vault, the 1.1
//! data is not imported but deleted (known shapes only, its Keychain items too) and marked as done, so the next
//! launch opens the vault normally: no create window, no legacy read-only mode. A vault that already holds data
//! next to 1.1 data that was never migrated is a distinct, non-failing outcome that is only logged.

mod common;

use common::TempDir;
use macvpn_app_core::backup::{BackupService, PasswordSource, PreferencePort};
use macvpn_app_core::migration::{self, LegacyKeychain, LegacyRead, LegacySources, PendingMigration};
use macvpn_app_core::vault::{VaultLifecycle, VaultState};
use macvpn_app_core::vault_setup::{LaunchDecision, launch_decision};
use macvpn_core::date::Date;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::{Connection, SecretField, VPNKind};
use macvpn_core::vault::backup::BackupPreferences;
use macvpn_core::vault::{FixedEntropy, KdfParams, MemoryKeyStore};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const MASTER: &str = "correct horse battery";
const BACKUP_PW: &str = "backup password 42";
const OPENVPN: &str = "0A1B2C3D-4E5F-4061-8273-94A5B6C7D8E9";
const SYSTEM_SERVICE: &str = "0F9E8D7C-6B5A-4938-2716-05F4E3D2C1B0";

/// The 1.1 Keychain items (`local.macvpn.secrets`); never read by the restore's cleanup.
#[derive(Default)]
struct OldItems(Mutex<Vec<(String, SecretField)>>);

impl LegacyKeychain for OldItems {
    fn items(&self) -> Vec<(String, SecretField)> {
        self.0.lock().unwrap().clone()
    }
    fn read(&self, _: &str, _: SecretField) -> LegacyRead {
        panic!("the restore's cleanup reads no old secret")
    }
    fn delete(&self, account: &str, field: SecretField) {
        self.0.lock().unwrap().retain(|(a, f)| !(a == account && *f == field));
    }
}

#[derive(Default)]
struct NoPrefs;

impl PreferencePort for NoPrefs {
    fn current(&self) -> BackupPreferences {
        BackupPreferences::default()
    }
    fn apply(&self, _: macvpn_app_core::backup::Preference, _: bool) -> Result<(), String> {
        Ok(())
    }
    fn confirm_auto_unlock(&self) -> Result<(), String> {
        Ok(())
    }
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

fn lifecycle(dir: &Path, ks: Arc<MemoryKeyStore>) -> Arc<VaultLifecycle> {
    let v = Arc::new(VaultLifecycle::new(
        dir.to_path_buf(),
        ks,
        Arc::new(FixedEntropy::new(3)),
        KdfParams::insecure_for_tests(),
    ));
    v.set_logger(|_| {});
    v
}

/// A backup made on another Mac, with one connection.
fn backup_from_elsewhere(tmp: &TempDir) -> Vec<u8> {
    let v = lifecycle(&tmp.path().join("Other"), Arc::new(MemoryKeyStore::new()));
    v.create(Zeroizing::new(MASTER.into()), false).unwrap();
    let c = Connection::new("From the backup", VPNKind::Openvpn);
    v.with(|vault| vault.save_connection(&c, Some("client\nremote vpn.example.com 1194\n"))).unwrap();
    let service = BackupService::new(v, Arc::new(FixedEntropy::new(9)), KdfParams::insecure_for_tests(), "1.2.0");
    service
        .make(
            Zeroizing::new(MASTER.into()),
            PasswordSource::Own(Zeroizing::new(BACKUP_PW.into())),
            BackupPreferences::default(),
            Date::now(),
        )
        .unwrap()
}

/// The 1.1 data of this Mac (the swift-era fixture) and its Keychain items.
fn mac_with_old_data(tmp: &TempDir) -> (PathBuf, Arc<OldItems>) {
    let support = tmp.path().join("MacVPN");
    copy_tree(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/migration/swift-era"), &support);
    let old = Arc::new(OldItems::default());
    old.0.lock().unwrap().push((OPENVPN.into(), SecretField::Password));
    old.0.lock().unwrap().push((SYSTEM_SERVICE.into(), SecretField::Password));
    (support, old)
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_fresh_restore_over_1_1_data_deletes_it_and_the_next_launch_is_normal() {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let tmp = TempDir::new();
    let bytes = backup_from_elsewhere(&tmp);
    let (support, old) = mac_with_old_data(&tmp);
    let ks = Arc::new(MemoryKeyStore::new());
    let v = lifecycle(&support, ks.clone());
    let src = LegacySources::new(support.clone(), old.clone());
    assert_eq!(launch_decision(&v, || migration::has_legacy_data(&src)), LaunchDecision::Create { migrating: true });

    // The create window: the backup is opened, the vault created, the backup restored into it.
    let service =
        BackupService::new(v.clone(), Arc::new(FixedEntropy::new(9)), KdfParams::insecure_for_tests(), "1.2.0");
    service.open("vault-create", &bytes, Zeroizing::new(BACKUP_PW.into()), true).unwrap();
    v.create(Zeroizing::new(MASTER.into()), true).unwrap();
    service.apply_fresh("vault-create", &HashSet::new(), Date::now(), &NoPrefs).unwrap();
    // Then the 1.1 data goes (not imported), and the legacy mode ends.
    migration::discard_after_restore(&v, &src).unwrap();
    v.set_legacy_read_only(None);

    assert!(!migration::has_legacy_data(&src));
    assert!(src.marker_path().exists());
    assert!(!support.join("connections").exists(), "the old connection files are deleted");
    assert!(!support.join("connection-order.json").exists() && !support.join("system-otp.json").exists());
    assert!(old.items().is_empty(), "the old Keychain items are deleted");
    let names: Vec<String> =
        v.with_read(|vault| Ok(vault.connections()?.into_iter().map(|s| s.connection.name).collect())).unwrap();
    assert_eq!(names, ["From the backup"], "nothing of the 1.1 data was imported");

    // The next launch: auto-unlock, nothing pending, no legacy mode.
    drop(service);
    drop(v);
    let v2 = lifecycle(&support, ks);
    assert_eq!(launch_decision(&v2, || migration::has_legacy_data(&src)), LaunchDecision::Unlocked);
    assert_eq!(migration::pending(&v2, &src), PendingMigration::Nothing);
    assert_eq!(v2.state(), VaultState::Unlocked);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_vault_with_data_next_to_unmigrated_1_1_data_is_only_logged() {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let tmp = TempDir::new();
    let (support, old) = mac_with_old_data(&tmp);
    let v = lifecycle(&support, Arc::new(MemoryKeyStore::new()));
    v.create(Zeroizing::new(MASTER.into()), false).unwrap();
    let c = Connection::new("Own data", VPNKind::Openvpn);
    v.with(|vault| vault.save_connection(&c, Some("client\n"))).unwrap();
    let src = LegacySources::new(support.clone(), old.clone());

    assert!(migration::has_legacy_data(&src));
    assert_eq!(migration::pending(&v, &src), PendingMigration::VaultHasData);
    let report = migration::migrate(&v, &src).unwrap();
    assert!(report.vault_had_data, "a distinct outcome, not a failure");
    assert_eq!(v.state(), VaultState::Unlocked, "no legacy mode");
    assert!(support.join("connections").exists() && old.items().len() == 2, "nothing is deleted");
}
