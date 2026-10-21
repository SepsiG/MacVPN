//! The vault lifecycle (plan B Task 10, spec 2.3): create, auto-unlock, unlock with the password or the recovery
//! key and the growing delay, Lock now, change password, new recovery key and the auto-unlock switch. Fakes only:
//! `MemoryKeyStore`, `FixedEntropy`, the insecure test KDF parameters and fake `Instant`s.

mod common;

use common::TempDir;
use macvpn_app_core::vault::{AutoUnlock, UnlockError, VaultLifecycle, VaultState};
use macvpn_core::vault::{
    FixedEntropy, KEYS_FILE, KdfParams, KeyStore, KeyStoreError, MemoryKeyStore, RecoveryKey, VAULT_FILE, VaultError,
};
use serde_json::{Value, json};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const PASSWORD: &str = "correct horse battery";
const OTHER: &str = "another fine password";

struct Fixture {
    _tmp: TempDir,
    dir: PathBuf,
    keystore: Arc<MemoryKeyStore>,
    log: Arc<Mutex<Vec<String>>>,
}

impl Fixture {
    fn new() -> Fixture {
        let tmp = TempDir::new();
        let dir = tmp.path().join("MacVPN");
        Fixture { _tmp: tmp, dir, keystore: Arc::new(MemoryKeyStore::new()), log: Arc::default() }
    }

    fn lifecycle(&self) -> VaultLifecycle {
        let v = VaultLifecycle::new(
            self.dir.clone(),
            self.keystore.clone(),
            Arc::new(FixedEntropy::new(7)),
            KdfParams::insecure_for_tests(),
        );
        let log = self.log.clone();
        v.set_logger(move |line| log.lock().unwrap().push(line.to_string()));
        v
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn store_marker(v: &VaultLifecycle) {
    v.with(|vault| vault.save_control_clients(&[json!({ "id": "marker" })])).unwrap();
}

fn read_marker(v: &VaultLifecycle) -> Vec<Value> {
    v.with(|vault| vault.control_clients()).unwrap()
}

fn assert_no_secret_logged(f: &Fixture, secrets: &[&str]) {
    for line in f.log() {
        for s in secrets {
            assert!(!line.contains(s), "secret in log line {line:?}");
        }
    }
}

#[cfg(unix)]
#[test]
fn create_unlocks_writes_both_files_0600_and_the_auto_unlock_item() {
    let f = Fixture::new();
    let v = f.lifecycle();
    assert_eq!(v.state(), VaultState::NotCreated);
    let key = v.create(pw(PASSWORD), true).unwrap();
    assert_eq!(key.as_str().len(), 29);
    assert_eq!(v.state(), VaultState::Unlocked);
    assert_eq!(mode(&f.dir.join(KEYS_FILE)), 0o600);
    assert_eq!(mode(&f.dir.join(VAULT_FILE)), 0o600);
    assert_eq!(mode(&f.dir), 0o700);
    assert!(f.keystore.get().unwrap().is_some());
    assert!(v.auto_unlock());
    assert!(f.log().iter().any(|l| l == "created"));
    assert_no_secret_logged(&f, &[PASSWORD, key.as_str()]);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn create_without_auto_unlock_leaves_no_item() {
    let f = Fixture::new();
    let v = f.lifecycle();
    v.create(pw(PASSWORD), false).unwrap();
    assert!(f.keystore.get().unwrap().is_none());
    assert!(!v.auto_unlock());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn create_refuses_an_existing_vault_and_a_short_password() {
    let f = Fixture::new();
    let v = f.lifecycle();
    assert!(v.create(pw("short"), true).is_err());
    assert_eq!(v.state(), VaultState::NotCreated);
    v.create(pw(PASSWORD), true).unwrap();
    assert!(matches!(v.create(pw(PASSWORD), true), Err(VaultError::Io(_))));
    let fresh = f.lifecycle();
    assert!(fresh.create(pw(PASSWORD), true).is_err());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_failure_in_create_after_the_key_file_leaves_neither_file() {
    let f = Fixture::new();
    let v = f.lifecycle();
    v.fail_next_create_after_keys();
    assert!(v.create(pw(PASSWORD), true).is_err());
    assert!(!f.dir.join(KEYS_FILE).exists());
    assert!(!f.dir.join(VAULT_FILE).exists());
    assert_eq!(v.state(), VaultState::NotCreated);
    assert!(f.keystore.get().unwrap().is_none());
    // And it can be created afterwards.
    v.create(pw(PASSWORD), true).unwrap();
    assert_eq!(v.state(), VaultState::Unlocked);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_new_instance_auto_unlocks_from_the_key_store() {
    let f = Fixture::new();
    f.lifecycle().create(pw(PASSWORD), true).unwrap();
    let v = f.lifecycle();
    assert_eq!(v.state(), VaultState::Locked);
    assert_eq!(v.try_auto_unlock(), AutoUnlock::Unlocked);
    assert_eq!(v.state(), VaultState::Unlocked);
    assert!(f.log().iter().any(|l| l == "unlocked (auto)"));
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn auto_unlock_without_the_item_needs_the_password() {
    let f = Fixture::new();
    f.lifecycle().create(pw(PASSWORD), true).unwrap();
    f.keystore.delete().unwrap();
    let v = f.lifecycle();
    assert_eq!(v.try_auto_unlock(), AutoUnlock::NeedsPassword);
    assert_eq!(v.state(), VaultState::Locked);
}

#[test]
fn auto_unlock_with_no_vault_reports_not_created() {
    let f = Fixture::new();
    assert_eq!(f.lifecycle().try_auto_unlock(), AutoUnlock::NotCreated);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_denied_or_unavailable_key_store_needs_the_password() {
    let f = Fixture::new();
    f.lifecycle().create(pw(PASSWORD), true).unwrap();
    for error in [KeyStoreError::Denied, KeyStoreError::Unavailable("OSStatus -25308".into())] {
        f.keystore.fail_get(Some(error));
        let v = f.lifecycle();
        assert_eq!(v.try_auto_unlock(), AutoUnlock::NeedsPassword);
        assert_eq!(v.state(), VaultState::Locked);
    }
    f.keystore.fail_get(None);
    assert!(f.keystore.get().unwrap().is_some());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_stale_item_needs_the_password_and_is_not_deleted() {
    let f = Fixture::new();
    f.lifecycle().create(pw(PASSWORD), true).unwrap();
    f.keystore.set(&[0x55; 32]).unwrap();
    let v = f.lifecycle();
    assert_eq!(v.try_auto_unlock(), AutoUnlock::NeedsPassword);
    assert_eq!(f.keystore.get().unwrap().unwrap().as_slice(), &[0x55; 32]);
    // A malformed item too.
    f.keystore.set(&[1, 2, 3]).unwrap();
    assert_eq!(f.lifecycle().try_auto_unlock(), AutoUnlock::NeedsPassword);
    assert!(f.keystore.get().unwrap().is_some());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn wrong_passwords_are_delayed_1_2_4_seconds_and_too_soon_skips_argon2() {
    let f = Fixture::new();
    f.lifecycle().create(pw(PASSWORD), false).unwrap();
    let v = f.lifecycle();
    let t0 = Instant::now();

    let runs = v.kdf_runs();
    assert_eq!(
        v.unlock_with_password(pw(OTHER), t0).unwrap_err(),
        UnlockError::Wrong { retry_after: Duration::from_secs(1) }
    );
    assert_eq!(v.kdf_runs(), runs + 1);

    // Inside the delay: refused without running the KDF.
    let runs = v.kdf_runs();
    assert_eq!(
        v.unlock_with_password(pw(PASSWORD), t0 + Duration::from_millis(400)).unwrap_err(),
        UnlockError::TooSoon { retry_after: Duration::from_millis(600) }
    );
    assert_eq!(v.kdf_runs(), runs);

    let t1 = t0 + Duration::from_secs(1);
    assert_eq!(
        v.unlock_with_password(pw(OTHER), t1).unwrap_err(),
        UnlockError::Wrong { retry_after: Duration::from_secs(2) }
    );
    let t2 = t1 + Duration::from_secs(2);
    assert_eq!(
        v.unlock_with_password(pw(OTHER), t2).unwrap_err(),
        UnlockError::Wrong { retry_after: Duration::from_secs(4) }
    );
    assert!(matches!(
        v.unlock_with_password(pw(PASSWORD), t2 + Duration::from_secs(3)),
        Err(UnlockError::TooSoon { .. })
    ));
    assert_eq!(v.state(), VaultState::Locked);

    // The right password after the delay works and resets the count.
    let t3 = t2 + Duration::from_secs(4);
    v.unlock_with_password(pw(PASSWORD), t3).unwrap();
    assert_eq!(v.state(), VaultState::Unlocked);
    v.lock();
    assert_eq!(
        v.unlock_with_password(pw(OTHER), t3).unwrap_err(),
        UnlockError::Wrong { retry_after: Duration::from_secs(1) }
    );

    let log = f.log();
    assert!(log.iter().any(|l| l == "wrong password (attempt 1)"));
    assert!(log.iter().any(|l| l == "wrong password (attempt 3)"));
    assert!(log.iter().any(|l| l == "unlocked (password)"));
    assert_no_secret_logged(&f, &[PASSWORD, OTHER]);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn the_delay_doubles_up_to_30_seconds_with_no_lockout() {
    let f = Fixture::new();
    f.lifecycle().create(pw(PASSWORD), false).unwrap();
    let v = f.lifecycle();
    let mut now = Instant::now();
    let mut delays = Vec::new();
    for _ in 0..8 {
        match v.unlock_with_password(pw(OTHER), now).unwrap_err() {
            UnlockError::Wrong { retry_after } => {
                delays.push(retry_after.as_secs());
                now += retry_after;
            }
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(delays, [1, 2, 4, 8, 16, 30, 30, 30]);
    v.unlock_with_password(pw(PASSWORD), now).unwrap();
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn lock_closes_the_vault_and_keeps_the_key_store_item() {
    let f = Fixture::new();
    let v = f.lifecycle();
    v.create(pw(PASSWORD), true).unwrap();
    store_marker(&v);
    let states = Arc::new(Mutex::new(Vec::new()));
    let seen = states.clone();
    v.add_listener(move |s| seen.lock().unwrap().push(s));

    v.lock();
    assert_eq!(v.state(), VaultState::Locked);
    assert!(matches!(v.with(|vault| vault.control_clients()), Err(VaultError::Locked)));
    assert!(f.keystore.get().unwrap().is_some());
    assert!(v.auto_unlock());
    assert!(f.log().iter().any(|l| l == "locked"));
    // Turning auto-unlock on needs the key, which is gone.
    assert!(matches!(v.set_auto_unlock(true), Err(VaultError::Locked)));

    v.unlock_with_password(pw(PASSWORD), Instant::now()).unwrap();
    assert_eq!(read_marker(&v), [json!({ "id": "marker" })]);
    assert_eq!(*states.lock().unwrap(), [VaultState::Locked, VaultState::Unlocked]);

    // Auto-unlock still works after a lock.
    v.lock();
    assert_eq!(v.try_auto_unlock(), AutoUnlock::Unlocked);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn change_password_replaces_only_the_password() {
    let f = Fixture::new();
    let v = f.lifecycle();
    let key = v.create(pw(PASSWORD), false).unwrap();
    store_marker(&v);
    assert!(v.change_password(pw(PASSWORD), pw("short")).is_err());
    v.change_password(pw(PASSWORD), pw(OTHER)).unwrap();
    // The old password no longer counts as the current one (and the failure is delayed like an unlock).
    assert_eq!(v.change_password(pw(PASSWORD), pw("a third password")).unwrap_err(), wrong(1));
    assert!(matches!(v.change_password(pw(OTHER), pw("a third password")), Err(UnlockError::TooSoon { .. })));

    let v = f.lifecycle();
    let later = Instant::now() + Duration::from_secs(60);
    assert_eq!(v.unlock_with_password(pw(PASSWORD), later).unwrap_err(), wrong(1));
    v.unlock_with_password(pw(OTHER), later + Duration::from_secs(1)).unwrap();
    assert_eq!(read_marker(&v), [json!({ "id": "marker" })]);
    // The recovery key is unchanged.
    v.lock();
    v.reset_with_recovery(&key, pw("reset password one"), later + Duration::from_secs(2)).unwrap();
    assert_no_secret_logged(&f, &[PASSWORD, OTHER, key.as_str()]);
}

fn wrong(seconds: u64) -> UnlockError {
    UnlockError::Wrong { retry_after: Duration::from_secs(seconds) }
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn reset_with_recovery_sets_a_new_password_and_unlocks() {
    let f = Fixture::new();
    let key = f.lifecycle().create(pw(PASSWORD), true).unwrap();
    let item_before = f.keystore.get().unwrap().unwrap().to_vec();
    let v = f.lifecycle();
    let t0 = Instant::now();
    v.reset_with_recovery(&key, pw(OTHER), t0).unwrap();
    assert_eq!(v.state(), VaultState::Unlocked);
    // Auto-unlock was on: the item was rewritten, with the same DEK.
    assert_eq!(f.keystore.get().unwrap().unwrap().to_vec(), item_before);
    assert!(f.log().iter().any(|l| l == "unlocked (recovery key)"));

    let v = f.lifecycle();
    assert_eq!(v.unlock_with_password(pw(PASSWORD), t0).unwrap_err(), wrong(1));
    v.unlock_with_password(pw(OTHER), t0 + Duration::from_secs(1)).unwrap();
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_wrong_recovery_key_gives_the_same_error_and_shares_the_delay() {
    let f = Fixture::new();
    f.lifecycle().create(pw(PASSWORD), false).unwrap();
    let bogus = RecoveryKey::parse("0000-0000-0000-0000-0000-0000").unwrap();
    let v = f.lifecycle();
    let t0 = Instant::now();
    assert_eq!(v.reset_with_recovery(&bogus, pw(OTHER), t0).unwrap_err(), wrong(1));
    assert!(matches!(
        v.unlock_with_password(pw(PASSWORD), t0 + Duration::from_millis(10)),
        Err(UnlockError::TooSoon { .. })
    ));
    assert_eq!(v.unlock_with_password(pw(OTHER), t0 + Duration::from_secs(1)).unwrap_err(), wrong(2));
    // The password was not changed.
    v.unlock_with_password(pw(PASSWORD), t0 + Duration::from_secs(3)).unwrap();
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_new_recovery_key_counts_only_once_it_was_checked() {
    let f = Fixture::new();
    let v = f.lifecycle();
    let old = v.create(pw(PASSWORD), false).unwrap();
    // Made, not saved yet (review 1.2.0 M7): the old key still works until the new one's group check passed.
    let unsaved = v.new_recovery_key(pw(PASSWORD)).unwrap();
    assert_ne!(old.as_str(), unsaved.as_str());
    drop(unsaved);
    let w = f.lifecycle();
    w.reset_with_recovery(&old, pw(PASSWORD), Instant::now()).unwrap();
    w.lock();
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_new_recovery_key_invalidates_the_old_one() {
    let f = Fixture::new();
    let v = f.lifecycle();
    let old = v.create(pw(PASSWORD), false).unwrap();
    let new = v.new_recovery_key(pw(PASSWORD)).unwrap();
    v.save_recovery_key(&new).unwrap();
    assert_eq!(v.new_recovery_key(pw(OTHER)).unwrap_err(), wrong(1));
    assert_ne!(old.as_str(), new.as_str());

    let v = f.lifecycle();
    let t0 = Instant::now() + Duration::from_secs(60);
    assert_eq!(v.reset_with_recovery(&old, pw(OTHER), t0).unwrap_err(), wrong(1));
    v.reset_with_recovery(&new, pw(OTHER), t0 + Duration::from_secs(1)).unwrap();
    v.lock();
    v.unlock_with_password(pw(OTHER), t0 + Duration::from_secs(2)).unwrap();
    assert_no_secret_logged(&f, &[old.as_str(), new.as_str()]);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn set_auto_unlock_writes_and_deletes_the_item() {
    let f = Fixture::new();
    let v = f.lifecycle();
    v.create(pw(PASSWORD), true).unwrap();
    v.set_auto_unlock(false).unwrap();
    assert!(f.keystore.get().unwrap().is_none());
    assert!(!v.auto_unlock());
    v.set_auto_unlock(true).unwrap();
    assert!(f.keystore.get().unwrap().is_some());
    assert!(v.auto_unlock());
    assert_eq!(f.lifecycle().try_auto_unlock(), AutoUnlock::Unlocked);

    // A failing key store is reported and leaves the switch as it was.
    f.keystore.fail_delete(Some(KeyStoreError::Denied));
    assert!(v.set_auto_unlock(false).is_err());
    assert!(v.auto_unlock());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn verify_password_checks_without_changing_the_state() {
    let f = Fixture::new();
    let v = f.lifecycle();
    v.create(pw(PASSWORD), false).unwrap();
    let t0 = Instant::now();
    assert_eq!(v.verify_password(pw(OTHER), t0).unwrap_err(), wrong(1));
    v.verify_password(pw(PASSWORD), t0 + Duration::from_secs(1)).unwrap();
    assert_eq!(v.state(), VaultState::Unlocked);
}

#[test]
fn legacy_read_only_overrides_the_state_until_cleared() {
    let f = Fixture::new();
    let v = f.lifecycle();
    v.set_legacy_read_only(Some("migration failed".into()));
    assert_eq!(v.state(), VaultState::LegacyReadOnly { error: "migration failed".into() });
    v.set_legacy_read_only(None);
    assert_eq!(v.state(), VaultState::NotCreated);
}

// --- Review fixes ------------------------------------------------------------------------------------------------

/// A key store that counts the reads of the key (each may show the macOS prompt).
struct CountingStore {
    inner: MemoryKeyStore,
    gets: Mutex<u32>,
}

impl KeyStore for CountingStore {
    fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        *self.gets.lock().unwrap() += 1;
        self.inner.get()
    }
    fn exists(&self) -> Result<bool, KeyStoreError> {
        self.inner.exists()
    }
    fn set(&self, key: &[u8]) -> Result<(), KeyStoreError> {
        self.inner.set(key)
    }
    fn delete(&self) -> Result<(), KeyStoreError> {
        self.inner.delete()
    }
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn the_auto_unlock_switch_state_never_reads_the_key() {
    let f = Fixture::new();
    f.lifecycle().create(pw(PASSWORD), true).unwrap();
    let store = Arc::new(CountingStore { inner: MemoryKeyStore::new(), gets: Mutex::new(0) });
    store.inner.set(&[1; 32]).unwrap();
    let v = VaultLifecycle::new(
        f.dir.clone(),
        store.clone(),
        Arc::new(FixedEntropy::new(7)),
        KdfParams::insecure_for_tests(),
    );
    assert!(v.auto_unlock());
    assert_eq!(*store.gets.lock().unwrap(), 0, "no key read (no prompt) for the switch");
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_key_store_error_forgets_the_cached_switch_state() {
    let f = Fixture::new();
    let v = f.lifecycle();
    v.create(pw(PASSWORD), true).unwrap();
    assert!(v.auto_unlock());
    f.keystore.fail_delete(Some(KeyStoreError::Unavailable("test".into())));
    assert!(v.set_auto_unlock(false).is_err());
    f.keystore.fail_delete(None);
    // Changed behind our back: the next look asks the key store again.
    f.keystore.delete().unwrap();
    assert!(!v.auto_unlock());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn reset_with_recovery_while_unlocked_refuses_a_key_file_of_another_vault() {
    let f = Fixture::new();
    let v = f.lifecycle();
    v.create(pw(PASSWORD), false).unwrap();
    // Another vault's key file is put in place while this one is open.
    let other_dir = f.dir.with_file_name("Other");
    let other = VaultLifecycle::new(
        other_dir.clone(),
        Arc::new(MemoryKeyStore::new()),
        Arc::new(FixedEntropy::new(99)),
        KdfParams::insecure_for_tests(),
    );
    let other_key = other.create(pw(PASSWORD), false).unwrap();
    std::fs::copy(other_dir.join(KEYS_FILE), f.dir.join(KEYS_FILE)).unwrap();
    let before = std::fs::read(f.dir.join(KEYS_FILE)).unwrap();

    let result = v.reset_with_recovery(&other_key, pw(OTHER), Instant::now());

    assert_eq!(result, Err(UnlockError::Corrupt));
    assert_eq!(std::fs::read(f.dir.join(KEYS_FILE)).unwrap(), before, "nothing was saved");
    let _ = std::fs::remove_dir_all(&other_dir);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_vault_is_marked_as_created_for_the_migration_until_another_write() {
    let f = Fixture::new();
    let v = f.lifecycle();
    v.create(pw(PASSWORD), true).unwrap();
    assert!(v.created_for_migration());
    // Reads keep the mark.
    v.with_read(|vault| vault.control_clients()).unwrap();
    assert!(v.created_for_migration());
    // A write from anywhere else ends it.
    store_marker(&v);
    assert!(!v.created_for_migration());
    // A vault opened in a later session is not marked.
    let fresh = f.lifecycle();
    assert_eq!(fresh.try_auto_unlock(), AutoUnlock::Unlocked);
    assert!(!fresh.created_for_migration());
}
