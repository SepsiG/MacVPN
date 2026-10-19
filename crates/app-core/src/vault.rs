//! The vault lifecycle (spec 2.3, plan B Task 10): create, auto-unlock from the OS key store, unlock with the
//! master password or the recovery key, Lock now, change the password, a new recovery key and the auto-unlock
//! switch. The vault itself (database, key file, key store) is core's `macvpn_core::vault`; this is the state
//! machine around it that the app, the vault-backed stores (Task 11) and the vault windows (Tasks 14 and 15) use.
//!
//! States: `NotCreated` (no `vault.keys` / `vault.db`), `Locked` (the files exist, nothing open), `Unlocked` (the
//! database is open and the DEK is held in memory for the auto-unlock switch), and `LegacyReadOnly` (set by the
//! migration, Task 13, while the app runs from the 1.1 storage).
//!
//! Wrong attempts: after the n-th consecutive wrong password or recovery key the next attempt is refused for
//! `min(2^(n-1), 30)` seconds (1, 2, 4, 8, 16, 30, 30, …), in memory only and never a lockout. A refused attempt
//! ([`UnlockError::TooSoon`]) does not run Argon2id. A wrong password and a wrong recovery key are the same
//! [`UnlockError::Wrong`]. Success resets the count.
//!
//! Clock: the unlock calls take the caller's `now` (tests pass fake `Instant`s); the app (Task 14) must pass
//! `Instant::now()`, never a stored or computed instant, or the delay could be skipped.
//!
//! Migration (Task 13): `create` marks the new vault as the migration's; the first write through
//! [`VaultLifecycle::with`] (anything but the migration) or a successful migration ends the mark, and only a marked
//! vault can be discarded by a failed migration. So the app (Task 14) must run the migration right after `create`,
//! before any store writes to the vault.
//!
//! Secrets: passwords arrive as `Zeroizing<String>`, the DEK lives in core's `Dek` (wiped on drop), and nothing
//! here logs or formats key material. The log has events only: `created`, `unlocked (password|recovery key|auto)`,
//! `locked`, `wrong password (attempt n)`, and key-store status codes.

use macvpn_core::vault::{
    Dek, Entropy, KEYS_FILE, KdfParams, KeyError, KeyFile, KeyStore, RecoveryKey, VAULT_FILE, Vault, VaultError,
    check_password_rules,
};
use std::fmt;
use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// The longest delay between wrong attempts.
pub const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// Where the vault stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultState {
    /// No vault yet: the create window runs.
    NotCreated,
    /// The vault exists and is closed: the unlock window / the locked menu.
    Locked,
    Unlocked,
    /// The migration from the 1.1 storage failed: the app runs from the old storage, read-only (Task 13).
    LegacyReadOnly {
        error: String,
    },
}

/// Why an unlock (or a password check) failed. Carries no part of the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockError {
    /// A wrong password or recovery key; the next attempt is accepted after `retry_after`.
    Wrong { retry_after: Duration },
    /// The delay after a wrong attempt has not passed yet; nothing was checked.
    TooSoon { retry_after: Duration },
    /// `vault.keys` or `vault.db` is damaged (or the unwrapped key does not open the database).
    Corrupt,
    /// Written by a newer MacVPN that this build cannot read.
    NewerSchema,
    /// A file or key-store error, or a new password that breaks the rules (the localized message).
    Io(String),
}

impl fmt::Display for UnlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnlockError::Wrong { retry_after } => {
                write!(f, "wrong password or recovery key (retry after {} s)", retry_after.as_secs())
            }
            UnlockError::TooSoon { retry_after } => {
                write!(f, "too soon after a wrong attempt (retry after {} ms)", retry_after.as_millis())
            }
            UnlockError::Corrupt => f.write_str("the vault is damaged"),
            UnlockError::NewerSchema => f.write_str("the vault was written by a newer MacVPN"),
            UnlockError::Io(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for UnlockError {}

/// The result of the launch-time auto-unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoUnlock {
    Unlocked,
    /// No usable key-store item (missing, denied, unavailable, stale): show the unlock window.
    NeedsPassword,
    NotCreated,
}

type Listener = Arc<dyn Fn(VaultState) + Send + Sync>;
type Logger = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Default)]
struct Inner {
    vault: Option<Vault>,
    /// Held while unlocked, for turning auto-unlock on; dropped (wiped) by `lock`.
    dek: Option<Dek>,
    failures: u32,
    not_before: Option<Instant>,
    /// Whether the key-store item exists, once known.
    auto_unlock: Option<bool>,
    legacy: Option<String>,
    /// Test hook ([`VaultLifecycle::fail_next_create_after_keys`]); never set in a release build.
    #[cfg(any(test, feature = "test-support"))]
    fail_create_after_keys: bool,
    /// Set by `create` (and by the migration for a vault it finds empty), cleared by the first write that is not
    /// the migration's and by a successful migration: only such a vault may be discarded (Task 13).
    created_for_migration: bool,
}

/// The vault's lifecycle; share it as `Arc<VaultLifecycle>`.
///
/// Locking order: `ops` (one key-file operation at a time, held across Argon2id) before `inner` (held only
/// briefly, and across the closure of [`VaultLifecycle::with`]). Calling back into the lifecycle from inside
/// `with`'s closure or from a listener's state-change callback for `with` deadlocks; listeners themselves are
/// called with no lock held.
pub struct VaultLifecycle {
    dir: PathBuf,
    keystore: Arc<dyn KeyStore>,
    entropy: Arc<dyn Entropy>,
    kdf: KdfParams,
    ops: Mutex<()>,
    inner: Mutex<Inner>,
    listeners: Mutex<Vec<Listener>>,
    logger: Mutex<Logger>,
    kdf_runs: AtomicU64,
}

impl fmt::Debug for VaultLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultLifecycle").field("dir", &self.dir).finish_non_exhaustive()
    }
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The delay after the n-th consecutive wrong attempt (n ≥ 1).
fn retry_delay(failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(5);
    Duration::from_secs(1u64 << exponent).min(MAX_RETRY_DELAY)
}

fn key_error(e: KeyError) -> UnlockError {
    match e {
        KeyError::Wrong | KeyError::Corrupt => UnlockError::Corrupt,
        KeyError::UnsupportedVersion(_) => UnlockError::NewerSchema,
        KeyError::Io(e) => UnlockError::Io(e.to_string()),
    }
}

fn open_error(e: VaultError) -> UnlockError {
    match e {
        VaultError::WrongKey | VaultError::Corrupt(_) => UnlockError::Corrupt,
        VaultError::NewerSchema { .. } => UnlockError::NewerSchema,
        other => UnlockError::Io(other.to_string()),
    }
}

/// Compares two keys without an early exit.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let diff = a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

fn rules(password: &str) -> Result<(), String> {
    check_password_rules(password)
}

fn remove_vault_files(dir: &Path) {
    let _ = fs::remove_file(dir.join(KEYS_FILE));
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let _ = fs::remove_file(dir.join(format!("{VAULT_FILE}{suffix}")));
    }
}

impl VaultLifecycle {
    /// `dir` is the app-data directory (`~/Library/Application Support/MacVPN`); `kdf` the parameters for new
    /// wraps (`KdfParams::DEFAULT` in the app, raised to at least that by core anyway).
    pub fn new(dir: PathBuf, keystore: Arc<dyn KeyStore>, entropy: Arc<dyn Entropy>, kdf: KdfParams) -> Self {
        let logger: Logger = Arc::new(|line: &str| eprintln!("MacVPN: Vault: {line}"));
        VaultLifecycle {
            dir,
            keystore,
            entropy,
            kdf,
            ops: Mutex::new(()),
            inner: Mutex::new(Inner::default()),
            listeners: Mutex::new(Vec::new()),
            logger: Mutex::new(logger),
            kdf_runs: AtomicU64::new(0),
        }
    }

    /// Replaces the event log sink (default: stderr, the app log, with the source "Vault"). Lines never carry
    /// key material.
    pub fn set_logger(&self, f: impl Fn(&str) + Send + Sync + 'static) {
        *guard(&self.logger) = Arc::new(f);
    }

    pub(crate) fn log(&self, line: &str) {
        let logger = guard(&self.logger).clone();
        logger(line);
    }

    /// The vault directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Whether `vault.keys` or `vault.db` exists.
    pub fn exists(&self) -> bool {
        self.dir.join(KEYS_FILE).symlink_metadata().is_ok() || self.dir.join(VAULT_FILE).symlink_metadata().is_ok()
    }

    pub fn state(&self) -> VaultState {
        let inner = guard(&self.inner);
        self.state_of(&inner)
    }

    fn state_of(&self, inner: &Inner) -> VaultState {
        if let Some(error) = &inner.legacy {
            return VaultState::LegacyReadOnly { error: error.clone() };
        }
        if inner.vault.is_some() {
            VaultState::Unlocked
        } else if self.exists() {
            VaultState::Locked
        } else {
            VaultState::NotCreated
        }
    }

    /// The key store of the automatic unlock (the uninstall deletes its item with the user data).
    pub fn key_store(&self) -> &Arc<dyn KeyStore> {
        &self.keystore
    }

    pub fn is_unlocked(&self) -> bool {
        guard(&self.inner).vault.is_some()
    }

    /// Calls every listener with the current state, with no lock held.
    fn notify(&self) {
        let state = self.state();
        let listeners = guard(&self.listeners).clone();
        for listener in listeners {
            listener(state.clone());
        }
    }

    /// Called with the new state after every change (create, unlock, lock, the legacy mode).
    pub fn add_listener(&self, f: impl Fn(VaultState) + Send + Sync + 'static) {
        guard(&self.listeners).push(Arc::new(f));
    }

    /// The migration (Task 13) enters (`Some(error)`) or leaves (`None`) the legacy read-only mode.
    pub fn set_legacy_read_only(&self, error: Option<String>) {
        guard(&self.inner).legacy = error;
        self.notify();
    }

    /// The migration (Task 13) gives up on a vault it just filled: closes it, removes `vault.keys` and `vault.db`
    /// (with the WAL files) and the key-store item. Refused (`false`, nothing changes) unless the vault is still
    /// marked as created for the migration, so a vault with the user's own data is never removed.
    pub(crate) fn discard(&self) -> bool {
        let _op = guard(&self.ops);
        {
            let mut inner = guard(&self.inner);
            if !inner.created_for_migration || inner.vault.is_none() {
                drop(inner);
                self.log("discard refused: the vault is not a fresh one of the migration");
                return false;
            }
            inner.created_for_migration = false;
            drop(inner.dek.take());
            if let Some(vault) = inner.vault.take() {
                vault.close();
            }
            inner.auto_unlock = None;
        }
        remove_vault_files(&self.dir);
        if let Err(e) = self.keystore.delete() {
            self.log(&format!("key store: {e}"));
        }
        self.log("discarded");
        self.notify();
        true
    }

    /// Whether the open vault is still the fresh one `create` made for the migration (no other write yet).
    pub fn created_for_migration(&self) -> bool {
        guard(&self.inner).created_for_migration
    }

    /// The migration (Task 13): checks that the open vault is empty and, if so, marks it as the migration's (a
    /// vault created in an earlier session holds nothing to lose either). `Ok(false)` when it holds data.
    pub(crate) fn claim_empty_for_migration(&self) -> Result<bool, VaultError> {
        let mut inner = guard(&self.inner);
        let empty = inner.vault.as_ref().ok_or(VaultError::Locked)?.is_empty()?;
        if empty {
            inner.created_for_migration = true;
        }
        Ok(empty)
    }

    /// A successful migration: the vault now holds the user's data.
    pub(crate) fn end_migration_mark(&self) {
        guard(&self.inner).created_for_migration = false;
    }

    // MARK: - Create

    /// Creates a new vault with `password` (at least `MIN_PASSWORD_CHARS` characters) and unlocks it. Writes
    /// `vault.keys` first, then `vault.db`; on any failure neither is left. With `auto_unlock` the DEK goes to the
    /// key store (a key-store failure is logged and leaves auto-unlock off; the vault is still created).
    /// Returns the recovery key, to be shown once.
    pub fn create(&self, password: Zeroizing<String>, auto_unlock: bool) -> Result<RecoveryKey, VaultError> {
        rules(&password).map_err(|m| VaultError::Io(io::Error::new(io::ErrorKind::InvalidInput, m)))?;
        let _op = guard(&self.ops);
        if self.exists() {
            return Err(VaultError::Io(io::Error::new(io::ErrorKind::AlreadyExists, "a vault already exists")));
        }
        DirBuilder::new().recursive(true).mode(0o700).create(&self.dir)?;
        let dek = Dek::generate(self.entropy.as_ref())?;
        let key = RecoveryKey::generate(self.entropy.as_ref())?;
        self.kdf_runs.fetch_add(2, Ordering::Relaxed);
        let key_file = KeyFile::create(&dek, &password, &key, self.kdf, self.entropy.as_ref())?;
        drop(password);
        let result = key_file.save(&self.dir).map_err(VaultError::from).and_then(|()| {
            let vault = Vault::create(&self.dir, &dek)?;
            #[cfg(any(test, feature = "test-support"))]
            if std::mem::take(&mut guard(&self.inner).fail_create_after_keys) {
                vault.close();
                return Err(VaultError::Io(io::Error::other("injected failure")));
            }
            Ok(vault)
        });
        let vault = match result {
            Ok(vault) => vault,
            Err(e) => {
                remove_vault_files(&self.dir);
                return Err(e);
            }
        };
        let stored = if auto_unlock { self.keystore.set(dek.as_bytes()) } else { self.keystore.delete() };
        if let Err(e) = &stored {
            self.log(&format!("key store: {e}"));
        }
        {
            let mut inner = guard(&self.inner);
            inner.vault = Some(vault);
            inner.dek = Some(dek);
            inner.failures = 0;
            inner.not_before = None;
            // A key-store error leaves the state unknown (asked again next time).
            inner.auto_unlock = if stored.is_ok() { Some(auto_unlock) } else { None };
            inner.created_for_migration = true;
        }
        self.log("created");
        self.notify();
        Ok(key)
    }

    /// Test hook: the next `create` fails after both files were written.
    #[cfg(any(test, feature = "test-support"))]
    pub fn fail_next_create_after_keys(&self) {
        guard(&self.inner).fail_create_after_keys = true;
    }

    // MARK: - Unlock

    /// At launch: open the vault with the DEK from the key store (which reads without UI first, and shows the
    /// macOS prompt only when needed). A missing, denied, unavailable or stale item gives `NeedsPassword`; a
    /// stale item is **not** deleted.
    pub fn try_auto_unlock(&self) -> AutoUnlock {
        let _op = guard(&self.ops);
        if self.is_unlocked() {
            return AutoUnlock::Unlocked;
        }
        if !self.exists() {
            return AutoUnlock::NotCreated;
        }
        let bytes = match self.keystore.get() {
            Ok(Some(bytes)) => bytes,
            Ok(None) => {
                guard(&self.inner).auto_unlock = Some(false);
                return AutoUnlock::NeedsPassword;
            }
            Err(e) => {
                guard(&self.inner).auto_unlock = None;
                self.log(&format!("auto-unlock unavailable: {e}"));
                return AutoUnlock::NeedsPassword;
            }
        };
        guard(&self.inner).auto_unlock = Some(true);
        let Some(dek) = Dek::from_bytes(&bytes) else {
            self.log("auto-unlock key does not open the vault");
            return AutoUnlock::NeedsPassword;
        };
        drop(bytes);
        match Vault::open(&self.dir, &dek) {
            Ok(vault) => {
                self.install(vault, dek, "auto");
                AutoUnlock::Unlocked
            }
            Err(e) => {
                let reason =
                    if matches!(e, VaultError::WrongKey) { "does not open the vault".into() } else { e.to_string() };
                self.log(&format!("auto-unlock key {reason}"));
                AutoUnlock::NeedsPassword
            }
        }
    }

    /// Unlocks with the master password. `now` is the caller's clock (the delay). Already unlocked: the password
    /// is still checked, and `Ok` means it is right.
    pub fn unlock_with_password(&self, password: Zeroizing<String>, now: Instant) -> Result<(), UnlockError> {
        let _op = guard(&self.ops);
        let (_, dek) = self.attempt(now, |k| k.unlock_password(&password))?;
        drop(password);
        if self.is_unlocked() {
            return Ok(());
        }
        let vault = Vault::open(&self.dir, &dek).map_err(open_error)?;
        self.install(vault, dek, "password");
        Ok(())
    }

    /// Checks the master password (with the same delay) without changing anything: Task 15's "confirm" mode
    /// before turning auto-unlock on.
    pub fn verify_password(&self, password: Zeroizing<String>, now: Instant) -> Result<(), UnlockError> {
        let _op = guard(&self.ops);
        self.attempt(now, |k| k.unlock_password(&password)).map(drop)
    }

    /// Opens the recovery slot, sets `new_password` as the master password, saves `vault.keys` and unlocks. With
    /// auto-unlock on, the key-store item is written again (same DEK).
    pub fn reset_with_recovery(
        &self,
        key: &RecoveryKey,
        new_password: Zeroizing<String>,
        now: Instant,
    ) -> Result<(), UnlockError> {
        rules(&new_password).map_err(UnlockError::Io)?;
        let _op = guard(&self.ops);
        let (mut key_file, dek) = self.attempt(now, |k| k.unlock_recovery(key))?;
        let open_dek_matches = {
            let inner = guard(&self.inner);
            inner.dek.as_ref().map(|open| constant_time_eq(open.as_bytes(), dek.as_bytes()))
        };
        let vault = match open_dek_matches {
            // Unlocked: the key file must belong to the open vault (else it was swapped; never save over it).
            Some(true) => None,
            Some(false) => {
                self.log("the key file does not match the open vault");
                return Err(UnlockError::Corrupt);
            }
            None => Some(Vault::open(&self.dir, &dek).map_err(open_error)?),
        };
        self.kdf_runs.fetch_add(1, Ordering::Relaxed);
        key_file
            .set_password(&dek, &new_password, self.entropy.as_ref())
            .map_err(|e| UnlockError::Io(e.to_string()))?;
        drop(new_password);
        key_file.save(&self.dir).map_err(|e| UnlockError::Io(e.to_string()))?;
        self.log("master password reset with the recovery key");
        if self.auto_unlock()
            && let Err(e) = self.keystore.set(dek.as_bytes())
        {
            guard(&self.inner).auto_unlock = None;
            self.log(&format!("key store: {e}"));
        }
        if let Some(vault) = vault {
            self.install(vault, dek, "recovery key");
        }
        Ok(())
    }

    /// One guarded attempt: refuses inside the delay (without running Argon2id), loads `vault.keys`, runs
    /// `unwrap`, and counts a wrong secret. Called with `ops` held.
    fn attempt(
        &self,
        now: Instant,
        unwrap: impl FnOnce(&KeyFile) -> Result<Dek, KeyError>,
    ) -> Result<(KeyFile, Dek), UnlockError> {
        if let Some(not_before) = guard(&self.inner).not_before
            && now < not_before
        {
            return Err(UnlockError::TooSoon { retry_after: not_before - now });
        }
        let key_file = KeyFile::load(&self.dir).map_err(key_error)?;
        self.kdf_runs.fetch_add(1, Ordering::Relaxed);
        match unwrap(&key_file) {
            Ok(dek) => {
                let mut inner = guard(&self.inner);
                inner.failures = 0;
                inner.not_before = None;
                Ok((key_file, dek))
            }
            Err(KeyError::Wrong) => {
                let (failures, delay) = {
                    let mut inner = guard(&self.inner);
                    inner.failures = inner.failures.saturating_add(1);
                    let delay = retry_delay(inner.failures);
                    inner.not_before = Some(now + delay);
                    (inner.failures, delay)
                };
                self.log(&format!("wrong password (attempt {failures})"));
                Err(UnlockError::Wrong { retry_after: delay })
            }
            Err(e) => Err(key_error(e)),
        }
    }

    fn install(&self, vault: Vault, dek: Dek, how: &str) {
        {
            let mut inner = guard(&self.inner);
            inner.vault = Some(vault);
            inner.dek = Some(dek);
            inner.created_for_migration = false;
        }
        self.log(&format!("unlocked ({how})"));
        self.notify();
    }

    /// The number of Argon2id runs so far (test hook: a refused attempt must not run it).
    #[cfg(any(test, feature = "test-support"))]
    pub fn kdf_runs(&self) -> u64 {
        self.kdf_runs.load(Ordering::Relaxed)
    }

    // MARK: - Lock

    /// Lock now: closes the database and wipes the DEK from memory. The key-store item stays (the next launch
    /// still auto-unlocks); running VPNs are the manager's business (Task 11).
    pub fn lock(&self) {
        let was_open = {
            let mut inner = guard(&self.inner);
            drop(inner.dek.take());
            match inner.vault.take() {
                Some(vault) => {
                    vault.close();
                    true
                }
                None => false,
            }
        };
        if was_open {
            self.log("locked");
            self.notify();
        }
    }

    // MARK: - Password and recovery key

    /// Changes the master password: `current` must be right (the wrong-attempt delay applies, with the real
    /// clock); only the password slot is rewritten, the database is not re-encrypted.
    pub fn change_password(&self, current: Zeroizing<String>, new: Zeroizing<String>) -> Result<(), UnlockError> {
        rules(&new).map_err(UnlockError::Io)?;
        let _op = guard(&self.ops);
        let (mut key_file, dek) = self.attempt(Instant::now(), |k| k.unlock_password(&current))?;
        drop(current);
        self.kdf_runs.fetch_add(1, Ordering::Relaxed);
        key_file.set_password(&dek, &new, self.entropy.as_ref()).map_err(|e| UnlockError::Io(e.to_string()))?;
        drop(new);
        key_file.save(&self.dir).map_err(|e| UnlockError::Io(e.to_string()))?;
        self.log("master password changed");
        Ok(())
    }

    /// A new recovery key (to be shown once): `password` must be right (delay as in `change_password`); the old
    /// key stops working.
    pub fn new_recovery_key(&self, password: Zeroizing<String>) -> Result<RecoveryKey, UnlockError> {
        let _op = guard(&self.ops);
        let (_key_file, dek) = self.attempt(Instant::now(), |k| k.unlock_password(&password))?;
        drop(password);
        drop(dek);
        RecoveryKey::generate(self.entropy.as_ref()).map_err(|e| UnlockError::Io(e.to_string()))
    }

    /// Saves a key made by [`Self::new_recovery_key`] once the user retyped its group: from now on it opens the
    /// vault and the old key does not. The vault must be unlocked (its key wraps the new recovery key).
    pub fn save_recovery_key(&self, key: &RecoveryKey) -> Result<(), UnlockError> {
        let _op = guard(&self.ops);
        let dek = {
            let inner = guard(&self.inner);
            inner.dek.as_ref().and_then(|d| Dek::from_bytes(d.as_bytes()))
        };
        let dek = dek.ok_or_else(|| UnlockError::Io("the vault is locked".into()))?;
        let mut key_file = KeyFile::load(&self.dir).map_err(key_error)?;
        self.kdf_runs.fetch_add(1, Ordering::Relaxed);
        key_file.set_recovery(&dek, key, self.entropy.as_ref()).map_err(|e| UnlockError::Io(e.to_string()))?;
        key_file.save(&self.dir).map_err(|e| UnlockError::Io(e.to_string()))?;
        self.log("new recovery key");
        Ok(())
    }

    // MARK: - Auto-unlock

    /// On: stores the DEK in the key store (the vault must be unlocked, else `Locked`). Off: deletes the item.
    /// A key-store failure is returned and leaves the switch as it was.
    pub fn set_auto_unlock(&self, on: bool) -> Result<(), VaultError> {
        let _op = guard(&self.ops);
        let result = if on {
            // A copy of the key (wiped on drop), so the key store is not called with `inner` held.
            let key: Zeroizing<[u8; 32]> = {
                let inner = guard(&self.inner);
                Zeroizing::new(*inner.dek.as_ref().ok_or(VaultError::Locked)?.as_bytes())
            };
            self.keystore.set(&key[..])
        } else {
            self.keystore.delete()
        };
        if let Err(e) = result {
            guard(&self.inner).auto_unlock = None;
            return Err(VaultError::Io(io::Error::other(e.to_string())));
        }
        guard(&self.inner).auto_unlock = Some(on);
        self.log(if on { "auto-unlock on" } else { "auto-unlock off" });
        Ok(())
    }

    /// Whether the key-store item exists: cached after the first look, which checks only that the item exists
    /// (never reads the key, never shows a prompt). A key-store error counts as off and is not cached.
    pub fn auto_unlock(&self) -> bool {
        if let Some(on) = guard(&self.inner).auto_unlock {
            return on;
        }
        match self.keystore.exists() {
            Ok(on) => {
                guard(&self.inner).auto_unlock = Some(on);
                on
            }
            Err(_) => false,
        }
    }

    // MARK: - Access

    /// Runs `f` on the open vault; `Locked` while locked. Do not call back into the lifecycle from `f`. `f` may
    /// write, so the vault stops being the migration's fresh one ([`Self::created_for_migration`]); use
    /// [`Self::with_read`] for reads. `ReadOnly` in the legacy read-only mode: until the migration succeeds only
    /// its own writes reach the new vault ([`Self::with_migration`]), so no other write can block it.
    pub fn with<R>(&self, f: impl FnOnce(&mut Vault) -> Result<R, VaultError>) -> Result<R, VaultError> {
        let mut inner = guard(&self.inner);
        if inner.legacy.is_some() {
            return Err(VaultError::ReadOnly);
        }
        inner.created_for_migration = false;
        match inner.vault.as_mut() {
            Some(vault) => f(vault),
            None => Err(VaultError::Locked),
        }
    }

    /// Runs `f` on the open vault for reading only; `Locked` while locked.
    pub fn with_read<R>(&self, f: impl FnOnce(&Vault) -> Result<R, VaultError>) -> Result<R, VaultError> {
        let inner = guard(&self.inner);
        match inner.vault.as_ref() {
            Some(vault) => f(vault),
            None => Err(VaultError::Locked),
        }
    }

    /// [`Self::with`] for the migration's own writes (and the create window's first-run restore, which replaces
    /// the migration): keeps the mark, and works in the legacy read-only mode.
    pub(crate) fn with_migration<R>(
        &self,
        f: impl FnOnce(&mut Vault) -> Result<R, VaultError>,
    ) -> Result<R, VaultError> {
        let mut inner = guard(&self.inner);
        match inner.vault.as_mut() {
            Some(vault) => f(vault),
            None => Err(VaultError::Locked),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use macvpn_core::vault::{FixedEntropy, MemoryKeyStore};

    fn lifecycle(dir: &Path) -> VaultLifecycle {
        let v = VaultLifecycle::new(
            dir.to_path_buf(),
            Arc::new(MemoryKeyStore::new()),
            Arc::new(FixedEntropy::new(5)),
            KdfParams::insecure_for_tests(),
        );
        v.set_logger(|_| {});
        v
    }

    #[test]
    fn discard_removes_only_a_vault_still_fresh_for_the_migration() {
        let tmp = std::env::temp_dir().join(format!("macvpn-app-core-unit-{}", uuid::Uuid::new_v4()));
        let dir = tmp.join("MacVPN");
        let v = lifecycle(&dir);
        v.create(Zeroizing::new("correct horse battery".into()), true).unwrap();
        // Written by something else: kept.
        v.with(|vault| vault.set_secret("A", macvpn_core::models::SecretField::Psk, "x")).unwrap();
        assert!(!v.discard());
        assert!(dir.join(KEYS_FILE).exists() && dir.join(VAULT_FILE).exists());
        assert_eq!(v.state(), VaultState::Unlocked);
        // Locked: nothing to discard either.
        v.lock();
        assert!(!v.discard());
        assert!(dir.join(VAULT_FILE).exists());
        let _ = fs::remove_dir_all(&tmp);

        let dir = tmp.join("Fresh");
        let v = lifecycle(&dir);
        v.create(Zeroizing::new("correct horse battery".into()), true).unwrap();
        assert!(v.discard());
        assert!(!dir.join(KEYS_FILE).exists() && !dir.join(VAULT_FILE).exists());
        assert_eq!(v.state(), VaultState::NotCreated);
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn the_delay_doubles_and_caps_at_30_seconds() {
        let delays: Vec<u64> = (1..=9).map(|n| retry_delay(n).as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 30, 30, 30, 30]);
        assert_eq!(retry_delay(u32::MAX), MAX_RETRY_DELAY);
    }
}
