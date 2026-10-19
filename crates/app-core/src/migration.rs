//! The migration from the 1.1 storage into the vault (spec 2.7, plan B Task 13).
//!
//! Sources: the connection directories (`connections/<UUID>/{meta.json,config}`), the Keychain items of
//! `local.macvpn.secrets` (through [`LegacyKeychain`]), `connection-order.json`, `system-otp.json` and the control
//! API's `control-clients.json`. Steps, in order:
//!
//! 1. **Read** everything into memory (configs and secrets in wiped buffers). A connection directory whose
//!    `meta.json` does not decode (or whose config is not UTF-8) is reported in [`MigrationReport::skipped`] and
//!    left on disk with its Keychain items; so is a ranking, OTP or registry file that does not decode. A Keychain
//!    item that cannot be read (access denied or cancelled, a locked keychain) fails the step, so the user can
//!    retry; one that holds no UTF-8 or disappeared between the listing and the read is skipped and left alone.
//! 2. **Import** in one vault transaction.
//! 3. **Verify**: every record is read back and compared with the source. The config bytes and each secret are
//!    compared byte for byte with what was read; the stored `meta_json` is compared byte for byte with the
//!    canonical re-encoding of the decoded `meta.json` (not with the file's own bytes: a Swift-era file is
//!    re-encoded on import) and must decode to the same connection; the ranking, the OTP settings and the paired
//!    clients are compared by value; the row counts must match too.
//! 4. **Delete files**: each old file is overwritten with zeros and unlinked ([`store::shred_file`]), then the
//!    empty directories are removed. Only the known shapes are ever deleted (`connections/<UUID>/meta.json`,
//!    `connections/<UUID>/config`, `connection-order.json`, `system-otp.json`, `control-clients.json`, the
//!    directories `connections/<UUID>` and `connections`), and only when every parent is a real directory (no
//!    symlink is followed).
//! 5. **Delete Keychain** items, each one, and check that they are gone.
//! 6. Write the **marker** `migrated-to-vault` (0600).
//!
//! The vault must be unlocked and empty. A failure in steps 1–3 deletes nothing: the new vault is closed and
//! removed (with its key-store item), and the lifecycle enters
//! [`VaultState::LegacyReadOnly`](crate::vault::VaultState) until the user retries. The vault is removed only
//! while it is still the migration's own ([`VaultLifecycle::created_for_migration`]): a write from anywhere else
//! keeps it, so **the app (Task 14) runs `migrate` right after `create`, before any store writes to the vault**. Before step 4
//! the list of what is to be deleted is saved as `migration-cleanup` (0600); a failure in steps 4–6 keeps the
//! verified vault in use and leaves that list, and the next [`migrate`] only finishes the deletion (it refuses if
//! the vault is gone, or is unlocked and empty). The marker is written only after both deletions are done.
//! A journal (`migration-in-progress`) is written before the import and removed once the list is saved: a quit in
//! between is found by the next [`migrate`], which reads the old data again, verifies the vault against it, and only
//! then saves the list and deletes.
//!
//! The paired control-API clients are imported as the raw JSON objects of `control-clients.json`, as the 1.1
//! `control::registry::Registry` wrote them; the control API keeps reading that file until the vault-backed
//! registry store replaces it (plan B Task 11).
//!
//! The log has counts and step names only; error messages name files, item ids and what differs, never a value.

use crate::vault::VaultLifecycle;
use macvpn_core::models::{Connection, OTPSetting, SecretField, parse_uuid, uuid_string};
use macvpn_core::ranking::{ConnectionRanking, ConnectionRankingStore};
use macvpn_core::store::{self, ConnectionStore, write_private};
use macvpn_core::swift_json;
use macvpn_core::system_otp::SystemOTPStore;
use macvpn_core::vault::{Vault, VaultError};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

pub use macvpn_core::vault::{LegacyKeychain, LegacyRead};

/// Written into the support directory when the migration is complete.
pub const MARKER: &str = "migrated-to-vault";
/// The deletion still to be done after a verified import (steps 4–6), one entry per line.
pub const CLEANUP_FILE: &str = "migration-cleanup";
/// The journal written before the import and replaced by the cleanup list: a quit in between (the import
/// committed, the list not written yet) is found at the next run, which verifies the vault against the old data
/// again and finishes.
pub const JOURNAL_FILE: &str = "migration-in-progress";
/// The control API's paired clients (1.1): the registry's own file name, below the support directory.
pub const REGISTRY_FILE: &str = macvpn_core::control::registry::FILE_NAME;

/// Where the 1.1 data lives.
pub struct LegacySources {
    /// `~/Library/Application Support/MacVPN` (the marker and the cleanup list go here).
    pub support_dir: PathBuf,
    pub store: Arc<ConnectionStore>,
    pub keychain: Arc<dyn LegacyKeychain>,
    pub ranking: ConnectionRankingStore,
    pub system_otp: SystemOTPStore,
    /// `control-clients.json`.
    pub registry_path: PathBuf,
}

impl LegacySources {
    /// The default layout below `support_dir`.
    pub fn new(support_dir: PathBuf, keychain: Arc<dyn LegacyKeychain>) -> Self {
        LegacySources {
            store: Arc::new(ConnectionStore::new(support_dir.join("connections"))),
            keychain,
            ranking: ConnectionRankingStore::new(ConnectionRankingStore::default_path(&support_dir)),
            system_otp: SystemOTPStore::new(SystemOTPStore::default_path(&support_dir)),
            // Where the 1.1 control API keeps it (`ControlApp::registry_dir` is the support directory).
            registry_path: macvpn_core::control::registry::Registry::path(&support_dir),
            support_dir,
        }
    }

    pub fn marker_path(&self) -> PathBuf {
        self.support_dir.join(MARKER)
    }

    fn cleanup_path(&self) -> PathBuf {
        self.support_dir.join(CLEANUP_FILE)
    }

    fn journal_path(&self) -> PathBuf {
        self.support_dir.join(JOURNAL_FILE)
    }
}

/// The steps, in order (also the failure-injection points of the tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStep {
    Read,
    Import,
    Verify,
    DeleteFiles,
    DeleteKeychain,
    Marker,
}

impl MigrationStep {
    /// A stable name for the log.
    pub fn as_str(self) -> &'static str {
        match self {
            MigrationStep::Read => "read",
            MigrationStep::Import => "import",
            MigrationStep::Verify => "verify",
            MigrationStep::DeleteFiles => "delete files",
            MigrationStep::DeleteKeychain => "delete keychain",
            MigrationStep::Marker => "marker",
        }
    }
}

/// What was migrated. A resumed run (only the deletion) has zero counts and `resumed`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    pub connections: usize,
    pub secrets: usize,
    /// Enabled system-VPN OTP settings.
    pub system_otp: usize,
    /// Paired control-API clients.
    pub clients: usize,
    /// What was left on disk (or in the Keychain) because it could not be read; no values.
    pub skipped: Vec<String>,
    pub resumed: bool,
    /// Nothing was done: the vault already holds the user's data (a restore, or data written before the 1.1 data
    /// turned up) and no migration of this data was started. The 1.1 data is left alone; not a failure.
    pub vault_had_data: bool,
}

/// What a launch finds of the migration (before deciding whether to show it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingMigration {
    /// No 1.1 data, or the migration is complete.
    Nothing,
    /// A migration to run or to finish (an empty vault, a journal or a cleanup list): shown in the create window.
    Run,
    /// The vault holds data and none of the 1.1 data was ever imported: only logged, never shown.
    VaultHasData,
}

/// What [`migrate`] would do now.
pub fn pending(vault: &VaultLifecycle, src: &LegacySources) -> PendingMigration {
    if !has_legacy_data(src) {
        return PendingMigration::Nothing;
    }
    if exists(&src.cleanup_path()) || exists(&src.journal_path()) {
        return PendingMigration::Run;
    }
    match vault.with_read(|v| v.is_empty()) {
        Ok(false) => PendingMigration::VaultHasData,
        _ => PendingMigration::Run,
    }
}

/// After a first-run restore over 1.1 data (the create window said the 1.1 data is not imported): the old data is
/// deleted like the migration's (known shapes only, no symlink followed; the old Keychain items, listed but never
/// read) and the marker is written, so no later launch offers a migration. The list is saved first: a quit in
/// between is finished by the next [`migrate`]. Call it only after the restore succeeded.
pub fn discard_after_restore(vault: &VaultLifecycle, src: &LegacySources) -> Result<MigrationReport, MigrationError> {
    if exists(&src.marker_path()) {
        return Ok(MigrationReport::default());
    }
    let mut data = LegacyData::default();
    read_connections(src, &mut data).map_err(MigrationError::Refused)?;
    for (item, field) in src.keychain.items() {
        if let Some(id) = parse_uuid(&item).filter(|id| uuid_string(id) == item) {
            data.keychain.push((id, field));
        }
    }
    for (path, file) in [
        (&src.ranking.path, OldFile::Ranking),
        (&src.system_otp.path, OldFile::SystemOtp),
        (&src.registry_path, OldFile::Registry),
    ] {
        if exists(path) {
            data.files.push(file);
        }
    }
    let cleanup = data.cleanup();
    cleanup.save(src).map_err(|e| MigrationError::Refused(format!("the list of old files could not be saved: {e}")))?;
    let _ = fs::remove_file(src.journal_path());
    vault.log("restore: the 1.1 data is deleted, not imported");
    finish(vault, src, cleanup, None, MigrationReport { resumed: true, ..MigrationReport::default() })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationError {
    /// Nothing was started and nothing changed: the vault is locked, missing or already holds data, or the
    /// cleanup list is damaged.
    Refused(String),
    /// A step failed. Before [`MigrationStep::DeleteFiles`] the vault was removed and the app runs from the old
    /// storage, read-only ([`MigrationError::legacy_read_only`]); from there on the vault stays in use and the
    /// next run finishes the deletion.
    Failed { step: MigrationStep, message: String, legacy_read_only: bool },
}

impl MigrationError {
    /// Whether the app now runs from the 1.1 storage in read-only mode (the new vault was removed). False after a
    /// failure in steps 4–6, and also in the rare case that steps 1–3 failed after another write to the vault
    /// (then the vault is kept as it is).
    pub fn legacy_read_only(&self) -> bool {
        matches!(self, MigrationError::Failed { legacy_read_only: true, .. })
    }
}

impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MigrationError::Refused(message) => write!(f, "the migration was not started: {message}"),
            MigrationError::Failed { step, message, .. } => {
                write!(f, "the migration failed ({}): {message}", step.as_str())
            }
        }
    }
}

impl std::error::Error for MigrationError {}

/// Whether there is 1.1 data to migrate (or a deletion to finish): false once the marker exists.
pub fn has_legacy_data(src: &LegacySources) -> bool {
    if exists(&src.marker_path()) {
        return false;
    }
    if exists(&src.cleanup_path()) {
        return true;
    }
    let has_connection_dir = fs::read_dir(&src.store.base_dir)
        .map(|entries| entries.flatten().any(|e| e.file_type().is_ok_and(|t| t.is_dir())))
        .unwrap_or(false);
    has_connection_dir
        || exists(&src.ranking.path)
        || exists(&src.system_otp.path)
        || exists(&src.registry_path)
        || !src.keychain.items().is_empty()
}

/// The number of Keychain items the migration reads (for "macOS may ask N times"). Items still under the older
/// service `macvpn` are not counted (they are moved over at launch).
pub fn keychain_item_count(src: &LegacySources) -> usize {
    src.keychain.items().len()
}

/// Runs the migration into the unlocked, empty vault (or finishes an interrupted deletion).
pub fn migrate(vault: &VaultLifecycle, src: &LegacySources) -> Result<MigrationReport, MigrationError> {
    run(vault, src, None, |_| {}, true)
}

/// Steps 1–3 and the cleanup list only: the vault is in use and verified, the old data is still there (the create
/// window offers a backup first, spec 2.7 step 5). The next [`migrate`] deletes it (steps 4–6).
pub fn migrate_keeping_old_data(
    vault: &VaultLifecycle,
    src: &LegacySources,
) -> Result<MigrationReport, MigrationError> {
    run(vault, src, None, |_| {}, false)
}

/// [`migrate`] with a failure injected at `fail_at` and a hook that runs on the vault between the import and the
/// verification (tests: tampering). Not in production builds.
#[cfg(any(test, feature = "test-support"))]
pub fn migrate_for_tests(
    vault: &VaultLifecycle,
    src: &LegacySources,
    fail_at: Option<MigrationStep>,
    after_import: impl FnOnce(&mut Vault),
) -> Result<MigrationReport, MigrationError> {
    run(vault, src, fail_at, after_import, true)
}

fn run(
    vault: &VaultLifecycle,
    src: &LegacySources,
    fail_at: Option<MigrationStep>,
    after_import: impl FnOnce(&mut Vault),
    delete_old: bool,
) -> Result<MigrationReport, MigrationError> {
    if exists(&src.marker_path()) {
        return Ok(MigrationReport::default());
    }
    match fs::read_to_string(src.cleanup_path()) {
        Ok(text) => {
            if !vault.exists() {
                return Err(MigrationError::Refused("the vault is missing; the old data is kept".into()));
            }
            // An open vault must hold the imported data before more of the old data goes.
            if vault.with_read(|v| v.is_empty()).unwrap_or(false) {
                return Err(MigrationError::Refused("the vault is empty; the old data is kept".into()));
            }
            let cleanup =
                Cleanup::parse(&text).ok_or_else(|| MigrationError::Refused(format!("{CLEANUP_FILE} is damaged")))?;
            vault.log("migration: finishing the deletion of the old data");
            return finish(vault, src, cleanup, fail_at, MigrationReport { resumed: true, ..Default::default() });
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(MigrationError::Refused(format!("{CLEANUP_FILE}: {e}"))),
    }
    if exists(&src.journal_path())
        && let Some(result) = resume_after_import(vault, src, fail_at)
    {
        return result;
    }
    match vault.claim_empty_for_migration() {
        Ok(true) => {}
        Ok(false) => {
            // Not a failure: the vault is the user's (a restore, or data written before); the 1.1 data stays.
            vault.log("migration: the vault already holds data; the old data is left as it is");
            vault.set_legacy_read_only(None);
            return Ok(MigrationReport { vault_had_data: true, ..MigrationReport::default() });
        }
        Err(VaultError::Locked) => return Err(MigrationError::Refused("the vault is locked".into())),
        Err(e) => return Err(MigrationError::Refused(e.to_string())),
    }

    // Steps 1–3: any failure removes the new vault and leaves the old data as it is.
    let fail = |step: MigrationStep, message: String| {
        let _ = fs::remove_file(src.journal_path());
        if vault.discard() {
            let err = MigrationError::Failed { step, message, legacy_read_only: true };
            vault.log(&format!("migration failed ({}); the old data is kept", step.as_str()));
            vault.set_legacy_read_only(Some(err.to_string()));
            err
        } else {
            vault.log(&format!("migration failed ({}); the vault was written meanwhile and is kept", step.as_str()));
            let message = format!("{message}; the vault was changed meanwhile and is kept");
            MigrationError::Failed { step, message, legacy_read_only: false }
        }
    };
    let data = read(src).map_err(|m| fail(MigrationStep::Read, m))?;
    if fail_at == Some(MigrationStep::Read) {
        return Err(fail(MigrationStep::Read, "injected failure".into()));
    }
    write_private(b"import\n", &src.journal_path())
        .map_err(|e| fail(MigrationStep::Import, format!("the migration journal could not be written: {e}")))?;
    import(vault, &data, fail_at == Some(MigrationStep::Import)).map_err(|e| fail(MigrationStep::Import, e))?;
    let _ = vault.with_migration(|v| {
        after_import(v);
        Ok(())
    });
    verify(vault, &data).map_err(|m| fail(MigrationStep::Verify, m))?;
    if fail_at == Some(MigrationStep::Verify) {
        return Err(fail(MigrationStep::Verify, "injected failure".into()));
    }
    let cleanup = data.cleanup();
    // Still before any deletion: without the list a failure in step 4 could not be finished later.
    cleanup
        .save(src)
        .map_err(|e| fail(MigrationStep::Verify, format!("the list of old files could not be saved: {e}")))?;
    let _ = fs::remove_file(src.journal_path());

    vault.end_migration_mark();
    vault.set_legacy_read_only(None);
    let report = MigrationReport {
        connections: data.connections.len(),
        secrets: data.secrets.len(),
        system_otp: data.system_otp.as_ref().map_or(0, HashMap::len),
        clients: data.clients.as_ref().map_or(0, Vec::len),
        skipped: data.skipped.clone(),
        resumed: false,
        vault_had_data: false,
    };
    vault.log(&format!(
        "migrated: {} connections, {} secrets, {} system OTP settings, {} paired clients, {} skipped",
        report.connections,
        report.secrets,
        report.system_otp,
        report.clients,
        report.skipped.len()
    ));
    drop(data);
    if !delete_old {
        return Ok(report);
    }
    finish(vault, src, cleanup, fail_at, report)
}

/// A journal without a cleanup list: an earlier run imported (or was about to) and stopped before the list was
/// written. An empty vault: the import never committed, the journal goes and the migration runs normally (`None`).
/// Otherwise the old data is read again and the vault verified against it: equal, the list is written and the
/// deletion finished; different, nothing is deleted.
fn resume_after_import(
    vault: &VaultLifecycle,
    src: &LegacySources,
    fail_at: Option<MigrationStep>,
) -> Option<Result<MigrationReport, MigrationError>> {
    let empty = match vault.with_read(|v| v.is_empty()) {
        Ok(empty) => empty,
        Err(VaultError::Locked) => return Some(Err(MigrationError::Refused("the vault is locked".into()))),
        Err(e) => return Some(Err(MigrationError::Refused(e.to_string()))),
    };
    if empty {
        let _ = fs::remove_file(src.journal_path());
        return None;
    }
    vault.log("migration: verifying an import of an earlier run");
    let refused = |m: String| Some(Err(MigrationError::Refused(m)));
    let data = match read(src) {
        Ok(data) => data,
        Err(m) => return refused(format!("the old data could not be read again: {m}; it is kept")),
    };
    if let Err(m) = verify(vault, &data) {
        return refused(format!("the vault does not match the old data ({m}); the old data is kept"));
    }
    let cleanup = data.cleanup();
    if let Err(e) = cleanup.save(src) {
        return refused(format!("the list of old files could not be saved: {e}"));
    }
    let _ = fs::remove_file(src.journal_path());
    vault.end_migration_mark();
    vault.set_legacy_read_only(None);
    let report = MigrationReport {
        connections: data.connections.len(),
        secrets: data.secrets.len(),
        system_otp: data.system_otp.as_ref().map_or(0, HashMap::len),
        clients: data.clients.as_ref().map_or(0, Vec::len),
        skipped: data.skipped.clone(),
        resumed: true,
        vault_had_data: false,
    };
    drop(data);
    Some(finish(vault, src, cleanup, fail_at, report))
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

// MARK: - Step 1: read

struct LegacyConnection {
    connection: Connection,
    /// The raw config text (a BOM and the line ends kept); empty when there was no config file.
    config: Zeroizing<String>,
}

#[derive(Default)]
struct LegacyData {
    connections: Vec<LegacyConnection>,
    secrets: Vec<(String, SecretField, Zeroizing<String>)>,
    /// `None`: no usable file (nothing is imported or deleted).
    ranking: Option<ConnectionRanking>,
    /// The enabled entries only (as the vault stores them).
    system_otp: Option<HashMap<String, OTPSetting>>,
    clients: Option<Vec<Value>>,
    /// What steps 4 and 5 delete: only what was imported.
    files: Vec<OldFile>,
    dirs: Vec<OldDir>,
    keychain: Vec<(Uuid, SecretField)>,
    skipped: Vec<String>,
}

impl LegacyData {
    fn cleanup(&self) -> Cleanup {
        Cleanup { files: self.files.clone(), dirs: self.dirs.clone(), keychain: self.keychain.clone() }
    }
}

/// A file's bytes; `None` when it does not exist.
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{} could not be read: {e}", path.display())),
    }
}

fn read(src: &LegacySources) -> Result<LegacyData, String> {
    let mut data = LegacyData::default();
    let skipped_ids = read_connections(src, &mut data)?;
    read_keychain(src, &skipped_ids, &mut data)?;
    read_ranking(src, &mut data)?;
    read_system_otp(src, &mut data)?;
    read_registry(src, &mut data)?;
    Ok(data)
}

/// Reads the connection directories; returns the ids of the skipped ones (their Keychain items stay too).
fn read_connections(src: &LegacySources, data: &mut LegacyData) -> Result<HashSet<String>, String> {
    let base = &src.store.base_dir;
    let mut skipped_ids = HashSet::new();
    match fs::symlink_metadata(base) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => {
            data.skipped.push("connections: not a directory".into());
            return Ok(skipped_ids);
        }
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(skipped_ids),
        Err(e) => return Err(format!("{} could not be read: {e}", base.display())),
    }
    let entries = match fs::read_dir(base) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(skipped_ids),
        Err(e) => return Err(format!("{} could not be listed: {e}", base.display())),
    };
    for entry in entries {
        let entry = entry.map_err(|e| format!("{} could not be listed: {e}", base.display()))?;
        // A symlink is not followed (and not a connection).
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let dir = entry.path();
        let mut skip = |why: &str| {
            data.skipped.push(format!("connections/{name}: {why}"));
            if let Some(id) = parse_uuid(&name) {
                skipped_ids.insert(uuid_string(&id));
            }
        };
        let Some(meta) = read_optional(&dir.join("meta.json"))? else {
            skip("no meta.json");
            continue;
        };
        let decoded = swift_json::parse(&meta).ok().and_then(|v| Connection::from_json(&v).ok());
        let Some(connection) = decoded else {
            skip("meta.json cannot be decoded");
            continue;
        };
        // The 1.1 app reads a connection's files from the directory named by its id.
        if uuid_string(&connection.id) != name {
            skip("the directory name is not the connection's id");
            continue;
        }
        let config_path = dir.join("config");
        let config = match read_optional(&config_path)? {
            None => Zeroizing::new(String::new()),
            Some(bytes) => match String::from_utf8(bytes) {
                Ok(text) => Zeroizing::new(text),
                Err(e) => {
                    drop(Zeroizing::new(e.into_bytes()));
                    skip("the config is not UTF-8");
                    continue;
                }
            },
        };
        let id = connection.id;
        data.files.push(OldFile::Meta(id));
        if exists(&config_path) {
            data.files.push(OldFile::Config(id));
        }
        data.dirs.push(OldDir::Connection(id));
        data.connections.push(LegacyConnection { connection, config });
    }
    data.connections.sort_by_key(|c| uuid_string(&c.connection.id));
    data.files.sort_by_key(OldFile::token);
    data.dirs.sort_by_key(OldDir::token);
    data.dirs.push(OldDir::Connections);
    Ok(skipped_ids)
}

fn read_keychain(src: &LegacySources, skipped_ids: &HashSet<String>, data: &mut LegacyData) -> Result<(), String> {
    src.keychain.prepare();
    for (item, field) in src.keychain.items() {
        let account = format!("{item}.{}", field.raw_value());
        if skipped_ids.contains(&item) {
            data.skipped.push(format!("Keychain item {account}: its connection was skipped"));
            continue;
        }
        // Only MacVPN's own item ids (a canonical UUID: a connection's id or a system VPN's service ID).
        let Some(id) = parse_uuid(&item).filter(|id| uuid_string(id) == item) else {
            data.skipped.push(format!("Keychain item {account}: not a MacVPN item id"));
            continue;
        };
        match src.keychain.read(&item, field) {
            LegacyRead::Value(value) => {
                // An empty value is no secret (the vault never stores one); the item is still deleted.
                if !value.is_empty() {
                    data.secrets.push((item.clone(), field, value));
                }
                data.keychain.push((id, field));
            }
            LegacyRead::Missing => data.skipped.push(format!("Keychain item {account}: gone before it was read")),
            LegacyRead::Undecodable => {
                data.skipped.push(format!("Keychain item {account}: not text; left in the Keychain"))
            }
            LegacyRead::Unavailable(status) => {
                return Err(format!(
                    "the Keychain item {account} could not be read (OSStatus {status}: access denied or cancelled?)"
                ));
            }
        }
    }
    Ok(())
}

fn read_ranking(src: &LegacySources, data: &mut LegacyData) -> Result<(), String> {
    let path = &src.ranking.path;
    let Some(bytes) = read_optional(path)? else { return Ok(()) };
    match swift_json::parse(&bytes).ok().and_then(|v| ConnectionRanking::from_json(&v).ok()) {
        Some(ranking) => {
            // The vault keeps each pin once (in its first place).
            let mut seen = HashSet::new();
            let pinned: Vec<String> = ranking.pinned().iter().filter(|id| seen.insert(*id)).cloned().collect();
            data.ranking = Some(ConnectionRanking::new(pinned, ranking.usage().clone()));
            data.files.push(OldFile::Ranking);
        }
        None => data.skipped.push(format!("{}: cannot be decoded", file_name(path))),
    }
    Ok(())
}

fn read_system_otp(src: &LegacySources, data: &mut LegacyData) -> Result<(), String> {
    let path = &src.system_otp.path;
    let Some(bytes) = read_optional(path)? else { return Ok(()) };
    // As `SystemOTPStore::load`: any entry of the wrong shape makes the whole file invalid.
    let decoded = match swift_json::parse(&bytes) {
        Ok(Value::Object(entries)) => entries
            .into_iter()
            .map(|(id, v)| OTPSetting::from_json(&v).ok().map(|s| (id, s)))
            .collect::<Option<HashMap<_, _>>>(),
        _ => None,
    };
    match decoded {
        Some(map) => {
            data.system_otp = Some(map.into_iter().filter(|(_, s)| s.enabled).collect());
            data.files.push(OldFile::SystemOtp);
        }
        None => data.skipped.push(format!("{}: cannot be decoded", file_name(path))),
    }
    Ok(())
}

fn read_registry(src: &LegacySources, data: &mut LegacyData) -> Result<(), String> {
    let path = &src.registry_path;
    let Some(bytes) = read_optional(path)? else { return Ok(()) };
    // `{"clients":[…]}`, each an object with a string `id`, no id twice (as the 1.1 registry requires).
    let decoded = swift_json::parse(&bytes).ok().and_then(|v| {
        let clients = v.as_object()?.get("clients")?.as_array()?.clone();
        let mut ids = HashSet::new();
        clients
            .iter()
            .all(|c| c.as_object().and_then(|o| o.get("id")?.as_str()).is_some_and(|id| ids.insert(id.to_string())))
            .then_some(clients)
    });
    match decoded {
        Some(clients) => {
            data.clients = Some(clients);
            data.files.push(OldFile::Registry);
        }
        None => data.skipped.push(format!("{}: cannot be decoded", file_name(path))),
    }
    Ok(())
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

// MARK: - Steps 2 and 3: import and verify

fn import(vault: &VaultLifecycle, data: &LegacyData, inject: bool) -> Result<(), String> {
    vault
        .with_migration(|v| {
            v.transaction(|tx| {
                for c in &data.connections {
                    tx.save_connection(&c.connection, Some(&c.config))?;
                }
                for (item, field, value) in &data.secrets {
                    tx.set_secret(item, *field, value)?;
                }
                if let Some(ranking) = &data.ranking {
                    tx.save_ranking(ranking)?;
                }
                if let Some(map) = &data.system_otp {
                    tx.save_system_otp_map(map)?;
                }
                if let Some(clients) = &data.clients {
                    tx.save_control_clients(clients)?;
                }
                if inject {
                    return Err(VaultError::Io(io::Error::other("injected failure")));
                }
                Ok(())
            })
        })
        .map_err(|e| e.to_string())
}

fn verify(vault: &VaultLifecycle, data: &LegacyData) -> Result<(), String> {
    vault.with_read(|v| Ok(verify_in(v, data))).map_err(|e| e.to_string())?
}

fn verify_in(v: &Vault, data: &LegacyData) -> Result<(), String> {
    let db = |e: VaultError| e.to_string();
    let count = v.connection_count().map_err(db)?;
    if count != data.connections.len() {
        return Err(format!("the vault holds {count} connections, {} were imported", data.connections.len()));
    }
    let listed: HashMap<_, _> =
        v.connections().map_err(db)?.into_iter().map(|s| (s.connection.id, s.connection)).collect();
    for c in &data.connections {
        let id = uuid_string(&c.connection.id);
        let (meta, config) = v.connection_record(&c.connection.id).map_err(db)?.ok_or(format!("{id} is missing"))?;
        let expected = swift_json::to_pretty_sorted(&c.connection.to_json()).map_err(|e| format!("{id}: {e}"))?;
        if meta.as_bytes() != expected.as_bytes() || listed.get(&c.connection.id) != Some(&c.connection) {
            return Err(format!("the metadata of {id} differs"));
        }
        if config[..] != *c.config.as_bytes() {
            return Err(format!("the config of {id} differs"));
        }
    }
    let count = v.secret_count().map_err(db)?;
    if count != data.secrets.len() {
        return Err(format!("the vault holds {count} secrets, {} were imported", data.secrets.len()));
    }
    for (item, field, value) in &data.secrets {
        let stored = v.secret(item, *field).map_err(db)?;
        if stored.as_ref().map(|s| s.as_bytes()) != Some(value.as_bytes()) {
            return Err(format!("the secret {item}.{} differs", field.raw_value()));
        }
    }
    if v.ranking().map_err(db)? != data.ranking.clone().unwrap_or_default() {
        return Err("the ranking differs".into());
    }
    if v.system_otp_map().map_err(db)? != data.system_otp.clone().unwrap_or_default() {
        return Err("the system OTP settings differ".into());
    }
    if v.control_clients().map_err(db)? != data.clients.clone().unwrap_or_default() {
        return Err("the paired clients differ".into());
    }
    Ok(())
}

// MARK: - Steps 4–6: delete and mark

/// An old file the migration may delete: only these shapes, so a damaged or planted cleanup list cannot name
/// anything else (the vault's own files included).
#[derive(Debug, Clone, PartialEq, Eq)]
enum OldFile {
    Meta(Uuid),
    Config(Uuid),
    Ranking,
    SystemOtp,
    Registry,
}

impl OldFile {
    fn token(&self) -> String {
        match self {
            OldFile::Meta(id) => format!("connections/{}/meta.json", uuid_string(id)),
            OldFile::Config(id) => format!("connections/{}/config", uuid_string(id)),
            OldFile::Ranking => "connection-order.json".into(),
            OldFile::SystemOtp => "system-otp.json".into(),
            OldFile::Registry => REGISTRY_FILE.into(),
        }
    }

    fn parse(token: &str) -> Option<OldFile> {
        match token {
            "connection-order.json" => return Some(OldFile::Ranking),
            "system-otp.json" => return Some(OldFile::SystemOtp),
            REGISTRY_FILE => return Some(OldFile::Registry),
            _ => {}
        }
        let rest = token.strip_prefix("connections/")?;
        let (id, name) = rest.split_once('/')?;
        let id = canonical_uuid(id)?;
        match name {
            "meta.json" => Some(OldFile::Meta(id)),
            "config" => Some(OldFile::Config(id)),
            _ => None,
        }
    }

    /// The path, and the directories that must be real (not symlinks) before it is touched.
    fn resolve(&self, src: &LegacySources) -> (PathBuf, Vec<PathBuf>) {
        let base = &src.store.base_dir;
        let in_connection = |id: &Uuid, name: &str| {
            let dir = base.join(uuid_string(id));
            (dir.join(name), vec![base.clone(), dir])
        };
        let top = |path: &PathBuf| (path.clone(), path.parent().map(Path::to_path_buf).into_iter().collect());
        match self {
            OldFile::Meta(id) => in_connection(id, "meta.json"),
            OldFile::Config(id) => in_connection(id, "config"),
            OldFile::Ranking => top(&src.ranking.path),
            OldFile::SystemOtp => top(&src.system_otp.path),
            OldFile::Registry => top(&src.registry_path),
        }
    }
}

/// A directory the migration may remove once it is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OldDir {
    Connection(Uuid),
    Connections,
}

impl OldDir {
    fn token(&self) -> String {
        match self {
            OldDir::Connection(id) => format!("connections/{}", uuid_string(id)),
            OldDir::Connections => "connections".into(),
        }
    }

    fn parse(token: &str) -> Option<OldDir> {
        if token == "connections" {
            return Some(OldDir::Connections);
        }
        canonical_uuid(token.strip_prefix("connections/")?).map(OldDir::Connection)
    }

    /// The path, and the directories that must be real (the path itself included).
    fn resolve(&self, src: &LegacySources) -> (PathBuf, Vec<PathBuf>) {
        let base = &src.store.base_dir;
        match self {
            OldDir::Connection(id) => {
                let dir = base.join(uuid_string(id));
                (dir.clone(), vec![base.clone(), dir])
            }
            OldDir::Connections => (base.clone(), vec![base.clone()]),
        }
    }
}

/// A UUID in exactly the form MacVPN writes (`uuid_string`).
fn canonical_uuid(s: &str) -> Option<Uuid> {
    parse_uuid(s).filter(|id| uuid_string(id) == s)
}

/// Whether every one of `dirs` is a real directory (`lstat`: a symlink is not).
fn real_dirs(dirs: &[PathBuf]) -> bool {
    dirs.iter().all(|d| fs::symlink_metadata(d).is_ok_and(|m| m.file_type().is_dir()))
}

/// What is still to be deleted. Saved as text lines: `file <shape>`, `dir <shape>`, `key <UUID> <field>`.
#[derive(Debug, Default)]
struct Cleanup {
    files: Vec<OldFile>,
    dirs: Vec<OldDir>,
    keychain: Vec<(Uuid, SecretField)>,
}

impl Cleanup {
    fn to_text(&self) -> String {
        let mut out = String::new();
        for f in &self.files {
            out.push_str(&format!("file {}\n", f.token()));
        }
        for d in &self.dirs {
            out.push_str(&format!("dir {}\n", d.token()));
        }
        for (item, field) in &self.keychain {
            out.push_str(&format!("key {} {}\n", uuid_string(item), field.raw_value()));
        }
        out
    }

    /// `None` (the whole list is refused) when any line is not one of the known shapes.
    fn parse(text: &str) -> Option<Cleanup> {
        let mut cleanup = Cleanup::default();
        for line in text.lines().filter(|l| !l.is_empty()) {
            let (kind, rest) = line.split_once(' ')?;
            match kind {
                "file" => cleanup.files.push(OldFile::parse(rest)?),
                "dir" => cleanup.dirs.push(OldDir::parse(rest)?),
                "key" => {
                    let (item, field) = rest.split_once(' ')?;
                    cleanup.keychain.push((canonical_uuid(item)?, SecretField::from_raw_value(field)?));
                }
                _ => return None,
            }
        }
        Some(cleanup)
    }

    fn save(&self, src: &LegacySources) -> io::Result<()> {
        write_private(self.to_text().as_bytes(), &src.cleanup_path())
    }
}

fn finish(
    vault: &VaultLifecycle,
    src: &LegacySources,
    mut cleanup: Cleanup,
    fail_at: Option<MigrationStep>,
    report: MigrationReport,
) -> Result<MigrationReport, MigrationError> {
    let fail = |step: MigrationStep, message: String, cleanup: &Cleanup| {
        // The previous list (a superset of this one) stays if this save fails: a resumed run tolerates files and
        // items that are already gone.
        let _ = cleanup.save(src);
        vault.log(&format!("migration: deleting the old data failed ({}); it is finished later", step.as_str()));
        MigrationError::Failed { step, message, legacy_read_only: false }
    };

    // Step 4: the files (overwritten, then unlinked), then the directories that are empty now. A file below a
    // symlinked directory is not ours to touch: it is left alone and dropped from the list.
    let inject = fail_at == Some(MigrationStep::DeleteFiles);
    let mut left = Vec::new();
    let mut deleted = 0usize;
    let mut first_error = None;
    for file in std::mem::take(&mut cleanup.files) {
        if inject && deleted > 0 {
            left.push(file);
            continue;
        }
        let (path, parents) = file.resolve(src);
        if !real_dirs(&parents) {
            continue;
        }
        match store::shred_file(&path) {
            Ok(()) => deleted += 1,
            Err(e) => {
                first_error.get_or_insert_with(|| format!("{} could not be deleted: {e}", file.token()));
                left.push(file);
            }
        }
    }
    cleanup.files = left;
    if inject {
        return Err(fail(MigrationStep::DeleteFiles, "injected failure".into(), &cleanup));
    }
    if let Some(message) = first_error {
        return Err(fail(MigrationStep::DeleteFiles, message, &cleanup));
    }
    for dir in std::mem::take(&mut cleanup.dirs) {
        let (path, real) = dir.resolve(src);
        // A directory with other files in it (not MacVPN's) stays.
        if real_dirs(&real) {
            let _ = fs::remove_dir(&path);
        }
    }

    // Step 5: the Keychain items, checked by listing them again.
    if fail_at == Some(MigrationStep::DeleteKeychain) {
        return Err(fail(MigrationStep::DeleteKeychain, "injected failure".into(), &cleanup));
    }
    for (item, field) in &cleanup.keychain {
        src.keychain.delete(&uuid_string(item), *field);
    }
    let present: HashSet<(String, SecretField)> = src.keychain.items().into_iter().collect();
    cleanup.keychain.retain(|(item, field)| present.contains(&(uuid_string(item), *field)));
    if !cleanup.keychain.is_empty() {
        let message = format!("{} Keychain items could not be deleted", cleanup.keychain.len());
        return Err(fail(MigrationStep::DeleteKeychain, message, &cleanup));
    }

    // Step 6: the marker, then the list goes.
    if fail_at == Some(MigrationStep::Marker) {
        return Err(fail(MigrationStep::Marker, "injected failure".into(), &cleanup));
    }
    if let Err(e) = write_private(format!("{}\n", macvpn_core::VERSION).as_bytes(), &src.marker_path()) {
        return Err(fail(MigrationStep::Marker, format!("{MARKER} could not be written: {e}"), &cleanup));
    }
    let _ = fs::remove_file(src.cleanup_path());
    vault.log("migration: the old data was deleted");
    Ok(report)
}
