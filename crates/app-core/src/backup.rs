//! The full backup and restore in the app (spec 3b, plan B Task 21): the orchestration between the vault
//! lifecycle, core's backup format (`macvpn_core::vault::backup`) and the windows. Platform-independent; the
//! Tauri shell (`app/src-tauri/src/backup.rs`) adds the native panels, the threads and the windows.
//!
//! **Backup:** [`BackupService::make`] checks the password (at least `MIN_PASSWORD_CHARS` characters, or the
//! master password checked against the vault when the user chose "Use my master password"), collects the vault
//! with the current preferences and seals it. The caller writes the bytes with `backup::write_backup`.
//!
//! **Restore:** [`BackupService::open`] opens a file's bytes (read only through `backup::read_backup_file`) with the
//! backup password and keeps the payload *staged* for the window that opened it, returning the numbers of the
//! plan ([`RestoreSummary`]); nothing is written yet. Then one of:
//! - [`BackupService::apply`]: a merge with one conflict mode, or "Replace everything", into the unlocked vault.
//!   Replace must name the number of items it loses as the window showed it; if the vault changed since, the
//!   restore is refused and the window asks again.
//! - [`BackupService::apply_fresh`]: the first-run restore (`vault-create` → "Restore from backup…"): the backup
//!   replaces the contents of the vault that was just created, which must still be empty.
//!
//! **After a restore** ([`RestoreOutcome`]): the backed-up preferences are listed one by one and applied only when
//! the user ticks them ([`BackupService::apply_preferences`]); the control API is never ticked by default. The
//! native (L2TP / Cisco) profiles are reinstalled one at a time through the existing [`NativeProfiles`]
//! ([`BackupService::reinstall_profile`]).
//!
//! Every long call (the KDF runs for seconds) is meant for a worker thread. Passwords arrive as `Zeroizing`
//! strings and are dropped (wiped) at the end of the call that used them; they are never stored, logged or part
//! of a returned value. A failure is one localized message; a wrong password and a damaged file are the same one.

use crate::deps::NativeProfiles;
use crate::vault::{UnlockError, VaultLifecycle};
use macvpn_core::date::Date;
use macvpn_core::l10n::{Arg, tr};
use macvpn_core::models::{SecretField, uuid_string};
use macvpn_core::vault::backup::{
    self as format, BackupError, BackupPayload, BackupPreferences, ConflictMode, RestorePlan,
};
use macvpn_core::vault::{Entropy, KdfParams, MIN_PASSWORD_CHARS, TreeError, VaultError, check_password_rules};
use serde::Serialize;
use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::time::Instant;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The default file name offered in the save panel: `MacVPN-backup-<YYYY-MM-DD>.macvpnbackup`.
pub fn default_file_name(today: &str) -> String {
    format!("MacVPN-backup-{today}.{}", format::EXTENSION)
}

/// Which password protects the new backup (the master password is checked in either case).
pub enum PasswordSource {
    /// A backup password of its own (typed twice in the window).
    Own(Zeroizing<String>),
    /// "Use my master password", after its confirmation step.
    Master,
}

/// The backup password rule: at least `MIN_PASSWORD_CHARS` characters, as for the master password.
pub fn check_backup_password(password: &str) -> Result<(), String> {
    check_password_rules(password)
        .map_err(|_| tr("The backup password must be at least %d characters long", &[Arg::from(MIN_PASSWORD_CHARS)]))
}

/// A preference carried in a backup (spec 3b), applied after a restore only when the user ticks it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Preference {
    AutoCheck,
    Delay24h,
    LaunchAtLogin,
    ControlApi,
    AutoUnlock,
}

impl Preference {
    pub const ALL: [Preference; 5] = [
        Preference::AutoCheck,
        Preference::Delay24h,
        Preference::LaunchAtLogin,
        Preference::ControlApi,
        Preference::AutoUnlock,
    ];

    /// The command argument (the serialized name).
    pub fn parse(raw: &str) -> Result<Preference, String> {
        match raw {
            "autoCheck" => Ok(Preference::AutoCheck),
            "delay24h" => Ok(Preference::Delay24h),
            "launchAtLogin" => Ok(Preference::LaunchAtLogin),
            "controlApi" => Ok(Preference::ControlApi),
            "autoUnlock" => Ok(Preference::AutoUnlock),
            _ => Err("invalid preference".into()),
        }
    }

    pub fn value(self, p: &BackupPreferences) -> bool {
        match self {
            Preference::AutoCheck => p.auto_check,
            Preference::Delay24h => p.delay_24h,
            Preference::LaunchAtLogin => p.launch_at_login,
            Preference::ControlApi => p.control_api_enabled,
            Preference::AutoUnlock => p.auto_unlock,
        }
    }
}

/// The app's preferences as the backup sees them: read for a backup, written one by one after a restore. The app
/// implements it over the update controller, the login item service, the control API switch and the vault's
/// auto-unlock switch.
pub trait PreferencePort: Send + Sync {
    fn current(&self) -> BackupPreferences;
    /// Sets one preference. The error is the localized message. Never called to turn automatic unlock on.
    fn apply(&self, preference: Preference, on: bool) -> Result<(), String>;
    /// Automatic unlock is to be turned on: it needs the master password, so the app asks for it (its password
    /// window); a restore never turns it on by itself. The error is the localized message.
    fn confirm_auto_unlock(&self) -> Result<(), String>;
}

/// Restore into an existing vault: a merge with one answer for every conflict, or "Replace everything".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreChoice {
    Merge(ConflictMode),
    /// `expected_lost`: everything lost ([`RestoreSummary::lost_total`]), as the confirmation named it.
    Replace {
        expected_lost: usize,
    },
}

/// Parses the restore window's choice (`merge` + `overwrite|keepExisting|keepBoth`, or `replace`).
pub fn parse_choice(mode: &str, conflict: Option<&str>, expected_lost: Option<usize>) -> Result<RestoreChoice, String> {
    match (mode, conflict, expected_lost) {
        ("merge", Some(conflict), None) => Ok(RestoreChoice::Merge(match conflict {
            "overwrite" => ConflictMode::Overwrite,
            "keepExisting" => ConflictMode::KeepExisting,
            "keepBoth" => ConflictMode::KeepBoth,
            _ => return Err("invalid conflict mode".into()),
        })),
        ("replace", None, Some(expected_lost)) => Ok(RestoreChoice::Replace { expected_lost }),
        _ => Err("invalid restore choice".into()),
    }
}

/// What the restore window shows once the file is open, before anything is written. Names and numbers only.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreSummary {
    /// When the backup was made (Unix time, seconds).
    pub created: f64,
    /// The MacVPN version that made it.
    pub app_version: String,
    pub connections: usize,
    pub folders: usize,
    pub credentials: usize,
    /// Connections, folders and credentials the restore adds without a conflict.
    pub added: usize,
    /// Connections, folders and credentials that already exist (one question for all of them).
    pub conflicts: usize,
    /// What "Replace everything" loses: the vault's items that are not in the backup.
    pub lost_on_replace: usize,
    /// The team catalog subscriptions "Replace everything" removes (not in the backup), by name.
    pub lost_subscriptions: Vec<String>,
    /// The admin key roles (`primary`, `backup`) the backup replaces with its own key. A role the backup has no
    /// key for keeps this Mac's key.
    pub lost_admin_keys: Vec<&'static str>,
    /// The publications the backup replaces with its own record (the version is never lowered), by name.
    pub lost_publications: Vec<String>,
    /// Everything "Replace everything" loses, counted together: the number its confirmation sends back.
    pub lost_total: usize,
    /// The connections whose acknowledged risky OpenVPN directives a replace (and a fresh restore) keeps; a merge
    /// drops them unless the same connection with the same config already exists.
    pub acknowledged_risky: Vec<String>,
    /// The L2TP / Cisco connections whose profiles are reinstalled afterwards.
    pub native_profiles: usize,
    /// The first-run restore into a new vault (no merge, nothing lost).
    pub fresh: bool,
}

/// A backed-up preference after a restore: its value in the backup, on this Mac now, and whether its checkbox
/// starts ticked (it differs, and it is not the control API).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreferenceChoice {
    pub key: Preference,
    pub backed_up: bool,
    pub current: bool,
    pub ticked: bool,
}

/// A native connection whose profile can be reinstalled after a restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeProfileView {
    pub id: String,
    pub name: String,
    /// Reinstalled in this restore (opened for approval).
    pub installed: bool,
}

/// The restore is written: the preferences to confirm and the profiles to reinstall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreOutcome {
    pub preferences: Vec<PreferenceChoice>,
    pub native_profiles: Vec<NativeProfileView>,
    /// The backup's folders and connections a team catalog owns here: not restored (the catalog's stay).
    pub skipped_catalog_items: Vec<String>,
}

/// A preference that could not be applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreferenceFailure {
    pub key: Preference,
    pub message: String,
}

/// An opened backup waiting for the choice, owned by one window.
struct Staged {
    owner: String,
    payload: BackupPayload,
    fresh: bool,
}

/// A written restore: the backed-up preferences and the native profiles, owned by one window.
struct Restored {
    owner: String,
    preferences: BackupPreferences,
    natives: Vec<NativeProfileView>,
}

#[derive(Default)]
struct Session {
    staged: Option<Staged>,
    restored: Option<Restored>,
}

/// The backup and restore orchestration over one vault. Share it as `Arc<BackupService>`.
pub struct BackupService {
    vault: Arc<VaultLifecycle>,
    entropy: Arc<dyn Entropy>,
    kdf: KdfParams,
    app_version: String,
    /// One backup or restore step at a time (they run the KDF or write the whole vault).
    ops: Mutex<()>,
    session: Mutex<Session>,
}

impl std::fmt::Debug for BackupService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackupService").field("kdf", &self.kdf).finish_non_exhaustive()
    }
}

fn locked() -> String {
    tr("The vault is locked. Unlock it first.", &[])
}

fn busy() -> String {
    tr("Another backup or restore is running.", &[])
}

/// The one message per backup error: a wrong password and a damaged file are the same.
pub fn backup_error_message(e: &BackupError) -> String {
    match e {
        BackupError::CannotOpen => {
            tr("The backup cannot be opened. The password is wrong, or the file is damaged.", &[])
        }
        BackupError::NewerVersion(_) => tr("This backup was made by a newer MacVPN. Update MacVPN to restore it.", &[]),
        BackupError::TooLarge => tr("The file is too large for a MacVPN backup.", &[]),
        BackupError::Invalid(_) => tr("This backup cannot be restored: it holds data MacVPN does not accept.", &[]),
        BackupError::Io(message) => message.clone(),
    }
}

/// A failed restore write: nothing was changed (one transaction).
pub fn restore_error_message(e: &VaultError) -> String {
    match e {
        VaultError::Locked => locked(),
        VaultError::InvalidBackup(_) => {
            tr("This backup cannot be restored: it holds data MacVPN does not accept.", &[])
        }
        VaultError::Tree(TreeError::Cycle) => {
            tr("The backup's folders would form a loop with the folders here. Nothing was changed.", &[])
        }
        _ => tr("The restore failed. Nothing was changed.", &[]),
    }
}

fn master_error_message(e: &UnlockError) -> String {
    match e {
        UnlockError::Wrong { .. } => tr("The master password is not correct.", &[]),
        UnlockError::TooSoon { retry_after } => {
            tr("Wait %d seconds before trying again.", &[Arg::from(retry_after.as_secs().max(1) as usize)])
        }
        UnlockError::Io(message) => message.clone(),
        _ => tr("The restore failed. Nothing was changed.", &[]),
    }
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The plan of a fresh restore: everything is added, nothing conflicts or is lost.
fn fresh_plan(p: &BackupPayload) -> RestorePlan {
    RestorePlan {
        added: p.connections.len() + p.folders.len() + p.credentials.len(),
        conflicts: 0,
        lost_on_replace: 0,
        acknowledged_risky: p
            .connections
            .iter()
            .filter(|c| !c.connection.acknowledged_risky_directives.is_empty())
            .map(|c| c.connection.name.clone())
            .collect(),
        lost_subscriptions: Vec::new(),
        lost_admin_keys: Vec::new(),
        lost_publications: Vec::new(),
    }
}

impl BackupService {
    /// `kdf`: the parameters new backups are sealed with (raised to at least `KdfParams::DEFAULT` by core).
    pub fn new(vault: Arc<VaultLifecycle>, entropy: Arc<dyn Entropy>, kdf: KdfParams, app_version: &str) -> Self {
        BackupService {
            vault,
            entropy,
            kdf,
            app_version: app_version.to_string(),
            ops: Mutex::new(()),
            session: Mutex::default(),
        }
    }

    pub fn vault(&self) -> &Arc<VaultLifecycle> {
        &self.vault
    }

    /// The menu and the Connections window offer backup and restore only while the vault is open.
    pub fn available(&self) -> bool {
        self.vault.is_unlocked()
    }

    fn op(&self) -> Result<MutexGuard<'_, ()>, String> {
        match self.ops.try_lock() {
            Ok(g) => Ok(g),
            Err(TryLockError::Poisoned(p)) => Ok(p.into_inner()),
            Err(TryLockError::WouldBlock) => Err(busy()),
        }
    }

    // MARK: - Backup

    /// Seals the whole vault (and `prefs`). The master password is always checked first (with the unlock delay):
    /// the backup holds every secret, so an unlocked Mac left alone is not enough to take one. The file is sealed
    /// with the own backup password ([`PasswordSource::Own`], which must follow the backup password rule) or with
    /// the master password itself. Runs the KDF: call it off the main thread.
    pub fn make(
        &self,
        master: Zeroizing<String>,
        source: PasswordSource,
        prefs: BackupPreferences,
        now: Date,
    ) -> Result<Vec<u8>, String> {
        let _op = self.op()?;
        if !self.vault.is_unlocked() {
            return Err(locked());
        }
        if let PasswordSource::Own(own) = &source {
            check_backup_password(own)?;
        }
        self.vault
            .verify_password(Zeroizing::new(master.as_str().to_owned()), Instant::now())
            .map_err(|e| master_error_message(&e))?;
        let password = match source {
            PasswordSource::Own(own) => own,
            PasswordSource::Master => master,
        };
        let payload =
            self.vault.with_read(|v| format::collect(v, prefs, now, &self.app_version)).map_err(|e| match e {
                VaultError::Locked => locked(),
                _ => tr("The backup could not be made.", &[]),
            })?;
        format::seal(&payload, &password, self.kdf, self.entropy.as_ref()).map_err(|e| match e {
            BackupError::Io(_) | BackupError::Invalid(_) => tr("The backup could not be made.", &[]),
            other => backup_error_message(&other),
        })
    }

    // MARK: - Restore

    /// Opens the backup (`bytes` from `read_backup_file`) and stages it for `owner` (the window), replacing what
    /// that window staged before. `fresh`: the first-run restore (no vault yet, or the new empty one). Runs the KDF:
    /// call it off the main thread.
    pub fn open(
        &self,
        owner: &str,
        bytes: &[u8],
        password: Zeroizing<String>,
        fresh: bool,
    ) -> Result<RestoreSummary, String> {
        let _op = self.op()?;
        if !fresh && !self.vault.is_unlocked() {
            return Err(locked());
        }
        if fresh && !self.fresh_target()? {
            return Err(tr("A restore from the first-run window needs a new, empty vault.", &[]));
        }
        let payload = format::open(bytes, &password).map_err(|e| backup_error_message(&e))?;
        drop(password);
        let plan = if fresh {
            fresh_plan(&payload)
        } else {
            self.vault.with_read(|v| format::plan_restore(v, &payload)).map_err(|e| restore_error_message(&e))?
        };
        let summary = RestoreSummary {
            created: payload.created.time_interval_since_1970(),
            app_version: payload.app_version.clone(),
            connections: payload.connections.len(),
            folders: payload.folders.len(),
            credentials: payload.credentials.len(),
            added: plan.added,
            conflicts: plan.conflicts,
            lost_on_replace: plan.lost_on_replace,
            lost_total: plan.lost_total(),
            lost_subscriptions: plan.lost_subscriptions,
            lost_admin_keys: plan.lost_admin_keys.iter().map(|r| r.as_str()).collect(),
            lost_publications: plan.lost_publications,
            acknowledged_risky: plan.acknowledged_risky,
            native_profiles: payload.native_connections().count(),
            fresh,
        };
        let mut session = guard(&self.session);
        session.staged = Some(Staged { owner: owner.to_string(), payload, fresh });
        session.restored = None;
        Ok(summary)
    }

    /// No vault yet, or the open vault is still empty. The legacy read-only mode (1.1 data waiting for the
    /// migration) counts too: the create window may restore a backup in place of the migration.
    fn fresh_target(&self) -> Result<bool, String> {
        if self.vault.is_unlocked() {
            return self.vault.with_read(|v| v.is_empty()).map_err(|e| restore_error_message(&e));
        }
        Ok(!self.vault.exists())
    }

    /// Whether `owner` has an opened backup waiting for the choice.
    pub fn has_staged(&self, owner: &str) -> bool {
        guard(&self.session).staged.as_ref().is_some_and(|s| s.owner == owner)
    }

    fn take_staged(&self, owner: &str, fresh: bool) -> Result<Staged, String> {
        let mut session = guard(&self.session);
        match session.staged.take() {
            Some(s) if s.owner == owner && s.fresh == fresh => Ok(s),
            other => {
                session.staged = other;
                Err("no backup is open in this window".into())
            }
        }
    }

    fn put_back(&self, staged: Staged) {
        let mut session = guard(&self.session);
        if session.staged.is_none() {
            session.staged = Some(staged);
        }
    }

    /// Restores the staged backup into the unlocked vault (one transaction). `known_services`: the system VPN
    /// service IDs present on this Mac (the others keep their placement for the 30-day retention).
    pub fn apply(
        &self,
        owner: &str,
        choice: RestoreChoice,
        known_services: &HashSet<String>,
        now: Date,
        prefs: &dyn PreferencePort,
    ) -> Result<RestoreOutcome, String> {
        let _op = self.op()?;
        if !self.vault.is_unlocked() {
            return Err(locked());
        }
        let mut staged = self.take_staged(owner, false)?;
        format::mark_missing_system_items(&mut staged.payload, known_services, now);
        let result = (|| {
            let before = self.native_ids()?;
            let written = self.vault.with(|v| match choice {
                RestoreChoice::Merge(mode) => Ok(Some(format::merge(v, &staged.payload, mode)?)),
                RestoreChoice::Replace { expected_lost } => {
                    let lost = format::plan_restore(v, &staged.payload)?.lost_total();
                    if lost != expected_lost {
                        return Ok(None);
                    }
                    format::replace(v, &staged.payload)?;
                    Ok(Some(format::RestoreReport::default()))
                }
            });
            let report = match written {
                Ok(Some(report)) => report,
                Ok(None) => {
                    return Err(tr("The vault changed since the summary. Review the restore again.", &[]));
                }
                Err(e) => return Err(restore_error_message(&e)),
            };
            let backup_ids: HashSet<Uuid> = staged.payload.native_connections().map(|c| c.id).collect();
            // Reinstalled: the backup's native connections as they are now in the vault (Keep existing leaves the
            // existing one, which needs nothing), and the new copies "Keep both" made.
            let keep_existing = choice == RestoreChoice::Merge(ConflictMode::KeepExisting);
            let natives = self.native_views(|id| {
                let new = !before.contains(id);
                new || (backup_ids.contains(id) && !keep_existing)
            })?;
            Ok((natives, report.skipped_catalog_items))
        })();
        match result {
            Ok((natives, skipped)) => Ok(self.finish(owner, staged.payload.preferences, natives, skipped, prefs)),
            Err(message) => {
                self.put_back(staged);
                Err(message)
            }
        }
    }

    /// The first-run restore: the staged backup replaces the contents of the vault created after it was opened
    /// (unlocked and still empty).
    pub fn apply_fresh(
        &self,
        owner: &str,
        known_services: &HashSet<String>,
        now: Date,
        prefs: &dyn PreferencePort,
    ) -> Result<RestoreOutcome, String> {
        let _op = self.op()?;
        if !self.vault.is_unlocked() {
            return Err(locked());
        }
        let mut staged = self.take_staged(owner, true)?;
        format::mark_missing_system_items(&mut staged.payload, known_services, now);
        // The create window's restore replaces the migration: it may write in the legacy read-only mode.
        let written = self.vault.with_migration(|v| {
            if !v.is_empty()? {
                return Ok(false);
            }
            format::replace(v, &staged.payload)?;
            Ok(true)
        });
        let result = match written {
            Ok(true) => {
                // The vault holds the user's data now: never the migration's to discard.
                self.vault.end_migration_mark();
                self.native_views(|_| true)
            }
            Ok(false) => Err(tr("A restore from the first-run window needs a new, empty vault.", &[])),
            Err(e) => Err(restore_error_message(&e)),
        };
        match result {
            Ok(natives) => Ok(self.finish(owner, staged.payload.preferences, natives, Vec::new(), prefs)),
            Err(message) => {
                self.put_back(staged);
                Err(message)
            }
        }
    }

    fn native_ids(&self) -> Result<HashSet<Uuid>, String> {
        self.vault
            .with_read(|v| {
                Ok(v.connections()?
                    .into_iter()
                    .filter(|s| s.connection.kind.is_native())
                    .map(|s| s.connection.id)
                    .collect())
            })
            .map_err(|e| restore_error_message(&e))
    }

    fn native_views(&self, include: impl Fn(&Uuid) -> bool) -> Result<Vec<NativeProfileView>, String> {
        self.vault
            .with_read(|v| {
                Ok(v.connections()?
                    .into_iter()
                    .map(|s| s.connection)
                    .filter(|c| c.kind.is_native() && include(&c.id))
                    .map(|c| NativeProfileView { id: uuid_string(&c.id), name: c.name, installed: false })
                    .collect())
            })
            .map_err(|e| restore_error_message(&e))
    }

    fn finish(
        &self,
        owner: &str,
        backed_up: BackupPreferences,
        natives: Vec<NativeProfileView>,
        skipped_catalog_items: Vec<String>,
        prefs: &dyn PreferencePort,
    ) -> RestoreOutcome {
        let outcome = RestoreOutcome {
            preferences: preference_choices(&backed_up, &prefs.current()),
            native_profiles: natives.clone(),
            skipped_catalog_items,
        };
        guard(&self.session).restored = Some(Restored { owner: owner.to_string(), preferences: backed_up, natives });
        outcome
    }

    /// Applies the ticked preferences with their backed-up values (the window names only which ones; the values
    /// come from the backup). The others stay as they are. Returns the ones that failed.
    pub fn apply_preferences(
        &self,
        owner: &str,
        ticked: &[Preference],
        prefs: &dyn PreferencePort,
    ) -> Result<Vec<PreferenceFailure>, String> {
        let backed_up = match &guard(&self.session).restored {
            Some(r) if r.owner == owner => r.preferences,
            _ => return Err("no restore in this window".into()),
        };
        let mut failures = Vec::new();
        let mut seen = HashSet::new();
        for &key in ticked {
            if !seen.insert(key) {
                continue;
            }
            let on = key.value(&backed_up);
            if key == Preference::AutoUnlock && on && !prefs.current().auto_unlock {
                let message = match prefs.confirm_auto_unlock() {
                    Ok(()) => {
                        tr("Enter your master password in the window that opened to turn on automatic unlock.", &[])
                    }
                    Err(message) => message,
                };
                failures.push(PreferenceFailure { key, message });
                continue;
            }
            if let Err(message) = prefs.apply(key, on) {
                failures.push(PreferenceFailure { key, message });
            }
        }
        Ok(failures)
    }

    /// Reinstalls one restored native profile (generated from the vault, the PSK included as the editor does) and
    /// opens it for approval. Returns the list with it marked.
    pub fn reinstall_profile(
        &self,
        owner: &str,
        id: &str,
        installer: &dyn NativeProfiles,
        service_existed: impl Fn(&Uuid) -> bool,
    ) -> Result<Vec<NativeProfileView>, String> {
        let listed = match &guard(&self.session).restored {
            Some(r) if r.owner == owner => r.natives.iter().any(|n| n.id == id),
            _ => return Err("no restore in this window".into()),
        };
        if !listed {
            return Err("not a restored profile".into());
        }
        let (connection, psk) = self
            .vault
            .with_read(|v| {
                let c = v.connections()?.into_iter().map(|s| s.connection).find(|c| uuid_string(&c.id) == id);
                let psk = match &c {
                    Some(c) => v.secret(&uuid_string(&c.id), SecretField::Psk)?,
                    None => None,
                };
                Ok((c, psk))
            })
            .map_err(|e| restore_error_message(&e))?;
        let connection = connection.ok_or_else(|| tr("The connection is no longer in the vault.", &[]))?;
        let psk = psk.unwrap_or_else(|| Zeroizing::new(String::new()));
        let profile = installer.build(&connection, &psk)?;
        drop(psk);
        installer.install(&connection.id, &profile.data, &profile.file_name, service_existed(&connection.id))?;
        let mut session = guard(&self.session);
        let restored = session.restored.as_mut().ok_or("no restore in this window")?;
        for n in &mut restored.natives {
            if n.id == id {
                n.installed = true;
            }
        }
        Ok(restored.natives.clone())
    }

    /// The window closed or started over: its staged backup and its restore record are dropped (the payload's
    /// secrets are wiped on drop).
    pub fn discard(&self, owner: &str) {
        let mut session = guard(&self.session);
        if session.staged.as_ref().is_some_and(|s| s.owner == owner) {
            session.staged = None;
        }
        if session.restored.as_ref().is_some_and(|r| r.owner == owner) {
            session.restored = None;
        }
    }
}

/// The preference rows after a restore: ticked when the backup's value differs from this Mac's, except the
/// control API, which is never ticked by default.
pub fn preference_choices(backed_up: &BackupPreferences, current: &BackupPreferences) -> Vec<PreferenceChoice> {
    Preference::ALL
        .iter()
        .map(|&key| {
            let (b, c) = (key.value(backed_up), key.value(current));
            PreferenceChoice { key, backed_up: b, current: c, ticked: b != c && key != Preference::ControlApi }
        })
        .collect()
}
