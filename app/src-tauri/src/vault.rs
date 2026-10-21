//! The vault in the app (spec 2.3 and 2.7, plan B Tasks 14 and 15): the launch decision, the vault windows and
//! their commands, and what follows an unlock or a lock.
//!
//! - **Launch** ([`launch`], the `OpenVault` launch step, after the Keychain move and before the connections are
//!   read): auto-unlock → the normal launch; a vault without a usable key-store item → the menu is locked and
//!   `vault-unlock` opens; no vault → `vault-create` opens, in migration mode when there is 1.1 data (the app reads
//!   it, read-only, meanwhile).
//! - **Windows** (`vault-*`, their own capability `capabilities/vault.json`): built like the prompt windows – shown
//!   without taking the focus or activating the app (`order_front_regardless`), the one-second input lock counted
//!   from the later of being ordered on screen and the page's `vault_ready` (every command that takes a secret is
//!   refused before), no default button, the navigation allowlist, the height following the content
//!   (`fit_window`, as the prompt windows). The create window cannot be closed while the recovery key is shown or confirmed, or while the
//!   migration runs.
//! - **Commands** check the calling window's label: each command belongs to exactly one window. Passwords and
//!   recovery keys arrive as `String`, move into `Zeroizing` at once, are never logged and never enter the view
//!   model or an event. The recovery key leaves the backend once, in the reply to `vault_create` (and in Task 15 to
//!   `vault_new_recovery_key`), wiped after the reply is serialized.
//! - **After an unlock** ([`after_unlock`]): a pending migration step finishes (an interrupted deletion, or a vault
//!   created in an earlier run before its migration), the manager reloads, and the control API starts if it is on.
//! - **After a lock** ([`after_lock`]): the manager keeps only the redacted active connections, the editors are
//!   dropped; running VPNs stay up.
//!
//! The restore branch of Task 21 hooks in at the create window's intro: `vault_open_restore` (a stub here that
//! Task 21 replaces) and `VaultSetup::set_can_restore`.

use macvpn_app_core::migration::{self, LegacySources, MigrationError, MigrationReport, PendingMigration};
use macvpn_app_core::vault::{VaultLifecycle, VaultState};
use macvpn_app_core::vault_setup::{
    InputLock, KeyConfirmation, LaunchDecision, RECOVERY_GROUPS, SetupAction, SetupStep, UnlockReply, VaultSetup,
    VaultSetupView, launch_decision, parse_setup_action,
};
use macvpn_app_core::view_model::VaultView;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::vault::{Entropy, RecoveryKey, check_password_rules};
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;
use tauri::{AppHandle, Manager, State, WebviewUrl, WebviewWindowBuilder, Window, WindowEvent};
use zeroize::Zeroizing;

use crate::state::AppState;

type Shared<'a> = State<'a, Arc<AppState>>;

/// The create window (first launch, or after the vault was removed by a failed migration).
pub const CREATE_WINDOW: &str = "vault-create";
/// The unlock window (password, or the recovery key with a new password).
pub const UNLOCK_WINDOW: &str = "vault-unlock";
/// Change the master password (`change`), or confirm it to turn auto-unlock on (`confirm`).
pub const PASSWORD_WINDOW: &str = "vault-password";
/// A new recovery key: the password, then the new key shown once and one group retyped.
pub const RECOVERY_WINDOW: &str = "vault-recovery";
/// Every vault window.
pub const VAULT_WINDOWS: [&str; 4] = [CREATE_WINDOW, UNLOCK_WINDOW, PASSWORD_WINDOW, RECOVERY_WINDOW];
/// The preference "Show Lock now" (default off).
pub const SHOW_LOCK_NOW_KEY: &str = "vaultShowLockNow";
/// The window width (points); the height follows the content (`fit_window`).
const WIDTH: f64 = crate::fit::VAULT.width;

/// The vault's part of the app state.
pub struct VaultApp {
    pub lifecycle: Arc<VaultLifecycle>,
    /// The 1.1 storage (the migration's source; the stores' read-only fallback).
    pub legacy: Arc<LegacySources>,
    entropy: Arc<dyn Entropy>,
    setup: Mutex<Option<VaultSetup>>,
    /// The input lock of each open vault window, by label.
    locks: Mutex<HashMap<String, InputLock>>,
    /// A migration runs (one at a time).
    migrating: AtomicBool,
    /// The `vault-password` window's mode while it is open.
    password_mode: Mutex<Option<PasswordMode>>,
    /// The new recovery key of `vault-recovery`, until its group was retyped (wiped on drop).
    new_key: Mutex<Option<KeyConfirmation>>,
}

/// What the `vault-password` window asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordMode {
    Change,
    Confirm,
}

impl PasswordMode {
    pub fn as_str(self) -> &'static str {
        match self {
            PasswordMode::Change => "change",
            PasswordMode::Confirm => "confirm",
        }
    }
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl VaultApp {
    pub fn new(lifecycle: Arc<VaultLifecycle>, legacy: Arc<LegacySources>, entropy: Arc<dyn Entropy>) -> Self {
        VaultApp {
            lifecycle,
            legacy,
            entropy,
            setup: Mutex::new(None),
            locks: Mutex::new(HashMap::new()),
            migrating: AtomicBool::new(false),
            password_mode: Mutex::new(None),
            new_key: Mutex::new(None),
        }
    }

    /// The stores have data to read: unlocked, or the 1.1 storage in the legacy read-only mode.
    pub fn readable(&self) -> bool {
        matches!(self.lifecycle.state(), VaultState::Unlocked | VaultState::LegacyReadOnly { .. })
    }

    /// The view model's part (never a secret).
    pub fn view(&self, show_lock_now_pref: bool) -> (VaultView, Option<VaultSetupView>) {
        let state = self.lifecycle.state();
        // The key-store item's existence (cached after the first look, never a prompt).
        let auto_unlock = !matches!(state, VaultState::NotCreated) && self.lifecycle.auto_unlock();
        let mut view = VaultView::build(&state, auto_unlock, show_lock_now_pref, 0);
        view.password_mode = guard(&self.password_mode).map(PasswordMode::as_str);
        (view, guard(&self.setup).as_ref().map(VaultSetup::view))
    }

    /// The create window's steps, for the fresh restore of Task 21 (`set_can_restore`, `set_restoring`). `None`:
    /// the create window is not open.
    pub fn with_setup<R>(&self, f: impl FnOnce(&mut VaultSetup) -> R) -> Option<R> {
        guard(&self.setup).as_mut().map(f)
    }

    fn lock_of(&self, label: &str) -> InputLock {
        guard(&self.locks).get(label).copied().unwrap_or_default()
    }

    /// One random group index for the "retype one group" check.
    fn random_group(&self) -> usize {
        let mut byte = [0u8; 1];
        match self.entropy.fill(&mut byte) {
            Ok(()) => usize::from(byte[0]) % RECOVERY_GROUPS,
            Err(_) => 0,
        }
    }
}

/// The calling window must be `expected` (each command belongs to one window).
pub fn own_window(label: &str, expected: &str) -> Result<(), String> {
    if label == expected { Ok(()) } else { Err("not this window's command".into()) }
}

/// Whether a window label is a vault window's.
pub fn is_vault_window(label: &str) -> bool {
    VAULT_WINDOWS.contains(&label)
}

// MARK: - Launch, unlock, lock

/// The `OpenVault` launch step (off the main thread).
pub fn launch(app: &AppHandle, state: &Arc<AppState>) {
    let vault = &state.vault;
    let legacy = vault.legacy.clone();
    match launch_decision(&vault.lifecycle, || migration::has_legacy_data(&legacy)) {
        // A migration left from an earlier run (a quit before the old data was deleted): shown in the create
        // window, which explains the Keychain prompts and says how it ended.
        LaunchDecision::Unlocked => match migration::pending(&vault.lifecycle, &legacy) {
            PendingMigration::Run => start_pending_migration(app, state),
            // A vault with the user's data next to 1.1 data that was never imported: left alone, only logged.
            PendingMigration::VaultHasData => {
                eprintln!("MacVPN: Vault: 1.1 data next to a vault with data; it is not migrated");
            }
            PendingMigration::Nothing => {}
        },
        LaunchDecision::Unlock => {
            after_lock(state);
            if let Err(e) = open_window(app, state, UNLOCK_WINDOW) {
                eprintln!("MacVPN: vault window: {e}");
            }
        }
        LaunchDecision::Create { migrating } => {
            if !migrating {
                // Nothing to show until the vault exists.
                state.manager.enter_locked();
            }
            start_setup(app, state, migrating);
        }
    }
    state.publisher.mark();
}

/// Opens the create window at its intro (again after a closed or failed one).
pub fn start_setup(app: &AppHandle, state: &Arc<AppState>, migrating: bool) {
    let items = if migrating { migration::keychain_item_count(&state.vault.legacy) } else { 0 };
    *guard(&state.vault.setup) = Some(VaultSetup::new(migrating, items));
    // "Restore from backup…" at the intro: in place of the migration, the backup becomes the new vault.
    if state.backup.service().is_some() {
        state.vault.with_setup(|s| s.set_can_restore(true));
    }
    if let Err(e) = open_window(app, state, CREATE_WINDOW) {
        eprintln!("MacVPN: vault window: {e}");
    }
    state.publisher.mark();
}

/// The create window for a migration left from an earlier run, at its `Migrating` step; the migration runs on its
/// own thread (macOS may ask for each old Keychain item).
fn start_pending_migration(app: &AppHandle, state: &Arc<AppState>) {
    let items = migration::keychain_item_count(&state.vault.legacy);
    *guard(&state.vault.setup) = Some(VaultSetup::resuming(items));
    if let Err(e) = open_window(app, state, CREATE_WINDOW) {
        eprintln!("MacVPN: vault window: {e}");
    }
    state.publisher.mark();
    let shared = state.clone();
    let spawned = std::thread::Builder::new().name("macvpn-migration".into()).spawn(move || {
        let vault = &shared.vault;
        if vault.migrating.swap(true, Ordering::SeqCst) {
            return;
        }
        let result = migration::migrate(&vault.lifecycle, &vault.legacy);
        vault.migrating.store(false, Ordering::SeqCst);
        if let Err(e) = &result {
            eprintln!("MacVPN: Vault: {e}");
        }
        migration_ended(&shared, result);
        use_the_vault(&shared);
    });
    if let Err(e) = spawned {
        eprintln!("MacVPN: Vault: {e}");
    }
}

/// A migration step left from an earlier run: the deletion of the old data after a verified import, or the
/// import into a vault created before its migration ran. Logged (after an unlock; at launch the create window shows
/// it, see [`start_pending_migration`]).
fn finish_pending_migration(state: &AppState) {
    let vault = &state.vault;
    if !migration::has_legacy_data(&vault.legacy) || vault.migrating.swap(true, Ordering::SeqCst) {
        return;
    }
    match migration::migrate(&vault.lifecycle, &vault.legacy) {
        Ok(report) if report.resumed => eprintln!("MacVPN: Vault: the deletion of the old data was finished"),
        Ok(_) => eprintln!("MacVPN: Vault: the old data was migrated"),
        Err(e) => eprintln!("MacVPN: Vault: {e}"),
    }
    vault.migrating.store(false, Ordering::SeqCst);
}

/// The vault was unlocked (or created): everything is read again, and the control API starts if it is on.
pub fn after_unlock(state: &Arc<AppState>) {
    finish_pending_migration(state);
    use_the_vault(state);
    // The team catalogs refresh once (the scheduler skipped its rounds while locked).
    state.catalog.service.unlocked();
    // Files opened from Finder while it was locked (unless a create window is still in progress).
    crate::open_files::flush(state);
}

/// The app reads the vault (after an unlock, or a migration that keeps the old data until the window's Continue).
fn use_the_vault(state: &Arc<AppState>) {
    state.manager.reload();
    state.connections.system_services_changed();
    state.poller.wake();
    crate::control::launch(state);
    state.publisher.mark();
}

/// The vault was locked: only the redacted active connections stay; the editors are dropped.
pub fn after_lock(state: &AppState) {
    state.manager.enter_locked();
    crate::backup::vault_locked(state);
    state.connections.vault_locked();
    // The add dialog's previews and the chosen files go; the scheduler skips its rounds while locked, and the
    // view model drops the catalogs, the badges and the publishing side.
    state.catalog.vault_locked();
    // A recovery key, team key or subscription string copied earlier leaves the pasteboard (if still there).
    crate::clipboard::clear_secret();
    state.publisher.mark();
}

// MARK: - Windows

fn title(label: &str) -> String {
    match label {
        CREATE_WINDOW => l10n::tr("Set Up the Vault", &[]),
        UNLOCK_WINDOW => l10n::tr("Unlock MacVPN", &[]),
        PASSWORD_WINDOW => l10n::tr("Master Password", &[]),
        RECOVERY_WINDOW => l10n::tr("New Recovery Key", &[]),
        _ => "MacVPN".into(),
    }
}

/// Opens (or brings forward) a vault window, shown like a prompt window: above the others, without taking the
/// focus and without activating the app. Its input lock counts from here (and from its page's `vault_ready`).
pub fn open_window(app: &AppHandle, state: &AppState, label: &str) -> Result<(), String> {
    if let Some(window) = app.get_webview_window(label) {
        return window.set_focus().map_err(|e| e.to_string());
    }
    guard(&state.vault.locks).insert(label.to_string(), InputLock::default());
    let window = WebviewWindowBuilder::new(app, label, WebviewUrl::App("index.html".into()))
        .title(title(label))
        .inner_size(WIDTH, 360.0)
        .resizable(false)
        .minimizable(false)
        .maximizable(false)
        .always_on_top(true)
        .visible(false)
        .focused(false)
        .center()
        .on_navigation(crate::navigation::is_allowed)
        .build()
        .map_err(|e| e.to_string())?;
    let target = window.clone();
    let handle = app.clone();
    let label = label.to_string();
    window
        .run_on_main_thread(move || {
            if let Some(native) = crate::platform::native_window(&target) {
                crate::platform::get().windows().order_front_regardless(native);
                if let Some(state) = handle.try_state::<Arc<AppState>>()
                    && let Some(lock) = guard(&state.vault.locks).get_mut(&label)
                {
                    lock.mark_shown(Instant::now());
                }
            }
        })
        .map_err(|e| e.to_string())
}

fn close_window(app: &AppHandle, label: &str) {
    if let Some(window) = app.get_webview_window(label) {
        let _ = window.destroy();
    }
}

/// The close button: refused while the create window must stay (the key shown, the migration running). A closed
/// create window leaves the app as it is (no vault yet: the menu offers to set it up; migration mode: the 1.1
/// data stays readable).
pub fn on_window_event(window: &Window, event: &WindowEvent) {
    let Some(state) = window.app_handle().try_state::<Arc<AppState>>() else { return };
    match event {
        WindowEvent::CloseRequested { api, .. } if window.label() == CREATE_WINDOW => {
            if guard(&state.vault.setup).as_ref().is_some_and(|s| !s.may_close()) {
                api.prevent_close();
            }
        }
        // The new recovery key is shown or being checked (not saved yet): the window stays.
        WindowEvent::CloseRequested { api, .. } if window.label() == RECOVERY_WINDOW => {
            if guard(&state.vault.new_key).is_some() {
                api.prevent_close();
            }
        }
        WindowEvent::Destroyed => {
            guard(&state.vault.locks).remove(window.label());
            let opening = matches!(window.label(), UNLOCK_WINDOW | CREATE_WINDOW);
            match window.label() {
                PASSWORD_WINDOW => *guard(&state.vault.password_mode) = None,
                RECOVERY_WINDOW => drop(guard(&state.vault.new_key).take()),
                _ => {}
            }
            if window.label() == CREATE_WINDOW {
                crate::backup::discard(&state, CREATE_WINDOW);
                let verified = guard(&state.vault.setup).take().is_some_and(|s| s.step() == SetupStep::Verified);
                if verified {
                    // Closed instead of Continue: the old data goes all the same.
                    let shared = state.inner().clone();
                    std::thread::spawn(move || finish_pending_migration(&shared));
                }
                state.publisher.mark();
            }
            // Files opened from Finder: imported now that the vault is open, dropped if it was not opened.
            if opening {
                crate::open_files::vault_window_closed(state.inner());
            }
        }
        _ => {}
    }
}

// MARK: - Commands (every vault window)

/// The window's page is loaded and shown: its input lock counts from the later of this and being ordered on screen.
#[tauri::command]
pub async fn vault_ready(window: Window, state: Shared<'_>) -> Result<(), String> {
    let label = window.label();
    if !is_vault_window(label) {
        return Err("not a vault window".into());
    }
    match guard(&state.vault.locks).get_mut(label) {
        Some(lock) => {
            lock.mark_loaded(Instant::now());
            Ok(())
        }
        None => Err("no such window".into()),
    }
}

/// Checks the calling window and its input lock.
pub fn armed(state: &AppState, label: &str, expected: &str) -> Result<(), String> {
    own_window(label, expected)?;
    state.vault.lock_of(label).check(Instant::now())
}

/// Whether the text is a recovery key (as the create or the new-key window shows it).
fn is_recovery_key(text: &str) -> bool {
    RecoveryKey::parse(text.trim()).is_ok()
}

/// The create or the new-key window's "Copy": the recovery key (checked) goes to the pasteboard concealed, and
/// leaves it a minute later, at a vault lock or at quit if it is still there.
#[tauri::command]
pub async fn vault_copy_recovery_key(window: Window, recovery_key: String) -> Result<(), String> {
    let recovery_key = Zeroizing::new(recovery_key);
    if window.label() != CREATE_WINDOW && window.label() != RECOVERY_WINDOW {
        return Err("not this window's command".into());
    }
    if recovery_key.len() > 256 || !is_recovery_key(&recovery_key) {
        return Err("invalid recovery key".into());
    }
    crate::clipboard::copy_secret(recovery_key.trim())
}

// MARK: - Create

/// The reply of `vault_create`: the recovery key, shown once (wiped once the reply was serialized).
pub struct CreateReply {
    recovery_key: Zeroizing<String>,
    group: usize,
}

impl Serialize for CreateReply {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("CreateReply", 2)?;
        s.serialize_field("recoveryKey", self.recovery_key.as_str())?;
        s.serialize_field("group", &self.group)?;
        s.end()
    }
}

/// The create window's navigation: `continue`, `back`, `saved`, `retry`, `finish` and `close`.
#[tauri::command]
pub async fn vault_setup_step(app: AppHandle, window: Window, state: Shared<'_>, action: String) -> Result<(), String> {
    own_window(window.label(), CREATE_WINDOW)?;
    if action == "close" {
        let closable = guard(&state.vault.setup).as_ref().is_none_or(VaultSetup::may_close);
        if !closable {
            return Err("not now".into());
        }
        close_window(&app, CREATE_WINDOW);
        return Ok(());
    }
    let action = parse_setup_action(&action)?;
    if action == SetupAction::Finish {
        // Continue after the check (and the backup offer): now the old data is deleted.
        let shared = state.inner().clone();
        tauri::async_runtime::spawn_blocking(move || finish_pending_migration(&shared))
            .await
            .map_err(|e| e.to_string())?;
    }
    if action == SetupAction::Retry && state.vault.lifecycle.exists() {
        // The failed migration kept its vault: the migration runs into it again (a resumed or a fresh import). The
        // legacy read-only mode only while the vault is still empty (the import can claim it); otherwise the run
        // finishes a deletion, finds the user's data, or is refused, and the mode is cleared after it.
        state.vault.with_setup(VaultSetup::retry_migration).ok_or("no setup")??;
        if state.vault.lifecycle.with_read(|v| v.is_empty()).unwrap_or(false) {
            state.vault.lifecycle.set_legacy_read_only(Some(String::new()));
        }
        state.publisher.mark();
        let shared = state.inner().clone();
        std::thread::Builder::new()
            .name("macvpn-migration".into())
            .spawn(move || run_migration(&shared))
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    let restoring = state.vault.with_setup(|setup| setup.restoring()).unwrap_or(false);
    state.vault.with_setup(|setup| setup.act(action)).ok_or("no setup")??;
    if restoring && action == SetupAction::Back {
        // The restore was given up at the password step: the opened backup goes.
        crate::backup::discard(&state, CREATE_WINDOW);
    }
    if action == SetupAction::Retry {
        // The failed migration removed its vault: the next one is created from the password step again.
        state.vault.lifecycle.set_legacy_read_only(Some(String::new()));
    }
    state.publisher.mark();
    Ok(())
}

/// Creates the vault with `password` (at least 10 characters) and `auto_unlock`; the recovery key comes back
/// once. Only at the password step, after the input lock.
#[tauri::command]
pub async fn vault_create(
    window: Window,
    state: Shared<'_>,
    password: String,
    auto_unlock: bool,
) -> Result<CreateReply, String> {
    let password = Zeroizing::new(password);
    armed(&state, window.label(), CREATE_WINDOW)?;
    guard(&state.vault.setup).as_ref().ok_or("no setup")?.may_create()?;
    check_password_rules(&password)?;
    let shared = state.inner().clone();
    let key = tauri::async_runtime::spawn_blocking(move || shared.vault.lifecycle.create(password, auto_unlock))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| l10n::tr("The vault could not be created: %@", &[Arg::Str(&e.to_string())]))?;
    let recovery_key = Zeroizing::new(key.as_str().to_string());
    let group = state.vault.random_group();
    let (migrating, restoring) = {
        let mut setup = guard(&state.vault.setup);
        let setup = setup.as_mut().ok_or("no setup")?;
        setup.created(key, group);
        (setup.migrating(), setup.restoring())
    };
    // Smoke runs keep the key for the recovery step (debug builds; never logged).
    #[cfg(debug_assertions)]
    crate::platform::smoke_remember_recovery_key(&recovery_key);
    // A restore fills the new vault after the recovery key check (`restore_fresh_apply`): until then nothing may
    // write to it (the pending migration of 1.1 data would claim the empty vault).
    if !migrating && !restoring {
        // A fresh vault holds nothing to migrate: the app uses it at once.
        let shared = state.inner().clone();
        tauri::async_runtime::spawn_blocking(move || after_unlock(&shared));
    }
    state.publisher.mark();
    Ok(CreateReply { recovery_key, group })
}

/// "Retype group N": right → the key is dropped and, in migration mode, the migration starts.
#[tauri::command]
pub async fn vault_confirm_recovery(
    window: Window,
    state: Shared<'_>,
    group: usize,
    typed: String,
) -> Result<(), String> {
    let typed = Zeroizing::new(typed);
    armed(&state, window.label(), CREATE_WINDOW)?;
    let step = {
        let mut setup = guard(&state.vault.setup);
        let setup = setup.as_mut().ok_or("no setup")?;
        let result = setup.confirm(group, &typed);
        state.publisher.mark();
        result?;
        setup.step()
    };
    if step == SetupStep::Migrating {
        let shared = state.inner().clone();
        std::thread::Builder::new()
            .name("macvpn-migration".into())
            .spawn(move || run_migration(&shared))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The migration of the create window (its own thread: macOS may show a Keychain prompt per old item).
fn run_migration(state: &Arc<AppState>) {
    let vault = &state.vault;
    if vault.migrating.swap(true, Ordering::SeqCst) {
        return;
    }
    // The old data stays until the window's Continue (it offers a backup first, spec 2.7 step 5).
    let result = migration::migrate_keeping_old_data(&vault.lifecycle, &vault.legacy);
    vault.migrating.store(false, Ordering::SeqCst);
    migration_ended(state, result);
    // The vault is in use unless a failure removed it (then the old data stays readable).
    if !matches!(vault.lifecycle.state(), VaultState::LegacyReadOnly { .. }) {
        use_the_vault(state);
    } else {
        // The failed migration removed the new vault: the 1.1 data stays readable.
        state.manager.reload();
    }
    state.publisher.mark();
}

/// The create window's step after a migration run. A failure that kept the vault (a refusal, or the deletion of
/// the old data) leaves no legacy read-only mode behind: the app uses the vault; only a failure that removed the
/// new vault keeps the old data in use, read-only.
fn migration_ended(state: &AppState, result: Result<MigrationReport, MigrationError>) {
    let lifecycle = &state.vault.lifecycle;
    let removed = result.as_ref().err().is_some_and(MigrationError::legacy_read_only);
    if result.is_err() && !removed && lifecycle.exists() {
        lifecycle.set_legacy_read_only(None);
    }
    if let Some(setup) = guard(&state.vault.setup).as_mut() {
        match result {
            Ok(report) => setup.migrated(Ok(report)),
            Err(e) => setup.failed(l10n::tr("The migration did not finish: %@", &[Arg::Str(&e.to_string())]), removed),
        }
    }
}

/// "Restore from backup…" at the create window's intro, once the window opened a backup (`restore_open`, fresh):
/// the window goes on to the master password and the recovery key as for a new vault, without the migration; after
/// the key check it restores the backup into the new vault (`restore_fresh_apply`).
#[tauri::command]
pub async fn vault_open_restore(window: Window, state: Shared<'_>) -> Result<(), String> {
    armed(&state, window.label(), CREATE_WINDOW)?;
    let opened = state.backup.service().is_some_and(|s| s.has_staged(CREATE_WINDOW));
    if !opened {
        return Err("no backup is open in this window".into());
    }
    state
        .vault
        .with_setup(|setup| {
            if !setup.view().can_restore {
                return Err("not at this step".to_string());
            }
            setup.set_restoring();
            setup.act(SetupAction::Continue)
        })
        .ok_or("no setup")??;
    state.publisher.mark();
    Ok(())
}

/// The password window in `mode`. An open window keeps its mode (it may hold typed text); it only comes forward.
fn show_password_window(app: &AppHandle, state: &AppState, mode: PasswordMode) -> Result<(), String> {
    if app.get_webview_window(PASSWORD_WINDOW).is_none() {
        *guard(&state.vault.password_mode) = Some(mode);
    }
    state.publisher.mark();
    open_window(app, state, PASSWORD_WINDOW)
}

/// Automatic unlock is to be turned on from elsewhere (a restore's preferences): the master password confirms it in
/// the password window, as from the menu.
pub fn show_confirm_password(app: &AppHandle, state: &AppState) -> Result<(), String> {
    if !window_allowed(VaultWindow::ConfirmPassword, &state.vault.lifecycle.state()) {
        return Err(l10n::tr("Automatic unlocking could not be changed.", &[]));
    }
    show_password_window(app, state, PasswordMode::Confirm)
}

/// The create window's restore is written (`restore_fresh_apply`): the backup is the vault's content now. The 1.1
/// data, when there was some, is not migrated (the app leaves the legacy read-only mode; the old files stay where
/// they are), and the app reads everything from the vault.
pub fn after_fresh_restore(state: &Arc<AppState>) {
    // The 1.1 data was not imported (the window said so before the restore): it is deleted now, its Keychain items
    // too, and marked as done, so no later launch offers a migration.
    if migration::has_legacy_data(&state.vault.legacy)
        && let Err(e) = migration::discard_after_restore(&state.vault.lifecycle, &state.vault.legacy)
    {
        eprintln!("MacVPN: Vault: the 1.1 data could not be deleted after the restore: {e}");
    }
    if matches!(state.vault.lifecycle.state(), VaultState::LegacyReadOnly { .. }) {
        state.vault.lifecycle.set_legacy_read_only(None);
    }
    state.manager.reload_all();
    state.connections.system_services_changed();
    state.poller.wake();
    crate::control::launch(state);
    state.publisher.mark();
}

// MARK: - Unlock

/// Unlocks with the master password (the wrong-attempt delay applies; the reply says how long).
#[tauri::command]
pub async fn vault_unlock(
    app: AppHandle,
    window: Window,
    state: Shared<'_>,
    password: String,
) -> Result<UnlockReply, String> {
    let password = Zeroizing::new(password);
    armed(&state, window.label(), UNLOCK_WINDOW)?;
    let shared = state.inner().clone();
    let reply = tauri::async_runtime::spawn_blocking(move || {
        let result = shared.vault.lifecycle.unlock_with_password(password, Instant::now());
        let ok = result.is_ok();
        if ok {
            after_unlock(&shared);
        }
        UnlockReply::from_result(result)
    })
    .await
    .map_err(|e| e.to_string())?;
    if reply.ok {
        close_window(&app, UNLOCK_WINDOW);
    }
    Ok(reply)
}

/// Resets the master password with the recovery key and unlocks.
#[tauri::command]
pub async fn vault_recover(
    app: AppHandle,
    window: Window,
    state: Shared<'_>,
    recovery_key: String,
    new_password: String,
) -> Result<UnlockReply, String> {
    let recovery_key = Zeroizing::new(recovery_key);
    let new_password = Zeroizing::new(new_password);
    armed(&state, window.label(), UNLOCK_WINDOW)?;
    let Ok(key) = RecoveryKey::parse(&recovery_key) else {
        return Ok(UnlockReply::invalid(l10n::tr("This is not a valid recovery key", &[])));
    };
    drop(recovery_key);
    if let Err(message) = check_password_rules(&new_password) {
        return Ok(UnlockReply::invalid(message));
    }
    let shared = state.inner().clone();
    let reply = tauri::async_runtime::spawn_blocking(move || {
        let result = shared.vault.lifecycle.reset_with_recovery(&key, new_password, Instant::now());
        if result.is_ok() {
            after_unlock(&shared);
        }
        UnlockReply::from_result(result)
    })
    .await
    .map_err(|e| e.to_string())?;
    if reply.ok {
        close_window(&app, UNLOCK_WINDOW);
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_recovery_key_is_copied() {
        let key = RecoveryKey::generate(&macvpn_core::vault::FixedEntropy::new(4)).unwrap();
        assert!(is_recovery_key(key.as_str()));
        assert!(is_recovery_key(&format!("  {}\n", key.as_str())));
        for other in ["", "hello", "ABCD-EFGH", "https://example.com/"] {
            assert!(!is_recovery_key(other), "{other}");
        }
    }

    #[test]
    fn each_command_belongs_to_one_window() {
        assert!(own_window(CREATE_WINDOW, CREATE_WINDOW).is_ok());
        for label in [UNLOCK_WINDOW, "menu", "manage", "vault-create2", "cred-1", ""] {
            assert!(own_window(label, CREATE_WINDOW).is_err(), "{label}");
        }
        assert!(is_vault_window(CREATE_WINDOW) && is_vault_window(UNLOCK_WINDOW));
        assert!(!is_vault_window("vault-other") && !is_vault_window("menu"));
    }

    #[test]
    fn the_menu_opens_each_window_only_in_its_state() {
        use VaultWindow::*;
        let legacy = VaultState::LegacyReadOnly { error: String::new() };
        for (window, allowed) in [
            (Unlock, vec![VaultState::Locked]),
            (Create, vec![VaultState::NotCreated, legacy.clone()]),
            (ChangePassword, vec![VaultState::Unlocked]),
            (ConfirmPassword, vec![VaultState::Unlocked]),
            (NewRecoveryKey, vec![VaultState::Unlocked]),
        ] {
            for state in [VaultState::NotCreated, VaultState::Locked, VaultState::Unlocked, legacy.clone()] {
                assert_eq!(window_allowed(window, &state), allowed.contains(&state), "{window:?} {state:?}");
            }
        }
        for (raw, window) in [
            ("unlock", Unlock),
            ("create", Create),
            ("changePassword", ChangePassword),
            ("confirmPassword", ConfirmPassword),
            ("newRecoveryKey", NewRecoveryKey),
        ] {
            assert_eq!(parse_vault_window(raw), Ok(window));
        }
        assert!(parse_vault_window("manage").is_err());
    }

    #[test]
    fn the_new_key_reply_carries_the_key_only_on_success() {
        let ok = NewKeyReply {
            reply: UnlockReply::ok(),
            key: Some(CreateReply { recovery_key: Zeroizing::new("ABCD".into()), group: 1 }),
        };
        let json = serde_json::to_value(&ok).unwrap();
        assert_eq!(json["key"], serde_json::json!({"recoveryKey": "ABCD", "group": 1}));
        assert_eq!(json["reply"]["ok"], true);
        let wrong = NewKeyReply {
            reply: UnlockReply::from_result(Err(macvpn_app_core::vault::UnlockError::Wrong {
                retry_after: std::time::Duration::from_secs(1),
            })),
            key: None,
        };
        assert_eq!(serde_json::to_value(&wrong).unwrap()["key"], serde_json::Value::Null);
    }

    #[test]
    fn the_create_reply_serializes_the_key_once() {
        let reply = CreateReply { recovery_key: Zeroizing::new("ABCD-EFGH".into()), group: 2 };
        assert_eq!(serde_json::to_value(&reply).unwrap(), serde_json::json!({"recoveryKey": "ABCD-EFGH", "group": 2}));
    }

    #[test]
    fn titles_are_translated() {
        for label in VAULT_WINDOWS {
            let en = title(label);
            let hu = l10n::with_language(l10n::AppLanguage::Hu, || title(label));
            assert_ne!(en, hu, "{label}");
        }
    }
}

// MARK: - Settings and Lock now (the menu and the Connections window)

/// Which vault window the menu may open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultWindow {
    Unlock,
    Create,
    ChangePassword,
    ConfirmPassword,
    NewRecoveryKey,
}

pub fn parse_vault_window(raw: &str) -> Result<VaultWindow, String> {
    match raw {
        "unlock" => Ok(VaultWindow::Unlock),
        "create" => Ok(VaultWindow::Create),
        "changePassword" => Ok(VaultWindow::ChangePassword),
        "confirmPassword" => Ok(VaultWindow::ConfirmPassword),
        "newRecoveryKey" => Ok(VaultWindow::NewRecoveryKey),
        _ => Err("unknown window".into()),
    }
}

/// Whether `window` may open in `state`: the unlock window while locked, the create window without a vault (or
/// in the legacy read-only mode), the others only while unlocked.
pub fn window_allowed(window: VaultWindow, state: &VaultState) -> bool {
    match window {
        VaultWindow::Unlock => *state == VaultState::Locked,
        VaultWindow::Create => matches!(state, VaultState::NotCreated | VaultState::LegacyReadOnly { .. }),
        VaultWindow::ChangePassword | VaultWindow::ConfirmPassword | VaultWindow::NewRecoveryKey => {
            *state == VaultState::Unlocked
        }
    }
}

/// Opens a vault window from the menu ("Unlock…", "Set Up the Vault…", "Change Master Password…", turning
/// "Unlock Automatically" on, "New Recovery Key…").
#[tauri::command]
pub async fn vault_show(app: AppHandle, state: Shared<'_>, window: String) -> Result<(), String> {
    let window = parse_vault_window(&window)?;
    let vault = &state.vault;
    if !window_allowed(window, &vault.lifecycle.state()) {
        return Err("not now".into());
    }
    crate::tray::hide_menu(&app);
    match window {
        VaultWindow::Unlock => open_window(&app, &state, UNLOCK_WINDOW),
        VaultWindow::Create => {
            if app.get_webview_window(CREATE_WINDOW).is_some() {
                return open_window(&app, &state, CREATE_WINDOW);
            }
            let shared = state.inner().clone();
            let migrating =
                tauri::async_runtime::spawn_blocking(move || migration::has_legacy_data(&shared.vault.legacy))
                    .await
                    .map_err(|e| e.to_string())?;
            start_setup(&app, &state, migrating);
            Ok(())
        }
        VaultWindow::ChangePassword => show_password_window(&app, &state, PasswordMode::Change),
        VaultWindow::ConfirmPassword => show_password_window(&app, &state, PasswordMode::Confirm),
        VaultWindow::NewRecoveryKey => open_window(&app, &state, RECOVERY_WINDOW),
    }
}

/// "Lock Now": the vault closes and its key is wiped; running VPNs stay up; the menu shows the locked state. The
/// password and recovery windows close (they need the open vault).
#[tauri::command]
pub async fn vault_lock_now(app: AppHandle, state: Shared<'_>) -> Result<(), String> {
    if !state.vault.lifecycle.is_unlocked() {
        return Err("not unlocked".into());
    }
    // The create window past its password step (the key shown or checked, the migration or the restore not
    // finished): the lock waits for it.
    if state.vault.with_setup(|s| s.blocks_lock()).unwrap_or(false) {
        return Err("not now".into());
    }
    close_window(&app, PASSWORD_WINDOW);
    close_window(&app, RECOVERY_WINDOW);
    // The backup and restore windows need the open vault too (their open backups are dropped with them).
    close_window(&app, crate::backup::BACKUP_WINDOW);
    close_window(&app, crate::backup::RESTORE_WINDOW);
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        // First the manager (the names go, the prompts close, the connects still asking end), then the vault.
        shared.manager.enter_locked();
        shared.vault.lifecycle.lock();
        after_lock(&shared);
    })
    .await
    .map_err(|e| e.to_string())
}

/// "Unlock Automatically" off (after the menu's confirmation): the Keychain item is deleted; every launch asks for
/// the master password. (On goes through `vault-password` in `confirm` mode.)
#[tauri::command]
pub async fn vault_auto_unlock_off(state: Shared<'_>) -> Result<(), String> {
    let shared = state.inner().clone();
    let result = tauri::async_runtime::spawn_blocking(move || shared.vault.lifecycle.set_auto_unlock(false))
        .await
        .map_err(|e| e.to_string())?;
    state.publisher.mark();
    result.map_err(|e| l10n::tr("Automatic unlock could not be turned off: %@", &[Arg::Str(&e.to_string())]))
}

/// "Show Lock Now" (preference, default off).
#[tauri::command]
pub async fn vault_set_show_lock_now(state: Shared<'_>, on: bool) -> Result<(), String> {
    state.prefs.set_bool(SHOW_LOCK_NOW_KEY, on);
    state.publisher.mark();
    Ok(())
}

// MARK: - The password and recovery windows

/// Closes the calling vault window (Cancel, Done). The create window only when it may close.
#[tauri::command]
pub async fn vault_close(app: AppHandle, window: Window, state: Shared<'_>) -> Result<(), String> {
    let label = window.label();
    if !is_vault_window(label) {
        return Err("not a vault window".into());
    }
    if label == CREATE_WINDOW && guard(&state.vault.setup).as_ref().is_some_and(|s| !s.may_close()) {
        return Err("not now".into());
    }
    if label == RECOVERY_WINDOW && guard(&state.vault.new_key).is_some() {
        return Err("not now".into());
    }
    close_window(&app, label);
    Ok(())
}

fn password_mode(state: &AppState) -> Option<PasswordMode> {
    *guard(&state.vault.password_mode)
}

/// `change` mode: the current password and the new one (at least 10 characters). Only the password slot is
/// rewritten; the wrong-attempt delay applies.
#[tauri::command]
pub async fn vault_change_password(
    window: Window,
    state: Shared<'_>,
    current: String,
    new_password: String,
) -> Result<UnlockReply, String> {
    let current = Zeroizing::new(current);
    let new_password = Zeroizing::new(new_password);
    armed(&state, window.label(), PASSWORD_WINDOW)?;
    if password_mode(&state) != Some(PasswordMode::Change) {
        return Err("not this mode".into());
    }
    if let Err(message) = check_password_rules(&new_password) {
        return Ok(UnlockReply::invalid(message));
    }
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        UnlockReply::from_result(shared.vault.lifecycle.change_password(current, new_password))
    })
    .await
    .map_err(|e| e.to_string())
}

/// `confirm` mode: the master password is checked (with the delay), then the vault key goes to the Keychain.
#[tauri::command]
pub async fn vault_enable_auto_unlock(
    app: AppHandle,
    window: Window,
    state: Shared<'_>,
    password: String,
) -> Result<UnlockReply, String> {
    let password = Zeroizing::new(password);
    armed(&state, window.label(), PASSWORD_WINDOW)?;
    if password_mode(&state) != Some(PasswordMode::Confirm) {
        return Err("not this mode".into());
    }
    let shared = state.inner().clone();
    let reply = tauri::async_runtime::spawn_blocking(move || {
        let lifecycle = &shared.vault.lifecycle;
        match lifecycle.verify_password(password, Instant::now()) {
            Ok(()) => match lifecycle.set_auto_unlock(true) {
                Ok(()) => UnlockReply::ok(),
                Err(e) => UnlockReply {
                    ok: false,
                    error: Some("error"),
                    retry_after_ms: None,
                    message: Some(l10n::tr("Automatic unlock could not be turned on: %@", &[Arg::Str(&e.to_string())])),
                },
            },
            Err(e) => UnlockReply::from_result(Err(e)),
        }
    })
    .await
    .map_err(|e| e.to_string())?;
    state.publisher.mark();
    if reply.ok {
        close_window(&app, PASSWORD_WINDOW);
    }
    Ok(reply)
}

/// The reply of `vault_new_recovery_key`: the unlock reply, and on success the new key (shown once; wiped once the
/// reply was serialized) with the group to retype.
pub struct NewKeyReply {
    reply: UnlockReply,
    key: Option<CreateReply>,
}

impl Serialize for NewKeyReply {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("NewKeyReply", 2)?;
        s.serialize_field("reply", &self.reply)?;
        s.serialize_field("key", &self.key)?;
        s.end()
    }
}

/// A new recovery key: the master password is checked (with the delay) and the new key comes back once. It is held
/// here, in memory only, and saved (the old key stops working) only once its group was retyped
/// (`vault_confirm_new_key`); until then the window cannot be closed.
#[tauri::command]
pub async fn vault_new_recovery_key(
    window: Window,
    state: Shared<'_>,
    password: String,
) -> Result<NewKeyReply, String> {
    let password = Zeroizing::new(password);
    armed(&state, window.label(), RECOVERY_WINDOW)?;
    if guard(&state.vault.new_key).is_some() {
        return Err("a new key is waiting for its check".into());
    }
    let shared = state.inner().clone();
    let result = tauri::async_runtime::spawn_blocking(move || shared.vault.lifecycle.new_recovery_key(password))
        .await
        .map_err(|e| e.to_string())?;
    let key = match result {
        Ok(key) => key,
        Err(e) => return Ok(NewKeyReply { reply: UnlockReply::from_result(Err(e)), key: None }),
    };
    let recovery_key = Zeroizing::new(key.as_str().to_string());
    let group = state.vault.random_group();
    *guard(&state.vault.new_key) = Some(KeyConfirmation::new(key, group));
    Ok(NewKeyReply { reply: UnlockReply::ok(), key: Some(CreateReply { recovery_key, group }) })
}

/// "Retype group N" of the new key: right → the key is saved (the old one stops working), then dropped here.
#[tauri::command]
pub async fn vault_confirm_new_key(
    window: Window,
    state: Shared<'_>,
    group: usize,
    typed: String,
) -> Result<(), String> {
    let typed = Zeroizing::new(typed);
    armed(&state, window.label(), RECOVERY_WINDOW)?;
    guard(&state.vault.new_key).as_ref().ok_or("no new key")?.check(group, &typed)?;
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let held = guard(&shared.vault.new_key);
        let key = held.as_ref().ok_or("no new key")?.key();
        shared
            .vault
            .lifecycle
            .save_recovery_key(key)
            .map_err(|e| UnlockReply::from_result(Err(e)).message.unwrap_or_default())
    })
    .await
    .map_err(|e| e.to_string())??;
    guard(&state.vault.new_key).take();
    Ok(())
}
