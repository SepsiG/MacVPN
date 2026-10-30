//! The full backup and restore windows (spec 3b, plan B Task 21): "Back up everything…" (`backup`) and "Restore
//! from backup…" (`restore`), opened from the menu's Settings and the Connections window, plus the first-run
//! restore from the create-vault window (`vault-create`, Task 14). The orchestration is
//! `macvpn_app_core::backup::BackupService`; this module adds the native panels, the worker threads and the label
//! checks.
//!
//! - **No path crosses IPC.** The save / open panel runs here (`dialogs.rs`); the chosen path stays in
//!   [`BackupApp`] under the window's label, and only the file's name goes back for display. The file is read only
//!   through `backup::read_backup_file` and written only through `backup::write_backup` (atomic, 0600).
//! - **Passwords** arrive once (`backup_save`, `restore_open`), move into `Zeroizing` strings at once, and are
//!   dropped when the call returns. They are never logged, stored, put into the view model or an event.
//! - **Long calls** (Argon2id runs for seconds; the restore writes the whole vault) run on the blocking pool; the
//!   window shows its progress until the command returns, and cannot be closed meanwhile.
//! - **Labels:** each command answers only the windows that use it (and the capability files grant it only to
//!   them): `backup` saves, `restore` restores into the open vault, `vault-create` restores into the new one.
//!
//! The vault is attached once it exists ([`BackupApp::attach`], from the vault wiring); until then every command
//! says the backup is not available, and the menu does not offer it.

use macvpn_app_core::backup::{
    BackupService, NativeProfileView, PasswordSource, Preference, PreferenceFailure, PreferencePort, RestoreOutcome,
    RestoreSummary, default_file_name, parse_choice,
};
use macvpn_core::date::Date;
use macvpn_core::l10n;
use macvpn_core::vault::backup::{self as format, BackupPreferences};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use tauri::{AppHandle, Manager, State, WebviewUrl, WebviewWindowBuilder, Window, WindowEvent};
use zeroize::Zeroizing;

use crate::state::AppState;

type Shared<'a> = State<'a, Arc<AppState>>;

pub const BACKUP_WINDOW: &str = "backup";
pub const RESTORE_WINDOW: &str = "restore";
/// Task 14's create-vault window: its "Restore from backup…" branch calls the `restore_*` commands below.
pub const FRESH_WINDOW: &str = "vault-create";

/// The backup service (once the vault exists) and the files chosen in the panels, by window label.
#[derive(Default)]
pub struct BackupApp {
    service: RwLock<Option<Arc<BackupService>>>,
    picked: Mutex<HashMap<String, PathBuf>>,
    /// A backup or restore call runs: its window cannot be closed.
    running: AtomicBool,
}

impl BackupApp {
    /// Connects the vault's backup service (the vault wiring calls this once the vault exists).
    pub fn attach(&self, service: Arc<BackupService>) {
        *self.service.write().unwrap_or_else(PoisonError::into_inner) = Some(service);
    }

    pub fn service(&self) -> Option<Arc<BackupService>> {
        self.service.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Backup and restore are offered (the vault is open).
    pub fn available(&self) -> bool {
        self.service().is_some_and(|s| s.available())
    }

    fn require(&self) -> Result<Arc<BackupService>, String> {
        self.service().ok_or_else(|| l10n::tr("Backup is available once the vault is set up.", &[]))
    }

    fn pick(&self, label: &str, path: PathBuf) {
        self.picked.lock().unwrap_or_else(PoisonError::into_inner).insert(label.to_string(), path);
    }

    fn picked(&self, label: &str) -> Result<PathBuf, String> {
        self.picked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(label)
            .cloned()
            .ok_or_else(|| "no file chosen".into())
    }

    fn forget(&self, label: &str) {
        self.picked.lock().unwrap_or_else(PoisonError::into_inner).remove(label);
    }
}

/// Marks a long call; the window's close button waits for it.
struct Running<'a>(&'a AtomicBool);

impl<'a> Running<'a> {
    fn start(flag: &'a AtomicBool) -> Result<Self, String> {
        if flag.swap(true, Ordering::SeqCst) {
            return Err(l10n::tr("Another backup or restore is running.", &[]));
        }
        Ok(Running(flag))
    }
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// The windows a command may answer.
fn allow(label: &str, windows: &[&str]) -> Result<(), String> {
    if windows.contains(&label) { Ok(()) } else { Err("not available in this window".into()) }
}

/// The create window's restore commands wait for the vault windows' input lock (like its other commands).
fn needs_input_lock(label: &str) -> bool {
    label == FRESH_WINDOW
}

/// [`allow`], and for the create window its input lock ([`crate::vault::armed`]).
fn allow_armed(state: &AppState, label: &str, windows: &[&str]) -> Result<(), String> {
    allow(label, windows)?;
    if needs_input_lock(label) {
        crate::vault::armed(state, label, FRESH_WINDOW)?;
    }
    Ok(())
}

/// The vault was locked: every open backup and chosen file is dropped (the windows are closed by the caller).
pub fn vault_locked(state: &AppState) {
    for label in [BACKUP_WINDOW, RESTORE_WINDOW, FRESH_WINDOW] {
        discard(state, label);
    }
}

/// Whether a window label is one of this module's windows.
pub fn is_backup_window(label: &str) -> bool {
    label == BACKUP_WINDOW || label == RESTORE_WINDOW
}

pub fn window_title(name: &str) -> Result<&'static str, String> {
    match name {
        BACKUP_WINDOW => Ok("Back Up Everything"),
        RESTORE_WINDOW => Ok("Restore from Backup"),
        _ => Err("unknown window".into()),
    }
}

/// "Back up everything…" / "Restore from backup…" (the menu's Settings, the Connections window, and "Back up the
/// current state first" in the restore window).
#[tauri::command]
pub async fn backup_show_window(app: AppHandle, state: Shared<'_>, name: String) -> Result<(), String> {
    window_title(&name)?;
    if !state.backup.available() {
        return Err(l10n::tr("The vault is locked. Unlock it first.", &[]));
    }
    show(&app, &name)
}

/// Opens (or brings forward) the backup or the restore window.
pub fn show(app: &AppHandle, name: &str) -> Result<(), String> {
    let title = window_title(name)?;
    crate::tray::hide_menu(app);
    let window = match app.get_webview_window(name) {
        Some(window) => window,
        None => WebviewWindowBuilder::new(app, name, WebviewUrl::App("index.html".into()))
            .title(l10n::tr(title, &[]))
            .inner_size(520.0, if name == BACKUP_WINDOW { 560.0 } else { 640.0 })
            .min_inner_size(440.0, 420.0)
            .minimizable(false)
            .maximizable(false)
            .center()
            .visible(false)
            .use_https_scheme(crate::navigation::uses_https_scheme())
            .on_navigation(crate::navigation::is_allowed)
            .build()
            .map_err(|e| e.to_string())?,
    };
    crate::dock::sync(app);
    let _ = window.show();
    window.set_focus().map_err(|e| e.to_string())
}

/// The file name of a chosen path, for display only.
fn display_name(path: &std::path::Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// The save panel for the new backup, with `<product>-backup-<date>.macvpnbackup` (`MacVPN-backup-…` on macOS).
/// The path stays here; the window gets the file name (`None`: cancelled).
#[tauri::command]
pub async fn backup_choose_destination(
    app: AppHandle,
    window: Window,
    state: Shared<'_>,
) -> Result<Option<String>, String> {
    allow(window.label(), &[BACKUP_WINDOW])?;
    state.backup.require()?;
    let platform = crate::platform::get();
    let today = platform.system().local_date(Date::now().time_interval_since_1970());
    let name = default_file_name(platform.product().name, &today);
    #[cfg(debug_assertions)]
    if let Some(path) = crate::platform::smoke_backup_file(&state) {
        state.backup.pick(BACKUP_WINDOW, path.clone());
        return Ok(Some(display_name(&path)));
    }
    let message = l10n::tr("Anyone with this file and its password can read all your VPN credentials.", &[]);
    let Some(path) = crate::dialogs::choose_save_path(&app, &state, BACKUP_WINDOW, name, Some(message)).await? else {
        return Ok(None);
    };
    state.backup.pick(BACKUP_WINDOW, path.clone());
    Ok(Some(display_name(&path)))
}

/// Seals the whole vault and writes it to the chosen file. `master` is always checked against the vault (with the
/// unlock delay); the file is sealed with `password` (an own backup password) or, without one, with `master`.
#[tauri::command]
pub async fn backup_save(
    window: Window,
    state: Shared<'_>,
    master: String,
    password: Option<String>,
) -> Result<(), String> {
    let master = Zeroizing::new(master);
    let password = password.map(Zeroizing::new);
    allow(window.label(), &[BACKUP_WINDOW])?;
    let service = state.backup.require()?;
    let path = state.backup.picked(BACKUP_WINDOW)?;
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _running = Running::start(&shared.backup.running)?;
        let prefs = AppPreferences { state: shared.clone(), service: service.clone(), app: None }.current();
        let source = password.map_or(PasswordSource::Master, PasswordSource::Own);
        let bytes = service.make(master, source, prefs, Date::now())?;
        format::write_backup(&path, &bytes).map_err(|e| macvpn_app_core::backup::backup_error_message(&e))?;
        shared.backup.forget(BACKUP_WINDOW);
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The open panel for a backup file (one file). The path stays here; the window gets the file name (`None`:
/// cancelled). A new file drops what this window had open.
#[tauri::command]
pub async fn restore_choose_file(app: AppHandle, window: Window, state: Shared<'_>) -> Result<Option<String>, String> {
    let label = window.label().to_string();
    allow_armed(&state, &label, &[RESTORE_WINDOW, FRESH_WINDOW])?;
    let service = state.backup.require()?;
    #[cfg(debug_assertions)]
    if let Some(path) = crate::platform::smoke_backup_file(&state) {
        service.discard(&label);
        state.backup.pick(&label, path.clone());
        return Ok(Some(display_name(&path)));
    }
    let Some(path) = crate::dialogs::choose_files(&app, &state, &label, false).await?.into_iter().next() else {
        return Ok(None);
    };
    service.discard(&label);
    state.backup.pick(&label, path.clone());
    Ok(Some(display_name(&path)))
}

/// Opens the chosen backup with its password and returns the restore's numbers; nothing is written yet.
#[tauri::command]
pub async fn restore_open(window: Window, state: Shared<'_>, password: String) -> Result<RestoreSummary, String> {
    let password = Zeroizing::new(password);
    let label = window.label().to_string();
    allow_armed(&state, &label, &[RESTORE_WINDOW, FRESH_WINDOW])?;
    let service = state.backup.require()?;
    let path = state.backup.picked(&label)?;
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _running = Running::start(&shared.backup.running)?;
        let bytes = format::read_backup_file(&path).map_err(|e| macvpn_app_core::backup::backup_error_message(&e))?;
        service.open(&label, &bytes, password, label == FRESH_WINDOW)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Restores the open backup into the vault: `mode` `merge` with `conflict` (`overwrite`, `keepExisting`,
/// `keepBoth`), or `replace` with `expected_lost` as the confirmation named it.
#[tauri::command]
pub async fn restore_apply(
    window: Window,
    state: Shared<'_>,
    mode: String,
    conflict: Option<String>,
    expected_lost: Option<usize>,
) -> Result<RestoreOutcome, String> {
    allow(window.label(), &[RESTORE_WINDOW])?;
    let choice = parse_choice(&mode, conflict.as_deref(), expected_lost)?;
    let service = state.backup.require()?;
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _running = Running::start(&shared.backup.running)?;
        let known = shared.manager.listed_service_ids();
        let prefs = AppPreferences { state: shared.clone(), service: service.clone(), app: None };
        let mut outcome = service.apply(RESTORE_WINDOW, choice, &known, Date::now(), &prefs)?;
        install_restored_profiles(&shared, &service, RESTORE_WINDOW, &mut outcome);
        restored(&shared);
        Ok(outcome)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The first-run restore (Task 14's create-vault window, after the new vault and its recovery key are set up,
/// in place of the migration): the open backup becomes the new vault's contents.
#[tauri::command]
pub async fn restore_fresh_apply(window: Window, state: Shared<'_>) -> Result<RestoreOutcome, String> {
    allow_armed(&state, window.label(), &[FRESH_WINDOW])?;
    // Only a restoring setup after its recovery key check (the new vault exists and its key was confirmed).
    state.vault.with_setup(|s| s.may_restore_fresh()).ok_or("no setup")??;
    let service = state.backup.require()?;
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _running = Running::start(&shared.backup.running)?;
        let known = shared.manager.listed_service_ids();
        let prefs = AppPreferences { state: shared.clone(), service: service.clone(), app: None };
        let mut outcome = service.apply_fresh(FRESH_WINDOW, &known, Date::now(), &prefs)?;
        install_restored_profiles(&shared, &service, FRESH_WINDOW, &mut outcome);
        crate::vault::after_fresh_restore(&shared);
        Ok(outcome)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// WinVPN 2c Task 13: where installing a native profile needs no approval, the restored L2TP connections get their
/// system profile (the Windows VPN entry) right away; a refused one (Cisco IPsec on Windows) shows its reason in
/// "After a restore". Nothing on macOS (each is reinstalled and approved one by one).
fn install_restored_profiles(state: &AppState, service: &BackupService, label: &str, outcome: &mut RestoreOutcome) {
    let installer = state.connections.deps().profiles.clone();
    if installer.needs_approval() {
        return;
    }
    let installed = state.manager.installed_native_ids();
    if let Ok(list) = service.install_profiles_without_approval(label, installer.as_ref(), |id| installed.contains(id))
    {
        outcome.native_profiles = list;
    }
}

/// After a restore: everything is read from the vault again (the ranking, the OTP settings and the folders too);
/// open editors are dropped (they hold what the restore replaced); the windows get the new state. WinVPN: the
/// profiles of connections the restore replaced are removed.
fn restored(state: &Arc<AppState>) {
    state.manager.reload_all();
    state.connections.vault_locked();
    state.connections.system_services_changed();
    crate::vault::sync_native_profiles(state);
    state.publisher.mark();
}

/// Applies the ticked preferences (by name; the values are the backup's). Returns the ones that failed.
#[tauri::command]
pub async fn restore_apply_preferences(
    app: AppHandle,
    window: Window,
    state: Shared<'_>,
    keys: Vec<String>,
) -> Result<Vec<PreferenceFailure>, String> {
    let label = window.label().to_string();
    allow_armed(&state, &label, &[RESTORE_WINDOW, FRESH_WINDOW])?;
    if keys.len() > Preference::ALL.len() {
        return Err("too many preferences".into());
    }
    let keys = keys.iter().map(|k| Preference::parse(k)).collect::<Result<Vec<_>, _>>()?;
    let service = state.backup.require()?;
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let prefs = AppPreferences { state: shared.clone(), service: service.clone(), app: Some(app) };
        let result = service.apply_preferences(&label, &keys, &prefs);
        shared.publisher.mark();
        result
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Reinstalls one restored native profile through the existing installer (macOS asks to approve it).
#[tauri::command]
pub async fn restore_reinstall_profile(
    window: Window,
    state: Shared<'_>,
    id: String,
) -> Result<Vec<NativeProfileView>, String> {
    let label = window.label().to_string();
    allow_armed(&state, &label, &[RESTORE_WINDOW, FRESH_WINDOW])?;
    crate::commands::validate_key(&id)?;
    let service = state.backup.require()?;
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let installed = shared.manager.installed_native_ids();
        let installer = shared.connections.deps().profiles.clone();
        service.reinstall_profile(&label, &id, installer.as_ref(), |id| installed.contains(id))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// "Done" / "Cancel": closes the calling backup or restore window (its state goes with it).
#[tauri::command]
pub async fn backup_close_window(window: Window, state: Shared<'_>) -> Result<(), String> {
    allow(window.label(), &[BACKUP_WINDOW, RESTORE_WINDOW])?;
    if state.backup.running.load(Ordering::SeqCst) {
        return Err(l10n::tr("Another backup or restore is running.", &[]));
    }
    discard(&state, window.label());
    window.close().map_err(|e| e.to_string())
}

/// The window starts over or is done: its open backup and restore record are dropped.
#[tauri::command]
pub async fn restore_discard(window: Window, state: Shared<'_>) -> Result<(), String> {
    let label = window.label();
    allow_armed(&state, label, &[RESTORE_WINDOW, FRESH_WINDOW])?;
    discard(&state, label);
    Ok(())
}

/// Drops what `label` opened or chose (also the create window's, when it closes or gives up the restore).
pub fn discard(state: &AppState, label: &str) {
    if let Some(service) = state.backup.service() {
        service.discard(label);
    }
    state.backup.forget(label);
}

/// The backup and restore windows: no close while a call runs; closed, their state goes.
pub fn on_window_event(window: &Window, event: &WindowEvent) {
    let Some(state) = window.app_handle().try_state::<Arc<AppState>>() else { return };
    match event {
        WindowEvent::CloseRequested { api, .. } if state.backup.running.load(Ordering::SeqCst) => api.prevent_close(),
        WindowEvent::Destroyed => discard(&state, window.label()),
        _ => {}
    }
}

/// The app's preferences for the backup: the update switches, launch at login, the control API switch and the
/// vault's auto-unlock.
struct AppPreferences {
    state: Arc<AppState>,
    service: Arc<BackupService>,
    /// To open the master password window (`confirm_auto_unlock`); `None` where nothing is applied.
    app: Option<AppHandle>,
}

impl PreferencePort for AppPreferences {
    fn current(&self) -> BackupPreferences {
        let updates = self.state.updates.preferences();
        BackupPreferences {
            auto_check: updates.auto_check,
            delay_24h: updates.delay_updates,
            launch_at_login: crate::platform::login_items(&self.state.env).state().is_on,
            control_api_enabled: self.state.prefs.bool(crate::control::ENABLED_KEY).unwrap_or(false),
            auto_unlock: self.service.vault().auto_unlock(),
        }
    }

    fn apply(&self, preference: Preference, on: bool) -> Result<(), String> {
        match preference {
            Preference::AutoCheck => self.state.updates.set_auto_check(on),
            Preference::Delay24h => self.state.updates.set_delay_updates(on),
            Preference::LaunchAtLogin => {
                let mut controller = crate::platform::login_items(&self.state.env);
                let result = controller.set_enabled(on);
                *self.state.login_item.write().unwrap_or_else(PoisonError::into_inner) = Some(controller.state());
                result.map_err(|_| {
                    l10n::tr(
                        if on { "Could not turn on launch at login" } else { "Could not turn off launch at login" },
                        &[],
                    )
                })?;
            }
            Preference::ControlApi => crate::control::set_enabled(&self.state, on),
            // Only ever off here: on needs the master password (`confirm_auto_unlock`).
            Preference::AutoUnlock if !on => self
                .service
                .vault()
                .set_auto_unlock(false)
                .map_err(|_| l10n::tr("Automatic unlocking could not be changed.", &[]))?,
            Preference::AutoUnlock => return Err(l10n::tr("Automatic unlocking could not be changed.", &[])),
        }
        Ok(())
    }

    fn confirm_auto_unlock(&self) -> Result<(), String> {
        let app = self.app.as_ref().ok_or_else(|| l10n::tr("Automatic unlocking could not be changed.", &[]))?;
        crate::vault::show_confirm_password(app, &self.state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_answer_only_their_windows() {
        assert!(allow("backup", &[BACKUP_WINDOW]).is_ok());
        for label in ["restore", "menu", "manage", "vault-create", "vault-unlock", "backup2", "cred-1", ""] {
            assert!(allow(label, &[BACKUP_WINDOW]).is_err(), "{label}");
        }
        for label in ["restore", "vault-create"] {
            assert!(allow(label, &[RESTORE_WINDOW, FRESH_WINDOW]).is_ok(), "{label}");
        }
        for label in ["backup", "menu", "manage", "vault-unlock", "vault-createx", "pair-1"] {
            assert!(allow(label, &[RESTORE_WINDOW, FRESH_WINDOW]).is_err(), "{label}");
        }
        assert!(is_backup_window("backup") && is_backup_window("restore"));
        // The create window's restore commands wait for its input lock; the backup windows have none.
        assert!(needs_input_lock("vault-create"));
        assert!(!needs_input_lock("restore") && !needs_input_lock("backup"));
        assert!(!is_backup_window("vault-create") && !is_backup_window("manage"));
    }

    #[test]
    fn only_the_two_windows_open() {
        assert!(window_title("backup").is_ok());
        assert!(window_title("restore").is_ok());
        for name in ["manage", "setup", "vault-create", "../backup", ""] {
            assert!(window_title(name).is_err(), "{name}");
        }
    }

    #[test]
    fn the_default_name_carries_the_local_date() {
        let date = crate::platform::get().system().local_date(1_792_400_000.0);
        assert_eq!(date.len(), 10, "{date}");
        assert!(date.starts_with("2026-"), "{date}");
        let name = default_file_name(crate::platform::get().product().name, &date);
        let own = if cfg!(windows) {
            "WinVPN-backup-2026-"
        } else if cfg!(target_os = "linux") {
            "LinVPN-backup-2026-"
        } else {
            "MacVPN-backup-2026-"
        };
        assert!(name.starts_with(own) && name.ends_with(".macvpnbackup"), "{name}");
        assert_eq!(
            display_name(std::path::Path::new("/Users/x/Desktop/MacVPN-backup.macvpnbackup")),
            "MacVPN-backup.macvpnbackup"
        );
    }

    #[test]
    fn no_backup_until_the_vault_is_attached() {
        let app = BackupApp::default();
        assert!(!app.available());
        assert!(app.require().is_err());
        assert!(app.picked("backup").is_err());
        app.pick("restore", PathBuf::from("/tmp/x.macvpnbackup"));
        assert!(app.picked("backup").is_err());
        assert!(app.picked("restore").is_ok());
        app.forget("restore");
        assert!(app.picked("restore").is_err());
        let flag = AtomicBool::new(false);
        let running = Running::start(&flag).unwrap();
        assert!(Running::start(&flag).is_err());
        drop(running);
        assert!(Running::start(&flag).is_ok());
    }
}
