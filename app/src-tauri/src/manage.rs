//! The Connections window's commands and window events (the logic is `macvpn_app_core::connections`, `editor`,
//! `import_export` and `logs`). Every argument is validated: connection keys are UUID-shaped and must name a
//! listed connection, kinds / choices / filters are allow-listed, the editor fields are bounded (config text and
//! CA PEM 1 MB, other fields 64 KB) and typed. No command takes a file path: files come only from the open / save
//! panels shown here and from a drop on the window (delivered by the window event, not by the web view).

use macvpn_app_core::ConnectionItem;
use macvpn_app_core::connections::{PendingAction, Resolved, SaveFailure, Tab, parse_unsaved_choice};
use macvpn_app_core::editor::{EditorFields, EditorView};
use macvpn_app_core::import_export::{self, ExportWarning, ImportReport};
use macvpn_app_core::logs::{self, LogChunk, LogFeed};
use macvpn_app_core::quit::QuitStep;
use macvpn_app_core::updates::Notice;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::{Connection, VPNKind};
use macvpn_core::wireguard_keys::KeyLine;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use tauri::{AppHandle, DragDropEvent, Emitter, Manager, State, Window, WindowEvent};

use crate::commands::validate_key;
use crate::state::AppState;

type Shared<'a> = State<'a, Arc<AppState>>;

pub const MANAGE_WINDOW: &str = "manage";
/// At most this many files per import (dialog or drop).
pub const MAX_IMPORT_FILES: usize = 64;
/// The log search text.
pub const MAX_SEARCH_BYTES: usize = 1024;

pub(crate) fn managed(state: &AppState, id: &str) -> Result<Connection, String> {
    validate_key(id)?;
    match state.manager.item(id) {
        Some(ConnectionItem::Managed(c)) => Ok(c),
        Some(ConnectionItem::System(_)) => Err("not a managed connection".into()),
        None => Err("unknown connection".into()),
    }
}

fn listed(state: &AppState, id: &str) -> Result<(), String> {
    validate_key(id)?;
    state.manager.item(id).map(|_| ()).ok_or_else(|| "unknown connection".into())
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())
}

pub fn parse_kind(raw: &str) -> Result<VPNKind, String> {
    VPNKind::ALL.into_iter().find(|k| k.raw_value() == raw).ok_or_else(|| "invalid kind".into())
}

// MARK: - Selection, unsaved changes, tab requests

/// True: selected; false: the "Unsaved Changes" question is shown first (view model `manage.pending`).
#[tauri::command]
pub async fn select_connection(state: Shared<'_>, id: Option<String>) -> Result<bool, String> {
    if let Some(id) = &id {
        listed(&state, id)?;
    }
    Ok(state.connections.select(id))
}

/// The answer to "Unsaved Changes": `save`, `discard` or `cancel`. A failed save comes back as the report.
#[tauri::command]
pub async fn resolve_unsaved(app: AppHandle, state: Shared<'_>, choice: String) -> Result<Option<SaveFailure>, String> {
    let choice = parse_unsaved_choice(&choice)?;
    let quitting = state.connections.pending() == Some(PendingAction::Quit);
    let shared = state.inner().clone();
    let resolved = blocking(move || shared.connections.resolve(choice)).await?;
    // The quit guard hears the answer when its question was asked (cancelled or a failed save stop the quit).
    if quitting {
        let proceed = resolved == Resolved::Quit;
        if let Some(action) = state.quit.unsaved_answered(proceed, state.manager.has_active()) {
            crate::commands::handle_quit(&app, &state, action);
        }
    }
    match resolved {
        Resolved::Failed(failure) => {
            let _ = crate::commands::open(&app, MANAGE_WINDOW);
            Ok(Some(failure))
        }
        Resolved::CloseWindow => {
            if let Some(window) = app.get_webview_window(MANAGE_WINDOW) {
                let _ = window.destroy();
            }
            Ok(None)
        }
        Resolved::Quit | Resolved::Done | Resolved::Cancelled => Ok(None),
    }
}

/// One-time: the tab the detail of `id` switches to (`settings` after a failed save, `log` after a debug
/// connect).
#[tauri::command]
pub async fn take_tab_request(state: Shared<'_>, id: String) -> Result<Option<Tab>, String> {
    validate_key(&id)?;
    Ok(state.connections.take_tab_request(&id))
}

// MARK: - Editors

#[tauri::command]
pub async fn editor_open(state: Shared<'_>, id: String) -> Result<EditorView, String> {
    listed(&state, &id)?;
    let shared = state.inner().clone();
    blocking(move || shared.connections.open_editor(&id)).await?
}

#[tauri::command]
pub async fn editor_update(state: Shared<'_>, id: String, fields: EditorFields) -> Result<EditorView, String> {
    validate_key(&id)?;
    fields.validate()?;
    let shared = state.inner().clone();
    blocking(move || shared.connections.update_editor(&id, fields)).await?
}

#[tauri::command]
pub async fn editor_save(state: Shared<'_>, id: String, fields: EditorFields) -> Result<EditorView, String> {
    listed(&state, &id)?;
    fields.validate()?;
    let shared = state.inner().clone();
    blocking(move || shared.connections.save_editor(&id, fields)).await?
}

/// "Forget saved secrets" of a system VPN.
#[tauri::command]
pub async fn editor_forget(state: Shared<'_>, id: String) -> Result<EditorView, String> {
    listed(&state, &id)?;
    let shared = state.inner().clone();
    blocking(move || shared.connections.forget_secrets(&id)).await?
}

/// "Choose PEM File…" of the SSTP form: the open panel, then the certificates of the chosen file (at most 1 MB,
/// UTF-8) into the editor. A cancelled panel changes nothing.
#[tauri::command]
pub async fn editor_choose_ca(app: AppHandle, state: Shared<'_>, id: String) -> Result<EditorView, String> {
    managed(&state, &id)?;
    let paths = crate::dialogs::choose_files(&app, &state, MANAGE_WINDOW, false).await?;
    let shared = state.inner().clone();
    blocking(move || match paths.first() {
        Some(path) => {
            let text = import_export::read_import_file(path);
            shared.connections.import_ca(&id, text.as_deref())
        }
        None => shared.connections.open_editor(&id),
    })
    .await?
}

/// The WireGuard key line a key command acts on (`privateKey` or `presharedKey`).
fn parse_key_line(raw: &str) -> Result<KeyLine, String> {
    match raw {
        "privateKey" => Ok(KeyLine::PrivateKey),
        "presharedKey" => Ok(KeyLine::PresharedKey),
        _ => Err("invalid key".into()),
    }
}

/// "Generate Key Pair" (`privateKey`) / "Generate Preshared Key" (`presharedKey`) of a WireGuard editor: a new key
/// from the platform's CSPRNG into the draft's config text (the web view only asked; it never makes key material).
/// The key is never logged.
#[tauri::command]
pub async fn editor_wireguard_generate(state: Shared<'_>, id: String, key: String) -> Result<EditorView, String> {
    managed(&state, &id)?;
    let which = parse_key_line(&key)?;
    let shared = state.inner().clone();
    blocking(move || {
        let entropy = crate::platform::get().entropy();
        shared.connections.generate_wireguard_key(&id, which, entropy.as_ref())
    })
    .await?
}

/// "Copy" of a WireGuard editor's private key or preshared key: read from the backend draft (the web view sends no
/// key) and put on the clipboard through the secret clipboard (concealed from clipboard managers, cleared a minute
/// later, at a vault lock and at quit if it is still there).
#[tauri::command]
pub async fn editor_wireguard_copy(window: Window, state: Shared<'_>, id: String, key: String) -> Result<(), String> {
    if window.label() != MANAGE_WINDOW {
        return Err("not allowed".into());
    }
    managed(&state, &id)?;
    let which = parse_key_line(&key)?;
    let shared = state.inner().clone();
    blocking(move || {
        let secret = shared.connections.wireguard_secret(&id, which)?;
        crate::clipboard::copy_secret(&secret)
    })
    .await?
}

// MARK: - Create, import, export, delete

#[tauri::command]
pub async fn create_connection(state: Shared<'_>, kind: String) -> Result<(), String> {
    let kind = parse_kind(&kind)?;
    let shared = state.inner().clone();
    blocking(move || shared.connections.create(kind).map(|_| ())).await?
}

/// An import's alert: "Import" / "Import Error" and the lines.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImportReportView {
    pub title: String,
    pub message: String,
}

fn report_view(report: &ImportReport) -> Option<ImportReportView> {
    (!report.is_empty()).then(|| ImportReportView { title: report.title(), message: report.message() })
}

/// "Import from File…": the open panel (several files), then the import. The credential-file question appears
/// in the window meanwhile (`manage.question`).
#[tauri::command]
pub async fn import_files(app: AppHandle, state: Shared<'_>) -> Result<Option<ImportReportView>, String> {
    let paths = crate::dialogs::choose_files(&app, &state, MANAGE_WINDOW, true).await?;
    if paths.is_empty() {
        return Ok(None);
    }
    let shared = state.inner().clone();
    let report = blocking(move || shared.connections.import_paths(&paths[..paths.len().min(MAX_IMPORT_FILES)])).await?;
    Ok(report_view(&report))
}

/// The answer to an import's question (Use: true, Ignore: false).
#[tauri::command]
pub async fn answer_question(state: Shared<'_>, id: u64, answer: bool) -> Result<(), String> {
    if state.connections.questions().answer(id, answer) { Ok(()) } else { Err("no such question".into()) }
}

/// Before an export: `Some` if the config holds key material (the three-way question comes first).
#[tauri::command]
pub async fn export_check(state: Shared<'_>, id: String) -> Result<Option<ExportWarning>, String> {
    let c = managed(&state, &id)?;
    let shared = state.inner().clone();
    blocking(move || import_export::export_warning(shared.connections.deps(), &c)).await?
}

/// The save panel and the export (0600, no symlink followed). `with_keys`: the answer "Export With Keys". An error
/// comes back as the alert to show.
#[tauri::command]
pub async fn export_connection(
    app: AppHandle,
    window: tauri::Window,
    state: Shared<'_>,
    id: String,
    with_keys: bool,
) -> Result<Option<Notice>, String> {
    crate::guard::only(&window, "export_connection", MANAGE_WINDOW)?;
    let c = managed(&state, &id)?;
    let shared = state.inner().clone();
    let plan = match blocking(move || import_export::export_plan(shared.connections.deps(), &c, with_keys)).await? {
        Ok(plan) => plan,
        Err(e) => return Ok(Some(Notice { title: e, message: String::new() })),
    };
    let Some(path) = crate::dialogs::choose_save_path(
        &app,
        &state,
        MANAGE_WINDOW,
        plan.file_name.clone(),
        Some(plan.message.clone()),
    )
    .await?
    else {
        return Ok(None);
    };
    let written = blocking(move || macvpn_core::exporter::write(&plan.data, &path)).await?;
    Ok(written.err().map(|e| Notice { title: e.message, message: String::new() }))
}

/// After deleting a native connection: the system's VPN settings open (the user removes the profile there, macOS'
/// Profiles pane) unless the platform removed it itself (WinVPN 2c: its RAS entry) or in the sandbox.
pub(crate) fn opens_native_settings_after_delete(removes_profiles: bool, sandbox: bool) -> bool {
    !removes_profiles && !sandbox
}

/// Deletes a managed connection (confirmed in the UI): disconnected first, its native debug log stopped, the
/// config and Keychain items deleted, its profile removed where the platform does it (WinVPN); for a native one
/// on macOS the Profiles pane opens (its profile is removed there).
#[tauri::command]
pub async fn delete_connection(window: tauri::Window, state: Shared<'_>, id: String) -> Result<(), String> {
    crate::guard::only(&window, "delete_connection", MANAGE_WINDOW)?;
    let c = managed(&state, &id)?;
    if state.manager.is_locked() {
        return Err(macvpn_app_core::vault_stores::locked_message());
    }
    let shared = state.inner().clone();
    blocking(move || {
        shared.native_logs.remove(&c.id);
        if let Some(deleted) = shared.connections.delete(&c.id) {
            // Auto-reconnect forgets it (its "off" entry and the planner's records).
            macvpn_app_core::reconnect::set_enabled(shared.prefs.as_ref(), &c.id, true);
            shared.reconnect.send(crate::reconnect::Event::Forget(id));
            if deleted.kind.is_native()
                && opens_native_settings_after_delete(shared.native_profiles.removes_profiles(), shared.env.sandbox)
            {
                crate::platform::get().shell().open_native_profile_settings();
            }
            shared.manager.refresh();
        }
    })
    .await
}

// MARK: - Log tab

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEvent {
    pub generation: u64,
    #[serde(flatten)]
    pub chunk: LogChunk,
}

/// Shows the Log tab of `id` (`None`: none): the first lines come back, the new ones arrive as `log-lines`
/// events with the same generation.
#[tauri::command]
pub async fn log_subscribe(app: AppHandle, state: Shared<'_>, id: Option<String>) -> Result<Option<LogEvent>, String> {
    let c = match &id {
        Some(id) => Some(managed(&state, id)?),
        None => None,
    };
    let generation = state.log_generation.fetch_add(1, Ordering::SeqCst) + 1;
    let Some(c) = c else {
        *state.log_feed.lock().unwrap_or_else(PoisonError::into_inner) = None;
        return Ok(None);
    };
    let shared = state.inner().clone();
    let event = blocking(move || {
        // The helper's log of the connection, through the manager's helper (a helper without one: none, which reads
        // nothing); a native connection's own log where the platform keeps one (WinVPN's RAS log; macOS: none).
        let source = shared.helper.log_source(&c.id);
        let native =
            if c.kind.is_native() { crate::platform::get().native_controller().log_source(&c.id) } else { None };
        let mut feed = LogFeed::with_native_source(&c, source, native, shared.native_logs.clone());
        let chunk = feed.poll().unwrap_or(LogChunk { reset: true, lines: Vec::new() });
        let mut slot = shared.log_feed.lock().unwrap_or_else(PoisonError::into_inner);
        // A newer subscription won meanwhile: this one is dropped.
        if shared.log_generation.load(Ordering::SeqCst) == generation {
            *slot = Some((generation, feed));
        }
        LogEvent { generation, chunk }
    })
    .await?;
    start_log_poller(&app, &state);
    Ok(Some(event))
}

fn start_log_poller(app: &AppHandle, state: &Arc<AppState>) {
    if state.log_poller.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    let state = state.clone();
    let _ = std::thread::Builder::new().name("macvpn-log".into()).spawn(move || {
        loop {
            std::thread::sleep(logs::POLL_INTERVAL);
            let event = {
                let mut slot = state.log_feed.lock().unwrap_or_else(PoisonError::into_inner);
                let Some((generation, feed)) = slot.as_mut() else { continue };
                feed.poll().map(|chunk| LogEvent { generation: *generation, chunk })
            };
            if let Some(event) = event {
                // `emit_to` only selects the listeners; it is not an isolation boundary (any window with the
                // event permission can listen). The payload must never carry a secret: these are the log's
                // lines, in which passwords, PSKs and codes are already masked.
                let _ = app.emit_to(MANAGE_WINDOW, "log-lines", &event);
            }
        }
    });
}

/// "Copy": the visible lines (filter `all` / `commands` / `errors`, the search, the time range: `from` / `to` as
/// `logs::civil_seconds`, `null`: open) to the pasteboard.
#[tauri::command]
pub async fn log_copy(
    state: Shared<'_>,
    filter: String,
    search: String,
    from: Option<f64>,
    to: Option<f64>,
) -> Result<(), String> {
    let filter = logs::parse_filter(&filter).ok_or("invalid filter")?;
    if search.len() > MAX_SEARCH_BYTES {
        return Err("invalid search".into());
    }
    let range = logs::TimeRange::from_bounds(from, to).ok_or("invalid time range")?;
    let text = {
        let slot = state.log_feed.lock().unwrap_or_else(PoisonError::into_inner);
        let (_, feed) = slot.as_ref().ok_or("no log")?;
        feed.buffer().visible_text(filter, &search, range)
    };
    blocking(move || crate::platform::get().shell().copy_text(&text).map_err(String::from)).await?
}

/// "Save…": the kept lines into a file chosen in the save panel (0600, no symlink followed: the log can hold
/// server addresses and user names). A failure comes back as the alert.
#[tauri::command]
pub async fn log_save(app: AppHandle, state: Shared<'_>) -> Result<Option<Notice>, String> {
    let (id, text) = {
        let slot = state.log_feed.lock().unwrap_or_else(PoisonError::into_inner);
        let (_, feed) = slot.as_ref().ok_or("no log")?;
        (feed.id, feed.buffer().all_text())
    };
    let name = state.manager.connections().into_iter().find(|c| c.id == id).map(|c| c.name).unwrap_or_default();
    let file_name = l10n::tr("%@-log.txt", &[Arg::Str(&name)]).replace(['/', ':'], "-");
    let Some(path) = crate::dialogs::choose_save_path(&app, &state, MANAGE_WINDOW, file_name, None).await? else {
        return Ok(None);
    };
    let written = blocking(move || macvpn_core::exporter::write(text.as_bytes(), &path)).await?;
    Ok(written.err().map(|e| Notice { title: l10n::tr("Could not save the log", &[]), message: e.message }))
}

/// "Clear Log…" (after the window's confirmation): empties the log of `id` as its Log tab shows it
/// (`logs::clear_log`), with the localized "Log cleared at <time>" note as its first line. The view then subscribes
/// again (a new generation: the tail starts over). A failure comes back as the alert.
#[tauri::command]
pub async fn log_clear(state: Shared<'_>, id: String) -> Result<Option<Notice>, String> {
    let c = managed(&state, &id)?;
    let shared = state.inner().clone();
    let cleared = blocking(move || {
        let platform = crate::platform::get();
        let time = platform.system().local_timestamp(macvpn_core::date::Date::now().time_interval_since_1970());
        let note = logs::cleared_note(&time);
        let native = platform.native_controller();
        logs::clear_log(&c, shared.helper.as_ref(), native.as_ref(), &shared.native_logs, &note)
    })
    .await?;
    Ok(cleared.err().map(|message| Notice { title: l10n::tr("Could not clear the log", &[]), message }))
}

// MARK: - Window events

/// Dropped paths: absolute, at most [`MAX_IMPORT_FILES`]. They come from the system's drag session, never from
/// the web view; the import reads only regular files of at most 1 MB.
pub fn dropped_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    paths.iter().filter(|p| p.is_absolute()).take(MAX_IMPORT_FILES).cloned().collect()
}

pub fn on_window_event(window: &Window, event: &WindowEvent) {
    let Some(state) = window.app_handle().try_state::<Arc<AppState>>() else { return };
    let state = state.inner().clone();
    match event {
        // The unsaved-changes guard (the Swift `WindowCloseGuard`): the window asks first.
        WindowEvent::CloseRequested { api, .. } => {
            if !state.connections.should_close_window() {
                api.prevent_close();
                let _ = window.set_focus();
            }
        }
        WindowEvent::Destroyed => {
            state.connections.window_closed();
            *state.log_feed.lock().unwrap_or_else(PoisonError::into_inner) = None;
            // A quit waiting for "Unsaved Changes" is cancelled with the window.
            if let Some(action) = state.quit.cancel(QuitStep::Unsaved) {
                crate::commands::handle_quit(window.app_handle(), &state, action);
            }
        }
        WindowEvent::DragDrop(DragDropEvent::Drop { paths, .. }) => {
            let paths = dropped_paths(paths);
            if paths.is_empty() {
                return;
            }
            let app = window.app_handle().clone();
            tauri::async_runtime::spawn_blocking(move || {
                let report = state.connections.import_paths(&paths);
                if let Some(view) = report_view(&report) {
                    // Targeting is not an isolation boundary (see the log feed): the report holds file names and
                    // messages only, never a secret.
                    let _ = app.emit_to(MANAGE_WINDOW, "import-report", &view);
                }
            });
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_are_allow_listed() {
        assert_eq!(parse_kind("openvpn"), Ok(VPNKind::Openvpn));
        assert_eq!(parse_kind("l2tp"), Ok(VPNKind::L2tp));
        assert!(parse_kind("OpenVPN").is_err());
        assert!(parse_kind("../x").is_err());
    }

    #[test]
    fn dropped_paths_are_absolute_and_bounded() {
        // An absolute path needs a drive on Windows.
        let root = if cfg!(windows) { "C:" } else { "" };
        let many: Vec<PathBuf> = (0..100).map(|i| PathBuf::from(format!("{root}/tmp/{i}.ovpn"))).collect();
        assert_eq!(dropped_paths(&many).len(), MAX_IMPORT_FILES);
        let absolute = PathBuf::from(format!("{root}/a.ovpn"));
        assert_eq!(dropped_paths(&[PathBuf::from("relative.ovpn"), absolute.clone()]), [absolute]);
    }

    #[test]
    fn only_the_two_wireguard_key_lines_are_accepted() {
        assert_eq!(super::parse_key_line("privateKey"), Ok(super::KeyLine::PrivateKey));
        assert_eq!(super::parse_key_line("presharedKey"), Ok(super::KeyLine::PresharedKey));
        for bad in ["publicKey", "PrivateKey", "", "privateKey "] {
            assert!(super::parse_key_line(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn editor_fields_are_strict() {
        let ok = r#"{"type":"system","psk":"a","password":"b","otp":{"enabled":true,"separator":"comma"}}"#;
        assert!(serde_json::from_str::<EditorFields>(ok).is_ok());
        for bad in [
            r#"{"type":"system","psk":"a","password":"b","otp":{"enabled":true,"separator":"semicolon"}}"#,
            r#"{"type":"system","psk":"a","password":"b","otp":{"enabled":true,"separator":"comma"},"path":"/etc"}"#,
            r#"{"type":"file","psk":"a"}"#,
            r#"{"type":"sstp","name":"","server":"","port":1.5,"user":"","cert":"system","routeAll":true,"peerDns":true,"caPem":"","password":"","otp":{"enabled":false,"separator":"none"}}"#,
            r#"{"type":"sstp","name":"","server":"","port":443,"user":"","cert":"file","routeAll":true,"peerDns":true,"caPem":"","password":"","otp":{"enabled":false,"separator":"none"}}"#,
        ] {
            assert!(serde_json::from_str::<EditorFields>(bad).is_err(), "{bad}");
        }
    }

    /// G-3: the system's VPN settings open after deleting a native connection only where the user removes the
    /// profile there (macOS), never in the sandbox; WinVPN removes its RAS entry itself.
    #[test]
    fn opens_native_settings_after_delete_only_where_the_user_removes_the_profile() {
        assert!(super::opens_native_settings_after_delete(false, false));
        assert!(!super::opens_native_settings_after_delete(false, true));
        assert!(!super::opens_native_settings_after_delete(true, false));
        assert!(!super::opens_native_settings_after_delete(true, true));
    }
}
