//! Files opened from Finder (a double click on a `.ovpn` / `.sstp` / `.macvpncatalog` file, "Open With → MacVPN",
//! a drop on the app's icon): macOS delivers them as `RunEvent::Opened` (`application:openURLs:`), at launch too.
//! The routing rules are `macvpn_app_core::open_files`; this module runs them.
//!
//! - **The same flows as inside the app.** VPN configs go through the Connections window's import
//!   (`ConnectionsModel::import_paths`: the size cap and `read_import_file`, the validators, the risky-directive
//!   list, the credential-file question, the shared-credential question, the `# macvpn-meta` folder) and its report;
//!   a team catalog file becomes the "Add team catalog" dialog's file source (the team key, the fingerprint, the
//!   preview and the "fingerprint matches" tick are still the user's). Admin key files and backups are refused.
//!   Nothing here connects.
//! - **Locked or no vault yet:** the paths wait in memory ([`OpenFilesApp`], at most
//!   `open_files::MAX_QUEUED`, never the contents), the unlock or create window is shown, and they run once the vault
//!   is open and no create window is in progress. Closing that window without opening the vault drops them.
//! - **No path crosses IPC.** The paths stay here; the Connections window gets the import report (file names and
//!   messages) and the catalog file's name through `open_files_take`, after an `open-files` event without payload.
//!   Nothing of this enters the view model. Logs carry counts only.

use macvpn_app_core::import_export::ImportReport;
use macvpn_app_core::open_files::{Batch, OpenQueue, Received, Refusal, WorkQueue};
use macvpn_app_core::vault::VaultState;
use macvpn_core::l10n;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use tauri::{AppHandle, Emitter, Manager, State, Url, Window};

use crate::manage::{ImportReportView, MANAGE_WINDOW};
use crate::state::AppState;
use crate::vault::{CREATE_WINDOW, UNLOCK_WINDOW};

/// Tells the Connections window that an opened file's outcome waits for `open_files_take` (no payload).
pub const OPEN_EVENT: &str = "open-files";

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The opens waiting for the vault, and what waits for the Connections window.
#[derive(Default)]
pub struct OpenFilesApp {
    queue: Mutex<OpenQueue>,
    /// The opens for the one worker thread that runs them (merged while it works).
    work: Mutex<WorkQueue>,
    pending: Mutex<Pending>,
    /// The app (set at setup), for the unlock hooks that have only the state.
    app: OnceLock<AppHandle>,
}

/// The outcome of the opens not yet taken by the Connections window.
#[derive(Default)]
struct Pending {
    report: ImportReport,
    catalog_file: Option<String>,
}

/// What the Connections window gets (once): the import report and the catalog file's name for the add dialog.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenedView {
    pub report: Option<ImportReportView>,
    pub catalog_file: Option<String>,
}

impl OpenFilesApp {
    /// The app's handle (setup).
    pub fn attach(&self, app: AppHandle) {
        let _ = self.app.set(app);
    }

    fn deliver(&self, report: ImportReport, catalog_file: Option<String>) {
        let mut pending = guard(&self.pending);
        pending.report.merge(report);
        if catalog_file.is_some() {
            pending.catalog_file = catalog_file;
        }
    }

    /// The outcome so far, once (taken out).
    pub fn take(&self) -> OpenedView {
        let pending = std::mem::take(&mut *guard(&self.pending));
        OpenedView {
            report: (!pending.report.is_empty())
                .then(|| ImportReportView { title: pending.report.title(), message: pending.report.message() }),
            catalog_file: pending.catalog_file,
        }
    }

    #[cfg(test)]
    fn queued(&self) -> usize {
        guard(&self.queue).len()
    }
}

/// The local files among the opened URLs (other schemes are ignored: MacVPN declares none).
pub fn file_paths(urls: &[Url]) -> Vec<PathBuf> {
    urls.iter()
        .filter(|u| u.scheme() == "file")
        .filter_map(|u| u.to_file_path().ok())
        .filter(|p| p.is_absolute())
        .collect()
}

/// The vault is open and no create window is in progress (a new vault is not used before its window finished: the
/// recovery key check, the migration or the restore come first).
pub fn vault_ready(state: &AppState) -> bool {
    state.vault.lifecycle.is_unlocked() && state.vault.with_setup(|_| ()).is_none()
}

/// `RunEvent::Opened` (main thread; nothing here blocks).
pub fn opened(app: &AppHandle, urls: &[Url]) {
    let Some(state) = app.try_state::<Arc<AppState>>() else { return };
    receive(app, &state, file_paths(urls));
}

/// Opened paths (from [`opened`], or the smoke run's simulated open in debug builds).
pub fn receive(app: &AppHandle, state: &Arc<AppState>, paths: Vec<PathBuf>) {
    if paths.is_empty() {
        return;
    }
    // Read before the queue's lock (the vault's locks are never taken while it is held).
    let ready = vault_ready(state);
    let received = guard(&state.open_files.queue).receive(paths, ready);
    match received {
        Received::Run(batch) => run(app, state, batch),
        Received::Queued { show_vault, dropped } => {
            if dropped > 0 {
                let max = macvpn_app_core::open_files::MAX_QUEUED;
                eprintln!("MacVPN: open: {dropped} files were not kept (at most {max} wait for the vault)");
            }
            // The vault may have opened meanwhile (an unlock that crossed this open).
            flush(state);
            if show_vault && !guard(&state.open_files.queue).is_empty() {
                let (app, state) = (app.clone(), state.clone());
                std::thread::spawn(move || show_vault_window(&app, &state));
            }
        }
    }
}

/// The unlock window (locked), or the create window (no vault yet, or the old storage read-only); a create window
/// in progress comes forward.
fn show_vault_window(app: &AppHandle, state: &Arc<AppState>) {
    let shown = match state.vault.lifecycle.state() {
        VaultState::Locked => crate::vault::open_window(app, state, UNLOCK_WINDOW),
        VaultState::Unlocked => match app.get_webview_window(CREATE_WINDOW) {
            Some(_) => crate::vault::open_window(app, state, CREATE_WINDOW),
            None => Ok(()),
        },
        VaultState::NotCreated | VaultState::LegacyReadOnly { .. } => {
            if app.get_webview_window(CREATE_WINDOW).is_some() {
                crate::vault::open_window(app, state, CREATE_WINDOW)
            } else {
                let migrating = macvpn_app_core::migration::has_legacy_data(&state.vault.legacy);
                crate::vault::start_setup(app, state, migrating);
                Ok(())
            }
        }
    };
    if let Err(e) = shown {
        eprintln!("MacVPN: vault window: {e}");
    }
}

/// The launch decided the vault's state (its windows are shown): what waits runs if the vault is ready.
pub fn launched(state: &Arc<AppState>) {
    let ready = vault_ready(state);
    let batch = guard(&state.open_files.queue).launched(ready);
    run_attached(state, batch);
}

/// The vault opened (an unlock, a create window finished): what waits runs.
pub fn flush(state: &Arc<AppState>) {
    let ready = vault_ready(state);
    let batch = guard(&state.open_files.queue).flush(ready);
    run_attached(state, batch);
}

fn run_attached(state: &Arc<AppState>, batch: Option<Batch>) {
    if let (Some(batch), Some(app)) = (batch, state.open_files.app.get()) {
        run(app, state, batch);
    }
}

/// The unlock or create window is gone: what waits runs if the vault is ready, and is dropped if the vault is still
/// closed (the user cancelled).
pub fn vault_window_closed(state: &Arc<AppState>) {
    if vault_ready(state) {
        flush(state);
    } else if !state.vault.lifecycle.is_unlocked() {
        let dropped = guard(&state.open_files.queue).cancel();
        if dropped > 0 {
            eprintln!("MacVPN: open: {dropped} opened files were dropped (the vault was not opened)");
        }
    }
}

/// The report line of a refused file.
pub fn refusal_text(why: &Refusal) -> String {
    match why {
        Refusal::PanelOnly => l10n::tr("This file is opened from its own panel in MacVPN, not from Finder.", &[]),
        Refusal::OneCatalog => l10n::tr("Only one team catalog file can be added at a time.", &[]),
    }
}

/// The report lines of the refused files (the names, then the count of the rest).
pub fn refusal_lines(batch: &Batch) -> Vec<String> {
    let mut lines: Vec<String> =
        batch.refused.iter().map(|(name, why)| format!("{name}: {}", refusal_text(why))).collect();
    if batch.refused_more > 0 {
        lines.push(l10n::tr("%lld more files were not opened.", &[l10n::Arg::Int(batch.refused_more as i64)]));
    }
    lines
}

/// Hands an open to the one worker thread (started for the first open; the opens that arrive while it works are
/// merged and run next by it). It brings the Connections window forward, confirms downloaded files, imports (its
/// questions appear in the window meanwhile), then gives the catalog file to the add dialog; the window learns of the outcome.
fn run(app: &AppHandle, state: &Arc<AppState>, batch: Batch) {
    if !guard(&state.open_files.work).submit(batch) {
        return;
    }
    let (app, state) = (app.clone(), state.clone());
    let worker_state = state.clone();
    let spawned = std::thread::Builder::new().name("macvpn-open".into()).spawn(move || {
        let state = worker_state;
        loop {
            let next = guard(&state.open_files.work).next_batch();
            let Some(batch) = next else { break };
            run_batch(&app, &state, batch);
        }
    });
    if let Err(e) = spawned {
        guard(&state.open_files.work).failed();
        eprintln!("MacVPN: open: {e}");
    }
}

/// One (merged) open, on the worker thread.
fn run_batch(app: &AppHandle, state: &Arc<AppState>, batch: Batch) {
    if let Err(e) = crate::commands::open(app, MANAGE_WINDOW) {
        eprintln!("MacVPN: open: the Connections window: {e}");
    }
    let mut report = ImportReport { errors: refusal_lines(&batch), notes: Vec::new() };
    // Downloaded files (the quarantine mark) are imported only after one confirmation in the window; local files
    // import directly. The mark is only read.
    let imports = macvpn_app_core::open_files::confirm_downloaded(
        batch.imports,
        macvpn_platform_mac::quarantine::is_quarantined,
        |title, message| {
            state.connections.questions().ask(title, message, l10n::tr("Import", &[]), l10n::tr("Cancel", &[]))
        },
    );
    if !imports.is_empty() {
        // The same import as the open panel and a drop (one at a time; it never connects).
        report.merge(state.connections.import_paths(&imports));
    }
    let catalog_file = batch.catalog.and_then(|path| {
        let name = macvpn_app_core::open_files::file_name(&path);
        match state.catalog.open_file_source(path) {
            Ok(shown) => Some(shown),
            Err(e) => {
                report.errors.push(format!("{name}: {e}"));
                None
            }
        }
    });
    state.open_files.deliver(report, catalog_file);
    // Targeting is not an isolation boundary (see the log feed): the event carries nothing.
    let _ = app.emit_to(MANAGE_WINDOW, OPEN_EVENT, ());
}

/// The Connections window takes what the opens left for it (the report, the catalog file's name), once.
#[tauri::command]
pub async fn open_files_take(window: Window, state: State<'_, Arc<AppState>>) -> Result<OpenedView, String> {
    if window.label() != MANAGE_WINDOW {
        return Err("not this window's command".into());
    }
    Ok(state.open_files.take())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const SECRET_DIR: &str = "/Users/someone/Secret Folder";

    #[test]
    fn only_local_files_are_taken() {
        let urls: Vec<Url> = [
            "file:///Users/someone/Secret%20Folder/a.ovpn",
            "https://example.com/b.ovpn",
            "macvpn://open?x=/c.ovpn",
            "file:///tmp/team.macvpncatalog",
        ]
        .iter()
        .map(|u| Url::parse(u).unwrap())
        .collect();
        assert_eq!(
            file_paths(&urls),
            [PathBuf::from(format!("{SECRET_DIR}/a.ovpn")), PathBuf::from("/tmp/team.macvpncatalog")]
        );
    }

    /// What the window gets from the opens carries file names and messages, never a path; and it goes once.
    #[test]
    fn paths_never_reach_the_window() {
        let app = OpenFilesApp::default();
        let batch = Batch::sort([
            PathBuf::from(format!("{SECRET_DIR}/k.macvpnadminkey")),
            PathBuf::from(format!("{SECRET_DIR}/one.macvpncatalog")),
            PathBuf::from(format!("{SECRET_DIR}/two.macvpncatalog")),
        ]);
        let report = ImportReport { errors: refusal_lines(&batch), notes: vec![] };
        let catalog = batch.catalog.as_deref().map(macvpn_app_core::open_files::file_name);
        app.deliver(report, catalog);
        let view = app.take();
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("Secret Folder") && !json.contains("/Users"), "{json}");
        assert_eq!(view.catalog_file.as_deref(), Some("one.macvpncatalog"));
        assert!(view.report.as_ref().is_some_and(|r| r.message.contains("k.macvpnadminkey")));
        assert_eq!(app.take(), OpenedView::default());
    }

    /// The opened files' state stays out of the view model: `AppState::view_model` never reads it, and the queue
    /// holds paths only in this module.
    #[test]
    fn the_view_model_never_reads_the_opened_files() {
        let state = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/state.rs")).unwrap();
        let start = state.find("pub fn view_model(").unwrap();
        let body = &state[start..start + state[start..].find("\n    }\n").unwrap()];
        assert!(!body.contains("open_files"), "the view model reads the opened files");
        let app_core = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/app-core/src/view_model.rs"),
        )
        .unwrap();
        assert!(!app_core.contains("open_files"));
        // The window's only command returns names and messages (no PathBuf in what it serializes).
        let me = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/open_files.rs")).unwrap();
        let view = &me[me.find("pub struct OpenedView").unwrap()..];
        let view = &view[..view.find('}').unwrap()];
        assert!(!view.contains("PathBuf") && !view.contains("Path"), "{view}");
    }

    #[test]
    fn reports_merge_until_taken() {
        let app = OpenFilesApp::default();
        app.deliver(ImportReport { errors: vec!["a.ovpn: x".into()], notes: vec![] }, None);
        app.deliver(ImportReport { errors: vec![], notes: vec!["b.ovpn: y".into()] }, Some("t.macvpncatalog".into()));
        let view = app.take();
        let report = view.report.unwrap();
        assert!(report.message.contains("a.ovpn: x") && report.message.contains("b.ovpn: y"));
        assert_eq!(view.catalog_file.as_deref(), Some("t.macvpncatalog"));
        assert_eq!(app.queued(), 0);
    }

    /// A flood of refused files is named up to the cap; the rest is one line with the count.
    #[test]
    fn many_refusals_make_a_short_report() {
        macvpn_core::l10n::AppLanguage::set_thread_override(Some(macvpn_core::l10n::AppLanguage::En));
        let batch = Batch::sort((0..40).map(|i| PathBuf::from(format!("/s/{i}.macvpnbackup"))));
        let lines = refusal_lines(&batch);
        assert_eq!(lines.len(), macvpn_app_core::open_files::MAX_REFUSED + 1);
        assert_eq!(lines.last().unwrap(), &format!("{} more files were not opened.", 40 - lines.len() + 1));
    }

    /// Info.plist (merged into the bundle's): the declared types and document types.
    fn info_plist() -> serde_json::Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Info.plist");
        let out = std::process::Command::new("/usr/bin/plutil")
            .args(["-convert", "json", "-o", "-"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(out.status.success(), "plutil");
        serde_json::from_slice(&out.stdout).unwrap()
    }

    /// `.ovpn` and `.sstp` are data, not text: macOS treats plain text as a "safe" download that Safari may open by
    /// itself ("Open safe files after downloading"), which would hand a drive-by file to MacVPN.
    #[test]
    fn vpn_config_types_are_not_safe_download_types() {
        let plist = info_plist();
        let imported = plist["UTImportedTypeDeclarations"].as_array().unwrap();
        assert_eq!(imported.len(), 2);
        for t in imported {
            let id = t["UTTypeIdentifier"].as_str().unwrap();
            let conforms: Vec<&str> =
                t["UTTypeConformsTo"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
            assert_eq!(conforms, ["public.data", "public.item"], "{id}");
        }
        let text = serde_json::to_string(&plist).unwrap();
        for safe in ["public.plain-text", "public.text", "public.utf8-plain-text", "public.source-code"] {
            assert!(!text.contains(safe), "{safe}");
        }
        // The .conf Alternate (by the extension, no content type) stays.
        let docs = plist["CFBundleDocumentTypes"].as_array().unwrap();
        let conf = docs.iter().find(|d| d["CFBundleTypeExtensions"][0] == "conf").expect(".conf");
        assert_eq!(conf["LSHandlerRank"], "Alternate");
        assert!(conf.get("LSItemContentTypes").is_none());
    }

    /// MacVPN owns only its own type (the catalog); the imported .ovpn and .sstp types are `Default` (another app's
    /// own declaration wins), the .conf extension `Alternate`.
    #[test]
    fn handler_ranks_claim_only_the_own_type() {
        let plist = info_plist();
        let ranks: Vec<(String, String)> = plist["CFBundleDocumentTypes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                let what = d["LSItemContentTypes"][0].as_str().or(d["CFBundleTypeExtensions"][0].as_str()).unwrap();
                (what.to_string(), d["LSHandlerRank"].as_str().unwrap().to_string())
            })
            .collect();
        let expected = [
            ("local.macvpn.ovpn", "Default"),
            ("local.macvpn.sstp", "Default"),
            ("local.macvpn.catalog", "Owner"),
            ("conf", "Alternate"),
        ];
        assert_eq!(ranks, expected.map(|(a, b)| (a.to_string(), b.to_string())));
    }

    #[test]
    fn refusals_are_translated() {
        for why in [Refusal::PanelOnly, Refusal::OneCatalog] {
            assert!(!refusal_text(&why).is_empty());
        }
    }
}
