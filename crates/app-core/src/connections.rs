//! The Connections window's state without a UI (port of the selection, unsaved-changes and tab-request parts of
//! the Swift `AppModel`, plus create / import / delete): the selected row, the open editors (drafts) and their
//! dirty registry, the pending action waiting for the "Unsaved Changes" answer (selection change, window close,
//! quit), "save all" with the "Saving failed" report, and the one-time Log / Settings tab requests.

use crate::editor::{Draft, EditorDeps, EditorFields, EditorView, Target};
use crate::import_export::{self, ImportReport};
use crate::manager::ConnectionItem;
use crate::questions::{QuestionBroker, QuestionView};
use macvpn_core::importer;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::log::LogFilter;
use macvpn_core::models::{Connection, NativeSettings, VPNKind, ValidationIssue, uuid_string};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use uuid::Uuid;

/// What waits for the "Unsaved Changes" answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingAction {
    Select(Option<String>),
    CloseWindow,
    Quit,
}

impl PendingAction {
    pub fn name(&self) -> &'static str {
        match self {
            PendingAction::Select(_) => "select",
            PendingAction::CloseWindow => "closeWindow",
            PendingAction::Quit => "quit",
        }
    }
}

/// The answer to "Unsaved Changes".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsavedChoice {
    Save,
    Discard,
    Cancel,
}

pub fn parse_unsaved_choice(raw: &str) -> Result<UnsavedChoice, String> {
    match raw {
        "save" => Ok(UnsavedChoice::Save),
        "discard" => Ok(UnsavedChoice::Discard),
        "cancel" => Ok(UnsavedChoice::Cancel),
        _ => Err("invalid choice".into()),
    }
}

/// "Saving failed": which editors could not be saved, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveFailure {
    pub title: String,
    pub message: String,
}

/// What the app does after the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// Nothing more (the selection changed, or nothing was pending).
    Done,
    /// The window may close now.
    CloseWindow,
    /// The quit may go on (the active-connections question next).
    Quit,
    /// Cancelled: nothing happens.
    Cancelled,
    /// Saving failed: shown to the user; the failed editor is selected, on its Settings tab.
    Failed(SaveFailure),
}

/// The Connections window's tab a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Tab {
    Settings,
    Log,
}

/// The window state the UI needs (part of the view model).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManageView {
    pub selected: Option<String>,
    /// `select`, `closeWindow` or `quit`: the "Unsaved Changes" question is shown.
    pub pending: Option<&'static str>,
    /// The editors with unsaved changes.
    pub dirty: Vec<String>,
    /// One-time: this connection's detail switches to the Log tab (debug connect, a notification).
    pub log_request: Option<String>,
    /// One-time: this connection's detail switches to the Settings tab (after a failed save).
    pub settings_request: Option<String>,
    /// A question of an import ("Use the credentials…").
    pub question: Option<QuestionView>,
    /// Grows whenever the editors are dropped (discarded, the window closed): a shown editor loads again.
    pub editors_epoch: u64,
    /// The "New" menu: the kinds (`openvpn`, …) with their names.
    pub kinds: Vec<Choice>,
    /// The Log tab's filter (`all`, `commands`, `errors`) with their titles.
    pub log_filters: Vec<Choice>,
    /// The selected system VPN was removed from macOS: the selection (and its detail) stays, read-only.
    pub selected_removed: bool,
}

/// A value with its (translated) title.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Choice {
    pub value: &'static str,
    pub title: String,
}

#[derive(Default)]
struct WindowState {
    selected: Option<String>,
    pending: Option<PendingAction>,
    /// A selection asked for while the quit's "Unsaved Changes" was shown (a notification click, a debug
    /// connect): applied once the quit's question is answered, if the app is still running.
    deferred_select: Option<Option<String>>,
    log_tab_request: Option<String>,
    settings_tab_request: Option<String>,
    drafts: HashMap<String, Draft>,
    /// The imported connections' validation problems: the editor shows them on its first load (one-time).
    import_issues: HashMap<Uuid, Vec<ValidationIssue>>,
    editors_epoch: u64,
    /// The system VPN service IDs of the last listing ([`ConnectionsModel::services_changed`]).
    known_services: HashSet<String>,
    /// System VPNs that were listed and are gone, kept only while selected or edited.
    removed_services: HashSet<String>,
}

impl WindowState {
    /// Drops every editor (none of them is shown with unsaved changes any more).
    fn drop_drafts(&mut self) {
        self.drafts.clear();
        self.editors_epoch += 1;
    }

    /// A removed system VPN's draft does not count: it cannot be saved, so it must not raise "Unsaved Changes"
    /// (it stays in memory and counts again if the VPN returns).
    fn has_unsaved(&self) -> bool {
        self.drafts.values().any(|d| d.is_dirty() && !d.removed)
    }

    fn dirty_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> =
            self.drafts.iter().filter(|(_, d)| d.is_dirty() && !d.removed).map(|(k, _)| k.clone()).collect();
        ids.sort();
        ids
    }
}

pub struct ConnectionsModel {
    deps: EditorDeps,
    state: Mutex<WindowState>,
    questions: Arc<QuestionBroker>,
    /// One import at a time (a dialog's and a drop's files are not interleaved).
    importing: Mutex<()>,
    /// [`Self::system_services_changed`] one at a time.
    services_sync: Mutex<()>,
    on_change: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

impl ConnectionsModel {
    pub fn new(deps: EditorDeps) -> Self {
        ConnectionsModel {
            deps,
            state: Mutex::default(),
            questions: Arc::new(QuestionBroker::new()),
            importing: Mutex::new(()),
            services_sync: Mutex::new(()),
            on_change: Mutex::new(None),
        }
    }

    pub fn deps(&self) -> &EditorDeps {
        &self.deps
    }

    pub fn questions(&self) -> &Arc<QuestionBroker> {
        &self.questions
    }

    pub fn set_on_change(&self, hook: impl Fn() + Send + Sync + 'static) {
        let hook: Arc<dyn Fn() + Send + Sync> = Arc::new(hook);
        let questions = hook.clone();
        self.questions.set_on_change(move || questions());
        *self.on_change.lock().unwrap_or_else(PoisonError::into_inner) = Some(hook);
    }

    fn changed(&self) {
        let hook = self.on_change.lock().unwrap_or_else(PoisonError::into_inner).clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    fn lock(&self) -> MutexGuard<'_, WindowState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn view(&self) -> ManageView {
        let s = self.lock();
        ManageView {
            selected: s.selected.clone(),
            pending: s.pending.as_ref().map(PendingAction::name),
            dirty: s.dirty_ids(),
            log_request: s.log_tab_request.clone(),
            settings_request: s.settings_tab_request.clone(),
            question: self.questions.current(),
            editors_epoch: s.editors_epoch,
            kinds: VPNKind::ALL
                .into_iter()
                .map(|k| Choice { value: k.raw_value(), title: k.display_name().to_string() })
                .collect(),
            log_filters: LogFilter::ALL
                .into_iter()
                .map(|f| Choice { value: f.raw_value(), title: f.title() })
                .collect(),
            selected_removed: s.selected.as_ref().is_some_and(|k| s.removed_services.contains(k)),
        }
    }

    pub fn selected(&self) -> Option<String> {
        self.lock().selected.clone()
    }

    pub fn pending(&self) -> Option<PendingAction> {
        self.lock().pending.clone()
    }

    pub fn has_unsaved_changes(&self) -> bool {
        self.lock().has_unsaved()
    }

    // MARK: - Selection, unsaved changes

    /// Changes the selection. With unsaved changes it asks first (the pending action): false. While the quit's
    /// question is shown it is never replaced: the selection waits for its answer (false).
    pub fn select(&self, id: Option<String>) -> bool {
        let mut s = self.lock();
        if s.pending == Some(PendingAction::Quit) {
            let same = id == s.selected;
            s.deferred_select = (!same).then_some(id);
            return same;
        }
        if id == s.selected {
            return true;
        }
        if s.has_unsaved() {
            s.pending = Some(PendingAction::Select(id));
            drop(s);
            self.changed();
            return false;
        }
        s.selected = id;
        // The previous detail's editors go with it (none of them has unsaved changes).
        s.drop_drafts();
        drop(s);
        self.changed();
        true
    }

    /// The window is about to close: false (and the question) if there are unsaved changes. A quit's question
    /// stays (closing the window then cancels the quit: [`Self::window_closed`]).
    pub fn should_close_window(&self) -> bool {
        let mut s = self.lock();
        if !s.has_unsaved() {
            return true;
        }
        if s.pending == Some(PendingAction::Quit) {
            return false;
        }
        s.pending = Some(PendingAction::CloseWindow);
        drop(s);
        self.changed();
        false
    }

    /// A quit with unsaved changes: the window asks first (true). False: nothing unsaved.
    pub fn ask_before_quit(&self) -> bool {
        let mut s = self.lock();
        if !s.has_unsaved() {
            return false;
        }
        // A selection's question gives way to the quit's; the selection follows if the app keeps running.
        if let Some(PendingAction::Select(id)) = s.pending.take() {
            s.deferred_select = Some(id);
        }
        s.pending = Some(PendingAction::Quit);
        drop(s);
        self.changed();
        true
    }

    /// The quit guard ended the quit's "Unsaved Changes" step without this window's answer (the Update window
    /// closed, which cancels its quit): the question goes away, the editing stays, a deferred selection follows.
    pub fn quit_question_ended(&self) {
        {
            let mut s = self.lock();
            if s.pending != Some(PendingAction::Quit) {
                return;
            }
            s.pending = None;
        }
        self.changed();
        self.apply_deferred_select();
    }

    /// The selection that waited for the quit's question, now that it is answered.
    fn apply_deferred_select(&self) {
        let deferred = self.lock().deferred_select.take();
        if let Some(id) = deferred {
            self.select(id);
        }
    }

    /// The window closed: its editors and a question of a running import go with it.
    pub fn window_closed(&self) {
        {
            let mut s = self.lock();
            s.drop_drafts();
            s.pending = None;
        }
        self.questions.cancel();
        self.changed();
        self.apply_deferred_select();
    }

    /// The answer to "Unsaved Changes".
    pub fn resolve(&self, choice: UnsavedChoice) -> Resolved {
        let Some(pending) = self.pending() else { return Resolved::Done };
        match choice {
            UnsavedChoice::Cancel => {
                self.cancel_pending_action();
                // A cancelled quit: the app goes on, with the selection asked for meanwhile.
                self.apply_deferred_select();
                Resolved::Cancelled
            }
            UnsavedChoice::Save => match self.save_all_unsaved() {
                Ok(()) => {
                    let resolved = self.proceed(pending);
                    self.apply_deferred_select();
                    resolved
                }
                Err(failure) => {
                    // The failed editor is shown instead.
                    self.cancel_pending_action();
                    self.lock().deferred_select = None;
                    Resolved::Failed(failure)
                }
            },
            UnsavedChoice::Discard => {
                self.discard_unsaved();
                let resolved = self.proceed(pending);
                self.apply_deferred_select();
                resolved
            }
        }
    }

    fn proceed(&self, pending: PendingAction) -> Resolved {
        let mut s = self.lock();
        s.pending = None;
        let resolved = match pending {
            PendingAction::Select(id) => {
                if s.selected != id {
                    s.selected = id;
                    s.drop_drafts();
                }
                Resolved::Done
            }
            PendingAction::CloseWindow => Resolved::CloseWindow,
            PendingAction::Quit => Resolved::Quit,
        };
        drop(s);
        self.changed();
        resolved
    }

    /// The pending action is cancelled. A cancelled selection drops its Log tab request; a cancelled quit keeps
    /// it (it belongs to the selection deferred by the quit).
    pub fn cancel_pending_action(&self) {
        {
            let mut s = self.lock();
            if s.pending.take() != Some(PendingAction::Quit) {
                s.log_tab_request = None;
            }
        }
        self.changed();
    }

    /// Every editor with unsaved changes is saved. If one cannot be (validation problem), the report says why,
    /// and the failed connection is selected on its Settings tab (the window opens it).
    pub fn save_all_unsaved(&self) -> Result<(), SaveFailure> {
        let keys = self.lock().dirty_ids();
        let mut failures: Vec<(String, String)> = Vec::new();
        for key in keys {
            if let Some(Err(message)) = self.save_draft(&key) {
                failures.push((key, message));
            }
        }
        let Some((first, _)) = failures.first().cloned() else { return Ok(()) };
        let mut names: HashMap<String, String> =
            self.deps.manager.connections().into_iter().map(|c| (uuid_string(&c.id), c.name)).collect();
        for s in self.deps.manager.system_services() {
            names.insert(s.id.clone(), s.name.clone());
        }
        let message = failures
            .iter()
            .map(|(id, m)| format!("{}: {m}", names.get(id).cloned().unwrap_or_else(|| id.clone())))
            .collect::<Vec<_>>()
            .join("\n\n");
        {
            // The failed editor is shown (on purpose without the dirty check: it shows the same editing).
            let mut s = self.lock();
            s.pending = None;
            s.log_tab_request = None;
            s.settings_tab_request = Some(first.clone());
            s.selected = Some(first);
        }
        self.changed();
        Err(SaveFailure { title: l10n::tr("Saving failed", &[]), message })
    }

    /// The edits are dropped; a shown editor loads the stored settings again (`editors_epoch`).
    pub fn discard_unsaved(&self) {
        self.lock().drop_drafts();
        self.changed();
    }

    /// Saves one draft outside the lock. `None`: no such draft; `Err`: the message.
    fn save_draft(&self, key: &str) -> Option<Result<(), String>> {
        let mut draft = self.lock().drafts.get(key).cloned()?;
        if draft.removed {
            return Some(Err(removed_message()));
        }
        let before = draft.fields.clone();
        let result = draft.save_reporting_error(&self.deps);
        {
            let mut s = self.lock();
            if let Some(current) = s.drafts.get_mut(key) {
                // Edits that arrived while saving are kept (still unsaved then).
                let edited = current.fields != before;
                let fields = current.fields.clone();
                // A refresh meanwhile may have marked it removed: that mark stays.
                let removed = current.removed;
                *current = draft;
                current.removed = removed;
                if edited {
                    current.fields = fields;
                }
            }
        }
        self.changed();
        Some(result.map_or(Ok(()), Err))
    }

    // MARK: - Tab requests

    /// The detail of `id` switches to the Log tab once (debug connect, a notification).
    pub fn request_log_tab(&self, id: &str) {
        self.lock().log_tab_request = Some(id.to_string());
        self.changed();
    }

    /// One-time: the tab the detail of `id` must switch to. The Settings request (failed save) comes first.
    pub fn take_tab_request(&self, id: &str) -> Option<Tab> {
        let mut s = self.lock();
        let tab = if s.settings_tab_request.as_deref() == Some(id) {
            s.settings_tab_request = None;
            Tab::Settings
        } else if s.log_tab_request.as_deref() == Some(id) {
            s.log_tab_request = None;
            Tab::Log
        } else {
            return None;
        };
        drop(s);
        self.changed();
        Some(tab)
    }

    // MARK: - Editors

    fn target(&self, key: &str) -> Result<Target, String> {
        match self.deps.manager.item(key) {
            Some(ConnectionItem::Managed(c)) => Ok(Target::Connection(c)),
            Some(ConnectionItem::System(s)) if s.supports_stored_secrets() => Ok(Target::System(s)),
            Some(ConnectionItem::System(_)) => Err("no editor".into()),
            None => Err("unknown connection".into()),
        }
    }

    /// The editor of `key`, loaded on its first use (a later open does not overwrite the editing).
    pub fn open_editor(&self, key: &str) -> Result<EditorView, String> {
        if let Some(d) = self.lock().drafts.get(key) {
            return Ok(d.view(key));
        }
        let target = self.target(key)?;
        let issues = match &target {
            Target::Connection(c) => self.lock().import_issues.remove(&c.id).unwrap_or_default(),
            Target::System(_) => Vec::new(),
        };
        let mut loaded = Draft::load(&self.deps, target, issues);
        let mut s = self.lock();
        // A refresh while loading may have found the service gone.
        loaded.removed = matches!(loaded.target, Target::System(_)) && s.removed_services.contains(key);
        let view = s.drafts.entry(key.to_string()).or_insert(loaded).view(key);
        Ok(view)
    }

    fn with_draft<T>(&self, key: &str, f: impl FnOnce(&mut Draft) -> Result<T, String>) -> Result<T, String> {
        let result = {
            let mut s = self.lock();
            let draft = s.drafts.get_mut(key).ok_or("no editor")?;
            f(draft)?
        };
        self.changed();
        Ok(result)
    }

    /// The editor's fields after a change in the UI.
    pub fn update_editor(&self, key: &str, fields: EditorFields) -> Result<EditorView, String> {
        self.with_draft(key, |d| {
            if d.removed {
                return Err(removed_message());
            }
            d.update(fields)?;
            Ok(d.view(key))
        })
    }

    /// "Save" (with the editor's latest fields).
    pub fn save_editor(&self, key: &str, fields: EditorFields) -> Result<EditorView, String> {
        self.update_editor(key, fields)?;
        self.save_draft(key).ok_or("no editor")?.ok();
        self.with_draft(key, |d| Ok(d.view(key)))
    }

    /// "Forget saved secrets" (system VPN). Allowed on a removed VPN too: deleting is not editing.
    pub fn forget_secrets(&self, key: &str) -> Result<EditorView, String> {
        let mut draft = self.lock().drafts.get(key).cloned().ok_or("no editor")?;
        draft.forget(&self.deps);
        self.with_draft(key, |d| {
            // A refresh meanwhile may have changed the removed mark: the current one stays.
            let removed = d.removed;
            *d = draft;
            d.removed = removed;
            Ok(d.view(key))
        })
    }

    /// The text of the chosen CA file (`None`: unreadable) into the SSTP editor.
    pub fn import_ca(&self, key: &str, text: Option<&str>) -> Result<EditorView, String> {
        self.with_draft(key, |d| {
            d.import_ca(text);
            Ok(d.view(key))
        })
    }

    // MARK: - Live system VPN list

    /// After a refresh: `present` are the system VPN service IDs listed now. A shown system VPN (selected, or with
    /// an open editor) that was listed before and is gone is marked removed: its editor is read-only and the
    /// selection stays. Listed again with the same ID, it is editable again with its draft. Managed connections
    /// are never marked. Stored secrets are not deleted (the service may return).
    pub fn services_changed(&self, present: &HashSet<String>) {
        let changed = {
            let mut s = self.lock();
            let mut removed: HashSet<String> = s.removed_services.clone();
            removed.extend(s.known_services.difference(present).cloned());
            let shown = |k: &String| s.selected.as_ref() == Some(k) || s.drafts.contains_key(k);
            removed.retain(|k| !present.contains(k) && shown(k));
            let mut changed = removed != s.removed_services;
            for (key, draft) in &mut s.drafts {
                let gone = matches!(draft.target, Target::System(_)) && removed.contains(key);
                if draft.removed != gone {
                    draft.removed = gone;
                    changed = true;
                }
            }
            s.removed_services = removed;
            s.known_services.clone_from(present);
            changed
        };
        if changed {
            self.changed();
        }
    }

    /// [`Self::services_changed`] with every service macOS lists now, managed ones included (a service a managed
    /// connection takes over is not gone). The app calls it on every manager change; the calls are serialized, so
    /// an older listing never overwrites a newer one.
    pub fn system_services_changed(&self) {
        let _one_at_a_time = self.services_sync.lock().unwrap_or_else(PoisonError::into_inner);
        self.services_changed(&self.deps.manager.listed_service_ids());
    }

    // MARK: - Create, import, delete

    /// "New <kind>": saved with the kind's template and selected.
    pub fn create(&self, kind: VPNKind) -> Result<Uuid, String> {
        let mut c = Connection::new(l10n::tr("New %@", &[Arg::Str(kind.display_name())]), kind);
        if kind.is_native() {
            c.native = Some(NativeSettings::default());
        }
        let template = (!kind.is_native()).then(|| importer::template(kind));
        self.deps.store.save(&c, template.as_deref()).map_err(|e| e.to_string())?;
        self.deps.manager.reload();
        self.select(Some(uuid_string(&c.id)));
        Ok(c.id)
    }

    /// Imports the files one after the other; each imported connection is selected (through the unsaved-changes
    /// check). The credential-file question goes to the window and waits for its answer.
    pub fn import_paths(&self, paths: &[PathBuf]) -> ImportReport {
        let _one_at_a_time = self.importing.lock().unwrap_or_else(PoisonError::into_inner);
        let mut report = ImportReport::default();
        for path in paths {
            let mut confirm = |files: &[String], config: &str| {
                let (title, message) = import_export::credential_question(files, config);
                self.questions.ask(title, message, l10n::tr("Use", &[]), l10n::tr("Ignore", &[]))
            };
            let file = import_export::import_file(&self.deps, path, &mut confirm);
            if let Some((id, issues)) = file.imported {
                if !issues.is_empty() {
                    self.lock().import_issues.insert(id, issues);
                }
                self.deps.manager.reload();
                self.select(Some(uuid_string(&id)));
            }
            report.merge(file.report);
        }
        report
    }

    /// Deletes a managed connection: disconnected first if active, its editor closed, its config and Keychain
    /// items deleted. Returns the deleted connection (the app stops its native log collection, opens the Profiles
    /// pane for a native one, and refreshes).
    pub fn delete(&self, id: &Uuid) -> Option<Connection> {
        let key = uuid_string(id);
        let c = self.deps.manager.connections().into_iter().find(|c| c.id == *id)?;
        if self.deps.manager.state(&key).is_active() {
            self.deps.manager.disconnect(&c);
        }
        {
            let mut s = self.lock();
            s.drafts.remove(&key);
            s.import_issues.remove(id);
        }
        // No "Save" of a connect still in flight may bring its Keychain items back.
        self.deps.manager.forget_saves(id);
        let _ = self.deps.store.delete(id);
        self.deps.secret_writer.delete_all(id);
        self.deps.manager.reload();
        {
            let mut s = self.lock();
            if s.selected.as_deref() == Some(key.as_str()) {
                s.selected = None;
            }
        }
        self.changed();
        Some(c)
    }

    /// The editors' fields by key (tests, diagnostics).
    pub fn draft_fields(&self) -> BTreeMap<String, EditorFields> {
        self.lock().drafts.iter().map(|(k, d)| (k.clone(), d.fields.clone())).collect()
    }
}

/// "This VPN was removed from macOS": the refusal of a removed system VPN's editor.
pub fn removed_message() -> String {
    l10n::tr("This VPN was removed from macOS", &[])
}
