//! The Connections window's state without a UI (port of the selection, unsaved-changes and tab-request parts of
//! the Swift `AppModel`, plus create / import / delete): the selected row, the open editors (drafts) and their
//! dirty registry, the pending action waiting for the "Unsaved Changes" answer (selection change, window close,
//! quit), "save all" with the "Saving failed" report, and the one-time Log / Settings tab requests.

use crate::deps::SecretField;
use crate::editor::{Cert, Draft, EditorDeps, EditorFields, EditorPlatformView, EditorView, Target};
use crate::import_export::{self, ImportReport};
use crate::manager::ConnectionItem;
use crate::questions::{QuestionBroker, QuestionView};
use crate::shared_credentials::{self, CredentialsView, ImportLink, SharedCredentials};
use macvpn_core::importer;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::log::LogFilter;
use macvpn_core::models::{Connection, NativeSettings, VPNKind, ValidationIssue, uuid_string};
use macvpn_core::validators::sstp::SSTPConfig;
use macvpn_platform_api::{AdminSteps, NativeSupport};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use uuid::Uuid;
use zeroize::Zeroizing;

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
    /// No kind can be created (every engine is missing): the "New" menu's note. Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds_note: Option<String>,
    /// The Log tab's filter (`all`, `commands`, `errors`) with their titles.
    pub log_filters: Vec<Choice>,
    /// The selected system VPN was removed from macOS: the selection (and its detail) stays, read-only.
    pub selected_removed: bool,
    /// Deleting a native connection removes its profile too ([`crate::deps::NativeProfiles::removes_profiles`];
    /// WinVPN): the delete confirmation says so. Absent from the JSON when false (macOS).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub native_delete_removes_profile: bool,
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
    /// Team catalog profiles staged by "Install profile" and not yet seen installed: the "reinstall its profile"
    /// mark is cleared only once macOS shows the new profile ([`ConnectionsModel::system_services_changed`]).
    pending_installs: HashMap<Uuid, PendingInstall>,
}

/// A staged team catalog profile waiting for macOS to show it installed.
#[derive(Debug, Clone)]
struct PendingInstall {
    /// The config hash of the version the profile was built from (compare-and-clear in the vault).
    built_from: String,
    /// The service the connection mapped to when the profile was staged, with its server address (`None`: none).
    baseline: Option<(String, Option<String>)>,
    /// The service was gone at a check since (removed, then installed again).
    gone: bool,
    /// The last check (the fresh `scutil` reads run at most every [`INSTALL_CHECK_INTERVAL`] seconds).
    checked: Option<f64>,
}

/// Seconds between two checks of a pending profile install.
const INSTALL_CHECK_INTERVAL: f64 = 3.0;

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
    /// The shared credentials over the vault (spec 3a): the Credentials section, the editors' selector, the
    /// import's question. `None` until the app has a vault: every credential action then says it is locked.
    credentials: Mutex<Option<SharedCredentials>>,
    /// Which kinds cannot be added (created or imported): the localized reason, `None` = allowed. The app builds it
    /// from the setup report; unset (and before the first check) everything is allowed.
    kind_gate: Mutex<Option<KindGate>>,
    /// The platform's editor notes and administrator steps ([`Self::set_native_platform`]; macOS: none).
    native_platform: Mutex<Option<NativePlatform>>,
    /// The last SSTP custom CA asked about and the platform's answer (the editor's updates do not ask again).
    ca_trust: Mutex<Option<(String, Option<bool>)>>,
}

/// [`ConnectionsModel::set_native_platform`].
#[derive(Clone)]
struct NativePlatform {
    support: Arc<dyn NativeSupport>,
    admin: Arc<dyn AdminSteps>,
}

/// The kind gate of [`ConnectionsModel::set_kind_gate`].
pub type KindGate = Box<dyn Fn(VPNKind) -> Option<String> + Send + Sync>;

impl ConnectionsModel {
    pub fn new(deps: EditorDeps) -> Self {
        ConnectionsModel {
            deps,
            state: Mutex::default(),
            questions: Arc::new(QuestionBroker::new()),
            importing: Mutex::new(()),
            services_sync: Mutex::new(()),
            on_change: Mutex::new(None),
            credentials: Mutex::new(None),
            kind_gate: Mutex::new(None),
            native_platform: Mutex::new(None),
            ca_trust: Mutex::new(None),
        }
    }

    /// The platform's notes on the editors' drafts and its administrator steps (WinVPN 2c): every editor view
    /// then carries [`EditorView::platform`]. Unset (macOS): no editor has one.
    pub fn set_native_platform(&self, support: Arc<dyn NativeSupport>, admin: Arc<dyn AdminSteps>) {
        *self.native_platform.lock().unwrap_or_else(PoisonError::into_inner) = Some(NativePlatform { support, admin });
    }

    /// The system's trust may have changed (a **Trust This CA in Windows…** ran): the next editor view asks again.
    pub fn ca_trust_changed(&self) {
        *self.ca_trust.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// Whether the system trusts `pem`, asked once per PEM.
    fn ca_trusted(&self, admin: &dyn AdminSteps, pem: &str) -> Option<bool> {
        let mut cache = self.ca_trust.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((cached, answer)) = cache.as_ref()
            && cached == pem
        {
            return *answer;
        }
        let answer = admin.ca_trusted(pem);
        *cache = Some((pem.to_string(), answer));
        answer
    }

    /// The view with the platform's notes on its fields (the draft, so they follow the typing). No lock of the
    /// window is held here: the platform may read the system (the CA store).
    fn with_platform(&self, mut view: EditorView) -> EditorView {
        let Some(platform) = self.native_platform.lock().unwrap_or_else(PoisonError::into_inner).clone() else {
            return view;
        };
        view.platform = match &view.fields {
            EditorFields::System(_) => platform
                .support
                .system_psk_note()
                .map(|note| EditorPlatformView { psk_note: Some(note), ..EditorPlatformView::default() }),
            fields => {
                let Some(ConnectionItem::Managed(mut c)) = self.deps.manager.item(&view.id) else { return view };
                let config = match fields {
                    EditorFields::Text(f) => f.text.clone().into_bytes(),
                    EditorFields::Sstp(f) => f.config().serialized().into_bytes(),
                    EditorFields::Native(f) => {
                        c.native = Some(NativeSettings {
                            server: f.server.clone(),
                            account: f.account.clone(),
                            group_name: f.group_name.clone(),
                            send_all_traffic: f.send_all_traffic,
                        });
                        Vec::new()
                    }
                    EditorFields::System(_) => Vec::new(),
                };
                let notes = platform.support.editor_notes(&c, &config);
                let ca_trusted = match fields {
                    EditorFields::Sstp(f) if notes.trust_ca && f.cert == Cert::Ca && !f.ca_pem.trim().is_empty() => {
                        self.ca_trusted(platform.admin.as_ref(), &f.ca_pem)
                    }
                    _ => None,
                };
                (!notes.is_empty() || ca_trusted.is_some()).then_some(EditorPlatformView {
                    reasons: notes.reasons,
                    summary: notes.summary,
                    warnings: notes.warnings,
                    insecure_cert: notes.insecure_cert,
                    trust_ca: notes.trust_ca,
                    ca_trusted,
                    l2tp_copy: notes.l2tp_copy,
                    no_install_step: notes.no_install_step,
                    psk_note: None,
                })
            }
        };
        view
    }

    /// The SSTP custom CA **Trust This CA in Windows…** trusts: the open editor's (as chosen, saved or not), else
    /// the saved config's. An error when the connection is not SSTP or has no CA.
    pub fn sstp_ca_pem(&self, key: &str) -> Result<String, String> {
        self.unlocked()?;
        let no_ca = || l10n::tr("No CA certificate loaded", &[]);
        let draft = self.lock().drafts.get(key).map(|d| d.fields.clone());
        let pem = match draft {
            Some(EditorFields::Sstp(f)) => f.ca_pem,
            Some(_) => return Err(no_ca()),
            None => match self.deps.manager.item(key) {
                Some(ConnectionItem::Managed(c)) if c.kind == VPNKind::Sstp => {
                    SSTPConfig::parse(&self.deps.store.load_config(&c.id).unwrap_or_default()).ca_pem
                }
                _ => return Err(no_ca()),
            },
        };
        if pem.trim().is_empty() { Err(no_ca()) } else { Ok(pem) }
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

    /// Sets which kinds cannot be added: the "New" menu leaves them out, "New" and an import of one are refused
    /// with the gate's reason. Team catalogs are not filtered (they never go through here).
    pub fn set_kind_gate(&self, gate: KindGate) {
        *self.kind_gate.lock().unwrap_or_else(PoisonError::into_inner) = Some(gate);
    }

    /// Why `kind` cannot be added (`None`: it can).
    fn unavailable(&self, kind: VPNKind) -> Option<String> {
        self.kind_gate.lock().unwrap_or_else(PoisonError::into_inner).as_ref().and_then(|gate| gate(kind))
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
        let kinds: Vec<Choice> = VPNKind::ALL
            .into_iter()
            .filter(|k| self.unavailable(*k).is_none())
            .map(|k| Choice { value: k.raw_value(), title: k.display_name().to_string() })
            .collect();
        let kinds_note =
            kinds.is_empty().then(|| l10n::tr("Install the VPN tools in System Status to add connections.", &[]));
        let s = self.lock();
        ManageView {
            selected: s.selected.clone(),
            pending: s.pending.as_ref().map(PendingAction::name),
            dirty: s.dirty_ids(),
            log_request: s.log_tab_request.clone(),
            settings_request: s.settings_tab_request.clone(),
            question: self.questions.current(),
            editors_epoch: s.editors_epoch,
            kinds,
            kinds_note,
            log_filters: LogFilter::ALL
                .into_iter()
                .map(|f| Choice { value: f.raw_value(), title: f.title() })
                .collect(),
            selected_removed: s.selected.as_ref().is_some_and(|k| s.removed_services.contains(k)),
            native_delete_removes_profile: self.deps.profiles.removes_profiles(),
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
        if let Err(locked) = self.unlocked() {
            return Some(Err(locked));
        }
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

    /// Refused while the vault is locked (nothing that reads or writes it works then).
    fn unlocked(&self) -> Result<(), String> {
        if self.deps.manager.is_locked() { Err(crate::vault_stores::locked_message()) } else { Ok(()) }
    }

    /// The vault was locked: every editor and its unsaved edits are dropped (the drafts hold connection settings
    /// and typed secrets). A pending "Unsaved Changes" question then finds nothing to save.
    pub fn vault_locked(&self) {
        {
            let mut s = self.lock();
            s.drop_drafts();
            s.import_issues.clear();
        }
        self.changed();
    }

    /// The editor of `key`, loaded on its first use (a later open does not overwrite the editing).
    pub fn open_editor(&self, key: &str) -> Result<EditorView, String> {
        self.open_editor_draft(key).map(|v| self.with_platform(v))
    }

    fn open_editor_draft(&self, key: &str) -> Result<EditorView, String> {
        self.unlocked()?;
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
        self.unlocked()?;
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
        self.update_draft(key, fields).map(|v| self.with_platform(v))
    }

    fn update_draft(&self, key: &str, fields: EditorFields) -> Result<EditorView, String> {
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
        self.update_draft(key, fields)?;
        self.save_draft(key).ok_or("no editor")?.ok();
        self.with_draft(key, |d| Ok(d.view(key))).map(|v| self.with_platform(v))
    }

    /// "Forget saved secrets" (system VPN). Allowed on a removed VPN too: deleting is not editing.
    pub fn forget_secrets(&self, key: &str) -> Result<EditorView, String> {
        self.unlocked()?;
        let mut draft = self.lock().drafts.get(key).cloned().ok_or("no editor")?;
        draft.forget(&self.deps);
        self.with_draft(key, |d| {
            // A refresh meanwhile may have changed the removed mark: the current one stays.
            let removed = d.removed;
            *d = draft;
            d.removed = removed;
            Ok(d.view(key))
        })
        .map(|v| self.with_platform(v))
    }

    /// The text of the chosen CA file (`None`: unreadable) into the SSTP editor.
    pub fn import_ca(&self, key: &str, text: Option<&str>) -> Result<EditorView, String> {
        self.with_draft(key, |d| {
            d.import_ca(text);
            Ok(d.view(key))
        })
        .map(|v| self.with_platform(v))
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
        self.reload_changed_catalog_drafts();
        self.check_pending_installs();
    }

    /// Clears the "reinstall its profile" mark of a staged team catalog profile once macOS shows it installed:
    /// its service appears (there was none), is replaced (another service ID, or gone and back), or shows the new
    /// server address. A cancelled install changes none of these, so the connect stays blocked. The vault clears
    /// the mark only if the profile was built from the version applied now (an apply racing the install keeps its
    /// new mark). A profile whose service stays the same and whose server did not change cannot be told from a
    /// cancelled one: remove the old VPN in System Settings → Network and install the profile again.
    fn check_pending_installs(&self) {
        let now = self.deps.clock.now().time_interval_since_1970();
        let due: Vec<(Uuid, PendingInstall)> = {
            let s = self.lock();
            s.pending_installs
                .iter()
                .filter(|(_, p)| p.checked.is_none_or(|t| now - t >= INSTALL_CHECK_INTERVAL || now < t))
                .map(|(id, p)| (*id, p.clone()))
                .collect()
        };
        let mut cleared = false;
        for (id, mut pending) in due {
            pending.checked = Some(now);
            let current = match self.deps.manager.item(&uuid_string(&id)) {
                Some(ConnectionItem::Managed(c)) if self.deps.store.team_managed(&id).is_some() => c,
                _ => {
                    // Deleted, or no longer a catalog connection: nothing to wait for.
                    self.lock().pending_installs.remove(&id);
                    continue;
                }
            };
            let installed = match self.deps.manager.native_service_for(&current) {
                None => false,
                Some(None) => {
                    pending.gone = true;
                    false
                }
                Some(Some(seen)) => match &pending.baseline {
                    None => true,
                    Some(_) if pending.gone => true,
                    Some((service, address)) => seen.0 != *service || seen.1 != *address,
                },
            };
            let mut s = self.lock();
            if !installed {
                if s.pending_installs.contains_key(&id) {
                    s.pending_installs.insert(id, pending);
                }
                continue;
            }
            s.pending_installs.remove(&id);
            drop(s);
            // `Ok(false)`: built from an older version; the mark stays and the user installs again.
            if self.deps.store.profile_reinstalled(&id, &pending.built_from).is_ok_and(|done| done) {
                cleared = true;
            }
        }
        if cleared {
            self.changed();
        }
    }

    /// The open editors of team catalog connections the catalog changed since they were loaded (an apply reloads
    /// the manager, which calls [`Self::system_services_changed`]) load again from the new version: a read-only
    /// editor only holds the risky checkbox, and it must never stand for a config the user has not seen. The vault
    /// refuses a stale acknowledgement anyway (`set_acknowledged_risky` compares the config).
    fn reload_changed_catalog_drafts(&self) {
        let open: Vec<(String, Connection, Option<String>)> = self
            .lock()
            .drafts
            .iter()
            .filter(|(_, d)| d.read_only.is_some())
            .filter_map(|(k, d)| match (&d.target, &d.original) {
                (Target::Connection(c), EditorFields::Text(o)) => Some((k.clone(), c.clone(), Some(o.text.clone()))),
                (Target::Connection(c), _) => Some((k.clone(), c.clone(), None)),
                _ => None,
            })
            .collect();
        let mut changed = false;
        for (key, before, text) in open {
            let Some(ConnectionItem::Managed(now)) = self.deps.manager.item(&key) else { continue };
            let settings_changed = now.kind != before.kind
                || now.name != before.name
                || now.native != before.native
                || now.otp != before.otp;
            let config_changed = match &text {
                Some(text) => self.deps.store.load_config(&now.id).is_ok_and(|current| current != *text),
                None => false,
            };
            if !settings_changed && !config_changed {
                continue;
            }
            let loaded = Draft::load(&self.deps, Target::Connection(now), Vec::new());
            let mut s = self.lock();
            if let Some(draft) = s.drafts.get_mut(&key)
                && draft.read_only.is_some()
            {
                *draft = loaded;
                changed = true;
            }
        }
        if changed {
            self.changed();
        }
    }

    // MARK: - Create, import, delete

    /// "New <kind>": saved with the kind's template and selected.
    pub fn create(&self, kind: VPNKind) -> Result<Uuid, String> {
        self.unlocked()?;
        if let Some(reason) = self.unavailable(kind) {
            return Err(reason);
        }
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

    /// **Make an L2TP/IPsec Copy** of a Cisco IPsec connection (WinVPN: Windows has no Cisco IPsec client; option
    /// A of the 2c plan): the copy ([`crate::editor::l2tp_copy_of`]) is selected, so its editor opens. Follows the
    /// kind gate for L2TP as "New" does. `Ok((id, install_error))`: the copy exists; `install_error` is what its
    /// profile install answered (shown as after a save).
    pub fn make_l2tp_copy(&self, key: &str) -> Result<(Uuid, Option<String>), String> {
        self.unlocked()?;
        let Some(ConnectionItem::Managed(original)) = self.deps.manager.item(key) else {
            return Err(l10n::tr("The editor is no longer available", &[]));
        };
        if let Some(reason) = self.unavailable(VPNKind::L2tp) {
            return Err(reason);
        }
        let credentials = self.shared_credentials();
        let copy = crate::editor::l2tp_copy_of(&self.deps, &original, credentials.as_ref())?;
        self.select(Some(uuid_string(&copy.id)));
        Ok((copy.id, copy.install_error))
    }

    /// Imports the files one after the other; each imported connection is selected (through the unsaved-changes
    /// check). The credential-file question goes to the window and waits for its answer.
    pub fn import_paths(&self, paths: &[PathBuf]) -> ImportReport {
        let _one_at_a_time = self.importing.lock().unwrap_or_else(PoisonError::into_inner);
        let mut report = ImportReport::default();
        if let Err(locked) = self.unlocked() {
            report.errors.push(locked);
            return report;
        }
        for path in paths {
            let mut confirm = |files: &[String], config: &str| {
                let (title, message) = import_export::credential_question(files, config);
                self.questions.ask(title, message, l10n::tr("Use", &[]), l10n::tr("Ignore", &[]))
            };
            let gate = |kind: VPNKind| self.unavailable(kind);
            let mut file = import_export::import_file(&self.deps, path, &gate, &mut confirm);
            if let Some((id, issues)) = file.imported {
                if let Some(imported) = &file.credential
                    && let Some(note) = self.ask_imported_credential(&id, imported)
                {
                    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    file.report.notes.push(format!("{name}: {note}"));
                }
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
        self.unlocked().ok()?;
        // A team catalog's connection is removed by the catalog (or by unsubscribing), never here: its slot link,
        // team secrets and pin stay.
        if self.deps.store.team_managed(id).is_some() {
            return None;
        }
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
        // Fail closed: the secrets and the credential link go only with the connection itself (the vault refuses
        // to delete a team catalog's connection even when the ownership read above failed).
        let deleted = self.deps.store.delete(id).is_ok();
        if deleted {
            self.deps.secret_writer.delete_all(id);
            // Its profile, whatever the kind (the platform knows what exists; nothing on macOS).
            self.deps.profiles.remove(id);
        }
        self.deps.manager.reload();
        {
            let mut s = self.lock();
            if s.selected.as_deref() == Some(key.as_str()) {
                s.selected = None;
            }
        }
        self.changed();
        deleted.then_some(c)
    }

    /// "Install profile" of a team catalog's native connection (spec 6), also the reinstall its "the team catalog
    /// changed this connection" mark offers: the profile from the catalog's settings without an account (the slot's
    /// user name is passed at connect) and with the stored (team) PSK, through the same installer as the native
    /// editor. The mark is cleared only once macOS shows the profile installed (see
    /// [`Self::system_services_changed`]): staging it is not installing it. Where installing needs no approval
    /// (WinVPN: [`crate::deps::NativeProfiles::needs_approval`] is false) an install that succeeded clears it at once.
    pub fn install_team_profile(&self, key: &str) -> Result<(), String> {
        self.unlocked()?;
        let Some(ConnectionItem::Managed(listed)) = self.deps.manager.item(key) else {
            return Err("unknown connection".into());
        };
        let team = self.deps.store.team_managed(&listed.id);
        if !listed.kind.is_native() || team.is_none() {
            return Err("not a team catalog profile".into());
        }
        let (c, built_from) = self.team_profile_source(&listed.id)?;
        let baseline = self.deps.manager.native_service_for(&c).flatten();
        self.install_profile(&c, true)?;
        if !self.deps.profiles.needs_approval() {
            self.lock().pending_installs.remove(&c.id);
            // `Ok(false)`: an apply changed it meanwhile; its own install follows that apply.
            let _ = self.deps.store.profile_reinstalled(&c.id, &built_from);
            self.changed();
            return Ok(());
        }
        self.lock().pending_installs.insert(c.id, PendingInstall { built_from, baseline, gone: false, checked: None });
        self.changed();
        Ok(())
    }

    /// A team catalog connection's settings and the config hash of the version they are of (the hash before and
    /// after reading the settings must agree).
    fn team_profile_source(&self, id: &Uuid) -> Result<(Connection, String), String> {
        let built_from =
            self.deps.store.team_managed(id).and_then(|t| t.config_hash).ok_or("not a team catalog profile")?;
        let c = self
            .deps
            .store
            .list()
            .map_err(|e| e.to_string())?
            .into_iter()
            .find(|c| c.id == *id)
            .ok_or("unknown connection")?;
        if self.deps.store.team_managed(id).and_then(|t| t.config_hash).as_deref() != Some(built_from.as_str()) {
            return Err(crate::deps::catalog_changed_message());
        }
        Ok((c, built_from))
    }

    /// Builds and installs the native profile of `c` with its stored PSK, as the native editor does; a team
    /// catalog connection's (`team`) without the account (the slot's user name is passed at connect).
    fn install_profile(&self, c: &Connection, team: bool) -> Result<(), String> {
        let mut profile = c.clone();
        if team && let Some(native) = profile.native.as_mut() {
            native.account.clear();
        }
        let psk = Zeroizing::new(self.deps.secrets.get(&c.id, SecretField::Psk).unwrap_or_default());
        let built = self.deps.profiles.build(&profile, &psk)?;
        drop(psk);
        let existed = self.deps.manager.installed_native_ids().contains(&c.id);
        self.deps.profiles.install(&c.id, &built.data, &built.file_name, existed)
    }

    /// WinVPN 2c: after the vault is unlocked and after a restore. With every connection of the open vault, the
    /// platform removes the profiles of connections that no longer exist ([`crate::deps::NativeProfiles::reconcile`]:
    /// WinVPN's orphaned `WinVPN-<UUID>` RAS entries, their PSKs and profile files), then
    /// [`Self::install_native_profiles`]. Nothing while the vault is locked or cannot be read: the connections of a
    /// locked vault are unknown, never "none". (The 1.1 read-only mode lists the old store: macOS only, where
    /// `reconcile` does nothing.) Returns the install failures, as [`Self::install_native_profiles`].
    pub fn sync_native_profiles(&self) -> Vec<(Uuid, String)> {
        if self.unlocked().is_err() {
            return Vec::new();
        }
        let Ok(all) = self.deps.store.list() else { return Vec::new() };
        let known: HashSet<Uuid> = all.iter().map(|c| c.id).collect();
        self.deps.profiles.reconcile(&known);
        self.install_all(all)
    }

    /// Where installing a native profile needs no approval (WinVPN), every L2TP / Cisco IPsec connection's profile
    /// is installed (a team catalog's as [`Self::install_team_profile`] makes it, its "reinstall" mark cleared), so
    /// a restored or catalog connection can connect at once; the platform skips what is already current. Nothing
    /// where the user approves each profile (macOS) or while the vault is locked. Returns the failures (connection,
    /// localized reason: WinVPN's "Cisco IPsec is not supported by Windows…"); the rows show their reasons anyway.
    pub fn install_native_profiles(&self) -> Vec<(Uuid, String)> {
        if self.deps.profiles.needs_approval() || self.unlocked().is_err() {
            return Vec::new();
        }
        let Ok(all) = self.deps.store.list() else { return Vec::new() };
        self.install_all(all)
    }

    fn install_all(&self, all: Vec<Connection>) -> Vec<(Uuid, String)> {
        if self.deps.profiles.needs_approval() {
            return Vec::new();
        }
        let mut failures = Vec::new();
        let mut cleared = false;
        for c in all.into_iter().filter(|c| c.kind.is_native()) {
            let result = match self.deps.store.team_managed(&c.id) {
                None => self.install_profile(&c, false),
                Some(team) => self.team_profile_source(&c.id).and_then(|(c, built_from)| {
                    self.install_profile(&c, true)?;
                    if team.profile_outdated {
                        self.lock().pending_installs.remove(&c.id);
                        cleared |= self.deps.store.profile_reinstalled(&c.id, &built_from).is_ok_and(|done| done);
                    }
                    Ok(())
                }),
            };
            if let Err(reason) = result {
                failures.push((c.id, reason));
            }
        }
        if cleared {
            self.changed();
        }
        failures
    }

    /// "I installed it" (the UI asks first and explains the risk): the user says the profile staged by
    /// [`Self::install_team_profile`] is installed, for the case macOS cannot show it (the same service ID and server,
    /// only the group name or "send all traffic" changed). Clears the "reinstall its profile" mark explicitly, but only
    /// for a staged profile and only if it was built from the version applied now (compare-and-clear in the vault).
    pub fn confirm_team_profile_installed(&self, key: &str) -> Result<(), String> {
        self.unlocked()?;
        let Some(ConnectionItem::Managed(listed)) = self.deps.manager.item(key) else {
            return Err("unknown connection".into());
        };
        if self.deps.store.team_managed(&listed.id).is_none() {
            return Err("not a team catalog profile".into());
        }
        let pending = self.lock().pending_installs.remove(&listed.id);
        let Some(pending) = pending else {
            return Err(macvpn_core::l10n::tr("Install the profile first.", &[]));
        };
        match self.deps.store.profile_reinstalled(&listed.id, &pending.built_from) {
            Ok(true) => {
                self.changed();
                Ok(())
            }
            // An apply changed the connection after the profile was staged: that profile is outdated too.
            Ok(false) => Err(crate::deps::catalog_changed_message()),
            Err(e) => {
                self.lock().pending_installs.insert(listed.id, pending);
                Err(e.to_string())
            }
        }
    }

    /// The editors' fields by key (tests, diagnostics).
    pub fn draft_fields(&self) -> BTreeMap<String, EditorFields> {
        self.lock().drafts.iter().map(|(k, d)| (k.clone(), d.fields.clone())).collect()
    }

    // MARK: - Shared credentials (spec 3a)

    /// The app's shared credentials, once it has a vault.
    pub fn set_shared_credentials(&self, credentials: SharedCredentials) {
        *self.credentials.lock().unwrap_or_else(PoisonError::into_inner) = Some(credentials);
        self.changed();
    }

    pub fn shared_credentials(&self) -> Option<SharedCredentials> {
        self.credentials.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    fn require_credentials(&self) -> Result<SharedCredentials, String> {
        self.shared_credentials().ok_or_else(shared_credentials::locked_message)
    }

    /// The Credentials section's list (a locked or missing vault: the reason instead).
    pub fn credentials_view(&self) -> CredentialsView {
        self.shared_credentials().map_or_else(CredentialsView::locked, |c| c.view())
    }

    /// The vault item of a listed connection that has a username or password: a managed connection's id, or an
    /// L2TP / Cisco IPsec system VPN's service ID.
    pub fn credential_item(&self, key: &str) -> Result<Uuid, String> {
        match self.deps.manager.item(key) {
            Some(ConnectionItem::Managed(c)) if c.kind != VPNKind::Wireguard => Ok(c.id),
            Some(ConnectionItem::System(s)) if s.supports_stored_secrets() => s.secret_id().ok_or("no item".into()),
            Some(_) => Err("this connection has no user name or password".into()),
            None => Err("unknown connection".into()),
        }
    }

    /// The display names of the vault items (managed connections and system VPNs).
    fn item_names(&self) -> HashMap<String, String> {
        let mut names: HashMap<String, String> =
            self.deps.manager.connections().into_iter().map(|c| (uuid_string(&c.id), c.name)).collect();
        for s in self.deps.manager.system_services() {
            if let Some(id) = s.secret_id() {
                names.insert(uuid_string(&id), s.name.clone());
            }
        }
        names
    }

    /// The open editors follow a credential change: a rename shows the new name, a link that came or went (the
    /// selector, "Copy into each connection", "Create from connection…") turns the own fields on or off.
    fn credentials_changed(&self) {
        // Read outside the window's lock (the vault and the manager have their own).
        let targets: Vec<(String, Target, Option<String>)> =
            self.lock().drafts.iter().map(|(k, d)| (k.clone(), d.target.clone(), d.credential.clone())).collect();
        for (key, target, before) in targets {
            let Some(state) = Draft::link_state(&self.deps, &target) else { continue };
            let mut s = self.lock();
            let Some(draft) = s.drafts.get_mut(&key) else { continue };
            if state.credential.is_some() != before.is_some() {
                draft.apply_link_state(state);
            } else {
                draft.credential = state.credential;
            }
        }
        self.changed();
    }

    /// The editor's selector: `Some` links the connection to the credential (the UI confirmed that its own
    /// username and password are deleted), `None` returns it to its own (empty) fields.
    pub fn link_credential(&self, key: &str, credential: Option<Uuid>) -> Result<(), String> {
        let item = self.credential_item(key)?;
        let credentials = self.require_credentials()?;
        credentials.link(&uuid_string(&item), credential).map_err(|e| shared_credentials::error_message(&e))?;
        self.credentials_changed();
        Ok(())
    }

    /// "Add" in the Credentials section.
    pub fn add_credential(
        &self,
        name: &str,
        username: &str,
        password: shared_credentials::PasswordInput,
    ) -> Result<(), String> {
        self.require_credentials()?.add(name, username, password)?;
        self.changed();
        Ok(())
    }

    /// "Edit" / "Rename" in the Credentials section.
    pub fn edit_credential(
        &self,
        id: Uuid,
        name: Option<&str>,
        username: Option<&str>,
        password: shared_credentials::PasswordInput,
    ) -> Result<(), String> {
        self.require_credentials()?.edit(id, name, username, password)?;
        self.credentials_changed();
        Ok(())
    }

    /// "Delete": `Ok(Some(names))` when connections still use it and `copy_into` is false (the question "Copy
    /// into each connection" or Cancel names them); with `copy_into` they get their own copies first.
    pub fn delete_credential(&self, id: Uuid, copy_into: bool) -> Result<Option<Vec<String>>, String> {
        let result = self.require_credentials()?.delete(id, copy_into);
        let names = match result {
            Ok(()) => None,
            Err(shared_credentials::DeleteCredentialError::InUse(items)) => {
                Some(shared_credentials::item_names(&items, &self.item_names()))
            }
            Err(shared_credentials::DeleteCredentialError::Vault(e)) => {
                return Err(shared_credentials::error_message(&e));
            }
        };
        self.credentials_changed();
        Ok(names)
    }

    /// "Create from connection…", step 2: the other connections with the same own username and password, as
    /// (vault item, name), sorted by name. The values are compared in the vault and never leave it.
    pub fn credential_matches(&self, key: &str) -> Result<Vec<(String, String)>, String> {
        let item = self.credential_item(key)?;
        let items = self
            .require_credentials()?
            .matching_items(&uuid_string(&item))
            .map_err(|e| shared_credentials::error_message(&e))?;
        let names = shared_credentials::item_names(&items, &self.item_names());
        let mut out: Vec<(String, String)> = items.into_iter().zip(names).collect();
        out.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
        Ok(out)
    }

    /// "Create from connection…", step 3: the credential from the connection's own values, linked to it and to
    /// the ticked matches (vault items from [`Self::credential_matches`]).
    pub fn credential_from_connection(&self, key: &str, name: &str, link: &[String]) -> Result<(), String> {
        let item = self.credential_item(key)?;
        self.require_credentials()?.from_connection(self.deps.secrets.as_ref(), &item, name, link)?;
        self.credentials_changed();
        Ok(())
    }

    /// The import's question about an exported `credentialName` (spec 3a): nothing is linked unless the user
    /// says so; the default answer (and a closed window) keeps the connection's own fields. `Some`: a note for
    /// the import report.
    fn ask_imported_credential(&self, id: &Uuid, imported: &import_export::ImportedCredentialName) -> Option<String> {
        let credentials = match self.require_credentials() {
            Ok(c) => c,
            Err(reason) => return Some(shared_credentials::import_not_checked_note(&imported.name, &reason)),
        };
        let item = uuid_string(id);
        let linked = match credentials.link_imported(Some(&imported.name), imported.kind, &imported.config) {
            Ok(ImportLink::Own) => return None,
            Ok(ImportLink::Ask { credential, name, remote }) => {
                let (title, message) = shared_credentials::import_question(&name, remote.as_deref());
                let yes = self.questions.ask(
                    title,
                    message,
                    l10n::tr("Use Shared Credential", &[]),
                    l10n::tr("Use Own Fields", &[]),
                );
                if !yes {
                    return None;
                }
                credentials.link(&item, Some(credential))
            }
            Ok(ImportLink::Unknown { name, remote }) => {
                let list = match credentials.list() {
                    Ok(list) => list,
                    Err(e) => {
                        return Some(shared_credentials::import_not_checked_note(
                            &name,
                            &shared_credentials::error_message(&e),
                        ));
                    }
                };
                if list.is_empty() {
                    return Some(shared_credentials::unknown_credential_note(&name));
                }
                let (title, message) = shared_credentials::unknown_credential_question(&name, remote.as_deref());
                let options = list.iter().map(|s| s.credential.name.clone()).collect();
                let choice = self.questions.ask_choice(
                    title,
                    message,
                    options,
                    l10n::tr("Use", &[]),
                    l10n::tr("Use Own Fields", &[]),
                );
                let chosen = choice.and_then(|i| list.get(i))?;
                credentials.link(&item, Some(chosen.credential.id))
            }
            Err(e) => {
                return Some(shared_credentials::import_not_checked_note(
                    &imported.name,
                    &shared_credentials::error_message(&e),
                ));
            }
        };
        linked.err().map(|e| shared_credentials::error_message(&e))
    }
}

/// "This VPN was removed from macOS": the refusal of a removed system VPN's editor.
pub fn removed_message() -> String {
    l10n::tr("This VPN was removed from macOS", &[])
}
