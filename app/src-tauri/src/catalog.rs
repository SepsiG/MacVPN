//! Team catalogs (plan Task 15, spec 5–7): the subscriber's and the publisher's commands, the scheduler's start and
//! stop, and the view model's catalog parts. The logic is `macvpn_app_core::catalog::CatalogService` and
//! `macvpn_app_core::catalog_publish::Publisher`; this module adds the native panels, the label checks, the input
//! validation and the pending subscriptions.
//!
//! - **Where:** every command answers only the Connections window (`manage`): the "Team catalogs" and "Publishing"
//!   sections, the add dialog and the publish wizard are parts of it (plan Tasks 16 and 17), so they share the main
//!   capability and need no window or capability of their own.
//! - **No path crosses IPC.** The open panel for a file source or an admin key file and the save panel for a
//!   catalog or an admin key file run here (`dialogs.rs`); the chosen path stays in [`CatalogApp`], and only the
//!   file's name goes back for display.
//! - **Secrets** (a team key, a bearer token, a subscription string, a password) arrive only as command arguments,
//!   move into `Zeroizing` strings at once and are never logged, stored here, echoed or put into the view model.
//!   The only key that goes back is a new team key, once, from `publish_catalog` / `publication_rotate_team_key`.
//!   A subscription string for the team goes to the pasteboard here (`publication_copy_subscription`), never to
//!   the web view.
//! - **Input:** ids are UUID-shaped (and must be listed), sources follow the core's rules (`https://` only; a file
//!   only from the open panel), team keys and fingerprints are parsed, tokens follow RFC 6750 `b64token`, names and
//!   selections are bounded. The vault checks everything again.
//! - **Long calls** (a fetch, Argon2id, a publish) run on the blocking pool.
//! - **The scheduler** starts with the launch step `StartCatalogRefresh` and is stopped and joined at quit
//!   ([`CatalogApp::stop_scheduler`]); the wake hook and an unlock ask it for a round. While the vault is locked it
//!   does nothing, and the view model's catalog parts are empty.

use macvpn_app_core::ViewModel;
use macvpn_app_core::catalog::{CatalogPreview, CatalogService, PendingSubscription, RefreshResult, SubscribeInput};
use macvpn_app_core::catalog::{SubscriptionChange, error_text};
use macvpn_app_core::catalog_publish::{PublishError, PublishInput, Publisher as CatalogPublisher};
use macvpn_app_core::catalog_schedule::RefreshTrigger;
use macvpn_app_core::vault::VaultLifecycle;
use macvpn_app_core::view_model::PublishingView;
use macvpn_core::catalog::admin_file;
use macvpn_core::catalog::format::{self as catalog_format};
use macvpn_core::catalog::ids::CatalogItemKind;
use macvpn_core::catalog::keys::{Fingerprint, TeamKey};
use macvpn_core::catalog::payload::{InvalidCatalog, PersonalField};
use macvpn_core::catalog::publish::PublishPreview;
use macvpn_core::catalog::selection::{InlineSecret, PublishSelection};
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl, parse_file_source};
use macvpn_core::catalog::subscription::{SubscriptionError, parse_subscription};
use macvpn_core::l10n;
use macvpn_core::models::{SecretField, parse_uuid, uuid_string};
use macvpn_core::vault::{AdminKeyRole, valid_bearer_token};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tauri::{AppHandle, State, Window};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::commands::validate_key;
use crate::manage::MANAGE_WINDOW;
use crate::state::AppState;

type Shared<'a> = State<'a, Arc<AppState>>;

/// Previews waiting for "Subscribe" at once (the oldest is dropped first).
pub const MAX_PENDING: usize = 4;
/// Ids per list of a publish selection.
pub const MAX_SELECTION: usize = 4096;
/// A pasted subscription string, a typed team key or URL: bytes (the core's rules are tighter).
pub const MAX_INPUT_BYTES: usize = 8192;
/// How long the quit waits for the scheduler thread (a running fetch has its own timeout; it is not waited for).
pub const SCHEDULER_JOIN_WAIT: Duration = Duration::from_secs(3);

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What an open panel chose, kept until it is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Pick {
    /// A catalog file chosen in an open panel: a subscription's source, a source edit's, or the source of a
    /// subscription string to copy.
    Source,
    /// A catalog file opened from Finder: only the add dialog reads it (never the source edit or "Copy subscription
    /// string"); a file chosen in a panel afterwards replaces it.
    Opened,
    /// An admin key file to import.
    AdminKey,
}

/// The catalog service, the publisher and what the commands keep between calls.
pub struct CatalogApp {
    pub service: Arc<CatalogService>,
    pub publisher: Arc<CatalogPublisher>,
    vault: Arc<VaultLifecycle>,
    /// The sandbox (smoke runs, `MACVPN_SANDBOX_HOME`) refuses HTTPS sources.
    sandbox: bool,
    scheduler: Mutex<Option<JoinHandle<()>>>,
    /// Verified first downloads waiting for "Subscribe", by a random id (the web view gets only the id).
    pending: Mutex<Previews<PendingSubscription>>,
    picked: Mutex<HashMap<Pick, PathBuf>>,
}

impl CatalogApp {
    pub fn new(
        service: Arc<CatalogService>,
        publisher: Arc<CatalogPublisher>,
        vault: Arc<VaultLifecycle>,
        sandbox: bool,
    ) -> Self {
        CatalogApp {
            service,
            publisher,
            vault,
            sandbox,
            scheduler: Mutex::new(None),
            pending: Mutex::new(Previews::default()),
            picked: Mutex::new(HashMap::new()),
        }
    }

    // MARK: scheduler

    /// The launch step `StartCatalogRefresh`: the scheduler thread (once; a launch round first).
    pub fn start_scheduler(&self) {
        let mut scheduler = guard(&self.scheduler);
        if scheduler.is_none() {
            *scheduler = Some(self.service.start_scheduler());
        }
    }

    #[cfg(test)]
    fn scheduler_running(&self) -> bool {
        guard(&self.scheduler).as_ref().is_some_and(|h| !h.is_finished())
    }

    /// Quitting: the scheduler stops (a waiting one at once, a running round before its next subscription) and is
    /// joined. A fetch in progress is not waited for beyond [`SCHEDULER_JOIN_WAIT`] (it has its own timeout and
    /// writes nothing after the quit). `true`: joined (or never started).
    pub fn stop_scheduler(&self) -> bool {
        self.service.stop_scheduler();
        let Some(handle) = guard(&self.scheduler).take() else { return true };
        let deadline = Instant::now() + SCHEDULER_JOIN_WAIT;
        while !handle.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if handle.is_finished() {
            let _ = handle.join();
            true
        } else {
            eprintln!("MacVPN: team catalog: the refresh did not end before the quit");
            false
        }
    }

    // MARK: the vault

    /// The vault was locked: the previews and the chosen files go (the scheduler skips its rounds by itself, and
    /// the view model drops the catalog parts). A preview still running is not kept when it ends (the epoch).
    pub fn vault_locked(&self) {
        guard(&self.pending).locked();
        guard(&self.picked).clear();
    }

    /// The open and save panels are shown only while the vault is open (a locked one answers at once).
    fn require_unlocked(&self) -> Result<(), String> {
        if self.vault.is_unlocked() { Ok(()) } else { Err(macvpn_app_core::vault_stores::locked_message()) }
    }

    /// The view model's catalog parts: the subscriptions, the "Team" badges, the catalog folders, the publishing
    /// side and the "Published in" badges. Everything is empty while the vault is locked (and `apply_vault`
    /// clears it again then).
    pub fn fill(&self, vm: &mut ViewModel) {
        if !self.vault.is_unlocked() {
            return;
        }
        vm.catalogs = self.service.view();
        vm.set_catalog_badges(&self.service.badges());
        vm.team_folders = self.team_folders();
        vm.publishing = PublishingView::build(&self.publisher);
        vm.set_published_badges(&self.publisher.published_badges().unwrap_or_default());
    }

    /// Folder id → catalog id of every folder a catalog owns (its root folder and the publisher's tree).
    fn team_folders(&self) -> BTreeMap<String, String> {
        self.vault
            .with_read(|v| {
                let mut out = BTreeMap::new();
                for record in v.subscriptions()? {
                    let catalog = uuid_string(&record.catalog_id);
                    let local = v.local_catalog(record.catalog_id)?;
                    out.insert(uuid_string(&local.root_folder), catalog.clone());
                    for item in local.items.iter().filter(|i| i.kind != CatalogItemKind::Connection) {
                        out.insert(uuid_string(&item.local_id), catalog.clone());
                    }
                }
                Ok(out)
            })
            .unwrap_or_default()
    }

    // MARK: previews

    /// The lock epoch a preview starts in (read before its fetch).
    fn preview_epoch(&self) -> u64 {
        guard(&self.pending).epoch()
    }

    /// Keeps a preview that started in `epoch` under a new random id. `None`: the vault was locked meanwhile (it
    /// is checked while the list is held, so a lock either comes before and drops it, or clears it after).
    fn keep(&self, pending: PendingSubscription, epoch: u64) -> Option<String> {
        let mut previews = guard(&self.pending);
        previews.keep(pending, epoch, self.vault.is_unlocked(), Instant::now())
    }

    /// Takes a preview out (a confirm uses it once; an expired one is still returned, `confirm` refuses it).
    fn take(&self, id: &str) -> Option<PendingSubscription> {
        guard(&self.pending).take(id)
    }

    fn pick(&self, what: Pick, path: PathBuf) {
        guard(&self.picked).insert(what, path);
    }

    fn picked(&self, what: Pick) -> Option<PathBuf> {
        guard(&self.picked).get(&what).cloned()
    }

    fn forget_pick(&self, what: Pick) {
        guard(&self.picked).remove(&what);
    }

    /// A team catalog file opened from Finder: the add dialog's file source (its own slot, [`Pick::Opened`]; the path
    /// stays here; the file's name goes to the window). Only while the vault is open.
    pub fn open_file_source(&self, path: PathBuf) -> Result<String, String> {
        self.require_unlocked()?;
        parse_file_source(&path.to_string_lossy())
            .map_err(|_| l10n::tr("The file path contains an invalid character.", &[]))?;
        let name = display_name(&path);
        self.pick_opened(path);
        Ok(name)
    }

    fn pick_opened(&self, path: PathBuf) {
        self.pick(Pick::Opened, path);
    }

    /// A catalog file chosen in an open panel (any dialog): the chosen source, in place of a file opened from Finder.
    fn chose_file(&self, path: PathBuf) {
        let mut picked = guard(&self.picked);
        picked.remove(&Pick::Opened);
        picked.insert(Pick::Source, path);
    }

    /// The add dialog subscribed: its file (opened or chosen) is used up.
    fn forget_add_picks(&self) {
        let mut picked = guard(&self.picked);
        picked.remove(&Pick::Opened);
        picked.remove(&Pick::Source);
    }

    /// The source of an edit or a subscription string to copy: a typed `https://` URL, or the file chosen in the
    /// open panel (never a file opened from Finder).
    fn source(&self, url: Option<&str>, chosen_file: bool) -> Result<CatalogSource, String> {
        parse_source(
            url,
            chosen_file.then(|| self.picked(Pick::Source)).flatten().as_deref(),
            chosen_file,
            self.sandbox,
        )
    }

    /// The add dialog's source: a typed `https://` URL, or its file: the one opened from Finder, else the one chosen
    /// in the open panel (choosing a file drops an opened one, so the latest of the two counts).
    fn add_source(&self, url: Option<&str>, chosen_file: bool) -> Result<CatalogSource, String> {
        let file = chosen_file.then(|| self.picked(Pick::Opened).or_else(|| self.picked(Pick::Source))).flatten();
        parse_source(url, file.as_deref(), chosen_file, self.sandbox)
    }
}

/// What can wait in [`Previews`].
trait Expiring {
    fn is_expired(&self, now: Instant) -> bool;
}

impl Expiring for PendingSubscription {
    fn is_expired(&self, now: Instant) -> bool {
        PendingSubscription::is_expired(self, now)
    }
}

/// The previews waiting for "Subscribe", and the lock epoch: every lock clears them and moves it on, and a preview
/// is kept only in the epoch it started in and while the vault is open.
struct Previews<T> {
    list: Vec<(String, T)>,
    epoch: u64,
}

impl<T> Default for Previews<T> {
    fn default() -> Self {
        Previews { list: Vec::new(), epoch: 0 }
    }
}

impl<T: Expiring> Previews<T> {
    fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Keeps `entry` under a new random id (the expired ones and the oldest beyond [`MAX_PENDING`] go). `None`
    /// (dropped): locked, or locked since it started.
    fn keep(&mut self, entry: T, epoch: u64, unlocked: bool, now: Instant) -> Option<String> {
        if !unlocked || epoch != self.epoch {
            return None;
        }
        self.list.retain(|(_, p)| !p.is_expired(now));
        while self.list.len() >= MAX_PENDING {
            self.list.remove(0);
        }
        let id = uuid_string(&Uuid::new_v4());
        self.list.push((id.clone(), entry));
        Some(id)
    }

    fn take(&mut self, id: &str) -> Option<T> {
        let index = self.list.iter().position(|(k, _)| k == id)?;
        Some(self.list.remove(index).1)
    }

    fn locked(&mut self) {
        self.list.clear();
        self.epoch = self.epoch.wrapping_add(1);
    }
}

/// The sandbox's HTTPS source: refused (smoke runs use a file source; HTTPS is covered by the fetcher's own
/// tests and the manual checklist). Debug builds only: release builds have no sandbox.
#[cfg(debug_assertions)]
pub struct SandboxHttps;

#[cfg(debug_assertions)]
impl macvpn_core::catalog::fetch::CatalogFetcher for SandboxHttps {
    fn fetch(
        &self,
        _: &macvpn_core::catalog::fetch::FetchRequest,
    ) -> Result<macvpn_core::catalog::fetch::FetchOutcome, macvpn_core::catalog::format::CatalogError> {
        Err(macvpn_core::catalog::format::CatalogError::Io(l10n::tr(
            "HTTPS sources are not available in the sandbox",
            &[],
        )))
    }
}

/// The HTTPS fetcher: curl (the sandbox's refusal in its place in a debug build's sandbox).
pub fn https_fetcher(sandbox: bool) -> Arc<dyn macvpn_core::catalog::fetch::CatalogFetcher> {
    #[cfg(debug_assertions)]
    if sandbox {
        return Arc::new(SandboxHttps);
    }
    let _ = sandbox;
    Arc::new(macvpn_platform_mac::catalog_http::CurlCatalogFetcher::default())
}

/// The sandbox refuses an HTTPS source (debug builds; release builds have no sandbox).
#[cfg(debug_assertions)]
fn sandbox_refuses_https(sandbox: bool) -> Result<(), String> {
    if sandbox { Err(l10n::tr("HTTPS sources are not available in the sandbox", &[])) } else { Ok(()) }
}

#[cfg(not(debug_assertions))]
fn sandbox_refuses_https(_: bool) -> Result<(), String> {
    Ok(())
}

// MARK: - validation (pure)

/// The windows these commands answer: only the Connections window.
fn allow(label: &str) -> Result<(), String> {
    if label == MANAGE_WINDOW { Ok(()) } else { Err("not available in this window".into()) }
}

/// A connection or catalog id: UUID-shaped.
pub fn parse_id(id: &str) -> Result<Uuid, String> {
    validate_key(id).map_err(|_| "invalid id".to_string())?;
    parse_uuid(id).ok_or_else(|| "invalid id".into())
}

fn too_long(text: &str) -> bool {
    text.len() > MAX_INPUT_BYTES
}

pub fn parse_team_key(text: &str) -> Result<TeamKey, String> {
    if too_long(text) {
        return Err(team_key_message());
    }
    TeamKey::parse(text).map_err(|_| team_key_message())
}

fn team_key_message() -> String {
    l10n::tr("The team key is not valid. Check it for typos.", &[])
}

pub fn parse_fingerprint(text: &str) -> Result<Fingerprint, String> {
    if too_long(text) {
        return Err(fingerprint_message());
    }
    Fingerprint::parse(text).map_err(|_| fingerprint_message())
}

fn fingerprint_message() -> String {
    l10n::tr("The publisher fingerprint is not valid: it has 8 groups of 4 characters.", &[])
}

/// An access token: `None` or empty → none; otherwise an RFC 6750 `b64token`.
pub fn parse_token(token: Option<Zeroizing<String>>) -> Result<Option<Zeroizing<String>>, String> {
    match token {
        None => Ok(None),
        Some(t) if t.is_empty() => Ok(None),
        Some(t) if valid_bearer_token(&t) => Ok(Some(t)),
        Some(_) => Err(l10n::tr("The access token is not valid.", &[])),
    }
}

/// A typed `https://` URL, or the file the open panel chose (`file`; `chosen_file` set). Exactly one of them. The
/// sandbox refuses HTTPS.
pub fn parse_source(
    url: Option<&str>,
    file: Option<&Path>,
    chosen_file: bool,
    sandbox: bool,
) -> Result<CatalogSource, String> {
    match (url.filter(|u| !u.trim().is_empty()), chosen_file) {
        (Some(_), true) | (None, false) => Err(l10n::tr("Enter an https:// address or choose a catalog file.", &[])),
        (Some(url), false) => {
            sandbox_refuses_https(sandbox)?;
            if too_long(url) {
                return Err(url_message());
            }
            HttpsUrl::parse(url.trim()).map(CatalogSource::Https).map_err(|_| url_message())
        }
        (None, true) => {
            let file = file.ok_or_else(|| l10n::tr("Choose the catalog file first.", &[]))?;
            let text = file.to_str().ok_or_else(|| l10n::tr("The file path contains an invalid character.", &[]))?;
            parse_file_source(text)
                .map(CatalogSource::File)
                .map_err(|_| l10n::tr("The file path contains an invalid character.", &[]))
        }
    }
}

fn url_message() -> String {
    l10n::tr("The address is not valid. Use an https:// address without a user name or a # part.", &[])
}

fn subscription_message(e: SubscriptionError) -> String {
    match e {
        SubscriptionError::NewerVersion(_) => l10n::tr("The subscription string was made by a newer MacVPN.", &[]),
        SubscriptionError::TeamKey(_) => team_key_message(),
        SubscriptionError::Fingerprint(_) => fingerprint_message(),
        SubscriptionError::Source(_) => url_message(),
        _ => l10n::tr("This is not a valid MacVPN subscription string.", &[]),
    }
}

pub fn parse_role(role: &str) -> Result<AdminKeyRole, String> {
    AdminKeyRole::parse(role).ok_or_else(|| "invalid role".into())
}

/// A catalog or connection name: bounded here, the vault applies its rules.
pub fn check_name(name: &str) -> Result<(), String> {
    crate::shared_credentials::check_name(name)
}

/// The admin key file password rule (at least 10 characters), before a panel is shown.
pub fn check_key_file_password(password: &str) -> Result<(), String> {
    if password.len() > crate::shared_credentials::MAX_PASSWORD_BYTES {
        return Err("invalid password".into());
    }
    admin_file::check_admin_key_password(password).map_err(|e| PublishError::from(e).to_string())
}

/// A file name for a save panel: the name with `/`, `:` and control characters replaced.
pub fn file_name(name: &str, extension: &str) -> String {
    let stem: String =
        name.trim().chars().map(|c| if c == '/' || c == ':' || c.is_control() { '-' } else { c }).collect();
    let stem = if stem.is_empty() || stem.starts_with('.') { format!("Team catalog{stem}") } else { stem };
    format!("{stem}.{extension}")
}

/// One secret field of a selected connection (`psk` or `keypass`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretChoice {
    pub item: String,
    pub field: String,
}

/// One inline key of a selected config (`InlineSecret::as_str`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InlineChoice {
    pub item: String,
    pub secret: String,
}

/// The publish wizard's selection (steps 1–3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
pub struct SelectionInput {
    pub folders: Vec<String>,
    pub connections: Vec<String>,
    pub secrets: Vec<SecretChoice>,
    pub slots: Vec<String>,
    pub inline_secrets: Vec<InlineChoice>,
}

impl SelectionInput {
    /// UUID-shaped ids, known fields, bounded lists (the builder checks that each exists and may be published).
    pub fn parse(&self) -> Result<PublishSelection, String> {
        let lists = [self.folders.len(), self.connections.len(), self.secrets.len(), self.slots.len()];
        if lists.into_iter().chain([self.inline_secrets.len()]).any(|n| n > MAX_SELECTION) {
            return Err("too many items".into());
        }
        let ids = |list: &[String]| list.iter().map(|id| parse_id(id)).collect::<Result<BTreeSet<Uuid>, String>>();
        let mut secrets = BTreeSet::new();
        for s in &self.secrets {
            let field = SecretField::from_raw_value(&s.field)
                .filter(|f| matches!(f, SecretField::Psk | SecretField::KeyPassword))
                .ok_or("invalid secret field")?;
            secrets.insert((parse_id(&s.item)?, field));
        }
        let mut inline_secrets = BTreeSet::new();
        for s in &self.inline_secrets {
            inline_secrets.insert((parse_id(&s.item)?, InlineSecret::parse(&s.secret).ok_or("invalid inline secret")?));
        }
        Ok(PublishSelection {
            folders: ids(&self.folders)?,
            connections: ids(&self.connections)?,
            secrets,
            slots: ids(&self.slots)?,
            inline_secrets,
        })
    }
}

// MARK: - views (never a key, a token or a password)

/// What `catalog_parse_subscription` shows: the source (a URL without its query, a file by its name) and the
/// fingerprint. The team key is checked but never sent back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedSubscription {
    /// `https` or `file`.
    pub kind: &'static str,
    pub source: String,
    pub fingerprint: String,
}

/// The add dialog's "Check": the preview and the id "Subscribe" confirms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewView {
    pub pending_id: String,
    #[serde(flatten)]
    pub preview: CatalogPreview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyView {
    pub added: usize,
    pub changed: usize,
    pub removed: usize,
    /// Removed connections that are up: deleted once they disconnect.
    pub deferred: usize,
}

/// One "Refresh now".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshView {
    pub id: String,
    /// `notModified`, `applied`, `unchanged`, `refused` or `locked`.
    pub outcome: &'static str,
    pub applied: Option<ApplyView>,
    /// Why it was refused (translated).
    pub error: Option<String>,
}

impl RefreshView {
    fn new(id: Uuid, result: RefreshResult) -> Self {
        let (outcome, applied, error) = match result {
            RefreshResult::NotModified => ("notModified", None, None),
            RefreshResult::Applied(s) => (
                "applied",
                Some(ApplyView { added: s.added, changed: s.changed, removed: s.removed, deferred: s.deferred }),
                None,
            ),
            RefreshResult::Unchanged => ("unchanged", None, None),
            RefreshResult::Refused(e) => ("refused", None, Some(error_text(&e))),
            RefreshResult::Locked => ("locked", None, Some(macvpn_app_core::vault_stores::locked_message())),
        };
        RefreshView { id: uuid_string(&id), outcome, applied, error }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsubscribeView {
    pub removed: usize,
    /// The slot credentials the user filled in, kept as ordinary shared credentials.
    pub kept_credentials: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemField {
    pub item: String,
    pub field: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotChoice {
    pub id: String,
    pub name: String,
    /// Selected connections linked to it.
    pub connections: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishCounts {
    pub folders: usize,
    pub connections: usize,
    pub slots: usize,
    pub secrets: usize,
}

/// The publish wizard's steps 2–4 for a selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishPreviewView {
    pub counts: PublishCounts,
    /// `sstpUser`, `nativeAccount`, `wireguardPrivateKey`, `openvpnInlineKey`.
    pub personal: Vec<ItemField>,
    /// `InlineSecret::as_str` per config: each needs a tick.
    pub inline_secrets: Vec<ItemField>,
    /// `psk` / `keypass` stored for a selected connection.
    pub available_secrets: Vec<ItemField>,
    pub available_slots: Vec<SlotChoice>,
    /// Connections that cannot be published: `inlineCredentials`, `config`, `nativeSettings`, `configTooLarge`,
    /// `connectionName` or `invalid`.
    pub refused: Vec<ItemField>,
    /// The publications whose next version would no longer announce the successor key their last one announced.
    pub successor_dropped_in: Vec<String>,
}

fn personal_name(f: PersonalField) -> &'static str {
    match f {
        PersonalField::SstpUser => "sstpUser",
        PersonalField::NativeAccount => "nativeAccount",
        PersonalField::WireGuardPrivateKey => "wireguardPrivateKey",
        PersonalField::OpenVpnInlineKey => "openvpnInlineKey",
    }
}

fn refusal_name(e: &InvalidCatalog) -> &'static str {
    match e {
        InvalidCatalog::InlineCredentials { .. } => "inlineCredentials",
        InvalidCatalog::Config { .. } => "config",
        InvalidCatalog::NativeSettings { .. } => "nativeSettings",
        InvalidCatalog::ConfigTooLarge => "configTooLarge",
        InvalidCatalog::ConnectionName => "connectionName",
        _ => "invalid",
    }
}

impl From<PublishPreview> for PublishPreviewView {
    fn from(p: PublishPreview) -> Self {
        let field = |item: &Uuid, field: &'static str| ItemField { item: uuid_string(item), field };
        let (folders, connections, slots, secrets) = p.payload_counts;
        PublishPreviewView {
            counts: PublishCounts { folders, connections, slots, secrets },
            personal: p.personal.iter().map(|(id, f)| field(id, personal_name(*f))).collect(),
            inline_secrets: p.inline_secrets.iter().map(|(id, s)| field(id, s.as_str())).collect(),
            available_secrets: p.available_secrets.iter().map(|(id, f)| field(id, f.raw_value())).collect(),
            available_slots: p
                .available_slots
                .iter()
                .map(|(id, name, n)| SlotChoice { id: uuid_string(id), name: name.clone(), connections: *n })
                .collect(),
            refused: p.refused.iter().map(|(id, e)| field(id, refusal_name(e))).collect(),
            successor_dropped_in: p.successor_dropped_in,
        }
    }
}

/// A written catalog. `team_key` only for a new catalog or a rotation: shown once, never kept (wiped once the
/// reply was serialized).
pub struct PublishedView {
    pub catalog_id: String,
    pub version: u64,
    pub fingerprint: String,
    pub file_name: String,
    pub team_key: Option<Zeroizing<String>>,
}

impl Serialize for PublishedView {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("PublishedView", 5)?;
        s.serialize_field("catalogId", &self.catalog_id)?;
        s.serialize_field("version", &self.version)?;
        s.serialize_field("fingerprint", &self.fingerprint)?;
        s.serialize_field("fileName", &self.file_name)?;
        s.serialize_field("teamKey", &self.team_key.as_deref().map(String::as_str))?;
        s.end()
    }
}

impl std::fmt::Debug for PublishedView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublishedView")
            .field("catalog_id", &self.catalog_id)
            .field("version", &self.version)
            .field("has_team_key", &self.team_key.is_some())
            .finish_non_exhaustive()
    }
}

// MARK: - helpers of the commands

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())
}

fn display_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// A subscription the user has (its id from the "Team catalogs" list).
fn subscribed(state: &AppState, id: &str) -> Result<Uuid, String> {
    let id = parse_id(id)?;
    let key = uuid_string(&id);
    if state.catalog.service.view().iter().any(|s| s.id == key) {
        Ok(id)
    } else {
        Err(l10n::tr("This team catalog no longer exists.", &[]))
    }
}

/// A publication the user has.
fn published(state: &AppState, id: &str) -> Result<Uuid, String> {
    let id = parse_id(id)?;
    let key = uuid_string(&id);
    let list = state.catalog.publisher.publications().map_err(|e| PublishError::from(e).to_string())?;
    if list.iter().any(|p| p.id == key) { Ok(id) } else { Err(PublishError::UnknownPublication.to_string()) }
}

/// A listed connection's key.
fn listed(state: &AppState, id: &str) -> Result<Uuid, String> {
    let id = parse_id(id)?;
    if state.manager.item(&uuid_string(&id)).is_some() { Ok(id) } else { Err("unknown connection".into()) }
}

fn vault_error(e: macvpn_core::vault::VaultError) -> String {
    macvpn_app_core::catalog::CatalogServiceError::from(e).to_string()
}

/// After a change of the catalogs: the view model again.
fn changed(state: &AppState) {
    state.publisher.mark();
}

/// The save panel on the Connections window (a smoke run takes its sandbox file instead: debug builds only).
async fn save_path(
    app: &AppHandle,
    state: &AppState,
    name: String,
    message: String,
    extension: &str,
) -> Result<Option<PathBuf>, String> {
    #[cfg(debug_assertions)]
    if let Some(path) = crate::smoke::panel_file(state, extension) {
        return Ok(Some(path));
    }
    let _ = extension;
    crate::dialogs::choose_save_path(app, state, MANAGE_WINDOW, name, Some(message)).await
}

/// The open panel for an admin key file (a smoke run takes its sandbox file instead: debug builds only).
async fn open_admin_key_path(app: &AppHandle, state: &AppState) -> Result<Option<PathBuf>, String> {
    #[cfg(debug_assertions)]
    if let Some(path) = crate::smoke::panel_file(state, admin_file::EXTENSION) {
        return Ok(Some(path));
    }
    Ok(crate::dialogs::choose_files(app, state, MANAGE_WINDOW, false).await?.into_iter().next())
}

// MARK: - subscriber commands

/// The add dialog's paste field: the source and the fingerprint of a `macvpn-sub:` string. The team key is checked
/// but never sent back (the dialog sends the string again with "Check").
#[tauri::command]
pub async fn catalog_parse_subscription(window: Window, text: String) -> Result<ParsedSubscription, String> {
    let text = Zeroizing::new(text);
    allow(window.label())?;
    parse_subscription_view(&text)
}

pub fn parse_subscription_view(text: &str) -> Result<ParsedSubscription, String> {
    if too_long(text) {
        return Err(subscription_message(SubscriptionError::TooLong));
    }
    let parsed = parse_subscription(text).map_err(subscription_message)?;
    Ok(ParsedSubscription {
        kind: match parsed.source {
            CatalogSource::Https(_) => "https",
            CatalogSource::File(_) => "file",
        },
        source: parsed.source.redacted(),
        fingerprint: parsed.fingerprint.to_text(),
    })
}

/// "Choose file…" of the add dialog or the source edit (and of "Copy subscription string"): the open panel. The
/// path stays here; the window gets the file name (`None`: cancelled).
#[tauri::command]
pub async fn catalog_choose_file_source(
    app: AppHandle,
    window: Window,
    state: Shared<'_>,
) -> Result<Option<String>, String> {
    allow(window.label())?;
    state.catalog.require_unlocked()?;
    // The smoke run's catalog file in place of the open panel (debug builds only).
    #[cfg(debug_assertions)]
    if let Some(path) = crate::smoke::panel_file(&state, catalog_format::EXTENSION) {
        state.catalog.chose_file(path.clone());
        return Ok(Some(display_name(&path)));
    }
    let Some(path) = crate::dialogs::choose_files(&app, &state, MANAGE_WINDOW, false).await?.into_iter().next() else {
        return Ok(None);
    };
    parse_file_source(&path.to_string_lossy())
        .map_err(|_| l10n::tr("The file path contains an invalid character.", &[]))?;
    state.catalog.chose_file(path.clone());
    Ok(Some(display_name(&path)))
}

/// Builds the subscribe input from a pasted subscription string, or from the fields (a URL or the chosen file, the
/// team key, the fingerprint). A typed token is added to either.
fn subscribe_input(
    catalog: &CatalogApp,
    subscription: Option<Zeroizing<String>>,
    url: Option<String>,
    chosen_file: bool,
    team_key: Option<Zeroizing<String>>,
    fingerprint: Option<String>,
    token: Option<Zeroizing<String>>,
) -> Result<SubscribeInput, String> {
    let bearer = parse_token(token)?;
    if let Some(text) = subscription.filter(|s| !s.trim().is_empty()) {
        if too_long(&text) {
            return Err(subscription_message(SubscriptionError::TooLong));
        }
        let parsed = parse_subscription(&text).map_err(subscription_message)?;
        if matches!(parsed.source, CatalogSource::Https(_)) {
            sandbox_refuses_https(catalog.sandbox)?;
        }
        return Ok(SubscribeInput::from_subscription(parsed, bearer));
    }
    let source = catalog.add_source(url.as_deref(), chosen_file)?;
    let team_key = parse_team_key(team_key.as_deref().map_or("", String::as_str))?;
    // No trust on first use: the fingerprint is required.
    let fingerprint = parse_fingerprint(fingerprint.as_deref().unwrap_or(""))?;
    Ok(SubscribeInput { source, team_key, fingerprint, bearer, catalog_id: None, min_version: None })
}

/// "Check": fetches and verifies the first download (nothing is stored) and keeps it for "Subscribe".
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn catalog_preview(
    window: Window,
    state: Shared<'_>,
    subscription: Option<String>,
    url: Option<String>,
    chosen_file: bool,
    team_key: Option<String>,
    fingerprint: Option<String>,
    token: Option<String>,
) -> Result<PreviewView, String> {
    // First: every early return below wipes them.
    let (subscription, team_key, token) =
        (subscription.map(Zeroizing::new), team_key.map(Zeroizing::new), token.map(Zeroizing::new));
    allow(window.label())?;
    let input = subscribe_input(&state.catalog, subscription, url, chosen_file, team_key, fingerprint, token)?;
    let shared = state.inner().clone();
    let epoch = state.catalog.preview_epoch();
    blocking(move || {
        let (preview, pending) = shared.catalog.service.preview(input).map_err(|e| e.to_string())?;
        // Locked while it ran: dropped (wiped), never kept for a later unlock.
        let pending_id =
            shared.catalog.keep(pending, epoch).ok_or_else(macvpn_app_core::vault_stores::locked_message)?;
        Ok(PreviewView { pending_id, preview })
    })
    .await?
}

/// "Subscribe": stores the subscription and applies its first catalog.
#[tauri::command]
pub async fn catalog_confirm(window: Window, state: Shared<'_>, pending_id: String) -> Result<ApplyView, String> {
    allow(window.label())?;
    parse_id(&pending_id)?;
    let pending = state
        .catalog
        .take(&pending_id)
        .ok_or_else(|| macvpn_app_core::catalog::CatalogServiceError::Expired.to_string())?;
    let shared = state.inner().clone();
    let summary = blocking(move || shared.catalog.service.confirm(pending).map_err(|e| e.to_string())).await??;
    state.catalog.forget_add_picks();
    changed(&state);
    Ok(ApplyView {
        added: summary.added,
        changed: summary.changed,
        removed: summary.removed,
        deferred: summary.deferred,
    })
}

/// The add dialog was closed without subscribing: its preview goes.
#[tauri::command]
pub async fn catalog_discard(window: Window, state: Shared<'_>, pending_id: String) -> Result<(), String> {
    allow(window.label())?;
    parse_id(&pending_id)?;
    drop(state.catalog.take(&pending_id));
    Ok(())
}

/// "Refresh now" of one subscription (the UI waits for it).
#[tauri::command]
pub async fn catalog_refresh(window: Window, state: Shared<'_>, catalog_id: String) -> Result<RefreshView, String> {
    allow(window.label())?;
    let id = subscribed(&state, &catalog_id)?;
    let shared = state.inner().clone();
    let result = blocking(move || shared.catalog.service.refresh(id, RefreshTrigger::Manual)).await?;
    changed(&state);
    Ok(RefreshView::new(id, result))
}

/// "Refresh all": every subscription, one after another.
#[tauri::command]
pub async fn catalog_refresh_all(window: Window, state: Shared<'_>) -> Result<Vec<RefreshView>, String> {
    allow(window.label())?;
    let shared = state.inner().clone();
    let results = blocking(move || shared.catalog.service.refresh_all(RefreshTrigger::Manual)).await?;
    changed(&state);
    Ok(results.into_iter().map(|(id, r)| RefreshView::new(id, r)).collect())
}

fn update(state: &AppState, id: Uuid, change: SubscriptionChange) -> Result<(), String> {
    state.catalog.service.update_subscription(id, change).map_err(vault_error)?;
    changed(state);
    Ok(())
}

/// "Edit" → source: a URL or the chosen file. On another origin the stored access token is dropped (it is never
/// sent to an address it was not entered for): `true` then, and the dialog asks for a new one.
#[tauri::command]
pub async fn catalog_update_source(
    window: Window,
    state: Shared<'_>,
    catalog_id: String,
    url: Option<String>,
    chosen_file: bool,
) -> Result<bool, String> {
    allow(window.label())?;
    let id = subscribed(&state, &catalog_id)?;
    let source = state.catalog.source(url.as_deref(), chosen_file)?;
    let shared = state.inner().clone();
    blocking(move || {
        let had_token = |s: &AppState| s.catalog.service.view().iter().any(|v| v.id == uuid_string(&id) && v.has_token);
        let before = had_token(&shared);
        update(&shared, id, SubscriptionChange::Source(source))?;
        shared.catalog.forget_pick(Pick::Source);
        Ok(before && !had_token(&shared))
    })
    .await?
}

/// "Edit" → team key (after the publisher rotated it).
#[tauri::command]
pub async fn catalog_update_team_key(
    window: Window,
    state: Shared<'_>,
    catalog_id: String,
    team_key: String,
) -> Result<(), String> {
    let team_key = Zeroizing::new(team_key);
    allow(window.label())?;
    let id = subscribed(&state, &catalog_id)?;
    let key = parse_team_key(&team_key)?;
    drop(team_key);
    let shared = state.inner().clone();
    blocking(move || update(&shared, id, SubscriptionChange::TeamKey(key))).await?
}

/// "Edit" → access token: a new one, or `None` / empty to remove it.
#[tauri::command]
pub async fn catalog_update_bearer(
    window: Window,
    state: Shared<'_>,
    catalog_id: String,
    token: Option<String>,
) -> Result<(), String> {
    let token = token.map(Zeroizing::new);
    allow(window.label())?;
    let id = subscribed(&state, &catalog_id)?;
    let token = parse_token(token)?;
    let shared = state.inner().clone();
    blocking(move || update(&shared, id, SubscriptionChange::Bearer(token))).await?
}

/// "Unsubscribe" (confirmed in the UI): the active catalog connections are disconnected first.
#[tauri::command]
pub async fn catalog_unsubscribe(
    window: Window,
    state: Shared<'_>,
    catalog_id: String,
) -> Result<UnsubscribeView, String> {
    allow(window.label())?;
    let id = subscribed(&state, &catalog_id)?;
    let shared = state.inner().clone();
    let report = blocking(move || shared.catalog.service.unsubscribe(id).map_err(|e| e.to_string())).await??;
    changed(&state);
    Ok(UnsubscribeView { removed: report.removed_connections.len(), kept_credentials: report.kept_credentials })
}

/// "Duplicate as personal connection…": a copy the user owns, named `name`. Returns its id.
#[tauri::command]
pub async fn catalog_duplicate(
    window: Window,
    state: Shared<'_>,
    item_id: String,
    name: String,
) -> Result<String, String> {
    allow(window.label())?;
    let id = listed(&state, &item_id)?;
    check_name(&name)?;
    let shared = state.inner().clone();
    let copy = blocking(move || shared.catalog.service.duplicate(id, &name).map_err(vault_error)).await??;
    changed(&state);
    Ok(uuid_string(&copy))
}

/// "Install profile" of a team catalog's native connection (also the reinstall after "the team catalog changed
/// this connection").
#[tauri::command]
pub async fn catalog_install_profile(window: Window, state: Shared<'_>, item_id: String) -> Result<(), String> {
    allow(window.label())?;
    let id = listed(&state, &item_id)?;
    let shared = state.inner().clone();
    blocking(move || shared.connections.install_team_profile(&uuid_string(&id))).await?
}

/// "I installed it" (confirmed in the UI): the profile staged by "Install profile" is installed although macOS
/// cannot show it; the "reinstall its profile" mark is cleared (only for a staged profile of the current version).
#[tauri::command]
pub async fn catalog_profile_installed(window: Window, state: Shared<'_>, item_id: String) -> Result<(), String> {
    allow(window.label())?;
    let id = listed(&state, &item_id)?;
    let shared = state.inner().clone();
    blocking(move || shared.connections.confirm_team_profile_installed(&uuid_string(&id))).await?
}

// MARK: - publisher commands

/// "Generate admin key" / "Generate backup admin key": returns the fingerprint.
#[tauri::command]
pub async fn admin_key_generate(window: Window, state: Shared<'_>, role: String) -> Result<String, String> {
    allow(window.label())?;
    let role = parse_role(&role)?;
    let shared = state.inner().clone();
    let fingerprint = blocking(move || {
        shared.catalog.publisher.generate_admin_key(role).map_err(|e| PublishError::from(e).to_string())
    })
    .await??;
    changed(&state);
    Ok(fingerprint.to_text())
}

/// "Export backup key…": the password rule first, then the save panel, then the sealed file (0600). With
/// `remove_after` the key leaves this Mac once the file is written. The file's name (`None`: cancelled).
#[tauri::command]
pub async fn admin_key_export(
    app: AppHandle,
    window: Window,
    state: Shared<'_>,
    password: String,
    remove_after: bool,
) -> Result<Option<String>, String> {
    let password = Zeroizing::new(password);
    allow(window.label())?;
    state.catalog.require_unlocked()?;
    check_key_file_password(&password)?;
    let name = file_name(&l10n::tr("MacVPN backup admin key", &[]), admin_file::EXTENSION);
    let message = l10n::tr("Anyone with this file and its password can sign your team catalogs.", &[]);
    let Some(path) = save_path(&app, &state, name, message, admin_file::EXTENSION).await? else {
        return Ok(None);
    };
    let shared = state.inner().clone();
    let written = path.clone();
    blocking(move || {
        shared.catalog.publisher.export_backup_key(&written, password, remove_after).map_err(|e| e.to_string())
    })
    .await??;
    changed(&state);
    Ok(Some(display_name(&path)))
}

/// "Import admin key…", step 1: the open panel. The file's name (`None`: cancelled).
#[tauri::command]
pub async fn admin_key_choose_file(
    app: AppHandle,
    window: Window,
    state: Shared<'_>,
) -> Result<Option<String>, String> {
    allow(window.label())?;
    state.catalog.require_unlocked()?;
    let Some(path) = open_admin_key_path(&app, &state).await? else {
        return Ok(None);
    };
    state.catalog.pick(Pick::AdminKey, path.clone());
    Ok(Some(display_name(&path)))
}

/// "Import admin key…", step 2: opens the chosen file with its password. Returns the fingerprint.
#[tauri::command]
pub async fn admin_key_import(window: Window, state: Shared<'_>, password: String) -> Result<String, String> {
    let password = Zeroizing::new(password);
    allow(window.label())?;
    if password.len() > crate::shared_credentials::MAX_PASSWORD_BYTES {
        return Err("invalid password".into());
    }
    let path = state.catalog.picked(Pick::AdminKey).ok_or_else(|| l10n::tr("Choose the admin key file first.", &[]))?;
    let shared = state.inner().clone();
    let fingerprint =
        blocking(move || shared.catalog.publisher.import_admin_key(&path, password).map_err(|e| e.to_string()))
            .await??;
    state.catalog.forget_pick(Pick::AdminKey);
    changed(&state);
    Ok(fingerprint.to_text())
}

/// "Switch to the backup key": returns the new primary's fingerprint.
#[tauri::command]
pub async fn admin_key_promote(window: Window, state: Shared<'_>) -> Result<String, String> {
    allow(window.label())?;
    let shared = state.inner().clone();
    let fingerprint =
        blocking(move || shared.catalog.publisher.promote_backup_key().map_err(|e| PublishError::from(e).to_string()))
            .await??;
    changed(&state);
    Ok(fingerprint.to_text())
}

/// The publish wizard's steps 2–4 for the selection.
#[tauri::command]
pub async fn publish_preview(
    window: Window,
    state: Shared<'_>,
    selection: SelectionInput,
) -> Result<PublishPreviewView, String> {
    allow(window.label())?;
    let selection = selection.parse()?;
    let shared = state.inner().clone();
    let preview = blocking(move || shared.catalog.publisher.preview(&selection).map_err(|e| e.to_string())).await??;
    Ok(preview.into())
}

/// Step 5: the save panel (`<name>.macvpncatalog`), then the signed and encrypted file. A new catalog
/// (`catalog_id` `None`) returns its team key once. `None`: the panel was cancelled.
#[tauri::command]
pub async fn publish_catalog(
    app: AppHandle,
    window: Window,
    state: Shared<'_>,
    catalog_id: Option<String>,
    name: String,
    selection: SelectionInput,
) -> Result<Option<PublishedView>, String> {
    allow(window.label())?;
    state.catalog.require_unlocked()?;
    let catalog_id = catalog_id.map(|id| published(&state, &id)).transpose()?;
    check_name(&name)?;
    let selection = selection.parse()?;
    let message = l10n::tr("MacVPN does not upload anything: put the file on your web server or share.", &[]);
    let default = file_name(&name, catalog_format::EXTENSION);
    let Some(path) = save_path(&app, &state, default, message, catalog_format::EXTENSION).await? else {
        return Ok(None);
    };
    let shared = state.inner().clone();
    let input = PublishInput { catalog_id, name, selection, path: path.clone() };
    let result = blocking(move || shared.catalog.publisher.publish(input).map_err(|e| e.to_string())).await??;
    changed(&state);
    Ok(Some(PublishedView {
        catalog_id: uuid_string(&result.catalog_id),
        version: result.version,
        fingerprint: result.fingerprint.to_text(),
        file_name: display_name(&path),
        team_key: result.new_team_key,
    }))
}

/// "Rotate team key" (confirmed in the UI with the revoke explanation): the save panel, then a new team key
/// published at once as the next version. The new key is returned once. `None`: the panel was cancelled.
#[tauri::command]
pub async fn publication_rotate_team_key(
    app: AppHandle,
    window: Window,
    state: Shared<'_>,
    catalog_id: String,
) -> Result<Option<PublishedView>, String> {
    allow(window.label())?;
    state.catalog.require_unlocked()?;
    let id = published(&state, &catalog_id)?;
    let list = state.catalog.publisher.publications().map_err(|e| PublishError::from(e).to_string())?;
    let publication = list.into_iter().find(|p| p.id == uuid_string(&id)).ok_or("unknown publication")?;
    let default = publication.file_name.unwrap_or_else(|| file_name(&publication.name, catalog_format::EXTENSION));
    let message = l10n::tr("MacVPN does not upload anything: put the file on your web server or share.", &[]);
    let Some(path) = save_path(&app, &state, default, message, catalog_format::EXTENSION).await? else {
        return Ok(None);
    };
    let shared = state.inner().clone();
    let written = path.clone();
    let result =
        blocking(move || shared.catalog.publisher.rotate_team_key(id, &written).map_err(|e| e.to_string())).await??;
    changed(&state);
    Ok(Some(PublishedView {
        catalog_id: uuid_string(&result.catalog_id),
        version: result.version,
        fingerprint: result.fingerprint.to_text(),
        file_name: display_name(&path),
        team_key: result.new_team_key,
    }))
}

/// "Copy subscription string": the master password is checked, then the string (with the source the team will
/// use: a URL or the chosen file) goes to the pasteboard. Nothing is returned: the string is never shown.
#[tauri::command]
pub async fn publication_copy_subscription(
    window: Window,
    state: Shared<'_>,
    catalog_id: String,
    master_password: String,
    url: Option<String>,
    chosen_file: bool,
) -> Result<(), String> {
    let master_password = Zeroizing::new(master_password);
    allow(window.label())?;
    if master_password.len() > crate::shared_credentials::MAX_PASSWORD_BYTES {
        return Err("invalid password".into());
    }
    let id = published(&state, &catalog_id)?;
    // The team may fetch over HTTPS even when this Mac runs in the sandbox: only a subscription is refused there.
    let source = parse_source(
        url.as_deref(),
        chosen_file.then(|| state.catalog.picked(Pick::Source)).flatten().as_deref(),
        chosen_file,
        false,
    )?;
    let shared = state.inner().clone();
    blocking(move || {
        let text =
            shared.catalog.publisher.subscription_string(id, master_password, source).map_err(|e| e.to_string())?;
        crate::clipboard::copy_secret(&text)?;
        drop(text);
        shared.catalog.forget_pick(Pick::Source);
        Ok(())
    })
    .await?
}

/// "Forget" a publication (the published file stays where it is).
#[tauri::command]
pub async fn publication_forget(window: Window, state: Shared<'_>, catalog_id: String) -> Result<(), String> {
    allow(window.label())?;
    let id = published(&state, &catalog_id)?;
    let shared = state.inner().clone();
    blocking(move || shared.catalog.publisher.forget(id).map_err(|e| PublishError::from(e).to_string())).await??;
    changed(&state);
    Ok(())
}

/// The team key reveal's "Copy": the key (as the reveal shows it, checked) goes to the pasteboard concealed, and
/// leaves it a minute later, at a vault lock or at quit if it is still there.
#[tauri::command]
pub async fn catalog_copy_team_key(window: Window, state: Shared<'_>, team_key: String) -> Result<(), String> {
    let team_key = Zeroizing::new(team_key);
    allow(window.label())?;
    state.catalog.require_unlocked()?;
    let key = parse_team_key(&team_key)?;
    drop(team_key);
    crate::clipboard::copy_secret(&key.to_text())
}

// MARK: - wiring

/// The catalog service's hooks (once, at launch): the notifications, the log, the control API's allowlist pruning
/// (through the running server, else the stored registry) and the manager listener of the pending removals.
pub fn connect_hooks(state: &Arc<AppState>) {
    let service = &state.catalog.service;
    let notifying = Arc::downgrade(state);
    service.set_notifier(move |content| {
        if let Some(state) = notifying.upgrade() {
            crate::notifications::catalog(&state, &content);
        }
    });
    service.set_logger(|line| eprintln!("MacVPN: {line}"));
    state.catalog.publisher.set_logger(|line| eprintln!("MacVPN: {line}"));
    let pruning = Arc::downgrade(state);
    service.set_forget_keys(move |keys| match pruning.upgrade() {
        Some(state) => state.control.forget_keys(keys),
        None => Err("MacVPN is quitting".into()),
    });
    service.attach();
}

#[cfg(test)]
mod tests {
    use super::*;
    use macvpn_app_core::catalog::{CatalogDeps, SlotView, SubscriptionView};
    use macvpn_app_core::catalog_publish::PublisherDeps;
    use macvpn_app_core::deps::{
        ConnectionRepository, NativeController, RootClient, SecretReader, SystemClock, SystemService,
    };
    use macvpn_core::catalog::fetch::{CatalogFetcher, FetchOutcome, FetchRequest};
    use macvpn_core::catalog::format::CatalogError;
    use macvpn_core::catalog::keys::TEAM_KEY_PREFIX;
    use macvpn_core::catalog::subscription::{SubscriptionString, format_subscription};
    use macvpn_core::mfa::AuthResponseKind;
    use macvpn_core::models::{Connection, Secrets, VPNKind};
    use macvpn_core::native::NativeKind;
    use macvpn_core::status::RootStatus;
    use macvpn_core::vault::{FixedEntropy, KdfParams, MemoryKeyStore};
    use std::io;

    const A: &str = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
    const FINGERPRINT: &str = "0123-4567-89AB-CDEF-0123-4567-89AB-CDEF";

    fn team_key() -> TeamKey {
        TeamKey::generate(&FixedEntropy::new(5)).unwrap()
    }

    fn subscription(source: CatalogSource) -> Zeroizing<String> {
        format_subscription(&SubscriptionString {
            source,
            team_key: team_key(),
            fingerprint: Fingerprint::parse(FINGERPRINT).unwrap(),
            catalog_id: None,
            min_version: None,
        })
    }

    fn https(url: &str) -> CatalogSource {
        CatalogSource::Https(HttpsUrl::parse(url).unwrap())
    }

    // MARK: label and ids

    #[test]
    fn only_the_connections_window_uses_them() {
        assert!(allow("manage").is_ok());
        for label in ["menu", "setup", "update", "backup", "restore", "vault-create", "cred-1", "pair-1", "manage2", ""]
        {
            assert!(allow(label).is_err(), "{label}");
        }
    }

    /// Every command of this module checks the calling window before it does anything else with its input (the
    /// secrets are only moved into wiped buffers first), `catalog_profile_installed` included.
    #[test]
    fn every_command_checks_the_window() {
        let source = include_str!("catalog.rs");
        let source = &source[..source.find("#[cfg(test)]\nmod tests").unwrap()];
        let commands: Vec<&str> = source.split("#[tauri::command]").skip(1).collect();
        assert!(commands.len() >= 24, "{}", commands.len());
        assert!(commands.iter().any(|c| c.contains("fn catalog_profile_installed(")));
        for command in commands {
            let body = &command[..command.find("\n}\n").unwrap()];
            let name = body.split("fn ").nth(1).and_then(|s| s.split('(').next()).unwrap_or("?");
            let check = body.find("allow(window.label())?").unwrap_or_else(|| panic!("{name}: no window check"));
            let start = body.find(" {\n").unwrap();
            assert!(!body[start..check].contains("state.") && !body[start..check].contains("parse_"), "{name}");
        }
    }

    /// A command that shows an open or a save panel (or takes the smoke run's file in its place) answers "locked"
    /// before it, while the vault is not open.
    #[test]
    fn no_panel_opens_while_the_vault_is_locked() {
        let source = include_str!("catalog.rs");
        let source = &source[..source.find("#[cfg(test)]\nmod tests").unwrap()];
        let panels = ["save_path(", "choose_files(", "open_admin_key_path(", "panel_file("];
        let mut checked = Vec::new();
        for command in source.split("#[tauri::command]").skip(1) {
            let body = &command[..command.find("\n}\n").unwrap()];
            let name = body.split("fn ").nth(1).and_then(|s| s.split('(').next()).unwrap_or("?");
            let start = body.find(" {\n").unwrap();
            let Some(panel) = panels.iter().filter_map(|p| body[start..].find(p)).min() else { continue };
            let check = body[start..].find("state.catalog.require_unlocked()?").unwrap_or_else(|| panic!("{name}"));
            assert!(check < panel, "{name}: the lock check comes after a panel");
            checked.push(name);
        }
        for name in ["catalog_choose_file_source", "admin_key_choose_file", "admin_key_export", "publish_catalog"] {
            assert!(checked.contains(&name), "{name}: {checked:?}");
        }
    }

    #[test]
    fn a_locked_vault_answers_locked() {
        let (app, _) = app();
        assert_eq!(app.require_unlocked().unwrap_err(), macvpn_app_core::vault_stores::locked_message());
    }

    #[test]
    fn ids_are_uuid_shaped() {
        assert!(parse_id(A).is_ok());
        for bad in ["", "Acme VPN", "../38B51E6D", &format!("{A}x"), &format!(" {A}")] {
            assert!(parse_id(bad).is_err(), "{bad}");
        }
    }

    // MARK: subscriber input

    #[test]
    fn team_keys_fingerprints_and_tokens_are_checked() {
        let text = team_key().to_text();
        assert!(parse_team_key(&text).is_ok());
        assert!(parse_team_key(&text.to_lowercase()).is_ok(), "case-insensitive like the recovery key");
        for bad in ["", "TEAM-", "TEAM-0000", &format!("{}X", text.as_str()), &"A".repeat(MAX_INPUT_BYTES + 1)] {
            assert!(parse_team_key(bad).is_err(), "{bad}");
        }
        // A typo in a key group is told apart by the check group.
        let typo: String = text.chars().enumerate().map(|(i, c)| if i == 6 && c != 'Z' { 'Z' } else { c }).collect();
        if typo != *text {
            assert!(parse_team_key(&typo).is_err());
        }
        assert!(parse_fingerprint(FINGERPRINT).is_ok());
        for bad in ["", "0123-4567", "XXXX-4567-89AB-CDEF-0123-4567-89AB-CDEF"] {
            assert!(parse_fingerprint(bad).is_err(), "{bad}");
        }
        let token = |t: &str| parse_token(Some(Zeroizing::new(t.to_string())));
        assert_eq!(token("abc.DEF-123_~+/==").unwrap().as_deref().map(String::as_str), Some("abc.DEF-123_~+/=="));
        assert_eq!(token("").unwrap(), None, "empty: no token");
        assert_eq!(parse_token(None).unwrap(), None);
        for bad in ["has space", "new\nline", "quote\"", "=", &"t".repeat(macvpn_core::vault::MAX_BEARER_BYTES + 1)] {
            assert!(token(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn sources_are_https_or_the_chosen_file() {
        let file = Path::new("/Volumes/Share/team/acme.macvpncatalog");
        assert_eq!(
            parse_source(Some("https://vpn.example.com/acme.macvpncatalog"), None, false, false).unwrap(),
            https("https://vpn.example.com/acme.macvpncatalog")
        );
        assert_eq!(parse_source(None, Some(file), true, false).unwrap(), CatalogSource::File(file.to_path_buf()));
        for (url, chosen) in [
            (Some("http://vpn.example.com/acme.macvpncatalog"), false),
            (Some("https://user:pw@vpn.example.com/acme"), false),
            (Some("https://vpn.example.com/acme#x"), false),
            (Some("ftp://vpn.example.com/acme"), false),
            (Some("/Volumes/Share/acme.macvpncatalog"), false),
            (None, false),
            (Some("   "), false),
            (Some("https://vpn.example.com/acme"), true),
        ] {
            assert!(parse_source(url, Some(file), chosen, false).is_err(), "{url:?} {chosen}");
        }
        // The file must have been chosen in the panel; a relative path is refused.
        assert!(parse_source(None, None, true, false).is_err());
        assert!(parse_source(None, Some(Path::new("relative/acme.macvpncatalog")), true, false).is_err());
        // The sandbox refuses HTTPS (with the text the smoke run expects) but not a file. Release builds have no
        // sandbox, so there the flag changes nothing.
        #[cfg(debug_assertions)]
        {
            let refused = parse_source(Some("https://vpn.example.com/acme"), None, false, true).unwrap_err();
            assert_eq!(refused, "HTTPS sources are not available in the sandbox");
        }
        #[cfg(not(debug_assertions))]
        assert!(parse_source(Some("https://vpn.example.com/acme"), None, false, true).is_ok());
        assert!(parse_source(None, Some(file), true, true).is_ok());
    }

    /// The sandbox's HTTPS refusal is debug-only code: release builds have no sandbox and do not ship it.
    #[test]
    fn the_sandbox_code_is_debug_only() {
        let source = include_str!("catalog.rs");
        let source = &source[..source.find("#[cfg(test)]\nmod tests").unwrap()];
        let lines: Vec<&str> = source.lines().collect();
        for item in ["pub struct SandboxHttps;", "impl macvpn_core::catalog::fetch::CatalogFetcher for SandboxHttps {"]
        {
            let at = lines.iter().position(|l| *l == item).unwrap_or_else(|| panic!("{item}"));
            assert_eq!(lines[at - 1], "#[cfg(debug_assertions)]", "{item}");
        }
        let refusal = "\"HTTPS sources are not available in the sandbox\"";
        for (at, line) in lines.iter().enumerate().filter(|(_, l)| l.contains(refusal) || l.contains("SandboxHttps")) {
            // Inside a debug-only statement, or a top-level item with the attribute right above it.
            let mut up = lines[..at].iter().rev();
            let debug_only = loop {
                let Some(l) = up.next() else { break false };
                if l.trim_start() == "#[cfg(debug_assertions)]" {
                    break true;
                }
                if !l.starts_with([' ', '}', '/', '#']) && !l.is_empty() {
                    break up.next().copied() == Some("#[cfg(debug_assertions)]");
                }
            };
            assert!(debug_only, "line {}: {line}", at + 1);
        }
        assert!(!include_str!("main.rs").contains("SandboxHttps"), "main.rs takes catalog::https_fetcher");
    }

    #[test]
    fn a_parsed_subscription_never_echoes_the_team_key() {
        let text = subscription(https("https://vpn.example.com/acme.macvpncatalog?token=secret-query"));
        let parsed = parse_subscription_view(&text).unwrap();
        assert_eq!(parsed.kind, "https");
        assert_eq!(parsed.fingerprint, FINGERPRINT);
        let json = serde_json::to_string(&parsed).unwrap();
        let key = team_key().to_text();
        assert!(!json.contains(key.as_str()), "{json}");
        assert!(!json.contains(&key[TEAM_KEY_PREFIX.len()..TEAM_KEY_PREFIX.len() + 9]), "not even a group: {json}");
        assert!(!json.contains("secret-query"), "the query is redacted: {json}");
        assert!(!json.contains(text.as_str()), "{json}");
        // A file source by its name only.
        let parsed = parse_subscription_view(&subscription(CatalogSource::File(
            "/Volumes/Share/team/acme.macvpncatalog".into(),
        )))
        .unwrap();
        assert_eq!((parsed.kind, parsed.source.as_str()), ("file", "acme.macvpncatalog"));
        for bad in ["", "macvpn-sub:", "macvpn-sub:!!!", "https://vpn.example.com", &"x".repeat(MAX_INPUT_BYTES + 1)] {
            assert!(parse_subscription_view(bad).is_err(), "{bad}");
        }
    }

    // MARK: publisher input

    #[test]
    fn roles_names_and_key_file_passwords_are_checked() {
        assert_eq!(parse_role("primary").unwrap(), AdminKeyRole::Primary);
        assert_eq!(parse_role("backup").unwrap(), AdminKeyRole::Backup);
        for bad in ["", "Primary", "successor"] {
            assert!(parse_role(bad).is_err(), "{bad}");
        }
        assert!(check_name("Acme VPN").is_ok());
        assert!(check_name("").is_err());
        assert!(check_name(&"x".repeat(crate::shared_credentials::MAX_NAME_BYTES + 1)).is_err());
        assert!(check_key_file_password("long enough password").is_ok());
        assert!(check_key_file_password("short").is_err());
        assert!(check_key_file_password(&"p".repeat(crate::shared_credentials::MAX_PASSWORD_BYTES + 1)).is_err());
    }

    #[test]
    fn save_panel_names_are_plain_file_names() {
        assert_eq!(file_name("Acme VPN", "macvpncatalog"), "Acme VPN.macvpncatalog");
        assert_eq!(file_name("a/b:c\n", "macvpncatalog"), "a-b-c.macvpncatalog");
        assert_eq!(file_name("", "macvpnadminkey"), "Team catalog.macvpnadminkey");
        assert_eq!(file_name("..", "macvpncatalog"), "Team catalog...macvpncatalog");
    }

    #[test]
    fn selections_are_uuid_shaped_known_and_bounded() {
        let input: SelectionInput = serde_json::from_value(serde_json::json!({
            "folders": [A],
            "connections": [A],
            "secrets": [{ "item": A, "field": "psk" }, { "item": A, "field": "keypass" }],
            "slots": [A],
            "inlineSecrets": [{ "item": A, "secret": "tlsCrypt" }]
        }))
        .unwrap();
        let sel = input.parse().unwrap();
        let id = parse_id(A).unwrap();
        assert_eq!(sel.secrets, BTreeSet::from([(id, SecretField::Psk), (id, SecretField::KeyPassword)]));
        assert_eq!(sel.inline_secrets, BTreeSet::from([(id, InlineSecret::TlsCrypt)]));
        // Missing lists are empty; unknown keys are refused.
        assert_eq!(serde_json::from_value::<SelectionInput>(serde_json::json!({})).unwrap(), SelectionInput::default());
        assert!(serde_json::from_value::<SelectionInput>(serde_json::json!({ "everything": true })).is_err());
        let bad = |input: SelectionInput| input.parse().is_err();
        assert!(bad(SelectionInput { connections: vec!["Office".into()], ..Default::default() }));
        // Only PSKs and key passwords can be shared: never a user name or a password.
        for field in ["username", "password", "otp", ""] {
            let secrets = vec![SecretChoice { item: A.into(), field: field.into() }];
            assert!(bad(SelectionInput { secrets, ..Default::default() }), "{field}");
        }
        let inline_secrets = vec![InlineChoice { item: A.into(), secret: "authUserPass".into() }];
        assert!(bad(SelectionInput { inline_secrets, ..Default::default() }));
        assert!(bad(SelectionInput { folders: vec![A.into(); MAX_SELECTION + 1], ..Default::default() }));
    }

    #[test]
    fn a_published_view_shows_the_team_key_only_in_its_field() {
        let view = PublishedView {
            catalog_id: A.into(),
            version: 1,
            fingerprint: FINGERPRINT.into(),
            file_name: "Acme VPN.macvpncatalog".into(),
            team_key: Some(Zeroizing::new(team_key().to_text().to_string())),
        };
        assert!(!format!("{view:?}").contains(TEAM_KEY_PREFIX), "redacted Debug");
        let json = serde_json::to_value(&view).unwrap();
        assert_eq!(json["teamKey"].as_str().unwrap(), team_key().to_text().as_str());
        assert_eq!(json["catalogId"], A);
        assert_eq!(json["version"], 1);
        assert_eq!(json["fingerprint"], FINGERPRINT);
        assert_eq!(json["fileName"], "Acme VPN.macvpncatalog");
        // An update: `teamKey` is null.
        let view = PublishedView { team_key: None, ..view };
        assert!(serde_json::to_value(&view).unwrap()["teamKey"].is_null());
    }

    // MARK: the view model and the scheduler, over a real service on a vault that is not open

    struct Repo;
    impl ConnectionRepository for Repo {
        fn list(&self) -> io::Result<Vec<Connection>> {
            Ok(Vec::new())
        }
        fn save(&self, _: &Connection, _: Option<&str>) -> io::Result<()> {
            Ok(())
        }
        fn load_config(&self, _: &Uuid) -> io::Result<String> {
            Ok(String::new())
        }
        fn delete(&self, _: &Uuid) -> io::Result<()> {
            Ok(())
        }
    }
    struct NoSecrets;
    impl SecretReader for NoSecrets {
        fn get(&self, _: &Uuid, _: SecretField) -> Option<String> {
            None
        }
    }
    struct Root;
    impl RootClient for Root {
        fn status(&self) -> Result<Vec<RootStatus>, String> {
            Ok(vec![])
        }
        fn up(&self, _: VPNKind, _: &Uuid, _: &[u8], _: &Secrets, _: bool, _: &[String]) -> Result<(), String> {
            Ok(())
        }
        fn down(&self, _: VPNKind, _: &Uuid) -> Result<(), String> {
            Ok(())
        }
        fn respond(&self, _: &Uuid, _: AuthResponseKind, _: &str) -> Result<(), String> {
            Ok(())
        }
    }
    struct Native;
    impl NativeController for Native {
        fn list(&self) -> Result<Vec<SystemService>, String> {
            Ok(vec![])
        }
        fn remote_address(&self, _: &str) -> Option<String> {
            None
        }
        fn start(&self, _: &str, _: Option<NativeKind>, _: &Secrets) -> Result<(), String> {
            Ok(())
        }
        fn stop(&self, _: &str) -> Result<(), String> {
            Ok(())
        }
    }

    /// Counts the fetches (none may run while the vault is not open).
    #[derive(Default)]
    struct Fetcher(std::sync::atomic::AtomicUsize);
    impl CatalogFetcher for Fetcher {
        fn fetch(&self, _: &FetchRequest) -> Result<FetchOutcome, CatalogError> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(CatalogError::Unavailable("test".into()))
        }
    }

    fn app() -> (CatalogApp, Arc<Fetcher>) {
        let dir = std::env::temp_dir().join(format!("macvpn-catalog-{}", Uuid::new_v4()));
        let vault = Arc::new(VaultLifecycle::new(
            dir,
            Arc::new(MemoryKeyStore::new()),
            Arc::new(FixedEntropy::new(3)),
            KdfParams::DEFAULT,
        ));
        let manager = macvpn_app_core::ConnectionManager::new(macvpn_app_core::Dependencies::new(
            Arc::new(Repo),
            Arc::new(NoSecrets),
            Arc::new(Root),
            Arc::new(Native),
        ));
        let fetcher = Arc::new(Fetcher::default());
        let service = CatalogService::new(CatalogDeps {
            vault: vault.clone(),
            https: fetcher.clone(),
            file: fetcher.clone(),
            manager,
            clock: Arc::new(SystemClock),
        });
        let publisher = Arc::new(CatalogPublisher::new(PublisherDeps {
            vault: vault.clone(),
            entropy: Arc::new(FixedEntropy::new(4)),
            kdf: KdfParams::DEFAULT,
            clock: Arc::new(SystemClock),
        }));
        (CatalogApp::new(service, publisher, vault, true), fetcher)
    }

    /// Quit: the scheduler started by the launch step stops and is joined at once; a second stop (or one without
    /// a start) is a no-op, and a locked vault never fetched.
    #[test]
    fn the_scheduler_starts_once_and_is_stopped_and_joined_at_quit() {
        let (app, fetcher) = app();
        assert!(app.stop_scheduler(), "never started: nothing to join");
        let (app, _) = self::app();
        app.start_scheduler();
        app.start_scheduler();
        assert!(app.scheduler_running());
        app.service.wake();
        app.service.unlocked();
        let started = Instant::now();
        assert!(app.stop_scheduler(), "joined");
        assert!(started.elapsed() < SCHEDULER_JOIN_WAIT);
        assert!(!app.scheduler_running());
        assert!(app.stop_scheduler());
        assert_eq!(fetcher.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// While the vault is not open the view model's catalog parts stay empty, and a locked `apply_vault` clears
    /// what a stale view put there.
    #[test]
    fn the_view_model_has_no_catalog_data_while_locked() {
        let (app, _) = app();
        let snapshot = macvpn_app_core::ManagerSnapshot::default();
        let mut vm = ViewModel::build(&snapshot, "en", |_| true, Vec::new(), true);
        vm.catalogs.push(SubscriptionView {
            id: A.into(),
            name: "Acme VPN".into(),
            source: "https://vpn.example.com/acme.macvpncatalog".into(),
            fingerprint: FINGERPRINT.into(),
            version: Some(3),
            status: "ok",
            last_refresh: None,
            last_success: None,
            error: None,
            has_token: true,
            slots: vec![SlotView { name: "Office AD".into(), filled: true, credential_name: Some("Office AD".into()) }],
        });
        vm.team_folders.insert(A.into(), A.into());
        app.fill(&mut vm);
        assert_eq!(vm.catalogs.len(), 1, "fill leaves it to apply_vault while locked");
        let locked = macvpn_app_core::view_model::VaultView { state: "locked", ..Default::default() };
        vm.apply_vault(locked);
        assert!(vm.catalogs.is_empty() && vm.team_folders.is_empty());
        assert_eq!(vm.publishing, PublishingView::default());
        let json = serde_json::to_string(&vm).unwrap();
        for leaked in ["Acme VPN", "vpn.example.com", FINGERPRINT, "Office AD"] {
            assert!(!json.contains(leaked), "{leaked}: {json}");
        }
    }

    #[test]
    fn previews_are_kept_by_id_and_dropped_on_lock() {
        let (app, _) = app();
        assert!(app.take(A).is_none());
        app.pick(Pick::Source, PathBuf::from("/Volumes/Share/acme.macvpncatalog"));
        app.pick(Pick::AdminKey, PathBuf::from("/Volumes/Key/acme.macvpnadminkey"));
        app.vault_locked();
        assert!(app.picked(Pick::Source).is_none() && app.picked(Pick::AdminKey).is_none());
    }

    /// A catalog file opened from Finder waits in its own slot that only the add dialog reads: the source edit and
    /// "Copy subscription string" never take it, and a file chosen in a panel afterwards replaces it.
    #[test]
    fn a_finder_opened_catalog_file_is_only_the_add_dialogs() {
        let (app, _) = app();
        let opened = PathBuf::from("/Volumes/Share/opened.macvpncatalog");
        app.pick_opened(opened.clone());
        let file = |s: CatalogSource| match s {
            CatalogSource::File(f) => f,
            other => panic!("{other:?}"),
        };
        assert_eq!(file(app.add_source(None, true).unwrap()), opened, "the add dialog takes it");
        assert!(app.source(None, true).is_err(), "the source edit does not");
        assert!(app.picked(Pick::Source).is_none(), "nor does Copy subscription string");
        // A file chosen in a panel (in any dialog) replaces it.
        let chosen = PathBuf::from("/Volumes/Share/chosen.macvpncatalog");
        app.chose_file(chosen.clone());
        assert!(app.picked(Pick::Opened).is_none());
        assert_eq!(file(app.add_source(None, true).unwrap()), chosen);
        assert_eq!(file(app.source(None, true).unwrap()), chosen);
        // A new open replaces an older chosen file for the add dialog only.
        app.pick_opened(opened.clone());
        assert_eq!(file(app.add_source(None, true).unwrap()), opened);
        assert_eq!(file(app.source(None, true).unwrap()), chosen);
        // Subscribed: both go.
        app.forget_add_picks();
        assert!(app.add_source(None, true).is_err());
        // Locked: dropped.
        app.pick_opened(opened);
        app.vault_locked();
        assert!(app.picked(Pick::Opened).is_none());
    }

    /// A stand-in preview: expires at `expires`.
    struct Preview(Instant);
    impl Expiring for Preview {
        fn is_expired(&self, now: Instant) -> bool {
            now >= self.0
        }
    }

    /// A preview that finishes after the lock (or after a lock and a new unlock) is dropped, not kept.
    #[test]
    fn a_preview_that_finishes_after_the_lock_is_dropped() {
        let later = Instant::now() + Duration::from_secs(600);
        let mut previews = Previews::default();
        let epoch = previews.epoch();
        let id = previews.keep(Preview(later), epoch, true, Instant::now()).expect("unlocked: kept");
        assert!(previews.take(&id).is_some());
        // Locked while the fetch ran: the vault is no longer open.
        assert!(previews.keep(Preview(later), epoch, false, Instant::now()).is_none());
        // Locked and unlocked again while it ran: the lock moved the epoch on.
        let kept = previews.keep(Preview(later), epoch, true, Instant::now()).unwrap();
        previews.locked();
        assert!(previews.take(&kept).is_none(), "the lock cleared it");
        assert!(previews.keep(Preview(later), epoch, true, Instant::now()).is_none(), "an older epoch");
        let epoch = previews.epoch();
        assert!(previews.keep(Preview(later), epoch, true, Instant::now()).is_some());
    }

    #[test]
    fn previews_expire_and_are_bounded() {
        let now = Instant::now();
        let mut previews = Previews::default();
        let epoch = previews.epoch();
        let expired = previews.keep(Preview(now), epoch, true, now).unwrap();
        let ids: Vec<String> = (0..MAX_PENDING)
            .map(|_| previews.keep(Preview(now + Duration::from_secs(600)), epoch, true, now).unwrap())
            .collect();
        assert!(previews.take(&expired).is_none(), "expired, then the oldest went");
        assert!(ids.iter().all(|id| previews.take(id).is_some()));
    }

    /// The app's lock moves the epoch on, and a locked vault keeps nothing.
    #[test]
    fn the_lock_moves_the_preview_epoch_on() {
        let (app, _) = app();
        let before = app.preview_epoch();
        app.vault_locked();
        assert_ne!(app.preview_epoch(), before);
    }
}
