//! The team catalog service (spec 5 and 6, plan Task 11): subscribe, refresh, verify, apply, unsubscribe, the
//! pending removals of connections that were up, and the notifications.
//!
//! - **Subscribe** ([`CatalogService::preview`], [`CatalogService::confirm`]): the first download must be signed by
//!   the key whose fingerprint the user entered (no trust on first use). The subscription string's optional
//!   `catalogId` and `minVersion` bind that first download. `confirm` stores the subscription (the publisher key
//!   now pinned in full), creates the root folder and applies the catalog in one transaction.
//! - **Refresh** ([`CatalogService::refresh`]): fetch with the stored validators, open with the stored trust, catalog
//!   id, rollback floor and team key, plan against the manager's active connections and apply in one transaction
//!   together with the new record. The validators are stored only with a catalog that was applied (or was the
//!   applied version), so a refused file is fetched again next time.
//! - **Successor keys** (spec 7): an announced successor is stored only from a catalog that was fully opened and
//!   applied; a catalog signed by the stored successor re-pins to it (and takes the new header's announcement, or
//!   none) in the same transaction as its apply.
//! - **After a restore** (`reapply`): the floor is `applied_version - 1`, so the same version opens once and a
//!   lower one is still a rollback.
//! - **Notifications** only when the status changes into a problem (rollback refused, per offered version; team key
//!   changed; failed), and one per applied version with changes. "Unavailable" never notifies.
//! - **Removals:** a removed connection that is up stays (marked) until it leaves the active states; then
//!   [`CatalogService::process_pending_removals`] deletes it. Every removal and unsubscribe prunes the control API
//!   allowlists, so a re-subscribe (same deterministic ids) never re-grants access silently.
//!
//! Secrets: the team key and the bearer token stay in `Zeroizing` buffers and in the vault; nothing here logs a key,
//! a token, a subscription string or catalog content. The log has events only, by catalog id.

use crate::catalog_schedule::{MAX_JITTER, RefreshTrigger, SCHEDULER_WAKE, is_due, next_attempt};
use crate::deps::{CatalogFetcher, Clock, FetchOutcome, FetchRequest, NativeProfiles};
use crate::manager::{ConnectionItem, ConnectionManager};
use crate::notify::{self, NotificationContent};
use crate::vault::VaultLifecycle;
use macvpn_core::catalog::format::{CatalogError, CatalogErrorKind, OpenRequest, OpenedCatalog, Trust, open_catalog};
use macvpn_core::catalog::ids::{CatalogItemKind, local_id, root_folder_id};
use macvpn_core::catalog::keys::{Fingerprint, TeamKey};
use macvpn_core::catalog::payload::{CatalogPayload, PAYLOAD_VERSION};
use macvpn_core::catalog::planner::{ApplySummary, LocalCatalog, plan_apply, plan_pending, plan_unsubscribe};
use macvpn_core::catalog::source::CatalogSource;
use macvpn_core::catalog::subscription::SubscriptionString;
use macvpn_core::importer;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::{parse_uuid, uuid_string};
use macvpn_core::vault::{
    ApplyContext, SourceValidators, SubscriptionRecord, SubscriptionStatus, UnsubscribeReport, Vault, VaultError,
};
use serde::Serialize;
use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock, Weak};
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

/// A pending subscription (the preview the user has not confirmed yet) is dropped after this.
pub const PENDING_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Unsubscribing waits this long for each active catalog connection to go down.
pub const DISCONNECT_WAIT: Duration = Duration::from_secs(15);
/// An apply plans again at most this often when the active connections change under it.
const MAX_PLAN_ATTEMPTS: usize = 5;

// MARK: - input and results

/// "Add team catalog…": the source, the team key, the publisher fingerprint, an optional bearer token, and the
/// subscription string's optional binding of the first download.
pub struct SubscribeInput {
    pub source: CatalogSource,
    pub team_key: TeamKey,
    pub fingerprint: Fingerprint,
    pub bearer: Option<Zeroizing<String>>,
    /// The catalog the first download must be (`catalogId`).
    pub catalog_id: Option<Uuid>,
    /// The lowest version the first download may have (`minVersion`).
    pub min_version: Option<u64>,
}

impl SubscribeInput {
    /// From a pasted subscription string (its `catalogId` and `minVersion` included) and a token typed apart.
    pub fn from_subscription(s: SubscriptionString, bearer: Option<Zeroizing<String>>) -> Self {
        SubscribeInput {
            source: s.source,
            team_key: s.team_key,
            fingerprint: s.fingerprint,
            bearer,
            catalog_id: s.catalog_id,
            min_version: s.min_version,
        }
    }
}

impl fmt::Debug for SubscribeInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscribeInput")
            .field("source", &self.source)
            .field("fingerprint", &self.fingerprint)
            .field("has_bearer", &self.bearer.is_some())
            .field("catalog_id", &self.catalog_id)
            .field("min_version", &self.min_version)
            .finish_non_exhaustive()
    }
}

/// What the user confirms before subscribing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogPreview {
    #[serde(serialize_with = "serialize_uuid")]
    pub catalog_id: Uuid,
    pub name: String,
    pub version: u64,
    #[serde(serialize_with = "serialize_fingerprint")]
    pub fingerprint: Fingerprint,
    pub connections: usize,
    pub folders: usize,
    /// The credential slots' names.
    pub slots: Vec<String>,
    /// Connections with risky directives (each subscriber acknowledges them).
    pub risky: usize,
    /// Team secrets the catalog carries.
    pub team_secrets: usize,
}

fn serialize_uuid<S: serde::Serializer>(id: &Uuid, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&uuid_string(id))
}

fn serialize_fingerprint<S: serde::Serializer>(f: &Fingerprint, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&f.to_text())
}

/// A verified first download waiting for the user's confirmation: the opened catalog and the secrets, wiped on
/// drop. It expires after [`PENDING_LIFETIME`].
pub struct PendingSubscription {
    input: SubscribeInput,
    opened: OpenedCatalog,
    validators: SourceValidators,
    created: Instant,
}

impl PendingSubscription {
    pub fn catalog_id(&self) -> Uuid {
        self.opened.header.catalog_id
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.created) >= PENDING_LIFETIME
    }
}

impl fmt::Debug for PendingSubscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingSubscription").field("catalog_id", &self.catalog_id()).finish_non_exhaustive()
    }
}

/// What one refresh did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshResult {
    /// The source has not changed (`304`, the same file).
    NotModified,
    /// A new version was applied.
    Applied(ApplySummary),
    /// The source offered the applied version again.
    Unchanged,
    /// Not applied: why.
    Refused(CatalogError),
    /// The vault is locked: nothing was fetched.
    Locked,
}

/// Why a subscribe, unsubscribe or change failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogServiceError {
    Catalog(CatalogError),
    /// The first download is signed by another key than the fingerprint entered.
    FingerprintMismatch,
    AlreadySubscribed,
    /// The preview is older than [`PENDING_LIFETIME`].
    Expired,
    /// A catalog connection is still up.
    StillActive,
    Locked,
    /// The vault refused the change (no value in it).
    Vault,
}

impl fmt::Display for CatalogServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            CatalogServiceError::Catalog(e) => error_text(e),
            CatalogServiceError::FingerprintMismatch => {
                l10n::tr("The catalog is signed by a different key than the fingerprint you entered.", &[])
            }
            CatalogServiceError::AlreadySubscribed => l10n::tr("You are already subscribed to this catalog.", &[]),
            CatalogServiceError::Expired => l10n::tr("The catalog preview expired. Add the catalog again.", &[]),
            CatalogServiceError::StillActive => l10n::tr("Disconnect the team catalog's connections first.", &[]),
            CatalogServiceError::Locked => crate::vault_stores::locked_message(),
            CatalogServiceError::Vault => l10n::tr("The vault could not save the change.", &[]),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for CatalogServiceError {}

impl From<VaultError> for CatalogServiceError {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::Locked => CatalogServiceError::Locked,
            _ => CatalogServiceError::Vault,
        }
    }
}

/// A subscription change from the subscription's settings.
pub enum SubscriptionChange {
    /// The publisher rotated the team key.
    TeamKey(TeamKey),
    /// `None` removes the token.
    Bearer(Option<Zeroizing<String>>),
    Source(CatalogSource),
}

impl fmt::Debug for SubscriptionChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubscriptionChange::TeamKey(_) => f.write_str("TeamKey(<redacted>)"),
            SubscriptionChange::Bearer(b) => write!(f, "Bearer({})", if b.is_some() { "<redacted>" } else { "None" }),
            SubscriptionChange::Source(s) => write!(f, "Source({s:?})"),
        }
    }
}

// MARK: - views

/// A credential slot of a subscription.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotView {
    pub name: String,
    /// The user filled in a user name or a password.
    pub filled: bool,
    pub credential_name: Option<String>,
}

/// One subscription in the "Team catalogs" section. Never a key, a token or the source's query.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionView {
    pub id: String,
    pub name: String,
    /// A URL without its query, a file by its file name.
    pub source: String,
    pub fingerprint: String,
    pub version: Option<u64>,
    /// `ok`, `notModified`, `unavailable`, `failed`, `rollbackRefused`, `teamKeyChanged`.
    pub status: &'static str,
    /// Unix time (seconds).
    pub last_refresh: Option<f64>,
    pub last_success: Option<f64>,
    /// The problem, translated.
    pub error: Option<String>,
    pub has_token: bool,
    pub slots: Vec<SlotView>,
}

/// The "Team" badge of a catalog connection's row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogBadge {
    pub catalog_id: String,
    pub name: String,
    /// Removed from the catalog while up: deleted once it disconnects.
    pub pending_removal: bool,
    /// The catalog changed this native connection: its profile needs a reinstall.
    pub profile_outdated: bool,
}

// MARK: - texts

/// A catalog error as the user reads it.
pub fn error_text(e: &CatalogError) -> String {
    match e {
        CatalogError::Unavailable(source) => {
            l10n::tr("The team catalog source is unavailable (%@).", &[Arg::Str(source)])
        }
        CatalogError::Io(message) => l10n::tr("The team catalog could not be read: %@", &[Arg::Str(message)]),
        CatalogError::SameVersion => l10n::tr("The team catalog has not changed.", &[]),
        CatalogError::Rollback { applied, offered } => l10n::tr(
            "The team catalog offers version %d, older than the applied version %d: refused.",
            &[Arg::Int(*offered as i64), Arg::Int(*applied as i64)],
        ),
        other => other.kind().map(kind_text).unwrap_or_default(),
    }
}

/// The text of a stored failure kind.
pub fn kind_text(kind: CatalogErrorKind) -> String {
    match kind {
        CatalogErrorKind::NotACatalog => l10n::tr("The file is not a MacVPN team catalog.", &[]),
        CatalogErrorKind::Truncated => l10n::tr("The team catalog file is incomplete.", &[]),
        CatalogErrorKind::TooLarge => l10n::tr("The team catalog file is too large.", &[]),
        CatalogErrorKind::NewerFormat => l10n::tr("The team catalog was made by a newer MacVPN.", &[]),
        CatalogErrorKind::BadHeader => l10n::tr("The team catalog file is damaged.", &[]),
        CatalogErrorKind::UnknownPublisher => {
            l10n::tr("The team catalog was signed by another publisher than the one you trust.", &[])
        }
        CatalogErrorKind::BadSignature => l10n::tr("The team catalog's signature is not valid: it was changed.", &[]),
        CatalogErrorKind::WrongCatalog => l10n::tr("The source holds another team catalog.", &[]),
        CatalogErrorKind::WrongTeamKey => {
            l10n::tr("The team key does not open this catalog (it is wrong or was rotated).", &[])
        }
        CatalogErrorKind::Invalid => l10n::tr("The team catalog contains a connection MacVPN cannot use.", &[]),
        CatalogErrorKind::Io => l10n::tr("The team catalog could not be read.", &[]),
    }
}

/// "Team catalog “Acme VPN” updated: 2 added, 1 removed" (only the non-zero parts); `None` without changes.
pub fn update_text(name: &str, s: &ApplySummary) -> Option<String> {
    let mut parts = Vec::new();
    if s.added > 0 {
        parts.push(l10n::tr("%d added", &[Arg::Int(s.added as i64)]));
    }
    if s.changed > 0 {
        parts.push(l10n::tr("%d changed", &[Arg::Int(s.changed as i64)]));
    }
    if s.removed > 0 {
        parts.push(l10n::tr("%d removed", &[Arg::Int(s.removed as i64)]));
    }
    if parts.is_empty() {
        return None;
    }
    Some(l10n::tr("Team catalog “%@” updated: %@", &[Arg::Str(name), Arg::Str(&parts.join(", "))]))
}

fn status_name(status: SubscriptionStatus) -> &'static str {
    match status {
        SubscriptionStatus::Ok => "ok",
        SubscriptionStatus::NotModified => "notModified",
        SubscriptionStatus::Unavailable => "unavailable",
        SubscriptionStatus::Failed(_) => "failed",
        SubscriptionStatus::RollbackRefused { .. } => "rollbackRefused",
        SubscriptionStatus::TeamKeyChanged => "teamKeyChanged",
    }
}

fn status_text(record: &SubscriptionRecord) -> Option<String> {
    match record.status {
        SubscriptionStatus::Ok | SubscriptionStatus::NotModified => None,
        SubscriptionStatus::Unavailable => Some(l10n::tr("The team catalog source is unavailable.", &[])),
        SubscriptionStatus::Failed(kind) => Some(kind_text(kind)),
        SubscriptionStatus::RollbackRefused { offered } => {
            Some(error_text(&CatalogError::Rollback { applied: record.applied_version.unwrap_or_default(), offered }))
        }
        SubscriptionStatus::TeamKeyChanged => Some(kind_text(CatalogErrorKind::WrongTeamKey)),
    }
}

/// The text of a notifying status (`None`: the status does not notify).
fn notice_text(record: &SubscriptionRecord, status: SubscriptionStatus) -> Option<String> {
    let name = record.name.as_str();
    match status {
        SubscriptionStatus::RollbackRefused { offered } => Some(l10n::tr(
            "Team catalog “%@” offered an older version (v%d after v%d) and was not applied.",
            &[Arg::Str(name), Arg::Int(offered as i64), Arg::Int(record.applied_version.unwrap_or_default() as i64)],
        )),
        SubscriptionStatus::TeamKeyChanged => Some(l10n::tr(
            "The team key of “%@” has changed. Ask your administrator for the new key.",
            &[Arg::Str(name)],
        )),
        SubscriptionStatus::Failed(kind) => {
            Some(l10n::tr("Team catalog “%@” could not be updated: %@", &[Arg::Str(name), Arg::Str(&kind_text(kind))]))
        }
        SubscriptionStatus::Ok | SubscriptionStatus::NotModified | SubscriptionStatus::Unavailable => None,
    }
}

/// The names of the connections whose server an apply changed (the update notice names them: a moved server is
/// where the slot's password goes next).
fn moved_servers(catalog_id: Uuid, payload: &CatalogPayload, before: &HashMap<Uuid, Option<String>>) -> Vec<String> {
    let mut names: Vec<String> = payload
        .connections
        .iter()
        .filter(|c| {
            let local = local_id(catalog_id, CatalogItemKind::Connection, c.id);
            before.get(&local).is_some_and(|old| *old != importer::server_host(c.kind, c.native.as_ref(), &c.config))
        })
        .map(|c| c.name.clone())
        .collect();
    names.sort();
    names
}

// MARK: - the service

/// What the service works with.
pub struct CatalogDeps {
    pub vault: Arc<VaultLifecycle>,
    /// The HTTPS source (`CurlCatalogFetcher` in the app).
    pub https: Arc<dyn CatalogFetcher>,
    /// The file source ([`crate::catalog_file::FileCatalogFetcher`]).
    pub file: Arc<dyn CatalogFetcher>,
    pub manager: Arc<ConnectionManager>,
    pub clock: Arc<dyn Clock>,
}

type Notifier = Arc<dyn Fn(NotificationContent) + Send + Sync>;
type Logger = Arc<dyn Fn(&str) + Send + Sync>;
type KeyPruner = Arc<dyn Fn(&[String]) -> Result<(), String> + Send + Sync>;

#[derive(Default, Clone)]
struct Hooks {
    notify: Option<Notifier>,
    log: Option<Logger>,
    forget_keys: Option<KeyPruner>,
    profiles: Option<Arc<dyn NativeProfiles>>,
    after_apply: Option<Arc<dyn Fn() + Send + Sync>>,
}

pub struct CatalogService {
    deps: CatalogDeps,
    hooks: RwLock<Hooks>,
    /// One refresh, subscribe, unsubscribe or pending-removal run at a time.
    serial: Mutex<()>,
    disconnect_wait: Mutex<Duration>,
    /// The connection keys marked for removal (the state listener's filter).
    pending_keys: Mutex<HashSet<String>>,
    next_notice: AtomicU64,
    this: Weak<CatalogService>,
    /// The scheduler's state (plan Task 12).
    schedule: Mutex<ScheduleState>,
    schedule_signal: Condvar,
    /// Seeds the back-off jitter, different in every run.
    jitter_seed: RandomState,
    /// A test hook before every apply transaction.
    before_apply: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

/// The scheduler's in-memory state: the last attempt of each subscription in this run (a launch refreshes all
/// anyway), a requested trigger (wake, unlock) and the stop flag.
#[derive(Default)]
struct ScheduleState {
    last: HashMap<Uuid, Instant>,
    requested: Option<RefreshTrigger>,
    stopped: bool,
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The local ids of the connections the manager has in an active state.
fn active_ids(manager: &ConnectionManager) -> HashSet<Uuid> {
    manager.states().into_iter().filter(|(_, s)| s.is_active()).filter_map(|(k, _)| parse_uuid(&k)).collect()
}

fn empty_payload() -> CatalogPayload {
    CatalogPayload {
        version: PAYLOAD_VERSION,
        folders: Vec::new(),
        connections: Vec::new(),
        credential_slots: Vec::new(),
        shared_secrets: BTreeMap::new(),
    }
}

fn connection_ids(local: &LocalCatalog) -> Vec<Uuid> {
    local.items.iter().filter(|i| i.kind == CatalogItemKind::Connection).map(|i| i.local_id).collect()
}

impl CatalogService {
    pub fn new(deps: CatalogDeps) -> Arc<Self> {
        Arc::new_cyclic(|this| CatalogService {
            deps,
            hooks: RwLock::new(Hooks::default()),
            serial: Mutex::new(()),
            disconnect_wait: Mutex::new(DISCONNECT_WAIT),
            pending_keys: Mutex::new(HashSet::new()),
            next_notice: AtomicU64::new(1),
            this: this.clone(),
            schedule: Mutex::new(ScheduleState::default()),
            schedule_signal: Condvar::new(),
            jitter_seed: RandomState::new(),
            before_apply: Mutex::new(None),
        })
    }

    fn hooks(&self) -> Hooks {
        self.hooks.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// Posts the user notifications (the app maps them to `UNUserNotificationCenter`).
    pub fn set_notifier(&self, f: impl Fn(NotificationContent) + Send + Sync + 'static) {
        self.hooks.write().unwrap_or_else(PoisonError::into_inner).notify = Some(Arc::new(f));
    }

    /// The log (events only, never a value).
    pub fn set_logger(&self, f: impl Fn(&str) + Send + Sync + 'static) {
        self.hooks.write().unwrap_or_else(PoisonError::into_inner).log = Some(Arc::new(f));
    }

    /// Prunes connection keys from every paired client's allowlist (`ControlServer::forget_keys`, or
    /// `control::forget_keys_in_registry` while the server is off). A failure is logged.
    pub fn set_forget_keys(&self, f: impl Fn(&[String]) -> Result<(), String> + Send + Sync + 'static) {
        self.hooks.write().unwrap_or_else(PoisonError::into_inner).forget_keys = Some(Arc::new(f));
    }

    /// The native profiles: a removed connection's profile is removed with it ([`NativeProfiles::remove`]; nothing
    /// on macOS), as when the user deletes a connection.
    pub fn set_native_profiles(&self, profiles: Arc<dyn NativeProfiles>) {
        self.hooks.write().unwrap_or_else(PoisonError::into_inner).profiles = Some(profiles);
    }

    /// Runs after every applied catalog (a subscribe, a refresh that applied a version) and a "Duplicate as
    /// personal connection", once the manager has reloaded: WinVPN installs the native profiles of the added and changed connections there
    /// ([`crate::connections::ConnectionsModel::install_native_profiles`]; nothing where macOS approves each).
    pub fn set_after_apply(&self, f: impl Fn() + Send + Sync + 'static) {
        self.hooks.write().unwrap_or_else(PoisonError::into_inner).after_apply = Some(Arc::new(f));
    }

    fn applied(&self) {
        if let Some(after) = self.hooks().after_apply {
            after();
        }
    }

    /// Runs right before an apply's transaction (tests: a connection that comes up meanwhile).
    #[cfg(feature = "test-support")]
    pub fn set_before_apply(&self, f: impl Fn() + Send + Sync + 'static) {
        *guard(&self.before_apply) = Some(Box::new(f));
    }

    /// How long unsubscribing waits for each connection to go down (tests shorten it).
    pub fn set_disconnect_wait(&self, wait: Duration) {
        *guard(&self.disconnect_wait) = wait;
    }

    /// Watches the manager: a pending removal that leaves the active states is deleted (on its own thread, since a
    /// state listener must not call back into the manager). Call once, after creating the service.
    pub fn attach(&self) {
        let weak = self.this.clone();
        self.deps.manager.add_state_listener(move |key, state| {
            if state.is_active() {
                return;
            }
            let Some(service) = weak.upgrade() else { return };
            if !guard(&service.pending_keys).contains(key) {
                return;
            }
            let _ = std::thread::Builder::new()
                .name("macvpn-catalog-pending".into())
                .spawn(move || service.process_pending_removals());
        });
    }

    fn log(&self, line: &str) {
        if let Some(log) = self.hooks().log {
            log(&format!("team catalog: {line}"));
        }
    }

    fn notify(&self, catalog_id: Uuid, text: String) {
        if let Some(notify) = self.hooks().notify {
            let n = self.next_notice.fetch_add(1, Ordering::SeqCst);
            notify(notify::for_catalog(&uuid_string(&catalog_id), text, format!("catalog-{n}")));
        }
    }

    /// After `removed` left the vault (an apply, a pending removal, an unsubscribe): their keys leave the control
    /// API's allowlists and their profiles are removed.
    fn forget(&self, removed: &[Uuid]) {
        if removed.is_empty() {
            return;
        }
        if let Some(profiles) = self.hooks().profiles {
            removed.iter().for_each(|id| profiles.remove(id));
        }
        if let Some(forget) = self.hooks().forget_keys {
            let keys: Vec<String> = removed.iter().map(uuid_string).collect();
            if forget(&keys).is_err() {
                self.log(&format!("pruning {} key(s) from the control API allowlists failed", keys.len()));
            }
        }
    }

    /// Runs `write` on the vault only while the manager's active connections are still `active` (checked under the
    /// vault's lock, which a connect needs to read its config): `Ok(None)` when they changed, so the caller plans
    /// again and a connection that just came up is never deleted.
    fn with_same_active<R>(
        &self,
        active: &HashSet<Uuid>,
        write: impl FnOnce(&mut Vault) -> Result<R, VaultError>,
    ) -> Result<Option<R>, VaultError> {
        if let Some(hook) = guard(&self.before_apply).as_ref() {
            hook();
        }
        self.deps.vault.with(|v| if active_ids(&self.deps.manager) != *active { Ok(None) } else { write(v).map(Some) })
    }

    fn fetcher(&self, source: &CatalogSource) -> &dyn CatalogFetcher {
        match source {
            CatalogSource::Https(_) => self.deps.https.as_ref(),
            CatalogSource::File(_) => self.deps.file.as_ref(),
        }
    }

    fn read<R>(&self, f: impl FnOnce(&Vault) -> Result<R, VaultError>) -> Result<R, VaultError> {
        self.deps.vault.with_read(f)
    }

    /// Re-reads which connection keys are marked for removal.
    fn update_pending_keys(&self) {
        let keys = self
            .read(|v| {
                let mut keys = HashSet::new();
                for record in v.subscriptions()? {
                    let local = v.local_catalog(record.catalog_id)?;
                    keys.extend(local.items.iter().filter(|i| i.pending_removal).map(|i| uuid_string(&i.local_id)));
                }
                Ok(keys)
            })
            .unwrap_or_default();
        *guard(&self.pending_keys) = keys;
    }

    // MARK: subscribe

    /// Fetches and verifies the first download (spec 5). Nothing is stored.
    pub fn preview(&self, input: SubscribeInput) -> Result<(CatalogPreview, PendingSubscription), CatalogServiceError> {
        let subscribed = |id: Uuid| self.read(|v| v.subscription(id)).map(|r| r.is_some());
        if let Some(id) = input.catalog_id
            && subscribed(id)?
        {
            return Err(CatalogServiceError::AlreadySubscribed);
        }
        if !self.deps.vault.is_unlocked() {
            return Err(CatalogServiceError::Locked);
        }
        let previous = SourceValidators::default();
        let outcome = self
            .fetcher(&input.source)
            .fetch(&FetchRequest {
                source: &input.source,
                bearer: input.bearer.as_deref().map(String::as_str),
                previous: &previous,
            })
            .map_err(CatalogServiceError::Catalog)?;
        let FetchOutcome::Fetched { bytes, validators } = outcome else {
            return Err(CatalogServiceError::Catalog(CatalogError::Io("the source sent no catalog".into())));
        };
        let min = input.min_version.filter(|m| *m > 0);
        let trust = Trust { pinned: input.fingerprint, publisher_key: None, successor: None };
        let opened = open_catalog(
            &bytes,
            &OpenRequest {
                trust: &trust,
                catalog_id: input.catalog_id,
                applied_version: min.map(|m| m - 1),
                team_key: &input.team_key,
            },
        )
        .map_err(|e| match (e, min) {
            (CatalogError::UnknownPublisher, _) => CatalogServiceError::FingerprintMismatch,
            (CatalogError::SameVersion, Some(m)) => {
                CatalogServiceError::Catalog(CatalogError::Rollback { applied: m, offered: m - 1 })
            }
            (CatalogError::Rollback { offered, .. }, Some(m)) => {
                CatalogServiceError::Catalog(CatalogError::Rollback { applied: m, offered })
            }
            (e, _) => CatalogServiceError::Catalog(e),
        })?;
        if subscribed(opened.header.catalog_id)? {
            return Err(CatalogServiceError::AlreadySubscribed);
        }
        let p = &opened.payload;
        let preview = CatalogPreview {
            catalog_id: opened.header.catalog_id,
            name: opened.header.name.clone(),
            version: opened.header.version,
            fingerprint: opened.header.publisher_key_id,
            connections: p.connections.len(),
            folders: p.folders.len(),
            slots: p.credential_slots.iter().map(|s| s.name.clone()).collect(),
            risky: opened.findings.risky.values().filter(|f| !f.is_empty()).count(),
            team_secrets: p.shared_secrets.len(),
        };
        Ok((preview, PendingSubscription { input, opened, validators, created: Instant::now() }))
    }

    /// Stores the subscription and applies its first catalog, in one transaction.
    pub fn confirm(&self, pending: PendingSubscription) -> Result<ApplySummary, CatalogServiceError> {
        if pending.is_expired(Instant::now()) {
            return Err(CatalogServiceError::Expired);
        }
        let _serial = guard(&self.serial);
        let header = &pending.opened.header;
        let id = header.catalog_id;
        if self.read(|v| v.subscription(id))?.is_some() {
            return Err(CatalogServiceError::AlreadySubscribed);
        }
        let now = self.deps.clock.now();
        let record = SubscriptionRecord {
            catalog_id: id,
            name: header.name.clone(),
            source: pending.input.source.clone(),
            pinned: header.publisher_key_id,
            applied_version: Some(header.version),
            reapply: false,
            status: SubscriptionStatus::Ok,
            validators: pending.validators.clone(),
            last_attempt: Some(now),
            last_success: Some(now),
            failures: 0,
            has_bearer: pending.input.bearer.is_some(),
            publisher_key: Some(header.publisher_key),
            successor_key: header.successor_key,
            added: now,
        };
        let empty = LocalCatalog {
            catalog_id: id,
            name: header.name.clone(),
            root_folder: root_folder_id(id),
            items: Vec::new(),
            slots: BTreeMap::new(),
        };
        let plan = plan_apply(&empty, &header.name, &pending.opened.payload, &HashSet::new());
        let ctx = ApplyContext { catalog_id: id, payload: &pending.opened.payload, now };
        let bearer = pending.input.bearer.as_deref().map(String::as_str);
        self.deps.vault.with(|v| v.subscribe_catalog(&record, &pending.input.team_key, bearer, &plan, &ctx))?;
        // The first download was this one: the timer's next refresh is an interval later, not at its next wake.
        self.attempted(id);
        self.log(&format!(
            "{} subscribed, applied v{}: {} added",
            uuid_string(&id),
            header.version,
            plan.summary.added
        ));
        self.deps.manager.reload();
        self.applied();
        Ok(plan.summary)
    }

    // MARK: refresh

    /// Every subscription, one after another.
    pub fn refresh_all(&self, trigger: RefreshTrigger) -> Vec<(Uuid, RefreshResult)> {
        let Ok(records) = self.read(|v| v.subscriptions()) else { return Vec::new() };
        records.into_iter().map(|r| (r.catalog_id, self.refresh(r.catalog_id, trigger))).collect()
    }

    /// Fetches, verifies and applies one subscription (see the module docs).
    pub fn refresh(&self, catalog_id: Uuid, trigger: RefreshTrigger) -> RefreshResult {
        let _serial = guard(&self.serial);
        let id = uuid_string(&catalog_id);
        let loaded = self.read(|v| {
            let record = v.subscription(catalog_id)?;
            match record {
                Some(r) => Ok(Some((r, v.subscription_secrets(catalog_id)?))),
                None => Ok(None),
            }
        });
        let (record, (team_key, bearer)) = match loaded {
            Ok(Some(found)) => found,
            Ok(None) => return RefreshResult::Refused(CatalogError::Io("no such team catalog subscription".into())),
            Err(VaultError::Locked) => return RefreshResult::Locked,
            Err(_) => return RefreshResult::Refused(CatalogError::Io("the vault could not be read".into())),
        };
        // Every attempt counts for the timer (a scheduler round sets its own instant after this): a "Refresh now"
        // is not followed by a timer refresh at the scheduler's next wake.
        self.attempted(catalog_id);
        let now = self.deps.clock.now();
        // After a restore the items are missing: download in full, whatever the stored validators say.
        let none = SourceValidators::default();
        let previous = if record.reapply { &none } else { &record.validators };
        let outcome = self.fetcher(&record.source).fetch(&FetchRequest {
            source: &record.source,
            bearer: bearer.as_deref().map(String::as_str),
            previous,
        });
        let (bytes, validators) = match outcome {
            Err(e) => return self.refused(&record, e, now),
            Ok(FetchOutcome::NotModified) => {
                self.store(&record, |r| {
                    r.last_attempt = Some(now);
                    r.last_success = Some(now);
                    r.failures = 0;
                    r.status = SubscriptionStatus::NotModified;
                });
                self.log(&format!("{id} refreshed ({trigger:?}): not modified"));
                return RefreshResult::NotModified;
            }
            Ok(FetchOutcome::Fetched { bytes, validators }) => (bytes, validators),
        };
        let applied = record.applied_version;
        let floor = if record.reapply { applied.map(|v| v.saturating_sub(1)) } else { applied };
        let trust =
            Trust { pinned: record.pinned, publisher_key: record.publisher_key, successor: record.successor_key };
        let opened = open_catalog(
            &bytes,
            &OpenRequest { trust: &trust, catalog_id: Some(catalog_id), applied_version: floor, team_key: &team_key },
        );
        let opened = match (opened, record.reapply, applied) {
            (Ok(opened), ..) => opened,
            (Err(CatalogError::SameVersion), true, Some(v)) => {
                return self.refused(&record, CatalogError::Rollback { applied: v, offered: v.saturating_sub(1) }, now);
            }
            (Err(CatalogError::Rollback { offered, .. }), true, Some(v)) => {
                return self.refused(&record, CatalogError::Rollback { applied: v, offered }, now);
            }
            (Err(CatalogError::SameVersion), ..) => {
                // A re-uploaded identical version: nothing to do, but the source is healthy.
                self.store(&record, |r| {
                    r.last_attempt = Some(now);
                    r.last_success = Some(now);
                    r.failures = 0;
                    r.status = SubscriptionStatus::Ok;
                    r.validators = validators;
                });
                self.log(&format!("{id} refreshed ({trigger:?}): same version"));
                return RefreshResult::Unchanged;
            }
            (Err(e), ..) => return self.refused(&record, e, now),
        };
        self.apply(record, opened, validators, now)
    }

    /// Applies a verified catalog in one transaction with the new record.
    fn apply(
        &self,
        record: SubscriptionRecord,
        opened: OpenedCatalog,
        validators: SourceValidators,
        now: macvpn_core::date::Date,
    ) -> RefreshResult {
        let catalog_id = record.catalog_id;
        let id = uuid_string(&catalog_id);
        let header = &opened.header;
        let mut next = record.clone();
        next.name = header.name.clone();
        next.applied_version = Some(header.version);
        next.reapply = false;
        next.status = SubscriptionStatus::Ok;
        next.validators = validators;
        next.last_attempt = Some(now);
        next.last_success = Some(now);
        next.failures = 0;
        // The full key is pinned once verified; a successor is stored only from a catalog that is applied here,
        // and a catalog signed by it re-pins (the old key is no longer accepted).
        next.publisher_key = Some(header.publisher_key);
        next.successor_key = header.successor_key;
        if opened.signed_by_successor {
            next.pinned = header.publisher_key.fingerprint();
        }
        let ctx = ApplyContext { catalog_id, payload: &opened.payload, now };
        let servers_before = self.servers_before(catalog_id, &opened.payload);
        let mut attempts = 0;
        let (plan, removed) = loop {
            attempts += 1;
            let active = active_ids(&self.deps.manager);
            let local = match self.read(|v| v.local_catalog(catalog_id)) {
                Ok(local) => local,
                Err(VaultError::Locked) => return RefreshResult::Locked,
                Err(_) => return RefreshResult::Refused(CatalogError::Io("the vault could not be read".into())),
            };
            let plan = plan_apply(&local, &header.name, &opened.payload, &active);
            match self.with_same_active(&active, |v| v.apply_catalog(&plan, &ctx, &next)) {
                Ok(Some(removed)) => break (plan, removed),
                Ok(None) if attempts < MAX_PLAN_ATTEMPTS => continue,
                Ok(None) => {
                    self.log(&format!("{id} refused: the connections kept changing"));
                    let e = CatalogError::Io("the connections kept changing; try again".into());
                    return self.refused(&record, e, now);
                }
                Err(VaultError::Locked) => return RefreshResult::Locked,
                Err(_) => {
                    self.log(&format!("{id} refused: the vault could not apply it"));
                    let e = CatalogError::Io("the vault could not apply the team catalog".into());
                    return self.refused(&record, e, now);
                }
            }
        };
        if opened.signed_by_successor {
            self.log(&format!("{id}: publisher key rotated"));
        }
        let s = plan.summary;
        self.log(&format!(
            "{id} refreshed: applied v{}: {} added, {} changed, {} removed",
            header.version, s.added, s.changed, s.removed
        ));
        self.forget(&removed);
        self.deps.manager.reload();
        self.applied();
        self.update_pending_keys();
        if let Some(text) = update_text(&next.name, &s) {
            let moved = moved_servers(catalog_id, &opened.payload, &servers_before);
            let text = if moved.is_empty() {
                text
            } else {
                format!("{text}. {}", l10n::tr("Server changed: %@", &[Arg::Str(&moved.join(", "))]))
            };
            self.notify(catalog_id, text);
        }
        RefreshResult::Applied(s)
    }

    /// The server of each of the catalog's connections as stored now (by local id), before an apply.
    fn servers_before(&self, catalog_id: Uuid, payload: &CatalogPayload) -> HashMap<Uuid, Option<String>> {
        self.read(|v| {
            let mut out = HashMap::new();
            let stored: HashMap<Uuid, _> = v.connections()?.into_iter().map(|s| (s.connection.id, s)).collect();
            for c in &payload.connections {
                let local = local_id(catalog_id, CatalogItemKind::Connection, c.id);
                let Some(stored) = stored.get(&local) else { continue };
                let config = v.config(&local)?;
                let kind = stored.connection.kind;
                out.insert(local, importer::server_host(kind, stored.connection.native.as_ref(), &config));
            }
            Ok(out)
        })
        .unwrap_or_default()
    }

    /// Records a refused refresh: the status, the failure count for transport problems and failures, and one
    /// notification when the status changes into a problem.
    fn refused(&self, record: &SubscriptionRecord, e: CatalogError, now: macvpn_core::date::Date) -> RefreshResult {
        let (status, counts) = match &e {
            CatalogError::Unavailable(_) => (SubscriptionStatus::Unavailable, true),
            CatalogError::Rollback { offered, .. } => {
                (SubscriptionStatus::RollbackRefused { offered: *offered }, false)
            }
            CatalogError::WrongTeamKey => (SubscriptionStatus::TeamKeyChanged, false),
            other => (SubscriptionStatus::Failed(other.kind().unwrap_or(CatalogErrorKind::Io)), true),
        };
        let stored = self.store(record, |r| {
            r.last_attempt = Some(now);
            r.status = status;
            r.failures = if counts { r.failures.saturating_add(1) } else { 0 };
        });
        let kind = match status {
            SubscriptionStatus::Failed(kind) => kind.as_str(),
            SubscriptionStatus::Unavailable => "unavailable",
            SubscriptionStatus::RollbackRefused { .. } => "rollback",
            _ => "wrong_team_key",
        };
        self.log(&format!("{} refused: {kind}", uuid_string(&record.catalog_id)));
        if !stored {
            // The status was not recorded (the vault locked meanwhile): no notice either, or it would repeat.
            if !self.deps.vault.is_unlocked() {
                return RefreshResult::Locked;
            }
            return RefreshResult::Refused(e);
        }
        if status != record.status
            && let Some(text) = notice_text(record, status)
        {
            self.notify(record.catalog_id, text);
        }
        RefreshResult::Refused(e)
    }

    /// `false`: the write was dropped (locked, or a vault error).
    fn store(&self, record: &SubscriptionRecord, f: impl FnOnce(&mut SubscriptionRecord)) -> bool {
        self.deps.vault.with(|v| v.update_subscription_state(record.catalog_id, f)).is_ok()
    }

    // MARK: changes

    /// A new team key, bearer token or source. The stored validators are dropped, so the next refresh downloads
    /// the catalog again. A source on another origin (host and port, or a file) drops the stored bearer token: a
    /// token is never sent to a host it was not entered for, and the UI asks for a new one.
    pub fn update_subscription(&self, catalog_id: Uuid, change: SubscriptionChange) -> Result<(), VaultError> {
        let _serial = guard(&self.serial);
        let reset = |r: &mut SubscriptionRecord| r.validators = SourceValidators::default();
        self.deps.vault.with(|v| match &change {
            SubscriptionChange::TeamKey(key) => {
                v.set_subscription_team_key(catalog_id, key)?;
                v.update_subscription_state(catalog_id, reset)
            }
            SubscriptionChange::Bearer(token) => {
                v.set_subscription_bearer(catalog_id, token.as_deref().map(String::as_str))?;
                v.update_subscription_state(catalog_id, reset)
            }
            SubscriptionChange::Source(source) => {
                let old = v.subscription(catalog_id)?.map(|r| r.source);
                let same_origin = match (&old, source) {
                    (Some(CatalogSource::Https(a)), CatalogSource::Https(b)) => a.origin() == b.origin(),
                    _ => false,
                };
                if !same_origin {
                    v.set_subscription_bearer(catalog_id, None)?;
                }
                v.update_subscription_state(catalog_id, |r| {
                    r.source = source.clone();
                    reset(r);
                })
            }
        })?;
        let what = match change {
            SubscriptionChange::TeamKey(_) => "team key",
            SubscriptionChange::Bearer(_) => "access token",
            SubscriptionChange::Source(_) => "source",
        };
        self.log(&format!("{} {what} changed", uuid_string(&catalog_id)));
        Ok(())
    }

    /// Unsubscribes (spec 6): the active catalog connections are disconnected first (waiting up to
    /// [`DISCONNECT_WAIT`] for each), then everything of the catalog is removed; filled slot credentials stay.
    pub fn unsubscribe(&self, catalog_id: Uuid) -> Result<UnsubscribeReport, CatalogServiceError> {
        let _serial = guard(&self.serial);
        let local = self.read(|v| v.local_catalog(catalog_id))?;
        let manager = &self.deps.manager;
        let wait = *guard(&self.disconnect_wait);
        for id in connection_ids(&local) {
            let key = uuid_string(&id);
            if !manager.state(&key).is_active() {
                continue;
            }
            if let Some(ConnectionItem::Managed(c)) = manager.item(&key) {
                manager.disconnect(&c);
            }
            let deadline = Instant::now() + wait;
            while manager.state(&key).is_active() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
                manager.refresh();
            }
        }
        let active = active_ids(manager);
        let plan = plan_unsubscribe(&local);
        let report = self
            .with_same_active(&active, |v| v.unsubscribe_catalog(catalog_id, &plan, &active))
            .map_err(|e| match e {
                VaultError::Constraint(_) if connection_ids(&local).iter().any(|i| active.contains(i)) => {
                    CatalogServiceError::StillActive
                }
                e => e.into(),
            })?
            // A catalog connection came up meanwhile.
            .ok_or(CatalogServiceError::StillActive)?;
        self.forget(&report.removed_connections);
        self.log(&format!("{} unsubscribed", uuid_string(&catalog_id)));
        manager.reload();
        self.update_pending_keys();
        Ok(report)
    }

    /// "Duplicate as personal connection" (spec 6).
    pub fn duplicate(&self, local_id: Uuid, name: &str) -> Result<Uuid, VaultError> {
        let id = self.deps.vault.with(|v| v.duplicate_catalog_connection(local_id, name))?;
        self.deps.manager.reload();
        self.applied();
        Ok(id)
    }

    /// Deletes the removed connections that are no longer up (from the state listener, and at the start of every
    /// scheduler round while unlocked).
    pub fn process_pending_removals(&self) {
        let _serial = guard(&self.serial);
        let Ok(records) = self.read(|v| v.subscriptions()) else { return };
        let empty = empty_payload();
        let mut removed_any = false;
        for record in records {
            let active = active_ids(&self.deps.manager);
            let Ok(local) = self.read(|v| v.local_catalog(record.catalog_id)) else { continue };
            let plan = plan_pending(&local, &active);
            if plan.is_empty() {
                continue;
            }
            let ctx = ApplyContext { catalog_id: record.catalog_id, payload: &empty, now: self.deps.clock.now() };
            // A connection that came up meanwhile stays: the next state change runs this again.
            if let Ok(Some(removed)) = self.with_same_active(&active, |v| v.apply_catalog(&plan, &ctx, &record)) {
                self.log(&format!(
                    "{} removed {} connection(s) after disconnect",
                    uuid_string(&record.catalog_id),
                    removed.len()
                ));
                self.forget(&removed);
                removed_any = true;
            }
        }
        if removed_any {
            self.deps.manager.reload();
        }
        self.update_pending_keys();
    }

    // MARK: views

    /// The "Team catalogs" section. Empty while locked.
    pub fn view(&self) -> Vec<SubscriptionView> {
        self.read(|v| {
            let mut out = Vec::new();
            for record in v.subscriptions()? {
                let local = v.local_catalog(record.catalog_id)?;
                let mut slots = Vec::new();
                for (name, credential) in local.slots.values() {
                    let found = match credential {
                        Some(c) => v.credential(*c)?,
                        None => None,
                    };
                    slots.push(SlotView {
                        name: name.clone(),
                        filled: found.as_ref().is_some_and(|c| !c.username.is_empty() || c.has_password),
                        credential_name: found.map(|c| c.name),
                    });
                }
                out.push(SubscriptionView {
                    id: uuid_string(&record.catalog_id),
                    name: record.name.clone(),
                    source: record.source.redacted(),
                    fingerprint: record.pinned.to_text(),
                    version: record.applied_version,
                    status: status_name(record.status),
                    last_refresh: record.last_attempt.map(|d| d.time_interval_since_1970()),
                    last_success: record.last_success.map(|d| d.time_interval_since_1970()),
                    error: status_text(&record),
                    has_token: record.has_bearer,
                    slots,
                });
            }
            Ok(out)
        })
        .unwrap_or_default()
    }

    /// The "Team" badges of the catalog connections, by connection key. Empty while locked.
    pub fn badges(&self) -> HashMap<String, CatalogBadge> {
        self.read(|v| {
            let mut out = HashMap::new();
            for record in v.subscriptions()? {
                for id in connection_ids(&v.local_catalog(record.catalog_id)?) {
                    let key = uuid_string(&id);
                    if let Some(owner) = v.catalog_owner(&key)? {
                        out.insert(
                            key,
                            CatalogBadge {
                                catalog_id: uuid_string(&owner.catalog_id),
                                name: owner.catalog_name,
                                pending_removal: owner.pending_removal,
                                profile_outdated: owner.profile_outdated,
                            },
                        );
                    }
                }
            }
            Ok(out)
        })
        .unwrap_or_default()
    }

    /// "Managed by the team catalog “…”" for a catalog-owned connection or folder (the read-only editors); `None`
    /// for the user's own.
    pub fn read_only_reason(&self, key: &str) -> Option<String> {
        let owner = self.read(|v| v.catalog_owner(key)).ok().flatten()?;
        Some(l10n::tr("Managed by the team catalog “%@”", &[Arg::Str(&owner.catalog_name)]))
    }

    // MARK: schedule (plan Task 12)

    /// Asks the scheduler for a refresh of every subscription now: on wake from sleep ([`RefreshTrigger::Wake`])
    /// or after an unlock ([`RefreshTrigger::Unlock`]).
    pub fn request(&self, trigger: RefreshTrigger) {
        guard(&self.schedule).requested = Some(trigger);
        self.schedule_signal.notify_all();
    }

    /// A subscription was fetched outside a scheduler round (subscribed, "Refresh now"): the timer counts from now.
    fn attempted(&self, catalog_id: Uuid) {
        guard(&self.schedule).last.insert(catalog_id, Instant::now());
    }

    /// The Mac woke from sleep.
    pub fn wake(&self) {
        self.request(RefreshTrigger::Wake);
    }

    /// The vault was unlocked.
    pub fn unlocked(&self) {
        self.request(RefreshTrigger::Unlock);
    }

    /// The scheduler thread: [`Self::run_scheduler`] with the real clock and [`Self::wait_for_trigger`]. The
    /// app joins the handle at quit after [`Self::stop_scheduler`].
    pub fn start_scheduler(&self) -> std::thread::JoinHandle<()> {
        let this = self.this.upgrade().expect("the catalog service is alive");
        std::thread::Builder::new()
            .name("macvpn-catalog-scheduler".into())
            .spawn(move || this.run_scheduler(Instant::now, |d| this.wait_for_trigger(d)))
            .expect("catalog scheduler thread")
    }

    fn scheduler_stopped(&self) -> bool {
        guard(&self.schedule).stopped
    }

    /// Ends [`Self::run_scheduler`] promptly: a waiting scheduler wakes at once, a running round stops before its
    /// next subscription, and a scheduler not started yet never runs a round.
    pub fn stop_scheduler(&self) {
        guard(&self.schedule).stopped = true;
        self.schedule_signal.notify_all();
    }

    /// The production wait of [`Self::run_scheduler`]: up to `timeout` for a request. `None`: stopped;
    /// `Some(None)`: the time passed; `Some(Some(trigger))`: requested.
    pub fn wait_for_trigger(&self, timeout: Duration) -> Option<Option<RefreshTrigger>> {
        let mut state = guard(&self.schedule);
        if state.requested.is_none() && !state.stopped {
            state = self.schedule_signal.wait_timeout(state, timeout).unwrap_or_else(PoisonError::into_inner).0;
        }
        if state.stopped {
            return None;
        }
        Some(state.requested.take())
    }

    fn jitter(&self, id: Uuid, failures: u32) -> f64 {
        (self.jitter_seed.hash_one((id, failures)) % 10_000) as f64 / 10_000.0 * MAX_JITTER
    }

    /// One scheduler round: every subscription that is due for `trigger` is refreshed, one after another (each
    /// fetch has its own timeout). Nothing runs while the vault is locked. Every round first deletes the
    /// pending removals that went down while nothing watched (before the launch, while locked).
    pub fn tick(&self, trigger: RefreshTrigger, now: Instant) -> Vec<(Uuid, RefreshResult)> {
        if !self.deps.vault.is_unlocked() {
            return Vec::new();
        }
        // Removals that went down while nothing watched (before a launch, while locked).
        self.process_pending_removals();
        let Ok(records) = self.read(|v| v.subscriptions()) else { return Vec::new() };
        let mut results = Vec::new();
        for record in records {
            if self.scheduler_stopped() {
                break;
            }
            let id = record.catalog_id;
            let last = guard(&self.schedule).last.get(&id).copied();
            let next = next_attempt(last, record.failures, self.jitter(id, record.failures));
            if !is_due(trigger, next, now) {
                continue;
            }
            let result = self.refresh(id, trigger);
            if result == RefreshResult::Locked {
                break;
            }
            guard(&self.schedule).last.insert(id, now);
            results.push((id, result));
        }
        results
    }

    /// The scheduler loop (one thread; the update scheduler's pattern): a [`RefreshTrigger::Launch`] round first,
    /// then a round every time `wait` returns: the requested trigger, or [`RefreshTrigger::Timer`] after
    /// [`SCHEDULER_WAKE`]. `wait` returns `None` to stop ([`Self::wait_for_trigger`] in the app). A manual
    /// "Refresh now" runs in the caller's task through [`Self::refresh`], not here.
    pub fn run_scheduler(
        &self,
        now: impl Fn() -> Instant,
        mut wait: impl FnMut(Duration) -> Option<Option<RefreshTrigger>>,
    ) {
        let mut trigger = RefreshTrigger::Launch;
        loop {
            // A stop before the start skips even the launch round.
            if self.scheduler_stopped() {
                return;
            }
            self.tick(trigger, now());
            match wait(SCHEDULER_WAKE) {
                None => return,
                Some(requested) => trigger = requested.unwrap_or(RefreshTrigger::Timer),
            }
        }
    }
}
