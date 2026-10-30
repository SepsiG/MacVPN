//! The connection manager (port of `ConnectionManager.swift`): the state of every managed connection and system
//! VPN, connect / disconnect with operation tokens, status polling with drop detection and sticky failures, the
//! MFA prompts (spec 10f) and the usage ranking (spec 10e).
//!
//! # Concurrency
//!
//! The Swift manager is a `@MainActor` class: the code between two `await`s runs atomically, and several
//! operations (a refresh, a connect, a disconnect) interleave at their `await`s. Here every method is blocking
//! and takes `&self`; the state lives behind one mutex, and each Swift "segment between awaits" is one locked
//! section. The mutex is never held while a dependency (sudo, scutil, the Keychain, the prompt UI) is called, so
//! several threads can run operations concurrently with exactly the Swift interleaving rules: the
//! `epoch` / `key_epoch` tokens decide which result may still be applied. Hooks (events, change notifications,
//! prompts) are called without the lock too, so they may call back into the manager.

use crate::deps::{
    AuthStateReader, Clock, ConnectionRepository, FolderOp, FolderStore, HelperClient, NativeController, NativeSupport,
    NoAuthState, Placement, RankingPersistence, SecretField, SecretReader, SecretWriter, SystemClock,
    SystemOTPPersistence, SystemVpn,
};
use macvpn_core::credentials::{
    self, CredentialAnswer, CredentialField, CredentialPrompt, CredentialValues, RequiredFields,
};
use macvpn_core::date::Date;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::mfa::{
    self, AuthPrompt, AuthPromptKind, AuthPromptResult, AuthResponseKind, AuthUIMethod, AuthUIState, AuthUIStateKind,
    PromptDeadline, WebAuthURL,
};
use macvpn_core::models::{
    AuthWait, AuthWaitKind, Connection, ConnectionState, OTPSetting, Secrets, VPNKind, uuid_string,
};
use macvpn_core::native::NativeKind;
use macvpn_core::ranking::ConnectionRanking;
use macvpn_core::validators::{ConfigValidator, OpenVPNValidator, SSTPConfig, SSTPValidator};
use macvpn_core::vault::{FolderNode, FolderTree, TreeEntry, order_tree};
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, Weak};
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

/// A failure or a drop, reported to the UI (notifications) after the new state is visible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ConnectionEvent {
    Failed { connection_id: String, name: String, reason: String },
    Dropped { connection_id: String, name: String },
}

/// A row of the menu and of the Connections window: a managed connection or a system VPN that the app does not
/// manage.
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionItem {
    Managed(Connection),
    System(SystemVpn),
}

impl ConnectionItem {
    /// The key of the states and of the ranking: the managed connection's UUID string or the scutil service ID.
    pub fn id(&self) -> String {
        match self {
            ConnectionItem::Managed(c) => uuid_string(&c.id),
            ConnectionItem::System(s) => s.id.clone(),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            ConnectionItem::Managed(c) => &c.name,
            ConnectionItem::System(s) => &s.name,
        }
    }
}

/// A connected tunnel whose traffic the app reads ([`ConnectionManager::tunnels`]).
#[derive(Debug, Clone, PartialEq)]
pub struct Tunnel {
    /// The row's key (a managed connection's UUID string, a system VPN's service ID).
    pub key: String,
    pub source: TunnelSource,
}

/// Where a tunnel's counters are asked.
#[derive(Debug, Clone, PartialEq)]
pub enum TunnelSource {
    /// A root-backed (helper) kind, with what the helper last reported.
    Helper { id: Uuid, kind: VPNKind, iface: Option<String>, ip: Option<String>, since: Option<f64> },
    /// A native service (managed native connection or system VPN).
    Native { service_id: String },
}

/// How a managed native connection maps to the listed services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeMatch {
    Service(SystemVpn),
    None,
    /// No bound ID, and more than one service has the name.
    Ambiguous(Vec<SystemVpn>),
}

/// The platform's own service for `c` ([`NativeController::managed_service_id`]; WinVPN: its RAS entry) first;
/// then the bound ID: only that counts (vanished: `None`); otherwise the name, with a unique match.
pub fn match_service(c: &Connection, services: &[SystemVpn], native: &dyn NativeController) -> NativeMatch {
    if let Some(id) = native.managed_service_id(&c.id) {
        return services.iter().find(|s| s.id == id).cloned().map_or(NativeMatch::None, NativeMatch::Service);
    }
    if let Some(id) = &c.native_service_id {
        return services.iter().find(|s| &s.id == id).cloned().map_or(NativeMatch::None, NativeMatch::Service);
    }
    let name = c.native_service_name.as_deref().unwrap_or(&c.name);
    let named: Vec<SystemVpn> = services.iter().filter(|s| s.name == name).cloned().collect();
    match named.len() {
        0 => NativeMatch::None,
        1 => NativeMatch::Service(named[0].clone()),
        _ => NativeMatch::Ambiguous(named),
    }
}

/// What a locked manager keeps of an active connection: the id, the kind, the bound native service ID (and, for a
/// native connection not bound yet, its service name, which the status match needs); never the name or a setting.
fn redacted(c: &Connection) -> Connection {
    let mut kept = Connection::with_id(c.id, String::new(), c.kind, c.created_at);
    kept.native_service_id.clone_from(&c.native_service_id);
    if c.kind.is_native() && c.native_service_id.is_none() {
        kept.native_service_name = Some(c.native_service_name.clone().unwrap_or_else(|| c.name.clone()));
    }
    kept
}

/// The service IDs of the managed native connections (these are not shown as system VPNs). For an unbound
/// connection, every service with its name. A connection of any kind with a platform-made service
/// ([`NativeController::managed_service_id`]; WinVPN: the RAS entries of IKEv2 and SSTP too) has that one.
pub fn managed_service_ids(
    connections: &[Connection],
    services: &[SystemVpn],
    native: &dyn NativeController,
) -> HashSet<String> {
    let mut ids = HashSet::new();
    for c in connections.iter().filter(|c| c.kind.is_native() || native.managed_service_id(&c.id).is_some()) {
        match match_service(c, services, native) {
            NativeMatch::Service(s) => {
                ids.insert(s.id);
            }
            NativeMatch::Ambiguous(all) => ids.extend(all.into_iter().map(|s| s.id)),
            NativeMatch::None => {}
        }
    }
    ids
}

pub const NATIVE_GRACE: f64 = 5.0;
pub const NATIVE_TIMEOUT: f64 = 45.0;
pub const STATUS_ERROR_THRESHOLD: u32 = 3;

pub fn server_mismatch_reason(name: &str) -> String {
    l10n::tr(
        "The server address of the VPN service named “%@” does not match this connection’s server. MacVPN does not pass the password or the PSK to it: reinstall the profile in MacVPN → Connections, or remove the other service in System Settings → Network.",
        &[Arg::Str(name)],
    )
}

pub fn native_failure_reason() -> String {
    l10n::tr("The connection could not be established – for details, connect in debug mode", &[])
}

pub fn auth_timeout_reason() -> String {
    l10n::tr("Authentication was not completed in time", &[])
}

/// A team catalog changed a native connection's settings (spec 6): the old profile is not used, the connect offers
/// the reinstall ("Install profile") first.
pub fn profile_outdated_reason() -> String {
    l10n::tr("The team catalog changed this connection: reinstall its profile", &[])
}

/// A team catalog's SSTP connection with its credential slot (spec 6, plan "Per-user fields"): the user name lives in
/// the config's `user=` line, so the slot's user name replaces it in memory before the config goes to the root
/// layer. The stored config is not changed. A user name the line cannot carry is refused with the validator's text,
/// and so is a stored config with any issue: parsing and serializing it would silently drop what the validator
/// refuses and send a config nobody validated.
fn sstp_with_user(config: &str, username: &str) -> Result<String, String> {
    if let Some(issue) = SSTPValidator.validate(config).into_iter().next() {
        return Err(issue.display());
    }
    if let Some(error) = SSTPValidator::user_error(username) {
        return Err(error);
    }
    let mut parsed = SSTPConfig::parse(config);
    parsed.user = username.to_string();
    Ok(parsed.serialized())
}

/// The failure reason after the user cancelled (or declined) an MFA prompt during `up`.
pub fn auth_cancelled_reason() -> String {
    l10n::tr("Authentication cancelled", &[])
}

fn timed_out() -> String {
    l10n::tr("Timed out", &[])
}

fn secret_field(field: CredentialField) -> SecretField {
    match field {
        CredentialField::Username => SecretField::Username,
        CredentialField::Password => SecretField::Password,
        CredentialField::Psk => SecretField::Psk,
        CredentialField::KeyPassword => SecretField::KeyPassword,
    }
}

fn stored_value(secrets: &Secrets, field: CredentialField) -> Option<&str> {
    match field {
        CredentialField::Username => secrets.username.as_deref(),
        CredentialField::Password => secrets.password.as_deref(),
        CredentialField::Psk => secrets.psk.as_deref(),
        CredentialField::KeyPassword => secrets.key_password.as_deref(),
    }
}

/// The re-prompt after a sign-in failure: the required user name and password again, plus a required PSK / key
/// password that is not stored (a stored one is not asked again).
fn retry_fields(required: &RequiredFields, stored: &Secrets) -> Vec<CredentialField> {
    let missing = credentials::missing(required, stored);
    required
        .fields
        .iter()
        .copied()
        .filter(|f| matches!(f, CredentialField::Username | CredentialField::Password) || missing.contains(f))
        .collect()
}

/// OpenVPN: the error message if the config has risky directives that are not acknowledged (the root layer would
/// refuse too, but this is clearer). `None`: fine, or the config cannot be read (the root layer decides).
pub fn unacknowledged_risk_reason(c: &Connection, config: Option<&str>) -> Option<String> {
    let config = config?;
    let acknowledged: HashSet<String> = c.acknowledged_risky_directives.iter().cloned().collect();
    let result = OpenVPNValidator.validate_full(config, &acknowledged);
    if result.unacknowledged.is_empty() {
        return None;
    }
    Some(l10n::tr(
        "Risky settings are not acknowledged: %@. Open the connection in MacVPN → Connections and tick the checkbox under Risky settings.",
        &[Arg::Str(&result.unacknowledged.join(", "))],
    ))
}

#[derive(Debug, Clone, PartialEq)]
enum Op {
    Connecting,
    Disconnecting,
    AwaitingNative { started: Date, saw_connecting: bool, service_id: String },
}

pub type EventHook = Arc<dyn Fn(ConnectionEvent) + Send + Sync>;
pub type ServicesSeenHook = Arc<dyn Fn(&HashSet<Uuid>) + Send + Sync>;
/// Blocks until the user answered (or the prompt was dismissed / timed out).
pub type PromptHandler = Arc<dyn Fn(AuthPrompt) -> AuthPromptResult + Send + Sync>;
pub type DismissHook = Arc<dyn Fn(&str) + Send + Sync>;
/// Blocks until the user answered the credential prompt (or it was dismissed / expired: `Cancelled`).
pub type CredentialHandler = Arc<dyn Fn(CredentialPrompt) -> CredentialAnswer + Send + Sync>;
pub type ChangeHook = Arc<dyn Fn() + Send + Sync>;
/// A connection's state changed (its key and the new state).
pub type StateListener = Arc<dyn Fn(&str, &ConnectionState) + Send + Sync>;
/// The user disconnected a connection by hand (its key).
pub type UserDisconnectListener = Arc<dyn Fn(&str) + Send + Sync>;

/// Why a connection is disconnected. Only [`DisconnectCause::User`] reaches the user-disconnect listeners: the
/// control API treats it as "the user wins" and ends every lease on the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectCause {
    /// The user asked for it (the menu, the Connections window, the quit question, deleting the connection).
    User,
    /// The control API's last lease on the connection ended.
    Lease,
    /// No physical network for `reconnect::OFFLINE_GRACE` (the network loss rule): not the user's, so
    /// auto-reconnect may bring it back when the network is; leases on it end as on a drop.
    NoNetwork,
    /// The tunnel stopped answering while the network is there (dead-tunnel detection): not the user's, so
    /// auto-reconnect may bring it back; leases on it end as on a drop.
    NotResponding,
}

#[derive(Default, Clone)]
struct Hooks {
    on_event: Option<EventHook>,
    on_native_services_seen: Option<ServicesSeenHook>,
    native_support: Option<Arc<dyn NativeSupport>>,
    prompt_handler: Option<PromptHandler>,
    dismiss_prompt: Option<DismissHook>,
    credential_handler: Option<CredentialHandler>,
    dismiss_credentials: Option<DismissHook>,
    on_change: Option<ChangeHook>,
    state_listeners: Vec<StateListener>,
    user_disconnect_listeners: Vec<UserDisconnectListener>,
}

/// The manager's dependencies.
#[derive(Clone)]
pub struct Dependencies {
    pub store: Arc<dyn ConnectionRepository>,
    pub secrets: Arc<dyn SecretReader>,
    pub helper: Arc<dyn HelperClient>,
    pub native: Arc<dyn NativeController>,
    pub ranking_store: Option<Arc<dyn RankingPersistence>>,
    pub system_otp_store: Option<Arc<dyn SystemOTPPersistence>>,
    pub auth_state: Arc<dyn AuthStateReader>,
    pub clock: Arc<dyn Clock>,
    /// Where "Save" of the credential prompt writes, once the connection is up (`None`: nothing is saved).
    pub secret_writer: Option<Arc<dyn SecretWriter>>,
    /// The folders and placements (spec 3). `None`: no folders, every item at the root (as in 1.1).
    pub folders: Option<Arc<dyn FolderStore>>,
}

impl Dependencies {
    /// No ranking / system OTP persistence, no MFA state file, the system clock, no credential saving.
    pub fn new(
        store: Arc<dyn ConnectionRepository>,
        secrets: Arc<dyn SecretReader>,
        helper: Arc<dyn HelperClient>,
        native: Arc<dyn NativeController>,
    ) -> Self {
        Dependencies {
            store,
            secrets,
            helper,
            native,
            ranking_store: None,
            system_otp_store: None,
            auth_state: Arc::new(NoAuthState),
            clock: Arc::new(SystemClock),
            secret_writer: None,
            folders: None,
        }
    }
}

struct Watcher {
    id: u64,
    stop: Arc<AtomicBool>,
}

/// The values typed into the credential prompt with "Save" ticked, written once the connect reached `connected`
/// (never before: a wrong password is never stored). Dropping it wipes the values.
struct PendingSave {
    id: Uuid,
    values: CredentialValues,
    /// Each typed field's stored value when the prompt was answered (empty: none). A field whose stored value
    /// changed meanwhile (the editor saved it during the connect) is not overwritten: the editor wins.
    prior: Vec<(CredentialField, Zeroizing<String>)>,
    /// A managed native connection: a typed user name also becomes its `native.account`, if the account is still
    /// the one it was when the prompt was answered (`prior_account`).
    native: bool,
    prior_account: String,
}

/// What [`ConnectionManager::credential_secrets`] gives the connect path. The secrets are wiped on drop, so an
/// early return (or a panic) never leaves them behind.
struct Prepared {
    secrets: Zeroizing<Secrets>,
    save: Option<PendingSave>,
}

#[derive(Default)]
struct Inner {
    connections: Vec<Connection>,
    /// Only the system VPNs the app does not manage.
    system_services: Vec<SystemVpn>,
    /// Every service ID of the last successful listing, managed ones included.
    listed_service_ids: HashSet<String>,
    states: HashMap<String, ConnectionState>,
    /// Set after several consecutive failed status queries.
    status_error: Option<String>,
    /// The managed native connections installed according to the last successful listing.
    installed_native_ids: HashSet<Uuid>,
    ranking: ConnectionRanking,
    system_otp: HashMap<String, OTPSetting>,
    auth_waits: HashMap<String, AuthWait>,
    auth_watchers: HashMap<String, Watcher>,
    /// The prompt expired (2 minutes / the server's deadline): the error text says so.
    auth_timed_out: HashSet<String>,
    /// The user cancelled (or declined) a prompt during this connect: a failing `up` says so.
    auth_cancelled: HashSet<String>,
    ops: HashMap<String, Op>,
    /// The user last asked to disconnect (a new connect clears it): a late successful up must be torn down.
    want_down: HashSet<String>,
    queued_events: Vec<ConnectionEvent>,
    /// Monotonic counter: every operation change and every refresh start takes one.
    epoch: u64,
    last_applied: u64,
    key_epoch: HashMap<String, u64>,
    failure_streak: u32,
    /// `scutil --nc show` results per service (for binding). `reload` clears it.
    remote_addresses: HashMap<String, Option<String>>,
    /// User-started connects that have not reached `connected` yet. The first transition to `connected` scores 1
    /// point and removes the key: later refreshes and connects not started by the user do not count.
    awaiting_success: HashSet<String>,
    /// A `reload` succeeded: before that the list is empty, so ranking entries must not be pruned.
    loaded: bool,
    /// Credential prompt values to save when the key's connect reaches `connected` (see [`PendingSave`]).
    pending_saves: HashMap<String, PendingSave>,
    /// The folders (spec 3), as last loaded from the folder store.
    folders: Vec<FolderNode>,
    /// The placed items (a folder or an own colour) by key; every other item is at the root without a colour.
    placements: HashMap<String, Placement>,
    /// Pending saves whose connect has just connected: written by the refresh, outside the lock.
    ready_saves: Vec<PendingSave>,
    /// Deleted connections ([`ConnectionManager::forget_saves`]): no "Save" is ever written for them.
    forgotten: HashSet<Uuid>,
    /// The key's last connect ended because the credential prompt was cancelled or expired (a new connect clears
    /// it). The control API reports it as `credentials_cancelled`.
    credentials_cancelled: HashSet<String>,
    /// The vault is locked ([`ConnectionManager::enter_locked`]): only the active connections are kept, redacted.
    locked: bool,
    /// The tunnel interface the helper last reported for a connected root-backed connection (live traffic).
    ifaces: HashMap<String, String>,
    /// When a native service (managed or a system VPN) was seen to connect: only a connect this app saw (a service
    /// already up at the first refresh has no time).
    native_since: HashMap<String, Date>,
}

impl Inner {
    fn key_epoch(&self, key: &str) -> u64 {
        self.key_epoch.get(key).copied().unwrap_or(0)
    }

    fn set_op(&mut self, key: &str, op: Option<Op>) {
        match op {
            Some(op) => self.ops.insert(key.to_string(), op),
            None => self.ops.remove(key),
        };
        self.epoch += 1;
        self.key_epoch.insert(key.to_string(), self.epoch);
    }

    /// The latest (bound) copy of the connection.
    fn current(&self, c: &Connection) -> Connection {
        self.connections.iter().find(|x| x.id == c.id).cloned().unwrap_or_else(|| c.clone())
    }

    fn state(&self, key: &str) -> ConnectionState {
        self.states.get(key).cloned().unwrap_or(ConnectionState::Disconnected)
    }

    /// After a late up / start: the user who asked to disconnect sees `disconnected`.
    fn settle_after_teardown(&mut self, key: &str) {
        if self.want_down.contains(key) && !self.ops.contains_key(key) {
            self.states.insert(key.to_string(), ConnectionState::Disconnected);
        }
    }

    /// The "waiting for authentication" state (`None`: back to `connecting`).
    fn set_awaiting(&mut self, key: &str, wait: Option<AuthWait>) {
        match wait {
            Some(wait) => {
                self.auth_waits.insert(key.to_string(), wait);
                self.states.insert(key.to_string(), ConnectionState::AwaitingAuth(wait));
            }
            None => {
                self.auth_waits.remove(key);
                if matches!(self.states.get(key), Some(ConnectionState::AwaitingAuth(_))) {
                    self.states.insert(key.to_string(), ConnectionState::Connecting);
                }
            }
        }
    }

    /// Drop detection and sticky failure. `native_like`: after a drop `disconnected`, not `failed`.
    fn resolve(
        &mut self,
        key: &str,
        name: &str,
        previous: Option<&ConnectionState>,
        current: ConnectionState,
        native_like: bool,
    ) -> ConnectionState {
        if previous.is_some_and(ConnectionState::is_connected)
            && matches!(current, ConnectionState::Failed(_) | ConnectionState::Disconnected)
        {
            self.queued_events
                .push(ConnectionEvent::Dropped { connection_id: key.to_string(), name: name.to_string() });
            return if native_like {
                ConnectionState::Disconnected
            } else {
                ConnectionState::Failed(l10n::tr("The connection dropped", &[]))
            };
        }
        if let Some(previous @ ConnectionState::Failed(_)) = previous
            && matches!(current, ConnectionState::Failed(_) | ConnectionState::Disconnected)
        {
            return previous.clone();
        }
        current
    }

    /// A native service's state with its tunnel address and the time this app saw it connect.
    fn native_details(
        &mut self,
        key: &str,
        previous: Option<&ConnectionState>,
        current: ConnectionState,
        address: Option<&String>,
        now: Date,
    ) -> ConnectionState {
        if !current.is_connected() {
            self.native_since.remove(key);
            return current;
        }
        if previous.is_some_and(|p| !p.is_connected()) {
            self.native_since.entry(key.to_string()).or_insert(now);
        }
        ConnectionState::Connected { ip: address.cloned(), since: self.native_since.get(key).copied() }
    }

    fn fail_native(&mut self, key: &str, name: &str, reason: String) -> ConnectionState {
        self.set_op(key, None);
        self.awaiting_success.remove(key);
        self.queued_events.push(ConnectionEvent::Failed {
            connection_id: key.to_string(),
            name: name.to_string(),
            reason: reason.clone(),
        });
        ConnectionState::Failed(reason)
    }

    /// The pending native start (`AwaitingNative`) against the fresh scutil state. `None`: no pending start, or
    /// it just connected – the caller uses the service's state.
    fn evaluate_awaiting(
        &mut self,
        key: &str,
        name: &str,
        service: Option<&SystemVpn>,
        now: Date,
        failure_reason: impl FnOnce() -> String,
        to_stop: &mut Vec<String>,
    ) -> Option<ConnectionState> {
        let Some(Op::AwaitingNative { started, saw_connecting, service_id }) = self.ops.get(key).cloned() else {
            return None;
        };
        let elapsed = now.time_interval_since(started);
        match service.map(SystemVpn::connection_state) {
            Some(ConnectionState::Connected { .. }) => {
                self.set_op(key, None);
                None
            }
            Some(ConnectionState::Connecting) => {
                self.ops.insert(
                    key.to_string(),
                    Op::AwaitingNative { started, saw_connecting: true, service_id: service_id.clone() },
                );
                if elapsed > NATIVE_TIMEOUT {
                    to_stop.push(service_id);
                    return Some(self.fail_native(key, name, timed_out()));
                }
                Some(ConnectionState::Connecting)
            }
            _ => {
                if saw_connecting || elapsed > NATIVE_GRACE {
                    return Some(self.fail_native(key, name, failure_reason()));
                }
                Some(ConnectionState::Connecting)
            }
        }
    }

    fn ordered_items(&self, now: Date) -> Vec<ConnectionItem> {
        let items: Vec<ConnectionItem> = self
            .connections
            .iter()
            .cloned()
            .map(ConnectionItem::Managed)
            .chain(self.system_services.iter().cloned().map(ConnectionItem::System))
            .collect();
        let mut by_id: HashMap<String, ConnectionItem> = HashMap::new();
        let mut ids = Vec::with_capacity(items.len());
        for item in items {
            let id = item.id();
            ids.push(id.clone());
            by_id.entry(id).or_insert(item);
        }
        self.ranking
            .order(&ids, now, |id| by_id.get(id).map(|i| i.name().to_string()).unwrap_or_default())
            .into_iter()
            .filter_map(|id| by_id.get(&id).cloned())
            .collect()
    }

    fn has_active(&self) -> bool {
        self.states.values().any(ConnectionState::is_active)
    }

    /// The folder tree; a stored tree that is not one (never written by the stores) shows everything at the root.
    fn folder_tree(&self) -> FolderTree {
        FolderTree::new(self.folders.clone()).unwrap_or_default()
    }

    /// Per folder (and the root): the subfolders by position, then the items in the ranking order (spec 3).
    fn ordered_tree(&self, tree: &FolderTree, now: Date) -> Vec<TreeEntry> {
        let items: Vec<(String, Option<Uuid>)> = self
            .ordered_items(now)
            .iter()
            .map(|item| {
                let key = item.id();
                let folder = self.placements.get(&key).and_then(|p| p.folder);
                (key, folder)
            })
            .collect();
        let names: HashMap<String, String> = self
            .connections
            .iter()
            .map(|c| (uuid_string(&c.id), c.name.clone()))
            .chain(self.system_services.iter().map(|s| (s.id.clone(), s.name.clone())))
            .collect();
        let name_of = |key: &str| names.get(key).cloned().unwrap_or_default();
        order_tree(tree, &items, &self.ranking, now, name_of)
    }
}

/// The folder part of a [`ManagerSnapshot`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FolderSnapshot {
    /// A folder store is configured (the UI offers folders).
    pub enabled: bool,
    pub folders: Vec<FolderNode>,
    /// Every folder and item in display order (collapsed folders' contents included).
    pub entries: Vec<TreeEntry>,
    pub placements: HashMap<String, Placement>,
}

/// A consistent copy of everything the UI shows.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ManagerSnapshot {
    /// In ranking order (pinned first).
    pub items: Vec<(ConnectionItem, ConnectionState, bool)>,
    pub status_error: Option<String>,
    pub has_active: bool,
    pub has_failure: bool,
    pub awaiting_auth: bool,
    /// A connection is connecting or reconnecting (not waiting for authentication: [`Self::awaiting_auth`]).
    pub connecting: bool,
    /// The folder tree and the placements (spec 3).
    pub folders: FolderSnapshot,
}

/// What [`ConnectionManager::reload`] reads from the configs, by row id: the server hosts, the platform's reasons
/// it cannot connect, the earliest certificate expiry.
type ConfigFacts = (HashMap<String, String>, HashMap<String, String>, HashMap<String, i64>);

pub struct ConnectionManager {
    deps: Dependencies,
    inner: Mutex<Inner>,
    hooks: RwLock<Hooks>,
    /// The states last delivered to the state listeners. Locked while the listeners run, so every listener sees
    /// the changes in order.
    published: Mutex<HashMap<String, ConnectionState>>,
    this: Weak<ConnectionManager>,
    /// The state file is read this often during an OpenVPN `up` (milliseconds).
    auth_poll_millis: AtomicU64,
    next_watch_id: AtomicU64,
    /// "Save" writer threads running, and their end.
    saves_in_flight: Arc<(Mutex<usize>, std::sync::Condvar)>,
    /// The server hosts of the configs ([`Self::server_hosts`]) by row id: read by [`Self::reload`] (which follows
    /// every save, import, delete, catalog apply, restore and unlock), never while the view model is built.
    server_hosts: RwLock<Arc<HashMap<String, String>>>,
    /// The connections the platform cannot connect with their settings ([`Self::unsupported_reasons`]), by row
    /// id: read by [`Self::reload`] like [`Self::server_hosts`].
    unsupported: RwLock<Arc<HashMap<String, String>>>,
    /// The earliest certificate expiry (`notAfter`, Unix seconds) of each managed connection's config
    /// ([`Self::certificate_expiry`]), by row id: read by [`Self::reload`] like [`Self::server_hosts`].
    certificate_expiry: RwLock<Arc<HashMap<String, i64>>>,
}

impl ConnectionManager {
    pub fn new(deps: Dependencies) -> Arc<Self> {
        let ranking = deps.ranking_store.as_ref().map(|s| s.load()).unwrap_or_default();
        let system_otp = deps.system_otp_store.as_ref().map(|s| s.load()).unwrap_or_default();
        Arc::new_cyclic(|this| ConnectionManager {
            deps,
            inner: Mutex::new(Inner { ranking, system_otp, ..Inner::default() }),
            hooks: RwLock::new(Hooks::default()),
            published: Mutex::new(HashMap::new()),
            this: this.clone(),
            auth_poll_millis: AtomicU64::new(500),
            next_watch_id: AtomicU64::new(1),
            saves_in_flight: Arc::default(),
            server_hosts: RwLock::default(),
            unsupported: RwLock::default(),
            certificate_expiry: RwLock::default(),
        })
    }

    /// The server host of each managed connection whose server is in its config (OpenVPN's first `remote`,
    /// WireGuard's `Endpoint`, strongSwan's `remote_addrs`, SSTP's `server=`), keyed by the row id, for the
    /// Connections window's search. Only the sanitized host ([`importer::remote_host`]: no port, user, path or
    /// other config text). What the last [`Self::reload`] read: no config is read here, so building the view model
    /// never touches the store. Native connections carry their server in the snapshot already
    /// ([`crate::ViewModel::build`]).
    pub fn server_hosts(&self) -> HashMap<String, String> {
        HashMap::clone(&self.server_hosts.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// The managed connections the platform cannot connect with their settings, by row id, with the localized
    /// reason ([`NativeSupport`], set with [`Self::set_native_support`]; WinVPN: an IKEv2 or SSTP setting Windows
    /// lacks). What the last [`Self::reload`] read; empty without a [`NativeSupport`] (macOS).
    pub fn unsupported_reasons(&self) -> HashMap<String, String> {
        HashMap::clone(&self.unsupported.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// The earliest `notAfter` (Unix seconds) of the certificates in each managed connection's config (OpenVPN
    /// `<cert>`, `<ca>`, `<extra-certs>`, an unencrypted `<pkcs12>`; the SSTP CA), keyed by the row id, for the
    /// row's expiry warning. What the last [`Self::reload`] read (no config is read here).
    pub fn certificate_expiry(&self) -> HashMap<String, i64> {
        HashMap::clone(&self.certificate_expiry.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// [`Self::unsupported_reasons`] of one row.
    pub fn unsupported_reason(&self, key: &str) -> Option<String> {
        self.unsupported.read().unwrap_or_else(PoisonError::into_inner).get(key).cloned()
    }

    /// Reads the server hosts of `connections` from their configs (each read wiped after parsing; a config that
    /// cannot be read or names no host is left out), and with a [`NativeSupport`] the connections it cannot
    /// connect (a native kind's settings are in its meta: asked with an empty config). Called by [`Self::reload`]
    /// without any lock held.
    fn read_config_facts(&self, connections: &[Connection]) -> ConfigFacts {
        let support = self.hooks().native_support;
        let mut hosts = HashMap::new();
        let mut unsupported = HashMap::new();
        let mut expiry = HashMap::new();
        for c in connections {
            let key = uuid_string(&c.id);
            if c.kind.is_native() {
                if let Some(reason) = support.as_ref().and_then(|s| s.unsupported_reason(c, &[])) {
                    unsupported.insert(key, reason);
                }
                continue;
            }
            let Ok(config) = self.deps.store.load_config_wiped(&c.id) else { continue };
            if let Some(reason) = support.as_ref().and_then(|s| s.unsupported_reason(c, config.as_bytes())) {
                unsupported.insert(key.clone(), reason);
            }
            if let Some(not_after) = macvpn_core::certificates::of_config(c.kind, &config).earliest_expiry() {
                expiry.insert(key.clone(), not_after);
            }
            if let Some(host) = macvpn_core::importer::remote_host(c.kind, &config) {
                hosts.insert(key, host);
            }
        }
        (hosts, unsupported, expiry)
    }

    /// The platform's answer which managed connections it cannot connect (read at every [`Self::reload`]; WinVPN
    /// 2c). Call before the first reload.
    pub fn set_native_support(&self, support: Arc<dyn NativeSupport>) {
        self.set_hooks(|h| h.native_support = Some(support));
    }

    // MARK: - Hooks

    fn hooks(&self) -> Hooks {
        self.hooks.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    fn set_hooks(&self, f: impl FnOnce(&mut Hooks)) {
        f(&mut self.hooks.write().unwrap_or_else(PoisonError::into_inner));
    }

    /// Failures and drops (after the new state is visible).
    pub fn set_on_event(&self, hook: impl Fn(ConnectionEvent) + Send + Sync + 'static) {
        self.set_hooks(|h| h.on_event = Some(Arc::new(hook)));
    }

    /// After every successful `scutil --nc list`: the managed native connections whose service is listed.
    pub fn set_on_native_services_seen(&self, hook: impl Fn(&HashSet<Uuid>) + Send + Sync + 'static) {
        self.set_hooks(|h| h.on_native_services_seen = Some(Arc::new(hook)));
    }

    /// The UI's code prompt / web confirmation. Without one (no UI) every request counts as cancelled.
    pub fn set_prompt_handler(&self, hook: impl Fn(AuthPrompt) -> AuthPromptResult + Send + Sync + 'static) {
        self.set_hooks(|h| h.prompt_handler = Some(Arc::new(hook)));
    }

    /// Closes the connection's open prompt (on disconnect, or when the connect ended meanwhile).
    pub fn set_dismiss_prompt(&self, hook: impl Fn(&str) + Send + Sync + 'static) {
        self.set_hooks(|h| h.dismiss_prompt = Some(Arc::new(hook)));
    }

    /// The UI's credential window. Without one (no UI) nothing is asked: the connect goes on with the stored
    /// secrets, exactly as before the prompt existed.
    pub fn set_credential_handler(&self, hook: impl Fn(CredentialPrompt) -> CredentialAnswer + Send + Sync + 'static) {
        self.set_hooks(|h| h.credential_handler = Some(Arc::new(hook)));
    }

    /// Closes the connection's open credential prompt (on disconnect).
    pub fn set_dismiss_credentials(&self, hook: impl Fn(&str) + Send + Sync + 'static) {
        self.set_hooks(|h| h.dismiss_credentials = Some(Arc::new(hook)));
    }

    /// Something the UI shows may have changed (the Swift `objectWillChange`).
    pub fn set_on_change(&self, hook: impl Fn() + Send + Sync + 'static) {
        self.set_hooks(|h| h.on_change = Some(Arc::new(hook)));
    }

    /// Called for every connection whose state changed, with the new state, right after the change is published
    /// (where [`Self::set_on_change`]'s hook runs). Several states set within one atomic section arrive as the last
    /// one; a key that disappears arrives as `Disconnected`. Listeners run one change at a time, in order, on the
    /// thread that made the change, under a lock: a listener must return quickly and must not call back into the
    /// manager.
    pub fn add_state_listener(&self, f: impl Fn(&str, &ConnectionState) + Send + Sync + 'static) {
        let mut published = self.published.lock().unwrap_or_else(PoisonError::into_inner);
        if self.hooks().state_listeners.is_empty() {
            *published = self.read(|i| i.states.clone());
        }
        self.set_hooks(|h| h.state_listeners.push(Arc::new(f)));
    }

    /// Called with the key when the user disconnects a connection ([`DisconnectCause::User`]), before its state
    /// changes; never for a disconnect on behalf of a lease.
    pub fn add_user_disconnect_listener(&self, f: impl Fn(&str) + Send + Sync + 'static) {
        self.set_hooks(|h| h.user_disconnect_listeners.push(Arc::new(f)));
    }

    pub fn set_auth_poll_interval(&self, interval: Duration) {
        self.auth_poll_millis.store(interval.as_millis() as u64, Ordering::SeqCst);
    }

    fn emit(&self, events: Vec<ConnectionEvent>) {
        if events.is_empty() {
            return;
        }
        if let Some(hook) = self.hooks().on_event {
            for event in events {
                hook(event);
            }
        }
    }

    fn dismiss(&self, key: &str) {
        if let Some(hook) = self.hooks().dismiss_prompt {
            hook(key);
        }
    }

    /// Closes the connection's open credential prompt (the user disconnected).
    fn dismiss_credentials(&self, key: &str) {
        if let Some(hook) = self.hooks().dismiss_credentials {
            hook(key);
        }
    }

    fn changed(&self) {
        let hooks = self.hooks();
        if let Some(hook) = &hooks.on_change {
            hook();
        }
        if !hooks.state_listeners.is_empty() {
            self.publish_states(&hooks.state_listeners);
        }
    }

    /// Delivers the per-key changes since the last delivery to the state listeners.
    fn publish_states(&self, listeners: &[StateListener]) {
        let mut published = self.published.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.read(|i| i.states.clone());
        let mut changes: Vec<(String, ConnectionState)> = current
            .iter()
            .filter(|(key, state)| published.get(*key) != Some(*state))
            .map(|(key, state)| (key.clone(), state.clone()))
            .collect();
        changes.extend(
            published
                .iter()
                .filter(|(key, state)| !current.contains_key(*key) && **state != ConnectionState::Disconnected)
                .map(|(key, _)| (key.clone(), ConnectionState::Disconnected)),
        );
        changes.sort_by(|a, b| a.0.cmp(&b.0));
        *published = current;
        for (key, state) in &changes {
            for listener in listeners {
                listener(key, state);
            }
        }
    }

    fn user_disconnected(&self, key: &str, cause: DisconnectCause) {
        if cause != DisconnectCause::User {
            return;
        }
        for listener in self.hooks().user_disconnect_listeners {
            listener(key);
        }
    }

    // MARK: - Locking

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn read<R>(&self, f: impl FnOnce(&Inner) -> R) -> R {
        f(&self.lock())
    }

    /// One atomic section that changes the state; the UI is notified after the lock is released.
    fn mutate<R>(&self, f: impl FnOnce(&mut Inner) -> R) -> R {
        let result = f(&mut self.lock());
        self.changed();
        result
    }

    fn now(&self) -> Date {
        self.deps.clock.now()
    }

    fn save_ranking(&self, ranking: &ConnectionRanking) {
        if let Some(store) = &self.deps.ranking_store {
            let _ = store.save(ranking);
        }
    }

    // MARK: - Reading

    pub fn connections(&self) -> Vec<Connection> {
        self.read(|i| i.connections.clone())
    }

    pub fn system_services(&self) -> Vec<SystemVpn> {
        self.read(|i| i.system_services.clone())
    }

    /// Every service ID macOS listed at the last successful listing (managed native ones included).
    pub fn listed_service_ids(&self) -> HashSet<String> {
        self.read(|i| i.listed_service_ids.clone())
    }

    pub fn states(&self) -> HashMap<String, ConnectionState> {
        self.read(|i| i.states.clone())
    }

    pub fn state(&self, key: &str) -> ConnectionState {
        self.read(|i| i.state(key))
    }

    pub fn status_error(&self) -> Option<String> {
        self.read(|i| i.status_error.clone())
    }

    /// The listed service a managed native connection maps to now, with its server address, both read fresh
    /// (`scutil --nc list` / `--nc show`): `Some(None)` when no service matches, `None` when that is unknown (the
    /// listing failed, or more than one service has the name).
    pub fn native_service_for(&self, c: &Connection) -> Option<Option<(String, Option<String>)>> {
        let services = self.deps.native.list().ok()?;
        match match_service(c, &services, self.deps.native.as_ref()) {
            NativeMatch::Service(s) => {
                let address = self.deps.native.remote_address(&s.id);
                Some(Some((s.id, address)))
            }
            NativeMatch::None => Some(None),
            NativeMatch::Ambiguous(_) => None,
        }
    }

    pub fn installed_native_ids(&self) -> HashSet<Uuid> {
        self.read(|i| i.installed_native_ids.clone())
    }

    pub fn ranking(&self) -> ConnectionRanking {
        self.read(|i| i.ranking.clone())
    }

    pub fn has_active(&self) -> bool {
        self.read(Inner::has_active)
    }

    /// Live traffic of a native service: the platform's [`NativeController::traffic`] (`None` on macOS).
    pub fn native_traffic(&self, service_id: &str) -> Option<macvpn_platform_api::TrafficReading> {
        self.deps.native.traffic(service_id)
    }

    /// The connected tunnels whose traffic can be read (live traffic): the managed root-backed connections with
    /// what the helper reported, the managed native ones by their bound service and the unmanaged system VPNs.
    pub fn tunnels(&self) -> Vec<Tunnel> {
        self.read(|i| {
            let connected = |key: &str| i.states.get(key).is_some_and(ConnectionState::is_connected);
            let mut out = Vec::new();
            for c in &i.connections {
                let key = uuid_string(&c.id);
                let Some(ConnectionState::Connected { ip, since }) = i.states.get(&key) else { continue };
                let source = if c.kind.is_native() {
                    let Some(service_id) = c.native_service_id.clone() else { continue };
                    TunnelSource::Native { service_id }
                } else {
                    TunnelSource::Helper {
                        id: c.id,
                        kind: c.kind,
                        iface: i.ifaces.get(&key).cloned(),
                        ip: ip.clone(),
                        since: since.map(|d| d.time_interval_since_1970()),
                    }
                };
                out.push(Tunnel { key, source });
            }
            for s in i.system_services.iter().filter(|s| connected(&s.id)) {
                out.push(Tunnel { key: s.id.clone(), source: TunnelSource::Native { service_id: s.id.clone() } });
            }
            out
        })
    }

    pub fn has_failure(&self) -> bool {
        self.read(|i| i.states.values().any(|s| matches!(s, ConnectionState::Failed(_))))
    }

    pub fn snapshot(&self) -> ManagerSnapshot {
        let now = self.now();
        self.read(|i| {
            let items = i
                .ordered_items(now)
                .into_iter()
                .map(|item| {
                    let id = item.id();
                    let state = i.state(&id);
                    let pinned = i.ranking.is_pinned(&id);
                    (item, state, pinned)
                })
                .collect();
            ManagerSnapshot {
                items,
                status_error: i.status_error.clone(),
                has_active: i.has_active(),
                has_failure: i.states.values().any(|s| matches!(s, ConnectionState::Failed(_))),
                awaiting_auth: i.states.values().any(|s| matches!(s, ConnectionState::AwaitingAuth(_))),
                connecting: i.states.values().any(|s| matches!(s, ConnectionState::Connecting)),
                folders: FolderSnapshot {
                    enabled: self.deps.folders.is_some(),
                    folders: i.folders.clone(),
                    entries: i.ordered_tree(&i.folder_tree(), now),
                    placements: i.placements.clone(),
                },
            }
        })
    }

    /// The managed connection or system VPN with this key.
    pub fn item(&self, key: &str) -> Option<ConnectionItem> {
        self.read(|i| {
            i.connections
                .iter()
                .find(|c| uuid_string(&c.id) == key)
                .cloned()
                .map(ConnectionItem::Managed)
                .or_else(|| i.system_services.iter().find(|s| s.id == key).cloned().map(ConnectionItem::System))
        })
    }

    /// Reads the connections again. The first successful read, and the first one after the vault was locked,
    /// also reads the ranking and the system OTP settings again (they may have been unreadable before: the vault
    /// was still locked when the manager was built, or [`Self::enter_locked`] dropped them).
    pub fn reload(&self) {
        let list = self.deps.store.list();
        let restore = list.is_ok() && self.read(|i| i.locked || !i.loaded);
        let stored = restore.then(|| {
            let ranking = self.deps.ranking_store.as_ref().map(|s| s.load());
            let otp = self.deps.system_otp_store.as_ref().map(|s| s.load());
            (ranking, otp)
        });
        // Read only once the connections are readable: a locked vault keeps the folders dropped.
        let folders = if list.is_ok() { self.load_folders() } else { None };
        // The search's server hosts, before the change is published (the view model built then has them).
        if let Ok(list) = &list {
            let (hosts, unsupported, expiry) = self.read_config_facts(list);
            *self.server_hosts.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(hosts);
            *self.unsupported.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(unsupported);
            *self.certificate_expiry.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(expiry);
        }
        self.mutate(|i| {
            if let Ok(list) = list {
                i.connections = list;
                i.loaded = true;
                i.locked = false;
            }
            if let Some((ranking, otp)) = stored {
                if let Some(ranking) = ranking {
                    i.ranking = ranking;
                }
                if let Some(otp) = otp {
                    i.system_otp = otp;
                }
            }
            i.remote_addresses.clear();
            if let Some((folders, placements)) = folders {
                i.folders = folders;
                i.placements = placements;
            }
        });
    }

    /// Reads everything again, the ranking, the system OTP settings and the folders included: a restore replaced
    /// the vault's contents.
    pub fn reload_all(&self) {
        self.lock().loaded = false;
        self.reload();
    }

    // MARK: - Locked vault

    /// The vault was locked (Lock now, or locked at launch): only what is needed to keep polling and to disconnect
    /// the active connections stays (the id, the kind and the bound native service ID; the name is empty), every
    /// other connection is dropped, and so are the ranking, the system OTP settings and the folders. Running VPNs are not
    /// touched. Connecting, pinning and the OTP setting are refused until [`Self::reload`] after the unlock.
    pub fn enter_locked(&self) {
        // The connects still asking (credentials, a code): their prompts close, and the connects end before the
        // next step (`connect_root` checks the lock).
        let connecting: Vec<String> = self
            .read(|i| i.ops.iter().filter(|(_, op)| matches!(op, Op::Connecting)).map(|(k, _)| k.clone()).collect());
        *self.server_hosts.write().unwrap_or_else(PoisonError::into_inner) = Arc::default();
        *self.unsupported.write().unwrap_or_else(PoisonError::into_inner) = Arc::default();
        *self.certificate_expiry.write().unwrap_or_else(PoisonError::into_inner) = Arc::default();
        self.mutate(|i| {
            i.locked = true;
            // No pruning of the (empty) ranking until the full list is back.
            i.loaded = false;
            let active: Vec<Connection> = i
                .connections
                .iter()
                .filter(|c| {
                    let key = uuid_string(&c.id);
                    i.state(&key).is_active() || i.ops.contains_key(&key)
                })
                .map(redacted)
                .collect();
            i.connections = active;
            i.ranking = ConnectionRanking::default();
            i.system_otp.clear();
            // The folder tree and the placements are in the vault: back with the reload after the unlock.
            i.folders.clear();
            i.placements.clear();
            i.remote_addresses.clear();
            // "Save" values of the credential prompt cannot be written any more: wiped.
            i.pending_saves.clear();
            i.ready_saves.clear();
        });
        for key in &connecting {
            self.dismiss(key);
            self.dismiss_credentials(key);
        }
    }

    /// The vault is locked ([`Self::enter_locked`] until the next successful [`Self::reload`]).
    pub fn is_locked(&self) -> bool {
        self.read(|i| i.locked)
    }

    // MARK: - Folders (spec 3)

    /// The folder store (`None`: no folders).
    pub fn folder_store(&self) -> Option<Arc<dyn FolderStore>> {
        self.deps.folders.clone()
    }

    /// The folders and placements from the store. `None` without a store; a store that cannot be read (the vault
    /// locked) gives none, so nothing stale is shown.
    fn load_folders(&self) -> Option<(Vec<FolderNode>, HashMap<String, Placement>)> {
        let store = self.deps.folders.as_ref()?;
        match (store.folders(), store.placements()) {
            (Ok(folders), Ok(placements)) => {
                Some((folders, placements.into_iter().map(|p| (p.key.clone(), p)).collect()))
            }
            _ => Some((Vec::new(), HashMap::new())),
        }
    }

    /// Re-reads the folders and placements (after a folder edit).
    pub fn reload_folders(&self) {
        let Some((folders, placements)) = self.load_folders() else { return };
        self.mutate(|i| {
            i.folders = folders;
            i.placements = placements;
        });
    }

    pub fn folders(&self) -> Vec<FolderNode> {
        self.read(|i| i.folders.clone())
    }

    pub fn folder_tree(&self) -> FolderTree {
        self.read(Inner::folder_tree)
    }

    /// The item's placement (`None`: at the root, no own colour).
    pub fn placement(&self, key: &str) -> Option<Placement> {
        self.read(|i| i.placements.get(key).cloned())
    }

    /// Every folder and item in display order: per folder the subfolders by position, then the items pinned
    /// first, then by usage (spec 3). The flat [`Self::ordered_items`] (the control API's `list`) is unchanged.
    pub fn ordered_tree(&self) -> Vec<TreeEntry> {
        let now = self.now();
        self.read(|i| i.ordered_tree(&i.folder_tree(), now))
    }

    /// The folder path (root → leaf names) of an item in a folder, for the export's metadata line.
    pub fn folder_path(&self, key: &str) -> Option<Vec<String>> {
        self.read(|i| {
            let folder = i.placements.get(key)?.folder?;
            let path = i.folder_tree().path(folder);
            (!path.is_empty()).then_some(path)
        })
    }

    /// The system-VPN placement retention after a successful listing (spec 5): a placed service that is not
    /// listed is marked missing, one listed again is cleared, one missing for 30 days loses its placement.
    fn retain_system_items(&self, services: &[SystemVpn]) {
        let Some(store) = &self.deps.folders else { return };
        let Ok(items) = store.system_items() else { return };
        let listed: HashSet<String> = services.iter().map(|s| s.id.clone()).collect();
        let changes = crate::folders::retention(&items, &listed, self.now());
        if changes.is_empty() {
            return;
        }
        if store.apply(FolderOp::Retention(changes)).is_ok() {
            self.reload_folders();
        }
    }

    // MARK: - Order (pinning, usage)

    /// The managed connections and the system VPNs in one list, in the ranking order.
    pub fn ordered_items(&self) -> Vec<ConnectionItem> {
        let now = self.now();
        self.read(|i| i.ordered_items(now))
    }

    pub fn pinned_items(&self) -> Vec<ConnectionItem> {
        let now = self.now();
        self.read(|i| i.ordered_items(now).into_iter().filter(|it| i.ranking.is_pinned(&it.id())).collect())
    }

    pub fn unpinned_items(&self) -> Vec<ConnectionItem> {
        let now = self.now();
        self.read(|i| i.ordered_items(now).into_iter().filter(|it| !i.ranking.is_pinned(&it.id())).collect())
    }

    pub fn is_pinned(&self, id: &str) -> bool {
        self.read(|i| i.ranking.is_pinned(id))
    }

    pub fn pin(&self, id: &str) {
        self.mutate(|i| {
            if i.locked {
                return;
            }
            i.ranking.pin(id);
            self.save_ranking(&i.ranking);
        });
    }

    pub fn unpin(&self, id: &str) {
        self.mutate(|i| {
            if i.locked {
                return;
            }
            i.ranking.unpin(id);
            self.save_ranking(&i.ranking);
        });
    }

    /// A drag in the pinned section, with the indexes of [`Self::pinned_items`] (SwiftUI `onMove`).
    pub fn move_pinned(&self, source: &BTreeSet<usize>, destination: usize) {
        let now = self.now();
        self.mutate(|i| {
            if i.locked {
                return;
            }
            let visible: Vec<String> =
                i.ordered_items(now).iter().map(ConnectionItem::id).filter(|id| i.ranking.is_pinned(id)).collect();
            i.ranking.move_pinned(&visible, source, destination);
            self.save_ranking(&i.ranking);
        });
    }

    /// The user-started connects, judged by the fresh state (see `awaiting_success`).
    fn settle_successes(&self, i: &mut Inner, now: Date) {
        let mut changed = false;
        let keys: Vec<String> = i.awaiting_success.iter().cloned().collect();
        for key in keys {
            match i.states.get(&key) {
                Some(ConnectionState::Connected { .. }) => {
                    i.awaiting_success.remove(&key);
                    i.ranking.record_success(&key, now);
                    changed = true;
                    if let Some(save) = i.pending_saves.remove(&key) {
                        i.ready_saves.push(save);
                    }
                }
                Some(
                    ConnectionState::Connecting | ConnectionState::Disconnecting | ConnectionState::AwaitingAuth(_),
                ) => {}
                _ => {
                    // Failed or disconnected without an operation in flight: this attempt did not succeed.
                    if !i.ops.contains_key(&key) {
                        i.awaiting_success.remove(&key);
                        i.pending_saves.remove(&key);
                    }
                }
            }
        }
        if changed && !i.locked {
            self.save_ranking(&i.ranking);
        }
    }

    // MARK: - Native service binding

    /// Binding: a bound but vanished ID is cleared; an unbound connection binds to the first service with its
    /// name whose server address matches too (and that no other connection is bound to). Saved to `meta.json`
    /// (only the binding, [`ConnectionRepository::set_native_service`], so a catalog connection keeps it too).
    fn bind_native_services(&self, services: &[SystemVpn]) {
        let listed: HashSet<&str> = services.iter().map(|s| s.id.as_str()).collect();
        let snapshot = self.read(|i| i.connections.clone());
        {
            let mut i = self.lock();
            i.remote_addresses.retain(|k, _| listed.contains(k.as_str()));
        }
        // A connection with the platform's own service (WinVPN) needs no binding.
        let own = |c: &Connection| self.deps.native.managed_service_id(&c.id).is_some();
        for c in snapshot.iter().filter(|c| c.kind.is_native() && !own(c)) {
            let mut updated = c.clone();
            if let Some(id) = &c.native_service_id {
                if listed.contains(id.as_str()) {
                    continue;
                }
                updated.native_service_id = None;
            }
            if updated.native_service_id.is_none()
                && let Some(server) = c.native.as_ref().map(|n| n.server.clone()).filter(|s| !s.is_empty())
            {
                let taken: HashSet<String> =
                    self.read(|i| i.connections.iter().filter_map(|c| c.native_service_id.clone()).collect());
                let name = c.native_service_name.as_deref().unwrap_or(&c.name);
                for s in services.iter().filter(|s| s.name == name && !taken.contains(&s.id)) {
                    let cached = self.read(|i| i.remote_addresses.get(&s.id).cloned());
                    let address = match cached {
                        Some(address) => address,
                        None => {
                            let address = self.deps.native.remote_address(&s.id);
                            self.lock().remote_addresses.insert(s.id.clone(), address.clone());
                            address
                        }
                    };
                    if address.map(|a| a.to_lowercase()) == Some(server.to_lowercase()) {
                        updated.native_service_id = Some(s.id.clone());
                        break;
                    }
                }
            }
            if updated.native_service_id == c.native_service_id {
                continue;
            }
            let replaced = self.mutate(|i| match i.connections.iter().position(|x| x.id == c.id) {
                Some(index) => {
                    i.connections[index] = updated.clone();
                    true
                }
                None => false,
            });
            if replaced {
                // Only the binding: a catalog connection's other metadata is read-only.
                let _ = self.deps.store.set_native_service(&updated.id, updated.native_service_id.as_deref());
            }
        }
    }

    // MARK: - Refresh

    pub fn refresh(&self) {
        let (start, has_root) = {
            let mut i = self.lock();
            i.epoch += 1;
            (i.epoch, i.connections.iter().any(|c| !c.kind.is_native()))
        };
        let mut failure: Option<String> = None;
        let root = if has_root {
            match self.deps.helper.status() {
                Ok(root) => Some(root),
                Err(e) => {
                    failure = Some(e);
                    None
                }
            }
        } else {
            // No root-backed connection: no query (sudo), and no error.
            Some(Vec::new())
        };
        let services = match self.deps.native.list() {
            Ok(services) => Some(services),
            Err(e) => {
                failure.get_or_insert(e);
                None
            }
        };
        if let Some(services) = &services {
            self.bind_native_services(services);
            self.retain_system_items(services);
        }

        // The system VPN failure hints read the Keychain: computed before the locked section, for the services
        // with a pending start only.
        let pending: HashSet<String> = self.read(|i| {
            i.ops.iter().filter(|(_, op)| matches!(op, Op::AwaitingNative { .. })).map(|(k, _)| k.clone()).collect()
        });
        let hints: HashMap<String, String> = services
            .iter()
            .flatten()
            .filter(|s| pending.contains(&s.id))
            .map(|s| (s.id.clone(), self.system_failure_reason(s)))
            .collect();
        // The connected native services' tunnel addresses (in-process reads), before the locked section.
        let addresses: HashMap<String, String> = services
            .iter()
            .flatten()
            .filter(|s| s.status == "Connected")
            .filter_map(|s| self.deps.native.address(&s.id).map(|a| (s.id.clone(), a)))
            .collect();
        let now = self.now();
        let native = self.deps.native.as_ref();
        let applied = self.mutate(|i| {
            if start < i.last_applied {
                return None; // a newer refresh has already been applied
            }
            i.last_applied = start;

            match &failure {
                Some(failure) => {
                    i.failure_streak += 1;
                    if i.failure_streak >= STATUS_ERROR_THRESHOLD {
                        i.status_error = Some(l10n::tr("Cannot query the status: %@", &[Arg::Str(failure)]));
                    }
                }
                None => {
                    i.failure_streak = 0;
                    i.status_error = None;
                }
            }

            let stale = |i: &Inner, key: &str| i.key_epoch(key) > start;
            let mut next: HashMap<String, ConnectionState> = HashMap::new();
            let mut to_stop: Vec<String> = Vec::new();

            for c in i.connections.clone() {
                let key = uuid_string(&c.id);
                let previous = i.states.get(&key).cloned();
                if stale(i, &key) {
                    if let Some(previous) = previous {
                        next.insert(key, previous);
                    }
                    continue;
                }
                match i.ops.get(&key) {
                    Some(Op::Connecting) => {
                        let state = i
                            .auth_waits
                            .get(&key)
                            .map_or(ConnectionState::Connecting, |w| ConnectionState::AwaitingAuth(*w));
                        next.insert(key, state);
                        continue;
                    }
                    Some(Op::Disconnecting) => {
                        next.insert(key, ConnectionState::Disconnecting);
                        continue;
                    }
                    _ => {}
                }

                let current = if c.kind.is_native() {
                    if let Some(Op::AwaitingNative { started, service_id, .. }) = i.ops.get(&key).cloned()
                        && services.is_none()
                        && now.time_interval_since(started) > NATIVE_TIMEOUT
                    {
                        to_stop.push(service_id);
                        let failed = i.fail_native(&key, &c.name, timed_out());
                        next.insert(key, failed);
                        continue;
                    }
                    let Some(services) = &services else {
                        next.insert(key, previous.unwrap_or(ConnectionState::Disconnected));
                        continue;
                    };
                    let service = match match_service(&c, services, native) {
                        NativeMatch::Service(s) => Some(s),
                        NativeMatch::Ambiguous(all) => all.into_iter().next(),
                        NativeMatch::None => None,
                    };
                    if let Some(pending) =
                        i.evaluate_awaiting(&key, &c.name, service.as_ref(), now, native_failure_reason, &mut to_stop)
                    {
                        next.insert(key, pending);
                        continue;
                    }
                    let current = service.as_ref().map_or(ConnectionState::Disconnected, |s| s.connection_state());
                    let address = service.as_ref().and_then(|s| addresses.get(&s.id));
                    i.native_details(&key, previous.as_ref(), current, address, now)
                } else {
                    let Some(root) = &root else {
                        next.insert(key, previous.unwrap_or(ConnectionState::Disconnected));
                        continue;
                    };
                    let reported = root.iter().find(|r| r.id == c.id);
                    match reported.filter(|r| r.state == "connected").and_then(|r| r.iface.clone()) {
                        Some(iface) if !iface.is_empty() => i.ifaces.insert(key.clone(), iface),
                        _ => i.ifaces.remove(&key),
                    };
                    reported.map_or(ConnectionState::Disconnected, |r| r.connection_state())
                };
                let resolved = i.resolve(&key, &c.name, previous.as_ref(), current, c.kind.is_native());
                next.insert(key, resolved);
            }

            if let Some(services) = &services {
                let managed = managed_service_ids(&i.connections, services, native);
                i.installed_native_ids = i
                    .connections
                    .iter()
                    .filter(|c| c.kind.is_native() && match_service(c, services, native) != NativeMatch::None)
                    .map(|c| c.id)
                    .collect();
                let unmanaged: Vec<SystemVpn> = services.iter().filter(|s| !managed.contains(&s.id)).cloned().collect();
                for s in &unmanaged {
                    let previous = i.states.get(&s.id).cloned();
                    if stale(i, &s.id) {
                        if let Some(previous) = previous {
                            next.insert(s.id.clone(), previous);
                        }
                        continue;
                    }
                    match i.ops.get(&s.id) {
                        Some(Op::Connecting) => {
                            let state = i
                                .auth_waits
                                .get(&s.id)
                                .map_or(ConnectionState::Connecting, |w| ConnectionState::AwaitingAuth(*w));
                            next.insert(s.id.clone(), state);
                            continue;
                        }
                        Some(Op::Disconnecting) => {
                            next.insert(s.id.clone(), ConnectionState::Disconnecting);
                            continue;
                        }
                        _ => {}
                    }
                    let reason = || hints.get(&s.id).cloned().unwrap_or_else(|| self.system_failure_reason(s));
                    if let Some(pending) = i.evaluate_awaiting(&s.id, &s.name, Some(s), now, reason, &mut to_stop) {
                        next.insert(s.id.clone(), pending);
                        continue;
                    }
                    let current =
                        i.native_details(&s.id, previous.as_ref(), s.connection_state(), addresses.get(&s.id), now);
                    let resolved = i.resolve(&s.id, &s.name, previous.as_ref(), current, true);
                    next.insert(s.id.clone(), resolved);
                }
                i.system_services = unmanaged;
                i.listed_service_ids = services.iter().map(|s| s.id.clone()).collect();
                // Deleted connections and vanished system VPNs: only after a full (successful) listing.
                if i.loaded {
                    let keep: HashSet<String> = i
                        .connections
                        .iter()
                        .map(|c| uuid_string(&c.id))
                        .chain(i.system_services.iter().map(|s| s.id.clone()))
                        .collect();
                    if i.ranking.prune(&keep) {
                        self.save_ranking(&i.ranking);
                    }
                }
            } else {
                for s in i.system_services.clone() {
                    let awaiting = match i.ops.get(&s.id) {
                        Some(Op::AwaitingNative { started, service_id, .. }) if !stale(i, &s.id) => {
                            Some((*started, service_id.clone()))
                        }
                        _ => None,
                    };
                    if let Some((started, service_id)) = awaiting
                        && now.time_interval_since(started) > NATIVE_TIMEOUT
                    {
                        to_stop.push(service_id);
                        let failed = i.fail_native(&s.id, &s.name, timed_out());
                        next.insert(s.id.clone(), failed);
                    } else if let Some(state) = i.states.get(&s.id).cloned() {
                        next.insert(s.id.clone(), state);
                    }
                }
            }
            i.states = next;
            self.settle_successes(i, now);
            let events = std::mem::take(&mut i.queued_events);
            let seen = services.as_ref().map(|_| i.installed_native_ids.clone());
            Some((events, seen, to_stop))
        });
        let saves = std::mem::take(&mut self.lock().ready_saves);
        self.write_saves(saves);
        let Some((events, seen, to_stop)) = applied else { return };
        self.emit(events);
        if let Some(seen) = seen
            && let Some(hook) = self.hooks().on_native_services_seen
        {
            hook(&seen);
        }
        for id in to_stop {
            let _ = self.deps.native.stop(&id);
        }
    }

    /// A system VPN's failure: without a PSK (L2TP / Cisco) the hint says it can be entered in MacVPN.
    pub fn system_failure_reason(&self, s: &SystemVpn) -> String {
        if s.supports_stored_secrets()
            && let Some(id) = s.secret_id()
            && self.deps.secrets.get(&id, SecretField::Psk).unwrap_or_default().is_empty()
        {
            return l10n::tr(
                "The connection did not come up. If this is an L2TP/IPsec VPN, enter its shared secret (PSK) in MacVPN → Connections → %@.",
                &[Arg::Str(&s.name)],
            );
        }
        l10n::tr("The connection did not come up.", &[])
    }

    /// The PSK / password MacVPN stores for a system VPN (in its secret store, the vault; L2TP / Cisco IPsec only).
    pub fn system_secrets(&self, s: &SystemVpn) -> Secrets {
        let (true, Some(id)) = (s.supports_stored_secrets(), s.secret_id()) else { return Secrets::default() };
        Secrets {
            password: self.deps.secrets.get(&id, SecretField::Password),
            psk: self.deps.secrets.get(&id, SecretField::Psk),
            ..Secrets::default()
        }
    }

    // MARK: - Connect / disconnect

    pub fn connect(&self, c: &Connection, debug: bool) {
        // Locked: the menu offers no connect, and the control API answers `locked`; nothing reads the vault.
        if self.is_locked() {
            return;
        }
        let (c, key, mut token) = self.mutate(|i| {
            let c = i.current(c);
            let key = uuid_string(&c.id);
            i.want_down.remove(&key);
            i.auth_cancelled.remove(&key);
            i.credentials_cancelled.remove(&key);
            i.pending_saves.remove(&key);
            i.awaiting_success.insert(key.clone());
            i.set_op(&key, Some(Op::Connecting));
            i.states.insert(key.clone(), ConnectionState::Connecting);
            // Token: only the call whose operation is still the latest may write the key.
            let token = i.key_epoch(&key);
            (c, key, token)
        });
        let result = if c.kind.is_native() {
            self.connect_native(&c, &key, &mut token)
        } else {
            self.connect_root(&c, &key, token, debug)
        };
        if let Err(error) = result {
            let event = self.mutate(|i| {
                if i.key_epoch(&key) != token {
                    return None;
                }
                let cancelled = i.auth_cancelled.remove(&key);
                let reason = if i.auth_timed_out.remove(&key) {
                    auth_timeout_reason()
                } else if cancelled {
                    auth_cancelled_reason()
                } else {
                    error
                };
                i.set_awaiting(&key, None);
                i.states.insert(key.clone(), ConnectionState::Failed(reason.clone()));
                i.set_op(&key, None);
                i.awaiting_success.remove(&key);
                i.pending_saves.remove(&key);
                Some(ConnectionEvent::Failed { connection_id: key.clone(), name: c.name.clone(), reason })
            });
            self.emit(event.into_iter().collect());
        }
    }

    fn connect_native(&self, c: &Connection, key: &str, token: &mut u64) -> Result<(), String> {
        if self.deps.store.team_managed(&c.id).is_some_and(|t| t.profile_outdated) {
            return Err(profile_outdated_reason());
        }
        let name = c.native_service_name.clone().unwrap_or_else(|| c.name.clone());
        let services = self.deps.native.list()?;
        let managed = self.deps.native.managed_service_id(&c.id).is_some();
        let service = match match_service(c, &services, self.deps.native.as_ref()) {
            NativeMatch::Service(s) => {
                // An unbound connection only matched by name: it may get the secrets only if the service's server
                // address (`scutil --nc show`, read fresh) is the connection's server. Otherwise it does not start
                // at all, not even without secrets. The platform's own service for it (WinVPN) is never foreign.
                if c.native_service_id.is_none() && !managed {
                    let address = self.deps.native.remote_address(&s.id);
                    self.lock().remote_addresses.insert(s.id.clone(), address.clone());
                    let server = c.native.as_ref().map(|n| n.server.clone()).unwrap_or_default();
                    if server.is_empty() || address.map(|a| a.to_lowercase()) != Some(server.to_lowercase()) {
                        return Err(server_mismatch_reason(&name));
                    }
                }
                s
            }
            NativeMatch::None => return Err(l10n::tr("The profile is not installed: %@", &[Arg::Str(&name)])),
            NativeMatch::Ambiguous(_) => {
                // Unknown which one is ours: the password / PSK is not passed to a possibly foreign service.
                return Err(l10n::tr(
                    "More than one VPN service is named “%@”. MacVPN does not pass the password until it is clear which one is its own: rename or remove the other one in System Settings → Network.",
                    &[Arg::Str(&name)],
                ));
            }
        };
        let base = Zeroizing::new(self.deps.secrets.secrets(&c.id));
        let account = c.native.as_ref().map(|n| n.account.clone()).filter(|a| !a.is_empty());
        let required = credentials::required_fields(c.kind, None);
        let Some(typed) = self.credential_secrets(key, &c.name, &c.id, c.kind, &required, account, base, false) else {
            self.abandon_connect(key, &c.name, *token);
            return Ok(());
        };
        // The vault was locked meanwhile (Lock Now): nothing more is asked, nothing connects.
        if self.is_locked() {
            self.abandon_connect(key, &c.name, *token);
            return Ok(());
        }
        if !self.keep_save(key, *token, typed.save) {
            return Ok(());
        }
        let Some(prepared) = self.code_secrets(key, &c.name, c.kind, None, c.otp, &typed.secrets)? else {
            self.abandon_connect(key, &c.name, *token);
            return Ok(());
        };
        drop(typed.secrets);
        if self.read(|i| i.key_epoch(key)) != *token || self.is_locked() {
            self.abandon_connect(key, &c.name, *token);
            return Ok(());
        }
        let started = self.deps.native.start(&service.id, NativeKind::from_kind(c.kind), &prepared);
        drop(prepared);
        started?;
        let now = self.now();
        let late = self.mutate(|i| {
            if i.key_epoch(key) != *token {
                return Some(i.want_down.contains(key));
            }
            // The refresh decides the actual outcome (see `AwaitingNative`).
            i.set_op(
                key,
                Some(Op::AwaitingNative { started: now, saw_connecting: false, service_id: service.id.clone() }),
            );
            *token = i.key_epoch(key);
            i.states.insert(key.to_string(), ConnectionState::Connecting);
            None
        });
        if let Some(want_down) = late
            && want_down
        {
            let _ = self.deps.native.stop(&service.id);
            self.mutate(|i| i.settle_after_teardown(key));
        }
        Ok(())
    }

    fn connect_root(&self, c: &Connection, key: &str, token: u64, debug: bool) -> Result<(), String> {
        // Root layer 8 gets the config on stdin: an unreadable one fails here, without calling `mvpn`.
        let Ok(config) = self.deps.store.load_config(&c.id) else {
            return Err(l10n::tr("Config not found", &[]));
        };
        if c.kind == VPNKind::Openvpn
            && let Some(reason) = unacknowledged_risk_reason(c, Some(&config))
        {
            return Err(reason);
        }
        let mut required = credentials::required_fields(c.kind, Some(&config));
        // IKEv2 with an imported client certificate (G2/G4): its key password, asked when not saved.
        let client_cert = (c.kind == VPNKind::Strongswan)
            .then(|| self.deps.secrets.get(&c.id, SecretField::ClientCert).map(Zeroizing::new))
            .flatten();
        if let Some(stored) = &client_cert
            && macvpn_core::client_cert::ClientCert::from_stored(stored).is_none()
        {
            return Err(l10n::tr("The imported client certificate cannot be read. Import it again.", &[]));
        }
        required.fields.extend(credentials::client_cert_fields(
            c.kind,
            &config,
            client_cert.as_deref().map(|s| s.as_str()),
        ));
        drop(client_cert);
        // A team SSTP connection on its credential slot: the slot's user name goes into `user=` (asked when empty).
        let team_sstp =
            c.kind == VPNKind::Sstp && self.deps.secrets.credential_for(&c.id).is_some_and(|r| r.team.is_some());
        if team_sstp {
            required.fields.insert(CredentialField::Username);
        }
        let mut retry = false;
        loop {
            // Credentials first (the missing ones; after a sign-in failure the user name and password again),
            // then the MFA static challenge / "code after the password"; for OpenVPN the bridge's state file is
            // watched during `up` (dynamic challenge, web authentication).
            // The vault was locked meanwhile (Lock Now): nothing more is asked, nothing connects.
            if self.is_locked() {
                self.abandon_connect(key, &c.name, token);
                return Ok(());
            }
            let base = Zeroizing::new(self.deps.secrets.secrets(&c.id));
            let Some(typed) = self.credential_secrets(key, &c.name, &c.id, c.kind, &required, None, base, retry) else {
                self.abandon_connect(key, &c.name, token);
                return Ok(());
            };
            if self.is_locked() {
                self.abandon_connect(key, &c.name, token);
                return Ok(());
            }
            let sent = match typed.secrets.username.as_deref().filter(|u| team_sstp && !u.is_empty()) {
                Some(username) => Zeroizing::new(sstp_with_user(&config, username)?),
                None => Zeroizing::new(config.clone()),
            };
            if !self.keep_save(key, token, typed.save) {
                return Ok(());
            }
            let Some(prepared) = self.code_secrets(key, &c.name, c.kind, Some(&config), c.otp, &typed.secrets)? else {
                self.abandon_connect(key, &c.name, token);
                return Ok(());
            };
            drop(typed.secrets);
            if self.read(|i| i.key_epoch(key)) != token || self.is_locked() {
                self.abandon_connect(key, &c.name, token);
                return Ok(());
            }
            let watch = (c.kind == VPNKind::Openvpn).then(|| self.start_auth_watch(c));
            let accept_risky =
                if c.kind == VPNKind::Openvpn { c.acknowledged_risky_directives.clone() } else { Vec::new() };
            let up = self.deps.helper.up(c.kind, &c.id, sent.as_bytes(), &prepared, debug, &accept_risky);
            drop(sent);
            drop(prepared);
            if let Some(watch) = watch {
                self.stop_auth_watch(key, watch);
            }
            match up {
                // A wrong user name or password: asked again once (never in a loop), if anything can be asked.
                Err(message)
                    if !retry
                        && credentials::is_sign_in_failure(&message)
                        && !retry_fields(&required, &Zeroizing::new(self.deps.secrets.secrets(&c.id))).is_empty()
                        && self.hooks().credential_handler.is_some()
                        && self.read(|i| i.key_epoch(key)) == token =>
                {
                    self.mutate(|i| {
                        i.pending_saves.remove(key);
                    });
                    retry = true;
                }
                other => {
                    other?;
                    break;
                }
            }
        }
        let late = self.mutate(|i| {
            if i.key_epoch(key) != token {
                return Some(i.want_down.contains(key));
            }
            i.states.insert(key.to_string(), ConnectionState::Connecting);
            i.set_op(key, None);
            None
        });
        match late {
            // Meanwhile the user disconnected: the successful tunnel is torn down. A newer connect is untouched.
            Some(want_down) => {
                if want_down {
                    let _ = self.deps.helper.down(c.kind, &c.id);
                    self.mutate(|i| i.settle_after_teardown(key));
                }
            }
            None => self.refresh(),
        }
        Ok(())
    }

    /// A disconnect the user asked for ([`DisconnectCause::User`]).
    pub fn disconnect(&self, c: &Connection) {
        self.disconnect_for(c, DisconnectCause::User);
    }

    pub fn disconnect_for(&self, c: &Connection, cause: DisconnectCause) {
        self.user_disconnected(&uuid_string(&c.id), cause);
        let (c, key, was_connecting, token) = self.mutate(|i| {
            let c = i.current(c);
            let key = uuid_string(&c.id);
            let was_connecting = matches!(i.ops.get(&key), Some(Op::Connecting));
            i.want_down.insert(key.clone());
            i.awaiting_success.remove(&key);
            i.pending_saves.remove(&key);
            i.set_op(&key, Some(Op::Disconnecting));
            let token = i.key_epoch(&key);
            i.auth_waits.remove(&key);
            i.states.insert(key.clone(), ConnectionState::Disconnecting);
            (c, key, was_connecting, token)
        });
        self.dismiss(&key);
        self.dismiss_credentials(&key);
        // OpenVPN while connecting (even waiting for authentication): cancelled through the bridge, so `up` cleans
        // up and releases the lock at once, and `down` does not wait for it. Without a running bridge the error
        // does not matter.
        if c.kind == VPNKind::Openvpn && was_connecting {
            let _ = self.deps.helper.respond(&c.id, AuthResponseKind::Cancel, "");
        }
        let result: Result<(), String> = if c.kind.is_native() {
            self.deps.native.list().and_then(|services| match match_service(&c, &services, self.deps.native.as_ref()) {
                NativeMatch::Service(s) => self.deps.native.stop(&s.id),
                NativeMatch::Ambiguous(all) => {
                    // No secret is passed when stopping: every active service with the name is stopped.
                    for s in all.iter().filter(|s| s.connection_state().is_active()) {
                        self.deps.native.stop(&s.id)?;
                    }
                    Ok(())
                }
                NativeMatch::None => Ok(()),
            })
        } else {
            self.deps.helper.down(c.kind, &c.id)
        };
        if let Err(reason) = result
            && self.read(|i| i.key_epoch(&key)) == token
        {
            self.emit(vec![ConnectionEvent::Failed { connection_id: key.clone(), name: c.name.clone(), reason }]);
        }
        self.mutate(|i| {
            if i.key_epoch(&key) == token {
                i.states.insert(key.clone(), ConnectionState::Disconnected);
                i.set_op(&key, None);
            }
        });
        self.refresh();
    }

    pub fn connect_system(&self, s: &SystemVpn) {
        if self.is_locked() {
            return;
        }
        let key = s.id.clone();
        let token = self.mutate(|i| {
            i.want_down.remove(&key);
            i.auth_cancelled.remove(&key);
            i.awaiting_success.insert(key.clone());
            i.set_op(&key, Some(Op::Connecting));
            i.states.insert(key.clone(), ConnectionState::Connecting);
            i.key_epoch(&key)
        });
        let result = (|| -> Result<(), String> {
            let mut secrets = Zeroizing::new(self.system_secrets(s));
            if s.supports_stored_secrets() {
                let otp = self.system_otp_setting(&s.id);
                let Some(prepared) = self.code_secrets(&key, &s.name, VPNKind::L2tp, None, otp, &secrets)? else {
                    self.abandon_connect(&key, &s.name, token);
                    return Ok(());
                };
                if self.read(|i| i.key_epoch(&key)) != token || self.is_locked() {
                    self.abandon_connect(&key, &s.name, token);
                    return Ok(());
                }
                secrets = prepared;
            }
            self.deps.native.start(&s.id, NativeKind::from_type_label(&s.type_label), &secrets)?;
            let now = self.now();
            let late = self.mutate(|i| {
                if i.key_epoch(&key) != token {
                    return Some(i.want_down.contains(&key));
                }
                // As for the managed native ones: the refresh decides, so a failure is not a silent "disconnected".
                i.set_op(
                    &key,
                    Some(Op::AwaitingNative { started: now, saw_connecting: false, service_id: s.id.clone() }),
                );
                i.states.insert(key.clone(), ConnectionState::Connecting);
                None
            });
            if let Some(want_down) = late
                && want_down
            {
                let _ = self.deps.native.stop(&s.id);
                self.mutate(|i| i.settle_after_teardown(&key));
            }
            Ok(())
        })();
        if let Err(error) = result {
            let event = self.mutate(|i| {
                if i.key_epoch(&key) != token {
                    return None;
                }
                let reason = if i.auth_cancelled.remove(&key) { auth_cancelled_reason() } else { error };
                i.states.insert(key.clone(), ConnectionState::Failed(reason.clone()));
                i.set_op(&key, None);
                i.awaiting_success.remove(&key);
                Some(ConnectionEvent::Failed { connection_id: key.clone(), name: s.name.clone(), reason })
            });
            self.emit(event.into_iter().collect());
        }
    }

    /// A disconnect the user asked for ([`DisconnectCause::User`]).
    pub fn disconnect_system(&self, s: &SystemVpn) {
        self.disconnect_system_for(s, DisconnectCause::User);
    }

    pub fn disconnect_system_for(&self, s: &SystemVpn, cause: DisconnectCause) {
        self.user_disconnected(&s.id, cause);
        self.mutate(|i| {
            i.want_down.insert(s.id.clone());
            i.awaiting_success.remove(&s.id);
            i.set_op(&s.id, Some(Op::Disconnecting));
            i.auth_waits.remove(&s.id);
            i.states.insert(s.id.clone(), ConnectionState::Disconnecting);
        });
        self.dismiss(&s.id);
        let _ = self.deps.native.stop(&s.id);
        self.mutate(|i| {
            i.states.insert(s.id.clone(), ConnectionState::Disconnected);
            i.set_op(&s.id, None);
        });
        self.refresh();
    }

    /// Disconnects the active managed connections (on quit).
    pub fn disconnect_all(&self) {
        for c in self.connections() {
            if self.state(&uuid_string(&c.id)).is_active() {
                self.disconnect(&c);
            }
        }
    }

    // MARK: - MFA

    pub fn system_otp(&self) -> HashMap<String, OTPSetting> {
        self.read(|i| i.system_otp.clone())
    }

    pub fn system_otp_setting(&self, id: &str) -> OTPSetting {
        self.read(|i| i.system_otp.get(id).copied().unwrap_or_default())
    }

    pub fn set_system_otp(&self, setting: OTPSetting, id: &str) {
        self.mutate(|i| {
            if i.locked {
                return;
            }
            if setting.enabled {
                i.system_otp.insert(id.to_string(), setting);
            } else {
                i.system_otp.remove(id);
            }
            if let Some(store) = &self.deps.system_otp_store {
                let _ = store.save(&i.system_otp);
            }
        });
    }

    /// A request to the UI; meanwhile the connection is "waiting for authentication". After a web sign-in was
    /// opened it stays so while `up` runs. `stop`: the auth watcher's cancel flag (checked atomically with the
    /// state change, so a stopped watcher never leaves the connection waiting).
    fn ask(
        &self,
        key: &str,
        name: &str,
        kind: AuthPromptKind,
        deadline: PromptDeadline,
        stop: Option<&AtomicBool>,
    ) -> AuthPromptResult {
        let Some(handler) = self.hooks().prompt_handler else { return AuthPromptResult::Cancelled };
        let wait_kind =
            if matches!(kind, AuthPromptKind::WebAuth { .. }) { AuthWaitKind::Web } else { AuthWaitKind::Code };
        let asked = self.mutate(|i| {
            if stop.is_some_and(|s| s.load(Ordering::SeqCst)) {
                return false;
            }
            i.set_awaiting(key, Some(AuthWait { kind: wait_kind, deadline: Some(deadline.end()) }));
            true
        });
        if !asked {
            return AuthPromptResult::Cancelled;
        }
        let result =
            handler(AuthPrompt { connection_id: key.to_string(), connection_name: name.to_string(), kind, deadline });
        self.mutate(|i| {
            if wait_kind == AuthWaitKind::Code || result != AuthPromptResult::OpenedUrl {
                i.set_awaiting(key, None);
            }
            if result == AuthPromptResult::TimedOut {
                i.auth_timed_out.insert(key.to_string());
            }
            if result == AuthPromptResult::Cancelled && !stop.is_some_and(|s| s.load(Ordering::SeqCst)) {
                i.auth_cancelled.insert(key.to_string());
            }
        });
        result
    }

    // MARK: - Credentials

    /// The credential prompt; meanwhile the connection is "waiting for credentials". `None`: cancelled, dismissed
    /// or expired.
    fn ask_credentials(&self, prompt: CredentialPrompt) -> Option<(CredentialValues, bool)> {
        let handler = self.hooks().credential_handler?;
        let key = prompt.connection_id.clone();
        let deadline = prompt.deadline.end();
        let asked = self.mutate(|i| {
            // The user disconnected (or the connect ended) before the prompt opened: nothing is asked.
            if i.ops.get(&key) != Some(&Op::Connecting) {
                return false;
            }
            i.set_awaiting(&key, Some(AuthWait { kind: AuthWaitKind::Credentials, deadline: Some(deadline) }));
            true
        });
        if !asked {
            return None;
        }
        let answer = handler(prompt);
        let cancelled = matches!(answer, CredentialAnswer::Cancelled);
        self.mutate(|i| {
            i.set_awaiting(&key, None);
            if cancelled {
                i.credentials_cancelled.insert(key.clone());
            }
        });
        match answer {
            CredentialAnswer::Provided { values, save } => Some((values, save)),
            CredentialAnswer::Cancelled => None,
        }
    }

    /// The stored secrets with the asked credentials over them. Asks for the missing required fields (`retry`:
    /// after a sign-in failure, the user name and password again, plus a missing PSK / key password); nothing to
    /// ask, or no credential window: the stored secrets as they are. `native_account`: a managed native
    /// connection's account, which counts as its user name. `None`: the prompt was cancelled.
    #[allow(clippy::too_many_arguments)]
    fn credential_secrets(
        &self,
        key: &str,
        name: &str,
        id: &Uuid,
        kind: VPNKind,
        required: &RequiredFields,
        native_account: Option<String>,
        base: Zeroizing<Secrets>,
        retry: bool,
    ) -> Option<Prepared> {
        let mut stored = base.clone();
        if stored.username.as_deref().unwrap_or("").is_empty() {
            stored.username.clone_from(&native_account);
        }
        let fields = if retry { retry_fields(required, &stored) } else { credentials::missing(required, &stored) };
        let username = stored.username.clone().filter(|u| !u.is_empty());
        drop(stored);
        if fields.is_empty() || self.hooks().credential_handler.is_none() {
            return Some(Prepared { secrets: base, save: None });
        }
        let asked: Vec<SecretField> = fields.iter().copied().map(secret_field).collect();
        let credential = crate::shared_credentials::prompt_credential(self.deps.secrets.as_ref(), id, &asked);
        let prompt = CredentialPrompt {
            connection_id: key.to_string(),
            connection_name: name.to_string(),
            kind,
            fields,
            username,
            retry,
            deadline: PromptDeadline::new(self.now()),
            credential,
        };
        let (values, save) = self.ask_credentials(prompt)?;
        let secrets = credentials::apply(&values, &base);
        let save = save.then(|| {
            let prior = values
                .fields()
                .into_iter()
                .map(|f| (f, Zeroizing::new(stored_value(&base, f).unwrap_or_default().to_string())))
                .collect();
            PendingSave {
                id: *id,
                values,
                prior,
                native: kind.is_native(),
                prior_account: native_account.unwrap_or_default(),
            }
        });
        Some(Prepared { secrets, save })
    }

    /// Keeps the "Save" values until the connect is up. False: the connect is no longer the latest (the user
    /// disconnected or connected again meanwhile); the values are dropped.
    fn keep_save(&self, key: &str, token: u64, save: Option<PendingSave>) -> bool {
        self.mutate(|i| {
            if i.key_epoch(key) != token {
                return false;
            }
            match save {
                Some(save) => i.pending_saves.insert(key.to_string(), save),
                None => i.pending_saves.remove(key),
            };
            true
        })
    }

    /// Writes the values of connects that came up (outside the lock). A failing write is not reported: the
    /// connection is up, and the prompt asks again next time.
    fn write_saves(&self, saves: Vec<PendingSave>) {
        if saves.is_empty() {
            return;
        }
        let (Some(writer), Some(this)) = (self.deps.secret_writer.clone(), self.this.upgrade()) else { return };
        // Off the refresh / poller thread: a Keychain write can wait for the user (a macOS access prompt).
        *self.saves_in_flight.0.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        let spawned = std::thread::Builder::new().name("macvpn-cred-save".into()).spawn(move || {
            for save in saves {
                this.write_save(writer.as_ref(), &save);
            }
            let (count, done) = &*this.saves_in_flight;
            *count.lock().unwrap_or_else(PoisonError::into_inner) -= 1;
            done.notify_all();
        });
        if spawned.is_err() {
            let (count, done) = &*self.saves_in_flight;
            *count.lock().unwrap_or_else(PoisonError::into_inner) -= 1;
            done.notify_all();
        }
    }

    fn write_save(&self, writer: &dyn SecretWriter, save: &PendingSave) {
        // A deleted connection never gets its items back (`forget_saves` marks it before the Keychain items go).
        if !self.read(|i| !i.forgotten.contains(&save.id) && i.connections.iter().any(|c| c.id == save.id)) {
            return;
        }
        for (field, prior) in &save.prior {
            let Some(value) = save.values.get(*field) else { continue };
            let target = secret_field(*field);
            let current = Zeroizing::new(self.deps.secrets.get(&save.id, target).unwrap_or_default());
            if *current == **prior {
                // The prompt's write (spec 3a): a linked item's username / password goes to its shared credential,
                // which an editor's `set` may never change.
                writer.save_prompted(value, &save.id, target);
            }
        }
        let Some(account) = save.values.get(CredentialField::Username).filter(|_| save.native) else { return };
        // The freshly stored meta, patched (never the cached copy: an edit made during the connect stays).
        let Ok(list) = self.deps.store.list() else { return };
        let Some(mut fresh) = list.into_iter().find(|c| c.id == save.id) else { return };
        let Some(native) = fresh.native.as_mut() else { return };
        if native.account != save.prior_account {
            return;
        }
        native.account = account.to_string();
        if self.deps.store.save(&fresh, None).is_ok() {
            self.mutate(|i| {
                if let Some(native) = i.connections.iter_mut().find(|c| c.id == save.id).and_then(|c| c.native.as_mut())
                {
                    native.account = account.to_string();
                }
            });
        }
    }

    /// The key's last connect ended because its credential prompt was cancelled or expired.
    pub fn credentials_cancelled(&self, key: &str) -> bool {
        self.read(|i| i.credentials_cancelled.contains(key))
    }

    /// Waits until the "Save" writes started so far are done.
    pub fn flush_saves(&self) {
        let (count, done) = &*self.saves_in_flight;
        let mut n = count.lock().unwrap_or_else(PoisonError::into_inner);
        while *n > 0 {
            n = done.wait(n).unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// The connection is being deleted: its pending "Save" values are dropped, a write in progress finishes
    /// first, and no later write happens. Call before deleting its Keychain items.
    pub fn forget_saves(&self, id: &Uuid) {
        self.mutate(|i| {
            i.forgotten.insert(*id);
            i.pending_saves.retain(|_, s| s.id != *id);
            i.ready_saves.retain(|s| s.id != *id);
        });
        self.flush_saves();
    }

    /// The code asked before connecting: the OpenVPN static challenge (by the config's `static-challenge` line,
    /// SCRV1 or concat), otherwise the "code after the password" setting. The code only lives in the returned
    /// `Secrets` (stdin, or the `SCNetworkConnection` options), never stored. `None`: cancelled or expired.
    fn code_secrets(
        &self,
        key: &str,
        name: &str,
        kind: VPNKind,
        config: Option<&str>,
        otp: OTPSetting,
        base: &Secrets,
    ) -> Result<Option<Zeroizing<Secrets>>, String> {
        if kind == VPNKind::Openvpn
            && let Some(challenge) = config.and_then(mfa::static_challenge)
        {
            let prompt =
                AuthPromptKind::Code { text: challenge.text.clone(), echo: challenge.echo, from_server: false };
            let AuthPromptResult::Code(code) = self.ask(key, name, prompt, PromptDeadline::new(self.now()), None)
            else {
                return Ok(None);
            };
            let code = Zeroizing::new(code);
            return mfa::apply_static_challenge(&challenge, &code, base).map(Some).map_err(|e| e.message());
        }
        if !otp.enabled || kind == VPNKind::Wireguard {
            return Ok(Some(Zeroizing::new(base.clone())));
        }
        let text = l10n::tr("Enter the one-time code. MacVPN appends it to the password for this connection.", &[]);
        let prompt = AuthPromptKind::Code { text, echo: true, from_server: false };
        let AuthPromptResult::Code(code) = self.ask(key, name, prompt, PromptDeadline::new(self.now()), None) else {
            return Ok(None);
        };
        let code = Zeroizing::new(code);
        mfa::apply_code(&code, otp.separator, base, kind).map(Some).map_err(|e| e.message())
    }

    /// The code prompt was cancelled or expired: no connect. Cancelled: `disconnected`; expired: failure.
    fn abandon_connect(&self, key: &str, name: &str, token: u64) {
        let event = self.mutate(|i| {
            if i.key_epoch(key) != token {
                return None;
            }
            i.set_awaiting(key, None);
            i.set_op(key, None);
            i.awaiting_success.remove(key);
            i.auth_cancelled.remove(key);
            if i.auth_timed_out.remove(key) {
                i.states.insert(key.to_string(), ConnectionState::Failed(auth_timeout_reason()));
                Some(ConnectionEvent::Failed {
                    connection_id: key.to_string(),
                    name: name.to_string(),
                    reason: auth_timeout_reason(),
                })
            } else {
                i.states.insert(key.to_string(), ConnectionState::Disconnected);
                None
            }
        });
        self.emit(event.into_iter().collect());
    }

    /// Watches the state file during an OpenVPN `up`. The returned ID stops it (a late `up` cannot stop the
    /// watcher of a newer connect).
    fn start_auth_watch(&self, c: &Connection) -> u64 {
        let key = uuid_string(&c.id);
        let id = self.next_watch_id.fetch_add(1, Ordering::SeqCst);
        let stop = Arc::new(AtomicBool::new(false));
        {
            let mut i = self.lock();
            if let Some(old) = i.auth_watchers.insert(key, Watcher { id, stop: stop.clone() }) {
                old.stop.store(true, Ordering::SeqCst);
            }
        }
        let this = self.this.clone();
        let c = c.clone();
        std::thread::Builder::new()
            .name("macvpn-auth-watch".into())
            .spawn(move || Self::watch_auth(&this, &c, &stop))
            .ok();
        id
    }

    fn stop_auth_watch(&self, key: &str, id: u64) {
        let stopped = self.mutate(|i| {
            if i.auth_watchers.get(key).map(|w| w.id) != Some(id) {
                return false;
            }
            if let Some(w) = i.auth_watchers.remove(key) {
                w.stop.store(true, Ordering::SeqCst);
            }
            i.set_awaiting(key, None);
            true
        });
        if stopped {
            self.dismiss(key);
        }
    }

    fn watch_auth(this: &Weak<ConnectionManager>, c: &Connection, stop: &AtomicBool) {
        let mut handled: i64 = -1;
        while !stop.load(Ordering::SeqCst) {
            let interval = {
                let Some(manager) = this.upgrade() else { return };
                if let Some(state) = manager.deps.auth_state.read(&c.id)
                    && state.seq != handled
                {
                    handled = state.seq;
                    manager.handle_auth_state_inner(&state, c, Some(stop));
                }
                Duration::from_millis(manager.auth_poll_millis.load(Ordering::SeqCst).max(50))
            };
            let mut slept = Duration::ZERO;
            while slept < interval && !stop.load(Ordering::SeqCst) {
                let step = (interval - slept).min(Duration::from_millis(50));
                std::thread::sleep(step);
                slept += step;
            }
        }
    }

    /// A new state of the bridge: code prompt (CRV1, CR_TEXT, static fallback), web authentication, waiting.
    pub fn handle_auth_state(&self, state: &AuthUIState, c: &Connection) {
        self.handle_auth_state_inner(state, c, None);
    }

    fn handle_auth_state_inner(&self, state: &AuthUIState, c: &Connection, stop: Option<&AtomicBool>) {
        let key = uuid_string(&c.id);
        let now = self.now();
        let cancelled = || stop.is_some_and(|s| s.load(Ordering::SeqCst));
        // A state with an expired deadline (e.g. the leftover of a crashed earlier run that `mvpn up` has not
        // deleted yet) is skipped, otherwise the prompt expiring at once would cancel the new connect.
        if let Some(deadline) = state.deadline_date()
            && deadline <= now
        {
            return;
        }
        match state.state {
            AuthUIStateKind::Challenge => {
                let deadline = PromptDeadline::until(now, state.deadline_date(), mfa::CODE_PROMPT_TIMEOUT);
                let text = match state.text.as_deref() {
                    Some(t) if !t.is_empty() => t.to_string(),
                    _ => l10n::tr("The server asks for a code.", &[]),
                };
                let prompt = AuthPromptKind::Code { text, echo: state.echo.unwrap_or(false), from_server: true };
                let result = self.ask(&key, &c.name, prompt, deadline, stop);
                if cancelled() {
                    return;
                }
                let _ = match result {
                    AuthPromptResult::Code(code) => {
                        let kind = if state.method == Some(AuthUIMethod::Static) {
                            AuthResponseKind::Static
                        } else {
                            AuthResponseKind::Crv1
                        };
                        self.deps.helper.respond(&c.id, kind, &code)
                    }
                    _ => self.deps.helper.respond(&c.id, AuthResponseKind::Cancel, ""),
                };
            }
            AuthUIStateKind::Webauth => {
                let Some(url) = state.url.as_deref().and_then(WebAuthURL::validate) else { return };
                let deadline = PromptDeadline::until(now, state.deadline_date(), mfa::WEB_AUTH_TIMEOUT);
                let result = self.ask(&key, &c.name, AuthPromptKind::WebAuth { url }, deadline, stop);
                if cancelled() {
                    return;
                }
                let kind = if result == AuthPromptResult::OpenedUrl {
                    AuthResponseKind::WebauthAck
                } else {
                    AuthResponseKind::Cancel
                };
                let _ = self.deps.helper.respond(&c.id, kind, "");
            }
            AuthUIStateKind::Pending => {
                self.mutate(|i| {
                    if !cancelled() {
                        i.set_awaiting(
                            &key,
                            Some(AuthWait { kind: AuthWaitKind::Web, deadline: state.deadline_date() }),
                        );
                    }
                });
            }
            AuthUIStateKind::Failed | AuthUIStateKind::Cancelled | AuthUIStateKind::Done => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::sstp_with_user;

    const SSTP: &str = "server=vpn.example.com\nport=443\nuser=placeholder\ncert=system\nroute_all=yes\npeer_dns=yes\n";

    #[test]
    fn the_slot_user_replaces_the_user_line_of_a_valid_config() {
        let sent = sstp_with_user(SSTP, "alice").unwrap();
        assert!(sent.contains("user=alice\n"), "{sent}");
        assert!(!sent.contains("placeholder"));
    }

    #[test]
    fn an_invalid_stored_config_is_refused_not_rewritten() {
        // Parsing and serializing would drop the line the validator refuses and send a "clean" config.
        let stored = format!("{SSTP}plugin=/tmp/evil.so\n");
        let e = sstp_with_user(&stored, "alice").unwrap_err();
        assert!(e.contains("plugin"), "{e}");
        assert!(sstp_with_user("server=\n", "alice").is_err());
    }
}
