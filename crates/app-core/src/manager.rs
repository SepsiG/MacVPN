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
    AuthStateReader, Clock, ConnectionRepository, NativeController, NoAuthState, RankingPersistence, RootClient,
    SecretField, SecretReader, SystemClock, SystemOTPPersistence, SystemService,
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
use macvpn_core::validators::OpenVPNValidator;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, Weak};
use std::time::Duration;
use uuid::Uuid;

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
    System(SystemService),
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

/// How a managed native connection maps to the listed services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeMatch {
    Service(SystemService),
    None,
    /// No bound ID, and more than one service has the name.
    Ambiguous(Vec<SystemService>),
}

/// Bound ID: only that counts (vanished: `None`); otherwise the name, with a unique match.
pub fn match_service(c: &Connection, services: &[SystemService]) -> NativeMatch {
    if let Some(id) = &c.native_service_id {
        return services.iter().find(|s| &s.id == id).cloned().map_or(NativeMatch::None, NativeMatch::Service);
    }
    let name = c.native_service_name.as_deref().unwrap_or(&c.name);
    let named: Vec<SystemService> = services.iter().filter(|s| s.name == name).cloned().collect();
    match named.len() {
        0 => NativeMatch::None,
        1 => NativeMatch::Service(named[0].clone()),
        _ => NativeMatch::Ambiguous(named),
    }
}

/// The service IDs of the managed native connections (these are not shown as system VPNs). For an unbound
/// connection, every service with its name.
pub fn managed_service_ids(connections: &[Connection], services: &[SystemService]) -> HashSet<String> {
    let mut ids = HashSet::new();
    for c in connections.iter().filter(|c| c.kind.is_native()) {
        match match_service(c, services) {
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

fn timed_out() -> String {
    l10n::tr("Timed out", &[])
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
pub type ChangeHook = Arc<dyn Fn() + Send + Sync>;

#[derive(Default, Clone)]
struct Hooks {
    on_event: Option<EventHook>,
    on_native_services_seen: Option<ServicesSeenHook>,
    prompt_handler: Option<PromptHandler>,
    dismiss_prompt: Option<DismissHook>,
    on_change: Option<ChangeHook>,
}

/// The manager's dependencies.
#[derive(Clone)]
pub struct Dependencies {
    pub store: Arc<dyn ConnectionRepository>,
    pub secrets: Arc<dyn SecretReader>,
    pub root: Arc<dyn RootClient>,
    pub native: Arc<dyn NativeController>,
    pub ranking_store: Option<Arc<dyn RankingPersistence>>,
    pub system_otp_store: Option<Arc<dyn SystemOTPPersistence>>,
    pub auth_state: Arc<dyn AuthStateReader>,
    pub clock: Arc<dyn Clock>,
}

impl Dependencies {
    /// No ranking / system OTP persistence, no MFA state file, the system clock.
    pub fn new(
        store: Arc<dyn ConnectionRepository>,
        secrets: Arc<dyn SecretReader>,
        root: Arc<dyn RootClient>,
        native: Arc<dyn NativeController>,
    ) -> Self {
        Dependencies {
            store,
            secrets,
            root,
            native,
            ranking_store: None,
            system_otp_store: None,
            auth_state: Arc::new(NoAuthState),
            clock: Arc::new(SystemClock),
        }
    }
}

struct Watcher {
    id: u64,
    stop: Arc<AtomicBool>,
}

#[derive(Default)]
struct Inner {
    connections: Vec<Connection>,
    /// Only the system VPNs the app does not manage.
    system_services: Vec<SystemService>,
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
        service: Option<&SystemService>,
        now: Date,
        failure_reason: impl FnOnce() -> String,
        to_stop: &mut Vec<String>,
    ) -> Option<ConnectionState> {
        let Some(Op::AwaitingNative { started, saw_connecting, service_id }) = self.ops.get(key).cloned() else {
            return None;
        };
        let elapsed = now.time_interval_since(started);
        match service.map(SystemService::connection_state) {
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
}

/// A consistent copy of everything the UI shows.
#[derive(Debug, Clone, PartialEq)]
pub struct ManagerSnapshot {
    /// In ranking order (pinned first).
    pub items: Vec<(ConnectionItem, ConnectionState, bool)>,
    pub status_error: Option<String>,
    pub has_active: bool,
    pub has_failure: bool,
    pub awaiting_auth: bool,
}

pub struct ConnectionManager {
    deps: Dependencies,
    inner: Mutex<Inner>,
    hooks: RwLock<Hooks>,
    this: Weak<ConnectionManager>,
    /// The state file is read this often during an OpenVPN `up` (milliseconds).
    auth_poll_millis: AtomicU64,
    next_watch_id: AtomicU64,
}

impl ConnectionManager {
    pub fn new(deps: Dependencies) -> Arc<Self> {
        let ranking = deps.ranking_store.as_ref().map(|s| s.load()).unwrap_or_default();
        let system_otp = deps.system_otp_store.as_ref().map(|s| s.load()).unwrap_or_default();
        Arc::new_cyclic(|this| ConnectionManager {
            deps,
            inner: Mutex::new(Inner { ranking, system_otp, ..Inner::default() }),
            hooks: RwLock::new(Hooks::default()),
            this: this.clone(),
            auth_poll_millis: AtomicU64::new(500),
            next_watch_id: AtomicU64::new(1),
        })
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

    /// Something the UI shows may have changed (the Swift `objectWillChange`).
    pub fn set_on_change(&self, hook: impl Fn() + Send + Sync + 'static) {
        self.set_hooks(|h| h.on_change = Some(Arc::new(hook)));
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

    fn changed(&self) {
        if let Some(hook) = self.hooks().on_change {
            hook();
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

    pub fn system_services(&self) -> Vec<SystemService> {
        self.read(|i| i.system_services.clone())
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

    pub fn installed_native_ids(&self) -> HashSet<Uuid> {
        self.read(|i| i.installed_native_ids.clone())
    }

    pub fn ranking(&self) -> ConnectionRanking {
        self.read(|i| i.ranking.clone())
    }

    pub fn has_active(&self) -> bool {
        self.read(Inner::has_active)
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

    pub fn reload(&self) {
        let list = self.deps.store.list();
        self.mutate(|i| {
            if let Ok(list) = list {
                i.connections = list;
                i.loaded = true;
            }
            i.remote_addresses.clear();
        });
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
            i.ranking.pin(id);
            self.save_ranking(&i.ranking);
        });
    }

    pub fn unpin(&self, id: &str) {
        self.mutate(|i| {
            i.ranking.unpin(id);
            self.save_ranking(&i.ranking);
        });
    }

    /// A drag in the pinned section, with the indexes of [`Self::pinned_items`] (SwiftUI `onMove`).
    pub fn move_pinned(&self, source: &BTreeSet<usize>, destination: usize) {
        let now = self.now();
        self.mutate(|i| {
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
                }
                Some(
                    ConnectionState::Connecting | ConnectionState::Disconnecting | ConnectionState::AwaitingAuth(_),
                ) => {}
                _ => {
                    // Failed or disconnected without an operation in flight: this attempt did not succeed.
                    if !i.ops.contains_key(&key) {
                        i.awaiting_success.remove(&key);
                    }
                }
            }
        }
        if changed {
            self.save_ranking(&i.ranking);
        }
    }

    // MARK: - Native service binding

    /// Binding: a bound but vanished ID is cleared; an unbound connection binds to the first service with its
    /// name whose server address matches too (and that no other connection is bound to). Saved to `meta.json`.
    fn bind_native_services(&self, services: &[SystemService]) {
        let listed: HashSet<&str> = services.iter().map(|s| s.id.as_str()).collect();
        let snapshot = self.read(|i| i.connections.clone());
        {
            let mut i = self.lock();
            i.remote_addresses.retain(|k, _| listed.contains(k.as_str()));
        }
        for c in snapshot.iter().filter(|c| c.kind.is_native()) {
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
                let _ = self.deps.store.save(&updated, None);
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
            match self.deps.root.status() {
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
        let now = self.now();
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
                    let service = match match_service(&c, services) {
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
                    service.map_or(ConnectionState::Disconnected, |s| s.connection_state())
                } else {
                    let Some(root) = &root else {
                        next.insert(key, previous.unwrap_or(ConnectionState::Disconnected));
                        continue;
                    };
                    root.iter().find(|r| r.id == c.id).map_or(ConnectionState::Disconnected, |r| r.connection_state())
                };
                let resolved = i.resolve(&key, &c.name, previous.as_ref(), current, c.kind.is_native());
                next.insert(key, resolved);
            }

            if let Some(services) = &services {
                let managed = managed_service_ids(&i.connections, services);
                i.installed_native_ids = i
                    .connections
                    .iter()
                    .filter(|c| c.kind.is_native() && match_service(c, services) != NativeMatch::None)
                    .map(|c| c.id)
                    .collect();
                let unmanaged: Vec<SystemService> =
                    services.iter().filter(|s| !managed.contains(&s.id)).cloned().collect();
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
                    let resolved = i.resolve(&s.id, &s.name, previous.as_ref(), s.connection_state(), true);
                    next.insert(s.id.clone(), resolved);
                }
                i.system_services = unmanaged;
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
    pub fn system_failure_reason(&self, s: &SystemService) -> String {
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

    /// The PSK / password stored for a system VPN in MacVPN's keychain (L2TP / Cisco IPsec only).
    pub fn system_secrets(&self, s: &SystemService) -> Secrets {
        let (true, Some(id)) = (s.supports_stored_secrets(), s.secret_id()) else { return Secrets::default() };
        Secrets {
            password: self.deps.secrets.get(&id, SecretField::Password),
            psk: self.deps.secrets.get(&id, SecretField::Psk),
            ..Secrets::default()
        }
    }

    // MARK: - Connect / disconnect

    pub fn connect(&self, c: &Connection, debug: bool) {
        let (c, key, mut token) = self.mutate(|i| {
            let c = i.current(c);
            let key = uuid_string(&c.id);
            i.want_down.remove(&key);
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
                let reason = if i.auth_timed_out.remove(&key) { auth_timeout_reason() } else { error };
                i.set_awaiting(&key, None);
                i.states.insert(key.clone(), ConnectionState::Failed(reason.clone()));
                i.set_op(&key, None);
                i.awaiting_success.remove(&key);
                Some(ConnectionEvent::Failed { connection_id: key.clone(), name: c.name.clone(), reason })
            });
            self.emit(event.into_iter().collect());
        }
    }

    fn connect_native(&self, c: &Connection, key: &str, token: &mut u64) -> Result<(), String> {
        let name = c.native_service_name.clone().unwrap_or_else(|| c.name.clone());
        let services = self.deps.native.list()?;
        let service = match match_service(c, &services) {
            NativeMatch::Service(s) => {
                // An unbound connection only matched by name: it may get the secrets only if the service's server
                // address (`scutil --nc show`, read fresh) is the connection's server. Otherwise it does not start
                // at all, not even without secrets.
                if c.native_service_id.is_none() {
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
        let base = self.deps.secrets.secrets(&c.id);
        let Some(prepared) = self.code_secrets(key, &c.name, c.kind, None, c.otp, base)? else {
            self.abandon_connect(key, &c.name, *token);
            return Ok(());
        };
        if self.read(|i| i.key_epoch(key)) != *token {
            return Ok(());
        }
        self.deps.native.start(&service.id, NativeKind::from_kind(c.kind), &prepared)?;
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
        let config = if c.kind == VPNKind::Openvpn { self.deps.store.load_config(&c.id).ok() } else { None };
        if c.kind == VPNKind::Openvpn
            && let Some(reason) = unacknowledged_risk_reason(c, config.as_deref())
        {
            return Err(reason);
        }
        // MFA: static challenge / "code after the password" before connecting; for OpenVPN the bridge's state
        // file is watched during `up` (dynamic challenge, web authentication).
        let base = self.deps.secrets.secrets(&c.id);
        let Some(prepared) = self.code_secrets(key, &c.name, c.kind, config.as_deref(), c.otp, base)? else {
            self.abandon_connect(key, &c.name, token);
            return Ok(());
        };
        if self.read(|i| i.key_epoch(key)) != token {
            return Ok(());
        }
        let watch = (c.kind == VPNKind::Openvpn).then(|| self.start_auth_watch(c));
        let accept_risky =
            if c.kind == VPNKind::Openvpn { c.acknowledged_risky_directives.clone() } else { Vec::new() };
        let up = self.deps.root.up(c.kind, &c.id, &prepared, debug, &accept_risky);
        if let Some(watch) = watch {
            self.stop_auth_watch(key, watch);
        }
        up?;
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
                    let _ = self.deps.root.down(c.kind, &c.id);
                    self.mutate(|i| i.settle_after_teardown(key));
                }
            }
            None => self.refresh(),
        }
        Ok(())
    }

    pub fn disconnect(&self, c: &Connection) {
        let (c, key, was_connecting, token) = self.mutate(|i| {
            let c = i.current(c);
            let key = uuid_string(&c.id);
            let was_connecting = matches!(i.ops.get(&key), Some(Op::Connecting));
            i.want_down.insert(key.clone());
            i.awaiting_success.remove(&key);
            i.set_op(&key, Some(Op::Disconnecting));
            let token = i.key_epoch(&key);
            i.auth_waits.remove(&key);
            i.states.insert(key.clone(), ConnectionState::Disconnecting);
            (c, key, was_connecting, token)
        });
        self.dismiss(&key);
        // OpenVPN while connecting (even waiting for authentication): cancelled through the bridge, so `up` cleans
        // up and releases the lock at once, and `down` does not wait for it. Without a running bridge the error
        // does not matter.
        if c.kind == VPNKind::Openvpn && was_connecting {
            let _ = self.deps.root.respond(&c.id, AuthResponseKind::Cancel, "");
        }
        let result: Result<(), String> = if c.kind.is_native() {
            self.deps.native.list().and_then(|services| match match_service(&c, &services) {
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
            self.deps.root.down(c.kind, &c.id)
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

    pub fn connect_system(&self, s: &SystemService) {
        let key = s.id.clone();
        let token = self.mutate(|i| {
            i.want_down.remove(&key);
            i.awaiting_success.insert(key.clone());
            i.set_op(&key, Some(Op::Connecting));
            i.states.insert(key.clone(), ConnectionState::Connecting);
            i.key_epoch(&key)
        });
        let result = (|| -> Result<(), String> {
            let mut secrets = self.system_secrets(s);
            if s.supports_stored_secrets() {
                let otp = self.system_otp_setting(&s.id);
                let Some(prepared) = self.code_secrets(&key, &s.name, VPNKind::L2tp, None, otp, secrets)? else {
                    self.abandon_connect(&key, &s.name, token);
                    return Ok(());
                };
                if self.read(|i| i.key_epoch(&key)) != token {
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
        if let Err(reason) = result {
            let event = self.mutate(|i| {
                if i.key_epoch(&key) != token {
                    return None;
                }
                i.states.insert(key.clone(), ConnectionState::Failed(reason.clone()));
                i.set_op(&key, None);
                i.awaiting_success.remove(&key);
                Some(ConnectionEvent::Failed { connection_id: key.clone(), name: s.name.clone(), reason })
            });
            self.emit(event.into_iter().collect());
        }
    }

    pub fn disconnect_system(&self, s: &SystemService) {
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
        });
        result
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
        base: Secrets,
    ) -> Result<Option<Secrets>, String> {
        if kind == VPNKind::Openvpn
            && let Some(challenge) = config.and_then(mfa::static_challenge)
        {
            let prompt =
                AuthPromptKind::Code { text: challenge.text.clone(), echo: challenge.echo, from_server: false };
            let AuthPromptResult::Code(code) = self.ask(key, name, prompt, PromptDeadline::new(self.now()), None)
            else {
                return Ok(None);
            };
            return mfa::apply_static_challenge(&challenge, &code, &base).map(Some).map_err(|e| e.message());
        }
        if !otp.enabled || kind == VPNKind::Wireguard {
            return Ok(Some(base));
        }
        let text = l10n::tr("Enter the one-time code. MacVPN appends it to the password for this connection.", &[]);
        let prompt = AuthPromptKind::Code { text, echo: true, from_server: false };
        let AuthPromptResult::Code(code) = self.ask(key, name, prompt, PromptDeadline::new(self.now()), None) else {
            return Ok(None);
        };
        mfa::apply_code(&code, otp.separator, &base, kind).map(Some).map_err(|e| e.message())
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
                        self.deps.root.respond(&c.id, kind, &code)
                    }
                    _ => self.deps.root.respond(&c.id, AuthResponseKind::Cancel, ""),
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
                let _ = self.deps.root.respond(&c.id, kind, "");
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
