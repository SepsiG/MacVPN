//! The local control server (spec `2026-10-19-control-api-design.md`): another program of the same user pairs
//! with MacVPN over a local socket, lists the connections it may use, and holds one up through a socket lease.
//!
//! The pure parts live in `macvpn_core::control` (protocol, registry, lease table). This module runs them: an
//! accept thread, and per client connection a reader thread (requests) plus a writer thread (replies and
//! events, through a bounded queue so a slow client never blocks the manager). The system is reached through two
//! seams: [`ControlTransport`] (the endpoint, its client streams with the peer identity, and the entropy; the app
//! implements it over `macvpn-platform-mac::control_socket`) and [`ControlHost`] (the connections, the pairing window and the
//! log; the app implements it over the `ConnectionManager` and the UI).
//!
//! The manager's state changes and the user's own disconnects come in through a [`ControlNotifier`]. The app
//! attaches one [`ControlRelay`] to the manager at launch (it registers the manager listeners once) and plugs
//! the running server's notifier into it with [`ControlRelay::set`] (and `None` after stopping it).
//!
//! # Starting and stopping
//!
//! The setting's toggle calls [`ControlServer::start`] and [`ControlServer::stop`] with [`StopMode::EndLeases`].
//! Quitting calls `stop(StopMode::Detach)` first, before the quit question's answer is carried out: the clients
//! get `app_quitting` and lose their leases, but nothing is disconnected on their behalf, so "Quit, Keep Them
//! Running" is honoured and "Disconnect and Quit" disconnects as usual. `stop` blocks (it waits for the lease
//! disconnects): call it off the main thread.
//!
//! # The connect gap
//!
//! A lease's connect runs on its own thread and reaches the manager a moment later. Until the manager has taken
//! the connect (the state shows `connecting`), a disconnect would come too early: the manager's connect would
//! clear it and bring the VPN up with no lease. So a lease release that has to disconnect a key that is still
//! "starting" waits for that first (see `State::starting`).
//!
//! # Locking
//!
//! One mutex guards the server state. While it is held the server may call the host's read-only methods
//! ([`ControlHost::items`], [`ControlHost::state`]) but never [`ControlHost::setup_ready_for`] (it takes the app's
//! setup lock: under the mutex that would be a lock-order cycle with any app path that reads the setup and then asks
//! the server), nor
//! [`ControlHost::connect`] / [`ControlHost::disconnect`] / [`ControlHost::ask_pairing`]: those change the manager,
//! which calls the notifier, which takes the mutex. Writes to a client only enqueue (non-blocking); a client whose
//! queue is full is disconnected. The registry is written to disk outside the mutex: a snapshot is taken under it,
//! and a separate save lock keeps the saves in order.
//!
//! # Audit
//!
//! Pairings, hello failures, every `up` and `down` and every lease end go to [`ControlHost::log`], with the
//! client's name and executable path. Tokens never do: a token only exists in the `hello` request (redacted in
//! its `Debug`) and in the one pairing reply.

use crate::deps::{Clock, SystemClock};
use crate::manager::{ConnectionItem, auth_cancelled_reason, auth_timeout_reason};
use macvpn_core::control::lease::{LeaseAction, LeaseTable, SessionId};
use macvpn_core::control::protocol::{
    API_VERSION, ErrorCode, MAX_LINE, Request, WireState, escape_unsafe_text, event_closing, event_state,
    has_unsafe_text_chars, is_token_shaped, is_uuid_shaped, parse_line, reply_err, reply_ok, wire_state,
};
use macvpn_core::control::registry::{PairedClient, Registry, new_token};
use macvpn_core::l10n;
use macvpn_core::models::{ConnectionState, uuid_string};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use uuid::Uuid;

// MARK: - Seams

/// What the server needs from the app.
///
/// [`Self::items`], [`Self::state`], [`Self::credentials_cancelled`] and [`Self::log`] are called with the server's
/// mutex held and from the manager's listener path: they must return quickly, must not block, and must not call a
/// manager method that changes state (reading the manager's state is fine). The other methods are never called
/// with the mutex held.
pub trait ControlHost: Send + Sync {
    /// Every connection in the app's order (`ConnectionManager::ordered_items`).
    fn items(&self) -> Vec<ConnectionItem>;
    fn state(&self, key: &str) -> ConnectionState;
    /// Starts the connection the same way as a manual connect (managed: `connect(c, false)`, system VPN:
    /// `connect_system`); blocks until that call returns. `Err`: it could not even start (e.g. the key vanished).
    fn connect(&self, key: &str) -> Result<(), ErrorCode>;
    /// Stops the connection on behalf of a lease (`DisconnectCause::Lease`); blocks.
    fn disconnect(&self, key: &str);
    /// Starting `key` has what it needs: for a connection run by the root layer, Homebrew, the root layer and its
    /// type's tools; a system VPN or a native (L2TP / Cisco) connection needs none of them. Asked only when an
    /// `up` would start the connection (otherwise it is `setup_required`); joining one that is already up or
    /// coming up for another lease needs no setup. Never called with the server's mutex held (it may take the
    /// app's own locks); it must still return quickly.
    fn setup_ready_for(&self, key: &str) -> bool;
    /// Shows the pairing window and blocks until the user answered or it timed out. Runs on its own thread; the
    /// server stops waiting after `ControlLimits::pairing_timeout` (counted as timed out) and ignores a later answer.
    fn ask_pairing(&self, request: PairingRequest) -> PairingAnswer;
    /// One audit line for the debug log and the Log tab's "Control API" source.
    fn log(&self, line: String);
    /// The connection's last connect ended because the user cancelled (or let expire) the credential prompt
    /// (`ConnectionManager::credentials_cancelled`). Called with the server's mutex held: must return quickly.
    fn credentials_cancelled(&self, key: &str) -> bool;
    /// The vault is locked (1.2.0): `pair`, `hello`, `list`, `up` and `status` answer `locked`; `down` of an
    /// authenticated session still works (it only releases a lease). Never called with the server's mutex held;
    /// it must return quickly.
    fn locked(&self) -> bool {
        false
    }
    /// The platform has no VPN engine yet (WinVPN 2a): the localized answer to every connect ("The VPN engine comes
    /// in a later version of WinVPN."). An `up` that would start a connection, of any type, is then `failed` with
    /// it as the message, and nothing starts. Asked like [`Self::setup_ready_for`] (never with the server's mutex
    /// held; it must return quickly). `None` (macOS): connects as usual.
    fn engine_missing(&self) -> Option<String> {
        None
    }
    /// The connection `key`'s kind comes in a later version on this platform (WinVPN 2b: the native VPNs): the
    /// localized reason, and an `up` that would start it is `failed` with it as the message. Asked like
    /// [`Self::engine_missing`]. `None` (macOS, and every other kind): connects as usual.
    fn later_reason(&self, _key: &str) -> Option<String> {
        None
    }
    /// Why an `up` that would start `key` is `failed` with this message (nothing starts): the one decision of
    /// the app's `connect` command (`SetupReport::start_refusal`, WinVPN 2c: a missing WinVPN Service refuses
    /// neither the native kinds nor the system VPNs; a connection the platform cannot connect). Default:
    /// [`Self::engine_missing`], then [`Self::later_reason`].
    fn start_refusal(&self, key: &str) -> Option<String> {
        self.engine_missing().or_else(|| self.later_reason(key))
    }
}

/// Where the paired clients are kept: the vault (1.2, `vault_stores::VaultRegistry`) or, before the vault and in
/// the tests, `control-clients.json` ([`FileRegistryStore`]). A store that exists but cannot be read is an error,
/// never an empty registry (that would be saved over the real one at the next change and unpair every client).
pub trait RegistryStore: Send + Sync {
    fn load(&self) -> io::Result<Registry>;
    fn save(&self, registry: &Registry) -> io::Result<()>;
}

/// `control-clients.json` in a directory (the 1.1 storage).
pub struct FileRegistryStore {
    pub dir: PathBuf,
}

impl RegistryStore for FileRegistryStore {
    fn load(&self) -> io::Result<Registry> {
        Registry::load(&self.dir)
    }

    fn save(&self, registry: &Registry) -> io::Result<()> {
        registry.save(&self.dir)
    }
}

/// What the pairing window shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingRequest {
    /// Self-reported by the client (sanitized).
    pub name: String,
    /// The peer's executable path: the identity the pairing pins.
    pub executable: String,
    /// The connections that can be allowed: (key, name), in the app's order.
    pub items: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairingAnswer {
    /// The keys the user ticked.
    Approved(Vec<String>),
    Denied,
    TimedOut,
}

/// The transport seam (the endpoint, its client streams with the peer identity, the entropy): defined in
/// `macvpn-platform-api` and re-exported here (their old home).
pub use macvpn_platform_api::{
    Accepted, BoundEndpoint, ControlListener, ControlStream, ControlTransport, PeerIdentity, PeerUser,
};

// MARK: - Options

/// The limits of spec section 4 (the timings are shortened in tests).
#[derive(Debug, Clone)]
pub struct ControlLimits {
    pub max_clients: usize,
    /// `pair` or `hello` must arrive within this long after connecting.
    pub auth_timeout: Duration,
    /// A failed `hello` is answered after this long.
    pub hello_failure_delay: Duration,
    /// The token bucket: this many requests per second, bursts of as many.
    pub requests_per_second: u32,
    /// Lines waiting for one client; a client that lets more pile up is disconnected.
    pub queue_length: usize,
    /// A write to a client that blocks this long disconnects it.
    pub write_timeout: Duration,
    /// [`ControlServer::stop`] waits at most this long for the clients' leases to end (and a lease release at most
    /// this long for its connect to reach the manager).
    pub stop_timeout: Duration,
    /// The server's own limit on the pairing window (the window times out after 2 minutes itself).
    pub pairing_timeout: Duration,
    /// How often the accept thread looks at the stop flag while no client connects.
    pub accept_poll: Duration,
    /// At most this many `up`s waiting for their result per client connection.
    pub max_pending: usize,
}

impl Default for ControlLimits {
    fn default() -> Self {
        ControlLimits {
            max_clients: 8,
            auth_timeout: Duration::from_secs(5),
            hello_failure_delay: Duration::from_secs(1),
            requests_per_second: 20,
            queue_length: 64,
            write_timeout: Duration::from_secs(5),
            stop_timeout: Duration::from_secs(30),
            pairing_timeout: Duration::from_secs(120),
            accept_poll: Duration::from_millis(100),
            max_pending: 16,
        }
    }
}

pub struct ControlOptions {
    /// The socket's private directory (`<application support>/control`).
    pub socket_dir: PathBuf,
    /// The paired clients (the vault in the app).
    pub registry: Arc<dyn RegistryStore>,
    pub limits: ControlLimits,
    pub clock: Arc<dyn Clock>,
}

impl ControlOptions {
    /// The registry in `control-clients.json` below `registry_dir`.
    pub fn new(socket_dir: PathBuf, registry_dir: PathBuf) -> Self {
        Self::with_registry(socket_dir, Arc::new(FileRegistryStore { dir: registry_dir }))
    }

    pub fn with_registry(socket_dir: PathBuf, registry: Arc<dyn RegistryStore>) -> Self {
        ControlOptions { socket_dir, registry, limits: ControlLimits::default(), clock: Arc::new(SystemClock) }
    }
}

/// How [`ControlServer::stop`] ends the leases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopMode {
    /// The setting was turned off: pending `up`s get `disabled`, and the leases end as usual (a connection whose
    /// last lease ends goes down).
    EndLeases,
    /// MacVPN quits: pending `up`s get `app_quitting`, the leases end without any disconnect (the quit question
    /// decides about the connections, which are unleased from then on).
    Detach,
}

impl StopMode {
    fn code(self) -> ErrorCode {
        match self {
            StopMode::EndLeases => ErrorCode::Disabled,
            StopMode::Detach => ErrorCode::AppQuitting,
        }
    }
}

/// The manager's listeners, registered once, forwarding to the current server's notifier (if any).
#[derive(Default)]
pub struct ControlRelay {
    notifier: Mutex<Option<ControlNotifier>>,
}

impl ControlRelay {
    /// Registers the state and user-disconnect listeners on `manager` (call once, at launch).
    pub fn attach(manager: &crate::manager::ConnectionManager) -> Arc<ControlRelay> {
        let relay = Arc::new(ControlRelay::default());
        let states = Arc::downgrade(&relay);
        manager.add_state_listener(move |key, state| {
            if let Some(n) = states.upgrade().and_then(|r| r.current()) {
                n.state_changed(key, state);
            }
        });
        let users = Arc::downgrade(&relay);
        manager.add_user_disconnect_listener(move |key| {
            if let Some(n) = users.upgrade().and_then(|r| r.current()) {
                n.user_disconnected(key);
            }
        });
        relay
    }

    /// The running server's [`ControlServer::notifier`], or `None` once it stopped.
    pub fn set(&self, notifier: Option<ControlNotifier>) {
        *self.notifier.lock().unwrap_or_else(PoisonError::into_inner) = notifier;
    }

    fn current(&self) -> Option<ControlNotifier> {
        self.notifier.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

// MARK: - Texts

/// The `message` of a pending `up` whose connection the user disconnected in MacVPN.
pub fn user_disconnected_message() -> String {
    l10n::tr("Disconnected in MacVPN", &[])
}

/// The wire `kind` of a connection.
pub fn wire_kind(item: &ConnectionItem) -> &'static str {
    match item {
        ConnectionItem::Managed(c) => c.kind.raw_value(),
        ConnectionItem::System(_) => "system",
    }
}

// MARK: - Server state

enum Out {
    Line(String),
    /// Flush what is queued, then shut the socket down.
    Close,
}

struct Pending {
    key: String,
    id: u64,
    /// The connection waited for MFA during this `up`. A cancelled code prompt asked *before* connecting (static
    /// challenge, "code after the password") ends the manager's connect as `disconnected`, not as a failure (the
    /// menu shows no failure for a user's cancel, and no notification): so a plain `disconnected` after
    /// `waiting_for_mfa` that the user did not cause is reported as `mfa_cancelled`. A cancelled credential prompt
    /// ends the same way; the manager records it, and the host reports it ([`ControlHost::credentials_cancelled`]):
    /// `credentials_cancelled`. A prompt cancelled during `up` fails with `auth_cancelled_reason()` and is
    /// identified exactly.
    saw_mfa: bool,
}

struct Session {
    out: SyncSender<Out>,
    /// For shutting the socket down from another thread.
    stream: Box<dyn ControlStream>,
    pid: i32,
    executable: Option<String>,
    /// After a successful `hello`.
    client: Option<(Uuid, String)>,
    subscribed: bool,
    pending: Vec<Pending>,
    /// Keys whose lease ended under this client (user disconnect, drop): their events are still delivered until
    /// the connection is down.
    watching: HashSet<String>,
    /// Blocked in the pairing window (stop does not wait for it).
    pairing: bool,
    /// Its leases have ended; the disconnects are running.
    closing: bool,
}

impl Session {
    fn send(&self, line: String) {
        match self.out.try_send(Out::Line(line)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                let _ = self.stream.shutdown(Shutdown::Both);
            }
        }
    }

    fn close(&self) {
        if self.out.try_send(Out::Close).is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
    }

    fn who(&self) -> String {
        let exe = escape_unsafe_text(self.executable.as_deref().unwrap_or("?"));
        match &self.client {
            Some((_, name)) => format!("“{name}” ({exe}, pid {})", self.pid),
            None => format!("{exe} (pid {})", self.pid),
        }
    }
}

#[derive(Default)]
struct State {
    registry: Registry,
    leases: LeaseTable,
    sessions: BTreeMap<SessionId, Session>,
    next_session: SessionId,
    /// A pairing window is open.
    pairing: bool,
    /// Keys whose last lease ended and whose disconnect is running: `up` is `busy` meanwhile.
    releasing: HashMap<String, usize>,
    /// The last state delivered per key (repeats are not sent again).
    last_wire: HashMap<String, WireState>,
    /// Every key ever leased (the lease table has no listing; [`ControlServer::holders`] asks it per key).
    acquired: BTreeSet<String>,
    /// Keys whose lease connect has not reached the manager yet, with the lease's generation (the connect gap).
    starting: HashMap<String, u64>,
    /// The generation of each key's current lease entry (a stale connect thread must not end a newer lease).
    lease_generation: HashMap<String, u64>,
    next_generation: u64,
    /// `stop(Detach)`: lease ends never disconnect.
    detached: bool,
    /// Clients whose token was last presented from another executable than the pinned one (a failed `hello`),
    /// with that path: the Paired apps list shows "path changed". Cleared by a successful `hello` and a revoke.
    /// In memory only.
    path_changes: HashMap<Uuid, String>,
}

impl State {
    fn client_of(&self, session: SessionId) -> Option<&PairedClient> {
        let (id, _) = self.sessions.get(&session)?.client.as_ref()?;
        self.registry.get(*id)
    }

    fn start_release(&mut self, key: &str) {
        *self.releasing.entry(key.to_string()).or_default() += 1;
    }

    fn end_release(&mut self, key: &str) {
        if let Some(n) = self.releasing.get_mut(key) {
            *n -= 1;
            if *n == 0 {
                self.releasing.remove(key);
            }
        }
    }

    /// The connect of the lease of `generation` reached the manager (or ended).
    fn started(&mut self, key: &str, generation: Option<u64>) -> bool {
        match (self.starting.get(key), generation) {
            (Some(_), None) => self.starting.remove(key).is_some(),
            (Some(g), Some(generation)) if *g == generation => self.starting.remove(key).is_some(),
            _ => false,
        }
    }
}

struct Shared {
    host: Arc<dyn ControlHost>,
    transport: Arc<dyn ControlTransport>,
    registry: Arc<dyn RegistryStore>,
    limits: ControlLimits,
    clock: Arc<dyn Clock>,
    stopping: AtomicBool,
    state: Mutex<State>,
    /// Signalled when a session goes away, a release ends, a pairing ends or a connect reaches the manager.
    signal: Condvar,
    /// Keeps the registry saves in order (taken before the state mutex, never inside it).
    save_lock: Mutex<()>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn log(&self, line: String) {
        self.host.log(line);
    }

    fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Writes the registry as it is now, without holding the state mutex during the I/O.
    fn persist(&self) -> io::Result<()> {
        let _order = self.save_lock.lock().unwrap_or_else(PoisonError::into_inner);
        let snapshot = self.lock().registry.clone();
        self.registry.save(&snapshot)
    }

    fn end_release(&self, key: &str) {
        self.lock().end_release(key);
        self.signal.notify_all();
    }

    /// Disconnects `key` for a lease that ended, after its connect (if still in the gap) reached the manager.
    /// Nothing after `stop(Detach)`.
    fn release_disconnect(&self, key: &str) {
        let deadline = Instant::now() + self.limits.stop_timeout;
        {
            let mut state = self.lock();
            while state.starting.contains_key(key) {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                state = self.signal.wait_timeout(state, deadline - now).unwrap_or_else(PoisonError::into_inner).0;
            }
            if state.detached {
                drop(state);
                self.log(format!("not disconnecting {key}: MacVPN is quitting"));
                self.end_release(key);
                return;
            }
        }
        self.log(format!("disconnecting {key}: its last lease ended"));
        self.host.disconnect(key);
        self.end_release(key);
    }
}

/// [`ControlServer::forget_keys`] while the server is not running: the registry file in `dir` is read, pruned and
/// written back (only when something changed). A missing file is nothing to do.
pub fn forget_keys_in_registry(dir: &Path, keys: &[String]) -> io::Result<()> {
    let mut registry = Registry::load(dir)?;
    if registry.forget_keys(keys) { registry.save(dir) } else { Ok(()) }
}

// MARK: - Server

/// A running control server. Dropping it stops it.
pub struct ControlServer {
    shared: Arc<Shared>,
    accept: Option<JoinHandle<()>>,
    endpoint: String,
    socket_file: Option<PathBuf>,
    guard: Option<Box<dyn Send + Sync>>,
}

impl ControlServer {
    /// Loads the registry and binds the socket. A registry that exists but cannot be read is an error (serving
    /// with an empty one would save over it at the next pairing and unpair every client).
    pub fn start(
        options: ControlOptions,
        host: Arc<dyn ControlHost>,
        transport: Arc<dyn ControlTransport>,
    ) -> io::Result<ControlServer> {
        let registry = options.registry.load()?;
        let bound = transport.bind(&options.socket_dir)?;
        let shared = Arc::new(Shared {
            host,
            transport,
            registry: options.registry,
            limits: options.limits,
            clock: options.clock,
            stopping: AtomicBool::new(false),
            state: Mutex::new(State { registry, next_session: 1, next_generation: 1, ..State::default() }),
            signal: Condvar::new(),
            save_lock: Mutex::new(()),
        });
        // The listener waits at most `accept_poll` per accept, so the accept thread can see the stop flag (a
        // wake-up connect could fail).
        let listener = bound.listener;
        let accept_shared = shared.clone();
        let accept = thread::Builder::new()
            .name("macvpn-control-accept".into())
            .spawn(move || accept_loop(&accept_shared, listener.as_ref()))?;
        shared.log(format!("listening on {}", bound.display));
        Ok(ControlServer {
            shared,
            accept: Some(accept),
            endpoint: bound.display,
            socket_file: bound.socket_file,
            guard: Some(bound.guard),
        })
    }

    /// Feeds the manager's state changes and the user's disconnects to this server; a no-op once it is gone.
    pub fn notifier(&self) -> ControlNotifier {
        ControlNotifier { shared: Arc::downgrade(&self.shared) }
    }

    /// The endpoint as the "listening on …" log line shows it.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The endpoint's file, removed by [`Self::stop`] (`None`: it has none).
    pub fn socket_file(&self) -> Option<&Path> {
        self.socket_file.as_deref()
    }

    /// The paired clients (no token: only its hash, which the view model must not show either).
    pub fn clients(&self) -> Vec<PairedClient> {
        self.shared.lock().registry.clients().to_vec()
    }

    /// Changes a client's allowlist and saves. `Ok(false)`: no such client.
    pub fn set_allowed(&self, id: Uuid, allowed: Vec<String>) -> io::Result<bool> {
        let before = {
            let mut state = self.shared.lock();
            let Some(before) = state.registry.get(id).map(|c| c.allowed.clone()) else { return Ok(false) };
            state.registry.set_allowed(id, allowed);
            before
        };
        if let Err(e) = self.shared.persist() {
            self.shared.lock().registry.set_allowed(id, before);
            return Err(e);
        }
        Ok(true)
    }

    /// Removes `keys` from every client's allowlist and saves once (only when something changed). Removed team
    /// catalog connections and unsubscribing call it, so a re-subscribe (same deterministic ids) never re-grants
    /// access silently. Fails closed: the pruned allowlists stay in effect even when saving fails (the error is
    /// returned, and the next save writes them).
    pub fn forget_keys(&self, keys: &[String]) -> io::Result<()> {
        if !self.shared.lock().registry.forget_keys(keys) {
            return Ok(());
        }
        self.shared.persist()
    }

    /// Unpairs a client and closes its open connections at once (their leases end through the normal close
    /// path). The client is cut off even if saving fails; the error is returned. `Ok(false)`: no such client.
    pub fn revoke(&self, id: Uuid) -> io::Result<bool> {
        let mut state = self.shared.lock();
        let name = state.registry.get(id).map(|c| c.name.clone());
        if !state.registry.revoke(id) {
            return Ok(false);
        }
        for session in state.sessions.values().filter(|s| s.client.as_ref().is_some_and(|(c, _)| *c == id)) {
            let _ = session.stream.shutdown(Shutdown::Both);
        }
        state.path_changes.remove(&id);
        drop(state);
        self.shared.log(format!("revoked “{}”", name.unwrap_or_default()));
        self.shared.persist().map(|()| true)
    }

    /// The clients whose last failed `hello` came from another executable than the pinned one, with that path
    /// (the "path changed" note; the user re-pairs).
    pub fn path_changes(&self) -> HashMap<Uuid, String> {
        self.shared.lock().path_changes.clone()
    }

    /// Per leased key, the names of the clients holding it, sorted, each once (for the "held by" labels).
    pub fn holders(&self) -> BTreeMap<String, Vec<String>> {
        let state = self.shared.lock();
        let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for key in &state.acquired {
            let names: BTreeSet<String> = state
                .leases
                .holders_of(key)
                .iter()
                .filter_map(|id| state.sessions.get(id)?.client.as_ref().map(|(_, name)| name.clone()))
                .collect();
            if !names.is_empty() {
                out.insert(key.clone(), names.into_iter().collect());
            }
        }
        out
    }

    /// The names of the clients holding any connection (for the quit question), sorted, each once.
    pub fn holder_names(&self) -> Vec<String> {
        let names: BTreeSet<String> = self.holders().into_values().flatten().collect();
        names.into_iter().collect()
    }

    /// Closes every client connection and removes the socket. Pending `up`s get `disabled`
    /// ([`StopMode::EndLeases`]) or `app_quitting` ([`StopMode::Detach`]), then every authenticated client gets
    /// `{"event":"closing","reason":…}` with the same code before its close; the leases end as the mode says. Waits
    /// for the leases' disconnects (at most `stop_timeout`), then releases the instance lock. Blocks: call it off
    /// the main thread. Idempotent.
    pub fn stop(&mut self, mode: StopMode) {
        let Some(accept) = self.accept.take() else { return };
        self.shared.stopping.store(true, Ordering::SeqCst);
        {
            let mut state = self.shared.lock();
            state.detached = mode == StopMode::Detach;
            for session in state.sessions.values_mut() {
                for p in session.pending.drain(..) {
                    let _ = session.out.try_send(Out::Line(reply_err(Some(p.id), mode.code(), None)));
                }
                if session.client.is_some() {
                    let _ = session.out.try_send(Out::Line(event_closing(mode.code())));
                }
                session.close();
            }
        }
        // The accept thread polls the stop flag.
        let _ = accept.join();
        if let Some(socket_file) = &self.socket_file {
            match fs::remove_file(socket_file) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => self.shared.log(format!("could not remove the socket: {e}")),
            }
        }
        let deadline = Instant::now() + self.shared.limits.stop_timeout;
        let mut state = self.shared.lock();
        while state.sessions.values().any(|s| !s.pairing) || !state.releasing.is_empty() {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            state = self.shared.signal.wait_timeout(state, deadline - now).unwrap_or_else(PoisonError::into_inner).0;
        }
        drop(state);
        // Last: the single-instance lock.
        self.guard = None;
        self.shared.log("stopped".into());
    }
}

/// Dropping a running server detaches ([`StopMode::Detach`]): it never takes a connection down on its own; the
/// setting toggle calls `stop(StopMode::EndLeases)` explicitly.
impl Drop for ControlServer {
    fn drop(&mut self) {
        self.stop(StopMode::Detach);
    }
}

// MARK: - Notifier

/// Delivers the manager's changes to a server. Cheap to clone; does nothing once the server is gone.
#[derive(Clone)]
pub struct ControlNotifier {
    shared: Weak<Shared>,
}

impl ControlNotifier {
    /// A connection's state changed (`ConnectionManager::add_state_listener`).
    pub fn state_changed(&self, key: &str, state: &ConnectionState) {
        if let Some(shared) = self.shared.upgrade() {
            state_changed(&shared, key, state);
        }
    }

    /// The user disconnected a connection by hand (`ConnectionManager::add_user_disconnect_listener`): the user
    /// wins, every lease on it ends and nothing reconnects.
    pub fn user_disconnected(&self, key: &str) {
        let Some(shared) = self.shared.upgrade() else { return };
        let mut state = shared.lock();
        let holders = state.leases.on_user_disconnect(key);
        let message = user_disconnected_message();
        let mut ended = Vec::new();
        for (id, session) in state.sessions.iter_mut() {
            let mut touched = holders.contains(id);
            let (cut, kept): (Vec<Pending>, Vec<Pending>) = session.pending.drain(..).partition(|p| p.key == key);
            session.pending = kept;
            for p in cut {
                touched = true;
                session.send(reply_err(Some(p.id), ErrorCode::Failed, Some(&message)));
            }
            if touched {
                session.watching.insert(key.to_string());
            }
            if holders.contains(id) {
                ended.push(session.who());
            }
        }
        drop(state);
        for who in ended {
            shared.log(format!("lease on {key} of {who} ended: disconnected by the user"));
        }
    }
}

fn state_changed(shared: &Shared, key: &str, new: &ConnectionState) {
    let wire = wire_state(new);
    let ends = matches!(new, ConnectionState::Failed(_) | ConnectionState::Disconnected);
    let reason = match new {
        ConnectionState::Failed(reason) => Some(reason.as_str()),
        _ => None,
    };
    let mut ended = Vec::new();
    let mut state = shared.lock();
    // The lease's connect reached the manager: a release may disconnect now.
    let reached = matches!(
        new,
        ConnectionState::Connecting | ConnectionState::AwaitingAuth(_) | ConnectionState::Connected { .. }
    ) && state.started(key, None);
    let changed = state.last_wire.insert(key.to_string(), wire) != Some(wire);
    let current_holders = state.leases.holders_of(key);
    let dropped = if ends && state.leases.is_leased(key) { state.leases.on_dropped(key) } else { Vec::new() };
    let allowed: HashSet<SessionId> = state
        .sessions
        .keys()
        .copied()
        .filter(|id| state.client_of(*id).is_some_and(|c| Registry::is_allowed(c, key)))
        .collect();
    let event = event_state(key, wire, reason);
    for (id, session) in state.sessions.iter_mut() {
        if session.closing {
            continue;
        }
        let pending_here = session.pending.iter().any(|p| p.key == key);
        let deliver = (session.subscribed && allowed.contains(id))
            || pending_here
            || current_holders.contains(id)
            || session.watching.contains(key);
        if changed && deliver {
            session.send(event.clone());
        }
        if ends {
            session.watching.remove(key);
        }
        if dropped.contains(id) {
            ended.push(session.who());
        }
        if pending_here {
            resolve_pending(session, key, new, shared.host.as_ref());
        }
    }
    drop(state);
    if reached {
        shared.signal.notify_all();
    }
    for who in ended {
        shared.log(format!("lease on {key} of {who} ended: the connection went down"));
    }
}

/// Answers the session's pending `up`s of `key` once the state is final.
fn resolve_pending(session: &mut Session, key: &str, new: &ConnectionState, host: &dyn ControlHost) {
    let mut kept = Vec::new();
    for mut p in std::mem::take(&mut session.pending) {
        if p.key != key {
            kept.push(p);
            continue;
        }
        match new {
            ConnectionState::AwaitingAuth(_) => {
                p.saw_mfa |= wire_state(new) == WireState::WaitingForMfa;
                kept.push(p);
            }
            ConnectionState::Connected { .. } => {
                session.send(reply_ok(Some(p.id), connected_extra()));
            }
            ConnectionState::Failed(reason) => {
                let code = if *reason == auth_timeout_reason() {
                    ErrorCode::MfaTimeout
                } else if *reason == auth_cancelled_reason() {
                    ErrorCode::MfaCancelled
                } else {
                    ErrorCode::Failed
                };
                session.send(reply_err(Some(p.id), code, Some(reason)));
            }
            // A connect that ends `disconnected` without the user disconnecting: the credential or code prompt was
            // cancelled (the manager's `abandon_connect`), or the tunnel did not come up.
            ConnectionState::Disconnected => {
                let code = if host.credentials_cancelled(key) {
                    ErrorCode::CredentialsCancelled
                } else if p.saw_mfa {
                    ErrorCode::MfaCancelled
                } else {
                    ErrorCode::Failed
                };
                session.send(reply_err(Some(p.id), code, None));
            }
            ConnectionState::Connecting | ConnectionState::Disconnecting => kept.push(p),
        }
    }
    session.pending = kept;
}

fn connected_extra() -> Map<String, Value> {
    let mut extra = Map::new();
    extra.insert("state".into(), Value::from(WireState::Connected.as_str()));
    extra
}

// MARK: - Accept

fn accept_loop(shared: &Arc<Shared>, listener: &dyn ControlListener) {
    loop {
        if shared.stopping() {
            return;
        }
        // The listener sleeps for the poll while nothing comes in, and hands over a blocking stream.
        let (stream, peer) = match listener.accept(shared.limits.accept_poll) {
            Ok(Accepted::Client { stream, peer }) => (stream, peer),
            Ok(Accepted::Idle) => continue,
            Err(e) => {
                shared.log(format!("accept failed: {e}"));
                // E.g. out of descriptors: do not spin.
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let peer = match peer {
            Ok(peer) => peer,
            Err(e) if shared.transport.is_already_closed(&e) => continue,
            Err(e) => {
                shared.log(format!("closed a connection: its peer could not be identified ({e})"));
                continue;
            }
        };
        if !peer.same_user {
            shared.log(format!("closed a connection from another user ({}, pid {})", peer.user, peer.pid));
            continue;
        }
        match spawn_session(shared, stream, peer) {
            Ok(()) => {}
            Err(e) if shared.transport.is_already_closed(&e) => {}
            Err(e) => shared.log(format!("could not serve a connection: {e}")),
        }
    }
}

fn spawn_session(shared: &Arc<Shared>, stream: Box<dyn ControlStream>, peer: PeerIdentity) -> io::Result<()> {
    let exe = escape_unsafe_text(peer.executable.as_deref().unwrap_or("?"));
    let mut state = shared.lock();
    if shared.stopping() {
        return Ok(());
    }
    if state.sessions.len() >= shared.limits.max_clients {
        drop(state);
        shared.log(format!("refused {exe} (pid {}): too many clients", peer.pid));
        return Ok(());
    }
    stream.set_write_timeout(Some(shared.limits.write_timeout))?;
    let (tx, rx) = sync_channel(shared.limits.queue_length);
    let id = state.next_session;
    state.next_session += 1;
    let writer_stream = stream.try_clone()?;
    let control_stream = stream.try_clone()?;
    let writer =
        thread::Builder::new().name("macvpn-control-write".into()).spawn(move || write_loop(writer_stream, rx))?;
    state.sessions.insert(
        id,
        Session {
            out: tx.clone(),
            stream: control_stream,
            pid: peer.pid,
            executable: peer.executable.clone(),
            client: None,
            subscribed: false,
            pending: Vec::new(),
            watching: HashSet::new(),
            pairing: false,
            closing: false,
        },
    );
    drop(state);
    let reader_shared = shared.clone();
    let spawned = thread::Builder::new().name("macvpn-control-client".into()).spawn(move || {
        let client = Client { shared: &reader_shared, id, stream, peer, out: tx, client: None };
        client.run();
        let _ = writer.join();
    });
    if let Err(e) = spawned {
        let mut state = shared.lock();
        if let Some(session) = state.sessions.remove(&id) {
            let _ = session.stream.shutdown(Shutdown::Both);
        }
        shared.signal.notify_all();
        return Err(e);
    }
    Ok(())
}

fn write_loop(mut stream: Box<dyn ControlStream>, rx: Receiver<Out>) {
    for out in rx {
        match out {
            Out::Line(line) => {
                if stream.write_all(line.as_bytes()).is_err() {
                    let _ = stream.shutdown(Shutdown::Both);
                    return;
                }
            }
            Out::Close => {
                let _ = stream.shutdown(Shutdown::Both);
                return;
            }
        }
    }
}

// MARK: - One client

enum Line {
    Data,
    /// Closed (a partial last line is dropped).
    Eof,
    TooLong,
}

/// The client's socket with the auth deadline: while it is set, every underlying read gets only the time left
/// (so a client dripping one byte at a time cannot stretch it), and a read after it is `TimedOut`.
struct DeadlineReader {
    stream: Box<dyn ControlStream>,
    deadline: Option<Instant>,
}

impl Read for DeadlineReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(deadline) = self.deadline {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::from(ErrorKind::TimedOut));
            }
            self.stream.set_read_timeout(Some(left))?;
        }
        self.stream.read(buf)
    }
}

/// Reads one line of at most `MAX_LINE` bytes (plus `\r\n`) into `buf`.
fn read_line(reader: &mut BufReader<DeadlineReader>, buf: &mut Vec<u8>) -> io::Result<Line> {
    buf.clear();
    let limit = MAX_LINE as u64 + 2;
    let n = reader.by_ref().take(limit).read_until(b'\n', buf)?;
    if buf.last() == Some(&b'\n') {
        Ok(Line::Data)
    } else if n as u64 >= limit {
        Ok(Line::TooLong)
    } else {
        Ok(Line::Eof)
    }
}

struct TokenBucket {
    capacity: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(per_second: u32) -> Self {
        let capacity = f64::from(per_second.max(1));
        TokenBucket { capacity, tokens: capacity, last: Instant::now() }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.capacity).min(self.capacity);
        self.last = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

enum Flow {
    Continue,
    Close,
}

struct Client<'a> {
    shared: &'a Arc<Shared>,
    id: SessionId,
    stream: Box<dyn ControlStream>,
    peer: PeerIdentity,
    out: SyncSender<Out>,
    /// After a successful `hello`: the client's id and name.
    client: Option<(Uuid, String)>,
}

impl Client<'_> {
    fn send(&self, line: String) {
        if self.out.try_send(Out::Line(line)).is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
    }

    fn close(&self) {
        if self.out.try_send(Out::Close).is_err() {
            let _ = self.stream.shutdown(Shutdown::Both);
        }
    }

    fn who(&self) -> String {
        let exe = escape_unsafe_text(self.peer.executable.as_deref().unwrap_or("?"));
        match &self.client {
            Some((_, name)) => format!("“{name}” ({exe}, pid {})", self.peer.pid),
            None => format!("{exe} (pid {})", self.peer.pid),
        }
    }

    fn run(mut self) {
        let mut reader = match self.stream.try_clone() {
            Ok(stream) => BufReader::new(DeadlineReader {
                stream,
                deadline: Some(Instant::now() + self.shared.limits.auth_timeout),
            }),
            Err(_) => {
                self.finish();
                return;
            }
        };
        let mut bucket = TokenBucket::new(self.shared.limits.requests_per_second);
        let mut buf = Vec::new();
        let mut said_anything = false;
        loop {
            if self.client.is_some() && reader.get_ref().deadline.is_some() {
                reader.get_mut().deadline = None;
                if self.stream.set_read_timeout(None).is_err() {
                    break;
                }
            }
            match read_line(&mut reader, &mut buf) {
                Ok(Line::Data) => said_anything = true,
                Ok(Line::Eof) => {
                    // A probe that connects and closes without a word is not worth a log line.
                    if said_anything || !buf.is_empty() {
                        self.shared.log(format!("{} closed the connection", self.who()));
                    }
                    break;
                }
                Ok(Line::TooLong) => {
                    self.send(reply_err(None, ErrorCode::BadRequest, None));
                    self.shared.log(format!("closed {}: line too long", self.who()));
                    self.close();
                    break;
                }
                // The peer is already gone (a socket option on it fails); one that never said a word is not worth
                // a log line.
                Err(e) if self.shared.transport.is_already_closed(&e) => {
                    if said_anything || !buf.is_empty() {
                        self.shared.log(format!("{} closed the connection", self.who()));
                    }
                    break;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    self.shared.log(format!("closed {}: no pair or hello in time", self.who()));
                    break;
                }
                Err(_) => break,
            }
            if !bucket.take() {
                self.shared.log(format!("closed {}: too many requests", self.who()));
                break;
            }
            let flow = match parse_line(&buf) {
                Ok(request) => self.handle(request),
                Err(e) => {
                    self.send(reply_err(e.id, e.code, None));
                    Flow::Continue
                }
            };
            if let Flow::Close = flow {
                self.close();
                break;
            }
        }
        let _ = self.stream.shutdown(Shutdown::Read);
        self.finish();
    }

    /// The connection is over: its leases end (the connections it alone started go down), then it is gone.
    fn finish(&self) {
        let (actions, ended) = {
            let mut state = self.shared.lock();
            let actions = state.leases.release_session(self.id);
            for (key, action) in &actions {
                if *action == LeaseAction::Disconnect {
                    state.start_release(key);
                }
            }
            let ended: Vec<String> = actions.iter().map(|(k, _)| k.clone()).collect();
            if let Some(session) = state.sessions.get_mut(&self.id) {
                session.closing = true;
                session.pending.clear();
            }
            (actions, ended)
        };
        let why = if self.shared.lock().detached { "MacVPN is quitting" } else { "connection closed" };
        for key in &ended {
            self.shared.log(format!("lease on {key} of {} ended: {why}", self.who()));
        }
        for (key, action) in actions {
            if action == LeaseAction::Disconnect {
                self.shared.release_disconnect(&key);
            }
        }
        // Dropping the session's sender lets the writer flush what is queued (e.g. a final reply) and end; the
        // socket closes with the last descriptor.
        self.shared.lock().sessions.remove(&self.id);
        self.shared.signal.notify_all();
    }

    fn handle(&mut self, request: Request) -> Flow {
        let authed = self.client.is_some();
        // Locked: nothing that reads the vault. A pairing or `hello` ends the connection as it would anyway (the
        // client retries after the unlock); `down` only releases a lease and still works. A request before `hello`
        // stays `unauthorized` (it learns nothing about the vault).
        let refused = match request {
            Request::Pair { .. } | Request::Hello { .. } => !authed,
            Request::List { .. } | Request::Up { .. } | Request::Status { .. } => authed,
            Request::Down { .. } => false,
        };
        if refused && self.shared.host.locked() {
            self.send(reply_err(request.id(), ErrorCode::Locked, None));
            if !authed {
                self.shared.log(format!("refused {}: the vault is locked", self.who()));
                return Flow::Close;
            }
            return Flow::Continue;
        }
        match request {
            Request::Pair { id, name } if !authed => self.pair(id, name),
            Request::Hello { id, token } if !authed => self.hello(id, &token),
            Request::Pair { id, .. } | Request::Hello { id, .. } => {
                self.send(reply_err(id, ErrorCode::BadRequest, None));
                Flow::Continue
            }
            other if !authed => {
                self.send(reply_err(other.id(), ErrorCode::Unauthorized, None));
                self.shared.log(format!("closed {}: request before hello", self.who()));
                Flow::Close
            }
            Request::List { id } => self.list(id),
            Request::Up { id, connection } => self.up(id, connection),
            Request::Down { id, connection } => self.down(id, &connection),
            Request::Status { id } => {
                if let Some(session) = self.shared.lock().sessions.get_mut(&self.id) {
                    session.subscribed = true;
                }
                self.send(reply_ok(Some(id), Map::new()));
                Flow::Continue
            }
        }
    }

    // MARK: pair / hello

    fn pair(&mut self, id: Option<u64>, name: String) -> Flow {
        let Some(executable) = self.peer.executable.clone() else {
            self.shared.log(format!("pairing refused for pid {}: its executable is unknown", self.peer.pid));
            self.send(reply_err(id, ErrorCode::Denied, None));
            return Flow::Close;
        };
        // A path with a control or format character could forge or hide text in the audit lines and the pairing
        // window: such a peer cannot pair (the generic reply; the audit line shows the path escaped).
        if has_unsafe_text_chars(&executable) {
            self.shared.log(format!(
                "pairing refused for {}: its executable path has control or format characters",
                self.who()
            ));
            self.send(reply_err(id, ErrorCode::Denied, None));
            return Flow::Close;
        }
        let now = self.shared.clock.now();
        {
            let mut state = self.shared.lock();
            if state.pairing {
                drop(state);
                self.send(reply_err(id, ErrorCode::Busy, None));
                return Flow::Close;
            }
            if state.registry.pairing_blocked(now) {
                drop(state);
                self.shared.log(format!("pairing of “{name}” ({executable}) refused: too many rejections"));
                self.send(reply_err(id, ErrorCode::Denied, None));
                return Flow::Close;
            }
            state.pairing = true;
            if let Some(session) = state.sessions.get_mut(&self.id) {
                session.pairing = true;
            }
        }
        let _reset = PairingReset { shared: self.shared, session: self.id };
        self.shared.log(format!("pairing requested by “{name}” ({executable}, pid {})", self.peer.pid));
        let items: Vec<(String, String)> = self
            .shared
            .host
            .items()
            .iter()
            .map(|i| (i.id(), i.name().to_string()))
            .filter(|(key, _)| is_uuid_shaped(key))
            .collect();
        let offered: HashSet<String> = items.iter().map(|(k, _)| k.clone()).collect();
        let answer = self.ask_pairing(PairingRequest { name: name.clone(), executable: executable.clone(), items });
        if self.shared.stopping() {
            let code = if self.shared.lock().detached { ErrorCode::AppQuitting } else { ErrorCode::Disabled };
            self.send(reply_err(id, code, None));
            return Flow::Close;
        }
        let now = self.shared.clock.now();
        let PairingAnswer::Approved(keys) = answer else {
            self.shared.lock().registry.record_rejection(now);
            let how = if answer == PairingAnswer::TimedOut { "timed out" } else { "denied" };
            self.shared.log(format!("pairing of “{name}” ({executable}) {how}"));
            self.send(reply_err(id, ErrorCode::Denied, None));
            return Flow::Close;
        };
        // Only keys the window offered, each once (the allowlist can be edited later in Paired apps).
        let mut allowed: Vec<String> = Vec::new();
        for key in keys {
            if offered.contains(&key) && !allowed.contains(&key) {
                allowed.push(key);
            }
        }
        let entropy = match self.shared.transport.random_32() {
            Ok(entropy) => entropy,
            Err(e) => {
                self.shared.log(format!("pairing of “{name}” failed: no random bytes ({e})"));
                self.send(reply_err(id, ErrorCode::Failed, None));
                return Flow::Close;
            }
        };
        if !self.peer_connected() {
            self.shared.log(format!("pairing of “{name}” ({executable}) dropped: the client is gone"));
            return Flow::Close;
        }
        let token = new_token(entropy);
        let client = PairedClient::new(Uuid::new_v4(), name.clone(), &token, executable.clone(), allowed, now);
        let client_id = client.id;
        let count = client.allowed.len();
        self.shared.lock().registry.add(client);
        let saved = self.shared.persist();
        if saved.is_err() {
            self.shared.lock().registry.revoke(client_id);
        }
        if let Err(e) = saved {
            self.shared.log(format!("pairing of “{name}” failed: the registry could not be saved ({e})"));
            self.send(reply_err(id, ErrorCode::Failed, None));
            return Flow::Close;
        }
        self.shared.log(format!("paired “{name}” ({executable}) with {count} connection(s)"));
        let mut extra = Map::new();
        extra.insert("token".into(), Value::from(token));
        extra.insert("client_id".into(), Value::from(uuid_string(&client_id)));
        self.send(reply_ok(id, extra));
        Flow::Close
    }

    /// The pairing window on its own thread, waited for at most `pairing_timeout` (then: timed out; the late
    /// answer is dropped).
    fn ask_pairing(&self, request: PairingRequest) -> PairingAnswer {
        let (tx, rx) = std::sync::mpsc::channel();
        let host = self.shared.host.clone();
        let spawned = thread::Builder::new().name("macvpn-control-pairing".into()).spawn(move || {
            let _ = tx.send(host.ask_pairing(request));
        });
        if spawned.is_err() {
            return PairingAnswer::Denied;
        }
        rx.recv_timeout(self.shared.limits.pairing_timeout).unwrap_or(PairingAnswer::TimedOut)
    }

    /// The client is still connected (it waits for the pairing reply): [`ControlStream::peer_connected`].
    fn peer_connected(&self) -> bool {
        self.stream.peer_connected()
    }

    fn hello(&mut self, id: Option<u64>, token: &str) -> Flow {
        let executable = self.peer.executable.clone();
        // Never authenticated from a path with a control or format character (see `pair`): the generic failure,
        // with its delay.
        if executable.as_deref().is_some_and(has_unsafe_text_chars) {
            self.shared.log(format!(
                "hello refused from {}: its executable path has control or format characters",
                self.who()
            ));
            thread::sleep(self.shared.limits.hello_failure_delay);
            self.send(reply_err(id, ErrorCode::Unauthorized, None));
            return Flow::Close;
        }
        let now = self.shared.clock.now();
        let mut moved = false;
        let found = {
            let mut state = self.shared.lock();
            // A malformed token fails like a wrong one (same reply, delay and audit line).
            let token = Some(token).filter(|t| is_token_shaped(t));
            let found = executable
                .as_deref()
                .zip(token)
                .and_then(|(exe, token)| state.registry.authenticate(token, exe).ok())
                .map(|c| (c.id, c.name.clone()));
            if let Some((client, _)) = &found {
                state.registry.touch(*client, now);
                state.path_changes.remove(client);
            } else if let Some(exe) = executable.as_deref()
                && let Some(id) = token.and_then(|t| state.registry.identify(t))
                && state.registry.get(id).is_some_and(|c| c.executable != exe)
            {
                state.path_changes.insert(id, exe.to_string());
                moved = true;
            }
            if let (Some(found), Some(session)) = (&found, state.sessions.get_mut(&self.id)) {
                session.client = Some(found.clone());
            }
            found
        };
        if found.is_some()
            && let Err(e) = self.shared.persist()
        {
            self.shared.log(format!("could not save the last use: {e}"));
        }
        let Some(found) = found else {
            let why = if moved { ": not the executable it was paired from" } else { "" };
            self.shared.log(format!("hello failed from {}{why}", self.who()));
            thread::sleep(self.shared.limits.hello_failure_delay);
            self.send(reply_err(id, ErrorCode::Unauthorized, None));
            return Flow::Close;
        };
        self.client = Some(found);
        if self.stream.set_read_timeout(None).is_err() {
            return Flow::Close;
        }
        self.shared.log(format!("hello from {}", self.who()));
        let mut extra = Map::new();
        extra.insert("api".into(), Value::from(API_VERSION));
        self.send(reply_ok(id, extra));
        Flow::Continue
    }

    // MARK: requests

    /// The client's current allowlist; `None`: it was revoked meanwhile.
    fn allowed(&self) -> Option<Vec<String>> {
        self.shared.lock().client_of(self.id).map(|c| c.allowed.clone())
    }

    fn list(&self, id: u64) -> Flow {
        let Some(allowed) = self.allowed() else {
            self.send(reply_err(Some(id), ErrorCode::Unauthorized, None));
            return Flow::Close;
        };
        let connections: Vec<Value> = self
            .shared
            .host
            .items()
            .iter()
            .filter(|item| {
                let key = item.id();
                is_uuid_shaped(&key) && allowed.contains(&key)
            })
            .map(|item| {
                let key = item.id();
                let mut obj = Map::new();
                obj.insert("id".into(), Value::from(key.clone()));
                obj.insert("name".into(), Value::from(item.name()));
                obj.insert("kind".into(), Value::from(wire_kind(item)));
                obj.insert("state".into(), Value::from(wire_state(&self.shared.host.state(&key)).as_str()));
                Value::Object(obj)
            })
            .collect();
        let mut extra = Map::new();
        extra.insert("connections".into(), Value::Array(connections));
        self.send(reply_ok(Some(id), extra));
        Flow::Continue
    }

    fn up(&self, id: u64, key: String) -> Flow {
        let Some(allowed) = self.allowed() else {
            self.send(reply_err(Some(id), ErrorCode::Unauthorized, None));
            return Flow::Close;
        };
        if !allowed.contains(&key) {
            self.send(reply_err(Some(id), ErrorCode::NotAllowed, None));
            return Flow::Continue;
        }
        if !self.shared.host.items().iter().any(|item| item.id() == key) {
            self.send(reply_err(Some(id), ErrorCode::UnknownConnection, None));
            return Flow::Continue;
        }
        // `setup_ready_for` reads the app's setup report (its own lock) and is never asked under the server's
        // mutex: the checks run under the mutex, the setup is asked outside it, and the checks run again (the
        // state may have changed meanwhile). The second round needs no setup check unless the `up` would start
        // the connection only now (e.g. the other lease ended meanwhile), which takes one more round.
        let mut setup_checked = false;
        let (mut state, current) = loop {
            let state = self.shared.lock();
            if self.shared.stopping() {
                let code = if state.detached { ErrorCode::AppQuitting } else { ErrorCode::Disabled };
                drop(state);
                self.send(reply_err(Some(id), code, None));
                return Flow::Continue;
            }
            let current = self.shared.host.state(&key);
            let changing = matches!(
                current,
                ConnectionState::Connecting | ConnectionState::Disconnecting | ConnectionState::AwaitingAuth(_)
            );
            if !state.leases.is_leased(&key) && (changing || state.releasing.contains_key(&key)) {
                drop(state);
                self.send(reply_err(Some(id), ErrorCode::Busy, None));
                return Flow::Continue;
            }
            let limit = self.shared.limits.max_pending;
            let crowded = state
                .sessions
                .get(&self.id)
                .is_some_and(|s| s.pending.iter().any(|p| p.key == key) || s.pending.len() >= limit);
            if crowded {
                drop(state);
                self.send(reply_err(Some(id), ErrorCode::Busy, None));
                return Flow::Continue;
            }
            // Only an `up` that starts the connection needs the setup: one that is already up (or coming up for
            // another lease) is joined as it is.
            let starts = !state.leases.is_leased(&key) && !current.is_active();
            if !starts || setup_checked {
                break (state, current);
            }
            drop(state);
            if let Some(reason) = self.shared.host.start_refusal(&key) {
                self.send(reply_err(Some(id), ErrorCode::Failed, Some(&reason)));
                return Flow::Continue;
            }
            if !self.shared.host.setup_ready_for(&key) {
                self.send(reply_err(Some(id), ErrorCode::SetupRequired, None));
                return Flow::Continue;
            }
            setup_checked = true;
        };
        if !state.leases.is_leased(&key) {
            let generation = state.next_generation;
            state.next_generation += 1;
            state.lease_generation.insert(key.clone(), generation);
        }
        let generation = state.lease_generation.get(&key).copied().unwrap_or_default();
        let action = state.leases.acquire(&key, self.id, current.is_active());
        state.acquired.insert(key.clone());
        if action == LeaseAction::Connect {
            state.starting.insert(key.clone(), generation);
        }
        let Some(session) = state.sessions.get_mut(&self.id) else { return Flow::Close };
        session.watching.remove(&key);
        if current.is_connected() && action == LeaseAction::None {
            session.send(reply_ok(Some(id), connected_extra()));
        } else {
            if matches!(current, ConnectionState::Connecting | ConnectionState::AwaitingAuth(_)) {
                session.send(event_state(&key, wire_state(&current), None));
            }
            session.pending.push(Pending {
                key: key.clone(),
                id,
                saw_mfa: wire_state(&current) == WireState::WaitingForMfa,
            });
        }
        drop(state);
        let how = match action {
            LeaseAction::Connect => "connecting",
            _ if current.is_connected() => "already connected",
            _ => "already coming up",
        };
        self.shared.log(format!("up {key} by {}: {how}", self.who()));
        if action == LeaseAction::Connect {
            let shared = self.shared.clone();
            let thread_key = key.clone();
            let spawned = thread::Builder::new()
                .name("macvpn-control-connect".into())
                .spawn(move || connect(&shared, &thread_key, generation));
            if spawned.is_err() {
                connect_failed(self.shared, &key, generation, ErrorCode::Failed);
            }
        }
        Flow::Continue
    }

    fn down(&self, id: u64, key: &str) -> Flow {
        let action = {
            let mut state = self.shared.lock();
            let action = state.leases.release(key, self.id);
            if action == LeaseAction::Disconnect {
                state.start_release(key);
            }
            if let Some(session) = state.sessions.get_mut(&self.id) {
                session.watching.remove(key);
                let (cut, kept): (Vec<Pending>, Vec<Pending>) = session.pending.drain(..).partition(|p| p.key == key);
                session.pending = kept;
                for p in cut {
                    session.send(reply_err(Some(p.id), ErrorCode::Failed, None));
                }
            }
            action
        };
        self.shared.log(format!("down {key} by {}", self.who()));
        if action == LeaseAction::Disconnect {
            self.shared.release_disconnect(key);
        }
        self.send(reply_ok(Some(id), Map::new()));
        Flow::Continue
    }
}

/// Clears the pairing flags however `pair` ends (a panicking host included).
struct PairingReset<'a> {
    shared: &'a Shared,
    session: SessionId,
}

impl Drop for PairingReset<'_> {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.pairing = false;
        if let Some(session) = state.sessions.get_mut(&self.session) {
            session.pairing = false;
        }
        drop(state);
        self.shared.signal.notify_all();
    }
}

/// Runs a lease's connect; a synchronous failure ends the lease (the lease table's contract).
fn connect(shared: &Shared, key: &str, generation: u64) {
    match shared.host.connect(key) {
        Ok(()) => {
            // Normally already cleared by the `connecting` state.
            if shared.lock().started(key, Some(generation)) {
                shared.signal.notify_all();
            }
        }
        Err(code) => connect_failed(shared, key, generation, code),
    }
}

/// The connect of the lease of `generation` could not start: that lease ends (a newer one is left alone).
fn connect_failed(shared: &Shared, key: &str, generation: u64, code: ErrorCode) {
    let mut state = shared.lock();
    state.started(key, Some(generation));
    let current = state.leases.is_leased(key) && state.lease_generation.get(key) == Some(&generation);
    if !current {
        drop(state);
        shared.signal.notify_all();
        shared.log(format!("connecting {key} failed: {} (its lease had already ended)", code.as_str()));
        return;
    }
    let holders = state.leases.on_dropped(key);
    let mut ended = Vec::new();
    for (id, session) in state.sessions.iter_mut() {
        let (cut, kept): (Vec<Pending>, Vec<Pending>) = session.pending.drain(..).partition(|p| p.key == key);
        session.pending = kept;
        for p in cut {
            session.send(reply_err(Some(p.id), code, None));
        }
        if holders.contains(id) {
            ended.push(session.who());
        }
    }
    drop(state);
    shared.signal.notify_all();
    shared.log(format!("connecting {key} failed: {}", code.as_str()));
    for who in ended {
        shared.log(format!("lease on {key} of {who} ended: the connect failed"));
    }
}
