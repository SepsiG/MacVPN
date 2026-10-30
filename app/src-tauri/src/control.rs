//! The local control API in the app (spec `2026-10-19-control-api-design.md`): the setting "Allow other apps to
//! control VPNs" (off by default), the server's start and stop, the [`ControlHost`] over the connection manager and
//! the pairing window, the platform socket as the [`ControlTransport`], and the Paired apps commands.
//!
//! - **Relay:** [`ControlRelay::attach`] runs once at launch ([`ControlApp::attach`]); a started server's notifier is
//!   plugged in, and `None` once it stopped.
//! - **Setting:** on starts the server, off stops it with [`StopMode::EndLeases`] (leases end, a connection whose
//!   last lease ends goes down). A start failure (another instance, an unusable folder, an unreadable registry) is
//!   kept as the view's `error` and shown in the Paired apps section and in System Status.
//! - **Quit:** [`stop_for_quit`] stops with [`StopMode::Detach`] once the quit really proceeds (`terminate`), and
//!   no start happens after it. "Disconnect and Quit" detaches first ([`stop_before_disconnect`], so no lease races
//!   the disconnects); if that quit then does not happen, [`resume_after_quit`] starts the server again. "Quit, Keep
//!   Them Running" disconnects nothing, so the leased connections stay up.
//! - **Threads:** `ControlServer::stop` blocks; it never runs on the main thread (every caller here is a command on
//!   the blocking pool or a worker thread). One lock (`ops`) orders the starts, stops and offline edits; the
//!   server slot itself is only locked briefly, so building the view model never waits for a stop.
//! - **Host:** `items`, `state` and `log` only read the manager (they run under the server's lock). Disconnects
//!   for a lease use `DisconnectCause::Lease`, so they never count as the user's. The audit lines go to stderr
//!   (the debug log), to the Paired apps section's activity list ("Control API") and to `control/audit.log` (0600,
//!   rotated at [`AUDIT_CAP`], one old file kept; written by its own thread); tokens never reach them. A start
//!   failure shows a translated text; the raw OS error goes to the audit lines only.

use macvpn_app_core::control::{
    ControlHost, ControlOptions, ControlRelay, ControlServer, PairingAnswer, PairingRequest, RegistryStore, StopMode,
};
use macvpn_app_core::pairing::{PAIRING_TIMEOUT, PairingBroker};
use macvpn_app_core::updates::Notice;
use macvpn_app_core::view_model::ControlView;
use macvpn_app_core::{ConnectionItem, ConnectionManager, DisconnectCause};
use macvpn_core::control::protocol::{ErrorCode, escape_unsafe_text};
use macvpn_core::control::registry::{PairedClient, Registry};
use macvpn_core::date::Date;
use macvpn_core::fsx::{self, Access, Follow, OpenFor};
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::ConnectionState;
use macvpn_platform_api::SetupReport;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;
use tauri::{AppHandle, State};
use uuid::Uuid;

use crate::state::AppState;

type Shared<'a> = State<'a, Arc<AppState>>;

/// The preference key of "Allow other apps to control VPNs" (default off).
pub const ENABLED_KEY: &str = "controlAPIEnabled";
/// The activity list keeps this many audit lines.
const ACTIVITY_LINES: usize = 100;
/// The audit file in the control directory, and its one rotated predecessor.
pub const AUDIT_FILE: &str = "audit.log";
pub const AUDIT_OLD_FILE: &str = "audit.log.1";
/// The audit file is rotated before it would grow past this.
pub const AUDIT_CAP: u64 = 256 * 1024;

/// Appends one line to `<dir>/audit.log` (0600, never through a symlink), rotating it to `audit.log.1` (replacing
/// an older one) when the line would take it past `cap`. `dir` is checked like the socket's directory (a real
/// directory of this user, 0700).
pub fn append_audit(dir: &Path, line: &str, cap: u64) -> io::Result<()> {
    crate::platform::get().control_transport().prepare_dir(dir)?;
    let path = dir.join(AUDIT_FILE);
    match fs::symlink_metadata(&path) {
        Ok(meta) if !meta.file_type().is_file() => {
            return Err(io::Error::new(ErrorKind::InvalidInput, "the audit log is not a regular file"));
        }
        Ok(meta) if meta.len() + line.len() as u64 + 1 > cap => fs::rename(&path, dir.join(AUDIT_OLD_FILE))?,
        _ => {}
    }
    let mut file = fsx::open_append(&path, Access::Private)?;
    fsx::set_access(&file, Access::Private)?;
    file.write_all(format!("{line}\n").as_bytes())
}

/// The audit file's text, the rotated part first (missing parts are empty; symlinks are not followed).
pub fn read_audit(dir: &Path) -> io::Result<String> {
    let mut text = String::new();
    for name in [AUDIT_OLD_FILE, AUDIT_FILE] {
        match fsx::open_regular(&dir.join(name), OpenFor::Read, Follow::No, false) {
            Ok((mut file, _)) => {
                file.read_to_string(&mut text)?;
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(text)
}

// MARK: - State

#[derive(Default)]
struct Slot {
    /// Shared so an edit can call it after the slot's lock is released (no disk I/O under that lock). Only the
    /// holder of `ops` clones it, and drops the clone before releasing `ops`, so a stop always unwraps it.
    server: Option<Arc<ControlServer>>,
    /// Why the last start failed (translated); cleared by a start or by turning the setting off.
    error: Option<String>,
    /// The registry as last read while the server is not running (the list stays editable).
    offline: Vec<PairedClient>,
}

/// The control API's part of the app state.
pub struct ControlApp {
    relay: Mutex<Option<Arc<ControlRelay>>>,
    pub pairing: Arc<PairingBroker>,
    slot: Mutex<Slot>,
    /// Orders the starts, stops and offline registry edits (held across `ControlServer::stop`).
    ops: Mutex<()>,
    activity: Mutex<VecDeque<String>>,
    /// The audit file's writer thread (started with the first line).
    audit: Mutex<Option<Sender<String>>>,
    /// The quit proceeds: the server stopped for it and is never started again (set under `ops`).
    quitting: AtomicBool,
    socket_dir: PathBuf,
    /// The paired clients (the vault; `control-clients.json` before 1.2).
    registry: Arc<dyn RegistryStore>,
    /// Where they are, for the "cannot be read" message.
    registry_path: PathBuf,
}

impl ControlApp {
    /// `support`: the app's Application Support directory (the socket under `control/`); `registry`: the paired
    /// clients' store, at `registry_path` (shown when it cannot be read).
    pub fn new(support: &Path, registry: Arc<dyn RegistryStore>, registry_path: PathBuf) -> Self {
        ControlApp {
            relay: Mutex::new(None),
            pairing: Arc::new(PairingBroker::new()),
            slot: Mutex::new(Slot::default()),
            ops: Mutex::new(()),
            activity: Mutex::new(VecDeque::new()),
            audit: Mutex::new(None),
            quitting: AtomicBool::new(false),
            socket_dir: support.join("control"),
            registry,
            registry_path,
        }
    }

    fn slot(&self) -> MutexGuard<'_, Slot> {
        self.slot.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ops(&self) -> MutexGuard<'_, ()> {
        self.ops.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers the manager listeners once (at launch, before any start).
    pub fn attach(&self, manager: &macvpn_app_core::ConnectionManager) {
        let mut relay = self.relay.lock().unwrap_or_else(PoisonError::into_inner);
        if relay.is_none() {
            *relay = Some(ControlRelay::attach(manager));
        }
    }

    fn relay_set(&self, notifier: Option<macvpn_app_core::control::ControlNotifier>) {
        if let Some(relay) = self.relay.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
            relay.set(notifier);
        }
    }

    pub fn is_running(&self) -> bool {
        self.slot().server.is_some()
    }

    /// The running server's endpoint as its "listening on …" line shows it (the Windows smoke run hands the pipe's
    /// name to its test client; debug builds only). macOS' smoke run looks at the socket file instead.
    #[cfg(debug_assertions)]
    #[allow(dead_code)]
    pub fn endpoint(&self) -> Option<String> {
        self.slot().server.as_ref().map(|s| s.endpoint().to_string())
    }

    /// The quit proceeds: no start from now on (`stop_for_quit` sets it under `ops`; `terminate` also sets it at
    /// once, so a start that comes later is refused).
    pub fn begin_quit(&self) {
        self.quitting.store(true, Ordering::SeqCst);
    }

    /// A start is allowed (the app is not quitting).
    fn may_start(&self) -> bool {
        !self.quitting.load(Ordering::SeqCst)
    }

    /// The directory of the socket and the audit file.
    pub fn control_dir(&self) -> &Path {
        &self.socket_dir
    }

    /// Per leased key, the names of the paired apps holding it (the "Held by" labels).
    pub fn holders(&self) -> BTreeMap<String, Vec<String>> {
        self.slot().server.as_deref().map(ControlServer::holders).unwrap_or_default()
    }

    /// The names of the paired apps holding any connection (the quit question's note).
    pub fn holder_names(&self) -> Vec<String> {
        self.slot().server.as_deref().map(ControlServer::holder_names).unwrap_or_default()
    }

    /// The Paired apps section's view.
    pub fn view(&self, enabled: bool) -> ControlView {
        let activity: Vec<String> =
            self.activity.lock().unwrap_or_else(PoisonError::into_inner).iter().cloned().collect();
        let slot = self.slot();
        match &slot.server {
            Some(server) => {
                ControlView::build(enabled, true, None, &server.clients(), &server.path_changes(), activity)
            }
            None => ControlView::build(
                enabled,
                false,
                if enabled { slot.error.clone() } else { None },
                &slot.offline,
                &HashMap::new(),
                activity,
            ),
        }
    }

    /// One audit line: stderr (the debug log), the activity list and the audit file (through its writer thread).
    /// Never blocks for long.
    fn record(&self, line: &str) {
        // The server escapes the peer's path already; any other control or format character is escaped here too,
        // so no line can split or reorder the activity list, the debug log or the audit file.
        let line = &escape_unsafe_text(line);
        eprintln!("MacVPN (Control API): {line}");
        let now = Date::now();
        let stamp = crate::platform::get()
            .system()
            .local_date_time(now.time_interval_since_1970(), l10n::AppLanguage::current());
        {
            let mut activity = self.activity.lock().unwrap_or_else(PoisonError::into_inner);
            activity.push_back(format!("{stamp}  {line}"));
            while activity.len() > ACTIVITY_LINES {
                activity.pop_front();
            }
        }
        self.audit_line(format!("{}  {line}", now.iso8601()));
    }

    fn audit_line(&self, line: String) {
        let mut audit = self.audit.lock().unwrap_or_else(PoisonError::into_inner);
        if audit.is_none() {
            let (tx, rx) = channel::<String>();
            let dir = self.socket_dir.clone();
            let spawned = std::thread::Builder::new().name("macvpn-control-audit".into()).spawn(move || {
                let mut failed = false;
                for line in rx {
                    match append_audit(&dir, &line, AUDIT_CAP) {
                        Ok(()) => failed = false,
                        Err(e) if !failed => {
                            failed = true;
                            eprintln!("MacVPN (Control API): the audit file cannot be written: {e}");
                        }
                        Err(_) => {}
                    }
                }
            });
            if spawned.is_ok() {
                *audit = Some(tx);
            }
        }
        if let Some(tx) = audit.as_ref() {
            let _ = tx.send(line);
        }
    }

    /// Reads the registry for the list shown while the server is not running.
    fn refresh_offline(&self) {
        let clients = self.registry.load().map(|r| r.clients().to_vec()).unwrap_or_default();
        self.slot().offline = clients;
    }

    /// Removes `keys` from every paired client's allowlist and saves once: through the running server
    /// (`ControlServer::forget_keys`, which keeps the pruned lists in effect even if saving fails), or, while it is
    /// not running, in the stored registry (the vault; `forget_keys_in_registry`'s counterpart for the
    /// `RegistryStore`). Removed team catalog connections and unsubscribing call it (`CatalogService::set_forget_keys`),
    /// so a re-subscribe with the same deterministic ids never re-grants access silently.
    pub fn forget_keys(&self, keys: &[String]) -> Result<(), String> {
        if keys.is_empty() {
            return Ok(());
        }
        let _ops = self.ops();
        // The server's save runs without the slot's lock (the view model reads the slot meanwhile).
        let server = self.slot().server.clone();
        let result = match server.as_deref() {
            Some(server) => server.forget_keys(keys).map_err(|e| e.to_string()),
            None => {
                let pruned = self.registry.load().and_then(|mut registry| {
                    if registry.forget_keys(keys) { self.registry.save(&registry) } else { Ok(()) }
                });
                self.refresh_offline();
                pruned.map_err(|e| e.to_string())
            }
        };
        drop(server);
        match &result {
            Ok(()) => self.record(&format!("removed {} team catalog connection(s) from the allowlists", keys.len())),
            Err(e) => self.record(&format!("could not remove team catalog connections from the allowlists: {e}")),
        }
        result
    }

    /// Puts a started server into the slot (tests of the paths that depend on a running server).
    #[cfg(test)]
    fn set_server_for_test(&self, server: ControlServer) {
        self.slot().server = Some(Arc::new(server));
    }

    #[cfg(test)]
    fn take_server_for_test(&self) -> Option<ControlServer> {
        let server = self.slot().server.take()?;
        unwrap_server(server)
    }
}

// MARK: - Host

/// The server's view of the app (see the module docs).
struct Host {
    state: Weak<AppState>,
}

impl Host {
    fn app(&self) -> Option<Arc<AppState>> {
        self.state.upgrade()
    }
}

impl ControlHost for Host {
    fn items(&self) -> Vec<ConnectionItem> {
        self.app().map(|s| s.manager.ordered_items()).unwrap_or_default()
    }

    fn state(&self, key: &str) -> macvpn_core::models::ConnectionState {
        self.app().map(|s| s.manager.state(key)).unwrap_or(ConnectionState::Disconnected)
    }

    fn connect(&self, key: &str) -> Result<(), ErrorCode> {
        let state = self.app().ok_or(ErrorCode::AppQuitting)?;
        let report = state.setup.read().unwrap_or_else(PoisonError::into_inner).clone();
        // Marked as the lease's: auto-reconnect never brings it back (a drop ends its leases).
        state.reconnect.lease_connect(key, || connect_key(&state.manager, &report, key))
    }

    fn disconnect(&self, key: &str) {
        if let Some(state) = self.app() {
            disconnect_key(&state.manager, key);
        }
    }

    fn setup_ready_for(&self, key: &str) -> bool {
        let Some(state) = self.app() else { return false };
        // A key that vanished meanwhile: the connect itself answers `unknown_connection`.
        let Some(item) = state.manager.item(key) else { return true };
        setup_ready_for(&state.setup.read().unwrap_or_else(PoisonError::into_inner), &item)
    }

    fn start_refusal(&self, key: &str) -> Option<String> {
        let state = self.app()?;
        let setup = state.setup.read().unwrap_or_else(PoisonError::into_inner).clone();
        match state.manager.item(key) {
            Some(item) => start_refusal(&setup, &state.manager, &item),
            // A key that vanished meanwhile: the connect itself answers `unknown_connection`, unless nothing can
            // start at all.
            None => setup.start_refusal(None),
        }
    }

    fn ask_pairing(&self, request: PairingRequest) -> PairingAnswer {
        let Some(state) = self.app() else { return PairingAnswer::Denied };
        let broker = state.control.pairing.clone();
        drop(state);
        broker.present(request, Date::now(), PAIRING_TIMEOUT)
    }

    fn credentials_cancelled(&self, key: &str) -> bool {
        self.app().is_some_and(|s| s.manager.credentials_cancelled(key))
    }

    /// The vault is locked: the manager keeps only the redacted active connections meanwhile.
    fn locked(&self) -> bool {
        self.app().is_some_and(|s| s.manager.is_locked())
    }

    fn log(&self, line: String) {
        let Some(state) = self.app() else { return };
        state.control.record(&line);
        // Every lease change, hello and pairing is logged: the "Held by" labels and the list follow.
        state.publisher.mark();
    }
}

/// Why a start of `item` is refused outright, the same for a manual connect (the `connect` command) and a lease's
/// `up`: the setup's answer (`SetupReport::start_refusal`: no VPN engine, a later kind; WinVPN 2c: a missing WinVPN
/// Service refuses neither the native kinds nor the system VPNs), then a connection the platform cannot connect
/// with its settings (`ConnectionManager::unsupported_reason`, WinVPN 2c). `None` (macOS with an engine): the
/// setup check ([`setup_ready_for`]) decides.
pub fn start_refusal(report: &SetupReport, manager: &ConnectionManager, item: &ConnectionItem) -> Option<String> {
    let kind = match item {
        ConnectionItem::Managed(c) => Some(c.kind),
        ConnectionItem::System(_) => None,
    };
    report.start_refusal(kind).or_else(|| match item {
        ConnectionItem::Managed(_) => manager.unsupported_reason(&item.id()),
        ConnectionItem::System(_) => None,
    })
}

/// Whether `item` can be started with this setup, decided as for a manual connect (the `connect` command): a
/// managed connection needs its type to be available (`SetupReport::is_available`: Homebrew, a current root
/// layer, `sudo -n` and the type's tools; a native L2TP / Cisco connection needs none of them), and a system VPN
/// starts through `SCNetworkConnection` without any. Otherwise `up` is `setup_required`.
pub fn setup_ready_for(report: &SetupReport, item: &ConnectionItem) -> bool {
    match item {
        ConnectionItem::Managed(c) => report.is_available(c.kind),
        ConnectionItem::System(_) => true,
    }
}

/// A lease's connect, the same way as a manual one (the `connect` command): a managed connection needs its
/// type's tools (`setup_required` otherwise, nothing starts); a system VPN starts with its stored secrets. Blocks
/// until the manager's call returns. A start [`start_refusal`] refuses (WinVPN: no usable WinVPN Service for a
/// kind it runs, Cisco IPsec) does not start: `failed` (the server's `up` has already answered with that reason,
/// `ControlHost::start_refusal`).
pub fn connect_key(manager: &ConnectionManager, report: &SetupReport, key: &str) -> Result<(), ErrorCode> {
    let Some(item) = manager.item(key) else { return Err(ErrorCode::UnknownConnection) };
    // Refused outright (the server's `up` has answered with the reason): see [`start_refusal`].
    if start_refusal(report, manager, &item).is_some() {
        return Err(ErrorCode::Failed);
    }
    if !setup_ready_for(report, &item) {
        return Err(ErrorCode::SetupRequired);
    }
    match item {
        ConnectionItem::Managed(c) => {
            manager.connect(&c, false);
            Ok(())
        }
        ConnectionItem::System(s) => {
            manager.connect_system(&s);
            Ok(())
        }
    }
}

/// A lease's disconnect: `DisconnectCause::Lease`, never counted as the user's.
pub fn disconnect_key(manager: &ConnectionManager, key: &str) {
    match manager.item(key) {
        Some(ConnectionItem::Managed(c)) => manager.disconnect_for(&c, DisconnectCause::Lease),
        Some(ConnectionItem::System(s)) => manager.disconnect_system_for(&s, DisconnectCause::Lease),
        None => {}
    }
}

// MARK: - Start / stop

/// Why the server could not start, for the user (translated; the raw OS error goes to the audit lines only).
pub fn start_error_message(e: &io::Error, socket_dir: &Path) -> String {
    let dir = socket_dir.display().to_string();
    match e.kind() {
        ErrorKind::AddrInUse => l10n::tr("Another copy of MacVPN already lets other apps control VPNs.", &[]),
        ErrorKind::NotADirectory => {
            l10n::tr("Other apps cannot control VPNs: %@ is not a folder that MacVPN can use.", &[Arg::Str(&dir)])
        }
        ErrorKind::PermissionDenied => {
            l10n::tr("Other apps cannot control VPNs: MacVPN has no access to %@.", &[Arg::Str(&dir)])
        }
        _ => l10n::tr("Other apps cannot control VPNs: the folder %@ cannot be used.", &[Arg::Str(&dir)]),
    }
}

/// The registry exists but cannot be read.
pub fn registry_error_message(registry: &Path) -> String {
    l10n::tr(
        "Other apps cannot control VPNs: the list of paired apps (%@) cannot be read.",
        &[Arg::Str(&registry.display().to_string())],
    )
}

fn enabled(state: &AppState) -> bool {
    state.prefs.bool(ENABLED_KEY).unwrap_or(false)
}

/// At launch, and after each unlock of the vault: starts the server if the setting is on, otherwise reads the list.
/// Nothing while the vault is locked or not created (the registry is in it; a running server stays across a
/// lock). Off the main thread.
pub fn launch(state: &Arc<AppState>) {
    state.control.attach(&state.manager);
    if !state.vault.readable() {
        return;
    }
    let _ops = state.control.ops();
    if enabled(state) {
        start_locked(state);
    } else {
        state.control.refresh_offline();
    }
    state.publisher.mark();
}

/// The setting's switch. Blocks (a stop waits for the leases' disconnects): call it off the main thread.
pub fn set_enabled(state: &Arc<AppState>, on: bool) {
    let _ops = state.control.ops();
    state.prefs.set_bool(ENABLED_KEY, on);
    if on {
        start_locked(state);
    } else {
        state.control.slot().error = None;
        stop_locked(state, StopMode::EndLeases);
    }
    state.publisher.mark();
}

/// The quit proceeds (`commands::terminate`): the clients get `app_quitting`, their leases end without any
/// disconnect, and the server is never started again. Blocks: call it off the main thread. Idempotent.
pub fn stop_for_quit(state: &Arc<AppState>) {
    let _ops = state.control.ops();
    state.control.begin_quit();
    stop_locked(state, StopMode::Detach);
}

/// "Disconnect and Quit", before the disconnects: the leases end without a disconnect of their own (none races
/// the quit's). True: a running server was stopped ([`resume_after_quit`] starts it again if the quit then does
/// not happen). Blocks: off the main thread.
pub fn stop_before_disconnect(state: &Arc<AppState>) -> bool {
    let _ops = state.control.ops();
    let running = state.control.is_running();
    stop_locked(state, StopMode::Detach);
    running
}

/// The quit did not happen after [`stop_before_disconnect`]: the server starts again (if the setting is still on
/// and the app is not quitting by now). Blocks: off the main thread.
pub fn resume_after_quit(state: &Arc<AppState>) {
    let _ops = state.control.ops();
    if enabled(state) {
        start_locked(state);
    }
    state.publisher.mark();
}

fn start_locked(state: &Arc<AppState>) {
    let control = &state.control;
    if control.is_running() || !control.may_start() {
        return;
    }
    // A registry that cannot be read is reported as such (the server refuses it too).
    if let Err(e) = control.registry.load() {
        let message = registry_error_message(&control.registry_path);
        control.record(&format!("not started: {e}"));
        control.slot().error = Some(message);
        return;
    }
    control.attach(&state.manager);
    let host = Arc::new(Host { state: Arc::downgrade(state) });
    let options = ControlOptions::with_registry(control.socket_dir.clone(), control.registry.clone());
    match ControlServer::start(options, host, crate::platform::get().control_transport()) {
        Ok(server) => {
            control.relay_set(Some(server.notifier()));
            let mut slot = control.slot();
            slot.server = Some(Arc::new(server));
            slot.error = None;
        }
        Err(e) => {
            let message = if e.kind() == ErrorKind::AddrInUse || control.registry.load().is_ok() {
                start_error_message(&e, &control.socket_dir)
            } else {
                registry_error_message(&control.registry_path)
            };
            control.record(&format!("not started: {e}"));
            control.slot().error = Some(message);
        }
    }
}

fn stop_locked(state: &Arc<AppState>, mode: StopMode) {
    let control = &state.control;
    let server = {
        let mut slot = control.slot();
        let server = slot.server.take();
        // The list stays as it was while the server stops (then it is read again).
        if let Some(server) = &server {
            slot.offline = server.clients();
        }
        server
    };
    // An open pairing window ends with the server (also one opened while it was stopping).
    control.pairing.deny_all();
    if let Some(server) = server {
        match unwrap_server(server) {
            Some(mut server) => server.stop(mode),
            None => control.record("could not stop the server: it is still in use"),
        }
        control.relay_set(None);
        control.pairing.deny_all();
    }
    control.refresh_offline();
    state.publisher.mark();
}

/// The only owner of a server taken out of the slot (an edit's clone is dropped before `ops` is released, so
/// this normally succeeds at once; it waits a moment for safety).
fn unwrap_server(mut server: Arc<ControlServer>) -> Option<ControlServer> {
    for _ in 0..100 {
        match Arc::try_unwrap(server) {
            Ok(server) => return Some(server),
            Err(shared) => server = shared,
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

// MARK: - Commands

/// A paired app's id (UUID-shaped, as every other id the UI sends).
pub fn parse_client_id(id: &str) -> Result<Uuid, String> {
    crate::commands::validate_key(id).map_err(|_| "invalid client id".to_string())?;
    macvpn_core::models::parse_uuid(id).ok_or_else(|| "invalid client id".into())
}

/// A paired app's new allowlist: listed connection keys only, each once (empty: none).
pub fn validate_allowed_keys(keys: &[String], listed: &[String]) -> Result<Vec<String>, String> {
    if keys.len() > listed.len() {
        return Err("too many connections".into());
    }
    let mut out: Vec<String> = Vec::new();
    for key in keys {
        crate::commands::validate_key(key)?;
        if !listed.contains(key) {
            return Err("unknown connection".into());
        }
        if out.contains(key) {
            return Err("repeated connection".into());
        }
        out.push(key.clone());
    }
    Ok(out)
}

/// "Allow other apps to control VPNs".
#[tauri::command]
pub async fn control_set_enabled(window: tauri::Window, state: Shared<'_>, on: bool) -> Result<(), String> {
    crate::guard::only(&window, "control_set_enabled", crate::manage::MANAGE_WINDOW)?;
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || set_enabled(&shared, on)).await.map_err(|e| e.to_string())
}

/// A paired app's allowed connections (the checkboxes of its card).
#[tauri::command]
pub async fn control_set_allowed(
    window: tauri::Window,
    state: Shared<'_>,
    client_id: String,
    keys: Vec<String>,
) -> Result<(), String> {
    crate::guard::only(&window, "control_set_allowed", crate::manage::MANAGE_WINDOW)?;
    let id = parse_client_id(&client_id)?;
    let listed: Vec<String> = state.manager.ordered_items().iter().map(ConnectionItem::id).collect();
    let keys = validate_allowed_keys(&keys, &listed)?;
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        edit(&shared, id, |server| server.set_allowed(id, keys.clone()), |r| r.set_allowed(id, keys.clone()))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Revoke (after the UI's confirmation): the app is unpaired and its open connections are closed at once.
#[tauri::command]
pub async fn control_revoke(window: tauri::Window, state: Shared<'_>, client_id: String) -> Result<(), String> {
    crate::guard::only(&window, "control_revoke", crate::manage::MANAGE_WINDOW)?;
    let id = parse_client_id(&client_id)?;
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || edit(&shared, id, |server| server.revoke(id), |r| r.revoke(id)))
        .await
        .map_err(|e| e.to_string())?
}

/// The Activity list's "Save…": the audit file (with its rotated part) into a file chosen in the save panel (0600,
/// no symlink followed). A failure comes back as the alert.
#[tauri::command]
pub async fn control_audit_save(app: AppHandle, state: Shared<'_>) -> Result<Option<Notice>, String> {
    let dir = state.control.control_dir().to_path_buf();
    let text = tauri::async_runtime::spawn_blocking(move || read_audit(&dir)).await.map_err(|e| e.to_string())?;
    let failed = |message: String| Notice { title: l10n::tr("Could not save the audit log", &[]), message };
    let text = match text {
        Ok(text) => text,
        Err(e) => return Ok(Some(failed(e.to_string()))),
    };
    let name = "MacVPN-control-audit.log".to_string();
    let Some(path) = crate::dialogs::choose_save_path(&app, &state, crate::manage::MANAGE_WINDOW, name, None).await?
    else {
        return Ok(None);
    };
    let written = tauri::async_runtime::spawn_blocking(move || macvpn_core::exporter::write(text.as_bytes(), &path))
        .await
        .map_err(|e| e.to_string())?;
    Ok(written.err().map(|e| failed(e.message)))
}

/// An edit of the registry: through the running server, or on the file while it is not running.
fn edit(
    state: &Arc<AppState>,
    id: Uuid,
    running: impl Fn(&ControlServer) -> io::Result<bool>,
    offline: impl Fn(&mut Registry) -> bool,
) -> Result<(), String> {
    let control = &state.control;
    let _ops = control.ops();
    // The server's save runs without the slot's lock (the view model reads the slot meanwhile).
    let server = control.slot().server.clone();
    let result = server.as_deref().map(&running);
    drop(server);
    let found = match result {
        Some(result) => result.map_err(|e| e.to_string())?,
        None => {
            let mut registry = control.registry.load().map_err(|e| e.to_string())?;
            let found = offline(&mut registry);
            if found {
                control.registry.save(&registry).map_err(|e| e.to_string())?;
                control.record(&format!("edited the pairing {id} while the API is off"));
            }
            control.refresh_offline();
            found
        }
    };
    state.publisher.mark();
    if found { Ok(()) } else { Err("no such app".into()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
    const B: &str = "11111111-2222-4333-8444-555555555555";

    /// macOS's tool table (platform-mac's `SetupChecker::REQUIRED_TOOLS`), for the readiness tests.
    const REQUIRED_TOOLS: &[(VPNKind, &[&str])] = &[
        (VPNKind::Openvpn, &["openvpn"]),
        (VPNKind::Wireguard, &["wg", "wg-quick", "wireguard-go", "bash"]),
        (VPNKind::Strongswan, &["swanctl", "charon"]),
        (VPNKind::Sstp, &["sstpc"]),
    ];

    #[test]
    fn client_ids_must_be_uuids() {
        assert_eq!(parse_client_id(A).unwrap(), macvpn_core::models::parse_uuid(A).unwrap());
        for bad in ["", "x", "38B51E6D5D774ABEBFDFB0E5DE45B1C4", "../../etc/passwd", &format!("{A} ")] {
            assert!(parse_client_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn allowed_keys_are_listed_connections_each_once() {
        let listed = vec![A.to_string(), B.to_string()];
        assert_eq!(validate_allowed_keys(&[], &listed), Ok(vec![]));
        assert_eq!(validate_allowed_keys(&[B.into(), A.into()], &listed), Ok(vec![B.to_string(), A.to_string()]));
        assert!(validate_allowed_keys(&[A.into(), A.into()], &listed).is_err());
        assert!(validate_allowed_keys(&["66666666-7777-4888-9999-AAAAAAAAAAAA".into()], &listed).is_err());
        assert!(validate_allowed_keys(&["not-a-key".into()], &listed).is_err());
        assert!(validate_allowed_keys(&[A.into(), B.into(), A.into()], &listed).is_err());
        assert!(validate_allowed_keys(&[A.into()], &[]).is_err());
    }

    #[test]
    fn setup_ready_for_depends_on_what_the_connection_needs() {
        let ready = SetupReport {
            package_manager: Some("/opt/homebrew".into()),
            required_tools: REQUIRED_TOOLS,
            missing_tools: vec!["sstpc".into()],
            installed_root_version: Some("7".into()),
            bundled_root_version: Some("7".into()),
            sudo_works: true,
            missing_root_files: vec![],
            engine_missing: None,
            engine: None,
            later_kinds: Vec::new(),
            outdated_packages: Vec::new(),
            ras: None,
            ras_unsupported_kinds: Vec::new(),
            nm: None,
        };
        let managed = |kind| ConnectionItem::Managed(Connection::new("C", kind));
        let openvpn = managed(VPNKind::Openvpn);
        // A root-layer connection: Homebrew, a current root layer, `sudo -n` and its type's tool.
        assert!(setup_ready_for(&ready, &openvpn));
        assert!(!setup_ready_for(&ready, &managed(VPNKind::Sstp)), "its tool is missing");
        assert!(!setup_ready_for(&SetupReport { package_manager: None, ..ready.clone() }, &openvpn));
        assert!(!setup_ready_for(&SetupReport { installed_root_version: None, ..ready.clone() }, &openvpn));
        assert!(!setup_ready_for(&SetupReport { installed_root_version: Some("6".into()), ..ready.clone() }, &openvpn));
        assert!(!setup_ready_for(&SetupReport { sudo_works: false, ..ready.clone() }, &openvpn));
        assert!(!setup_ready_for(&SetupReport::unknown(), &openvpn));
        // Native L2TP / Cisco and system VPNs start through SCNetworkConnection: no Homebrew, no root layer.
        let none = SetupReport::unknown();
        assert!(setup_ready_for(&none, &managed(VPNKind::L2tp)));
        assert!(setup_ready_for(&none, &managed(VPNKind::Cisco)));
        assert!(setup_ready_for(&none, &ConnectionItem::System(SystemVpn::new(B, "Corp", "IKEv2", "Disconnected"))));
    }

    #[test]
    fn start_errors_are_translated_without_the_os_error() {
        let dir = Path::new("/Users/x/Library/Application Support/MacVPN/control");
        let shown = dir.display().to_string();
        let os = |kind: ErrorKind| io::Error::new(kind, "RAW OS DETAIL");
        let busy = start_error_message(&os(ErrorKind::AddrInUse), dir);
        assert!(busy.contains("Another copy"), "{busy}");
        let not_dir = start_error_message(&os(ErrorKind::NotADirectory), dir);
        assert!(not_dir.contains("is not a folder") && not_dir.contains(&shown), "{not_dir}");
        let denied = start_error_message(&os(ErrorKind::PermissionDenied), dir);
        assert!(denied.contains("no access") && denied.contains(&shown), "{denied}");
        let other = start_error_message(&os(ErrorKind::InvalidInput), dir);
        assert!(other.contains("cannot be used"), "{other}");
        let registry = registry_error_message(Path::new("/r.json"));
        assert!(registry.contains("/r.json"), "{registry}");
        for text in [&busy, &not_dir, &denied, &other, &registry] {
            assert!(!text.contains("RAW OS DETAIL"), "{text}");
        }
        let hu = l10n::with_language(l10n::AppLanguage::Hu, || {
            [ErrorKind::AddrInUse, ErrorKind::NotADirectory, ErrorKind::PermissionDenied, ErrorKind::Other]
                .map(|k| start_error_message(&os(k), dir))
        });
        for (en, hu) in [&busy, &not_dir, &denied, &other].into_iter().zip(hu.iter()) {
            assert_ne!(en, hu);
        }
        assert_ne!(
            registry,
            l10n::with_language(l10n::AppLanguage::Hu, || registry_error_message(Path::new("/r.json")))
        );
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("macvpn-audit-{name}-{}", uuid::Uuid::new_v4()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn the_audit_file_is_private_and_rotates() {
        let root = scratch("rotate");
        let dir = root.join("control");
        append_audit(&dir, "one", 64).unwrap();
        append_audit(&dir, "two", 64).unwrap();
        let path = dir.join(AUDIT_FILE);
        assert!(fsx::has_access(&fsx::stat_path(&path, Follow::Yes).unwrap(), Access::Private), "0600");
        assert!(fsx::has_access(&fsx::stat_path(&dir, Follow::Yes).unwrap(), Access::Private), "0700");
        assert_eq!(fs::read_to_string(&path).unwrap(), "one\ntwo\n");
        // Past the cap: the file moves to audit.log.1 (one old file kept).
        append_audit(&dir, &"x".repeat(60), 64).unwrap();
        assert_eq!(fs::read_to_string(dir.join(AUDIT_OLD_FILE)).unwrap(), "one\ntwo\n");
        append_audit(&dir, &"y".repeat(60), 64).unwrap();
        assert_eq!(fs::read_to_string(dir.join(AUDIT_OLD_FILE)).unwrap(), format!("{}\n", "x".repeat(60)));
        assert_eq!(read_audit(&dir).unwrap(), format!("{}\n{}\n", "x".repeat(60), "y".repeat(60)));
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2);
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_audit_file_never_follows_a_symlink() {
        let root = scratch("link");
        let dir = root.join("control");
        fs::create_dir_all(&dir).unwrap();
        let target = root.join("elsewhere");
        fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, dir.join(AUDIT_FILE)).unwrap();
        assert!(append_audit(&dir, "line", AUDIT_CAP).is_err());
        assert!(read_audit(&dir).is_err());
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
        // A symlinked control directory is refused too.
        let linked = root.join("linked");
        std::os::unix::fs::symlink(&dir, &linked).unwrap();
        assert!(append_audit(&linked, "line", AUDIT_CAP).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    /// The paired clients in memory (the vault's `VaultRegistry` in the app), counting the saves.
    #[derive(Default)]
    struct MemoryRegistry {
        registry: Mutex<Registry>,
        saves: AtomicUsize,
    }

    impl RegistryStore for MemoryRegistry {
        fn load(&self) -> io::Result<Registry> {
            Ok(self.registry.lock().unwrap().clone())
        }
        fn save(&self, registry: &Registry) -> io::Result<()> {
            self.saves.fetch_add(1, Ordering::SeqCst);
            *self.registry.lock().unwrap() = registry.clone();
            Ok(())
        }
    }

    fn paired(allowed: &[&str]) -> Arc<MemoryRegistry> {
        let store = Arc::new(MemoryRegistry::default());
        let mut registry = Registry::default();
        registry.add(PairedClient::new(
            Uuid::from_u128(7),
            "Raycast".into(),
            "token",
            "/Applications/Raycast.app/Contents/MacOS/Raycast".into(),
            allowed.iter().map(|k| k.to_string()).collect(),
            Date::now(),
        ));
        *store.registry.lock().unwrap() = registry;
        store
    }

    fn allowed(store: &MemoryRegistry) -> Vec<String> {
        store.registry.lock().unwrap().clients()[0].allowed.clone()
    }

    /// A server host that is never asked anything in these tests.
    struct IdleHost;
    impl ControlHost for IdleHost {
        fn items(&self) -> Vec<ConnectionItem> {
            Vec::new()
        }
        fn state(&self, _: &str) -> ConnectionState {
            ConnectionState::Disconnected
        }
        fn connect(&self, _: &str) -> Result<(), ErrorCode> {
            Err(ErrorCode::UnknownConnection)
        }
        fn disconnect(&self, _: &str) {}
        fn setup_ready_for(&self, _: &str) -> bool {
            false
        }
        fn ask_pairing(&self, _: PairingRequest) -> PairingAnswer {
            PairingAnswer::Denied
        }
        fn log(&self, _: String) {}
        fn credentials_cancelled(&self, _: &str) -> bool {
            false
        }
    }

    /// The catalog's pruning while the control API is off: the stored registry loses the keys, saved once; an
    /// unknown key changes (and saves) nothing.
    #[test]
    fn forgetting_keys_prunes_the_stored_registry_while_the_server_is_off() {
        let root = scratch("forget-off");
        let store = paired(&[A, B]);
        let control = ControlApp::new(&root, store.clone(), root.join("vault"));
        assert!(!control.is_running());
        control.forget_keys(&[A.to_string()]).unwrap();
        assert_eq!(allowed(&store), [B]);
        assert_eq!(store.saves.load(Ordering::SeqCst), 1);
        control.forget_keys(&["66666666-7777-4888-9999-AAAAAAAAAAAA".to_string()]).unwrap();
        control.forget_keys(&[]).unwrap();
        assert_eq!(store.saves.load(Ordering::SeqCst), 1, "nothing changed, nothing saved");
        // The Paired apps list shown while the server is off follows.
        assert_eq!(control.slot().offline[0].allowed, [B]);
        let _ = fs::remove_dir_all(&root);
    }

    /// The catalog's pruning while the control API runs: the server's live registry loses the keys (so a client
    /// cannot use them any more) and saves them.
    #[test]
    fn forgetting_keys_goes_through_the_running_server() {
        // A short directory: the socket path must fit `sun_path`.
        let root = PathBuf::from(format!("/tmp/mvfk-{}", &Uuid::new_v4().simple().to_string()[..8]));
        let store = paired(&[A, B]);
        let control = ControlApp::new(&root, store.clone(), root.join("vault"));
        // Linux binds in the runtime directory, which the test's sandbox platform does not have
        // (`MACVPN_SANDBOX_HOME` unset): the sandbox's transport over the test's own directory instead.
        #[cfg(target_os = "linux")]
        let transport: Arc<dyn macvpn_platform_api::ControlTransport> =
            Arc::new(macvpn_platform_linux::LinTransport::sandbox(root.join("run")));
        #[cfg(not(target_os = "linux"))]
        let transport = crate::platform::get().control_transport();
        let server = ControlServer::start(
            ControlOptions::with_registry(control.control_dir().to_path_buf(), store.clone()),
            Arc::new(IdleHost),
            transport,
        )
        .unwrap();
        control.set_server_for_test(server);
        assert!(control.is_running());
        control.forget_keys(&[B.to_string()]).unwrap();
        let server = control.take_server_for_test().unwrap();
        assert_eq!(server.clients()[0].allowed, [A], "the live allowlist");
        assert_eq!(allowed(&store), [A], "and the stored one");
        let mut server = server;
        server.stop(StopMode::EndLeases);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn no_start_once_the_quit_proceeds() {
        let root = scratch("quit");
        let registry = Arc::new(macvpn_app_core::control::FileRegistryStore { dir: root.clone() });
        let control = ControlApp::new(&root, registry, root.join("control-clients.json"));
        assert!(control.may_start());
        control.begin_quit();
        assert!(!control.may_start());
        assert_eq!(control.control_dir(), root.join("control"));
    }

    // MARK: the host's mapping, over a real manager with fake system parts

    use macvpn_app_core::deps::{
        ConnectionRepository, HelperClient, NativeController, SecretField, SecretReader, SystemVpn,
    };
    use macvpn_core::mfa::AuthResponseKind;
    use macvpn_core::models::{Connection, Secrets, VPNKind, uuid_string};
    use macvpn_core::native::NativeKind;
    use macvpn_core::status::RootStatus;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Calls(Mutex<Vec<String>>);

    impl Calls {
        fn push(&self, call: String) {
            self.0.lock().unwrap().push(call);
        }
        fn take(&self) -> Vec<String> {
            std::mem::take(&mut self.0.lock().unwrap())
        }
    }

    struct Repo(Vec<Connection>);
    impl ConnectionRepository for Repo {
        fn list(&self) -> io::Result<Vec<Connection>> {
            Ok(self.0.clone())
        }
        fn save(&self, _: &Connection, _: Option<&str>) -> io::Result<()> {
            Ok(())
        }
        fn load_config(&self, _: &Uuid) -> io::Result<String> {
            Ok("remote vpn.example.com\n".into())
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

    struct Root(Arc<Calls>);
    impl HelperClient for Root {
        fn status(&self) -> Result<Vec<RootStatus>, String> {
            Ok(vec![])
        }
        fn up(&self, kind: VPNKind, id: &Uuid, _: &[u8], _: &Secrets, debug: bool, _: &[String]) -> Result<(), String> {
            self.0.push(format!("up {} {} debug={debug}", kind.raw_value(), uuid_string(id)));
            Ok(())
        }
        fn down(&self, kind: VPNKind, id: &Uuid) -> Result<(), String> {
            self.0.push(format!("down {} {}", kind.raw_value(), uuid_string(id)));
            Ok(())
        }
        fn respond(&self, _: &Uuid, _: AuthResponseKind, _: &str) -> Result<(), String> {
            Ok(())
        }
    }

    struct Native(Arc<Calls>);
    impl NativeController for Native {
        fn list(&self) -> Result<Vec<SystemVpn>, String> {
            Ok(vec![SystemVpn::new(B, "Corp", "IKEv2", "Disconnected")])
        }
        fn remote_address(&self, _: &str) -> Option<String> {
            None
        }
        fn start(&self, id: &str, _: Option<NativeKind>, _: &Secrets) -> Result<(), String> {
            self.0.push(format!("start {id}"));
            Ok(())
        }
        fn stop(&self, id: &str) -> Result<(), String> {
            self.0.push(format!("stop {id}"));
            Ok(())
        }
    }

    fn manager(connections: Vec<Connection>) -> (Arc<ConnectionManager>, Arc<Calls>) {
        let calls = Arc::new(Calls::default());
        let deps = macvpn_app_core::Dependencies::new(
            Arc::new(Repo(connections)),
            Arc::new(NoSecrets),
            Arc::new(Root(calls.clone())),
            Arc::new(Native(calls.clone())),
        );
        let m = ConnectionManager::new(deps);
        m.reload();
        m.refresh();
        (m, calls)
    }

    fn ready() -> SetupReport {
        SetupReport {
            package_manager: Some("/opt/homebrew".into()),
            required_tools: REQUIRED_TOOLS,
            missing_tools: vec!["sstpc".into()],
            installed_root_version: Some("7".into()),
            bundled_root_version: Some("7".into()),
            sudo_works: true,
            missing_root_files: vec![],
            engine_missing: None,
            engine: None,
            later_kinds: Vec::new(),
            outdated_packages: Vec::new(),
            ras: None,
            ras_unsupported_kinds: Vec::new(),
            nm: None,
        }
    }

    #[test]
    fn host_connects_like_a_manual_connect() {
        let wg = Connection::new("Lab", VPNKind::Wireguard);
        let sstp = Connection::new("Azure", VPNKind::Sstp);
        let (wg_key, sstp_key) = (uuid_string(&wg.id), uuid_string(&sstp.id));
        let (m, calls) = manager(vec![wg, sstp]);
        assert_eq!(connect_key(&m, &ready(), A), Err(ErrorCode::UnknownConnection));
        // The SSTP tool is missing: nothing starts.
        assert_eq!(connect_key(&m, &ready(), &sstp_key), Err(ErrorCode::SetupRequired));
        assert_eq!(connect_key(&m, &SetupReport::unknown(), &wg_key), Err(ErrorCode::SetupRequired));
        // Without a VPN engine nothing starts, whatever the type.
        let no_engine = SetupReport { engine_missing: Some("Later.".into()), ..ready() };
        assert_eq!(connect_key(&m, &no_engine, &wg_key), Err(ErrorCode::Failed));
        // A kind that comes later fails the same way (WinVPN: the native VPNs).
        let later = SetupReport { later_kinds: vec![(VPNKind::Sstp, "Later.".into())], ..ready() };
        assert_eq!(connect_key(&m, &later, &sstp_key), Err(ErrorCode::Failed));
        assert!(calls.take().is_empty());
        assert_eq!(connect_key(&m, &ready(), &wg_key), Ok(()));
        assert_eq!(calls.take(), [format!("up wireguard {wg_key} debug=false")]);
        // A system VPN starts through the native controller.
        assert_eq!(connect_key(&m, &ready(), B), Ok(()));
        assert_eq!(calls.take(), [format!("start {B}")]);
    }

    /// WinVPN 2c (G-4): with the Windows VPN client usable, a missing WinVPN Service refuses only OpenVPN and
    /// WireGuard: an IKEv2 connection and a system VPN reach the manager; a connection the platform cannot connect
    /// with its settings is refused.
    #[test]
    fn a_missing_service_does_not_refuse_ras_kinds_or_system_vpns() {
        struct NoTls;
        impl macvpn_app_core::deps::NativeSupport for NoTls {
            fn unsupported_reason(&self, c: &Connection, _: &[u8]) -> Option<String> {
                (c.name == "TLS").then(|| "Not on Windows.".to_string())
            }
        }
        let wg = Connection::new("Lab", VPNKind::Wireguard);
        let ikev2 = Connection::new("Branch", VPNKind::Strongswan);
        let tls = Connection::new("TLS", VPNKind::Strongswan);
        let (wg_key, ikev2_key, tls_key) = (uuid_string(&wg.id), uuid_string(&ikev2.id), uuid_string(&tls.id));
        let (m, calls) = manager(vec![wg, ikev2, tls]);
        m.set_native_support(Arc::new(NoTls));
        m.reload();
        let row = macvpn_platform_api::EngineRow { ok: true, usable: true, detail: String::new(), action: None };
        let report = SetupReport { engine_missing: Some("No service.".into()), ras: Some(row), ..ready() };
        assert_eq!(connect_key(&m, &report, &wg_key), Err(ErrorCode::Failed));
        assert_eq!(connect_key(&m, &report, &tls_key), Err(ErrorCode::Failed));
        let item = m.item(&tls_key).unwrap();
        assert_eq!(start_refusal(&report, &m, &item).as_deref(), Some("Not on Windows."));
        assert!(calls.take().is_empty());
        assert_eq!(connect_key(&m, &report, &ikev2_key), Ok(()));
        assert_eq!(calls.take(), [format!("up strongswan {ikev2_key} debug=false")]);
        assert_eq!(connect_key(&m, &report, B), Ok(()));
        assert_eq!(calls.take(), [format!("start {B}")]);
        // macOS / WinVPN before 2c: no RAS row, the engine-missing text refuses the system VPN too.
        let old = SetupReport { ras: None, ..report };
        assert_eq!(connect_key(&m, &old, B), Err(ErrorCode::Failed));
        assert_eq!(connect_key(&m, &old, &ikev2_key), Err(ErrorCode::Failed));
    }

    #[test]
    fn host_disconnects_for_the_lease_not_the_user() {
        let wg = Connection::new("Lab", VPNKind::Wireguard);
        let key = uuid_string(&wg.id);
        let (m, calls) = manager(vec![wg]);
        let users = Arc::new(AtomicUsize::new(0));
        let counted = users.clone();
        m.add_user_disconnect_listener(move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
        });
        disconnect_key(&m, &key);
        disconnect_key(&m, B);
        disconnect_key(&m, A);
        assert_eq!(calls.take(), [format!("down wireguard {key}"), format!("stop {B}")]);
        assert_eq!(users.load(Ordering::SeqCst), 0, "a lease's disconnect is not the user's");
        // The user's own disconnect is (the control API ends every lease on it).
        m.disconnect_system(&SystemVpn::new(B, "Corp", "IKEv2", "Connected"));
        assert_eq!(users.load(Ordering::SeqCst), 1);
    }
}
