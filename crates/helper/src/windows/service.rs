//! What the WinVPN Service decides for one request (see the module docs of `macvpn_core::service_proto` for the
//! wire format). The caller's SID comes from the pipe (the host reads it from the client's token); everything else
//! from the request is untrusted. The rules of the macOS root layer apply: the shared CLI and framing, the shared
//! validators, masked logs, the status JSON; plus ownership: a connection belongs to the SID that brought it up.
//!
//! Ownership is fail-closed: another SID's connection answers exactly like an unknown ID ("Invalid ID"), and a
//! connection whose `down` failed stays owned (it may still run; only its owner can retry). The state is bounded:
//! [`MAX_PER_USER`] / [`MAX_TOTAL`] connections, [`MAX_LOGS_PER_USER`] / [`MAX_LOGS_TOTAL`] past logs (the oldest
//! of a connection that is not running is deleted first).

use crate::shared::framing::{self, Secrets};
use crate::shared::l10n::tr;
use crate::shared::mask::Masker;
use crate::shared::status_json::{self, StatusLine};
use crate::shared::{cli, respond, validate};
use crate::windows::diagnostics::{self, PeerStatus, Snapshot};
use macvpn_core::l10n::with_language;
use macvpn_core::liveness::{LIVENESS, Liveness};
use macvpn_core::models::VPNKind;
use macvpn_core::service_proto::{
    CLEAR_LOG, EngineFacts, EngineUpdate, LogSlice, Request, Response, SERVICE_VERSION, UPDATE_BUSY, WIREGUARD_CHECK,
    WIREGUARD_UPDATE,
};
use macvpn_core::traffic::{ByteCount, TRAFFIC};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

/// Connections one user may have at a time.
pub const MAX_PER_USER: usize = 8;
/// Connections the service runs at a time.
pub const MAX_TOTAL: usize = 32;
/// Logs one user keeps (running connections included; the oldest of a stopped one is deleted first).
pub const MAX_LOGS_PER_USER: usize = 32;
/// Logs the service keeps.
pub const MAX_LOGS_TOTAL: usize = 256;
/// The longest log slice one `log` request returns.
pub const LOG_SLICE_MAX: usize = 1024 * 1024;
/// The longest `auth-state` answer (`AuthUIState::parse` refuses anything longer).
const AUTH_STATE_MAX: usize = 8192;

// Every limit of the past logs leaves room for the running connections (which are never evicted).
const _: () = assert!(MAX_LOGS_PER_USER >= MAX_PER_USER && MAX_LOGS_TOTAL >= MAX_TOTAL);

/// Who sent the request: the SID from the client's token (string form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub sid: String,
}

/// One line sink of a connection's log; every line is masked by the sink.
pub trait LogSink: Send + Sync {
    fn line(&self, text: &str);
}

/// The connection logs (`C:\ProgramData\WinVPN\logs`).
pub trait LogStore: Send + Sync {
    /// Starts a new log for `id` (a new generation), masking with `masker`.
    fn open(&self, id: &str, masker: Masker) -> Box<dyn LogSink>;
    /// The bytes from `offset` (at most `max`) of the current log; `None`: no log.
    fn read(&self, id: &str, offset: u64, max: usize) -> Option<LogSlice>;
    /// "Clear Log…": empties the log of `id` (its rotated part too) in place, `note` as its first line, as a new
    /// generation; its sink keeps writing after the note. `false`: no log of `id` (nothing changed).
    fn clear(&self, _id: &str, _note: &str) -> bool {
        false
    }
    /// Deletes the log of `id` (the service no longer keeps it).
    fn remove(&self, id: &str);
}

/// What an engine gets for an `up`: the validated config and the secrets (both zeroed on drop by their owner).
pub struct UpRequest<'a> {
    /// The canonical (upper-case) UUID.
    pub id: &'a str,
    pub config: &'a [u8],
    pub secrets: &'a Secrets,
    pub debug: bool,
    /// The connection's log; an engine may keep it beyond `up` (OpenVPN logs while the connection runs).
    pub log: &'a Arc<dyn LogSink>,
}

/// A connection's state as `status` reports it. The engine passes checked values (`iface` letters, digits and
/// `-`, `ip` hex digits, `:` and `.`); the service checks them again and reports anything else as unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineState {
    pub state: &'static str,
    pub iface: String,
    pub ip: String,
    pub since: Option<u64>,
}

/// Why an engine update did not run (2b plan, "As built (fix4)").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateRefusal {
    /// Not now: a connection of the engine is up, or another update runs (the localized reason; exit
    /// [`UPDATE_BUSY`]).
    Busy(String),
    /// The update failed; what was loaded before stays loaded (the localized reason).
    Failed(String),
}

/// One VPN engine of the service (OpenVPN, WireGuard).
pub trait Engine: Send + Sync {
    /// Blocks until the connection is up or has failed (the localized message; then nothing of it runs). A `down`
    /// of the same id may come while it blocks (the user cancels a connect): it must make this `up` return.
    fn up(&self, req: &UpRequest<'_>) -> Result<(), String>;
    /// `Ok` also when nothing of `id` runs; `Err`: it may still run.
    fn down(&self, id: &str) -> Result<(), String>;
    /// `None`: not running.
    fn state(&self, id: &str) -> Option<EngineState>;
    /// The MFA answer (`respond`'s body, already checked by `respond::parse`).
    fn respond(&self, _id: &str, _body: &[u8]) -> Result<(), String> {
        Err(tr("Not available on this system yet", &[]))
    }
    /// The bridge's `AuthUIState` JSON for the app.
    fn auth_state(&self, _id: &str) -> Option<Vec<u8>> {
        None
    }
    /// Whether a newer version of the engine than the loaded one is available (the service asks upstream itself).
    fn update_check(&self) -> Result<EngineUpdate, String> {
        Err(tr("Not available on this system yet", &[]))
    }
    /// Downloads, verifies and loads the newest version (only while none of the engine's connections is up).
    fn update(&self) -> Result<EngineUpdate, UpdateRefusal> {
        Err(UpdateRefusal::Failed(tr("Not available on this system yet", &[])))
    }
    /// Dead-tunnel detection: the running connection's liveness facts (`liveness <id>`). `None`: not running, or
    /// nothing to report.
    fn liveness(&self, _id: &str) -> Option<Liveness> {
        None
    }
    /// Live traffic: the running connection's byte counters of its engine run (`traffic <id>`; OpenVPN's
    /// `>BYTECOUNT`). `None`: not running, not connected yet, or an engine without them.
    fn traffic(&self, _id: &str) -> Option<ByteCount> {
        None
    }
    /// Debug mode, after a successful `up` (G-6): the adapter's name and its peers' status (WireGuard; `wg show`
    /// on macOS). `None`: the engine has none.
    fn peer_status(&self, _id: &str) -> Option<(String, Vec<PeerStatus>)> {
        None
    }
}

/// The service's environment: the engines, the facts, the logs, and whether it may connect at all.
pub trait Host: Send + Sync {
    fn engine(&self, kind: VPNKind) -> Option<&dyn Engine>;
    fn facts(&self) -> EngineFacts;
    fn logs(&self) -> &dyn LogStore;
    /// Degraded (the data directory is unsafe): the localized reason; `up` is refused with it.
    fn problem(&self) -> Option<String>;
    /// Debug mode (G-6): the system's routes, DNS and interfaces and `server`'s addresses, read-only. `None`: the
    /// host cannot read them (the default).
    fn snapshot(&self, _server: Option<&str>) -> Option<Snapshot> {
        None
    }
    /// The local date and time as the logs write it (`YYYY-MM-DD HH:MM:SS`; the "Log cleared at" note). Default:
    /// the UTC time of [`Self::now`] (the real host reads the local time).
    fn local_timestamp(&self) -> String {
        let iso = macvpn_core::date::Date::from_time_interval_since_1970(self.now() as f64).iso8601();
        iso.trim_end_matches('Z').replacen('T', " ", 1)
    }
    /// Unix seconds (the peer status' "latest handshake … ago").
    fn now(&self) -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
    }
}

struct Owned {
    sid: String,
    kind: VPNKind,
    /// Which `up` recorded it (an `up` that returns finds out whether a `down` took it meanwhile).
    epoch: u64,
}

struct LogOwner {
    sid: String,
    /// The `up` that started the log (older logs are deleted first).
    seq: u64,
}

pub struct Service<H: Host> {
    host: H,
    /// The connections: running, connecting, or whose `down` failed. Lock order: `owned`, `busy`, `log_owner`.
    owned: Mutex<HashMap<String, Owned>>,
    /// The IDs whose `up` is in progress, and whose it is.
    busy: Mutex<HashMap<String, String>>,
    /// The last owner of each log (logs stay readable by their owner after `down`).
    log_owner: Mutex<HashMap<String, LogOwner>>,
    seq: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn invalid_id() -> Response {
    Response::fail(1, &tr("Invalid ID", &[]))
}

fn usage() -> Response {
    Response::fail(
        2,
        &tr(
            "Usage: up|down <openvpn|wireguard> <id> [--debug] [--accept-risky a,b] [--lang en|hu] | respond openvpn <id> | status | version | engine | auth-state <id> | log <id> <offset> | clear-log <id> | liveness <id> | traffic <id>",
            &[],
        ),
    )
}

/// A WireGuard connection is up (any user's): wireguard-nt cannot be replaced while its driver is in use.
pub fn wireguard_busy() -> String {
    tr(
        "wireguard-nt can be updated only while no WireGuard connection is up on this computer. Disconnect WireGuard, then try again.",
        &[],
    )
}

fn not_available() -> Response {
    Response::fail(1, &tr("Not available on this system yet", &[]))
}

/// The kind of a request (`openvpn|wireguard|strongswan|sstp`), or the usage error.
fn kind_of(raw: &str) -> Result<VPNKind, Response> {
    VPNKind::from_raw_value(raw).filter(|_| cli::is_kind(raw)).ok_or_else(usage)
}

fn is_iface(s: &str) -> bool {
    s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn is_ip(s: &str) -> bool {
    s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
}

impl<H: Host> Service<H> {
    pub fn new(host: H) -> Service<H> {
        Service {
            host,
            owned: Mutex::default(),
            busy: Mutex::default(),
            log_owner: Mutex::default(),
            seq: AtomicU64::new(1),
        }
    }

    pub fn host(&self) -> &H {
        &self.host
    }

    /// One request, answered in the language it asks for (`--lang hu`), on this thread only.
    pub fn handle(&self, caller: &Caller, req: &Request) -> Response {
        let args = cli::Args::parse(&req.args);
        with_language(args.language(), || self.dispatch(caller, &args, &req.body))
    }

    fn dispatch(&self, caller: &Caller, a: &cli::Args, body: &[u8]) -> Response {
        // The service has no dry run: a request that asks for one must not connect anything.
        if a.dry_run {
            return usage();
        }
        match a.cmd.as_str() {
            "version" => Response::ok(format!("{SERVICE_VERSION}\n")),
            "engine" => {
                let mut facts = self.host.facts();
                if let Some(p) = self.host.problem() {
                    facts.problem = Some(p);
                }
                Response::ok(facts.to_json())
            }
            "status" => Response::ok(self.status(caller)),
            "up" => self.up(caller, a, body),
            "down" => self.down(caller, a),
            "respond" => self.respond(caller, a, body),
            // `auth-state <id>` and `log <id> <offset>`: the id is the CLI's second positional ("kind").
            "auth-state" => self.auth_state(caller, &a.kind),
            "log" => self.log(caller, &a.kind, &a.id),
            CLEAR_LOG => self.clear_log(caller, &a.kind),
            LIVENESS => self.liveness(caller, &a.kind),
            TRAFFIC => self.traffic(caller, &a.kind),
            // Engine updates: nothing of the request but the command is used (the service decides what to fetch).
            WIREGUARD_CHECK if a.kind.is_empty() => self.wireguard_check(),
            WIREGUARD_UPDATE if a.kind.is_empty() => self.wireguard_update(),
            _ => usage(),
        }
    }

    /// The canonical ID and kind if `raw` is a UUID of a connection `caller` owns.
    fn owned_kind(&self, caller: &Caller, raw: &str) -> Option<(String, VPNKind)> {
        if !cli::is_uuid(raw) {
            return None;
        }
        let id = raw.to_ascii_uppercase();
        let kind = lock(&self.owned).get(&id).filter(|o| o.sid == caller.sid).map(|o| o.kind)?;
        Some((id, kind))
    }

    /// `liveness <id>`: the caller's own running connection's liveness facts (dead-tunnel detection); only times
    /// and counters. Another user's or an unknown ID: "Invalid ID"; nothing to report: exit 1 with no output.
    fn liveness(&self, caller: &Caller, raw: &str) -> Response {
        let Some((id, kind)) = self.owned_kind(caller, raw) else { return invalid_id() };
        // The engine is asked without the service's locks held.
        match self.host.engine(kind).and_then(|e| e.liveness(&id)) {
            Some(l) => Response::ok(l.encode()),
            None => Response { code: 1, stdout: Vec::new(), stderr: Vec::new() },
        }
    }

    /// `traffic <id>`: the caller's own running connection's byte counters (live traffic); only numbers. Another
    /// user's or an unknown ID: "Invalid ID"; nothing to report: exit 1 with no output.
    fn traffic(&self, caller: &Caller, raw: &str) -> Response {
        let Some((id, kind)) = self.owned_kind(caller, raw) else { return invalid_id() };
        // The engine is asked without the service's locks held.
        match self.host.engine(kind).and_then(|e| e.traffic(&id)) {
            Some(b) => Response::ok(b.encode()),
            None => Response { code: 1, stdout: Vec::new(), stderr: Vec::new() },
        }
    }

    fn status(&self, caller: &Caller) -> String {
        let mut mine: Vec<(String, VPNKind)> =
            lock(&self.owned).iter().filter(|(_, o)| o.sid == caller.sid).map(|(id, o)| (id.clone(), o.kind)).collect();
        mine.sort_by(|a, b| a.0.cmp(&b.0));
        let connecting: HashSet<String> = lock(&self.busy).keys().cloned().collect();
        // The engines are asked without the service's locks held.
        let lines: Vec<StatusLine> = mine
            .into_iter()
            .map(|(id, kind)| {
                let st = self.host.engine(kind).and_then(|e| e.state(&id));
                let state = match st.as_ref().map(|s| s.state) {
                    Some(s @ ("connected" | "connecting")) => s,
                    None if connecting.contains(&id) => "connecting",
                    _ => "failed",
                };
                let iface = st.as_ref().map(|s| s.iface.clone()).filter(|v| is_iface(v)).unwrap_or_default();
                let ip = st.as_ref().map(|s| s.ip.clone()).filter(|v| is_ip(v)).unwrap_or_default();
                StatusLine {
                    kind: kind.raw_value().to_string(),
                    state,
                    iface,
                    ip,
                    since: st.and_then(|s| s.since).map(|n| n.to_string()),
                    id,
                }
            })
            .collect();
        status_json::render(&lines)
    }

    fn up(&self, caller: &Caller, a: &cli::Args, body: &[u8]) -> Response {
        if let Some(problem) = self.host.problem() {
            return Response::fail(1, &problem);
        }
        let kind = match kind_of(&a.kind) {
            Ok(k) => k,
            Err(r) => return r,
        };
        let Some(engine) = self.host.engine(kind) else { return not_available() };
        if !cli::is_uuid(&a.id) {
            return invalid_id();
        }
        if !a.accept_risky_valid() {
            return Response::fail(2, &tr("Invalid --accept-risky value", &[]));
        }
        let id = a.id.to_ascii_uppercase();
        let (config, secrets) = match framing::parse_framed(body, true) {
            Ok(x) => x,
            Err(e) => return Response::fail(1, &e.message()),
        };
        // The framing checked UTF-8; anything else is refused, never validated as empty.
        let Ok(text) = std::str::from_utf8(&config) else {
            return Response::fail(1, &framing::FrameError::Invalid.message());
        };
        let Some(issues) = validate::issues(kind, text, &validate::risky_set(&a.accept_risky)) else {
            return not_available();
        };
        if !issues.is_empty() {
            return Response::fail(1, &format!("{}\n{}", tr("Invalid config:", &[]), issues.join("\n")));
        }
        let epoch = self.seq.fetch_add(1, Ordering::SeqCst);
        let previous = {
            let mut owned = lock(&self.owned);
            let mut busy = lock(&self.busy);
            if let Some(sid) = busy.get(&id) {
                return if *sid == caller.sid {
                    Response::fail(1, &tr("Another operation on this connection is in progress", &[]))
                } else {
                    invalid_id()
                };
            }
            let previous = match owned.get(&id) {
                Some(o) if o.sid != caller.sid => return invalid_id(),
                Some(o) => Some(o.kind),
                None => {
                    let mine = owned.values().filter(|o| o.sid == caller.sid).count();
                    if mine >= MAX_PER_USER || owned.len() >= MAX_TOTAL {
                        return Response::fail(1, &tr("Too many connections", &[]));
                    }
                    None
                }
            };
            busy.insert(id.clone(), caller.sid.clone());
            owned.insert(id.clone(), Owned { sid: caller.sid.clone(), kind, epoch });
            drop(busy);
            self.record_log_owner(&owned, &id, &caller.sid, epoch);
            previous
        };
        let response = self.up_owned(caller, &id, kind, epoch, previous, engine, a.debug, &config, &secrets);
        lock(&self.busy).remove(&id);
        response
    }

    /// The part of `up` while `id` is marked busy (no other `up` of it runs).
    #[allow(clippy::too_many_arguments)]
    fn up_owned(
        &self,
        caller: &Caller,
        id: &str,
        kind: VPNKind,
        epoch: u64,
        previous: Option<VPNKind>,
        engine: &dyn Engine,
        debug: bool,
        config: &[u8],
        secrets: &Secrets,
    ) -> Response {
        // A connection of this id still recorded is closed first (by the engine that brought it up), so it is never
        // orphaned; if that fails it stays recorded as it was.
        if let Some(prev) = previous {
            let closed = self.host.engine(prev).is_some_and(|e| e.down(id).is_ok());
            if !closed {
                if let Some(o) = lock(&self.owned).get_mut(id).filter(|o| o.epoch == epoch) {
                    o.kind = prev;
                }
                return Response::fail(1, &tr("Cannot close the previous connection", &[]));
            }
        }
        let sink: Arc<dyn LogSink> = Arc::from(self.host.logs().open(id, secrets.masker()));
        // Debug mode: the diagnostics before and after, as macOS' `snapshot` (G-6); never without `--debug`.
        let server = if debug { diagnostics::server_of(kind, config) } else { None };
        if debug {
            self.write_snapshot(&*sink, &tr("before", &[]), server.as_deref());
        }
        let result = engine.up(&UpRequest { id, config, secrets, debug, log: &sink });
        if debug && result.is_ok() {
            if let Some((adapter, peers)) = engine.peer_status(id) {
                for line in diagnostics::peer_lines(&adapter, &peers, self.host.now()) {
                    sink.line(&line);
                }
            }
            self.write_snapshot(&*sink, &tr("after", &[]), server.as_deref());
        }
        let mut owned = lock(&self.owned);
        let ours = owned.get(id).is_some_and(|o| o.epoch == epoch);
        match result {
            Ok(()) if ours => Response::ok(Vec::new()),
            Ok(()) => {
                // A `down` (or the owner's logoff) took it while it was connecting: it must not run unowned.
                drop(owned);
                if let Err(m) = engine.down(id) {
                    lock(&self.owned).entry(id.to_string()).or_insert(Owned { sid: caller.sid.clone(), kind, epoch });
                    return Response::fail(1, &m);
                }
                Response::fail(1, &tr("The connection was taken down while connecting", &[]))
            }
            Err(message) => {
                if ours {
                    owned.remove(id);
                }
                Response::fail(1, &message)
            }
        }
    }

    /// The diagnostics block (debug mode only: the caller checks).
    fn write_snapshot(&self, sink: &dyn LogSink, label: &str, server: Option<&str>) {
        if let Some(snapshot) = self.host.snapshot(server) {
            for line in diagnostics::snapshot_lines(label, &snapshot) {
                sink.line(&line);
            }
        }
    }

    /// Records `sid` as the owner of `id`'s log and deletes the oldest logs over the limits (never one of a
    /// connection in `owned`).
    fn record_log_owner(&self, owned: &HashMap<String, Owned>, id: &str, sid: &str, seq: u64) {
        let mut logs = lock(&self.log_owner);
        logs.insert(id.to_string(), LogOwner { sid: sid.to_string(), seq });
        loop {
            let mine = logs.values().filter(|l| l.sid == sid).count();
            let only_mine = mine > MAX_LOGS_PER_USER;
            if !only_mine && logs.len() <= MAX_LOGS_TOTAL {
                return;
            }
            let victim = logs
                .iter()
                .filter(|(i, l)| !owned.contains_key(*i) && (!only_mine || l.sid == sid))
                .min_by_key(|(_, l)| l.seq)
                .map(|(i, _)| i.clone());
            let Some(victim) = victim else { return };
            logs.remove(&victim);
            self.host.logs().remove(&victim);
        }
    }

    fn down(&self, caller: &Caller, a: &cli::Args) -> Response {
        // The kind is checked for its form only: the engine that brought the connection up takes it down.
        if let Err(r) = kind_of(&a.kind) {
            return r;
        }
        let Some((id, kind)) = self.owned_kind(caller, &a.id) else { return invalid_id() };
        let Some(engine) = self.host.engine(kind) else { return not_available() };
        match engine.down(&id) {
            Ok(()) => {
                self.forget(&id, &caller.sid);
                Response::ok(Vec::new())
            }
            Err(m) => Response::fail(1, &m),
        }
    }

    /// `id` no longer runs: it is no longer `sid`'s connection (its log stays).
    fn forget(&self, id: &str, sid: &str) {
        let mut owned = lock(&self.owned);
        if owned.get(id).is_some_and(|o| o.sid == sid) {
            owned.remove(id);
        }
    }

    fn respond(&self, caller: &Caller, a: &cli::Args, body: &[u8]) -> Response {
        if a.kind != "openvpn" {
            return usage();
        }
        let Some((id, VPNKind::Openvpn)) = self.owned_kind(caller, &a.id) else { return invalid_id() };
        if let Err(key) = respond::parse(body) {
            return Response::fail(1, &respond::message(key));
        }
        match self.host.engine(VPNKind::Openvpn).map(|e| e.respond(&id, body)) {
            Some(Ok(())) => Response::ok(Vec::new()),
            Some(Err(m)) => Response::fail(1, &m),
            None => not_available(),
        }
    }

    fn auth_state(&self, caller: &Caller, raw: &str) -> Response {
        let Some((id, kind)) = self.owned_kind(caller, raw) else { return invalid_id() };
        let state = self.host.engine(kind).and_then(|e| e.auth_state(&id)).filter(|s| s.len() <= AUTH_STATE_MAX);
        Response::ok(state.unwrap_or_default())
    }

    /// The canonical ID if `raw` is a UUID whose log `caller` may read: the connection is theirs now, or its log is
    /// (after `down`). Anyone else's log answers as an unknown ID.
    fn own_log(&self, caller: &Caller, raw: &str) -> Option<String> {
        if !cli::is_uuid(raw) {
            return None;
        }
        let id = raw.to_ascii_uppercase();
        let now = lock(&self.owned).get(&id).is_some_and(|o| o.sid == caller.sid);
        let past = lock(&self.log_owner).get(&id).is_some_and(|l| l.sid == caller.sid);
        (now || past).then_some(id)
    }

    /// `clear-log <id>`: the owner's "Clear Log…" (the note in the request's language, the service's local time).
    /// Never the usage error (exit 2): the app reads that as a service too old to know the request.
    fn clear_log(&self, caller: &Caller, raw: &str) -> Response {
        let Some(id) = self.own_log(caller, raw) else { return invalid_id() };
        let note = macvpn_core::log::cleared_note(&self.host.local_timestamp());
        self.host.logs().clear(&id, &note);
        Response::ok(Vec::new())
    }

    fn log(&self, caller: &Caller, raw: &str, offset: &str) -> Response {
        let Some(id) = self.own_log(caller, raw) else { return invalid_id() };
        let Some(offset) = offset.parse::<u64>().ok().filter(|_| offset.bytes().all(|b| b.is_ascii_digit())) else {
            return usage();
        };
        match self.host.logs().read(&id, offset, LOG_SLICE_MAX) {
            Some(slice) => Response::ok(slice.encode()),
            None => Response::ok(LogSlice { generation: 0, size: 0, start: 0, data: Vec::new() }.encode()),
        }
    }

    fn wireguard_check(&self) -> Response {
        match self.host.engine(VPNKind::Wireguard).map(|e| e.update_check()) {
            Some(Ok(u)) => Response::ok(u.to_json()),
            Some(Err(m)) => Response::fail(1, &m),
            None => not_available(),
        }
    }

    /// Refused while any WireGuard connection is recorded (up, connecting, or one whose `down` failed): the engine
    /// checks again under its own lock (an `up` may start meanwhile).
    fn wireguard_update(&self) -> Response {
        if let Some(problem) = self.host.problem() {
            return Response::fail(1, &problem);
        }
        let Some(engine) = self.host.engine(VPNKind::Wireguard) else { return not_available() };
        if lock(&self.owned).values().any(|o| o.kind == VPNKind::Wireguard) {
            return Response::fail(UPDATE_BUSY, &wireguard_busy());
        }
        match engine.update() {
            Ok(u) => Response::ok(u.to_json()),
            Err(UpdateRefusal::Busy(m)) => Response::fail(UPDATE_BUSY, &m),
            Err(UpdateRefusal::Failed(m)) => Response::fail(1, &m),
        }
    }

    /// The user's session ended (logoff, decision 2): every connection of `sid` goes down (one whose `down`
    /// fails stays owned).
    pub fn drop_user(&self, sid: &str) {
        let ids: Vec<(String, VPNKind)> =
            lock(&self.owned).iter().filter(|(_, o)| o.sid == sid).map(|(id, o)| (id.clone(), o.kind)).collect();
        for (id, kind) in ids {
            if self.host.engine(kind).is_some_and(|e| e.down(&id).is_ok()) {
                self.forget(&id, sid);
            }
        }
    }

    /// The service stops: every connection goes down.
    pub fn shutdown(&self) {
        for sid in self.owners() {
            self.drop_user(&sid);
        }
    }

    /// The SIDs that own a connection (the host's logoff check).
    pub fn owners(&self) -> HashSet<String> {
        lock(&self.owned).values().map(|o| o.sid.clone()).collect()
    }
}
