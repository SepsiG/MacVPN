//! Test doubles (the Rust counterparts of the Swift `MockCommandRunner` / `MockNativeDriver` /
//! `InMemorySecretStore` as the connection manager sees them) and a fixture with a throwaway store directory.
#![allow(dead_code)]

use macvpn_app_core::deps::{HelperClient, ManualClock, NativeController, SecretField, SecretReader, SystemVpn};
use macvpn_app_core::{ConnectionEvent, ConnectionManager, Dependencies};
use macvpn_core::date::Date;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::mfa::AuthResponseKind;
use macvpn_core::models::{Connection, Secrets, VPNKind, uuid_string};
use macvpn_core::native::{NativeKind, NativeStartOptions, start_options};
use macvpn_core::status::{RootStatus, parse_status};
use macvpn_core::store::ConnectionStore;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// A unique directory under the system temp dir, removed on drop. Never the user's Application Support.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        TempDir(std::env::temp_dir().join(format!("macvpn-app-core-test-{}", Uuid::new_v4())))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// `status`, `up <kind> <id> [--debug] [--accept-risky a,b]`, `down <kind> <id>`, `respond openvpn <id>`.
    pub line: String,
    /// The secret lines (`up`, `respond`); the config of an `up` is in `config`.
    pub stdin: Option<String>,
    /// `up`: the config sent on stdin ahead of the secrets (root layer 8).
    pub config: Option<Vec<u8>>,
}

/// The root helper: a response per command line (default: success with empty output), optional delays.
#[derive(Default)]
pub struct MockHelper {
    responses: Mutex<HashMap<String, Result<String, String>>>,
    /// One-shot responses, used before `responses` (first in, first out).
    once: Mutex<HashMap<String, std::collections::VecDeque<Result<String, String>>>>,
    delays: Mutex<HashMap<String, Duration>>,
    calls: Mutex<Vec<Call>>,
}

impl MockHelper {
    pub fn respond(&self, line: &str, result: Result<&str, &str>) {
        self.responses.lock().unwrap().insert(line.to_string(), result.map(str::to_string).map_err(str::to_string));
    }

    /// The next call of `line` gets this response (then the regular one again).
    pub fn respond_once(&self, line: &str, result: Result<&str, &str>) {
        self.once
            .lock()
            .unwrap()
            .entry(line.to_string())
            .or_default()
            .push_back(result.map(str::to_string).map_err(str::to_string));
    }

    pub fn delay(&self, line: &str, seconds: f64) {
        self.delays.lock().unwrap().insert(line.to_string(), Duration::from_secs_f64(seconds));
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    pub fn lines(&self) -> Vec<String> {
        self.calls().into_iter().map(|c| c.line).collect()
    }

    /// Waits (up to 5 s) until `line` was called `count` times. A call is recorded when it starts, before its
    /// delay: an ordering point that does not depend on the runner's pace (unlike a fixed sleep).
    pub fn wait_for_call(&self, line: &str, count: usize) {
        let start = Instant::now();
        while self.lines().iter().filter(|l| *l == line).count() < count {
            assert!(start.elapsed() < Duration::from_secs(5), "no call of {line:?} (x{count})");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// The response is decided when the call starts (as the Swift mock does); the delay comes after.
    fn run(&self, line: String, stdin: Option<String>) -> Result<String, String> {
        self.run_with(line, stdin, None)
    }

    fn run_with(&self, line: String, stdin: Option<String>, config: Option<Vec<u8>>) -> Result<String, String> {
        let (response, delay) = {
            let mut calls = self.calls.lock().unwrap();
            calls.push(Call { line: line.clone(), stdin, config });
            let once = self.once.lock().unwrap().get_mut(&line).and_then(|q| q.pop_front());
            (
                once.or_else(|| self.responses.lock().unwrap().get(&line).cloned()),
                self.delays.lock().unwrap().get(&line).copied(),
            )
        };
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
        response.unwrap_or(Ok(String::new()))
    }
}

pub fn up_line(kind: VPNKind, id: &Uuid) -> String {
    format!("up {} {}", kind.raw_value(), uuid_string(id))
}

pub fn down_line(kind: VPNKind, id: &Uuid) -> String {
    format!("down {} {}", kind.raw_value(), uuid_string(id))
}

pub fn respond_line(id: &Uuid) -> String {
    format!("respond openvpn {}", uuid_string(id))
}

impl HelperClient for MockHelper {
    fn status(&self) -> Result<Vec<RootStatus>, String> {
        let out = self.run("status".into(), None)?;
        parse_status(&out).map_err(|e| e.to_string())
    }

    fn up(
        &self,
        kind: VPNKind,
        id: &Uuid,
        config: &[u8],
        secrets: &Secrets,
        debug: bool,
        accept_risky: &[String],
    ) -> Result<(), String> {
        let mut line = up_line(kind, id);
        if debug {
            line.push_str(" --debug");
        }
        if !accept_risky.is_empty() {
            line.push_str(" --accept-risky ");
            line.push_str(&accept_risky.join(","));
        }
        self.run_with(line, Some(secrets.stdin_payload().to_string()), Some(config.to_vec())).map(|_| ())
    }

    fn down(&self, kind: VPNKind, id: &Uuid) -> Result<(), String> {
        self.run(down_line(kind, id), None).map(|_| ())
    }

    fn respond(&self, id: &Uuid, kind: AuthResponseKind, response: &str) -> Result<(), String> {
        let payload = kind.stdin_payload(response).ok_or_else(|| "invalid code".to_string())?;
        self.run(respond_line(id), Some(payload)).map(|_| ())
    }

    /// Recorded as `clear-log <id>` with the note as its stdin.
    fn clear_log(&self, id: &Uuid, note: &str) -> Result<(), String> {
        self.run(format!("clear-log {}", uuid_string(id)), Some(note.to_string())).map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Start {
    pub service_id: String,
    /// What the platform layer would pass to `SCNetworkConnectionStart` (`None`: the stored configuration only).
    pub options: Option<NativeStartOptions>,
}

/// `scutil --nc list` / `--nc show` and the in-process start/stop driver.
pub struct MockNative {
    list: Mutex<Result<Vec<SystemVpn>, String>>,
    addresses: Mutex<HashMap<String, Option<String>>>,
    shows: Mutex<Vec<String>>,
    starts: Mutex<Vec<Start>>,
    stops: Mutex<Vec<String>>,
    start_error: Mutex<Option<String>>,
    /// `managed_service_id` (WinVPN's own RAS entries); empty: `None` for every connection (macOS).
    managed: Mutex<HashMap<Uuid, String>>,
    /// The connections whose log the platform keeps itself (WinVPN's RAS log); empty: none (macOS).
    own_logs: Mutex<HashMap<Uuid, Vec<String>>>,
}

impl Default for MockNative {
    fn default() -> Self {
        MockNative {
            list: Mutex::new(Ok(Vec::new())),
            addresses: Mutex::new(HashMap::new()),
            shows: Mutex::new(Vec::new()),
            starts: Mutex::new(Vec::new()),
            stops: Mutex::new(Vec::new()),
            start_error: Mutex::new(None),
            managed: Mutex::new(HashMap::new()),
            own_logs: Mutex::new(HashMap::new()),
        }
    }
}

impl MockNative {
    pub fn set_list(&self, list: Result<Vec<SystemVpn>, &str>) {
        *self.list.lock().unwrap() = list.map_err(str::to_string);
    }

    pub fn set_address(&self, service_id: &str, address: Option<&str>) {
        self.addresses.lock().unwrap().insert(service_id.to_string(), address.map(str::to_string));
    }

    pub fn set_start_error(&self, error: Option<&str>) {
        *self.start_error.lock().unwrap() = error.map(str::to_string);
    }

    pub fn set_managed(&self, connection: &Uuid, service_id: &str) {
        self.managed.lock().unwrap().insert(*connection, service_id.to_string());
    }

    /// The platform keeps `connection`'s log itself (its clears are recorded).
    pub fn set_own_log(&self, connection: &Uuid) {
        self.own_logs.lock().unwrap().insert(*connection, Vec::new());
    }

    /// The notes of the clears of `connection`'s own log.
    pub fn own_log_clears(&self, connection: &Uuid) -> Vec<String> {
        self.own_logs.lock().unwrap().get(connection).cloned().unwrap_or_default()
    }

    pub fn shows(&self) -> usize {
        self.shows.lock().unwrap().len()
    }

    pub fn starts(&self) -> Vec<Start> {
        self.starts.lock().unwrap().clone()
    }

    pub fn stops(&self) -> Vec<String> {
        self.stops.lock().unwrap().clone()
    }
}

impl NativeController for MockNative {
    fn list(&self) -> Result<Vec<SystemVpn>, String> {
        self.list.lock().unwrap().clone()
    }

    fn remote_address(&self, service_id: &str) -> Option<String> {
        self.shows.lock().unwrap().push(service_id.to_string());
        self.addresses.lock().unwrap().get(service_id).cloned().flatten()
    }

    fn start(&self, service_id: &str, kind: Option<NativeKind>, secrets: &Secrets) -> Result<(), String> {
        self.starts
            .lock()
            .unwrap()
            .push(Start { service_id: service_id.to_string(), options: kind.and_then(|k| start_options(k, secrets)) });
        match self.start_error.lock().unwrap().clone() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn stop(&self, service_id: &str) -> Result<(), String> {
        self.stops.lock().unwrap().push(service_id.to_string());
        Ok(())
    }

    fn managed_service_id(&self, connection: &Uuid) -> Option<String> {
        self.managed.lock().unwrap().get(connection).cloned()
    }

    fn clear_log(&self, connection: &Uuid, note: &str) -> Result<bool, String> {
        match self.own_logs.lock().unwrap().get_mut(connection) {
            Some(clears) => {
                clears.push(note.to_string());
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

#[derive(Default)]
pub struct MemorySecrets(Mutex<HashMap<(Uuid, SecretField), String>>, Mutex<Vec<(Uuid, SecretField)>>);

impl MemorySecrets {
    pub fn set(&self, value: &str, id: &Uuid, field: SecretField) {
        self.0.lock().unwrap().insert((*id, field), value.to_string());
    }

    /// The writes through `SecretWriter::set` (not the test's own `set`), in order.
    pub fn writes(&self) -> Vec<(Uuid, SecretField)> {
        self.1.lock().unwrap().clone()
    }
}

impl macvpn_app_core::deps::SecretWriter for MemorySecrets {
    fn set(&self, value: &str, id: &Uuid, field: SecretField) {
        self.1.lock().unwrap().push((*id, field));
        if value.is_empty() {
            self.0.lock().unwrap().remove(&(*id, field));
        } else {
            MemorySecrets::set(self, value, id, field);
        }
    }

    fn delete_all(&self, id: &Uuid) {
        self.0.lock().unwrap().retain(|(i, _), _| i != id);
    }

    fn remove_all(&self) {
        self.0.lock().unwrap().clear();
    }
}

impl MemorySecrets {
    pub fn count(&self, id: &Uuid) -> usize {
        self.0.lock().unwrap().keys().filter(|(i, _)| i == id).count()
    }
}

/// The native profiles as the macOS app makes them (`mobileconfig::generate` under the export's file name); the
/// installs are recorded instead of staging and opening a file.
#[derive(Default)]
pub struct MobileconfigProfiles {
    pub installs: Mutex<Vec<(Uuid, String, String, bool)>>,
    pub fail: Mutex<Option<String>>,
    /// The `remove` calls (WinVPN 2c), in order.
    pub removed: Mutex<Vec<Uuid>>,
    /// `removes_profiles` (WinVPN: true; macOS: false).
    pub removes: std::sync::atomic::AtomicBool,
    /// WinVPN's installer (Task 13): no approval step, and a Cisco IPsec profile refused with [`CISCO_REFUSED`].
    pub silent: std::sync::atomic::AtomicBool,
    /// The `reconcile` calls (WinVPN 2c Task 13), each with its known connections.
    pub reconciled: Mutex<Vec<std::collections::HashSet<Uuid>>>,
}

/// [`MobileconfigProfiles::silent`]'s answer to a Cisco IPsec install.
pub const CISCO_REFUSED: &str = "Cisco IPsec is not supported by Windows.";

impl macvpn_app_core::deps::NativeProfiles for MobileconfigProfiles {
    fn build(&self, connection: &Connection, psk: &str) -> Result<macvpn_app_core::deps::NativeProfile, String> {
        let data =
            zeroize::Zeroizing::new(macvpn_core::mobileconfig::generate(connection, psk).map_err(|e| e.message())?);
        Ok(macvpn_app_core::deps::NativeProfile { data, file_name: macvpn_core::exporter::file_name(connection) })
    }

    fn install(&self, id: &Uuid, profile: &[u8], file_name: &str, service_existed: bool) -> Result<(), String> {
        if let Some(e) = self.fail.lock().unwrap().clone() {
            return Err(e);
        }
        if self.silent.load(std::sync::atomic::Ordering::SeqCst) && String::from_utf8_lossy(profile).contains("XAuth") {
            return Err(CISCO_REFUSED.into());
        }
        self.installs.lock().unwrap().push((
            *id,
            String::from_utf8_lossy(profile).into_owned(),
            file_name.to_string(),
            service_existed,
        ));
        Ok(())
    }

    fn remove(&self, id: &Uuid) {
        self.removed.lock().unwrap().push(*id);
    }

    fn reconcile(&self, known: &std::collections::HashSet<Uuid>) {
        self.reconciled.lock().unwrap().push(known.clone());
    }

    fn removes_profiles(&self) -> bool {
        self.removes.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn needs_approval(&self) -> bool {
        !self.silent.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl SecretReader for MemorySecrets {
    fn get(&self, id: &Uuid, field: SecretField) -> Option<String> {
        self.0.lock().unwrap().get(&(*id, field)).cloned()
    }
}

pub struct Fixture {
    pub dir: TempDir,
    pub store: Arc<ConnectionStore>,
    pub helper: Arc<MockHelper>,
    pub native: Arc<MockNative>,
    pub secrets: Arc<MemorySecrets>,
}

impl Fixture {
    /// Fixes this thread's language (Swift `AppLanguage.override` in `setUp`).
    pub fn new(language: AppLanguage) -> Fixture {
        AppLanguage::set_thread_override(Some(language));
        let dir = TempDir::new();
        let store = Arc::new(ConnectionStore::new(dir.path().join("connections")));
        Fixture {
            dir,
            store,
            helper: Arc::new(MockHelper::default()),
            native: Arc::new(MockNative::default()),
            secrets: Arc::new(MemorySecrets::default()),
        }
    }

    pub fn deps(&self) -> Dependencies {
        Dependencies::new(self.store.clone(), self.secrets.clone(), self.helper.clone(), self.native.clone())
    }

    /// A manager after `reload()`.
    pub fn manager(&self) -> Arc<ConnectionManager> {
        self.manager_with(self.deps())
    }

    pub fn manager_with(&self, deps: Dependencies) -> Arc<ConnectionManager> {
        let m = ConnectionManager::new(deps);
        m.reload();
        m
    }

    pub fn manager_with_clock(&self, clock: Arc<ManualClock>) -> Arc<ConnectionManager> {
        let mut deps = self.deps();
        deps.clock = clock;
        self.manager_with(deps)
    }
}

pub fn clock_at(unix: f64) -> Arc<ManualClock> {
    Arc::new(ManualClock::new(Date::from_time_interval_since_1970(unix)))
}

/// Collects the manager's events.
pub fn record_events(m: &ConnectionManager) -> Arc<Mutex<Vec<ConnectionEvent>>> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    m.set_on_event(move |e| sink.lock().unwrap().push(e));
    events
}

pub fn events_of(events: &Arc<Mutex<Vec<ConnectionEvent>>>) -> Vec<ConnectionEvent> {
    events.lock().unwrap().clone()
}

pub fn failed(id: &str, name: &str, reason: &str) -> ConnectionEvent {
    ConnectionEvent::Failed { connection_id: id.to_string(), name: name.to_string(), reason: reason.to_string() }
}

pub fn dropped(id: &str, name: &str) -> ConnectionEvent {
    ConnectionEvent::Dropped { connection_id: id.to_string(), name: name.to_string() }
}

/// Runs `f` on another thread with the given language (the thread override does not cross threads).
pub fn spawn<T: Send + 'static>(
    language: AppLanguage,
    f: impl FnOnce() -> T + Send + 'static,
) -> std::thread::JoinHandle<T> {
    std::thread::spawn(move || macvpn_core::l10n::with_language(language, f))
}

pub fn sleep(seconds: f64) {
    std::thread::sleep(Duration::from_secs_f64(seconds));
}
