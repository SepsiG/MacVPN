//! The control server test harness, shared by `control_server.rs` and `control_example_client.rs`: a real Unix
//! socket in a short temp directory, a fake host whose connections follow a script, and a fake transport (the
//! peer identity is set by the test).
//!
//! Waits poll a condition with a deadline (never a fixed sleep), and the server's timings are shortened through
//! `ControlLimits`, so the tests are deterministic.
#![allow(dead_code)]

use macvpn_app_core::ConnectionItem;
use macvpn_app_core::control::{
    BoundSocket, ControlHost, ControlLimits, ControlNotifier, ControlOptions, ControlServer, ControlTransport,
    PairingAnswer, PairingRequest, PeerIdentity,
};
use macvpn_core::control::protocol::ErrorCode;
use macvpn_core::models::{AuthWait, AuthWaitKind, Connection, ConnectionState, VPNKind, uuid_string};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

pub const EXE: &str = "/Applications/Remote Desktop.app/Contents/MacOS/Remote Desktop";
pub const SYSTEM_KEY: &str = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
pub const WAIT: Duration = Duration::from_secs(5);

// MARK: - Scratch directory

/// `<temp>/mc<8 hex>`: short enough for `sun_path` (104 bytes) with `control/macvpn.sock`.
pub struct Scratch(pub PathBuf);

impl Scratch {
    pub fn new() -> Scratch {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let name = format!("mc{}", &id[..8]);
        let mut dir = std::env::temp_dir().join(&name);
        if dir.join("control/macvpn.sock").as_os_str().len() >= 104 {
            dir = Path::new("/tmp").join(&name);
        }
        std::fs::create_dir(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !f() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

// MARK: - Fake transport

pub struct FakeTransport {
    pub executable: Mutex<Option<String>>,
    pub same_user: AtomicBool,
}

impl FakeTransport {
    pub fn new() -> Arc<FakeTransport> {
        Arc::new(FakeTransport { executable: Mutex::new(Some(EXE.into())), same_user: AtomicBool::new(true) })
    }

    pub fn set_executable(&self, exe: Option<&str>) {
        *self.executable.lock().unwrap() = exe.map(str::to_string);
    }
}

impl ControlTransport for FakeTransport {
    fn bind(&self, dir: &Path) -> std::io::Result<BoundSocket> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("macvpn.sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        Ok(BoundSocket { listener, path, guard: Box::new(()) })
    }

    fn peer(&self, _stream: &UnixStream) -> std::io::Result<PeerIdentity> {
        Ok(PeerIdentity {
            uid: 501,
            same_user: self.same_user.load(Ordering::SeqCst),
            pid: 4242,
            executable: self.executable.lock().unwrap().clone(),
        })
    }

    fn random_32(&self) -> std::io::Result<[u8; 32]> {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        Ok(bytes)
    }
}

// MARK: - Fake host

#[derive(Clone)]
pub enum Step {
    State(ConnectionState),
    /// Blocks the connect until the test calls `resume`.
    Pause,
    /// The manager records a cancelled credential prompt (before it ends the connect `disconnected`).
    CredentialsCancelled,
}

#[derive(Default)]
pub struct FakeHost {
    pub items: Mutex<Vec<ConnectionItem>>,
    pub states: Mutex<HashMap<String, ConnectionState>>,
    pub scripts: Mutex<HashMap<String, VecDeque<Vec<Step>>>>,
    pub sync_errors: Mutex<HashMap<String, ErrorCode>>,
    pub calls: Mutex<Vec<String>>,
    pub notifier: Mutex<Option<ControlNotifier>>,
    /// Serializes deliveries, like the manager's listeners.
    pub publish: Mutex<()>,
    pub paused: Mutex<HashSet<String>>,
    pub resumed: Condvar,
    pub answers: Mutex<VecDeque<PairingAnswer>>,
    pub pairing_requests: Mutex<Vec<PairingRequest>>,
    /// The pairing window stays open until `release_pairing`.
    pub hold_pairing: AtomicBool,
    pub pairing_open: AtomicBool,
    pub pairing_released: Condvar,
    pub pairing_gate: Mutex<bool>,
    pub setup_missing: AtomicBool,
    /// Like the app's `AppState::setup`: `setup_ready_for` reads it.
    pub setup_lock: RwLock<()>,
    /// Runs at the start of every `setup_ready_for` (before `setup_lock` is read).
    pub setup_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    pub logs: Mutex<Vec<String>>,
    pub asks: AtomicUsize,
    /// Pairing windows that returned their answer.
    pub answered: AtomicUsize,
    pub epochs: Mutex<HashMap<String, u64>>,
    pub connects_done: AtomicUsize,
    pub credentials_cancelled: Mutex<HashSet<String>>,
}

pub fn managed(name: &str) -> (String, ConnectionItem) {
    let c = Connection::new(name, VPNKind::Openvpn);
    (uuid_string(&c.id), ConnectionItem::Managed(c))
}

impl FakeHost {
    pub fn add(&self, item: ConnectionItem) -> String {
        let key = item.id();
        self.items.lock().unwrap().push(item);
        key
    }

    /// Changes a state the way the manager does: set, then tell the listeners.
    pub fn set(&self, key: &str, state: ConnectionState) {
        let _order = self.publish.lock().unwrap();
        self.states.lock().unwrap().insert(key.to_string(), state.clone());
        let notifier = self.notifier.lock().unwrap().clone();
        if let Some(n) = notifier {
            n.state_changed(key, &state);
        }
    }

    /// The steps of the next connect of `key` (default: connecting, connected).
    pub fn script(&self, key: &str, steps: Vec<Step>) {
        self.scripts.lock().unwrap().entry(key.to_string()).or_default().push_back(steps);
    }

    pub fn resume(&self, key: &str) {
        self.paused.lock().unwrap().remove(key);
        self.resumed.notify_all();
    }

    pub fn is_paused(&self, key: &str) -> bool {
        self.paused.lock().unwrap().contains(key)
    }

    /// The user disconnects in the menu: the user listener first, then the disconnect path.
    pub fn user_disconnect(&self, key: &str) {
        let notifier = self.notifier.lock().unwrap().clone();
        if let Some(n) = notifier {
            n.user_disconnected(key);
        }
        self.set(key, ConnectionState::Disconnecting);
        self.set(key, ConnectionState::Disconnected);
    }

    pub fn epoch(&self, key: &str) -> u64 {
        self.epochs.lock().unwrap().get(key).copied().unwrap_or(0)
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    pub fn count(&self, call: &str) -> usize {
        self.calls().iter().filter(|c| *c == call).count()
    }

    pub fn logs(&self) -> Vec<String> {
        self.logs.lock().unwrap().clone()
    }

    pub fn release_pairing(&self) {
        *self.pairing_gate.lock().unwrap() = true;
        self.pairing_released.notify_all();
    }
}

impl ControlHost for FakeHost {
    fn items(&self) -> Vec<ConnectionItem> {
        self.items.lock().unwrap().clone()
    }

    fn state(&self, key: &str) -> ConnectionState {
        self.states.lock().unwrap().get(key).cloned().unwrap_or(ConnectionState::Disconnected)
    }

    fn connect(&self, key: &str) -> Result<(), ErrorCode> {
        self.calls.lock().unwrap().push(format!("connect {key}"));
        if let Some(code) = self.sync_errors.lock().unwrap().remove(key) {
            return Err(code);
        }
        let steps = self.scripts.lock().unwrap().get_mut(key).and_then(VecDeque::pop_front).unwrap_or_else(|| {
            vec![
                Step::State(ConnectionState::Connecting),
                Step::State(ConnectionState::Connected { ip: None, since: None }),
            ]
        });
        // Like the manager's operation token: taken when the connect first changes the state; a disconnect after
        // that ends this connect (a disconnect before it does not).
        let mut token = None;
        self.credentials_cancelled.lock().unwrap().remove(key);
        for step in steps {
            match step {
                Step::State(state) => {
                    let epoch = self.epoch(key);
                    if *token.get_or_insert(epoch) != epoch {
                        break;
                    }
                    self.set(key, state);
                }
                Step::CredentialsCancelled => {
                    self.credentials_cancelled.lock().unwrap().insert(key.to_string());
                }
                Step::Pause => {
                    let mut paused = self.paused.lock().unwrap();
                    paused.insert(key.to_string());
                    while paused.contains(key) {
                        paused = self.resumed.wait(paused).unwrap();
                    }
                }
            }
        }
        self.connects_done.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn disconnect(&self, key: &str) {
        self.calls.lock().unwrap().push(format!("disconnect {key}"));
        *self.epochs.lock().unwrap().entry(key.to_string()).or_default() += 1;
        self.set(key, ConnectionState::Disconnecting);
        self.set(key, ConnectionState::Disconnected);
    }

    /// `setup_missing`: Homebrew and the root layer are missing. Like the app's host, only a managed connection
    /// run by the root layer needs them; a system VPN and a native (L2TP / Cisco) connection do not.
    fn setup_ready_for(&self, key: &str) -> bool {
        let hook = self.setup_hook.lock().unwrap().clone();
        if let Some(hook) = hook {
            hook();
        }
        let _setup = self.setup_lock.read().unwrap();
        let needs_setup = self
            .items
            .lock()
            .unwrap()
            .iter()
            .any(|item| item.id() == key && matches!(item, ConnectionItem::Managed(c) if !c.kind.is_native()));
        !(needs_setup && self.setup_missing.load(Ordering::SeqCst))
    }

    fn ask_pairing(&self, request: PairingRequest) -> PairingAnswer {
        self.asks.fetch_add(1, Ordering::SeqCst);
        self.pairing_requests.lock().unwrap().push(request);
        if self.hold_pairing.load(Ordering::SeqCst) {
            self.pairing_open.store(true, Ordering::SeqCst);
            let mut released = self.pairing_gate.lock().unwrap();
            while !*released {
                released = self.pairing_released.wait(released).unwrap();
            }
        }
        let answer = self.answers.lock().unwrap().pop_front().unwrap_or(PairingAnswer::Denied);
        self.answered.fetch_add(1, Ordering::SeqCst);
        answer
    }

    fn log(&self, line: String) {
        self.logs.lock().unwrap().push(line);
    }

    fn credentials_cancelled(&self, key: &str) -> bool {
        self.credentials_cancelled.lock().unwrap().contains(key)
    }
}

// MARK: - Harness

pub struct Harness {
    pub dir: Scratch,
    pub host: Arc<FakeHost>,
    pub transport: Arc<FakeTransport>,
    pub server: Option<ControlServer>,
}

pub fn fast_limits() -> ControlLimits {
    ControlLimits {
        auth_timeout: Duration::from_millis(300),
        hello_failure_delay: Duration::from_millis(50),
        stop_timeout: Duration::from_secs(5),
        ..ControlLimits::default()
    }
}

impl Harness {
    pub fn new() -> Harness {
        Harness::with_limits(fast_limits())
    }

    pub fn with_limits(limits: ControlLimits) -> Harness {
        let dir = Scratch::new();
        let host = Arc::new(FakeHost::default());
        let transport = FakeTransport::new();
        let mut h = Harness { dir, host, transport, server: None };
        h.start(limits);
        h
    }

    pub fn options(&self, limits: ControlLimits) -> ControlOptions {
        let mut options = ControlOptions::new(self.dir.0.join("control"), self.dir.0.clone());
        options.limits = limits;
        options
    }

    pub fn start(&mut self, limits: ControlLimits) {
        let server = ControlServer::start(self.options(limits), self.host.clone(), self.transport.clone()).unwrap();
        *self.host.notifier.lock().unwrap() = Some(server.notifier());
        self.server = Some(server);
    }

    pub fn server(&self) -> &ControlServer {
        self.server.as_ref().unwrap()
    }

    pub fn socket(&self) -> PathBuf {
        self.dir.0.join("control/macvpn.sock")
    }

    pub fn connect(&self) -> TestClient {
        TestClient::connect(&self.socket())
    }

    /// Pairs a client allowed to use `keys`; returns its token.
    pub fn pair(&self, keys: &[&str]) -> String {
        self.host
            .answers
            .lock()
            .unwrap()
            .push_back(PairingAnswer::Approved(keys.iter().map(|k| k.to_string()).collect()));
        let mut c = self.connect();
        c.send(json!({"op":"pair","name":"Remote Desktop"}));
        let reply = c.read();
        assert_eq!(reply["ok"], true, "{reply}");
        c.expect_closed();
        reply["token"].as_str().unwrap().to_string()
    }

    /// A paired and authenticated client.
    pub fn authed(&self, keys: &[&str]) -> TestClient {
        let token = self.pair(keys);
        self.hello(&token)
    }

    pub fn hello(&self, token: &str) -> TestClient {
        let mut c = self.connect();
        c.send(json!({"op":"hello","token":token}));
        let reply = c.read();
        assert_eq!(reply, json!({"ok":true,"api":1}));
        c
    }
}

pub struct TestClient {
    pub stream: UnixStream,
    pub reader: BufReader<UnixStream>,
}

impl TestClient {
    pub fn connect(path: &Path) -> TestClient {
        let stream = UnixStream::connect(path).unwrap();
        // macOS refuses socket options (EINVAL) once the server has closed the connection (a refused client):
        // reads then end at once anyway.
        if let Err(e) = stream.set_read_timeout(Some(WAIT)) {
            assert_eq!(e.raw_os_error(), Some(22), "{e}");
        }
        let reader = BufReader::new(stream.try_clone().unwrap());
        TestClient { stream, reader }
    }

    pub fn send(&mut self, value: Value) {
        self.send_raw(&format!("{value}\n"));
    }

    pub fn send_raw(&mut self, line: &str) {
        let _ = self.stream.write_all(line.as_bytes());
    }

    pub fn read(&mut self) -> Value {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).expect("a line before the timeout");
        assert!(n > 0, "the server closed the connection");
        serde_json::from_str(&line).unwrap()
    }

    /// Reads until the reply with this `id`, returning the events before it too.
    pub fn reply_to(&mut self, id: u64) -> (Vec<Value>, Value) {
        let mut events = Vec::new();
        loop {
            let v = self.read();
            if v.get("id") == Some(&json!(id)) {
                return (events, v);
            }
            events.push(v);
        }
    }

    pub fn expect_closed(&mut self) {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => {}
            Err(e) if e.kind() == ErrorKind::ConnectionReset => {}
            other => panic!("expected the connection to close, got {other:?} {line:?}"),
        }
    }

    pub fn close(self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

pub fn states(events: &[Value]) -> Vec<&str> {
    events.iter().map(|e| e["state"].as_str().unwrap()).collect()
}

pub fn connected() -> ConnectionState {
    ConnectionState::Connected { ip: None, since: None }
}

pub fn awaiting() -> ConnectionState {
    ConnectionState::AwaitingAuth(AuthWait { kind: AuthWaitKind::Code, deadline: None })
}

pub fn awaiting_credentials() -> ConnectionState {
    ConnectionState::AwaitingAuth(AuthWait { kind: AuthWaitKind::Credentials, deadline: None })
}

impl TestClient {
    /// No extra line is waiting (checked with a short timeout); `key` only names what was not expected.
    pub fn read_nothing_pending(&mut self, key: &str) -> bool {
        self.stream.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut line = String::new();
        let got = matches!(self.reader.read_line(&mut line), Ok(n) if n > 0);
        self.stream.set_read_timeout(Some(WAIT)).unwrap();
        assert!(!line.contains(key), "{line}");
        got
    }
}
