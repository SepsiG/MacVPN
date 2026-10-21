//! The control server test harness, shared by `control_server.rs` and `control_example_client.rs`: a real Unix
//! socket in a short temp directory (or TCP on the loopback address, which runs on every OS), a fake host whose
//! connections follow a script, and a fake transport (the peer identity is set by the test).
//!
//! Waits poll a condition with a deadline (never a fixed sleep), and the server's timings are shortened through
//! `ControlLimits`, so the tests are deterministic.
#![allow(dead_code)]

use macvpn_app_core::ConnectionItem;
use macvpn_app_core::control::{
    Accepted, BoundEndpoint, ControlHost, ControlLimits, ControlListener, ControlNotifier, ControlOptions,
    ControlServer, ControlStream, ControlTransport, PairingAnswer, PairingRequest, PeerIdentity, PeerUser,
};
use macvpn_core::control::protocol::ErrorCode;
use macvpn_core::models::{AuthWait, AuthWaitKind, Connection, ConnectionState, VPNKind, uuid_string};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
#[cfg(unix)]
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

// MARK: - Fake transports

/// Which test transport a harness runs over. The server suite runs over both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A real Unix socket at `control/macvpn.sock` (Unix only).
    Unix,
    /// TCP on `127.0.0.1` (every OS). The peer is always `uid 0`; its address is written to
    /// `control/macvpn.sock`, a plain file, which is the endpoint's `socket_file`.
    Loopback,
}

/// The peer identity the test sets (shared with the bound listener, so a change applies to the next accept).
pub struct FakePeer {
    pub executable: Mutex<Option<String>>,
    pub same_user: AtomicBool,
}

impl FakePeer {
    fn identity(&self, uid: u32) -> PeerIdentity {
        PeerIdentity {
            user: PeerUser::Uid(uid),
            same_user: self.same_user.load(Ordering::SeqCst),
            pid: 4242,
            executable: self.executable.lock().unwrap().clone(),
        }
    }
}

/// The test transport: a real stream of `kind`; the peer identity is set by the test.
pub struct FakeTransport {
    pub kind: Kind,
    pub peer: Arc<FakePeer>,
    /// Loopback: report the address file as the endpoint's `socket_file` (otherwise `None`).
    pub socket_file: AtomicBool,
    /// Loopback: the address of the last bind.
    pub addr: Mutex<Option<SocketAddr>>,
}

impl FakeTransport {
    #[cfg(unix)]
    pub fn new() -> Arc<FakeTransport> {
        FakeTransport::over(Kind::Unix)
    }

    pub fn over(kind: Kind) -> Arc<FakeTransport> {
        Arc::new(FakeTransport {
            kind,
            peer: Arc::new(FakePeer { executable: Mutex::new(Some(EXE.into())), same_user: AtomicBool::new(true) }),
            socket_file: AtomicBool::new(true),
            addr: Mutex::new(None),
        })
    }

    pub fn set_executable(&self, exe: Option<&str>) {
        *self.peer.executable.lock().unwrap() = exe.map(str::to_string);
    }

    fn uid(&self) -> u32 {
        if self.kind == Kind::Unix { 501 } else { 0 }
    }
}

/// The log line's user part for this transport's peer.
pub fn peer_user(kind: Kind) -> &'static str {
    if kind == Kind::Unix { "uid 501" } else { "uid 0" }
}

impl ControlTransport for FakeTransport {
    fn bind(&self, dir: &Path) -> io::Result<BoundEndpoint> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("macvpn.sock");
        let _ = std::fs::remove_file(&path);
        let (peer, uid) = (self.peer.clone(), self.uid());
        match self.kind {
            #[cfg(unix)]
            Kind::Unix => {
                let listener = UnixListener::bind(&path)?;
                listener.set_nonblocking(true)?;
                Ok(BoundEndpoint {
                    listener: Box::new(UnixTestListener { listener, peer, uid }),
                    display: path.display().to_string(),
                    socket_file: Some(path),
                    guard: Box::new(()),
                })
            }
            #[cfg(not(unix))]
            Kind::Unix => Err(io::Error::from(ErrorKind::Unsupported)),
            Kind::Loopback => {
                let listener = TcpListener::bind("127.0.0.1:0")?;
                listener.set_nonblocking(true)?;
                let addr = listener.local_addr()?;
                *self.addr.lock().unwrap() = Some(addr);
                let socket_file = if self.socket_file.load(Ordering::SeqCst) {
                    std::fs::write(&path, addr.to_string())?;
                    Some(path)
                } else {
                    None
                };
                Ok(BoundEndpoint {
                    listener: Box::new(LoopbackListener { listener, peer, uid }),
                    display: addr.to_string(),
                    socket_file,
                    guard: Box::new(()),
                })
            }
        }
    }

    fn random_32(&self) -> io::Result<[u8; 32]> {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        Ok(bytes)
    }

    /// EINVAL / ENOTCONN / ECONNRESET, as the macOS transport.
    fn is_already_closed(&self, e: &io::Error) -> bool {
        matches!(e.kind(), ErrorKind::InvalidInput | ErrorKind::NotConnected | ErrorKind::ConnectionReset)
    }

    /// Deliberately core's `fsx::ensure_private_dir` alone (no owner check): the test directories are this user's
    /// own temp folders, and the platforms' owner checks have their own tests.
    fn prepare_dir(&self, dir: &Path) -> io::Result<()> {
        macvpn_core::fsx::ensure_private_dir(dir).map(|_| ())
    }
}

/// The non-blocking accept of both listeners, as the macOS transport does it.
macro_rules! accept_with {
    ($self:ident, $poll:ident, $wrap:ident) => {{
        let stream = match $self.listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep($poll);
                return Ok(Accepted::Idle);
            }
            Err(e) => return Err(e),
        };
        if stream.set_nonblocking(false).is_err() {
            return Ok(Accepted::Idle);
        }
        Ok(Accepted::Client { stream: Box::new($wrap(stream)), peer: Ok($self.peer.identity($self.uid)) })
    }};
}

/// The one-byte peek of the macOS transport, for both test streams.
macro_rules! peek_connected {
    ($stream:expr) => {{
        let stream = $stream;
        if stream.set_nonblocking(true).is_err() {
            return false;
        }
        let mut byte = [0u8; 1];
        let alive = match (&*stream).read(&mut byte) {
            Ok(0) => false,
            Ok(_) => true,
            Err(e) => e.kind() == ErrorKind::WouldBlock,
        };
        stream.set_nonblocking(false).is_ok() && alive
    }};
}

macro_rules! control_stream {
    ($wrap:ident, $inner:ty) => {
        pub struct $wrap(pub $inner);

        impl Read for $wrap {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.0.read(buf)
            }
        }

        impl Write for $wrap {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.write(buf)
            }

            fn flush(&mut self) -> io::Result<()> {
                self.0.flush()
            }
        }

        impl ControlStream for $wrap {
            fn try_clone(&self) -> io::Result<Box<dyn ControlStream>> {
                Ok(Box::new($wrap(self.0.try_clone()?)))
            }

            fn shutdown(&self, how: Shutdown) -> io::Result<()> {
                self.0.shutdown(how)
            }

            fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
                self.0.set_read_timeout(timeout)
            }

            fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
                self.0.set_write_timeout(timeout)
            }

            fn peer_connected(&self) -> bool {
                peek_connected!(&self.0)
            }
        }
    };
}

#[cfg(unix)]
control_stream!(UnixTestStream, UnixStream);
control_stream!(LoopbackStream, TcpStream);

#[cfg(unix)]
pub struct UnixTestListener {
    listener: UnixListener,
    peer: Arc<FakePeer>,
    uid: u32,
}

#[cfg(unix)]
impl ControlListener for UnixTestListener {
    fn accept(&self, poll: Duration) -> io::Result<Accepted> {
        accept_with!(self, poll, UnixTestStream)
    }
}

pub struct LoopbackListener {
    listener: TcpListener,
    peer: Arc<FakePeer>,
    uid: u32,
}

impl ControlListener for LoopbackListener {
    fn accept(&self, poll: Duration) -> io::Result<Accepted> {
        accept_with!(self, poll, LoopbackStream)
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
    /// The vault is locked (`ControlHost::locked`).
    pub locked: AtomicBool,
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

    fn locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
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
    /// Over the Unix socket.
    #[cfg(unix)]
    pub fn new() -> Harness {
        Harness::over(Kind::Unix)
    }

    #[cfg(unix)]
    pub fn with_limits(limits: ControlLimits) -> Harness {
        Harness::over_with_limits(Kind::Unix, limits)
    }

    pub fn over(kind: Kind) -> Harness {
        Harness::over_with_limits(kind, fast_limits())
    }

    pub fn over_with_limits(kind: Kind, limits: ControlLimits) -> Harness {
        let dir = Scratch::new();
        let host = Arc::new(FakeHost::default());
        let transport = FakeTransport::over(kind);
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

    /// The endpoint's `socket_file` (Unix: the socket; loopback: the address file).
    pub fn socket(&self) -> PathBuf {
        self.dir.0.join("control/macvpn.sock")
    }

    /// A raw connection to the current endpoint.
    pub fn try_connect(&self) -> io::Result<TestStream> {
        match self.transport.kind {
            #[cfg(unix)]
            Kind::Unix => UnixStream::connect(self.socket()).map(TestStream::Unix),
            #[cfg(not(unix))]
            Kind::Unix => Err(io::Error::from(ErrorKind::Unsupported)),
            Kind::Loopback => {
                let addr = self.transport.addr.lock().unwrap().expect("bound");
                TcpStream::connect(addr).map(TestStream::Tcp)
            }
        }
    }

    pub fn connect(&self) -> TestClient {
        TestClient::over(self.try_connect().unwrap())
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

/// The test client's end of either transport.
pub enum TestStream {
    #[cfg(unix)]
    Unix(UnixStream),
    Tcp(TcpStream),
}

impl TestStream {
    pub fn try_clone(&self) -> io::Result<TestStream> {
        match self {
            #[cfg(unix)]
            TestStream::Unix(s) => s.try_clone().map(TestStream::Unix),
            TestStream::Tcp(s) => s.try_clone().map(TestStream::Tcp),
        }
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            TestStream::Unix(s) => s.shutdown(how),
            TestStream::Tcp(s) => s.shutdown(how),
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            TestStream::Unix(s) => s.set_read_timeout(timeout),
            TestStream::Tcp(s) => s.set_read_timeout(timeout),
        }
    }
}

impl Read for TestStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            TestStream::Unix(s) => s.read(buf),
            TestStream::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for TestStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            TestStream::Unix(s) => s.write(buf),
            TestStream::Tcp(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            TestStream::Unix(s) => s.flush(),
            TestStream::Tcp(s) => s.flush(),
        }
    }
}

pub struct TestClient {
    pub stream: TestStream,
    pub reader: BufReader<TestStream>,
}

impl TestClient {
    #[cfg(unix)]
    pub fn connect(path: &Path) -> TestClient {
        TestClient::over(TestStream::Unix(UnixStream::connect(path).unwrap()))
    }

    pub fn over(stream: TestStream) -> TestClient {
        // macOS refuses socket options (EINVAL) once the server has closed the connection (a refused client):
        // reads then end at once anyway.
        if let Err(e) = stream.set_read_timeout(Some(WAIT)) {
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{e}");
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
            // A close with unread data resets the connection; Windows reports it as aborted (WSAECONNABORTED).
            Err(e) if matches!(e.kind(), ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted) => {}
            other => panic!("expected the connection to close, got {other:?} {line:?}"),
        }
    }

    pub fn close(self) {
        let _ = self.stream.shutdown(Shutdown::Both);
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
