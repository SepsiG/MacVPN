//! The OpenVPN engine of the WinVPN Service (the macOS `openvpn::up` + `wait_connected` + `down`, in process):
//! before every start `openvpn.exe`'s trust ([`super::detect`]); the driver from the validated config (DCO or
//! TAP-Windows6; one TAP-Windows6 retry after a DCO incompatibility); a private run directory (`config.ovpn`,
//! `mgmt.pw`, `askpass`; created new with the data directory's protection, removed on down); `openvpn.exe` as
//! SYSTEM with the fixed argv of `ovpn_args` and a cleared environment, in the service's kill-on-close job; its
//! output through `log_safe` into the connection log (masked by the sink); the loopback management interface with
//! a random password on a port outside Windows' dynamic port range (started again on another port, at most twice,
//! when OpenVPN could not bind it or another process answered it), used only once its accepting socket is shown to
//! be this child's; the shared bridge on a thread (MFA through `auth-state` / `respond`), one management command at
//! a time; the macOS wait rules and messages.

use super::data_dir::DataDir;
use super::detect::Ready;
use super::mgmt;
use super::service_log::ServiceLog;
use crate::shared::bridge::{Bridge, BridgeArgs};
use crate::shared::l10n::tr;
use crate::shared::mask::{MAX_LINE, Masker};
use crate::windows::bridge_state::{BridgeState, ByteCounter, InProcessFiles, OneCommandAtATime, StateWatch};
use crate::windows::ovpn_args::{self, Driver};
use crate::windows::ovpn_run::{self, Failure, Output, Snapshot, Verdict, Wait};
use crate::windows::service::{Engine, EngineState, LogSink, UpRequest};
use macvpn_core::management::ManagementCredentials;
use std::collections::HashMap;
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// `CREATE_NO_WINDOW` (winbase.h): no console window for the child.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// How long the management interface may take to come up.
const MGMT_CONNECT: Duration = Duration::from_secs(10);
/// How long a stopping `openvpn.exe` may take after `signal SIGTERM` (it restores routes and DNS) before it is
/// terminated, and after that.
const GRACE: Duration = Duration::from_secs(5);
const KILL_WAIT: Duration = Duration::from_secs(5);
/// The look interval of the wait loop.
const TICK: Duration = Duration::from_millis(200);
/// The management ports: below Windows' default dynamic (ephemeral) range 49152–65535, so no connecting socket of
/// any process is given one of them by chance (an outgoing connection's port would make OpenVPN's bind fail; the
/// service's own connect to a port nobody listens on yet could reach itself). Above the common fixed ports.
const MGMT_PORTS: std::ops::RangeInclusive<u16> = 30000..=48999;
/// How many times `openvpn.exe` is started again on another management port.
const PORT_RETRIES: usize = 2;

/// Finds the `openvpn.exe` to run (production: [`super::detect::ready`]).
pub type Detector = Box<dyn Fn() -> Result<Ready, String> + Send + Sync>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The started `openvpn.exe`.
struct Proc {
    child: Mutex<Child>,
    /// A second handle on the management connection, for `signal SIGTERM` (the bridge holds the first).
    control: Mutex<Option<TcpStream>>,
    /// `signal SIGTERM` was sent: a second, concurrent stop (a `down` while the bridge stops it) waits out the same
    /// grace period instead of terminating OpenVPN before it has taken its routes and DNS back.
    signalled: AtomicBool,
}

impl Proc {
    fn exited(&self) -> bool {
        !matches!(lock(&self.child).try_wait(), Ok(None))
    }

    fn wait_exit(&self, limit: Duration) -> bool {
        let until = Instant::now() + limit;
        loop {
            if self.exited() {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Asks OpenVPN to stop (it takes its routes and DNS back), then terminates it. `true`: it has exited.
    fn stop(&self) -> bool {
        if self.exited() {
            return true;
        }
        let control = lock(&self.control).take();
        let signalled = match control {
            Some(mut c) => {
                let sent = c.write_all(b"signal SIGTERM\n").is_ok();
                self.signalled.store(sent, Ordering::SeqCst);
                sent
            }
            None => self.signalled.load(Ordering::SeqCst),
        };
        if signalled && self.wait_exit(GRACE) {
            return true;
        }
        let _ = lock(&self.child).kill();
        self.wait_exit(KILL_WAIT)
    }
}

/// One attempt of one connection.
struct Run {
    proc: Arc<Proc>,
    /// `down` took it: the readers stop writing to its log.
    closed: Arc<AtomicBool>,
    out: Arc<Mutex<Output>>,
    /// How many of the two output readers have reached the end.
    readers_done: Arc<AtomicUsize>,
    bridge: Arc<BridgeState>,
    ip: Arc<Mutex<Option<String>>>,
    /// OpenVPN's latest `>BYTECOUNT` (received, sent) of this process.
    bytes: Arc<Mutex<Option<(u64, u64)>>>,
    since: u64,
}

impl Run {
    /// Gives the readers up to a second to reach the end of the output (once the process has exited).
    fn drain_output(&self) {
        let until = Instant::now() + Duration::from_secs(1);
        while self.readers_done.load(Ordering::SeqCst) < 2 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Why an attempt ended without a connection.
enum Attempt {
    Failed(Failure),
    /// Before `openvpn.exe` ran, or a broken management connection: the localized message.
    Setup(String),
    /// The management port was not this `openvpn.exe`'s (its bind failed, or another process answered there): it
    /// was stopped; another port may work. The message if none does.
    PortTaken(String),
}

pub struct OpenVpnEngine {
    data: Arc<DataDir>,
    log: ServiceLog,
    detect: Detector,
    runs: Mutex<HashMap<String, Arc<Run>>>,
}

impl OpenVpnEngine {
    pub fn new(data: Arc<DataDir>, log: ServiceLog) -> OpenVpnEngine {
        OpenVpnEngine::with_detector(data, log, Box::new(super::detect::ready))
    }

    /// With another detector (the debug console's fake `openvpn.exe`).
    pub fn with_detector(data: Arc<DataDir>, log: ServiceLog, detect: Detector) -> OpenVpnEngine {
        OpenVpnEngine { data, log, detect, runs: Mutex::default() }
    }

    fn run_of(&self, id: &str) -> Option<Arc<Run>> {
        lock(&self.runs).get(id).cloned()
    }

    /// Forgets `run` if it is still `id`'s current one (`false`: a `down` took it meanwhile), stops it and removes
    /// the run directory.
    fn discard(&self, id: &str, run: &Arc<Run>) -> bool {
        let ours = {
            let mut runs = lock(&self.runs);
            let ours = runs.get(id).is_some_and(|r| Arc::ptr_eq(r, run));
            if ours {
                runs.remove(id);
            }
            ours
        };
        if ours {
            run.closed.store(true, Ordering::SeqCst);
            if !run.proc.stop() {
                self.log.line(&format!("openvpn {id}: did not stop"));
            }
            self.remove_dir(id);
        }
        ours
    }

    fn remove_dir(&self, id: &str) {
        if let Err(e) = self.data.remove_run_dir(id) {
            self.log.line(&format!("openvpn {id}: run directory not removed: {:?}", e.kind()));
        }
    }

    /// One start of `openvpn.exe` with `driver`, up to connected or a failure (then nothing of it runs).
    fn attempt(&self, req: &UpRequest<'_>, exe: &Path, driver: Driver) -> Result<(), Attempt> {
        let id = req.id;
        let setup = |what: &str, e: std::io::Error| {
            self.log.line(&format!("openvpn {id}: {what}: {:?}", e.kind()));
        };
        let dir = self.data.make_run_dir(id).map_err(|e| {
            setup("run directory", e);
            Attempt::Setup(tr("Cannot create: %@", &[&self.data.run.join(id).display().to_string()]))
        })?;
        let fail = |message: String| {
            self.remove_dir(id);
            Err(Attempt::Setup(message))
        };
        // The management password: 32 random bytes as 64 hex digits, only in memory and in the private run dir.
        let password = match management_password() {
            Ok(p) => p,
            Err(e) => {
                setup("random", e);
                return fail(tr("The management connection to OpenVPN failed", &[]));
            }
        };
        let mut pw_file = Zeroizing::new(password.to_vec());
        pw_file.push(b'\n');
        let mut files: Vec<(&str, Zeroizing<Vec<u8>>)> =
            vec![("config.ovpn", Zeroizing::new(req.config.to_vec())), ("mgmt.pw", pw_file)];
        let keypass = !req.secrets.keypass.is_empty();
        if keypass {
            let mut k = Zeroizing::new(req.secrets.keypass.to_vec());
            k.push(b'\n');
            files.push(("askpass", k));
        }
        for (name, bytes) in &files {
            if let Err(e) = self.data.write_private(&dir.join(name), bytes) {
                setup("run file", e);
                return fail(tr("Cannot create: %@", &[&dir.join(name).display().to_string()]));
            }
        }
        drop(files);
        let Some(port) = free_port() else {
            return fail(tr("The management connection to OpenVPN failed", &[]));
        };
        let user_pass = !req.secrets.user.is_empty() || !req.secrets.pass.is_empty();
        let argv = ovpn_args::argv(&dir, port, driver, req.debug, user_pass, keypass);
        let mut child = match start(exe, &argv, &dir) {
            Ok(c) => c,
            Err(e) => {
                setup("start", e);
                return fail(tr("openvpn.exe could not be started", &[]));
            }
        };
        let pid = child.id();
        let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
        let proc =
            Arc::new(Proc { child: Mutex::new(child), control: Mutex::new(None), signalled: AtomicBool::new(false) });
        let sink: Arc<dyn LogSink> = req.log.clone();
        let stopper = proc.clone();
        let bridge_log = sink.clone();
        let bridge = Arc::new(BridgeState::new(
            Box::new(move |line| bridge_log.line(&format!("[mgmt] {line}"))),
            Box::new(move || {
                let _ = stopper.stop();
            }),
        ));
        let run = Arc::new(Run {
            proc: proc.clone(),
            closed: Arc::new(AtomicBool::new(false)),
            out: Arc::new(Mutex::new(Output::new(req.secrets.masker()))),
            readers_done: Arc::new(AtomicUsize::new(0)),
            bridge: bridge.clone(),
            ip: Arc::new(Mutex::new(None)),
            bytes: Arc::new(Mutex::new(None)),
            since: unix_now(),
        });
        // Registered before anything waits: a `down` from now on stops this attempt.
        lock(&self.runs).insert(id.to_string(), run.clone());
        for pipe in [stdout.map(|s| Box::new(s) as Box<dyn std::io::Read + Send>), stderr.map(|s| Box::new(s) as _)] {
            spawn_reader(pipe, &run, sink.clone());
        }
        let deadline = Instant::now() + MGMT_CONNECT;
        let gone = || proc.exited();
        let stream = match mgmt::connect(port, pid, &password, deadline, &gone) {
            Ok(s) => s,
            Err(e) => {
                let squatted = e.kind() == std::io::ErrorKind::AddrInUse && e.to_string() == mgmt::NOT_OPENVPNS;
                setup("management", e);
                // OpenVPN ended before its management interface came up: its last line says why (as on macOS).
                let exited = proc.exited();
                if exited {
                    run.drain_output();
                }
                let (failure, bind_failed) = {
                    let out = lock(&run.out);
                    (exited.then(|| Failure::Exited(out.last_line())), exited && out.mgmt_bind_failed)
                };
                let message = || tr("The management connection to OpenVPN failed", &[]);
                return Err(match (self.discard(id, &run), failure) {
                    (true, Some(f)) if bind_failed => Attempt::PortTaken(f.message()),
                    (true, None) if squatted => Attempt::PortTaken(message()),
                    (true, Some(f)) => Attempt::Failed(f),
                    (true, None) => Attempt::Setup(message()),
                    (false, _) => Attempt::Setup(self.cancelled_message(&run)),
                });
            }
        };
        *lock(&proc.control) = stream.try_clone().ok();
        let creds = credentials(req);
        let args = BridgeArgs::in_process(id, ovpn_run::MFA_MAX_SECS as f64).expect("a canonical ID");
        let (files, ip) = (InProcessFiles::new(bridge.clone()), run.ip.clone());
        // One command in flight at a time: OpenVPN on Windows can drop a command sent while it answers the last one.
        // Its byte counters for `traffic` (asked once OpenVPN reports a state).
        let stream = StateWatch::new(ByteCounter::new(OneCommandAtATime::new(stream), run.bytes.clone()), ip);
        std::thread::spawn(move || Bridge::new(args, stream, files, creds).run());
        self.wait(id, &run, driver)
    }

    fn cancelled_message(&self, run: &Run) -> String {
        Failure::Exited(lock(&run.out).last_line()).message()
    }

    /// The macOS wait loop over this attempt.
    fn wait(&self, id: &str, run: &Arc<Run>, driver: Driver) -> Result<(), Attempt> {
        let mut wait = Wait::new(run.since, driver);
        loop {
            std::thread::sleep(TICK);
            // An exit counts once its output has been read (its last lines decide the verdict).
            let exited = run.proc.exited();
            if exited {
                run.drain_output();
            }
            let status = run.bridge.mgmt_status();
            let verdict = {
                let out = lock(&run.out);
                let last = out.last_line();
                wait.step(
                    unix_now(),
                    &Snapshot {
                        done: out.done,
                        auth_failed: out.auth_failed,
                        dco_incompatible: out.dco_incompatible,
                        exited,
                        last_line: &last,
                        mgmt_status: status.as_deref(),
                    },
                )
            };
            match verdict {
                None => continue,
                Some(Verdict::Connected) => {
                    // A `down` while it connected wins (the service then reports it).
                    return if self.run_of(id).is_some_and(|r| Arc::ptr_eq(&r, run)) {
                        Ok(())
                    } else {
                        Err(Attempt::Setup(self.cancelled_message(run)))
                    };
                }
                Some(Verdict::Failed(f)) => {
                    if !self.discard(id, run) {
                        // Taken down meanwhile: never retried.
                        return Err(Attempt::Setup(f.message()));
                    }
                    return Err(Attempt::Failed(f));
                }
            }
        }
    }
}

/// 32 random bytes as 64 lowercase hex digits.
fn management_password() -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut raw = Zeroizing::new([0u8; 32]);
    macvpn_winsys::random::fill(&mut raw[..])?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Zeroizing::new(Vec::with_capacity(64));
    for b in raw.iter() {
        out.push(HEX[usize::from(b >> 4)]);
        out.push(HEX[usize::from(b & 15)]);
    }
    Ok(out)
}

/// A random port of [`MGMT_PORTS`] that is free on 127.0.0.1 right now (up to 8 tries: a port of a range Windows
/// excludes, as Hyper-V's, does not bind either).
fn free_port() -> Option<u16> {
    let span = MGMT_PORTS.end() - MGMT_PORTS.start() + 1;
    for _ in 0..8 {
        let mut b = [0u8; 2];
        macvpn_winsys::random::fill(&mut b).ok()?;
        let port = MGMT_PORTS.start() + u16::from_le_bytes(b) % span;
        if TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok() {
            return Some(port);
        }
    }
    None
}

/// `openvpn.exe` by its absolute path, the argv from `ovpn_args`, the run directory as working directory, an
/// environment of only the Windows folders (from Windows, not from the service's environment), no window. It
/// inherits the service's job.
fn start(exe: &Path, argv: &[std::ffi::OsString], dir: &Path) -> std::io::Result<Child> {
    let windows = super::detect::windows_dir()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no Windows folder"))?;
    let drive: String = windows.to_string_lossy().chars().take(2).collect();
    Command::new(exe)
        .args(argv)
        .current_dir(dir)
        .env_clear()
        .env("SystemRoot", &windows)
        .env("windir", &windows)
        .env("SystemDrive", drive)
        .env("TEMP", dir)
        .env("TMP", dir)
        .env("PATH", windows.join("System32"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
}

/// One output pipe: every line judged by [`Output`] and, if it may, written to the connection log (until `down`).
fn spawn_reader(pipe: Option<Box<dyn std::io::Read + Send>>, run: &Arc<Run>, sink: Arc<dyn LogSink>) {
    let (out, closed, done) = (run.out.clone(), run.closed.clone(), run.readers_done.clone());
    std::thread::spawn(move || {
        if let Some(pipe) = pipe {
            // No masking here (the sink masks); only the line splitting with its length cap.
            Masker::default().stream_lines(pipe, MAX_LINE, |line| {
                let line = line.strip_suffix(b"\n").unwrap_or(line);
                let logged = lock(&out).line(line);
                if let Some(l) = logged
                    && !closed.load(Ordering::SeqCst)
                {
                    sink.line(&String::from_utf8_lossy(&l));
                }
                true
            });
        }
        done.fetch_add(1, Ordering::SeqCst);
    });
}

/// The stored user name and password for the bridge (zeroed by the bridge when it ends); `None` without either.
fn credentials(req: &UpRequest<'_>) -> Option<ManagementCredentials> {
    let s = req.secrets;
    if s.user.is_empty() && s.pass.is_empty() {
        return None;
    }
    let text = |v: &[u8]| {
        String::from_utf8(v.to_vec()).unwrap_or_else(|e| {
            let mut bytes = e.into_bytes();
            bytes.zeroize();
            String::new()
        })
    };
    Some(ManagementCredentials { username: text(&s.user), password: text(&s.pass), packed: s.packed })
}

impl Engine for OpenVpnEngine {
    fn up(&self, req: &UpRequest<'_>) -> Result<(), String> {
        let ready = (self.detect)()?;
        let mut driver = ovpn_args::choose_driver(std::str::from_utf8(req.config).unwrap_or_default());
        // A run of this ID is taken down first (as macOS' `up` does).
        self.down(req.id)?;
        let mut port_retries = PORT_RETRIES;
        loop {
            if !ready.has(driver) {
                return Err(ovpn_run::needs_driver(driver));
            }
            match self.attempt(req, &ready.exe, driver) {
                Ok(()) => return Ok(()),
                Err(Attempt::Failed(Failure::DcoIncompatible)) if driver == Driver::Dco => {
                    req.log
                        .line("[WinVPN] DCO cannot run this connection (pushed options); retrying with TAP-Windows6");
                    driver = Driver::TapWindows6;
                }
                Err(Attempt::PortTaken(_)) if port_retries > 0 => {
                    port_retries -= 1;
                    req.log.line("[WinVPN] The management port was taken; retrying with another port");
                }
                Err(Attempt::PortTaken(m)) => return Err(m),
                Err(Attempt::Failed(f)) => return Err(f.message()),
                Err(Attempt::Setup(m)) => return Err(m),
            }
        }
    }

    fn down(&self, id: &str) -> Result<(), String> {
        let Some(run) = lock(&self.runs).remove(id) else {
            // Nothing runs; a leftover directory goes too.
            let _ = self.data.remove_run_dir(id);
            return Ok(());
        };
        run.closed.store(true, Ordering::SeqCst);
        if !run.proc.stop() {
            // It may still run: it stays this ID's run (a later `down` tries again).
            lock(&self.runs).entry(id.to_string()).or_insert(run);
            return Err(tr("openvpn.exe did not stop", &[]));
        }
        self.remove_dir(id);
        Ok(())
    }

    fn state(&self, id: &str) -> Option<EngineState> {
        let run = self.run_of(id)?;
        let running = !run.proc.exited();
        let done = lock(&run.out).done;
        let state = match (running, done) {
            (true, true) => "connected",
            (true, false) => "connecting",
            _ => "failed",
        };
        let ip = if state == "connected" { lock(&run.ip).clone().unwrap_or_default() } else { String::new() };
        Some(EngineState { state, iface: String::new(), ip, since: Some(run.since) })
    }

    /// Dead-tunnel detection: OpenVPN restarting itself (the bridge's view of `>STATE:…,RECONNECTING`), only while
    /// the process runs and the first connect is done.
    fn liveness(&self, id: &str) -> Option<macvpn_core::liveness::Liveness> {
        let run = self.run_of(id)?;
        if run.proc.exited() || !lock(&run.out).done {
            return None;
        }
        Some(macvpn_core::liveness::Liveness::OpenVpn { reconnecting_since: run.bridge.reconnecting_since() })
    }

    /// Live traffic: OpenVPN's latest `>BYTECOUNT` of this process run, while it runs and once connected.
    fn traffic(&self, id: &str) -> Option<macvpn_core::traffic::ByteCount> {
        let run = self.run_of(id)?;
        if run.proc.exited() || !lock(&run.out).done {
            return None;
        }
        let (rx, tx) = (*lock(&run.bytes))?;
        Some(macvpn_core::traffic::ByteCount { rx, tx, run: run.since })
    }

    fn respond(&self, id: &str, body: &[u8]) -> Result<(), String> {
        let run = self.run_of(id).ok_or_else(|| tr("Invalid ID", &[]))?;
        run.bridge.set_response(body);
        Ok(())
    }

    fn auth_state(&self, id: &str) -> Option<Vec<u8>> {
        self.run_of(id)?.bridge.ui()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_management_password_is_random_hex() {
        let (a, b) = (management_password().unwrap(), management_password().unwrap());
        assert_eq!(a.len(), 64);
        assert!(a.iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c)));
        assert_ne!(a, b);
    }

    #[test]
    fn a_free_port_is_below_the_dynamic_range() {
        assert!(*MGMT_PORTS.end() < 49152);
        for _ in 0..50 {
            let p = free_port().unwrap();
            assert!(MGMT_PORTS.contains(&p), "{p}");
        }
        TcpListener::bind((Ipv4Addr::LOCALHOST, free_port().unwrap())).unwrap();
    }
}
