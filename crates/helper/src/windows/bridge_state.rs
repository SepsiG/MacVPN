//! The management bridge's files, in memory: the service runs the shared `Bridge` on a thread of its own, so the
//! user's `AuthUIState` (macOS: `/var/run/macvpn-ui/<id>.json`) is served by `auth-state`, the app's answer
//! (macOS: `<run>/mgmt-resp`) comes from `respond`, and `mgmt-status` is read by the engine's wait loop. Nothing of
//! it is a file, so nothing of it can be planted, read or replaced by another process.
//!
//! [`StateWatch`] passes the management stream through to the bridge and takes the tunnel's address from OpenVPN's
//! `>STATE:…,CONNECTED,…` line (OpenVPN on Windows logs no adapter name at the default verbosity; the address is
//! what `status` reports).
//!
//! [`ByteCounter`] asks OpenVPN for its byte counters once it reports a state (`bytecount 1`, through
//! [`OneCommandAtATime`]) and keeps the latest `>BYTECOUNT:` for the service's `traffic` (live traffic).
//!
//! [`OneCommandAtATime`] sends the bridge's next command only once OpenVPN has answered the last one (OpenVPN on
//! Windows can lose a command that arrives while it answers the one before).
//!
//! Portable (no `cfg`): tested on every OS.

use crate::shared::bridge::{BridgeFiles, valid_status};
use crate::shared::cli;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// The longest `AuthUIState` kept (`AuthUIState::parse` refuses anything longer).
const UI_MAX: usize = 8192;

type LogFn = Box<dyn Fn(&str) + Send + Sync>;
type StopFn = Box<dyn Fn() + Send + Sync>;

/// What the bridge of one connection shares with the service.
pub struct BridgeState {
    ui: Mutex<Option<Vec<u8>>>,
    status: Mutex<Option<String>>,
    response: Mutex<Option<Zeroizing<Vec<u8>>>>,
    /// Dead-tunnel detection: `Some(t)` OpenVPN restarts the tunnel itself since `t` (after it was connected).
    reconnecting_since: Mutex<Option<u64>>,
    log: LogFn,
    stop: StopFn,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl BridgeState {
    /// `log`: the connection log's line sink (masked by the sink); `stop`: kills this connection's `openvpn.exe`.
    pub fn new(log: LogFn, stop: StopFn) -> BridgeState {
        BridgeState {
            ui: Mutex::default(),
            status: Mutex::default(),
            response: Mutex::default(),
            reconnecting_since: Mutex::default(),
            log,
            stop,
        }
    }

    /// Since when OpenVPN restarts the tunnel itself (`None`: up, or not connected yet).
    pub fn reconnecting_since(&self) -> Option<u64> {
        *lock(&self.reconnecting_since)
    }

    /// The `AuthUIState` JSON for `auth-state` (`None`: nothing pending).
    pub fn ui(&self) -> Option<Vec<u8>> {
        lock(&self.ui).clone()
    }

    /// The strict `mgmt-status` (`valid_status`), `None` otherwise.
    pub fn mgmt_status(&self) -> Option<String> {
        lock(&self.status).clone()
    }

    /// `respond`'s body, for the bridge's next poll (a newer answer replaces an unread one).
    pub fn set_response(&self, body: &[u8]) {
        *lock(&self.response) = Some(Zeroizing::new(body.to_vec()));
    }
}

/// The bridge's [`BridgeFiles`] over a [`BridgeState`].
pub struct InProcessFiles(Arc<BridgeState>);

impl InProcessFiles {
    pub fn new(state: Arc<BridgeState>) -> InProcessFiles {
        InProcessFiles(state)
    }

    pub fn state(&self) -> &BridgeState {
        &self.0
    }
}

impl BridgeFiles for InProcessFiles {
    fn log(&mut self, line: &str) {
        (self.0.log)(line);
    }
    /// Memory of the service: always "safe".
    fn run_trusted(&self) -> bool {
        true
    }
    fn ui_trusted(&self) -> bool {
        true
    }
    /// Only the name the bridge uses (`<ID>.json`), at most [`UI_MAX`] bytes.
    fn write_ui(&mut self, name: &str, data: &[u8]) -> bool {
        if !name.strip_suffix(".json").is_some_and(cli::is_uuid) || data.len() > UI_MAX {
            return false;
        }
        *lock(&self.0.ui) = Some(data.to_vec());
        true
    }
    /// Only `mgmt-status` (the one run file the bridge writes); its first line, if it is a valid status.
    fn write_run(&mut self, name: &str, data: &[u8]) -> bool {
        if name != "mgmt-status" {
            return false;
        }
        let first = data.split(|&b| b == b'\n').next().unwrap_or_default();
        let parsed = std::str::from_utf8(first).ok().filter(|s| valid_status(s)).map(String::from);
        *lock(&self.0.status) = parsed;
        true
    }
    fn remove_ui(&mut self, _name: &str) {
        *lock(&self.0.ui) = None;
    }
    fn take_response(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        lock(&self.0.response).take()
    }
    fn stop_openvpn(&mut self) {
        (self.0.stop)();
    }
    /// In memory (`liveness` reads it), never a file.
    fn tunnel(&mut self, reconnecting_since: Option<u64>) {
        *lock(&self.0.reconnecting_since) = reconnecting_since;
    }
}

/// The longest management line [`StateWatch`] looks at (longer ones are skipped to their end; the bridge has its
/// own limit).
const WATCH_LINE_MAX: usize = 4096;

/// The management stream as the bridge sees it (unchanged), watching OpenVPN's real-time state lines: the local
/// tunnel address of a `CONNECTED` state (the IPv4 field, else the IPv6 one) once it parses as an address; any
/// other state clears it.
pub struct StateWatch<S> {
    inner: S,
    ip: Arc<Mutex<Option<String>>>,
    line: Vec<u8>,
    skipping: bool,
}

impl<S> StateWatch<S> {
    pub fn new(inner: S, ip: Arc<Mutex<Option<String>>>) -> StateWatch<S> {
        StateWatch { inner, ip, line: Vec::new(), skipping: false }
    }

    fn see(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                if !self.skipping {
                    let line = std::mem::take(&mut self.line);
                    self.state_line(line.strip_suffix(b"\r").unwrap_or(&line));
                }
                self.line.clear();
                self.skipping = false;
            } else if !self.skipping {
                self.line.push(b);
                if self.line.len() > WATCH_LINE_MAX {
                    self.line.clear();
                    self.skipping = true;
                }
            }
        }
    }

    /// `>STATE:<time>,<state>,<desc>,<local IPv4>,<remote>,<remote port>,<local addr>,<local port>,<local IPv6>`
    fn state_line(&self, line: &[u8]) {
        let Some(rest) = line.strip_prefix(b">STATE:") else { return };
        let Ok(rest) = std::str::from_utf8(rest) else { return };
        let fields: Vec<&str> = rest.split(',').collect();
        let ip = if fields.get(1) == Some(&"CONNECTED") {
            [3, 8].iter().filter_map(|&i| fields.get(i)).find_map(|f| f.parse::<IpAddr>().ok()).map(|a| a.to_string())
        } else {
            None
        };
        *lock(&self.ip) = ip;
    }
}

impl<S: Read> Read for StateWatch<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.see(&buf[..n]);
        Ok(n)
    }
}

impl<S: Write> Write for StateWatch<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// The interval OpenVPN reports its byte counters at (seconds).
const BYTECOUNT_INTERVAL: u32 = 1;

/// The management stream as the bridge sees it (unchanged), asking OpenVPN for its byte counters: at the first
/// `>STATE:` line (the bridge's `state on` was answered, OpenVPN no longer holds) it writes `bytecount 1` once into
/// the inner stream (over [`OneCommandAtATime`], so it never overlaps the bridge's commands; the bridge ignores the
/// `SUCCESS:` answer and the `>BYTECOUNT:` lines), and keeps the latest `>BYTECOUNT:<in>,<out>` in `bytes`. OpenVPN
/// counts from its process start; a reconnect inside the process keeps counting.
pub struct ByteCounter<S> {
    inner: S,
    bytes: Arc<Mutex<Option<(u64, u64)>>>,
    line: Vec<u8>,
    skipping: bool,
    asked: bool,
}

impl<S> ByteCounter<S> {
    pub fn new(inner: S, bytes: Arc<Mutex<Option<(u64, u64)>>>) -> ByteCounter<S> {
        ByteCounter { inner, bytes, line: Vec::new(), skipping: false, asked: false }
    }

    /// Whether a complete line asks for the counters now.
    fn see(&mut self, bytes: &[u8]) -> bool {
        let mut ask = false;
        for &b in bytes {
            if b == b'\n' {
                if !self.skipping {
                    let line = std::mem::take(&mut self.line);
                    let line = line.strip_suffix(b"\r").unwrap_or(&line);
                    if let Some(c) = std::str::from_utf8(line)
                        .ok()
                        .and_then(|l| macvpn_core::traffic::ByteCount::from_management(l, 0))
                    {
                        *lock(&self.bytes) = Some((c.rx, c.tx));
                    } else if line.starts_with(b">STATE:") && !self.asked {
                        self.asked = true;
                        ask = true;
                    }
                }
                self.line.clear();
                self.skipping = false;
            } else if !self.skipping {
                self.line.push(b);
                if self.line.len() > WATCH_LINE_MAX {
                    self.line.clear();
                    self.skipping = true;
                }
            }
        }
        ask
    }
}

impl<S: Read + Write> Read for ByteCounter<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if self.see(&buf[..n]) {
            // Lost (a closed stream): no counters, nothing else changes.
            let _ = self.inner.write_all(format!("bytecount {BYTECOUNT_INTERVAL}\n").as_bytes());
        }
        Ok(n)
    }
}

impl<S: Write> Write for ByteCounter<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// How long a command waits for the answer to the one before; then it is sent anyway.
const ANSWER_WAIT: Duration = Duration::from_secs(5);
/// The most management output read ahead while waiting (then the command is sent anyway).
const AHEAD_MAX: usize = 64 * 1024;
/// The longest line start kept to recognise an answer (`SUCCESS:` / `ERROR:`).
const ANSWER_PREFIX_MAX: usize = 8;

/// The management stream as the bridge sees it (unchanged), with one command in flight at a time: a write that
/// starts a new command line while the previous command has no answer yet (a line starting `SUCCESS:` or `ERROR:`)
/// first reads OpenVPN's output ahead (kept, in order, for the bridge's next reads) until the answer arrives, at
/// most [`ANSWER_WAIT`]. Every command the bridge sends gets exactly one such answer line.
///
/// Why: OpenVPN 2.7.8 on Windows (`manage.c`) answers a command from inside `man_read`, before it has taken the
/// command line out of its buffer; writing the answer re-enters `management_io`, whose stale `FD_READ` reads the
/// next command into that buffer behind the old, NUL-terminated line. The old command then runs a second time and
/// the new one is dropped. CI saw `state on` twice and no `hold release`: OpenVPN held forever. The bridge sends
/// `hold release` (and `password` after `username`) right after the command before, so on fast loopback the next
/// command often arrives in that window. Answered commands never overlap.
pub struct OneCommandAtATime<S> {
    inner: S,
    /// Output read while waiting, not yet handed to the bridge.
    ahead: VecDeque<u8>,
    /// A command was sent and its answer has not been read yet.
    awaiting_answer: bool,
    /// The last write ended inside a command line (`write_all` writing the rest).
    mid_command: bool,
    /// The start of the current output line.
    prefix: Vec<u8>,
    wait: Duration,
}

impl<S: Read + Write> OneCommandAtATime<S> {
    pub fn new(inner: S) -> OneCommandAtATime<S> {
        OneCommandAtATime::with_wait(inner, ANSWER_WAIT)
    }

    /// With another answer wait (tests).
    pub fn with_wait(inner: S, wait: Duration) -> OneCommandAtATime<S> {
        OneCommandAtATime {
            inner,
            ahead: VecDeque::new(),
            awaiting_answer: false,
            mid_command: false,
            prefix: Vec::new(),
            wait,
        }
    }

    fn see(&mut self, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                if self.prefix.starts_with(b"SUCCESS:") || self.prefix.starts_with(b"ERROR:") {
                    self.awaiting_answer = false;
                }
                self.prefix.clear();
            } else if self.prefix.len() < ANSWER_PREFIX_MAX {
                self.prefix.push(b);
            }
        }
    }

    /// Reads ahead until the last command's answer, the end of the stream, an error, [`AHEAD_MAX`] or the wait.
    fn wait_for_answer(&mut self) {
        let until = Instant::now() + self.wait;
        let mut chunk = [0u8; 4096];
        while self.awaiting_answer && self.ahead.len() < AHEAD_MAX && Instant::now() < until {
            match self.inner.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    self.ahead.extend(&chunk[..n]);
                    self.see(&chunk[..n]);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                    ) =>
                {
                    // The stream's read timeout (the bridge's poll, 250 ms) paces this loop; a stream without one
                    // that reports WouldBlock at once must not spin.
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        // Answered, or given up: the command goes now either way.
        self.awaiting_answer = false;
    }
}

impl<S: Read + Write> Read for OneCommandAtATime<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.ahead.is_empty() {
            let n = buf.len().min(self.ahead.len());
            for (slot, b) in buf.iter_mut().zip(self.ahead.drain(..n)) {
                *slot = b;
            }
            return Ok(n);
        }
        let n = self.inner.read(buf)?;
        self.see(&buf[..n]);
        Ok(n)
    }
}

impl<S: Read + Write> Write for OneCommandAtATime<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.mid_command && self.awaiting_answer {
            self.wait_for_answer();
        }
        let n = self.inner.write(buf)?;
        let sent = &buf[..n];
        if sent.contains(&b'\n') {
            self.awaiting_answer = true;
        }
        self.mid_command = sent.last().is_some_and(|&b| b != b'\n');
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
