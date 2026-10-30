//! `linvpn-logd`, LinVPN's journal reader (L-b Task 18, resolved points 9 and 10).
//!
//! systemd starts one instance per connection (`linvpn-logd.socket`, `Accept=yes`) with the accepted socket on fd 0,
//! as a dynamic user in the `systemd-journal` group, heavily sandboxed and never root. One instance answers exactly
//! one request and exits:
//!
//! 1. the caller's uid from `SO_PEERCRED` (fail closed: no credentials, no answer);
//! 2. one request ([`macvpn_core::logd::Request`], at most `MAX_REQUEST` bytes, within [`READ_TIMEOUT`]); anything
//!    else gets the empty answer `C -\nE\n` and no journal is read; a request that never ends is closed unanswered;
//! 3. the NM UUID derived from that uid and the named LinVPN connection
//!    ([`macvpn_core::nm_plan::names::nm_uuid`]): a caller can only ever reach its own connections' UUIDs;
//! 4. `/usr/bin/journalctl` with the fixed arguments of [`macvpn_core::logd::journalctl_args`] (no caller-chosen
//!    match), environment cleared but `LANG=C.UTF-8`, stdout capped at [`JOURNAL_CAP`], killed after
//!    [`JOURNAL_TIMEOUT`]; then once more for NetworkManager's VPN history
//!    ([`macvpn_core::logd::history_args`], fixed, whole or not at all), and once for logd's own recorded readings
//!    of NetworkManager's active VPN connections ([`macvpn_core::logd::observation_args`]);
//! 5. a reading now ([`ActiveVpns`]: NetworkManager's `ActiveConnections` over the system bus, read-only), between
//!    two clock readings ([`macvpn_core::logd::Observation`]); recorded for later requests when it says something
//!    new ([`macvpn_core::logd::should_record`]);
//! 6. [`macvpn_core::logd::select`] with the history, the readings and the trusted senders ([`senders`]: the
//!    `nm-openvpn` user's uid looked up with `getpwnam`), one response, exit.
//!
//! It never writes anything but the response, and logs only `uid=<n> lines=<n>` (or the error kind) and a reading
//! to record (`<5>linvpn-logd-vpns-v1 …`, priority "notice") to stderr, the service's journal.
//!
//! NetworkManager 1.54.3's journal fields (`src/libnm-log-core/nm-logging.c`, `_nm_log_impl`, the journal backend):
//! `PRIORITY`, `MESSAGE`, `SYSLOG_IDENTIFIER`, `SYSLOG_PID`, `SYSLOG_FACILITY`, `NM_LOG_DOMAINS`, `NM_LOG_LEVEL`,
//! `CODE_FUNC`, `CODE_FILE`, `CODE_LINE`, `TIMESTAMP_MONOTONIC`, `TIMESTAMP_BOOTTIME`, `ERRNO`, `NM_DEVICE` (the
//! interface name) and `NM_CONNECTION` (the connection's UUID): resolved point 10's main rule holds, the `MESSAGE`
//! fallback is not needed on the target.

use std::ffi::CString;
use std::io::{self, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use macvpn_core::logd::{self, Observation, Request, Response, Senders};
use macvpn_core::nm_plan::names;

/// How long the caller may take to send its request.
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the caller may take to read the response.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long `journalctl` may run.
pub const JOURNAL_TIMEOUT: Duration = Duration::from_secs(10);
/// The most `journalctl` output read; the rest is cut at the last whole line (the client's cursor picks it up).
pub const JOURNAL_CAP: usize = 32 * 1024 * 1024;
pub const JOURNALCTL: &str = "/usr/bin/journalctl";
/// How much unread input is discarded after the answer, and for how long at most.
const DRAIN_LIMIT: usize = 64 * 1024;
const DRAIN_TIME: Duration = Duration::from_secs(1);

/// The journal: production runs `journalctl` ([`JournalCtl`]); the tests answer with fixtures.
pub trait Journal {
    /// `journalctl`'s stdout for `args` (the program not included); output beyond the cap is cut at a whole line.
    fn read(&self, args: &[String]) -> io::Result<Vec<u8>>;

    /// [`Journal::read`], but output beyond the cap is an error rather than cut (the VPN history must be whole: a
    /// cut would drop its newest lines).
    fn read_whole(&self, args: &[String]) -> io::Result<Vec<u8>> {
        self.read(args)
    }
}

/// NetworkManager's active VPN connections now: production asks NetworkManager over the system bus
/// ([`crate::linux::xfrmd::NmBus`]); the tests answer with fixed sets.
pub trait ActiveVpns {
    /// The `Uuid` of every active connection with `Vpn` true that is not yet deactivated. Any doubt (a property that
    /// cannot be read, too many connections) is an error: a partial set would let a connection pass as gone.
    fn active_vpns(&self) -> io::Result<Vec<String>>;
}

/// No system bus: no reading (plugin lines then rest on NetworkManager's history and earlier readings alone).
pub struct NoBus;

impl ActiveVpns for NoBus {
    fn active_vpns(&self) -> io::Result<Vec<String>> {
        Err(io::Error::new(ErrorKind::NotConnected, "no system bus"))
    }
}

/// What one request came to: the returned lines and the reading to record in the journal (`None`: nothing new, or
/// no reading).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Served {
    pub lines: usize,
    pub record: Option<String>,
}

/// `journalctl` as a child process.
#[derive(Clone, Debug)]
pub struct JournalCtl {
    pub program: PathBuf,
    pub timeout: Duration,
    pub cap: usize,
}

impl Default for JournalCtl {
    fn default() -> Self {
        JournalCtl { program: PathBuf::from(JOURNALCTL), timeout: JOURNAL_TIMEOUT, cap: JOURNAL_CAP }
    }
}

impl Journal for JournalCtl {
    fn read(&self, args: &[String]) -> io::Result<Vec<u8>> {
        self.run(args).map(|(buf, _cut)| buf)
    }

    fn read_whole(&self, args: &[String]) -> io::Result<Vec<u8>> {
        match self.run(args)? {
            (_, true) => Err(io::Error::other("journalctl's output exceeds the cap")),
            (buf, false) => Ok(buf),
        }
    }
}

impl JournalCtl {
    /// The output (cut at the cap) and whether it was cut.
    fn run(&self, args: &[String]) -> io::Result<(Vec<u8>, bool)> {
        let mut child = Command::new(&self.program)
            .args(args)
            .env_clear()
            .env("LANG", "C.UTF-8")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let mut stdout = child.stdout.take().ok_or_else(|| io::Error::other("journalctl: no stdout"))?;
        let limit = self.cap as u64 + 1;
        let reader = thread::spawn(move || {
            let mut buf = Vec::new();
            let r = (&mut stdout).take(limit).read_to_end(&mut buf);
            // Dropping the pipe here stops a journalctl that has more to say (EPIPE).
            (buf, r)
        });
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(io::Error::new(ErrorKind::TimedOut, "journalctl timed out"));
            }
            thread::sleep(Duration::from_millis(20));
        };
        let (mut buf, r) = reader.join().map_err(|_| io::Error::other("journalctl reader panicked"))?;
        r?;
        if buf.len() > self.cap {
            let end = buf[..self.cap].iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
            buf.truncate(end);
            return Ok((buf, true));
        }
        if !status.success() {
            return Err(io::Error::other(format!("journalctl exited with {status}")));
        }
        Ok((buf, false))
    }
}

/// One request on `stream` from `uid`, answered from `journal` and `nm`. An invalid request gets the empty answer
/// and reads no journal; a request not complete within [`READ_TIMEOUT`] is closed unanswered (`TimedOut`); a
/// journal failure gets the empty answer and the error.
pub fn serve(
    stream: UnixStream,
    uid: u32,
    journal: &dyn Journal,
    nm: &dyn ActiveVpns,
    senders: &Senders,
) -> io::Result<Served> {
    serve_within(stream, uid, journal, nm, senders, READ_TIMEOUT)
}

/// [`serve`] with another read timeout (the tests').
pub fn serve_within(
    mut stream: UnixStream,
    uid: u32,
    journal: &dyn Journal,
    nm: &dyn ActiveVpns,
    senders: &Senders,
    read_timeout: Duration,
) -> io::Result<Served> {
    let request = match read_request(&mut stream, read_timeout) {
        Ok(r) => r,
        Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(io::Error::new(ErrorKind::TimedOut, "no request in time"));
        }
        Err(_) => None,
    };
    let Some(request) = request else {
        answer(&mut stream, &Response::default())?;
        return Ok(Served::default());
    };
    let nm_uuid = names::nm_uuid(uid, &request.connection);
    let args = logd::journalctl_args(nm_uuid, request.since_usec, request.cursor.as_deref());
    let bytes = match journal.read(&args) {
        Ok(b) => b,
        Err(e) => {
            let _ = answer(&mut stream, &Response::default());
            return Err(e);
        }
    };
    let parse = |bytes: &[u8]| -> Vec<logd::Entry> {
        bytes.split(|&b| b == b'\n').filter_map(|l| std::str::from_utf8(l).ok()).filter_map(logd::parse_entry).collect()
    };
    let entries = parse(&bytes);
    // Read after the lines: NetworkManager's VPN history up to now (who else had a VPN up when a plugin wrote). On a
    // failure it stays empty, and no plugin line is returned.
    let history = journal.read_whole(&logd::history_args()).map(|b| parse(&b)).unwrap_or_default();
    // logd's earlier readings (a failure, or a cut: fewer readings, so connections count as up longer), then one now.
    let mut observations =
        journal.read(&logd::observation_args()).map(|b| logd::observations(&parse(&b))).unwrap_or_default();
    let mut record = None;
    if let Some(live) = observe(nm) {
        if logd::should_record(&history, &observations, &live) {
            record = Some(live.record_line());
        }
        observations.push(live);
    }
    let response =
        logd::select(&entries, &history, &observations, &nm_uuid.hyphenated().to_string(), request.since_usec, senders);
    answer(&mut stream, &response)?;
    Ok(Served { lines: response.lines.len(), record })
}

/// A reading of `nm` between two clock readings (the journal's realtime clock), or `None` when it fails.
pub fn observe(nm: &dyn ActiveVpns) -> Option<Observation> {
    let before = realtime_usec()?;
    let active = nm.active_vpns().ok()?;
    let after = realtime_usec()?;
    Observation::new(before, after, active)
}

fn realtime_usec() -> Option<u64> {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?;
    u64::try_from(d.as_micros()).ok()
}

/// The request bytes up to the first `\n` (at most `MAX_REQUEST` in all), parsed strictly; `Ok(None)` for anything
/// that is not one valid request (too long, not UTF-8, closed early, malformed).
fn read_request(stream: &mut UnixStream, timeout: Duration) -> io::Result<Option<Request>> {
    let deadline = Instant::now() + timeout;
    let mut buf = Vec::with_capacity(logd::MAX_REQUEST + 1);
    let mut chunk = [0u8; logd::MAX_REQUEST + 1];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(ErrorKind::TimedOut, "request timeout"));
        }
        stream.set_read_timeout(Some(left))?;
        let room = logd::MAX_REQUEST + 1 - buf.len();
        let n = match stream.read(&mut chunk[..room]) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > logd::MAX_REQUEST {
            return Ok(None);
        }
        if buf.contains(&b'\n') {
            return Ok(std::str::from_utf8(&buf).ok().and_then(Request::parse));
        }
    }
}

fn answer(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    stream.write_all(response.encode().as_bytes())?;
    stream.flush()?;
    let _ = stream.shutdown(Shutdown::Write);
    drain(stream);
    Ok(())
}

/// Reads and discards what the caller sent beyond its request (at most [`DRAIN_LIMIT`] bytes, for at most
/// [`DRAIN_TIME`]): closing a Unix socket with unread input resets the connection, and the caller would lose the
/// answer.
pub(crate) fn drain(stream: &mut UnixStream) {
    let deadline = Instant::now() + DRAIN_TIME;
    let mut left = DRAIN_LIMIT;
    let mut chunk = [0u8; 4096];
    while left > 0 {
        let time = deadline.saturating_duration_since(Instant::now());
        if time.is_zero() || stream.set_read_timeout(Some(time)).is_err() {
            return;
        }
        match stream.read(&mut chunk[..left.min(4096)]) {
            Ok(0) => return,
            Ok(n) => left -= n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// The peer's uid (`SO_PEERCRED`, recorded by the kernel at `connect`).
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    Ok(macvpn_unixsys::control_socket::peer(stream)?.uid)
}

/// Whether `fd` is a connected-or-listening `AF_UNIX` stream socket (`SO_DOMAIN`, `SO_TYPE`).
pub fn check_unix_stream(fd: BorrowedFd<'_>) -> io::Result<()> {
    let domain = sockopt_int(fd, libc::SO_DOMAIN)?;
    let kind = sockopt_int(fd, libc::SO_TYPE)?;
    if domain != libc::AF_UNIX || kind != libc::SOCK_STREAM {
        return Err(io::Error::new(ErrorKind::InvalidInput, "not an AF_UNIX stream socket"));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn sockopt_int(fd: BorrowedFd<'_>, name: libc::c_int) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: the out-buffer is `value` on the stack and its size is passed in `length`.
    let rc = unsafe { libc::getsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, name, (&raw mut value).cast(), &mut length) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<libc::c_int>() {
        return Err(io::Error::new(ErrorKind::InvalidData, "unexpected socket option size"));
    }
    Ok(value)
}

/// The uid of the system user `name` (`getpwnam_r`), `None` if there is none or the lookup fails.
#[allow(unsafe_code)]
pub fn user_uid(name: &str) -> Option<u32> {
    let cname = CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: an all-zero `passwd` is a valid value (null pointers, zero ids); getpwnam_r fills it.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `cname` is NUL-terminated; `pwd`, `buf` (its length passed) and `result` are valid for the call; the
    // strings it points into `buf` are not read.
    let rc = unsafe { libc::getpwnam_r(cname.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    (rc == 0 && !result.is_null()).then_some(pwd.pw_uid)
}

/// The trusted senders on this system: the `nm-openvpn` user's uid, looked up now.
pub fn senders() -> Senders {
    Senders { nm_openvpn_uid: user_uid(logd::NM_OPENVPN_USER) }
}

/// The binary's entry: fd 0 must be the accepted `AF_UNIX` stream socket (else exit 2). Exit 0 after an answer,
/// 1 on a failure (no peer credentials: no answer at all; a journal failure: the empty answer).
#[allow(unsafe_code)]
pub fn main() -> i32 {
    // SAFETY: fd 0 is borrowed only for the two getsockopt calls.
    let fd0 = unsafe { BorrowedFd::borrow_raw(0) };
    if let Err(e) = check_unix_stream(fd0) {
        eprintln!("linvpn-logd: stdin is not the accepted socket ({:?})", e.kind());
        return 2;
    }
    // SAFETY: fd 0 is open and a socket (checked above), and nothing else in this process uses it: std's stdin
    // handle is never touched, so the stream becomes its only owner.
    let stream = UnixStream::from(unsafe { OwnedFd::from_raw_fd(0) });
    let uid = match peer_uid(&stream) {
        Ok(uid) => uid,
        Err(e) => {
            eprintln!("linvpn-logd: no peer credentials ({:?})", e.kind());
            return 1;
        }
    };
    let bus = crate::linux::xfrmd::NmBus::system();
    let nm: &dyn ActiveVpns = match &bus {
        Ok(bus) => bus,
        Err(_) => &NoBus,
    };
    match serve(stream, uid, &JournalCtl::default(), nm, &senders()) {
        Ok(served) => {
            eprintln!("uid={uid} lines={}", served.lines);
            if let Some(record) = served.record {
                eprintln!("{record}");
            }
            0
        }
        Err(e) => {
            eprintln!("uid={uid} error={:?}", e.kind());
            1
        }
    }
}
