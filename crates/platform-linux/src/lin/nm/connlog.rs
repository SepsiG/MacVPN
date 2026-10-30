//! A connection's log file (`$XDG_DATA_HOME/LinVPN/logs/<UUID>.log`, resolved point 11): the engine's own lines
//! and the journal pump's.
//!
//! Every line starts with the local time `YYYY-MM-DD HH:MM:SS` (the logs' format: the Log tab's time filter reads
//! it), so `HelperClient::log_path` with the existing `FileLogSource`, "Clear Log…" (`macvpn_core::log::clear_file`,
//! the system journal untouched) and the time filter work unchanged. The folder is 0700, the file 0600, never
//! written through a symlink. The file is capped at [`LOG_MAX`] (the root layer's user-log cap): a write that would
//! grow it over the cap first drops its oldest half (cut at a line start), in place, so a reader sees it shrink and
//! starts over.
//!
//! The journal pump ([`ConnLog::pump`]) asks `linvpn-logd` every [`POLL`] for the connection's new journal lines
//! (following the returned cursor) and appends each as `<journal time> [nm|openvpn|<ident>] <text>`, masked with the
//! connection's [`Masker`], while its [`Pump`] guard lives and for [`LINGER`] after it is dropped.

use crate::lin::nm::logd_client::{self, LogdError};
use crate::lin::system;
use macvpn_core::l10n;
use macvpn_core::logd::{Request, Response, Source};
use macvpn_core::models::Secrets;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

/// The cap of a connection log: the root layer's user-log cap (`helper::macos::paths::LOG_MAX`; this crate cannot
/// depend on the helper).
pub const LOG_MAX: u64 = 5_242_880;
/// How often the pump asks `linvpn-logd` (each answer is one short-lived `journalctl` run).
pub const POLL: Duration = Duration::from_secs(2);
/// How long the pump keeps asking after its guard is dropped (NM's and the plugin's last lines of a disconnect).
pub const LINGER: Duration = Duration::from_secs(15);
/// How far before the pump's start the first query looks (lines of the add that came just before it).
const LOOKBACK_USEC: u64 = 10_000_000;

const WITHHELD: &str = "Some plugin lines were withheld: another VPN was active at the same time.";
const NO_LOGD: &str = "The system log is not available (linvpn-logd is not installed).";

pub fn path(logs_dir: &Path, id: &Uuid) -> PathBuf {
    logs_dir.join(format!("{}.log", id.hyphenated().to_string().to_uppercase()))
}

/// `YYYY-MM-DD HH:MM:SS` in local time (empty if it cannot be converted).
pub fn stamp(unix: f64) -> String {
    system::local_time(unix)
        .map(|(y, mo, d, h, mi, s)| format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}"))
        .unwrap_or_default()
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

pub struct ConnLog {
    pub path: PathBuf,
    writer: Writer,
}

/// Runs the journal pump while it lives (and 15 s after it is dropped).
pub struct Pump {
    _stop: Box<dyn Send>,
    masker: Arc<Mutex<Masker>>,
}

impl Pump {
    /// More secrets to mask from now on (an adopted tunnel's, once the vault is unlocked).
    pub fn add_secrets(&self, secrets: &Secrets) {
        let more = Masker::new(secrets);
        let mut masker = self.masker.lock().unwrap_or_else(|p| p.into_inner());
        for s in more.secrets {
            if !masker.secrets.iter().any(|m| **m == *s) {
                masker.secrets.push(s);
            }
        }
    }
}

impl ConnLog {
    pub fn open(logs_dir: &Path, id: &Uuid) -> ConnLog {
        ConnLog::open_capped(logs_dir, id, LOG_MAX)
    }

    /// [`ConnLog::open`] with another cap (the tests').
    #[doc(hidden)]
    pub fn open_capped(logs_dir: &Path, id: &Uuid, max: u64) -> ConnLog {
        let path = path(logs_dir, id);
        if fs::create_dir_all(logs_dir).is_ok() {
            let _ = fs::set_permissions(logs_dir, fs::Permissions::from_mode(0o700));
        }
        // Created 0600; an existing file (an older run's) is made 0600 too. Never through a symlink.
        if let Some(f) = open_append(&path) {
            let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
        }
        let writer = Writer { path: path.clone(), max: max.max(2), lock: Arc::new(Mutex::new(())) };
        ConnLog { path, writer }
    }

    /// One line `YYYY-MM-DD HH:MM:SS <text>` (local time), masked by the caller.
    pub fn line(&self, text: &str) {
        self.writer.append(&format!("{} {text}\n", stamp(now())));
    }

    pub fn pump(&self, id: Uuid, masker: Masker) -> Pump {
        self.pump_with(id, masker, Path::new(logd_client::SOCKET), POLL, LINGER)
    }

    /// [`ConnLog::pump`] from the `linvpn-logd` at `socket` (`None`: the installed one).
    pub fn pump_from(&self, id: Uuid, masker: Masker, socket: Option<&Path>) -> Pump {
        self.pump_with(id, masker, socket.unwrap_or(Path::new(logd_client::SOCKET)), POLL, LINGER)
    }

    /// [`ConnLog::pump`] with another server, poll interval and linger time (the tests'). The production socket is
    /// queried through [`logd_client::query`] (which checks that root owns it); any other through `query_at`.
    #[doc(hidden)]
    pub fn pump_with(&self, id: Uuid, masker: Masker, socket: &Path, poll: Duration, linger: Duration) -> Pump {
        let (stop, stopped) = mpsc::channel::<()>();
        let writer = self.writer.clone();
        let socket = socket.to_path_buf();
        let since_usec = (now() * 1e6) as u64;
        let since_usec = since_usec.saturating_sub(LOOKBACK_USEC);
        let masker = Arc::new(Mutex::new(masker));
        let shared = masker.clone();
        // A thread that cannot start leaves the log without journal lines (the engine's own lines still come).
        let _ = std::thread::Builder::new().name("linvpn-journal-pump".into()).spawn(move || {
            let mut state = PumpState { writer, masker, cursor: None, said_withheld: false, said_missing: false };
            let mut until: Option<Instant> = None;
            loop {
                let request = Request { connection: id, since_usec, cursor: state.cursor.clone() };
                let answer = if socket == Path::new(logd_client::SOCKET) {
                    logd_client::query(&request)
                } else {
                    logd_client::query_at(&socket, &request)
                };
                state.take(answer);
                if until.is_some_and(|t| Instant::now() >= t) {
                    return;
                }
                match until {
                    None => match stopped.recv_timeout(poll) {
                        Ok(()) | Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => until = Some(Instant::now() + linger),
                    },
                    Some(t) => std::thread::sleep(poll.min(t.saturating_duration_since(Instant::now()))),
                }
            }
        });
        Pump { _stop: Box::new(stop), masker: shared }
    }
}

/// The pump thread's state between two answers.
struct PumpState {
    writer: Writer,
    masker: Arc<Mutex<Masker>>,
    cursor: Option<String>,
    said_withheld: bool,
    said_missing: bool,
}

impl PumpState {
    fn take(&mut self, answer: Result<Response, LogdError>) {
        match answer {
            Ok(r) => {
                let mut out = String::new();
                let masker = self.masker.lock().unwrap_or_else(|p| p.into_inner());
                for l in &r.lines {
                    let tag = match &l.source {
                        Source::NetworkManager => "nm",
                        Source::OpenVpn => "openvpn",
                        Source::Plugin(p) => p.as_str(),
                    };
                    out.push_str(&format!("{} [{tag}] {}\n", stamp(l.usec as f64 / 1e6), masker.line(&l.text)));
                }
                drop(masker);
                if r.withheld && !self.said_withheld {
                    self.said_withheld = true;
                    out.push_str(&format!("{} {}\n", stamp(now()), l10n::tr(WITHHELD, &[])));
                }
                self.writer.append(&out);
                if r.cursor.is_some() {
                    self.cursor = r.cursor;
                }
            }
            Err(LogdError::Unavailable) if !self.said_missing => {
                self.said_missing = true;
                self.writer.append(&format!("{} {}\n", stamp(now()), l10n::tr(NO_LOGD, &[])));
            }
            // A slow or broken answer: asked again at the next poll with the same cursor.
            Err(_) => {}
        }
    }
}

/// The file's writer: appends serialized between the engine and the pump, capped.
#[derive(Clone)]
struct Writer {
    path: PathBuf,
    max: u64,
    lock: Arc<Mutex<()>>,
}

impl Writer {
    fn append(&self, data: &str) {
        if data.is_empty() {
            return;
        }
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let data = newest_lines(data.as_bytes(), self.max / 2);
        let Some(mut f) = open_append(&self.path) else { return };
        let size = f.metadata().map_or(0, |m| m.len());
        if size + data.len() as u64 > self.max {
            drop_oldest_half(&mut f, size, self.max);
        }
        let _ = f.write_all(data);
    }
}

/// The file opened for appending (created 0600), never through a symlink, only a regular file.
fn open_append(path: &Path) -> Option<File> {
    let f = OpenOptions::new()
        .append(true)
        .read(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    f.metadata().ok().filter(|m| m.is_file())?;
    Some(f)
}

/// Keeps the newest part of the file of at most `max / 2` bytes, from a line start, in place.
fn drop_oldest_half(f: &mut File, size: u64, max: u64) {
    let keep = (max / 2).min(size);
    let start = size - keep;
    let mut tail = Vec::with_capacity(keep as usize);
    if f.seek(SeekFrom::Start(start)).is_err() || f.take(keep).read_to_end(&mut tail).is_err() {
        return;
    }
    // A cut inside a line drops the rest of that line (a cut right at a line start keeps it).
    let at_line_start = start == 0 || {
        let mut prev = [0u8; 1];
        f.seek(SeekFrom::Start(start - 1)).is_ok() && f.read_exact(&mut prev).is_ok() && prev[0] == b'\n'
    };
    let cut = if at_line_start { 0 } else { tail.iter().position(|&b| b == b'\n').map_or(tail.len(), |i| i + 1) };
    if f.set_len(0).is_ok() {
        // O_APPEND: the write goes to the (new) end.
        let _ = f.write_all(&tail[cut..]);
    }
}

/// The newest whole lines of `data` within `max` bytes (all of it when it fits).
fn newest_lines(data: &[u8], max: u64) -> &[u8] {
    let max = max as usize;
    if data.len() <= max {
        return data;
    }
    let start = data.len() - max;
    if data[start - 1] == b'\n' {
        return &data[start..];
    }
    let rest = &data[start..];
    rest.iter().position(|&b| b == b'\n').map_or(&[][..], |i| &rest[i + 1..])
}

/// The connection's secrets, to mask the journal's lines (`platform-win`'s `LogMasker` rule).
///
/// The masking rule is copied from `platform-win/src/pure/ras_log.rs` (`LogMasker`, itself the root layer's
/// `helper::shared::mask` rule), which this crate cannot depend on: a secret of 3 bytes or more is replaced by `***`
/// anywhere, literally; a shorter one only as a whole token (neither neighbour an ASCII letter or digit). A password
/// with the OTP code appended is covered by masking both.
#[derive(Default)]
pub struct Masker {
    pub secrets: Vec<Zeroizing<String>>,
}

impl Masker {
    /// The password, PSK, key password and one-time code (not the user name).
    pub fn new(secrets: &Secrets) -> Masker {
        let mut m = Masker::default();
        for s in [&secrets.password, &secrets.psk, &secrets.key_password, &secrets.one_time_code].into_iter().flatten()
        {
            if !s.is_empty() {
                m.secrets.push(Zeroizing::new(s.clone()));
            }
        }
        m
    }

    /// One line, every secret replaced in turn.
    pub fn line(&self, line: &str) -> String {
        let mut out = line.to_string();
        for s in self.secrets.iter().filter(|s| !s.is_empty()) {
            out = mask_one(&out, s);
        }
        out
    }
}

fn is_alnum(b: Option<u8>) -> bool {
    b.is_some_and(|b| b.is_ascii_alphanumeric())
}

/// `ras_log::mask_one`: a UTF-8 secret only matches on character boundaries, so the result stays UTF-8.
fn mask_one(line: &str, secret: &str) -> String {
    let n = secret.len();
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(p) = rest.find(secret) {
        let whole_token = n >= 3 || {
            let pre = if p > 0 { Some(rest.as_bytes()[p - 1]) } else { out.as_bytes().last().copied() };
            !is_alnum(pre) && !is_alnum(rest.as_bytes().get(p + n).copied())
        };
        out.push_str(&rest[..p]);
        out.push_str(if whole_token { "***" } else { &rest[p..p + n] });
        rest = &rest[p + n..];
    }
    out.push_str(rest);
    out
}
