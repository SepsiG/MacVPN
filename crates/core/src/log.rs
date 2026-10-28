//! Log lines and the log tailer (port of `LogLine.swift` and `LogTailer.swift`).

use crate::fsx::{self, FileId, FileOwner, Follow, OpenFor};
use crate::l10n;
use crate::swift_str;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFilter {
    All,
    Commands,
    Errors,
}

impl LogFilter {
    pub const ALL: [LogFilter; 3] = [LogFilter::All, LogFilter::Commands, LogFilter::Errors];

    pub fn raw_value(self) -> &'static str {
        match self {
            LogFilter::All => "all",
            LogFilter::Commands => "commands",
            LogFilter::Errors => "errors",
        }
    }

    pub fn title(self) -> String {
        match self {
            LogFilter::All => l10n::tr("All", &[]),
            LogFilter::Commands => l10n::tr("Commands", &[]),
            LogFilter::Errors => l10n::tr("Errors", &[]),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLineKind {
    Header,
    Step,
    Command,
    Error,
    Output,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub text: String,
    pub kind: LogLineKind,
}

pub const ERROR_MARKERS: [&str; 7] = [
    "AUTH_FAILED",
    "TLS handshake failed",
    "TLS Error",
    "Exiting due to fatal error",
    "establishing connection failed",
    "failed to establish",
    "Connection refused",
];

impl LogLine {
    pub fn new(text: impl Into<String>) -> LogLine {
        let text = text.into();
        let kind = if swift_str::has_prefix(&text, "═══") {
            LogLineKind::Header
        } else if swift_str::has_prefix(&text, "▶ [mvpn]") {
            LogLineKind::Step
        } else if swift_str::has_prefix(&text, "$ ") || swift_str::has_prefix(&text, "[#] ") {
            LogLineKind::Command
        } else if swift_str::has_prefix(&text, "✗") || ERROR_MARKERS.iter().any(|m| swift_str::contains(&text, m)) {
            LogLineKind::Error
        } else {
            LogLineKind::Output
        };
        LogLine { text, kind }
    }

    pub fn matches(&self, filter: LogFilter) -> bool {
        match filter {
            LogFilter::All => true,
            LogFilter::Commands => {
                matches!(self.kind, LogLineKind::Command | LogLineKind::Step | LogLineKind::Header)
            }
            LogFilter::Errors => self.kind == LogLineKind::Error,
        }
    }
}

/// What identifies one log: the file id on macOS (the inode check), the service's generation on Windows. A new
/// identity means a new log: the tail starts over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogIdentity {
    File(FileId),
    Generation(u64),
}

/// One read of a log: its identity, its size, and the bytes from `start` (at most what was asked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRead {
    pub identity: Option<LogIdentity>,
    pub size: u64,
    pub start: u64,
    pub data: Vec<u8>,
}

/// Where a [`LogTailer`] reads from.
pub trait LogSource: Send {
    /// The bytes from `offset` (at most `max`; none when `offset >= size`). `None`: there is no log (yet).
    fn read(&mut self, offset: u64, max: usize) -> Option<LogRead>;
}

/// The file at `path` (macOS: `/var/log/macvpn/<id>.log`), opened for each read, as the tailer always did.
#[derive(Debug, Clone)]
pub struct FileLogSource {
    pub path: PathBuf,
}

impl LogSource for FileLogSource {
    fn read(&mut self, offset: u64, max: usize) -> Option<LogRead> {
        let mut file = File::open(&self.path).ok()?;
        let identity = fsx::stat(&file).ok().and_then(|s| fsx::file_id(&s)).map(LogIdentity::File);
        let size = file.seek(SeekFrom::End(0)).unwrap_or(0);
        let mut data = Vec::new();
        if offset < size && file.seek(SeekFrom::Start(offset)).is_ok() {
            let _ = (&mut file).take(max as u64).read_to_end(&mut data);
        }
        Some(LogRead { identity, size, start: offset, data })
    }
}

/// The first line of a cleared log (the Log tab's "Clear Log…"): `═══ Log cleared at <time> ═══`, `time` as the logs
/// write it (`YYYY-MM-DD HH:MM:SS`, local). A header line: the Commands filter shows it and the time filter reads its
/// time. Written by the app (macOS, WinVPN's RAS log) and by the WinVPN Service (its connection logs).
pub fn cleared_note(time: &str) -> String {
    format!("═══ {} ═══", l10n::tr("Log cleared at %@", &[l10n::Arg::Str(time)]))
}

/// Empties the log file at `path` in place (the Log tab's "Clear Log…"), then appends `note` as its first line.
/// The file stays the same file: a writer holding it open for appending (OpenVPN's `--log-append`, the root
/// layer's child processes) continues at its new end, and a tail sees it shrink and starts over. Only a regular
/// file of `owner` is touched, never through a symlink (`Ok(false)`: there is no such file, nothing to clear).
pub fn clear_file(path: &Path, owner: &FileOwner, note: Option<&str>) -> io::Result<bool> {
    let (mut file, stat) = match fsx::open_regular(path, OpenFor::Write, Follow::No, true) {
        Ok(opened) => opened,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if fsx::owner(&stat)? != *owner {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the log belongs to another user"));
    }
    file.set_len(0)?;
    if let Some(note) = note {
        // At the end: a line an appending writer wrote since the truncation stays whole.
        file.seek(SeekFrom::End(0))?;
        file.write_all(format!("{note}\n").as_bytes())?;
    }
    Ok(true)
}

/// Reads a log's new, complete lines from an offset, through a [`LogSource`]. After truncation or a new log (a new
/// file id or generation) it starts over. The first read only looks at the last 256 KB, a call reads at most 1 MB,
/// and an unterminated line over 64 KB is emitted as a line.
pub struct LogTailer {
    /// The file's path for [`LogTailer::new`]; empty for [`LogTailer::with_source`].
    pub path: PathBuf,
    source: Box<dyn LogSource>,
    offset: u64,
    partial: Vec<u8>,
    started: bool,
    identity: Option<LogIdentity>,
    /// Starting in the middle of the window, the first (truncated) line is dropped.
    discard_leading: bool,
}

impl std::fmt::Debug for LogTailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogTailer")
            .field("path", &self.path)
            .field("offset", &self.offset)
            .field("partial", &self.partial.len())
            .field("started", &self.started)
            .field("identity", &self.identity)
            .field("discard_leading", &self.discard_leading)
            .finish_non_exhaustive()
    }
}

pub const INITIAL_WINDOW: u64 = 256 * 1024;
pub const MAX_READ_BYTES: usize = 1024 * 1024;
pub const MAX_PARTIAL_BYTES: usize = 64 * 1024;

/// `String(decoding:as: UTF8.self).components(separatedBy: "\n")`.
fn decode_lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes).split('\n').map(str::to_string).collect()
}

impl LogTailer {
    /// The tail of the file at `path` ([`FileLogSource`]).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut tailer = Self::with_source(Box::new(FileLogSource { path: path.clone() }));
        tailer.path = path;
        tailer
    }

    /// The tail of any source (the WinVPN Service's log).
    pub fn with_source(source: Box<dyn LogSource>) -> Self {
        LogTailer {
            path: PathBuf::new(),
            source,
            offset: 0,
            partial: Vec::new(),
            started: false,
            identity: None,
            discard_leading: false,
        }
    }

    pub fn read_new(&mut self) -> Vec<String> {
        let Some(mut r) = self.source.read(self.offset, MAX_READ_BYTES) else { return Vec::new() };
        if let (Some(old), Some(new)) = (&self.identity, &r.identity)
            && old != new
        {
            self.offset = 0;
            self.partial.clear();
            self.discard_leading = false;
            self.started = false; // the 256 KB window applies to the new file too
        }
        self.identity = r.identity.clone();
        let size = r.size;
        if !self.started {
            self.started = true;
            if size > INITIAL_WINDOW {
                self.offset = size - INITIAL_WINDOW;
                self.discard_leading = true;
            }
        }
        if size < self.offset {
            self.offset = 0;
            self.partial.clear();
            self.discard_leading = false;
        }
        if size <= self.offset {
            return Vec::new();
        }
        // The window or a reset moved the offset after the read: read again from there (same log only).
        if r.start != self.offset {
            match self.source.read(self.offset, MAX_READ_BYTES) {
                Some(again) if again.identity == self.identity && again.start == self.offset => r = again,
                _ => return Vec::new(),
            }
        }
        let mut data = r.data;
        self.offset += data.len() as u64;
        if self.discard_leading {
            let Some(nl) = data.iter().position(|&b| b == b'\n') else { return Vec::new() };
            data.drain(..=nl);
            self.discard_leading = false;
        }
        self.partial.extend_from_slice(&data);
        let mut lines = Vec::new();
        if let Some(last_newline) = self.partial.iter().rposition(|&b| b == b'\n') {
            lines = decode_lines(&self.partial[..last_newline]);
            self.partial.drain(..=last_newline);
        }
        if self.partial.len() > MAX_PARTIAL_BYTES {
            let cut = complete_utf8_prefix(&self.partial);
            lines.push(String::from_utf8_lossy(&self.partial[..cut]).into_owned());
            self.partial.drain(..cut);
        }
        lines
    }
}

/// The length up to which no multi-byte UTF-8 character is cut in half.
pub fn complete_utf8_prefix(d: &[u8]) -> usize {
    let mut i = d.len() as isize - 1;
    let mut back = 0;
    while i >= 0 && back < 3 && (d[i as usize] & 0xC0) == 0x80 {
        i -= 1;
        back += 1;
    }
    if i < 0 {
        return d.len();
    }
    let lead = d[i as usize];
    let need = if lead >= 0xF0 {
        4
    } else if lead >= 0xE0 {
        3
    } else if lead >= 0xC0 {
        2
    } else {
        1
    };
    let i = i as usize;
    if d.len() - i < need { i } else { d.len() }
}
