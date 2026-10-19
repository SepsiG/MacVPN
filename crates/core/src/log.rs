//! Log lines and the log tailer (port of `LogLine.swift` and `LogTailer.swift`).

use crate::l10n;
use crate::swift_str;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

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

/// Reads the file's new, complete lines from an offset. After truncation or a file replacement (inode) it starts
/// over. The first read only looks at the last 256 KB, a call reads at most 1 MB, and an unterminated line over
/// 64 KB is emitted as a line.
#[derive(Debug)]
pub struct LogTailer {
    pub path: PathBuf,
    offset: u64,
    partial: Vec<u8>,
    started: bool,
    inode: Option<u64>,
    /// Starting in the middle of the window, the first (truncated) line is dropped.
    discard_leading: bool,
}

pub const INITIAL_WINDOW: u64 = 256 * 1024;
pub const MAX_READ_BYTES: usize = 1024 * 1024;
pub const MAX_PARTIAL_BYTES: usize = 64 * 1024;

/// `String(decoding:as: UTF8.self).components(separatedBy: "\n")`.
fn decode_lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(bytes).split('\n').map(str::to_string).collect()
}

impl LogTailer {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        LogTailer {
            path: path.into(),
            offset: 0,
            partial: Vec::new(),
            started: false,
            inode: None,
            discard_leading: false,
        }
    }

    pub fn read_new(&mut self) -> Vec<String> {
        let Ok(mut file) = File::open(&self.path) else { return Vec::new() };
        let ino = file.metadata().ok().map(|m| m.ino());
        if let (Some(old), Some(new)) = (self.inode, ino)
            && old != new
        {
            self.offset = 0;
            self.partial.clear();
            self.discard_leading = false;
            self.started = false; // the 256 KB window applies to the new file too
        }
        self.inode = ino;
        let size = file.seek(SeekFrom::End(0)).unwrap_or(0);
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
        if file.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }
        let mut data = Vec::new();
        let _ = (&mut file).take(MAX_READ_BYTES as u64).read_to_end(&mut data);
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
