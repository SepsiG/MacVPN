//! The Log tab without a UI (port of `LogViewModel`, `LogView`'s filtering and `NativeLogCollector`): the live
//! tail of the helper's log (core `LogTailer` over the helper's `LogSource`; on macOS `/var/log/macvpn/<id>.log`)
//! or, for a native connection, the system log collected during a debug connect (`log stream`, at most 60 s,
//! stopped once the connection settles), kept to the last 5000 lines, with the All / Commands / Errors filter,
//! the search and the time range (each line's time read from the log formats; a line without one has the time of
//! the line before it).

use crate::deps::Clock;
use macvpn_core::date::Date;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::log::{FileLogSource, LogFilter, LogLine, LogLineKind, LogSource, LogTailer};
use macvpn_core::models::{Connection, ConnectionState};
use macvpn_platform_api::{HelperClient, NativeController};
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use uuid::Uuid;

/// The view keeps this many lines (the oldest are dropped).
pub const MAX_LINES: usize = 5000;
/// The view polls the log file this often.
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);

// MARK: - Lines and filtering

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogLineView {
    pub text: String,
    /// `header`, `step`, `command`, `error` or `output` (the colour).
    pub kind: &'static str,
    /// The line's local time as [`civil_seconds`] (its own or the previous line's); `null`: none known.
    pub time: Option<i64>,
}

pub fn kind_name(kind: LogLineKind) -> &'static str {
    match kind {
        LogLineKind::Header => "header",
        LogLineKind::Step => "step",
        LogLineKind::Command => "command",
        LogLineKind::Error => "error",
        LogLineKind::Output => "output",
    }
}

impl From<&LogEntry> for LogLineView {
    fn from(entry: &LogEntry) -> Self {
        LogLineView { text: entry.line.text.clone(), kind: kind_name(entry.line.kind), time: entry.time }
    }
}

pub fn parse_filter(raw: &str) -> Option<LogFilter> {
    LogFilter::ALL.into_iter().find(|f| f.raw_value() == raw)
}

/// `localizedCaseInsensitiveContains` (an empty search matches everything).
pub fn matches_search(text: &str, search: &str) -> bool {
    search.is_empty() || text.to_lowercase().contains(&search.to_lowercase())
}

// MARK: - Line times

/// A local wall-clock time as seconds since 1970-01-01 00:00 of the same wall clock (no time zone: the logs write
/// local time, and the UI computes its bounds the same way). `None`: not a valid date and time.
pub fn civil_seconds(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> Option<i64> {
    let valid = (1970..=9999).contains(&y)
        && (1..=12).contains(&mo)
        && (1..=31).contains(&d)
        && (0..24).contains(&h)
        && (0..60).contains(&mi)
        && (0..=60).contains(&s);
    valid.then(|| macvpn_core::date::days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s)
}

/// `n` ASCII digits at `at` as a number.
fn digits(b: &[u8], at: usize, n: usize) -> Option<i64> {
    let part = b.get(at..at + n)?;
    part.iter().all(u8::is_ascii_digit).then(|| part.iter().fold(0, |v, d| v * 10 + i64::from(d - b'0')))
}

/// `YYYY<sep>MM<sep>DD<T or space>HH:MM:SS` at `at` (`sep`: `-` or `/`).
fn date_time_at(b: &[u8], at: usize, sep: u8) -> Option<i64> {
    let y = digits(b, at, 4)?;
    (b.get(at + 4) == Some(&sep) && b.get(at + 7) == Some(&sep)).then_some(())?;
    let (mo, d) = (digits(b, at + 5, 2)?, digits(b, at + 8, 2)?);
    let t = *b.get(at + 10)?;
    (t == b' ' || (t == b'T' && sep == b'-')).then_some(())?;
    clock_at(b, at + 11).and_then(|(h, mi, s)| civil_seconds(y, mo, d, h, mi, s))
}

/// `HH:MM:SS` at `at`.
fn clock_at(b: &[u8], at: usize) -> Option<(i64, i64, i64)> {
    (b.get(at + 2) == Some(&b':') && b.get(at + 5) == Some(&b':')).then_some(())?;
    Some((digits(b, at, 2)?, digits(b, at + 3, 2)?, digits(b, at + 6, 2)?))
}

const MONTHS: [&[u8]; 12] =
    [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

/// pppd's `Www Mmm d HH:MM:SS YYYY` (`%a %b %e %T %Y`) at the start of `b`.
fn pppd_time(b: &[u8]) -> Option<i64> {
    let (week, rest) = (b.get(..3)?, b.get(3..)?);
    (week.iter().all(u8::is_ascii_alphabetic) && rest.first() == Some(&b' ')).then_some(())?;
    let mo = MONTHS.iter().position(|m| rest.get(1..4) == Some(m))? as i64 + 1;
    let mut i = 4;
    (rest.get(i) == Some(&b' ')).then_some(())?;
    while rest.get(i) == Some(&b' ') {
        i += 1;
    }
    let width = if rest.get(i + 1).is_some_and(u8::is_ascii_digit) { 2 } else { 1 };
    let d = digits(rest, i, width)?;
    i += width;
    (rest.get(i) == Some(&b' ')).then_some(())?;
    let (h, mi, s) = clock_at(rest, i + 1)?;
    (rest.get(i + 9) == Some(&b' ')).then_some(())?;
    civil_seconds(digits(rest, i + 10, 4)?, mo, d, h, mi, s)
}

/// The helper's prefix of a copied tool line (`[pppd] `): a short lower-case tag in brackets.
fn tool_prefix(b: &[u8]) -> usize {
    let tag = |t: &[u8]| !t.is_empty() && t.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-');
    match b.iter().take(18).position(|&c| c == b']') {
        Some(end) if b[0] == b'[' && tag(&b[1..end]) && b.get(end + 1) == Some(&b' ') => end + 2,
        _ => 0,
    }
}

/// How far into a line Go's log time is looked for (`DEBUG: (utun12) ` and the like).
const GO_PREFIX_MAX: usize = 40;

/// The time a log line starts with, in the formats the logs contain: OpenVPN's and `log stream`'s
/// `YYYY-MM-DD HH:MM:SS` (also with `T`), wireguard-go's `LEVEL: (iface) YYYY/MM/DD HH:MM:SS`, pppd's
/// `Www Mmm d HH:MM:SS YYYY` (after the helper's `[pppd] ` too), and a header line (`═══ … ═══`: the helper's and
/// the RAS engine's connect header, the clear note) with a `YYYY-MM-DD HH:MM:SS` anywhere. A date elsewhere in a
/// line is its text, not its time.
pub fn line_time(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if text.starts_with("═══") {
        return (0..b.len()).find_map(|i| date_time_at(b, i, b'-').filter(|_| i == 0 || b[i - 1] == b' '));
    }
    let start = tool_prefix(b);
    let b = &b[start..];
    if let Some(t) = date_time_at(b, 0, b'-').or_else(|| pppd_time(b)) {
        return Some(t);
    }
    (0..b.len().min(GO_PREFIX_MAX)).find_map(|i| date_time_at(b, i, b'/').filter(|_| i == 0 || b[i - 1] == b' '))
}

/// The time range of the view (inclusive, as [`civil_seconds`]); both `None`: every line. With a bound, a line
/// without a known time is outside.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimeRange {
    pub from: Option<i64>,
    pub to: Option<i64>,
}

/// The largest bound the UI may send (year 9999).
const BOUND_MAX: f64 = 253_402_300_800.0;

impl TimeRange {
    /// The bounds as the UI sends them (whole seconds); `None`: not a valid bound.
    pub fn from_bounds(from: Option<f64>, to: Option<f64>) -> Option<TimeRange> {
        let check = |v: Option<f64>| match v {
            None => Some(None),
            Some(v) if v.is_finite() && v.fract() == 0.0 && v.abs() <= BOUND_MAX => Some(Some(v as i64)),
            Some(_) => None,
        };
        Some(TimeRange { from: check(from)?, to: check(to)? })
    }

    pub fn contains(&self, time: Option<i64>) -> bool {
        if self.from.is_none() && self.to.is_none() {
            return true;
        }
        time.is_some_and(|t| self.from.is_none_or(|f| t >= f) && self.to.is_none_or(|to| t <= to))
    }
}

/// A kept line and its time ([`line_time`], or the previous line's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub line: LogLine,
    pub time: Option<i64>,
}

/// The lines the view shows.
pub fn visible<'a>(
    entries: impl IntoIterator<Item = &'a LogEntry>,
    filter: LogFilter,
    search: &str,
    range: TimeRange,
) -> Vec<&'a LogEntry> {
    entries
        .into_iter()
        .filter(|e| e.line.matches(filter) && range.contains(e.time) && matches_search(&e.line.text, search))
        .collect()
}

/// The last [`MAX_LINES`] lines.
#[derive(Debug, Default, Clone)]
pub struct LogBuffer {
    lines: VecDeque<LogEntry>,
    /// The time of the newest line (what the next line without its own time gets).
    last_time: Option<i64>,
}

impl LogBuffer {
    pub fn append(&mut self, new: impl IntoIterator<Item = LogLine>) {
        for line in new {
            let time = line_time(&line.text).or(self.last_time);
            self.last_time = time;
            self.lines.push_back(LogEntry { line, time });
        }
        while self.lines.len() > MAX_LINES {
            self.lines.pop_front();
        }
    }

    pub fn clear(&mut self) {
        self.lines.clear();
        self.last_time = None;
    }

    pub fn lines(&self) -> impl Iterator<Item = &LogLine> {
        self.lines.iter().map(|e| &e.line)
    }

    pub fn entries(&self) -> impl DoubleEndedIterator<Item = &LogEntry> + ExactSizeIterator {
        self.lines.iter()
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// The text "Copy" puts on the pasteboard: the visible lines.
    pub fn visible_text(&self, filter: LogFilter, search: &str, range: TimeRange) -> String {
        visible(&self.lines, filter, search, range).iter().map(|e| e.line.text.as_str()).collect::<Vec<_>>().join("\n")
    }

    /// The text "Save…" writes: every kept line.
    pub fn all_text(&self) -> String {
        self.lines.iter().map(|e| e.line.text.as_str()).collect::<Vec<_>>().join("\n")
    }
}

// MARK: - Native debug log collection

/// The collection's upper limit.
pub const NATIVE_LOG_MAX_SECONDS: f64 = 60.0;

/// The system's log stream: defined in `macvpn-platform-api` and re-exported here (their old home).
pub use macvpn_platform_api::{LogStreamSpawner, StreamHandle};

#[derive(Default)]
struct CollectorState {
    lines: VecDeque<String>,
    /// Lines ever appended since the last start (the view's cursor).
    total: u64,
    /// Starts so far: a new start replaces the lines.
    epoch: u64,
    /// Every start and stop takes a new one: late output or a late timer of an earlier run is ignored.
    generation: u64,
    handle: Option<Box<dyn StreamHandle>>,
}

impl CollectorState {
    fn push(&mut self, line: String) {
        self.lines.push_back(line);
        self.total += 1;
        while self.lines.len() > MAX_LINES {
            self.lines.pop_front();
        }
    }
}

/// Collects the system log during a native (L2TP / Cisco) debug connect, for at most 60 s.
pub struct NativeLogCollector {
    state: Arc<Mutex<CollectorState>>,
    spawner: Arc<dyn LogStreamSpawner>,
    /// The header's date (`Date().formatted(date: .numeric, time: .standard)`).
    timestamp: Arc<dyn Fn(Date) -> String + Send + Sync>,
    clock: Arc<dyn Clock>,
    max_duration: Duration,
}

impl NativeLogCollector {
    pub fn new(
        spawner: Arc<dyn LogStreamSpawner>,
        timestamp: Arc<dyn Fn(Date) -> String + Send + Sync>,
        clock: Arc<dyn Clock>,
        max_duration: Duration,
    ) -> Self {
        NativeLogCollector { state: Arc::default(), spawner, timestamp, clock, max_duration }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CollectorState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn generation(&self) -> u64 {
        self.lock().generation
    }

    pub fn is_running(&self) -> bool {
        self.lock().handle.is_some()
    }

    /// The platform has a system log stream to collect ([`LogStreamSpawner::is_available`]).
    pub fn is_available(&self) -> bool {
        self.spawner.is_available()
    }

    /// Starts a new collection (stopping a running one). Returns its generation.
    pub fn start(&self) -> u64 {
        self.stop();
        let current = {
            let mut s = self.lock();
            s.generation += 1;
            s.epoch += 1;
            s.lines.clear();
            s.total = 0;
            let header = format!("═══ {} {} ═══", (self.timestamp)(self.clock.now()), l10n::tr("native debug", &[]));
            s.push(header);
            s.push(format!("$ {}", self.spawner.command_line()));
            s.generation
        };
        let output = Arc::downgrade(&self.state);
        let ended = Arc::downgrade(&self.state);
        let spawned = self.spawner.spawn(
            Box::new(move |lines| {
                let Some(state) = output.upgrade() else { return };
                let mut s = state.lock().unwrap_or_else(PoisonError::into_inner);
                if s.generation == current {
                    for line in lines.into_iter().filter(|l| !l.is_empty()) {
                        s.push(line);
                    }
                }
            }),
            Box::new(move || {
                // After our own stop (a new generation) nothing is reported; only an unexpected end.
                let Some(state) = ended.upgrade() else { return };
                let mut s = state.lock().unwrap_or_else(PoisonError::into_inner);
                if s.generation == current {
                    s.handle = None;
                    s.generation += 1;
                    s.push(format!("▶ [mvpn] {}", l10n::tr("log stream stopped", &[])));
                }
            }),
        );
        match spawned {
            Ok(handle) => {
                let mut s = self.lock();
                if s.generation == current {
                    s.handle = Some(handle);
                } else {
                    handle.stop();
                }
                drop(s);
                let state = Arc::downgrade(&self.state);
                let max = self.max_duration;
                let _ = std::thread::Builder::new().name("macvpn-native-log-limit".into()).spawn(move || {
                    std::thread::sleep(max);
                    if let Some(state) = state.upgrade() {
                        Self::stop_state(&state, Some(current));
                    }
                });
            }
            Err(e) => {
                self.lock().push(format!("✗ {}", l10n::tr("log stream did not start: %@", &[Arg::Str(&e)])));
            }
        }
        current
    }

    /// Stops a running collection ("log collection stopped").
    pub fn stop(&self) {
        Self::stop_state(&self.state, None);
    }

    /// Stops only if `generation` is still the current one (`None`: any).
    pub fn stop_generation(&self, generation: u64) {
        Self::stop_state(&self.state, Some(generation));
    }

    fn stop_state(state: &Mutex<CollectorState>, generation: Option<u64>) {
        let handle = {
            let mut s = state.lock().unwrap_or_else(PoisonError::into_inner);
            if generation.is_some_and(|g| g != s.generation) {
                return;
            }
            let Some(handle) = s.handle.take() else { return };
            // The output still on its way no longer gets in.
            s.generation += 1;
            s.push(format!("▶ [mvpn] {}", l10n::tr("log collection stopped", &[])));
            handle
        };
        handle.stop();
    }

    /// (epoch, total, the lines kept): what a view needs to follow the collection.
    fn snapshot_since(&self, cursor: u64) -> (u64, u64, Vec<String>) {
        let s = self.lock();
        let new = s.total.saturating_sub(cursor).min(s.lines.len() as u64) as usize;
        let lines = s.lines.iter().skip(s.lines.len() - new).cloned().collect();
        (s.epoch, s.total, lines)
    }

    pub fn lines(&self) -> Vec<String> {
        self.lock().lines.iter().cloned().collect()
    }

    /// "Clear Log…": the collected lines are replaced by `note`; a running collection goes on after it. A view
    /// starts over (a new epoch).
    pub fn clear(&self, note: &str) {
        let mut s = self.lock();
        s.lines.clear();
        s.total = 0;
        s.epoch += 1;
        s.push(note.to_string());
    }
}

/// The native connections' collectors (the Swift `nativeLogs`).
pub struct NativeLogs {
    collectors: Mutex<HashMap<Uuid, Arc<NativeLogCollector>>>,
    make: Box<dyn Fn() -> NativeLogCollector + Send + Sync>,
}

impl NativeLogs {
    pub fn new(make: Box<dyn Fn() -> NativeLogCollector + Send + Sync>) -> Self {
        NativeLogs { collectors: Mutex::default(), make }
    }

    pub fn get(&self, id: &Uuid) -> Option<Arc<NativeLogCollector>> {
        self.collectors.lock().unwrap_or_else(PoisonError::into_inner).get(id).cloned()
    }

    /// Starts (or restarts) the connection's collection; returns the collector and the run's generation.
    pub fn start(&self, id: &Uuid) -> (Arc<NativeLogCollector>, u64) {
        let collector = self
            .collectors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(*id)
            .or_insert_with(|| Arc::new((self.make)()))
            .clone();
        let generation = collector.start();
        (collector, generation)
    }

    /// A debug connect's collection: [`Self::start`] where the platform has a system log stream; `None` (nothing
    /// started, nothing kept) where it has none (WinVPN: the native kinds have their own log, see
    /// [`LogFeed::with_native_source`]).
    pub fn start_for_debug(&self, id: &Uuid) -> Option<(Arc<NativeLogCollector>, u64)> {
        let collector = {
            let mut collectors = self.collectors.lock().unwrap_or_else(PoisonError::into_inner);
            match collectors.get(id) {
                Some(c) => c.clone(),
                None => {
                    let c = Arc::new((self.make)());
                    if !c.is_available() {
                        return None;
                    }
                    collectors.insert(*id, c.clone());
                    c
                }
            }
        };
        let generation = collector.start();
        Some((collector, generation))
    }

    pub fn stop(&self, id: &Uuid) {
        if let Some(c) = self.get(id) {
            c.stop();
        }
    }

    /// Stopped and forgotten (the connection was deleted).
    pub fn remove(&self, id: &Uuid) {
        if let Some(c) = self.collectors.lock().unwrap_or_else(PoisonError::into_inner).remove(id) {
            c.stop();
        }
    }
}

/// Native debug: the collection stops once the connection is `connected`, `failed` or `disconnected`, or after
/// 60 s. The state is decided by the manager (its polling refreshes); this only watches it (every 500 ms).
pub fn stop_when_settled(
    collector: &NativeLogCollector,
    generation: u64,
    state: impl Fn() -> ConnectionState,
    clock: &dyn Clock,
    mut sleep: impl FnMut(Duration),
) {
    let deadline = clock.now().adding(NATIVE_LOG_MAX_SECONDS);
    while clock.now().time_interval_since(deadline) < 0.0 && collector.generation() == generation {
        match state() {
            ConnectionState::Connected { .. } | ConnectionState::Failed(_) | ConnectionState::Disconnected => {
                collector.stop_generation(generation);
                return;
            }
            ConnectionState::Connecting | ConnectionState::Disconnecting | ConnectionState::AwaitingAuth(_) => {
                sleep(Duration::from_millis(500))
            }
        }
    }
    collector.stop_generation(generation);
}

// MARK: - Clear Log…

/// The first line of a cleared log: `═══ Log cleared at <time> ═══` (a header: the Commands filter shows it, and
/// [`line_time`] reads its time).
pub use macvpn_core::log::cleared_note;

/// "Clear Log…" of `c`: the log its Log tab shows. A helper kind's log through the helper (macOS: the user's
/// `/var/log/macvpn/<id>.log` and `.1`; WinVPN: the service's or the RAS log); a native kind's own platform log
/// (WinVPN's RAS log), else its debug collection (macOS). `note` ([`cleared_note`]) becomes the first line.
pub fn clear_log(
    c: &Connection,
    helper: &dyn HelperClient,
    native: &dyn NativeController,
    native_logs: &NativeLogs,
    note: &str,
) -> Result<(), String> {
    if !c.kind.is_native() {
        return helper.clear_log(&c.id, note);
    }
    if !native.clear_log(&c.id, note)?
        && let Some(collector) = native_logs.get(&c.id)
    {
        collector.clear(note);
    }
    Ok(())
}

// MARK: - The view's feed

/// New lines for the view; `reset`: replace what it shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogChunk {
    pub reset: bool,
    pub lines: Vec<LogLineView>,
}

enum Source {
    Tail(LogTailer),
    /// The collector being followed (by identity), its epoch and the cursor.
    Native(Option<(Arc<NativeLogCollector>, u64, u64)>),
}

/// The Log tab of one connection: polled every [`POLL_INTERVAL`] while it is shown.
pub struct LogFeed {
    pub id: Uuid,
    source: Source,
    buffer: LogBuffer,
    native_logs: Arc<NativeLogs>,
    started: bool,
}

impl LogFeed {
    /// `source`: the helper's log of the connection (macOS: the root layer's `/var/log/macvpn/<id>.log`; `None`:
    /// the helper keeps none, which reads nothing). A native connection follows its debug collection.
    pub fn new(c: &Connection, source: Option<Box<dyn LogSource>>, native_logs: Arc<NativeLogs>) -> LogFeed {
        LogFeed::with_native_source(c, source, None, native_logs)
    }

    /// [`Self::new`], with the platform's own log of a native connection (`NativeController::log_source`; WinVPN:
    /// the RAS log): `Some` is tailed as a helper kind's log is; `None` (macOS) follows the debug collection.
    pub fn with_native_source(
        c: &Connection,
        source: Option<Box<dyn LogSource>>,
        native_source: Option<Box<dyn LogSource>>,
        native_logs: Arc<NativeLogs>,
    ) -> LogFeed {
        let source = if c.kind.is_native()
            && let Some(native) = native_source
        {
            Source::Tail(LogTailer::with_source(native))
        } else if c.kind.is_native() {
            Source::Native(None)
        } else {
            // An empty path opens nothing.
            let source = source.unwrap_or_else(|| Box::new(FileLogSource { path: PathBuf::new() }));
            Source::Tail(LogTailer::with_source(source))
        };
        LogFeed { id: c.id, source, buffer: LogBuffer::default(), native_logs, started: false }
    }

    pub fn buffer(&self) -> &LogBuffer {
        &self.buffer
    }

    /// The new lines since the last poll (`None`: nothing changed).
    pub fn poll(&mut self) -> Option<LogChunk> {
        let first = !std::mem::replace(&mut self.started, true);
        let (reset, new): (bool, Vec<String>) = match &mut self.source {
            Source::Tail(tailer) => (first, tailer.read_new()),
            Source::Native(following) => {
                let current = self.native_logs.get(&self.id);
                let same = match (&*following, &current) {
                    (Some((a, epoch, _)), Some(b)) => Arc::ptr_eq(a, b) && b.lock().epoch == *epoch,
                    (None, None) => !first,
                    _ => false,
                };
                if same {
                    let (collector, _, cursor) = following.as_mut()?;
                    let (_, total, lines) = collector.snapshot_since(*cursor);
                    *cursor = total;
                    (false, lines)
                } else if let Some(collector) = current {
                    let (epoch, total, lines) = collector.snapshot_since(0);
                    *following = Some((collector, epoch, total));
                    (true, lines)
                } else {
                    *following = None;
                    let message = l10n::tr("Native connections only have a log when connected in debug mode.", &[]);
                    (true, vec![format!("▶ [mvpn] {message}")])
                }
            }
        };
        if !reset && new.is_empty() {
            return None;
        }
        let count = new.len().min(MAX_LINES);
        if reset {
            self.buffer.clear();
        }
        // Every line goes through the buffer (a line's time may come from one before it); only what the view
        // keeps is sent.
        self.buffer.append(new.into_iter().map(LogLine::new));
        let views = self.buffer.entries().skip(self.buffer.len() - count).map(LogLineView::from).collect();
        Some(LogChunk { reset, lines: views })
    }
}
