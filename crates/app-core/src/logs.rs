//! The Log tab without a UI (port of `LogViewModel`, `LogView`'s filtering and `NativeLogCollector`): the live
//! tail of `/var/log/macvpn/<id>.log` (core `LogTailer`) or, for a native connection, the system log collected
//! during a debug connect (`log stream`, at most 60 s, stopped once the connection settles), kept to the last
//! 5000 lines, with the All / Commands / Errors filter and the search.

use crate::deps::Clock;
use macvpn_core::date::Date;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::log::{LogFilter, LogLine, LogLineKind, LogTailer};
use macvpn_core::models::{Connection, ConnectionState};
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

impl From<&LogLine> for LogLineView {
    fn from(line: &LogLine) -> Self {
        LogLineView { text: line.text.clone(), kind: kind_name(line.kind) }
    }
}

pub fn parse_filter(raw: &str) -> Option<LogFilter> {
    LogFilter::ALL.into_iter().find(|f| f.raw_value() == raw)
}

/// `localizedCaseInsensitiveContains` (an empty search matches everything).
pub fn matches_search(text: &str, search: &str) -> bool {
    search.is_empty() || text.to_lowercase().contains(&search.to_lowercase())
}

/// The lines the view shows.
pub fn visible<'a>(lines: impl IntoIterator<Item = &'a LogLine>, filter: LogFilter, search: &str) -> Vec<&'a LogLine> {
    lines.into_iter().filter(|l| l.matches(filter) && matches_search(&l.text, search)).collect()
}

/// The last [`MAX_LINES`] lines.
#[derive(Debug, Default, Clone)]
pub struct LogBuffer {
    lines: VecDeque<LogLine>,
}

impl LogBuffer {
    pub fn append(&mut self, new: impl IntoIterator<Item = LogLine>) {
        self.lines.extend(new);
        while self.lines.len() > MAX_LINES {
            self.lines.pop_front();
        }
    }

    pub fn clear(&mut self) {
        self.lines.clear();
    }

    pub fn lines(&self) -> impl Iterator<Item = &LogLine> {
        self.lines.iter()
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// The text "Copy" puts on the pasteboard: the visible lines.
    pub fn visible_text(&self, filter: LogFilter, search: &str) -> String {
        visible(&self.lines, filter, search).iter().map(|l| l.text.as_str()).collect::<Vec<_>>().join("\n")
    }

    /// The text "Save…" writes: every kept line.
    pub fn all_text(&self) -> String {
        self.lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>().join("\n")
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
    /// `log_path`: the root layer's log of the connection (`/var/log/macvpn/<id>.log`).
    pub fn new(c: &Connection, log_path: PathBuf, native_logs: Arc<NativeLogs>) -> LogFeed {
        let source = if c.kind.is_native() { Source::Native(None) } else { Source::Tail(LogTailer::new(log_path)) };
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
        let lines: Vec<LogLine> = new.into_iter().map(LogLine::new).collect();
        if reset {
            self.buffer.clear();
        }
        // Only what the view keeps is sent.
        let skip = lines.len().saturating_sub(MAX_LINES);
        let views = lines[skip..].iter().map(LogLineView::from).collect();
        self.buffer.append(lines.into_iter().skip(skip));
        Some(LogChunk { reset, lines: views })
    }
}
