//! The Log tab without a UI (the Swift `LogViewModel`, `LogView` filtering and `NativeLogCollector`): the 5000-line
//! cap, filter and search, the file tail, the native collection with its generations, 60 s cap and settle stop.

mod common;

use common::*;
use macvpn_app_core::deps::{Clock, ManualClock};
use macvpn_app_core::logs::{
    self, LogBuffer, LogFeed, LogStreamSpawner, MAX_LINES, NativeLogCollector, NativeLogs, StreamHandle,
};
use macvpn_core::date::Date;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::log::{FileLogSource, LogFilter, LogLine};
use macvpn_core::models::{Connection, ConnectionState, VPNKind};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[test]
fn buffer_keeps_the_last_5000_lines() {
    let mut b = LogBuffer::default();
    b.append((0..MAX_LINES + 10).map(|i| LogLine::new(format!("line {i}"))));
    assert_eq!(b.len(), MAX_LINES);
    assert_eq!(b.lines().next().unwrap().text, "line 10");
}

#[test]
fn filter_and_search() {
    let mut b = LogBuffer::default();
    b.append(
        ["═══ start ═══", "▶ [mvpn] step", "$ openvpn --config x", "AUTH_FAILED", "plain Output"].map(LogLine::new),
    );
    assert_eq!(b.visible_text(LogFilter::Errors, "", logs::TimeRange::default()), "AUTH_FAILED");
    assert_eq!(
        b.visible_text(LogFilter::Commands, "", logs::TimeRange::default()),
        "═══ start ═══\n▶ [mvpn] step\n$ openvpn --config x"
    );
    assert_eq!(b.visible_text(LogFilter::All, "output", logs::TimeRange::default()), "plain Output");
    assert_eq!(b.visible_text(LogFilter::Commands, "OPENVPN", logs::TimeRange::default()), "$ openvpn --config x");
    assert_eq!(b.all_text().lines().count(), 5);
    assert_eq!(logs::parse_filter("errors"), Some(LogFilter::Errors));
    assert_eq!(logs::parse_filter("Errors"), None);
}

fn spawner_never() -> Arc<dyn LogStreamSpawner> {
    Arc::new(FakeSpawner::default())
}

fn native_logs(spawner: Arc<dyn LogStreamSpawner>) -> Arc<NativeLogs> {
    Arc::new(NativeLogs::new(Box::new(move || collector(spawner.clone(), Duration::from_secs(60)))))
}

fn collector(spawner: Arc<dyn LogStreamSpawner>, max: Duration) -> NativeLogCollector {
    NativeLogCollector::new(spawner, Arc::new(|_| "DATE".to_string()), clock_at(0.0), max)
}

#[test]
fn file_feed_tails_new_lines() {
    let dir = TempDir::new();
    std::fs::create_dir_all(dir.path()).unwrap();
    let path = dir.path().join("x.log");
    let c = Connection::new("A", VPNKind::Openvpn);
    let mut feed = LogFeed::new(&c, Some(Box::new(FileLogSource { path: path.clone() })), native_logs(spawner_never()));
    let first = feed.poll().unwrap();
    assert!(first.reset && first.lines.is_empty(), "the first poll resets even without a file");
    assert_eq!(feed.poll(), None);
    std::fs::write(&path, "═══ header ═══\nAUTH_FAILED\npartial").unwrap();
    let chunk = feed.poll().unwrap();
    assert!(!chunk.reset);
    assert_eq!(
        chunk.lines.iter().map(|l| (l.text.as_str(), l.kind)).collect::<Vec<_>>(),
        [("═══ header ═══", "header"), ("AUTH_FAILED", "error")]
    );
    std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b" line\n").unwrap();
    assert_eq!(feed.poll().unwrap().lines[0].text, "partial line");
    assert_eq!(feed.buffer().len(), 3);
}

type Sink = (Box<dyn FnMut(Vec<String>) + Send>, Option<Box<dyn FnOnce() + Send>>);

#[derive(Default)]
struct FakeSpawner {
    sinks: Mutex<Vec<Sink>>,
    stops: Arc<Mutex<usize>>,
    fail: bool,
}

struct FakeHandle(Arc<Mutex<usize>>);

impl StreamHandle for FakeHandle {
    fn stop(&self) {
        *self.0.lock().unwrap() += 1;
    }
}

impl LogStreamSpawner for FakeSpawner {
    fn command_line(&self) -> String {
        r#"log stream --style compact --predicate 'process IN {"racoon","pppd","neagent","nesessionmanager"} OR subsystem == "com.apple.networkextension"'"#.into()
    }

    fn spawn(
        &self,
        on_lines: Box<dyn FnMut(Vec<String>) + Send>,
        on_exit: Box<dyn FnOnce() + Send>,
    ) -> Result<Box<dyn StreamHandle>, String> {
        if self.fail {
            return Err("no such file".into());
        }
        self.sinks.lock().unwrap().push((on_lines, Some(on_exit)));
        Ok(Box::new(FakeHandle(self.stops.clone())))
    }
}

impl FakeSpawner {
    fn emit(&self, run: usize, lines: &[&str]) {
        let mut sinks = self.sinks.lock().unwrap();
        (sinks[run].0)(lines.iter().map(|s| s.to_string()).collect());
    }

    fn exit(&self, run: usize) {
        let exit = self.sinks.lock().unwrap()[run].1.take().unwrap();
        exit();
    }
}

#[test]
fn native_collection_lines_and_generations() {
    let _fx = Fixture::new(AppLanguage::En);
    let spawner = Arc::new(FakeSpawner::default());
    let c = collector(spawner.clone(), Duration::from_secs(60));
    let g1 = c.start();
    assert_eq!(c.lines()[0], "═══ DATE native debug ═══");
    assert!(c.lines()[1].starts_with("$ log stream --style compact --predicate 'process IN {\"racoon\""));
    spawner.emit(0, &["racoon: phase 1", ""]);
    assert_eq!(c.lines().len(), 3, "empty lines are dropped");
    // A restart: the earlier run's late output is ignored.
    let g2 = c.start();
    assert!(g2 > g1);
    assert_eq!(*spawner.stops.lock().unwrap(), 1);
    spawner.emit(0, &["late"]);
    assert_eq!(c.lines().len(), 2);
    spawner.exit(0);
    assert!(c.is_running(), "the earlier run's end is not this one's");
    // An unexpected end of the current run.
    spawner.exit(1);
    assert!(!c.is_running());
    assert_eq!(c.lines().last().unwrap(), "▶ [mvpn] log stream stopped");
    // Own stop.
    c.start();
    c.stop();
    assert_eq!(c.lines().last().unwrap(), "▶ [mvpn] log collection stopped");
    c.stop();
    assert_eq!(c.lines().iter().filter(|l| l.contains("log collection stopped")).count(), 1);
}

#[test]
fn native_collection_start_failure() {
    let _fx = Fixture::new(AppLanguage::En);
    let c = collector(Arc::new(FakeSpawner { fail: true, ..Default::default() }), Duration::from_secs(60));
    c.start();
    assert_eq!(c.lines().last().unwrap(), "✗ log stream did not start: no such file");
    assert!(!c.is_running());
}

#[test]
fn native_collection_stops_after_its_limit() {
    let _fx = Fixture::new(AppLanguage::En);
    let spawner = Arc::new(FakeSpawner::default());
    let c = collector(spawner.clone(), Duration::from_millis(50));
    c.start();
    for _ in 0..100 {
        if !c.is_running() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!c.is_running());
    assert_eq!(c.lines().last().unwrap(), "▶ [mvpn] log collection stopped");
}

#[test]
fn stop_when_settled_watches_the_state() {
    let _fx = Fixture::new(AppLanguage::En);
    let spawner = Arc::new(FakeSpawner::default());
    let c = collector(spawner.clone(), Duration::from_secs(60));
    let g = c.start();
    let clock = ManualClock::new(Date::from_time_interval_since_1970(0.0));
    let states = Mutex::new(vec![ConnectionState::Connecting, ConnectionState::Connecting]);
    let mut sleeps = 0;
    logs::stop_when_settled(
        &c,
        g,
        || states.lock().unwrap().pop().unwrap_or(ConnectionState::Connected { ip: None, since: None }),
        &clock,
        |_| sleeps += 1,
    );
    assert_eq!(sleeps, 2);
    assert!(!c.is_running());

    // Still connecting after 60 s: stopped by the deadline.
    let g = c.start();
    let mut sleeps = 0;
    logs::stop_when_settled(
        &c,
        g,
        || ConnectionState::Connecting,
        &clock,
        |_| {
            sleeps += 1;
            clock.advance(0.5);
        },
    );
    assert_eq!(sleeps, 120);
    assert!(!c.is_running());
    assert!(clock.now().time_interval_since_1970() >= 60.0);

    // A newer run is not stopped by an older watcher.
    let old = c.start();
    let new = c.start();
    logs::stop_when_settled(&c, old, || ConnectionState::Disconnected, &clock, |_| {});
    assert!(c.is_running());
    assert!(new > old);
}

#[test]
fn native_feed_follows_the_collector() {
    let _fx = Fixture::new(AppLanguage::En);
    let spawner = Arc::new(FakeSpawner::default());
    let natives = native_logs(spawner.clone());
    let c = Connection::new("L2TP", VPNKind::L2tp);
    let mut feed = LogFeed::new(&c, Some(Box::new(FileLogSource { path: "/nonexistent".into() })), natives.clone());
    let first = feed.poll().unwrap();
    assert!(first.reset);
    assert_eq!(first.lines[0].text, "▶ [mvpn] Native connections only have a log when connected in debug mode.");
    assert_eq!(feed.poll(), None);

    natives.start(&c.id);
    let chunk = feed.poll().unwrap();
    assert!(chunk.reset);
    assert_eq!(chunk.lines.len(), 2);
    spawner.emit(0, &["pppd: hello"]);
    let chunk = feed.poll().unwrap();
    assert!(!chunk.reset);
    assert_eq!(chunk.lines[0].text, "pppd: hello");
    assert_eq!(feed.poll(), None);
    // A new debug connect replaces the lines.
    natives.start(&c.id);
    assert!(feed.poll().unwrap().reset);
    natives.remove(&c.id);
    assert!(feed.poll().unwrap().lines[0].text.contains("only have a log"));
}

/// A platform without a system log stream (WinVPN's `log_streams`).
struct NoStream;

impl LogStreamSpawner for NoStream {
    fn command_line(&self) -> String {
        String::new()
    }

    fn spawn(
        &self,
        _on_lines: Box<dyn FnMut(Vec<String>) + Send>,
        _on_exit: Box<dyn FnOnce() + Send>,
    ) -> Result<Box<dyn StreamHandle>, String> {
        panic!("never spawned where the platform has no stream")
    }

    fn is_available(&self) -> bool {
        false
    }
}

/// G-2 (WinVPN 2c): the platform's own log of a native connection (the RAS log) is tailed like a helper's.
#[test]
fn a_native_connection_with_a_platform_log_is_tailed() {
    let _fx = Fixture::new(AppLanguage::En);
    let dir = TempDir::new();
    std::fs::create_dir_all(dir.path()).unwrap();
    let path = dir.path().join("ras.log");
    std::fs::write(&path, "═══ up l2tp ═══\nConnecting to vpn.example.com…\n").unwrap();
    let c = Connection::new("L2TP", VPNKind::L2tp);
    let helper = Some(Box::new(FileLogSource { path: "/nonexistent".into() }) as Box<dyn macvpn_core::log::LogSource>);
    let native = Some(Box::new(FileLogSource { path: path.clone() }) as Box<dyn macvpn_core::log::LogSource>);
    let mut feed = LogFeed::with_native_source(&c, helper, native, native_logs(spawner_never()));
    let first = feed.poll().unwrap();
    assert!(first.reset);
    assert_eq!(
        first.lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(),
        ["═══ up l2tp ═══", "Connecting to vpn.example.com…"]
    );
    let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
    f.write_all("Connected, IPv4 10.8.0.6\n".as_bytes()).unwrap();
    assert_eq!(feed.poll().unwrap().lines[0].text, "Connected, IPv4 10.8.0.6");
}

/// Without a platform log (macOS) a native connection follows the debug collection, as before.
#[test]
fn a_native_connection_without_one_uses_the_collector() {
    let _fx = Fixture::new(AppLanguage::En);
    let natives = native_logs(spawner_never());
    let c = Connection::new("L2TP", VPNKind::L2tp);
    let helper = Some(Box::new(FileLogSource { path: "/nonexistent".into() }) as Box<dyn macvpn_core::log::LogSource>);
    let mut feed = LogFeed::with_native_source(&c, helper, None, natives);
    let first = feed.poll().unwrap();
    assert_eq!(first.lines[0].text, "▶ [mvpn] Native connections only have a log when connected in debug mode.");
}

#[test]
fn a_debug_connect_starts_no_collector_when_the_platform_has_none() {
    let none = native_logs(Arc::new(NoStream));
    let id = uuid::Uuid::new_v4();
    assert!(none.start_for_debug(&id).is_none());
    assert!(none.get(&id).is_none(), "nothing is kept");

    // macOS: the collection starts as with `start`.
    let spawner = Arc::new(FakeSpawner::default());
    let natives = native_logs(spawner.clone());
    let (collector, generation) = natives.start_for_debug(&id).unwrap();
    assert!(collector.is_running());
    assert_eq!(collector.generation(), generation);
    assert!(Arc::ptr_eq(&natives.get(&id).unwrap(), &collector));
}

// MARK: - Search by time

/// The local wall-clock seconds of a log time (`logs::civil_seconds`).
fn at(h: i64, mi: i64, s: i64) -> i64 {
    logs::civil_seconds(2026, 10, 28, h, mi, s).unwrap()
}

#[test]
fn line_times_are_read_from_the_formats_the_logs_contain() {
    let t = at(14, 3, 5);
    for line in [
        // OpenVPN (macOS run-dir log copied into the user's log; Windows openvpn.exe stdout).
        "2026-10-28 14:03:05 OpenVPN 2.6.12 x86_64-apple-darwin",
        "2026-10-28 14:03:05 us=123456 TCP/UDP: Preserving recently used remote address",
        // The helper's and the RAS engine's headers, and the clear note.
        "═══ 2026-10-28 14:03:05 up openvpn 0F0E0D0C-0B0A-4908-8706-050403020100 (debug) ═══",
        "═══ Log cleared at 2026-10-28 14:03:05 ═══",
        "═══ Napló törölve: 2026-10-28 14:03:05 ═══",
        // wireguard-go (Go's log date and time after its level and interface).
        "DEBUG: (utun5) 2026/10/28 14:03:05 Routine: event worker - started",
        "INFO: (utun5) 2026/10/28 14:03:05 Starting wireguard-go version 0.0.20230223",
        // pppd (SSTP), with the helper's prefix and without.
        "[pppd] Wed Oct 28 14:03:05 2026 : Using interface ppp0",
        "Wed Oct  28 14:03:05 2026 : local  IP address 10.0.0.2",
        // `log stream --style compact` (macOS native debug), an ISO time (the service's own log).
        "2026-10-28 14:03:05.123 Df racoon[123:456] IPSec connecting",
        "2026-10-28T14:03:05Z service started",
    ] {
        assert_eq!(logs::line_time(line), Some(t), "{line}");
    }
    assert_eq!(logs::line_time("Wed Oct  8 14:03:05 2026 : x"), logs::civil_seconds(2026, 10, 8, 14, 3, 5));
    for line in [
        "▶ [mvpn] waiting for the connection",
        "$ openvpn --config x",
        "[#] ip link add mv1 type wireguard",
        "✗ error 691",
        "notAfter 2027-01-01 00:00:00 (a date in the text, not the line's time)",
        "2026-13-28 14:03:05 not a month",
        "2026-10-28 24:03:05 not an hour",
        "2026-10-28 14:03",
        "",
    ] {
        assert_eq!(logs::line_time(line), None, "{line}");
    }
}

#[test]
fn lines_without_a_time_inherit_the_previous_one() {
    let mut b = LogBuffer::default();
    b.append(
        ["no time yet", "2026-10-28 10:00:00 a", "continued a", "2026-10-28 10:10:00 b", "continued b"]
            .map(LogLine::new),
    );
    let times: Vec<Option<i64>> = b.entries().map(|e| e.time).collect();
    assert_eq!(times, [None, Some(at(10, 0, 0)), Some(at(10, 0, 0)), Some(at(10, 10, 0)), Some(at(10, 10, 0))]);
    // Across appends too, until cleared.
    b.append([LogLine::new("later")]);
    assert_eq!(b.entries().last().unwrap().time, Some(at(10, 10, 0)));
    b.clear();
    b.append([LogLine::new("after a clear")]);
    assert_eq!(b.entries().last().unwrap().time, None);
}

#[test]
fn the_time_range_combines_with_the_filter_and_the_search() {
    let mut b = LogBuffer::default();
    b.append(
        [
            "before any time",
            "═══ 2026-10-28 10:00:00 up openvpn X ═══",
            "2026-10-28 10:00:01 AUTH_FAILED early",
            "2026-10-28 10:30:00 middle line",
            "continued middle",
            "2026-10-28 11:00:00 AUTH_FAILED late",
        ]
        .map(LogLine::new),
    );
    let all = logs::TimeRange::default();
    assert_eq!(b.visible_text(LogFilter::All, "", all).lines().count(), 6, "no range: every line");
    let from = logs::TimeRange { from: Some(at(10, 15, 0)), to: None };
    assert_eq!(
        b.visible_text(LogFilter::All, "", from),
        "2026-10-28 10:30:00 middle line\ncontinued middle\n2026-10-28 11:00:00 AUTH_FAILED late"
    );
    let to = logs::TimeRange { from: None, to: Some(at(10, 30, 0)) };
    assert_eq!(
        b.visible_text(LogFilter::All, "", to),
        "═══ 2026-10-28 10:00:00 up openvpn X ═══\n2026-10-28 10:00:01 AUTH_FAILED early\n2026-10-28 10:30:00 middle line\ncontinued middle",
        "the bounds are inclusive; a line without any time is outside every range"
    );
    let both = logs::TimeRange { from: Some(at(10, 0, 0)), to: Some(at(10, 59, 59)) };
    assert_eq!(b.visible_text(LogFilter::Errors, "", both), "2026-10-28 10:00:01 AUTH_FAILED early");
    assert_eq!(b.visible_text(LogFilter::All, "CONTINUED", both), "continued middle");
    assert_eq!(b.visible_text(LogFilter::Commands, "", from), "");
}

#[test]
fn time_bounds_from_the_ui_are_checked() {
    assert_eq!(logs::TimeRange::from_bounds(None, None), Some(logs::TimeRange::default()));
    assert_eq!(
        logs::TimeRange::from_bounds(Some(at(10, 0, 0) as f64), None),
        Some(logs::TimeRange { from: Some(at(10, 0, 0)), to: None })
    );
    assert_eq!(logs::TimeRange::from_bounds(Some(f64::NAN), None), None);
    assert_eq!(logs::TimeRange::from_bounds(None, Some(f64::INFINITY)), None);
    assert_eq!(logs::TimeRange::from_bounds(Some(1.5), None), None);
    assert_eq!(logs::TimeRange::from_bounds(Some(1e18), None), None);
}

#[test]
fn the_feed_sends_each_line_with_its_time() {
    let dir = TempDir::new();
    std::fs::create_dir_all(dir.path()).unwrap();
    let path = dir.path().join("x.log");
    std::fs::write(&path, "head\n2026-10-28 10:00:00 a\nmore\n").unwrap();
    let c = Connection::new("A", VPNKind::Openvpn);
    let mut feed = LogFeed::new(&c, Some(Box::new(FileLogSource { path: path.clone() })), native_logs(spawner_never()));
    let first = feed.poll().unwrap();
    assert_eq!(first.lines.iter().map(|l| l.time).collect::<Vec<_>>(), [None, Some(at(10, 0, 0)), Some(at(10, 0, 0))]);
    std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"still a\n").unwrap();
    assert_eq!(feed.poll().unwrap().lines[0].time, Some(at(10, 0, 0)), "inherited across polls");
    let json = serde_json::to_value(&first.lines[0]).unwrap();
    assert_eq!(json, serde_json::json!({ "text": "head", "kind": "output", "time": null }));
}

// MARK: - Clear Log…

#[test]
fn the_clear_note_is_a_localized_header_with_its_time() {
    let _fx = Fixture::new(AppLanguage::En);
    let note = logs::cleared_note("2026-10-28 14:03:05");
    assert_eq!(note, "═══ Log cleared at 2026-10-28 14:03:05 ═══");
    assert_eq!(LogLine::new(note.clone()).kind, macvpn_core::log::LogLineKind::Header);
    assert_eq!(logs::line_time(&note), Some(at(14, 3, 5)), "the time filter reads the note's time");
    drop(_fx);
    let _fx = Fixture::new(AppLanguage::Hu);
    let note = logs::cleared_note("2026-10-28 14:03:05");
    assert_eq!(note, "═══ Napló törölve: 2026-10-28 14:03:05 ═══");
    assert_eq!(logs::line_time(&note), Some(at(14, 3, 5)));
}

#[test]
fn clearing_a_helper_kind_asks_the_helper_with_the_note() {
    let helper = MockHelper::default();
    let native = MockNative::default();
    let natives = native_logs(spawner_never());
    let c = Connection::new("A", VPNKind::Openvpn);
    logs::clear_log(&c, &helper, &native, &natives, "NOTE").unwrap();
    let calls = helper.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].line, format!("clear-log {}", macvpn_core::models::uuid_string(&c.id)));
    assert_eq!(calls[0].stdin.as_deref(), Some("NOTE"));
    // The helper's refusal is the error.
    helper.respond(&calls[0].line, Err("no"));
    assert_eq!(logs::clear_log(&c, &helper, &native, &natives, "NOTE"), Err("no".to_string()));
}

#[test]
fn clearing_a_native_kind_clears_the_platform_log_or_the_collection() {
    let _fx = Fixture::new(AppLanguage::En);
    let helper = MockHelper::default();
    let native = MockNative::default();
    let spawner = Arc::new(FakeSpawner::default());
    let natives = native_logs(spawner.clone());
    let c = Connection::new("L2TP", VPNKind::L2tp);

    // WinVPN: the platform's own log (the RAS log).
    native.set_own_log(&c.id);
    logs::clear_log(&c, &helper, &native, &natives, "NOTE").unwrap();
    assert_eq!(native.own_log_clears(&c.id), ["NOTE"]);
    assert!(helper.calls().is_empty(), "never the helper for a native kind");

    // macOS: the debug collection, which goes on collecting after the note.
    let c = Connection::new("Cisco", VPNKind::L2tp);
    logs::clear_log(&c, &helper, &native, &natives, "NOTE").unwrap();
    natives.start(&c.id);
    let mut feed = LogFeed::new(&c, None, natives.clone());
    assert_eq!(feed.poll().unwrap().lines.len(), 2);
    spawner.emit(0, &["before"]);
    logs::clear_log(&c, &helper, &native, &natives, "═══ NOTE ═══").unwrap();
    assert_eq!(natives.get(&c.id).unwrap().lines(), ["═══ NOTE ═══"]);
    let chunk = feed.poll().unwrap();
    assert!(chunk.reset, "the view starts over");
    assert_eq!(chunk.lines.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(), ["═══ NOTE ═══"]);
    spawner.emit(0, &["after"]);
    assert_eq!(feed.poll().unwrap().lines[0].text, "after");
    assert!(natives.get(&c.id).unwrap().is_running());
}
