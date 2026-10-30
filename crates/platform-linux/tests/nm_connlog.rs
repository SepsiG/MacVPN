#![cfg(target_os = "linux")]
//! L-b Task 19: the logd client, the connection log and the journal pump (resolved point 11), against a fake
//! `linvpn-logd` on a socket in a temp dir.

use macvpn_core::logd::{Line, Request, Response, Source};
use macvpn_core::models::Secrets;
use macvpn_platform_linux::lin_for_tests::nm::connlog::{self, ConnLog, Masker};
use macvpn_platform_linux::lin_for_tests::nm::logd_client::{self, LogdError};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const ID: &str = "0b5f7c1e-2d3a-4b5c-8d6e-7f8091a2b3c4";
const WITHHELD: &str = "Some plugin lines were withheld: another VPN was active at the same time.";
const NO_LOGD: &str = "The system log is not available (linvpn-logd is not installed).";

fn id() -> Uuid {
    Uuid::parse_str(ID).unwrap()
}

fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("linvpn-nm-connlog-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn mode(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

/// A fake `linvpn-logd`: answers each connection with the next canned bytes (the last one repeated), recording
/// the requests it read.
struct FakeLogd {
    requests: Arc<Mutex<Vec<String>>>,
}

impl FakeLogd {
    fn start(sock: &Path, answers: Vec<Vec<u8>>) -> FakeLogd {
        let listener = UnixListener::bind(sock).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        thread::spawn(move || {
            for (n, stream) in listener.incoming().enumerate() {
                let Ok(stream) = stream else { return };
                let mut line = String::new();
                let _ = BufReader::new(&stream).read_line(&mut line);
                seen.lock().unwrap().push(line);
                let answer = &answers[n.min(answers.len() - 1)];
                let _ = (&stream).write_all(answer);
            }
        });
        FakeLogd { requests }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

fn response(lines: &[(u64, Source, &str)], withheld: bool, cursor: Option<&str>) -> Vec<u8> {
    Response {
        lines: lines
            .iter()
            .map(|(usec, source, text)| Line { usec: *usec, source: source.clone(), text: (*text).into() })
            .collect(),
        withheld,
        cursor: cursor.map(str::to_string),
    }
    .encode()
    .into_bytes()
}

fn request() -> Request {
    Request { connection: id(), since_usec: 1_700_000_000_000_000, cursor: None }
}

fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !ok() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(20));
    }
}

fn read(p: &Path) -> String {
    fs::read_to_string(p).unwrap_or_default()
}

fn is_stamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 19
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b' ',
            13 | 16 => *c == b':',
            _ => c.is_ascii_digit(),
        })
}

// ---- logd_client -------------------------------------------------------------------------------------------------

#[test]
fn a_query_round_trips_a_canned_response() {
    let dir = tmp("roundtrip");
    let sock = dir.join("logd.sock");
    let canned = response(&[(1_700_000_000_000_001, Source::NetworkManager, "starting")], true, Some("s=ab;i=1"));
    let logd = FakeLogd::start(&sock, vec![canned.clone()]);
    let got = logd_client::query_at(&sock, &request()).unwrap();
    assert_eq!(got.encode().into_bytes(), canned);
    assert_eq!(logd.requests(), vec![request().encode()]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_response_over_the_bound_is_refused() {
    let dir = tmp("toolarge");
    let sock = dir.join("logd.sock");
    let _logd = FakeLogd::start(&sock, vec![vec![b'L'; 2 * 1024 * 1024]]);
    assert_eq!(logd_client::query_at(&sock, &request()).unwrap_err(), LogdError::TooLarge);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_malformed_response_is_refused() {
    let dir = tmp("malformed");
    let sock = dir.join("logd.sock");
    let _logd = FakeLogd::start(&sock, vec![b"L x nm hi\nE\n".to_vec()]);
    assert_eq!(logd_client::query_at(&sock, &request()).unwrap_err(), LogdError::Malformed);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn no_server_is_unavailable() {
    let dir = tmp("noserver");
    assert_eq!(logd_client::query_at(&dir.join("missing.sock"), &request()).unwrap_err(), LogdError::Unavailable);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_silent_server_times_out() {
    assert_eq!(logd_client::TIMEOUT, Duration::from_secs(5));
    let dir = tmp("timeout");
    let sock = dir.join("logd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let hold = thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_millis(800));
        drop(s);
    });
    let start = Instant::now();
    let err = logd_client::query_within(&sock, &request(), Duration::from_millis(200)).unwrap_err();
    assert_eq!(err, LogdError::Timeout);
    assert!(start.elapsed() < Duration::from_millis(700));
    hold.join().unwrap();
    let _ = fs::remove_dir_all(dir);
}

// ---- ConnLog ---------------------------------------------------------------------------------------------------

#[test]
fn open_creates_a_private_folder_and_file() {
    let dir = tmp("open");
    let logs = dir.join("logs");
    let log = ConnLog::open(&logs, &id());
    assert_eq!(log.path, logs.join("0B5F7C1E-2D3A-4B5C-8D6E-7F8091A2B3C4.log"));
    assert_eq!(mode(&logs), 0o700);
    assert_eq!(mode(&log.path), 0o600);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_line_starts_with_the_local_time() {
    let dir = tmp("line");
    let log = ConnLog::open(&dir.join("logs"), &id());
    log.line("Connecting");
    let text = read(&log.path);
    assert!(text.ends_with(" Connecting\n"), "{text:?}");
    assert!(is_stamp(&text[..19]), "{text:?}");
    assert_eq!(text.len(), 19 + " Connecting\n".len());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn the_masker_hides_the_connections_secrets() {
    let secrets = Secrets {
        password: Some("hunter22".into()),
        psk: Some("ab".into()),
        one_time_code: Some("123456".into()),
        ..Default::default()
    };
    let m = Masker::new(&secrets);
    assert_eq!(m.line("auth hunter22+123456 ok"), "auth ***+*** ok");
    // A short secret only as a whole token.
    assert_eq!(m.line("psk ab, tab"), "psk ***, tab");
    let dir = tmp("mask");
    let log = ConnLog::open(&dir.join("logs"), &id());
    log.line(&m.line("password hunter22"));
    let text = read(&log.path);
    assert!(text.ends_with(" password ***\n") && !text.contains("hunter22"), "{text:?}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn the_file_is_capped_by_dropping_its_oldest_half() {
    assert_eq!(connlog::LOG_MAX, 5_242_880);
    let dir = tmp("cap");
    let log = ConnLog::open_capped(&dir.join("logs"), &id(), 1000);
    for i in 0..200 {
        log.line(&format!("line {i:04}"));
    }
    let text = read(&log.path);
    assert!(text.len() <= 1000, "{}", text.len());
    assert!(text.len() >= 400, "{}", text.len());
    assert!(text.ends_with(" line 0199\n"));
    assert!(!text.contains("line 0000"));
    assert!(text.lines().all(|l| is_stamp(&l[..19])), "cut on a line start");
    let _ = fs::remove_dir_all(dir);
}

// ---- the journal pump ------------------------------------------------------------------------------------------

#[test]
fn the_pump_appends_masked_journal_lines_and_follows_the_cursor() {
    let dir = tmp("pump");
    let sock = dir.join("logd.sock");
    let t1 = 1_700_000_000_250_000u64;
    let first = response(
        &[
            (t1, Source::NetworkManager, "vpn[0x1,x]: starting openvpn"),
            (t1 + 1, Source::OpenVpn, "AUTH: password hunter22"),
            (t1 + 2, Source::Plugin("nm-openvpn-serv".into()), "plugin line"),
        ],
        false,
        Some("s=ab;i=3"),
    );
    let second = response(&[(t1 + 3, Source::NetworkManager, "activated")], true, Some("s=ab;i=4"));
    let quiet = response(&[], true, None);
    let logd = FakeLogd::start(&sock, vec![first, second, quiet]);
    let log = ConnLog::open(&dir.join("logs"), &id());
    let masker = Masker { secrets: vec![zeroize::Zeroizing::new("hunter22".into())] };
    let pump = log.pump_with(id(), masker, &sock, Duration::from_millis(30), Duration::from_millis(100));
    wait_for("three requests", || logd.requests().len() >= 4);

    let text = read(&log.path);
    let stamp = connlog::stamp(t1 as f64 / 1e6);
    assert!(text.contains(&format!("{stamp} [nm] vpn[0x1,x]: starting openvpn\n")), "{text}");
    assert!(text.contains(&format!("{stamp} [openvpn] AUTH: password ***\n")), "{text}");
    assert!(text.contains(&format!("{stamp} [nm-openvpn-serv] plugin line\n")), "{text}");
    assert!(text.contains(" [nm] activated\n"), "{text}");
    assert!(!text.contains("hunter22"));
    assert_eq!(text.matches(WITHHELD).count(), 1, "{text}");

    let reqs = logd.requests();
    let parsed: Vec<Request> = reqs.iter().map(|r| Request::parse(r).expect("a valid request")).collect();
    assert!(parsed.iter().all(|r| r.connection == id()));
    assert_eq!(parsed[0].cursor, None);
    assert_eq!(parsed[1].cursor.as_deref(), Some("s=ab;i=3"));
    assert_eq!(parsed[2].cursor.as_deref(), Some("s=ab;i=4"));
    assert_eq!(parsed[3].cursor.as_deref(), Some("s=ab;i=4"), "an empty answer keeps the cursor");

    // It keeps asking for the linger time after the guard is dropped, then stops.
    drop(pump);
    thread::sleep(Duration::from_millis(400));
    let n = logd.requests().len();
    thread::sleep(Duration::from_millis(300));
    assert_eq!(logd.requests().len(), n, "the pump stopped");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn secrets_handed_over_later_are_masked_from_then_on() {
    // An adopted tunnel's pump starts without the secrets (the vault is still locked); app-core hands them over.
    let dir = tmp("later");
    let sock = dir.join("logd.sock");
    let t1 = 1_700_000_000_250_000u64;
    let quiet = response(&[], false, None);
    let line = response(&[(t1, Source::OpenVpn, "AUTH: password hunter22")], false, Some("s=ab;i=1"));
    let logd = FakeLogd::start(&sock, vec![quiet, line]);
    let log = ConnLog::open(&dir.join("logs"), &id());
    let pump = log.pump_with(id(), Masker::default(), &sock, Duration::from_millis(300), Duration::from_millis(50));
    wait_for("the first request", || !logd.requests().is_empty());
    pump.add_secrets(&macvpn_core::models::Secrets { password: Some("hunter22".into()), ..Default::default() });
    wait_for("the line", || read(&log.path).contains("AUTH: password"));
    let text = read(&log.path);
    assert!(text.contains("AUTH: password ***"), "{text}");
    assert!(!text.contains("hunter22"), "{text}");
    drop(pump);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn the_pump_says_once_that_logd_is_missing() {
    let dir = tmp("nologd");
    let log = ConnLog::open(&dir.join("logs"), &id());
    let pump = log.pump_with(
        id(),
        Masker::default(),
        &dir.join("missing.sock"),
        Duration::from_millis(20),
        Duration::from_millis(50),
    );
    thread::sleep(Duration::from_millis(200));
    drop(pump);
    thread::sleep(Duration::from_millis(150));
    let text = read(&log.path);
    assert_eq!(text.matches(NO_LOGD).count(), 1, "{text}");
    assert!(is_stamp(&text[..19]));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_cleared_log_keeps_receiving_new_lines() {
    let dir = tmp("clear");
    let log = ConnLog::open(&dir.join("logs"), &id());
    log.line("before");
    let owner = macvpn_core::fsx::FileOwner::from_uid(std::os::unix::fs::MetadataExt::uid(
        &fs::metadata("/proc/self").unwrap(),
    ));
    assert!(macvpn_core::log::clear_file(&log.path, &owner, Some("═══ cleared ═══")).unwrap());
    log.line("after");
    let text = read(&log.path);
    assert!(text.starts_with("═══ cleared ═══\n") && text.ends_with(" after\n") && !text.contains("before"), "{text}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn the_mark_before_an_activation_is_one_request_from_now_without_a_cursor() {
    let dir = tmp("mark");
    let sock = dir.join("logd.sock");
    let logd = FakeLogd::start(&sock, vec![b"C -\nE\n".to_vec()]);
    let before = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as u64;
    logd_client::mark(Some(&sock), id());
    let requests = logd.requests();
    assert_eq!(requests.len(), 1);
    let r = Request::parse(&requests[0]).unwrap();
    assert_eq!((r.connection, r.cursor), (id(), None));
    assert!(r.since_usec >= before);
    // A missing server costs nothing.
    let t = Instant::now();
    logd_client::mark(Some(&dir.join("none.sock")), id());
    assert!(t.elapsed() < Duration::from_secs(1));
    // A server that never answers costs at most the mark's time limit.
    let _silent = UnixListener::bind(dir.join("silent.sock")).unwrap();
    let t = Instant::now();
    logd_client::mark(Some(&dir.join("silent.sock")), id());
    assert!(t.elapsed() <= logd_client::MARK_TIMEOUT + Duration::from_secs(1));
    fs::remove_dir_all(dir).unwrap();
}
