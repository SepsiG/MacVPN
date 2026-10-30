//! `linvpn-logd`'s server (L-b Task 18): one request per connection, the caller's uid from `SO_PEERCRED`, fixed
//! `journalctl` arguments, the caller's own lines only. Against a fake journal (Task 10's fixtures), fake
//! `journalctl` scripts and the binary itself (whose real `journalctl` sees only the test user's own journal).
#![cfg(target_os = "linux")]

use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use macvpn_core::logd::{self, Response, Senders, Source};
use macvpn_core::nm_plan::names;
use macvpn_helper::linux::logd::{self as server, ActiveVpns, Journal, JournalCtl, Served};
use uuid::Uuid;

const ID: &str = "0b5f7c1e-2d3a-4b5c-8d6e-7f8091a2b3c4";
const SINCE: u64 = 1_700_000_000_000_000;
const CURSOR: &str = "s=7a1c0e4b9d2f;i=3";
/// The fixtures' `nm-openvpn` uid (crates/core/tests/fixtures/logd).
const SENDERS: Senders = Senders { nm_openvpn_uid: Some(984) };

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../core/tests/fixtures/logd").join(name)).unwrap()
}

/// A journal that answers with fixed bytes and records every call's arguments.
struct Fake {
    bytes: Vec<u8>,
    calls: Mutex<Vec<Vec<String>>>,
}

impl Fake {
    fn new(bytes: Vec<u8>) -> Fake {
        Fake { bytes, calls: Mutex::new(Vec::new()) }
    }
    fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }
}

impl Journal for Fake {
    fn read(&self, args: &[String]) -> std::io::Result<Vec<u8>> {
        self.calls.lock().unwrap().push(args.to_vec());
        Ok(self.bytes.clone())
    }
}

/// NetworkManager answering with a fixed set of active VPN connections (`None`: no answer).
struct Nm(Option<Vec<String>>);

impl ActiveVpns for Nm {
    fn active_vpns(&self) -> std::io::Result<Vec<String>> {
        self.0.clone().ok_or_else(|| std::io::Error::other("no bus"))
    }
}

const NO_VPN: Nm = Nm(Some(Vec::new()));

fn request(cursor: Option<&str>) -> String {
    logd::Request { connection: Uuid::parse_str(ID).unwrap(), since_usec: SINCE, cursor: cursor.map(String::from) }
        .encode()
}

/// Serves `send` (then half-closes) from `uid`; the raw answer and the server's result.
fn exchange(send: &[u8], uid: u32, journal: &Fake) -> (String, std::io::Result<Served>) {
    let (mut client, srv) = UnixStream::pair().unwrap();
    client.write_all(send).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let result = server::serve(srv, uid, journal, &NO_VPN, &SENDERS);
    let mut out = String::new();
    client.read_to_string(&mut out).unwrap();
    (out, result)
}

#[test]
fn a_valid_request_gets_the_callers_own_lines() {
    let fake = Fake::new(fixture("own.jsonl"));
    let (out, result) = exchange(request(None).as_bytes(), 1001, &fake);
    assert!(out.ends_with("\nE\n"), "{out}");
    let response = Response::parse(&out).unwrap();
    assert_eq!(result.unwrap().lines, 7);
    assert_eq!(response.lines.len(), 7);
    assert!(response.lines.iter().any(|l| matches!(l.source, Source::Plugin(_))), "its plugin line, by NM's history");
    assert!(response.lines.iter().any(|l| l.source == Source::NetworkManager));
    assert!(response.lines.iter().any(|l| l.source == Source::OpenVpn));
    assert!(response.lines.iter().all(|l| !l.text.contains("OTHER") && !l.text.contains("FORGED")), "{out}");
    assert!(response.cursor.is_some());
}

#[test]
fn the_journal_gets_exactly_the_fixed_arguments() {
    let fake = Fake::new(fixture("own.jsonl"));
    let _ = exchange(request(Some(CURSOR)).as_bytes(), 1001, &fake);
    let nm = names::nm_uuid(1001, &Uuid::parse_str(ID).unwrap());
    assert_eq!(
        fake.calls(),
        [logd::journalctl_args(nm, SINCE, Some(CURSOR)), logd::history_args(), logd::observation_args()]
    );
}

#[test]
fn another_uid_gets_no_line() {
    let fake = Fake::new(fixture("own.jsonl"));
    let (out, result) = exchange(request(None).as_bytes(), 1002, &fake);
    assert_eq!(out, "C -\nE\n");
    assert_eq!(result.unwrap().lines, 0);
    let nm = names::nm_uuid(1002, &Uuid::parse_str(ID).unwrap());
    assert_eq!(
        fake.calls(),
        [logd::journalctl_args(nm, SINCE, None), logd::history_args(), logd::observation_args()],
        "the query names only the caller's UUID"
    );
}

#[test]
fn a_bad_request_gets_the_empty_answer_and_reads_no_journal() {
    let valid = request(None);
    let oversized = format!("{}\n", "x".repeat(logd::MAX_REQUEST + 10));
    let mut not_utf8 = valid.clone().into_bytes();
    not_utf8[20] = 0xff;
    let cases: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"hello\n".to_vec(),
        valid.trim_end().as_bytes().to_vec(),
        format!("{valid}junk").into_bytes(),
        format!("{valid}{valid}").into_bytes(),
        oversized.into_bytes(),
        "x".repeat(logd::MAX_REQUEST + 1).into_bytes(),
        not_utf8,
        valid.replace(ID, &ID.to_uppercase()).into_bytes(),
    ];
    for send in cases {
        let fake = Fake::new(fixture("own.jsonl"));
        let (out, result) = exchange(&send, 1001, &fake);
        assert_eq!(out, "C -\nE\n", "{:?}", String::from_utf8_lossy(&send));
        assert_eq!(result.unwrap(), Served::default());
        assert!(fake.calls().is_empty(), "{:?}", String::from_utf8_lossy(&send));
    }
}

#[test]
fn a_request_that_never_ends_is_closed_after_the_timeout() {
    let fake = Fake::new(fixture("own.jsonl"));
    let (mut client, srv) = UnixStream::pair().unwrap();
    client.write_all(b"linvpn-logd-v1 ").unwrap();
    let start = Instant::now();
    let err = server::serve_within(srv, 1001, &fake, &NO_VPN, &SENDERS, Duration::from_millis(300)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(3));
    let mut out = Vec::new();
    client.read_to_end(&mut out).unwrap();
    assert!(out.is_empty(), "no answer");
    assert!(fake.calls().is_empty());
}

#[test]
fn a_trickling_request_cannot_extend_the_timeout() {
    let fake = Fake::new(fixture("own.jsonl"));
    let (mut client, srv) = UnixStream::pair().unwrap();
    let feeder = thread::spawn(move || {
        for b in b"linvpn-logd-v1 0b5f7c1e" {
            if client.write_all(&[*b]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
    });
    let start = Instant::now();
    let err = server::serve_within(srv, 1001, &fake, &NO_VPN, &SENDERS, Duration::from_millis(300)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_millis(900), "{:?}", start.elapsed());
    feeder.join().unwrap();
    assert!(fake.calls().is_empty());
}

#[test]
fn a_journal_failure_gets_the_empty_answer() {
    struct Broken;
    impl Journal for Broken {
        fn read(&self, _: &[String]) -> std::io::Result<Vec<u8>> {
            Err(std::io::Error::other("journalctl exited with 1"))
        }
    }
    let (mut client, srv) = UnixStream::pair().unwrap();
    client.write_all(request(None).as_bytes()).unwrap();
    assert!(server::serve(srv, 1001, &Broken, &NO_VPN, &SENDERS).is_err());
    let mut out = String::new();
    client.read_to_string(&mut out).unwrap();
    assert_eq!(out, "C -\nE\n");
}

#[test]
fn the_peer_uid_of_a_socketpair_is_ours() {
    let (a, _b) = UnixStream::pair().unwrap();
    let ours = std::fs::metadata("/proc/self").unwrap().uid();
    assert_eq!(server::peer_uid(&a).unwrap(), ours);
}

#[test]
fn only_an_af_unix_stream_socket_is_accepted_on_stdin() {
    let (a, _b) = UnixStream::pair().unwrap();
    assert!(server::check_unix_stream(a.as_fd()).is_ok());
    let (d, _e) = UnixDatagram::pair().unwrap();
    assert!(server::check_unix_stream(d.as_fd()).is_err());
    let f = std::fs::File::open("/proc/self/status").unwrap();
    assert!(server::check_unix_stream(f.as_fd()).is_err());
}

#[test]
fn the_nm_openvpn_user_is_looked_up_by_name() {
    assert_eq!(server::user_uid("root"), Some(0));
    assert_eq!(server::user_uid("linvpn-no-such-user"), None);
    assert_eq!(server::user_uid("a\0b"), None);
}

// ---- JournalCtl against fake journalctl scripts ----

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("linvpn-logd-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn script(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("journalctl");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// `read`, retried while another test's fork still holds the fresh script open for writing (ETXTBSY).
fn read_with(j: &JournalCtl, args: &[String]) -> std::io::Result<Vec<u8>> {
    for _ in 0..20 {
        match j.read(args) {
            Err(e) if e.kind() == ErrorKind::ExecutableFileBusy => thread::sleep(Duration::from_millis(50)),
            other => return other,
        }
    }
    j.read(args)
}

#[test]
fn journalctl_runs_with_the_arguments_and_a_cleared_environment() {
    let dir = temp_dir("env");
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../core/tests/fixtures/logd/own.jsonl");
    let body = format!(
        "env > '{d}/env'\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > '{d}/args'\ncat '{f}'",
        d = dir.display(),
        f = fixture_path.display()
    );
    let j = JournalCtl { program: script(&dir, &body), ..JournalCtl::default() };
    let nm = names::nm_uuid(1001, &Uuid::parse_str(ID).unwrap());
    let args = logd::journalctl_args(nm, SINCE, Some(CURSOR));
    assert_eq!(read_with(&j, &args).unwrap(), fixture("own.jsonl"));
    let got: Vec<String> = std::fs::read_to_string(dir.join("args")).unwrap().lines().map(String::from).collect();
    assert_eq!(got, args);
    let env = std::fs::read_to_string(dir.join("env")).unwrap();
    assert!(env.lines().any(|l| l == "LANG=C.UTF-8"), "{env}");
    for leaked in ["HOME=", "USER=", "CARGO", "SSH_", "DBUS_"] {
        assert!(!env.lines().any(|l| l.starts_with(leaked)), "{leaked} leaked: {env}");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_real_journalctl_accepts_a_follow_up_query_with_a_cursor() {
    // A pump's second and later queries carry the cursor of its last line. journalctl refused them while they also
    // had `--since` (lab run 2: a run's log kept only the first answer's lines). The test user's own newest entry
    // gives a real cursor; a runner without a journal has nothing to check.
    let out = Command::new(server::JOURNALCTL)
        .args(["--no-pager", "-n", "1", "-o", "json", "--output-fields=__CURSOR"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let cursor = text.split("\"__CURSOR\":\"").nth(1).and_then(|r| r.split('"').next()).map(String::from);
    let Some(cursor) = cursor else {
        eprintln!("no journal entry readable here: nothing to check");
        return;
    };
    let nm = names::nm_uuid(1001, &Uuid::parse_str(ID).unwrap());
    let args = logd::journalctl_args(nm, SINCE, Some(&cursor));
    assert!(args.contains(&format!("--after-cursor={cursor}")), "{args:?}");
    JournalCtl::default().read(&args).expect("journalctl accepts the follow-up query");
}

#[test]
fn a_hanging_journalctl_is_killed_after_the_timeout() {
    let dir = temp_dir("hang");
    let j = JournalCtl { program: script(&dir, "exec sleep 30"), timeout: Duration::from_millis(300), cap: 1024 };
    let start = Instant::now();
    assert_eq!(read_with(&j, &[]).unwrap_err().kind(), ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn journalctl_output_is_capped_at_a_whole_line() {
    let dir = temp_dir("cap");
    let j = JournalCtl {
        program: script(&dir, "while :; do echo '0123456789abcdef'; done"),
        timeout: Duration::from_secs(10),
        cap: 1000,
    };
    let out = read_with(&j, &[]).unwrap();
    assert!(out.len() <= 1000 && out.len() > 900, "{}", out.len());
    assert!(out.ends_with(b"\n"));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_history_is_whole_or_an_error() {
    let dir = temp_dir("whole");
    let j = JournalCtl {
        program: script(&dir, "while :; do echo '0123456789abcdef'; done"),
        timeout: Duration::from_secs(10),
        cap: 1000,
    };
    let mut r = j.read_whole(&[]);
    for _ in 0..20 {
        match &r {
            Err(e) if e.kind() == ErrorKind::ExecutableFileBusy => {
                thread::sleep(Duration::from_millis(50));
                r = j.read_whole(&[]);
            }
            _ => break,
        }
    }
    assert!(r.is_err(), "a cut history would lose its newest lines");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn without_the_history_no_plugin_line_is_returned() {
    struct NoHistory(Vec<u8>);
    impl Journal for NoHistory {
        fn read(&self, _: &[String]) -> std::io::Result<Vec<u8>> {
            Ok(self.0.clone())
        }
        fn read_whole(&self, _: &[String]) -> std::io::Result<Vec<u8>> {
            Err(std::io::Error::other("too much"))
        }
    }
    // Without NM's start line (only in the history here) nothing is known about other VPNs.
    let lines: Vec<u8> = fixture("own.jsonl")
        .split(|&b| b == b'\n')
        .filter(|l| !l.windows(10).any(|w| w == b"CODE_FUNC\""))
        .flat_map(|l| [l, b"\n"].concat())
        .collect();
    let (mut client, srv) = UnixStream::pair().unwrap();
    client.write_all(request(None).as_bytes()).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    server::serve(srv, 1001, &NoHistory(lines), &NO_VPN, &SENDERS).unwrap();
    let mut out = String::new();
    client.read_to_string(&mut out).unwrap();
    let response = Response::parse(&out).unwrap();
    assert!(response.lines.iter().all(|l| !matches!(l.source, Source::Plugin(_))));
    assert!(response.withheld);
    assert!(response.lines.iter().any(|l| l.source == Source::NetworkManager));
}

#[test]
fn a_failing_journalctl_is_an_error() {
    let dir = temp_dir("fail");
    let j = JournalCtl {
        program: script(&dir, "echo 'No journal files were found.' >&2; exit 1"),
        ..JournalCtl::default()
    };
    assert!(read_with(&j, &[]).is_err());
    let missing = JournalCtl { program: dir.join("missing"), ..JournalCtl::default() };
    assert!(missing.read(&[]).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}

// ---- NetworkManager's active VPN connections: logd's readings ----

const NM_A: &str = "93959792-b4e2-8e81-ae54-6ed8d08d927d";
const NM_B: &str = "4afc4c01-0988-87e3-a22c-93b84ad56c54";

fn nm_line(usec: u64, uuid: &str, rest: &str) -> String {
    format!(
        r#"{{"__REALTIME_TIMESTAMP":"{usec}","__CURSOR":"n={usec}","SYSLOG_IDENTIFIER":"NetworkManager","MESSAGE":"vpn[0x1,{uuid},\"W\"]: {rest}","NM_CONNECTION":"{uuid}","NM_LOG_DOMAINS":"VPN","_UID":"0","_SYSTEMD_UNIT":"NetworkManager.service","_COMM":"NetworkManager"}}"#
    )
}

fn nm_start_line(usec: u64) -> String {
    format!(
        r#"{{"__REALTIME_TIMESTAMP":"{usec}","__CURSOR":"st={usec}","SYSLOG_IDENTIFIER":"NetworkManager","MESSAGE":"NetworkManager (version 1.54.3) is starting... (boot:x)","NM_LOG_DOMAINS":"CORE","CODE_FUNC":"main","_UID":"0","_SYSTEMD_UNIT":"NetworkManager.service","_COMM":"NetworkManager"}}"#
    )
}

fn sstpc_line(usec: u64, msg: &str) -> String {
    format!(
        r#"{{"__REALTIME_TIMESTAMP":"{usec}","__CURSOR":"s={usec}","SYSLOG_IDENTIFIER":"sstpc","MESSAGE":"{msg}","_UID":"0","_COMM":"sstpc"}}"#
    )
}

fn recorded_line(usec: u64, unit: &str, message: &str) -> String {
    format!(
        r#"{{"__REALTIME_TIMESTAMP":"{usec}","__CURSOR":"o={usec}","SYSLOG_IDENTIFIER":"linvpn-logd","MESSAGE":"{message}","_UID":"61234","_SYSTEMD_UNIT":"{unit}"}}"#
    )
}

/// A journal answering each of logd's three queries with its own lines.
struct Routed {
    lines: Vec<String>,
    history: Vec<String>,
    recorded: Vec<String>,
}

impl Journal for Routed {
    fn read(&self, args: &[String]) -> std::io::Result<Vec<u8>> {
        let pick = if args == logd::history_args().as_slice() {
            &self.history
        } else if args == logd::observation_args().as_slice() {
            &self.recorded
        } else {
            &self.lines
        };
        Ok(pick.iter().map(|l| format!("{l}\n")).collect::<String>().into_bytes())
    }
}

fn ask(journal: &Routed, nm: &Nm) -> (Response, Served) {
    let (mut client, srv) = UnixStream::pair().unwrap();
    let r = logd::Request { connection: Uuid::parse_str(ID).unwrap(), since_usec: 0, cursor: None };
    client.write_all(r.encode().as_bytes()).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let served = server::serve(srv, 1001, journal, nm, &SENDERS).unwrap();
    let mut out = String::new();
    client.read_to_string(&mut out).unwrap();
    (Response::parse(&out).unwrap(), served)
}

fn plugin_texts(r: &Response) -> Vec<String> {
    r.lines.iter().filter(|l| matches!(l.source, Source::Plugin(_))).map(|l| l.text.clone()).collect()
}

/// The lab's case: B's earlier VPN has no end line (NM's default level); A's SSTP fails with sstpc's error.
fn lab_case(recorded: Vec<String>) -> Routed {
    let own = vec![nm_line(30, NM_A, "starting sstp"), sstpc_line(31, "OWN certificate verify failed")];
    let mut history = vec![nm_start_line(1), nm_line(5, NM_B, "starting strongswan")];
    history.push(own[0].clone());
    Routed { lines: own, history, recorded }
}

#[test]
fn a_recorded_reading_before_the_activation_lets_the_callers_plugin_lines_through() {
    assert_eq!(NM_A, names::nm_uuid(1001, &Uuid::parse_str(ID).unwrap()).to_string());
    // Without a reading between B's activation and A's: withheld (B may still have been up).
    let (r, _) = ask(&lab_case(vec![]), &NO_VPN);
    assert!(plugin_texts(&r).is_empty() && r.withheld);
    // logd's own reading recorded at A's mark (28..29) shows B gone: A's line is A's.
    let mark = recorded_line(29, "linvpn-logd@7-4242-1001.service", "linvpn-logd-vpns-v1 28 29 -");
    let (r, _) = ask(&lab_case(vec![mark.clone()]), &NO_VPN);
    assert_eq!(plugin_texts(&r), ["OWN certificate verify failed"]);
    assert!(!r.withheld);
    // The same line from anywhere but logd's own unit does not count.
    for unit in ["session-7.scope", "user@1002.service", "linvpn-logd.socket"] {
        let forged = recorded_line(29, unit, "linvpn-logd-vpns-v1 28 29 -");
        let (r, _) = ask(&lab_case(vec![forged]), &NO_VPN);
        assert!(plugin_texts(&r).is_empty(), "{unit}");
    }
}

#[test]
fn a_connection_networkmanager_reports_active_now_withholds_even_without_its_activation_line() {
    // B's activation line was lost (rate limit), but NM lists B now: everything since NM's start is held back.
    let mark = recorded_line(29, "linvpn-logd@7-4242-1001.service", "linvpn-logd-vpns-v1 28 29 -");
    let mut j = lab_case(vec![mark]);
    j.history.retain(|l| !l.contains("starting strongswan"));
    let (r, served) = ask(&j, &Nm(Some(vec![NM_B.to_string()])));
    assert!(plugin_texts(&r).is_empty() && r.withheld);
    assert!(
        served.record.is_some_and(|l| l.starts_with("<5>linvpn-logd-vpns-v1 ") && l.ends_with(&format!(" {NM_B}")))
    );
}

#[test]
fn a_reading_is_recorded_only_when_it_says_something_new() {
    // No reading since NM's start: recorded, with the priority prefix and the clock around the bus call.
    let (_, served) = ask(&lab_case(vec![]), &NO_VPN);
    let line = served.record.expect("the first reading is recorded");
    let o = logd::Observation::parse(line.strip_prefix("<5>").unwrap()).unwrap();
    assert!(o.active.is_empty() && o.before_usec <= o.after_usec && o.before_usec > 1_700_000_000_000_000);
    // The same set as the newest recorded one and no activation since it began: nothing new.
    let newest = recorded_line(o.after_usec, "linvpn-logd@8-1-1001.service", &o.encode());
    let (_, served) = ask(&lab_case(vec![newest.clone()]), &NO_VPN);
    assert_eq!(served.record, None);
    // Another set: recorded.
    let (_, served) = ask(&lab_case(vec![newest]), &Nm(Some(vec![NM_B.to_string()])));
    assert!(served.record.is_some());
    // No answer from NetworkManager: no reading, nothing recorded, the request is still answered.
    let (r, served) = ask(&lab_case(vec![]), &Nm(None));
    assert_eq!(served.record, None);
    assert!(r.withheld && plugin_texts(&r).is_empty());
}

// ---- the binary ----

fn run_binary(stdin: Stdio) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_linvpn-logd"))
        .stdin(stdin)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn the_binary_refuses_a_stdin_that_is_not_a_socket() {
    let child = run_binary(Stdio::piped());
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let child = run_binary(Stdio::null());
    assert_eq!(child.wait_with_output().unwrap().status.code(), Some(2));
}

#[test]
fn the_binary_answers_one_request_on_its_stdin_socket() {
    let (mut client, srv) = UnixStream::pair().unwrap();
    let child = run_binary(Stdio::from(OwnedFd::from(srv)));
    client.write_all(request(None).as_bytes()).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut out = String::new();
    client.read_to_string(&mut out).unwrap();
    let done = child.wait_with_output().unwrap();
    // The test user's journalctl sees only its own journal (or none on a CI runner): never a line of this
    // connection, and always a well-formed answer.
    let response = Response::parse(&out).unwrap_or_else(|| panic!("{out:?}"));
    assert!(response.lines.is_empty(), "{out}");
    let stderr = String::from_utf8_lossy(&done.stderr);
    assert!(matches!(done.status.code(), Some(0 | 1)), "{stderr}");
    let ours = std::fs::metadata("/proc/self").unwrap().uid();
    assert!(stderr.starts_with(&format!("uid={ours} ")), "{stderr}");
    assert!(!stderr.contains(ID), "the request is never logged: {stderr}");
}
