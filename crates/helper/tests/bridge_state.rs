//! The management bridge running inside the service: its state in memory instead of files (every OS).

use macvpn_helper::shared::bridge::{Bridge, BridgeArgs, BridgeFiles};
use macvpn_helper::windows::bridge_state::{BridgeState, InProcessFiles, OneCommandAtATime, StateWatch};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const ID: &str = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";

/// One step of a scripted management stream.
enum Step {
    /// OpenVPN sends these bytes.
    Data(&'static [u8]),
    /// A read timeout (the bridge's poll).
    Timeout,
    /// The app answers through `respond` (the service calls `set_response`), then a read timeout.
    Respond(&'static [u8]),
}

/// A management stream: the scripted steps, the bridge's writes recorded; the end of the script is EOF.
struct Script {
    steps: VecDeque<Step>,
    state: Arc<BridgeState>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.steps.pop_front() {
            Some(Step::Data(chunk)) => {
                buf[..chunk.len()].copy_from_slice(chunk);
                Ok(chunk.len())
            }
            Some(Step::Timeout) => Err(io::ErrorKind::WouldBlock.into()),
            Some(Step::Respond(body)) => {
                self.state.set_response(body);
                Err(io::ErrorKind::WouldBlock.into())
            }
            None => Ok(0),
        }
    }
}

impl Write for Script {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Run {
    state: Arc<BridgeState>,
    sent: String,
    log: Vec<String>,
    stops: u32,
    /// Every `AuthUIState` the app could have read, in order.
    seen: Vec<Vec<u8>>,
}

fn run(steps: Vec<Step>, creds: Option<(&str, &str)>) -> Run {
    let log = Arc::new(Mutex::new(Vec::new()));
    let stops = Arc::new(AtomicU32::new(0));
    let (l, s) = (log.clone(), stops.clone());
    let state = Arc::new(BridgeState::new(
        Box::new(move |line| l.lock().unwrap().push(line.to_string())),
        Box::new(move || {
            s.fetch_add(1, Ordering::SeqCst);
        }),
    ));
    let written = Arc::new(Mutex::new(Vec::new()));
    let stream = Script { steps: steps.into(), state: state.clone(), written: written.clone() };
    let creds = creds.map(|(u, p)| macvpn_core::management::ManagementCredentials {
        username: u.into(),
        password: p.into(),
        packed: false,
    });
    let args = BridgeArgs::in_process(ID, 420.0).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let files = Recorder { inner: InProcessFiles::new(state.clone()), seen: seen.clone() };
    Bridge::new(args, stream, files, creds).run();
    let sent = String::from_utf8(written.lock().unwrap().clone()).unwrap();
    let log = log.lock().unwrap().clone();
    let seen = seen.lock().unwrap().clone();
    Run { state, sent, log, stops: stops.load(Ordering::SeqCst), seen }
}

/// Records every state the app could read (the in-process files keep only the latest).
struct Recorder {
    inner: InProcessFiles,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl BridgeFiles for Recorder {
    fn log(&mut self, line: &str) {
        self.inner.log(line)
    }
    fn run_trusted(&self) -> bool {
        self.inner.run_trusted()
    }
    fn ui_trusted(&self) -> bool {
        self.inner.ui_trusted()
    }
    fn write_ui(&mut self, name: &str, data: &[u8]) -> bool {
        let ok = self.inner.write_ui(name, data);
        if ok {
            self.seen.lock().unwrap().push(self.inner.state().ui().unwrap());
        }
        ok
    }
    fn write_run(&mut self, name: &str, data: &[u8]) -> bool {
        self.inner.write_run(name, data)
    }
    fn remove_ui(&mut self, name: &str) {
        self.inner.remove_ui(name)
    }
    fn take_response(&mut self) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        self.inner.take_response()
    }
    fn stop_openvpn(&mut self) {
        self.inner.stop_openvpn()
    }
}

const CRV1: &[u8] =
    b">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Ym9i:Enter the code']\r\n";
const NEED_AUTH: &[u8] = b">PASSWORD:Need 'Auth' username/password\r\n";
const CONNECTED: &[u8] = b">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,192.0.2.1,1194,,\r\n";

#[test]
fn a_crv1_challenge_reaches_the_app_and_the_answer_reaches_openvpn() {
    let r = run(
        vec![
            Step::Data(CRV1),
            Step::Data(NEED_AUTH),
            Step::Timeout,
            Step::Respond(b"kind=crv1\nresponse=123456\n"),
            Step::Data(CONNECTED),
        ],
        None,
    );
    // The challenge the app read is a valid AuthUIState with the server's text (and never the answer).
    let first = macvpn_core::mfa::AuthUIState::parse(&r.seen[0]).expect("a valid AuthUIState");
    assert_eq!(first.text.as_deref(), Some("Enter the code"));
    assert!(r.seen.iter().all(|s| !String::from_utf8_lossy(s).contains("123456")));
    // The bridge's exact command (`CRV1Challenge::password`: CRV1::<state>::<response>, user from the challenge).
    assert_eq!(
        r.sent,
        "state on\nusername \"Auth\" \"bob\"\npassword \"Auth\" \"CRV1::Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l::123456\"\n"
    );
    // Connected: the state for the app is cleared, the status for the engine says so.
    assert_eq!(r.state.ui(), None);
    assert_eq!(r.state.mgmt_status().as_deref(), Some("ok"));
    assert!(r.log.contains(&"authenticated".to_string()), "{:?}", r.log);
    assert_eq!(r.stops, 0);
}

#[test]
fn a_cancel_stops_openvpn_and_says_so() {
    let r = run(
        vec![
            Step::Data(b">INFOMSG:WEB_AUTH::https://login.example.com/x\r\n"),
            Step::Respond(b"kind=cancel\nresponse=\n"),
        ],
        Some(("alice", "pw")),
    );
    assert_eq!(r.state.mgmt_status().as_deref(), Some("cancelled"));
    assert_eq!(r.stops, 1);
    let last = macvpn_core::mfa::AuthUIState::parse(&r.state.ui().unwrap()).unwrap();
    assert_eq!(last.state, macvpn_core::mfa::AuthUIStateKind::Cancelled);
}

#[test]
fn stored_credentials_go_to_openvpn_and_never_to_the_log() {
    let r = run(vec![Step::Data(NEED_AUTH), Step::Data(CONNECTED)], Some(("alice", "s3cret-pw")));
    assert!(r.sent.ends_with("username \"Auth\" \"alice\"\npassword \"Auth\" \"s3cret-pw\"\n"), "{}", r.sent);
    assert!(r.log.iter().all(|l| !l.contains("s3cret-pw")), "{:?}", r.log);
}

#[test]
fn the_bridge_status_is_strict() {
    let state = BridgeState::new(Box::new(|_| {}), Box::new(|| {}));
    let mut files = InProcessFiles::new(Arc::new(state));
    assert!(files.write_run("mgmt-status", b"wait 1700000000\n"));
    assert_eq!(files.state().mgmt_status().as_deref(), Some("wait 1700000000"));
    assert!(files.write_run("mgmt-status", b"rm -rf\n"));
    assert_eq!(files.state().mgmt_status(), None);
    assert!(!files.write_run("../x", b"ok"), "only the bridge's own names");
    assert!(!files.write_run("mgmt-resp", b"ok"));
    // The user's state: only `<ID>.json` of this connection, at most 8 KiB.
    let name = format!("{}.json", ID.to_ascii_uppercase());
    assert!(files.write_ui(&name, b"{}"));
    assert_eq!(files.state().ui().as_deref(), Some(&b"{}"[..]));
    assert!(!files.write_ui("other.json", b"{}"));
    assert!(!files.write_ui(r"..\x.json", b"{}"));
    assert!(!files.write_ui(&name, &vec![b' '; 8193]));
    files.remove_ui(&name);
    assert_eq!(files.state().ui(), None);
    // An answer is read once; a newer one replaces an unread one.
    files.state().set_response(b"kind=crv1\nresponse=1\n");
    files.state().set_response(b"kind=crv1\nresponse=2\n");
    assert_eq!(files.take_response().as_deref().map(Vec::as_slice), Some(&b"kind=crv1\nresponse=2\n"[..]));
    assert_eq!(files.take_response(), None);
}

/// Hands out fixed chunks; records nothing.
struct Chunks(VecDeque<&'static [u8]>);

impl Read for Chunks {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let Some(c) = self.0.pop_front() else { return Ok(0) };
        let n = c.len().min(buf.len());
        buf[..n].copy_from_slice(&c[..n]);
        if n < c.len() {
            self.0.push_front(&c[n..]);
        }
        Ok(n)
    }
}

impl Write for Chunks {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn the_tunnel_address_comes_from_the_connected_state_line() {
    let read_all = |chunks: &[&'static [u8]]| {
        let ip = Arc::new(Mutex::new(None));
        let mut w = StateWatch::new(Chunks(chunks.iter().copied().collect()), ip.clone());
        let mut out = Vec::new();
        w.read_to_end(&mut out).unwrap();
        (out, ip.lock().unwrap().clone())
    };
    // Passed through unchanged; the line may arrive in pieces.
    let (out, ip) = read_all(&[b">STATE:1700000000,CONNEC", b"TED,SUCCESS,10.8.0.2,192.0.2.1,1194,,\r\n"]);
    assert_eq!(out, CONNECTED);
    assert_eq!(ip.as_deref(), Some("10.8.0.2"));
    // IPv6 only: the ninth field.
    let (_, ip) = read_all(&[b">STATE:1,CONNECTED,SUCCESS,,192.0.2.1,1194,,,fd00::2\r\n"]);
    assert_eq!(ip.as_deref(), Some("fd00::2"));
    // A later state other than CONNECTED forgets it; anything that is not an address is never taken.
    let (_, ip) = read_all(&[CONNECTED, b">STATE:1700000001,RECONNECTING,ping-restart,,,,,\r\n"]);
    assert_eq!(ip, None);
    for bad in [
        &b">STATE:1,CONNECTED,SUCCESS,10.8.0.2;rm,192.0.2.1,1194,,\r\n"[..],
        b">STATE:1,CONNECTED,SUCCESS,not-an-ip,192.0.2.1\r\n",
        b">LOG:1,I,>STATE:1,CONNECTED,SUCCESS,10.8.0.2,x\r\n",
    ] {
        let (_, ip) = read_all(&[bad]);
        assert_eq!(ip, None, "{}", String::from_utf8_lossy(bad));
    }
}

/// What happened on a management stream, in order.
#[derive(Debug, Clone, PartialEq)]
enum Event {
    /// OpenVPN's bytes were read (by the bridge or ahead).
    Read(String),
    /// Bytes were written to OpenVPN.
    Write(String),
}

/// A scripted management stream (`None`: a read timeout; the end of the script is EOF) that records reads and
/// writes in one timeline; a write takes at most `max_write` bytes.
struct Timeline {
    steps: VecDeque<Option<&'static str>>,
    events: Arc<Mutex<Vec<Event>>>,
    max_write: usize,
}

impl Timeline {
    fn new(steps: &[Option<&'static str>]) -> (Timeline, Arc<Mutex<Vec<Event>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        (Timeline { steps: steps.iter().copied().collect(), events: events.clone(), max_write: usize::MAX }, events)
    }
}

impl Read for Timeline {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.steps.pop_front() {
            Some(Some(chunk)) => {
                buf[..chunk.len()].copy_from_slice(chunk.as_bytes());
                self.events.lock().unwrap().push(Event::Read(chunk.into()));
                Ok(chunk.len())
            }
            Some(None) => Err(io::ErrorKind::WouldBlock.into()),
            None => Ok(0),
        }
    }
}

impl Write for Timeline {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len().min(self.max_write);
        self.events.lock().unwrap().push(Event::Write(String::from_utf8_lossy(&buf[..n]).into_owned()));
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The writes of a timeline joined per command line (a command written in pieces is one entry).
fn writes(events: &[Event]) -> Vec<String> {
    let all: String =
        events.iter().filter_map(|e| if let Event::Write(w) = e { Some(w.as_str()) } else { None }).collect();
    all.split_inclusive('\n').map(String::from).collect()
}

/// The position of the first event that is `event`.
fn at(events: &[Event], event: &Event) -> usize {
    events.iter().position(|e| e == event).unwrap_or_else(|| panic!("no {event:?} in {events:?}"))
}

const STATE_ON_OK: &str = "SUCCESS: real-time state notification set to ON\r\n";

/// The bridge over the Windows engine's stream (StateWatch over OneCommandAtATime) on a scripted OpenVPN.
fn bridge_over(steps: &[Option<&'static str>], creds: Option<(&str, &str)>) -> (Vec<Event>, Arc<BridgeState>) {
    let (stream, events) = Timeline::new(steps);
    let state = Arc::new(BridgeState::new(Box::new(|_| {}), Box::new(|| {})));
    let creds = creds.map(|(u, p)| macvpn_core::management::ManagementCredentials {
        username: u.into(),
        password: p.into(),
        packed: false,
    });
    let stream =
        StateWatch::new(OneCommandAtATime::with_wait(stream, Duration::from_secs(5)), Arc::new(Mutex::new(None)));
    let args = BridgeArgs::in_process(ID, 420.0).unwrap();
    Bridge::new(args, stream, InProcessFiles::new(state.clone()), creds).run();
    let events = events.lock().unwrap().clone();
    (events, state)
}

/// CI's OpenVPN 2.7.8 (Windows Server 2025): the HOLD notice comes with the login, before `state on` is answered;
/// `hold release` sent at once was lost (OpenVPN ran `state on` twice and held forever). It now waits for the
/// answer.
#[test]
fn hold_release_waits_for_the_answer_to_state_on() {
    let (events, state) = bridge_over(
        &[
            Some(
                ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n>HOLD:Waiting for hold release:0\r\n",
            ),
            None,
            Some(STATE_ON_OK),
            Some("SUCCESS: hold release succeeded\r\n"),
            Some(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,192.0.2.1,1194,,\r\n"),
        ],
        None,
    );
    assert_eq!(writes(&events), ["state on\n", "hold release\n"]);
    let answered = at(&events, &Event::Read(STATE_ON_OK.into()));
    assert!(at(&events, &Event::Write("hold release\n".into())) > answered, "{events:?}");
    // Everything read ahead reached the bridge: it saw CONNECTED.
    assert_eq!(state.mgmt_status().as_deref(), Some("ok"));
}

#[test]
fn the_password_waits_for_the_answer_to_the_user_name() {
    const USER_OK: &str = "SUCCESS: 'Auth' username entered, but not yet verified\r\n";
    let (events, state) = bridge_over(
        &[
            Some(">PASSWORD:Need 'Auth' username/password\r\n"),
            Some(STATE_ON_OK),
            None,
            Some(USER_OK),
            Some("SUCCESS: 'Auth' password entered, but not yet verified\r\n"),
            Some(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,192.0.2.1,1194,,\r\n"),
        ],
        Some(("alice", "pw")),
    );
    assert_eq!(writes(&events), ["state on\n", "username \"Auth\" \"alice\"\n", "password \"Auth\" \"pw\"\n"]);
    let user = at(&events, &Event::Write("username \"Auth\" \"alice\"\n".into()));
    assert!(user > at(&events, &Event::Read(STATE_ON_OK.into())), "{events:?}");
    assert!(
        at(&events, &Event::Write("password \"Auth\" \"pw\"\n".into())) > at(&events, &Event::Read(USER_OK.into()))
    );
    assert_eq!(state.mgmt_status().as_deref(), Some("ok"));
}

#[test]
fn one_command_at_a_time_on_its_own() {
    let wait = Duration::from_millis(300);
    // A command written in pieces is one command: no wait inside it.
    let (mut stream, events) = Timeline::new(&[]);
    stream.max_write = 3;
    let mut p = OneCommandAtATime::with_wait(stream, wait);
    let started = Instant::now();
    p.write_all(b"state on\n").unwrap();
    assert!(started.elapsed() < wait);
    assert_eq!(writes(&events.lock().unwrap()), ["state on\n"]);
    // No answer at all (read timeouts only): the next command goes after the wait.
    let (stream, events) = Timeline::new(&[None; 200]);
    let mut p = OneCommandAtATime::with_wait(stream, wait);
    p.write_all(b"state on\n").unwrap();
    let started = Instant::now();
    p.write_all(b"hold release\n").unwrap();
    assert!(started.elapsed() >= wait, "{:?}", started.elapsed());
    assert_eq!(writes(&events.lock().unwrap()), ["state on\n", "hold release\n"]);
    // An answer split over reads counts, ERROR counts too, and everything read ahead is handed out once, in order.
    let (stream, events) = Timeline::new(&[
        Some(">HOLD:Waiting for hold release:0\r\nSUCC"),
        Some("ESS: real-time state notification set to ON\r\n>LOG:x\r\n"),
        Some("ERROR: unknown command\r\n"),
        Some(">STATE:1,CONNECTING,,,,,,\r\n"),
    ]);
    let mut p = OneCommandAtATime::with_wait(stream, Duration::from_secs(5));
    p.write_all(b"state on\n").unwrap();
    p.write_all(b"hold release\n").unwrap();
    p.write_all(b"bytecount 0\n").unwrap();
    let mut out = Vec::new();
    p.read_to_end(&mut out).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        ">HOLD:Waiting for hold release:0\r\nSUCCESS: real-time state notification set to ON\r\n>LOG:x\r\n\
         ERROR: unknown command\r\n>STATE:1,CONNECTING,,,,,,\r\n"
    );
    let events = events.lock().unwrap().clone();
    assert!(
        at(&events, &Event::Write("hold release\n".into()))
            > at(&events, &Event::Read("ESS: real-time state notification set to ON\r\n>LOG:x\r\n".into()))
    );
    assert!(
        at(&events, &Event::Write("bytecount 0\n".into()))
            > at(&events, &Event::Read("ERROR: unknown command\r\n".into()))
    );
    // A notification is no answer: `>HOLD`, `>LOG`, `>STATE` lines never let the next command through.
}
