//! `mvpn serve --uid <uid>` (root layer 13): the read-only questions the app polls while a tunnel is up (`status`,
//! `liveness <id>`, `traffic <id>`, and from root layer 15 `dns-check <id>`) answered over a Unix socket instead
//! of a new `sudo -n mvpn …` each time (a `sudo` and an `mvpn` process, PAM, a group lookup and some 30 unified-log
//! lines every few seconds).
//!
//! - Started only by launchd (`/Library/LaunchDaemons/local.macvpn.mvpn-query.plist`, written by the installer):
//!   launchd owns the listening socket `/var/run/macvpn-query.sock` (owner the installing user, group 0, 0600) and
//!   starts this process on the first connection; it takes the socket with `launch_activate_socket`, serves the
//!   connections one at a time (a `dns-check`, whose probe takes seconds, on its own thread: [`MAX_CHECKS`]) and exits after [`IDLE`] without one (launchd starts it again on the next).
//!   Not reachable through the sudoers rule (`refuse_via_sudo` in `main`).
//! - Every connection: the peer ([`crate::macos::sys::peer_uid`]) must be `--uid` or root, else it is closed without
//!   an answer. Then one request line of at most [`REQUEST_MAX`] bytes, read within [`IO_TIMEOUT`]: `status`,
//!   `liveness <UUID>`, `traffic <UUID>` or `dns-check <UUID>` ([`Request::parse`], the CLI's UUID check).
//!   Anything else: closed.
//! - The answer ([`frame`]): the exit code as a decimal line, then exactly what the CLI prints on stdout for that
//!   command; the same code runs (`status::answer`, `liveness::answer`, `traffic::answer`, `dns::check_answer`),
//!   the status' log housekeeping and DNS reconcile included, and nothing else. Written within [`IO_TIMEOUT`];
//!   then closed.
//!
//! No request reaches anything that changes state beyond what `mvpn status` already does, with one documented
//! extension (maintainer decision O4, root layer 15): `dns-check` sends one DNS query (the probe) to the running
//! connection's own DNS servers and may re-publish **that connection's own** DNS layout (the Automatic mode's
//! fallback and its return) — the same class of change as the DNS reconcile `status` already does. No answer
//! holds more than the user's own `sudo mvpn status` / `liveness` / `traffic` / `dns-check` prints. Nothing is
//! logged here (the DNS manager logs a layout change in the connection's own log, as `status`' reconcile does).

use crate::macos::ctx::Ctx;
use crate::macos::paths::Settings;
use crate::shared::cli::{self, is_uuid};
use macvpn_core::liveness::LIVENESS;
use macvpn_core::status::DNS_CHECK;
use macvpn_core::traffic::TRAFFIC;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// The plist's `Sockets` key the listening socket is under.
pub const LISTENERS: &str = "Listeners";
/// Without a new connection for this long the daemon exits (launchd starts it again on demand).
pub const IDLE: Duration = Duration::from_secs(60);
/// The request must arrive, and the answer must be written, within this.
pub const IO_TIMEOUT: Duration = Duration::from_secs(2);
/// The longest request line, `\n` included (`liveness <36-byte UUID>\n` is 46).
pub const REQUEST_MAX: usize = 128;
/// At most this many `dns-check`s at a time. Each runs on its own thread (its probe takes up to 9 s), so the loop
/// keeps answering `status` / `liveness` meanwhile; one more is closed without an answer.
pub const MAX_CHECKS: usize = 4;

/// One of the four questions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Status,
    Liveness(String),
    Traffic(String),
    DnsCheck(String),
}

impl Request {
    /// Exactly one line ending in `\n` (no `\r`, nothing after it): `status`, `liveness <UUID>` or
    /// `traffic <UUID>`, the UUID as the CLI accepts it.
    pub fn parse(line: &[u8]) -> Option<Request> {
        if line.len() > REQUEST_MAX {
            return None;
        }
        let text = std::str::from_utf8(line).ok()?.strip_suffix('\n')?;
        if text.contains(['\n', '\r']) {
            return None;
        }
        match text.split_once(' ') {
            None if text == "status" => Some(Request::Status),
            Some((LIVENESS, id)) if is_uuid(id) => Some(Request::Liveness(id.to_string())),
            Some((TRAFFIC, id)) if is_uuid(id) => Some(Request::Traffic(id.to_string())),
            Some((DNS_CHECK, id)) if is_uuid(id) => Some(Request::DnsCheck(id.to_string())),
            _ => None,
        }
    }

    /// The exit code and the stdout of the same request on the command line (`load`: the invocation's settings).
    fn answer(&self, load: &dyn Fn() -> Settings) -> (i32, String) {
        let ctx = |cmd: &str, id: &str| Ctx::new(load(), cli::Args::parse(&[cmd.to_string(), id.to_string()]));
        match self {
            Request::Status => (0, crate::macos::status::answer(&load())),
            Request::Liveness(id) => crate::macos::liveness::answer(&ctx(LIVENESS, id)),
            Request::Traffic(id) => crate::macos::traffic::answer(&ctx(TRAFFIC, id)),
            Request::DnsCheck(id) => crate::macos::dns::check_answer(&ctx(DNS_CHECK, id)),
        }
    }
}

/// The peer check: only the installed user (`--uid`) and root get an answer.
pub fn peer_allowed(peer: Option<u32>, uid: u32) -> bool {
    peer.is_some_and(|p| p == uid || p == 0)
}

/// The answer on the wire: `<exit code>\n<stdout>`.
pub fn frame(code: i32, stdout: &str) -> Vec<u8> {
    let mut out = format!("{code}\n").into_bytes();
    out.extend_from_slice(stdout.as_bytes());
    out
}

/// `--uid <n>`: a plain decimal number (the installer writes it from `id -u`).
pub fn parse_args(args: &[String]) -> Option<u32> {
    match args {
        [flag, n] if flag == "--uid" && (1..=10).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()) => {
            n.parse().ok()
        }
        _ => None,
    }
}

/// `mvpn serve --uid <uid>` (launchd only); returns the exit code.
pub fn main(args: &[String]) -> i32 {
    let Some(uid) = parse_args(args) else { return 2 };
    let Ok(sockets) = crate::macos::sys::launch_sockets(LISTENERS) else { return 1 };
    // One `SockPathName` gives one socket; any other is closed when dropped.
    let Some(fd) = sockets.into_iter().next() else { return 1 };
    serve_on(&UnixListener::from(fd), uid, IDLE, &Settings::load)
}

/// The serve loop over `listener` (launchd's socket, or a test's): one connection at a time, until `idle` passes
/// without one (exit 0). `load`: the settings of each request (as root always the fixed paths).
pub fn serve_on(listener: &UnixListener, uid: u32, idle: Duration, load: &dyn Fn() -> Settings) -> i32 {
    // Non-blocking, so a connection that went away between `poll` and `accept` cannot block the loop.
    if listener.set_nonblocking(true).is_err() {
        return 1;
    }
    let checks = Arc::new(AtomicUsize::new(0));
    loop {
        if !crate::macos::sys::wait_readable(listener, idle) {
            if checks.load(Ordering::SeqCst) == 0 {
                return 0;
            }
            // A `dns-check` is still running: never cut it short (it may be changing the DNS).
            continue;
        }
        match listener.accept() {
            Ok((stream, _)) => handle(stream, uid, load, &checks),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::ConnectionAborted
                ) => {}
            Err(_) => return 1,
        }
    }
}

/// One connection: the peer check, the request, the answer; any failure just closes it. A `dns-check` is answered
/// on its own thread (at most [`MAX_CHECKS`], counted in `checks`).
fn handle(stream: UnixStream, uid: u32, load: &dyn Fn() -> Settings, checks: &Arc<AtomicUsize>) {
    // An accepted socket inherits the listener's O_NONBLOCK on macOS; the timeouts below need a blocking one.
    if stream.set_nonblocking(false).is_err() || !peer_allowed(crate::macos::sys::peer_uid(&stream), uid) {
        return;
    }
    let Some(request) = read_request(&stream).and_then(|line| Request::parse(&line)) else { return };
    if matches!(request, Request::DnsCheck(_)) {
        if checks.fetch_add(1, Ordering::SeqCst) >= MAX_CHECKS {
            checks.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        let settings = load();
        let done = checks.clone();
        let spawned = std::thread::Builder::new().spawn(move || {
            answer(&stream, &request, &move || settings.clone());
            done.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            checks.fetch_sub(1, Ordering::SeqCst);
        }
        return;
    }
    answer(&stream, &request, load);
}

fn answer(stream: &UnixStream, request: &Request, load: &dyn Fn() -> Settings) {
    let (code, stdout) = request.answer(load);
    if stream.set_write_timeout(Some(IO_TIMEOUT)).is_ok() {
        let _ = (&*stream).write_all(&frame(code, &stdout));
    }
}

/// The bytes up to and including the first `\n`, at most [`REQUEST_MAX`], all within [`IO_TIMEOUT`] (a peer that
/// trickles bytes gets no more time). `None`: too long, too slow, or closed before the line ended.
fn read_request(mut stream: &UnixStream) -> Option<Vec<u8>> {
    let end = Instant::now() + IO_TIMEOUT;
    let mut line = Vec::with_capacity(REQUEST_MAX);
    let mut chunk = [0u8; REQUEST_MAX];
    while !line.contains(&b'\n') {
        let room = REQUEST_MAX - line.len();
        let left = end.saturating_duration_since(Instant::now());
        if room == 0 || left.is_zero() {
            return None;
        }
        stream.set_read_timeout(Some(left)).ok()?;
        match stream.read(&mut chunk[..room]) {
            Ok(0) => return None,
            Ok(n) => line.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some(line)
}

/// `mvpn __serve-on <socket> <uid> <idle seconds>` (test mode only): the serve loop on a socket the test names,
/// without launchd, with the test mode's settings.
pub fn test_main(args: &[String]) -> i32 {
    let [path, uid, idle] = args else { return 2 };
    let (Some(uid), Ok(idle)) = (parse_args(&["--uid".to_string(), uid.clone()]), idle.parse::<u64>()) else {
        return 2;
    };
    let Ok(listener) = UnixListener::bind(path) else { return 1 };
    serve_on(&listener, uid, Duration::from_secs(idle), &Settings::load)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::testmode::TestEnv;

    const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";

    #[test]
    fn only_the_four_questions_are_understood() {
        assert_eq!(Request::parse(b"status\n"), Some(Request::Status));
        assert_eq!(Request::parse(format!("dns-check {ID}\n").as_bytes()), Some(Request::DnsCheck(ID.into())));
        assert_eq!(Request::parse(format!("liveness {ID}\n").as_bytes()), Some(Request::Liveness(ID.into())));
        let lower = ID.to_lowercase();
        assert_eq!(Request::parse(format!("traffic {lower}\n").as_bytes()), Some(Request::Traffic(lower)));
        for bad in [
            "status".to_string(),
            "status\r\n".into(),
            "status \n".into(),
            "status\nstatus\n".into(),
            "STATUS\n".into(),
            "version\n".into(),
            format!("down openvpn {ID}\n"),
            format!("up openvpn {ID}\n"),
            format!("respond openvpn {ID}\n"),
            format!("liveness  {ID}\n"),
            format!("liveness {ID} --lang hu\n"),
            format!("liveness {ID}x\n"),
            "liveness ../../etc\n".into(),
            "liveness\n".into(),
            "traffic \n".into(),
            "dns-check \n".into(),
            format!("dns-check {ID} x\n"),
            "dns-check ../x\n".into(),
            format!("status{}\n", " ".repeat(REQUEST_MAX)),
        ] {
            assert_eq!(Request::parse(bad.as_bytes()), None, "{bad:?}");
        }
        assert_eq!(Request::parse(b"status\xff\n"), None);
    }

    #[test]
    fn only_the_installed_user_and_root_are_answered() {
        assert!(peer_allowed(Some(501), 501));
        assert!(peer_allowed(Some(0), 501));
        assert!(!peer_allowed(Some(502), 501));
        assert!(!peer_allowed(None, 501));
    }

    #[test]
    fn the_uid_argument() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(parse_args(&v(&["--uid", "501"])), Some(501));
        for bad in [&["--uid"][..], &["--uid", ""], &["--uid", "-1"], &["--uid", "5 01"], &["--uid", "99999999999"]] {
            assert_eq!(parse_args(&v(bad)), None, "{bad:?}");
        }
        assert_eq!(parse_args(&v(&["--uid", "501", "x"])), None);
        assert_eq!(parse_args(&v(&["--gid", "501"])), None);
    }

    #[test]
    fn answers_are_framed_with_the_exit_code() {
        assert_eq!(frame(0, "[]\n"), b"0\n[]\n");
        assert_eq!(frame(1, ""), b"1\n");
    }

    /// The loop on a socket in a temp directory (no launchd): `status` answered as the CLI prints it, a malformed
    /// request closed without an answer, and the loop ends after `idle` without a connection.
    #[test]
    fn serves_status_on_a_socket_and_exits_when_idle() {
        let base = std::env::temp_dir().join(format!("mvq-{}", &uuid::Uuid::new_v4().to_string()[..8]));
        let run = base.join("run");
        std::fs::create_dir_all(run.join(ID)).unwrap();
        std::fs::write(run.join(ID).join("kind"), "wireguard\n").unwrap();
        std::fs::write(run.join(ID).join("iface"), "mv12345678\n").unwrap();
        let t = TestEnv {
            run_base: Some(run.display().to_string()),
            wg_run: Some(base.join("no-wg").display().to_string()),
            log_base: Some(base.join("no-log").display().to_string()),
            dns_base: Some(base.join("no-dns").display().to_string()),
            brew: Some(base.join("no-brew").display().to_string()),
            ..TestEnv::default()
        };
        let settings = Settings::resolve(true, t, String::new());
        let expected = crate::macos::status::render(&settings);
        let sock = base.join("q.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let me = crate::macos::sys::geteuid();
        let server = std::thread::spawn(move || {
            let load = move || settings.clone();
            serve_on(&listener, me, Duration::from_millis(1500), &load)
        });
        let ask = |request: &[u8]| {
            let mut c = UnixStream::connect(&sock).unwrap();
            c.write_all(request).unwrap();
            let mut answer = Vec::new();
            c.read_to_end(&mut answer).unwrap();
            String::from_utf8(answer).unwrap()
        };
        assert_eq!(ask(b"status\n"), format!("0\n{expected}"));
        assert!(expected.contains(ID), "{expected}");
        assert_eq!(ask(b"down\n"), "");
        assert_eq!(ask(format!("liveness {ID}\n").as_bytes()), "1\n", "a wireguard run without its utun");
        assert_eq!(ask(format!("traffic {ID}\n").as_bytes()), "1\n", "not strongSwan");
        assert_eq!(ask(format!("dns-check {ID}\n").as_bytes()), "1\n", "no DNS session");
        let session = "mode=automatic\ntunnel=split\nlayout=vpn-local\nprobe=ok\nfails=0\nwarn=\n\
                       servers=10.8.0.1\nsearch=\nresolve=\nzones=\nsince=1\n";
        let f = run.join(ID).join("dns-session");
        std::fs::write(&f, session).unwrap();
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        assert_eq!(ask(format!("dns-check {ID}\n").as_bytes()), "0\nvpn\n", "the session's state");
        let started = Instant::now();
        assert_eq!(server.join().unwrap(), 0);
        assert!(started.elapsed() >= Duration::from_millis(1000));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A `dns-check` probes on its own thread: the loop answers `status` meanwhile.
    #[test]
    fn a_dns_check_does_not_hold_up_the_other_questions() {
        let base = std::env::temp_dir().join(format!("mvq-{}", &uuid::Uuid::new_v4().to_string()[..8]));
        let run = base.join("run");
        std::fs::create_dir_all(run.join(ID)).unwrap();
        std::fs::write(run.join(ID).join("kind"), "wireguard\n").unwrap();
        let session = "mode=automatic\ntunnel=split\nlayout=vpn-local\nprobe=ok\nfails=0\nwarn=\n\
                       servers=10.8.0.1\nsearch=\nresolve=\nzones=\nsince=1\n";
        let f = run.join(ID).join("dns-session");
        std::fs::write(&f, session).unwrap();
        std::fs::set_permissions(&f, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        let t = TestEnv {
            run_base: Some(run.display().to_string()),
            wg_run: Some(base.join("no-wg").display().to_string()),
            log_base: Some(base.join("no-log").display().to_string()),
            dns_base: Some(base.join("dns").display().to_string()),
            dynstore: Some(base.join("dyn").display().to_string()),
            dns_probe: Some("slow-ok".into()),
            brew: Some(base.join("no-brew").display().to_string()),
            ..TestEnv::default()
        };
        let settings = Settings::resolve(true, t, String::new());
        let sock = base.join("q.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let me = crate::macos::sys::geteuid();
        let server = std::thread::spawn(move || {
            let load = move || settings.clone();
            serve_on(&listener, me, Duration::from_millis(300), &load)
        });
        let ask = move |request: String| {
            let mut c = UnixStream::connect(&sock).unwrap();
            c.write_all(request.as_bytes()).unwrap();
            let mut answer = Vec::new();
            c.read_to_end(&mut answer).unwrap();
            String::from_utf8(answer).unwrap()
        };
        let ask2 = ask.clone();
        let check = std::thread::spawn(move || ask2(format!("dns-check {ID}\n")));
        std::thread::sleep(Duration::from_millis(200));
        let started = Instant::now();
        assert!(ask("status\n".into()).starts_with("0\n"));
        assert!(started.elapsed() < Duration::from_millis(700), "status waited for the probe");
        assert_eq!(check.join().unwrap(), "0\nvpn\n");
        // The loop ends only after the check finished (idle 300 ms < the 1 s probe).
        assert_eq!(server.join().unwrap(), 0);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A different uid gets no answer.
    #[test]
    fn another_user_gets_nothing() {
        let base = std::env::temp_dir().join(format!("mvq-{}", &uuid::Uuid::new_v4().to_string()[..8]));
        std::fs::create_dir_all(&base).unwrap();
        let sock = base.join("q.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let other = crate::macos::sys::geteuid() + 1;
        let t = TestEnv { run_base: Some(base.join("run").display().to_string()), ..TestEnv::default() };
        let settings = Settings::resolve(true, t, String::new());
        let server = std::thread::spawn(move || {
            let load = move || settings.clone();
            serve_on(&listener, other, Duration::from_millis(500), &load)
        });
        let mut c = UnixStream::connect(&sock).unwrap();
        let _ = c.write_all(b"status\n");
        let mut answer = Vec::new();
        let _ = c.read_to_end(&mut answer);
        assert!(answer.is_empty());
        assert_eq!(server.join().unwrap(), 0);
        let _ = std::fs::remove_dir_all(&base);
    }
}
