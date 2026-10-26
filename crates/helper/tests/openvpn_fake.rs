//! The OpenVPN engine end to end as a standard user: the debug console with `--fake-openvpn` runs the real engine
//! (run directory, argv, environment, output, management login, bridge, wait rules, down) with `mvpn.exe` itself
//! as a stand-in `openvpn.exe` (`sys/fake_openvpn.rs`; the trust checks of the real one are tested in `detect`).
#![cfg(all(windows, debug_assertions))]

use macvpn_core::service_proto::{self as proto, LogSlice, Response};
use macvpn_winsys::file::{self, Protection};
use macvpn_winsys::pipe::{self, ServerTrust};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";

struct Console {
    child: Child,
    pipe: String,
    data: PathBuf,
}

impl Console {
    fn start() -> Console {
        let pipe = format!(r"\\.\pipe\WinVPN-test-{}", uuid::Uuid::new_v4());
        let data = std::env::temp_dir().join(format!("winvpn-ovpn-{}", uuid::Uuid::new_v4()));
        let mut child = Command::new(env!("CARGO_BIN_EXE_mvpn"))
            .args(["console", "--pipe", &pipe, "--data", data.to_str().unwrap(), "--fake-openvpn"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut first = String::new();
        BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut first).unwrap();
        assert_eq!(first.trim(), "ready");
        Console { child, pipe, data }
    }

    fn call(&self, args: &[&str], body: &[u8]) -> Response {
        let mut s = pipe::connect_with(&self.pipe, Duration::from_secs(5), ServerTrust::SameUser).unwrap();
        proto::write_request(&mut s, args, body).unwrap();
        proto::read_response(&mut s).unwrap()
    }

    fn up(&self, scenario: &str, extra: &str, secrets: &str) -> Response {
        let config =
            format!("# winvpn-fake: {scenario}\nclient\n{extra}proto udp\nremote vpn.example.com 1194\nnobind\n");
        let mut body = format!("config {}\n{config}", config.len()).into_bytes();
        body.extend_from_slice(secrets.as_bytes());
        self.call(&["up", "openvpn", ID, "--lang", "en"], &body)
    }

    fn log(&self) -> String {
        let r = self.call(&["log", ID, "0"], b"");
        assert_eq!(r.code, 0);
        String::from_utf8(LogSlice::parse(&r.stdout).unwrap().data).unwrap()
    }

    fn run_dir(&self) -> PathBuf {
        self.data.join("run").join(ID)
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data);
    }
}

fn err(r: &Response) -> String {
    String::from_utf8_lossy(&r.stderr).trim().to_string()
}

fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < until, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_connection_comes_up_with_the_stored_credentials_and_goes_down() {
    let c = Console::start();
    let r = c.up("userpass", "dev tun\n", "username=alice\npassword=s3cret-pw\nkeypass=kp-secret\n");
    assert_eq!(r.code, 0, "{}", err(&r));
    // The run directory: the three files, each created private (this user and SYSTEM; SYSTEM and Administrators
    // in the service).
    let dir = c.run_dir();
    for name in ["config.ovpn", "mgmt.pw", "askpass"] {
        let f = file::open_metadata(&dir.join(name), false).unwrap();
        assert!(file::has_protection(&f, Protection::Private, false).unwrap(), "{name}");
    }
    let pw = std::fs::read_to_string(dir.join("mgmt.pw")).unwrap();
    let pw = pw.trim_end();
    assert!(pw.len() == 64 && pw.bytes().all(|b| b.is_ascii_hexdigit()), "{pw}");
    assert_eq!(std::fs::read(dir.join("askpass")).unwrap(), b"kp-secret\n");
    // Connected, with the address from OpenVPN's CONNECTED state.
    eventually("the tunnel address in status", || {
        let st = String::from_utf8(c.call(&["status"], b"").stdout).unwrap();
        st.contains(ID) && st.contains("connected") && st.contains("10.8.0.2")
    });
    // The log: OpenVPN's lines, the bridge's events; the password masked; never the management password; the
    // child's environment is only the Windows folders; DCO for a config DCO can run.
    let log = c.log();
    assert!(log.contains("fake openvpn: password received ***"), "{log}");
    assert!(log.contains("[mgmt] credentials sent"), "{log}");
    assert!(log.contains("fake openvpn: env PATH,SystemDrive,SystemRoot,TEMP,TMP,windir\n"), "{log}");
    assert!(log.contains("fake openvpn: driver ovpn-dco"), "{log}");
    for secret in ["s3cret-pw", "kp-secret", pw] {
        assert!(!log.contains(secret), "{secret} in {log}");
    }
    // Down: OpenVPN is stopped and the run directory is gone.
    assert_eq!(c.call(&["down", "openvpn", ID], b"").code, 0);
    assert!(!dir.exists());
    let st = String::from_utf8(c.call(&["status"], b"").stdout).unwrap();
    assert!(!st.contains(ID), "{st}");
}

#[test]
fn a_dynamic_challenge_is_answered_through_auth_state_and_respond() {
    let c = Console::start();
    std::thread::scope(|s| {
        let up = s.spawn(|| c.up("crv1", "dev tun\n", ""));
        let mut state = Vec::new();
        eventually("the challenge in auth-state", || {
            state = c.call(&["auth-state", ID], b"").stdout;
            !state.is_empty()
        });
        let ui = macvpn_core::mfa::AuthUIState::parse(&state).expect("a valid AuthUIState");
        assert_eq!(ui.text.as_deref(), Some("Enter the code"));
        let r = c.call(&["respond", "openvpn", ID], b"kind=crv1\nresponse=123456\n");
        assert_eq!(r.code, 0, "{}", err(&r));
        let r = up.join().unwrap();
        assert_eq!(r.code, 0, "{}", err(&r));
    });
    assert!(c.call(&["auth-state", ID], b"").stdout.is_empty(), "cleared once connected");
    assert!(!c.log().contains("123456"));
    assert_eq!(c.call(&["down", "openvpn", ID], b"").code, 0);
}

#[test]
fn failures_answer_the_macos_messages_and_leave_nothing() {
    let c = Console::start();
    let r = c.up("authfail", "dev tun\n", "username=alice\npassword=pw\n");
    assert_eq!((r.code, err(&r).as_str()), (1, "Authentication failed (AUTH_FAILED)"));
    assert!(!c.run_dir().exists());
    let r = c.up("exit", "dev tun\n", "");
    assert_eq!(r.code, 1);
    assert_eq!(
        err(&r),
        "openvpn exited: 2026-10-22 10:00:00 RESOLVE: Cannot resolve host address: vpn.example.com:1194"
    );
    assert!(!c.run_dir().exists());
    // A wrong code: the server's AUTH_FAILED.
    std::thread::scope(|s| {
        let up = s.spawn(|| c.up("crv1", "dev tun\n", ""));
        eventually("the challenge", || !c.call(&["auth-state", ID], b"").stdout.is_empty());
        assert_eq!(c.call(&["respond", "openvpn", ID], b"kind=crv1\nresponse=999999\n").code, 0);
        assert_eq!(err(&up.join().unwrap()), "Authentication failed (AUTH_FAILED)");
    });
    // Cancelled by the user.
    std::thread::scope(|s| {
        let up = s.spawn(|| c.up("crv1", "dev tun\n", ""));
        eventually("the challenge", || !c.call(&["auth-state", ID], b"").stdout.is_empty());
        assert_eq!(c.call(&["respond", "openvpn", ID], b"kind=cancel\nresponse=\n").code, 0);
        assert_eq!(err(&up.join().unwrap()), "Authentication cancelled");
    });
    assert!(!c.run_dir().exists());
}

#[test]
fn the_driver_follows_the_config_and_a_dco_incompatibility_is_retried_once_with_tap_windows6() {
    let c = Console::start();
    let r = c.up("dco", "dev tun\n", "");
    assert_eq!(r.code, 0, "{}", err(&r));
    let log = c.log();
    let dco = log.find("fake openvpn: driver ovpn-dco").expect("first DCO");
    let retry =
        log.find("[WinVPN] DCO cannot run this connection (pushed options); retrying with TAP-Windows6").unwrap();
    let tap = log.find("fake openvpn: driver tap-windows6").expect("then TAP-Windows6");
    assert!(dco < retry && retry < tap, "{log}");
    assert_eq!(c.call(&["down", "openvpn", ID], b"").code, 0);
    // A layer-2 config goes to TAP-Windows6 at once.
    let r = c.up("ok", "dev tap\n", "");
    assert_eq!(r.code, 0, "{}", err(&r));
    let log = c.log();
    assert!(log.contains("fake openvpn: driver tap-windows6") && !log.contains("ovpn-dco"), "{log}");
    assert_eq!(c.call(&["down", "openvpn", ID], b"").code, 0);
}

#[test]
fn a_down_while_connecting_stops_the_connect() {
    let c = Console::start();
    std::thread::scope(|s| {
        let up = s.spawn(|| c.up("hang", "dev tun\n", ""));
        eventually("the connect in progress", || {
            String::from_utf8(c.call(&["status"], b"").stdout).unwrap().contains("connecting")
        });
        let started = Instant::now();
        assert_eq!(c.call(&["down", "openvpn", ID], b"").code, 0);
        let r = up.join().unwrap();
        assert_eq!(r.code, 1);
        assert!(started.elapsed() < Duration::from_secs(10));
    });
    assert!(!c.run_dir().exists());
    let st = String::from_utf8(c.call(&["status"], b"").stdout).unwrap();
    assert!(!st.contains(ID), "{st}");
}
