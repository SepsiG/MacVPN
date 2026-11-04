//! `mvpn serve` (root layer 13) end to end as a standard user, without launchd: the built `mvpn` runs the same
//! serve loop on a socket in a temp directory (`mvpn __serve-on`, test mode only), with the test mode's settings.
//! The answers are compared with what `mvpn status` / `liveness` / `traffic` print on the command line.
#![cfg(target_os = "macos")]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";

/// A run directory with one WireGuard connection whose interface is gone (state `failed`), and the `MVPN_*`
/// environment that points the root layer there.
fn sandbox() -> (PathBuf, Vec<(&'static str, String)>) {
    // Short: a Unix socket path is at most 104 bytes.
    let base = std::env::temp_dir().join(format!("mvqd-{}", &uuid::Uuid::new_v4().to_string()[..8]));
    let run = base.join("run");
    std::fs::create_dir_all(run.join(ID)).unwrap();
    std::fs::write(run.join(ID).join("kind"), "wireguard\n").unwrap();
    std::fs::write(run.join(ID).join("iface"), "mv12345678\n").unwrap();
    let p = |n: &str| base.join(n).display().to_string();
    let env = vec![
        ("MVPN_RUN_BASE", run.display().to_string()),
        ("MVPN_LOG_BASE", p("log")),
        ("MVPN_WG_RUN", p("wg")),
        ("MVPN_DNS_BASE", p("dns")),
        ("MVPN_BREW", p("brew")),
        ("MVPN_UI_BASE", p("ui")),
    ];
    (base, env)
}

fn mvpn(env: &[(&str, String)]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_mvpn"));
    c.envs(env.iter().map(|(k, v)| (*k, v.as_str()))).stdin(Stdio::null());
    c
}

/// `<exit code>\n<stdout>` of the command line, as the daemon frames it.
fn cli(env: &[(&str, String)], args: &[&str]) -> String {
    let out = mvpn(env).args(args).output().unwrap();
    format!("{}\n{}", out.status.code().unwrap(), String::from_utf8(out.stdout).unwrap())
}

fn ask(sock: &Path, request: &[u8]) -> String {
    let mut c = UnixStream::connect(sock).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let _ = c.write_all(request);
    let mut answer = Vec::new();
    let _ = c.read_to_end(&mut answer);
    String::from_utf8(answer).unwrap()
}

#[test]
fn serve_answers_like_the_command_line_and_exits_when_idle() {
    let (base, env) = sandbox();
    let sock = base.join("q.sock");
    let uid = String::from_utf8(Command::new("/usr/bin/id").arg("-u").output().unwrap().stdout).unwrap();
    let uid = uid.trim();
    let mut child = mvpn(&env).args(["__serve-on", sock.to_str().unwrap(), uid, "2"]).spawn().unwrap();
    let end = Instant::now() + Duration::from_secs(10);
    while !sock.exists() {
        assert!(Instant::now() < end, "the socket did not appear");
        std::thread::sleep(Duration::from_millis(20));
    }
    let status = ask(&sock, b"status\n");
    assert!(status.starts_with("0\n[{\"id\":\"0F1E2D3C-"), "{status}");
    assert_eq!(status, cli(&env, &["status"]));
    for verb in ["liveness", "traffic"] {
        assert_eq!(ask(&sock, format!("{verb} {ID}\n").as_bytes()), cli(&env, &[verb, ID]), "{verb}");
        assert_eq!(ask(&sock, format!("{verb} {ID}\n").as_bytes()), "1\n", "{verb}");
    }
    // Nothing that changes state, nothing malformed: closed without an answer.
    for bad in [format!("down wireguard {ID}\n"), "version\n".into(), "status".into(), "x".repeat(300)] {
        assert_eq!(ask(&sock, bad.as_bytes()), "", "{bad:?}");
    }
    assert!(base.join("run").join(ID).join("kind").exists());
    // Idle for 2 s: exits 0 (launchd would start it again on the next connection).
    let end = Instant::now() + Duration::from_secs(20);
    let code = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s.code();
        }
        if Instant::now() > end {
            let _ = child.kill();
            panic!("still running after the idle time");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(code, Some(0));
    let _ = std::fs::remove_dir_all(&base);
}

/// Not root: `serve` itself needs launchd's socket and refuses without one; its argument must be `--uid <n>`.
#[test]
fn serve_without_launchd_or_with_bad_arguments_refuses() {
    let (base, env) = sandbox();
    assert_eq!(mvpn(&env).args(["serve", "--uid", "501"]).status().unwrap().code(), Some(1));
    for bad in [&["serve"][..], &["serve", "--uid", "x"], &["serve", "--uid", "501", "--debug"]] {
        assert_eq!(mvpn(&env).args(bad).status().unwrap().code(), Some(2), "{bad:?}");
    }
    let _ = std::fs::remove_dir_all(&base);
}
