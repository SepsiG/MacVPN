//! The WinVPN Service's server in its debug console mode, over a real pipe, as a standard user (the console exists
//! only in debug builds, so these tests too).
#![cfg(all(windows, debug_assertions))]

mod common;

use common::console::{Console, framed, spawn, test_pipe, wireguard_dll};
use macvpn_core::service_proto as proto;
use macvpn_winsys::pipe::{self, ServerTrust};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
const WG: &str = "[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n";

#[test]
fn the_console_answers_the_protocol() {
    let c = Console::start(true);
    let v = c.call(&["version"], b"");
    assert_eq!((v.code, v.stdout.as_slice()), (0, &b"1\n"[..]));
    let up = c.call(&["up", "wireguard", ID, "--lang", "en"], &framed(WG));
    assert_eq!(up.code, 0, "{}", String::from_utf8_lossy(&up.stderr));
    let st = String::from_utf8(c.call(&["status"], b"").stdout).unwrap();
    assert!(st.contains(ID), "{st}");
    assert_eq!(c.call(&["down", "wireguard", ID], b"").code, 0);
    // The data directory the console created is private (this user and SYSTEM only), with its two folders.
    let f = macvpn_winsys::file::open_metadata(&c.data, false).unwrap();
    assert!(macvpn_winsys::file::has_protection(&f, macvpn_winsys::file::Protection::Private, true).unwrap());
    assert!(c.data.join("run").is_dir() && c.data.join("logs").is_dir());
}

#[test]
fn a_malformed_or_slow_request_gets_no_service() {
    let c = Console::start(true);
    let mut s = pipe::connect_with(&c.pipe, Duration::from_secs(5), ServerTrust::SameUser).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let r = proto::read_response(&mut s).unwrap();
    assert_eq!(r.code, 2);
    // Silent client: closed after the 5 s request timeout, with an answer of code 2.
    let mut s = pipe::connect_with(&c.pipe, Duration::from_secs(5), ServerTrust::SameUser).unwrap();
    let started = std::time::Instant::now();
    let r = proto::read_response(&mut s);
    assert!(started.elapsed() >= Duration::from_secs(5) && started.elapsed() < Duration::from_secs(9));
    assert!(r.map(|r| r.code == 2).unwrap_or(true));
    // A trickling client (a byte every second) gets no more time: 5 s for the whole request, not per read.
    let mut s = pipe::connect_with(&c.pipe, Duration::from_secs(5), ServerTrust::SameUser).unwrap();
    let started = std::time::Instant::now();
    for b in b"winvpn 1\nargs 1\n" {
        if s.write_all(&[*b]).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(700));
    }
    let r = proto::read_response(&mut s);
    assert!(started.elapsed() < Duration::from_secs(13), "{:?}", started.elapsed());
    assert!(r.map(|r| r.code == 2).unwrap_or(true));
    // The server still serves.
    assert_eq!(c.call(&["version"], b"").code, 0);
}

/// Security review L-4: clients that open the pipe without SQOS and write nothing (each could hold an accept loop
/// for 2 s) do not hold up anyone else: a request made while they wait is answered at once, and they are closed
/// unanswered after their 2 s.
#[test]
fn silent_clients_without_sqos_do_not_hold_up_other_requests() {
    let c = Console::start(true);
    assert_eq!(c.call(&["version"], b"").code, 0);
    // std opens without SQOS; a busy pipe (the next instance not made yet) is tried again.
    let open_silent = || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match std::fs::OpenOptions::new().read(true).write(true).open(&c.pipe) {
                Err(e) if e.raw_os_error() == Some(231) && std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                r => break r.unwrap(),
            }
        }
    };
    let silent: Vec<std::fs::File> = (0..4).map(|_| open_silent()).collect();
    let started = std::time::Instant::now();
    let v = c.call(&["version"], b"");
    assert_eq!(v.code, 0);
    assert!(started.elapsed() < Duration::from_millis(1500), "{:?}", started.elapsed());
    // The silent ones get no answer: closed after their wait.
    for mut s in silent {
        let mut buf = [0u8; 1];
        assert_eq!(std::io::Read::read(&mut s, &mut buf).unwrap_or(0), 0);
    }
    assert_eq!(c.call(&["version"], b"").code, 0);
}

#[test]
fn the_real_engines_fail_cleanly_without_admin_rights() {
    // The premise: a standard user (the test machine's SSH account). Elevated (GitHub's runners run as an
    // administrator) the console may create adapters, so `up` would install wireguard-nt's driver and connect.
    if macvpn_winsys::sid::this_process_is_elevated() {
        eprintln!("skipped: this process is elevated; the test is about a standard user");
        return;
    }
    // No wireguard.dll next to the console's exe: refused with the repair hint.
    let c = Console::start(false);
    let r = c.call(&["up", "wireguard", ID, "--lang", "en"], &framed(WG));
    assert_eq!(r.code, 1);
    assert!(String::from_utf8_lossy(&r.stderr).contains("Repair WinVPN"), "{}", String::from_utf8_lossy(&r.stderr));
    let r = c.call(&["engine"], b"");
    let facts = proto::EngineFacts::parse(&r.stdout).unwrap();
    assert_eq!(facts.wireguard.dll_version, None);
    assert!(facts.wireguard.problem.is_some_and(|p| p.contains("Repair WinVPN")));
    // OpenVPN: the trust checks before every start (the test machine has no OpenVPN Community until CP1).
    let config = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nnobind\n";
    let r = c.call(&["up", "openvpn", ID, "--lang", "en"], &framed(config));
    assert_eq!(r.code, 1);
    let facts = macvpn_core::service_proto::EngineFacts::parse(&c.call(&["engine"], b"").stdout).unwrap();
    if facts.openvpn.path.is_none() {
        assert_eq!(String::from_utf8_lossy(&r.stderr).trim(), "OpenVPN Community is not installed.");
        assert_eq!(facts.openvpn.problem.as_deref(), Some("OpenVPN Community is not installed."));
    }
    // The pinned DLL loads (loading installs nothing); a standard user cannot create an adapter, so `up` stops
    // before wireguard-nt is asked to (no driver install is attempted) and nothing of the connection remains.
    let dll = wireguard_dll();
    let c = Console::start_with(&["--wireguard-dll", dll.to_str().unwrap()]);
    let facts = proto::EngineFacts::parse(&c.call(&["engine"], b"").stdout).unwrap();
    assert_eq!((facts.wireguard.dll_version.as_deref(), facts.wireguard.problem), (Some("1.1.0"), None));
    let r = c.call(&["up", "wireguard", ID, "--lang", "en"], &framed(WG));
    assert_eq!(r.code, 1);
    assert!(
        String::from_utf8_lossy(&r.stderr).contains("Cannot create the WireGuard adapter ("),
        "{}",
        String::from_utf8_lossy(&r.stderr)
    );
    let st = String::from_utf8(c.call(&["status"], b"").stdout).unwrap();
    assert!(!st.contains(ID), "{st}");
    // The connection's log names the step, never a key.
    let log = c.call(&["log", ID, "0"], b"");
    let text = String::from_utf8_lossy(&log.stdout);
    assert!(text.contains("Cannot create the WireGuard adapter"), "{text}");
    assert!(!text.contains("bWFjdnBu"), "{text}");
}

#[test]
fn a_wireguard_dll_that_is_not_the_pinned_one_is_never_loaded() {
    // The pinned DLL with one byte appended (still a loadable PE file): refused by its hash, before loading.
    let dir = std::env::temp_dir().join(format!("winvpn-wgdll-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let tampered = dir.join("wireguard.dll");
    let mut bytes = std::fs::read(wireguard_dll()).unwrap();
    bytes.push(0);
    std::fs::write(&tampered, &bytes).unwrap();
    {
        let c = Console::start_with(&["--wireguard-dll", tampered.to_str().unwrap()]);
        let r = c.call(&["up", "wireguard", ID, "--lang", "en"], &framed(WG));
        assert_eq!(r.code, 1);
        let err = String::from_utf8_lossy(&r.stderr).into_owned();
        assert!(err.contains("wireguard.dll does not match its pinned version. Repair WinVPN."), "{err}");
        let facts = proto::EngineFacts::parse(&c.call(&["engine"], b"").stdout).unwrap();
        assert_eq!(facts.wireguard.dll_version, None);
        // The file is still deletable: the console never mapped it.
    }
    std::fs::remove_file(&tampered).unwrap();
    // A relative path is refused by the console's argument check.
    let status = Command::new(env!("CARGO_BIN_EXE_mvpn"))
        .args(["console", "--pipe", &test_pipe(), "--data", dir.join("d").to_str().unwrap()])
        .args(["--wireguard-dll", "wireguard.dll"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_console_refuses_an_unsafe_data_directory() {
    // A data directory that inherits the temp folder's permissions is not private: the console runs degraded.
    let data = std::env::temp_dir().join(format!("winvpn-open-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&data).unwrap();
    let pipe = test_pipe();
    let mut child = spawn(&["--pipe", &pipe, "--data", data.to_str().unwrap(), "--fake-engine", "--existing-data"]);
    let mut s = pipe::connect_with(&pipe, Duration::from_secs(5), ServerTrust::SameUser).unwrap();
    proto::write_request(&mut s, &["up", "wireguard", ID, "--lang", "en"], &framed(WG)).unwrap();
    let r = proto::read_response(&mut s).unwrap();
    assert_eq!(r.code, 1);
    assert!(String::from_utf8_lossy(&r.stderr).contains("unsafe permissions"));
    // `engine` names the problem; nothing was created inside the folder (it is never repaired).
    let mut s = pipe::connect_with(&pipe, Duration::from_secs(5), ServerTrust::SameUser).unwrap();
    proto::write_request(&mut s, &["engine"], b"").unwrap();
    let facts = macvpn_core::service_proto::EngineFacts::parse(&proto::read_response(&mut s).unwrap().stdout).unwrap();
    assert!(facts.problem.is_some_and(|p| p.contains("unsafe permissions")));
    assert_eq!(std::fs::read_dir(&data).unwrap().count(), 0);
    drop(child.stdin.take());
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&data);
}

#[test]
fn the_console_refuses_a_data_directory_that_is_a_junction() {
    // A junction at the data directory's name (a planted link) is never followed: degraded.
    let base = std::env::temp_dir().join(format!("winvpn-junction-{}", uuid::Uuid::new_v4()));
    let (target, link) = (base.join("target"), base.join("link"));
    std::fs::create_dir_all(&target).unwrap();
    macvpn_winsys::file::create_dir(&link, Some(macvpn_winsys::file::Protection::Private)).unwrap();
    macvpn_winsys::file::make_junction_for_tests(&link, &format!(r"\??\{}", target.display())).unwrap();
    let pipe = test_pipe();
    let mut child = spawn(&["--pipe", &pipe, "--data", link.to_str().unwrap(), "--fake-engine", "--existing-data"]);
    let mut s = pipe::connect_with(&pipe, Duration::from_secs(5), ServerTrust::SameUser).unwrap();
    proto::write_request(&mut s, &["up", "wireguard", ID, "--lang", "en"], &framed(WG)).unwrap();
    let r = proto::read_response(&mut s).unwrap();
    assert_eq!(r.code, 1);
    assert!(String::from_utf8_lossy(&r.stderr).contains("unsafe permissions"));
    assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0, "nothing was created through the junction");
    drop(child.stdin.take());
    let _ = child.wait();
    let _ = std::fs::remove_dir(&link);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn the_console_refuses_bad_arguments() {
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_mvpn"))
            .arg("console")
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .code()
    };
    let data = std::env::temp_dir().join(format!("winvpn-args-{}", uuid::Uuid::new_v4()));
    let d = data.to_str().unwrap();
    // Only test pipe names; no unknown option; a data directory that exists needs --existing-data.
    assert_eq!(run(&["--pipe", r"\\.\pipe\WinVPN", "--data", d]), Some(2));
    assert_eq!(run(&["--pipe", &test_pipe(), "--data", d, "--bogus"]), Some(2));
    assert_eq!(run(&["--pipe", &test_pipe()]), Some(2));
    let temp = std::env::temp_dir();
    assert_eq!(run(&["--pipe", &test_pipe(), "--data", temp.to_str().unwrap()]), Some(2));
    assert!(!data.exists());
}
