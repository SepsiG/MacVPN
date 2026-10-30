#![cfg(target_os = "linux")]
//! The `linvpn-xfrmd` client (IKEv2 traffic and liveness) against a fake server on a socket in a temp dir: the
//! request it sends, the answers it accepts, and every failure falling back to "no counters".

use macvpn_core::xfrmd::{Counters, Request, Target};
use macvpn_platform_linux::lin_for_tests::nm::xfrmd_client;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const ID: &str = "0b5f7c1e-2d3a-4b5c-8d6e-7f8091a2b3c4";

fn request() -> Request {
    Request { target: Target::Linvpn(Uuid::parse_str(ID).unwrap()) }
}

fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("linvpn-xfrmd-client-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// A fake server answering one connection with `answer`; the request line it read.
fn serve_once(tag: &str, answer: &'static [u8]) -> (PathBuf, thread::JoinHandle<String>) {
    let dir = tmp(tag);
    let sock = dir.join("xfrmd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let t = thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&s).read_line(&mut line).unwrap();
        let _ = (&s).write_all(answer);
        line
    });
    (sock, t)
}

#[test]
fn counters_and_n_are_read_and_the_request_is_the_wire_form() {
    let (sock, t) = serve_once("t", b"T 9000 300\n");
    let got = xfrmd_client::query_within(&sock, &request(), Duration::from_secs(2)).unwrap();
    assert_eq!(got, Some(Counters { rx: 9000, tx: 300 }));
    assert_eq!(t.join().unwrap(), format!("linvpn-xfrmd-v1 linvpn {ID}\n"));
    let (sock, t) = serve_once("n", b"N\n");
    assert_eq!(xfrmd_client::query_within(&sock, &request(), Duration::from_secs(2)).unwrap(), None);
    t.join().unwrap();
}

#[test]
fn malformed_or_oversized_answers_are_errors() {
    for (tag, answer) in [("bad", &b"T 1\n"[..]), ("long", &[b'7'; 200][..]), ("utf", &b"T \xff 1\n"[..])] {
        let answer: &'static [u8] = Box::leak(answer.to_vec().into_boxed_slice());
        let (sock, t) = serve_once(tag, answer);
        assert!(xfrmd_client::query_within(&sock, &request(), Duration::from_secs(2)).is_err(), "{tag}");
        t.join().unwrap();
    }
}

#[test]
fn a_silent_server_times_out() {
    let dir = tmp("timeout");
    let sock = dir.join("xfrmd.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let hold = thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_millis(800));
        drop(s);
    });
    let start = Instant::now();
    assert!(xfrmd_client::query_within(&sock, &request(), Duration::from_millis(200)).is_err());
    assert!(start.elapsed() < Duration::from_millis(700));
    hold.join().unwrap();
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn no_server_is_an_error_and_the_installed_one_is_only_trusted_as_roots_socket() {
    let dir = tmp("none");
    assert!(xfrmd_client::query_within(&dir.join("missing.sock"), &request(), Duration::from_secs(1)).is_err());
    let _ = fs::remove_dir_all(dir);
    assert_eq!(xfrmd_client::SOCKET, "/run/linvpn-xfrmd.sock");
    // The tests' machine has no linvpn-xfrmd (or one that does not know this id): no counters, never a panic.
    assert_eq!(xfrmd_client::counters(&Target::Linvpn(Uuid::new_v4())), None);
}
