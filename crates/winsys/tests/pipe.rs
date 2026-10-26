//! Named pipes on a real Windows system.

#![cfg(windows)]

use macvpn_winsys::pipe::{self, Listener, NetworkLogons, PipeStream};
use macvpn_winsys::sid::Sid;
use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn unique_name() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!(r"\\.\pipe\winsys-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst))
}

/// The tests run over SSH on the Windows test machine: a network logon, which [`Listener::bind`]'s DACL refuses
/// (see `the_default_pipe_refuses_this_users_network_logons`). Everything else is tested on pipes that admit them.
fn bind(name: &str) -> Listener {
    Listener::bind_with(name, NetworkLogons::Allow).unwrap()
}

/// Whether this process's token has `NT AUTHORITY\NETWORK` (S-1-5-2): an SSH session has, a desktop session not.
fn in_network_logon() -> bool {
    let out = std::process::Command::new("whoami").args(["/groups", "/fo", "csv", "/nh"]).output().unwrap();
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).contains("\"S-1-5-2\"")
}

/// A connected pair: (server side, client side, the server's view of the peer).
fn pair() -> (Listener, PipeStream, PipeStream, pipe::Peer) {
    let name = unique_name();
    let listener = bind(&name);
    let client_name = name.clone();
    let client = thread::spawn(move || pipe::connect(&client_name, Duration::from_secs(5)).unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some((server, peer)) = listener.accept(Duration::from_millis(50)).unwrap() {
            return (listener, server, client.join().unwrap(), peer.unwrap());
        }
        assert!(Instant::now() < deadline, "no client within 5 s");
    }
}

#[test]
fn the_peer_is_this_process_and_user() {
    let (_l, _s, _c, peer) = pair();
    assert_eq!(peer.sid, Sid::current_user().unwrap());
    assert_eq!(peer.pid, std::process::id());
    let exe = std::env::current_exe().unwrap();
    let image = peer.image.expect("the image path");
    assert!(image.to_string_lossy().eq_ignore_ascii_case(&exe.to_string_lossy()), "{image:?} vs {exe:?}");
}

/// A client that opens the pipe without `SECURITY_SQOS_PRESENT` (Node's `net.connect`, most runtimes; std's
/// `OpenOptions` by default) can only be impersonated once it has written (`ERROR_CANNOT_IMPERSONATE` before): the
/// listener waits a moment for its first bytes, identifies it, and the bytes are still there to be read. Found by the
/// Windows smoke run (the control API's Node test client was closed as unidentified).
#[test]
fn a_client_without_sqos_is_identified_once_it_writes() {
    let name = unique_name();
    let listener = bind(&name);
    let client_name = name.clone();
    let client = thread::spawn(move || {
        let mut c = std::fs::OpenOptions::new().read(true).write(true).open(&client_name).unwrap();
        thread::sleep(Duration::from_millis(300));
        c.write_all(b"hello\n").unwrap();
        c
    });
    let (mut server, peer) = listener.accept(Duration::from_secs(5)).unwrap().expect("the client");
    let peer = peer.expect("identified after its first write");
    assert_eq!(peer.sid, Sid::current_user().unwrap());
    assert_eq!(peer.pid, std::process::id());
    let mut buf = [0u8; 6];
    server.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello\n");
    drop(client.join().unwrap());
}

/// Such a client that never writes stays unidentified (and the listener does not wait for it for long).
#[test]
fn a_silent_client_without_sqos_is_not_identified() {
    let name = unique_name();
    let listener = bind(&name);
    let _client = std::fs::OpenOptions::new().read(true).write(true).open(&name).unwrap();
    let started = Instant::now();
    let (_server, peer) = listener.accept(Duration::from_secs(5)).unwrap().expect("the client");
    assert!(peer.is_err());
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
}

/// Security review L-4: `accept_unidentified` hands a silent client out at once; its identification (up to
/// `FIRST_WRITE_WAIT`, then an error) runs wherever the caller runs it, so the next client is accepted meanwhile.
#[test]
fn a_silent_client_does_not_hold_up_the_next_accept() {
    let name = unique_name();
    let listener = bind(&name);
    let _silent = std::fs::OpenOptions::new().read(true).write(true).open(&name).unwrap();
    let started = Instant::now();
    let silent = listener.accept_unidentified(Duration::from_secs(5)).unwrap().expect("the silent client");
    assert!(started.elapsed() < Duration::from_millis(500), "{:?}", started.elapsed());
    let identifying = thread::spawn(move || {
        let started = Instant::now();
        (silent.identify().is_err(), started.elapsed())
    });
    // A second client (with SQOS: identified at once) is accepted and identified while the first one waits.
    let client_name = name.clone();
    let client = thread::spawn(move || pipe::connect(&client_name, Duration::from_secs(5)).unwrap());
    let started = Instant::now();
    let second = listener.accept_unidentified(Duration::from_secs(5)).unwrap().expect("the second client");
    let peer = second.identify().expect("identified");
    assert!(started.elapsed() < Duration::from_millis(1500), "{:?}", started.elapsed());
    assert_eq!(peer.sid, Sid::current_user().unwrap());
    let (refused, waited) = identifying.join().unwrap();
    assert!(refused, "a silent client stays unidentified");
    assert!(waited >= pipe::FIRST_WRITE_WAIT - Duration::from_millis(100), "{waited:?}");
    drop(client.join().unwrap());
}

#[test]
fn a_second_bind_of_the_same_name_is_addr_in_use() {
    let name = unique_name();
    let _first = Listener::bind(&name).unwrap();
    assert_eq!(Listener::bind(&name).err().unwrap().kind(), ErrorKind::AddrInUse);
}

#[test]
fn the_name_stays_taken_while_clients_come_and_go() {
    let name = unique_name();
    let listener = bind(&name);
    for _ in 0..3 {
        let client_name = name.clone();
        let client = thread::spawn(move || pipe::connect(&client_name, Duration::from_secs(5)).unwrap());
        let (server, _) = listener.accept(Duration::from_secs(5)).unwrap().expect("the client");
        let client = client.join().unwrap();
        client.shutdown(Shutdown::Both).unwrap();
        server.shutdown(Shutdown::Both).unwrap();
        // Between clients the name is still ours: nobody can create a first instance of it.
        assert_eq!(Listener::bind(&name).err().unwrap().kind(), ErrorKind::AddrInUse);
    }
}

#[test]
fn accept_without_a_client_is_idle_after_the_poll() {
    let listener = Listener::bind(&unique_name()).unwrap();
    let start = Instant::now();
    assert!(listener.accept(Duration::from_millis(100)).unwrap().is_none());
    assert!(start.elapsed() >= Duration::from_millis(90));
}

#[test]
fn bytes_flow_both_ways_and_clones_share_the_stream() {
    let (_l, server, client, _) = pair();
    (&client).write_all(b"hello\n").unwrap();
    let mut buf = [0u8; 6];
    (&server).read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello\n");
    let clone = server.try_clone();
    (&clone).write_all(b"ok").unwrap();
    let mut two = [0u8; 2];
    (&client).read_exact(&mut two).unwrap();
    assert_eq!(&two, b"ok");
}

#[test]
fn a_clone_writes_while_another_clone_is_blocked_reading() {
    let (_l, server, client, _) = pair();
    let reader = server.try_clone();
    let blocked = thread::spawn(move || {
        let mut buf = [0u8; 4];
        (&reader).read_exact(&mut buf).unwrap();
        buf
    });
    thread::sleep(Duration::from_millis(100));
    (&server).write_all(b"ping").unwrap();
    let mut got = [0u8; 4];
    (&client).read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ping");
    (&client).write_all(b"pong").unwrap();
    assert_eq!(&blocked.join().unwrap(), b"pong");
}

#[test]
fn a_read_times_out_exactly() {
    let (_l, server, _client, _) = pair();
    server.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
    let start = Instant::now();
    let err = (&server).read(&mut [0u8; 1]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::TimedOut);
    let waited = start.elapsed();
    assert!(waited >= Duration::from_millis(140) && waited < Duration::from_secs(2), "{waited:?}");
    assert_eq!(server.set_read_timeout(Some(Duration::ZERO)).unwrap_err().kind(), ErrorKind::InvalidInput);
    assert_eq!(server.set_write_timeout(Some(Duration::ZERO)).unwrap_err().kind(), ErrorKind::InvalidInput);
}

/// A Windows wait can come back up to a timer tick (~15.6 ms) before its timeout; a read with timeout T must still
/// never time out before T has passed on the monotonic clock. Small timeouts, around and below a tick, many times.
#[test]
fn a_read_never_times_out_early() {
    let (_l, server, _client, _) = pair();
    for i in 0..120u64 {
        let timeout = Duration::from_micros(500 + (i % 12) * 1_700);
        server.set_read_timeout(Some(timeout)).unwrap();
        let start = Instant::now();
        let err = (&server).read(&mut [0u8; 1]).unwrap_err();
        let waited = start.elapsed();
        assert_eq!(err.kind(), ErrorKind::TimedOut);
        assert!(waited >= timeout, "iteration {i}: timed out after {waited:?}, before {timeout:?}");
    }
}

#[test]
fn data_after_a_timed_out_read_is_still_read() {
    let (_l, server, client, _) = pair();
    server.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    assert_eq!((&server).read(&mut [0u8; 1]).unwrap_err().kind(), ErrorKind::TimedOut);
    (&client).write_all(b"late").unwrap();
    server.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut got = [0u8; 4];
    (&server).read_exact(&mut got).unwrap();
    assert_eq!(&got, b"late");
}

#[test]
fn a_write_times_out_when_the_peer_does_not_read() {
    let (_l, server, _client, _) = pair();
    server.set_write_timeout(Some(Duration::from_millis(150))).unwrap();
    let chunk = vec![0x55u8; 256 * 1024];
    let start = Instant::now();
    let err = loop {
        if let Err(e) = (&server).write_all(&chunk) {
            break e;
        }
        assert!(start.elapsed() < Duration::from_secs(5), "the pipe never filled");
    };
    assert_eq!(err.kind(), ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn shutdown_read_ends_a_blocked_read() {
    let (_l, server, _client, _) = pair();
    let reader = server.try_clone();
    let blocked = thread::spawn(move || (&reader).read(&mut [0u8; 8]).unwrap());
    thread::sleep(Duration::from_millis(100));
    server.shutdown(Shutdown::Read).unwrap();
    assert_eq!(blocked.join().unwrap(), 0);
    // Reads stay at the end; writing still works.
    assert_eq!((&server).read(&mut [0u8; 8]).unwrap(), 0);
    (&server).write_all(b"still").unwrap();
}

#[test]
fn shutdown_both_ends_a_blocked_read_and_later_writes_fail() {
    let (_l, server, _client, _) = pair();
    let reader = server.try_clone();
    let blocked = thread::spawn(move || (&reader).read(&mut [0u8; 8]).unwrap());
    thread::sleep(Duration::from_millis(100));
    server.shutdown(Shutdown::Both).unwrap();
    assert_eq!(blocked.join().unwrap(), 0);
    assert_eq!((&server).write_all(b"x").unwrap_err().kind(), ErrorKind::BrokenPipe);
    assert!(!server.peer_connected());
}

#[test]
fn the_client_closing_is_eof_for_the_server_and_data_sent_before_survives() {
    let (_l, server, client, _) = pair();
    (&server).write_all(b"bye").unwrap();
    server.shutdown(Shutdown::Both).unwrap();
    let mut got = Vec::new();
    (&client).read_to_end(&mut got).unwrap();
    assert_eq!(got, b"bye");
    client.shutdown(Shutdown::Both).unwrap();
    assert!(!client.peer_connected());
}

#[test]
fn writing_to_a_closed_peer_is_broken_pipe() {
    let (_l, server, client, _) = pair();
    client.shutdown(Shutdown::Both).unwrap();
    assert_eq!((&server).write_all(b"x").unwrap_err().kind(), ErrorKind::BrokenPipe);
    assert_eq!((&server).read(&mut [0u8; 1]).unwrap(), 0);
}

#[test]
fn peer_connected_follows_the_other_end() {
    let (_l, server, client, _) = pair();
    assert!(server.peer_connected());
    client.shutdown(Shutdown::Both).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while server.peer_connected() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn peer_connected_does_not_consume_data() {
    let (_l, server, client, _) = pair();
    (&client).write_all(b"keep").unwrap();
    thread::sleep(Duration::from_millis(50));
    assert!(server.peer_connected());
    assert!(server.peer_connected());
    let mut got = [0u8; 4];
    (&server).read_exact(&mut got).unwrap();
    assert_eq!(&got, b"keep");
}

#[test]
fn connecting_to_a_missing_pipe_is_not_found() {
    assert_eq!(pipe::connect(&unique_name(), Duration::from_millis(200)).unwrap_err().kind(), ErrorKind::NotFound);
}

#[test]
fn the_client_opens_local_pipes_only() {
    for name in [r"\\localhost\pipe\x", r"C:\Windows\win.ini", r"\\.\pipe\", r"\\?\pipe\x"] {
        assert_eq!(
            pipe::connect(name, Duration::from_millis(200)).unwrap_err().kind(),
            ErrorKind::InvalidInput,
            "{name}"
        );
    }
}

/// The client refuses a server that runs as another user before it writes anything: the system's own RPC pipe
/// `lsass` is served by `NT AUTHORITY\SYSTEM`.
#[test]
fn the_client_refuses_a_server_of_another_user() {
    let err = pipe::connect(r"\\.\pipe\lsass", Duration::from_secs(2)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{err}");
    assert_eq!(err.to_string(), pipe::NOT_THIS_USER, "refused at open instead of by the server check: {err}");
}

#[test]
fn an_anonymous_client_cannot_be_identified() {
    use std::os::windows::fs::OpenOptionsExt;
    let name = unique_name();
    let listener = bind(&name);
    // SECURITY_ANONYMOUS: std adds SECURITY_SQOS_PRESENT to the flags it is given.
    let _anon = std::fs::OpenOptions::new().read(true).write(true).security_qos_flags(0).open(&name).unwrap();
    let (_server, peer) = listener.accept(Duration::from_secs(2)).unwrap().expect("the client");
    assert!(peer.is_err());
}

#[test]
fn a_client_over_the_network_redirector_is_refused() {
    let name = unique_name();
    // Without the NETWORK deny ACE: PIPE_REJECT_REMOTE_CLIENTS alone refuses the same pipe through SMB loopback.
    let _listener = bind(&name);
    let remote = name.replacen(r"\\.\", r"\\127.0.0.1\", 1);
    let err = std::fs::OpenOptions::new().read(true).write(true).open(&remote).unwrap_err();
    eprintln!("over SMB loopback: {err}");
}

#[test]
fn the_pipe_denies_the_network_and_admits_only_the_user_and_system() {
    let user = Sid::current_user().unwrap().to_string();
    let system = "S-1-5-18".to_string();
    let (_l, server, _c, _) = pair();
    assert_eq!(pipe::dacl_summary(&server).unwrap(), [(true, user.clone()), (true, system.clone())]);
    // The default: the same after a deny ACE for NETWORK.
    let listener = Listener::bind(&unique_name()).unwrap();
    assert_eq!(
        listener.dacl_summary().unwrap(),
        [(false, "S-1-5-2".to_string()), (true, "S-1-3-4".to_string()), (true, user), (true, system)]
    );
}

/// This user's network logon (the SSH session the tests run in) cannot open the default pipe even for `WRITE_DAC`
/// alone, so it cannot rewrite the DACL; the owner's implicit rights are replaced by the OWNER RIGHTS entry (review
/// L1). The pipe that admits network logons still opens for it.
#[test]
fn a_network_logon_cannot_rewrite_the_default_pipes_dacl() {
    use std::os::windows::fs::OpenOptionsExt;
    const WRITE_DAC: u32 = 0x0004_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    let open = |name: &str, access: u32| std::fs::OpenOptions::new().access_mode(access).open(name);
    let name = unique_name();
    let _listener = Listener::bind(&name).unwrap();
    if in_network_logon() {
        for access in [WRITE_DAC, READ_CONTROL | WRITE_DAC] {
            assert_eq!(open(&name, access).unwrap_err().raw_os_error(), Some(5), "access {access:#x}");
        }
    } else {
        open(&name, WRITE_DAC).unwrap();
    }
    let allowing = unique_name();
    let _admitting = bind(&allowing);
    open(&allowing, WRITE_DAC).unwrap();
}

#[test]
fn the_default_pipe_refuses_this_users_network_logons() {
    let name = unique_name();
    let _listener = Listener::bind(&name).unwrap();
    let result = pipe::connect(&name, Duration::from_secs(2));
    if in_network_logon() {
        assert_eq!(result.unwrap_err().raw_os_error(), Some(5));
    } else {
        result.unwrap();
    }
}

#[test]
fn user_pipe_names_carry_the_sid() {
    let name = pipe::user_pipe_name("WinVPN-control").unwrap();
    assert_eq!(name, format!(r"\\.\pipe\WinVPN-control-{}", Sid::current_user().unwrap()));
}

/// Needs a second standard account on the machine (manual checklist, "Control pipe: other users"): another user's
/// process opening `\\.\pipe\WinVPN-control-<this user's SID>` is denied by the DACL, and a pipe this user's
/// client finds served by that other user is refused with `NOT_THIS_USER`.
#[test]
#[ignore = "needs a second user account: manual checklist"]
fn another_user_is_refused_both_ways() {}
