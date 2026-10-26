//! The control transport over the named pipe (Windows), and the app-core control server over it with the real peer
//! identity: the same-user check, the executable path the pairing pins, and the audit lines.

#![cfg(windows)]

use macvpn_app_core::ConnectionItem;
use macvpn_app_core::control::{
    ControlHost, ControlLimits, ControlNotifier, ControlOptions, ControlServer, PairingAnswer, PairingRequest,
};
use macvpn_control_client::{Client, ErrorCode};
use macvpn_core::control::protocol::ErrorCode as WireError;
use macvpn_core::fsx::{self, Access, Follow};
use macvpn_core::models::{Connection, ConnectionState, VPNKind, uuid_string};
use macvpn_platform_api::{Accepted, PeerUser, Platform};
use macvpn_platform_win::{WinPlatform, control_transport_for_tests};
use macvpn_winsys::pipe::{self, NetworkLogons};
use macvpn_winsys::sid::Sid;
use std::io::{ErrorKind, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(format!("control-{}", uuid::Uuid::new_v4()))
}

fn test_pipe_name() -> String {
    format!(r"\\.\pipe\WinVPN-control-test-{}", uuid::Uuid::new_v4())
}

/// Whether this process's token has `NT AUTHORITY\NETWORK` (S-1-5-2): an SSH session has, a desktop session not.
fn in_network_logon() -> bool {
    let out = std::process::Command::new("whoami").args(["/groups", "/fo", "csv", "/nh"]).output().unwrap();
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stdout).contains("\"S-1-5-2\"")
}

/// The tests run over SSH on the Windows test machine (a network logon, which the production DACL refuses: see
/// `the_production_pipe_refuses_network_logons`), so they bind with `NetworkLogons::Allow`.
#[test]
fn bind_accept_and_the_peer() {
    let dir = temp_dir();
    let name = test_pipe_name();
    let transport = control_transport_for_tests(&name, NetworkLogons::Allow);
    let bound = transport.bind(&dir).unwrap();
    assert_eq!(bound.display, name);
    assert_eq!(bound.socket_file, None);
    assert!(fsx::has_access(&fsx::stat_path(&dir, Follow::No).unwrap(), Access::Private), "the directory is private");
    assert_eq!(transport.bind(&dir).err().unwrap().kind(), ErrorKind::AddrInUse);
    assert_ne!(transport.random_32().unwrap(), [0u8; 32]);
    assert_ne!(transport.random_32().unwrap(), transport.random_32().unwrap());
    assert!(matches!(bound.listener.accept(Duration::from_millis(1)).unwrap(), Accepted::Idle));

    let client = std::thread::spawn({
        let name = name.clone();
        move || {
            let s = pipe::connect(&name, Duration::from_secs(5)).unwrap();
            (&s).write_all(b"{}\n").unwrap();
            s
        }
    });
    let (stream, peer) = loop {
        if let Accepted::Client { stream, peer } = bound.listener.accept(Duration::from_millis(100)).unwrap() {
            break (stream, peer.unwrap());
        }
    };
    let me = Sid::current_user().unwrap().to_string();
    assert_eq!(peer.user, PeerUser::Sid(me.clone()));
    assert_eq!(peer.user.to_string(), format!("sid {me}"));
    assert!(peer.same_user);
    assert_eq!(peer.pid, std::process::id() as i32);
    let exe = std::env::current_exe().unwrap().to_string_lossy().to_lowercase();
    assert_eq!(peer.executable.map(|e| e.to_lowercase()), Some(exe));
    assert!(stream.peer_connected());
    assert!(stream.peer_connected(), "the check consumes nothing");
    // What the client sent is read first: a closed client's unread data keeps the pipe readable (as a socket), and
    // `peer_connected` consumes nothing.
    let mut stream = stream;
    let mut line = [0u8; 3];
    stream.read_exact(&mut line).unwrap();
    assert_eq!(&line, b"{}\n");
    drop(client.join().unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    while stream.peer_connected() {
        assert!(Instant::now() < deadline, "still connected after the close");
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(bound);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn closed_pipe_errors_are_already_closed() {
    let transport = control_transport_for_tests(r"\\.\pipe\unused", NetworkLogons::Allow);
    assert!(transport.is_already_closed(&std::io::Error::from(ErrorKind::BrokenPipe)));
    assert!(transport.is_already_closed(&std::io::Error::from_raw_os_error(233)));
    assert!(!transport.is_already_closed(&std::io::Error::from(ErrorKind::TimedOut)));
}

/// The production transport binds `\\.\pipe\WinVPN-control-<SID>` with the default DACL: this user's network
/// logons (an SSH session) are refused, the desktop session is admitted.
#[test]
fn the_production_pipe_refuses_network_logons() {
    let transport = WinPlatform::new(true).control_transport();
    let dir = temp_dir();
    let bound = match transport.bind(&dir) {
        Ok(bound) => bound,
        Err(e) if e.kind() == ErrorKind::AddrInUse => {
            eprintln!("skipped: a WinVPN of this user serves the control pipe");
            std::fs::remove_dir_all(dir).unwrap();
            return;
        }
        Err(e) => panic!("{e}"),
    };
    let name = pipe::user_pipe_name("WinVPN-control").unwrap();
    assert_eq!(bound.display, name);
    assert_eq!(bound.socket_file, None);
    let result = pipe::connect(&name, Duration::from_secs(2));
    if in_network_logon() {
        assert_eq!(result.unwrap_err().raw_os_error(), Some(5), "ERROR_ACCESS_DENIED");
    } else {
        result.unwrap();
    }
    drop(bound);
    std::fs::remove_dir_all(dir).unwrap();
}

/// `prepare_dir` makes the audit file's directory private, as `bind` does.
#[test]
fn prepare_dir_makes_the_directory_private() {
    let dir = temp_dir();
    let transport = control_transport_for_tests(&test_pipe_name(), NetworkLogons::Allow);
    transport.prepare_dir(&dir).unwrap();
    assert!(fsx::has_access(&fsx::stat_path(&dir, Follow::No).unwrap(), Access::Private));
    std::fs::remove_dir_all(dir).unwrap();
}

// MARK: - The server over the real pipe

/// A host with one connection that connects at once; it approves every pairing with that connection.
struct Host {
    item: ConnectionItem,
    key: String,
    states: Mutex<Vec<(String, ConnectionState)>>,
    requests: Mutex<Vec<PairingRequest>>,
    logs: Mutex<Vec<String>>,
    notifier: Mutex<Option<ControlNotifier>>,
}

impl Host {
    /// Sets a state and tells the server, as the connection manager does.
    fn set(&self, key: &str, state: ConnectionState) {
        self.states.lock().unwrap().push((key.into(), state.clone()));
        let notifier = self.notifier.lock().unwrap().clone();
        if let Some(n) = notifier {
            n.state_changed(key, &state);
        }
    }
}

impl ControlHost for Host {
    fn items(&self) -> Vec<ConnectionItem> {
        vec![self.item.clone()]
    }

    fn state(&self, key: &str) -> ConnectionState {
        let states = self.states.lock().unwrap();
        states.iter().rev().find(|(k, _)| k == key).map(|(_, s)| s.clone()).unwrap_or(ConnectionState::Disconnected)
    }

    fn connect(&self, key: &str) -> Result<(), WireError> {
        self.set(key, ConnectionState::Connecting);
        self.set(key, ConnectionState::Connected { ip: None, since: None });
        Ok(())
    }

    fn disconnect(&self, key: &str) {
        self.set(key, ConnectionState::Disconnected);
    }

    fn setup_ready_for(&self, _key: &str) -> bool {
        true
    }

    fn ask_pairing(&self, request: PairingRequest) -> PairingAnswer {
        self.requests.lock().unwrap().push(request);
        PairingAnswer::Approved(vec![self.key.clone()])
    }

    fn log(&self, line: String) {
        self.logs.lock().unwrap().push(line);
    }

    fn credentials_cancelled(&self, _key: &str) -> bool {
        false
    }
}

/// Pairing pins this test binary's real image path (from the pipe's peer), the token works in `hello` from the
/// same executable, and the audit lines show the path but never the token.
#[test]
fn the_server_pairs_and_authenticates_over_the_pipe_with_the_real_peer() {
    let dir = temp_dir();
    let name = test_pipe_name();
    let c = Connection::new("Office VPN", VPNKind::Openvpn);
    let key = uuid_string(&c.id);
    let host = Arc::new(Host {
        item: ConnectionItem::Managed(c),
        key: key.clone(),
        states: Mutex::new(Vec::new()),
        requests: Mutex::new(Vec::new()),
        logs: Mutex::new(Vec::new()),
        notifier: Mutex::new(None),
    });
    let mut options = ControlOptions::new(dir.join("control"), dir.clone());
    options.limits = ControlLimits { hello_failure_delay: Duration::from_millis(10), ..ControlLimits::default() };
    let transport = control_transport_for_tests(&name, NetworkLogons::Allow);
    let mut server = ControlServer::start(options, host.clone(), transport).unwrap();
    *host.notifier.lock().unwrap() = Some(server.notifier());
    assert_eq!(server.endpoint(), name);
    assert_eq!(server.socket_file(), None);

    let endpoint = PathBuf::from(&name);
    let pairing = Client::pair(&endpoint, "Remote Desktop").unwrap();
    let exe = std::env::current_exe().unwrap().into_os_string().into_string().unwrap();
    let requests = host.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].executable.eq_ignore_ascii_case(&exe), "{} vs {exe}", requests[0].executable);

    let mut client = Client::open(&endpoint, &pairing.token).unwrap();
    assert_eq!(client.list().unwrap()[0].id, key);
    client.up(&key, |_| {}).unwrap();
    drop(client);
    let deadline = Instant::now() + Duration::from_secs(5);
    while host.state(&key) != ConnectionState::Disconnected {
        assert!(Instant::now() < deadline, "the lease end did not disconnect");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(Client::open(&endpoint, "not-the-token").err().unwrap().code(), Some(ErrorCode::Unauthorized));

    server.stop(macvpn_app_core::control::StopMode::EndLeases);
    let logs = host.logs.lock().unwrap().clone();
    assert!(logs.iter().all(|l| !l.contains(&pairing.token)), "{logs:?}");
    assert!(logs.contains(&format!("listening on {name}")), "{logs:?}");
    assert!(logs.iter().any(|l| l.starts_with("paired “Remote Desktop” (") && l.contains(&requests[0].executable)));
    assert!(pipe::connect(&name, Duration::from_millis(200)).is_err(), "the pipe is gone after stop");
    std::fs::remove_dir_all(dir).unwrap();
}
