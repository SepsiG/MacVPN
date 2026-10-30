//! The app-core control server over the real Linux transport (`LinTransport`) with the example client: the socket in
//! the runtime dir, pairing pins this test binary's real path (`SO_PEERCRED` + `/proc/<pid>/exe`), `hello` answers
//! the API version, and a client that has not authenticated is refused.

#![cfg(target_os = "linux")]

use macvpn_app_core::ConnectionItem;
use macvpn_app_core::control::{
    ControlHost, ControlLimits, ControlOptions, ControlServer, PairingAnswer, PairingRequest, StopMode,
};
use macvpn_control_client::{API_VERSION, Client, ErrorCode};
use macvpn_core::control::protocol::ErrorCode as WireError;
use macvpn_core::models::{Connection, ConnectionState, VPNKind, uuid_string};
use macvpn_platform_linux::LinTransport;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn temp_root(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("linvpn-server-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// One connection; every pairing is approved with it.
struct Host {
    item: ConnectionItem,
    key: String,
    requests: Mutex<Vec<PairingRequest>>,
    logs: Mutex<Vec<String>>,
}

impl ControlHost for Host {
    fn items(&self) -> Vec<ConnectionItem> {
        vec![self.item.clone()]
    }

    fn state(&self, _key: &str) -> ConnectionState {
        ConnectionState::Disconnected
    }

    fn connect(&self, _key: &str) -> Result<(), WireError> {
        Err(WireError::Failed)
    }

    fn disconnect(&self, _key: &str) {}

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

#[test]
fn the_server_pairs_and_authenticates_over_the_runtime_dir_socket() {
    let run = temp_root("run");
    let data = temp_root("data");
    let c = Connection::new("Office VPN", VPNKind::Openvpn);
    let key = uuid_string(&c.id);
    let host = Arc::new(Host {
        item: ConnectionItem::Managed(c),
        key: key.clone(),
        requests: Mutex::new(Vec::new()),
        logs: Mutex::new(Vec::new()),
    });
    let mut options = ControlOptions::new(data.join("control"), data.clone());
    options.limits = ControlLimits { hello_failure_delay: Duration::from_millis(10), ..ControlLimits::default() };
    let mut server = ControlServer::start(options, host.clone(), Arc::new(LinTransport::under(&run))).unwrap();
    let socket = run.join("linvpn/control/linvpn.sock");
    assert_eq!(server.endpoint(), socket.display().to_string());
    assert_eq!(server.socket_file(), Some(socket.as_path()));

    // Not authenticated: refused.
    let mut unpaired = Client::connect(&socket).unwrap();
    assert_eq!(unpaired.list().err().unwrap().code(), Some(ErrorCode::Unauthorized));
    drop(unpaired);

    let pairing = Client::pair(&socket, "Remote Desktop").unwrap();
    let exe = std::env::current_exe().unwrap().into_os_string().into_string().unwrap();
    let requests = host.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].executable, exe);

    let mut client = Client::connect(&socket).unwrap();
    assert_eq!(client.hello(&pairing.token).unwrap(), API_VERSION);
    assert_eq!(API_VERSION, 1);
    assert_eq!(client.list().unwrap()[0].id, key);
    drop(client);
    assert_eq!(Client::open(&socket, "not-the-token").err().unwrap().code(), Some(ErrorCode::Unauthorized));

    server.stop(StopMode::EndLeases);
    let logs = host.logs.lock().unwrap().clone();
    assert!(logs.iter().all(|l| !l.contains(&pairing.token)), "{logs:?}");
    assert!(logs.contains(&format!("listening on {}", socket.display())), "{logs:?}");
    assert!(!socket.exists(), "the socket is removed at stop");
    std::fs::remove_dir_all(run).unwrap();
    std::fs::remove_dir_all(data).unwrap();
}
