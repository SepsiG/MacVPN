//! The service endpoint's DACL and the client's trust (run as a standard user: the server is owned by this user,
//! the production shape is checked by the admin test at the end and, with this user as a test-only owner, by the
//! unit tests in `src/pipe.rs`).
#![cfg(windows)]

use macvpn_winsys::pipe::{self, Endpoint, ServerTrust};
use macvpn_winsys::sid::Sid;
use std::io::{ErrorKind, Read, Write};
use std::time::Duration;

fn name() -> String {
    format!(r"\\.\pipe\WinVPN-test-{}", uuid::Uuid::new_v4())
}

#[test]
fn the_test_endpoint_grants_clients_no_create_instance_right() {
    let n = name();
    let l = pipe::Listener::bind_endpoint(&n, Endpoint::ServiceForTests).unwrap();
    let dacl = l.dacl_masks().unwrap();
    let interactive = Sid::interactive().to_string();
    let entry = dacl.iter().find(|e| e.sid == interactive).expect("INTERACTIVE is granted");
    assert!(entry.allow);
    assert_eq!(entry.mask & pipe::FILE_CREATE_PIPE_INSTANCE, 0, "{:#x}", entry.mask);
    assert_eq!(entry.mask & (pipe::WRITE_DAC | pipe::WRITE_OWNER), 0);
    assert_eq!(entry.mask, pipe::SERVICE_CLIENT_ACCESS);
    // Nobody but the owner (this user, standing in for SYSTEM) and SYSTEM may create instances.
    let me = Sid::current_user().unwrap().to_string();
    let system = Sid::local_system().to_string();
    for e in &dacl {
        assert!(e.allow, "{e:?}");
        if e.sid != me && e.sid != system {
            assert_eq!(e.mask & pipe::FILE_CREATE_PIPE_INSTANCE, 0, "{e:?}");
        }
    }
}

#[test]
fn a_client_trusting_local_system_refuses_a_user_owned_pipe() {
    let n = name();
    let _l = pipe::Listener::bind_endpoint(&n, Endpoint::ServiceForTests).unwrap();
    let e = pipe::connect_with(&n, Duration::from_secs(2), ServerTrust::LocalSystem).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
    assert_eq!(e.to_string(), pipe::NOT_THE_SERVICE);
}

#[test]
fn a_client_trusting_local_system_finds_no_pipe() {
    let e = pipe::connect_with(&name(), Duration::from_secs(1), ServerTrust::LocalSystem).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
}

#[test]
fn a_same_user_client_talks_to_the_test_endpoint() {
    let n = name();
    let l = pipe::Listener::bind_endpoint(&n, Endpoint::ServiceForTests).unwrap();
    let server = std::thread::spawn(move || {
        let (s, peer) = loop {
            if let Some(c) = l.accept(Duration::from_millis(100)).unwrap() {
                break c;
            }
        };
        assert_eq!(peer.unwrap().sid, Sid::current_user().unwrap());
        let mut buf = [0u8; 4];
        let mut s2 = s.clone();
        s2.read_exact(&mut buf).unwrap();
        s2.write_all(&buf).unwrap();
    });
    let mut c = pipe::connect_with(&n, Duration::from_secs(2), ServerTrust::SameUser).unwrap();
    c.write_all(b"ping").unwrap();
    let mut back = [0u8; 4];
    c.read_exact(&mut back).unwrap();
    assert_eq!(&back, b"ping");
    server.join().unwrap();
}

#[test]
fn the_production_endpoint_needs_local_system() {
    // As a standard user the owner cannot be SYSTEM: binding the production shape fails closed.
    let e = pipe::Listener::bind_endpoint(&name(), Endpoint::Service).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::PermissionDenied);
}

#[test]
#[ignore = "admin: needs the installed WinVPN Service (CI windows-admin job, or the maintainer in an elevated Git Bash)"]
fn admin_the_installed_service_pipe_is_owned_by_system() {
    let c = pipe::connect_with(r"\\.\pipe\WinVPN", Duration::from_secs(5), ServerTrust::LocalSystem).unwrap();
    drop(c);
    let dacl = pipe::dacl_of_name(r"\\.\pipe\WinVPN").unwrap();
    let interactive = Sid::interactive().to_string();
    let network = Sid::network().to_string();
    assert!(dacl.iter().any(|e| !e.allow && e.sid == network));
    assert!(dacl.iter().any(|e| e.allow && e.sid == interactive && e.mask == pipe::SERVICE_CLIENT_ACCESS));
    assert!(dacl.iter().all(|e| !e.allow || e.sid == interactive || e.sid == Sid::local_system().to_string()));
}
