#![cfg(target_os = "linux")]

use macvpn_platform_api::{Accepted, ControlTransport, PeerUser};
use macvpn_platform_linux::LinTransport;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn temp_root(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("linvpn-control-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[test]
fn binds_in_the_runtime_dir_and_identifies_the_peer() {
    let root = temp_root("ok");
    let audit = temp_root("audit");
    let t = LinTransport::under(&root);
    t.prepare_dir(&audit.join("control")).unwrap();
    let bound = t.bind(&audit.join("control")).unwrap();
    let socket = root.join("linvpn/control/linvpn.sock");
    assert_eq!(bound.socket_file.as_deref(), Some(socket.as_path()));
    assert_eq!(bound.display, socket.display().to_string());
    for dir in [root.join("linvpn"), root.join("linvpn/control")] {
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700, "{}", dir.display());
    }
    let _client = UnixStream::connect(&socket).unwrap();
    let Accepted::Client { peer, .. } = bound.listener.accept(Duration::from_millis(500)).unwrap() else {
        panic!("no client")
    };
    let peer = peer.unwrap();
    assert!(peer.same_user);
    assert!(matches!(peer.user, PeerUser::Uid(_)));
    assert_eq!(peer.pid, std::process::id() as i32);
    assert_eq!(peer.executable.as_deref(), std::env::current_exe().unwrap().to_str());
    // A second bind while the first holds the lock: AddrInUse.
    assert_eq!(t.bind(&audit.join("control")).err().map(|e| e.kind()), Some(std::io::ErrorKind::AddrInUse));
}

#[test]
fn a_runtime_dir_open_to_others_is_refused() {
    let root = temp_root("open");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let e = LinTransport::under(&root).bind(&temp_root("a2")).err().unwrap();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn a_symlinked_runtime_dir_is_refused() {
    let real = temp_root("real");
    let link = std::env::temp_dir().join(format!("linvpn-control-link-{}", uuid::Uuid::new_v4()));
    symlink(&real, &link).unwrap();
    assert!(LinTransport::under(&link).bind(&temp_root("a3")).is_err());
}

#[test]
fn no_runtime_dir_is_unsupported() {
    let e = LinTransport::without_runtime_dir().bind(&temp_root("a4")).err().unwrap();
    assert_eq!(e.kind(), std::io::ErrorKind::Unsupported);
}
