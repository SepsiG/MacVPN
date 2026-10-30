//! The control API socket: the private directory, the bind rules (stale socket, single instance, modes), the
//! peer identity and the random source.
#![cfg(unix)]
#![allow(unsafe_code)]

mod common;

use common::{Scratch, chmod, mode, short_scratch};
use macvpn_unixsys::control_socket::{
    self, LOCK_NAME, SOCKET_NAME, bind, is_already_closed, peer, prepare_dir, random_32, same_user,
};
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};

fn control_dir(scratch: &Scratch) -> std::path::PathBuf {
    let dir = scratch.join("control");
    prepare_dir(&dir).unwrap();
    dir
}

/// `getuid()` without spawning `/usr/bin/id` (as `common::getuid` does): a child spawned by a parallel test
/// briefly shares this process's descriptors, which would keep a dropped listener alive for a moment.
fn getuid() -> u32 {
    // SAFETY: no arguments, cannot fail.
    unsafe { libc::getuid() }
}

fn is_cloexec(fd: i32) -> bool {
    // SAFETY: plain integer arguments on an fd this test owns.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    flags >= 0 && flags & libc::FD_CLOEXEC != 0
}

#[test]
fn prepare_dir_creates_a_private_directory() {
    let scratch = short_scratch();
    let dir = scratch.join("control");
    prepare_dir(&dir).unwrap();
    let meta = std::fs::symlink_metadata(&dir).unwrap();
    assert!(meta.file_type().is_dir());
    assert_eq!(meta.uid(), getuid());
    assert_eq!(mode(&dir), 0o700);
    // Idempotent.
    prepare_dir(&dir).unwrap();
    assert_eq!(mode(&dir), 0o700);
}

#[test]
fn prepare_dir_refuses_a_symlinked_directory() {
    let scratch = short_scratch();
    let real = scratch.join("real");
    std::fs::create_dir(&real).unwrap();
    chmod(&real, 0o700);
    let link = scratch.join("control");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(prepare_dir(&link).unwrap_err().kind(), ErrorKind::NotADirectory);
    assert!(bind(&link).is_err());
    assert!(!real.join(SOCKET_NAME).exists());
}

#[test]
fn prepare_dir_refuses_a_regular_file() {
    let scratch = short_scratch();
    let file = scratch.join("control");
    std::fs::write(&file, b"x").unwrap();
    assert_eq!(prepare_dir(&file).unwrap_err().kind(), ErrorKind::NotADirectory);
}

#[test]
fn prepare_dir_tightens_a_loose_mode() {
    let scratch = short_scratch();
    let dir = scratch.join("control");
    std::fs::create_dir(&dir).unwrap();
    chmod(&dir, 0o755);
    prepare_dir(&dir).unwrap();
    assert_eq!(mode(&dir), 0o700);
}

#[test]
fn the_socket_is_0600_and_close_on_exec() {
    let scratch = short_scratch();
    let dir = control_dir(&scratch);
    let listener = bind(&dir).unwrap();
    let path = dir.join(SOCKET_NAME);
    assert_eq!(control_socket::socket_path(&dir), path);
    let meta = std::fs::symlink_metadata(&path).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(mode(&path), 0o600);
    assert!(is_cloexec(listener.as_raw_fd()));

    let _client = UnixStream::connect(&path).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    assert!(is_cloexec(accepted.as_raw_fd()));
}

#[test]
fn a_stale_socket_is_replaced() {
    let scratch = short_scratch();
    let dir = control_dir(&scratch);
    let path = dir.join(SOCKET_NAME);
    // A socket file nobody listens on any more.
    drop(UnixListener::bind(&path).unwrap());
    assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_socket());
    assert_eq!(UnixStream::connect(&path).unwrap_err().kind(), ErrorKind::ConnectionRefused);

    let listener = bind(&dir).unwrap();
    assert_eq!(mode(&path), 0o600);
    let _client = UnixStream::connect(&path).unwrap();
    listener.accept().unwrap();
}

#[test]
fn a_regular_file_in_place_of_the_socket_is_an_error() {
    let scratch = short_scratch();
    let dir = control_dir(&scratch);
    let path = dir.join(SOCKET_NAME);
    std::fs::write(&path, b"not a socket").unwrap();
    assert!(bind(&dir).is_err());
    // Left alone.
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
}

#[test]
fn a_symlink_in_place_of_the_socket_is_an_error() {
    let scratch = short_scratch();
    let dir = control_dir(&scratch);
    let target = scratch.join("elsewhere");
    std::fs::write(&target, b"x").unwrap();
    std::os::unix::fs::symlink(&target, dir.join(SOCKET_NAME)).unwrap();
    assert!(bind(&dir).is_err());
    assert!(target.exists());
}

#[test]
fn a_second_bind_while_live_is_addr_in_use() {
    let scratch = short_scratch();
    let dir = control_dir(&scratch);
    let first = bind(&dir).unwrap();
    let err = bind(&dir).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::AddrInUse);
    // The first instance still serves.
    let _client = UnixStream::connect(dir.join(SOCKET_NAME)).unwrap();
    first.accept().unwrap();
}

#[test]
fn a_too_long_path_is_a_clear_error() {
    let scratch = short_scratch();
    let dir = scratch.join(&"d".repeat(100));
    prepare_dir(&dir).unwrap();
    let err = bind(&dir).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);
    assert!(err.to_string().contains("too long"), "{err}");
}

#[test]
fn peer_of_a_pair_is_this_process() {
    let (a, _b) = UnixStream::pair().unwrap();
    let p = peer(&a).unwrap();
    assert_eq!(p.uid, getuid());
    assert_eq!(p.pid, std::process::id() as i32);
    let exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let executable: std::path::PathBuf = p.executable.expect("executable path");
    let got = std::fs::canonicalize(executable).unwrap();
    assert_eq!(got, exe);
    assert!(same_user(p.uid));
}

#[test]
fn peer_over_the_bound_socket() {
    let scratch = short_scratch();
    let dir = control_dir(&scratch);
    let listener = bind(&dir).unwrap();
    let _client = UnixStream::connect(dir.join(SOCKET_NAME)).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    let p = peer(&accepted).unwrap();
    assert_eq!(p.uid, getuid());
    assert_eq!(p.pid, std::process::id() as i32);
}

#[test]
fn same_user_compares_with_getuid() {
    assert!(same_user(getuid()));
    assert!(!same_user(getuid().wrapping_add(1)));
    if getuid() != 0 {
        assert!(!same_user(0));
    }
}

#[test]
fn already_closed_is_einval_enotconn_or_econnreset() {
    for errno in [libc::EINVAL, libc::ENOTCONN, libc::ECONNRESET] {
        assert!(is_already_closed(&std::io::Error::from_raw_os_error(errno)), "{errno}");
    }
    for errno in [libc::EPIPE, libc::EBADF, libc::EAGAIN, libc::ETIMEDOUT] {
        assert!(!is_already_closed(&std::io::Error::from_raw_os_error(errno)), "{errno}");
    }
    // Only the OS error counts, not a kind std made up.
    assert!(!is_already_closed(&std::io::Error::from(ErrorKind::InvalidInput)));
    assert!(!is_already_closed(&std::io::Error::from(ErrorKind::ConnectionReset)));
}

#[test]
fn random_32_differs() {
    let a = random_32().unwrap();
    let b = random_32().unwrap();
    assert_ne!(a, b);
    assert_ne!(a, [0u8; 32]);
}

#[test]
fn prepare_dir_refuses_a_foreign_owner() {
    if getuid() == 0 {
        return;
    }
    // A real directory owned by root (never modified: the owner check comes before any chmod).
    let err = prepare_dir(std::path::Path::new("/usr")).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{err}");
}

#[test]
fn the_lock_is_held_for_the_life_of_the_listener() {
    let scratch = short_scratch();
    let dir = control_dir(&scratch);
    let first = bind(&dir).unwrap();
    let lock = dir.join(LOCK_NAME);
    assert!(std::fs::symlink_metadata(&lock).unwrap().file_type().is_file());
    assert_eq!(mode(&lock), 0o600);
    // Even with the socket file gone (so no connect probe could see the first instance), the lock refuses.
    std::fs::remove_file(dir.join(SOCKET_NAME)).unwrap();
    assert_eq!(bind(&dir).unwrap_err().kind(), ErrorKind::AddrInUse);
    drop(first);

    let second = bind(&dir).unwrap();
    let _client = UnixStream::connect(dir.join(SOCKET_NAME)).unwrap();
    second.accept().unwrap();
}

#[test]
fn a_symlink_in_place_of_the_lock_is_an_error() {
    let scratch = short_scratch();
    let dir = control_dir(&scratch);
    let target = scratch.join("elsewhere");
    std::fs::write(&target, b"x").unwrap();
    std::os::unix::fs::symlink(&target, dir.join(LOCK_NAME)).unwrap();
    assert!(bind(&dir).is_err());
    assert_eq!(std::fs::read(&target).unwrap(), b"x");
}

#[test]
fn concurrent_binds_yield_exactly_one_listener() {
    let scratch = short_scratch();
    let dir = control_dir(&scratch);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let dir = dir.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                bind(&dir)
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let winners: Vec<_> = results.iter().filter_map(|r| r.as_ref().ok()).collect();
    assert_eq!(winners.len(), 1);
    for r in &results {
        if let Err(e) = r {
            assert_eq!(e.kind(), ErrorKind::AddrInUse, "{e}");
        }
    }
    let _client = UnixStream::connect(dir.join(SOCKET_NAME)).unwrap();
    winners[0].accept().unwrap();
}

#[test]
fn bind_at_uses_the_given_names() {
    let scratch = short_scratch();
    let dir = scratch.join("bind-at");
    let bound = macvpn_unixsys::control_socket::bind_at(&dir, "linvpn.sock", "linvpn.lock").unwrap();
    assert!(dir.join("linvpn.sock").exists());
    assert!(dir.join("linvpn.lock").exists());
    assert!(!dir.join("macvpn.sock").exists());
    // A second bind in the same place is refused while the first holds the lock.
    let again = macvpn_unixsys::control_socket::bind_at(&dir, "linvpn.sock", "linvpn.lock");
    assert_eq!(again.err().map(|e| e.kind()), Some(std::io::ErrorKind::AddrInUse));
    drop(bound);
}

/// Linux: the peer of a socket this process connected to itself is this process: its uid, its pid and its
/// executable (the test binary).
#[cfg(target_os = "linux")]
#[test]
fn linux_peer_is_this_process() {
    use std::os::unix::net::UnixStream;
    let (a, _b) = UnixStream::pair().unwrap();
    let peer = macvpn_unixsys::control_socket::peer(&a).unwrap();
    assert_eq!(peer.pid, std::process::id() as i32);
    assert!(macvpn_unixsys::control_socket::same_user(peer.uid));
    assert_eq!(peer.executable.unwrap(), std::env::current_exe().unwrap());
}
