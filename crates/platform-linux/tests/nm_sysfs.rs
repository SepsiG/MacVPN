#![cfg(target_os = "linux")]
//! L-b Task 15: the tunnel counters from sysfs, the tunnel interface of an address, the private runtime files.

use macvpn_core::models::VPNKind;
use macvpn_core::nm_plan::RuntimeFile;
use macvpn_platform_linux::lin_for_tests::nm::files::RunRecord;
use macvpn_platform_linux::lin_for_tests::nm::{files, sysfs};
use std::collections::HashSet;
use std::fs;
use std::net::UdpSocket;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

fn uid() -> u32 {
    fs::metadata("/proc/self").unwrap().uid()
}

/// A fresh private directory standing in for `$XDG_RUNTIME_DIR`.
fn tmp_runtime(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("linvpn-nm-sysfs-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn file(name: &str, data: &[u8]) -> RuntimeFile {
    RuntimeFile { name: name.into(), data: Zeroizing::new(data.to_vec()) }
}

fn mode(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().mode() & 0o7777
}

#[test]
fn loopback_counters_grow_after_a_datagram() {
    let (rx0, tx0) = sysfs::counters("lo").expect("lo has counters");
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let to = sock.local_addr().unwrap();
    for _ in 0..4 {
        sock.send_to(&[0u8; 512], to).unwrap();
    }
    let (rx1, tx1) = sysfs::counters("lo").unwrap();
    assert!(rx1 > rx0 && tx1 > tx0, "rx {rx0}->{rx1}, tx {tx0}->{tx1}");
}

#[test]
fn loopback_is_interface_one() {
    assert_eq!(sysfs::ifindex("lo"), Some(1));
    assert_eq!(sysfs::ifindex("linvpn-none0"), None);
}

#[test]
fn a_name_that_is_not_one_plain_component_is_never_read() {
    for bad in ["../etc", "a/b", "", "1234567890123456", "..", "."] {
        assert_eq!(sysfs::counters(bad), None, "{bad:?}");
        assert_eq!(sysfs::ifindex(bad), None, "{bad:?}");
    }
    // `/sys/class/net/../../../proc/self` would exist; the check comes before any path is built.
    assert_eq!(sysfs::counters("../../../proc"), None);
}

#[test]
fn loopback_is_no_tunnel() {
    assert_eq!(sysfs::tunnel_iface_for("127.0.0.1"), None);
    assert_eq!(sysfs::tunnel_iface_for("not an address"), None);
    assert_eq!(sysfs::tunnel_iface_for("192.0.2.77"), None);
    assert!(sysfs::tunnel_ifaces_for("127.0.0.1").is_empty(), "lo is no tunnel");
    assert!(sysfs::tunnel_ifaces_for("not an address").is_empty());
}

#[test]
fn writes_private_files_and_removes_them_on_drop() {
    let rt = tmp_runtime("write");
    let dir = files::dir_for(&rt, "u-1");
    {
        let guard = files::write(&rt, "u-1", &[file("ca.pem", b"CA\n"), file("tls-crypt.key", b"KEY\n")]).unwrap();
        assert_eq!(guard.dir, dir);
        assert_eq!(dir, rt.join("linvpn/nm/u-1"));
        for d in [rt.join("linvpn"), rt.join("linvpn/nm"), dir.to_path_buf()] {
            assert_eq!(mode(&d), 0o700, "{}", d.display());
            assert_eq!(fs::symlink_metadata(&d).unwrap().uid(), uid());
        }
        for (name, data) in [("ca.pem", &b"CA\n"[..]), ("tls-crypt.key", &b"KEY\n"[..])] {
            let p = dir.join(name);
            assert_eq!(mode(&p), 0o600);
            assert_eq!(fs::symlink_metadata(&p).unwrap().uid(), uid());
            assert_eq!(fs::read(&p).unwrap(), data);
        }
    }
    assert!(!dir.exists(), "the guard's drop removes the directory");
    assert!(rt.join("linvpn/nm").is_dir(), "only the connection's own directory goes");
    fs::remove_dir_all(&rt).unwrap();
}

#[test]
fn a_second_write_replaces_a_stale_directory() {
    let rt = tmp_runtime("stale");
    let dir = files::dir_for(&rt, "u-2");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("ca.pem"), b"old").unwrap();
    let guard = files::write(&rt, "u-2", &[file("ca.pem", b"new")]).unwrap();
    assert_eq!(fs::read(dir.join("ca.pem")).unwrap(), b"new");
    assert_eq!(mode(&dir.join("ca.pem")), 0o600);
    drop(guard);
    fs::remove_dir_all(&rt).unwrap();
}

#[test]
fn refuses_a_file_name_that_is_not_one_plain_component() {
    let rt = tmp_runtime("names");
    for bad in ["a/b", "/etc/passwd", ".hidden", "..", ".", "", "a\0b"] {
        assert!(files::write(&rt, "u-3", &[file(bad, b"x")]).is_err(), "{bad:?}");
        assert!(!files::dir_for(&rt, "u-3").exists(), "{bad:?}: nothing left behind");
    }
    for bad in ["", "..", "a/b", ".x"] {
        assert!(files::write(&rt, bad, &[file("ca.pem", b"x")]).is_err(), "uuid {bad:?}");
    }
    fs::remove_dir_all(&rt).unwrap();
}

#[test]
fn refuses_a_symlinked_linvpn_dir() {
    let rt = tmp_runtime("symlink");
    let elsewhere = rt.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&elsewhere, rt.join("linvpn")).unwrap();
    assert!(files::write(&rt, "u-4", &[file("ca.pem", b"x")]).is_err());
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0, "nothing written through the link");
    fs::remove_file(rt.join("linvpn")).unwrap();

    // A symlinked `nm` below a real `linvpn` too.
    fs::create_dir(rt.join("linvpn")).unwrap();
    symlink(&elsewhere, rt.join("linvpn/nm")).unwrap();
    assert!(files::write(&rt, "u-4", &[file("ca.pem", b"x")]).is_err());
    assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0);
    fs::remove_dir_all(&rt).unwrap();
}

#[test]
fn refuses_a_linvpn_dir_that_is_not_ours() {
    // An unprivileged test cannot make a directory owned by someone else; the same check runs with an owner that
    // is not the directory's.
    let rt = tmp_runtime("owner");
    fs::create_dir(rt.join("linvpn")).unwrap();
    fs::set_permissions(rt.join("linvpn"), fs::Permissions::from_mode(0o700)).unwrap();
    let e = files::write_for_owner(&rt, "u-5", &[file("ca.pem", b"x")], uid().wrapping_add(1)).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
    assert!(!rt.join("linvpn/nm").exists());
    fs::remove_dir_all(&rt).unwrap();
}

#[test]
fn sweep_removes_leftovers_but_keeps_the_active_connections_files() {
    let rt = tmp_runtime("sweep");
    let a = files::write(&rt, "u-6", &[file("ca.pem", b"x")]).unwrap();
    let b = files::write(&rt, "u-7", &[file("key.pem", b"y")]).unwrap();
    std::mem::forget(a);
    std::mem::forget(b);
    assert_eq!(fs::read_dir(rt.join("linvpn/nm")).unwrap().count(), 2);
    // `u-6` is still active in NetworkManager (a tunnel left running): its certificate stays.
    files::sweep(&rt, &HashSet::from(["u-6".to_string()]));
    assert_eq!(fs::read(rt.join("linvpn/nm/u-6/ca.pem")).unwrap(), b"x");
    assert!(!rt.join("linvpn/nm/u-7").exists());
    files::sweep(&rt, &HashSet::new());
    assert_eq!(fs::read_dir(rt.join("linvpn/nm")).unwrap().count(), 0);
    // No runtime dir yet, or a symlinked `linvpn`: nothing happens, nothing outside is touched.
    files::sweep(&rt.join("missing"), &HashSet::new());
    fs::remove_dir_all(rt.join("linvpn")).unwrap();
    let elsewhere = rt.join("elsewhere");
    fs::create_dir_all(elsewhere.join("nm/keep")).unwrap();
    symlink(&elsewhere, rt.join("linvpn")).unwrap();
    files::sweep(&rt, &HashSet::new());
    assert!(elsewhere.join("nm/keep").is_dir());
    fs::remove_dir_all(&rt).unwrap();
}

#[test]
fn the_run_record_is_read_back_only_from_our_own_private_file() {
    let rt = tmp_runtime("record");
    let id = uuid::Uuid::new_v4();
    let record = RunRecord {
        id,
        kind: VPNKind::Wireguard,
        iface: Some("lvw0123456789ab".into()),
        keepalive: 25,
        since: 1_700_000_000.5,
    };
    let guard = files::write(&rt, "u-8", &[]).unwrap();
    guard.write_record(&record).unwrap();
    let path = rt.join("linvpn/nm/u-8").join(files::RECORD);
    assert_eq!(mode(&path), 0o600);
    assert_eq!(files::records(&rt), vec![("u-8".to_string(), record.clone())]);
    // The record's name can never be a plan file's (those are plain names, never starting with a dot).
    assert!(files::write(&rt, "u-9", &[file(files::RECORD, b"{}")]).is_err());
    // Not JSON, other keys, a symlink, a group-readable file: left out (R9).
    for bad in [
        &b"not json"[..],
        br#"{"v":1}"#,
        br#"{"v":2,"id":"x","kind":"wireguard","iface":null,"keepalive":0,"since":0}"#,
    ] {
        fs::remove_file(&path).unwrap();
        fs::write(&path, bad).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(files::records(&rt).is_empty(), "{}", String::from_utf8_lossy(bad));
    }
    fs::remove_file(&path).unwrap();
    guard.write_record(&record).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(files::records(&rt).is_empty());
    fs::remove_file(&path).unwrap();
    let real = rt.join("real.json");
    fs::write(&real, record.encode()).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&real, &path).unwrap();
    assert!(files::records(&rt).is_empty());
    drop(guard);
    assert!(!rt.join("linvpn/nm/u-8").exists());
    fs::remove_dir_all(&rt).unwrap();
}
