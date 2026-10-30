use macvpn_platform_linux::pure::instance::{bus_name, launch_files};
use std::path::{Path, PathBuf};

#[test]
fn the_installed_name_and_one_per_sandbox() {
    assert_eq!(bus_name(None), "local.linvpn.Instance");
    let a = bus_name(Some(Path::new("/tmp/sb-a")));
    let b = bus_name(Some(Path::new("/tmp/sb-b")));
    assert!(a.starts_with("local.linvpn.Sandbox.h") && a.len() == "local.linvpn.Sandbox.h".len() + 16, "{a}");
    assert_ne!(a, b);
    assert_eq!(a, bus_name(Some(Path::new("/tmp/sb-a"))));
}

#[test]
fn only_absolute_paths_are_files() {
    let args = ["--after-update", "relative.ovpn", "/home/ann/a.ovpn", "", "/tmp/b.conf"].map(std::ffi::OsString::from);
    assert_eq!(launch_files(args), vec![PathBuf::from("/home/ann/a.ovpn"), PathBuf::from("/tmp/b.conf")]);
}
