//! The package upgrade watch, its portable parts (every OS): the `.deb`'s marker and the restart decision.

use macvpn_platform_linux::pure::package_watch::{MARKER, parse_marker, read_marker, upgraded_to};
use std::path::PathBuf;

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("linvpn-package-watch-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_marker_is_one_plain_version() {
    assert_eq!(MARKER, "/run/linvpn/package-version");
    assert_eq!(parse_marker("2.1.0\n").as_deref(), Some("2.1.0"));
    assert_eq!(parse_marker("2.1.0").as_deref(), Some("2.1.0"));
    for bad in ["", "\n", "2.1", "2.1.0-1", "2.1.0\n\n", " 2.1.0", "2.1.0 ", "v2.1.0", "2.1.0\r\n", "a.b.c"] {
        assert_eq!(parse_marker(bad), None, "{bad:?}");
    }
}

#[test]
fn only_a_small_regular_file_is_read() {
    let dir = scratch();
    let marker = dir.join("package-version");
    assert_eq!(read_marker(&marker), None, "missing");
    std::fs::write(&marker, "2.2.0\n").unwrap();
    assert_eq!(read_marker(&marker).as_deref(), Some("2.2.0"));
    std::fs::write(&marker, format!("2.2.0\n{}", " ".repeat(300))).unwrap();
    assert_eq!(read_marker(&marker), None, "too large");
    assert_eq!(read_marker(&dir), None, "a directory");
    #[cfg(unix)]
    {
        let real = dir.join("real");
        std::fs::write(&real, "2.2.0\n").unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(read_marker(&link), None, "a symbolic link");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn another_version_than_the_running_one_restarts() {
    // An upgrade and a downgrade.
    assert_eq!(upgraded_to("2.1.0", Some("2.1.0"), Some("2.2.0")).as_deref(), Some("2.2.0"));
    assert_eq!(upgraded_to("2.1.0", Some("2.1.0"), Some("2.0.9")).as_deref(), Some("2.0.9"));
    // No marker at start (a fresh boot, an older package).
    assert_eq!(upgraded_to("2.1.0", None, Some("2.2.0")).as_deref(), Some("2.2.0"));
    // Nothing (yet), or the same version again (a reinstall).
    assert_eq!(upgraded_to("2.1.0", None, None), None);
    assert_eq!(upgraded_to("2.1.0", Some("2.1.0"), None), None);
    assert_eq!(upgraded_to("2.1.0", Some("2.1.0"), Some("2.1.0")), None);
    assert_eq!(upgraded_to("2.1.0", None, Some("2.1.0")), None);
    // A marker that already differed at start waits for a change (no restart loop).
    assert_eq!(upgraded_to("2.1.0", Some("2.2.0"), Some("2.2.0")), None);
    assert_eq!(upgraded_to("2.1.0", Some("2.2.0"), Some("2.3.0")).as_deref(), Some("2.3.0"));
}
