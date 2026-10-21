//! Port of `SecureTempDirectoryTests.swift` and `RootInstallerTempTests` (`RootInstallerTests.swift`).
#![cfg(target_os = "macos")]

mod common;

use common::{Scratch, mode};
use macvpn_platform_mac::temp_dir::{
    SecureTempDirectory, make_private_temp_directory, temporary_directory, write_script,
};
use std::path::{Path, PathBuf};

#[test]
fn make_creates_private_directory_in_parent_with_prefix() {
    let parent = Scratch::new("stdt");
    // Many times: the old (return-pointer) Swift version produced empty / garbage paths in optimized builds here.
    for _ in 0..50 {
        let dir = SecureTempDirectory::make("macvpn-test.", parent.path()).unwrap();
        assert!(dir.is_absolute());
        assert_eq!(dir.parent(), Some(parent.path()));
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("macvpn-test."));
        assert_eq!(name.len(), "macvpn-test.".len() + 8);
        assert_eq!(mode(&dir), 0o700);
    }
}

#[test]
fn make_rejects_relative_parent_and_bad_prefix() {
    let parent = Scratch::new("stdt");
    assert!(SecureTempDirectory::make("a/b", parent.path()).is_err());
    assert!(SecureTempDirectory::make("", parent.path()).is_err());
    assert!(SecureTempDirectory::make("x.", Path::new("relative/dir")).is_err());
    assert!(SecureTempDirectory::make("x.", &parent.join("missing")).is_err());
}

#[test]
fn remove_if_owned_never_touches_foreign_paths() {
    let parent = Scratch::new("stdt");
    let keep = parent.join("keep");
    std::fs::create_dir_all(&keep).unwrap();
    let sentinel = keep.join("sentinel");
    std::fs::write(&sentinel, "x").unwrap();
    let cwd = std::env::current_dir().unwrap();
    for candidate in [
        PathBuf::from("/"),
        PathBuf::from(""),
        PathBuf::from("."),
        cwd.clone(),
        keep.clone(),
        parent.join("macvpn-test."),
    ] {
        SecureTempDirectory::remove_if_owned(&candidate, "macvpn-test.");
    }
    assert!(sentinel.exists());
    assert!(cwd.exists());

    // Prefixed, but a symlink: not followed, the target is not deleted.
    let link = parent.join("macvpn-test.ABCDEFGH");
    std::os::unix::fs::symlink(&keep, &link).unwrap();
    SecureTempDirectory::remove_if_owned(&link, "macvpn-test.");
    assert!(sentinel.exists());
}

#[test]
fn remove_if_owned_removes_own_directory() {
    let parent = Scratch::new("stdt");
    let dir = SecureTempDirectory::make("macvpn-test.", parent.path()).unwrap();
    std::fs::write(dir.join("f"), "x").unwrap();
    SecureTempDirectory::remove_if_owned(&dir, "macvpn-test.");
    assert!(!dir.exists());
}

#[test]
fn private_temp_directory_and_script_modes() {
    let dir = make_private_temp_directory("macvpn-install", &temporary_directory().unwrap()).unwrap();
    let _guard = Scratch(dir.clone());
    assert!(dir.file_name().unwrap().to_string_lossy().starts_with("macvpn-install."));
    assert_eq!(mode(&dir), 0o700);
    let path = write_script("#!/bin/bash\necho hi\n", &dir, "install.sh").unwrap();
    assert_eq!(mode(&path), 0o700);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "#!/bin/bash\necho hi\n");
    // A second write to the same place: an error because of O_EXCL (never overwritten, no symlink followed).
    assert!(write_script("x", &dir, "install.sh").is_err());
    // A planted symlink is not followed either.
    let target = dir.join("target");
    std::fs::write(&target, "keep").unwrap();
    std::os::unix::fs::symlink(&target, dir.join("link.sh")).unwrap();
    assert!(write_script("x", &dir, "link.sh").is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
}

/// Foundation's per-user temp dir (`confstr(_CS_DARWIN_USER_TEMP_DIR)`), not `$TMPDIR` or `/tmp`.
#[test]
fn temporary_directory_is_the_darwin_user_temp_dir() {
    let dir = temporary_directory().unwrap();
    assert!(dir.is_absolute() && dir.is_dir());
    assert_ne!(dir, Path::new("/tmp"));
    let out = std::process::Command::new("/usr/bin/getconf").arg("DARWIN_USER_TEMP_DIR").output().unwrap();
    let expected = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(dir.to_string_lossy().trim_end_matches('/'), expected.trim_end_matches('/'));
}
