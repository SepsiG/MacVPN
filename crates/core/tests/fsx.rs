//! `macvpn_core::fsx`: the safe file operations (plan Task 4). The Unix assertions run under `#[cfg(unix)]`.

#![cfg(unix)]

use macvpn_core::fsx::{self, Access, FileOwner, Follow, OpenFor};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("macvpn-fsx-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn mkfifo(path: &Path) {
    let status = std::process::Command::new("/usr/bin/mkfifo").arg("-m").arg("600").arg(path).status().unwrap();
    assert!(status.success(), "mkfifo");
}

/// Runs `f` on a thread and fails the test (instead of hanging it) when it does not return within 2 s.
fn within_2s<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(2)).expect("blocked for more than 2 s")
}

// --- create_new -----------------------------------------------------------------------------------------------

#[test]
fn create_new_private_is_0600_and_shared_is_0644() {
    let tmp = TempDir::new();
    let private = tmp.path().join("private");
    let shared = tmp.path().join("shared");
    drop(fsx::create_new(&private, Access::Private).unwrap());
    drop(fsx::create_new(&shared, Access::Shared).unwrap());
    assert_eq!(mode(&private), 0o600);
    assert_eq!(mode(&shared), 0o644);
}

#[test]
fn create_new_refuses_an_existing_file_and_a_symlink() {
    let tmp = TempDir::new();
    let existing = tmp.path().join("existing");
    fs::write(&existing, "keep").unwrap();
    let err = fsx::create_new(&existing, Access::Private).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&existing).unwrap(), b"keep");

    let target = tmp.path().join("target");
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(fsx::create_new(&link, Access::Private).is_err(), "a dangling symlink is not followed");
    assert!(fs::symlink_metadata(&target).is_err(), "the symlink's target was not created");
}

#[test]
fn create_new_rw_is_readable_and_writable_and_0600() {
    let tmp = TempDir::new();
    let path = tmp.path().join("db");
    let mut file = fsx::create_new_rw(&path, Access::Private).unwrap();
    std::io::Write::write_all(&mut file, b"abc").unwrap();
    std::io::Seek::seek(&mut file, io::SeekFrom::Start(0)).unwrap();
    let mut back = String::new();
    file.read_to_string(&mut back).unwrap();
    assert_eq!(back, "abc");
    assert_eq!(mode(&path), 0o600);
    assert!(fsx::create_new_rw(&path, Access::Private).is_err());
}

#[test]
fn set_access_and_has_access() {
    let tmp = TempDir::new();
    let path = tmp.path().join("f");
    let file = fsx::create_new(&path, Access::Private).unwrap();
    assert!(fsx::has_access(&fsx::stat_path(&path, Follow::Yes).unwrap(), Access::Private));
    assert!(!fsx::has_access(&fsx::stat_path(&path, Follow::Yes).unwrap(), Access::Shared));
    fsx::set_access(&file, Access::Shared).unwrap();
    assert_eq!(mode(&path), 0o644);
    assert!(fsx::has_access(&fsx::stat_path(&path, Follow::Yes).unwrap(), Access::Shared));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o4600)).unwrap();
    assert!(!fsx::has_access(&fsx::stat_path(&path, Follow::Yes).unwrap(), Access::Private), "special bits count");
    fsx::set_access(&file, Access::Private).unwrap();
    assert_eq!(mode(&path), 0o600);

    let dir = tmp.path().join("d");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(fsx::has_access(&fsx::stat_path(&dir, Follow::Yes).unwrap(), Access::Private));
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!fsx::has_access(&fsx::stat_path(&dir, Follow::Yes).unwrap(), Access::Private));
    assert!(fsx::has_access(&fsx::stat_path(&dir, Follow::Yes).unwrap(), Access::Shared));
}

// --- directories ----------------------------------------------------------------------------------------------

/// `ConnectionStore::save`: every created level 0700, and an existing leaf is tightened to 0700.
#[test]
fn create_private_dir_all_makes_every_level_0700_and_tightens_the_leaf() {
    let tmp = TempDir::new();
    let leaf = tmp.path().join("a/b/c");
    fsx::create_private_dir_all(&leaf).unwrap();
    for level in ["a", "a/b", "a/b/c"] {
        assert_eq!(mode(&tmp.path().join(level)), 0o700, "{level}");
    }
    fs::set_permissions(&leaf, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(tmp.path().join("a"), fs::Permissions::from_mode(0o755)).unwrap();
    fsx::create_private_dir_all(&leaf).unwrap();
    assert_eq!(mode(&leaf), 0o700, "the existing leaf is tightened");
    assert_eq!(mode(&tmp.path().join("a")), 0o755, "an existing parent is left alone");
}

/// `ensure_private_parent` and app-core's vault directory: created levels 0700, an existing directory unchanged.
#[test]
fn create_missing_private_dirs_leaves_an_existing_directory_alone() {
    let tmp = TempDir::new();
    let leaf = tmp.path().join("x/y");
    fsx::create_missing_private_dirs(&leaf).unwrap();
    assert_eq!(mode(&tmp.path().join("x")), 0o700);
    assert_eq!(mode(&leaf), 0o700);
    fs::set_permissions(&leaf, fs::Permissions::from_mode(0o755)).unwrap();
    fsx::create_missing_private_dirs(&leaf).unwrap();
    assert_eq!(mode(&leaf), 0o755);
}

#[test]
fn ensure_private_dir_refuses_a_symlink_and_tightens_the_mode() {
    let tmp = TempDir::new();
    let real = tmp.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(fsx::ensure_private_dir(&link).unwrap_err().kind(), io::ErrorKind::NotADirectory);

    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
    fsx::ensure_private_dir(&real).unwrap();
    assert_eq!(mode(&real), 0o700);

    let file = tmp.path().join("file");
    fs::write(&file, "").unwrap();
    assert_eq!(fsx::ensure_private_dir(&file).unwrap_err().kind(), io::ErrorKind::NotADirectory);
}

#[test]
fn ensure_private_dir_creates_the_directory_and_returns_its_owner() {
    let tmp = TempDir::new();
    let dir = tmp.path().join("parent/vault");
    let owner = fsx::ensure_private_dir(&dir).unwrap();
    assert_eq!(mode(&dir), 0o700);
    let file = dir.join("f");
    drop(fsx::create_new(&file, Access::Private).unwrap());
    assert_eq!(owner, fsx::owner(&fsx::stat_path(&file, Follow::Yes).unwrap()).unwrap());
    assert_eq!(owner, FileOwner::from_uid(fs::metadata(&file).unwrap().uid()));
    assert_ne!(owner, FileOwner::from_uid(fs::metadata(&file).unwrap().uid() + 1));
}

// --- open_regular ---------------------------------------------------------------------------------------------

#[test]
fn open_regular_refuses_a_fifo_without_hanging() {
    let tmp = TempDir::new();
    let fifo = tmp.path().join("pipe");
    mkfifo(&fifo);
    for open in [OpenFor::Read, OpenFor::Write] {
        let path = fifo.clone();
        let err = within_2s(move || fsx::open_regular(&path, open, Follow::No, false).map(|_| ()).unwrap_err());
        // Read: the open succeeds and the descriptor check refuses; write: a FIFO without a reader is ENXIO.
        assert!(fsx::is_not_regular_file(&err) || err.raw_os_error() == Some(6), "{err:?}");
    }
    let path = fifo.clone();
    let err = within_2s(move || fsx::open_regular(&path, OpenFor::Read, Follow::Yes, true).map(|_| ()).unwrap_err());
    assert!(fsx::is_not_regular_file(&err));
}

#[test]
fn open_regular_refuses_a_directory() {
    let tmp = TempDir::new();
    let err = fsx::open_regular(tmp.path(), OpenFor::Read, Follow::No, false).map(|_| ()).unwrap_err();
    assert!(fsx::is_not_regular_file(&err));
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(err.to_string(), "not a regular file");
    assert_eq!(err.to_string(), fsx::not_regular_file().to_string());
}

#[test]
fn open_regular_refuses_a_symlink_unless_asked_to_follow() {
    let tmp = TempDir::new();
    let file = tmp.path().join("file");
    fs::write(&file, "content").unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    let err = fsx::open_regular(&link, OpenFor::Read, Follow::No, false).map(|_| ()).unwrap_err();
    assert!(fsx::is_symlink_refused(&err), "{err:?}");
    assert!(!fsx::is_not_regular_file(&err));
    let (mut opened, meta) = fsx::open_regular(&link, OpenFor::Read, Follow::Yes, false).unwrap();
    assert_eq!(meta.len(), 7);
    let mut text = String::new();
    opened.read_to_string(&mut text).unwrap();
    assert_eq!(text, "content");
}

/// The descriptor is switched back to blocking reads (`O_NONBLOCK` is set only for the open). A regular file reads
/// the same either way, so this checks the complete read; the FIFO tests check that the open never blocks.
#[test]
fn open_regular_reads_the_whole_file() {
    let tmp = TempDir::new();
    let file = tmp.path().join("file");
    fs::write(&file, vec![b'a'; 100_000]).unwrap();
    let (mut opened, meta) = fsx::open_regular(&file, OpenFor::Read, Follow::No, true).unwrap();
    assert!(meta.is_file());
    let mut data = Vec::new();
    opened.read_to_end(&mut data).unwrap();
    assert_eq!(data.len(), 100_000);
}

#[test]
fn open_regular_for_write_and_hard_links() {
    let tmp = TempDir::new();
    let file = tmp.path().join("file");
    fs::write(&file, "abc").unwrap();
    let (mut opened, meta) = fsx::open_regular(&file, OpenFor::Write, Follow::No, false).unwrap();
    let single = fsx::hard_links(&meta);
    std::io::Write::write_all(&mut opened, b"x").unwrap();
    drop(opened);
    assert_eq!(fs::read(&file).unwrap(), b"xbc");
    fs::hard_link(&file, tmp.path().join("other")).unwrap();
    let (_, meta) = fsx::open_regular(&file, OpenFor::Write, Follow::No, false).unwrap();
    let shared = fsx::hard_links(&meta);
    // The contract on every OS: never less than the real count, so a shared file never looks single.
    assert!(single >= 1 && shared >= 2);
    if cfg!(windows) {
        // Unknown in phase 1: "maybe shared" (Task 20, L2).
        assert_eq!((single, shared), (u64::MAX, u64::MAX));
    } else {
        assert_eq!((single, shared), (1, 2));
    }
}

#[test]
fn file_id_tells_files_apart() {
    let tmp = TempDir::new();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    fs::write(&a, "").unwrap();
    fs::write(&b, "").unwrap();
    let id_a = fsx::file_id(&fsx::stat_path(&a, Follow::Yes).unwrap()).unwrap();
    assert_eq!(Some(id_a), fsx::file_id(&fsx::stat(&fs::File::open(&a).unwrap()).unwrap()));
    assert_ne!(Some(id_a), fsx::file_id(&fsx::stat_path(&b, Follow::Yes).unwrap()));
}

#[test]
fn stat_path_follows_only_when_asked() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let real = tmp.path().join("real");
    fs::write(&real, b"x").unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(fsx::stat_path(&link, Follow::No).unwrap().file_type().is_symlink());
    let followed = fsx::stat_path(&link, Follow::Yes).unwrap();
    assert!(followed.file_type().is_file());
    assert_eq!(followed.ino(), fs::metadata(&real).unwrap().ino());
}

#[test]
fn stat_of_an_open_file_is_its_fstat() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let path = tmp.path().join("f");
    fs::write(&path, b"abc").unwrap();
    let file = fs::File::open(&path).unwrap();
    let stat = fsx::stat(&file).unwrap();
    assert_eq!(stat.len(), 3);
    assert_eq!(stat.ino(), file.metadata().unwrap().ino());
    assert_eq!(fsx::owner(&stat).unwrap(), FileOwner::from_uid(stat.uid()));
    assert_eq!(fsx::hard_links(&stat), 1);
}

// --- atomic_write ---------------------------------------------------------------------------------------------

#[test]
fn atomic_write_writes_the_complete_content_with_the_mode() {
    let tmp = TempDir::new();
    let path = tmp.path().join("meta.json");
    fs::write(&path, "an old and longer content").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    fsx::atomic_write(&path, b"new", Access::Private).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"new");
    assert_eq!(mode(&path), 0o600);
    fsx::atomic_write(&path, b"shared", Access::Shared).unwrap();
    assert_eq!(mode(&path), 0o644);
    let names: Vec<_> = fs::read_dir(tmp.path()).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(names, ["meta.json"]);
}

#[test]
fn atomic_write_leaves_no_temp_file_after_a_failed_rename() {
    let tmp = TempDir::new();
    let target = tmp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("inside"), "").unwrap();
    assert!(fsx::atomic_write(&target, b"data", Access::Private).is_err());
    let names: Vec<_> = fs::read_dir(tmp.path()).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(names, ["target"]);
}

#[test]
fn sync_dir_is_best_effort() {
    let tmp = TempDir::new();
    fsx::sync_dir(tmp.path());
    fsx::sync_dir(&tmp.path().join("missing"));
}

// --- errors ---------------------------------------------------------------------------------------------------

#[test]
fn the_unavailable_errors() {
    for errno in [libc_errno::ENOENT, libc_errno::ETIMEDOUT, libc_errno::EDEADLK, libc_errno::ENOTDIR] {
        assert!(fsx::is_unavailable(&io::Error::from_raw_os_error(errno)), "{errno}");
    }
    assert!(!fsx::is_unavailable(&io::Error::from_raw_os_error(libc_errno::EACCES)));
    assert!(!fsx::is_unavailable(&io::Error::other("no errno")));
    assert!(fsx::is_symlink_refused(&io::Error::from_raw_os_error(libc_errno::ELOOP)));
    assert!(!fsx::is_symlink_refused(&io::Error::from_raw_os_error(libc_errno::ENOENT)));
    assert!(!fsx::is_not_regular_file(&io::Error::new(io::ErrorKind::InvalidInput, "not a regular file")));
}

/// The errno values (macOS and Linux agree on these), without a `libc` dev-dependency.
mod libc_errno {
    pub const ENOENT: i32 = 2;
    pub const EACCES: i32 = 13;
    pub const ENOTDIR: i32 = 20;
    pub const ETIMEDOUT: i32 = if cfg!(target_os = "linux") { 110 } else { 60 };
    pub const EDEADLK: i32 = if cfg!(target_os = "linux") { 35 } else { 11 };
    pub const ELOOP: i32 = if cfg!(target_os = "linux") { 40 } else { 62 };
}
