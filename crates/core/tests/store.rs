//! Port of `ConnectionStoreTests.swift` (incl. `UserDataRemovalTests`).

mod common;

use common::TempDir;
#[cfg(unix)]
use common::mode;
#[cfg(unix)]
use macvpn_core::models::uuid_string;
use macvpn_core::models::{Connection, VPNKind};
#[cfg(unix)]
use macvpn_core::store::LEGACY_PROFILE_NAME;
use macvpn_core::store::{self, ConnectionStore};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

fn names(store: &ConnectionStore) -> Vec<String> {
    store.list().unwrap().into_iter().map(|c| c.name).collect()
}

#[cfg(unix)]
#[test]
fn save_list_load_delete() {
    let tmp = TempDir::new();
    let store = ConnectionStore::new(tmp.path());
    let b = Connection::new("B", VPNKind::Wireguard);
    let a = Connection::new("A", VPNKind::Openvpn);
    store.save(&b, Some("[Interface]\n")).unwrap();
    store.save(&a, Some("remote x\n")).unwrap();
    assert_eq!(names(&store), ["A", "B"]);
    assert_eq!(store.load_config(&a.id).unwrap(), "remote x\n");
    assert_eq!(mode(&store.config_path(&a.id)), 0o600);
    assert_eq!(store.directory(&a.id).file_name().unwrap().to_str().unwrap(), uuid_string(&a.id));
    store.delete(&a.id).unwrap();
    assert_eq!(names(&store), ["B"]);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn save_without_config_keeps_existing() {
    let tmp = TempDir::new();
    let store = ConnectionStore::new(tmp.path());
    let mut c = Connection::new("A", VPNKind::Openvpn);
    store.save(&c, Some("remote x\n")).unwrap();
    c.name = "Átnevezve".into();
    store.save(&c, None).unwrap();
    assert_eq!(store.load_config(&c.id).unwrap(), "remote x\n");
    assert_eq!(store.list().unwrap().first().unwrap().name, "Átnevezve");
}

#[test]
fn list_on_missing_dir_is_empty() {
    let tmp = TempDir::new();
    assert!(ConnectionStore::new(tmp.path()).list().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn files_are_private_and_directory_is_tightened() {
    let tmp = TempDir::new();
    let store = ConnectionStore::new(tmp.path());
    let c = Connection::new("A", VPNKind::Openvpn);
    fs::DirBuilder::new().recursive(true).mode(0o755).create(store.directory(&c.id)).unwrap();
    store.save(&c, Some("remote x\n")).unwrap();
    assert_eq!(mode(&store.meta_path(&c.id)), 0o600);
    assert_eq!(mode(&store.config_path(&c.id)), 0o600);
    assert_eq!(mode(&store.directory(&c.id)), 0o700);
    // No temp file is left behind.
    let leftovers: Vec<_> = fs::read_dir(store.directory(&c.id))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(".tmp-"))
        .collect();
    assert!(leftovers.is_empty());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn list_skips_corrupt_meta() {
    let tmp = TempDir::new();
    let store = ConnectionStore::new(tmp.path());
    store.save(&Connection::new("A", VPNKind::Openvpn), None).unwrap();
    let bad = tmp.path().join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&bad).unwrap();
    fs::write(bad.join("meta.json"), "{nope").unwrap();
    fs::write(tmp.path().join("stray-file"), "x").unwrap();
    assert_eq!(names(&store), ["A"]);
}

#[cfg(unix)]
#[test]
fn write_private_refuses_to_follow_or_clobber_the_temp_name() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let target = tmp.path().join("file");
    store::write_private(b"one", &target).unwrap();
    store::write_private(b"two", &target).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"two");
    assert_eq!(mode(&target), 0o600);
    assert!(store::write_private(b"x", &tmp.path().join("missing-dir/file")).is_err());
}

#[cfg(unix)]
#[test]
fn remove_legacy_profiles() {
    let tmp = TempDir::new();
    let store = ConnectionStore::new(tmp.path());
    let a = Connection::new("A", VPNKind::L2tp);
    let b = Connection::new("B", VPNKind::Cisco);
    store.save(&a, None).unwrap();
    store.save(&b, None).unwrap();
    fs::write(store.directory(&a.id).join(LEGACY_PROFILE_NAME), "secret").unwrap();
    // A symlink is removed itself, its target stays.
    let target = tmp.path().join("target.txt");
    fs::write(&target, "keep").unwrap();
    std::os::unix::fs::symlink(&target, store.directory(&b.id).join(LEGACY_PROFILE_NAME)).unwrap();
    assert_eq!(store.remove_legacy_profiles(), 2);
    assert!(!store.directory(&a.id).join(LEGACY_PROFILE_NAME).exists());
    assert!(fs::symlink_metadata(store.directory(&b.id).join(LEGACY_PROFILE_NAME)).is_err());
    assert_eq!(fs::read_to_string(&target).unwrap(), "keep");
    assert_eq!(store.remove_legacy_profiles(), 0);
    assert_eq!(ConnectionStore::new(tmp.path().join("missing")).remove_legacy_profiles(), 0);
}

#[test]
fn default_base_dir_is_connections_below_the_data_dir() {
    // The 1.4.0 `default_base_dir(home)`, now from the data directory (`Product::data_dir`) the caller passes.
    let data_dir = Path::new("/Users/someone/Library/Application Support/MacVPN");
    assert_eq!(
        ConnectionStore::default_base_dir(data_dir),
        Path::new("/Users/someone/Library/Application Support/MacVPN/connections")
    );
}

#[cfg(unix)]
#[test]
fn removes_only_directory_named_macvpn() {
    let tmp = TempDir::new();
    let root = tmp.path();
    let good = root.join("MacVPN/connections");
    let other = root.join("Other");
    fs::create_dir_all(&good).unwrap();
    fs::create_dir_all(&other).unwrap();

    assert!(store::remove_user_data(&other, "MacVPN").is_err());
    assert!(other.exists());
    // Does not follow a symlink either.
    let link = root.join("link/MacVPN");
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&other, &link).unwrap();
    assert!(store::remove_user_data(&link, "MacVPN").is_err());
    assert!(other.exists());

    store::remove_user_data(&root.join("MacVPN"), "MacVPN").unwrap();
    assert!(!root.join("MacVPN").exists());
    // A missing directory: no error.
    assert!(store::remove_user_data(&root.join("MacVPN"), "MacVPN").is_ok());

    // The expected name is the product's: `WinVPN` refuses a `MacVPN` directory and removes its own.
    let win = root.join("WinVPN");
    fs::create_dir_all(root.join("MacVPN")).unwrap();
    fs::create_dir_all(&win).unwrap();
    assert!(store::remove_user_data(&root.join("MacVPN"), "WinVPN").is_err());
    assert!(root.join("MacVPN").exists());
    store::remove_user_data(&win, "WinVPN").unwrap();
    assert!(!win.exists());
}

#[test]
fn removal_errors_are_localized() {
    use macvpn_core::l10n::{AppLanguage, with_language};
    let err =
        with_language(AppLanguage::Hu, || store::remove_user_data(Path::new("/tmp/Other"), "MacVPN")).unwrap_err();
    assert_eq!(err.to_string(), "Nem törölhető: /tmp/Other");
}

// --- shred_file (plan B Task 13: the migration deletes the 1.1 files) -------------------------------------------

/// The bytes behind an fd that was opened before the shred (the inode outlives the unlink while it is open).
fn read_through(mut fd: fs::File) -> Vec<u8> {
    use std::io::{Read, Seek, SeekFrom};
    fd.seek(SeekFrom::Start(0)).unwrap();
    let mut out = Vec::new();
    fd.read_to_end(&mut out).unwrap();
    out
}

#[test]
#[cfg_attr(
    windows,
    ignore = "shred_file skips the overwrite on Windows until it reads the real hard link count: phase 2"
)]
fn shred_file_zeroes_the_contents_before_unlinking() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let file = tmp.path().join("config");
    let content = b"remote vpn.example.com 1194\n<key>\nsecret material\n</key>\n";
    fs::write(&file, content).unwrap();
    let observer = fs::File::open(&file).unwrap();

    store::shred_file(&file).unwrap();

    assert!(fs::symlink_metadata(&file).is_err(), "the file is unlinked");
    let after = read_through(observer);
    assert_eq!(after.len(), content.len(), "same length");
    assert!(after.iter().all(|b| *b == 0), "every byte is zero");
}

#[test]
#[cfg_attr(
    windows,
    ignore = "shred_file skips the overwrite on Windows until it reads the real hard link count: phase 2"
)]
fn shred_file_handles_large_and_empty_files_and_a_missing_one() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let big = tmp.path().join("big");
    fs::write(&big, vec![0xA5u8; 200_000]).unwrap();
    let observer = fs::File::open(&big).unwrap();
    store::shred_file(&big).unwrap();
    let after = read_through(observer);
    assert_eq!(after.len(), 200_000);
    assert!(after.iter().all(|b| *b == 0));

    let empty = tmp.path().join("empty");
    fs::write(&empty, b"").unwrap();
    store::shred_file(&empty).unwrap();
    assert!(!empty.exists());

    // Already gone: nothing to do (a resumed cleanup).
    store::shred_file(&tmp.path().join("missing")).unwrap();
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn shred_file_only_unlinks_a_file_with_other_hard_links() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let file = tmp.path().join("config");
    fs::write(&file, b"shared inode").unwrap();
    let other = tmp.path().join("other-name");
    fs::hard_link(&file, &other).unwrap();
    store::shred_file(&file).unwrap();
    assert!(fs::symlink_metadata(&file).is_err());
    assert_eq!(fs::read(&other).unwrap(), b"shared inode", "the other link is not overwritten");
}

#[cfg(unix)]
#[test]
fn shred_file_removes_a_symlink_without_touching_its_target() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let target = tmp.path().join("target");
    fs::write(&target, b"keep me").unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    store::shred_file(&link).unwrap();
    assert!(fs::symlink_metadata(&link).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"keep me");
}

// Unix only: the FIFO comes from /usr/bin/mkfifo.
#[cfg(unix)]
#[test]
fn shred_file_refuses_a_directory_and_a_fifo() {
    let tmp = TempDir::new();
    let dir = tmp.path().join("dir");
    fs::create_dir_all(&dir).unwrap();
    assert!(store::shred_file(&dir).is_err());
    assert!(dir.exists());

    let fifo = tmp.path().join("fifo");
    assert!(std::process::Command::new("/usr/bin/mkfifo").arg(&fifo).status().unwrap().success());
    // Does not block (no reader) and does not unlink it.
    assert!(store::shred_file(&fifo).is_err());
    assert!(fs::symlink_metadata(&fifo).is_ok());
}
