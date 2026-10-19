//! Port of `ConnectionStoreTests.swift` (incl. `UserDataRemovalTests`).

mod common;

use common::{TempDir, mode};
use macvpn_core::models::{Connection, VPNKind, uuid_string};
use macvpn_core::store::{self, ConnectionStore, LEGACY_PROFILE_NAME};
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::Path;

fn names(store: &ConnectionStore) -> Vec<String> {
    store.list().unwrap().into_iter().map(|c| c.name).collect()
}

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
fn default_application_support_directory() {
    let home = Path::new("/Users/someone");
    assert_eq!(
        store::application_support_directory(home),
        Path::new("/Users/someone/Library/Application Support/MacVPN")
    );
    assert_eq!(store::default_base_dir(home).parent().unwrap(), store::application_support_directory(home));
}

#[test]
fn removes_only_directory_named_macvpn() {
    let tmp = TempDir::new();
    let root = tmp.path();
    let good = root.join("MacVPN/connections");
    let other = root.join("Other");
    fs::create_dir_all(&good).unwrap();
    fs::create_dir_all(&other).unwrap();

    assert!(store::remove_application_support_directory(&other).is_err());
    assert!(other.exists());
    // Does not follow a symlink either.
    let link = root.join("link/MacVPN");
    fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&other, &link).unwrap();
    assert!(store::remove_application_support_directory(&link).is_err());
    assert!(other.exists());

    store::remove_application_support_directory(&root.join("MacVPN")).unwrap();
    assert!(!root.join("MacVPN").exists());
    // A missing directory: no error.
    assert!(store::remove_application_support_directory(&root.join("MacVPN")).is_ok());
}

#[test]
fn removal_errors_are_localized() {
    use macvpn_core::l10n::{AppLanguage, with_language};
    let err = with_language(AppLanguage::Hu, || store::remove_application_support_directory(Path::new("/tmp/Other")))
        .unwrap_err();
    assert_eq!(err.to_string(), "Nem törölhető: /tmp/Other");
}
