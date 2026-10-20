//! The admin key file (`.macvpnadminkey`, plan Task 14): the backup admin key kept offline, sealed with a password.

mod common;

use common::{TempDir, mode};
use macvpn_core::catalog::admin_file::{
    AdminKeyFileError, MAX_ADMIN_KEY_FILE_BYTES, export_admin_key, import_admin_key, read_admin_key_file,
    write_admin_key_file,
};
use macvpn_core::catalog::keys::AdminKey;
use macvpn_core::date::Date;
use macvpn_core::vault::{AdminKeyRole, FixedEntropy, KdfParams};
use std::fs;

const PASSWORD: &str = "offline backup password";

fn created() -> Date {
    Date::parse_iso8601("2026-10-19T08:00:00Z").unwrap()
}

fn sealed(key: &AdminKey) -> Vec<u8> {
    export_admin_key(
        key,
        AdminKeyRole::Backup,
        created(),
        PASSWORD,
        KdfParams::insecure_for_tests(),
        &FixedEntropy::new(4),
    )
    .unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn round_trip_keeps_the_key_the_role_and_the_date() {
    let key = AdminKey::generate(&FixedEntropy::new(10)).unwrap();
    let bytes = sealed(&key);
    assert_eq!(&bytes[..8], b"MVPNAKEY");
    assert!(!contains(&bytes, &key.seed()[..]), "the seed is never in the clear");
    let imported = import_admin_key(&bytes, PASSWORD).unwrap();
    assert_eq!(imported.key.public(), key.public());
    assert_eq!(imported.role, AdminKeyRole::Backup);
    assert_eq!(imported.created, created());
    // Debug shows the fingerprint only.
    let debug = format!("{imported:?}");
    assert!(debug.contains(&key.public().fingerprint().to_text()));
}

#[test]
fn a_wrong_password_and_a_flipped_byte_give_the_same_error() {
    let key = AdminKey::generate(&FixedEntropy::new(10)).unwrap();
    let bytes = sealed(&key);
    assert_eq!(import_admin_key(&bytes, "another password").unwrap_err(), AdminKeyFileError::CannotOpen);
    for at in [0, 20, 70, bytes.len() - 1] {
        let mut damaged = bytes.clone();
        damaged[at] ^= 0x01;
        assert_eq!(import_admin_key(&damaged, PASSWORD).unwrap_err(), AdminKeyFileError::CannotOpen, "byte {at}");
    }
    assert_eq!(import_admin_key(&bytes[..bytes.len() - 1], PASSWORD).unwrap_err(), AdminKeyFileError::CannotOpen);
    let mut newer = bytes.clone();
    newer[9] = 2;
    assert_eq!(import_admin_key(&newer, PASSWORD).unwrap_err(), AdminKeyFileError::NewerVersion);
}

#[test]
fn a_short_password_is_refused() {
    let key = AdminKey::generate(&FixedEntropy::new(10)).unwrap();
    let e = export_admin_key(
        &key,
        AdminKeyRole::Backup,
        created(),
        "short",
        KdfParams::insecure_for_tests(),
        &FixedEntropy::new(4),
    )
    .unwrap_err();
    assert!(matches!(e, AdminKeyFileError::WeakPassword(_)));
}

#[test]
fn the_file_is_written_private_and_read_with_the_backup_rules() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let key = AdminKey::generate(&FixedEntropy::new(10)).unwrap();
    let path = tmp.path().join("Acme.macvpnadminkey");
    write_admin_key_file(&path, &sealed(&key)).unwrap();
    assert_eq!(mode(&path), 0o600);
    let bytes = read_admin_key_file(&path).unwrap();
    assert_eq!(import_admin_key(&bytes, PASSWORD).unwrap().key.public(), key.public());

    // A symlink is never followed, a directory is not a file, a large file is refused.
    let link = tmp.path().join("link.macvpnadminkey");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(matches!(read_admin_key_file(&link), Err(AdminKeyFileError::Io(_))));
    assert!(matches!(read_admin_key_file(tmp.path()), Err(AdminKeyFileError::Io(_))));
    let big = tmp.path().join("big.macvpnadminkey");
    fs::write(&big, vec![0u8; MAX_ADMIN_KEY_FILE_BYTES + 1]).unwrap();
    assert_eq!(read_admin_key_file(&big).unwrap_err(), AdminKeyFileError::TooLarge);
}
