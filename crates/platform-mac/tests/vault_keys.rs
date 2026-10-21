//! The vault's system entropy and Keychain key store (plan B Task 5).
//!
//! The Keychain test is `#[ignore]`d (CI never touches a Keychain). It is isolated anyway: it creates a throwaway
//! keychain file in a temporary directory with `security create-keychain`, addresses only that file
//! (`kSecUseKeychain` / `kSecMatchSearchList`), uses a random test service name, leaves the user's search list
//! unchanged (checked) and deletes the keychain afterwards. It never reads or writes the login keychain.
#![cfg(target_os = "macos")]

use macvpn_core::vault::{Entropy, KeyStore};
use macvpn_platform_mac::vault_keys::{KeychainKeyStore, SystemEntropy};
use std::path::PathBuf;
use std::process::Command;

#[test]
fn system_entropy_fills_any_length() {
    for len in [1usize, 255, 256, 257, 4096] {
        let mut a = vec![0u8; len];
        let mut b = vec![0u8; len];
        SystemEntropy.fill(&mut a).unwrap();
        SystemEntropy.fill(&mut b).unwrap();
        if len >= 16 {
            assert_ne!(a, b, "{len}");
            // Every 256-byte chunk is filled, the last one included.
            for chunk in a.chunks(256).filter(|c| c.len() >= 16) {
                assert!(chunk.iter().any(|&x| x != 0), "{len}");
            }
        }
    }
    let mut empty: [u8; 0] = [];
    SystemEntropy.fill(&mut empty).unwrap();
}

struct TempKeychain {
    dir: PathBuf,
    path: PathBuf,
}

impl TempKeychain {
    fn create() -> TempKeychain {
        let dir = std::env::temp_dir().join(format!("macvpn-keychain-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.keychain-db");
        let status = Command::new("/usr/bin/security")
            .args(["create-keychain", "-p", "throwaway-test-password"])
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        TempKeychain { dir, path }
    }
}

impl Drop for TempKeychain {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/security").arg("delete-keychain").arg(&self.path).status();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn security(args: &[&str], keychain: &std::path::Path) -> std::process::Output {
    Command::new("/usr/bin/security").args(args).arg(keychain).output().unwrap()
}

fn search_list() -> String {
    let out = Command::new("/usr/bin/security").args(["list-keychains", "-d", "user"]).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
#[ignore = "uses a temporary Keychain file (macOS only, never the login keychain); run by hand"]
fn keychain_key_store_round_trip_in_a_temporary_keychain() {
    let before = search_list();
    let keychain = TempKeychain::create();
    let service = format!("local.macvpn.vault-test-{}", uuid::Uuid::new_v4());
    let store = KeychainKeyStore::in_keychain(&keychain.path, &service);

    assert_eq!(store.get().unwrap(), None);
    assert!(!store.exists().unwrap());
    store.set(&[0x11; 32]).unwrap();
    assert!(store.exists().unwrap());
    assert_eq!(store.get().unwrap().unwrap().as_slice(), &[0x11u8; 32]);
    store.set(&[0x22; 32]).unwrap();
    assert_eq!(store.get().unwrap().unwrap().as_slice(), &[0x22u8; 32]);

    // The item is in the temporary keychain, under the test service name, with the vault's account and label.
    let dump = Command::new("/usr/bin/security").arg("dump-keychain").arg(&keychain.path).output().unwrap();
    let dump = String::from_utf8_lossy(&dump.stdout);
    assert!(dump.contains(&service), "{dump}");
    assert!(dump.contains("\"acct\"<blob>=\"dek\""), "{dump}");
    assert!(dump.contains("MacVPN vault key"), "{dump}");

    store.delete().unwrap();
    assert_eq!(store.get().unwrap(), None);
    assert!(!store.exists().unwrap());
    store.delete().unwrap();

    drop(keychain);
    assert_eq!(search_list(), before, "the user's keychain search list must not change");
}

/// An item planted before the app writes (another program created it, so it carries that program's ACL and label)
/// is replaced by a fresh item of the app, not updated in place (security review M2).
#[test]
#[ignore = "uses a temporary Keychain file (macOS only, never the login keychain); run by hand"]
fn set_replaces_a_planted_item_instead_of_updating_it() {
    let before = search_list();
    let keychain = TempKeychain::create();
    let service = format!("local.macvpn.vault-test-{}", uuid::Uuid::new_v4());
    // -A: any application may read the planted item, so no access prompt can appear in this test.
    let planted = security(
        &["add-generic-password", "-A", "-s", &service, "-a", "dek", "-l", "planted by someone else", "-w", "squat"],
        &keychain.path,
    );
    assert!(planted.status.success(), "{}", String::from_utf8_lossy(&planted.stderr));

    let store = KeychainKeyStore::in_keychain(&keychain.path, &service);
    store.set(&[0x33; 32]).unwrap();
    assert_eq!(store.get().unwrap().unwrap().as_slice(), &[0x33u8; 32]);

    let dump = String::from_utf8_lossy(&security(&["dump-keychain"], &keychain.path).stdout).into_owned();
    assert!(dump.contains("MacVPN vault key"), "{dump}");
    assert!(!dump.contains("planted by someone else"), "the planted item must be gone: {dump}");
    assert_eq!(dump.matches(&service).count(), 1, "exactly one item: {dump}");

    store.delete().unwrap();
    drop(keychain);
    assert_eq!(search_list(), before);
}
