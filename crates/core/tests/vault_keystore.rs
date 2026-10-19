//! The `KeyStore` abstraction and its in-memory implementation (plan B Task 5).

use macvpn_core::vault::{KeyStore, KeyStoreError, MemoryKeyStore};
use std::sync::Arc;

#[test]
fn set_get_delete() {
    let store = MemoryKeyStore::new();
    assert_eq!(store.get().unwrap(), None);
    store.set(&[1, 2, 3]).unwrap();
    assert_eq!(store.get().unwrap().as_deref().map(|v| v.as_slice()), Some(&[1u8, 2, 3][..]));
    store.set(&[9; 32]).unwrap();
    assert_eq!(store.get().unwrap().unwrap().as_slice(), &[9u8; 32]);
    store.delete().unwrap();
    assert_eq!(store.get().unwrap(), None);
    // Deleting a missing item is not an error.
    store.delete().unwrap();
}

#[test]
fn injected_failures() {
    let store = MemoryKeyStore::new();
    store.set(&[7; 32]).unwrap();

    store.fail_get(Some(KeyStoreError::Denied));
    assert_eq!(store.get(), Err(KeyStoreError::Denied));
    store.fail_get(None);
    assert!(store.get().unwrap().is_some());

    store.fail_set(Some(KeyStoreError::Unavailable("OSStatus -25308".into())));
    assert_eq!(store.set(&[8; 32]), Err(KeyStoreError::Unavailable("OSStatus -25308".into())));
    store.fail_set(None);
    assert_eq!(store.get().unwrap().unwrap().as_slice(), &[7u8; 32], "a failed set keeps the old item");

    store.fail_delete(Some(KeyStoreError::Io("disk".into())));
    assert_eq!(store.delete(), Err(KeyStoreError::Io("disk".into())));
    assert!(store.get().unwrap().is_some(), "a failed delete keeps the item");
    store.fail_delete(None);
    store.delete().unwrap();
    assert_eq!(store.get().unwrap(), None);
}

#[test]
fn usable_as_a_shared_trait_object() {
    let store: Arc<dyn KeyStore> = Arc::new(MemoryKeyStore::new());
    let other = Arc::clone(&store);
    std::thread::spawn(move || other.set(&[5; 32]).unwrap()).join().unwrap();
    assert!(store.get().unwrap().is_some());
}

#[test]
fn debug_shows_no_key_material() {
    let store = MemoryKeyStore::new();
    store.set(&[0xAB; 32]).unwrap();
    let text = format!("{store:?}");
    assert!(!text.contains("171") && !text.to_lowercase().contains("ab, "), "{text}");
}

#[test]
fn exists_reports_the_item_and_fails_like_get() {
    let store = MemoryKeyStore::new();
    assert!(!store.exists().unwrap());
    store.set(&[1; 32]).unwrap();
    assert!(store.exists().unwrap());
    store.fail_get(Some(KeyStoreError::Denied));
    assert_eq!(store.exists(), Err(KeyStoreError::Denied));
    store.fail_get(None);
    store.delete().unwrap();
    assert!(!store.exists().unwrap());
}
