//! The OS key store that caches the DEK for auto-unlock (spec 2.3): one item, read at launch.
//!
//! `platform-mac` implements it with the Keychain (service `local.macvpn.vault`, account `dek`); Linux
//! (libsecret) and Windows (DPAPI) implementations can follow behind the same trait. [`MemoryKeyStore`] is for
//! tests and the sandbox.

use std::fmt;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Why the key store could not be used. The texts carry status codes only, never key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStoreError {
    /// The store cannot be used right now (locked keychain, no UI allowed, any other OS error).
    Unavailable(String),
    /// The user cancelled or refused the OS access prompt.
    Denied,
    Io(String),
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyStoreError::Unavailable(detail) => write!(f, "key store unavailable ({detail})"),
            KeyStoreError::Denied => f.write_str("key store access denied"),
            KeyStoreError::Io(detail) => write!(f, "key store I/O error ({detail})"),
        }
    }
}

impl std::error::Error for KeyStoreError {}

/// The single cached-key item.
pub trait KeyStore: Send + Sync {
    /// `Ok(None)` when there is no item.
    fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError>;
    /// Whether the item exists, without reading the key and without any OS prompt (the auto-unlock switch's
    /// state in the settings).
    fn exists(&self) -> Result<bool, KeyStoreError>;
    /// Creates or replaces the item.
    fn set(&self, key: &[u8]) -> Result<(), KeyStoreError>;
    /// Removes the item; a missing item is not an error.
    fn delete(&self) -> Result<(), KeyStoreError>;
}

/// An in-memory [`KeyStore`] with injectable failures, for tests and the sandbox.
#[derive(Default)]
pub struct MemoryKeyStore {
    item: Mutex<Option<Zeroizing<Vec<u8>>>>,
    fail_get: Mutex<Option<KeyStoreError>>,
    fail_set: Mutex<Option<KeyStoreError>>,
    fail_delete: Mutex<Option<KeyStoreError>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl MemoryKeyStore {
    pub fn new() -> MemoryKeyStore {
        MemoryKeyStore::default()
    }

    /// Every `get` fails with `error` until called again with `None`.
    pub fn fail_get(&self, error: Option<KeyStoreError>) {
        *lock(&self.fail_get) = error;
    }

    /// Every `set` fails with `error` (and keeps the old item) until called again with `None`.
    pub fn fail_set(&self, error: Option<KeyStoreError>) {
        *lock(&self.fail_set) = error;
    }

    /// Every `delete` fails with `error` (and keeps the item) until called again with `None`.
    pub fn fail_delete(&self, error: Option<KeyStoreError>) {
        *lock(&self.fail_delete) = error;
    }
}

impl KeyStore for MemoryKeyStore {
    fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        if let Some(e) = lock(&self.fail_get).clone() {
            return Err(e);
        }
        Ok(lock(&self.item).as_ref().map(|v| Zeroizing::new(v.to_vec())))
    }

    /// Fails like `get` (`fail_get`).
    fn exists(&self) -> Result<bool, KeyStoreError> {
        if let Some(e) = lock(&self.fail_get).clone() {
            return Err(e);
        }
        Ok(lock(&self.item).is_some())
    }

    fn set(&self, key: &[u8]) -> Result<(), KeyStoreError> {
        if let Some(e) = lock(&self.fail_set).clone() {
            return Err(e);
        }
        *lock(&self.item) = Some(Zeroizing::new(key.to_vec()));
        Ok(())
    }

    fn delete(&self) -> Result<(), KeyStoreError> {
        if let Some(e) = lock(&self.fail_delete).clone() {
            return Err(e);
        }
        *lock(&self.item) = None;
        Ok(())
    }
}

impl fmt::Debug for MemoryKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryKeyStore").field("has_item", &lock(&self.item).is_some()).finish_non_exhaustive()
    }
}
