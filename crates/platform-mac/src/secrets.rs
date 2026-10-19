//! Connection secrets in the Keychain (port of `SecretStore.swift`).
//!
//! Generic passwords: service `local.macvpn.secrets`, account `<UUID>.<field>`. Earlier versions used the
//! service `macvpn`; [`KeychainSecretStore::migrate_legacy_items`] moves those over. The raw Keychain calls are in
//! [`crate::keychain_ffi`], behind [`KeychainBackend`] so the store logic is testable without the real Keychain.

use macvpn_core::models::{Secrets, parse_uuid, uuid_string};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretField {
    Username,
    Password,
    Psk,
    /// The password of an OpenVPN private key (PKCS#12 / encrypted PEM).
    KeyPassword,
}

impl SecretField {
    pub const ALL: [SecretField; 4] =
        [SecretField::Username, SecretField::Password, SecretField::Psk, SecretField::KeyPassword];

    pub fn raw_value(self) -> &'static str {
        match self {
            SecretField::Username => "username",
            SecretField::Password => "password",
            SecretField::Psk => "psk",
            SecretField::KeyPassword => "keypass",
        }
    }

    pub fn from_raw_value(raw: &str) -> Option<SecretField> {
        Self::ALL.into_iter().find(|f| f.raw_value() == raw)
    }

    /// Swift's `"\(field)"` (the case name), used by the in-memory store's keys.
    fn case_name(self) -> &'static str {
        match self {
            SecretField::KeyPassword => "keyPassword",
            other => other.raw_value(),
        }
    }
}

pub trait SecretStore: Send + Sync {
    fn get(&self, id: &Uuid, field: SecretField) -> Option<String>;
    /// An empty value deletes the field.
    fn set(&self, value: &str, id: &Uuid, field: SecretField);
    fn delete_all(&self, id: &Uuid);
    /// Deletes every MacVPN item (on uninstall; leftovers of already deleted connections too).
    fn remove_all(&self);

    fn secrets(&self, id: &Uuid) -> Secrets {
        Secrets {
            username: self.get(id, SecretField::Username),
            password: self.get(id, SecretField::Password),
            psk: self.get(id, SecretField::Psk),
            key_password: self.get(id, SecretField::KeyPassword),
            ..Secrets::default()
        }
    }
}

/// Raw generic-password access.
pub trait KeychainBackend: Send + Sync {
    fn read(&self, service: &str, account: &str) -> Option<Vec<u8>>;
    /// Creates or updates the item. False on error.
    fn write(&self, data: &[u8], service: &str, account: &str) -> bool;
    fn delete(&self, service: &str, account: &str);
    /// Every account name stored under `service`.
    fn accounts(&self, service: &str) -> Vec<String>;
}

/// The real Keychain (see [`crate::keychain_ffi`]).
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemKeychain;

impl SystemKeychain {
    pub fn new() -> Self {
        SystemKeychain
    }
}

impl KeychainBackend for SystemKeychain {
    fn read(&self, service: &str, account: &str) -> Option<Vec<u8>> {
        crate::keychain_ffi::read(service, account)
    }

    fn write(&self, data: &[u8], service: &str, account: &str) -> bool {
        crate::keychain_ffi::write(data, service, account)
    }

    fn delete(&self, service: &str, account: &str) {
        crate::keychain_ffi::delete(service, account)
    }

    fn accounts(&self, service: &str) -> Vec<String> {
        crate::keychain_ffi::accounts(service)
    }
}

/// In-memory [`KeychainBackend`] for tests.
#[derive(Debug, Default)]
pub struct InMemoryKeychain {
    items: Mutex<HashMap<String, BTreeMap<String, Vec<u8>>>>,
    /// Simulates a failing keychain write.
    pub fail_writes: AtomicBool,
}

impl InMemoryKeychain {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_fail_writes(&self, fail: bool) {
        self.fail_writes.store(fail, Ordering::SeqCst);
    }
}

impl KeychainBackend for InMemoryKeychain {
    fn read(&self, service: &str, account: &str) -> Option<Vec<u8>> {
        self.items.lock().ok()?.get(service)?.get(account).cloned()
    }

    fn write(&self, data: &[u8], service: &str, account: &str) -> bool {
        if self.fail_writes.load(Ordering::SeqCst) {
            return false;
        }
        let Ok(mut items) = self.items.lock() else { return false };
        items.entry(service.to_string()).or_default().insert(account.to_string(), data.to_vec());
        true
    }

    fn delete(&self, service: &str, account: &str) {
        if let Ok(mut items) = self.items.lock()
            && let Some(s) = items.get_mut(service)
        {
            s.remove(account);
        }
    }

    fn accounts(&self, service: &str) -> Vec<String> {
        self.items
            .lock()
            .ok()
            .and_then(|items| items.get(service).map(|s| s.keys().cloned().collect()))
            .unwrap_or_default()
    }
}

pub struct KeychainSecretStore<B: KeychainBackend = SystemKeychain> {
    service: String,
    legacy_service: String,
    backend: B,
}

impl KeychainSecretStore<SystemKeychain> {
    /// The production store: the real Keychain, the default services.
    pub fn system() -> Self {
        Self::new(SystemKeychain)
    }
}

impl<B: KeychainBackend> KeychainSecretStore<B> {
    pub const DEFAULT_SERVICE: &'static str = "local.macvpn.secrets";
    pub const LEGACY_SERVICE: &'static str = "macvpn";

    pub fn new(backend: B) -> Self {
        Self::with_services(Self::DEFAULT_SERVICE, Self::LEGACY_SERVICE, backend)
    }

    pub fn with_services(service: &str, legacy_service: &str, backend: B) -> Self {
        KeychainSecretStore { service: service.to_string(), legacy_service: legacy_service.to_string(), backend }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    fn account(id: &Uuid, field: SecretField) -> String {
        format!("{}.{}", uuid_string(id), field.raw_value())
    }

    /// `<UUID>.<username|password|psk|keypass>`: the account names MacVPN writes.
    pub fn is_our_account(account: &str) -> bool {
        let Some(dot) = account.rfind('.') else { return false };
        parse_uuid(&account[..dot]).is_some() && SecretField::from_raw_value(&account[dot + 1..]).is_some()
    }

    /// One-time move from the legacy service: read, write the new item, read it back, then delete the old one.
    /// Idempotent and safe to interrupt: an existing new item is never overwritten (it is newer), and the old item
    /// is deleted only once the new one holds the value. Returns the number of legacy items removed.
    pub fn migrate_legacy_items(&self) -> usize {
        let mut moved = 0;
        for account in self.backend.accounts(&self.legacy_service) {
            if !Self::is_our_account(&account) {
                continue;
            }
            if self.backend.read(&self.service, &account).is_none() {
                let Some(data) = self.backend.read(&self.legacy_service, &account) else { continue };
                if !self.backend.write(&data, &self.service, &account)
                    || self.backend.read(&self.service, &account).as_deref() != Some(&data[..])
                {
                    continue;
                }
            }
            self.backend.delete(&self.legacy_service, &account);
            moved += 1;
        }
        moved
    }
}

impl<B: KeychainBackend> SecretStore for KeychainSecretStore<B> {
    fn get(&self, id: &Uuid, field: SecretField) -> Option<String> {
        // Swift `String(data:encoding: .utf8)`: invalid UTF-8 is no value.
        self.backend.read(&self.service, &Self::account(id, field)).and_then(|d| String::from_utf8(d).ok())
    }

    fn set(&self, value: &str, id: &Uuid, field: SecretField) {
        if value.is_empty() {
            self.backend.delete(&self.service, &Self::account(id, field));
        } else {
            self.backend.write(value.as_bytes(), &self.service, &Self::account(id, field));
        }
    }

    fn delete_all(&self, id: &Uuid) {
        for field in SecretField::ALL {
            self.backend.delete(&self.service, &Self::account(id, field));
        }
    }

    /// The new service's items, plus any of our items left under the legacy service. Others' items are not
    /// touched.
    fn remove_all(&self) {
        for account in self.backend.accounts(&self.service) {
            self.backend.delete(&self.service, &account);
        }
        for account in self.backend.accounts(&self.legacy_service) {
            if Self::is_our_account(&account) {
                self.backend.delete(&self.legacy_service, &account);
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct InMemorySecretStore {
    values: Mutex<HashMap<String, String>>,
}

impl InMemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(id: &Uuid, field: SecretField) -> String {
        format!("{}.{}", uuid_string(id), field.case_name())
    }
}

impl SecretStore for InMemorySecretStore {
    fn get(&self, id: &Uuid, field: SecretField) -> Option<String> {
        self.values.lock().ok()?.get(&Self::key(id, field)).cloned()
    }

    fn set(&self, value: &str, id: &Uuid, field: SecretField) {
        if let Ok(mut values) = self.values.lock() {
            if value.is_empty() {
                values.remove(&Self::key(id, field));
            } else {
                values.insert(Self::key(id, field), value.to_string());
            }
        }
    }

    fn delete_all(&self, id: &Uuid) {
        if let Ok(mut values) = self.values.lock() {
            for field in SecretField::ALL {
                values.remove(&Self::key(id, field));
            }
        }
    }

    fn remove_all(&self) {
        if let Ok(mut values) = self.values.lock() {
            values.clear();
        }
    }
}
