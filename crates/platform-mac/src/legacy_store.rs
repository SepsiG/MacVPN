//! The 1.1 Keychain items for the migration into the vault (plan B Task 13): core's [`LegacyKeychain`] over the
//! existing [`KeychainSecretStore`] (service `local.macvpn.secrets`, account `<item>.<field>`, where the item is a
//! managed connection's UUID or a system VPN's service ID). Values are read through the store's
//! backend's checked read and handed on in wiped buffers (deletes go through the [`SecretStore`] API); nothing here logs.

use crate::secrets::{KeychainBackend, KeychainSecretStore, SecretStore, SystemKeychain};
use macvpn_core::models::{SecretField, parse_uuid, uuid_string};
use macvpn_core::vault::{LegacyKeychain, LegacyRead};
use uuid::Uuid;
use zeroize::Zeroizing;

/// The legacy Keychain items, over the real Keychain (`KeychainLegacy::system()`) or a test backend.
pub struct KeychainLegacy<B: KeychainBackend = SystemKeychain> {
    store: KeychainSecretStore<B>,
}

impl KeychainLegacy<SystemKeychain> {
    pub fn system() -> Self {
        Self::new(KeychainSecretStore::system())
    }
}

/// The item id of a MacVPN account name, as MacVPN writes it (`uuid_string`: upper case, hyphens).
fn item_id(item: &str) -> Option<Uuid> {
    parse_uuid(item).filter(|id| uuid_string(id) == item)
}

impl<B: KeychainBackend> KeychainLegacy<B> {
    pub fn new(store: KeychainSecretStore<B>) -> Self {
        KeychainLegacy { store }
    }

    pub fn store(&self) -> &KeychainSecretStore<B> {
        &self.store
    }
}

impl<B: KeychainBackend> LegacyKeychain for KeychainLegacy<B> {
    /// Moves the items of the older service `macvpn` over first, as the 1.1 launch does.
    fn prepare(&self) {
        self.store.migrate_legacy_items();
    }

    fn items(&self) -> Vec<(String, SecretField)> {
        let service = KeychainSecretStore::<B>::DEFAULT_SERVICE;
        let mut out: Vec<(String, SecretField)> = self
            .store
            .backend()
            .accounts(service)
            .into_iter()
            .filter_map(|account| {
                let (item, field) = account.rsplit_once('.')?;
                item_id(item)?;
                Some((item.to_string(), SecretField::from_raw_value(field)?))
            })
            .collect();
        out.sort_by(|a, b| (&a.0, a.1.raw_value()).cmp(&(&b.0, b.1.raw_value())));
        out
    }

    /// Read through the backend's checked read (the store's `get` cannot tell a denied prompt from a missing
    /// item).
    fn read(&self, item: &str, field: SecretField) -> LegacyRead {
        if item_id(item).is_none() {
            return LegacyRead::Missing;
        }
        let service = KeychainSecretStore::<B>::DEFAULT_SERVICE;
        match self.store.backend().read_checked(service, &format!("{item}.{}", field.raw_value())) {
            Ok(None) => LegacyRead::Missing,
            Ok(Some(bytes)) => match String::from_utf8(bytes) {
                Ok(text) => LegacyRead::Value(Zeroizing::new(text)),
                Err(e) => {
                    drop(Zeroizing::new(e.into_bytes()));
                    LegacyRead::Undecodable
                }
            },
            Err(status) => LegacyRead::Unavailable(status),
        }
    }

    fn delete(&self, item: &str, field: SecretField) {
        if let Some(id) = item_id(item) {
            self.store.set("", &id, field);
        }
    }
}
