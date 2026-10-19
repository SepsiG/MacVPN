//! The macOS side of the vault's key handling: the Keychain [`KeyStore`] that caches the DEK for auto-unlock and
//! the `getentropy` [`Entropy`].
//!
//! The DEK item (spike report B.3): a generic password in the default (login) keychain, service
//! `local.macvpn.vault`, account `dek`, label `MacVPN vault key`, written with
//! `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and never in the data-protection keychain. The file-based login
//! keychain drops the accessibility class; what protects the item is the keychain's lock state and the item ACL,
//! which trusts the app's ad-hoc cdhash, so after an update macOS asks once.
//!
//! Every read is limited to the default keychain; every write deletes all matching items in the search list and
//! adds a fresh one there, so the app always owns the item and its ACL (security review M2).
//!
//! `get` reads without UI first. Only when that fails because a prompt would be needed does it read once more
//! with the macOS access prompt allowed. Nothing is logged but the `OSStatus` (in `keychain_ffi`).

use crate::keychain_ffi::{self, Target, Ui};
use macvpn_core::vault::{Entropy, KeyStore, KeyStoreError};
use std::io;
use zeroize::Zeroizing;

pub const VAULT_SERVICE: &str = "local.macvpn.vault";
pub const VAULT_ACCOUNT: &str = "dek";
pub const VAULT_LABEL: &str = "MacVPN vault key";

const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_AUTH_FAILED: i32 = -25293;
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

/// What a failed Keychain call means for the key store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    NotFound,
    /// The silent read was refused because macOS would have to ask (new cdhash, locked keychain).
    NeedsPrompt,
    Denied,
    Other,
}

fn classify(status: i32, ui: Ui) -> Outcome {
    match status {
        ERR_SEC_ITEM_NOT_FOUND => Outcome::NotFound,
        ERR_SEC_INTERACTION_NOT_ALLOWED | ERR_SEC_AUTH_FAILED if ui == Ui::Fail => Outcome::NeedsPrompt,
        ERR_SEC_USER_CANCELED | ERR_SEC_AUTH_FAILED => Outcome::Denied,
        _ => Outcome::Other,
    }
}

fn error(status: i32) -> KeyStoreError {
    match classify(status, Ui::Allow) {
        Outcome::Denied => KeyStoreError::Denied,
        _ => KeyStoreError::Unavailable(format!("OSStatus {status}")),
    }
}

/// The DEK in the Keychain.
pub struct KeychainKeyStore {
    service: String,
    account: String,
    target: Target,
}

impl KeychainKeyStore {
    /// The production item in the login keychain.
    pub fn new() -> KeychainKeyStore {
        KeychainKeyStore { service: VAULT_SERVICE.into(), account: VAULT_ACCOUNT.into(), target: Target::Default }
    }

    /// An item in one explicitly addressed keychain file (created and unlocked by the caller), under a test
    /// service name. For the isolated integration test only (the `test-support` feature, enabled only by this
    /// crate's own dev-dependency): it never reads or writes the login keychain.
    #[cfg(feature = "test-support")]
    pub fn in_keychain(keychain: &std::path::Path, service: &str) -> KeychainKeyStore {
        let target = Target::Keychain(keychain.to_path_buf());
        KeychainKeyStore { service: service.into(), account: VAULT_ACCOUNT.into(), target }
    }

    fn read(&self, ui: Ui) -> Result<Zeroizing<Vec<u8>>, i32> {
        keychain_ffi::item_read(&self.service, &self.account, ui, &self.target).map(Zeroizing::new)
    }
}

impl Default for KeychainKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore for KeychainKeyStore {
    fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        let status = match self.read(Ui::Fail) {
            Ok(data) => return Ok(Some(data)),
            Err(status) => status,
        };
        match classify(status, Ui::Fail) {
            Outcome::NotFound => Ok(None),
            Outcome::NeedsPrompt => match self.read(Ui::Allow) {
                Ok(data) => Ok(Some(data)),
                Err(status) if classify(status, Ui::Allow) == Outcome::NotFound => Ok(None),
                Err(status) => Err(error(status)),
            },
            _ => Err(error(status)),
        }
    }

    fn exists(&self) -> Result<bool, KeyStoreError> {
        keychain_ffi::item_exists(&self.service, &self.account, &self.target).map_err(error)
    }

    fn set(&self, key: &[u8]) -> Result<(), KeyStoreError> {
        keychain_ffi::item_write(&self.service, &self.account, VAULT_LABEL, key, &self.target).map_err(error)
    }

    fn delete(&self) -> Result<(), KeyStoreError> {
        keychain_ffi::item_delete(&self.service, &self.account, &self.target).map_err(error)
    }
}

/// `getentropy(2)`, the kernel CSPRNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn fill(&self, buf: &mut [u8]) -> io::Result<()> {
        crate::sys::getentropy(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_map_to_the_documented_outcomes() {
        assert_eq!(classify(ERR_SEC_ITEM_NOT_FOUND, Ui::Fail), Outcome::NotFound);
        assert_eq!(classify(ERR_SEC_ITEM_NOT_FOUND, Ui::Allow), Outcome::NotFound);
        // A silent read that would need the prompt is retried once with UI.
        assert_eq!(classify(ERR_SEC_INTERACTION_NOT_ALLOWED, Ui::Fail), Outcome::NeedsPrompt);
        assert_eq!(classify(ERR_SEC_AUTH_FAILED, Ui::Fail), Outcome::NeedsPrompt);
        // With the prompt shown: a cancel or a refusal is `Denied`.
        assert_eq!(classify(ERR_SEC_USER_CANCELED, Ui::Allow), Outcome::Denied);
        assert_eq!(classify(ERR_SEC_AUTH_FAILED, Ui::Allow), Outcome::Denied);
        assert_eq!(classify(ERR_SEC_INTERACTION_NOT_ALLOWED, Ui::Allow), Outcome::Other);
        assert_eq!(classify(-25291, Ui::Fail), Outcome::Other);
    }

    #[test]
    fn errors_carry_only_the_status() {
        assert_eq!(error(ERR_SEC_USER_CANCELED), KeyStoreError::Denied);
        assert_eq!(error(ERR_SEC_AUTH_FAILED), KeyStoreError::Denied);
        assert_eq!(error(-25291), KeyStoreError::Unavailable("OSStatus -25291".into()));
    }

    #[test]
    fn production_item_names() {
        let store = KeychainKeyStore::new();
        assert_eq!(store.service, "local.macvpn.vault");
        assert_eq!(store.account, "dek");
        assert_eq!(store.target, Target::Default);
        assert_eq!(VAULT_LABEL, "MacVPN vault key");
    }
}
