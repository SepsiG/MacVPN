//! The 1.1 Keychain items as the migration into the vault sees them (plan B Task 13): generic passwords of the
//! service `local.macvpn.secrets`, account `<item>.<field>`, where the item is a managed connection's UUID or a
//! system VPN's service ID. `platform-mac` implements it over the Keychain secret store; tests use a fake.

use crate::models::SecretField;
use std::fmt;
use zeroize::Zeroizing;

/// The outcome of reading one item.
pub enum LegacyRead {
    Value(Zeroizing<String>),
    /// The item is gone (deleted between the listing and the read).
    Missing,
    /// The item holds bytes that are not UTF-8 (never written by MacVPN; the 1.1 app could not use it either).
    Undecodable,
    /// The read failed (the user denied or cancelled the macOS prompt, a locked keychain, any other `OSStatus`):
    /// worth retrying later.
    Unavailable(i32),
}

impl fmt::Debug for LegacyRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LegacyRead::Value(_) => f.write_str("Value(..)"),
            LegacyRead::Missing => f.write_str("Missing"),
            LegacyRead::Undecodable => f.write_str("Undecodable"),
            LegacyRead::Unavailable(status) => write!(f, "Unavailable({status})"),
        }
    }
}

/// List, read and delete the 1.1 secret items. Reading may show a macOS prompt per item.
pub trait LegacyKeychain: Send + Sync {
    /// Runs before the items are listed (the Keychain implementation moves the items of the older service
    /// `macvpn` over first, as the 1.1 launch does).
    fn prepare(&self) {}
    /// Every MacVPN item: `(item id, field)`. Listing shows no prompt.
    fn items(&self) -> Vec<(String, SecretField)>;
    fn read(&self, item: &str, field: SecretField) -> LegacyRead;
    fn delete(&self, item: &str, field: SecretField);
}
