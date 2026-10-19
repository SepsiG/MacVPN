//! The encrypted vault (spec `2026-10-19-vault-folders-design.md`, section 2): one SQLCipher database for all user
//! data, keyed by a random DEK that is wrapped twice in `vault.keys` (master password and recovery key).
//!
//! Platform-independent and without `unsafe`: randomness comes in through [`Entropy`] and the OS key store through
//! `KeyStore`, both implemented in `platform-mac`. Compiled only with the `vault` feature, which the root layer
//! (`mvpn`) never enables.
//!
//! Nothing in here logs or formats key material: [`Dek`], [`RecoveryKey`] and the KEKs live in `Zeroizing`
//! buffers and their `Debug` output is redacted.

pub mod backup;
mod color;
mod db;
mod entropy;
mod keys;
mod keystore;
mod legacy;
mod recovery;
mod repo_connections;
mod repo_credentials;
mod repo_folders;
mod repo_misc;
mod schema;
mod tree;

pub use color::FolderColor;
pub use db::{Tx, VAULT_FILE, Vault, VaultError};
pub use entropy::{Entropy, FixedEntropy};
pub use keys::{
    AAD_PASSWORD, AAD_RECOVERY, Dek, KEYS_FILE, KdfParams, KeyError, KeyFile, MIN_PASSWORD_CHARS, Slot,
    check_password_rules, derive_kek,
};
pub use keystore::{KeyStore, KeyStoreError, MemoryKeyStore};
pub use legacy::{LegacyKeychain, LegacyRead};
pub use recovery::{RecoveryKey, RecoveryKeyError};
pub use repo_connections::{ConnectionRecord, StoredConnection};
pub use repo_credentials::{
    CredentialInUse, MAX_CREDENTIAL_NAME_CHARACTERS, MAX_CREDENTIAL_PASSWORD_BYTES, MAX_CREDENTIAL_USERNAME_BYTES,
    SharedCredential, validate_credential_name,
};
pub use repo_folders::DeleteMode;
pub use repo_misc::SystemItem;
pub use schema::{CURRENT_SCHEMA, Migration};
pub use tree::{
    ColorSource, FolderNode, FolderTree, MAX_FOLDER_NAME_CHARACTERS, TreeEntry, TreeError, order_tree,
    validate_folder_name,
};
