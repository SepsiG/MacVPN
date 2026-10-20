//! The admin key file, `<name>.macvpnadminkey` (spec 7, plan Task 14): an admin signing key (normally the backup
//! admin key, kept offline) sealed with a password in the backup's container ([`crate::vault::sealed`]): magic
//! `MVPNAKEY`, format 1, Argon2id under the backup's ceiling, XChaCha20-Poly1305 with the header as AAD.
//!
//! The plaintext is the JSON `{"version": 1, "role": "backup", "seed": "<base64>", "created": "<iso8601>"}` in a
//! right-sized `Zeroizing` buffer (the seed base64 inside it, the `Value` trees wiped). Opening fails with one
//! [`AdminKeyFileError::CannotOpen`] for a wrong password, a damaged byte, a truncated or foreign file; only a newer
//! container is told apart. The password needs at least `MIN_PASSWORD_CHARS` characters. The file is written 0600
//! through `exporter::write` and read like a backup (`O_NOFOLLOW`, regular file, at most 64 KiB).

use super::keys::AdminKey;
use crate::date::Date;
use crate::exporter;
use crate::l10n::{self, Arg};
use crate::vault::sealed::{self, ReadError, SealedError};
use crate::vault::wiped_json::{WipedValue, parse_strict, to_wiped_vec};
use crate::vault::{AdminKeyRole, Entropy, KdfParams, MIN_PASSWORD_CHARS, check_password_rules};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Map, Value};
use std::fmt;
use std::path::Path;
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 8] = b"MVPNAKEY";
/// The container format this build writes and reads.
pub const FORMAT: u16 = 1;
pub const EXTENSION: &str = "macvpnadminkey";
/// The largest admin key file read (a real one is a few hundred bytes).
pub const MAX_ADMIN_KEY_FILE_BYTES: usize = 64 * 1024;
const PAYLOAD_VERSION: u64 = 1;

/// Why an admin key file could not be written or read. No variant carries the password or the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminKeyFileError {
    /// A wrong password or a damaged, truncated or foreign file.
    CannotOpen,
    /// Made by a newer MacVPN.
    NewerVersion,
    /// Over [`MAX_ADMIN_KEY_FILE_BYTES`].
    TooLarge,
    /// The password is too short; the localized rule.
    WeakPassword(String),
    /// Reading, writing or sealing failed; a message without secrets.
    Io(String),
}

impl fmt::Display for AdminKeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            AdminKeyFileError::CannotOpen => {
                l10n::tr("The admin key file cannot be opened: the password is wrong or the file is damaged.", &[])
            }
            AdminKeyFileError::NewerVersion => l10n::tr("The admin key file was made by a newer MacVPN.", &[]),
            AdminKeyFileError::TooLarge => l10n::tr("The file is too large to be an admin key file.", &[]),
            AdminKeyFileError::WeakPassword(rule) => rule.clone(),
            AdminKeyFileError::Io(message) => message.clone(),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for AdminKeyFileError {}

/// The admin key file password rule: at least `MIN_PASSWORD_CHARS` characters.
pub fn check_admin_key_password(password: &str) -> Result<(), AdminKeyFileError> {
    check_password_rules(password).map_err(|_| {
        AdminKeyFileError::WeakPassword(l10n::tr(
            "The admin key file password must be at least %d characters long",
            &[Arg::from(MIN_PASSWORD_CHARS)],
        ))
    })
}

/// An admin key read from a file. `Debug` shows the fingerprint only.
#[derive(Debug)]
pub struct ImportedAdminKey {
    pub key: AdminKey,
    pub role: AdminKeyRole,
    pub created: Date,
}

/// Seals `key` with `password` (see the module docs). Runs the KDF: call it off the main thread.
pub fn export_admin_key(
    key: &AdminKey,
    role: AdminKeyRole,
    created: Date,
    password: &str,
    kdf: KdfParams,
    e: &dyn Entropy,
) -> Result<Vec<u8>, AdminKeyFileError> {
    check_admin_key_password(password)?;
    let seed = key.seed();
    let mut m = Map::new();
    m.insert("version".into(), Value::from(PAYLOAD_VERSION));
    m.insert("role".into(), Value::String(role.as_str().into()));
    m.insert("seed".into(), Value::String(BASE64.encode(&seed[..])));
    m.insert("created".into(), Value::String(created.iso8601()));
    let tree = WipedValue(Value::Object(m));
    let plaintext = to_wiped_vec(&tree.0).map_err(|_| AdminKeyFileError::Io("cannot encode the key".into()))?;
    sealed::seal_with_password(MAGIC, FORMAT, &plaintext, password, kdf, e).map_err(sealed_error)
}

/// Opens an admin key file's bytes (see the module docs). Runs the KDF: call it off the main thread.
pub fn import_admin_key(bytes: &[u8], password: &str) -> Result<ImportedAdminKey, AdminKeyFileError> {
    let plaintext =
        sealed::open_with_password(bytes, MAGIC, FORMAT, password, MAX_ADMIN_KEY_FILE_BYTES).map_err(sealed_error)?;
    decode(&plaintext).ok_or(AdminKeyFileError::CannotOpen)
}

fn decode(plaintext: &[u8]) -> Option<ImportedAdminKey> {
    let tree = parse_strict(plaintext)?;
    let root = tree.0.as_object()?;
    let known = ["version", "role", "seed", "created"];
    if root.len() != known.len() || !known.iter().all(|k| root.contains_key(*k)) {
        return None;
    }
    if root["version"].as_u64()? != PAYLOAD_VERSION {
        return None;
    }
    let role = AdminKeyRole::parse(root["role"].as_str()?)?;
    let text = root["seed"].as_str()?;
    let mut seed = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(text.len())]);
    let n = BASE64.decode_slice(text, &mut seed[..]).ok()?;
    let key = AdminKey::from_seed(&seed[..n])?;
    let created = Date::parse_iso8601(root["created"].as_str()?)?;
    Some(ImportedAdminKey { key, role, created })
}

fn sealed_error(e: SealedError) -> AdminKeyFileError {
    match e {
        SealedError::CannotOpen => AdminKeyFileError::CannotOpen,
        SealedError::NewerVersion(_) => AdminKeyFileError::NewerVersion,
        SealedError::TooLarge => AdminKeyFileError::TooLarge,
        SealedError::Io(message) => AdminKeyFileError::Io(message),
    }
}

/// Reads an admin key file the user picked: never a symlink, only a regular file, at most
/// [`MAX_ADMIN_KEY_FILE_BYTES`].
pub fn read_admin_key_file(path: &Path) -> Result<Vec<u8>, AdminKeyFileError> {
    sealed::read_sealed_file(path, MAX_ADMIN_KEY_FILE_BYTES).map_err(|e| match e {
        ReadError::TooLarge => AdminKeyFileError::TooLarge,
        ReadError::CannotRead => AdminKeyFileError::Io(l10n::tr("Cannot read the file", &[])),
    })
}

/// Writes the sealed bytes atomically, 0600 (`exporter::write`).
pub fn write_admin_key_file(path: &Path, bytes: &[u8]) -> Result<(), AdminKeyFileError> {
    if bytes.len() > MAX_ADMIN_KEY_FILE_BYTES {
        return Err(AdminKeyFileError::TooLarge);
    }
    exporter::write(bytes, path).map_err(|e| AdminKeyFileError::Io(e.message))
}
