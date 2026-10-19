//! The full backup (spec 3b, plan B Task 20): everything in the vault but the paired control clients, sealed with a
//! backup password into one `.macvpnbackup` file, and the pure restore planner.
//!
//! **Container**, version 1, all integers big-endian: a 64-byte header followed by the ciphertext.
//!
//! ```text
//! magic        8  b"MVPNBKUP"
//! format       2  1
//! kdf          1  1 = Argon2id
//! reserved     1  0
//! m_kib        4
//! t            4
//! p            4
//! salt        16
//! nonce       24
//! ciphertext   …  XChaCha20-Poly1305(key = Argon2id(backup password, salt, params), nonce, payload,
//!                 AAD = the 64 header bytes), the 16-byte tag last
//! ```
//!
//! The key derivation and the AEAD are the vault's own ([`derive_kek`], with its floor), under a lower ceiling of
//! its own ([`MAX_KDF`]: 256 MiB, 64 passes, 4 lanes), checked before the KDF runs, so a crafted header cannot make
//! the app allocate a gigabyte or spin for minutes. Even within the ceiling the KDF takes seconds: the app calls
//! [`open`] (and [`seal`]) off the main thread (plan B Task 21). Opening fails with one generic
//! [`BackupError::CannotOpen`] for a wrong password, any damaged byte, a truncated file, an unknown KDF or
//! impossible parameters, so the error tells nothing about which part was wrong. Only a newer `format` is told
//! apart (checked first, since an unknown format cannot be authenticated), and a newer payload version after
//! decryption.
//!
//! **Untrusted input.** Whoever knows a backup password can craft a payload, so an opened payload is checked
//! like any other input before anything is written ([`validate`]): the repository's own rules for credential
//! names, usernames, passwords, folder names and item ids, the control-character rule of `Secrets::input_error`
//! for every secret, a size cap per secret, a count cap per collection ([`MAX_ITEMS`]) and a plaintext cap
//! ([`MAX_PLAINTEXT_BYTES`]). A refused payload is [`BackupError::Invalid`] (on open) or
//! [`VaultError::InvalidBackup`] (on restore), naming the kind of problem, never the value. [`read_backup_file`]
//! reads the file with a size cap, without following a symlink, and only from a regular file.
//!
//! **Payload:** JSON (plan B, "Resolved"), never a database image, so no plain database file can exist even
//! briefly. It is built and parsed in memory only: the serialized text lives in a `Zeroizing` buffer of exactly the
//! right size, the intermediate `serde_json::Value` trees are wiped before they are dropped, and the config and the
//! secret values are base64 inside the JSON (so the parser never copies them into its unescaping scratch buffer).
//! Nothing here writes a temporary file; [`write_backup`] writes only the sealed bytes.

use super::color::FolderColor;
use super::db::{Vault, VaultError};
use super::entropy::Entropy;
use super::keys::{KdfParams, derive_kek};
use super::repo_connections::wiped_bytes_opt;
use super::repo_credentials::{
    MAX_CREDENTIAL_NAME_CHARACTERS, check_item, check_password, check_username, validate_credential_name,
};
use super::repo_misc::SystemItem;
use super::tree::{FolderNode, FolderTree, MAX_FOLDER_NAME_CHARACTERS, validate_folder_name};
use crate::date::Date;
use crate::exporter;
use crate::mfa;
use crate::models::{Connection, OTPSetting, SecretField, parse_uuid, uuid_string};
use crate::ranking::ConnectionRanking;
use crate::swift_json;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use rusqlite::OptionalExtension;
use rusqlite::types::ValueRef;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use unicode_segmentation::UnicodeSegmentation;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 8] = b"MVPNBKUP";
/// The container format this build writes and reads.
pub const FORMAT: u16 = 1;
/// The payload schema this build writes; older ones are migrated on open.
pub const PAYLOAD_VERSION: u32 = 1;
pub const HEADER_LEN: usize = 64;
/// The largest payload (the serialized JSON) sealed or opened.
pub const MAX_PLAINTEXT_BYTES: usize = 64 * 1024 * 1024;
/// The largest backup file read or written: the header, [`MAX_PLAINTEXT_BYTES`] and the tag.
pub const MAX_BACKUP_BYTES: usize = HEADER_LEN + MAX_PLAINTEXT_BYTES + TAG_LEN;
/// The KDF ceiling of a backup header (below the vault's own): a header above it cannot be opened, before the KDF
/// runs. [`seal`] refuses parameters above it.
pub const MAX_KDF: KdfParams = KdfParams { m_kib: 256 * 1024, t: 64, p: 4 };
/// The most entries of each collection in a payload (connections, folders, credentials, links, pins, usage
/// entries, system items, system secrets, system OTP settings).
pub const MAX_ITEMS: usize = 10_000;
/// The longest secret value of an item (the editors' field limit).
pub const MAX_SECRET_BYTES: usize = 64 * 1024;
/// The longest `appVersion`.
const MAX_APP_VERSION_BYTES: usize = 64;
/// The file name extension (`MacVPN-backup-<YYYY-MM-DD>.macvpnbackup`).
pub const EXTENSION: &str = "macvpnbackup";

const KDF_ARGON2ID: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const BACKUP_SUFFIX: &str = "backup";

/// Why a backup could not be written or read. No variant carries a password or payload contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupError {
    /// A wrong password or a damaged, truncated or foreign file: deliberately one error for all of them.
    CannotOpen,
    /// Made by a newer MacVPN (the container format, or the payload version).
    NewerVersion(u16),
    /// Over [`MAX_BACKUP_BYTES`] (or the payload over [`MAX_PLAINTEXT_BYTES`]).
    TooLarge,
    /// The password was right but the payload breaks a rule (see [`validate`]), or [`seal`] was given such a
    /// payload. Names the kind of problem only.
    Invalid(InvalidBackup),
    /// Writing the file (or preparing the payload) failed; the localized message for the UI.
    Io(String),
}

impl fmt::Display for BackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BackupError::CannotOpen => f.write_str("the backup cannot be opened (wrong password or damaged file)"),
            BackupError::NewerVersion(v) => write!(f, "the backup was made by a newer MacVPN (version {v})"),
            BackupError::TooLarge => f.write_str("the backup file is too large"),
            BackupError::Invalid(e) => e.fmt(f),
            BackupError::Io(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for BackupError {}

/// A collection of the payload, for [`InvalidBackup::TooMany`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Collection {
    Connections,
    Folders,
    Credentials,
    CredentialLinks,
    Pins,
    Usage,
    SystemItems,
    SystemSecrets,
    SystemOtp,
}

/// Why a payload is refused ([`validate`]). Carries no value from the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidBackup {
    /// More than [`MAX_ITEMS`] entries.
    TooMany(Collection),
    /// A credential name the Credentials section would refuse (`validate_credential_name`), or not in its stored
    /// (cleaned) form.
    CredentialName,
    /// Over 256 bytes or a control character.
    CredentialUsername,
    /// Over 1024 bytes or a control character.
    CredentialPassword,
    /// Two credentials with the same id or name, or two folders or connections with the same id.
    Duplicate,
    /// A folder name `validate_folder_name` refuses, or not in its stored form.
    FolderName,
    /// The backup's folders are not a tree (a cycle, an unknown parent).
    FolderTree,
    /// An item id (system VPN service ID, link, OTP, ranking key) that is empty, over 256 bytes or has a control
    /// character.
    ItemId,
    /// A secret with a line break or control character, or over [`MAX_SECRET_BYTES`].
    Secret,
    /// The `appVersion` is over 64 bytes or has a control character.
    AppVersion,
}

impl fmt::Display for InvalidBackup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self {
            InvalidBackup::TooMany(_) => "too many entries",
            InvalidBackup::CredentialName => "an invalid credential name",
            InvalidBackup::CredentialUsername => "an invalid credential user name",
            InvalidBackup::CredentialPassword => "an invalid credential password",
            InvalidBackup::Duplicate => "a duplicate entry",
            InvalidBackup::FolderName => "an invalid folder name",
            InvalidBackup::FolderTree => "folders that are not a tree",
            InvalidBackup::ItemId => "an invalid item id",
            InvalidBackup::Secret => "an invalid secret",
            InvalidBackup::AppVersion => "an invalid app version",
        };
        write!(f, "the backup cannot be restored: it has {what}")
    }
}

impl std::error::Error for InvalidBackup {}
/// One secret of an item: the field and its value.
pub type ItemSecrets = Vec<(SecretField, Zeroizing<String>)>;

/// A managed connection with its config, placement and own secrets.
#[derive(Clone, PartialEq)]
pub struct BackupConnection {
    /// The metadata (`meta.json`).
    pub connection: Connection,
    pub config: Zeroizing<String>,
    pub folder_id: Option<Uuid>,
    pub color: Option<FolderColor>,
    pub position: i64,
    /// In [`SecretField::ALL`] order.
    pub secrets: ItemSecrets,
}

impl fmt::Debug for BackupConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupConnection")
            .field("connection", &self.connection)
            .field("folder_id", &self.folder_id)
            .field("color", &self.color)
            .field("position", &self.position)
            .field("secrets", &self.secrets.iter().map(|(field, _)| *field).collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// A shared credential (spec 3a) with its username and password (both base64 in the JSON and wiped on drop,
/// like an item's secrets). Field names follow plan B Task 18's `SharedCredential`.
#[derive(Clone, PartialEq)]
pub struct BackupCredential {
    pub id: Uuid,
    pub name: String,
    pub username: Zeroizing<String>,
    pub password: Option<Zeroizing<String>>,
    pub created: Date,
    pub updated: Date,
}

impl fmt::Debug for BackupCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupCredential")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("has_password", &self.password.is_some())
            .finish_non_exhaustive()
    }
}

/// The app preferences carried in a backup (spec 3b); the app reads and applies them (Task 21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackupPreferences {
    pub auto_check: bool,
    pub delay_24h: bool,
    pub launch_at_login: bool,
    pub control_api_enabled: bool,
    pub auto_unlock: bool,
}

/// Everything a backup holds. Paired control clients, the DEK, the recovery key and the logs are **not** in it.
#[derive(Clone, PartialEq)]
pub struct BackupPayload {
    /// The payload schema ([`PAYLOAD_VERSION`]).
    pub version: u32,
    pub created: Date,
    pub app_version: String,
    /// Sorted by name, like [`Vault::connections`].
    pub connections: Vec<BackupConnection>,
    /// The secrets of every other item (the system VPNs, by service ID).
    pub system_secrets: BTreeMap<String, ItemSecrets>,
    /// Sorted by id.
    pub folders: Vec<FolderNode>,
    /// Sorted by name.
    pub credentials: Vec<BackupCredential>,
    /// `(item, credential)`, sorted by item.
    pub credential_links: Vec<(String, Uuid)>,
    /// Sorted by service ID.
    pub system_items: Vec<SystemItem>,
    pub system_otp: HashMap<String, OTPSetting>,
    /// Usage and pins.
    pub ranking: ConnectionRanking,
    pub preferences: BackupPreferences,
}

impl fmt::Debug for BackupPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackupPayload")
            .field("version", &self.version)
            .field("created", &self.created)
            .field("app_version", &self.app_version)
            .field("connections", &self.connections)
            .field("system_secrets", &self.system_secrets.keys().collect::<Vec<_>>())
            .field("folders", &self.folders)
            .field("credentials", &self.credentials)
            .field("credential_links", &self.credential_links)
            .field("system_items", &self.system_items)
            .field("system_otp", &self.system_otp)
            .field("ranking", &self.ranking)
            .field("preferences", &self.preferences)
            .finish()
    }
}

impl BackupPayload {
    /// A payload with no data.
    pub fn empty(created: Date, app_version: &str, preferences: BackupPreferences) -> BackupPayload {
        BackupPayload {
            version: PAYLOAD_VERSION,
            created,
            app_version: app_version.to_string(),
            connections: Vec::new(),
            system_secrets: BTreeMap::new(),
            folders: Vec::new(),
            credentials: Vec::new(),
            credential_links: Vec::new(),
            system_items: Vec::new(),
            system_otp: HashMap::new(),
            ranking: ConnectionRanking::default(),
            preferences,
        }
    }

    /// The native (L2TP / Cisco) connections, whose profiles are reinstalled after a restore.
    pub fn native_connections(&self) -> impl Iterator<Item = &Connection> {
        self.connections.iter().map(|c| &c.connection).filter(|c| c.kind.is_native())
    }
}

// MARK: - collect

/// Reads everything but the paired clients out of the vault. A connection row this build cannot decode is left
/// out (as [`Vault::connections`] skips it), and so is a secret of an unknown field.
pub fn collect(
    vault: &Vault,
    prefs: BackupPreferences,
    now: Date,
    app_version: &str,
) -> Result<BackupPayload, VaultError> {
    let conn = vault.connection();
    let mut secrets = all_secrets(conn)?;
    let mut connections = Vec::new();
    {
        let mut stmt = conn.prepare("SELECT meta_json, config, folder_id, color, position FROM connections")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let meta: String = row.get(0)?;
            let Some(connection) = swift_json::parse(meta.as_bytes()).ok().and_then(|v| Connection::from_json(&v).ok())
            else {
                continue;
            };
            let config = blob_text(row, 1, "a config")?;
            let folder: Option<String> = row.get(2)?;
            let color: Option<String> = row.get(3)?;
            let own = secrets.remove(&uuid_string(&connection.id)).unwrap_or_default();
            connections.push(BackupConnection {
                connection,
                config,
                folder_id: folder.as_deref().and_then(parse_uuid),
                color: color.as_deref().and_then(FolderColor::parse),
                position: row.get(4)?,
                secrets: own,
            });
        }
    }
    connections.sort_by(|a, b| {
        crate::collation::localized_case_insensitive_compare(&a.connection.name, &b.connection.name)
            .then_with(|| a.connection.id.cmp(&b.connection.id))
    });

    let mut folders = vault.folders()?;
    folders.sort_by_key(|f| uuid_string(&f.id));

    let mut credentials = Vec::new();
    {
        let mut stmt =
            conn.prepare("SELECT id, name, username, password, created, updated FROM credentials ORDER BY name")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let id = parse_uuid(&id).ok_or_else(|| VaultError::Corrupt("invalid credential id".into()))?;
            let password = match row.get_ref(3)? {
                ValueRef::Null => None,
                _ => Some(blob_text(row, 3, "a credential password")?),
            };
            let created: String = row.get(4)?;
            let updated: String = row.get(5)?;
            credentials.push(BackupCredential {
                id,
                name: row.get(1)?,
                username: blob_text(row, 2, "a credential username")?,
                password,
                created: Date::parse_iso8601(&created).unwrap_or(now),
                updated: Date::parse_iso8601(&updated).unwrap_or(now),
            });
        }
    }

    let mut credential_links = Vec::new();
    {
        let mut stmt = conn.prepare("SELECT item_id, credential_id FROM credential_links ORDER BY item_id")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (item, credential) = row?;
            let credential =
                parse_uuid(&credential).ok_or_else(|| VaultError::Corrupt("invalid credential id".into()))?;
            credential_links.push((item, credential));
        }
    }

    Ok(BackupPayload {
        version: PAYLOAD_VERSION,
        created: now,
        app_version: app_version.to_string(),
        connections,
        system_secrets: secrets,
        folders,
        credentials,
        credential_links,
        system_items: vault.system_items()?,
        system_otp: vault.system_otp_map()?,
        ranking: vault.ranking()?,
        preferences: prefs,
    })
}

/// Every stored secret by item, each item's fields in [`SecretField::ALL`] order.
fn all_secrets(conn: &rusqlite::Connection) -> Result<BTreeMap<String, ItemSecrets>, VaultError> {
    let mut stmt = conn.prepare("SELECT connection_id, field, value FROM secrets")?;
    let mut rows = stmt.query([])?;
    let mut out: BTreeMap<String, ItemSecrets> = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let item: String = row.get(0)?;
        let field: String = row.get(1)?;
        let Some(field) = SecretField::from_raw_value(&field) else { continue };
        let value = blob_text(row, 2, "a secret")?;
        if !value.is_empty() {
            out.entry(item).or_default().push((field, value));
        }
    }
    for fields in out.values_mut() {
        fields.sort_by_key(|(f, _)| SecretField::ALL.iter().position(|a| a == f));
    }
    Ok(out)
}

/// A BLOB (or TEXT) column as UTF-8 text in a wiped buffer; the error names only the column.
fn blob_text(row: &rusqlite::Row<'_>, index: usize, what: &str) -> Result<Zeroizing<String>, VaultError> {
    let bytes = match row.get_ref(index)? {
        ValueRef::Blob(b) | ValueRef::Text(b) => b,
        ValueRef::Null => &[],
        _ => return Err(VaultError::Corrupt(format!("{what} is not text"))),
    };
    std::str::from_utf8(bytes)
        .map(|s| Zeroizing::new(s.to_owned()))
        .map_err(|_| VaultError::Corrupt(format!("{what} is not UTF-8")))
}

/// Sets `missing_since = now` on the payload's system VPNs that are not installed on this Mac (`known`: the
/// service IDs present now), so their placement is kept for the 30-day retention (spec 5); an already set date is
/// kept, and an installed one is cleared. The app calls this before [`merge`] or [`replace`] (the planner itself
/// does not see the system services).
pub fn mark_missing_system_items(payload: &mut BackupPayload, known: &HashSet<String>, now: Date) {
    for item in &mut payload.system_items {
        if known.contains(&item.service_id) {
            item.missing_since = None;
        } else if item.missing_since.is_none() {
            item.missing_since = Some(now);
        }
    }
}

// MARK: - the container

/// Serializes and seals the payload. `kdf` is raised to at least [`KdfParams::DEFAULT`] (never lowered) and must
/// stay within [`MAX_KDF`]; salt and nonce come fresh from `e`. A payload [`validate`] refuses is not sealed
/// ([`BackupError::Invalid`]): a backup that could not be restored is refused when it is made, not when it is
/// needed. Runs the KDF: call it off the main thread.
pub fn seal(payload: &BackupPayload, password: &str, kdf: KdfParams, e: &dyn Entropy) -> Result<Vec<u8>, BackupError> {
    validate(payload).map_err(BackupError::Invalid)?;
    seal_payload(payload, password, kdf, e)
}

/// [`seal`] without [`validate`]: lets tests build the crafted files a restore must refuse. Test builds only.
#[cfg(feature = "test-support")]
pub fn seal_unchecked(
    payload: &BackupPayload,
    password: &str,
    kdf: KdfParams,
    e: &dyn Entropy,
) -> Result<Vec<u8>, BackupError> {
    seal_payload(payload, password, kdf, e)
}

fn within_ceiling(kdf: KdfParams) -> bool {
    kdf.m_kib <= MAX_KDF.m_kib && kdf.t <= MAX_KDF.t && kdf.p <= MAX_KDF.p
}

fn seal_payload(
    payload: &BackupPayload,
    password: &str,
    kdf: KdfParams,
    e: &dyn Entropy,
) -> Result<Vec<u8>, BackupError> {
    let kdf = kdf.strengthened();
    if !within_ceiling(kdf) {
        return Err(BackupError::Io("the key derivation parameters are above the backup ceiling".into()));
    }
    let mut plaintext = encode_payload(payload)?;
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(BackupError::TooLarge);
    }
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    e.fill(&mut salt).map_err(io_error)?;
    e.fill(&mut nonce).map_err(io_error)?;
    let header = header(kdf, &salt, &nonce);
    let key = derive_kek(password.as_bytes(), &salt, kdf).map_err(|e| BackupError::Io(e.to_string()))?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| BackupError::Io("invalid key".into()))?;
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(nonce), &header, (&mut plaintext[..]).into())
        .map_err(|_| BackupError::Io("encryption failed".into()))?;
    // `plaintext` now holds the ciphertext.
    let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(&header);
    out.extend_from_slice(&plaintext);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Opens a sealed backup (see the module docs for the errors) and [`validate`]s the payload. Runs the KDF (up to
/// [`MAX_KDF`], seconds): the app calls it off the main thread.
pub fn open(bytes: &[u8], password: &str) -> Result<BackupPayload, BackupError> {
    if bytes.len() > MAX_BACKUP_BYTES {
        return Err(BackupError::TooLarge);
    }
    if bytes.len() < HEADER_LEN + TAG_LEN || &bytes[..8] != MAGIC {
        return Err(BackupError::CannotOpen);
    }
    let format = u16::from_be_bytes([bytes[8], bytes[9]]);
    if format > FORMAT {
        return Err(BackupError::NewerVersion(format));
    }
    if format != FORMAT || bytes[10] != KDF_ARGON2ID || bytes[11] != 0 {
        return Err(BackupError::CannotOpen);
    }
    let word = |at: usize| u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    let kdf = KdfParams { m_kib: word(12), t: word(16), p: word(20) };
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[24..40]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[40..HEADER_LEN]);
    let (header, rest) = bytes.split_at(HEADER_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
    // Above the backup ceiling: refused before the KDF runs. Below the vault's floor: refused by `derive_kek`.
    if !within_ceiling(kdf) {
        return Err(BackupError::CannotOpen);
    }
    let key = derive_kek(password.as_bytes(), &salt, kdf).map_err(|_| BackupError::CannotOpen)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| BackupError::CannotOpen)?;
    let tag = Tag::try_from(tag).map_err(|_| BackupError::CannotOpen)?;
    let mut plaintext = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_inout_detached(&XNonce::from(nonce), header, (&mut plaintext[..]).into(), &tag)
        .map_err(|_| BackupError::CannotOpen)?;
    let payload = decode_payload(&plaintext)?;
    validate(&payload).map_err(BackupError::Invalid)?;
    Ok(payload)
}

/// Reads a backup file for [`open`]: never follows a symlink (`O_NOFOLLOW`), never blocks on a FIFO
/// (`O_NONBLOCK`), only a regular file, and at most [`MAX_BACKUP_BYTES`] (read through `take`, so a file that grows
/// while it is read cannot exhaust memory). The app reads backups only through this, never with `fs::read`.
pub fn read_backup_file(path: &Path) -> Result<Vec<u8>, BackupError> {
    let cannot_read = || BackupError::Io(crate::l10n::tr("Cannot read the file", &[]));
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| cannot_read())?;
    let meta = file.metadata().map_err(|_| cannot_read())?;
    if !meta.file_type().is_file() {
        return Err(cannot_read());
    }
    if meta.len() > MAX_BACKUP_BYTES as u64 {
        return Err(BackupError::TooLarge);
    }
    let mut bytes = Vec::new();
    file.take(MAX_BACKUP_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(|_| cannot_read())?;
    if bytes.len() > MAX_BACKUP_BYTES {
        return Err(BackupError::TooLarge);
    }
    Ok(bytes)
}

/// Writes the sealed bytes atomically (a temp file in the same directory, `O_EXCL | O_NOFOLLOW`, 0600, fsync,
/// rename, fsync of the directory); on any error the partial file is removed.
pub fn write_backup(path: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    if bytes.len() > MAX_BACKUP_BYTES {
        return Err(BackupError::TooLarge);
    }
    exporter::write(bytes, path).map_err(|e| BackupError::Io(e.message))
}

fn header(kdf: KdfParams, salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..8].copy_from_slice(MAGIC);
    h[8..10].copy_from_slice(&FORMAT.to_be_bytes());
    h[10] = KDF_ARGON2ID;
    h[11] = 0;
    h[12..16].copy_from_slice(&kdf.m_kib.to_be_bytes());
    h[16..20].copy_from_slice(&kdf.t.to_be_bytes());
    h[20..24].copy_from_slice(&kdf.p.to_be_bytes());
    h[24..40].copy_from_slice(salt);
    h[40..HEADER_LEN].copy_from_slice(nonce);
    h
}

fn io_error(e: io::Error) -> BackupError {
    BackupError::Io(e.to_string())
}

// MARK: - the payload JSON

/// A JSON tree whose strings are wiped when it is dropped.
struct WipedValue(Value);

impl Drop for WipedValue {
    fn drop(&mut self) {
        fn wipe(v: &mut Value) {
            match v {
                Value::String(s) => s.zeroize(),
                Value::Array(items) => items.iter_mut().for_each(wipe),
                Value::Object(map) => map.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

/// Counts the bytes a serialization would take, so the real one goes into a buffer that never reallocates (a
/// reallocation would leave an unwiped copy behind).
struct Counter(usize);

impl io::Write for Counter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn secret_b64(value: &str) -> Value {
    Value::String(BASE64.encode(value.as_bytes()))
}

fn uuid_value(id: &Uuid) -> Value {
    Value::String(uuid_string(id))
}

fn opt<T>(value: Option<T>, f: impl FnOnce(T) -> Value) -> Value {
    value.map_or(Value::Null, f)
}

fn secrets_value(secrets: &ItemSecrets) -> Value {
    Value::Object(secrets.iter().map(|(field, value)| (field.raw_value().to_string(), secret_b64(value))).collect())
}

fn encode_payload(p: &BackupPayload) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    let mut root = Map::new();
    root.insert("version".into(), Value::from(p.version));
    root.insert("created".into(), Value::String(p.created.iso8601()));
    root.insert("appVersion".into(), Value::String(p.app_version.clone()));
    let connections = p
        .connections
        .iter()
        .map(|c| {
            let mut m = Map::new();
            m.insert("meta".into(), c.connection.to_json());
            m.insert("config".into(), secret_b64(&c.config));
            m.insert("folderId".into(), opt(c.folder_id.as_ref(), uuid_value));
            m.insert("color".into(), opt(c.color, |c| Value::String(c.as_str().into())));
            m.insert("position".into(), Value::from(c.position));
            m.insert("secrets".into(), secrets_value(&c.secrets));
            Value::Object(m)
        })
        .collect();
    root.insert("connections".into(), Value::Array(connections));
    root.insert(
        "systemSecrets".into(),
        Value::Object(p.system_secrets.iter().map(|(item, s)| (item.clone(), secrets_value(s))).collect()),
    );
    let folders = p
        .folders
        .iter()
        .map(|f| {
            let mut m = Map::new();
            m.insert("id".into(), uuid_value(&f.id));
            m.insert("parentId".into(), opt(f.parent.as_ref(), uuid_value));
            m.insert("name".into(), Value::String(f.name.clone()));
            m.insert("color".into(), opt(f.color, |c| Value::String(c.as_str().into())));
            m.insert("position".into(), Value::from(f.position));
            m.insert("collapsed".into(), Value::Bool(f.collapsed));
            Value::Object(m)
        })
        .collect();
    root.insert("folders".into(), Value::Array(folders));
    let credentials = p
        .credentials
        .iter()
        .map(|c| {
            let mut m = Map::new();
            m.insert("id".into(), uuid_value(&c.id));
            m.insert("name".into(), Value::String(c.name.clone()));
            m.insert("username".into(), secret_b64(&c.username));
            m.insert("password".into(), opt(c.password.as_deref(), |s| secret_b64(s)));
            m.insert("created".into(), Value::String(c.created.iso8601()));
            m.insert("updated".into(), Value::String(c.updated.iso8601()));
            Value::Object(m)
        })
        .collect();
    root.insert("credentials".into(), Value::Array(credentials));
    let links = p
        .credential_links
        .iter()
        .map(|(item, credential)| {
            let mut m = Map::new();
            m.insert("item".into(), Value::String(item.clone()));
            m.insert("credential".into(), uuid_value(credential));
            Value::Object(m)
        })
        .collect();
    root.insert("credentialLinks".into(), Value::Array(links));
    let system_items = p
        .system_items
        .iter()
        .map(|s| {
            let mut m = Map::new();
            m.insert("serviceId".into(), Value::String(s.service_id.clone()));
            m.insert("folderId".into(), opt(s.folder_id.as_ref(), uuid_value));
            m.insert("color".into(), opt(s.color, |c| Value::String(c.as_str().into())));
            m.insert("position".into(), Value::from(s.position));
            m.insert("missingSince".into(), opt(s.missing_since, |d| Value::String(d.iso8601())));
            Value::Object(m)
        })
        .collect();
    root.insert("systemItems".into(), Value::Array(system_items));
    root.insert(
        "systemOtp".into(),
        Value::Object(p.system_otp.iter().map(|(id, s)| (id.clone(), s.to_json())).collect()),
    );
    root.insert("ranking".into(), p.ranking.to_json().map_err(BackupError::Io)?);
    let prefs = &p.preferences;
    let mut m = Map::new();
    m.insert("autoCheck".into(), Value::Bool(prefs.auto_check));
    m.insert("delay24h".into(), Value::Bool(prefs.delay_24h));
    m.insert("launchAtLogin".into(), Value::Bool(prefs.launch_at_login));
    m.insert("controlApiEnabled".into(), Value::Bool(prefs.control_api_enabled));
    m.insert("autoUnlock".into(), Value::Bool(prefs.auto_unlock));
    root.insert("preferences".into(), Value::Object(m));

    let tree = WipedValue(Value::Object(root));
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, &tree.0).map_err(|e| BackupError::Io(e.to_string()))?;
    let mut out = Zeroizing::new(Vec::with_capacity(counter.0));
    serde_json::to_writer(&mut *out, &tree.0).map_err(|e| BackupError::Io(e.to_string()))?;
    Ok(out)
}

/// One payload migration step on the JSON object; `None` refuses the payload.
type PayloadMigration = fn(&mut Map<String, Value>) -> Option<()>;

/// Payload migrations: `MIGRATIONS[i]` turns version `i + 1` into `i + 2`. None yet (version 1 is the first).
const MIGRATIONS: &[PayloadMigration] = &[];

fn decode_payload(plaintext: &[u8]) -> Result<BackupPayload, BackupError> {
    let mut tree = WipedValue(serde_json::from_slice(plaintext).map_err(|_| BackupError::CannotOpen)?);
    let root = tree.0.as_object_mut().ok_or(BackupError::CannotOpen)?;
    let version = root.get("version").and_then(Value::as_u64).ok_or(BackupError::CannotOpen)?;
    if version > u64::from(PAYLOAD_VERSION) {
        return Err(BackupError::NewerVersion(u16::try_from(version).unwrap_or(u16::MAX)));
    }
    if version == 0 {
        return Err(BackupError::CannotOpen);
    }
    // Older payloads step up one version at a time.
    for step in MIGRATIONS.iter().skip(version as usize - 1) {
        step(root).ok_or(BackupError::CannotOpen)?;
    }
    root.insert("version".into(), Value::from(PAYLOAD_VERSION));
    decode_root(root).ok_or(BackupError::CannotOpen)
}

fn string(v: &Value, key: &str) -> Option<String> {
    v.get(key)?.as_str().map(str::to_string)
}

/// An optional field: absent or `null` is `Some(None)`, a present value that `f` refuses is `None`.
fn optional<T>(v: &Value, key: &str, f: impl FnOnce(&Value) -> Option<T>) -> Option<Option<T>> {
    match v.get(key) {
        None | Some(Value::Null) => Some(None),
        Some(x) => f(x).map(Some),
    }
}

fn uuid_of(v: &Value) -> Option<Uuid> {
    v.as_str().and_then(parse_uuid)
}

/// A colour this build does not know (a newer palette) reads as no colour, as in the database.
fn color_of(v: &Value) -> Option<FolderColor> {
    v.as_str().and_then(FolderColor::parse)
}

fn date_of(v: &Value) -> Option<Date> {
    v.as_str().and_then(Date::parse_iso8601)
}

/// Base64 text into a wiped string.
fn secret_of(v: &Value) -> Option<Zeroizing<String>> {
    let text = v.as_str()?;
    let mut buffer = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(text.len())]);
    let n = BASE64.decode_slice(text, &mut buffer[..]).ok()?;
    std::str::from_utf8(&buffer[..n]).ok().map(|s| Zeroizing::new(s.to_owned()))
}

fn secrets_of(v: &Value) -> Option<ItemSecrets> {
    let mut out = Vec::new();
    for (field, value) in v.as_object()? {
        // A field this build does not know is left out.
        let Some(field) = SecretField::from_raw_value(field) else { continue };
        out.push((field, secret_of(value)?));
    }
    out.sort_by_key(|(f, _)| SecretField::ALL.iter().position(|a| a == f));
    Some(out)
}

fn array<'a>(root: &'a Map<String, Value>, key: &str) -> Option<&'a Vec<Value>> {
    root.get(key)?.as_array()
}

fn decode_root(root: &Map<String, Value>) -> Option<BackupPayload> {
    let version = u32::try_from(root.get("version")?.as_u64()?).ok()?;
    let created = date_of(root.get("created")?)?;
    let app_version = root.get("appVersion")?.as_str()?.to_string();

    let mut connections = Vec::new();
    for c in array(root, "connections")? {
        connections.push(BackupConnection {
            connection: Connection::from_json(c.get("meta")?).ok()?,
            config: secret_of(c.get("config")?)?,
            folder_id: optional(c, "folderId", uuid_of)?,
            color: optional(c, "color", |v| Some(color_of(v)))?.flatten(),
            position: c.get("position")?.as_i64()?,
            secrets: secrets_of(c.get("secrets")?)?,
        });
    }
    let mut system_secrets = BTreeMap::new();
    for (item, s) in root.get("systemSecrets")?.as_object()? {
        system_secrets.insert(item.clone(), secrets_of(s)?);
    }
    let mut folders = Vec::new();
    for f in array(root, "folders")? {
        folders.push(FolderNode {
            id: uuid_of(f.get("id")?)?,
            parent: optional(f, "parentId", uuid_of)?,
            name: string(f, "name")?,
            color: optional(f, "color", |v| Some(color_of(v)))?.flatten(),
            position: f.get("position")?.as_i64()?,
            collapsed: f.get("collapsed")?.as_bool()?,
        });
    }
    let mut credentials = Vec::new();
    for c in array(root, "credentials")? {
        credentials.push(BackupCredential {
            id: uuid_of(c.get("id")?)?,
            name: string(c, "name")?,
            username: secret_of(c.get("username")?)?,
            password: optional(c, "password", secret_of)?,
            created: date_of(c.get("created")?)?,
            updated: date_of(c.get("updated")?)?,
        });
    }
    let mut credential_links = Vec::new();
    for l in array(root, "credentialLinks")? {
        credential_links.push((string(l, "item")?, uuid_of(l.get("credential")?)?));
    }
    let mut system_items = Vec::new();
    for s in array(root, "systemItems")? {
        system_items.push(SystemItem {
            service_id: string(s, "serviceId")?,
            folder_id: optional(s, "folderId", uuid_of)?,
            color: optional(s, "color", |v| Some(color_of(v)))?.flatten(),
            position: s.get("position")?.as_i64()?,
            missing_since: optional(s, "missingSince", date_of)?,
        });
    }
    let mut system_otp = HashMap::new();
    for (id, s) in root.get("systemOtp")?.as_object()? {
        system_otp.insert(id.clone(), OTPSetting::from_json(s).ok()?);
    }
    let ranking = ConnectionRanking::from_json(root.get("ranking")?).ok()?;
    let p = root.get("preferences")?;
    let flag = |key: &str| p.get(key).and_then(Value::as_bool);
    let preferences = BackupPreferences {
        auto_check: flag("autoCheck")?,
        delay_24h: flag("delay24h")?,
        launch_at_login: flag("launchAtLogin")?,
        control_api_enabled: flag("controlApiEnabled")?,
        auto_unlock: flag("autoUnlock")?,
    };
    Some(BackupPayload {
        version,
        created,
        app_version,
        connections,
        system_secrets,
        folders,
        credentials,
        credential_links,
        system_items,
        system_otp,
        ranking,
        preferences,
    })
}

// MARK: - validation

/// `Secrets::input_error`'s rule (no line break, no control character) and at most [`MAX_SECRET_BYTES`].
fn valid_secret(value: &str) -> bool {
    value.len() <= MAX_SECRET_BYTES && !mfa::has_control(value)
}

fn valid_secrets(secrets: &ItemSecrets) -> Result<(), InvalidBackup> {
    match secrets.iter().all(|(_, value)| valid_secret(value)) {
        true => Ok(()),
        false => Err(InvalidBackup::Secret),
    }
}

fn cap(n: usize, collection: Collection) -> Result<(), InvalidBackup> {
    match n <= MAX_ITEMS {
        true => Ok(()),
        false => Err(InvalidBackup::TooMany(collection)),
    }
}

fn valid_item(id: &str) -> Result<(), InvalidBackup> {
    check_item(id).map_err(|_| InvalidBackup::ItemId)
}

/// A name the validator accepts **and** in the form it stores (so a restored name is exactly what the
/// Credentials section or the folder editor would have saved).
fn stored_form<E>(name: &str, validator: impl FnOnce(&str) -> Result<String, E>) -> bool {
    validator(name).is_ok_and(|cleaned| cleaned == name)
}

/// The checks every payload passes before it is sealed ([`seal`]), after it is opened ([`open`]) and before a
/// restore writes anything ([`merge`], [`replace`]): the same rules the repositories apply to the user's input
/// (`validate_credential_name`, the credential username and password limits, `validate_folder_name`, the item-id
/// rule), the control-character rule for every secret, the folders forming a tree, no duplicate ids or credential
/// names, and [`MAX_ITEMS`] per collection.
pub fn validate(p: &BackupPayload) -> Result<(), InvalidBackup> {
    use InvalidBackup as I;
    cap(p.connections.len(), Collection::Connections)?;
    cap(p.folders.len(), Collection::Folders)?;
    cap(p.credentials.len(), Collection::Credentials)?;
    cap(p.credential_links.len(), Collection::CredentialLinks)?;
    cap(p.ranking.pinned().len(), Collection::Pins)?;
    cap(p.ranking.usage().len(), Collection::Usage)?;
    cap(p.system_items.len(), Collection::SystemItems)?;
    cap(p.system_secrets.len(), Collection::SystemSecrets)?;
    cap(p.system_otp.len(), Collection::SystemOtp)?;
    if p.app_version.len() > MAX_APP_VERSION_BYTES || mfa::has_control(&p.app_version) {
        return Err(I::AppVersion);
    }

    let mut connection_ids = HashSet::new();
    for c in &p.connections {
        if !connection_ids.insert(c.connection.id) {
            return Err(I::Duplicate);
        }
        valid_secrets(&c.secrets)?;
    }
    for (item, secrets) in &p.system_secrets {
        valid_item(item)?;
        valid_secrets(secrets)?;
    }

    let mut folder_ids = HashSet::new();
    for f in &p.folders {
        if !folder_ids.insert(f.id) {
            return Err(I::Duplicate);
        }
        if !stored_form(&f.name, validate_folder_name) {
            return Err(I::FolderName);
        }
    }
    FolderTree::new(p.folders.clone()).map_err(|_| I::FolderTree)?;

    let mut credential_ids = HashSet::new();
    let mut credential_names = HashSet::new();
    for c in &p.credentials {
        if !credential_ids.insert(c.id) || !credential_names.insert(c.name.as_str()) {
            return Err(I::Duplicate);
        }
        if !stored_form(&c.name, validate_credential_name) {
            return Err(I::CredentialName);
        }
        check_username(&c.username).map_err(|_| I::CredentialUsername)?;
        if let Some(password) = &c.password {
            check_password(password).map_err(|_| I::CredentialPassword)?;
        }
    }

    for (item, _) in &p.credential_links {
        valid_item(item)?;
    }
    for s in &p.system_items {
        valid_item(&s.service_id)?;
    }
    for id in p.system_otp.keys().chain(p.ranking.usage().keys()).chain(p.ranking.pinned()) {
        valid_item(id)?;
    }
    Ok(())
}

// MARK: - the restore planner

/// What a merge does with an item (connection, folder or credential) whose id already exists, or a credential
/// whose name exists under another id. One mode applies to every conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictMode {
    /// The backup's copy replaces the existing one.
    Overwrite,
    /// The existing one stays; the backup's copy is skipped.
    KeepExisting,
    /// The backup's copy is added under a new id with the suffix " (backup)" (" (backup 2)", … while taken).
    KeepBoth,
}

/// The numbers the restore window shows before the choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePlan {
    /// Connections, folders and credentials of the backup that do not conflict.
    pub added: usize,
    /// Connections, folders and credentials that conflict (see [`ConflictMode`]).
    pub conflicts: usize,
    /// The vault's connections, folders and credentials whose id is not in the backup: what "Replace everything"
    /// loses.
    pub lost_on_replace: usize,
    /// The names of the backup's connections with acknowledged risky OpenVPN directives, in the backup's order.
    /// "Replace everything" (and a fresh restore) keeps those acknowledgements, so the restore window lists these
    /// connections (Task 21); a merge drops them unless the same connection with the same config already exists.
    pub acknowledged_risky: Vec<String>,
}

/// The vault's current ids and names, as the planner sees them.
#[derive(Default)]
struct Existing {
    /// Connection id → name.
    connections: HashMap<String, String>,
    folders: HashMap<Uuid, String>,
    /// Credential id → name.
    credentials: HashMap<Uuid, String>,
    /// Credential name → id.
    credential_names: HashMap<String, Uuid>,
}

impl Existing {
    fn read(conn: &rusqlite::Connection) -> Result<Existing, VaultError> {
        let mut e = Existing::default();
        let mut stmt = conn.prepare("SELECT id, meta_json FROM connections")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (id, meta) = row?;
            let name = swift_json::parse(meta.as_bytes())
                .ok()
                .and_then(|v| v.get("name").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_default();
            e.connections.insert(id, name);
        }
        let mut stmt = conn.prepare("SELECT id, name FROM folders")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (id, name) = row?;
            e.folders.insert(parse_uuid(&id).ok_or_else(|| VaultError::Corrupt("invalid folder id".into()))?, name);
        }
        let mut stmt = conn.prepare("SELECT id, name FROM credentials")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (id, name) = row?;
            let id = parse_uuid(&id).ok_or_else(|| VaultError::Corrupt("invalid credential id".into()))?;
            e.credential_names.insert(name.clone(), id);
            e.credentials.insert(id, name);
        }
        Ok(e)
    }

    fn add_credential(&mut self, id: Uuid, name: &str) {
        self.credentials.insert(id, name.to_string());
        self.credential_names.insert(name.to_string(), id);
    }

    /// The existing credential a backup credential conflicts with: the same id first, else the same name.
    fn credential_conflict(&self, c: &BackupCredential) -> Option<Uuid> {
        if self.credentials.contains_key(&c.id) {
            return Some(c.id);
        }
        self.credential_names.get(&c.name).copied()
    }
}

/// Counts what a restore of `payload` would add, where it conflicts, and what "Replace everything" would lose.
pub fn plan_restore(vault: &Vault, payload: &BackupPayload) -> Result<RestorePlan, VaultError> {
    let existing = Existing::read(vault.connection())?;
    let mut added = 0;
    let mut conflicts = 0;
    let mut count = |conflict: bool| if conflict { conflicts += 1 } else { added += 1 };
    for c in &payload.connections {
        count(existing.connections.contains_key(&uuid_string(&c.connection.id)));
    }
    for f in &payload.folders {
        count(existing.folders.contains_key(&f.id));
    }
    for c in &payload.credentials {
        count(existing.credential_conflict(c).is_some());
    }
    let backup_connections: HashSet<String> =
        payload.connections.iter().map(|c| uuid_string(&c.connection.id)).collect();
    let backup_folders: HashSet<Uuid> = payload.folders.iter().map(|f| f.id).collect();
    let backup_credentials: HashSet<Uuid> = payload.credentials.iter().map(|c| c.id).collect();
    let lost_on_replace = existing.connections.keys().filter(|id| !backup_connections.contains(*id)).count()
        + existing.folders.keys().filter(|id| !backup_folders.contains(id)).count()
        + existing.credentials.keys().filter(|id| !backup_credentials.contains(id)).count();
    let acknowledged_risky = payload
        .connections
        .iter()
        .filter(|c| !c.connection.acknowledged_risky_directives.is_empty())
        .map(|c| c.connection.name.clone())
        .collect();
    Ok(RestorePlan { added, conflicts, lost_on_replace, acknowledged_risky })
}

/// Adds the backup to the vault in one transaction, resolving every conflict with `mode`. Items only in the vault
/// stay as they are; so do the paired clients. On any error nothing changes. The payload is [`validate`]d first.
///
/// Besides the three conflict kinds: a system VPN's placement, secrets with its link, OTP setting, and a usage
/// entry, are added when the vault has none for that item and replaced only with [`ConflictMode::Overwrite`] (a
/// system VPN's secrets and link are replaced together; without Overwrite, a link is not added to an item that
/// has its own username or password). The backup's pins are appended after the existing ones.
///
/// A restored connection's acknowledged risky directives are dropped (the editor asks again) unless the same
/// connection already exists with the same config: whoever crafted the file must not be able to pre-approve
/// `up` scripts on this Mac.
///
/// Every link is written through [`super::db::Tx::link`], and at the end no linked item keeps its own username or
/// password (spec 3a).
pub fn merge(vault: &mut Vault, payload: &BackupPayload, mode: ConflictMode) -> Result<(), VaultError> {
    let current = vault.ranking()?;
    vault.transaction(|tx| restore_into(tx, payload, mode, &current, false))
}

/// Clears every table but `control_clients` and `meta` (the paired clients belong to this Mac) and writes the
/// backup, in one transaction: ids, positions, the acknowledged risky directives (listed by
/// [`RestorePlan::acknowledged_risky`]) and the ranking exactly as backed up. On any error nothing changes.
pub fn replace(vault: &mut Vault, payload: &BackupPayload) -> Result<(), VaultError> {
    vault.transaction(|tx| {
        validate(payload).map_err(VaultError::InvalidBackup)?;
        tx.execute_batch(
            "DELETE FROM credential_links;
             DELETE FROM secrets;
             DELETE FROM connections;
             DELETE FROM credentials;
             DELETE FROM system_items;
             DELETE FROM system_otp;
             DELETE FROM ranking;
             DELETE FROM pins;
             DELETE FROM folders;",
        )?;
        restore_into(tx, payload, ConflictMode::Overwrite, &ConnectionRanking::default(), true)
    })
}

/// Hands out the " (backup)" names of one kind: `taken` holds every name in use, `next` the next suffix number
/// to try per base name, so repeated copies of one name do not probe from 1 again.
struct Names {
    taken: HashSet<String>,
    next: HashMap<String, usize>,
    /// The longest name, in characters.
    max: Option<usize>,
}

impl Names {
    fn new(taken: impl IntoIterator<Item = String>, max: Option<usize>) -> Names {
        Names { taken: taken.into_iter().collect(), next: HashMap::new(), max }
    }

    fn insert(&mut self, name: &str) {
        self.taken.insert(name.to_string());
    }

    /// `"<base> (backup)"`, then `"<base> (backup 2)"`, … the first one not taken (and now taken). With `max`,
    /// the base is shortened so the whole name fits.
    fn unique(&mut self, base: &str) -> String {
        let mut n = self.next.get(base).copied().unwrap_or(1);
        loop {
            let name = suffixed(base, n, self.max);
            n += 1;
            if !self.taken.contains(&name) {
                self.next.insert(base.to_string(), n);
                self.taken.insert(name.clone());
                return name;
            }
        }
    }
}

fn suffixed(base: &str, n: usize, max: Option<usize>) -> String {
    let suffix = if n == 1 { format!(" ({BACKUP_SUFFIX})") } else { format!(" ({BACKUP_SUFFIX} {n})") };
    let base = match max {
        Some(max) => {
            let keep = max.saturating_sub(suffix.graphemes(true).count());
            base.graphemes(true).take(keep).collect::<String>().trim_end().to_string()
        }
        None => base.to_string(),
    };
    format!("{base}{suffix}")
}

/// The stored config of a connection equals `config`, compared in wiped buffers.
fn same_config(conn: &rusqlite::Connection, key: &str, config: &str) -> Result<bool, VaultError> {
    let stored = conn
        .query_row("SELECT config FROM connections WHERE id = ?1", [key], |r| wiped_bytes_opt(r, 0))
        .optional()?
        .flatten();
    Ok(stored.is_some_and(|bytes| bytes.as_slice() == config.as_bytes()))
}

/// The items that have their own username or password.
fn items_with_own_login(conn: &rusqlite::Connection) -> Result<HashSet<String>, VaultError> {
    let mut stmt = conn.prepare("SELECT DISTINCT connection_id FROM secrets WHERE field IN (?1, ?2)")?;
    let rows = stmt
        .query_map((SecretField::Username.raw_value(), SecretField::Password.raw_value()), |r| r.get::<_, String>(0))?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// The shared body of [`merge`] and [`replace`]. `replace` (into an emptied vault): keep the backup's positions
/// instead of appending, and keep the acknowledged risky directives.
fn restore_into(
    tx: &super::db::Tx<'_>,
    payload: &BackupPayload,
    mode: ConflictMode,
    current: &ConnectionRanking,
    replace: bool,
) -> Result<(), VaultError> {
    validate(payload).map_err(VaultError::InvalidBackup)?;
    let exact = replace;
    let conn: &rusqlite::Connection = tx;
    let tree =
        FolderTree::new(payload.folders.clone()).map_err(|_| VaultError::InvalidBackup(InvalidBackup::FolderTree))?;
    let mut existing = Existing::read(conn)?;
    let own_login_before = items_with_own_login(conn)?;
    let overwrite = mode == ConflictMode::Overwrite;

    // Folders, parents first: backup id → id in the vault.
    let mut folder_map: HashMap<Uuid, Uuid> = HashMap::new();
    let mut folder_names = Names::new(existing.folders.values().cloned(), Some(MAX_FOLDER_NAME_CHARACTERS));
    let mut queue: Vec<Option<Uuid>> = vec![None];
    while let Some(parent) = queue.pop() {
        for &id in tree.children(parent) {
            queue.push(Some(id));
            let Some(f) = tree.get(id) else { continue };
            let parent = f.parent.and_then(|p| folder_map.get(&p).copied());
            let target = match (existing.folders.contains_key(&f.id), mode) {
                (false, _) => {
                    insert_folder(conn, f.id, parent, &f.name, f, exact)?;
                    f.id
                }
                (true, ConflictMode::Overwrite) => {
                    let (old_parent, position): (Option<String>, i64) = conn.query_row(
                        "SELECT parent_id, position FROM folders WHERE id = ?1",
                        [uuid_string(&f.id)],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )?;
                    let parent_key = parent.map(|p| uuid_string(&p));
                    let position =
                        if old_parent == parent_key { position } else { next_folder_position(conn, parent)? };
                    conn.execute(
                        "UPDATE folders SET parent_id = ?2, name = ?3, color = ?4, position = ?5, collapsed = ?6
                         WHERE id = ?1",
                        (
                            uuid_string(&f.id),
                            parent_key,
                            &f.name,
                            f.color.map(FolderColor::as_str),
                            position,
                            f.collapsed,
                        ),
                    )?;
                    f.id
                }
                (true, ConflictMode::KeepExisting) => f.id,
                (true, ConflictMode::KeepBoth) => {
                    let copy = Uuid::new_v4();
                    let name = folder_names.unique(&f.name);
                    insert_folder(conn, copy, parent, &name, f, false)?;
                    copy
                }
            };
            if let Some(name) = name_of_folder(conn, target)? {
                folder_names.insert(&name);
            }
            folder_map.insert(f.id, target);
        }
    }
    let place = |folder: Option<Uuid>| folder.and_then(|f| folder_map.get(&f).copied());

    // Credentials: backup id → id in the vault.
    let mut credential_map: HashMap<Uuid, Uuid> = HashMap::new();
    let mut credential_names =
        Names::new(existing.credential_names.keys().cloned(), Some(MAX_CREDENTIAL_NAME_CHARACTERS));
    for c in &payload.credentials {
        let target = match (existing.credential_conflict(c), mode) {
            (None, _) => {
                insert_credential(conn, c.id, &c.name, c)?;
                existing.add_credential(c.id, &c.name);
                credential_names.insert(&c.name);
                c.id
            }
            (Some(target), ConflictMode::Overwrite) => {
                // The backup's name, unless another credential has it (an id match whose name belongs to another).
                let name = match existing.credential_names.get(&c.name) {
                    Some(owner) if *owner != target => credential_names.unique(&c.name),
                    _ => c.name.clone(),
                };
                conn.execute(
                    "UPDATE credentials SET name = ?2, username = ?3, password = ?4, created = ?5, updated = ?6
                     WHERE id = ?1",
                    (
                        uuid_string(&target),
                        &name,
                        c.username.as_str(),
                        c.password.as_ref().map(|p| p.as_bytes()),
                        c.created.iso8601(),
                        c.updated.iso8601(),
                    ),
                )?;
                if let Some(old) = existing.credentials.get(&target).cloned() {
                    existing.credential_names.remove(&old);
                }
                existing.add_credential(target, &name);
                credential_names.insert(&name);
                target
            }
            (Some(target), ConflictMode::KeepExisting) => target,
            (Some(_), ConflictMode::KeepBoth) => {
                let id = if existing.credentials.contains_key(&c.id) { Uuid::new_v4() } else { c.id };
                let name = credential_names.unique(&c.name);
                insert_credential(conn, id, &name, c)?;
                existing.add_credential(id, &name);
                id
            }
        };
        credential_map.insert(c.id, target);
    }

    // Connections: backup id → the item written (`None`: kept the existing one).
    let mut connection_map: HashMap<String, Option<String>> = HashMap::new();
    let mut connection_names = Names::new(existing.connections.values().cloned(), None);
    for c in &payload.connections {
        let key = uuid_string(&c.connection.id);
        let folder = place(c.folder_id);
        let exists = existing.connections.contains_key(&key);
        // Acknowledgements survive a merge only onto the same connection with the same config.
        let mut restored = c.connection.clone();
        if !replace && !(exists && same_config(conn, &key, &c.config)?) {
            restored.acknowledged_risky_directives.clear();
        }
        let written = match (exists, mode) {
            (false, _) => {
                write_connection(conn, &restored, c, folder, exact)?;
                Some(key.clone())
            }
            (true, ConflictMode::Overwrite) => {
                conn.execute("DELETE FROM secrets WHERE connection_id = ?1", [&key])?;
                conn.execute("DELETE FROM credential_links WHERE item_id = ?1", [&key])?;
                write_connection(conn, &restored, c, folder, exact)?;
                Some(key.clone())
            }
            (true, ConflictMode::KeepExisting) => None,
            (true, ConflictMode::KeepBoth) => {
                let mut copy = restored;
                copy.id = Uuid::new_v4();
                copy.name = connection_names.unique(&c.connection.name);
                // The copy is not the installed service: it gets its own profile when it is reinstalled.
                if copy.native_service_name.is_some() {
                    copy.native_service_name = Some(copy.name.clone());
                }
                copy.native_service_id = None;
                write_connection(conn, &copy, c, folder, false)?;
                Some(uuid_string(&copy.id))
            }
        };
        if let Some(item) = &written {
            for (field, value) in &c.secrets {
                set_secret(conn, item, *field, value)?;
            }
        }
        connection_names.insert(&c.connection.name);
        connection_map.insert(key, written);
    }

    // The other items' secrets (system VPNs). With Overwrite the backup's secrets replace the item's together with
    // its link (the link pass below writes the backup's link, if it has one).
    for (item, secrets) in &payload.system_secrets {
        if connection_map.contains_key(item) {
            continue;
        }
        let has: Option<i64> = conn
            .query_row("SELECT 1 FROM secrets WHERE connection_id = ?1 LIMIT 1", [item], |r| r.get(0))
            .optional()?;
        if has.is_some() && !overwrite {
            continue;
        }
        conn.execute("DELETE FROM secrets WHERE connection_id = ?1", [item])?;
        if overwrite {
            conn.execute("DELETE FROM credential_links WHERE item_id = ?1", [item])?;
        }
        for (field, value) in secrets {
            set_secret(conn, item, *field, value)?;
        }
    }

    // Links, through `Tx::link` (which deletes the item's own username and password): a backed-up connection's
    // link goes with the copy written; another item's link is added if it has none (and, without Overwrite, no
    // own username or password either).
    for (item, credential) in &payload.credential_links {
        let Some(credential) = credential_map.get(credential) else { continue };
        let target = match connection_map.get(item) {
            Some(Some(written)) => written.clone(),
            Some(None) => continue,
            None => {
                let has: Option<i64> = conn
                    .query_row("SELECT 1 FROM credential_links WHERE item_id = ?1", [item], |r| r.get(0))
                    .optional()?;
                if !overwrite && (has.is_some() || own_login_before.contains(item)) {
                    continue;
                }
                item.clone()
            }
        };
        tx.link(&target, *credential)?;
    }
    // The invariant, whatever the payload held: a linked item has no own username or password.
    conn.execute(
        "DELETE FROM secrets WHERE field IN (?1, ?2) AND connection_id IN (SELECT item_id FROM credential_links)",
        (SecretField::Username.raw_value(), SecretField::Password.raw_value()),
    )?;

    // System-VPN placements.
    for s in &payload.system_items {
        let has: Option<i64> = conn
            .query_row("SELECT 1 FROM system_items WHERE service_id = ?1", [&s.service_id], |r| r.get(0))
            .optional()?;
        if has.is_some() && !overwrite {
            continue;
        }
        let folder = place(s.folder_id);
        let position = if exact { s.position } else { next_item_position(conn, "system_items", folder)? };
        conn.execute(
            "INSERT INTO system_items(service_id, folder_id, color, position, missing_since) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(service_id) DO UPDATE SET
                 folder_id = excluded.folder_id, color = excluded.color, position = excluded.position,
                 missing_since = excluded.missing_since",
            (
                &s.service_id,
                folder.map(|f| uuid_string(&f)),
                s.color.map(FolderColor::as_str),
                position,
                s.missing_since.map(Date::iso8601),
            ),
        )?;
    }

    // System OTP settings (only enabled ones are stored, as in `system-otp.json`).
    let mut otp = HashMap::new();
    {
        let mut stmt = conn.prepare("SELECT service_id, json FROM system_otp")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (id, json) = row?;
            if let Some(s) = swift_json::parse(json.as_bytes()).ok().and_then(|v| OTPSetting::from_json(&v).ok()) {
                otp.insert(id, s);
            }
        }
    }
    for (id, s) in &payload.system_otp {
        if overwrite || !otp.contains_key(id) {
            otp.insert(id.clone(), *s);
        }
    }
    tx.save_system_otp_map(&otp)?;

    // The ranking: usage added where missing (replaced with Overwrite), the backup's pins after the existing ones.
    let mut usage = current.usage().clone();
    for (id, stats) in payload.ranking.usage() {
        if overwrite || !usage.contains_key(id) {
            usage.insert(id.clone(), *stats);
        }
    }
    let mut pinned = current.pinned().to_vec();
    let mut seen: HashSet<String> = pinned.iter().cloned().collect();
    for id in payload.ranking.pinned() {
        if seen.insert(id.clone()) {
            pinned.push(id.clone());
        }
    }
    tx.save_ranking(&ConnectionRanking::new(pinned, usage))?;

    // The result must still be a tree; a cycle is reported as such (`TreeError::Cycle`), not as a damaged vault.
    let mut stmt = conn.prepare("SELECT id, parent_id, name, position FROM folders")?;
    let nodes = stmt
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, String>(2)?, r.get(3)?))
        })?
        .map(|row| {
            let (id, parent, name, position) = row?;
            let bad = || VaultError::Corrupt("invalid folder id".into());
            Ok(FolderNode {
                id: parse_uuid(&id).ok_or_else(bad)?,
                parent: parent.map(|p| parse_uuid(&p).ok_or_else(bad)).transpose()?,
                name,
                color: None,
                position,
                collapsed: false,
            })
        })
        .collect::<Result<Vec<_>, VaultError>>()?;
    FolderTree::new(nodes).map_err(VaultError::Tree)?;
    Ok(())
}

fn name_of_folder(conn: &rusqlite::Connection, id: Uuid) -> Result<Option<String>, VaultError> {
    Ok(conn.query_row("SELECT name FROM folders WHERE id = ?1", [uuid_string(&id)], |r| r.get(0)).optional()?)
}

fn insert_folder(
    conn: &rusqlite::Connection,
    id: Uuid,
    parent: Option<Uuid>,
    name: &str,
    f: &FolderNode,
    exact: bool,
) -> Result<(), VaultError> {
    let position = if exact { f.position } else { next_folder_position(conn, parent)? };
    conn.execute(
        "INSERT INTO folders(id, parent_id, name, color, position, collapsed) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        (
            uuid_string(&id),
            parent.map(|p| uuid_string(&p)),
            name,
            f.color.map(FolderColor::as_str),
            position,
            f.collapsed,
        ),
    )?;
    Ok(())
}

fn insert_credential(
    conn: &rusqlite::Connection,
    id: Uuid,
    name: &str,
    c: &BackupCredential,
) -> Result<(), VaultError> {
    conn.execute(
        "INSERT INTO credentials(id, name, username, password, created, updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        (
            uuid_string(&id),
            name,
            c.username.as_str(),
            c.password.as_ref().map(|p| p.as_bytes()),
            c.created.iso8601(),
            c.updated.iso8601(),
        ),
    )?;
    Ok(())
}

/// Inserts or replaces a connection row with the backup's config and colour, in `folder`.
fn write_connection(
    conn: &rusqlite::Connection,
    connection: &Connection,
    c: &BackupConnection,
    folder: Option<Uuid>,
    exact: bool,
) -> Result<(), VaultError> {
    let meta = swift_json::to_pretty_sorted(&connection.to_json()).map_err(VaultError::Corrupt)?;
    let position = if exact { c.position } else { next_item_position(conn, "connections", folder)? };
    conn.execute(
        "INSERT INTO connections(id, kind, meta_json, config, folder_id, color, position)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(id) DO UPDATE SET
             kind = excluded.kind, meta_json = excluded.meta_json, config = excluded.config,
             folder_id = excluded.folder_id, color = excluded.color, position = excluded.position",
        (
            uuid_string(&connection.id),
            connection.kind.raw_value(),
            &meta,
            c.config.as_bytes(),
            folder.map(|f| uuid_string(&f)),
            c.color.map(FolderColor::as_str),
            position,
        ),
    )?;
    Ok(())
}

fn set_secret(conn: &rusqlite::Connection, item: &str, field: SecretField, value: &str) -> Result<(), VaultError> {
    if value.is_empty() {
        return Ok(());
    }
    conn.execute(
        "INSERT INTO secrets(connection_id, field, value) VALUES (?1, ?2, ?3)
         ON CONFLICT(connection_id, field) DO UPDATE SET value = excluded.value",
        (item, field.raw_value(), value.as_bytes()),
    )?;
    Ok(())
}

fn next_folder_position(conn: &rusqlite::Connection, parent: Option<Uuid>) -> Result<i64, VaultError> {
    Ok(conn.query_row(
        "SELECT COALESCE(MAX(position) + 1, 0) FROM folders WHERE parent_id IS ?1",
        [parent.map(|p| uuid_string(&p))],
        |r| r.get(0),
    )?)
}

/// The next append position in `folder` of `table` (`connections` or `system_items`, fixed names).
fn next_item_position(conn: &rusqlite::Connection, table: &str, folder: Option<Uuid>) -> Result<i64, VaultError> {
    let sql = format!("SELECT COALESCE(MAX(position) + 1, 0) FROM {table} WHERE folder_id IS ?1");
    Ok(conn.query_row(&sql, [folder.map(|f| uuid_string(&f))], |r| r.get(0))?)
}
