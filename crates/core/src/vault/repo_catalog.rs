//! The team catalog tables of schema v2 (plan Task 6): subscriptions, the catalog-owned items, the credential
//! slots, the admin signing keys and the publications, and the read-only guard of the generic write paths.
//!
//! - **Key material lives only in its BLOB column:** the team key, the bearer token and the admin key seed are never
//!   part of a JSON column, never in `Debug` output and never in an error. They are read back into `Zeroizing`
//!   buffers.
//! - **Read-only catalog items (spec 6):** the generic writes (`save_connection`, `delete_connection`, the folder
//!   edits, `set_item_folder`, the secret writes of a field the catalog provides) refuse catalog-owned rows with
//!   [`VaultError::CatalogManaged`]. The colour override, the collapse state, pins and ranking, the user's own
//!   secrets, the credential link and [`Vault::set_acknowledged_risky`] stay writable. Only the catalog executor
//!   (`catalog_apply.rs`) writes the rest, through its own statements.
//!
//! Every write runs in [`Vault::transaction`]. Nothing here logs.

use super::db::{Tx, Vault, VaultError};
use super::repo_connections::wiped_bytes_opt;
use super::repo_credentials::validate_credential_name;
use super::tree::validate_folder_name;
use crate::catalog::format::CatalogErrorKind;
use crate::catalog::ids::{CatalogItemKind, root_folder_id};
use crate::catalog::keys::{AdminKey, Fingerprint, PublisherKey, TeamKey};
use crate::catalog::planner::{LocalCatalog, LocalItem};
use crate::catalog::selection::{InlineSecret, PublishSelection};
use crate::catalog::source::{CatalogSource, HttpsUrl, parse_file_source};
use crate::collation;
use crate::date::Date;
use crate::models::{Connection, SecretField, parse_uuid, uuid_string};
use crate::swift_json;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use rusqlite::{Connection as Db, OptionalExtension};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The longest bearer token, in bytes.
pub const MAX_BEARER_BYTES: usize = 4096;

/// What the last refresh of a subscription found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionStatus {
    Ok,
    NotModified,
    Unavailable,
    Failed(CatalogErrorKind),
    RollbackRefused { offered: u64 },
    TeamKeyChanged,
}

/// The conditional-GET validators of an HTTPS source and the content hash of the last fetched file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SourceValidators {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub content_hash: Option<[u8; 32]>,
}

/// One subscription without its secrets (the team key and the bearer token are read with
/// [`Vault::subscription_secrets`]).
#[derive(Debug, Clone, PartialEq)]
pub struct SubscriptionRecord {
    pub catalog_id: Uuid,
    /// The catalog's name (also the root folder's name).
    pub name: String,
    pub source: CatalogSource,
    pub pinned: Fingerprint,
    pub applied_version: Option<u64>,
    /// Set by a backup restore: the next refresh applies the same version once (plan Task 8).
    pub reapply: bool,
    pub status: SubscriptionStatus,
    pub validators: SourceValidators,
    pub last_attempt: Option<Date>,
    pub last_success: Option<Date>,
    pub failures: u32,
    /// Read only: whether a bearer token is stored ([`Vault::set_subscription_bearer`] changes it).
    pub has_bearer: bool,
    pub publisher_key: Option<PublisherKey>,
    pub successor_key: Option<PublisherKey>,
    pub added: Date,
}

/// An admin signing key's role (spec 7): the primary signs, the backup is the announced successor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AdminKeyRole {
    Primary,
    Backup,
}

impl AdminKeyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            AdminKeyRole::Primary => "primary",
            AdminKeyRole::Backup => "backup",
        }
    }

    pub fn parse(s: &str) -> Option<AdminKeyRole> {
        [AdminKeyRole::Primary, AdminKeyRole::Backup].into_iter().find(|r| r.as_str() == s)
    }
}

/// An admin key as listed: never the seed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AdminKeyRecord {
    pub role: AdminKeyRole,
    pub public: PublisherKey,
    pub fingerprint: Fingerprint,
    pub created: Date,
    /// A backup key taken offline (exported to a `.macvpnadminkey` file and removed): only its public half is
    /// kept, so new versions still announce it; it must be imported again before it can be promoted.
    pub offline: bool,
}

/// The `meta` key of the backup admin key taken offline: `{"public": base64, "created": iso8601}`.
const OFFLINE_BACKUP_KEY: &str = "catalog.offlineBackupAdminKey";

/// Stores the public half of a backup admin key taken offline (the `meta` row); replaces an earlier one.
pub(crate) fn set_offline_backup(conn: &Db, public: &PublisherKey, created: Date) -> Result<(), VaultError> {
    let mut m = Map::new();
    m.insert("public".into(), Value::String(BASE64.encode(public.as_bytes())));
    m.insert("created".into(), Value::String(created.iso8601()));
    let json = serde_json::to_string(&Value::Object(m)).map_err(|_| invalid("cannot store the key"))?;
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (OFFLINE_BACKUP_KEY, &json),
    )?;
    Ok(())
}

/// Forgets the backup admin key taken offline.
pub(crate) fn delete_offline_backup(conn: &Db) -> Result<(), VaultError> {
    conn.execute("DELETE FROM meta WHERE key = ?1", [OFFLINE_BACKUP_KEY])?;
    Ok(())
}

pub(crate) fn offline_backup_in(conn: &Db) -> Result<Option<AdminKeyRecord>, VaultError> {
    let text: Option<String> =
        conn.query_row("SELECT value FROM meta WHERE key = ?1", [OFFLINE_BACKUP_KEY], |r| r.get(0)).optional()?;
    let Some(text) = text else { return Ok(None) };
    let damaged = || corrupt("the offline backup admin key is damaged");
    let v: Value = serde_json::from_str(&text).map_err(|_| damaged())?;
    let public = v
        .get("public")
        .and_then(Value::as_str)
        .and_then(|b| BASE64.decode(b).ok())
        .and_then(|b| PublisherKey::from_bytes(&b))
        .ok_or_else(damaged)?;
    let created = v.get("created").and_then(Value::as_str).and_then(Date::parse_iso8601).ok_or_else(damaged)?;
    Ok(Some(AdminKeyRecord {
        role: AdminKeyRole::Backup,
        public,
        fingerprint: public.fingerprint(),
        created,
        offline: true,
    }))
}

/// One catalog this Mac publishes, without its team key ([`Vault::publication_team_key`]).
#[derive(Debug, Clone, PartialEq)]
pub struct PublicationRecord {
    pub catalog_id: Uuid,
    pub name: String,
    pub version: u64,
    pub selection: PublishSelection,
    /// The id of each published team secret, stable across publishes.
    pub secret_ids: BTreeMap<(Uuid, SecretField), Uuid>,
    /// What each published item looked like at the last publish (the "changed since" badge).
    pub item_hashes: BTreeMap<Uuid, String>,
    pub last_path: Option<PathBuf>,
    pub last_published: Option<Date>,
    /// The successor key the last version announced (the publish preview warns before a version drops it).
    pub announced_successor: Option<PublisherKey>,
}

/// Which catalog owns a row, for the views and the guards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogOwnership {
    pub catalog_id: Uuid,
    pub catalog_name: String,
    pub kind: CatalogItemKind,
    pub slot_id: Option<Uuid>,
    pub provided_secrets: BTreeSet<SecretField>,
    pub pending_removal: bool,
    pub profile_outdated: bool,
    /// The config hash of the applied version (connections only): what a native profile is built from.
    pub config_hash: Option<String>,
}

fn invalid(what: &str) -> VaultError {
    VaultError::Constraint(what.to_string())
}

fn corrupt(what: &str) -> VaultError {
    VaultError::Corrupt(what.to_string())
}

/// RFC 6750 `b64token` (`[A-Za-z0-9._~+/-]+=*`), 1 to [`MAX_BEARER_BYTES`] bytes. Such a token needs no escaping in
/// curl's config line.
pub fn valid_bearer_token(token: &str) -> bool {
    if token.is_empty() || token.len() > MAX_BEARER_BYTES {
        return false;
    }
    let body = token.trim_end_matches('=');
    !body.is_empty() && body.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~+/-".contains(&b))
}

/// A subscription's or publication's catalog name in stored form (the credential-name rule; it is also the root
/// folder's name).
pub(crate) fn check_catalog_name(name: &str) -> Result<(), VaultError> {
    let stored = validate_credential_name(name).ok().filter(|n| n == name);
    let folder = validate_folder_name(name).ok().filter(|n| n == name);
    match (stored, folder) {
        (Some(_), Some(_)) => Ok(()),
        _ => Err(invalid("a catalog name must have 1 to 64 characters and no control characters")),
    }
}

// MARK: - JSON of the records

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn opt_str(v: Option<&str>) -> Value {
    v.map_or(Value::Null, |s| Value::String(s.to_string()))
}

fn opt_date(d: Option<Date>) -> Value {
    d.map_or(Value::Null, |d| Value::String(d.iso8601()))
}

pub(crate) fn source_value(source: &CatalogSource) -> Option<Value> {
    let mut m = Map::new();
    match source {
        CatalogSource::Https(url) => m.insert("https".into(), Value::String(url.as_str().to_string())),
        CatalogSource::File(path) => m.insert("file".into(), Value::String(path.to_str()?.to_string())),
    };
    Some(Value::Object(m))
}

pub(crate) fn source_of(v: &Value) -> Option<CatalogSource> {
    let m = v.as_object()?;
    if m.len() != 1 {
        return None;
    }
    if let Some(url) = m.get("https") {
        return HttpsUrl::parse(url.as_str()?).ok().map(CatalogSource::Https);
    }
    parse_file_source(m.get("file")?.as_str()?).ok().map(CatalogSource::File)
}

fn status_value(s: SubscriptionStatus) -> Value {
    let mut m = Map::new();
    let state = match s {
        SubscriptionStatus::Ok => "ok",
        SubscriptionStatus::NotModified => "not_modified",
        SubscriptionStatus::Unavailable => "unavailable",
        SubscriptionStatus::Failed(kind) => {
            m.insert("error".into(), Value::String(kind.as_str().into()));
            "failed"
        }
        SubscriptionStatus::RollbackRefused { offered } => {
            m.insert("offered".into(), Value::from(offered));
            "rollback_refused"
        }
        SubscriptionStatus::TeamKeyChanged => "team_key_changed",
    };
    m.insert("state".into(), Value::String(state.into()));
    Value::Object(m)
}

fn status_of(v: &Value) -> Option<SubscriptionStatus> {
    Some(match v.get("state")?.as_str()? {
        "ok" => SubscriptionStatus::Ok,
        "not_modified" => SubscriptionStatus::NotModified,
        "unavailable" => SubscriptionStatus::Unavailable,
        "failed" => SubscriptionStatus::Failed(CatalogErrorKind::parse(v.get("error")?.as_str()?)?),
        "rollback_refused" => SubscriptionStatus::RollbackRefused { offered: v.get("offered")?.as_u64()? },
        "team_key_changed" => SubscriptionStatus::TeamKeyChanged,
        _ => return None,
    })
}

fn record_json(r: &SubscriptionRecord) -> Result<String, VaultError> {
    serde_json::to_string(&record_value(r)?).map_err(|_| invalid("a catalog subscription cannot be stored"))
}

/// The JSON of a subscription record without its id, secrets and keys (`catalog_subscriptions.json`, and the
/// backup's `record`).
pub(crate) fn record_value(r: &SubscriptionRecord) -> Result<Value, VaultError> {
    let mut m = Map::new();
    m.insert("name".into(), Value::String(r.name.clone()));
    m.insert("source".into(), source_value(&r.source).ok_or_else(|| invalid("the file source is not UTF-8"))?);
    m.insert("pinned".into(), Value::String(r.pinned.to_text()));
    m.insert("appliedVersion".into(), r.applied_version.map_or(Value::Null, Value::from));
    m.insert("reapply".into(), Value::Bool(r.reapply));
    m.insert("status".into(), status_value(r.status));
    let mut v = Map::new();
    v.insert("etag".into(), opt_str(r.validators.etag.as_deref()));
    v.insert("lastModified".into(), opt_str(r.validators.last_modified.as_deref()));
    v.insert("contentHash".into(), r.validators.content_hash.map_or(Value::Null, |h| Value::String(hex(&h))));
    m.insert("validators".into(), Value::Object(v));
    m.insert("lastAttempt".into(), opt_date(r.last_attempt));
    m.insert("lastSuccess".into(), opt_date(r.last_success));
    m.insert("failures".into(), Value::from(r.failures));
    m.insert("added".into(), Value::String(r.added.iso8601()));
    Ok(Value::Object(m))
}

fn optional<T>(v: &Value, key: &str, f: impl FnOnce(&Value) -> Option<T>) -> Option<Option<T>> {
    match v.get(key) {
        None | Some(Value::Null) => Some(None),
        Some(x) => f(x).map(Some),
    }
}

fn date_of(v: &Value) -> Option<Date> {
    v.as_str().and_then(Date::parse_iso8601)
}

fn record_of(
    catalog_id: Uuid,
    json: &str,
    has_bearer: bool,
    publisher_key: Option<Vec<u8>>,
    successor_key: Option<Vec<u8>>,
) -> Option<SubscriptionRecord> {
    let v: Value = serde_json::from_str(json).ok()?;
    record_from_value(catalog_id, &v, has_bearer, publisher_key, successor_key)
}

/// [`record_value`] read back.
pub(crate) fn record_from_value(
    catalog_id: Uuid,
    v: &Value,
    has_bearer: bool,
    publisher_key: Option<Vec<u8>>,
    successor_key: Option<Vec<u8>>,
) -> Option<SubscriptionRecord> {
    let v = v.clone();
    let validators = v.get("validators")?;
    let key = |bytes: Option<Vec<u8>>| match bytes {
        None => Some(None),
        Some(b) => PublisherKey::from_bytes(&b).map(Some),
    };
    Some(SubscriptionRecord {
        catalog_id,
        name: v.get("name")?.as_str()?.to_string(),
        source: source_of(v.get("source")?)?,
        pinned: Fingerprint::parse(v.get("pinned")?.as_str()?).ok()?,
        applied_version: optional(&v, "appliedVersion", Value::as_u64)?,
        reapply: v.get("reapply")?.as_bool()?,
        status: status_of(v.get("status")?)?,
        validators: SourceValidators {
            etag: optional(validators, "etag", |x| x.as_str().map(str::to_string))?,
            last_modified: optional(validators, "lastModified", |x| x.as_str().map(str::to_string))?,
            content_hash: optional(validators, "contentHash", |x| x.as_str().and_then(unhex32))?,
        },
        last_attempt: optional(&v, "lastAttempt", date_of)?,
        last_success: optional(&v, "lastSuccess", date_of)?,
        failures: u32::try_from(v.get("failures")?.as_u64()?).ok()?,
        has_bearer,
        publisher_key: key(publisher_key)?,
        successor_key: key(successor_key)?,
        added: date_of(v.get("added")?)?,
    })
}

fn field_pair(conn: Uuid, field: SecretField) -> Value {
    Value::Array(vec![Value::String(uuid_string(&conn)), Value::String(field.raw_value().into())])
}

fn uuids(set: &BTreeSet<Uuid>) -> Value {
    Value::Array(set.iter().map(|id| Value::String(uuid_string(id))).collect())
}

pub(crate) fn publication_json(p: &PublicationRecord) -> Result<String, VaultError> {
    serde_json::to_string(&publication_value(p)?).map_err(|_| invalid("a publication cannot be stored"))
}

/// The JSON of a publication record without its id and team key.
pub(crate) fn publication_value(p: &PublicationRecord) -> Result<Value, VaultError> {
    let mut sel = Map::new();
    sel.insert("folders".into(), uuids(&p.selection.folders));
    sel.insert("connections".into(), uuids(&p.selection.connections));
    sel.insert("secrets".into(), Value::Array(p.selection.secrets.iter().map(|(c, f)| field_pair(*c, *f)).collect()));
    sel.insert("slots".into(), uuids(&p.selection.slots));
    sel.insert(
        "inlineSecrets".into(),
        Value::Array(
            p.selection
                .inline_secrets
                .iter()
                .map(|(c, s)| Value::Array(vec![Value::String(uuid_string(c)), Value::String(s.as_str().into())]))
                .collect(),
        ),
    );
    let mut m = Map::new();
    m.insert("name".into(), Value::String(p.name.clone()));
    m.insert("version".into(), Value::from(p.version));
    m.insert("selection".into(), Value::Object(sel));
    let secret_ids = p
        .secret_ids
        .iter()
        .map(|((c, f), id)| {
            let Value::Array(mut pair) = field_pair(*c, *f) else { unreachable!() };
            pair.push(Value::String(uuid_string(id)));
            Value::Array(pair)
        })
        .collect();
    m.insert("secretIds".into(), Value::Array(secret_ids));
    m.insert(
        "itemHashes".into(),
        Value::Object(p.item_hashes.iter().map(|(id, h)| (uuid_string(id), Value::String(h.clone()))).collect()),
    );
    let path = match &p.last_path {
        None => Value::Null,
        Some(path) => Value::String(path.to_str().ok_or_else(|| invalid("the path is not UTF-8"))?.to_string()),
    };
    m.insert("lastPath".into(), path);
    m.insert("lastPublished".into(), opt_date(p.last_published));
    if let Some(k) = &p.announced_successor {
        m.insert("announcedSuccessor".into(), Value::String(BASE64.encode(k.as_bytes())));
    }
    Ok(Value::Object(m))
}

fn uuid_set(v: &Value) -> Option<BTreeSet<Uuid>> {
    v.as_array()?.iter().map(|x| x.as_str().and_then(parse_uuid)).collect()
}

fn pair_of(v: &Value) -> Option<(Uuid, SecretField)> {
    let a = v.as_array()?;
    Some((parse_uuid(a.first()?.as_str()?)?, SecretField::from_raw_value(a.get(1)?.as_str()?)?))
}

fn inline_pair_of(v: &Value) -> Option<(Uuid, InlineSecret)> {
    let a = v.as_array()?;
    Some((parse_uuid(a.first()?.as_str()?)?, InlineSecret::parse(a.get(1)?.as_str()?)?))
}

pub(crate) fn publication_of(catalog_id: Uuid, json: &str) -> Option<PublicationRecord> {
    let v: Value = serde_json::from_str(json).ok()?;
    publication_from_value(catalog_id, &v)
}

/// [`publication_value`] read back.
pub(crate) fn publication_from_value(catalog_id: Uuid, v: &Value) -> Option<PublicationRecord> {
    let sel = v.get("selection")?;
    let selection = PublishSelection {
        folders: uuid_set(sel.get("folders")?)?,
        connections: uuid_set(sel.get("connections")?)?,
        secrets: sel.get("secrets")?.as_array()?.iter().map(pair_of).collect::<Option<_>>()?,
        slots: uuid_set(sel.get("slots")?)?,
        inline_secrets: match sel.get("inlineSecrets") {
            None => BTreeSet::new(),
            Some(v) => v.as_array()?.iter().map(inline_pair_of).collect::<Option<_>>()?,
        },
    };
    let mut secret_ids = BTreeMap::new();
    for entry in v.get("secretIds")?.as_array()? {
        let pair = pair_of(entry)?;
        let id = parse_uuid(entry.as_array()?.get(2)?.as_str()?)?;
        secret_ids.insert(pair, id);
    }
    let mut item_hashes = BTreeMap::new();
    for (id, hash) in v.get("itemHashes")?.as_object()? {
        item_hashes.insert(parse_uuid(id)?, hash.as_str()?.to_string());
    }
    Some(PublicationRecord {
        catalog_id,
        name: v.get("name")?.as_str()?.to_string(),
        version: v.get("version")?.as_u64()?,
        selection,
        secret_ids,
        item_hashes,
        last_path: optional(v, "lastPath", |x| x.as_str().map(PathBuf::from))?,
        last_published: optional(v, "lastPublished", date_of)?,
        announced_successor: optional(v, "announcedSuccessor", |x| {
            PublisherKey::from_bytes(&BASE64.decode(x.as_str()?).ok()?)
        })?,
    })
}

// MARK: - provided secrets, ownership and the guard

pub(crate) fn provided_of(text: &str) -> BTreeSet<SecretField> {
    text.split(',').filter_map(SecretField::from_raw_value).collect()
}

pub(crate) fn owner_of(conn: &Db, key: &str) -> Result<Option<CatalogOwnership>, VaultError> {
    let row = conn
        .query_row(
            "SELECT i.catalog_id, s.json, i.kind, i.slot_id, i.provided_secrets, i.pending_removal, i.profile_outdated,
                    i.config_hash
             FROM catalog_items i JOIN catalog_subscriptions s ON s.catalog_id = i.catalog_id
             WHERE i.local_id = ?1",
            [key],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, bool>(5)?,
                    r.get::<_, bool>(6)?,
                    r.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((catalog_id, json, kind, slot, provided, pending, outdated, config_hash)) = row else { return Ok(None) };
    let damaged = || corrupt("a catalog item is damaged");
    let name = serde_json::from_str::<Value>(&json)
        .ok()
        .and_then(|v| v.get("name").and_then(Value::as_str).map(str::to_string))
        .ok_or_else(damaged)?;
    Ok(Some(CatalogOwnership {
        catalog_id: parse_uuid(&catalog_id).ok_or_else(damaged)?,
        catalog_name: name,
        kind: CatalogItemKind::parse(&kind).ok_or_else(damaged)?,
        slot_id: slot.as_deref().map(|s| parse_uuid(s).ok_or_else(damaged)).transpose()?,
        provided_secrets: provided_of(&provided),
        pending_removal: pending,
        profile_outdated: outdated,
        config_hash,
    }))
}

/// Refuses a generic write to any catalog-owned row (`key`: a connection, folder or root id).
pub(crate) fn guard_owned(conn: &Db, key: &str) -> Result<(), VaultError> {
    let owned: Option<i64> =
        conn.query_row("SELECT 1 FROM catalog_items WHERE local_id = ?1", [key], |r| r.get(0)).optional()?;
    match owned {
        Some(_) => Err(VaultError::CatalogManaged),
        None => Ok(()),
    }
}

/// [`guard_owned`] for a folder id.
pub(crate) fn guard_folder(conn: &Db, folder: Uuid) -> Result<(), VaultError> {
    guard_owned(conn, &uuid_string(&folder))
}

/// Refuses a write of a secret field the catalog provides for this item.
pub(crate) fn guard_provided(conn: &Db, item: &str, field: SecretField) -> Result<(), VaultError> {
    let provided: Option<String> = conn
        .query_row("SELECT provided_secrets FROM catalog_items WHERE local_id = ?1", [item], |r| r.get(0))
        .optional()?;
    match provided {
        Some(text) if provided_of(&text).contains(&field) => Err(VaultError::CatalogManaged),
        _ => Ok(()),
    }
}

// MARK: - reads

fn read_subscriptions(conn: &Db, filter: &str, arg: Option<String>) -> Result<Vec<SubscriptionRecord>, VaultError> {
    let sql = format!(
        "SELECT catalog_id, json, bearer IS NOT NULL, publisher_key, successor_key FROM catalog_subscriptions {filter}"
    );
    let mut stmt = conn.prepare(&sql)?;
    let map = |r: &rusqlite::Row<'_>| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, bool>(2)?,
            r.get::<_, Option<Vec<u8>>>(3)?,
            r.get::<_, Option<Vec<u8>>>(4)?,
        ))
    };
    let rows = match arg {
        Some(arg) => stmt.query_map([arg], map)?.collect::<Result<Vec<_>, _>>()?,
        None => stmt.query_map([], map)?.collect::<Result<Vec<_>, _>>()?,
    };
    rows.into_iter()
        .map(|(id, json, has_bearer, publisher, successor)| {
            let id = parse_uuid(&id).ok_or_else(|| corrupt("a catalog subscription is damaged"))?;
            record_of(id, &json, has_bearer, publisher, successor)
                .ok_or_else(|| corrupt("a catalog subscription is damaged"))
        })
        .collect()
}

/// One subscription read inside a transaction.
pub(crate) fn subscription_in(conn: &Db, id: Uuid) -> Result<Option<SubscriptionRecord>, VaultError> {
    Ok(read_subscriptions(conn, "WHERE catalog_id = ?1", Some(uuid_string(&id)))?.into_iter().next())
}

/// One publication read inside a transaction.
pub(crate) fn publication_in(conn: &Db, id: Uuid) -> Result<Option<PublicationRecord>, VaultError> {
    let json: Option<String> = conn
        .query_row("SELECT json FROM catalog_publications WHERE catalog_id = ?1", [uuid_string(&id)], |r| r.get(0))
        .optional()?;
    json.map(|j| publication_of(id, &j).ok_or_else(|| corrupt("a publication is damaged"))).transpose()
}

fn subscription_exists(conn: &Db, id: Uuid) -> Result<bool, VaultError> {
    Ok(conn
        .query_row("SELECT 1 FROM catalog_subscriptions WHERE catalog_id = ?1", [uuid_string(&id)], |_| Ok(()))
        .optional()?
        .is_some())
}

fn team_key_of(bytes: Option<Zeroizing<Vec<u8>>>) -> Result<TeamKey, VaultError> {
    bytes.as_deref().and_then(|b| TeamKey::from_bytes(b)).ok_or_else(|| corrupt("a stored team key is damaged"))
}

fn wiped_text(bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, VaultError> {
    match std::str::from_utf8(&bytes) {
        Ok(s) => Ok(Zeroizing::new(s.to_owned())),
        Err(_) => Err(corrupt("a stored bearer token is damaged")),
    }
}

fn read_admin_keys(conn: &Db) -> Result<Vec<(AdminKeyRole, AdminKey, Date)>, VaultError> {
    let mut stmt = conn.prepare("SELECT role, seed, created FROM catalog_admin_keys")?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, wiped_bytes_opt(r, 1)?, r.get::<_, String>(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    let damaged = || corrupt("a stored admin key is damaged");
    let mut out = Vec::new();
    for (role, seed, created) in rows {
        let role = AdminKeyRole::parse(&role).ok_or_else(damaged)?;
        let key = seed.as_deref().and_then(|s| AdminKey::from_seed(s)).ok_or_else(damaged)?;
        out.push((role, key, Date::parse_iso8601(&created).ok_or_else(damaged)?));
    }
    out.sort_by_key(|(role, _, _)| *role);
    Ok(out)
}

fn read_local_catalog(conn: &Db, id: Uuid, name: String) -> Result<LocalCatalog, VaultError> {
    let damaged = || corrupt("a catalog item is damaged");
    let key = uuid_string(&id);
    let mut stmt = conn.prepare(
        "SELECT i.local_id, i.item_id, i.kind, i.config_hash, i.meta_hash, i.pending_removal, i.slot_id,
                i.provided_secrets, f.parent_id
         FROM catalog_items i LEFT JOIN folders f ON f.id = i.local_id
         WHERE i.catalog_id = ?1 AND i.kind <> 'root' ORDER BY i.local_id",
    )?;
    let rows = stmt
        .query_map([&key], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, Option<String>>(4)?,
                r.get::<_, bool>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, Option<String>>(8)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut items = Vec::new();
    for (local, item, kind, config_hash, meta_hash, pending, slot, provided, parent) in rows {
        let kind = CatalogItemKind::parse(&kind).ok_or_else(damaged)?;
        items.push(LocalItem {
            local_id: parse_uuid(&local).ok_or_else(damaged)?,
            item_id: parse_uuid(&item).ok_or_else(damaged)?,
            kind,
            config_hash,
            meta_hash: meta_hash.unwrap_or_default(),
            pending_removal: pending,
            slot_id: slot.as_deref().map(|s| parse_uuid(s).ok_or_else(damaged)).transpose()?,
            provided: provided_of(&provided),
            parent: match kind {
                CatalogItemKind::Folder => parent.as_deref().and_then(parse_uuid),
                _ => None,
            },
        });
    }
    let mut slots = BTreeMap::new();
    let mut stmt = conn.prepare("SELECT slot_id, name, credential_id FROM catalog_slots WHERE catalog_id = ?1")?;
    for row in stmt
        .query_map([&key], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Option<String>>(2)?)))?
    {
        let (slot, slot_name, credential) = row?;
        let credential = credential.as_deref().map(|c| parse_uuid(c).ok_or_else(damaged)).transpose()?;
        slots.insert(parse_uuid(&slot).ok_or_else(damaged)?, (slot_name, credential));
    }
    Ok(LocalCatalog { catalog_id: id, name, root_folder: root_folder_id(id), items, slots })
}

impl Vault {
    /// Every subscription, sorted by name.
    pub fn subscriptions(&self) -> Result<Vec<SubscriptionRecord>, VaultError> {
        let mut out = read_subscriptions(self.connection(), "ORDER BY rowid", None)?;
        out.sort_by(|a, b| collation::localized_case_insensitive_compare(&a.name, &b.name));
        Ok(out)
    }

    /// One subscription.
    pub fn subscription(&self, id: Uuid) -> Result<Option<SubscriptionRecord>, VaultError> {
        Ok(read_subscriptions(self.connection(), "WHERE catalog_id = ?1", Some(uuid_string(&id)))?.into_iter().next())
    }

    /// The team key and the bearer token of a subscription (both wiped on drop). An unknown subscription is
    /// [`VaultError::Constraint`].
    pub fn subscription_secrets(&self, id: Uuid) -> Result<(TeamKey, Option<Zeroizing<String>>), VaultError> {
        let row = self
            .connection()
            .query_row(
                "SELECT team_key, bearer FROM catalog_subscriptions WHERE catalog_id = ?1",
                [uuid_string(&id)],
                |r| Ok((wiped_bytes_opt(r, 0)?, wiped_bytes_opt(r, 1)?)),
            )
            .optional()?;
        let Some((team_key, bearer)) = row else { return Err(invalid("no such catalog subscription")) };
        Ok((team_key_of(team_key)?, bearer.map(wiped_text).transpose()?))
    }

    /// Stores a new subscription with its secrets and creates its root folder (named after the catalog, at the end
    /// of the vault root), in one transaction. Subscribing twice to one catalog is [`VaultError::Constraint`].
    pub fn add_subscription(
        &mut self,
        record: &SubscriptionRecord,
        team_key: &TeamKey,
        bearer: Option<&str>,
    ) -> Result<(), VaultError> {
        self.transaction(|tx| tx.add_subscription(record, team_key, bearer))
    }

    /// Changes a subscription's record (name, source, trust, version, status, validators, times). `has_bearer`
    /// is ignored (see [`Vault::set_subscription_bearer`]).
    pub fn update_subscription_state(
        &mut self,
        id: Uuid,
        f: impl FnOnce(&mut SubscriptionRecord),
    ) -> Result<(), VaultError> {
        self.transaction(|tx| {
            let mut record = read_subscriptions(tx, "WHERE catalog_id = ?1", Some(uuid_string(&id)))?
                .into_iter()
                .next()
                .ok_or_else(|| invalid("no such catalog subscription"))?;
            f(&mut record);
            record.catalog_id = id;
            tx.save_subscription_record(&record)
        })
    }

    /// Replaces a subscription's team key (after a rotation by the publisher).
    pub fn set_subscription_team_key(&mut self, id: Uuid, key: &TeamKey) -> Result<(), VaultError> {
        self.transaction(|tx| {
            let n = tx.execute(
                "UPDATE catalog_subscriptions SET team_key = ?2 WHERE catalog_id = ?1",
                (uuid_string(&id), &key.as_bytes()[..]),
            )?;
            if n == 0 { Err(invalid("no such catalog subscription")) } else { Ok(()) }
        })
    }

    /// Stores or (`None`) removes a subscription's bearer token. A token that is not an RFC 6750 `b64token` of
    /// 1 to 4096 bytes is [`VaultError::Constraint`].
    pub fn set_subscription_bearer(&mut self, id: Uuid, bearer: Option<&str>) -> Result<(), VaultError> {
        if bearer.is_some_and(|b| !valid_bearer_token(b)) {
            return Err(invalid("the access token has characters a bearer token cannot have"));
        }
        self.transaction(|tx| {
            let n = tx.execute(
                "UPDATE catalog_subscriptions SET bearer = ?2 WHERE catalog_id = ?1",
                (uuid_string(&id), bearer.map(str::as_bytes)),
            )?;
            if n == 0 { Err(invalid("no such catalog subscription")) } else { Ok(()) }
        })
    }

    /// What the vault holds for one subscription: the planner's input.
    pub fn local_catalog(&self, id: Uuid) -> Result<LocalCatalog, VaultError> {
        let record = self.subscription(id)?.ok_or_else(|| invalid("no such catalog subscription"))?;
        read_local_catalog(self.connection(), id, record.name)
    }

    /// Which catalog owns a connection, folder or root folder (its id string); `None` for the user's own rows.
    pub fn catalog_owner(&self, local_id: &str) -> Result<Option<CatalogOwnership>, VaultError> {
        owner_of(self.connection(), local_id)
    }

    /// The publisher's colour of a catalog connection (`catalog_items.color`); the effective colour is the local
    /// override (`connections.color`), else this, else the folder's.
    pub fn catalog_color(&self, local_id: &str) -> Result<Option<crate::vault::FolderColor>, VaultError> {
        let color: Option<Option<String>> = self
            .connection()
            .query_row("SELECT color FROM catalog_items WHERE local_id = ?1", [local_id], |r| r.get(0))
            .optional()?;
        Ok(color.flatten().as_deref().and_then(crate::vault::FolderColor::parse))
    }

    /// The subscriber's own acknowledgement of a connection's risky directives (also of a catalog connection,
    /// whose other metadata is read-only): changes only `acknowledged_risky_directives` in `meta_json`.
    ///
    /// `seen_config` is the config the user reviewed. It is compared with the stored config inside the transaction:
    /// when a team catalog changed the connection meanwhile, the acknowledgement is refused with
    /// [`VaultError::CatalogChanged`] (a stale editor never acknowledges directives the user has not seen).
    pub fn set_acknowledged_risky(
        &mut self,
        id: Uuid,
        seen_config: &str,
        directives: &[String],
    ) -> Result<(), VaultError> {
        self.transaction(|tx| {
            let key = uuid_string(&id);
            let row: Option<(String, Zeroizing<Vec<u8>>)> = tx
                .query_row("SELECT meta_json, config FROM connections WHERE id = ?1", [&key], |r| {
                    Ok((r.get(0)?, super::repo_connections::wiped_bytes(r, 1)?))
                })
                .optional()?;
            let (meta, config) = row.ok_or_else(|| invalid("no such connection"))?;
            if config.as_slice() != seen_config.as_bytes() {
                return Err(VaultError::CatalogChanged);
            }
            let value = swift_json::parse(meta.as_bytes()).map_err(|_| corrupt("a connection is damaged"))?;
            let mut connection = Connection::from_json(&value).map_err(|_| corrupt("a connection is damaged"))?;
            let mut sorted = directives.to_vec();
            sorted.sort();
            sorted.dedup();
            connection.acknowledged_risky_directives = sorted;
            let meta = swift_json::to_pretty_sorted(&connection.to_json()).map_err(VaultError::Corrupt)?;
            tx.execute("UPDATE connections SET meta_json = ?2 WHERE id = ?1", (&key, &meta))?;
            Ok(())
        })
    }

    /// The native service a native connection is bound to (`None`: unbound): changes only `native_service_id` in
    /// `meta_json`. Also for a catalog connection, whose other metadata is read-only: the binding is this Mac's (the
    /// catalog executor keeps it across an apply), and without it the connection would claim every system VPN
    /// with its name.
    pub fn set_native_service_id(&mut self, id: Uuid, service_id: Option<&str>) -> Result<(), VaultError> {
        if service_id.is_some_and(|s| s.is_empty() || s.len() > 256 || s.chars().any(char::is_control)) {
            return Err(invalid("not a service id"));
        }
        self.transaction(|tx| {
            let key = uuid_string(&id);
            let meta: String = tx
                .query_row("SELECT meta_json FROM connections WHERE id = ?1", [&key], |r| r.get(0))
                .optional()?
                .ok_or_else(|| invalid("no such connection"))?;
            let value = swift_json::parse(meta.as_bytes()).map_err(|_| corrupt("a connection is damaged"))?;
            let mut connection = Connection::from_json(&value).map_err(|_| corrupt("a connection is damaged"))?;
            if !connection.kind.is_native() {
                return Err(invalid("not a native connection"));
            }
            connection.native_service_id = service_id.map(str::to_string);
            let meta = swift_json::to_pretty_sorted(&connection.to_json()).map_err(VaultError::Corrupt)?;
            tx.execute("UPDATE connections SET meta_json = ?2 WHERE id = ?1", (&key, &meta))?;
            Ok(())
        })
    }

    /// The admin keys, primary first: roles, public keys and fingerprints, never the seeds.
    pub fn admin_keys(&self) -> Result<Vec<AdminKeyRecord>, VaultError> {
        Ok(read_admin_keys(self.connection())?
            .into_iter()
            .map(|(role, key, created)| {
                let public = key.public();
                AdminKeyRecord { role, public, fingerprint: public.fingerprint(), created, offline: false }
            })
            .chain(offline_backup_in(self.connection())?)
            .collect())
    }

    /// The backup key goes offline after its file was written (spec 7): its seed is deleted, its public half kept
    /// (announced in every new version, listed with `offline`), in one transaction. Only the stored backup key
    /// (by fingerprint) can be taken offline, else [`VaultError::Constraint`].
    pub fn take_backup_key_offline(&mut self, key_id: &Fingerprint) -> Result<(), VaultError> {
        self.transaction(|tx| {
            let backup = read_admin_keys(tx)?
                .into_iter()
                .find(|(role, key, _)| *role == AdminKeyRole::Backup && key.public().fingerprint() == *key_id);
            let Some((_, key, created)) = backup else { return Err(invalid("no such backup admin key")) };
            set_offline_backup(tx, &key.public(), created)?;
            tx.execute("DELETE FROM catalog_admin_keys WHERE key_id = ?1", [key_id.to_text()])?;
            Ok(())
        })
    }

    /// The signing key of a role.
    pub fn admin_key(&self, role: AdminKeyRole) -> Result<Option<AdminKey>, VaultError> {
        Ok(read_admin_keys(self.connection())?.into_iter().find(|(r, _, _)| *r == role).map(|(_, key, _)| key))
    }

    /// Stores an admin key under a role. A role held by another key, or the same key under the other role, is
    /// [`VaultError::Constraint`] (an admin key is never replaced silently: losing it means re-subscribing
    /// everyone); storing the same key again is a no-op.
    pub fn save_admin_key(&mut self, key: &AdminKey, role: AdminKeyRole, created: Date) -> Result<(), VaultError> {
        self.transaction(|tx| tx.save_admin_key(key, role, created))
    }

    /// Deletes an admin key (by fingerprint); an unknown one is not an error.
    pub fn delete_admin_key(&mut self, key_id: &Fingerprint) -> Result<(), VaultError> {
        self.transaction(|tx| {
            tx.execute("DELETE FROM catalog_admin_keys WHERE key_id = ?1", [key_id.to_text()])?;
            if offline_backup_in(tx)?.is_some_and(|k| k.fingerprint == *key_id) {
                tx.execute("DELETE FROM meta WHERE key = ?1", [OFFLINE_BACKUP_KEY])?;
            }
            Ok(())
        })
    }

    /// "Switch to the backup key": the backup key becomes the primary and the old primary is deleted, in one
    /// transaction. Without a backup key: [`VaultError::Constraint`].
    pub fn promote_backup_key(&mut self) -> Result<(), VaultError> {
        self.transaction(|tx| {
            let backup: Option<i64> =
                tx.query_row("SELECT 1 FROM catalog_admin_keys WHERE role = 'backup'", [], |r| r.get(0)).optional()?;
            if backup.is_none() {
                return Err(invalid("there is no backup admin key"));
            }
            tx.execute("DELETE FROM catalog_admin_keys WHERE role = 'primary'", ())?;
            tx.execute("UPDATE catalog_admin_keys SET role = 'primary' WHERE role = 'backup'", ())?;
            Ok(())
        })
    }

    /// Every publication, sorted by name.
    pub fn publications(&self) -> Result<Vec<PublicationRecord>, VaultError> {
        let mut stmt = self.connection().prepare("SELECT catalog_id, json FROM catalog_publications ORDER BY rowid")?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut out = rows
            .into_iter()
            .map(|(id, json)| {
                parse_uuid(&id)
                    .and_then(|id| publication_of(id, &json))
                    .ok_or_else(|| corrupt("a publication is damaged"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        out.sort_by(|a, b| collation::localized_case_insensitive_compare(&a.name, &b.name));
        Ok(out)
    }

    /// A publication's team key (wiped on drop).
    pub fn publication_team_key(&self, id: Uuid) -> Result<TeamKey, VaultError> {
        let bytes = self
            .connection()
            .query_row("SELECT team_key FROM catalog_publications WHERE catalog_id = ?1", [uuid_string(&id)], |r| {
                wiped_bytes_opt(r, 0)
            })
            .optional()?
            .ok_or_else(|| invalid("no such publication"))?;
        team_key_of(bytes)
    }

    /// Inserts or updates a publication. A new one needs its team key; `None` keeps the stored key.
    pub fn save_publication(&mut self, p: &PublicationRecord, team_key: Option<&TeamKey>) -> Result<(), VaultError> {
        self.transaction(|tx| tx.save_publication(p, team_key))
    }

    /// Forgets a publication (the published file stays where it is).
    pub fn delete_publication(&mut self, id: Uuid) -> Result<(), VaultError> {
        self.transaction(|tx| {
            tx.execute("DELETE FROM catalog_publications WHERE catalog_id = ?1", [uuid_string(&id)])?;
            Ok(())
        })
    }
}

impl Tx<'_> {
    /// [`Vault::add_subscription`] inside this transaction.
    pub fn add_subscription(
        &self,
        record: &SubscriptionRecord,
        team_key: &TeamKey,
        bearer: Option<&str>,
    ) -> Result<(), VaultError> {
        check_catalog_name(&record.name)?;
        if bearer.is_some_and(|b| !valid_bearer_token(b)) {
            return Err(invalid("the access token has characters a bearer token cannot have"));
        }
        if subscription_exists(self, record.catalog_id)? {
            return Err(invalid("already subscribed to this catalog"));
        }
        let key = uuid_string(&record.catalog_id);
        self.execute(
            "INSERT INTO catalog_subscriptions(catalog_id, json, team_key, bearer) VALUES (?1, '{}', ?2, ?3)",
            (&key, &team_key.as_bytes()[..], bearer.map(str::as_bytes)),
        )?;
        self.save_subscription_record(record)?;
        let root = uuid_string(&root_folder_id(record.catalog_id));
        let position: i64 =
            self.query_row("SELECT COALESCE(MAX(position) + 1, 0) FROM folders WHERE parent_id IS NULL", [], |r| {
                r.get(0)
            })?;
        self.execute(
            "INSERT INTO folders(id, parent_id, name, color, position, collapsed) VALUES (?1, NULL, ?2, NULL, ?3, 0)",
            (&root, &record.name, position),
        )?;
        self.execute(
            "INSERT INTO catalog_items(local_id, catalog_id, item_id, kind) VALUES (?1, ?2, ?2, 'root')",
            (&root, &key),
        )?;
        Ok(())
    }

    /// Writes a subscription's record (its JSON and the two public-key columns) of an existing subscription.
    pub fn save_subscription_record(&self, record: &SubscriptionRecord) -> Result<(), VaultError> {
        check_catalog_name(&record.name)?;
        let json = record_json(record)?;
        let n = self.execute(
            "UPDATE catalog_subscriptions SET json = ?2, publisher_key = ?3, successor_key = ?4 WHERE catalog_id = ?1",
            (
                uuid_string(&record.catalog_id),
                &json,
                record.publisher_key.map(|k| k.as_bytes().to_vec()),
                record.successor_key.map(|k| k.as_bytes().to_vec()),
            ),
        )?;
        if n == 0 { Err(invalid("no such catalog subscription")) } else { Ok(()) }
    }

    /// [`Vault::save_admin_key`] inside this transaction.
    pub fn save_admin_key(&self, key: &AdminKey, role: AdminKeyRole, created: Date) -> Result<(), VaultError> {
        let key_id = key.public().fingerprint().to_text();
        let holders: Vec<(String, String)> = {
            let mut stmt = self.prepare("SELECT key_id, role FROM catalog_admin_keys")?;
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?
        };
        // A backup key taken offline holds its role; importing it again brings it back online.
        if let Some(offline) = offline_backup_in(self)? {
            match (offline.fingerprint == key.public().fingerprint(), role) {
                (true, AdminKeyRole::Backup) => {
                    self.execute("DELETE FROM meta WHERE key = ?1", [OFFLINE_BACKUP_KEY])?;
                }
                (true, AdminKeyRole::Primary) => {
                    return Err(invalid("this admin key is already stored under the other role"));
                }
                (false, AdminKeyRole::Backup) => return Err(invalid("another admin key already has this role")),
                (false, AdminKeyRole::Primary) => {}
            }
        }
        for (id, r) in &holders {
            match (*id == key_id, r == role.as_str()) {
                (true, true) => return Ok(()),
                (true, false) => return Err(invalid("this admin key is already stored under the other role")),
                (false, true) => return Err(invalid("another admin key already has this role")),
                (false, false) => {}
            }
        }
        let seed = key.seed();
        self.execute(
            "INSERT INTO catalog_admin_keys(key_id, role, seed, created) VALUES (?1, ?2, ?3, ?4)",
            (&key_id, role.as_str(), &seed[..], created.iso8601()),
        )?;
        Ok(())
    }

    /// [`Vault::save_publication`] inside this transaction.
    pub fn save_publication(&self, p: &PublicationRecord, team_key: Option<&TeamKey>) -> Result<(), VaultError> {
        check_catalog_name(&p.name)?;
        let json = publication_json(p)?;
        let key = uuid_string(&p.catalog_id);
        match team_key {
            Some(team_key) => {
                self.execute(
                    "INSERT INTO catalog_publications(catalog_id, json, team_key) VALUES (?1, ?2, ?3)
                     ON CONFLICT(catalog_id) DO UPDATE SET json = excluded.json, team_key = excluded.team_key",
                    (&key, &json, &team_key.as_bytes()[..]),
                )?;
            }
            None => {
                let n =
                    self.execute("UPDATE catalog_publications SET json = ?2 WHERE catalog_id = ?1", (&key, &json))?;
                if n == 0 {
                    return Err(invalid("a new publication needs its team key"));
                }
            }
        }
        Ok(())
    }
}
