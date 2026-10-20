//! Schema v1 (spec 2.4) and the migration list.
//!
//! A migration is an ordered list of statements for one step `v → v+1`; the runner ([`super::db`]) backs the file
//! up, applies every step newer than the stored `meta.schema_version` in order (one savepoint each, one
//! transaction overall) and records `schema_version` and `min_app_schema` in the same transaction.
//! Add a migration by appending `Migration { version: N + 1, … }` and raising [`CURRENT_SCHEMA`]; never edit a
//! released one. A migration must never be needed to *read* an older database: an older build reads a newer
//! database read-only as long as every table and column it knows is still there, so prefer additive changes.
//!
//! Each step names the lowest app schema that may still write a database at that version
//! ([`Migration::min_app_schema`]); the runner stores the highest value of every step up to the target. An
//! additive step that older builds cannot break keeps the previous value.

/// The newest schema this build knows (the app's schema).
pub const CURRENT_SCHEMA: u32 = 2;

/// One schema step.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    pub version: u32,
    /// The lowest app schema that may write a database of this version (`meta.min_app_schema`).
    pub min_app_schema: u32,
    pub statements: &'static [&'static str],
}

/// v1: exactly the spec's tables, plus `system_items.missing_since` (the 30-day placement retention of spec 5).
const V1: &[&str] = &[
    "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)",
    "CREATE TABLE folders(
        id TEXT PRIMARY KEY,
        parent_id TEXT NULL REFERENCES folders(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        color TEXT NULL,
        position INTEGER NOT NULL,
        collapsed INTEGER NOT NULL DEFAULT 0
    )",
    "CREATE TABLE connections(
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        meta_json TEXT NOT NULL,
        config BLOB NOT NULL,
        folder_id TEXT NULL REFERENCES folders(id) ON DELETE SET NULL,
        color TEXT NULL,
        position INTEGER NOT NULL
    )",
    "CREATE TABLE secrets(connection_id TEXT, field TEXT, value BLOB, PRIMARY KEY(connection_id, field))",
    "CREATE TABLE credentials(
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL,
        password BLOB NULL,
        created TEXT NOT NULL,
        updated TEXT NOT NULL
    )",
    "CREATE TABLE credential_links(
        item_id TEXT PRIMARY KEY,
        credential_id TEXT NOT NULL REFERENCES credentials(id) ON DELETE RESTRICT
    )",
    "CREATE TABLE system_items(
        service_id TEXT PRIMARY KEY,
        folder_id TEXT NULL,
        color TEXT NULL,
        position INTEGER NOT NULL,
        missing_since TEXT NULL
    )",
    "CREATE TABLE system_otp(service_id TEXT PRIMARY KEY, json TEXT NOT NULL)",
    "CREATE TABLE ranking(id TEXT PRIMARY KEY, json TEXT NOT NULL)",
    "CREATE TABLE pins(id TEXT PRIMARY KEY, position INTEGER NOT NULL)",
    "CREATE TABLE control_clients(id TEXT PRIMARY KEY, json TEXT NOT NULL)",
];

/// v2 (1.3, team catalogs): additive only, `min_app_schema` 1. A 1.2 build opens any newer `schema_version`
/// read-only (whatever `min_app_schema` says), so it reads a v2 vault and never writes it.
const V2: &[&str] = &[
    "CREATE TABLE catalog_subscriptions(
        catalog_id TEXT PRIMARY KEY,
        json TEXT NOT NULL,
        team_key BLOB NOT NULL,
        bearer BLOB NULL,
        publisher_key BLOB NULL,
        successor_key BLOB NULL
    )",
    "CREATE TABLE catalog_items(
        local_id TEXT PRIMARY KEY,
        catalog_id TEXT NOT NULL REFERENCES catalog_subscriptions(catalog_id) ON DELETE CASCADE,
        item_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('root','folder','connection')),
        color TEXT NULL,
        slot_id TEXT NULL,
        provided_secrets TEXT NOT NULL DEFAULT '',
        config_hash TEXT NULL,
        meta_hash TEXT NULL,
        pending_removal INTEGER NOT NULL DEFAULT 0,
        profile_outdated INTEGER NOT NULL DEFAULT 0,
        UNIQUE(catalog_id, item_id, kind)
    )",
    "CREATE TABLE catalog_slots(
        catalog_id TEXT NOT NULL REFERENCES catalog_subscriptions(catalog_id) ON DELETE CASCADE,
        slot_id TEXT NOT NULL,
        name TEXT NOT NULL,
        credential_id TEXT NULL REFERENCES credentials(id) ON DELETE SET NULL,
        PRIMARY KEY(catalog_id, slot_id)
    )",
    "CREATE TABLE catalog_admin_keys(
        key_id TEXT PRIMARY KEY,
        role TEXT NOT NULL CHECK(role IN ('primary','backup')),
        seed BLOB NOT NULL,
        created TEXT NOT NULL
    )",
    "CREATE TABLE catalog_publications(
        catalog_id TEXT PRIMARY KEY,
        json TEXT NOT NULL,
        team_key BLOB NOT NULL
    )",
];

/// Every migration of this build, in order.
pub const MIGRATIONS: &[Migration] = &[
    Migration { version: 1, min_app_schema: 1, statements: V1 },
    Migration { version: 2, min_app_schema: 1, statements: V2 },
];
