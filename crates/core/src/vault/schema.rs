//! Schema v1 (spec 2.4) and the migration list.
//!
//! A migration is an ordered list of statements for one step `v → v+1`; the runner ([`super::db`]) backs the file
//! up, applies every step newer than the stored `meta.schema_version` in order (one savepoint each, one
//! transaction overall) and records `schema_version` and `min_app_schema` in the same transaction.
//! Add a migration by appending `Migration { version: N + 1, … }` and raising [`CURRENT_SCHEMA`]; never edit a
//! released one. A migration must never be needed to *read* an older database: an older build reads a newer
//! database read-only as long as every table and column it knows is still there, so prefer additive changes.

/// The newest schema this build knows (the app's schema).
pub const CURRENT_SCHEMA: u32 = 1;

/// One schema step.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    pub version: u32,
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

/// Every migration of this build, in order.
pub const MIGRATIONS: &[Migration] = &[Migration { version: 1, statements: V1 }];
