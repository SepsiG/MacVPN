//! The `connections` and `secrets` tables (spec 2.4).
//!
//! - `connections.meta_json` is exactly today's `meta.json` (`swift_json::to_pretty_sorted(&Connection::to_json())`),
//!   so it stays compatible with the Swift-era files and the export; `Connection::from_json` reads it back. The
//!   config is a BLOB of the UTF-8 text. A row's key is the upper-case UUID string (the Keychain account and
//!   ranking key today).
//! - `secrets` holds one BLOB per `(item, field)`, where the item is a managed connection's UUID string **or** a
//!   system VPN's service ID, like the Keychain account today. An empty value is never stored: it deletes.
//!
//! Every write runs in [`Vault::transaction`], so a database of a newer MacVPN refuses it with
//! [`VaultError::NewerSchema`]. Nothing here logs, and no error carries a config or a secret.

use super::color::FolderColor;
use super::db::{Tx, Vault, VaultError};
use super::repo_catalog::{guard_owned, guard_provided};
use crate::collation;
use crate::models::{Connection, SecretField, parse_uuid, uuid_string};
use crate::swift_json;
use rusqlite::OptionalExtension;
use rusqlite::types::{FromSqlError, ValueRef};
use std::io;
use uuid::Uuid;
use zeroize::Zeroizing;

/// A connection with its placement. `Debug` shows the metadata only (the config is not part of it).
#[derive(Debug, Clone, PartialEq)]
pub struct StoredConnection {
    pub connection: Connection,
    pub folder_id: Option<Uuid>,
    pub color: Option<FolderColor>,
    /// Append order inside the folder; not used for display (plan B, resolved points).
    pub position: i64,
}

/// A connection row as stored: the `meta_json` text and the raw config bytes (wiped on drop).
pub type ConnectionRecord = (String, Zeroizing<Vec<u8>>);

/// The bytes of a BLOB (or TEXT) column, copied straight into a buffer that is wiped on drop.
pub(super) fn wiped_bytes(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Zeroizing<Vec<u8>>> {
    match row.get_ref(index)? {
        ValueRef::Blob(b) | ValueRef::Text(b) => Ok(Zeroizing::new(b.to_vec())),
        other => Err(rusqlite::Error::FromSqlConversionFailure(
            index,
            other.data_type(),
            Box::new(FromSqlError::InvalidType),
        )),
    }
}

/// [`wiped_bytes`] of a nullable column: `NULL` is `None`.
pub(super) fn wiped_bytes_opt(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Option<Zeroizing<Vec<u8>>>> {
    match row.get_ref(index)? {
        ValueRef::Null => Ok(None),
        _ => wiped_bytes(row, index).map(Some),
    }
}

/// UTF-8 text from wiped bytes, into a wiped string. The error names only the column, never the contents.
fn wiped_text(bytes: &[u8], what: &str) -> Result<Zeroizing<String>, VaultError> {
    match std::str::from_utf8(bytes) {
        Ok(s) => Ok(Zeroizing::new(s.to_owned())),
        Err(_) => Err(VaultError::Corrupt(format!("{what} is not UTF-8"))),
    }
}

impl Vault {
    /// Every connection whose `meta_json` decodes, sorted by name (localized, case-insensitive; ties in insertion
    /// order), like `ConnectionStore::list`. A row this build cannot decode (an unknown kind of a newer version) is
    /// skipped, as an unreadable `meta.json` is today.
    pub fn connections(&self) -> Result<Vec<StoredConnection>, VaultError> {
        let mut stmt = self
            .connection()
            .prepare("SELECT meta_json, folder_id, color, position FROM connections ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?, r.get(3)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (meta, folder, color, position) = row?;
            let Ok(value) = swift_json::parse(meta.as_bytes()) else { continue };
            let Ok(connection) = Connection::from_json(&value) else { continue };
            out.push(StoredConnection {
                connection,
                folder_id: folder.as_deref().and_then(parse_uuid),
                color: color.as_deref().and_then(FolderColor::parse),
                position,
            });
        }
        out.sort_by(|a, b| collation::localized_case_insensitive_compare(&a.connection.name, &b.connection.name));
        Ok(out)
    }

    /// Inserts or updates a connection. `config == None` keeps the stored config (a new row gets an empty one).
    /// A new row goes into the root folder at `position = max + 1` there; an existing row keeps its folder, colour
    /// and position.
    pub fn save_connection(&mut self, c: &Connection, config: Option<&str>) -> Result<(), VaultError> {
        self.transaction(|tx| tx.save_connection(c, config))
    }

    /// The stored config of a connection; an unknown connection is a `NotFound` I/O error (as a missing config file
    /// is today).
    pub fn config(&self, id: &Uuid) -> Result<Zeroizing<String>, VaultError> {
        let bytes = self
            .connection()
            .query_row("SELECT config FROM connections WHERE id = ?1", [uuid_string(id)], |r| wiped_bytes(r, 0))
            .optional()?
            .ok_or_else(|| VaultError::Io(io::Error::new(io::ErrorKind::NotFound, "no such connection")))?;
        wiped_text(&bytes, "the config")
    }

    /// Deletes a connection with everything keyed by it: its secrets, its credential link, its ranking entry and
    /// its pin. A shared credential itself stays. Deleting an unknown connection is not an error.
    pub fn delete_connection(&mut self, id: &Uuid) -> Result<(), VaultError> {
        let key = uuid_string(id);
        self.transaction(|tx| {
            guard_owned(tx, &key)?;
            tx.execute("DELETE FROM secrets WHERE connection_id = ?1", [&key])?;
            tx.execute("DELETE FROM credential_links WHERE item_id = ?1", [&key])?;
            tx.execute("DELETE FROM ranking WHERE id = ?1", [&key])?;
            tx.execute("DELETE FROM pins WHERE id = ?1", [&key])?;
            tx.execute("DELETE FROM connections WHERE id = ?1", [&key])?;
            Ok(())
        })
    }

    /// One secret of a connection (UUID string) or a system VPN (service ID).
    pub fn secret(&self, item: &str, field: SecretField) -> Result<Option<Zeroizing<String>>, VaultError> {
        let bytes = self
            .connection()
            .query_row(
                "SELECT value FROM secrets WHERE connection_id = ?1 AND field = ?2",
                (item, field.raw_value()),
                |r| wiped_bytes(r, 0),
            )
            .optional()?;
        bytes.map(|b| wiped_text(&b, "a secret")).transpose()
    }

    /// Stores a secret as a BLOB; an empty value deletes it. A field a team catalog provides for the item is
    /// [`VaultError::CatalogManaged`].
    pub fn set_secret(&mut self, item: &str, field: SecretField, value: &str) -> Result<(), VaultError> {
        self.transaction(|tx| {
            guard_provided(tx, item, field)?;
            tx.set_secret(item, field, value)
        })
    }

    /// Every secret of one item. An item with secrets a team catalog provides is [`VaultError::CatalogManaged`].
    pub fn delete_secrets(&mut self, item: &str) -> Result<(), VaultError> {
        self.transaction(|tx| {
            for field in SecretField::ALL {
                guard_provided(tx, item, field)?;
            }
            tx.execute("DELETE FROM secrets WHERE connection_id = ?1", [item])?;
            Ok(())
        })
    }

    /// Every secret (uninstall with the user data; leftovers of deleted items too).
    pub fn delete_all_secrets(&mut self) -> Result<(), VaultError> {
        self.transaction(|tx| {
            tx.execute("DELETE FROM secrets", ())?;
            Ok(())
        })
    }

    /// The stored `meta_json` and the raw config bytes of one connection, exactly as written (the migration's
    /// verification pass compares them byte for byte). `Debug` of the result would show the config: do not log it.
    pub fn connection_record(&self, id: &Uuid) -> Result<Option<ConnectionRecord>, VaultError> {
        Ok(self
            .connection()
            .query_row("SELECT meta_json, config FROM connections WHERE id = ?1", [uuid_string(id)], |r| {
                Ok((r.get::<_, String>(0)?, wiped_bytes(r, 1)?))
            })
            .optional()?)
    }

    /// The number of connection rows (decodable or not).
    pub fn connection_count(&self) -> Result<usize, VaultError> {
        count_rows(self, "connections")
    }

    /// The number of stored secrets (all items).
    pub fn secret_count(&self) -> Result<usize, VaultError> {
        count_rows(self, "secrets")
    }

    /// Whether no user data is stored yet: no connection, secret, folder, credential, ranking, pin, system-VPN
    /// placement, OTP setting or paired client (the migration imports only into an empty vault).
    pub fn is_empty(&self) -> Result<bool, VaultError> {
        for table in USER_TABLES {
            if count_rows(self, table)? > 0 {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Every table that holds user data (not `meta`).
const USER_TABLES: [&str; 15] = [
    "connections",
    "secrets",
    "folders",
    "credentials",
    "credential_links",
    "system_items",
    "system_otp",
    "ranking",
    "pins",
    "control_clients",
    "catalog_subscriptions",
    "catalog_items",
    "catalog_slots",
    "catalog_admin_keys",
    "catalog_publications",
];

fn count_rows(vault: &Vault, table: &str) -> Result<usize, VaultError> {
    // `table` is one of the fixed names above, never input.
    let n: i64 = vault.connection().query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?;
    Ok(usize::try_from(n).unwrap_or(0))
}

/// The same writes inside a caller's transaction, so several of them commit together (the migration imports
/// everything in one transaction).
impl Tx<'_> {
    /// [`Vault::save_connection`] inside this transaction. A catalog-owned connection is
    /// [`VaultError::CatalogManaged`] (only the catalog executor writes it).
    pub fn save_connection(&self, c: &Connection, config: Option<&str>) -> Result<(), VaultError> {
        let meta = swift_json::to_pretty_sorted(&c.to_json()).map_err(VaultError::Corrupt)?;
        let key = uuid_string(&c.id);
        guard_owned(self, &key)?;
        self.execute(
            "INSERT INTO connections(id, kind, meta_json, config, folder_id, position)
             VALUES (?1, ?2, ?3, coalesce(?4, x''), NULL,
                     (SELECT coalesce(max(position), -1) + 1 FROM connections WHERE folder_id IS NULL))
             ON CONFLICT(id) DO UPDATE SET
                 kind = excluded.kind,
                 meta_json = excluded.meta_json,
                 config = coalesce(?4, connections.config)",
            (&key, c.kind.raw_value(), &meta, config.map(str::as_bytes)),
        )?;
        Ok(())
    }

    /// [`Vault::set_secret`] inside this transaction.
    pub fn set_secret(&self, item: &str, field: SecretField, value: &str) -> Result<(), VaultError> {
        if value.is_empty() {
            self.execute("DELETE FROM secrets WHERE connection_id = ?1 AND field = ?2", (item, field.raw_value()))?;
        } else {
            self.execute(
                "INSERT INTO secrets(connection_id, field, value) VALUES (?1, ?2, ?3)
                 ON CONFLICT(connection_id, field) DO UPDATE SET value = excluded.value",
                (item, field.raw_value(), value.as_bytes()),
            )?;
        }
        Ok(())
    }
}
