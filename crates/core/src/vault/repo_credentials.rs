//! Shared credentials (spec 3a, plan B Task 18): the `credentials` and `credential_links` tables.
//!
//! - A credential is a uniquely named username + optional password. The password is a BLOB (`NULL`: none; the
//!   credential prompt asks for it at connect time). Names are compared byte for byte, as the import matches them.
//! - A link binds one item (a managed connection's UUID string or a system VPN's service ID, like the `secrets`
//!   table) to one credential. Linking deletes the item's own username and password in the same transaction, so a
//!   linked item never has two sets. Its other secrets (PSK, key password) stay its own.
//! - [`Vault::resolved_secret`] is the link-aware read the app's secret store uses: the username and password of
//!   a linked item are the credential's, so the connect path (the root layer's stdin,
//!   `SCNetworkConnectionStart`'s `AuthName`/`XAuthName`) works on the credential without knowing about it.
//! - Two writes, deliberately apart: [`Vault::save_prompted_secret`] (only the credential prompt's "Save" and the
//!   re-prompt) writes a linked item's username or password into the shared credential; [`Vault::set_item_secret`]
//!   (the editors, the import) refuses those fields of a linked item with [`VaultError::LinkedToCredential`], so
//!   editing one connection never changes every connection that shares the credential.
//! - A linked credential is never deleted (`ON DELETE RESTRICT`, and [`Vault::delete_credential`] reports the
//!   items); [`Vault::copy_into_connections`] turns the links back into own copies first.
//! - [`Vault::matching_items`] ("Create from connection…") compares the values in memory, in wiped buffers, and
//!   returns item ids only.
//!
//! Every write runs in [`Vault::transaction`]. Nothing here logs, and no error or `Debug` output carries a
//! username, a password or any other secret.

use super::db::{Tx, Vault, VaultError};
use super::repo_catalog::guard_provided;
use super::repo_connections::wiped_bytes_opt;
use crate::collation;
use crate::date::Date;
use crate::mfa;
use crate::models::{SecretField, parse_uuid, uuid_string};
use rusqlite::{Connection, OptionalExtension};
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The longest credential name, in characters (grapheme clusters).
pub const MAX_CREDENTIAL_NAME_CHARACTERS: usize = 64;
/// The longest credential username, in bytes.
pub const MAX_CREDENTIAL_USERNAME_BYTES: usize = 256;
/// The longest credential password, in bytes (the credential prompt's limit).
pub const MAX_CREDENTIAL_PASSWORD_BYTES: usize = 1024;

/// A credential as listed: never the password, only whether one is stored.
#[derive(Debug, Clone, PartialEq)]
pub struct SharedCredential {
    pub id: Uuid,
    pub name: String,
    pub username: String,
    pub has_password: bool,
    pub created: Date,
    pub updated: Date,
}

/// A delete refused because items still use the credential: their ids (connection UUID strings or service IDs),
/// sorted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialInUse {
    pub items: Vec<String>,
}

fn invalid(what: &str) -> VaultError {
    VaultError::Constraint(what.to_string())
}

/// A credential name as stored: format characters dropped, trimmed, 1 to [`MAX_CREDENTIAL_NAME_CHARACTERS`]
/// characters, no control character (the folder-name rule).
pub fn validate_credential_name(name: &str) -> Result<String, VaultError> {
    mfa::clean_name(name, MAX_CREDENTIAL_NAME_CHARACTERS)
        .ok_or_else(|| invalid("a credential name must have 1 to 64 characters and no control characters"))
}

pub(crate) fn check_username(username: &str) -> Result<(), VaultError> {
    if username.len() > MAX_CREDENTIAL_USERNAME_BYTES || mfa::has_control(username) {
        return Err(invalid("a credential username must have at most 256 bytes and no control characters"));
    }
    Ok(())
}

pub(crate) fn check_password(password: &str) -> Result<(), VaultError> {
    if password.len() > MAX_CREDENTIAL_PASSWORD_BYTES || mfa::has_control(password) {
        return Err(invalid("a credential password must have at most 1024 bytes and no control characters"));
    }
    Ok(())
}

pub(crate) fn check_item(item: &str) -> Result<(), VaultError> {
    if item.is_empty() || item.len() > 256 || mfa::has_control(item) {
        return Err(invalid("invalid item id"));
    }
    Ok(())
}

/// A field a credential covers.
fn covered(field: SecretField) -> bool {
    matches!(field, SecretField::Username | SecretField::Password)
}

fn now() -> String {
    Date::now().iso8601()
}

fn date(s: &str) -> Date {
    Date::parse_iso8601(s).unwrap_or_else(|| Date::from_time_interval_since_1970(0.0))
}

fn utf8(bytes: Zeroizing<Vec<u8>>, what: &str) -> Result<Zeroizing<String>, VaultError> {
    match std::str::from_utf8(&bytes) {
        Ok(s) => Ok(Zeroizing::new(s.to_owned())),
        Err(_) => Err(VaultError::Corrupt(format!("{what} is not UTF-8"))),
    }
}

const SELECT_CREDENTIAL: &str = "SELECT id, name, username, coalesce(length(password), 0) > 0, created, updated
                                 FROM credentials";

fn read_credentials(conn: &Connection, filter: &str, arg: Option<String>) -> Result<Vec<SharedCredential>, VaultError> {
    let mut stmt = conn.prepare(&format!("{SELECT_CREDENTIAL} {filter}"))?;
    let map = |r: &rusqlite::Row<'_>| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, bool>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
        ))
    };
    let rows = match arg {
        Some(arg) => stmt.query_map([arg], map)?.collect::<Result<Vec<_>, _>>()?,
        None => stmt.query_map([], map)?.collect::<Result<Vec<_>, _>>()?,
    };
    Ok(rows
        .into_iter()
        .filter_map(|(id, name, username, has_password, created, updated)| {
            Some(SharedCredential {
                id: parse_uuid(&id)?,
                name,
                username,
                has_password,
                created: date(&created),
                updated: date(&updated),
            })
        })
        .collect())
}

fn credential_exists(conn: &Connection, id: Uuid) -> Result<bool, VaultError> {
    Ok(conn.query_row("SELECT 1 FROM credentials WHERE id = ?1", [uuid_string(&id)], |_| Ok(())).optional()?.is_some())
}

/// Another credential (not `except`) already has this name.
fn name_taken(conn: &Connection, name: &str, except: Option<Uuid>) -> Result<bool, VaultError> {
    let other: Option<String> =
        conn.query_row("SELECT id FROM credentials WHERE name = ?1", [name], |r| r.get(0)).optional()?;
    Ok(other.is_some_and(|other| Some(other) != except.map(|e| uuid_string(&e))))
}

fn credential_of(conn: &Connection, item: &str) -> Result<Option<Uuid>, VaultError> {
    let id: Option<String> = conn
        .query_row("SELECT credential_id FROM credential_links WHERE item_id = ?1", [item], |r| r.get(0))
        .optional()?;
    Ok(id.as_deref().and_then(parse_uuid))
}

fn linked_items(conn: &Connection, credential: Uuid) -> Result<Vec<String>, VaultError> {
    let mut stmt = conn.prepare("SELECT item_id FROM credential_links WHERE credential_id = ?1 ORDER BY item_id")?;
    Ok(stmt.query_map([uuid_string(&credential)], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?)
}

fn credential_username(conn: &Connection, id: Uuid) -> Result<Option<Zeroizing<String>>, VaultError> {
    let name: Option<String> = conn
        .query_row("SELECT username FROM credentials WHERE id = ?1", [uuid_string(&id)], |r| r.get(0))
        .optional()?;
    Ok(name.map(Zeroizing::new))
}

fn credential_password(conn: &Connection, id: Uuid) -> Result<Option<Zeroizing<String>>, VaultError> {
    let bytes = conn
        .query_row("SELECT password FROM credentials WHERE id = ?1", [uuid_string(&id)], |r| wiped_bytes_opt(r, 0))
        .optional()?
        .flatten();
    match bytes {
        Some(b) if !b.is_empty() => Ok(Some(utf8(b, "a credential password")?)),
        _ => Ok(None),
    }
}

/// The item's own secret (not resolved through a link).
fn own_secret(conn: &Connection, item: &str, field: SecretField) -> Result<Option<Zeroizing<String>>, VaultError> {
    let bytes = conn
        .query_row(
            "SELECT value FROM secrets WHERE connection_id = ?1 AND field = ?2",
            (item, field.raw_value()),
            |r| wiped_bytes_opt(r, 0),
        )
        .optional()?
        .flatten();
    match bytes {
        Some(b) if !b.is_empty() => Ok(Some(utf8(b, "a secret")?)),
        _ => Ok(None),
    }
}

/// A username and a password, wiped on drop.
type Pair = (Zeroizing<String>, Zeroizing<String>);

/// The item's own username and password, when both are stored and the item is not linked.
fn own_pair(conn: &Connection, item: &str) -> Result<Option<Pair>, VaultError> {
    if credential_of(conn, item)?.is_some() {
        return Ok(None);
    }
    let (Some(user), Some(pass)) =
        (own_secret(conn, item, SecretField::Username)?, own_secret(conn, item, SecretField::Password)?)
    else {
        return Ok(None);
    };
    Ok(Some((user, pass)))
}

/// The other unlinked items whose own username and password equal `item`'s, sorted. The values are compared in
/// wiped buffers and never leave this function.
fn matching(conn: &Connection, item: &str) -> Result<Vec<String>, VaultError> {
    let Some((user, pass)) = own_pair(conn, item)? else { return Ok(Vec::new()) };
    let candidates: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT connection_id FROM secrets
             WHERE field = ?1 AND connection_id <> ?2
               AND connection_id NOT IN (SELECT item_id FROM credential_links)
             ORDER BY connection_id",
        )?;
        stmt.query_map((SecretField::Username.raw_value(), item), |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut out = Vec::new();
    for candidate in candidates {
        if let Some((u, p)) = own_pair(conn, &candidate)?
            && u.as_bytes() == user.as_bytes()
            && p.as_bytes() == pass.as_bytes()
        {
            out.push(candidate);
        }
    }
    Ok(out)
}

impl Vault {
    /// Every credential, sorted by name (localized, case-insensitive).
    pub fn credentials(&self) -> Result<Vec<SharedCredential>, VaultError> {
        let mut out = read_credentials(self.connection(), "ORDER BY rowid", None)?;
        out.sort_by(|a, b| collation::localized_case_insensitive_compare(&a.name, &b.name));
        Ok(out)
    }

    /// One credential.
    pub fn credential(&self, id: Uuid) -> Result<Option<SharedCredential>, VaultError> {
        Ok(read_credentials(self.connection(), "WHERE id = ?1", Some(uuid_string(&id)))?.into_iter().next())
    }

    /// The credential with exactly this name (the import's automatic link).
    pub fn credential_by_name(&self, name: &str) -> Result<Option<Uuid>, VaultError> {
        let id: Option<String> = self
            .connection()
            .query_row("SELECT id FROM credentials WHERE name = ?1", [name], |r| r.get(0))
            .optional()?;
        Ok(id.as_deref().and_then(parse_uuid))
    }

    /// How many items use each credential (every credential is listed, unused ones with 0).
    pub fn credential_usage(&self) -> Result<HashMap<Uuid, usize>, VaultError> {
        let mut stmt = self.connection().prepare(
            "SELECT c.id, count(l.item_id) FROM credentials c
             LEFT JOIN credential_links l ON l.credential_id = c.id GROUP BY c.id",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        let mut out = HashMap::new();
        for row in rows {
            let (id, n) = row?;
            if let Some(id) = parse_uuid(&id) {
                out.insert(id, usize::try_from(n).unwrap_or(0));
            }
        }
        Ok(out)
    }

    /// A new credential. The name must be unused (else [`VaultError::Constraint`]); `password` `None` or empty:
    /// none stored, the credential prompt asks for it.
    pub fn create_credential(
        &mut self,
        name: &str,
        username: &str,
        password: Option<&str>,
    ) -> Result<Uuid, VaultError> {
        self.transaction(|tx| tx.create_credential(name, username, password))
    }

    /// Changes the given fields: `None` keeps one; `password: Some(None)` (or an empty one) removes the password.
    pub fn update_credential(
        &mut self,
        id: Uuid,
        name: Option<&str>,
        username: Option<&str>,
        password: Option<Option<&str>>,
    ) -> Result<(), VaultError> {
        let name = name.map(validate_credential_name).transpose()?;
        if let Some(username) = username {
            check_username(username)?;
        }
        if let Some(Some(password)) = password {
            check_password(password)?;
        }
        self.transaction(|tx| {
            if !credential_exists(tx, id)? {
                return Err(invalid("no such credential"));
            }
            let key = uuid_string(&id);
            if let Some(name) = &name {
                if name_taken(tx, name, Some(id))? {
                    return Err(invalid("a credential with this name already exists"));
                }
                tx.execute("UPDATE credentials SET name = ?1 WHERE id = ?2", (name, &key))?;
            }
            if let Some(username) = username {
                tx.execute("UPDATE credentials SET username = ?1 WHERE id = ?2", (username, &key))?;
            }
            if let Some(password) = password {
                let blob = password.filter(|p| !p.is_empty()).map(str::as_bytes);
                tx.execute("UPDATE credentials SET password = ?1 WHERE id = ?2", (blob, &key))?;
            }
            tx.execute("UPDATE credentials SET updated = ?1 WHERE id = ?2", (now(), &key))?;
            Ok(())
        })
    }

    /// The credential's password (wiped on drop); `None` when it has none (or is unknown).
    pub fn credential_password(&self, id: Uuid) -> Result<Option<Zeroizing<String>>, VaultError> {
        credential_password(self.connection(), id)
    }

    /// Deletes an unused credential. While items use it, nothing changes and the outer `Err(Ok(_))` lists them
    /// (`ON DELETE RESTRICT`); `Err(Err(_))` is a database error. An unknown id is not an error.
    pub fn delete_credential(&mut self, id: Uuid) -> Result<(), Result<CredentialInUse, VaultError>> {
        let result = self.transaction(|tx| {
            let items = linked_items(tx, id)?;
            if !items.is_empty() {
                return Ok(Some(CredentialInUse { items }));
            }
            tx.execute("DELETE FROM credentials WHERE id = ?1", [uuid_string(&id)])?;
            Ok(None)
        });
        match result {
            Ok(None) => Ok(()),
            Ok(Some(in_use)) => Err(Ok(in_use)),
            Err(e) => Err(Err(e)),
        }
    }

    /// Links `item` to `credential` (replacing an earlier link) and deletes the item's own username and password
    /// in the same transaction.
    pub fn link(&mut self, item: &str, credential: Uuid) -> Result<(), VaultError> {
        self.transaction(|tx| tx.link(item, credential))
    }

    /// Removes the item's link; it then has no username or password until new ones are stored. Unlinking an
    /// unlinked item is not an error.
    pub fn unlink(&mut self, item: &str) -> Result<(), VaultError> {
        self.transaction(|tx| {
            tx.execute("DELETE FROM credential_links WHERE item_id = ?1", [item])?;
            Ok(())
        })
    }

    /// Forgets everything stored for one item: its own secrets and its link (the credential itself stays). A team
    /// catalog's item is [`VaultError::CatalogManaged`]: its provided secrets and its slot link are the catalog's,
    /// and only the catalog removes it.
    pub fn forget_item(&mut self, item: &str) -> Result<(), VaultError> {
        self.transaction(|tx| {
            super::repo_catalog::guard_owned(tx, item)?;
            tx.execute("DELETE FROM secrets WHERE connection_id = ?1", [item])?;
            tx.execute("DELETE FROM credential_links WHERE item_id = ?1", [item])?;
            Ok(())
        })
    }

    /// The credential `item` is linked to.
    pub fn credential_of(&self, item: &str) -> Result<Option<Uuid>, VaultError> {
        credential_of(self.connection(), item)
    }

    /// The items linked to `credential`, sorted.
    pub fn linked_items(&self, credential: Uuid) -> Result<Vec<String>, VaultError> {
        linked_items(self.connection(), credential)
    }

    /// "Copy into each connection": writes the credential's username and password into every linked item as its
    /// own, removes the links and deletes the credential, in one transaction.
    pub fn copy_into_connections(&mut self, credential: Uuid) -> Result<(), VaultError> {
        self.transaction(|tx| {
            let Some(username) = credential_username(tx, credential)? else {
                return Err(invalid("no such credential"));
            };
            let password = credential_password(tx, credential)?;
            for item in linked_items(tx, credential)? {
                tx.set_secret(&item, SecretField::Username, &username)?;
                tx.set_secret(&item, SecretField::Password, password.as_deref().map_or("", String::as_str))?;
            }
            let key = uuid_string(&credential);
            tx.execute("DELETE FROM credential_links WHERE credential_id = ?1", [&key])?;
            tx.execute("DELETE FROM credentials WHERE id = ?1", [&key])?;
            Ok(())
        })
    }

    /// A secret as the connect path sees it: for a linked item, the username and password are the credential's
    /// (an empty username or a missing password is `None`); every other field, and every field of an unlinked
    /// item, is the item's own.
    pub fn resolved_secret(&self, item: &str, field: SecretField) -> Result<Option<Zeroizing<String>>, VaultError> {
        let conn = self.connection();
        if covered(field)
            && let Some(credential) = credential_of(conn, item)?
        {
            return match field {
                SecretField::Username => Ok(credential_username(conn, credential)?.filter(|u| !u.is_empty())),
                _ => credential_password(conn, credential),
            };
        }
        own_secret(conn, item, field)
    }

    /// The credential prompt's "Save" and the sign-in failure re-prompt, **and nothing else**: stores a secret the
    /// way [`Self::resolved_secret`] reads it, so the username or password of a linked item goes to the shared
    /// credential (and every linked item sees it). An empty value never clears a credential's field. Every other
    /// write is the item's own ([`Vault::set_secret`], where an empty value deletes).
    ///
    /// The editors must not use this: editing one connection would silently change every connection linked to
    /// the same credential. They use [`Self::set_item_secret`].
    pub fn save_prompted_secret(&mut self, item: &str, field: SecretField, value: &str) -> Result<(), VaultError> {
        self.transaction(|tx| {
            guard_provided(tx, item, field)?;
            if covered(field)
                && let Some(credential) = credential_of(tx, item)?
            {
                if value.is_empty() {
                    return Ok(());
                }
                let key = uuid_string(&credential);
                if field == SecretField::Username {
                    check_username(value)?;
                    tx.execute(
                        "UPDATE credentials SET username = ?1, updated = ?2 WHERE id = ?3",
                        (value, now(), &key),
                    )?;
                } else {
                    check_password(value)?;
                    tx.execute(
                        "UPDATE credentials SET password = ?1, updated = ?2 WHERE id = ?3",
                        (value.as_bytes(), now(), &key),
                    )?;
                }
                return Ok(());
            }
            tx.set_secret(item, field, value)
        })
    }

    /// The editors' (and the import's) secret write: the item's own value ([`Vault::set_secret`], where an empty
    /// value deletes). For an item linked to a shared credential, a non-empty username or password is refused with
    /// [`VaultError::LinkedToCredential`] and nothing changes (a linked editor sends no value for those fields; an
    /// empty one is accepted as a no-op, since a linked item has no own username or password to clear). The
    /// other fields (PSK, key password) are always the item's own. A field a team catalog provides for the item is
    /// [`VaultError::CatalogManaged`].
    pub fn set_item_secret(&mut self, item: &str, field: SecretField, value: &str) -> Result<(), VaultError> {
        self.transaction(|tx| {
            guard_provided(tx, item, field)?;
            if covered(field) && credential_of(tx, item)?.is_some() {
                return if value.is_empty() { Ok(()) } else { Err(VaultError::LinkedToCredential) };
            }
            tx.set_secret(item, field, value)
        })
    }

    /// Every secret, link and shared credential (uninstall with the user data), in one transaction.
    pub fn delete_all_secrets_and_credentials(&mut self) -> Result<(), VaultError> {
        self.transaction(|tx| {
            tx.execute("DELETE FROM credential_links", ())?;
            tx.execute("DELETE FROM secrets", ())?;
            tx.execute("DELETE FROM credentials", ())?;
            Ok(())
        })
    }

    /// "Create from connection…": the other unlinked items whose own username **and** password equal `item`'s
    /// (sorted ids; empty when `item` has no own username and password). The values are compared in memory and
    /// never returned.
    pub fn matching_items(&self, item: &str) -> Result<Vec<String>, VaultError> {
        matching(self.connection(), item)
    }

    /// "Create from connection…", in one transaction: a new credential `name` from `item`'s own username and
    /// password (the password may be missing), linked to `item` and to each of `link`, which must all be
    /// [`Self::matching_items`] of `item` (anything else refuses the whole operation). The values never leave
    /// the vault.
    pub fn create_credential_from(&mut self, item: &str, name: &str, link: &[String]) -> Result<Uuid, VaultError> {
        self.transaction(|tx| {
            if credential_of(tx, item)?.is_some() {
                return Err(invalid("the item already uses a credential"));
            }
            let Some(username) = own_secret(tx, item, SecretField::Username)? else {
                return Err(invalid("the item has no username to share"));
            };
            let password = own_secret(tx, item, SecretField::Password)?;
            let matches = matching(tx, item)?;
            if link.iter().any(|l| !matches.contains(l)) {
                return Err(invalid("an item to link does not have the same username and password"));
            }
            let id = tx.create_credential(name, &username, password.as_deref().map(String::as_str))?;
            tx.link(item, id)?;
            for other in link {
                tx.link(other, id)?;
            }
            Ok(id)
        })
    }
}

/// The credential writes inside a caller's transaction (the import and the backup restore commit them together
/// with other rows).
impl Tx<'_> {
    /// [`Vault::create_credential`] inside this transaction.
    pub fn create_credential(&self, name: &str, username: &str, password: Option<&str>) -> Result<Uuid, VaultError> {
        let name = validate_credential_name(name)?;
        check_username(username)?;
        let password = password.filter(|p| !p.is_empty());
        if let Some(password) = password {
            check_password(password)?;
        }
        if name_taken(self, &name, None)? {
            return Err(invalid("a credential with this name already exists"));
        }
        let id = Uuid::new_v4();
        let stamp = now();
        self.execute(
            "INSERT INTO credentials(id, name, username, password, created, updated) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            (uuid_string(&id), &name, username, password.map(str::as_bytes), &stamp),
        )?;
        Ok(id)
    }

    /// [`Vault::link`] inside this transaction.
    pub fn link(&self, item: &str, credential: Uuid) -> Result<(), VaultError> {
        check_item(item)?;
        if !credential_exists(self, credential)? {
            return Err(invalid("no such credential"));
        }
        self.set_secret(item, SecretField::Username, "")?;
        self.set_secret(item, SecretField::Password, "")?;
        self.execute(
            "INSERT INTO credential_links(item_id, credential_id) VALUES (?1, ?2)
             ON CONFLICT(item_id) DO UPDATE SET credential_id = excluded.credential_id",
            (item, uuid_string(&credential)),
        )?;
        Ok(())
    }
}
