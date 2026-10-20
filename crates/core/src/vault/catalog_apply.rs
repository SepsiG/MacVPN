//! The catalog executor (plan Task 7): runs an [`ApplyPlan`] of the pure planner against the vault, in **one**
//! transaction together with the new [`SubscriptionRecord`] (version, validators, status), so either the whole
//! new version is applied or nothing is.
//!
//! It is the only writer of catalog-owned rows: it uses its own statements, past the read-only guard of the
//! generic write paths ([`VaultError::CatalogManaged`]).
//!
//! What stays the subscriber's own across an apply: `created_at`, the native service binding, the colour override
//! (`connections.color`; the publisher's colour goes to `catalog_items.color`), the collapse state, pins and
//! ranking, the user's own secrets, the credential link, and `acknowledged_risky_directives` **only** while the
//! config is byte-identical (equal config hash); a changed config is acknowledged again.
//!
//! Credential slots (spec 6): each slot gets, at its first link, a new shared credential named after the slot
//! (suffixed " (<catalog>)", " (<catalog> 2)", … when the name is taken) with an empty username and no password;
//! the credential prompt fills it at the first connect. A connection with its own stored login is not linked, and a
//! slot is never linked to an existing personal credential by name. A removed slot's credential is kept when it was
//! filled in or is linked elsewhere, else deleted.

use super::db::{Tx, Vault, VaultError};
use super::repo_catalog::{SubscriptionRecord, owner_of, provided_of};
use super::repo_credentials::{MAX_CREDENTIAL_NAME_CHARACTERS, validate_credential_name};
use super::tree::validate_folder_name;
use crate::catalog::ids::{CatalogItemKind, local_id, root_folder_id};
use crate::catalog::keys::TeamKey;
use crate::catalog::payload::{CatalogConnection, CatalogFolder, CatalogPayload, MAX_CONNECTION_NAME_CHARACTERS};
use crate::catalog::planner::{ApplyPlan, CatalogOp, config_hash, folder_hash, meta_hash};
use crate::date::Date;
use crate::mfa;
use crate::models::{Connection, SecretField, parse_uuid, uuid_string};
use crate::swift_json;
use crate::vault::FolderColor;
use rusqlite::{Connection as Db, OptionalExtension};
use std::collections::{BTreeSet, HashMap, HashSet};
use unicode_segmentation::UnicodeSegmentation;
use uuid::Uuid;

/// What an apply needs besides the plan.
pub struct ApplyContext<'a> {
    pub catalog_id: Uuid,
    pub payload: &'a CatalogPayload,
    pub now: Date,
}

/// What unsubscribing removed and kept.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnsubscribeReport {
    /// The catalog's connections, now deleted (for the control API's allowlists).
    pub removed_connections: Vec<Uuid>,
    /// The names of the slot credentials the user had filled in, kept as normal shared credentials.
    pub kept_credentials: Vec<String>,
}

fn mismatch() -> VaultError {
    VaultError::Constraint("the plan does not match the catalog".into())
}

fn corrupt(what: &str) -> VaultError {
    VaultError::Corrupt(what.to_string())
}

fn next_position(conn: &Db, folder: &str) -> Result<i64, VaultError> {
    Ok(conn.query_row(
        "SELECT COALESCE(MAX(position) + 1, 0) FROM connections WHERE folder_id IS ?1",
        [folder],
        |r| r.get(0),
    )?)
}

/// The catalog that owns a row (`None`: not catalog-owned).
fn owning_catalog(conn: &Db, key: &str) -> Result<Option<String>, VaultError> {
    Ok(conn.query_row("SELECT catalog_id FROM catalog_items WHERE local_id = ?1", [key], |r| r.get(0)).optional()?)
}

/// Fails unless `key` is a row of `catalog` of the given kind.
fn require_owned(conn: &Db, catalog: &str, key: &str, kind: CatalogItemKind) -> Result<(), VaultError> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM catalog_items WHERE local_id = ?1 AND catalog_id = ?2 AND kind = ?3",
            (key, catalog, kind.as_str()),
            |r| r.get(0),
        )
        .optional()?;
    found.map(|_| ()).ok_or_else(mismatch)
}

fn read_connection(conn: &Db, key: &str) -> Result<Connection, VaultError> {
    let meta: String = conn
        .query_row("SELECT meta_json FROM connections WHERE id = ?1", [key], |r| r.get(0))
        .optional()?
        .ok_or_else(mismatch)?;
    let value = swift_json::parse(meta.as_bytes()).map_err(|_| corrupt("a connection is damaged"))?;
    Connection::from_json(&value).map_err(|_| corrupt("a connection is damaged"))
}

fn meta_json(c: &Connection) -> Result<String, VaultError> {
    swift_json::to_pretty_sorted(&c.to_json()).map_err(VaultError::Corrupt)
}

fn set_provided(conn: &Db, key: &str, fields: &BTreeSet<SecretField>) -> Result<(), VaultError> {
    let text = fields.iter().map(|f| f.raw_value()).collect::<Vec<_>>().join(",");
    conn.execute("UPDATE catalog_items SET provided_secrets = ?2 WHERE local_id = ?1", (key, text))?;
    Ok(())
}

fn provided(conn: &Db, key: &str) -> Result<BTreeSet<SecretField>, VaultError> {
    let text: String = conn
        .query_row("SELECT provided_secrets FROM catalog_items WHERE local_id = ?1", [key], |r| r.get(0))
        .optional()?
        .ok_or_else(mismatch)?;
    Ok(provided_of(&text))
}

/// The item has its own stored username or password.
fn has_own_login(conn: &Db, key: &str) -> Result<bool, VaultError> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM secrets WHERE connection_id = ?1 AND field IN ('username', 'password') LIMIT 1",
            [key],
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

fn current_link(conn: &Db, key: &str) -> Result<Option<String>, VaultError> {
    Ok(conn
        .query_row("SELECT credential_id FROM credential_links WHERE item_id = ?1", [key], |r| r.get(0))
        .optional()?)
}

/// Whether `credential` is the credential of one of `catalog`'s slots.
fn is_slot_credential(conn: &Db, catalog: &str, credential: &str) -> Result<bool, VaultError> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM catalog_slots WHERE catalog_id = ?1 AND credential_id = ?2",
            (catalog, credential),
            |r| r.get(0),
        )
        .optional()?;
    Ok(found.is_some())
}

fn credential_name_taken(conn: &Db, name: &str) -> Result<bool, VaultError> {
    let found: Option<i64> =
        conn.query_row("SELECT 1 FROM credentials WHERE name = ?1", [name], |r| r.get(0)).optional()?;
    Ok(found.is_some())
}

/// The slot's name, else "<slot> (<catalog>)", "<slot> (<catalog> 2)", …: the first free one, shortened to fit
/// the credential-name limit.
fn slot_credential_name(conn: &Db, slot: &str, catalog: &str) -> Result<String, VaultError> {
    if !credential_name_taken(conn, slot)? {
        return Ok(slot.to_string());
    }
    for n in 1usize.. {
        let suffix = if n == 1 { format!(" ({catalog})") } else { format!(" ({catalog} {n})") };
        let keep = MAX_CREDENTIAL_NAME_CHARACTERS.saturating_sub(suffix.graphemes(true).count());
        let base: String = slot.graphemes(true).take(keep).collect::<String>().trim_end().to_string();
        let candidate = format!("{base}{suffix}");
        let Ok(stored) = validate_credential_name(&candidate) else { continue };
        if !credential_name_taken(conn, &stored)? {
            return Ok(stored);
        }
        if n > 10_000 {
            break;
        }
    }
    Err(VaultError::Constraint("no free name for a credential slot".into()))
}

/// Deletes a slot's credential unless it was filled in or is linked; returns its name when it is kept.
fn release_slot_credential(conn: &Db, credential: &str) -> Result<Option<String>, VaultError> {
    let row: Option<(String, String, bool)> = conn
        .query_row(
            "SELECT name, username, password IS NOT NULL AND length(password) > 0 FROM credentials WHERE id = ?1",
            [credential],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((name, username, has_password)) = row else { return Ok(None) };
    let linked: Option<i64> = conn
        .query_row("SELECT 1 FROM credential_links WHERE credential_id = ?1 LIMIT 1", [credential], |r| r.get(0))
        .optional()?;
    if username.is_empty() && !has_password && linked.is_none() {
        conn.execute("DELETE FROM credentials WHERE id = ?1", [credential])?;
        return Ok(None);
    }
    Ok(Some(name))
}

/// The executor's state for one plan.
struct Run<'a, 'b> {
    tx: &'a Tx<'b>,
    catalog: String,
    catalog_name: String,
    root: String,
    connections: HashMap<Uuid, &'a CatalogConnection>,
    folders: HashMap<Uuid, &'a CatalogFolder>,
    payload: &'a CatalogPayload,
    now: Date,
    removed: Vec<Uuid>,
    kept_credentials: Vec<String>,
}

impl Run<'_, '_> {
    fn op(&mut self, op: &CatalogOp) -> Result<(), VaultError> {
        let tx = self.tx;
        match op {
            CatalogOp::RenameRoot { name } => {
                let stored = validate_folder_name(name).map_err(|_| mismatch())?;
                tx.execute("UPDATE folders SET name = ?2 WHERE id = ?1", (&self.root, stored))?;
                self.catalog_name = name.clone();
            }
            CatalogOp::UpsertFolder { local_id: local, parent, name, color, position } => {
                let f = self.folders.get(local).ok_or_else(mismatch)?;
                let key = uuid_string(local);
                let parent = uuid_string(parent);
                if parent != self.root {
                    require_owned(tx, &self.catalog, &parent, CatalogItemKind::Folder)?;
                }
                if let Some(owner) = owning_catalog(tx, &key)?
                    && owner != self.catalog
                {
                    return Err(mismatch());
                }
                tx.execute(
                    "INSERT INTO folders(id, parent_id, name, color, position, collapsed) VALUES (?1, ?2, ?3, ?4, ?5, 0)
                     ON CONFLICT(id) DO UPDATE SET parent_id = excluded.parent_id, name = excluded.name,
                         color = excluded.color, position = excluded.position",
                    (&key, &parent, name, color.map(FolderColor::as_str), position),
                )?;
                tx.execute(
                    "INSERT INTO catalog_items(local_id, catalog_id, item_id, kind, meta_hash) VALUES (?1, ?2, ?3, 'folder', ?4)
                     ON CONFLICT(local_id) DO UPDATE SET meta_hash = excluded.meta_hash",
                    (&key, &self.catalog, uuid_string(&f.id), folder_hash(f)),
                )?;
            }
            CatalogOp::RemoveFolder { local_id: local } => {
                let key = uuid_string(local);
                require_owned(tx, &self.catalog, &key, CatalogItemKind::Folder)?;
                // Personal items never sit in a catalog folder (the guard); anything left goes to the catalog root.
                tx.execute("UPDATE connections SET folder_id = ?2 WHERE folder_id = ?1", (&key, &self.root))?;
                tx.execute("UPDATE system_items SET folder_id = NULL WHERE folder_id = ?1", [&key])?;
                tx.execute("DELETE FROM folders WHERE id = ?1", [&key])?;
                tx.execute("DELETE FROM catalog_items WHERE local_id = ?1", [&key])?;
            }
            CatalogOp::AddConnection { local_id: local, item } => {
                let c = *self.connections.get(item).ok_or_else(mismatch)?;
                let cat = parse_uuid(&self.catalog).ok_or_else(mismatch)?;
                if local_id(cat, CatalogItemKind::Connection, *item) != *local {
                    return Err(mismatch());
                }
                let key = uuid_string(local);
                let mut connection = Connection::with_id(*local, c.name.clone(), c.kind, self.now);
                connection.native = c.native.clone();
                connection.otp = c.otp;
                let folder = self.folder_of(c)?;
                let position = next_position(tx, &folder)?;
                tx.execute(
                    "INSERT INTO connections(id, kind, meta_json, config, folder_id, color, position)
                     VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
                    (&key, c.kind.raw_value(), meta_json(&connection)?, c.config.as_bytes(), &folder, position),
                )?;
                tx.execute(
                    "INSERT INTO catalog_items(local_id, catalog_id, item_id, kind, color, slot_id, config_hash, meta_hash)
                     VALUES (?1, ?2, ?3, 'connection', ?4, ?5, ?6, ?7)",
                    (
                        &key,
                        &self.catalog,
                        uuid_string(item),
                        c.color.map(FolderColor::as_str),
                        c.slot.map(|s| uuid_string(&s)),
                        config_hash(c),
                        meta_hash(c, self.payload),
                    ),
                )?;
            }
            CatalogOp::UpdateConnection { local_id: local, item, config_changed: _, native_changed } => {
                let c = *self.connections.get(item).ok_or_else(mismatch)?;
                let key = uuid_string(local);
                require_owned(tx, &self.catalog, &key, CatalogItemKind::Connection)?;
                let old = read_connection(tx, &key)?;
                let (stored_hash, stored_folder): (Option<String>, Option<String>) = tx.query_row(
                    "SELECT i.config_hash, c.folder_id FROM catalog_items i JOIN connections c ON c.id = i.local_id
                     WHERE i.local_id = ?1",
                    [&key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                let new_hash = config_hash(c);
                let mut connection = Connection::with_id(*local, c.name.clone(), c.kind, old.created_at);
                connection.native_service_name = old.native_service_name;
                connection.native_service_id = old.native_service_id;
                connection.native = c.native.clone();
                connection.otp = c.otp;
                // The acknowledgement survives only a byte-identical config.
                if stored_hash.as_deref() == Some(new_hash.as_str()) {
                    connection.acknowledged_risky_directives = old.acknowledged_risky_directives;
                }
                let folder = self.folder_of(c)?;
                let position = if stored_folder.as_deref() == Some(folder.as_str()) {
                    tx.query_row("SELECT position FROM connections WHERE id = ?1", [&key], |r| r.get(0))?
                } else {
                    next_position(tx, &folder)?
                };
                tx.execute(
                    "UPDATE connections SET kind = ?2, meta_json = ?3, config = ?4, folder_id = ?5, position = ?6
                     WHERE id = ?1",
                    (&key, c.kind.raw_value(), meta_json(&connection)?, c.config.as_bytes(), &folder, position),
                )?;
                tx.execute(
                    "UPDATE catalog_items SET color = ?2, slot_id = ?3, config_hash = ?4, meta_hash = ?5,
                         pending_removal = 0, profile_outdated = (profile_outdated OR ?6)
                     WHERE local_id = ?1",
                    (
                        &key,
                        c.color.map(FolderColor::as_str),
                        c.slot.map(|s| uuid_string(&s)),
                        new_hash,
                        meta_hash(c, self.payload),
                        *native_changed,
                    ),
                )?;
            }
            CatalogOp::MarkPendingRemoval { local_id: local, folder_to } => {
                let key = uuid_string(local);
                require_owned(tx, &self.catalog, &key, CatalogItemKind::Connection)?;
                let folder = uuid_string(folder_to);
                if folder != self.root {
                    return Err(mismatch());
                }
                let position = next_position(tx, &folder)?;
                tx.execute(
                    "UPDATE connections SET folder_id = ?2, position = ?3 WHERE id = ?1",
                    (&key, &folder, position),
                )?;
                tx.execute("UPDATE catalog_items SET pending_removal = 1 WHERE local_id = ?1", [&key])?;
            }
            CatalogOp::RemoveConnection { local_id: local } => {
                let key = uuid_string(local);
                require_owned(tx, &self.catalog, &key, CatalogItemKind::Connection)?;
                remove_connection(tx, &key)?;
                self.removed.push(*local);
            }
            CatalogOp::SetProvidedSecret { local_id: local, field, secret } => {
                let key = uuid_string(local);
                require_owned(tx, &self.catalog, &key, CatalogItemKind::Connection)?;
                if !matches!(field, SecretField::Psk | SecretField::KeyPassword) {
                    return Err(mismatch());
                }
                let value = self.payload.shared_secrets.get(secret).ok_or_else(mismatch)?;
                tx.set_secret(&key, *field, value)?;
                let mut fields = provided(tx, &key)?;
                fields.insert(*field);
                set_provided(tx, &key, &fields)?;
            }
            CatalogOp::ClearProvidedSecret { local_id: local, field } => {
                let key = uuid_string(local);
                require_owned(tx, &self.catalog, &key, CatalogItemKind::Connection)?;
                let mut fields = provided(tx, &key)?;
                if fields.remove(field) {
                    tx.set_secret(&key, *field, "")?;
                    set_provided(tx, &key, &fields)?;
                }
            }
            CatalogOp::UpsertSlot { slot, name } => {
                let stored = validate_credential_name(name).map_err(|_| mismatch())?;
                tx.execute(
                    "INSERT INTO catalog_slots(catalog_id, slot_id, name) VALUES (?1, ?2, ?3)
                     ON CONFLICT(catalog_id, slot_id) DO UPDATE SET name = excluded.name",
                    (&self.catalog, uuid_string(slot), stored),
                )?;
            }
            CatalogOp::RemoveSlot { slot } => {
                let credential: Option<Option<String>> = tx
                    .query_row(
                        "SELECT credential_id FROM catalog_slots WHERE catalog_id = ?1 AND slot_id = ?2",
                        (&self.catalog, uuid_string(slot)),
                        |r| r.get(0),
                    )
                    .optional()?;
                tx.execute(
                    "DELETE FROM catalog_slots WHERE catalog_id = ?1 AND slot_id = ?2",
                    (&self.catalog, uuid_string(slot)),
                )?;
                if let Some(Some(credential)) = credential
                    && let Some(kept) = release_slot_credential(tx, &credential)?
                {
                    self.kept_credentials.push(kept);
                }
            }
            CatalogOp::LinkSlot { local_id: local, slot } => {
                let key = uuid_string(local);
                require_owned(tx, &self.catalog, &key, CatalogItemKind::Connection)?;
                if has_own_login(tx, &key)? {
                    return Ok(());
                }
                if let Some(linked) = current_link(tx, &key)?
                    && !is_slot_credential(tx, &self.catalog, &linked)?
                {
                    // The user linked it to a credential of their own: theirs to keep.
                    return Ok(());
                }
                let credential = self.slot_credential(*slot)?;
                tx.link(&key, credential)?;
            }
            CatalogOp::UnlinkSlot { local_id: local } => {
                let key = uuid_string(local);
                require_owned(tx, &self.catalog, &key, CatalogItemKind::Connection)?;
                if let Some(linked) = current_link(tx, &key)?
                    && is_slot_credential(tx, &self.catalog, &linked)?
                {
                    tx.execute("DELETE FROM credential_links WHERE item_id = ?1", [&key])?;
                }
            }
        }
        Ok(())
    }

    /// The local folder of a payload connection: its catalog folder, else the catalog root.
    fn folder_of(&self, c: &CatalogConnection) -> Result<String, VaultError> {
        let Some(folder) = c.folder else { return Ok(self.root.clone()) };
        let cat = parse_uuid(&self.catalog).ok_or_else(mismatch)?;
        let key = uuid_string(&local_id(cat, CatalogItemKind::Folder, folder));
        require_owned(self.tx, &self.catalog, &key, CatalogItemKind::Folder)?;
        Ok(key)
    }

    /// The slot's credential, created (empty username, no password) when it has none yet.
    fn slot_credential(&self, slot: Uuid) -> Result<Uuid, VaultError> {
        let tx = self.tx;
        let row: Option<(String, Option<String>)> = tx
            .query_row(
                "SELECT s.name, c.id FROM catalog_slots s LEFT JOIN credentials c ON c.id = s.credential_id
                 WHERE s.catalog_id = ?1 AND s.slot_id = ?2",
                (&self.catalog, uuid_string(&slot)),
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (name, credential) = row.ok_or_else(mismatch)?;
        if let Some(id) = credential.as_deref().and_then(parse_uuid) {
            return Ok(id);
        }
        let name = slot_credential_name(tx, &name, &self.catalog_name)?;
        let id = tx.create_credential(&name, "", None)?;
        tx.execute(
            "UPDATE catalog_slots SET credential_id = ?3 WHERE catalog_id = ?1 AND slot_id = ?2",
            (&self.catalog, uuid_string(&slot), uuid_string(&id)),
        )?;
        Ok(id)
    }
}

/// `delete_connection`'s clean-up (secrets, link, ranking, pin) plus the catalog row.
fn remove_connection(tx: &Tx<'_>, key: &str) -> Result<(), VaultError> {
    tx.execute("DELETE FROM secrets WHERE connection_id = ?1", [key])?;
    tx.execute("DELETE FROM credential_links WHERE item_id = ?1", [key])?;
    tx.execute("DELETE FROM ranking WHERE id = ?1", [key])?;
    tx.execute("DELETE FROM pins WHERE id = ?1", [key])?;
    tx.execute("DELETE FROM connections WHERE id = ?1", [key])?;
    tx.execute("DELETE FROM catalog_items WHERE local_id = ?1", [key])?;
    Ok(())
}

fn run_plan<'a, 'b>(
    tx: &'a Tx<'b>,
    catalog_id: Uuid,
    catalog_name: &str,
    payload: &'a CatalogPayload,
    now: Date,
    plan: &ApplyPlan,
) -> Result<Run<'a, 'b>, VaultError> {
    let catalog = uuid_string(&catalog_id);
    let mut run = Run {
        tx,
        catalog,
        catalog_name: catalog_name.to_string(),
        root: uuid_string(&root_folder_id(catalog_id)),
        connections: payload.connections.iter().map(|c| (c.id, c)).collect(),
        folders: payload.folders.iter().map(|f| (local_id(catalog_id, CatalogItemKind::Folder, f.id), f)).collect(),
        payload,
        now,
        removed: Vec::new(),
        kept_credentials: Vec::new(),
    };
    for op in &plan.ops {
        run.op(op)?;
    }
    Ok(run)
}

impl Vault {
    /// Applies a plan of [`crate::catalog::planner::plan_apply`] (or `plan_pending`) and stores `record` (the new
    /// version, validators, status), all in one transaction. Returns the ids of the connections it deleted (for the
    /// control API's allowlists).
    pub fn apply_catalog(
        &mut self,
        plan: &ApplyPlan,
        ctx: &ApplyContext,
        record: &SubscriptionRecord,
    ) -> Result<Vec<Uuid>, VaultError> {
        if record.catalog_id != ctx.catalog_id {
            return Err(mismatch());
        }
        self.transaction(|tx| {
            let run = run_plan(tx, ctx.catalog_id, &record.name, ctx.payload, ctx.now, plan)?;
            let removed = run.removed;
            tx.save_subscription_record(record)?;
            Ok(removed)
        })
    }

    /// Subscribes (spec 5): stores the new subscription with its secrets, creates its root folder and applies the
    /// first catalog (`plan` from [`crate::catalog::planner::plan_apply`] over an empty
    /// [`crate::catalog::planner::LocalCatalog`]), all in one transaction. Subscribing twice is
    /// [`VaultError::Constraint`].
    pub fn subscribe_catalog(
        &mut self,
        record: &SubscriptionRecord,
        team_key: &TeamKey,
        bearer: Option<&str>,
        plan: &ApplyPlan,
        ctx: &ApplyContext,
    ) -> Result<(), VaultError> {
        if record.catalog_id != ctx.catalog_id {
            return Err(mismatch());
        }
        self.transaction(|tx| {
            tx.add_subscription(record, team_key, bearer)?;
            run_plan(tx, ctx.catalog_id, &record.name, ctx.payload, ctx.now, plan)?;
            tx.save_subscription_record(record)
        })
    }

    /// Unsubscribes (spec 6): runs [`crate::catalog::planner::plan_unsubscribe`]'s plan, deletes the root folder and
    /// the subscription with its secrets, in one transaction. Filled slot credentials are kept as normal shared
    /// credentials (listed in the report), unfilled ones are deleted. Refused ([`VaultError::Constraint`]) while
    /// any of the catalog's connections is in `active` (the app disconnects them first).
    pub fn unsubscribe_catalog(
        &mut self,
        catalog_id: Uuid,
        plan: &ApplyPlan,
        active: &HashSet<Uuid>,
    ) -> Result<UnsubscribeReport, VaultError> {
        let empty = CatalogPayload {
            version: crate::catalog::payload::PAYLOAD_VERSION,
            folders: Vec::new(),
            connections: Vec::new(),
            credential_slots: Vec::new(),
            shared_secrets: Default::default(),
        };
        self.transaction(|tx| {
            let catalog = uuid_string(&catalog_id);
            let name: String = {
                let json: String = tx
                    .query_row("SELECT json FROM catalog_subscriptions WHERE catalog_id = ?1", [&catalog], |r| r.get(0))
                    .optional()?
                    .ok_or_else(|| VaultError::Constraint("no such catalog subscription".into()))?;
                serde_json::from_str::<serde_json::Value>(&json)
                    .ok()
                    .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(str::to_string))
                    .ok_or_else(|| corrupt("a catalog subscription is damaged"))?
            };
            let owned: Vec<String> = {
                let mut stmt = tx.prepare(
                    "SELECT local_id FROM catalog_items WHERE catalog_id = ?1 AND kind = 'connection' ORDER BY local_id",
                )?;
                stmt.query_map([&catalog], |r| r.get::<_, String>(0))?.collect::<Result<_, _>>()?
            };
            if owned.iter().filter_map(|k| parse_uuid(k)).any(|id| active.contains(&id)) {
                return Err(VaultError::Constraint("disconnect the catalog's connections first".into()));
            }
            let mut run = run_plan(tx, catalog_id, &name, &empty, Date::now(), plan)?;
            // Whatever a stale plan missed goes too.
            for key in owned {
                if let Some(id) = parse_uuid(&key)
                    && !run.removed.contains(&id)
                {
                    remove_connection(tx, &key)?;
                    run.removed.push(id);
                }
            }
            let slots: Vec<Option<String>> = {
                let mut stmt = tx.prepare("SELECT credential_id FROM catalog_slots WHERE catalog_id = ?1")?;
                stmt.query_map([&catalog], |r| r.get(0))?.collect::<Result<_, _>>()?
            };
            tx.execute("DELETE FROM catalog_slots WHERE catalog_id = ?1", [&catalog])?;
            for credential in slots.into_iter().flatten() {
                if let Some(kept) = release_slot_credential(tx, &credential)? {
                    run.kept_credentials.push(kept);
                }
            }
            tx.execute("DELETE FROM folders WHERE id = ?1", [uuid_string(&root_folder_id(catalog_id))])?;
            tx.execute("DELETE FROM catalog_subscriptions WHERE catalog_id = ?1", [&catalog])?;
            let mut kept = run.kept_credentials;
            kept.sort();
            kept.dedup();
            Ok(UnsubscribeReport { removed_connections: run.removed, kept_credentials: kept })
        })
    }

    /// The native profile of a catalog connection was installed from the version whose config hash is
    /// `built_from` (read from [`crate::vault::CatalogOwnership::config_hash`] before the profile was built), and
    /// macOS shows it installed: clears its "reinstall its profile" mark, compare-and-clear. `Ok(false)`: an apply
    /// changed the connection again meanwhile, so the mark stays (the installed profile is already outdated). Not
    /// a catalog connection: [`VaultError::Constraint`].
    pub fn clear_profile_outdated(&mut self, local_id: Uuid, built_from: &str) -> Result<bool, VaultError> {
        self.transaction(|tx| {
            let key = uuid_string(&local_id);
            let hash: Option<Option<String>> = tx
                .query_row(
                    "SELECT config_hash FROM catalog_items WHERE local_id = ?1 AND kind = 'connection'",
                    [&key],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(hash) = hash else { return Err(VaultError::Constraint("not a team catalog connection".into())) };
            if hash.as_deref() != Some(built_from) {
                return Ok(false);
            }
            tx.execute("UPDATE catalog_items SET profile_outdated = 0 WHERE local_id = ?1", [&key])?;
            Ok(true)
        })
    }

    /// "Duplicate as personal connection" (spec 6): an independent, editable copy of a catalog connection under a
    /// new random id, at the vault root, without a catalog row: the same kind, config, native settings and OTP
    /// setting, the item's own and provided secrets as its own, the same credential link; the acknowledged risky
    /// directives are cleared (the copy is acknowledged on its own).
    pub fn duplicate_catalog_connection(&mut self, local_id: Uuid, name: &str) -> Result<Uuid, VaultError> {
        let name = mfa::clean_name(name, MAX_CONNECTION_NAME_CHARACTERS)
            .ok_or_else(|| VaultError::Constraint("a connection name must have 1 to 128 characters".into()))?;
        self.transaction(|tx| {
            let key = uuid_string(&local_id);
            match owner_of(tx, &key)? {
                Some(o) if o.kind == CatalogItemKind::Connection => {}
                _ => return Err(VaultError::Constraint("not a team catalog connection".into())),
            }
            let old = read_connection(tx, &key)?;
            let id = Uuid::new_v4();
            let new_key = uuid_string(&id);
            let mut copy = Connection::with_id(id, name.clone(), old.kind, Date::now());
            copy.native = old.native.clone();
            copy.otp = old.otp;
            if old.kind.is_native() {
                copy.native_service_name = Some(name.clone());
            }
            let position: i64 = tx.query_row(
                "SELECT COALESCE(MAX(position) + 1, 0) FROM connections WHERE folder_id IS NULL",
                [],
                |r| r.get(0),
            )?;
            tx.execute(
                "INSERT INTO connections(id, kind, meta_json, config, folder_id, color, position)
                 SELECT ?2, kind, ?3, config, NULL, NULL, ?4 FROM connections WHERE id = ?1",
                (&key, &new_key, meta_json(&copy)?, position),
            )?;
            tx.execute(
                "INSERT INTO secrets(connection_id, field, value) SELECT ?2, field, value FROM secrets WHERE connection_id = ?1",
                (&key, &new_key),
            )?;
            if let Some(credential) = current_link(tx, &key)?.as_deref().and_then(parse_uuid) {
                tx.link(&new_key, credential)?;
            }
            Ok(id)
        })
    }
}
