//! The folder repository (spec 3, plan B Task 9): the `folders` table and the placement columns (`folder_id`,
//! `color`) of `connections` and `system_items`.
//!
//! Every write runs in one [`Vault::transaction`], and the folder tree is read again inside it, so the cycle check
//! and the renumbering see the same state they change. Ids are stored as upper-case UUID strings
//! ([`uuid_string`]), colours as the palette's storage ids ([`FolderColor::as_str`]).
//!
//! Sibling folders are renumbered `0..n` after every move and delete. `connections.position` and
//! `system_items.position` get the next number in the target folder (append order); they are written for a stable
//! schema but not used for display, where items follow the pins and the usage ranking.

use super::color::FolderColor;
use super::db::{Vault, VaultError};
use super::repo_catalog::{guard_folder, guard_owned};
use super::tree::{FolderNode, FolderTree, TreeError, validate_folder_name};
use crate::models::uuid_string;
use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

/// What happens to a deleted folder's contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteMode {
    /// The direct subfolders and items move to the deleted folder's parent (the root for a root folder), after the
    /// parent's own subfolders.
    MoveContentsUp,
    /// The subfolders go too (`ON DELETE CASCADE`); [`Vault::delete_folder`] returns the managed connections in the
    /// whole subtree, for the app to delete through its normal path (profiles, secrets). System VPNs in it move to
    /// the root, since they cannot be deleted here.
    DeleteContents,
}

/// The two tables that place an item: `(table, key column)`.
#[derive(Clone, Copy)]
enum Items {
    Connections,
    System,
}

impl Items {
    fn table(self) -> &'static str {
        match self {
            Items::Connections => "connections",
            Items::System => "system_items",
        }
    }

    fn key(self) -> &'static str {
        match self {
            Items::Connections => "id",
            Items::System => "service_id",
        }
    }
}

impl Vault {
    /// Every folder, unordered (build a [`FolderTree`] for the order).
    pub fn folders(&self) -> Result<Vec<FolderNode>, VaultError> {
        load_folders(self.connection())
    }

    /// The folders as a tree. A stored cycle or dangling parent (which the writes here never produce) is
    /// [`VaultError::Corrupt`].
    pub fn folder_tree(&self) -> Result<FolderTree, VaultError> {
        load_tree(self.connection())
    }

    /// A new folder at the end of `parent` (`None`: the root). The name goes through [`validate_folder_name`].
    pub fn create_folder(&mut self, parent: Option<Uuid>, name: &str) -> Result<Uuid, VaultError> {
        let name = validate_folder_name(name)?;
        self.transaction(|tx| {
            let tree = load_tree(tx)?;
            if let Some(parent) = parent
                && !tree.contains(parent)
            {
                return Err(TreeError::UnknownFolder(parent).into());
            }
            if let Some(parent) = parent {
                guard_folder(tx, parent)?;
            }
            let id = Uuid::new_v4();
            let position = tree.children(parent).last().and_then(|last| tree.get(*last)).map_or(0, |n| n.position + 1);
            tx.execute(
                "INSERT INTO folders(id, parent_id, name, color, position, collapsed) VALUES (?1, ?2, ?3, NULL, ?4, 0)",
                (uuid_string(&id), parent.map(|p| uuid_string(&p)), &name, position),
            )?;
            Ok(id)
        })
    }

    /// A catalog folder is [`VaultError::CatalogManaged`].
    pub fn rename_folder(&mut self, id: Uuid, name: &str) -> Result<(), VaultError> {
        let name = validate_folder_name(name)?;
        self.update_folder(id, true, "UPDATE folders SET name = ?2 WHERE id = ?1", name)
    }

    /// `None` clears the folder's own colour (it inherits from its parent again). A catalog folder (its colour is
    /// the publisher's) is [`VaultError::CatalogManaged`].
    pub fn set_folder_color(&mut self, id: Uuid, color: Option<FolderColor>) -> Result<(), VaultError> {
        self.update_folder(id, true, "UPDATE folders SET color = ?2 WHERE id = ?1", color.map(FolderColor::as_str))
    }

    /// The menu's persisted collapsed state (also of catalog folders: it is the user's own).
    pub fn set_collapsed(&mut self, id: Uuid, collapsed: bool) -> Result<(), VaultError> {
        self.update_folder(id, false, "UPDATE folders SET collapsed = ?2 WHERE id = ?1", collapsed)
    }

    /// Moves `id` under `new_parent` (`None`: the root) at `position` among its new siblings (past the end
    /// appends), also for a reorder within the same parent. A move into the folder itself or a descendant is
    /// [`TreeError::Cycle`] and changes nothing. Both sibling lists are renumbered `0..n`.
    pub fn move_folder(&mut self, id: Uuid, new_parent: Option<Uuid>, position: usize) -> Result<(), VaultError> {
        self.transaction(|tx| {
            let tree = load_tree(tx)?;
            tree.check_move(id, new_parent)?;
            guard_folder(tx, id)?;
            if let Some(parent) = new_parent {
                guard_folder(tx, parent)?;
            }
            let old_parent = tree.get(id).and_then(|n| n.parent);
            let mut siblings: Vec<Uuid> = tree.children(new_parent).iter().copied().filter(|c| *c != id).collect();
            siblings.insert(position.min(siblings.len()), id);
            place_folders(tx, new_parent, &siblings)?;
            if old_parent != new_parent {
                let rest: Vec<Uuid> = tree.children(old_parent).iter().copied().filter(|c| *c != id).collect();
                place_folders(tx, old_parent, &rest)?;
            }
            Ok(())
        })
    }

    /// Deletes a folder. [`DeleteMode::MoveContentsUp`] returns nothing; [`DeleteMode::DeleteContents`] returns
    /// the managed connections of the whole subtree (still stored, now at the root), which the caller deletes.
    pub fn delete_folder(&mut self, id: Uuid, mode: DeleteMode) -> Result<Vec<Uuid>, VaultError> {
        self.transaction(|tx| {
            let tree = load_tree(tx)?;
            let node = tree.get(id).ok_or(TreeError::UnknownFolder(id))?;
            guard_folder(tx, id)?;
            let parent = node.parent;
            let mut connections = Vec::new();
            match mode {
                DeleteMode::MoveContentsUp => {
                    let mut siblings: Vec<Uuid> = tree.children(parent).iter().copied().filter(|c| *c != id).collect();
                    siblings.extend(tree.children(Some(id)));
                    place_folders(tx, parent, &siblings)?;
                    move_items(tx, Items::Connections, id, parent)?;
                    move_items(tx, Items::System, id, parent)?;
                }
                DeleteMode::DeleteContents => {
                    let subtree = std::iter::once(id).chain(tree.descendants(id));
                    for folder in subtree {
                        connections.extend(items_in(tx, Items::Connections, folder)?);
                        move_items(tx, Items::System, folder, None)?;
                    }
                }
            }
            tx.execute("DELETE FROM folders WHERE id = ?1", [uuid_string(&id)])?;
            if mode == DeleteMode::MoveContentsUp {
                return Ok(Vec::new());
            }
            connections
                .iter()
                .map(|c| Uuid::parse_str(c).map_err(|_| VaultError::Corrupt("invalid connection id".into())))
                .collect()
        })
    }

    /// Puts an item into `folder` (`None`: the root). `key` is the ranking key: a stored managed connection's
    /// UUID string updates `connections`; anything else is a system VPN's service ID and upserts `system_items`.
    pub fn set_item_folder(&mut self, key: &str, folder: Option<Uuid>) -> Result<(), VaultError> {
        self.transaction(|tx| {
            if let Some(folder) = folder
                && !folder_exists(tx, folder)?
            {
                return Err(TreeError::UnknownFolder(folder).into());
            }
            // Neither a catalog connection out of its place nor anything into a catalog folder.
            guard_owned(tx, key)?;
            if let Some(folder) = folder {
                guard_folder(tx, folder)?;
            }
            let folder_id = folder.map(|f| uuid_string(&f));
            if is_managed(tx, key)? {
                let position = next_position(tx, Items::Connections, folder_id.as_deref())?;
                tx.execute("UPDATE connections SET folder_id = ?2, position = ?3 WHERE id = ?1", (key, &folder_id, position))?;
            } else {
                let position = next_position(tx, Items::System, folder_id.as_deref())?;
                tx.execute(
                    "INSERT INTO system_items(service_id, folder_id, color, position) VALUES (?1, ?2, NULL, ?3)
                     ON CONFLICT(service_id) DO UPDATE SET folder_id = excluded.folder_id, position = excluded.position",
                    (key, &folder_id, position),
                )?;
            }
            Ok(())
        })
    }

    /// An item's own colour; `None` is "Use folder colour". `key` as in [`Vault::set_item_folder`].
    pub fn set_item_color(&mut self, key: &str, color: Option<FolderColor>) -> Result<(), VaultError> {
        let color = color.map(FolderColor::as_str);
        self.transaction(|tx| {
            if is_managed(tx, key)? {
                tx.execute("UPDATE connections SET color = ?2 WHERE id = ?1", (key, color))?;
            } else {
                let position = next_position(tx, Items::System, None)?;
                tx.execute(
                    "INSERT INTO system_items(service_id, folder_id, color, position) VALUES (?1, NULL, ?2, ?3)
                     ON CONFLICT(service_id) DO UPDATE SET color = excluded.color",
                    (key, color, position),
                )?;
            }
            Ok(())
        })
    }

    /// One `UPDATE folders … WHERE id = ?1` with `?2 = value`; no row is [`TreeError::UnknownFolder`]. `guarded`:
    /// a catalog folder is [`VaultError::CatalogManaged`].
    fn update_folder(
        &mut self,
        id: Uuid,
        guarded: bool,
        sql: &str,
        value: impl rusqlite::ToSql,
    ) -> Result<(), VaultError> {
        self.transaction(|tx| {
            if guarded {
                guard_folder(tx, id)?;
            }
            match tx.execute(sql, (uuid_string(&id), value))? {
                0 => Err(TreeError::UnknownFolder(id).into()),
                _ => Ok(()),
            }
        })
    }
}

fn parse_id(s: &str) -> Result<Uuid, VaultError> {
    Uuid::parse_str(s).map_err(|_| VaultError::Corrupt("invalid folder id".into()))
}

fn load_folders(conn: &Connection) -> Result<Vec<FolderNode>, VaultError> {
    let mut stmt = conn.prepare("SELECT id, parent_id, name, color, position, collapsed FROM folders")?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, i64>(4)?,
            r.get::<_, bool>(5)?,
        ))
    })?;
    let mut folders = Vec::new();
    for row in rows {
        let (id, parent, name, color, position, collapsed) = row?;
        folders.push(FolderNode {
            id: parse_id(&id)?,
            parent: parent.as_deref().map(parse_id).transpose()?,
            name,
            color: color.as_deref().and_then(FolderColor::parse),
            position,
            collapsed,
        });
    }
    Ok(folders)
}

fn load_tree(conn: &Connection) -> Result<FolderTree, VaultError> {
    FolderTree::new(load_folders(conn)?).map_err(|e| VaultError::Corrupt(format!("folder tree: {e}")))
}

fn folder_exists(conn: &Connection, folder: Uuid) -> Result<bool, VaultError> {
    let found: Option<i64> =
        conn.query_row("SELECT 1 FROM folders WHERE id = ?1", [uuid_string(&folder)], |r| r.get(0)).optional()?;
    Ok(found.is_some())
}

/// Whether `key` is a stored managed connection.
fn is_managed(conn: &Connection, key: &str) -> Result<bool, VaultError> {
    let found: Option<i64> =
        conn.query_row("SELECT 1 FROM connections WHERE id = ?1", [key], |r| r.get(0)).optional()?;
    Ok(found.is_some())
}

/// Sets `parent` and the positions `0..n` of `folders`, in that order.
fn place_folders(conn: &Connection, parent: Option<Uuid>, folders: &[Uuid]) -> Result<(), VaultError> {
    let parent = parent.map(|p| uuid_string(&p));
    let mut stmt = conn.prepare("UPDATE folders SET parent_id = ?2, position = ?3 WHERE id = ?1")?;
    for (position, id) in folders.iter().enumerate() {
        stmt.execute((uuid_string(id), &parent, position as i64))?;
    }
    Ok(())
}

/// The next append position in `folder` (`None`: the root).
fn next_position(conn: &Connection, items: Items, folder: Option<&str>) -> Result<i64, VaultError> {
    let sql = format!("SELECT COALESCE(MAX(position) + 1, 0) FROM {} WHERE folder_id IS ?1", items.table());
    Ok(conn.query_row(&sql, [folder], |r| r.get(0))?)
}

/// The keys of the items directly in `folder`, in stored order.
fn items_in(conn: &Connection, items: Items, folder: Uuid) -> Result<Vec<String>, VaultError> {
    let sql = format!("SELECT {} FROM {} WHERE folder_id = ?1 ORDER BY position, {0}", items.key(), items.table());
    let mut stmt = conn.prepare(&sql)?;
    let keys = stmt.query_map([uuid_string(&folder)], |r| r.get::<_, String>(0))?.collect::<Result<_, _>>()?;
    Ok(keys)
}

/// Moves the items directly in `from` to the end of `to` (`None`: the root), keeping their relative order.
fn move_items(conn: &Connection, items: Items, from: Uuid, to: Option<Uuid>) -> Result<(), VaultError> {
    let to = to.map(|t| uuid_string(&t));
    let first = next_position(conn, items, to.as_deref())?;
    let sql = format!("UPDATE {} SET folder_id = ?2, position = ?3 WHERE {} = ?1", items.table(), items.key());
    let mut stmt = conn.prepare(&sql)?;
    for (position, key) in (first..).zip(items_in(conn, items, from)?) {
        stmt.execute((key, &to, position))?;
    }
    Ok(())
}
