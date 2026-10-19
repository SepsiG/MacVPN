//! Folders and colours in the app (spec 3, plan B Task 16): the folder stores, the system-VPN placement retention,
//! the folder commands' validation and orchestration, and the import's folder path.
//!
//! - [`VaultFolders`]: the [`FolderStore`] over the vault lifecycle (reads through [`VaultLifecycle::with_read`],
//!   writes through [`VaultLifecycle::with`]); locked, every call fails with a message saying so.
//! - [`MemoryFolders`]: the same rules in memory, for the sandbox and the tests. It is told which keys are managed
//!   connections, so it answers a delete exactly like the vault (managed keys returned, system VPNs to the root).
//! - The commands ([`create`], [`rename`], …) validate their input (UUID-shaped ids of existing folders, a palette
//!   colour or none, the folder-name rule), apply the edit and reload the manager's folder state. "Delete the
//!   connections too" deletes the returned connections one by one through [`ConnectionsModel::delete`], so the
//!   profile and secret clean-up is today's, and is refused while any of them is active.
//!
//! Items are keyed like the ranking: a managed connection's upper-case UUID string or a system VPN's service ID.
//! Items have no manual order: dropping one only changes its folder (plan B, "Resolved").

use crate::connections::ConnectionsModel;
use crate::deps::{FolderOp, FolderOpResult, FolderStore, Placement, SystemItemChange};
use crate::manager::ConnectionManager;
use crate::vault::VaultLifecycle;
use macvpn_core::date::Date;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::{Connection, uuid_string};
use macvpn_core::vault::{
    DeleteMode, FolderColor, FolderNode, FolderTree, SystemItem, TreeError, VaultError, validate_folder_name,
};
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex, PoisonError};
use uuid::Uuid;

/// How long a system VPN that macOS no longer lists keeps its folder and colour (spec 5).
pub const SYSTEM_ITEM_RETENTION_DAYS: f64 = 30.0;

/// The retention changes after a listing: a placed service not in `listed` gets `missing_since = now` (if unset),
/// one listed again gets it cleared, one missing for longer than [`SYSTEM_ITEM_RETENTION_DAYS`] is removed.
pub fn retention(items: &[SystemItem], listed: &HashSet<String>, now: Date) -> Vec<SystemItemChange> {
    let limit = SYSTEM_ITEM_RETENTION_DAYS * 86_400.0;
    items
        .iter()
        .filter_map(|item| {
            let service_id = item.service_id.clone();
            match (listed.contains(&item.service_id), item.missing_since) {
                (true, Some(_)) => Some(SystemItemChange::Clear { service_id }),
                (true, None) => None,
                (false, None) => Some(SystemItemChange::MarkMissing { service_id, since: now }),
                (false, Some(since)) if now.time_interval_since(since) > limit => {
                    Some(SystemItemChange::Remove { service_id })
                }
                (false, Some(_)) => None,
            }
        })
        .collect()
}

// MARK: - Messages

fn tree_message(e: TreeError) -> String {
    match e {
        TreeError::Cycle => l10n::tr("A folder cannot be moved into itself or one of its subfolders", &[]),
        TreeError::UnknownFolder(_) => l10n::tr("This folder no longer exists", &[]),
        TreeError::InvalidName => l10n::tr("A folder name needs 1 to 64 characters and no control characters", &[]),
    }
}

/// The user-facing message of a failed folder edit.
pub fn vault_message(e: &VaultError) -> String {
    match e {
        VaultError::Tree(tree) => tree_message(*tree),
        VaultError::Locked => l10n::tr("Folders cannot be changed while the vault is locked", &[]),
        VaultError::ReadOnly => crate::vault_stores::read_only_message(),
        other => l10n::tr("The folder change failed: %@", &[Arg::Str(&other.to_string())]),
    }
}

fn io_error(message: String) -> io::Error {
    io::Error::other(message)
}

fn vault_io(e: VaultError) -> io::Error {
    io_error(vault_message(&e))
}

fn tree_io(e: TreeError) -> io::Error {
    io_error(tree_message(e))
}

// MARK: - The vault store

/// The folders in the vault (`folders` table, the placement columns of `connections` and `system_items`).
pub struct VaultFolders {
    vault: Arc<VaultLifecycle>,
}

impl VaultFolders {
    pub fn new(vault: Arc<VaultLifecycle>) -> Self {
        VaultFolders { vault }
    }
}

impl FolderStore for VaultFolders {
    fn folders(&self) -> io::Result<Vec<FolderNode>> {
        self.vault.with_read(|v| v.folders()).map_err(vault_io)
    }

    fn placements(&self) -> io::Result<Vec<Placement>> {
        self.vault
            .with_read(|v| {
                let managed = v.connections()?.into_iter().map(|c| Placement {
                    key: uuid_string(&c.connection.id),
                    folder: c.folder_id,
                    color: c.color,
                });
                let system = v.system_items()?.into_iter().map(|s| Placement {
                    key: s.service_id,
                    folder: s.folder_id,
                    color: s.color,
                });
                Ok(managed.chain(system).filter(|p| p.folder.is_some() || p.color.is_some()).collect())
            })
            .map_err(vault_io)
    }

    fn system_items(&self) -> io::Result<Vec<SystemItem>> {
        self.vault.with_read(|v| v.system_items()).map_err(vault_io)
    }

    fn apply(&self, op: FolderOp) -> io::Result<FolderOpResult> {
        self.vault
            .with(|v| match op {
                FolderOp::Create { parent, name } => v.create_folder(parent, &name).map(FolderOpResult::Created),
                FolderOp::Rename { id, name } => v.rename_folder(id, &name).map(|()| FolderOpResult::Done),
                FolderOp::SetColor { id, color } => v.set_folder_color(id, color).map(|()| FolderOpResult::Done),
                FolderOp::SetCollapsed { id, collapsed } => {
                    v.set_collapsed(id, collapsed).map(|()| FolderOpResult::Done)
                }
                FolderOp::Move { id, parent, position } => {
                    v.move_folder(id, parent, position).map(|()| FolderOpResult::Done)
                }
                FolderOp::Delete { id, mode } => {
                    v.delete_folder(id, mode).map(|ids| FolderOpResult::Deleted(ids.iter().map(uuid_string).collect()))
                }
                FolderOp::MoveItem { key, folder } => v.set_item_folder(&key, folder).map(|()| FolderOpResult::Done),
                FolderOp::SetItemColor { key, color } => v.set_item_color(&key, color).map(|()| FolderOpResult::Done),
                FolderOp::Retention(changes) => {
                    let items: HashMap<String, SystemItem> =
                        v.system_items()?.into_iter().map(|s| (s.service_id.clone(), s)).collect();
                    for change in changes {
                        match change {
                            SystemItemChange::MarkMissing { service_id, since } => {
                                if let Some(item) = items.get(&service_id) {
                                    v.save_system_item(&SystemItem { missing_since: Some(since), ..item.clone() })?;
                                }
                            }
                            SystemItemChange::Clear { service_id } => {
                                if let Some(item) = items.get(&service_id) {
                                    v.save_system_item(&SystemItem { missing_since: None, ..item.clone() })?;
                                }
                            }
                            SystemItemChange::Remove { service_id } => v.delete_system_item(&service_id)?,
                        }
                    }
                    Ok(FolderOpResult::Done)
                }
            })
            .map_err(vault_io)
    }
}

// MARK: - The in-memory store

#[derive(Default)]
struct MemoryState {
    folders: Vec<FolderNode>,
    /// Managed connections and system VPNs alike, by key.
    items: HashMap<String, Placement>,
    /// `missing_since` of the system VPNs (retention).
    missing: HashMap<String, Date>,
}

/// The folder rules of the vault store, in memory (the sandbox, tests). `is_managed` tells the managed connections'
/// keys from the system VPNs' (the vault knows by its `connections` table).
pub struct MemoryFolders {
    state: Mutex<MemoryState>,
    is_managed: Box<dyn Fn(&str) -> bool + Send + Sync>,
}

impl MemoryFolders {
    pub fn new(is_managed: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        MemoryFolders { state: Mutex::default(), is_managed: Box::new(is_managed) }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, MemoryState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn tree_of(folders: &[FolderNode]) -> io::Result<FolderTree> {
    FolderTree::new(folders.to_vec()).map_err(tree_io)
}

/// Sets `parent` and the positions `0..n` of `ids` (the vault's `place_folders`).
fn place(folders: &mut [FolderNode], parent: Option<Uuid>, ids: &[Uuid]) {
    for (position, id) in ids.iter().enumerate() {
        if let Some(node) = folders.iter_mut().find(|f| f.id == *id) {
            node.parent = parent;
            node.position = position as i64;
        }
    }
}

impl FolderStore for MemoryFolders {
    fn folders(&self) -> io::Result<Vec<FolderNode>> {
        Ok(self.state().folders.clone())
    }

    fn placements(&self) -> io::Result<Vec<Placement>> {
        let mut out: Vec<Placement> =
            self.state().items.values().filter(|p| p.folder.is_some() || p.color.is_some()).cloned().collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    fn system_items(&self) -> io::Result<Vec<SystemItem>> {
        let s = self.state();
        let mut out: Vec<SystemItem> = s
            .items
            .values()
            .filter(|p| !(self.is_managed)(&p.key))
            .map(|p| SystemItem {
                service_id: p.key.clone(),
                folder_id: p.folder,
                color: p.color,
                position: 0,
                missing_since: s.missing.get(&p.key).copied(),
            })
            .collect();
        out.sort_by(|a, b| a.service_id.cmp(&b.service_id));
        Ok(out)
    }

    fn apply(&self, op: FolderOp) -> io::Result<FolderOpResult> {
        let mut s = self.state();
        let tree = tree_of(&s.folders)?;
        let known = |id: Uuid| if tree.contains(id) { Ok(()) } else { Err(tree_io(TreeError::UnknownFolder(id))) };
        let name_of = |name: &str| validate_folder_name(name).map_err(tree_io);
        match op {
            FolderOp::Create { parent, name } => {
                let name = name_of(&name)?;
                if let Some(parent) = parent {
                    known(parent)?;
                }
                let position = tree.children(parent).last().and_then(|l| tree.get(*l)).map_or(0, |n| n.position + 1);
                let id = Uuid::new_v4();
                s.folders.push(FolderNode { id, parent, name, color: None, position, collapsed: false });
                Ok(FolderOpResult::Created(id))
            }
            FolderOp::Rename { id, name } => {
                let name = name_of(&name)?;
                known(id)?;
                s.folders.iter_mut().filter(|f| f.id == id).for_each(|f| f.name = name.clone());
                Ok(FolderOpResult::Done)
            }
            FolderOp::SetColor { id, color } => {
                known(id)?;
                s.folders.iter_mut().filter(|f| f.id == id).for_each(|f| f.color = color);
                Ok(FolderOpResult::Done)
            }
            FolderOp::SetCollapsed { id, collapsed } => {
                known(id)?;
                s.folders.iter_mut().filter(|f| f.id == id).for_each(|f| f.collapsed = collapsed);
                Ok(FolderOpResult::Done)
            }
            FolderOp::Move { id, parent, position } => {
                tree.check_move(id, parent).map_err(tree_io)?;
                let old_parent = tree.get(id).and_then(|n| n.parent);
                let mut siblings: Vec<Uuid> = tree.children(parent).iter().copied().filter(|c| *c != id).collect();
                siblings.insert(position.min(siblings.len()), id);
                place(&mut s.folders, parent, &siblings);
                if old_parent != parent {
                    let rest: Vec<Uuid> = tree.children(old_parent).iter().copied().filter(|c| *c != id).collect();
                    place(&mut s.folders, old_parent, &rest);
                }
                Ok(FolderOpResult::Done)
            }
            FolderOp::Delete { id, mode } => {
                known(id)?;
                let parent = tree.get(id).and_then(|n| n.parent);
                let mut deleted = Vec::new();
                match mode {
                    DeleteMode::MoveContentsUp => {
                        let mut siblings: Vec<Uuid> =
                            tree.children(parent).iter().copied().filter(|c| *c != id).collect();
                        siblings.extend(tree.children(Some(id)));
                        place(&mut s.folders, parent, &siblings);
                        s.items.values_mut().filter(|p| p.folder == Some(id)).for_each(|p| p.folder = parent);
                        s.folders.retain(|f| f.id != id);
                    }
                    DeleteMode::DeleteContents => {
                        let subtree: HashSet<Uuid> = std::iter::once(id).chain(tree.descendants(id)).collect();
                        for p in s.items.values_mut().filter(|p| p.folder.is_some_and(|f| subtree.contains(&f))) {
                            if (self.is_managed)(&p.key) {
                                deleted.push(p.key.clone());
                            } else {
                                p.folder = None;
                            }
                        }
                        deleted.sort();
                        for key in &deleted {
                            s.items.remove(key);
                        }
                        s.folders.retain(|f| !subtree.contains(&f.id));
                    }
                }
                Ok(match mode {
                    DeleteMode::MoveContentsUp => FolderOpResult::Done,
                    DeleteMode::DeleteContents => FolderOpResult::Deleted(deleted),
                })
            }
            FolderOp::MoveItem { key, folder } => {
                if let Some(folder) = folder {
                    known(folder)?;
                }
                s.items.entry(key.clone()).or_insert(Placement { key, folder: None, color: None }).folder = folder;
                Ok(FolderOpResult::Done)
            }
            FolderOp::SetItemColor { key, color } => {
                s.items.entry(key.clone()).or_insert(Placement { key, folder: None, color: None }).color = color;
                Ok(FolderOpResult::Done)
            }
            FolderOp::Retention(changes) => {
                for change in changes {
                    match change {
                        SystemItemChange::MarkMissing { service_id, since } => {
                            s.missing.insert(service_id, since);
                        }
                        SystemItemChange::Clear { service_id } => {
                            s.missing.remove(&service_id);
                        }
                        SystemItemChange::Remove { service_id } => {
                            s.missing.remove(&service_id);
                            s.items.remove(&service_id);
                        }
                    }
                }
                Ok(FolderOpResult::Done)
            }
        }
    }
}

// MARK: - Commands

fn store(m: &ConnectionManager) -> Result<Arc<dyn FolderStore>, String> {
    m.folder_store().ok_or_else(|| l10n::tr("Folders are not available", &[]))
}

/// A UUID-shaped id of a folder the manager knows.
fn folder_id(m: &ConnectionManager, id: &str) -> Result<Uuid, String> {
    Uuid::parse_str(id)
        .ok()
        .filter(|id| m.folder_tree().contains(*id))
        .ok_or_else(|| tree_message(TreeError::UnknownFolder(Uuid::nil())))
}

fn parent_id(m: &ConnectionManager, parent: Option<&str>) -> Result<Option<Uuid>, String> {
    parent.map(|p| folder_id(m, p)).transpose()
}

/// A palette colour's storage id, or `None` (no colour / "Use folder colour").
pub fn parse_color(color: Option<&str>) -> Result<Option<FolderColor>, String> {
    color.map(|c| FolderColor::parse(c).ok_or_else(|| l10n::tr("Unknown colour", &[]))).transpose()
}

/// `moveUp` (the default in the UI) or `deleteContents`.
pub fn parse_delete_mode(mode: &str) -> Result<DeleteMode, String> {
    match mode {
        "moveUp" => Ok(DeleteMode::MoveContentsUp),
        "deleteContents" => Ok(DeleteMode::DeleteContents),
        _ => Err(l10n::tr("Unknown delete option", &[])),
    }
}

fn name(name: &str) -> Result<String, String> {
    validate_folder_name(name).map_err(tree_message)
}

/// An item the manager lists (a managed connection or a system VPN).
fn item_key(m: &ConnectionManager, key: &str) -> Result<String, String> {
    m.item(key).map(|_| key.to_string()).ok_or_else(|| l10n::tr("This connection no longer exists", &[]))
}

fn run(m: &ConnectionManager, op: FolderOp) -> Result<FolderOpResult, String> {
    let result = store(m)?.apply(op).map_err(|e| e.to_string());
    m.reload_folders();
    result
}

/// "New folder" in `parent` (`None`: the root): the new folder's id.
pub fn create(m: &ConnectionManager, parent: Option<&str>, folder_name: &str) -> Result<String, String> {
    let op = FolderOp::Create { parent: parent_id(m, parent)?, name: name(folder_name)? };
    match run(m, op)? {
        FolderOpResult::Created(id) => Ok(uuid_string(&id)),
        _ => Err(l10n::tr("Folders are not available", &[])),
    }
}

pub fn rename(m: &ConnectionManager, id: &str, folder_name: &str) -> Result<(), String> {
    run(m, FolderOp::Rename { id: folder_id(m, id)?, name: name(folder_name)? }).map(drop)
}

pub fn set_color(m: &ConnectionManager, id: &str, color: Option<&str>) -> Result<(), String> {
    run(m, FolderOp::SetColor { id: folder_id(m, id)?, color: parse_color(color)? }).map(drop)
}

pub fn set_collapsed(m: &ConnectionManager, id: &str, collapsed: bool) -> Result<(), String> {
    run(m, FolderOp::SetCollapsed { id: folder_id(m, id)?, collapsed }).map(drop)
}

/// Moves (or reorders) a folder: under `parent` at `position` among its subfolders. Into itself or a descendant
/// is refused before the store is asked.
pub fn move_folder(m: &ConnectionManager, id: &str, parent: Option<&str>, position: usize) -> Result<(), String> {
    let id = folder_id(m, id)?;
    let parent = parent_id(m, parent)?;
    m.folder_tree().check_move(id, parent).map_err(tree_message)?;
    run(m, FolderOp::Move { id, parent, position }).map(drop)
}

pub fn move_item(m: &ConnectionManager, key: &str, folder: Option<&str>) -> Result<(), String> {
    run(m, FolderOp::MoveItem { key: item_key(m, key)?, folder: parent_id(m, folder)? }).map(drop)
}

pub fn set_item_color(m: &ConnectionManager, key: &str, color: Option<&str>) -> Result<(), String> {
    run(m, FolderOp::SetItemColor { key: item_key(m, key)?, color: parse_color(color)? }).map(drop)
}

/// The managed connections in the folder and all its subfolders (what "Delete the connections too" deletes).
pub fn managed_in(m: &ConnectionManager, folder: Uuid) -> Vec<Connection> {
    let tree = m.folder_tree();
    let subtree: HashSet<Uuid> = std::iter::once(folder).chain(tree.descendants(folder)).collect();
    m.connections()
        .into_iter()
        .filter(|c| m.placement(&uuid_string(&c.id)).and_then(|p| p.folder).is_some_and(|f| subtree.contains(&f)))
        .collect()
}

/// Deletes a folder. `moveUp`: its subfolders and items go to its parent. `deleteContents`: refused while one of
/// the connections in it is active; otherwise the folder and its subfolders go, the managed connections in them
/// are deleted through [`ConnectionsModel::delete`] (returned, for the app's clean-up), and the system VPNs move
/// to the root.
pub fn delete(
    m: &ConnectionManager,
    connections: &ConnectionsModel,
    id: &str,
    mode: &str,
) -> Result<Vec<Connection>, String> {
    let id = folder_id(m, id)?;
    let mode = parse_delete_mode(mode)?;
    if mode == DeleteMode::DeleteContents && managed_in(m, id).iter().any(|c| m.state(&uuid_string(&c.id)).is_active())
    {
        return Err(l10n::tr("Disconnect the connections in this folder before deleting them", &[]));
    }
    let FolderOpResult::Deleted(keys) = run(m, FolderOp::Delete { id, mode })? else { return Ok(Vec::new()) };
    let mut deleted = Vec::new();
    for key in keys {
        let managed = m.connections().into_iter().find(|c| uuid_string(&c.id) == key);
        match managed {
            Some(c) => deleted.extend(connections.delete(&c.id)),
            // Not a managed connection after all (a store that cannot tell): kept, at the root.
            None => {
                let _ = run(m, FolderOp::MoveItem { key, folder: None });
            }
        }
    }
    m.reload_folders();
    Ok(deleted)
}

// MARK: - Import

/// The folder for an imported folder path: each component found by name under the previous one (the root
/// first), the missing ones created. `None` for an empty path.
pub fn ensure_path(store: &dyn FolderStore, path: &[String]) -> io::Result<Option<Uuid>> {
    let mut parent: Option<Uuid> = None;
    for component in path {
        let folders = store.folders()?;
        let existing = folders.iter().filter(|f| f.parent == parent && f.name == *component).min_by_key(|f| f.position);
        parent = Some(match existing {
            Some(f) => f.id,
            None => match store.apply(FolderOp::Create { parent, name: component.clone() })? {
                FolderOpResult::Created(id) => id,
                _ => return Err(io_error(l10n::tr("Folders are not available", &[]))),
            },
        });
    }
    Ok(parent)
}

/// Places an imported connection at its exported folder path (recreating the missing folders). Without a store or
/// a path it stays at the root.
pub fn place_imported(m: &ConnectionManager, id: &Uuid, path: Option<&[String]>) -> io::Result<()> {
    let (Some(store), Some(path)) = (m.folder_store(), path) else { return Ok(()) };
    if path.is_empty() {
        return Ok(());
    }
    let folder = ensure_path(store.as_ref(), path)?;
    store.apply(FolderOp::MoveItem { key: uuid_string(id), folder })?;
    m.reload_folders();
    Ok(())
}
