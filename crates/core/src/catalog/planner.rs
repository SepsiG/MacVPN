//! The pure apply/diff planner (plan Tasks 6 and 7): from what the vault holds for one subscription
//! ([`LocalCatalog`]) and a new catalog version to the operations that bring the vault there ([`plan_apply`]),
//! plus unsubscribing ([`plan_unsubscribe`]) and the deferred removals of connections that were up
//! ([`plan_pending`]). No I/O: the vault's executor (`vault/catalog_apply.rs`) runs the plan in one transaction.
//!
//! "Changed" means a different config hash (config and native settings: [`config_hash`]) or meta hash (name,
//! folder, colour, OTP setting, slot, secret references and the referenced values: [`meta_hash`]); an unchanged
//! item yields no op. The summary counts connections only.

use super::ids::{CatalogItemKind, local_id};
use super::payload::{CatalogConnection, CatalogFolder, CatalogPayload};
use crate::models::{SecretField, uuid_string};
use crate::vault::FolderColor;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use uuid::Uuid;

/// One catalog-owned row (`catalog_items`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalItem {
    /// The `connections.id` or `folders.id`.
    pub local_id: Uuid,
    /// The publisher's item id.
    pub item_id: Uuid,
    pub kind: CatalogItemKind,
    pub config_hash: Option<String>,
    pub meta_hash: String,
    pub pending_removal: bool,
    pub slot_id: Option<Uuid>,
    /// The secret fields the catalog wrote.
    pub provided: BTreeSet<SecretField>,
    /// Folders: the local id of the parent folder (the catalog root for a top-level folder), for the
    /// children-first order of removals. `None` for connections and the root.
    pub parent: Option<Uuid>,
}

/// Everything the vault holds for one subscription.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCatalog {
    pub catalog_id: Uuid,
    pub name: String,
    pub root_folder: Uuid,
    /// Folders and connections (not the root), sorted by local id.
    pub items: Vec<LocalItem>,
    /// Slot id → (name, the shared credential that holds the user's login, once created).
    pub slots: BTreeMap<Uuid, (String, Option<Uuid>)>,
}

// MARK: - the pure planner (plan Task 7)

/// One step of an apply, in the order the executor runs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogOp {
    RenameRoot {
        name: String,
    },
    UpsertFolder {
        local_id: Uuid,
        parent: Uuid,
        name: String,
        color: Option<FolderColor>,
        position: i64,
    },
    RemoveFolder {
        local_id: Uuid,
    },
    /// The payload entry is looked up by its item id.
    AddConnection {
        local_id: Uuid,
        item: Uuid,
    },
    UpdateConnection {
        local_id: Uuid,
        item: Uuid,
        config_changed: bool,
        native_changed: bool,
    },
    /// A removed connection that is up: kept (moved to the catalog root) until it leaves the active states.
    MarkPendingRemoval {
        local_id: Uuid,
        folder_to: Uuid,
    },
    RemoveConnection {
        local_id: Uuid,
    },
    SetProvidedSecret {
        local_id: Uuid,
        field: SecretField,
        secret: Uuid,
    },
    ClearProvidedSecret {
        local_id: Uuid,
        field: SecretField,
    },
    UpsertSlot {
        slot: Uuid,
        name: String,
    },
    RemoveSlot {
        slot: Uuid,
    },
    LinkSlot {
        local_id: Uuid,
        slot: Uuid,
    },
    UnlinkSlot {
        local_id: Uuid,
    },
}

/// What an apply did to the catalog's connections (folders and slots are not counted): the notification text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApplySummary {
    pub added: usize,
    pub changed: usize,
    /// Removed connections, the deferred ones included.
    pub removed: usize,
    /// Removed connections that were up: deleted once they disconnect.
    pub deferred: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApplyPlan {
    pub ops: Vec<CatalogOp>,
    pub summary: ApplySummary,
}

impl ApplyPlan {
    /// Whether the plan changes nothing.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

const CONFIG_HASH_DOMAIN: &[u8] = b"macvpn-catalog-config-v1\n";
const META_HASH_DOMAIN: &[u8] = b"macvpn-catalog-meta-v1\n";
const FOLDER_HASH_DOMAIN: &[u8] = b"macvpn-catalog-folder-v1\n";
const SECRET_HASH_DOMAIN: &[u8] = b"macvpn-catalog-secret-v1\n";

/// A length-prefixed field, so two different field lists never hash alike.
fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

fn opt_id(id: Option<Uuid>) -> String {
    id.map(|i| uuid_string(&i)).unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 of what the root layer or the native profile gets: the kind, the config and the native settings. Equal
/// hashes mean a byte-identical config, so the subscriber's acknowledgement of risky directives survives.
pub fn config_hash(c: &CatalogConnection) -> String {
    let mut h = Sha256::new();
    h.update(CONFIG_HASH_DOMAIN);
    field(&mut h, c.kind.raw_value().as_bytes());
    field(&mut h, c.config.as_bytes());
    match &c.native {
        None => field(&mut h, b""),
        Some(n) => {
            field(&mut h, b"native");
            field(&mut h, n.server.as_bytes());
            field(&mut h, n.account.as_bytes());
            field(&mut h, n.group_name.as_bytes());
            field(&mut h, &[u8::from(n.send_all_traffic)]);
        }
    }
    hex(&h.finalize())
}

/// SHA-256 of the rest a catalog connection carries: name, folder, colour, OTP setting, slot and the secret
/// references, with a hash of each referenced team secret's value (so a team PSK that changes under the same id is
/// written again).
pub fn meta_hash(c: &CatalogConnection, payload: &CatalogPayload) -> String {
    let mut h = Sha256::new();
    h.update(META_HASH_DOMAIN);
    field(&mut h, c.name.as_bytes());
    field(&mut h, opt_id(c.folder).as_bytes());
    field(&mut h, c.color.map_or("", FolderColor::as_str).as_bytes());
    field(&mut h, &[u8::from(c.otp.enabled)]);
    field(&mut h, c.otp.separator.raw_value().as_bytes());
    field(&mut h, opt_id(c.slot).as_bytes());
    for (f, secret) in &c.secret_refs {
        field(&mut h, f.raw_value().as_bytes());
        field(&mut h, uuid_string(secret).as_bytes());
        let mut v = Sha256::new();
        v.update(SECRET_HASH_DOMAIN);
        v.update(payload.shared_secrets.get(secret).map_or(&b""[..], |s| s.as_bytes()));
        field(&mut h, &v.finalize());
    }
    hex(&h.finalize())
}

/// SHA-256 of a folder's name, parent, colour and position.
pub fn folder_hash(f: &CatalogFolder) -> String {
    let mut h = Sha256::new();
    h.update(FOLDER_HASH_DOMAIN);
    field(&mut h, f.name.as_bytes());
    field(&mut h, opt_id(f.parent).as_bytes());
    field(&mut h, f.color.map_or("", FolderColor::as_str).as_bytes());
    field(&mut h, &f.position.to_be_bytes());
    hex(&h.finalize())
}

/// The payload's folders, parents first (siblings by position, then id). A folder whose parent is missing (never
/// in a validated payload) comes last.
fn folders_parents_first(new: &CatalogPayload) -> Vec<&CatalogFolder> {
    let mut out: Vec<&CatalogFolder> = Vec::new();
    let mut placed: HashSet<Uuid> = HashSet::new();
    let mut level: Vec<Option<Uuid>> = vec![None];
    while !level.is_empty() {
        let mut next = Vec::new();
        for parent in level {
            let mut children: Vec<&CatalogFolder> =
                new.folders.iter().filter(|f| f.parent == parent && !placed.contains(&f.id)).collect();
            children.sort_by_key(|f| (f.position, f.id));
            for f in children {
                placed.insert(f.id);
                out.push(f);
                next.push(Some(f.id));
            }
        }
        level = next;
    }
    out.extend(new.folders.iter().filter(|f| !placed.contains(&f.id)));
    out
}

/// The local folders, children first (deepest first, by the stored parents).
fn folders_children_first<'a>(items: impl Iterator<Item = &'a LocalItem>, all: &[LocalItem]) -> Vec<Uuid> {
    let parent: BTreeMap<Uuid, Option<Uuid>> =
        all.iter().filter(|i| i.kind == CatalogItemKind::Folder).map(|i| (i.local_id, i.parent)).collect();
    let depth = |mut id: Uuid| {
        let mut d = 0usize;
        while let Some(Some(p)) = parent.get(&id) {
            d += 1;
            id = *p;
            if d > parent.len() {
                break;
            }
        }
        d
    };
    let mut out: Vec<(usize, Uuid)> = items.map(|i| (depth(i.local_id), i.local_id)).collect();
    out.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    out.into_iter().map(|(_, id)| id).collect()
}

/// The diff between what the vault holds (`old`) and a new catalog version: every op that brings the vault to
/// the new version, ordered so every reference exists when it is used. `active`: the local ids of the catalog's
/// connections that are up (a removed one is only marked; a changed one is updated at once, since the running
/// tunnel already has its config).
pub fn plan_apply(old: &LocalCatalog, new_name: &str, new: &CatalogPayload, active: &HashSet<Uuid>) -> ApplyPlan {
    let cat = old.catalog_id;
    let mut ops = Vec::new();
    let mut summary = ApplySummary::default();
    if new_name != old.name {
        ops.push(CatalogOp::RenameRoot { name: new_name.to_string() });
    }
    let existing: BTreeMap<(CatalogItemKind, Uuid), &LocalItem> =
        old.items.iter().map(|i| ((i.kind, i.item_id), i)).collect();

    // Folders, parents first.
    let folder_local = |item: Uuid| local_id(cat, CatalogItemKind::Folder, item);
    for f in folders_parents_first(new) {
        let hash = folder_hash(f);
        if existing.get(&(CatalogItemKind::Folder, f.id)).is_some_and(|i| i.meta_hash == hash) {
            continue;
        }
        ops.push(CatalogOp::UpsertFolder {
            local_id: folder_local(f.id),
            parent: f.parent.map_or(old.root_folder, folder_local),
            name: f.name.clone(),
            color: f.color,
            position: f.position,
        });
    }

    // Slots.
    for s in &new.credential_slots {
        if old.slots.get(&s.id).is_none_or(|(name, _)| *name != s.name) {
            ops.push(CatalogOp::UpsertSlot { slot: s.id, name: s.name.clone() });
        }
    }

    // Connections, then their secrets, then their links.
    let mut secret_ops = Vec::new();
    let mut link_ops = Vec::new();
    for c in &new.connections {
        let local = local_id(cat, CatalogItemKind::Connection, c.id);
        let config = config_hash(c);
        let meta = meta_hash(c, new);
        let (old_provided, old_slot) = match existing.get(&(CatalogItemKind::Connection, c.id)) {
            None => {
                ops.push(CatalogOp::AddConnection { local_id: local, item: c.id });
                summary.added += 1;
                (BTreeSet::new(), None)
            }
            Some(item) => {
                let config_changed = item.config_hash.as_deref() != Some(config.as_str());
                if !config_changed && item.meta_hash == meta && !item.pending_removal {
                    continue;
                }
                ops.push(CatalogOp::UpdateConnection {
                    local_id: local,
                    item: c.id,
                    config_changed,
                    native_changed: config_changed && c.kind.is_native(),
                });
                summary.changed += 1;
                (item.provided.clone(), item.slot_id)
            }
        };
        for (field, secret) in &c.secret_refs {
            secret_ops.push(CatalogOp::SetProvidedSecret { local_id: local, field: *field, secret: *secret });
        }
        for field in old_provided.iter().filter(|f| !c.secret_refs.contains_key(f)) {
            secret_ops.push(CatalogOp::ClearProvidedSecret { local_id: local, field: *field });
        }
        match (old_slot, c.slot) {
            (old, Some(slot)) if old != Some(slot) => link_ops.push(CatalogOp::LinkSlot { local_id: local, slot }),
            (Some(_), None) => link_ops.push(CatalogOp::UnlinkSlot { local_id: local }),
            _ => {}
        }
    }
    ops.extend(secret_ops);
    ops.extend(link_ops);

    // Removals: connections, then folders children first, then slots.
    let new_connections: HashSet<Uuid> = new.connections.iter().map(|c| c.id).collect();
    for item in old.items.iter().filter(|i| i.kind == CatalogItemKind::Connection) {
        if new_connections.contains(&item.item_id) {
            continue;
        }
        if active.contains(&item.local_id) {
            if !item.pending_removal {
                ops.push(CatalogOp::MarkPendingRemoval { local_id: item.local_id, folder_to: old.root_folder });
                summary.removed += 1;
                summary.deferred += 1;
            }
        } else {
            ops.push(CatalogOp::RemoveConnection { local_id: item.local_id });
            if !item.pending_removal {
                summary.removed += 1;
            }
        }
    }
    let new_folders: HashSet<Uuid> = new.folders.iter().map(|f| f.id).collect();
    let gone = old.items.iter().filter(|i| i.kind == CatalogItemKind::Folder && !new_folders.contains(&i.item_id));
    for local in folders_children_first(gone, &old.items) {
        ops.push(CatalogOp::RemoveFolder { local_id: local });
    }
    let new_slots: HashSet<Uuid> = new.credential_slots.iter().map(|s| s.id).collect();
    for slot in old.slots.keys().filter(|s| !new_slots.contains(s)) {
        ops.push(CatalogOp::RemoveSlot { slot: *slot });
    }
    ApplyPlan { ops, summary }
}

/// Unsubscribing: every connection and folder (children first) and every slot removed. The root folder and the
/// subscription row are removed by the executor.
pub fn plan_unsubscribe(old: &LocalCatalog) -> ApplyPlan {
    let mut ops = Vec::new();
    let mut summary = ApplySummary::default();
    for item in old.items.iter().filter(|i| i.kind == CatalogItemKind::Connection) {
        ops.push(CatalogOp::RemoveConnection { local_id: item.local_id });
        summary.removed += 1;
    }
    let folders = old.items.iter().filter(|i| i.kind == CatalogItemKind::Folder);
    for local in folders_children_first(folders, &old.items) {
        ops.push(CatalogOp::RemoveFolder { local_id: local });
    }
    for slot in old.slots.keys() {
        ops.push(CatalogOp::RemoveSlot { slot: *slot });
    }
    ApplyPlan { ops, summary }
}

/// The pending removals whose connection is no longer up.
pub fn plan_pending(old: &LocalCatalog, active: &HashSet<Uuid>) -> ApplyPlan {
    let ops: Vec<CatalogOp> = old
        .items
        .iter()
        .filter(|i| i.kind == CatalogItemKind::Connection && i.pending_removal && !active.contains(&i.local_id))
        .map(|i| CatalogOp::RemoveConnection { local_id: i.local_id })
        .collect();
    ApplyPlan { ops, summary: ApplySummary::default() }
}
