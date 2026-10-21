//! Folder tree, colours and ordering (spec 3, plan B Task 9): the pure tree logic (cycles, colour inheritance,
//! paths, the display order) and the folder repository on the vault (create, rename, colour, collapse, move,
//! delete with both modes, item placement).

mod common;

use common::TempDir;
use macvpn_core::date::Date;
use macvpn_core::models::uuid_string;
use macvpn_core::ranking::{ConnectionRanking, UsageStats};
use macvpn_core::vault::{
    ColorSource, Dek, DeleteMode, FixedEntropy, FolderColor, FolderNode, FolderTree, TreeEntry, TreeError, Vault,
    VaultError, order_tree, validate_folder_name,
};
use std::collections::HashMap;
use std::fs;
use uuid::Uuid;

// ---------------------------------------------------------------------------------------------------------------
// Pure tree

fn id(n: u8) -> Uuid {
    Uuid::from_bytes([n; 16])
}

fn node(n: u8, parent: Option<u8>, name: &str, color: Option<FolderColor>, position: i64) -> FolderNode {
    FolderNode { id: id(n), parent: parent.map(id), name: name.into(), color, position, collapsed: false }
}

/// 1 Work (blue) → 2 Clients (none) → 3 Acme (none); 4 Home (none) at the root.
fn sample() -> FolderTree {
    FolderTree::new(vec![
        node(1, None, "Work", Some(FolderColor::Blue), 0),
        node(2, Some(1), "Clients", None, 0),
        node(3, Some(2), "Acme", None, 0),
        node(4, None, "Home", None, 1),
    ])
    .unwrap()
}

#[test]
fn palette_has_twelve_stable_ids() {
    let ids: Vec<&str> = FolderColor::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(
        ids,
        ["red", "orange", "amber", "yellow", "lime", "green", "teal", "cyan", "blue", "indigo", "purple", "pink"]
    );
    for c in FolderColor::ALL {
        assert_eq!(FolderColor::parse(c.as_str()), Some(c));
    }
    assert_eq!(FolderColor::parse("magenta"), None);
    assert_eq!(FolderColor::parse("Blue"), None);
    assert_eq!(FolderColor::parse(""), None);
}

#[test]
fn folder_colour_own_parent_grandparent_none() {
    let mut folders = vec![
        node(1, None, "Work", Some(FolderColor::Blue), 0),
        node(2, Some(1), "Clients", None, 0),
        node(3, Some(2), "Acme", None, 0),
        node(4, None, "Home", None, 1),
        node(5, Some(1), "Lab", Some(FolderColor::Red), 1),
    ];
    let tree = FolderTree::new(folders.clone()).unwrap();
    assert_eq!(tree.folder_color(id(1)), (Some(FolderColor::Blue), ColorSource::Own));
    assert_eq!(tree.folder_color(id(2)), (Some(FolderColor::Blue), ColorSource::Inherited(id(1))));
    // Through an uncoloured parent.
    assert_eq!(tree.folder_color(id(3)), (Some(FolderColor::Blue), ColorSource::Inherited(id(1))));
    assert_eq!(tree.folder_color(id(4)), (None, ColorSource::None));
    assert_eq!(tree.folder_color(id(5)), (Some(FolderColor::Red), ColorSource::Own));
    // The nearest ancestor wins.
    folders[1].color = Some(FolderColor::Teal);
    let tree = FolderTree::new(folders).unwrap();
    assert_eq!(tree.folder_color(id(3)), (Some(FolderColor::Teal), ColorSource::Inherited(id(2))));
}

#[test]
fn item_colour_override_and_use_folder_colour() {
    let tree = sample();
    // An item in an uncoloured folder inherits from the grandparent.
    assert_eq!(tree.item_color(None, Some(id(3))), (Some(FolderColor::Blue), ColorSource::Inherited(id(1))));
    // Its own colour overrides.
    assert_eq!(tree.item_color(Some(FolderColor::Pink), Some(id(3))), (Some(FolderColor::Pink), ColorSource::Own));
    // "Use folder colour" clears the override: inherited again.
    assert_eq!(tree.item_color(None, Some(id(3))), (Some(FolderColor::Blue), ColorSource::Inherited(id(1))));
    // An item directly in a coloured folder.
    assert_eq!(tree.item_color(None, Some(id(1))), (Some(FolderColor::Blue), ColorSource::Inherited(id(1))));
    // Root, and a folder without any colour up the chain.
    assert_eq!(tree.item_color(None, None), (None, ColorSource::None));
    assert_eq!(tree.item_color(Some(FolderColor::Lime), None), (Some(FolderColor::Lime), ColorSource::Own));
    assert_eq!(tree.item_color(None, Some(id(4))), (None, ColorSource::None));
}

#[test]
fn move_under_itself_or_a_descendant_is_a_cycle() {
    let tree = sample();
    assert_eq!(tree.check_move(id(1), Some(id(1))), Err(TreeError::Cycle));
    assert_eq!(tree.check_move(id(1), Some(id(2))), Err(TreeError::Cycle));
    assert_eq!(tree.check_move(id(1), Some(id(3))), Err(TreeError::Cycle));
    assert_eq!(tree.check_move(id(1), Some(id(4))), Ok(()));
    assert_eq!(tree.check_move(id(3), None), Ok(()));
    assert_eq!(tree.check_move(id(3), Some(id(1))), Ok(()));
    assert_eq!(tree.check_move(id(9), None), Err(TreeError::UnknownFolder(id(9))));
    assert_eq!(tree.check_move(id(1), Some(id(9))), Err(TreeError::UnknownFolder(id(9))));
}

#[test]
fn new_rejects_cycles_and_dangling_parents() {
    let cyclic = vec![node(1, Some(3), "A", None, 0), node(2, Some(1), "B", None, 0), node(3, Some(2), "C", None, 0)];
    assert_eq!(FolderTree::new(cyclic).err(), Some(TreeError::Cycle));
    assert_eq!(FolderTree::new(vec![node(1, Some(1), "Self", None, 0)]).err(), Some(TreeError::Cycle));
    let dangling = vec![node(1, None, "A", None, 0), node(2, Some(7), "B", None, 0)];
    assert_eq!(FolderTree::new(dangling).err(), Some(TreeError::UnknownFolder(id(7))));
    assert!(FolderTree::new(Vec::new()).is_ok());
}

#[test]
fn path_depth_and_descendants() {
    let tree = sample();
    assert_eq!(tree.path(id(3)), ["Work", "Clients", "Acme"]);
    assert_eq!(tree.path(id(4)), ["Home"]);
    assert!(tree.path(id(9)).is_empty());
    assert_eq!(tree.depth(id(1)), 0);
    assert_eq!(tree.depth(id(3)), 2);
    assert_eq!(tree.descendants(id(1)), [id(2), id(3)]);
    assert!(tree.descendants(id(3)).is_empty());
    assert_eq!(tree.children(None), [id(1), id(4)]);
    assert_eq!(tree.get(id(2)).map(|n| n.name.as_str()), Some("Clients"));
}

#[test]
fn folder_names_are_validated() {
    assert_eq!(validate_folder_name("  Office AD  "), Ok("Office AD".into()));
    assert_eq!(validate_folder_name("Ügyfelek"), Ok("Ügyfelek".into()));
    assert_eq!(validate_folder_name(""), Err(TreeError::InvalidName));
    assert_eq!(validate_folder_name("   "), Err(TreeError::InvalidName));
    assert_eq!(validate_folder_name("a\nb"), Err(TreeError::InvalidName));
    assert_eq!(validate_folder_name("a\u{7}b"), Err(TreeError::InvalidName));
    assert_eq!(validate_folder_name("a\u{2028}b"), Err(TreeError::InvalidName));
    // Format characters (bidi controls, zero width) are dropped.
    assert_eq!(validate_folder_name("Wo\u{202E}rk\u{200B}"), Ok("Work".into()));
    assert_eq!(validate_folder_name("\u{200B}"), Err(TreeError::InvalidName));
    let max: String = "é".repeat(64);
    assert_eq!(validate_folder_name(&max), Ok(max.clone()));
    assert_eq!(validate_folder_name(&"é".repeat(65)), Err(TreeError::InvalidName));
}

fn now() -> Date {
    Date::from_time_interval_since_1970(1_800_000_000.0)
}

fn used(score: f64) -> UsageStats {
    UsageStats { score, last_updated: now() }
}

fn folder_entry(n: u8, depth: usize) -> TreeEntry {
    TreeEntry::Folder { id: id(n), depth }
}

fn item_entry(key: &str, depth: usize) -> TreeEntry {
    TreeEntry::Item { key: key.into(), depth }
}

#[test]
fn order_subfolders_first_by_position_then_pins_then_score() {
    // Root: folders B (position 0) and A (position 1); in A: subfolders A2 (1), A1 (0).
    let tree = FolderTree::new(vec![
        node(1, None, "A", None, 1),
        node(2, None, "B", None, 0),
        node(3, Some(1), "A2", None, 1),
        node(4, Some(1), "A1", None, 0),
        node(5, Some(2), "Same", None, 0),
        node(6, Some(2), "Also", None, 0),
    ])
    .unwrap();
    let items: Vec<(String, Option<Uuid>)> = vec![
        ("r-low".into(), None),
        ("r-pin2".into(), None),
        ("r-high".into(), None),
        ("r-pin1".into(), None),
        ("a-x".into(), Some(id(1))),
        ("a-pin".into(), Some(id(1))),
        ("a-y".into(), Some(id(1))),
        ("orphan".into(), Some(id(99))),
    ];
    let usage: HashMap<String, UsageStats> = [
        ("r-low".to_string(), used(1.0)),
        ("r-high".to_string(), used(5.0)),
        ("r-pin2".to_string(), used(9.0)),
        ("a-y".to_string(), used(3.0)),
    ]
    .into_iter()
    .collect();
    let ranking = ConnectionRanking::new(vec!["r-pin1".into(), "a-pin".into(), "r-pin2".into()], usage);
    let order = order_tree(&tree, &items, &ranking, now(), |k| k.to_string());
    assert_eq!(
        order,
        vec![
            folder_entry(2, 0),
            // Equal positions: by name.
            folder_entry(6, 1),
            folder_entry(5, 1),
            folder_entry(1, 0),
            folder_entry(4, 1),
            folder_entry(3, 1),
            item_entry("a-pin", 1),
            item_entry("a-y", 1),
            item_entry("a-x", 1),
            // The root behaves the same: pins in pin order, then by score, then by name. An item whose folder is
            // unknown shows at the root.
            item_entry("r-pin1", 0),
            item_entry("r-pin2", 0),
            item_entry("r-high", 0),
            item_entry("r-low", 0),
            item_entry("orphan", 0),
        ]
    );
}

#[test]
fn order_works_at_depth_five() {
    let folders: Vec<FolderNode> =
        (1..=5).map(|n| node(n, if n == 1 { None } else { Some(n - 1) }, &format!("L{n}"), None, 0)).collect();
    let tree = FolderTree::new(folders).unwrap();
    let items = vec![("deep".to_string(), Some(id(5))), ("top".to_string(), None)];
    let order = order_tree(&tree, &items, &ConnectionRanking::default(), now(), |k| k.to_string());
    assert_eq!(
        order,
        vec![
            folder_entry(1, 0),
            folder_entry(2, 1),
            folder_entry(3, 2),
            folder_entry(4, 3),
            folder_entry(5, 4),
            item_entry("deep", 5),
            item_entry("top", 0),
        ]
    );
    assert_eq!(tree.depth(id(5)), 4);
    assert_eq!(tree.path(id(5)), ["L1", "L2", "L3", "L4", "L5"]);
}

// ---------------------------------------------------------------------------------------------------------------
// Repository

fn new_vault(tmp: &TempDir) -> Vault {
    fs::create_dir_all(tmp.path()).unwrap();
    Vault::create(&tmp.path().join("MacVPN"), &Dek::generate(&FixedEntropy::new(7)).unwrap()).unwrap()
}

/// A managed connection row (the connection repository is Task 7; only the columns matter here).
fn insert_connection(vault: &mut Vault, conn: Uuid, folder: Option<Uuid>) {
    vault
        .transaction(|tx| {
            tx.execute(
                "INSERT INTO connections(id, kind, meta_json, config, folder_id, position) VALUES (?1, 'openvpn', '{}', '', ?2, 0)",
                (uuid_string(&conn), folder.map(|f| uuid_string(&f))),
            )?;
            Ok(())
        })
        .unwrap();
}

fn connection_placement(vault: &Vault, conn: Uuid) -> (Option<String>, Option<String>) {
    vault
        .connection()
        .query_row("SELECT folder_id, color FROM connections WHERE id = ?1", [uuid_string(&conn)], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap()
}

fn system_placement(vault: &Vault, service: &str) -> Option<(Option<String>, Option<String>)> {
    vault
        .connection()
        .query_row("SELECT folder_id, color FROM system_items WHERE service_id = ?1", [service], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .ok()
}

fn by_id(vault: &Vault) -> HashMap<Uuid, FolderNode> {
    vault.folders().unwrap().into_iter().map(|f| (f.id, f)).collect()
}

/// The children of `parent` in display order, by name.
fn child_names(vault: &Vault, parent: Option<Uuid>) -> Vec<String> {
    let tree = vault.folder_tree().unwrap();
    tree.children(parent).iter().map(|c| tree.get(*c).unwrap().name.clone()).collect()
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn create_rename_colour_collapse_round_trip() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let work = vault.create_folder(None, "  Work ").unwrap();
    let home = vault.create_folder(None, "Home").unwrap();
    let clients = vault.create_folder(Some(work), "Clients").unwrap();
    let folders = by_id(&vault);
    assert_eq!(folders.len(), 3);
    assert_eq!(folders[&work].name, "Work");
    assert_eq!(folders[&work].parent, None);
    assert_eq!((folders[&work].position, folders[&home].position), (0, 1));
    assert_eq!(folders[&clients].parent, Some(work));
    assert_eq!(folders[&clients].position, 0);
    assert!(!folders[&work].collapsed);
    assert_eq!(folders[&work].color, None);

    vault.rename_folder(work, "Office AD").unwrap();
    vault.set_folder_color(work, Some(FolderColor::Indigo)).unwrap();
    vault.set_collapsed(work, true).unwrap();
    let folders = by_id(&vault);
    assert_eq!(folders[&work].name, "Office AD");
    assert_eq!(folders[&work].color, Some(FolderColor::Indigo));
    assert!(folders[&work].collapsed);
    // Stored by the palette's stable id.
    let stored: String = vault
        .connection()
        .query_row("SELECT color FROM folders WHERE id = ?1", [uuid_string(&work)], |r| r.get(0))
        .unwrap();
    assert_eq!(stored, "indigo");
    vault.set_folder_color(work, None).unwrap();
    vault.set_collapsed(work, false).unwrap();
    let folders = by_id(&vault);
    assert_eq!(folders[&work].color, None);
    assert!(!folders[&work].collapsed);

    // An unknown stored colour reads as none.
    vault
        .transaction(|tx| {
            tx.execute("UPDATE folders SET color = 'magenta' WHERE id = ?1", [uuid_string(&home)])?;
            Ok(())
        })
        .unwrap();
    assert_eq!(by_id(&vault)[&home].color, None);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn invalid_names_and_unknown_folders_are_refused() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let work = vault.create_folder(None, "Work").unwrap();
    assert!(matches!(vault.create_folder(None, " "), Err(VaultError::Tree(TreeError::InvalidName))));
    assert!(matches!(vault.rename_folder(work, "a\nb"), Err(VaultError::Tree(TreeError::InvalidName))));
    let ghost = Uuid::new_v4();
    assert!(
        matches!(vault.create_folder(Some(ghost), "X"), Err(VaultError::Tree(TreeError::UnknownFolder(g))) if g == ghost)
    );
    assert!(matches!(vault.rename_folder(ghost, "X"), Err(VaultError::Tree(TreeError::UnknownFolder(_)))));
    assert!(matches!(vault.set_folder_color(ghost, None), Err(VaultError::Tree(TreeError::UnknownFolder(_)))));
    assert!(matches!(vault.set_collapsed(ghost, true), Err(VaultError::Tree(TreeError::UnknownFolder(_)))));
    assert!(matches!(
        vault.delete_folder(ghost, DeleteMode::MoveContentsUp),
        Err(VaultError::Tree(TreeError::UnknownFolder(_)))
    ));
    assert!(matches!(vault.set_item_folder("SVC", Some(ghost)), Err(VaultError::Tree(TreeError::UnknownFolder(_)))));
    assert_eq!(vault.folders().unwrap().len(), 1);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn move_folder_checks_cycles_and_renumbers_siblings() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let a = vault.create_folder(None, "A").unwrap();
    let b = vault.create_folder(None, "B").unwrap();
    let c = vault.create_folder(None, "C").unwrap();
    let a1 = vault.create_folder(Some(a), "A1").unwrap();
    let a11 = vault.create_folder(Some(a1), "A11").unwrap();

    // Reorder at the root: C to the front.
    vault.move_folder(c, None, 0).unwrap();
    assert_eq!(child_names(&vault, None), ["C", "A", "B"]);
    let folders = by_id(&vault);
    assert_eq!((folders[&c].position, folders[&a].position, folders[&b].position), (0, 1, 2));

    // Under itself, its child, its grandchild: refused, nothing changes.
    for target in [a, a1, a11] {
        assert!(matches!(vault.move_folder(a, Some(target), 0), Err(VaultError::Tree(TreeError::Cycle))));
    }
    assert_eq!(child_names(&vault, None), ["C", "A", "B"]);

    // Reparent B into A at position 0 (before A1); the root closes the gap.
    vault.move_folder(b, Some(a), 0).unwrap();
    assert_eq!(child_names(&vault, Some(a)), ["B", "A1"]);
    assert_eq!(child_names(&vault, None), ["C", "A"]);
    let folders = by_id(&vault);
    assert_eq!(folders[&b].parent, Some(a));
    assert_eq!((folders[&c].position, folders[&a].position), (0, 1));
    // A position past the end appends.
    vault.move_folder(a11, None, 99).unwrap();
    assert_eq!(child_names(&vault, None), ["C", "A", "A11"]);
    assert!(child_names(&vault, Some(a1)).is_empty());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn delete_move_contents_up_lands_at_the_end_of_the_parent() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let work = vault.create_folder(None, "Work").unwrap();
    let early = vault.create_folder(Some(work), "Early").unwrap();
    let clients = vault.create_folder(Some(work), "Clients").unwrap();
    let late = vault.create_folder(Some(work), "Late").unwrap();
    let acme = vault.create_folder(Some(clients), "Acme").unwrap();
    let beta = vault.create_folder(Some(clients), "Beta").unwrap();
    let deep = vault.create_folder(Some(acme), "Deep").unwrap();
    let conn = Uuid::new_v4();
    insert_connection(&mut vault, conn, Some(clients));
    vault.set_item_folder("SVC-1", Some(clients)).unwrap();

    let deleted = vault.delete_folder(clients, DeleteMode::MoveContentsUp).unwrap();
    assert!(deleted.is_empty());
    let folders = by_id(&vault);
    assert!(!folders.contains_key(&clients));
    assert_eq!(child_names(&vault, Some(work)), ["Early", "Late", "Acme", "Beta"]);
    assert_eq!(folders[&acme].parent, Some(work));
    assert_eq!(folders[&deep].parent, Some(acme));
    let _ = (early, late, beta);
    assert_eq!(connection_placement(&vault, conn).0, Some(uuid_string(&work)));
    assert_eq!(system_placement(&vault, "SVC-1").unwrap().0, Some(uuid_string(&work)));

    // At the root too.
    let deleted = vault.delete_folder(work, DeleteMode::MoveContentsUp).unwrap();
    assert!(deleted.is_empty());
    assert_eq!(child_names(&vault, None), ["Early", "Late", "Acme", "Beta"]);
    assert_eq!(connection_placement(&vault, conn).0, None);
    assert_eq!(system_placement(&vault, "SVC-1").unwrap().0, None);
    assert_eq!(by_id(&vault).len(), 5);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn delete_contents_cascades_and_returns_nested_connections() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let work = vault.create_folder(None, "Work").unwrap();
    let clients = vault.create_folder(Some(work), "Clients").unwrap();
    let acme = vault.create_folder(Some(clients), "Acme").unwrap();
    let home = vault.create_folder(None, "Home").unwrap();
    let (c1, c2, c3, keep) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    insert_connection(&mut vault, c1, Some(work));
    insert_connection(&mut vault, c2, Some(clients));
    insert_connection(&mut vault, c3, Some(acme));
    insert_connection(&mut vault, keep, Some(home));
    vault.set_item_folder("SVC-DEEP", Some(acme)).unwrap();
    vault.set_item_color("SVC-DEEP", Some(FolderColor::Green)).unwrap();
    vault.set_item_folder("SVC-HOME", Some(home)).unwrap();

    let mut deleted = vault.delete_folder(work, DeleteMode::DeleteContents).unwrap();
    deleted.sort();
    let mut expected = vec![c1, c2, c3];
    expected.sort();
    assert_eq!(deleted, expected);
    let folders = by_id(&vault);
    assert_eq!(folders.keys().copied().collect::<Vec<_>>(), [home]);
    // System VPNs always move to the root (keeping their own colour).
    assert_eq!(system_placement(&vault, "SVC-DEEP").unwrap(), (None, Some("green".into())));
    assert_eq!(system_placement(&vault, "SVC-HOME").unwrap().0, Some(uuid_string(&home)));
    assert_eq!(connection_placement(&vault, keep).0, Some(uuid_string(&home)));
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_connection_whose_folder_vanished_lands_at_the_root() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let work = vault.create_folder(None, "Work").unwrap();
    let conn = Uuid::new_v4();
    insert_connection(&mut vault, conn, Some(work));
    vault
        .transaction(|tx| {
            tx.execute("DELETE FROM folders WHERE id = ?1", [uuid_string(&work)])?;
            Ok(())
        })
        .unwrap();
    assert_eq!(connection_placement(&vault, conn).0, None);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn item_folder_and_colour_for_managed_and_system_keys() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let work = vault.create_folder(None, "Work").unwrap();
    vault.set_folder_color(work, Some(FolderColor::Blue)).unwrap();
    let conn = Uuid::new_v4();
    insert_connection(&mut vault, conn, None);
    let key = uuid_string(&conn);

    vault.set_item_folder(&key, Some(work)).unwrap();
    vault.set_item_color(&key, Some(FolderColor::Orange)).unwrap();
    assert_eq!(connection_placement(&vault, conn), (Some(uuid_string(&work)), Some("orange".into())));
    // A managed key never creates a system item.
    assert!(system_placement(&vault, &key).is_none());
    // "Use folder colour".
    vault.set_item_color(&key, None).unwrap();
    assert_eq!(connection_placement(&vault, conn), (Some(uuid_string(&work)), None));
    let tree = vault.folder_tree().unwrap();
    assert_eq!(tree.item_color(None, Some(work)), (Some(FolderColor::Blue), ColorSource::Inherited(work)));

    // A system key upserts `system_items`.
    vault.set_item_color("SVC-9", Some(FolderColor::Cyan)).unwrap();
    assert_eq!(system_placement(&vault, "SVC-9").unwrap(), (None, Some("cyan".into())));
    vault.set_item_folder("SVC-9", Some(work)).unwrap();
    assert_eq!(system_placement(&vault, "SVC-9").unwrap(), (Some(uuid_string(&work)), Some("cyan".into())));
    vault.set_item_folder("SVC-9", None).unwrap();
    assert_eq!(system_placement(&vault, "SVC-9").unwrap(), (None, Some("cyan".into())));

    // Each move appends in the target folder (`connections.position` is written, not used for display).
    let other = Uuid::new_v4();
    insert_connection(&mut vault, other, None);
    vault.set_item_folder(&uuid_string(&other), Some(work)).unwrap();
    let position = |c: Uuid| -> i64 {
        vault
            .connection()
            .query_row("SELECT position FROM connections WHERE id = ?1", [uuid_string(&c)], |r| r.get(0))
            .unwrap()
    };
    assert!(position(other) > position(conn));
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn folder_tree_from_the_vault_orders_like_the_pure_tree() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let b = vault.create_folder(None, "B").unwrap();
    let a = vault.create_folder(None, "A").unwrap();
    let tree = vault.folder_tree().unwrap();
    let order = order_tree(&tree, &[("x".into(), Some(a))], &ConnectionRanking::default(), now(), |k| k.into());
    assert_eq!(
        order,
        vec![
            TreeEntry::Folder { id: b, depth: 0 },
            TreeEntry::Folder { id: a, depth: 0 },
            TreeEntry::Item { key: "x".into(), depth: 1 }
        ]
    );
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn folders_persist_across_reopen() {
    let tmp = TempDir::new();
    let dir = tmp.path().join("MacVPN");
    let dek = Dek::generate(&FixedEntropy::new(7)).unwrap();
    fs::create_dir_all(tmp.path()).unwrap();
    let mut vault = Vault::create(&dir, &dek).unwrap();
    let work = vault.create_folder(None, "Work").unwrap();
    vault.close();
    let mut vault = Vault::open(&dir, &dek).unwrap();
    assert_eq!(vault.folders().unwrap()[0].id, work);
    vault.set_collapsed(work, true).unwrap();
}
