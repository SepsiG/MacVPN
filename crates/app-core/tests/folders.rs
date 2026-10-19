//! Folders and colours in the app (plan B Task 16, spec 3): the manager's tree order over the folder store, the
//! system-VPN placement retention, the folder commands' validation and orchestration ("Delete the connections
//! too" included), the view model's tree rows, the vault-backed store, and the export / import metadata line.

mod common;

use common::{MockProfiles, TempDir, clock_at};
use macvpn_app_core::connections::ConnectionsModel;
use macvpn_app_core::deps::{
    FolderOp, FolderOpResult, FolderStore, RankingPersistence, SystemItemChange, SystemService,
};
use macvpn_app_core::editor::EditorDeps;
use macvpn_app_core::folders::{self, MemoryFolders, VaultFolders, retention};
use macvpn_app_core::import_export;
use macvpn_app_core::vault::VaultLifecycle;
use macvpn_app_core::view_model::TreeRowView;
use macvpn_app_core::{ConnectionManager, ViewModel};
use macvpn_core::date::Date;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::{Connection, VPNKind, uuid_string};
use macvpn_core::ranking::{ConnectionRanking, UsageStats};
use macvpn_core::vault::{DeleteMode, FixedEntropy, FolderColor, KdfParams, MemoryKeyStore, SystemItem, TreeEntry};
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

const NOW: f64 = 1_800_000_000.0;
const SVC: &str = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
const SVC2: &str = "48B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
const OVPN: &str = "client\ndev tun\nremote vpn.example.com 1194\n";

struct FixedRanking(ConnectionRanking);

impl RankingPersistence for FixedRanking {
    fn load(&self) -> ConnectionRanking {
        self.0.clone()
    }
    fn save(&self, _: &ConnectionRanking) -> io::Result<()> {
        Ok(())
    }
}

struct World {
    fx: common::Fixture,
    folders: Arc<MemoryFolders>,
    manager: Arc<ConnectionManager>,
    model: Arc<ConnectionsModel>,
}

fn world_with(ranking: ConnectionRanking) -> World {
    let fx = common::Fixture::new(AppLanguage::En);
    let store = fx.store.clone();
    let folders = Arc::new(MemoryFolders::new(move |key| {
        store.list().unwrap_or_default().iter().any(|c| uuid_string(&c.id) == key)
    }));
    let mut deps = fx.deps();
    deps.folders = Some(folders.clone());
    deps.clock = clock_at(NOW);
    deps.ranking_store = Some(Arc::new(FixedRanking(ranking)));
    let manager = fx.manager_with(deps);
    let model = Arc::new(ConnectionsModel::new(EditorDeps {
        manager: manager.clone(),
        store: fx.store.clone(),
        secrets: fx.secrets.clone(),
        secret_writer: fx.secrets.clone(),
        profiles: Arc::new(MockProfiles::default()),
        clock: clock_at(NOW),
    }));
    World { fx, folders, manager, model }
}

fn world() -> World {
    world_with(ConnectionRanking::default())
}

impl World {
    fn add(&self, name: &str) -> Connection {
        let c = Connection::new(name, VPNKind::Openvpn);
        self.fx.store.save(&c, Some(OVPN)).unwrap();
        self.manager.reload();
        c
    }

    fn folder(&self, parent: Option<&str>, name: &str) -> String {
        folders::create(&self.manager, parent, name).unwrap()
    }

    fn put(&self, c: &Connection, folder: Option<&str>) {
        folders::move_item(&self.manager, &uuid_string(&c.id), folder).unwrap();
    }

    fn name_of(&self, key: &str) -> String {
        self.manager.item(key).map(|i| i.name().to_string()).unwrap_or_default()
    }

    /// The tree as `<indent><name>` lines (folders end in `/`).
    fn outline(&self) -> Vec<String> {
        let tree = self.manager.folder_tree();
        self.manager
            .ordered_tree()
            .into_iter()
            .map(|e| match e {
                TreeEntry::Folder { id, depth } => format!("{}{}/", "  ".repeat(depth), tree.get(id).unwrap().name),
                TreeEntry::Item { key, depth } => format!("{}{}", "  ".repeat(depth), self.name_of(&key)),
            })
            .collect()
    }

    fn vm(&self) -> ViewModel {
        ViewModel::build(&self.manager.snapshot(), "en", |_| true, Vec::new(), true)
    }
}

fn connected_json(cs: &[&Connection]) -> String {
    let rows: Vec<String> = cs
        .iter()
        .map(|c| {
            format!(
                r#"{{"id":"{}","kind":"openvpn","state":"connected","iface":null,"ip":null,"since":null}}"#,
                uuid_string(&c.id)
            )
        })
        .collect();
    format!("[{}]", rows.join(","))
}

// MARK: - Order

#[test]
fn the_tree_orders_subfolders_first_then_pinned_items_then_usage() {
    let now = Date::from_time_interval_since_1970(NOW);
    let fx_ids: Vec<Connection> = ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot"]
        .iter()
        .map(|n| Connection::new(*n, VPNKind::Openvpn))
        .collect();
    let key = |i: usize| uuid_string(&fx_ids[i].id);
    let stats = |score: f64| UsageStats { score, last_updated: now };
    // Pinned: Echo, then Bravo. Usage: Delta > Charlie; Alpha and Foxtrot none (by name).
    let ranking =
        ConnectionRanking::new(vec![key(4), key(1)], HashMap::from([(key(3), stats(5.0)), (key(2), stats(2.0))]));
    let w = world_with(ranking);
    for c in &fx_ids {
        w.fx.store.save(c, Some(OVPN)).unwrap();
    }
    w.fx.native.set_list(Ok(vec![SystemService::new(SVC, "Zulu system", "IKEv2", "Disconnected")]));
    w.manager.reload();
    w.manager.refresh();
    let work = w.folder(None, "Work");
    let clients = w.folder(Some(&work), "Clients");
    let deep: String = (0..4).fold(clients.clone(), |parent, i| w.folder(Some(&parent), &format!("L{}", i + 3)));
    let archive = w.folder(None, "Archive");
    for i in [1, 2, 3] {
        w.put(&fx_ids[i], Some(&work));
    }
    w.put(&fx_ids[5], Some(&deep));
    folders::move_item(&w.manager, SVC, Some(&clients)).unwrap();
    assert_eq!(
        w.outline(),
        vec![
            "Work/",
            "  Clients/",
            "    L3/",
            "      L4/",
            "        L5/",
            "          L6/",
            "            Foxtrot",
            "    Zulu system",
            "  Bravo",
            "  Delta",
            "  Charlie",
            "Archive/",
            "Echo",
            "Alpha",
        ]
    );
    // Reordering folders: Archive first at the root.
    folders::move_folder(&w.manager, &archive, None, 0).unwrap();
    assert_eq!(w.outline()[0], "Archive/");
    // The flat order (the control API's `list`) ignores the folders.
    let flat: Vec<String> = w.manager.ordered_items().iter().map(|i| i.name().to_string()).collect();
    assert_eq!(flat, ["Echo", "Bravo", "Delta", "Charlie", "Alpha", "Foxtrot", "Zulu system"]);
}

#[test]
fn without_a_folder_store_everything_is_at_the_root_in_ranking_order() {
    let fx = common::Fixture::new(AppLanguage::En);
    let a = Connection::new("B", VPNKind::Openvpn);
    let b = Connection::new("A", VPNKind::Wireguard);
    fx.store.save(&a, Some(OVPN)).unwrap();
    fx.store.save(&b, Some("[Interface]\n")).unwrap();
    let m = fx.manager();
    let vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    assert!(!vm.folders_enabled);
    let ids: Vec<String> = vm
        .tree
        .iter()
        .map(|r| match r {
            TreeRowView::Item { id, depth: 0, parent: None, .. } => id.clone(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(ids, vm.rows.iter().map(|r| r.id.clone()).collect::<Vec<_>>());
    assert!(folders::create(&m, None, "Work").is_err());
    assert_eq!(vm.palette.len(), 12);
}

// MARK: - View model

#[test]
fn folder_rows_count_active_connections_in_the_whole_subtree_and_show_the_green_dot() {
    let w = world();
    let a = w.add("A");
    let b = w.add("B");
    let c = w.add("C");
    let work = w.folder(None, "Work");
    let clients = w.folder(Some(&work), "Clients");
    let empty = w.folder(None, "Empty");
    w.put(&a, Some(&clients));
    w.put(&b, Some(&work));
    w.put(&c, Some(&work));
    folders::set_color(&w.manager, &work, Some("teal")).unwrap();
    folders::set_item_color(&w.manager, &uuid_string(&b.id), Some("pink")).unwrap();
    folders::set_collapsed(&w.manager, &work, true).unwrap();
    w.fx.root.respond("status", Ok(&connected_json(&[&a])));
    w.manager.refresh();
    // B is connecting: active, but no green dot for it alone.
    let vm = w.vm();
    let folder = |id: &str| {
        vm.tree
            .iter()
            .find_map(|r| match r {
                TreeRowView::Folder { id: fid, .. } if fid == id => Some(r.clone()),
                _ => None,
            })
            .unwrap()
    };
    let item = |c: &Connection| {
        vm.tree
            .iter()
            .find_map(|r| match r {
                TreeRowView::Item { id, .. } if *id == uuid_string(&c.id) => Some(r.clone()),
                _ => None,
            })
            .unwrap()
    };
    let TreeRowView::Folder { active_count, has_connected, collapsed, color, color_source, connection_count, .. } =
        folder(&work)
    else {
        unreachable!()
    };
    assert_eq!((active_count, has_connected, collapsed), (1, true, true));
    assert_eq!((color, color_source, connection_count), (Some("teal"), "own", 3));
    let TreeRowView::Folder { active_count, has_connected, depth, color, color_source, parent, .. } = folder(&clients)
    else {
        unreachable!()
    };
    assert_eq!((active_count, has_connected, depth), (1, true, 1));
    assert_eq!((color, color_source, parent.as_deref()), (Some("teal"), "inherited", Some(work.as_str())));
    let TreeRowView::Folder { active_count, has_connected, .. } = folder(&empty) else { unreachable!() };
    assert_eq!((active_count, has_connected), (0, false));
    // An item's own colour is an override; the others inherit; "Use folder colour" clears the override.
    let TreeRowView::Item { color, color_source, own_color, depth, .. } = item(&b) else { unreachable!() };
    assert_eq!((color, color_source, own_color, depth), (Some("pink"), "own", Some("pink"), 1));
    let TreeRowView::Item { color, color_source, depth, .. } = item(&a) else { unreachable!() };
    assert_eq!((color, color_source, depth), (Some("teal"), "inherited", 2));
    folders::set_item_color(&w.manager, &uuid_string(&b.id), None).unwrap();
    let vm = w.vm();
    let b_row = vm.tree.iter().find(|r| matches!(r, TreeRowView::Item { id, .. } if *id == uuid_string(&b.id)));
    assert!(matches!(
        b_row,
        Some(TreeRowView::Item { color: Some("teal"), color_source: "inherited", own_color: None, .. })
    ));
    // Serialized for the UI.
    let json = serde_json::to_value(&vm.tree).unwrap();
    assert_eq!(json[0]["type"], "folder");
    assert_eq!(json[0]["activeCount"], 1);
    assert_eq!(json[0]["hasConnected"], true);
    assert_eq!(json[0]["colorSource"], "own");
}

// MARK: - Commands

#[test]
fn commands_validate_ids_colours_names_and_modes() {
    let w = world();
    let c = w.add("A");
    let work = w.folder(None, "Work");
    let unknown = uuid_string(&Uuid::new_v4());
    assert_eq!(folders::rename(&w.manager, "not-a-uuid", "X").unwrap_err(), "This folder no longer exists");
    assert_eq!(folders::rename(&w.manager, &unknown, "X").unwrap_err(), "This folder no longer exists");
    assert_eq!(folders::create(&w.manager, Some(&unknown), "X").unwrap_err(), "This folder no longer exists");
    for bad in ["", "   ", "a\u{7}b", &"x".repeat(65)] {
        assert_eq!(
            folders::create(&w.manager, None, bad).unwrap_err(),
            "A folder name needs 1 to 64 characters and no control characters",
            "{bad:?}"
        );
    }
    assert_eq!(folders::create(&w.manager, None, "  Trimmed  ").map(|_| ()), Ok(()));
    assert!(w.manager.folders().iter().any(|f| f.name == "Trimmed"));
    assert_eq!(folders::set_color(&w.manager, &work, Some("magenta")).unwrap_err(), "Unknown colour");
    assert_eq!(folders::set_color(&w.manager, &work, Some("Red")).unwrap_err(), "Unknown colour");
    for color in FolderColor::ALL {
        folders::set_color(&w.manager, &work, Some(color.as_str())).unwrap();
    }
    folders::set_color(&w.manager, &work, None).unwrap();
    assert_eq!(folders::delete(&w.manager, &w.model, &work, "everything").unwrap_err(), "Unknown delete option");
    assert_eq!(
        folders::move_item(&w.manager, &uuid_string(&Uuid::new_v4()), Some(&work)).unwrap_err(),
        "This connection no longer exists"
    );
    assert_eq!(
        folders::move_item(&w.manager, &uuid_string(&c.id), Some(&unknown)).unwrap_err(),
        "This folder no longer exists"
    );
    folders::rename(&w.manager, &work, "Office").unwrap();
    assert!(w.manager.folders().iter().any(|f| f.name == "Office"));
}

#[test]
fn a_folder_cannot_move_into_itself_or_a_descendant() {
    let w = world();
    let a = w.folder(None, "A");
    let b = w.folder(Some(&a), "B");
    let c = w.folder(Some(&b), "C");
    let message = "A folder cannot be moved into itself or one of its subfolders";
    for target in [&a, &b, &c] {
        assert_eq!(folders::move_folder(&w.manager, &a, Some(target), 0).unwrap_err(), message);
    }
    // The store refuses it too (a stale UI view).
    let id = Uuid::parse_str(&a).unwrap();
    let err = w.folders.apply(FolderOp::Move { id, parent: Some(Uuid::parse_str(&c).unwrap()), position: 0 });
    assert_eq!(err.unwrap_err().to_string(), message);
    // A legal move: C to the root, after A.
    folders::move_folder(&w.manager, &c, None, 9).unwrap();
    assert_eq!(w.outline(), ["A/", "  B/", "C/"]);
}

#[test]
fn delete_with_move_up_puts_the_contents_into_the_parent() {
    let w = world();
    let a = w.add("A");
    let b = w.add("B");
    let work = w.folder(None, "Work");
    let clients = w.folder(Some(&work), "Clients");
    let sub = w.folder(Some(&clients), "Sub");
    w.folder(Some(&work), "Zeta");
    w.put(&a, Some(&clients));
    w.put(&b, Some(&work));
    assert!(folders::delete(&w.manager, &w.model, &clients, "moveUp").unwrap().is_empty());
    assert_eq!(w.outline(), ["Work/", "  Zeta/", "  Sub/", "  A", "  B"]);
    // At the root too.
    folders::delete(&w.manager, &w.model, &work, "moveUp").unwrap();
    assert_eq!(w.outline(), ["Zeta/", "Sub/", "A", "B"]);
    assert!(w.manager.folder_tree().get(Uuid::parse_str(&sub).unwrap()).is_some());
    assert_eq!(w.manager.connections().len(), 2, "nothing deleted");
}

#[test]
fn delete_contents_deletes_the_connections_of_the_subtree_and_keeps_system_vpns() {
    let w = world();
    let a = w.add("A");
    let b = w.add("B");
    let keep = w.add("Keep");
    w.fx.native.set_list(Ok(vec![SystemService::new(SVC, "Corp", "IKEv2", "Disconnected")]));
    w.manager.refresh();
    let work = w.folder(None, "Work");
    let clients = w.folder(Some(&work), "Clients");
    w.put(&a, Some(&work));
    w.put(&b, Some(&clients));
    folders::move_item(&w.manager, SVC, Some(&clients)).unwrap();
    // Refused while one of them is active.
    w.fx.root.respond("status", Ok(&connected_json(&[&b])));
    w.manager.refresh();
    assert_eq!(
        folders::delete(&w.manager, &w.model, &work, "deleteContents").unwrap_err(),
        "Disconnect the connections in this folder before deleting them"
    );
    assert_eq!(w.manager.folders().len(), 2, "nothing deleted");
    w.fx.root.respond("status", Ok("[]"));
    w.manager.refresh();
    let deleted = folders::delete(&w.manager, &w.model, &work, "deleteContents").unwrap();
    let mut names: Vec<String> = deleted.iter().map(|c| c.name.clone()).collect();
    names.sort();
    assert_eq!(names, ["A", "B"]);
    assert!(w.manager.folders().is_empty());
    let left: Vec<String> = w.manager.connections().iter().map(|c| c.name.clone()).collect();
    assert_eq!(left, ["Keep"]);
    assert!(w.fx.store.load_config(&a.id).is_err() && w.fx.store.load_config(&b.id).is_err());
    assert!(w.fx.store.load_config(&keep.id).is_ok());
    assert_eq!(w.outline(), ["Corp", "Keep"], "the system VPN moved to the root");
}

// MARK: - Retention

fn item(id: &str, missing: Option<f64>) -> SystemItem {
    SystemItem {
        service_id: id.into(),
        folder_id: Some(Uuid::new_v4()),
        color: None,
        position: 0,
        missing_since: missing.map(Date::from_time_interval_since_1970),
    }
}

#[test]
fn retention_marks_clears_and_removes_after_30_days() {
    let now = Date::from_time_interval_since_1970(NOW);
    let day = 86_400.0;
    let listed: HashSet<String> = [SVC.to_string()].into();
    // Listed and never missing: nothing. Not listed: marked now.
    assert!(retention(&[item(SVC, None)], &listed, now).is_empty());
    assert_eq!(
        retention(&[item(SVC2, None)], &listed, now),
        [SystemItemChange::MarkMissing { service_id: SVC2.into(), since: now }]
    );
    // Back within 30 days: cleared.
    assert_eq!(
        retention(&[item(SVC, Some(NOW - 29.0 * day))], &listed, now),
        [SystemItemChange::Clear { service_id: SVC.into() }]
    );
    // Still missing: kept until 30 days have passed, then removed.
    assert!(retention(&[item(SVC2, Some(NOW - 29.0 * day))], &listed, now).is_empty());
    assert_eq!(
        retention(&[item(SVC2, Some(NOW - 31.0 * day))], &listed, now),
        [SystemItemChange::Remove { service_id: SVC2.into() }]
    );
}

#[test]
fn the_manager_applies_the_retention_after_each_listing() {
    let w = world();
    let clock = clock_at(NOW);
    let mut deps = w.fx.deps();
    deps.folders = Some(w.folders.clone());
    deps.clock = clock.clone();
    let m = w.fx.manager_with(deps);
    w.fx.native.set_list(Ok(vec![SystemService::new(SVC, "Corp", "IKEv2", "Disconnected")]));
    m.refresh();
    let work = folders::create(&m, None, "Work").unwrap();
    folders::move_item(&m, SVC, Some(&work)).unwrap();
    // Removed from macOS: marked, the placement kept.
    w.fx.native.set_list(Ok(Vec::new()));
    m.refresh();
    let items = w.folders.system_items().unwrap();
    assert_eq!(items[0].missing_since, Some(Date::from_time_interval_since_1970(NOW)));
    // Back after 10 days: cleared, still in Work.
    clock.advance(10.0 * 86_400.0);
    w.fx.native.set_list(Ok(vec![SystemService::new(SVC, "Corp", "IKEv2", "Disconnected")]));
    m.refresh();
    assert_eq!(w.folders.system_items().unwrap()[0].missing_since, None);
    assert_eq!(m.placement(SVC).and_then(|p| p.folder).map(|f| uuid_string(&f)), Some(work.clone()));
    // Gone for 31 days: the placement is deleted.
    w.fx.native.set_list(Ok(Vec::new()));
    m.refresh();
    clock.advance(31.0 * 86_400.0);
    m.refresh();
    assert!(w.folders.system_items().unwrap().is_empty());
    assert!(m.placement(SVC).is_none());
    // A failed listing changes nothing.
    w.fx.native.set_list(Err("scutil failed"));
    m.refresh();
}

// MARK: - The vault store

fn vault() -> (TempDir, Arc<VaultLifecycle>) {
    let tmp = TempDir::new();
    let vault = Arc::new(VaultLifecycle::new(
        tmp.path().join("MacVPN"),
        Arc::new(MemoryKeyStore::new()),
        Arc::new(FixedEntropy::new(5)),
        KdfParams::insecure_for_tests(),
    ));
    vault.create(Zeroizing::new("correct horse battery".into()), false).unwrap();
    (tmp, vault)
}

#[test]
fn the_vault_store_round_trips_and_refuses_while_locked() {
    let (_tmp, vault) = vault();
    let store = VaultFolders::new(vault.clone());
    let c = Connection::new("Office", VPNKind::Openvpn);
    vault.with(|v| v.save_connection(&c, Some(OVPN))).unwrap();
    let FolderOpResult::Created(work) = store.apply(FolderOp::Create { parent: None, name: "Work".into() }).unwrap()
    else {
        panic!()
    };
    let FolderOpResult::Created(sub) =
        store.apply(FolderOp::Create { parent: Some(work), name: "Sub".into() }).unwrap()
    else {
        panic!()
    };
    store.apply(FolderOp::MoveItem { key: uuid_string(&c.id), folder: Some(sub) }).unwrap();
    store.apply(FolderOp::MoveItem { key: SVC.into(), folder: Some(sub) }).unwrap();
    store.apply(FolderOp::SetItemColor { key: SVC.into(), color: Some(FolderColor::Amber) }).unwrap();
    store.apply(FolderOp::SetColor { id: work, color: Some(FolderColor::Blue) }).unwrap();
    store.apply(FolderOp::SetCollapsed { id: work, collapsed: true }).unwrap();
    let placements = store.placements().unwrap();
    assert_eq!(placements.len(), 2);
    assert!(placements.iter().any(|p| p.key == SVC && p.color == Some(FolderColor::Amber)));
    let folders = store.folders().unwrap();
    assert!(folders.iter().any(|f| f.id == work && f.collapsed && f.color == Some(FolderColor::Blue)));
    // A cycle is refused with the user-facing message.
    let err = store.apply(FolderOp::Move { id: work, parent: Some(sub), position: 0 }).unwrap_err();
    assert_eq!(err.to_string(), "A folder cannot be moved into itself or one of its subfolders");
    // The retention.
    let now = Date::from_time_interval_since_1970(NOW);
    store
        .apply(FolderOp::Retention(vec![SystemItemChange::MarkMissing { service_id: SVC.into(), since: now }]))
        .unwrap();
    assert_eq!(store.system_items().unwrap()[0].missing_since, Some(now));
    // Delete the connections too: the managed one is returned, the system VPN moved to the root.
    let result = store.apply(FolderOp::Delete { id: work, mode: DeleteMode::DeleteContents }).unwrap();
    assert_eq!(result, FolderOpResult::Deleted(vec![uuid_string(&c.id)]));
    assert_eq!(store.system_items().unwrap()[0].folder_id, None);
    store.apply(FolderOp::Retention(vec![SystemItemChange::Remove { service_id: SVC.into() }])).unwrap();
    assert!(store.system_items().unwrap().is_empty());
    // Locked: every call fails, saying so.
    vault.lock();
    assert_eq!(store.folders().unwrap_err().to_string(), "Folders cannot be changed while the vault is locked");
    assert!(store.apply(FolderOp::Create { parent: None, name: "X".into() }).is_err());
}

// MARK: - Export and import

#[test]
fn export_adds_the_folder_line_only_for_a_connection_in_a_folder() {
    let w = world();
    let c = w.add("Office");
    let deps = w.model.deps();
    let plain = import_export::export_plan(deps, &c, true).unwrap();
    assert_eq!(plain.data, OVPN.as_bytes(), "no folder, no line");
    let work = w.folder(None, "Work");
    let clients = w.folder(Some(&work), "Clients \"A\"");
    w.put(&c, Some(&clients));
    let plan = import_export::export_plan(deps, &c, true).unwrap();
    let text = String::from_utf8(plan.data).unwrap();
    let (first, rest) = text.split_once('\n').unwrap();
    assert_eq!(first, r#"# macvpn-meta: {"folder":["Work","Clients \"A\""]}"#);
    assert_eq!(rest, OVPN);
    // Only the folder path: no secret field, whatever is stored.
    w.fx.secrets.set("hunter2-secret", &c.id, macvpn_app_core::deps::SecretField::Password);
    let again = String::from_utf8(import_export::export_plan(deps, &c, true).unwrap().data).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(again.lines().next().unwrap().trim_start_matches("# macvpn-meta: ")).unwrap();
    assert_eq!(json.as_object().unwrap().keys().collect::<Vec<_>>(), ["folder"]);
    assert!(!again.contains("hunter2"));
}

fn import(w: &World, dir: &TempDir, file: &str, text: &str) -> Connection {
    std::fs::create_dir_all(dir.path()).unwrap();
    let path = dir.path().join(file);
    std::fs::write(&path, text).unwrap();
    let report = w.model.import_paths(&[path]);
    assert!(report.errors.is_empty(), "{report:?}");
    let stem = file.rsplit_once('.').unwrap().0;
    w.manager.connections().into_iter().find(|c| c.name == stem).unwrap()
}

#[test]
fn import_strips_the_line_and_recreates_the_folder_path() {
    let w = world();
    let dir = TempDir::new();
    let existing = w.folder(None, "Work");
    let line = "# macvpn-meta: {\"folder\":[\"Work\",\"Clients\"],\"future\":1}\n";
    let c = import(&w, &dir, "office.ovpn", &format!("{line}{OVPN}"));
    assert_eq!(w.fx.store.load_config(&c.id).unwrap(), OVPN, "the line is not stored");
    let path = w.manager.folder_path(&uuid_string(&c.id)).unwrap();
    assert_eq!(path, ["Work", "Clients"]);
    // "Work" was reused, "Clients" created under it.
    assert_eq!(w.manager.folders().len(), 2);
    assert!(
        w.manager
            .folders()
            .iter()
            .any(|f| f.name == "Clients" && f.parent.map(|p| uuid_string(&p)) == Some(existing.clone()))
    );
    // A second import into the same path creates nothing new.
    let d = import(&w, &dir, "second.ovpn", &format!("{line}{OVPN}"));
    assert_eq!(w.manager.folder_path(&uuid_string(&d.id)).unwrap(), ["Work", "Clients"]);
    assert_eq!(w.manager.folders().len(), 2);
    // An older export without the line lands at the root.
    let old = import(&w, &dir, "old.ovpn", OVPN);
    assert_eq!(w.manager.placement(&uuid_string(&old.id)), None);
    // Every text kind carries it.
    let wg = import(
        &w,
        &dir,
        "wg.conf",
        &format!(
            "{line}[Interface]\nPrivateKey = x\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = y\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"
        ),
    );
    assert_eq!(w.manager.folder_path(&uuid_string(&wg.id)).unwrap(), ["Work", "Clients"]);
    assert!(!w.fx.store.load_config(&wg.id).unwrap().contains("macvpn-meta"));
}

#[test]
fn a_malformed_meta_line_stays_in_the_config_as_a_comment() {
    let w = world();
    let dir = TempDir::new();
    for (file, line) in [
        ("broken.ovpn", "# macvpn-meta: {\"folder\":\"Work\"}\n"),
        ("syntax.ovpn", "# macvpn-meta: {folder: [Work]}\n"),
        ("control.ovpn", "# macvpn-meta: {\"folder\":[\"a\\u0007b\"]}\n"),
    ] {
        let c = import(&w, &dir, file, &format!("{line}{OVPN}"));
        assert_eq!(w.fx.store.load_config(&c.id).unwrap(), format!("{line}{OVPN}"));
        assert_eq!(w.manager.placement(&uuid_string(&c.id)), None);
    }
    assert!(w.manager.folders().is_empty());
}
