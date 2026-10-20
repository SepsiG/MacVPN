//! The pure apply/diff planner (plan Task 7): add, change, remove, connections that are up, several catalogs,
//! namespacing, unsubscribe and the op order.

use macvpn_core::catalog::ids::{CatalogItemKind, local_id, root_folder_id};
use macvpn_core::catalog::payload::{
    CatalogConnection, CatalogFolder, CatalogPayload, CredentialSlot, PAYLOAD_VERSION,
};
use macvpn_core::catalog::planner::{
    ApplySummary, CatalogOp, LocalCatalog, LocalItem, config_hash, folder_hash, meta_hash, plan_apply, plan_pending,
    plan_unsubscribe,
};
use macvpn_core::models::{NativeSettings, OTPSeparator, OTPSetting, SecretField, VPNKind};
use macvpn_core::vault::FolderColor;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use uuid::Uuid;
use zeroize::Zeroizing;

const OPENVPN: &str = "client\ndev tun\nremote vpn.example.com 1194\nauth-user-pass\n";

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0x1000_0000_0000_4000_8000_0000_0000_0000 + n)
}

const CAT_A: u128 = 0xA;
const CAT_B: u128 = 0xB;

fn connection(n: u128, name: &str) -> CatalogConnection {
    CatalogConnection {
        id: id(n),
        name: name.into(),
        kind: VPNKind::Openvpn,
        folder: None,
        color: None,
        config: Zeroizing::new(OPENVPN.into()),
        native: None,
        otp: OTPSetting::default(),
        slot: None,
        secret_refs: BTreeMap::new(),
    }
}

fn folder(n: u128, parent: Option<u128>, name: &str) -> CatalogFolder {
    CatalogFolder { id: id(n), parent: parent.map(id), name: name.into(), color: None, position: 0 }
}

/// Folders 100 > 101 > 102, connections 1 (in 102) and 2 (at the root), slot 200, a PSK 300 on connection 2.
fn v1() -> CatalogPayload {
    let mut one = connection(1, "One");
    one.folder = Some(id(102));
    one.slot = Some(id(200));
    let mut two = connection(2, "Two");
    two.secret_refs.insert(SecretField::Psk, id(300));
    CatalogPayload {
        version: PAYLOAD_VERSION,
        folders: vec![folder(102, Some(101), "Lab"), folder(100, None, "Offices"), folder(101, Some(100), "Budapest")],
        connections: vec![one, two],
        credential_slots: vec![CredentialSlot { id: id(200), name: "Office AD".into() }],
        shared_secrets: BTreeMap::from([(id(300), Zeroizing::new("psk".to_string()))]),
    }
}

/// What the vault holds after `payload` was applied to catalog `cat`.
fn applied(cat: u128, name: &str, payload: &CatalogPayload) -> LocalCatalog {
    let cat = id(cat);
    let mut items = Vec::new();
    for f in &payload.folders {
        items.push(LocalItem {
            local_id: local_id(cat, CatalogItemKind::Folder, f.id),
            item_id: f.id,
            kind: CatalogItemKind::Folder,
            config_hash: None,
            meta_hash: folder_hash(f),
            pending_removal: false,
            slot_id: None,
            provided: BTreeSet::new(),
            parent: Some(f.parent.map_or(root_folder_id(cat), |p| local_id(cat, CatalogItemKind::Folder, p))),
        });
    }
    for c in &payload.connections {
        items.push(LocalItem {
            local_id: local_id(cat, CatalogItemKind::Connection, c.id),
            item_id: c.id,
            kind: CatalogItemKind::Connection,
            config_hash: Some(config_hash(c)),
            meta_hash: meta_hash(c, payload),
            pending_removal: false,
            slot_id: c.slot,
            provided: c.secret_refs.keys().copied().collect(),
            parent: None,
        });
    }
    items.sort_by_key(|i| i.local_id);
    LocalCatalog {
        catalog_id: cat,
        name: name.into(),
        root_folder: root_folder_id(cat),
        items,
        slots: payload.credential_slots.iter().map(|s| (s.id, (s.name.clone(), None))).collect(),
    }
}

fn empty_local(cat: u128, name: &str) -> LocalCatalog {
    applied(cat, name, &CatalogPayload { folders: vec![], connections: vec![], credential_slots: vec![], ..v1() })
}

/// One edit of a payload.
type Change = Box<dyn Fn(&mut CatalogPayload)>;

fn none() -> HashSet<Uuid> {
    HashSet::new()
}

fn conn_local(cat: u128, n: u128) -> Uuid {
    local_id(id(cat), CatalogItemKind::Connection, id(n))
}

fn folder_local(cat: u128, n: u128) -> Uuid {
    local_id(id(cat), CatalogItemKind::Folder, id(n))
}

fn position(ops: &[CatalogOp], wanted: &CatalogOp) -> usize {
    ops.iter().position(|op| op == wanted).unwrap_or_else(|| panic!("{wanted:?} not in {ops:#?}"))
}

#[test]
fn first_apply_adds_everything_parents_first() {
    let plan = plan_apply(&empty_local(CAT_A, "Acme VPN"), "Acme VPN", &v1(), &none());
    assert_eq!(plan.summary, ApplySummary { added: 2, changed: 0, removed: 0, deferred: 0 });
    let upsert = |n: u128| {
        plan.ops
            .iter()
            .position(
                |op| matches!(op, CatalogOp::UpsertFolder { local_id, .. } if *local_id == folder_local(CAT_A, n)),
            )
            .unwrap()
    };
    assert!(upsert(100) < upsert(101) && upsert(101) < upsert(102), "parents before children");
    let root = root_folder_id(id(CAT_A));
    assert!(plan.ops.contains(&CatalogOp::UpsertFolder {
        local_id: folder_local(CAT_A, 100),
        parent: root,
        name: "Offices".into(),
        color: None,
        position: 0
    }));
    let slot = position(&plan.ops, &CatalogOp::UpsertSlot { slot: id(200), name: "Office AD".into() });
    let add = position(&plan.ops, &CatalogOp::AddConnection { local_id: conn_local(CAT_A, 1), item: id(1) });
    let secret = position(
        &plan.ops,
        &CatalogOp::SetProvidedSecret { local_id: conn_local(CAT_A, 2), field: SecretField::Psk, secret: id(300) },
    );
    let link = position(&plan.ops, &CatalogOp::LinkSlot { local_id: conn_local(CAT_A, 1), slot: id(200) });
    assert!(upsert(102) < slot && slot < add && add < secret && secret < link, "{:#?}", plan.ops);
}

#[test]
fn an_unchanged_catalog_gives_no_op() {
    let old = applied(CAT_A, "Acme VPN", &v1());
    let plan = plan_apply(&old, "Acme VPN", &v1(), &none());
    assert!(plan.is_empty(), "{:#?}", plan.ops);
    assert_eq!(plan.summary, ApplySummary::default());
}

#[test]
fn each_kind_of_change_updates_the_connection() {
    let old = applied(CAT_A, "Acme VPN", &v1());
    let changes: Vec<(&str, Change, bool)> = vec![
        ("config only", Box::new(|p| p.connections[0].config.push_str("verb 3\n")), true),
        ("name only", Box::new(|p| p.connections[0].name = "Renamed".into()), false),
        ("folder move", Box::new(|p| p.connections[0].folder = Some(id(100))), false),
        ("colour", Box::new(|p| p.connections[0].color = Some(FolderColor::Red)), false),
        ("otp", Box::new(|p| p.connections[0].otp = OTPSetting::new(true, OTPSeparator::Comma)), false),
        ("slot", Box::new(|p| p.connections[0].slot = None), false),
        (
            "secret refs",
            Box::new(|p| {
                p.connections[0].secret_refs.insert(SecretField::KeyPassword, id(300));
            }),
            false,
        ),
    ];
    for (what, change, config_changed) in changes {
        let mut new = v1();
        change(&mut new);
        let plan = plan_apply(&old, "Acme VPN", &new, &none());
        assert_eq!(plan.summary, ApplySummary { changed: 1, ..Default::default() }, "{what}");
        assert!(
            plan.ops.contains(&CatalogOp::UpdateConnection {
                local_id: conn_local(CAT_A, 1),
                item: id(1),
                config_changed,
                native_changed: false
            }),
            "{what}: {:#?}",
            plan.ops
        );
    }
    // The slot removal unlinks; the new secret ref is written.
    let mut new = v1();
    new.connections[0].slot = None;
    assert!(
        plan_apply(&old, "Acme VPN", &new, &none())
            .ops
            .contains(&CatalogOp::UnlinkSlot { local_id: conn_local(CAT_A, 1) })
    );
}

#[test]
fn a_team_secret_that_changes_value_or_is_withdrawn() {
    let old = applied(CAT_A, "Acme VPN", &v1());
    let mut new = v1();
    new.shared_secrets.insert(id(300), Zeroizing::new("new-psk".to_string()));
    let plan = plan_apply(&old, "Acme VPN", &new, &none());
    assert!(plan.ops.contains(&CatalogOp::SetProvidedSecret {
        local_id: conn_local(CAT_A, 2),
        field: SecretField::Psk,
        secret: id(300)
    }));
    let mut new = v1();
    new.connections[1].secret_refs.clear();
    new.shared_secrets.clear();
    let plan = plan_apply(&old, "Acme VPN", &new, &none());
    assert!(
        plan.ops.contains(&CatalogOp::ClearProvidedSecret { local_id: conn_local(CAT_A, 2), field: SecretField::Psk })
    );
}

#[test]
fn a_native_settings_change_flags_the_profile() {
    let mut p = v1();
    let mut l2tp = connection(3, "L2TP");
    l2tp.kind = VPNKind::L2tp;
    l2tp.config = Zeroizing::new(String::new());
    l2tp.native = Some(NativeSettings { server: "a.example.com".into(), ..Default::default() });
    p.connections.push(l2tp);
    let old = applied(CAT_A, "Acme VPN", &p);
    p.connections[2].native.as_mut().unwrap().server = "b.example.com".into();
    let plan = plan_apply(&old, "Acme VPN", &p, &none());
    assert!(plan.ops.contains(&CatalogOp::UpdateConnection {
        local_id: conn_local(CAT_A, 3),
        item: id(3),
        config_changed: true,
        native_changed: true
    }));
}

#[test]
fn a_removal_and_a_rename_of_the_catalog() {
    let old = applied(CAT_A, "Acme VPN", &v1());
    let mut new = v1();
    new.connections.remove(0);
    let plan = plan_apply(&old, "Acme Team", &new, &none());
    assert_eq!(plan.ops[0], CatalogOp::RenameRoot { name: "Acme Team".into() });
    assert!(plan.ops.contains(&CatalogOp::RemoveConnection { local_id: conn_local(CAT_A, 1) }));
    assert_eq!(plan.summary, ApplySummary { removed: 1, ..Default::default() });
}

#[test]
fn a_connection_that_is_up_is_updated_or_marked() {
    let old = applied(CAT_A, "Acme VPN", &v1());
    let active = HashSet::from([conn_local(CAT_A, 1)]);
    // Changed while up: updated at once.
    let mut new = v1();
    new.connections[0].config.push_str("verb 3\n");
    let plan = plan_apply(&old, "Acme VPN", &new, &active);
    assert_eq!(plan.summary.changed, 1);
    assert!(
        plan.ops
            .iter()
            .any(|op| matches!(op, CatalogOp::UpdateConnection { local_id, .. } if *local_id == conn_local(CAT_A, 1)))
    );

    // Removed while up: marked, moved to the root, deferred.
    let mut new = v1();
    new.connections.remove(0);
    let plan = plan_apply(&old, "Acme VPN", &new, &active);
    assert_eq!(plan.summary, ApplySummary { removed: 1, deferred: 1, ..Default::default() });
    assert!(plan.ops.contains(&CatalogOp::MarkPendingRemoval {
        local_id: conn_local(CAT_A, 1),
        folder_to: root_folder_id(id(CAT_A))
    }));
    assert!(!plan.ops.iter().any(|op| matches!(op, CatalogOp::RemoveConnection { .. })));

    // Later, once it is down, plan_pending removes it.
    let mut marked = applied(CAT_A, "Acme VPN", &new);
    let mut item = old.items.iter().find(|i| i.local_id == conn_local(CAT_A, 1)).unwrap().clone();
    item.pending_removal = true;
    marked.items.push(item);
    assert!(plan_pending(&marked, &active).is_empty(), "still up");
    let plan = plan_pending(&marked, &none());
    assert_eq!(plan.ops, [CatalogOp::RemoveConnection { local_id: conn_local(CAT_A, 1) }]);
    // A pending item that is still up is not marked or counted again by the next apply.
    let again = plan_apply(&marked, "Acme VPN", &new, &active);
    assert!(again.is_empty(), "{:#?}", again.ops);
    // And one that comes back in a later version is updated (back into its folder).
    let back = plan_apply(&marked, "Acme VPN", &v1(), &active);
    assert!(
        back.ops
            .iter()
            .any(|op| matches!(op, CatalogOp::UpdateConnection { local_id, .. } if *local_id == conn_local(CAT_A, 1)))
    );
}

#[test]
fn removals_are_ordered_connections_then_folders_children_first_then_slots() {
    let old = applied(CAT_A, "Acme VPN", &v1());
    let new = CatalogPayload { folders: vec![], connections: vec![], credential_slots: vec![], ..v1() };
    let plan = plan_apply(&old, "Acme VPN", &new, &none());
    let at = |op: CatalogOp| position(&plan.ops, &op);
    let c1 = at(CatalogOp::RemoveConnection { local_id: conn_local(CAT_A, 1) });
    let f102 = at(CatalogOp::RemoveFolder { local_id: folder_local(CAT_A, 102) });
    let f101 = at(CatalogOp::RemoveFolder { local_id: folder_local(CAT_A, 101) });
    let f100 = at(CatalogOp::RemoveFolder { local_id: folder_local(CAT_A, 100) });
    let slot = at(CatalogOp::RemoveSlot { slot: id(200) });
    assert!(c1 < f102 && f102 < f101 && f101 < f100 && f100 < slot, "{:#?}", plan.ops);
    assert_eq!(plan.summary.removed, 2);
}

#[test]
fn unsubscribe_removes_every_item_and_slot() {
    let old = applied(CAT_A, "Acme VPN", &v1());
    let plan = plan_unsubscribe(&old);
    let removed = &plan.ops;
    for op in [
        CatalogOp::RemoveConnection { local_id: conn_local(CAT_A, 1) },
        CatalogOp::RemoveConnection { local_id: conn_local(CAT_A, 2) },
        CatalogOp::RemoveFolder { local_id: folder_local(CAT_A, 100) },
        CatalogOp::RemoveFolder { local_id: folder_local(CAT_A, 101) },
        CatalogOp::RemoveFolder { local_id: folder_local(CAT_A, 102) },
        CatalogOp::RemoveSlot { slot: id(200) },
    ] {
        assert!(removed.contains(&op), "{op:?}");
    }
    assert_eq!(plan.ops.len(), 6);
    assert!(
        position(&plan.ops, &CatalogOp::RemoveFolder { local_id: folder_local(CAT_A, 102) })
            < position(&plan.ops, &CatalogOp::RemoveFolder { local_id: folder_local(CAT_A, 100) })
    );
}

#[test]
fn several_catalogs_with_the_same_item_ids_stay_apart() {
    let a = plan_apply(&empty_local(CAT_A, "A"), "A", &v1(), &none());
    let b = plan_apply(&empty_local(CAT_B, "B"), "B", &v1(), &none());
    let ids = |plan: &macvpn_core::catalog::planner::ApplyPlan| -> HashSet<Uuid> {
        plan.ops
            .iter()
            .filter_map(|op| match op {
                CatalogOp::AddConnection { local_id, .. } | CatalogOp::UpsertFolder { local_id, .. } => Some(*local_id),
                _ => None,
            })
            .collect()
    };
    assert_eq!(ids(&a).len(), 5);
    assert!(ids(&a).is_disjoint(&ids(&b)), "namespaced: disjoint local ids");
    assert_ne!(conn_local(CAT_A, 1), conn_local(CAT_B, 1));
    // Applying (or removing) one catalog never names a row of the other.
    let gone = plan_apply(&applied(CAT_A, "A", &v1()), "A", &CatalogPayload { connections: vec![], ..v1() }, &none());
    for op in &gone.ops {
        if let CatalogOp::RemoveConnection { local_id } = op {
            assert!(![conn_local(CAT_B, 1), conn_local(CAT_B, 2)].contains(local_id));
        }
    }
    assert!(
        plan_unsubscribe(&applied(CAT_A, "A", &v1()))
            .ops
            .iter()
            .all(|op| !ids(&b).iter().any(|id| format!("{op:?}").contains(&id.to_string())))
    );
}
