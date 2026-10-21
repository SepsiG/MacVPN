//! The catalog executor (plan Task 7): applying planner output to the vault in one transaction, what survives an
//! apply, provided secrets, credential slots, unsubscribe and "Duplicate as personal connection".

mod common;

use common::TempDir;
use macvpn_core::catalog::ids::{CatalogItemKind, local_id, root_folder_id};
use macvpn_core::catalog::keys::{AdminKey, TeamKey};
use macvpn_core::catalog::payload::{
    CatalogConnection, CatalogFolder, CatalogPayload, CredentialSlot, PAYLOAD_VERSION, validate_payload,
};
use macvpn_core::catalog::planner::{ApplyPlan, CatalogOp, plan_apply, plan_pending, plan_unsubscribe};
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl};
use macvpn_core::date::Date;
use macvpn_core::models::{SecretField, VPNKind, uuid_string};
use macvpn_core::ranking::{ConnectionRanking, UsageStats};
use macvpn_core::vault::{
    ApplyContext, Dek, FixedEntropy, FolderColor, SourceValidators, SubscriptionRecord, SubscriptionStatus, Vault,
    VaultError,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use uuid::Uuid;
use zeroize::Zeroizing;

const OPENVPN: &str = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nnobind\nauth-user-pass\n";

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0x2000_0000_0000_4000_8000_0000_0000_0000 + n)
}

fn cat() -> Uuid {
    id(0xCA7)
}

fn conn_local(n: u128) -> Uuid {
    local_id(cat(), CatalogItemKind::Connection, id(n))
}

fn key(n: u128) -> String {
    uuid_string(&conn_local(n))
}

fn folder_local(n: u128) -> Uuid {
    local_id(cat(), CatalogItemKind::Folder, id(n))
}

fn connection(n: u128, name: &str) -> CatalogConnection {
    CatalogConnection {
        id: id(n),
        name: name.into(),
        kind: VPNKind::Openvpn,
        folder: None,
        color: None,
        config: Zeroizing::new(OPENVPN.into()),
        native: None,
        otp: Default::default(),
        slot: None,
        secret_refs: BTreeMap::new(),
    }
}

/// Folder 100 (blue) > 101; connection 1 in 101 (red, slot 200), connection 2 at the root (slot 200, PSK 300),
/// connection 3 in 100.
fn v1() -> CatalogPayload {
    let mut one = connection(1, "One");
    one.folder = Some(id(101));
    one.color = Some(FolderColor::Red);
    one.slot = Some(id(200));
    let mut two = connection(2, "Two");
    two.slot = Some(id(200));
    two.secret_refs.insert(SecretField::KeyPassword, id(300));
    let mut three = connection(3, "Three");
    three.folder = Some(id(100));
    let p = CatalogPayload {
        version: PAYLOAD_VERSION,
        folders: vec![
            CatalogFolder {
                id: id(100),
                parent: None,
                name: "Offices".into(),
                color: Some(FolderColor::Blue),
                position: 0,
            },
            CatalogFolder { id: id(101), parent: Some(id(100)), name: "Lab".into(), color: None, position: 0 },
        ],
        connections: vec![one, two, three],
        credential_slots: vec![CredentialSlot { id: id(200), name: "Office AD".into() }],
        shared_secrets: BTreeMap::from([(id(300), Zeroizing::new("team-key-pass".to_string()))]),
    };
    validate_payload(&p).unwrap();
    p
}

fn now() -> Date {
    Date::parse_iso8601("2026-10-19T08:00:00Z").unwrap()
}

fn new_vault(tmp: &TempDir) -> Vault {
    fs::create_dir_all(tmp.path()).unwrap();
    Vault::create(&tmp.path().join("MacVPN"), &Dek::generate(&FixedEntropy::new(4)).unwrap()).unwrap()
}

fn subscribe(vault: &mut Vault, name: &str) {
    let admin = AdminKey::generate(&FixedEntropy::new(9)).unwrap();
    let record = SubscriptionRecord {
        catalog_id: cat(),
        name: name.into(),
        source: CatalogSource::Https(HttpsUrl::parse("https://vpn.example.com/c.macvpncatalog").unwrap()),
        pinned: admin.public().fingerprint(),
        applied_version: None,
        reapply: false,
        status: SubscriptionStatus::Ok,
        validators: SourceValidators::default(),
        last_attempt: None,
        last_success: None,
        failures: 0,
        has_bearer: false,
        publisher_key: None,
        successor_key: None,
        added: now(),
    };
    vault.add_subscription(&record, &TeamKey::generate(&FixedEntropy::new(1)).unwrap(), None).unwrap();
}

/// Plans and applies `payload` as `version`; returns the plan and the removed ids.
fn apply(vault: &mut Vault, payload: &CatalogPayload, version: u64, active: &HashSet<Uuid>) -> (ApplyPlan, Vec<Uuid>) {
    let mut record = vault.subscription(cat()).unwrap().unwrap();
    let local = vault.local_catalog(cat()).unwrap();
    let plan = plan_apply(&local, &record.name, payload, active);
    record.applied_version = Some(version);
    let removed =
        vault.apply_catalog(&plan, &ApplyContext { catalog_id: cat(), payload, now: now() }, &record).unwrap();
    (plan, removed)
}

fn stored(vault: &Vault, local: Uuid) -> Option<macvpn_core::vault::StoredConnection> {
    vault.connections().unwrap().into_iter().find(|c| c.connection.id == local)
}

fn secret(vault: &Vault, item: &str, field: SecretField) -> Option<String> {
    vault.secret(item, field).unwrap().map(|s| s.as_str().to_owned())
}

fn count(vault: &Vault, sql: &str) -> i64 {
    vault.connection().query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn applying_v1_creates_the_rows_under_the_catalog_root() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    subscribe(&mut vault, "Acme VPN");
    let (plan, removed) = apply(&mut vault, &v1(), 1, &HashSet::new());
    assert_eq!(plan.summary.added, 3);
    assert!(removed.is_empty());
    assert_eq!(vault.subscription(cat()).unwrap().unwrap().applied_version, Some(1));

    let tree = vault.folder_tree().unwrap();
    let root = root_folder_id(cat());
    let offices = tree.get(folder_local(100)).unwrap();
    assert_eq!(
        (offices.parent, offices.name.as_str(), offices.color),
        (Some(root), "Offices", Some(FolderColor::Blue))
    );
    assert_eq!(tree.get(folder_local(101)).unwrap().parent, Some(folder_local(100)));

    let one = stored(&vault, conn_local(1)).unwrap();
    assert_eq!(one.connection.name, "One");
    assert_eq!(one.folder_id, Some(folder_local(101)));
    assert_eq!(one.color, None, "no local override");
    assert_eq!(vault.catalog_color(&key(1)).unwrap(), Some(FolderColor::Red), "the publisher's colour");
    assert_eq!(one.connection.created_at, now());
    assert_eq!(*vault.config(&conn_local(1)).unwrap(), OPENVPN);
    assert_eq!(stored(&vault, conn_local(2)).unwrap().folder_id, Some(root));

    // Both connections of slot 200 link to one new, empty credential named after the slot.
    let credential = vault.credential_of(&key(1)).unwrap().unwrap();
    assert_eq!(vault.credential_of(&key(2)).unwrap(), Some(credential));
    let c = vault.credential(credential).unwrap().unwrap();
    assert_eq!((c.name.as_str(), c.username.as_str(), c.has_password), ("Office AD", "", false));
    assert_eq!(vault.local_catalog(cat()).unwrap().slots[&id(200)], ("Office AD".to_string(), Some(credential)));

    // The provided key password is the item's own secret, recorded as provided.
    assert_eq!(secret(&vault, &key(2), SecretField::KeyPassword).as_deref(), Some("team-key-pass"));
    let owner = vault.catalog_owner(&key(2)).unwrap().unwrap();
    assert!(owner.provided_secrets.contains(&SecretField::KeyPassword));

    // Applying the same version again changes nothing.
    let (plan, _) = apply(&mut vault, &v1(), 1, &HashSet::new());
    assert!(plan.is_empty(), "{:#?}", plan.ops);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn the_acknowledgement_survives_only_a_byte_identical_config() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    subscribe(&mut vault, "Acme VPN");
    apply(&mut vault, &v1(), 1, &HashSet::new());
    let seen = vault.config(&conn_local(1)).unwrap();
    vault.set_acknowledged_risky(conn_local(1), &seen, &["up".into()]).unwrap();

    let mut v2 = v1();
    v2.connections[0].name = "One renamed".into();
    apply(&mut vault, &v2, 2, &HashSet::new());
    let one = stored(&vault, conn_local(1)).unwrap();
    assert_eq!(one.connection.name, "One renamed");
    assert_eq!(one.connection.acknowledged_risky_directives, ["up"], "name only: kept");

    let mut v3 = v2.clone();
    v3.connections[0].config.push_str("verb 3\n");
    apply(&mut vault, &v3, 3, &HashSet::new());
    let one = stored(&vault, conn_local(1)).unwrap();
    assert!(one.connection.acknowledged_risky_directives.is_empty(), "config changed: asked again");
    assert_eq!(one.connection.created_at, now(), "created_at kept");
    assert!(vault.config(&conn_local(1)).unwrap().ends_with("verb 3\n"));
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn user_state_survives_an_apply_and_a_removal_drops_its_pin_and_ranking() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    subscribe(&mut vault, "Acme VPN");
    apply(&mut vault, &v1(), 1, &HashSet::new());
    vault.set_item_color(&key(1), Some(FolderColor::Green)).unwrap();
    vault.set_collapsed(folder_local(100), true).unwrap();
    vault.set_collapsed(root_folder_id(cat()), true).unwrap();
    let mut usage = HashMap::new();
    usage.insert(key(1), UsageStats { score: 3.0, last_updated: now() });
    usage.insert(key(3), UsageStats { score: 1.0, last_updated: now() });
    vault.save_ranking(&ConnectionRanking::new(vec![key(1), key(3)], usage)).unwrap();

    let mut v2 = v1();
    v2.connections[0].color = Some(FolderColor::Purple);
    v2.folders[0].name = "Offices EU".into();
    v2.connections.remove(2);
    let (plan, removed) = apply(&mut vault, &v2, 2, &HashSet::new());
    assert_eq!(removed, [conn_local(3)]);
    assert_eq!(plan.summary.removed, 1);

    assert_eq!(stored(&vault, conn_local(1)).unwrap().color, Some(FolderColor::Green), "override kept");
    assert_eq!(vault.catalog_color(&key(1)).unwrap(), Some(FolderColor::Purple));
    let tree = vault.folder_tree().unwrap();
    let offices = tree.get(folder_local(100)).unwrap();
    assert!(offices.collapsed && offices.name == "Offices EU");
    assert!(tree.get(root_folder_id(cat())).unwrap().collapsed);
    let ranking = vault.ranking().unwrap();
    assert_eq!(ranking.pinned(), std::slice::from_ref(&key(1)));
    assert!(ranking.usage().contains_key(&key(1)) && !ranking.usage().contains_key(&key(3)));
    assert!(stored(&vault, conn_local(3)).is_none());
    assert!(vault.catalog_owner(&key(3)).unwrap().is_none());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_provided_secret_is_read_only_and_deleted_when_withdrawn() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    subscribe(&mut vault, "Acme VPN");
    apply(&mut vault, &v1(), 1, &HashSet::new());
    assert!(matches!(
        vault.set_item_secret(&key(2), SecretField::KeyPassword, "mine"),
        Err(VaultError::CatalogManaged)
    ));
    // The user's own PSK on the same item is theirs.
    vault.set_item_secret(&key(2), SecretField::Psk, "own").unwrap();

    let mut v2 = v1();
    v2.connections[1].secret_refs.clear();
    v2.shared_secrets.clear();
    apply(&mut vault, &v2, 2, &HashSet::new());
    assert_eq!(secret(&vault, &key(2), SecretField::KeyPassword), None, "no team secret lingers");
    assert_eq!(secret(&vault, &key(2), SecretField::Psk).as_deref(), Some("own"));
    vault.set_item_secret(&key(2), SecretField::KeyPassword, "mine now").unwrap();
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_taken_slot_name_is_suffixed_and_an_own_login_is_not_linked() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    subscribe(&mut vault, "Acme VPN");
    let personal = vault.create_credential("Office AD", "me", Some("pw")).unwrap();
    // Connection 1 already has its own login (restored from a backup, for example).
    vault
        .transaction(|tx| {
            tx.set_secret(&key(1), SecretField::Username, "alice")?;
            tx.set_secret(&key(1), SecretField::Password, "pw")
        })
        .unwrap();
    apply(&mut vault, &v1(), 1, &HashSet::new());

    assert_eq!(vault.credential_of(&key(1)).unwrap(), None, "own login: not linked");
    assert_eq!(secret(&vault, &key(1), SecretField::Username).as_deref(), Some("alice"));
    let slot = vault.credential_of(&key(2)).unwrap().unwrap();
    assert_ne!(slot, personal, "never linked to a personal credential by name");
    assert_eq!(vault.credential(slot).unwrap().unwrap().name, "Office AD (Acme VPN)");
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_failure_in_the_middle_of_a_plan_changes_nothing() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    subscribe(&mut vault, "Acme VPN");
    apply(&mut vault, &v1(), 1, &HashSet::new());
    let before = (
        count(&vault, "SELECT count(*) FROM connections"),
        count(&vault, "SELECT count(*) FROM folders"),
        count(&vault, "SELECT count(*) FROM catalog_items"),
    );

    let mut v2 = v1();
    v2.connections[0].name = "Changed".into();
    v2.connections.remove(2);
    let local = vault.local_catalog(cat()).unwrap();
    let mut plan = plan_apply(&local, "Acme VPN", &v2, &HashSet::new());
    // An op the payload cannot satisfy, after the rename and before the removal.
    let at = plan.ops.iter().position(|op| matches!(op, CatalogOp::RemoveConnection { .. })).unwrap();
    plan.ops.insert(at, CatalogOp::AddConnection { local_id: conn_local(99), item: id(99) });
    let mut record = vault.subscription(cat()).unwrap().unwrap();
    record.applied_version = Some(2);
    let r = vault.apply_catalog(&plan, &ApplyContext { catalog_id: cat(), payload: &v2, now: now() }, &record);
    assert!(matches!(r, Err(VaultError::Constraint(_))), "{r:?}");

    assert_eq!(vault.subscription(cat()).unwrap().unwrap().applied_version, Some(1), "the record too");
    assert_eq!(stored(&vault, conn_local(1)).unwrap().connection.name, "One");
    assert!(stored(&vault, conn_local(3)).is_some());
    assert_eq!(
        before,
        (
            count(&vault, "SELECT count(*) FROM connections"),
            count(&vault, "SELECT count(*) FROM folders"),
            count(&vault, "SELECT count(*) FROM catalog_items"),
        )
    );
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_removed_connection_that_is_up_waits_for_the_disconnect() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    subscribe(&mut vault, "Acme VPN");
    apply(&mut vault, &v1(), 1, &HashSet::new());
    let active = HashSet::from([conn_local(1)]);
    let mut v2 = v1();
    v2.connections.remove(0);
    v2.folders.remove(1);
    let (plan, removed) = apply(&mut vault, &v2, 2, &active);
    assert_eq!((plan.summary.removed, plan.summary.deferred), (1, 1));
    assert!(removed.is_empty());
    let one = stored(&vault, conn_local(1)).unwrap();
    assert_eq!(one.folder_id, Some(root_folder_id(cat())), "moved to the catalog root");
    assert!(vault.catalog_owner(&key(1)).unwrap().unwrap().pending_removal);
    assert!(vault.folder_tree().unwrap().get(folder_local(101)).is_none(), "its folder went");

    // Once down: plan_pending removes it.
    let local = vault.local_catalog(cat()).unwrap();
    let plan = plan_pending(&local, &HashSet::new());
    let record = vault.subscription(cat()).unwrap().unwrap();
    let removed =
        vault.apply_catalog(&plan, &ApplyContext { catalog_id: cat(), payload: &v2, now: now() }, &record).unwrap();
    assert_eq!(removed, [conn_local(1)]);
    assert!(stored(&vault, conn_local(1)).is_none());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn unsubscribe_keeps_a_filled_slot_credential_and_refuses_while_active() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    subscribe(&mut vault, "Acme VPN");
    let mut p = v1();
    p.credential_slots.push(CredentialSlot { id: id(201), name: "Unused slot".into() });
    p.connections[2].slot = Some(id(201));
    apply(&mut vault, &p, 1, &HashSet::new());
    let filled = vault.credential_of(&key(1)).unwrap().unwrap();
    let unfilled = vault.credential_of(&key(3)).unwrap().unwrap();
    vault.save_prompted_secret(&key(1), SecretField::Username, "alice").unwrap();
    vault.save_prompted_secret(&key(1), SecretField::Password, "pw").unwrap();
    let personal = macvpn_core::models::Connection::new("Mine", VPNKind::Wireguard);
    vault.save_connection(&personal, Some("[Interface]\n")).unwrap();

    let local = vault.local_catalog(cat()).unwrap();
    let plan = plan_unsubscribe(&local);
    let r = vault.unsubscribe_catalog(cat(), &plan, &HashSet::from([conn_local(2)]));
    assert!(matches!(r, Err(VaultError::Constraint(_))), "{r:?}");
    assert!(stored(&vault, conn_local(2)).is_some(), "nothing changed");

    let report = vault.unsubscribe_catalog(cat(), &plan, &HashSet::new()).unwrap();
    let mut removed = report.removed_connections.clone();
    removed.sort();
    let mut expected = vec![conn_local(1), conn_local(2), conn_local(3)];
    expected.sort();
    assert_eq!(removed, expected);
    assert_eq!(report.kept_credentials, ["Office AD"]);
    let kept = vault.credential(filled).unwrap().unwrap();
    assert_eq!(kept.username, "alice");
    assert!(vault.credential(unfilled).unwrap().is_none(), "the unfilled one is deleted");
    assert!(vault.subscriptions().unwrap().is_empty());
    assert!(vault.folders().unwrap().is_empty(), "the root and its folders are gone");
    assert_eq!(count(&vault, "SELECT count(*) FROM catalog_items"), 0);
    assert_eq!(count(&vault, "SELECT count(*) FROM catalog_slots"), 0);
    assert_eq!(vault.connections().unwrap().len(), 1, "the personal connection stays");
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn an_acknowledgement_of_an_older_config_is_refused() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    subscribe(&mut vault, "Acme VPN");
    apply(&mut vault, &v1(), 1, &HashSet::new());
    let seen_v1 = vault.config(&conn_local(1)).unwrap();
    let mut v2 = v1();
    v2.connections[0].config.push_str("verb 3\n");
    apply(&mut vault, &v2, 2, &HashSet::new());

    let e = vault.set_acknowledged_risky(conn_local(1), &seen_v1, &["up".into()]).unwrap_err();
    assert!(matches!(e, VaultError::CatalogChanged), "{e:?}");
    assert!(stored(&vault, conn_local(1)).unwrap().connection.acknowledged_risky_directives.is_empty());
    // The current config is acknowledged.
    let seen_v2 = vault.config(&conn_local(1)).unwrap();
    vault.set_acknowledged_risky(conn_local(1), &seen_v2, &["up".into()]).unwrap();
    assert_eq!(stored(&vault, conn_local(1)).unwrap().connection.acknowledged_risky_directives, ["up"]);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn forgetting_a_catalog_item_or_its_provided_secrets_is_refused() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    subscribe(&mut vault, "Acme VPN");
    apply(&mut vault, &v1(), 1, &HashSet::new());
    // Connection 2 has a provided key password.
    assert!(matches!(vault.forget_item(&key(2)), Err(VaultError::CatalogManaged)));
    assert!(matches!(vault.delete_secrets(&key(2)), Err(VaultError::CatalogManaged)));
    assert_eq!(secret(&vault, &key(2), SecretField::KeyPassword).as_deref(), Some("team-key-pass"));
    // A catalog connection is never forgotten (its slot link is the catalog's).
    assert!(matches!(vault.forget_item(&key(1)), Err(VaultError::CatalogManaged)));
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn duplicate_makes_an_independent_editable_copy() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    subscribe(&mut vault, "Acme VPN");
    apply(&mut vault, &v1(), 1, &HashSet::new());
    let seen = vault.config(&conn_local(2)).unwrap();
    vault.set_acknowledged_risky(conn_local(2), &seen, &["up".into()]).unwrap();
    vault.set_item_secret(&key(2), SecretField::Psk, "own psk").unwrap();

    let copy = vault.duplicate_catalog_connection(conn_local(2), "Two (mine)").unwrap();
    let ck = uuid_string(&copy);
    let c = stored(&vault, copy).unwrap();
    assert_eq!((c.connection.name.as_str(), c.connection.kind, c.folder_id), ("Two (mine)", VPNKind::Openvpn, None));
    assert!(c.connection.acknowledged_risky_directives.is_empty());
    assert_eq!(*vault.config(&copy).unwrap(), OPENVPN);
    assert!(vault.catalog_owner(&ck).unwrap().is_none(), "no catalog row");
    assert_eq!(secret(&vault, &ck, SecretField::KeyPassword).as_deref(), Some("team-key-pass"));
    assert_eq!(secret(&vault, &ck, SecretField::Psk).as_deref(), Some("own psk"));
    assert_eq!(vault.credential_of(&ck).unwrap(), vault.credential_of(&key(2)).unwrap());

    // Saving it works, and the catalog item is unchanged.
    let mut edited = c.connection.clone();
    edited.name = "Edited".into();
    vault.save_connection(&edited, Some("client\n")).unwrap();
    vault.set_item_secret(&ck, SecretField::KeyPassword, "changed").unwrap();
    assert_eq!(*vault.config(&conn_local(2)).unwrap(), OPENVPN);
    assert_eq!(stored(&vault, conn_local(2)).unwrap().connection.name, "Two");
    assert_eq!(secret(&vault, &key(2), SecretField::KeyPassword).as_deref(), Some("team-key-pass"));

    assert!(matches!(vault.duplicate_catalog_connection(copy, "x"), Err(VaultError::Constraint(_))));
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn subscribe_catalog_stores_and_applies_in_one_transaction() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let admin = AdminKey::generate(&FixedEntropy::new(9)).unwrap();
    let record = SubscriptionRecord {
        catalog_id: cat(),
        name: "Acme VPN".into(),
        source: CatalogSource::Https(HttpsUrl::parse("https://vpn.example.com/c.macvpncatalog").unwrap()),
        pinned: admin.public().fingerprint(),
        applied_version: Some(1),
        reapply: false,
        status: SubscriptionStatus::Ok,
        validators: SourceValidators::default(),
        last_attempt: Some(now()),
        last_success: Some(now()),
        failures: 0,
        has_bearer: true,
        publisher_key: Some(admin.public()),
        successor_key: None,
        added: now(),
    };
    let payload = v1();
    let empty = macvpn_core::catalog::planner::LocalCatalog {
        catalog_id: cat(),
        name: "Acme VPN".into(),
        root_folder: root_folder_id(cat()),
        items: Vec::new(),
        slots: BTreeMap::new(),
    };
    let plan = plan_apply(&empty, "Acme VPN", &payload, &HashSet::new());
    let team_key = TeamKey::generate(&FixedEntropy::new(1)).unwrap();
    // A plan for another catalog: refused, nothing stored.
    let wrong = ApplyContext { catalog_id: id(0xBAD), payload: &payload, now: now() };
    assert!(vault.subscribe_catalog(&record, &team_key, Some("tok"), &plan, &wrong).is_err());
    assert!(vault.subscriptions().unwrap().is_empty());
    // A plan that fails half way (a stale op): nothing stored either.
    let mut broken = plan.clone();
    broken.ops.push(CatalogOp::UpdateConnection {
        local_id: conn_local(99),
        item: id(99),
        config_changed: true,
        native_changed: false,
    });
    let ctx = ApplyContext { catalog_id: cat(), payload: &payload, now: now() };
    assert!(vault.subscribe_catalog(&record, &team_key, Some("tok"), &broken, &ctx).is_err());
    assert!(vault.subscriptions().unwrap().is_empty());
    assert_eq!(count(&vault, "SELECT count(*) FROM connections"), 0);
    // The real one.
    vault.subscribe_catalog(&record, &team_key, Some("tok"), &plan, &ctx).unwrap();
    assert_eq!(vault.subscription(cat()).unwrap().unwrap(), record);
    assert!(stored(&vault, conn_local(1)).is_some());
    assert_eq!(count(&vault, "SELECT count(*) FROM connections"), 3);
    assert_eq!(vault.subscription_secrets(cat()).unwrap().1.as_deref().map(|s| s.as_str()), Some("tok"));
    // Twice: refused.
    assert!(vault.subscribe_catalog(&record, &team_key, None, &plan, &ctx).is_err());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_changed_native_connection_is_marked_until_its_profile_is_reinstalled() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    subscribe(&mut vault, "Acme VPN");
    let native = |server: &str| {
        let mut c = connection(4, "Office L2TP");
        c.kind = VPNKind::L2tp;
        c.config = Zeroizing::new(String::new());
        c.native = Some(macvpn_core::models::NativeSettings { server: server.into(), ..Default::default() });
        let mut p = v1();
        p.connections.push(c);
        p
    };
    apply(&mut vault, &native("vpn.example.com"), 1, &HashSet::new());
    assert!(!vault.catalog_owner(&key(4)).unwrap().unwrap().profile_outdated);
    apply(&mut vault, &native("vpn2.example.com"), 2, &HashSet::new());
    assert!(vault.catalog_owner(&key(4)).unwrap().unwrap().profile_outdated);

    // The profile is built from v2; v3 changes the server again before the install is seen: the mark stays.
    let built_from = vault.catalog_owner(&key(4)).unwrap().unwrap().config_hash.expect("a config hash");
    apply(&mut vault, &native("vpn3.example.com"), 3, &HashSet::new());
    assert!(!vault.clear_profile_outdated(conn_local(4), &built_from).unwrap(), "built from an older version");
    assert!(vault.catalog_owner(&key(4)).unwrap().unwrap().profile_outdated);

    let built_from = vault.catalog_owner(&key(4)).unwrap().unwrap().config_hash.unwrap();
    assert!(vault.clear_profile_outdated(conn_local(4), &built_from).unwrap());
    assert!(!vault.catalog_owner(&key(4)).unwrap().unwrap().profile_outdated);
    // Only a catalog connection has the mark.
    assert!(matches!(vault.clear_profile_outdated(folder_local(100), "x"), Err(VaultError::Constraint(_))));
    assert!(matches!(vault.clear_profile_outdated(id(999), "x"), Err(VaultError::Constraint(_))));
}
