//! The pure publish builder (plan Task 14, spec 7 steps 1–3): the selection, team secrets, credential slots, the
//! refusals, the inline key material that needs a tick, and the "changed since the last publish" hashes.

mod common;

use common::TempDir;
use macvpn_core::catalog::ids::{CatalogItemKind, local_id};
use macvpn_core::catalog::keys::{AdminKey, TeamKey};
use macvpn_core::catalog::payload::{
    CatalogConnection, CatalogPayload, InvalidCatalog, PAYLOAD_VERSION, PersonalField, encode_payload,
};
use macvpn_core::catalog::planner::plan_apply;
use macvpn_core::catalog::publish::{BuildError, build_payload, changed_since_publish, preview};
use macvpn_core::catalog::selection::{InlineSecret, PublishSelection};
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl};
use macvpn_core::date::Date;
use macvpn_core::models::{Connection, NativeSettings, SecretField, VPNKind, uuid_string};
use macvpn_core::vault::{
    ApplyContext, Dek, FixedEntropy, FolderColor, PublicationRecord, SourceValidators, SubscriptionRecord,
    SubscriptionStatus, SystemItem, Vault,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use uuid::Uuid;
use zeroize::Zeroizing;

const OPENVPN: &str = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nnobind\nauth-user-pass\n";
const WIREGUARD: &str = "[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = \
                         10.0.0.2/32\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\n\
                         PresharedKey = bWFjdnBuLXRlc3QtcHJlc2hhcmVkLWtleS0zMmJ5dGU=\nAllowedIPs = \
                         0.0.0.0/0\nEndpoint = vpn.example.com:51820\n";
const USERNAME: &str = "alice-user-value";
const PASSWORD: &str = "alice-password-value";
const PSK: &str = "team-psk-value";

fn new_vault(tmp: &TempDir) -> Vault {
    fs::create_dir_all(tmp.path()).unwrap();
    Vault::create(&tmp.path().join("MacVPN"), &Dek::generate(&FixedEntropy::new(3)).unwrap()).unwrap()
}

fn now() -> Date {
    Date::parse_iso8601("2026-10-19T08:00:00Z").unwrap()
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0x4000_0000_0000_4000_8000_0000_0000_0000 + n)
}

fn add(vault: &mut Vault, n: u128, name: &str, kind: VPNKind, config: &str) -> Uuid {
    let c = Connection::with_id(id(n), name, kind, now());
    vault.save_connection(&c, Some(config)).unwrap();
    id(n)
}

fn add_native(vault: &mut Vault, n: u128, name: &str, account: &str) -> Uuid {
    let mut c = Connection::with_id(id(n), name, VPNKind::L2tp, now());
    c.native = Some(NativeSettings {
        server: "vpn.example.com".into(),
        account: account.into(),
        group_name: String::new(),
        send_all_traffic: true,
    });
    c.native_service_name = Some("Acme L2TP".into());
    vault.save_connection(&c, Some("")).unwrap();
    id(n)
}

fn key(id: Uuid) -> String {
    uuid_string(&id)
}

/// Offices (blue) > Lab; "Lab VPN" in Lab (red), "Office" in Offices, "Loose" at the root, "Elsewhere" in Other.
struct Fixture {
    _tmp: TempDir,
    vault: Vault,
    offices: Uuid,
    lab: Uuid,
    other: Uuid,
    lab_vpn: Uuid,
    office: Uuid,
    loose: Uuid,
    elsewhere: Uuid,
    credential: Uuid,
}

fn fixture() -> Fixture {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp);
    let offices = vault.create_folder(None, "Offices").unwrap();
    vault.set_folder_color(offices, Some(FolderColor::Blue)).unwrap();
    let lab = vault.create_folder(Some(offices), "Lab").unwrap();
    let other = vault.create_folder(None, "Other").unwrap();
    let lab_vpn = add(&mut vault, 1, "Lab VPN", VPNKind::Openvpn, OPENVPN);
    vault.set_item_folder(&key(lab_vpn), Some(lab)).unwrap();
    vault.set_item_color(&key(lab_vpn), Some(FolderColor::Red)).unwrap();
    let office = add(&mut vault, 2, "Office", VPNKind::Openvpn, OPENVPN);
    vault.set_item_folder(&key(office), Some(offices)).unwrap();
    let loose = add(&mut vault, 3, "Loose", VPNKind::Openvpn, OPENVPN);
    let elsewhere = add(&mut vault, 4, "Elsewhere", VPNKind::Openvpn, OPENVPN);
    vault.set_item_folder(&key(elsewhere), Some(other)).unwrap();
    let credential = vault.create_credential("Office AD", USERNAME, Some(PASSWORD)).unwrap();
    vault.link(&key(lab_vpn), credential).unwrap();
    vault.link(&key(office), credential).unwrap();
    vault.set_secret(&key(office), SecretField::KeyPassword, PSK).unwrap();
    Fixture { _tmp: tmp, vault, offices, lab, other, lab_vpn, office, loose, elsewhere, credential }
}

fn select(folders: &[Uuid], connections: &[Uuid]) -> PublishSelection {
    PublishSelection {
        folders: folders.iter().copied().collect(),
        connections: connections.iter().copied().collect(),
        ..Default::default()
    }
}

fn build(vault: &Vault, sel: &PublishSelection) -> macvpn_core::catalog::publish::BuiltPayload {
    build_payload(vault, sel, None, &FixedEntropy::new(7)).unwrap()
}

fn conn(p: &CatalogPayload, id: Uuid) -> &CatalogConnection {
    p.connections.iter().find(|c| c.id == id).unwrap()
}

fn json(p: &CatalogPayload) -> String {
    String::from_utf8(encode_payload(p).unwrap().to_vec()).unwrap()
}

#[test]
fn a_selected_folder_brings_its_subtree_and_a_loose_connection_lands_at_the_root() {
    let f = fixture();
    let built = build(&f.vault, &select(&[f.offices], &[f.loose]));
    let p = &built.payload;
    assert_eq!(p.version, PAYLOAD_VERSION);
    let folders: BTreeMap<Uuid, (Option<Uuid>, &str, Option<FolderColor>)> =
        p.folders.iter().map(|x| (x.id, (x.parent, x.name.as_str(), x.color))).collect();
    assert_eq!(
        folders,
        BTreeMap::from([
            (f.offices, (None, "Offices", Some(FolderColor::Blue))),
            (f.lab, (Some(f.offices), "Lab", None)),
        ])
    );
    let ids: BTreeSet<Uuid> = p.connections.iter().map(|c| c.id).collect();
    assert_eq!(ids, BTreeSet::from([f.lab_vpn, f.office, f.loose]), "the publisher's own ids, Other not included");
    assert_eq!(conn(p, f.lab_vpn).folder, Some(f.lab));
    assert_eq!(conn(p, f.lab_vpn).color, Some(FolderColor::Red));
    assert_eq!(conn(p, f.office).folder, Some(f.offices));
    assert_eq!(conn(p, f.loose).folder, None);
    assert_eq!(*conn(p, f.loose).config, OPENVPN);

    // A sub-folder selected alone becomes a top-level folder of the catalog; a connection in an unselected folder
    // goes to the catalog root.
    let built = build(&f.vault, &select(&[f.lab], &[f.elsewhere]));
    assert_eq!(built.payload.folders.len(), 1);
    assert_eq!(built.payload.folders[0].parent, None);
    assert_eq!(conn(&built.payload, f.elsewhere).folder, None);
    let _ = f.other;
}

#[test]
fn secrets_are_offered_but_included_only_when_ticked() {
    let f = fixture();
    let mut sel = select(&[], &[f.office, f.loose]);
    let pv = preview(&f.vault, &sel).unwrap();
    assert_eq!(pv.available_secrets, vec![(f.office, SecretField::KeyPassword)]);
    let built = build(&f.vault, &sel);
    assert!(built.payload.shared_secrets.is_empty());
    assert!(conn(&built.payload, f.office).secret_refs.is_empty());
    assert!(!json(&built.payload).contains(&base64(PSK)));

    sel.secrets.insert((f.office, SecretField::KeyPassword));
    // A tick for a secret that is not stored, or for a field that cannot be shared, adds nothing.
    sel.secrets.insert((f.loose, SecretField::Psk));
    sel.secrets.insert((f.office, SecretField::Password));
    let built = build(&f.vault, &sel);
    let secret_id = built.secret_ids[&(f.office, SecretField::KeyPassword)];
    assert_eq!(built.secret_ids.len(), 1);
    assert_eq!(conn(&built.payload, f.office).secret_refs, BTreeMap::from([(SecretField::KeyPassword, secret_id)]));
    assert_eq!(built.payload.shared_secrets[&secret_id].as_str(), PSK);

    // The id is kept across publishes.
    let prior = record(&sel, &built);
    let again = build_payload(&f.vault, &sel, Some(&prior), &FixedEntropy::new(99)).unwrap();
    assert_eq!(again.secret_ids, built.secret_ids);
}

fn base64(s: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(s)
}

fn record(sel: &PublishSelection, built: &macvpn_core::catalog::publish::BuiltPayload) -> PublicationRecord {
    PublicationRecord {
        catalog_id: id(0xCA7),
        name: "Acme VPN".into(),
        version: 1,
        selection: sel.clone(),
        secret_ids: built.secret_ids.clone(),
        item_hashes: built.item_hashes.clone(),
        last_path: None,
        last_published: Some(now()),
        announced_successor: None,
    }
}

#[test]
fn slots_carry_the_credentials_id_and_name_never_its_values() {
    let f = fixture();
    let mut sel = select(&[f.offices], &[f.loose]);
    let pv = preview(&f.vault, &sel).unwrap();
    assert_eq!(pv.available_slots, vec![(f.credential, "Office AD".to_string(), 2)]);
    // Unticked: no slot, each subscriber's prompt asks per connection.
    let built = build(&f.vault, &sel);
    assert!(built.payload.credential_slots.is_empty());
    assert!(built.payload.connections.iter().all(|c| c.slot.is_none()));

    sel.slots.insert(f.credential);
    let built = build(&f.vault, &sel);
    assert_eq!(built.payload.credential_slots.len(), 1);
    assert_eq!(
        (built.payload.credential_slots[0].id, built.payload.credential_slots[0].name.as_str()),
        (f.credential, "Office AD")
    );
    assert_eq!(conn(&built.payload, f.lab_vpn).slot, Some(f.credential));
    assert_eq!(conn(&built.payload, f.office).slot, Some(f.credential));
    assert_eq!(conn(&built.payload, f.loose).slot, None);
    let text = json(&built.payload);
    for value in [USERNAME, PASSWORD] {
        assert!(!text.contains(value) && !text.contains(&base64(value)), "a credential value in the payload");
    }
    let debug = format!("{:?}", built.payload);
    assert!(!debug.contains(USERNAME) && !debug.contains(PASSWORD));
}

#[test]
fn refusals_are_listed_and_block_the_build() {
    let f = fixture();
    let mut vault = f.vault;
    let inline = add(
        &mut vault,
        10,
        "Inline login",
        VPNKind::Openvpn,
        &format!("{OPENVPN}<auth-user-pass>\nalice\nsecret\n</auth-user-pass>\n"),
    );
    let broken = add(&mut vault, 11, "Broken", VPNKind::Openvpn, "client\nremote\n");
    let sel = select(&[], &[inline, broken, f.loose]);
    let pv = preview(&vault, &sel).unwrap();
    assert_eq!(
        pv.refused,
        vec![
            (inline, InvalidCatalog::InlineCredentials { connection: inline }),
            (broken, InvalidCatalog::Config { connection: broken }),
        ]
    );
    match build_payload(&vault, &sel, None, &FixedEntropy::new(7)) {
        Err(BuildError::Refused(list)) => assert_eq!(list, pv.refused),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(build_payload(&vault, &select(&[], &[f.loose]), None, &FixedEntropy::new(7)).is_ok());
}

#[test]
fn a_native_account_is_listed_and_always_stripped() {
    let f = fixture();
    let mut vault = f.vault;
    let l2tp = add_native(&mut vault, 20, "Acme L2TP", "alice");
    vault.set_secret(&key(l2tp), SecretField::Psk, PSK).unwrap();
    let mut sel = select(&[], &[l2tp]);
    sel.secrets.insert((l2tp, SecretField::Psk));
    let pv = preview(&vault, &sel).unwrap();
    assert_eq!(pv.personal, vec![(l2tp, PersonalField::NativeAccount)]);
    assert_eq!(pv.available_secrets, vec![(l2tp, SecretField::Psk)]);
    let built = build_payload(&vault, &sel, None, &FixedEntropy::new(7)).unwrap();
    let c = conn(&built.payload, l2tp);
    let native = c.native.as_ref().unwrap();
    assert_eq!((native.server.as_str(), native.account.as_str()), ("vpn.example.com", ""));
    assert!(c.config.is_empty());
    assert!(!json(&built.payload).contains("alice"));
    assert_eq!(c.secret_refs.len(), 1);
}

#[test]
fn inline_key_material_needs_an_explicit_tick_each() {
    let f = fixture();
    let mut vault = f.vault;
    let wg = add(&mut vault, 30, "WireGuard lab", VPNKind::Wireguard, WIREGUARD);
    let tls = add(
        &mut vault,
        31,
        "TLS auth",
        VPNKind::Openvpn,
        &format!(
            "{OPENVPN}<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\nabc\n-----END OpenVPN Static key V1-----\n</tls-auth>\nkey-direction 1\n"
        ),
    );
    let mut sel = select(&[], &[wg, tls]);
    let pv = preview(&vault, &sel).unwrap();
    assert_eq!(
        pv.inline_secrets,
        vec![
            (wg, InlineSecret::WireGuardPrivateKey),
            (wg, InlineSecret::WireGuardPresharedKey),
            (tls, InlineSecret::TlsAuth),
        ]
    );
    assert!(pv.personal.contains(&(wg, PersonalField::WireGuardPrivateKey)));
    match build_payload(&vault, &sel, None, &FixedEntropy::new(7)) {
        Err(BuildError::Unacknowledged(list)) => assert_eq!(list, pv.inline_secrets),
        other => panic!("expected the acknowledgement to be required, got {other:?}"),
    }
    // The shared WireGuard private key alone is not enough.
    sel.inline_secrets.insert((wg, InlineSecret::WireGuardPrivateKey));
    sel.inline_secrets.insert((wg, InlineSecret::WireGuardPresharedKey));
    match build_payload(&vault, &sel, None, &FixedEntropy::new(7)) {
        Err(BuildError::Unacknowledged(list)) => assert_eq!(list, vec![(tls, InlineSecret::TlsAuth)]),
        other => panic!("expected the tls-auth tick to be required, got {other:?}"),
    }
    sel.inline_secrets.insert((tls, InlineSecret::TlsAuth));
    let built = build_payload(&vault, &sel, None, &FixedEntropy::new(7)).unwrap();
    assert_eq!(*conn(&built.payload, wg).config, WIREGUARD, "the ticked key material is published as is");
}

const SSTP: &str = "server=vpn.example.com\nport=443\nuser=alice.admin\ncert=system\nroute_all=yes\npeer_dns=yes\n";

#[test]
fn an_sstp_user_goes_with_a_slot_or_needs_a_tick() {
    let f = fixture();
    let mut vault = f.vault;
    let sstp = add(&mut vault, 40, "Office SSTP", VPNKind::Sstp, SSTP);
    let credential = vault.credentials().unwrap().into_iter().find(|c| c.name == "Office AD").unwrap().id;
    vault.link(&key(sstp), credential).unwrap();

    // With the slot ticked: the publisher's user name is not published (the subscriber's slot user goes in at
    // connect), and nothing needs a tick.
    let mut sel = select(&[], &[sstp]);
    sel.slots.insert(credential);
    assert!(preview(&vault, &sel).unwrap().inline_secrets.is_empty());
    let built = build_payload(&vault, &sel, None, &FixedEntropy::new(7)).unwrap();
    let published = conn(&built.payload, sstp).config.to_string();
    assert!(!published.contains("alice.admin"), "{published}");
    assert_eq!(conn(&built.payload, sstp).slot, Some(credential));

    // Without a slot: everyone would connect as that user, so it needs an explicit tick.
    let mut sel = select(&[], &[sstp]);
    assert_eq!(preview(&vault, &sel).unwrap().inline_secrets, vec![(sstp, InlineSecret::SstpUser)]);
    match build_payload(&vault, &sel, None, &FixedEntropy::new(7)) {
        Err(BuildError::Unacknowledged(list)) => assert_eq!(list, vec![(sstp, InlineSecret::SstpUser)]),
        other => panic!("expected the tick to be required, got {other:?}"),
    }
    sel.inline_secrets.insert((sstp, InlineSecret::SstpUser));
    let built = build_payload(&vault, &sel, None, &FixedEntropy::new(7)).unwrap();
    assert!(conn(&built.payload, sstp).config.contains("user=alice.admin\n"), "ticked: published as is");
}

#[test]
fn system_vpns_and_catalog_connections_cannot_be_selected() {
    let f = fixture();
    let mut vault = f.vault;
    let service = id(0x5E);
    vault
        .save_system_item(&SystemItem {
            service_id: uuid_string(&service),
            folder_id: None,
            color: None,
            position: 0,
            missing_since: None,
        })
        .unwrap();
    assert!(matches!(preview(&vault, &select(&[], &[service])), Err(BuildError::NotSelectable(x)) if x == service));
    assert!(matches!(
        build_payload(&vault, &select(&[], &[service]), None, &FixedEntropy::new(7)),
        Err(BuildError::NotSelectable(x)) if x == service
    ));

    // A catalog this publisher itself subscribes to.
    let cat = id(0xCA7);
    let admin = AdminKey::generate(&FixedEntropy::new(9)).unwrap();
    let record = SubscriptionRecord {
        catalog_id: cat,
        name: "Partner VPN".into(),
        source: CatalogSource::Https(HttpsUrl::parse("https://vpn.example.com/p.macvpncatalog").unwrap()),
        pinned: admin.public().fingerprint(),
        applied_version: Some(1),
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
    let payload = CatalogPayload {
        version: PAYLOAD_VERSION,
        folders: Vec::new(),
        connections: vec![CatalogConnection {
            id: id(500),
            name: "Partner".into(),
            kind: VPNKind::Openvpn,
            folder: None,
            color: None,
            config: Zeroizing::new(OPENVPN.into()),
            native: None,
            otp: Default::default(),
            slot: None,
            secret_refs: BTreeMap::new(),
        }],
        credential_slots: Vec::new(),
        shared_secrets: BTreeMap::new(),
    };
    let plan = plan_apply(&vault.local_catalog(cat).unwrap(), "Partner VPN", &payload, &HashSet::new());
    vault.apply_catalog(&plan, &ApplyContext { catalog_id: cat, payload: &payload, now: now() }, &record).unwrap();
    let partner = local_id(cat, CatalogItemKind::Connection, id(500));
    let root = macvpn_core::catalog::ids::root_folder_id(cat);
    assert!(matches!(preview(&vault, &select(&[], &[partner])), Err(BuildError::NotSelectable(x)) if x == partner));
    assert!(matches!(preview(&vault, &select(&[root], &[])), Err(BuildError::NotSelectable(x)) if x == root));
}

#[test]
fn an_empty_selection_is_refused_and_a_deleted_connection_is_dropped() {
    let f = fixture();
    let mut vault = f.vault;
    assert!(matches!(build_payload(&vault, &select(&[], &[]), None, &FixedEntropy::new(7)), Err(BuildError::Empty)));
    vault.delete_connection(&f.loose).unwrap();
    let built = build_payload(&vault, &select(&[], &[f.loose, f.office]), None, &FixedEntropy::new(7)).unwrap();
    assert_eq!(built.payload.connections.len(), 1);
}

#[test]
fn changed_since_publish_marks_what_the_catalog_would_carry_differently() {
    let f = fixture();
    let mut vault = f.vault;
    let mut sel = select(&[f.offices], &[f.loose]);
    sel.slots.insert(f.credential);
    sel.secrets.insert((f.office, SecretField::KeyPassword));
    let built = build_payload(&vault, &sel, None, &FixedEntropy::new(7)).unwrap();
    let published = record(&sel, &built);
    assert_eq!(published.item_hashes.len(), 5, "two folders and three connections");
    assert!(changed_since_publish(&vault, &published).unwrap().is_empty());

    // Things the catalog does not carry change nothing: the credential's password, a local pin.
    vault.update_credential(f.credential, None, None, Some(Some("another password"))).unwrap();
    assert!(changed_since_publish(&vault, &published).unwrap().is_empty());

    // A config edit marks that connection only.
    let c = vault.connections().unwrap().into_iter().find(|c| c.connection.id == f.loose).unwrap().connection;
    vault.save_connection(&c, Some(&format!("{OPENVPN}verb 3\n"))).unwrap();
    assert_eq!(changed_since_publish(&vault, &published).unwrap(), BTreeSet::from([f.loose]));

    // A shared secret's new value, a colour, a folder rename and a new connection in a selected folder.
    vault.set_secret(&key(f.office), SecretField::KeyPassword, "new-team-psk").unwrap();
    vault.set_item_color(&key(f.lab_vpn), None).unwrap();
    vault.rename_folder(f.lab, "Laboratory").unwrap();
    let new = add(&mut vault, 40, "New", VPNKind::Openvpn, OPENVPN);
    vault.set_item_folder(&key(new), Some(f.offices)).unwrap();
    assert_eq!(
        changed_since_publish(&vault, &published).unwrap(),
        BTreeSet::from([f.loose, f.office, f.lab_vpn, f.lab, new])
    );

    // A deleted connection is a change too.
    vault.delete_connection(&f.elsewhere).unwrap();
    vault.delete_connection(&f.loose).unwrap();
    assert!(changed_since_publish(&vault, &published).unwrap().contains(&f.loose));
}
