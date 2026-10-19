//! Port of `ConnectionOrderManagerTests.swift` (spec 10e): counting successful connects, the order, and pruning
//! the entries of deleted connections.

mod common;

use common::*;
use macvpn_app_core::deps::{ManualClock, SystemService};
use macvpn_app_core::{ConnectionItem, ConnectionManager};
use macvpn_core::date::Date;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::{Connection, VPNKind, uuid_string};
use macvpn_core::ranking::ConnectionRankingStore;
use std::collections::BTreeSet;
use std::sync::Arc;

const HU: AppLanguage = AppLanguage::Hu;
const SVC: &str = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";

fn list(status: &str) -> Vec<SystemService> {
    vec![SystemService::new(SVC, "Office L2TP", "L2TP", status)]
}

fn connected_json(c: &Connection, state: &str) -> String {
    format!(
        r#"[{{"id":"{}","kind":"openvpn","state":"{state}","iface":null,"ip":null,"since":null}}]"#,
        uuid_string(&c.id)
    )
}

fn usage(m: &ConnectionManager, clock: &ManualClock, key: &str) -> f64 {
    use macvpn_app_core::deps::Clock;
    (m.ranking().score(key, clock.now()) * 1e6).round() / 1e6
}

fn names(items: &[ConnectionItem]) -> Vec<String> {
    items.iter().map(|i| i.name().to_string()).collect()
}

fn fixed_clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(Date::from_time_interval_since_1970(1_800_000_000.0)))
}

#[test]
fn root_connect_counts_once_and_refreshes_do_not_add_more() {
    let f = Fixture::new(HU);
    let c = Connection::new("Iroda", VPNKind::Openvpn);
    f.store.save(&c, Some("remote x\n")).unwrap();
    f.root.respond("status", Ok(&connected_json(&c, "connected")));
    let clock = fixed_clock();
    let m = f.manager_with_clock(clock.clone());
    let key = uuid_string(&c.id);
    m.connect(&c, false);
    assert!(m.state(&key).is_connected());
    assert_eq!(usage(&m, &clock, &key), 1.0);
    m.refresh();
    m.refresh();
    assert_eq!(usage(&m, &clock, &key), 1.0, "polling an already connected tunnel does not count");
    m.disconnect(&c);
    f.root.respond("status", Ok(&connected_json(&c, "connected")));
    m.connect(&c, false);
    assert_eq!(usage(&m, &clock, &key), 2.0, "a new user-initiated connect counts again");
}

#[test]
fn connection_not_started_by_the_user_does_not_count() {
    let f = Fixture::new(HU);
    let c = Connection::new("Iroda", VPNKind::Openvpn);
    f.store.save(&c, Some("remote x\n")).unwrap();
    let clock = fixed_clock();
    let m = f.manager_with_clock(clock.clone());
    let key = uuid_string(&c.id);
    f.root.respond("status", Ok(&connected_json(&c, "connected")));
    m.refresh();
    assert!(m.state(&key).is_connected());
    // Drops, then comes back up by itself (not started by the user).
    f.root.respond("status", Ok(&connected_json(&c, "failed")));
    m.refresh();
    f.root.respond("status", Ok(&connected_json(&c, "connected")));
    m.refresh();
    assert_eq!(usage(&m, &clock, &key), 0.0);
}

#[test]
fn failed_connect_does_not_count_and_does_not_linger() {
    let f = Fixture::new(HU);
    let c = Connection::new("WG", VPNKind::Wireguard);
    f.store.save(&c, Some("x")).unwrap();
    f.root.respond(&up_line(VPNKind::Wireguard, &c.id), Err("időtúllépés"));
    f.root.respond("status", Ok("[]"));
    let clock = fixed_clock();
    let m = f.manager_with_clock(clock.clone());
    let key = uuid_string(&c.id);
    m.connect(&c, false);
    assert_eq!(usage(&m, &clock, &key), 0.0);
    // A connection that comes up later from outside does not count for the failed attempt either.
    f.root.respond(
        "status",
        Ok(&format!(
            r#"[{{"id":"{key}","kind":"wireguard","state":"connected","iface":null,"ip":null,"since":null}}]"#
        )),
    );
    m.refresh();
    assert_eq!(usage(&m, &clock, &key), 0.0);
}

fn native_connection(f: &Fixture) -> Connection {
    let mut c = Connection::new("Office L2TP", VPNKind::L2tp);
    c.native_service_name = Some("Office L2TP".into());
    c.native = Some(macvpn_core::models::NativeSettings {
        server: "vpn.example.com".into(),
        account: "bob".into(),
        ..Default::default()
    });
    f.store.save(&c, None).unwrap();
    f.root.respond("status", Ok("[]"));
    f.native.set_list(Ok(list("Disconnected")));
    f.native.set_address(SVC, Some("vpn.example.com"));
    c
}

#[test]
fn native_connect_counts_once_when_it_comes_up() {
    let f = Fixture::new(HU);
    let c = native_connection(&f);
    let clock = fixed_clock();
    let m = f.manager_with_clock(clock.clone());
    let key = uuid_string(&c.id);
    m.connect(&c, false);
    f.native.set_list(Ok(list("Connecting")));
    m.refresh();
    assert_eq!(usage(&m, &clock, &key), 0.0, "connecting is not a success yet");
    f.native.set_list(Ok(list("Connected")));
    m.refresh();
    m.refresh();
    assert_eq!(usage(&m, &clock, &key), 1.0);
}

#[test]
fn native_connect_failure_does_not_count() {
    let f = Fixture::new(HU);
    let c = native_connection(&f);
    let clock = fixed_clock();
    let m = f.manager_with_clock(clock.clone());
    let key = uuid_string(&c.id);
    m.connect(&c, false);
    f.native.set_list(Ok(list("Connecting")));
    m.refresh();
    f.native.set_list(Ok(list("Disconnected")));
    m.refresh();
    f.native.set_list(Ok(list("Connected")));
    m.refresh();
    assert_eq!(usage(&m, &clock, &key), 0.0);
}

#[test]
fn system_service_connect_counts_once_under_its_service_id() {
    let f = Fixture::new(HU);
    f.native.set_list(Ok(list("Disconnected")));
    let clock = fixed_clock();
    let m = f.manager_with_clock(clock.clone());
    m.refresh();
    let s = m.system_services()[0].clone();
    m.connect_system(&s);
    f.native.set_list(Ok(list("Connected")));
    m.refresh();
    m.refresh();
    assert_eq!(usage(&m, &clock, SVC), 1.0);
    f.native.set_list(Ok(list("Disconnected")));
    m.disconnect_system(&s);
    f.native.set_list(Ok(list("Connected")));
    m.refresh();
    assert_eq!(usage(&m, &clock, SVC), 1.0, "a connect started outside MacVPN does not count");
}

#[test]
fn ordered_items_mix_managed_and_system_and_pins_come_first() {
    let f = Fixture::new(HU);
    let a = Connection::new("alpha", VPNKind::Openvpn);
    let b = Connection::new("Bravo", VPNKind::Openvpn);
    f.store.save(&a, Some("remote x\n")).unwrap();
    f.store.save(&b, Some("remote x\n")).unwrap();
    f.root.respond("status", Ok("[]"));
    f.native.set_list(Ok(list("Disconnected"))); // the "Office L2TP" system VPN
    let m = f.manager_with_clock(fixed_clock());
    m.refresh();
    assert_eq!(names(&m.ordered_items()), ["alpha", "Bravo", "Office L2TP"], "no usage: by name");
    let s = m.system_services()[0].clone();
    m.connect_system(&s);
    f.native.set_list(Ok(list("Connected")));
    m.refresh();
    assert_eq!(names(&m.ordered_items()), ["Office L2TP", "alpha", "Bravo"]);
    m.pin(&uuid_string(&b.id));
    assert_eq!(names(&m.ordered_items()), ["Bravo", "Office L2TP", "alpha"]);
    assert_eq!(m.pinned_items().iter().map(ConnectionItem::id).collect::<Vec<_>>(), [uuid_string(&b.id)]);
    assert_eq!(names(&m.unpinned_items()), ["Office L2TP", "alpha"]);
    m.pin(&uuid_string(&a.id));
    m.move_pinned(&BTreeSet::from([1]), 0);
    assert_eq!(names(&m.pinned_items()), ["alpha", "Bravo"]);
    m.unpin(&uuid_string(&a.id));
    assert_eq!(names(&m.ordered_items()), ["Bravo", "Office L2TP", "alpha"]);
}

#[test]
fn deleted_connections_are_pruned_after_a_full_listing_and_persisted() {
    let f = Fixture::new(HU);
    let a = Connection::new("A", VPNKind::Openvpn);
    let b = Connection::new("B", VPNKind::Openvpn);
    f.store.save(&a, Some("remote x\n")).unwrap();
    f.store.save(&b, Some("remote x\n")).unwrap();
    f.root.respond("status", Ok("[]"));
    f.native.set_list(Ok(list("Disconnected")));
    let ranking_store = Arc::new(ConnectionRankingStore::new(f.dir.path().join("connection-order.json")));
    let mut deps = f.deps();
    deps.ranking_store = Some(ranking_store.clone());
    // No reload yet: the empty list must not delete the entries.
    let m = ConnectionManager::new(deps.clone());
    let (ka, kb) = (uuid_string(&a.id), uuid_string(&b.id));
    m.pin(&ka);
    m.pin(&kb);
    m.pin(SVC);
    m.refresh();
    assert_eq!(m.ranking().pinned(), [ka.clone(), kb.clone(), SVC.to_string()]);
    m.reload();
    m.refresh();
    assert_eq!(m.ranking().pinned(), [ka.clone(), kb.clone(), SVC.to_string()]);
    f.store.delete(&a.id).unwrap();
    m.reload();
    f.native.set_list(Ok(Vec::new()));
    m.refresh();
    assert_eq!(m.ranking().pinned(), std::slice::from_ref(&kb));
    assert_eq!(ranking_store.load().pinned(), std::slice::from_ref(&kb), "saved");
    // A new manager from the same file (restart).
    let restarted = ConnectionManager::new(deps);
    assert_eq!(restarted.ranking(), m.ranking());
}

#[test]
fn list_failure_does_not_prune() {
    let f = Fixture::new(HU);
    f.native.set_list(Ok(list("Disconnected")));
    let m = f.manager();
    m.refresh();
    m.pin(SVC);
    f.native.set_list(Err("scutil hiba"));
    m.refresh();
    assert_eq!(m.ranking().pinned(), [SVC.to_string()]);
}
