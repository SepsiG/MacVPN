//! Port of `ConnectionManagerTests.swift`: refresh merging, failures, drop detection, the operation tokens and
//! races, native services (grace period, timeout, binding by service ID and server address), system VPNs.
//!
//! The Swift tests drive the real `MvpnClient` / `NativeVPNController` over a mock command runner and assert on
//! command lines; here the manager's traits are mocked one level higher, so the assertions are on the calls the
//! manager makes (`up <kind> <id> [--debug]`, the stdin payload, the native start options).

mod common;

use common::*;
use macvpn_app_core::deps::{SecretField, SystemVpn};
use macvpn_app_core::manager::server_mismatch_reason;
use macvpn_core::l10n::{self, AppLanguage, Arg};
use macvpn_core::models::{Connection, ConnectionState, NativeSettings, VPNKind, uuid_string};
use macvpn_core::native::NativeStartOptions;
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

const HU: AppLanguage = AppLanguage::Hu;
const SVC: &str = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
const OTHER: &str = "AAAAAAAA-1111-2222-3333-444444444444";
const WG_SVC: &str = "052ED352-624D-4F75-BD84-D3E278CFD84F";

fn connected(ip: Option<&str>) -> ConnectionState {
    ConnectionState::Connected { ip: ip.map(str::to_string), since: None }
}

/// Connected, without an address, with the time the manager saw it connect.
fn seen_connected(state: &ConnectionState) -> bool {
    matches!(state, ConnectionState::Connected { ip: None, since: Some(_) })
}

fn failed_state(reason: &str) -> ConnectionState {
    ConnectionState::Failed(reason.to_string())
}

fn l2tp(status: &str) -> SystemVpn {
    SystemVpn::new(SVC, "Office L2TP", "L2TP", status)
}

fn list(status: &str) -> Vec<SystemVpn> {
    vec![l2tp(status)]
}

fn two_services(first: &str, second: &str) -> Vec<SystemVpn> {
    vec![SystemVpn::new(OTHER, "Office L2TP", "L2TP", first), l2tp(second)]
}

fn home_wg() -> SystemVpn {
    SystemVpn::new(WG_SVC, "Home", "WireGuard (app)", "Disconnected")
}

fn status_json(c: &Connection, kind: &str, state: &str, ip: Option<&str>) -> String {
    let ip = ip.map_or("null".to_string(), |ip| format!("\"{ip}\""));
    format!(
        r#"[{{"id":"{}","kind":"{kind}","state":"{state}","iface":null,"ip":{ip},"since":null}}]"#,
        uuid_string(&c.id)
    )
}

fn connected_json(c: &Connection) -> String {
    status_json(c, "openvpn", "connected", None)
}

fn opts(entries: &[(&'static str, &[(&'static str, &str)])]) -> Option<NativeStartOptions> {
    let mut out: NativeStartOptions = BTreeMap::new();
    for (entity, props) in entries {
        out.insert(entity, props.iter().map(|(k, v)| (*k, v.to_string())).collect());
    }
    Some(out)
}

fn l2tp_connection(server: Option<&str>) -> Connection {
    let mut c = Connection::new("Office L2TP", VPNKind::L2tp);
    c.native_service_name = Some("Office L2TP".into());
    c.native = server.map(|s| NativeSettings { server: s.into(), account: "bob".into(), ..NativeSettings::default() });
    c
}

/// An unbound managed connection whose only same-named service points to its server (secrets may be passed).
fn native_manager(f: &Fixture) -> (Arc<macvpn_app_core::ConnectionManager>, Connection) {
    let c = l2tp_connection(Some("vpn.example.com"));
    f.store.save(&c, None).unwrap();
    f.helper.respond("status", Ok("[]"));
    f.native.set_list(Ok(list("Disconnected")));
    f.native.set_address(SVC, Some("vpn.example.com"));
    (f.manager(), c)
}

fn system_manager(f: &Fixture) -> (Arc<macvpn_app_core::ConnectionManager>, SystemVpn) {
    f.native.set_list(Ok(list("Disconnected")));
    let m = f.manager();
    m.refresh();
    let s = m.system_services().first().cloned().expect("a system VPN");
    (m, s)
}

#[test]
fn refresh_merges_root_and_native_and_hides_managed_native() {
    let f = Fixture::new(HU);
    let ovpn = Connection::new("Iroda", VPNKind::Openvpn);
    let l2tp_c = l2tp_connection(None);
    f.store.save(&ovpn, Some("remote x\n")).unwrap();
    f.store.save(&l2tp_c, None).unwrap();
    f.helper.respond("status", Ok(&status_json(&ovpn, "openvpn", "connected", Some("10.8.0.2"))));
    f.native.set_list(Ok(vec![
        SystemVpn::new(SVC, "Office L2TP", "L2TP", "Connected"),
        SystemVpn::new(WG_SVC, "Home", "WireGuard (app)", "Disconnected"),
    ]));
    let m = f.manager();
    m.refresh();
    assert_eq!(m.state(&uuid_string(&ovpn.id)), connected(Some("10.8.0.2")));
    assert_eq!(m.state(&uuid_string(&l2tp_c.id)), connected(None));
    assert_eq!(m.system_services().iter().map(|s| s.name.clone()).collect::<Vec<_>>(), ["Home"]);
    assert_eq!(m.state(WG_SVC), ConnectionState::Disconnected);
    assert!(m.has_active());
}

#[test]
fn connect_failure_sets_failed_and_emits_event() {
    let f = Fixture::new(HU);
    let c = Connection::new("WG", VPNKind::Wireguard);
    f.store.save(&c, Some("x")).unwrap();
    f.helper.respond(&up_line(VPNKind::Wireguard, &c.id), Err("időtúllépés"));
    f.helper.respond("status", Ok("[]"));
    let m = f.manager();
    let events = record_events(&m);
    m.connect(&c, false);
    let key = uuid_string(&c.id);
    assert_eq!(m.state(&key), failed_state("időtúllépés"));
    assert_eq!(events_of(&events), [failed(&key, "WG", "időtúllépés")]);
    assert!(m.has_failure());
    m.refresh();
    assert_eq!(m.state(&key), failed_state("időtúllépés"), "a refresh nem törölheti a hibát");
}

/// SSTP is a root type: the same path as the others (`mvpn up sstp <id>`, the password on stdin).
#[test]
fn sstp_connect_uses_root_path() {
    let f = Fixture::new(HU);
    let c = Connection::new("SSTP", VPNKind::Sstp);
    f.store.save(&c, Some("server=vpn.example.com\nuser=bob\n")).unwrap();
    f.secrets.set("Titok123", &c.id, SecretField::Password);
    f.helper.respond("status", Ok(&status_json(&c, "sstp", "connected", Some("10.0.0.7"))));
    let m = f.manager();
    m.connect(&c, false);
    let up = up_line(VPNKind::Sstp, &c.id);
    let call = f.helper.calls().into_iter().find(|call| call.line == up).expect("up call");
    assert_eq!(call.stdin.as_deref(), Some("password=Titok123\n"));
    assert!(!call.line.contains("Titok123"));
    assert_eq!(m.state(&uuid_string(&c.id)), connected(Some("10.0.0.7")));
    m.disconnect(&c);
    assert!(f.helper.lines().contains(&down_line(VPNKind::Sstp, &c.id)));
}

/// Root layer 8: every root kind sends its stored config to `mvpn up` (on stdin, ahead of the secrets).
#[test]
fn root_up_receives_the_config() {
    let f = Fixture::new(HU);
    for (kind, config) in [
        (VPNKind::Wireguard, "[Interface]\nAddress = 10.0.0.2/32\n# árvíztűrő\n"),
        (VPNKind::Openvpn, "client\nremote vpn.example.com 1194\n"),
        (VPNKind::Strongswan, "connections {\n}\n"),
        (VPNKind::Sstp, "server=vpn.example.com\nuser=bob\npassword=FromConfig\n"),
    ] {
        let c = Connection::new("Iroda", kind);
        f.store.save(&c, Some(config)).unwrap();
        f.secrets.set("Titok123", &c.id, SecretField::Password);
        f.manager().connect(&c, false);
        let call = f.helper.calls().into_iter().find(|call| call.line == up_line(kind, &c.id)).expect("up call");
        assert_eq!(call.config.as_deref(), Some(config.as_bytes()), "{kind:?}");
        assert_eq!(call.stdin.as_deref(), Some("password=Titok123\n"), "{kind:?}");
    }
}

/// A config that cannot be read fails the connect with the existing text, without calling `mvpn`.
#[test]
fn unreadable_config_fails_without_up() {
    let f = Fixture::new(HU);
    let c = Connection::new("WG", VPNKind::Wireguard);
    f.store.save(&c, None).unwrap();
    let m = f.manager();
    m.connect(&c, false);
    assert_eq!(m.state(&uuid_string(&c.id)), failed_state("A config nem található"));
    assert!(f.helper.lines().iter().all(|l| !l.starts_with("up ")), "{:?}", f.helper.lines());
}

#[test]
fn drop_detection() {
    let f = Fixture::new(HU);
    let c = Connection::new("Iroda", VPNKind::Openvpn);
    f.store.save(&c, Some("remote x\n")).unwrap();
    let m = f.manager();
    let events = record_events(&m);
    f.helper.respond("status", Ok(&connected_json(&c)));
    m.refresh();
    f.helper.respond("status", Ok(&status_json(&c, "openvpn", "failed", None)));
    m.refresh();
    assert_eq!(events_of(&events), [dropped(&uuid_string(&c.id), "Iroda")]);
}

/// LinVPN (audit C1): stopped outside the app (GNOME's menu, `nmcli connection down`; the log's last own line is
/// `NetworkManager: disconnected by the user`): off as after a disconnect in the app, no drop event (no notice,
/// no reconnect), and the user-disconnect listeners hear it (the planner and the control API's leases).
#[test]
fn a_stop_outside_the_app_is_off_without_a_drop() {
    let f = Fixture::new(HU);
    let c = Connection::new("Iroda", VPNKind::Openvpn);
    f.store.save(&c, Some("remote x\n")).unwrap();
    let log = f.dir.path().join("iroda.log");
    std::fs::write(&log, "2026-10-30 10:00:00 Connected, IPv4 198.51.100.7\n").unwrap();
    f.helper.set_log(&c.id, &log);
    let m = f.manager();
    let events = record_events(&m);
    let stops = Arc::new(Mutex::new(Vec::new()));
    let sink = stops.clone();
    m.add_user_disconnect_listener(move |key| sink.lock().unwrap().push(key.to_string()));
    let key = uuid_string(&c.id);
    f.helper.respond("status", Ok(&connected_json(&c)));
    m.refresh();
    std::fs::write(
        &log,
        "2026-10-30 10:00:00 Connected, IPv4 198.51.100.7\n2026-10-30 10:05:00 NetworkManager: disconnected by the user\n2026-10-30 10:05:00 [openvpn] SIGTERM[hard,] received, process exiting\n",
    )
    .unwrap();
    f.helper.respond("status", Ok("[]"));
    m.refresh();
    assert_eq!(m.state(&key), ConnectionState::Disconnected);
    assert!(events_of(&events).is_empty(), "{:?}", events_of(&events));
    assert_eq!(*stops.lock().unwrap(), vec![key.clone()]);
    // Any other end is a drop as before.
    std::fs::write(
        &log,
        "2026-10-30 11:00:00 Connected, IPv4 198.51.100.7\n2026-10-30 11:05:00 NetworkManager: disconnected\n",
    )
    .unwrap();
    f.helper.respond("status", Ok(&connected_json(&c)));
    m.refresh();
    f.helper.respond("status", Ok("[]"));
    m.refresh();
    assert_eq!(events_of(&events), [dropped(&key, "Iroda")]);
    assert_eq!(stops.lock().unwrap().len(), 1);
}

#[test]
fn a_managed_native_stop_outside_the_app_is_off_without_a_drop() {
    let f = Fixture::new(HU);
    let (m, c) = native_manager(&f);
    let log = f.dir.path().join("l2tp.log");
    std::fs::write(&log, "2026-10-30 10:05:00 NetworkManager: disconnected by the user\n").unwrap();
    f.native.set_log_file(&c.id, &log);
    let events = record_events(&m);
    let key = uuid_string(&c.id);
    f.native.set_list(Ok(list("Connected")));
    m.refresh();
    assert!(m.state(&key).is_connected());
    f.native.set_list(Ok(list("Disconnected")));
    m.refresh();
    assert_eq!(m.state(&key), ConnectionState::Disconnected);
    assert!(events_of(&events).is_empty());
}

#[test]
fn connect_passes_secrets_and_disconnect_clears_failure() {
    let f = Fixture::new(HU);
    let c = Connection::new("Iroda", VPNKind::Openvpn);
    f.store.save(&c, Some("remote x\n")).unwrap();
    f.secrets.set("bob", &c.id, SecretField::Username);
    f.helper.respond("status", Ok("[]"));
    let m = f.manager();
    m.connect(&c, true);
    let up = f.helper.calls().into_iter().find(|call| call.line.starts_with("up ")).expect("up call");
    assert_eq!(up.line, format!("{} --debug", up_line(VPNKind::Openvpn, &c.id)));
    assert_eq!(up.stdin.as_deref(), Some("username=bob\n"));
    m.disconnect(&c);
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Disconnected);
}

// MARK: - State machine, races

#[test]
fn transient_status_failure_keeps_connected() {
    let f = Fixture::new(HU);
    let c = Connection::new("Iroda", VPNKind::Openvpn);
    f.store.save(&c, Some("remote x\n")).unwrap();
    let m = f.manager();
    let events = record_events(&m);
    f.helper.respond("status", Ok(&connected_json(&c)));
    m.refresh();
    assert!(m.state(&uuid_string(&c.id)).is_connected());
    f.helper.respond("status", Err("sudo hiba"));
    m.refresh();
    assert!(m.state(&uuid_string(&c.id)).is_connected());
    assert!(events_of(&events).is_empty());
}

#[test]
fn status_error_after_three_failures_and_cleared_on_success() {
    let f = Fixture::new(HU);
    f.store.save(&Connection::new("Iroda", VPNKind::Openvpn), Some("remote x\n")).unwrap();
    f.helper.respond("status", Err("sudo hiba"));
    let m = f.manager();
    m.refresh();
    m.refresh();
    assert_eq!(m.status_error(), None);
    m.refresh();
    assert_eq!(m.status_error().as_deref(), Some("Az állapot nem kérdezhető le: sudo hiba"));
    f.helper.respond("status", Ok("[]"));
    m.refresh();
    assert_eq!(m.status_error(), None);
}

#[test]
fn root_status_skipped_without_root_backed_connections() {
    let f = Fixture::new(HU);
    let (m, _) = native_manager(&f);
    f.helper.respond("status", Err("nincs telepítve"));
    for _ in 0..3 {
        m.refresh();
    }
    assert_eq!(m.status_error(), None);
    assert!(!f.helper.lines().contains(&"status".to_string()));
}

#[test]
fn stale_refresh_does_not_overwrite_disconnect() {
    let f = Fixture::new(HU);
    let c = Connection::new("Iroda", VPNKind::Openvpn);
    f.store.save(&c, Some("remote x\n")).unwrap();
    let m = f.manager();
    let events = record_events(&m);
    f.helper.respond("status", Ok(&connected_json(&c)));
    m.refresh();
    let key = uuid_string(&c.id);
    f.helper.delay("status", 0.1);
    let down = down_line(VPNKind::Openvpn, &c.id);
    f.helper.delay(&down, 1.0);
    let stale = spawn(HU, {
        let m = m.clone();
        move || m.refresh() // reads the old "connected" answer
    });
    f.helper.wait_for_call("status", 2);
    f.helper.respond("status", Ok("[]"));
    let disc = spawn(HU, {
        let (m, c) = (m.clone(), c.clone());
        move || m.disconnect(&c)
    });
    f.helper.wait_for_call(&down, 1);
    stale.join().unwrap(); // the stale refresh finished while the disconnect runs
    assert_eq!(m.state(&key), ConnectionState::Disconnecting);
    disc.join().unwrap();
    assert_eq!(m.state(&key), ConnectionState::Disconnected);
    assert!(events_of(&events).is_empty());
}

#[test]
fn stale_result_from_older_refresh_is_discarded() {
    let f = Fixture::new(HU);
    let c = Connection::new("Iroda", VPNKind::Openvpn);
    f.store.save(&c, Some("remote x\n")).unwrap();
    let m = f.manager();
    f.helper.respond("status", Ok(&connected_json(&c)));
    f.helper.delay("status", 0.15);
    let slow = spawn(HU, {
        let m = m.clone();
        move || m.refresh() // reads connected, slowly
    });
    f.helper.wait_for_call("status", 1);
    f.helper.respond("status", Ok("[]"));
    f.helper.delay("status", 0.0);
    m.refresh(); // newer and fast: disconnected
    slow.join().unwrap();
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Disconnected);
}

#[test]
fn native_connect_failure_detected() {
    let f = Fixture::new(HU);
    let (m, c) = native_manager(&f);
    let events = record_events(&m);
    let key = uuid_string(&c.id);
    m.connect(&c, false);
    assert_eq!(m.state(&key), ConnectionState::Connecting);
    f.native.set_list(Ok(list("Connecting")));
    m.refresh();
    assert_eq!(m.state(&key), ConnectionState::Connecting);
    f.native.set_list(Ok(list("Disconnected")));
    m.refresh();
    let reason = "A kapcsolat nem jött létre – részletek: debug csatlakozás";
    assert_eq!(m.state(&key), failed_state(reason));
    assert_eq!(events_of(&events), [failed(&key, "Office L2TP", reason)]);
}

#[test]
fn native_connect_success() {
    let f = Fixture::new(HU);
    let (m, c) = native_manager(&f);
    m.connect(&c, false);
    f.native.set_list(Ok(list("Connecting")));
    m.refresh();
    f.native.set_list(Ok(list("Connected")));
    m.refresh();
    // Seen to connect: the time is shown (live traffic plan: the same detail as the other engines).
    assert!(seen_connected(&m.state(&uuid_string(&c.id))));
}

#[test]
fn native_never_connecting_fails_after_grace_period_and_timeout() {
    let f = Fixture::new(HU);
    let (_, c) = native_manager(&f);
    let clock = clock_at(1000.0);
    let m = f.manager_with_clock(clock.clone());
    let events = record_events(&m);
    let key = uuid_string(&c.id);
    m.connect(&c, false);
    clock.advance(3.0);
    m.refresh();
    assert_eq!(m.state(&key), ConnectionState::Connecting, "5 mp-en belül még nem hiba");
    clock.advance(3.0);
    m.refresh();
    assert_eq!(m.state(&key), failed_state("A kapcsolat nem jött létre – részletek: debug csatlakozás"));
    assert_eq!(events_of(&events).len(), 1);
}

#[test]
fn native_stuck_connecting_times_out() {
    let f = Fixture::new(HU);
    let (_, c) = native_manager(&f);
    let clock = clock_at(1000.0);
    let m = f.manager_with_clock(clock.clone());
    m.connect(&c, false);
    f.native.set_list(Ok(list("Connecting")));
    m.refresh();
    clock.advance(46.0);
    m.refresh();
    assert_eq!(m.state(&uuid_string(&c.id)), failed_state("Időtúllépés"));
}

#[test]
fn native_drop_detected() {
    let f = Fixture::new(HU);
    let (m, c) = native_manager(&f);
    let events = record_events(&m);
    let key = uuid_string(&c.id);
    f.native.set_list(Ok(list("Connected")));
    m.refresh();
    assert!(m.state(&key).is_connected());
    f.native.set_list(Ok(list("Disconnected")));
    m.refresh();
    assert_eq!(m.state(&key), ConnectionState::Disconnected);
    assert_eq!(events_of(&events), [dropped(&key, "Office L2TP")]);
}

#[test]
fn list_failure_keeps_native_and_system_states() {
    let f = Fixture::new(HU);
    let (m, c) = native_manager(&f);
    f.native.set_list(Ok(list("Connected")));
    m.refresh();
    f.native.set_list(Err("scutil hiba"));
    m.refresh();
    assert!(m.state(&uuid_string(&c.id)).is_connected());
}

#[test]
fn disconnect_during_pending_connect_then_up_fails_is_silent() {
    let f = Fixture::new(HU);
    let c = Connection::new("WG", VPNKind::Wireguard);
    f.store.save(&c, Some("x")).unwrap();
    let key = uuid_string(&c.id);
    let up = up_line(VPNKind::Wireguard, &c.id);
    f.helper.respond(&up, Err("megszakítva"));
    f.helper.delay(&up, 0.5);
    f.helper.respond("status", Ok("[]"));
    let m = f.manager();
    let events = record_events(&m);
    let connecting = spawn(HU, {
        let (m, c) = (m.clone(), c.clone());
        move || m.connect(&c, false)
    });
    f.helper.wait_for_call(&up, 1);
    assert_eq!(m.state(&key), ConnectionState::Connecting);
    m.disconnect(&c);
    connecting.join().unwrap();
    assert_eq!(m.state(&key), ConnectionState::Disconnected);
    assert!(events_of(&events).is_empty());
}

#[test]
fn failed_system_connect_is_sticky() {
    let f = Fixture::new(HU);
    f.helper.respond("status", Ok("[]"));
    f.native.set_list(Ok(vec![home_wg()]));
    let m = f.manager();
    m.refresh();
    let s = m.system_services().first().cloned().expect("system VPN");
    f.native.set_start_error(Some("nem indul"));
    m.connect_system(&s);
    assert_eq!(m.state(WG_SVC), failed_state("nem indul"));
    m.refresh();
    assert_eq!(m.state(WG_SVC), failed_state("nem indul"));
    m.disconnect_system(&s);
    assert_eq!(m.state(WG_SVC), ConnectionState::Disconnected);
}

#[test]
fn reload_keeps_list_on_store_error() {
    let f = Fixture::new(HU);
    let c = Connection::new("A", VPNKind::Openvpn);
    f.store.save(&c, Some("x")).unwrap();
    let m = f.manager();
    assert_eq!(m.connections().len(), 1);
    // The base directory replaced by a file -> list() fails.
    std::fs::remove_dir_all(&f.store.base_dir).unwrap();
    std::fs::write(&f.store.base_dir, "x").unwrap();
    m.reload();
    assert_eq!(m.connections().len(), 1);
}

// MARK: - Cancelled connect, tokens

#[test]
fn late_successful_up_after_cancel_is_torn_down() {
    let f = Fixture::new(HU);
    let c = Connection::new("WG", VPNKind::Wireguard);
    f.store.save(&c, Some("x")).unwrap();
    let key = uuid_string(&c.id);
    let up = up_line(VPNKind::Wireguard, &c.id);
    f.helper.delay(&up, 0.5);
    f.helper.respond("status", Ok("[]"));
    let m = f.manager();
    let events = record_events(&m);
    let connecting = spawn(HU, {
        let (m, c) = (m.clone(), c.clone());
        move || m.connect(&c, false)
    });
    f.helper.wait_for_call(&up, 1);
    m.disconnect(&c);
    connecting.join().unwrap();
    let lines = f.helper.lines();
    let up_index = lines.iter().position(|l| *l == up).expect("up");
    let downs: Vec<usize> =
        lines.iter().enumerate().filter(|(_, l)| l.starts_with("down wireguard ")).map(|(i, _)| i).collect();
    assert_eq!(downs.len(), 2, "a disconnect down + a late teardown down");
    assert!(downs.iter().all(|&i| i > up_index));
    assert_eq!(m.state(&key), ConnectionState::Disconnected);
    assert!(events_of(&events).is_empty());
}

#[test]
fn stale_failure_does_not_touch_newer_connect() {
    let f = Fixture::new(HU);
    let c = Connection::new("WG", VPNKind::Wireguard);
    f.store.save(&c, Some("x")).unwrap();
    let key = uuid_string(&c.id);
    let up = up_line(VPNKind::Wireguard, &c.id);
    f.helper.respond("status", Ok("[]"));
    f.helper.respond(&up, Err("A hibája"));
    f.helper.delay(&up, 0.3);
    let m = f.manager();
    let events = record_events(&m);
    let a = spawn(HU, {
        let (m, c) = (m.clone(), c.clone());
        move || m.connect(&c, false)
    });
    f.helper.wait_for_call(&up, 1);
    m.disconnect(&c);
    f.helper.respond(&up, Ok(""));
    f.helper.delay(&up, 0.6);
    let b = spawn(HU, {
        let (m, c) = (m.clone(), c.clone());
        move || m.connect(&c, false)
    });
    f.helper.wait_for_call(&up, 2);
    a.join().unwrap(); // A fails now
    assert!(events_of(&events).is_empty());
    assert_eq!(m.state(&key), ConnectionState::Connecting, "B művelete érintetlen");
    b.join().unwrap();
    assert!(events_of(&events).is_empty());
}

#[test]
fn native_timeout_stops_service_and_works_without_list() {
    let f = Fixture::new(HU);
    let (_, c) = native_manager(&f);
    let clock = clock_at(1000.0);
    let m = f.manager_with_clock(clock.clone());
    m.connect(&c, false);
    f.native.set_list(Err("scutil hiba"));
    clock.advance(46.0);
    m.refresh();
    assert_eq!(m.state(&uuid_string(&c.id)), failed_state("Időtúllépés"));
    assert_eq!(f.native.stops(), [SVC]);
}

#[test]
fn events_are_emitted_after_state_is_published() {
    let f = Fixture::new(HU);
    let (m, c) = native_manager(&f);
    f.native.set_list(Ok(list("Connected")));
    m.refresh();
    let seen: Arc<Mutex<Option<ConnectionState>>> = Arc::new(Mutex::new(None));
    {
        let (seen, weak, key) = (seen.clone(), Arc::downgrade(&m), uuid_string(&c.id));
        m.set_on_event(move |_| {
            *seen.lock().unwrap() = weak.upgrade().map(|m| m.state(&key));
        });
    }
    f.native.set_list(Ok(list("Disconnected")));
    m.refresh();
    assert_eq!(*seen.lock().unwrap(), Some(ConnectionState::Disconnected));
}

// MARK: - In-process native start: secrets

#[test]
fn managed_native_connect_passes_secrets_to_driver() {
    let f = Fixture::new(HU);
    let (m, c) = native_manager(&f);
    f.secrets.set("bob", &c.id, SecretField::Username);
    f.secrets.set("pw", &c.id, SecretField::Password);
    f.secrets.set("k", &c.id, SecretField::Psk);
    m.connect(&c, false);
    assert_eq!(
        f.native.starts(),
        [Start {
            service_id: SVC.into(),
            options: opts(&[
                ("IPSec", &[("SharedSecret", "k")]),
                ("PPP", &[("AuthName", "bob"), ("AuthPassword", "pw")]),
            ]),
        }]
    );
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Connecting);
}

#[test]
fn managed_cisco_connect_passes_xauth() {
    let f = Fixture::new(HU);
    let mut c = Connection::new("Partner", VPNKind::Cisco);
    c.native_service_name = Some("Partner".into());
    c.native = Some(NativeSettings {
        server: "1.2.3.4".into(),
        account: "bob".into(),
        group_name: "g".into(),
        ..NativeSettings::default()
    });
    f.store.save(&c, None).unwrap();
    f.native.set_list(Ok(vec![SystemVpn::new(SVC, "Partner", "Cisco IPsec", "Disconnected")]));
    f.native.set_address(SVC, Some("1.2.3.4"));
    f.secrets.set("bob", &c.id, SecretField::Username);
    f.secrets.set("k", &c.id, SecretField::Psk);
    let m = f.manager();
    m.connect(&c, false);
    assert_eq!(
        f.native.starts().first().and_then(|s| s.options.clone()),
        opts(&[("IPSec", &[("SharedSecret", "k"), ("XAuthName", "bob")])])
    );
}

#[test]
fn managed_native_connect_without_secrets_uses_stored_config() {
    let f = Fixture::new(HU);
    let (m, c) = native_manager(&f);
    m.connect(&c, false);
    assert_eq!(f.native.starts(), [Start { service_id: SVC.into(), options: None }]);
}

#[test]
fn managed_native_driver_failure() {
    let f = Fixture::new(HU);
    let (m, c) = native_manager(&f);
    // The platform layer's message for a failed `SCNetworkConnectionStart` passes through unchanged.
    let reason = l10n::tr("Cannot start the VPN service: %@", &[Arg::Str("No service")]);
    assert_eq!(reason, "A VPN szolgáltatás nem indítható: No service");
    f.native.set_start_error(Some(&reason));
    let events = record_events(&m);
    m.connect(&c, false);
    let key = uuid_string(&c.id);
    assert_eq!(m.state(&key), failed_state(&reason));
    assert_eq!(events_of(&events), [failed(&key, "Office L2TP", &reason)]);
}

#[test]
fn system_connect_passes_stored_secrets() {
    let f = Fixture::new(HU);
    let (m, s) = system_manager(&f);
    let id = s.secret_id().unwrap();
    f.secrets.set("k", &id, SecretField::Psk);
    f.secrets.set("pw", &id, SecretField::Password);
    m.connect_system(&s);
    assert_eq!(
        f.native.starts(),
        [Start {
            service_id: SVC.into(),
            options: opts(&[("IPSec", &[("SharedSecret", "k")]), ("PPP", &[("AuthPassword", "pw")])]),
        }]
    );
    assert_eq!(m.state(SVC), ConnectionState::Connecting);
}

#[test]
fn system_connect_without_secrets_passes_no_options() {
    let f = Fixture::new(HU);
    let (m, s) = system_manager(&f);
    m.connect_system(&s);
    assert_eq!(f.native.starts(), [Start { service_id: SVC.into(), options: None }]);
}

#[test]
fn system_connect_ignores_secrets_for_unsupported_type() {
    let f = Fixture::new(HU);
    f.native.set_list(Ok(vec![home_wg()]));
    let m = f.manager();
    m.refresh();
    let s = m.system_services().first().cloned().unwrap();
    f.secrets.set("k", &s.secret_id().unwrap(), SecretField::Psk);
    m.connect_system(&s);
    assert_eq!(f.native.starts().into_iter().map(|s| s.options).collect::<Vec<_>>(), [None]);
}

const PSK_HINT: &str = "A kapcsolat nem jött létre. Ha ez egy L2TP/IPsec VPN, add meg a közös kulcsát (PSK) itt: MacVPN → Kapcsolatok → Office L2TP.";
const SYSTEM_GENERIC: &str = "A kapcsolat nem jött létre.";

#[test]
fn system_connecting_then_disconnected_fails_with_psk_hint() {
    let f = Fixture::new(HU);
    let (m, s) = system_manager(&f);
    let events = record_events(&m);
    m.connect_system(&s);
    f.native.set_list(Ok(list("Connecting")));
    m.refresh();
    assert_eq!(m.state(SVC), ConnectionState::Connecting);
    f.native.set_list(Ok(list("Disconnected")));
    m.refresh();
    assert_eq!(m.state(SVC), failed_state(PSK_HINT));
    assert_eq!(events_of(&events), [failed(SVC, "Office L2TP", PSK_HINT)]);
    m.refresh();
    assert_eq!(m.state(SVC), failed_state(PSK_HINT), "sticky");
}

#[test]
fn system_failure_with_stored_psk_uses_generic_reason() {
    let f = Fixture::new(HU);
    let (m, s) = system_manager(&f);
    f.secrets.set("k", &s.secret_id().unwrap(), SecretField::Psk);
    m.connect_system(&s);
    f.native.set_list(Ok(list("Connecting")));
    m.refresh();
    f.native.set_list(Ok(list("Disconnected")));
    m.refresh();
    assert_eq!(m.state(SVC), failed_state(SYSTEM_GENERIC));
}

#[test]
fn system_psk_hint_is_english_too() {
    let f = Fixture::new(AppLanguage::En);
    let (m, s) = system_manager(&f);
    m.connect_system(&s);
    f.native.set_list(Ok(list("Connecting")));
    m.refresh();
    f.native.set_list(Ok(list("Disconnected")));
    m.refresh();
    assert_eq!(
        m.state(SVC),
        failed_state(
            "The connection did not come up. If this is an L2TP/IPsec VPN, enter its shared secret (PSK) in MacVPN → Connections → Office L2TP."
        )
    );
}

#[test]
fn system_never_connecting_fails_after_grace() {
    let f = Fixture::new(HU);
    f.native.set_list(Ok(list("Disconnected")));
    let clock = clock_at(1000.0);
    let m = f.manager_with_clock(clock.clone());
    m.refresh();
    let s = m.system_services().first().cloned().unwrap();
    m.connect_system(&s);
    clock.advance(3.0);
    m.refresh();
    assert_eq!(m.state(SVC), ConnectionState::Connecting, "5 mp-en belül még nem hiba");
    clock.advance(3.0);
    m.refresh();
    assert_eq!(m.state(SVC), failed_state(PSK_HINT));
}

#[test]
fn system_stuck_connecting_times_out_and_stops() {
    let f = Fixture::new(HU);
    f.native.set_list(Ok(list("Disconnected")));
    let clock = clock_at(1000.0);
    let m = f.manager_with_clock(clock.clone());
    m.refresh();
    let s = m.system_services().first().cloned().unwrap();
    m.connect_system(&s);
    f.native.set_list(Ok(list("Connecting")));
    m.refresh();
    clock.advance(46.0);
    m.refresh();
    assert_eq!(m.state(SVC), failed_state("Időtúllépés"));
    assert_eq!(f.native.stops(), [SVC]);
}

#[test]
fn system_timeout_works_without_list() {
    let f = Fixture::new(HU);
    f.native.set_list(Ok(list("Disconnected")));
    let clock = clock_at(1000.0);
    let m = f.manager_with_clock(clock.clone());
    m.refresh();
    let s = m.system_services().first().cloned().unwrap();
    m.connect_system(&s);
    f.native.set_list(Err("scutil hiba"));
    clock.advance(46.0);
    m.refresh();
    assert_eq!(m.state(SVC), failed_state("Időtúllépés"));
    assert_eq!(f.native.stops(), [SVC]);
}

#[test]
fn system_connect_success_then_disconnect() {
    let f = Fixture::new(HU);
    let (m, s) = system_manager(&f);
    m.connect_system(&s);
    f.native.set_list(Ok(list("Connected")));
    m.refresh();
    assert!(seen_connected(&m.state(SVC)));
    f.native.set_list(Ok(list("Disconnected")));
    m.disconnect_system(&s);
    assert_eq!(m.state(SVC), ConnectionState::Disconnected);
    assert_eq!(f.native.stops(), [SVC]);
}

// MARK: - Native service binding (scutil service ID)

fn bound_candidate(f: &Fixture) -> Connection {
    let c = l2tp_connection(Some("vpn.example.com"));
    f.store.save(&c, None).unwrap();
    f.native.set_list(Ok(two_services("Disconnected", "Disconnected")));
    f.native.set_address(OTHER, Some("evil.example.net"));
    f.native.set_address(SVC, Some("VPN.example.com"));
    c
}

#[test]
fn refresh_binds_service_by_name_and_server_address() {
    let f = Fixture::new(HU);
    bound_candidate(&f);
    let m = f.manager();
    m.refresh();
    assert_eq!(m.connections().first().and_then(|c| c.native_service_id.clone()).as_deref(), Some(SVC));
    assert_eq!(
        f.store.list().unwrap().first().and_then(|c| c.native_service_id.clone()).as_deref(),
        Some(SVC),
        "persisted in meta.json"
    );
    // The same-named foreign service is not hidden as "managed".
    assert_eq!(m.system_services().iter().map(|s| s.id.clone()).collect::<Vec<_>>(), [OTHER]);
    // Once bound, no more scutil --nc show.
    let shows = f.native.shows();
    m.refresh();
    assert_eq!(f.native.shows(), shows);
}

#[test]
fn bound_connect_and_status_use_the_service_id() {
    let f = Fixture::new(HU);
    let c = bound_candidate(&f);
    f.secrets.set("pw", &c.id, SecretField::Password);
    let m = f.manager();
    m.refresh();
    let bound = m.connections().first().cloned().unwrap();
    m.connect(&bound, false);
    assert_eq!(f.native.starts().into_iter().map(|s| s.service_id).collect::<Vec<_>>(), [SVC]);
    f.native.set_list(Ok(two_services("Connected", "Disconnected")));
    m.refresh();
    assert_ne!(m.state(&uuid_string(&c.id)), connected(None), "the foreign service's state is not ours");
    f.native.set_list(Ok(two_services("Disconnected", "Connected")));
    m.refresh();
    assert!(seen_connected(&m.state(&uuid_string(&c.id))));
    m.disconnect(&bound);
    assert_eq!(f.native.stops(), [SVC]);
}

#[test]
fn ambiguous_name_refuses_to_pass_secrets() {
    let f = Fixture::new(HU);
    let c = l2tp_connection(None);
    f.store.save(&c, None).unwrap();
    f.secrets.set("pw", &c.id, SecretField::Password);
    f.native.set_list(Ok(two_services("Disconnected", "Disconnected")));
    let m = f.manager();
    let events = record_events(&m);
    m.connect(&c, false);
    assert!(f.native.starts().is_empty());
    let reason = "Több „Office L2TP” nevű VPN szolgáltatás van. A MacVPN nem adja át a jelszót, amíg nem egyértelmű, melyik az övé: nevezd át vagy töröld a másikat a Rendszerbeállítások → Hálózat alatt.";
    let key = uuid_string(&c.id);
    assert_eq!(m.state(&key), failed_state(reason));
    assert_eq!(events_of(&events), [failed(&key, "Office L2TP", reason)]);
}

const SERVER_MISMATCH_HU: &str = "A(z) „Office L2TP” nevű VPN szolgáltatás szervercíme nem egyezik a kapcsolat szerverével. A MacVPN nem adja át neki a jelszót és a PSK-t: telepítsd újra a profilt a MacVPN → Kapcsolatok alatt, vagy töröld a másik szolgáltatást a Rendszerbeállítások → Hálózat alatt.";

/// Unbound, the only same-named service points to another server: no start at all (neither with nor without
/// secrets).
#[test]
fn unbound_name_match_with_other_server_refuses_to_start() {
    let f = Fixture::new(HU);
    let c = l2tp_connection(Some("other.example.com"));
    f.store.save(&c, None).unwrap();
    f.secrets.set("pw", &c.id, SecretField::Password);
    f.secrets.set("k", &c.id, SecretField::Psk);
    f.native.set_list(Ok(list("Disconnected")));
    f.native.set_address(SVC, Some("vpn.example.com"));
    let m = f.manager();
    m.refresh();
    assert_eq!(m.connections().first().and_then(|c| c.native_service_id.clone()), None);
    let events = record_events(&m);
    m.connect(&m.connections()[0].clone(), false);
    assert!(f.native.starts().is_empty());
    let key = uuid_string(&c.id);
    assert_eq!(m.state(&key), failed_state(SERVER_MISMATCH_HU));
    assert_eq!(events_of(&events), [failed(&key, "Office L2TP", SERVER_MISMATCH_HU)]);
}

/// Unbound and the server address cannot be read (or the connection has no server): refused too.
#[test]
fn unbound_name_match_with_unknown_address_refuses_to_start() {
    let f = Fixture::new(HU);
    let c = l2tp_connection(Some("vpn.example.com"));
    f.store.save(&c, None).unwrap();
    f.secrets.set("pw", &c.id, SecretField::Password);
    f.native.set_list(Ok(list("Disconnected")));
    f.native.set_address(SVC, None);
    let m = f.manager();
    m.connect(&c, false);
    assert!(f.native.starts().is_empty());
    assert_eq!(m.state(&uuid_string(&c.id)), failed_state(SERVER_MISMATCH_HU));

    let legacy = l2tp_connection(None);
    f.store.save(&legacy, None).unwrap();
    f.native.set_address(SVC, Some("vpn.example.com"));
    m.reload();
    m.connect(&legacy, false);
    assert!(f.native.starts().is_empty());
    assert_eq!(m.state(&uuid_string(&legacy.id)), failed_state(SERVER_MISMATCH_HU));
}

/// Unbound, the address matches (case-insensitively) at connect time even without a prior refresh: secrets
/// passed.
#[test]
fn unbound_name_match_with_same_server_passes_secrets() {
    let f = Fixture::new(HU);
    let (m, c) = native_manager(&f);
    f.native.set_address(SVC, Some("VPN.Example.com"));
    f.secrets.set("pw", &c.id, SecretField::Password);
    m.connect(&c, false);
    assert_eq!(f.native.starts().into_iter().map(|s| s.service_id).collect::<Vec<_>>(), [SVC]);
    assert_eq!(f.native.starts()[0].options, opts(&[("PPP", &[("AuthPassword", "pw")])]));
}

#[test]
fn server_mismatch_message_is_english_too() {
    let _f = Fixture::new(AppLanguage::En);
    assert_eq!(
        server_mismatch_reason("Office L2TP"),
        "The server address of the VPN service named “Office L2TP” does not match this connection’s server. MacVPN does not pass the password or the PSK to it: reinstall the profile in MacVPN → Connections, or remove the other service in System Settings → Network."
    );
}

#[test]
fn vanished_bound_service_is_unbound() {
    let f = Fixture::new(HU);
    let mut c = l2tp_connection(None);
    c.native_service_id = Some(OTHER.into());
    f.store.save(&c, None).unwrap();
    f.native.set_list(Ok(list("Disconnected")));
    let m = f.manager();
    m.connect(&c, false);
    assert!(f.native.starts().is_empty(), "a bound but missing service is not replaced by a name match");
    assert_eq!(m.state(&uuid_string(&c.id)), failed_state("A profil nincs telepítve: Office L2TP"));
    m.refresh();
    assert_eq!(m.connections().first().and_then(|c| c.native_service_id.clone()), None);
    assert_eq!(f.store.list().unwrap().first().and_then(|c| c.native_service_id.clone()), None);
}

#[test]
fn installed_native_ids_are_reported() {
    let f = Fixture::new(HU);
    let (m, c) = native_manager(&f);
    let seen: Arc<Mutex<Vec<HashSet<uuid::Uuid>>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let seen = seen.clone();
        m.set_on_native_services_seen(move |ids| seen.lock().unwrap().push(ids.clone()));
    }
    m.refresh();
    assert_eq!(*seen.lock().unwrap(), [HashSet::from([c.id])]);
    f.native.set_list(Ok(Vec::new()));
    m.refresh();
    assert_eq!(*seen.lock().unwrap(), [HashSet::from([c.id]), HashSet::new()]);
    assert!(m.installed_native_ids().is_empty());
}

/// WinVPN 2c: the platform's own service of a connection (its RAS entry `WinVPN-<UUID>`, named after the ID, not
/// the connection) binds it before the name: its state, its start (no server-address check: it is never foreign)
/// and its stop go there, and a same-named VPN of the user stays a system VPN. An IKEv2 connection's entry is not a
/// system VPN either. Without a managed ID (macOS) the name + server binding is unchanged (the tests above).
#[test]
fn a_managed_service_id_binds_without_the_name() {
    let f = Fixture::new(HU);
    let c = l2tp_connection(Some("vpn.example.com"));
    let ikev2 = Connection::new("Branch IKEv2", VPNKind::Strongswan);
    f.store.save(&c, None).unwrap();
    f.store.save(&ikev2, Some("connections {}\n")).unwrap();
    let entry = format!("WinVPN-{}", uuid_string(&c.id));
    let ikev2_entry = format!("WinVPN-{}", uuid_string(&ikev2.id));
    f.native.set_managed(&c.id, &entry);
    f.native.set_managed(&ikev2.id, &ikev2_entry);
    f.helper.respond("status", Ok("[]"));
    f.native.set_list(Ok(vec![
        SystemVpn::new(&entry, &entry, "L2TP", "Connected"),
        SystemVpn::new(&ikev2_entry, &ikev2_entry, "IKEv2", "Disconnected"),
        // The user's own VPN with the connection's name and server: not ours.
        l2tp("Disconnected"),
    ]));
    f.native.set_address(SVC, Some("vpn.example.com"));
    let m = f.manager();
    m.refresh();
    assert_eq!(m.state(&uuid_string(&c.id)), connected(None));
    assert_eq!(m.system_services().iter().map(|s| s.id.clone()).collect::<Vec<_>>(), [SVC]);
    assert_eq!(m.installed_native_ids(), HashSet::from([c.id]));
    // Not bound to the user's VPN in the store.
    assert_eq!(m.connections().iter().find(|x| x.id == c.id).unwrap().native_service_id, None);

    f.native.set_list(Ok(vec![SystemVpn::new(&entry, &entry, "L2TP", "Disconnected"), l2tp("Disconnected")]));
    m.refresh();
    let shows = f.native.shows();
    f.secrets.set("pw", &c.id, SecretField::Password);
    m.connect(&c, false);
    assert_eq!(
        f.native.starts().iter().map(|s| s.service_id.clone()).collect::<Vec<_>>(),
        std::slice::from_ref(&entry)
    );
    assert_eq!(f.native.shows(), shows, "no server address check for the platform's own entry");
    m.disconnect(&c);
    assert_eq!(f.native.stops(), std::slice::from_ref(&entry));

    // Its entry gone: not installed, and never the user's same-named VPN instead.
    f.native.set_list(Ok(vec![l2tp("Connected")]));
    m.refresh();
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Disconnected);
    assert!(m.installed_native_ids().is_empty());
}

/// WinVPN 2c: the platform's answer which connections it cannot connect with their settings, read at every reload
/// with the stored config (an empty one for the native kinds); none without a `NativeSupport` (macOS).
#[test]
fn unsupported_settings_are_read_at_reload() {
    struct Support(Mutex<Vec<(VPNKind, String)>>);
    impl macvpn_app_core::deps::NativeSupport for Support {
        fn unsupported_reason(&self, c: &Connection, config: &[u8]) -> Option<String> {
            let config = String::from_utf8_lossy(config).into_owned();
            self.0.lock().unwrap().push((c.kind, config.clone()));
            (config.contains("eap-tls") || c.kind == VPNKind::Cisco).then(|| format!("Not on Windows: {}", c.name))
        }
    }
    let f = Fixture::new(HU);
    let tls = Connection::new("TLS", VPNKind::Strongswan);
    let eap = Connection::new("EAP", VPNKind::Strongswan);
    let cisco = Connection::new("Partner", VPNKind::Cisco);
    f.store.save(&tls, Some("auth = eap-tls\n")).unwrap();
    f.store.save(&eap, Some("auth = eap-mschapv2\n")).unwrap();
    f.store.save(&cisco, None).unwrap();
    let plain = f.manager();
    assert!(plain.unsupported_reasons().is_empty());

    let support = Arc::new(Support(Mutex::new(Vec::new())));
    let m = macvpn_app_core::ConnectionManager::new(f.deps());
    m.set_native_support(support.clone());
    m.reload();
    let reasons = m.unsupported_reasons();
    assert_eq!(reasons.len(), 2);
    assert_eq!(reasons.get(&uuid_string(&tls.id)).map(String::as_str), Some("Not on Windows: TLS"));
    assert_eq!(m.unsupported_reason(&uuid_string(&cisco.id)).as_deref(), Some("Not on Windows: Partner"));
    assert_eq!(m.unsupported_reason(&uuid_string(&eap.id)), None);
    let asked = support.0.lock().unwrap().clone();
    assert!(asked.contains(&(VPNKind::Cisco, String::new())));
    assert!(asked.contains(&(VPNKind::Strongswan, "auth = eap-mschapv2\n".into())));
    m.enter_locked();
    assert!(m.unsupported_reasons().is_empty(), "nothing kept while locked");
}

/// Live traffic: the connected tunnels with what the helper reported (the interface, the address, the run's
/// start), the managed native ones by their bound service and the connected system VPNs; nothing else.
#[test]
fn tunnels_lists_the_connected_ones_with_their_interface() {
    use macvpn_app_core::manager::{Tunnel, TunnelSource};
    let f = Fixture::new(HU);
    let ovpn = Connection::new("Iroda", VPNKind::Openvpn);
    let wg = Connection::new("Otthon", VPNKind::Wireguard);
    let mut l2tp_c = l2tp_connection(None);
    l2tp_c.native_service_id = Some(SVC.into());
    f.store.save(&ovpn, Some("remote x\n")).unwrap();
    f.store.save(&wg, Some("x")).unwrap();
    f.store.save(&l2tp_c, None).unwrap();
    let json = format!(
        r#"[{{"id":"{}","kind":"openvpn","state":"connected","iface":"utun7","ip":"10.8.0.2","since":1800000000}},{{"id":"{}","kind":"wireguard","state":"connecting","iface":"utun9","ip":null,"since":null}}]"#,
        uuid_string(&ovpn.id),
        uuid_string(&wg.id)
    );
    f.helper.respond("status", Ok(&json));
    f.native.set_list(Ok(vec![
        SystemVpn::new(SVC, "Office L2TP", "L2TP", "Connected"),
        SystemVpn::new(OTHER, "Other", "IKEv2", "Connected"),
        SystemVpn::new(WG_SVC, "Home", "WireGuard (app)", "Disconnected"),
    ]));
    let m = f.manager();
    m.refresh();
    let tunnels = m.tunnels();
    assert_eq!(
        tunnels,
        [
            Tunnel {
                key: uuid_string(&ovpn.id),
                source: TunnelSource::Helper {
                    id: ovpn.id,
                    kind: VPNKind::Openvpn,
                    iface: Some("utun7".into()),
                    ip: Some("10.8.0.2".into()),
                    since: Some(1_800_000_000.0),
                },
            },
            Tunnel { key: uuid_string(&l2tp_c.id), source: TunnelSource::Native { service_id: SVC.into() } },
            Tunnel { key: OTHER.into(), source: TunnelSource::Native { service_id: OTHER.into() } },
        ]
    );
    // Down: the interface is forgotten with the state.
    f.helper.respond("status", Ok("[]"));
    m.refresh();
    assert!(m.tunnels().iter().all(|t| t.key != uuid_string(&ovpn.id)));
}

/// A native service: its tunnel address from the platform (`NativeController::address`) and the time the manager saw
/// it connect; a service already up at the first refresh has no time; down forgets it.
#[test]
fn native_services_show_their_address_and_the_time_they_were_seen_to_connect() {
    let f = Fixture::new(HU);
    f.native.set_list(Ok(list("Connected")));
    f.native.set_address_of(SVC, Some("10.0.0.5"));
    let m = f.manager();
    m.refresh();
    assert_eq!(m.state(SVC), connected(Some("10.0.0.5")), "already up: no time");
    f.native.set_list(Ok(list("Disconnected")));
    m.refresh();
    f.native.set_list(Ok(list("Connected")));
    m.refresh();
    assert!(matches!(m.state(SVC), ConnectionState::Connected { ip: Some(ip), since: Some(_) } if ip == "10.0.0.5"));
}
