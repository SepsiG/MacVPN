#![cfg(target_os = "linux")]
//! The user's own NetworkManager VPNs as system VPNs (resolved point 14) and the watch, against the fake NM,
//! polkit and agent manager on the test's private bus (dbus-run-session). Nothing here reads or writes the real NM.
mod fake_nm;

use fake_nm::engine_ext::{Outcome, Tmp, with_agent_manager};
use fake_nm::{Polkit, ROOT, SETTINGS};
use macvpn_core::models::Secrets;
use macvpn_core::native::NativeKind;
use macvpn_platform_api::NativeController;
use macvpn_platform_linux::lin_for_tests::nm::engine::Engine;
use macvpn_platform_linux::lin_for_tests::nm::system_vpns;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;
use zbus::zvariant::{ObjectPath, Value};

const L2TP: &str = "org.freedesktop.NetworkManager.l2tp";
const UUID_L2TP: &str = "3c1f6a2e-5d4b-4e8a-9f70-1a2b3c4d5e6f";
const UUID_WG: &str = "8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d";

fn engine(tmp: &Tmp) -> Arc<Engine> {
    let e = Engine::new(
        zbus::blocking::Connection::session,
        false,
        "linvpn-dev".into(),
        1001,
        Some(tmp.path().join("run")),
        tmp.path().join("data"),
    );
    // No journal lines from the host's linvpn-logd: the logs here are the engine's own.
    e.set_logd_socket_for_tests(tmp.path().join("no-logd.sock"));
    e
}

fn secrets() -> Secrets {
    Secrets { password: Some("pass-word-1".into()), psk: Some("shared-secret-2".into()), ..Secrets::default() }
}

fn wait<T>(f: impl Fn() -> Option<T>) -> T {
    for _ in 0..200 {
        if let Some(v) = f() {
            return v;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out")
}

fn index_of(nm: &fake_nm::FakeNm, method: &str) -> Option<usize> {
    nm.calls().iter().position(|c| c.method == method)
}

#[test]
fn only_the_users_own_profiles_are_listed_with_labels_and_addresses() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    nm.add_vpn_profile(UUID_L2TP, "Office L2TP", L2TP, &[("gateway", "vpn.example.com")], &["user:linvpn-dev"], 0);
    nm.add_vpn_profile(
        "4d2a7b3f-6e5c-4f9b-8a81-2b3c4d5e6f70",
        "Branch",
        "org.freedesktop.NetworkManager.vpnc",
        &[("IPSec gateway", "198.51.100.7")],
        &[],
        0,
    );
    nm.add_wireguard_profile(UUID_WG, "Home WG", "wg.example.com:51820", &[]);
    nm.add_profile("5e3b8c4a-7f6d-4a0c-9b92-3c4d5e6f7081", &["user:other"], 0);
    nm.add_profile("6f4c9d5b-8a7e-4b1d-8ca3-4d5e6f708192", &[], 4);
    // A LinVPN-derived (UUIDv8) connection and an ethernet profile are never system VPNs.
    let derived = macvpn_core::nm_plan::names::nm_uuid(1001, &uuid::Uuid::new_v4()).to_string();
    nm.add_profile(&derived, &[], 0);
    let list = e.list().unwrap();
    let mut rows: Vec<(String, String, String, String)> =
        list.iter().map(|v| (v.id.clone(), v.name.clone(), v.type_label.clone(), v.status.clone())).collect();
    rows.sort();
    assert_eq!(
        rows,
        vec![
            (UUID_L2TP.into(), "Office L2TP".into(), "L2TP".into(), "Disconnected".into()),
            (
                "4d2a7b3f-6e5c-4f9b-8a81-2b3c4d5e6f70".into(),
                "Branch".into(),
                "Cisco IPsec".into(),
                "Disconnected".into()
            ),
            (UUID_WG.into(), "Home WG".into(), "WireGuard (app)".into(), "Disconnected".into()),
        ]
    );
    assert_eq!(system_vpns::list(&e).unwrap().len(), 3);
    assert_eq!(e.remote_address(UUID_L2TP), Some("vpn.example.com".into()));
    assert_eq!(e.remote_address("4d2a7b3f-6e5c-4f9b-8a81-2b3c4d5e6f70"), Some("198.51.100.7".into()));
    assert_eq!(e.remote_address(UUID_WG), Some("wg.example.com".into()));
    assert_eq!(e.remote_address("5e3b8c4a-7f6d-4a0c-9b92-3c4d5e6f7081"), None, "not the user's");
    // Read-only: listing wrote nothing.
    assert!(nm.calls().iter().all(|c| c.method != "Delete" && c.method != "AddAndActivateConnection2"));
}

#[test]
fn a_system_l2tp_starts_after_polkit_with_the_agent_answering_its_secrets() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let path =
        nm.add_vpn_profile(UUID_L2TP, "Office", L2TP, &[("gateway", "vpn.example.com")], &["user:linvpn-dev"], 0);
    nm.activate_next(Outcome::Activated { ip4: "10.99.16.4" });
    e.start(UUID_L2TP, Some(NativeKind::L2tp), &secrets()).unwrap();
    assert_eq!(nm.activated_profiles(), vec![path.clone()]);
    let activate = nm.calls().into_iter().find(|c| c.method == "ActivateConnection").unwrap();
    assert!(!activate.allow_interactive_authorization);
    assert!(index_of(&nm, "CheckAuthorization").unwrap() < index_of(&nm, "ActivateConnection").unwrap());
    let answer = nm.as_nm_get_secrets(UUID_L2TP, "vpn", &[]).unwrap();
    assert_eq!(answer.get("password").map(String::as_str), Some("pass-word-1"));
    assert_eq!(answer.get("ipsec-psk").map(String::as_str), Some("shared-secret-2"));
    wait(|| e.list().unwrap().into_iter().find(|v| v.id == UUID_L2TP && v.status == "Connected"));
    assert_eq!(e.address(UUID_L2TP), Some("10.99.16.4".into()));

    e.stop(UUID_L2TP).unwrap();
    assert!(nm.deactivated().contains(&nm.last_active_path()));
    assert!(nm.as_nm_get_secrets(UUID_L2TP, "vpn", &[]).is_err(), "forgotten after stop");
    assert_eq!(e.list().unwrap().into_iter().find(|v| v.id == UUID_L2TP).unwrap().status, "Disconnected");
    assert_eq!(e.address(UUID_L2TP), None);

    // Without secrets, or without a kind: the stored configuration only, no agent expectation.
    nm.activate_next(Outcome::Activated { ip4: "10.99.16.5" });
    e.start(UUID_L2TP, Some(NativeKind::L2tp), &Secrets::default()).unwrap();
    assert!(nm.as_nm_get_secrets(UUID_L2TP, "vpn", &[]).is_err());
    e.stop(UUID_L2TP).unwrap();
    nm.activate_next(Outcome::Activated { ip4: "10.99.16.6" });
    e.start(UUID_L2TP, None, &secrets()).unwrap();
    assert!(nm.as_nm_get_secrets(UUID_L2TP, "vpn", &[]).is_err());
    e.stop(UUID_L2TP).unwrap();
}

#[test]
fn a_profile_that_is_not_the_users_or_a_refused_polkit_starts_nothing() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    nm.add_profile("5e3b8c4a-7f6d-4a0c-9b92-3c4d5e6f7081", &["user:other"], 0);
    assert!(e.start("5e3b8c4a-7f6d-4a0c-9b92-3c4d5e6f7081", Some(NativeKind::L2tp), &secrets()).is_err());
    assert!(e.start("not-a-profile", None, &Secrets::default()).is_err());
    assert!(nm.activated_profiles().is_empty());

    nm.add_vpn_profile(UUID_L2TP, "Office", L2TP, &[("gateway", "vpn.example.com")], &["user:linvpn-dev"], 0);
    nm.set_polkit(Polkit::Challenge);
    let err = e.start(UUID_L2TP, Some(NativeKind::L2tp), &secrets()).unwrap_err();
    assert!(err.contains("without asking for a password"), "{err}");
    assert!(nm.activated_profiles().is_empty());
    assert!(nm.as_nm_get_secrets(UUID_L2TP, "vpn", &[]).is_err(), "no secrets kept after a refusal");
    assert!(nm.calls().iter().all(|c| !c.allow_interactive_authorization));
}

#[test]
fn traffic_and_address_of_a_connected_system_vpn() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    nm.add_wireguard_profile(UUID_WG, "Home WG", "wg.example.com:51820", &["user:linvpn-dev"]);
    nm.add_active(UUID_WG, "wireguard", 2, Some("10.99.20.2"), "wg-home");
    e.set_counters_for_tests(Box::new(|i| (i == "wg-home").then_some((100, 444))));
    assert_eq!(e.list().unwrap().into_iter().find(|v| v.id == UUID_WG).unwrap().status, "Connected");
    assert_eq!(e.address(UUID_WG), Some("10.99.20.2".into()));
    let r = e.traffic(UUID_WG).expect("the interface's counters");
    assert_eq!((r.rx, r.tx), (100, 444));
    assert_eq!(e.traffic(UUID_WG).unwrap().generation, r.generation, "the same activation");

    // IKEv2 through charon-nm: an address, but no tunnel interface (policy-based): its SAs' counters from
    // linvpn-xfrmd, none without its answer.
    let ike = "7a5d0e6c-9b8f-4c2e-8db4-5e6f708192a3";
    e.set_xfrm_for_tests(Box::new(|_| None));
    nm.add_vpn_profile(
        ike,
        "IKE",
        "org.freedesktop.NetworkManager.strongswan",
        &[("address", "vpn.example.com")],
        &[],
        0,
    );
    nm.activate_next(Outcome::Activated { ip4: "10.99.21.3" });
    e.start(ike, None, &Secrets::default()).unwrap();
    wait(|| e.address(ike));
    assert!(e.traffic(ike).is_none());
    let target = macvpn_core::xfrmd::Target::System(ike.parse().unwrap());
    e.set_xfrm_for_tests(Box::new(move |t| (*t == target).then_some((70, 80))));
    assert_eq!(e.traffic(ike).map(|r| (r.rx, r.tx, r.from_zero)), Some((70, 80, true)));
    // strongSwan 6: charon-nm's XFRM interface holds the address; its counters win.
    e.set_tunnel_ifaces_for_tests(Box::new(|ip| if ip == "10.99.21.3" { vec!["nm-xfrm-77".into()] } else { vec![] }));
    e.set_counters_for_tests(Box::new(|i| (i == "nm-xfrm-77").then_some((700, 800))));
    assert_eq!(e.traffic(ike).map(|r| (r.rx, r.tx)), Some((700, 800)));
    assert_eq!(e.list().unwrap().into_iter().find(|v| v.id == ike).unwrap().type_label, "IKEv2");
    e.stop(ike).unwrap();
    // Not connected: nothing.
    assert!(e.traffic("8b6e1f7d-0c9a-4d3f-9ec5-6f708192a3b4").is_none());
}

#[test]
fn the_watch_reports_profile_and_active_changes() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let (tx, rx) = mpsc::channel::<()>();
    let guard = system_vpns::watch(
        &e,
        Box::new(move || {
            let _ = tx.send(());
        }),
    )
    .unwrap();
    let drain = || while rx.recv_timeout(Duration::from_millis(200)).is_ok() {};

    let new = ObjectPath::try_from("/org/freedesktop/NetworkManager/Settings/99").unwrap();
    nm.emit(SETTINGS, "org.freedesktop.NetworkManager.Settings", "NewConnection", &(new,));
    rx.recv_timeout(Duration::from_secs(5)).expect("ProfilesChanged");
    drain();

    let changed: HashMap<&str, Value<'_>> = HashMap::from([("ActiveConnections", Value::from(Vec::<String>::new()))]);
    nm.emit(
        ROOT,
        "org.freedesktop.DBus.Properties",
        "PropertiesChanged",
        &("org.freedesktop.NetworkManager", changed, Vec::<String>::new()),
    );
    rx.recv_timeout(Duration::from_secs(5)).expect("ActiveChanged");
    drain();

    // The network alone (connectivity) is not a system VPN change.
    let changed: HashMap<&str, Value<'_>> = HashMap::from([("Connectivity", Value::from(4u32))]);
    nm.emit(
        ROOT,
        "org.freedesktop.DBus.Properties",
        "PropertiesChanged",
        &("org.freedesktop.NetworkManager", changed, Vec::<String>::new()),
    );
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());

    drop(guard);
    let new = ObjectPath::try_from("/org/freedesktop/NetworkManager/Settings/100").unwrap();
    nm.emit(SETTINGS, "org.freedesktop.NetworkManager.Settings", "NewConnection", &(new,));
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err(), "stopped with its guard");
}

#[test]
fn the_sandbox_lists_no_system_vpn_and_watches_nothing() {
    let (nm, _am, tmp) = with_agent_manager();
    nm.add_vpn_profile(UUID_L2TP, "Office", L2TP, &[("gateway", "vpn.example.com")], &[], 0);
    let e = Engine::new(
        zbus::blocking::Connection::session,
        true,
        "linvpn-dev".into(),
        1001,
        None,
        tmp.path().join("data"),
    );
    assert!(e.list().unwrap().is_empty());
    assert!(e.start(UUID_L2TP, Some(NativeKind::L2tp), &secrets()).is_err());
    assert!(system_vpns::watch(&e, Box::new(|| {})).is_ok());
    assert!(nm.calls().is_empty());
}

/// The real NetworkManager, read-only (`ListConnections`, `GetSettings`, the active connections): every listed
/// system VPN has a known label and status. Run by hand on the VM: `cargo test --test nm_system_vpns -- --ignored`.
#[test]
#[ignore = "reads the real NetworkManager (read-only)"]
fn desktop_lists_the_real_profiles_read_only() {
    let tmp = Tmp::new("desktop");
    let e = Engine::new(
        zbus::blocking::Connection::system,
        false,
        "linvpn-dev".into(),
        1001,
        None,
        tmp.path().join("data"),
    );
    let list = system_vpns::list(&e).expect("NetworkManager answers");
    for v in &list {
        assert!(
            ["L2TP", "Cisco IPsec", "IKEv2", "WireGuard (app)", "OpenVPN (app)", "VPN"]
                .contains(&v.type_label.as_str())
        );
        assert!(["Connected", "Connecting", "Disconnecting", "Disconnected"].contains(&v.status.as_str()));
    }
    eprintln!("{} system VPN(s)", list.len());
}
