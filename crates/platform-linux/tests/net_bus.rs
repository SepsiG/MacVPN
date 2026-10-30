//! The network probe against a fake NetworkManager on the test's private bus (dbus-run-session), plus one read-only
//! look at the real one (`desktop_*`, ignored everywhere).
#![cfg(target_os = "linux")]

#[path = "fake_nm/net_ext.rs"]
mod net_ext;

use macvpn_core::netaddr::IpPrefix;
use macvpn_platform_api::{NetworkProbe, PlatformError};
use macvpn_platform_linux::lin_for_tests::net::LinNetwork;
use net_ext::{FakeDevice, FakeNet, NM_PATH, device, ip};
use std::sync::{Mutex, MutexGuard, PoisonError, mpsc};
use std::time::Duration;

/// One fake owns NM's name at a time.
static ONE_NM: Mutex<()> = Mutex::new(());

fn one_nm() -> MutexGuard<'static, ()> {
    ONE_NM.lock().unwrap_or_else(PoisonError::into_inner)
}

fn probe() -> LinNetwork {
    LinNetwork { bus: zbus::blocking::Connection::session }
}

fn prefix(s: &str) -> IpPrefix {
    IpPrefix::parse(s).unwrap()
}

const ACTIVATED: u32 = 100;
const DISCONNECTED: u32 = 30;

/// Ethernet (activated, metric 100), Wi-Fi "Office" (metric 600), and LinVPN's WireGuard tunnel (metric 50, NM's
/// primary connection in a full tunnel).
fn office(ethernet_state: u32) -> Vec<FakeDevice> {
    let ethernet = device(
        "enp1s0",
        1,
        ethernet_state,
        Some(ip("192.0.2.1", &[("192.0.2.10", 24)], Some(100))),
        Some(ip("fe80::1", &[("2001:db8::10", 64), ("fe80::5054:ff:fe12:3456", 64)], Some(100))),
    );
    let mut wifi = device("wlp2s0", 2, ACTIVATED, Some(ip("198.51.100.1", &[("198.51.100.20", 24)], Some(600))), None);
    wifi.ssid = Some(b"Office\x07".to_vec());
    let wireguard = device("linvpn-wg0", 29, ACTIVATED, Some(ip("10.99.13.1", &[("10.99.13.5", 32)], Some(50))), None);
    let loopback = device("lo", 32, ACTIVATED, Some(ip("", &[("127.0.0.1", 8)], None)), None);
    vec![ethernet, wifi, wireguard, loopback]
}

#[test]
fn the_snapshot_is_the_physical_network_and_never_the_tunnel() {
    let _one = one_nm();
    let _nm = FakeNet::start(office(ACTIVATED));
    let s = probe().snapshot().expect("a snapshot");
    let g = s.gateway.expect("a gateway");
    assert_eq!(g.interface, "enp1s0");
    assert_eq!(g.ip, "192.0.2.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(g.ssid, None, "wired");
    assert_eq!(g.mac, None, "a documentation address is in no neighbour table");
    assert_eq!(s.connected, vec![prefix("192.0.2.0/24"), prefix("2001:db8::/64"), prefix("198.51.100.0/24")]);
}

#[test]
fn on_wi_fi_the_snapshot_names_the_network() {
    let _one = one_nm();
    let _nm = FakeNet::start(office(DISCONNECTED));
    let g = probe().snapshot().unwrap().gateway.expect("a gateway");
    assert_eq!(g.interface, "wlp2s0");
    assert_eq!(g.ssid.as_deref(), Some("Office"), "control characters removed");
}

#[test]
fn only_a_tunnel_is_no_network() {
    let _one = one_nm();
    let devices = office(ACTIVATED).into_iter().filter(|d| d.device_type == 29).collect();
    let _nm = FakeNet::start(devices);
    let s = probe().snapshot().unwrap();
    assert!(!s.has_network());
    assert!(s.connected.is_empty());
}

#[test]
fn without_networkmanager_the_snapshot_fails() {
    let _one = one_nm();
    assert!(matches!(probe().snapshot(), Err(PlatformError::Failed(_))));
}

fn watch(nm_devices: Vec<FakeDevice>) -> (FakeNet, mpsc::Receiver<()>, Box<dyn Send>) {
    let nm = FakeNet::start(nm_devices);
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let guard = probe()
        .watch(Box::new(move || {
            let _ = tx.lock().unwrap_or_else(PoisonError::into_inner).send(());
        }))
        .expect("the watch starts");
    (nm, rx, guard)
}

#[test]
fn a_device_state_change_calls_on_change() {
    let _one = one_nm();
    let (nm, rx, _guard) = watch(office(ACTIVATED));
    nm.emit_device_state(0, DISCONNECTED, ACTIVATED);
    rx.recv_timeout(Duration::from_secs(5)).expect("on_change after StateChanged");
}

#[test]
fn nm_network_and_address_changes_call_on_change_and_signal_strength_does_not() {
    let _one = one_nm();
    let (nm, rx, _guard) = watch(office(ACTIVATED));
    nm.emit_property_changed(
        &format!("{NM_PATH}/AccessPoint/2"),
        "org.freedesktop.NetworkManager.AccessPoint",
        "Strength",
        40,
    );
    nm.emit_property_changed(NM_PATH, "org.freedesktop.NetworkManager", "PrimaryConnection", 0);
    rx.recv_timeout(Duration::from_secs(5)).expect("on_change after PrimaryConnection");
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err(), "the access point's strength is no change");
    nm.emit_property_changed(
        &format!("{NM_PATH}/IP4Config/1"),
        "org.freedesktop.NetworkManager.IP4Config",
        "Gateway",
        0,
    );
    rx.recv_timeout(Duration::from_secs(5)).expect("on_change after an IP4Config change");
}

#[test]
fn dropping_the_watch_stops_it() {
    let _one = one_nm();
    let (nm, rx, guard) = watch(office(ACTIVATED));
    drop(guard);
    nm.emit_device_state(0, DISCONNECTED, ACTIVATED);
    assert!(rx.recv_timeout(Duration::from_secs(1)).is_err(), "no call after the guard is gone");
}

#[test]
#[ignore = "desktop: reads the real NetworkManager's devices (read-only)"]
fn desktop_net_snapshot_of_the_real_network() {
    let s = LinNetwork { bus: zbus::blocking::Connection::system }.snapshot().expect("a snapshot");
    match &s.gateway {
        Some(g) => println!(
            "interface {}, gateway found, MAC {}, SSID {}",
            g.interface,
            if g.mac.is_some() { "found" } else { "not found" },
            if g.ssid.is_some() { "found" } else { "not found" }
        ),
        None => println!("no gateway"),
    }
    println!("{} connected subnets", s.connected.len());
}
