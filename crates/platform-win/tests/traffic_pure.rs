//! Live traffic on Windows: where a service tunnel's counters are read, and the RAS generations.

use macvpn_core::models::VPNKind;
use macvpn_platform_api::CounterWidth;
use macvpn_platform_win::pure::traffic::{Lookup, RasGenerations, interface_reading, lookup, service_count_reading};

#[test]
fn wireguard_by_its_alias_openvpn_by_its_address() {
    assert_eq!(
        lookup(VPNKind::Wireguard, Some("WinVPN-1a2b3c4d"), None),
        Some(Lookup::Alias("WinVPN-1a2b3c4d".into()))
    );
    assert_eq!(lookup(VPNKind::Wireguard, Some("bad name"), Some("10.0.0.2")), None);
    assert_eq!(lookup(VPNKind::Wireguard, None, Some("10.0.0.2")), None);
    assert_eq!(lookup(VPNKind::Openvpn, None, Some("10.8.0.6")), Some(Lookup::Address("10.8.0.6".parse().unwrap())));
    assert_eq!(lookup(VPNKind::Openvpn, None, Some("fd00::6")), Some(Lookup::Address("fd00::6".parse().unwrap())));
    assert_eq!(lookup(VPNKind::Openvpn, None, Some("nope")), None);
    assert_eq!(lookup(VPNKind::Openvpn, None, None), None);
    assert_eq!(lookup(VPNKind::Strongswan, Some("x"), Some("10.0.0.2")), None);
}

#[test]
fn a_wireguard_adapter_counts_from_zero_an_openvpn_one_does_not() {
    let wg = interface_reading(&Lookup::Alias("a".into()), 7, Some(1_800_000_000.0), 10, 20);
    assert!(wg.from_zero);
    assert_eq!((wg.rx, wg.tx, wg.width), (10, 20, CounterWidth::Bits64));
    let ovpn = interface_reading(&Lookup::Address("10.8.0.6".parse().unwrap()), 7, Some(1_800_000_000.0), 10, 20);
    assert!(!ovpn.from_zero);
    // Another run (or another adapter index) is another generation.
    let later = interface_reading(&Lookup::Alias("a".into()), 7, Some(1_800_000_100.0), 10, 20);
    let other = interface_reading(&Lookup::Alias("a".into()), 8, Some(1_800_000_000.0), 10, 20);
    assert_ne!(wg.generation, later.generation);
    assert_ne!(wg.generation, other.generation);
    assert_eq!(wg.generation, interface_reading(&Lookup::Alias("b".into()), 7, Some(1_800_000_000.0), 1, 2).generation);
}

#[test]
fn a_reused_ras_handle_is_another_generation() {
    let mut g = RasGenerations::default();
    let a = g.reading(0x40, 1000, 2000, 5_000);
    let b = g.reading(0x40, 1500, 2100, 6_000);
    assert_eq!(a.generation, b.generation);
    assert_eq!((b.rx, b.tx, b.width, b.from_zero), (1500, 2100, CounterWidth::Bits32, true));
    // The handle came back for a new connection: its connected time started again.
    let c = g.reading(0x40, 10, 20, 1_000);
    assert_ne!(b.generation, c.generation);
    assert_eq!(c.generation, g.reading(0x40, 30, 40, 2_000).generation);
    assert_ne!(g.reading(0x41, 1, 1, 1).generation, c.generation);
}

#[test]
fn openvpns_bytecount_is_one_generation_per_process_run() {
    use macvpn_core::traffic::ByteCount;
    let a = service_count_reading(&ByteCount { rx: 10, tx: 20, run: 1_800_000_000 });
    assert_eq!((a.rx, a.tx, a.width, a.from_zero), (10, 20, CounterWidth::Bits64, true));
    // The same process later (a reconnect inside it keeps counting): the same generation.
    assert_eq!(a.generation, service_count_reading(&ByteCount { rx: 99, tx: 99, run: 1_800_000_000 }).generation);
    // A new openvpn.exe: a new generation.
    assert_ne!(a.generation, service_count_reading(&ByteCount { rx: 1, tx: 1, run: 1_800_000_050 }).generation);
    // Never the generation of the adapter fallback.
    let adapter = interface_reading(&Lookup::Address("10.8.0.6".parse().unwrap()), 7, Some(1_800_000_000.0), 10, 20);
    assert_ne!(a.generation, adapter.generation);
}
