//! The network reads (Windows only; no administrator rights). Only the `#[ignore]`d probe touches the live network
//! (it sends one ARP / NDP request to the default gateway, read-only); it is listed in
//! scripts/ignored-everywhere.txt and run by hand: `cargo test -p macvpn-winsys --test net -- --ignored --nocapture`.

#![cfg(windows)]

use macvpn_winsys::net;

#[test]
fn adapters_include_loopback_and_their_prefixes() {
    let list = net::adapters().unwrap();
    assert!(list.iter().any(|a| a.if_type == 24), "the loopback adapter is listed");
    for a in &list {
        for (ip, len) in &a.unicast {
            assert!(*len <= if ip.is_ipv4() { 32 } else { 128 }, "{}: {ip}/{len}", a.alias);
        }
        assert!(a.gateway.is_some() || a.route_metric == u32::MAX);
    }
    let lo = list.iter().find(|a| a.if_type == 24).unwrap();
    assert!(lo.unicast.iter().any(|(ip, _)| ip.is_loopback()));
    assert_ne!(lo.luid, 0);
}

/// G-6: the diagnostics' reads: the IPv4 routes (loopback's 127.0.0.0/8 is always there) and the adapters with
/// their DNS servers, consistent with `adapters`.
#[test]
fn the_diagnostics_read_routes_and_dns() {
    let routes = net::ipv4_routes().unwrap();
    assert!(routes.iter().all(|r| r.destination.is_ipv4() && r.next_hop.is_ipv4() && r.prefix_len <= 32));
    assert!(routes.iter().any(|r| r.destination.to_string() == "127.0.0.0" && r.prefix_len == 8), "{routes:?}");
    let diag = net::adapters_with_dns().unwrap();
    let plain = net::adapters().unwrap();
    assert_eq!(diag.len(), plain.len());
    for (d, a) in diag.iter().zip(&plain) {
        assert_eq!((d.luid, &d.alias, d.up, &d.unicast), (a.luid, &a.alias, a.up, &a.unicast));
    }
    // Every route's adapter is listed.
    assert!(routes.iter().all(|r| diag.iter().any(|d| d.luid == r.luid)), "{routes:?}");
}

#[test]
fn ssid_of_a_non_wifi_adapter_is_none() {
    let list = net::adapters().unwrap();
    for a in list.iter().filter(|a| a.if_type != 71) {
        assert_eq!(net::wlan_ssid(a.guid).unwrap_or(None), None, "{}", a.alias);
    }
    assert_eq!(net::wlan_ssid([0x5a; 16]).unwrap_or(None), None, "an interface that does not exist");
}

#[test]
fn the_watch_starts_and_stops() {
    for _ in 0..10 {
        drop(net::watch(Box::new(|| {})).unwrap());
    }
}

#[test]
fn a_panicking_watch_callback_does_not_matter_when_nothing_changes() {
    drop(net::watch(Box::new(|| panic!("never called without a change"))).unwrap());
}

/// Read-only live probe: the default gateway answers with a MAC. Prints what it found (the MAC cut to its vendor
/// part).
#[test]
#[ignore = "live network: run by hand with --ignored"]
fn probe_the_default_gateway_answers_with_a_mac() {
    let list = net::adapters().unwrap();
    for a in &list {
        eprintln!(
            "{:<32} type {:>3} up {:<5} gw {:<26} metric {:>10} {} unicast",
            a.alias,
            a.if_type,
            a.up,
            a.gateway.map(|g| g.to_string()).unwrap_or_default(),
            a.route_metric,
            a.unicast.len()
        );
    }
    let Some(a) = list
        .iter()
        .filter(|a| a.up && a.gateway.is_some_and(|g| !g.is_unspecified()) && ![23, 24, 53, 131].contains(&a.if_type))
        .min_by_key(|a| a.route_metric)
    else {
        panic!("no default route on this machine");
    };
    let mac = net::neighbor_mac(a.luid, a.gateway.unwrap()).unwrap();
    eprintln!(
        "gateway {} on {}: MAC {}",
        a.gateway.unwrap(),
        a.alias,
        mac.map(|m| format!("{:02x}:{:02x}:{:02x}:xx:xx:xx", m[0], m[1], m[2])).unwrap_or("none".into())
    );
    eprintln!("ssid of {}: {:?}", a.alias, net::wlan_ssid(a.guid).unwrap_or(None));
    assert!(mac.is_some_and(|m| m != [0; 6]));
}
