use macvpn_app_core::reconnect::{
    Decision, Fingerprint, Skip, decide, fingerprint, is_enabled, set_enabled, surviving_check,
};
use macvpn_core::netaddr::IpPrefix;
use macvpn_core::vpn_networks::VpnNetworks;
use macvpn_platform_api::{Gateway, MemoryPreferences, NetworkSnapshot};
use uuid::Uuid;

const MAC_A: [u8; 6] = [0xa4, 0x2b, 0xb0, 0, 0, 1];
const MAC_B: [u8; 6] = [0xa4, 0x2b, 0xb0, 0, 0, 2];

fn snap(gw: &str, mac: Option<[u8; 6]>, ssid: Option<&str>, connected: &[&str]) -> NetworkSnapshot {
    NetworkSnapshot {
        gateway: Some(Gateway {
            ip: gw.parse().unwrap(),
            mac,
            interface: "en0".into(),
            ssid: ssid.map(str::to_string),
        }),
        connected: connected.iter().map(|c| IpPrefix::parse(c).unwrap()).collect(),
    }
}

fn home() -> NetworkSnapshot {
    snap("192.168.1.1", Some(MAC_A), Some("Home"), &["192.168.1.0/24"])
}

fn vpn(prefixes: &[&str], dns: &[&str]) -> VpnNetworks {
    VpnNetworks {
        prefixes: prefixes.iter().map(|p| IpPrefix::parse(p).unwrap()).collect(),
        dns: dns.iter().map(|d| d.parse().unwrap()).collect(),
    }
}

#[test]
fn same_network_and_nothing_reachable_reconnects() {
    let fp = fingerprint(&home());
    assert_eq!(decide(fp.as_ref(), &home(), &vpn(&["10.20.30.0/24"], &["10.20.30.53"])), Decision::Reconnect);
}

#[test]
fn no_gateway_waits() {
    let fp = fingerprint(&home());
    assert_eq!(decide(fp.as_ref(), &NetworkSnapshot::default(), &VpnNetworks::default()), Decision::Wait);
}

#[test]
fn another_gateway_or_mac_or_ssid_is_another_network() {
    let fp = fingerprint(&home());
    let v = VpnNetworks::default();
    let other_ip = snap("192.168.0.1", Some(MAC_A), Some("Home"), &["192.168.0.0/24"]);
    let other_mac = snap("192.168.1.1", Some(MAC_B), Some("Home"), &["192.168.1.0/24"]);
    let other_ssid = snap("192.168.1.1", Some(MAC_A), Some("Cafe"), &["192.168.1.0/24"]);
    for s in [other_ip, other_mac, other_ssid] {
        assert_eq!(decide(fp.as_ref(), &s, &v), Decision::Skip(Skip::DifferentNetwork));
    }
}

#[test]
fn an_unknown_ssid_on_either_side_is_not_compared() {
    let fp = fingerprint(&snap("192.168.1.1", Some(MAC_A), None, &["192.168.1.0/24"]));
    assert_eq!(decide(fp.as_ref(), &home(), &VpnNetworks::default()), Decision::Reconnect);
}

#[test]
fn without_a_mac_the_network_is_unidentified() {
    let no_mac = snap("192.168.1.1", None, Some("Home"), &["192.168.1.0/24"]);
    assert_eq!(fingerprint(&no_mac), None);
    assert_eq!(decide(None, &home(), &VpnNetworks::default()), Decision::Skip(Skip::Unidentified));
    let fp = fingerprint(&home());
    assert_eq!(decide(fp.as_ref(), &no_mac, &VpnNetworks::default()), Decision::Skip(Skip::Unidentified));
}

#[test]
fn the_vpns_network_directly_connected_is_skipped() {
    // At the office: the laptop is on 10.20.30.0/24, which the VPN from home routes.
    let office = snap("10.20.30.1", Some(MAC_A), None, &["10.20.30.0/24"]);
    let fp = fingerprint(&office);
    let skip = decide(fp.as_ref(), &office, &vpn(&["10.20.0.0/16"], &[]));
    assert_eq!(skip, Decision::Skip(Skip::DirectlyReachable(IpPrefix::parse("10.20.0.0/16").unwrap())));
    let dns = decide(fp.as_ref(), &office, &vpn(&["172.16.0.0/12"], &["10.20.30.53"]));
    assert_eq!(dns, Decision::Skip(Skip::DnsDirectlyReachable("10.20.30.53".parse().unwrap())));
}

#[test]
fn default_routes_never_count_as_reachable() {
    let fp = fingerprint(&home());
    let full = VpnNetworks { prefixes: vec![], dns: vec![] }; // from_config drops 0.0.0.0/0 already
    assert_eq!(decide(fp.as_ref(), &home(), &full), Decision::Reconnect);
    let raw = vpn(&["0.0.0.0/1", "128.0.0.0/1"], &[]);
    assert_eq!(decide(fp.as_ref(), &home(), &raw), Decision::Reconnect);
}

#[test]
fn a_surviving_tunnel_is_flagged_only_where_its_network_is_directly_reachable() {
    let v = vpn(&["10.20.30.0/24", "0.0.0.0/1"], &["10.20.30.53"]);
    // At the office (any gateway, any MAC): the VPN's subnet is the local one.
    let office = snap("10.20.30.1", Some(MAC_B), None, &["10.20.30.0/24"]);
    assert_eq!(surviving_check(&office, &v), Some(Skip::DirectlyReachable(IpPrefix::parse("10.20.30.0/24").unwrap())));
    // Only the DNS server is local.
    let dns_only = snap("10.20.30.1", Some(MAC_B), None, &["10.20.30.0/25"]);
    assert_eq!(
        surviving_check(&dns_only, &vpn(&["172.16.0.0/12"], &["10.20.30.53"])),
        Some(Skip::DnsDirectlyReachable("10.20.30.53".parse().unwrap()))
    );
    // A café: another network, nothing reachable: left alone.
    let cafe = snap("10.0.0.1", Some(MAC_B), Some("Cafe"), &["10.0.0.0/24"]);
    assert_eq!(surviving_check(&cafe, &v), None);
    // No network, or a full tunnel only: nothing to say.
    assert_eq!(surviving_check(&NetworkSnapshot::default(), &v), None);
    assert_eq!(surviving_check(&home(), &vpn(&["0.0.0.0/1", "128.0.0.0/1"], &[])), None);
}

#[test]
fn the_opt_out_list_is_a_preference() {
    let prefs = MemoryPreferences::new();
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    assert!(is_enabled(&prefs, &a));
    set_enabled(&prefs, &b, false);
    set_enabled(&prefs, &a, false);
    assert!(!is_enabled(&prefs, &a) && !is_enabled(&prefs, &b));
    set_enabled(&prefs, &a, true);
    assert!(is_enabled(&prefs, &a) && !is_enabled(&prefs, &b));
}

#[test]
fn a_fingerprint_keeps_only_what_identifies_the_network() {
    assert_eq!(
        fingerprint(&home()),
        Some(Fingerprint { gateway: "192.168.1.1".parse().unwrap(), gateway_mac: MAC_A, ssid: Some("Home".into()) })
    );
}

/// At the office the router is new, but "the VPN's network is directly reachable" is the reason given.
#[test]
fn the_office_on_a_new_router_names_the_reachable_network() {
    let home = NetworkSnapshot {
        gateway: Some(Gateway {
            ip: "192.168.1.1".parse().unwrap(),
            mac: Some([1, 2, 3, 4, 5, 6]),
            interface: "en0".into(),
            ssid: None,
        }),
        connected: vec![IpPrefix::parse("192.168.1.0/24").unwrap()],
    };
    let office = NetworkSnapshot {
        gateway: Some(Gateway {
            ip: "10.20.30.1".parse().unwrap(),
            mac: Some([9, 9, 9, 9, 9, 9]),
            interface: "en0".into(),
            ssid: None,
        }),
        connected: vec![IpPrefix::parse("10.20.30.0/24").unwrap()],
    };
    let fp = macvpn_app_core::reconnect::fingerprint(&home);
    let nets = VpnNetworks { prefixes: vec![IpPrefix::parse("10.20.30.0/24").unwrap()], dns: vec![] };
    assert_eq!(
        decide(fp.as_ref(), &office, &nets),
        Decision::Skip(Skip::DirectlyReachable(IpPrefix::parse("10.20.30.0/24").unwrap()))
    );
}
