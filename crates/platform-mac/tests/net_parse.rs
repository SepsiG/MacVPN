//! The network commands' parsers (`netstat -rn`, `scutil`, `arp -n`, `ndp -n -a`, `ipconfig getsummary`) over scrubbed
//! fixtures (documentation addresses, MACs `a4:2b:b0:…`, SSID `Home`). Nothing here runs a command.
#![cfg(target_os = "macos")]

use macvpn_platform_mac::net_parse::{
    default_routes, gateway_mac, is_tunnel_interface, ndp_mac, router_hardware_address, service_ipv4_keys, ssid,
};
use std::net::IpAddr;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/fixtures/net/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn default_routes_skip_tunnels_and_keep_order() {
    let routes = default_routes(&fixture("netstat-inet.txt"));
    assert_eq!(routes, vec![(ip("192.168.1.1"), "en0".to_string())]);
}

#[test]
fn ipv6_default_routes_drop_the_scope_and_skip_tunnels() {
    let routes = default_routes(&fixture("netstat-inet6.txt"));
    assert_eq!(routes, vec![(ip("fe80::1"), "en0".to_string())]);
}

#[test]
fn an_unscoped_default_route_comes_before_the_interface_scoped_ones() {
    let netstat = "\
Destination        Gateway            Flags               Netif Expire
default            192.168.7.1        UGScIg                en7
default            192.168.1.1        UGScg                 en0
default            192.168.9.1        UGScIg                en9
";
    assert_eq!(
        default_routes(netstat),
        vec![
            (ip("192.168.1.1"), "en0".to_string()),
            (ip("192.168.7.1"), "en7".to_string()),
            (ip("192.168.9.1"), "en9".to_string()),
        ]
    );
}

#[test]
fn malformed_and_empty_tables_give_no_route() {
    assert!(default_routes("").is_empty());
    assert!(default_routes("default\ndefault 192.168.1.1\ndefault not-an-ip UGScg en0\n").is_empty());
}

#[test]
fn tunnel_interfaces_are_recognized() {
    for t in ["utun0", "utun12", "ipsec0", "ppp0", "tun3", "tap1", "gif0", "stf0", "awdl0", "llw0", "bridge100", "lo0"]
    {
        assert!(is_tunnel_interface(t), "{t}");
    }
    for p in ["en0", "en7", "lom0", "utun", "bridge", "tunnel0", ""] {
        assert!(!is_tunnel_interface(p), "{p}");
    }
}

#[test]
fn the_gateway_mac_is_read_and_incomplete_is_none() {
    assert_eq!(gateway_mac(&fixture("arp.txt")), Some([0xa4, 0x2b, 0xb0, 0x00, 0x00, 0x01]));
    assert_eq!(gateway_mac(&fixture("arp-incomplete.txt")), None);
    // macOS prints single-digit octets without the leading zero.
    assert_eq!(
        gateway_mac("? (192.168.1.1) at a4:2b:b0:0:0:1 on en0 ifscope [ethernet]\n"),
        Some([0xa4, 0x2b, 0xb0, 0, 0, 1])
    );
    assert_eq!(gateway_mac("192.168.1.9 (192.168.1.9) -- no entry\n"), None);
    assert_eq!(gateway_mac(""), None);
    assert_eq!(gateway_mac("? (192.168.1.1) at a4:2b:b0:0:0:100 on en0\n"), None);
}

#[test]
fn the_ipv6_gateway_mac_is_read_from_the_neighbour_table_by_address_and_interface() {
    let ndp = fixture("ndp.txt");
    assert_eq!(ndp_mac(&ndp, &ip("fe80::1"), "en0"), Some([0xa4, 0x2b, 0xb0, 0, 0, 1]));
    assert_eq!(ndp_mac(&ndp, &ip("fe80::1"), "en7"), Some([0xa4, 0x2b, 0xb0, 0, 0, 7]));
    assert_eq!(ndp_mac(&ndp, &ip("fe80::9"), "en0"), None);
    assert_eq!(ndp_mac(&ndp, &ip("fe80::2"), "en0"), None);
    assert_eq!(ndp_mac("", &ip("fe80::1"), "en0"), None);
}

#[test]
fn the_ssid_is_read_and_redacted_is_none() {
    assert_eq!(ssid(&fixture("ipconfig-wifi.txt")).as_deref(), Some("Home"));
    assert_eq!(ssid(&fixture("ipconfig-redacted.txt")), None);
    assert_eq!(ssid(""), None);
    assert_eq!(ssid("<dictionary> {\n  SSID : \n}\n"), None);
}

#[test]
fn the_service_ipv4_keys_are_listed() {
    assert_eq!(
        service_ipv4_keys(&fixture("scutil-list.txt")),
        [
            "State:/Network/Service/00000000-0000-0000-0000-000000000007/IPv4",
            "State:/Network/Service/00000000-0000-0000-0000-000000000001/IPv4",
            "State:/Network/Service/00000000-0000-0000-0000-000000000009/IPv4",
        ]
    );
    assert!(service_ipv4_keys("  No such key\n").is_empty());
    // A key with a space or a newline would change the `show` script: never listed.
    assert!(service_ipv4_keys("  subKey [0] = State:/Network/Service/a b/IPv4\n").is_empty());
    assert!(service_ipv4_keys("  subKey [0] = State:/Network/Global/IPv4\n").is_empty());
}

#[test]
fn the_router_mac_is_the_one_the_system_resolved_for_this_gateway_and_interface() {
    let show = fixture("scutil-show.txt");
    assert_eq!(router_hardware_address(&show, &ip("192.168.1.1"), "en0"), Some([0xa4, 0x2b, 0xb0, 0, 0, 1]));
    assert_eq!(router_hardware_address(&show, &ip("192.168.7.1"), "en7"), Some([0xa4, 0x2b, 0xb0, 0, 0, 7]));
    // Another interface or router: not this network's.
    assert_eq!(router_hardware_address(&show, &ip("192.168.1.1"), "en7"), None);
    assert_eq!(router_hardware_address(&show, &ip("192.168.1.9"), "en0"), None);
    // A nested dictionary's `InterfaceName` is not the service's.
    assert_eq!(router_hardware_address(&show, &ip("192.168.1.1"), "en9"), None);
    assert_eq!(router_hardware_address("", &ip("192.168.1.1"), "en0"), None);
    assert_eq!(router_hardware_address("  No such key\n", &ip("192.168.1.1"), "en0"), None);
}
