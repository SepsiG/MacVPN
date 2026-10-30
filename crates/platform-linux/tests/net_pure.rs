//! The network probe's pure parts (every OS): `/proc/net/arp`, the physical device's choice, the SSID's text.

use macvpn_core::netaddr::IpPrefix;
use macvpn_platform_linux::pure::net::{
    DEVICE_STATE_ACTIVATED, DEVICE_TYPE_ETHERNET, DEVICE_TYPE_WIFI, Device, arp_mac, choose, is_physical, ssid_text,
};
use std::net::IpAddr;

const ARP: &str = "IP address       HW type     Flags       HW address            Mask     Device\n\
192.0.2.1        0x1         0x2         52:54:00:12:34:56     *        enp1s0\n\
198.51.100.1     0x1         0x0         00:00:00:00:00:00     *        wlp2s0\n\
198.51.100.7     0x1         0x2         00:00:00:00:00:00     *        wlp2s0\n";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn dev(interface: &str, device_type: u32, gateway: Option<&str>, metric: Option<u32>, addrs: &[(&str, u8)]) -> Device {
    Device {
        interface: interface.to_string(),
        device_type,
        state: DEVICE_STATE_ACTIVATED,
        gateway: gateway.map(ip),
        default_metric: metric,
        addresses: addrs.iter().map(|(a, l)| (ip(a), *l)).collect(),
    }
}

fn prefix(s: &str) -> IpPrefix {
    IpPrefix::parse(s).unwrap()
}

#[test]
fn the_gateway_mac_comes_from_a_complete_arp_entry() {
    assert_eq!(arp_mac(ARP, "192.0.2.1"), Some([0x52, 0x54, 0, 0x12, 0x34, 0x56]));
    assert_eq!(arp_mac(ARP, "198.51.100.1"), None, "incomplete (flags 0x0)");
    assert_eq!(arp_mac(ARP, "198.51.100.7"), None, "an all-zero address is no address");
    assert_eq!(arp_mac(ARP, "192.0.2.10"), None, "not in the table");
    assert_eq!(arp_mac(ARP, "192.0.2"), None, "a prefix of an address is not the address");
    assert_eq!(arp_mac("", "192.0.2.1"), None);
    assert_eq!(
        arp_mac("IP address HW type Flags HW address Mask Device\n192.0.2.1 0x1 0x2 52:54:00:12:34 * e\n", "192.0.2.1"),
        None
    );
}

#[test]
fn the_activated_physical_device_with_a_gateway_and_the_lowest_metric_wins() {
    let devices = [
        dev("wlp2s0", DEVICE_TYPE_WIFI, Some("198.51.100.1"), Some(600), &[("198.51.100.20", 24)]),
        dev("enp1s0", DEVICE_TYPE_ETHERNET, Some("192.0.2.1"), Some(100), &[("192.0.2.10", 24)]),
    ];
    let choice = choose(&devices);
    assert_eq!(choice.gateway.map(|d| d.interface.as_str()), Some("enp1s0"));
    assert_eq!(choice.connected, vec![prefix("198.51.100.0/24"), prefix("192.0.2.0/24")]);
}

#[test]
fn a_device_that_is_not_activated_is_not_the_network() {
    let mut eth = dev("enp1s0", DEVICE_TYPE_ETHERNET, Some("192.0.2.1"), Some(100), &[("192.0.2.10", 24)]);
    eth.state = 30; // disconnected
    let choice = choose(std::slice::from_ref(&eth));
    assert!(choice.gateway.is_none());
    assert!(choice.connected.is_empty());
}

#[test]
fn a_full_tunnel_vpn_never_changes_the_choice() {
    // NM's primary connection is the VPN (its default route has the lower metric), on its own tun/WireGuard device.
    let devices = [
        dev("tun0", 16, Some("10.99.11.1"), Some(50), &[("10.99.11.6", 24)]),
        dev("linvpn-wg0", 29, Some("10.99.13.1"), Some(50), &[("10.99.13.5", 32)]),
        dev("br-vpn", 13, Some("10.99.14.1"), Some(10), &[("10.99.14.2", 24)]),
        dev("enp1s0", DEVICE_TYPE_ETHERNET, Some("192.0.2.1"), Some(100), &[("192.0.2.10", 24)]),
    ];
    let choice = choose(&devices);
    assert_eq!(choice.gateway.map(|d| d.interface.as_str()), Some("enp1s0"));
    assert_eq!(choice.connected, vec![prefix("192.0.2.0/24")], "no tunnel subnet is a connected one");
    assert!(!is_physical(16) && !is_physical(29) && !is_physical(13) && !is_physical(14));
    assert!(is_physical(DEVICE_TYPE_ETHERNET) && is_physical(DEVICE_TYPE_WIFI));
}

#[test]
fn a_device_without_a_gateway_contributes_only_its_subnets() {
    let devices = [
        dev("enp7s0", DEVICE_TYPE_ETHERNET, None, None, &[("203.0.113.5", 25)]),
        dev("enp1s0", DEVICE_TYPE_ETHERNET, Some("0.0.0.0"), Some(10), &[("192.0.2.10", 24)]),
    ];
    let choice = choose(&devices);
    assert!(choice.gateway.is_none(), "an unspecified next hop is no gateway");
    assert_eq!(choice.connected, vec![prefix("203.0.113.0/25"), prefix("192.0.2.0/24")]);
}

#[test]
fn a_gateway_without_a_default_route_metric_loses_to_one_with_it() {
    let devices = [
        dev("enp7s0", DEVICE_TYPE_ETHERNET, Some("203.0.113.1"), None, &[("203.0.113.5", 25)]),
        dev("enp1s0", DEVICE_TYPE_ETHERNET, Some("192.0.2.1"), Some(20100), &[("192.0.2.10", 24)]),
    ];
    assert_eq!(choose(&devices).gateway.map(|d| d.interface.as_str()), Some("enp1s0"));
}

#[test]
fn link_local_is_never_a_connected_subnet_and_each_subnet_counts_once() {
    let devices = [
        dev(
            "enp1s0",
            DEVICE_TYPE_ETHERNET,
            Some("192.0.2.1"),
            Some(100),
            &[("169.254.3.4", 16), ("fe80::1", 64), ("192.0.2.10", 24), ("192.0.2.11", 24), ("2001:db8::10", 64)],
        ),
        dev("enp2s0", DEVICE_TYPE_ETHERNET, None, None, &[("fe80::2", 64), ("192.0.2.12", 24)]),
    ];
    assert_eq!(choose(&devices).connected, vec![prefix("192.0.2.0/24"), prefix("2001:db8::/64")]);
}

#[test]
fn the_ssid_is_lossy_utf8_without_control_characters() {
    assert_eq!(ssid_text(b"Office"), Some("Office".to_string()));
    assert_eq!(ssid_text("Kávé-Wi-Fi".as_bytes()), Some("Kávé-Wi-Fi".to_string()));
    assert_eq!(ssid_text(b"Caf\xe9\n\x1b[31m\x00"), Some("Caf\u{fffd}[31m".to_string()));
    assert_eq!(ssid_text(b""), None, "a hidden network has no name");
    assert_eq!(ssid_text(b"\x00\x00"), None);
}
