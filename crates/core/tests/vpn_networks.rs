//! IP prefix arithmetic and the networks a VPN routes (configs and OpenVPN's PUSH_REPLY).

use macvpn_core::models::VPNKind;
use macvpn_core::netaddr::IpPrefix;
use macvpn_core::vpn_networks::VpnNetworks;
use std::net::IpAddr;

fn p(s: &str) -> IpPrefix {
    IpPrefix::parse(s).unwrap_or_else(|| panic!("{s}"))
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn prefixes_parse_and_normalize() {
    assert_eq!(p("10.20.30.7/24"), p("10.20.30.0/24"));
    assert_eq!(p("10.20.30.7"), p("10.20.30.7/32"));
    assert_eq!(p("fd00::1/64"), p("fd00::/64"));
    for bad in ["", "10.20.30.0/33", "fd00::/129", "10.20.30/24", "host.example/24", "10.20.30.0/-1", "10.20.30.0/ 24"]
    {
        assert!(IpPrefix::parse(bad).is_none(), "{bad}");
    }
    assert_eq!(
        IpPrefix::from_mask("10.20.30.0".parse().unwrap(), "255.255.255.0".parse().unwrap()),
        Some(p("10.20.30.0/24"))
    );
    assert_eq!(IpPrefix::from_mask("10.20.30.0".parse().unwrap(), "255.0.255.0".parse().unwrap()), None);
}

#[test]
fn contains_and_overlaps() {
    assert!(p("10.20.30.0/24").contains(&ip("10.20.30.200")));
    assert!(!p("10.20.30.0/24").contains(&ip("10.20.31.1")));
    assert!(!p("10.20.30.0/24").contains(&ip("fd00::1")));
    assert!(p("10.0.0.0/8").overlaps(&p("10.20.30.0/24")));
    assert!(p("10.20.30.0/24").overlaps(&p("10.0.0.0/8")));
    assert!(!p("10.20.30.0/24").overlaps(&p("10.1.6.0/24")));
    assert!(!p("10.20.30.0/24").overlaps(&p("fd00::/8")));
}

#[test]
fn default_routes_are_recognized() {
    for d in ["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "::/0", "::/1", "8000::/1"] {
        assert!(p(d).is_default_route(), "{d}");
    }
    for n in ["10.0.0.0/8", "128.0.0.0/2", "2000::/3"] {
        assert!(!p(n).is_default_route(), "{n}");
    }
}

#[test]
fn openvpn_config_routes_and_dns() {
    let config = "client\nremote vpn.example.com 1194\nroute 10.20.30.0 255.255.255.0\nroute 192.168.50.0 255.255.255.0 vpn_gateway\n\
        route 172.16.0.1\nroute intranet.example 255.255.255.0\nroute-ipv6 fd00:5::/64\nredirect-gateway def1\n\
        dhcp-option DNS 10.20.30.53\ndhcp-option DNS6 fd00:5::53\ndhcp-option DOMAIN office.example\ndns server 1 address 10.20.30.54\n";
    let n = VpnNetworks::from_config(VPNKind::Openvpn, config);
    assert_eq!(n.prefixes, vec![p("10.20.30.0/24"), p("192.168.50.0/24"), p("172.16.0.1/32"), p("fd00:5::/64")]);
    assert_eq!(n.dns, vec![ip("10.20.30.53"), ip("fd00:5::53"), ip("10.20.30.54")]);
}

#[test]
fn wireguard_allowed_ips_without_default_routes() {
    let config = "[Interface]\nPrivateKey = x\nAddress = 10.8.0.2/32\nDNS = 10.20.30.53, office.example\n\
        [Peer]\nPublicKey = y\nAllowedIPs = 10.20.30.0/24, 0.0.0.0/0, ::/0\nEndpoint = vpn.example.com:51820\n";
    let n = VpnNetworks::from_config(VPNKind::Wireguard, config);
    assert_eq!(n.prefixes, vec![p("10.20.30.0/24")]);
    assert_eq!(n.dns, vec![ip("10.20.30.53")]);
}

#[test]
fn other_kinds_route_nothing_known() {
    assert!(VpnNetworks::from_config(VPNKind::Strongswan, "connections { }").is_empty());
    assert!(VpnNetworks::from_config(VPNKind::Sstp, "server=vpn.example.com").is_empty());
}

#[test]
fn pushed_options_come_from_the_push_reply_line() {
    let lines = vec![
        "2026-10-24 10:00:00 PUSH: Received control message: 'PUSH_REPLY,route 10.20.30.0 255.255.255.0,route-gateway 10.8.0.1,dhcp-option DNS 10.20.30.53,route-ipv6 fd00:5::/64,ifconfig 10.8.0.6 255.255.255.0,peer-id 0'".to_string(),
        "2026-10-24 10:00:00 some other line route 1.2.3.0 255.255.255.0".to_string(),
    ];
    let mut n = VpnNetworks::default();
    n.add_pushed(&lines);
    assert_eq!(n.prefixes, vec![p("10.20.30.0/24"), p("fd00:5::/64")]);
    assert_eq!(n.dns, vec![ip("10.20.30.53")]);
}

#[test]
fn duplicates_are_kept_once() {
    let mut n = VpnNetworks::from_config(VPNKind::Openvpn, "route 10.20.30.0 255.255.255.0\n");
    n.add_pushed(&["PUSH: Received control message: 'PUSH_REPLY,route 10.20.30.0 255.255.255.0'".to_string()]);
    assert_eq!(n.prefixes, vec![p("10.20.30.0/24")]);
}
