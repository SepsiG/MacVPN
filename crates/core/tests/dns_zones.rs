//! Reverse zones and the domain overlap rule for split DNS (root layer 15).
use macvpn_core::dns_zones::{covered_by, is_private, reverse_zones};
use macvpn_core::netaddr::IpPrefix;

fn zones(p: &str) -> Vec<String> {
    reverse_zones(&IpPrefix::parse(p).unwrap())
}

fn private(p: &str) -> bool {
    is_private(&IpPrefix::parse(p).unwrap())
}

#[test]
fn v4_octet_boundaries() {
    assert_eq!(zones("10.0.0.0/8"), ["10.in-addr.arpa"]);
    assert_eq!(zones("192.168.50.0/24"), ["50.168.192.in-addr.arpa"]);
    assert_eq!(zones("172.20.0.0/16"), ["20.172.in-addr.arpa"]);
}

#[test]
fn v4_small_expansion() {
    assert_eq!(zones("10.1.2.0/23"), ["2.1.10.in-addr.arpa", "3.1.10.in-addr.arpa"]);
    assert_eq!(
        zones("10.1.4.0/22"),
        ["4.1.10.in-addr.arpa", "5.1.10.in-addr.arpa", "6.1.10.in-addr.arpa", "7.1.10.in-addr.arpa"]
    );
}

#[test]
fn v4_large_rounds_down() {
    assert_eq!(zones("172.16.0.0/12"), ["172.in-addr.arpa"]);
    assert_eq!(zones("10.0.0.0/21"), ["0.10.in-addr.arpa"]);
}

#[test]
fn host_routes_give_the_24() {
    assert_eq!(zones("10.1.2.3/32"), ["2.1.10.in-addr.arpa"]);
    assert_eq!(zones("10.1.2.128/25"), ["2.1.10.in-addr.arpa"]);
}

#[test]
fn v6_nibbles() {
    assert_eq!(zones("fd00:1234::/32"), ["4.3.2.1.0.0.d.f.ip6.arpa"]);
    assert_eq!(zones("fd00:1234::/31"), ["4.3.2.1.0.0.d.f.ip6.arpa", "5.3.2.1.0.0.d.f.ip6.arpa"]);
    assert_eq!(zones("fd00::1/128").len(), 1, "a host route gives its /64 zone");
    assert!(zones("fd00::1/128")[0].starts_with("0.0.0.0.0.0.0.0."));
}

#[test]
fn too_short_gives_nothing() {
    assert!(zones("0.0.0.0/0").is_empty());
    assert!(zones("10.0.0.0/7").is_empty());
    assert!(zones("fc00::/7").is_empty());
}

#[test]
fn default_and_public_are_skipped() {
    for p in
        ["10.0.0.0/8", "10.1.0.0/16", "172.16.0.0/12", "172.31.1.0/24", "192.168.0.0/16", "100.64.0.0/10", "fd00::/8"]
    {
        assert!(private(p), "{p}");
    }
    for p in
        ["0.0.0.0/0", "0.0.0.0/1", "8.8.8.0/24", "172.32.0.0/16", "10.0.0.0/7", "169.254.0.0/16", "fe80::/10", "::/0"]
    {
        assert!(!private(p), "{p}");
    }
}

#[test]
fn covered_by_is_label_wise() {
    let vpn = vec!["corp.example".to_string(), "lan".to_string()];
    assert!(covered_by("lan", &vpn));
    assert!(covered_by("LAN.", &vpn));
    assert!(covered_by("x.corp.example", &vpn));
    assert!(!covered_by("example", &vpn), "a parent stays");
    assert!(!covered_by("xcorp.example", &vpn));
    assert!(covered_by("2.1.10.in-addr.arpa", &["10.in-addr.arpa".to_string()]));
    assert!(!covered_by("10.in-addr.arpa", &["2.1.10.in-addr.arpa".to_string()]));
}
