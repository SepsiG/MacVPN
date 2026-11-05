//! Reverse zones and domain overlap for split DNS (root layer 15): which `in-addr.arpa` / `ip6.arpa` zones a routed
//! private network needs on the VPN's DNS (so `ssh 10.1.2.3` shows the internal name), which zones the local network
//! keeps on its own DNS, and the overlap rule between the two (the VPN wins). Pure.

use crate::netaddr::IpPrefix;
use std::net::IpAddr;

/// At most this many match domains (zones) per dynamic-store entry; the rest are dropped (logged by the caller).
pub const MAX_ZONES: usize = 32;
/// A prefix that would need more zones than this at its next octet / nibble boundary is rounded down instead.
const MAX_EXPANSION: u32 = 4;

/// The private, unicast ranges whose reverse zones are worth a resolver entry: RFC 1918, the shared address space
/// (RFC 6598, carrier-grade NAT and many VPNs) and IPv6 unique local addresses. Link-local (`169.254/16`,
/// `fe80::/10`) is left out: mDNS owns those zones and macOS already has resolvers for them.
const PRIVATE: [&str; 5] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"];

/// `p` lies wholly inside a private range (a default route or a public network does not).
pub fn is_private(p: &IpPrefix) -> bool {
    PRIVATE.iter().filter_map(|r| IpPrefix::parse(r)).any(|r| p.len >= r.len && r.contains(&p.addr))
}

/// The reverse zones covering `p`: octet (IPv4) or nibble (IPv6) boundaries; up to 4 zones by expansion, else the
/// zone rounded down; none for a prefix shorter than /8 (IPv4) or /16 (IPv6). Host routes and longer prefixes give
/// their /24 (IPv4) or /64 (IPv6) zone: a zone per host would only fill the resolver list.
pub fn reverse_zones(p: &IpPrefix) -> Vec<String> {
    let (value, width, step, min, max) = match p.addr {
        IpAddr::V4(a) => (u128::from(u32::from(a)), 32u32, 8u32, 8u32, 24u32),
        IpAddr::V6(a) => (u128::from(a), 128, 4, 16, 64),
    };
    let len = u32::from(p.len).min(max);
    if len < min {
        return Vec::new();
    }
    let up = len.div_ceil(step) * step;
    let (zone_len, count) =
        if 1u32 << (up - len) <= MAX_EXPANSION { (up, 1u128 << (up - len)) } else { (len / step * step, 1) };
    let base = value >> (width - zone_len);
    let base = base & !(count - 1);
    (0..count).map(|i| zone_name(base + i, zone_len / step, step, p.addr.is_ipv4())).collect()
}

/// The zone name of the leading `units` octets / nibbles held in the low bits of `bits`.
fn zone_name(bits: u128, units: u32, step: u32, v4: bool) -> String {
    let mask = (1u128 << step) - 1;
    let mut labels: Vec<String> = (0..units)
        .map(|i| {
            let unit = (bits >> (i * step)) & mask;
            if v4 { unit.to_string() } else { format!("{unit:x}") }
        })
        .collect();
    labels.push(if v4 { "in-addr.arpa" } else { "ip6.arpa" }.to_string());
    labels.join(".")
}

fn norm(d: &str) -> String {
    d.trim_end_matches('.').to_ascii_lowercase()
}

/// `domain` equals, or lies under, one of `by` (case-insensitive, trailing dot ignored, label-wise: `example` is
/// not under `corp.example`, `xcorp.example` is not under `corp.example`). The overlap rule: a local domain or zone
/// covered by a VPN domain or zone is dropped; a local *parent* of a VPN domain stays (the longest match already
/// gives the VPN its names).
pub fn covered_by(domain: &str, by: &[String]) -> bool {
    let d = norm(domain);
    by.iter().map(|b| norm(b)).any(|b| !b.is_empty() && (d == b || d.ends_with(&format!(".{b}"))))
}
