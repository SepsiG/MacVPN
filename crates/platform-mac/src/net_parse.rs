//! Parsers of the network commands' output (`netstat -rn`, `scutil`, `arp -n`, `ndp -n -a`, `ipconfig getsummary`),
//! pure and fixture-tested. Tunnel interfaces (VPNs, bridges, AWDL, loopback) are never the physical network.

use std::net::IpAddr;

const TUNNEL_PREFIXES: &[&str] = &["utun", "ipsec", "ppp", "tun", "tap", "gif", "stf", "awdl", "llw", "bridge", "lo"];

/// `utun4`, `ipsec0`, `bridge100`, `lo0`, …: a known virtual prefix followed by the unit number only.
pub fn is_tunnel_interface(name: &str) -> bool {
    TUNNEL_PREFIXES
        .iter()
        .any(|p| name.strip_prefix(p).is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())))
}

/// The `default` routes with a gateway address, on physical interfaces: the unscoped routes first (the system's
/// primary one), then the interface-scoped ones (flag `I`), each group in the table's order. The first is used.
pub fn default_routes(netstat: &str) -> Vec<(IpAddr, String)> {
    let mut routes: Vec<(bool, IpAddr, String)> = netstat
        .lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.first() != Some(&"default") || cols.len() < 4 {
                return None;
            }
            // IPv6 gateways carry a scope (`fe80::1%en0`); `link#13` (no gateway address) does not parse.
            let gw: IpAddr = cols[1].split('%').next()?.parse().ok()?;
            let iface = cols[3];
            (!is_tunnel_interface(iface)).then(|| (cols[2].contains('I'), gw, iface.to_string()))
        })
        .collect();
    // Stable: the table's order within each group.
    routes.sort_by_key(|(scoped, _, _)| *scoped);
    routes.into_iter().map(|(_, gw, iface)| (gw, iface)).collect()
}

/// `a4:2b:b0:0:0:1` (macOS leaves out leading zeros) → the six bytes; anything else → `None`.
fn parse_mac(word: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = word.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (slot, part) in mac.iter_mut().zip(parts) {
        if part.is_empty() || part.len() > 2 {
            return None;
        }
        *slot = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

/// The `State:/Network/Service/<id>/IPv4` keys of `scutil`'s `list State:/Network/Service/[^/]+/IPv4`
/// (`  subKey [0] = State:/Network/Service/…/IPv4`). Only keys of that exact shape, whose service ID holds no
/// space or control character, so a key can be written back into a `show` script as is.
pub fn service_ipv4_keys(list: &str) -> Vec<String> {
    list.lines()
        .filter_map(|line| {
            let key = line.split_once(" = ")?.1.trim_end();
            let id = key.strip_prefix("State:/Network/Service/")?.strip_suffix("/IPv4")?;
            let valid = !id.is_empty() && id.bytes().all(|b| b.is_ascii_graphic() && b != b'/');
            valid.then(|| key.to_string())
        })
        .collect()
}

/// The MAC of `gateway` as the system resolved it for the network signature (`ARPResolvedIPAddress` /
/// `ARPResolvedHardwareAddress` of the service whose `InterfaceName` is `interface`), from `scutil`'s `show` of the
/// service IPv4 keys (several dictionaries one after the other). Only the top level of each dictionary counts.
pub fn router_hardware_address(show: &str, gateway: &IpAddr, interface: &str) -> Option<[u8; 6]> {
    let mut depth = 0usize;
    let (mut name, mut router, mut mac): (Option<&str>, Option<&str>, Option<&str>) = (None, None, None);
    for line in show.lines() {
        let trimmed = line.trim();
        if trimmed == "}" {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                let matches =
                    name == Some(interface) && router.and_then(|r| r.parse::<IpAddr>().ok()) == Some(*gateway);
                if let (true, Some(found)) = (matches, mac.and_then(parse_mac)) {
                    return Some(found);
                }
                (name, router, mac) = (None, None, None);
            }
            continue;
        }
        let opens = trimmed.ends_with('{');
        if depth == 1
            && !opens
            && let Some((key, value)) = trimmed.split_once(" : ")
        {
            match key {
                "InterfaceName" => name = Some(value.trim()),
                "ARPResolvedIPAddress" => router = Some(value.trim()),
                "ARPResolvedHardwareAddress" => mac = Some(value.trim()),
                _ => {}
            }
        }
        if opens {
            depth += 1;
        }
    }
    None
}

/// `? (192.168.1.1) at a4:2b:b0:0:0:1 on en0 …`; `(incomplete)` or no entry → `None`.
pub fn gateway_mac(arp: &str) -> Option<[u8; 6]> {
    arp.lines().find_map(|line| {
        let after = line.split(" at ").nth(1)?;
        parse_mac(after.split_whitespace().next()?)
    })
}

/// The link-layer address of `gateway` on `interface` in `ndp -n -a`'s table (`fe80::1%en0  a4:2b:b0:0:0:1  en0 …`);
/// `(incomplete)` or no entry → `None`.
pub fn ndp_mac(ndp: &str, gateway: &IpAddr, interface: &str) -> Option<[u8; 6]> {
    ndp.lines().find_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 || cols[2] != interface {
            return None;
        }
        let neighbour: IpAddr = cols[0].split('%').next()?.parse().ok()?;
        if neighbour != *gateway {
            return None;
        }
        parse_mac(cols[1])
    })
}

/// `  SSID : Home` of `ipconfig getsummary <if>`; `<redacted>` (no location permission) → `None`.
pub fn ssid(summary: &str) -> Option<String> {
    summary
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(" : ")?;
            (key.trim() == "SSID").then(|| value.trim().to_string())
        })
        .filter(|s| !s.is_empty() && s != "<redacted>")
}
