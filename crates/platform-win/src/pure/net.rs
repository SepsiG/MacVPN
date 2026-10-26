//! Which adapter is the physical network (pure; the Win32 reads are `macvpn_winsys::net`, composed by `win::net`).

use macvpn_core::netaddr::IpPrefix;
use std::net::IpAddr;

/// What `macvpn_winsys::net::adapters` reads of one adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adapter {
    pub alias: String,
    /// `IF_TYPE_*` (6 Ethernet, 71 Wi-Fi, 23 PPP, 24 loopback, 53 proprietary virtual, 131 tunnel).
    pub if_type: u32,
    pub description: String,
    pub up: bool,
    /// The next hop of this adapter's best default route, if it has one.
    pub gateway: Option<IpAddr>,
    /// The default route's metric plus the interface metric (lower wins).
    pub route_metric: u32,
    pub prefixes: Vec<IpPrefix>,
    pub luid: u64,
    pub guid: [u8; 16],
}

/// PPP, loopback, proprietary virtual (WireGuard, OpenVPN DCO, Wintun), tunnel.
const VIRTUAL_TYPES: &[u32] = &[23, 24, 53, 131];
/// VPN adapters that present themselves as Ethernet (TAP-Windows) or might.
const VPN_DESCRIPTIONS: &[&str] = &["TAP-Windows", "OpenVPN Data Channel Offload", "WireGuard", "Wintun"];

/// Up, and neither a virtual interface type nor a known VPN adapter.
pub fn is_physical(a: &Adapter) -> bool {
    a.up && !VIRTUAL_TYPES.contains(&a.if_type) && !VPN_DESCRIPTIONS.iter().any(|d| a.description.contains(d))
}

/// The physical adapter with the best default route through a real next hop (an on-link default route, `0.0.0.0`
/// or `::`, has none).
pub fn physical_gateway(adapters: &[Adapter]) -> Option<&Adapter> {
    adapters
        .iter()
        .filter(|a| is_physical(a) && a.gateway.is_some_and(|g| !g.is_unspecified()))
        .min_by_key(|a| a.route_metric)
}

/// Wi-Fi adapters (`IF_TYPE_IEEE80211`; the SSID is asked only for them).
pub fn is_wifi(a: &Adapter) -> bool {
    a.if_type == 71
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_link_local(),
        IpAddr::V6(a) => a.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// The subnets of every physical adapter (link-local left out), in adapter order, each once.
pub fn connected(adapters: &[Adapter]) -> Vec<IpPrefix> {
    let mut out: Vec<IpPrefix> = Vec::new();
    for p in adapters.iter().filter(|a| is_physical(a)).flat_map(|a| &a.prefixes) {
        if !is_link_local(&p.addr) && !out.contains(p) {
            out.push(*p);
        }
    }
    out
}
