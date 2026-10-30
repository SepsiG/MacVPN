//! The network probe's pure parts: /proc/net/arp, the physical device's choice (Task 16).
//!
//! The physical network is what NetworkManager's ethernet and Wi-Fi devices carry. A VPN never counts, whatever NM's
//! primary connection is: tun (16), WireGuard (29), PPP (14), bridges (13), veth, loopback and every other device type
//! are left out by type, so LinVPN's own tunnels are never the gateway or a connected subnet.

use macvpn_core::netaddr::IpPrefix;
use std::net::IpAddr;

/// `NM_DEVICE_TYPE_ETHERNET`.
pub const DEVICE_TYPE_ETHERNET: u32 = 1;
/// `NM_DEVICE_TYPE_WIFI`.
pub const DEVICE_TYPE_WIFI: u32 = 2;
/// `NM_DEVICE_STATE_ACTIVATED`.
pub const DEVICE_STATE_ACTIVATED: u32 = 100;

/// What the probe reads of one NetworkManager device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// `Interface` (`enp1s0`, `wlp2s0`).
    pub interface: String,
    /// `DeviceType` (`NMDeviceType`).
    pub device_type: u32,
    /// `State` (`NMDeviceState`).
    pub state: u32,
    /// The `Gateway` of its `Ip4Config` (else of its `Ip6Config`); `0.0.0.0`/`::` counts as none.
    pub gateway: Option<IpAddr>,
    /// The metric of its default route of the gateway's family (`RouteData`), if NM lists one.
    pub default_metric: Option<u32>,
    /// The addresses of its `Ip4Config` and `Ip6Config` (`AddressData`) with their prefix lengths.
    pub addresses: Vec<(IpAddr, u8)>,
}

/// The probe's decision: the device whose gateway is the network's, and the connected subnets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice<'a> {
    pub gateway: Option<&'a Device>,
    pub connected: Vec<IpPrefix>,
}

/// Ethernet or Wi-Fi: the only device types that are the physical network.
pub fn is_physical(device_type: u32) -> bool {
    device_type == DEVICE_TYPE_ETHERNET || device_type == DEVICE_TYPE_WIFI
}

fn is_up_physical(d: &Device) -> bool {
    is_physical(d.device_type) && d.state == DEVICE_STATE_ACTIVATED
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_link_local(),
        IpAddr::V6(a) => a.segments()[0] & 0xffc0 == 0xfe80,
    }
}

/// The activated physical device with a real next hop and the lowest default-route metric (a device whose default
/// route NM does not list comes last), and the subnets of every activated physical device (link-local and loopback
/// left out), in device order, each once.
pub fn choose(devices: &[Device]) -> Choice<'_> {
    let gateway = devices
        .iter()
        .filter(|d| is_up_physical(d) && d.gateway.is_some_and(|g| !g.is_unspecified()))
        .min_by_key(|d| (d.default_metric.is_none(), d.default_metric.unwrap_or(u32::MAX)));
    let mut connected: Vec<IpPrefix> = Vec::new();
    for (addr, len) in devices.iter().filter(|d| is_up_physical(d)).flat_map(|d| &d.addresses) {
        if is_link_local(addr) || addr.is_loopback() || addr.is_unspecified() {
            continue;
        }
        if let Some(p) = IpPrefix::new(*addr, *len)
            && !connected.contains(&p)
        {
            connected.push(p);
        }
    }
    Choice { gateway, connected }
}

/// `ATF_COM`: the entry is complete (the MAC is known).
const ATF_COM: u32 = 0x2;

fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = text.split(':');
    for byte in &mut mac {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    if parts.next().is_some() || mac == [0; 6] {
        return None;
    }
    Some(mac)
}

/// The MAC of `ip` in `/proc/net/arp`'s text: only a complete entry (`Flags` has `ATF_COM`) with a non-zero address.
pub fn arp_mac(table: &str, ip: &str) -> Option<[u8; 6]> {
    table.lines().skip(1).find_map(|line| {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 || cols[0] != ip {
            return None;
        }
        let flags = u32::from_str_radix(cols[2].trim_start_matches("0x"), 16).ok()?;
        if flags & ATF_COM == 0 {
            return None;
        }
        parse_mac(cols[3])
    })
}

/// An access point's `Ssid` bytes as text: lossy UTF-8, control characters removed; `None` when nothing is left (a
/// hidden network).
pub fn ssid_text(raw: &[u8]) -> Option<String> {
    let text: String = String::from_utf8_lossy(raw).chars().filter(|c| !c.is_control()).collect();
    (!text.is_empty()).then_some(text)
}
