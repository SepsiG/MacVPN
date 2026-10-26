//! `NetworkProbe` for macOS: commands through the crate's `CommandRunner` (each with its timeout) plus
//! `getifaddrs` for the connected subnets. Read-only, and nothing is sent to the network: `netstat -rn`, `scutil`
//! (`list` / `show` of the dynamic store), `arp -n <ip>`, `ndp -n -a` and `ipconfig getsummary <if>` only read the
//! system's tables.
//!
//! The gateway's MAC comes first from the dynamic store (`ARPResolvedHardwareAddress` of the interface's IPv4
//! service: the router MAC the system resolved for its network signature), then from the ARP cache. The ARP table
//! is not enough on its own: macOS 15's local network privacy hides its entries from a process without the
//! permission, and asking for it (or sending to the gateway to fill the cache) would show a permission prompt.
//! The SSID comes from `ipconfig`, which never asks for the location permission; without it the SSID is
//! `<redacted>`, read as unknown.
//!
//! A command that fails or times out reads as empty output: no default route is "no network" (the reconnect
//! waits), no MAC is "unidentified" (it does not reconnect).

use crate::command::CommandRunner;
use crate::net_parse;
use macvpn_core::netaddr::IpPrefix;
use macvpn_platform_api::{Gateway, NetworkSnapshot, PlatformError};
use std::net::IpAddr;

const SCUTIL: &str = "/usr/sbin/scutil";

pub struct MacNetworkProbe<R: CommandRunner> {
    runner: R,
}

impl<R: CommandRunner> MacNetworkProbe<R> {
    pub fn new(runner: R) -> Self {
        MacNetworkProbe { runner }
    }

    pub fn runner(&self) -> &R {
        &self.runner
    }

    fn run(&self, executable: &str, arguments: &[&str], stdin: Option<&str>) -> String {
        let arguments: Vec<String> = arguments.iter().map(|a| a.to_string()).collect();
        self.runner.run(executable, &arguments, stdin).map(|r| r.stdout).unwrap_or_default()
    }

    /// The default gateway of the physical network (tunnel routes left out): IPv4 first, IPv6 when there is no
    /// IPv4 default route.
    pub fn gateway(&self) -> Option<Gateway> {
        let mut routes = net_parse::default_routes(&self.run("/usr/sbin/netstat", &["-rn", "-f", "inet"], None));
        if routes.is_empty() {
            routes = net_parse::default_routes(&self.run("/usr/sbin/netstat", &["-rn", "-f", "inet6"], None));
        }
        let (ip, interface) = routes.into_iter().next()?;
        let mac = match ip {
            IpAddr::V4(_) => self
                .resolved_router_mac(&ip, &interface)
                .or_else(|| net_parse::gateway_mac(&self.run("/usr/sbin/arp", &["-n", &ip.to_string()], None))),
            // The default router is in the neighbour cache (router advertisements keep it there).
            IpAddr::V6(_) => net_parse::ndp_mac(&self.run("/usr/sbin/ndp", &["-n", "-a"], None), &ip, &interface),
        };
        let ssid = net_parse::ssid(&self.run("/usr/sbin/ipconfig", &["getsummary", &interface], None));
        Some(Gateway { ip, mac, interface, ssid })
    }

    /// The dynamic store's `ARPResolvedHardwareAddress` of the IPv4 service on `interface` whose resolved router is
    /// `gateway`.
    fn resolved_router_mac(&self, gateway: &IpAddr, interface: &str) -> Option<[u8; 6]> {
        let keys =
            net_parse::service_ipv4_keys(&self.run(SCUTIL, &[], Some("list State:/Network/Service/[^/]+/IPv4\n")));
        if keys.is_empty() {
            return None;
        }
        let script: String = keys.iter().map(|k| format!("show {k}\n")).collect();
        net_parse::router_hardware_address(&self.run(SCUTIL, &[], Some(&script)), gateway, interface)
    }

    pub fn snapshot(&self) -> Result<NetworkSnapshot, PlatformError> {
        Ok(NetworkSnapshot { gateway: self.gateway(), connected: connected_prefixes() })
    }
}

/// The subnets of up, physical interfaces (`getifaddrs`; loopback, link-local and tunnels left out).
pub fn connected_prefixes() -> Vec<IpPrefix> {
    physical_prefixes(crate::sys::interface_prefixes())
}

/// [`connected_prefixes`]' filter over `(interface, prefix)` pairs, sorted and without duplicates.
pub fn physical_prefixes(all: Vec<(String, IpPrefix)>) -> Vec<IpPrefix> {
    let mut prefixes: Vec<IpPrefix> = all
        .into_iter()
        .filter(|(name, _)| !net_parse::is_tunnel_interface(name))
        .map(|(_, p)| p)
        .filter(|p| p.len > 0 && !is_link_local(p) && !is_loopback(p))
        .collect();
    prefixes.sort();
    prefixes.dedup();
    prefixes
}

fn is_link_local(p: &IpPrefix) -> bool {
    match p.addr {
        IpAddr::V4(a) => a.is_link_local(),
        IpAddr::V6(a) => (a.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn is_loopback(p: &IpPrefix) -> bool {
    p.addr.is_loopback()
}
