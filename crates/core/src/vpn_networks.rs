//! The networks a VPN routes and its DNS servers, for the auto-reconnect check "is the VPN's network directly
//! reachable here?": from the stored config (OpenVPN, WireGuard) and from OpenVPN's PUSH_REPLY in the connection's
//! log. Default routes are left out (a full tunnel overlaps every network). Other kinds give nothing.

use crate::models::VPNKind;
use crate::netaddr::IpPrefix;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VpnNetworks {
    pub prefixes: Vec<IpPrefix>,
    pub dns: Vec<IpAddr>,
}

const PUSH_MARK: &str = "PUSH_REPLY,";

impl VpnNetworks {
    pub fn from_config(kind: VPNKind, config: &str) -> VpnNetworks {
        let mut n = VpnNetworks::default();
        match kind {
            VPNKind::Openvpn => {
                for line in config.lines() {
                    n.openvpn_option(line.trim());
                }
            }
            VPNKind::Wireguard => n.wireguard(config),
            _ => {}
        }
        n
    }

    pub fn is_empty(&self) -> bool {
        self.prefixes.is_empty() && self.dns.is_empty()
    }

    /// OpenVPN's pushed options, from the log lines of the current session (the last PUSH_REPLY wins nothing:
    /// every one adds, duplicates are kept once).
    pub fn add_pushed(&mut self, lines: &[String]) {
        for line in lines {
            let Some(start) = line.find(PUSH_MARK) else { continue };
            let rest = &line[start + PUSH_MARK.len()..];
            let rest = rest.split('\'').next().unwrap_or(rest);
            for option in rest.split(',') {
                self.openvpn_option(option.trim());
            }
        }
    }

    fn add_prefix(&mut self, prefix: Option<IpPrefix>) {
        if let Some(p) = prefix
            && !p.is_default_route()
            && !self.prefixes.contains(&p)
        {
            self.prefixes.push(p);
        }
    }

    fn add_dns(&mut self, ip: Option<IpAddr>) {
        if let Some(ip) = ip
            && !self.dns.contains(&ip)
        {
            self.dns.push(ip);
        }
    }

    fn openvpn_option(&mut self, line: &str) {
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["route", net, rest @ ..] => {
                let Ok(net) = net.parse::<Ipv4Addr>() else { return };
                let netmask = rest.first().and_then(|m| m.parse::<Ipv4Addr>().ok()).unwrap_or(Ipv4Addr::BROADCAST);
                self.add_prefix(IpPrefix::from_mask(net, netmask));
            }
            ["route-ipv6", prefix, ..] => self.add_prefix(IpPrefix::parse(prefix)),
            ["dhcp-option", "DNS" | "DNS6", ip, ..] => self.add_dns(ip.parse().ok()),
            ["dns", "server", _, "address", ip, ..] => {
                // `dns server <n> address <ip>[:port]` (OpenVPN 2.6); IPv6 may be bracketed.
                let ip = ip.trim_start_matches('[').split(']').next().unwrap_or(ip);
                let ip = if ip.matches(':').count() == 1 { ip.split(':').next().unwrap_or(ip) } else { ip };
                self.add_dns(ip.parse().ok());
            }
            _ => {}
        }
    }

    fn wireguard(&mut self, config: &str) {
        for line in config.lines() {
            let Some((key, value)) = line.split_once('=') else { continue };
            let key = key.trim().to_ascii_lowercase();
            let values = value.split(',').map(str::trim).filter(|v| !v.is_empty());
            match key.as_str() {
                "allowedips" => values.for_each(|v| self.add_prefix(IpPrefix::parse(v))),
                // Non-addresses in DNS are search domains.
                "dns" => values.for_each(|v| self.add_dns(v.parse().ok())),
                _ => {}
            }
        }
    }
}
