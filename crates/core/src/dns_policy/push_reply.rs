//! OpenVPN's `PUSH_REPLY` read for its DNS: the line OpenVPN prints at verb 3 (`PUSH: Received control message:
//! 'PUSH_REPLY,…'`) holds every pushed option, including the domains the VPN adapter itself cannot carry
//! (`dhcp-option DOMAIN-SEARCH`, `dns … resolve-domains`). WinVPN reads it from OpenVPN's output, together with
//! the push's `redirect-gateway` (a full tunnel) and `ifconfig` (the tunnel's address, which finds its adapter).

use super::{Pushed, dedup};
use crate::dns_settings::{MAX_DOMAINS, MAX_SERVERS, is_dns_domain, is_dns_server, normalize_domain};
use crate::dns_zones::MAX_ZONES;
use crate::netaddr::IpPrefix;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const PUSH_MARK: &str = "PUSH_REPLY,";

/// What WinVPN reads of a connection's push: its DNS and routes, whether it takes the default route, and the
/// tunnel's own address (which finds the VPN adapter).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Push {
    /// The DNS servers, search and resolve domains, and routed networks.
    pub dns: Pushed,
    /// `redirect-gateway` without `!ipv4` (the config's own routing reads it the same way): a full tunnel.
    pub redirect_gateway: bool,
    /// The tunnel's address: `ifconfig <local> …`, else `ifconfig-ipv6 <local>/<len> …`.
    pub local: Option<IpAddr>,
    /// `push-continuation 2`: more `PUSH_REPLY` messages of the same push follow.
    pub continues: bool,
}

impl Push {
    /// The push of one `PUSH_REPLY` line; `None` for any other line. Invalid servers and domains are dropped,
    /// duplicates kept once, the lists capped.
    ///
    /// ```
    /// use macvpn_core::dns_policy::push_reply::Push;
    /// let p = Push::from_line("PUSH: Received control message: 'PUSH_REPLY,redirect-gateway def1,ping 10'").unwrap();
    /// assert!(p.redirect_gateway);
    /// ```
    pub fn from_line(line: &str) -> Option<Push> {
        let start = line.find(PUSH_MARK)? + PUSH_MARK.len();
        let rest = &line[start..];
        let rest = rest.split('\'').next().unwrap_or(rest);
        let (mut servers, mut search, mut resolve) = (Vec::new(), Vec::new(), Vec::new());
        let mut routes = Vec::new();
        let (mut redirect_gateway, mut local4, mut local6, mut continues) = (false, None, None, false);
        for option in rest.split(',') {
            let words: Vec<&str> = option.split_whitespace().collect();
            match words.as_slice() {
                ["dhcp-option", "DNS" | "DNS6", ip, ..] => servers.push(*ip),
                ["dhcp-option", "DOMAIN" | "DOMAIN-SEARCH", d, ..] => search.push(*d),
                ["dns", "server", _, "address", ips @ ..] => servers.extend(ips.iter().map(|ip| server_address(ip))),
                ["dns", "server", _, "resolve-domains", ds @ ..] => resolve.extend(ds),
                ["dns", "search-domains", ds @ ..] => search.extend(ds),
                ["route", net, mask, ..] => {
                    if let (Ok(net), Ok(mask)) = (net.parse::<Ipv4Addr>(), mask.parse::<Ipv4Addr>())
                        && let Some(p) = IpPrefix::from_mask(net, mask)
                    {
                        routes.push(p);
                    }
                }
                ["route-ipv6", prefix, ..] => routes.extend(IpPrefix::parse(prefix)),
                ["redirect-gateway", flags @ ..] => redirect_gateway |= !flags.contains(&"!ipv4"),
                ["push-continuation", n] => continues = *n == "2",
                ["ifconfig", ip, ..] => local4 = local4.or(ip.parse::<Ipv4Addr>().ok().map(IpAddr::V4)),
                ["ifconfig-ipv6", prefix, ..] => {
                    local6 =
                        local6.or(prefix.split('/').next().and_then(|a| a.parse::<Ipv6Addr>().ok()).map(IpAddr::V6))
                }
                _ => {}
            }
        }
        let servers = dedup(servers.into_iter().filter(|s| is_dns_server(s)).map(str::to_string), MAX_SERVERS);
        let domains =
            |ds: Vec<&str>| dedup(ds.into_iter().map(normalize_domain).filter(|d| is_dns_domain(d)), MAX_DOMAINS);
        let dns = Pushed { servers, search: domains(search), resolve: domains(resolve), routes };
        Some(Push { dns, redirect_gateway, local: local4.or(local6), continues })
    }

    /// Folds in the next `PUSH_REPLY` of the same push (OpenVPN splits a long one, `push-continuation`): the lists
    /// joined (each item once, capped), a full tunnel if either says so, the first tunnel address; it continues as
    /// the newer one says.
    pub fn merge(&mut self, more: Push) {
        let d = &mut self.dns;
        d.servers = dedup(d.servers.drain(..).chain(more.dns.servers), MAX_SERVERS);
        d.search = dedup(d.search.drain(..).chain(more.dns.search), MAX_DOMAINS);
        d.resolve = dedup(d.resolve.drain(..).chain(more.dns.resolve), MAX_DOMAINS);
        for r in more.dns.routes {
            if !d.routes.contains(&r) && d.routes.len() < MAX_ROUTES {
                d.routes.push(r);
            }
        }
        self.redirect_gateway |= more.redirect_gateway;
        self.local = self.local.or(more.local);
        self.continues = more.continues;
    }
}

/// At most this many routes are kept from a merged push (only their reverse zones are used, at most
/// [`MAX_ZONES`] of them).
const MAX_ROUTES: usize = 4 * MAX_ZONES;

/// The DNS servers, search and resolve domains and routed networks of a `PUSH_REPLY` line; `None` for any other
/// line ([`Push::from_line`]'s DNS part).
///
/// ```
/// use macvpn_core::dns_policy::push_reply::parse_push_reply;
/// let p = parse_push_reply("PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.0.0.53,ping 10'").unwrap();
/// assert_eq!(p.servers, ["10.0.0.53"]);
/// ```
pub fn parse_push_reply(line: &str) -> Option<Pushed> {
    Push::from_line(line).map(|p| p.dns)
}

/// The address of `dns server <n> address <ip>[:port]` (OpenVPN 2.6): the port dropped, an IPv6 bracket removed.
pub(crate) fn server_address(word: &str) -> &str {
    let ip = word.trim_start_matches('[').split(']').next().unwrap_or(word);
    if ip.matches(':').count() == 1 { ip.split(':').next().unwrap_or(ip) } else { ip }
}
