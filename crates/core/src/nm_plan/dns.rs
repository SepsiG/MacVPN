//! DNS through NetworkManager and systemd-resolved (spec "Linux"): the connection's DNS mode decides the profile's
//! keys, NM and resolved do the rest. Pushed DNS (OpenVPN's `dhcp-option`, PPP, IKEv2 configuration payload) is
//! applied by NM itself; these extras add what the plan knows (the config's domains, the connection's own servers
//! and domains).
//!
//! | Mode | `dns-search` | `dns-priority` |
//! |---|---|---|
//! | Automatic, Full | VPN domains + own domains as `~d` + `~.` | [`DEFAULT_PRIORITY`] |
//! | Strict | VPN domains + own domains as `~d` + `~.` | [`STRICT_PRIORITY`] |
//! | Targeted (split tunnel) | `~d` for every VPN and own domain | [`DEFAULT_PRIORITY`] |
//! | Targeted on a full tunnel | as Automatic | [`DEFAULT_PRIORITY`] |
//!
//! At the default priority the VPN is the only default-route DNS link while the physical links stay at NM's 100,
//! and the local network keeps its own domains. Automatic's fallback after failed probes is a runtime change made
//! by `platform-linux`'s `dns_runtime` (it lowers the physical links' priority). Kinds without the per-connection
//! setting (L2TP, Cisco, IKEv2) pass `None` and keep the plain rule: a full tunnel takes every name at the strict
//! priority, a split tunnel only its domains.

use super::NmValue;
use crate::dns_policy::dedup;
use crate::dns_settings::{DnsMode, DnsSetting, MAX_DOMAINS};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// NM's default priority for VPNs: the VPN takes the default DNS role next to the local network's own domains.
pub const DEFAULT_PRIORITY: i32 = 50;
/// Negative: only this connection's DNS is used while it is up (the local network's domains too).
pub const STRICT_PRIORITY: i32 = -50;

/// The `ipv4` (`v4`) or `ipv6` DNS keys for a tunnel. `full`: the plan knows it is a full tunnel; `domains`: the
/// search domains the config names (a leading `~` is ignored); `dns`: the connection's DNS setting, `None` for the
/// kinds that do not apply it. Merge the result into a section with [`merge_into`].
///
/// ```
/// use macvpn_core::nm_plan::NmValue;
/// use macvpn_core::nm_plan::dns::{STRICT_PRIORITY, section_extras};
/// let keys = section_extras(true, &[], None, true);
/// assert_eq!(keys["dns-search"], NmValue::StrList(vec!["~.".into()]));
/// assert_eq!(keys["dns-priority"], NmValue::I32(STRICT_PRIORITY));
/// ```
pub fn section_extras(full: bool, domains: &[String], dns: Option<&DnsSetting>, v4: bool) -> BTreeMap<String, NmValue> {
    let vpn = dedup(domains.iter().map(|d| d.trim_start_matches('~').to_string()), MAX_DOMAINS);
    let own: &[String] = dns.map_or(&[], |d| &d.domains);
    let names =
        dedup(vpn.iter().cloned().chain(own.iter().map(|d| d.trim_start_matches('~').to_string())), MAX_DOMAINS);
    let match_only = |d: &String| format!("~{d}");

    let (search, priority) = match dns.map(|d| d.mode) {
        None if full => (vpn.iter().cloned().chain(["~.".to_string()]).collect(), STRICT_PRIORITY),
        None => (vpn.iter().map(match_only).collect(), DEFAULT_PRIORITY),
        Some(DnsMode::Targeted) if !full => (names.iter().map(match_only).collect(), DEFAULT_PRIORITY),
        Some(mode) => {
            let (plain, own) = names.split_at(vpn.len().min(names.len()));
            let search: Vec<String> =
                plain.iter().cloned().chain(own.iter().map(match_only)).chain(["~.".to_string()]).collect();
            (search, if mode == DnsMode::Strict { STRICT_PRIORITY } else { DEFAULT_PRIORITY })
        }
    };

    let mut s = BTreeMap::new();
    if !search.is_empty() {
        s.insert("dns-search".into(), NmValue::StrList(search));
    }
    s.insert("dns-priority".into(), NmValue::I32(priority));
    if let Some(d) = dns {
        let servers: Vec<String> =
            d.servers.iter().filter(|s| s.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv4() == v4)).cloned().collect();
        // "Use instead" drops the VPN's DNS only in a family with an own server; the other keeps the VPN's.
        if !servers.is_empty() {
            if d.override_vpn {
                s.insert("ignore-auto-dns".into(), NmValue::Bool(true));
            }
            s.insert("dns-data".into(), NmValue::StrList(servers));
        }
    }
    s
}

/// Merges [`section_extras`] into an `ipv4` / `ipv6` section: the own servers follow the servers the config
/// already names, or replace them with `ignore-auto-dns` ("use instead of the VPN's DNS"); every other key is set.
pub fn merge_into(section: &mut BTreeMap<String, NmValue>, mut extras: BTreeMap<String, NmValue>) {
    let replace = extras.get("ignore-auto-dns") == Some(&NmValue::Bool(true));
    if !replace
        && let (Some(NmValue::StrList(own)), Some(NmValue::StrList(existing))) =
            (extras.get("dns-data"), section.get_mut("dns-data"))
    {
        for server in own {
            if !existing.contains(server) {
                existing.push(server.clone());
            }
        }
        extras.remove("dns-data");
    }
    section.extend(extras);
}
