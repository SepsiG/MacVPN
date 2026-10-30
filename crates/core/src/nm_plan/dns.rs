//! DNS through NetworkManager and systemd-resolved (spec 4 "DNS"): LinVPN has no DNS manager. A split tunnel uses
//! the connection's DNS only for its domains (routing-only `~domain` entries); a full tunnel takes every query
//! (`~.`) with a negative priority (resolved then asks only this link). Pushed DNS (OpenVPN's `dhcp-option`, PPP,
//! IKEv2 configuration payload) is applied by NM itself; these extras only add what the plan knows.

use super::NmValue;
use std::collections::BTreeMap;

/// NM's default priority for VPNs is 50; a split tunnel keeps it.
pub const SPLIT_PRIORITY: i32 = 50;
/// Negative: only this connection's DNS is used while it is up.
pub const FULL_PRIORITY: i32 = -50;

/// The `ipv4` / `ipv6` DNS keys for a tunnel. `full`: the plan knows it is a full tunnel; `domains`: the search
/// domains the config names (without a leading `~`).
pub fn section_extras(full: bool, domains: &[String]) -> BTreeMap<String, NmValue> {
    let mut s = BTreeMap::new();
    let mut search: Vec<String> = if full {
        domains.iter().map(|d| d.trim_start_matches('~').to_string()).collect()
    } else {
        domains.iter().map(|d| format!("~{}", d.trim_start_matches('~'))).collect()
    };
    if full {
        search.push("~.".into());
    }
    if !search.is_empty() {
        s.insert("dns-search".into(), NmValue::StrList(search));
    }
    s.insert("dns-priority".into(), NmValue::I32(if full { FULL_PRIORITY } else { SPLIT_PRIORITY }));
    s
}
