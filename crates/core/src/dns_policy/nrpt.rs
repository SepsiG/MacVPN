//! The local NRPT rules (Windows' Name Resolution Policy Table) a DNS layout needs. Pure: the WinVPN Service writes
//! them under `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\<key>`, as OpenVPN's
//! interactive service does for `--dns`.

use super::{Effective, Layout};
use crate::dns_zones::covered_by;

/// One NRPT rule: these names are resolved by these servers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NrptRule {
    /// The registry key name: `WinVPN-<id>-<n>` (the prefix marks ours for cleanup).
    pub key: String,
    /// NRPT names: `.` for every name, `.<suffix>` for a domain.
    pub names: Vec<String>,
    /// The DNS servers (IP literals).
    pub servers: Vec<String>,
}

/// The key prefix of every rule of connection `id` (`WinVPN-<id>-`).
pub fn key_prefix(id: &str) -> String {
    format!("WinVPN-{id}-")
}

/// The rules of connection `id` for `layout`, keys numbered from 0:
/// - `Vpn`: `.` (every name) to the VPN's servers; with `local`, the physical network's own domains not covered by
///   the VPN's domains stay on the physical network's servers;
/// - `Split` and `Fallback`: only the VPN's domains and reverse zones to the VPN's servers;
/// - `None`: nothing.
///
/// `local`: the physical network's own domains and its DNS servers.
///
/// ```
/// use macvpn_core::dns_policy::nrpt::rules;
/// use macvpn_core::dns_policy::{Effective, Layout};
/// let e = Effective { servers: vec!["10.0.0.53".into()], search: vec!["corp.example".into()], ..Effective::default() };
/// let r = rules("work", Layout::Split, &e, None);
/// assert_eq!(r[0].key, "WinVPN-work-0");
/// assert_eq!(r[0].names, [".corp.example"]);
/// ```
pub fn rules(id: &str, layout: Layout, e: &Effective, local: Option<(&[String], &[String])>) -> Vec<NrptRule> {
    let names: Vec<(Vec<String>, &[String])> = match layout {
        Layout::None => Vec::new(),
        Layout::Vpn { local: keep_local } => {
            let mut out = vec![(vec![".".to_string()], e.servers.as_slice())];
            if keep_local && let Some((domains, servers)) = local {
                let vpn = e.all_matches();
                let own: Vec<String> = domains.iter().filter(|d| !covered_by(d, &vpn)).map(|d| suffix(d)).collect();
                if !own.is_empty() && !servers.is_empty() {
                    out.push((own, servers));
                }
            }
            out
        }
        Layout::Split | Layout::Fallback => {
            let vpn: Vec<String> = e.all_matches().iter().map(|d| suffix(d)).collect();
            if vpn.is_empty() { Vec::new() } else { vec![(vpn, e.servers.as_slice())] }
        }
    };
    let prefix = key_prefix(id);
    names
        .into_iter()
        .enumerate()
        .map(|(n, (names, servers))| NrptRule { key: format!("{prefix}{n}"), names, servers: servers.to_vec() })
        .collect()
}

/// A domain as an NRPT name: `.<domain>`.
fn suffix(domain: &str) -> String {
    format!(".{}", domain.trim_end_matches('.'))
}
