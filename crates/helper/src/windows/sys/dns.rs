//! The real environment of the DNS manager (`windows::dns`): the local NRPT rules in the registry
//! (`macvpn_winsys::nrpt`), the adapters through IP Helper (`macvpn_winsys::net`, `iphlp`) and the shared probe.

use super::iphlp;
use crate::windows::dns::{AdapterDns, AdapterNet, Manager, Nrpt, usable_server};
use macvpn_core::dns_policy::nrpt::NrptRule;
use macvpn_core::netaddr::IpPrefix;
use macvpn_core::win_adapters::is_virtual;
use macvpn_winsys::net::{self, AdapterDiag};
use macvpn_winsys::nrpt::{self as registry, POLICY_PATH};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

/// `IF_TYPE_PPP`: a RAS connection's adapter.
const IF_TYPE_PPP: u32 = 23;

/// The rules under `HKLM\…\Dnscache\Parameters\DnsPolicyConfig`.
struct RegistryNrpt;

impl Nrpt for RegistryNrpt {
    fn write(&self, rules: &[NrptRule]) -> Result<(), String> {
        rules
            .iter()
            .try_for_each(|r| registry::write_rule(POLICY_PATH, &r.key, &r.names, &r.servers))
            .map_err(|e| e.to_string())
    }
    fn delete(&self, prefix: &str) -> Result<usize, String> {
        registry::delete_rules(POLICY_PATH, prefix).map_err(|e| e.to_string())
    }
    fn keys(&self) -> Result<Vec<String>, String> {
        registry::rule_keys(POLICY_PATH).map_err(|e| e.to_string())
    }
    fn apply(&self) -> Result<(), String> {
        registry::apply().map_err(|e| e.to_string())
    }
}

/// The adapters as IP Helper reports them.
struct IpHelperAdapters;

/// An adapter's DNS servers (usable ones), its suffix and its subnets.
fn net_of(a: &AdapterDiag) -> AdapterNet {
    AdapterNet {
        servers: a.dns.iter().filter(|ip| usable_server(ip)).map(ToString::to_string).collect(),
        domains: Some(a.suffix.clone()).filter(|s| !s.is_empty()).into_iter().collect(),
        subnets: a.unicast.iter().filter_map(|(ip, len)| IpPrefix::new(*ip, *len)).collect(),
    }
}

impl AdapterDns for IpHelperAdapters {
    fn get(&self, luid: u64) -> Option<AdapterNet> {
        net::adapters_with_dns().ok()?.iter().find(|a| a.luid == luid).map(net_of)
    }

    /// Both families' servers and the search list (set as WireGuard's are, empty values clearing them).
    fn clear(&self, luid: u64) -> Result<(), String> {
        let guid = iphlp::guid_of(NET_LUID_LH { Value: luid }).map_err(|e| e.to_string())?;
        iphlp::set_dns(guid, false, "", Some("")).map_err(|e| e.to_string())?;
        iphlp::set_dns(guid, true, "", None).map_err(|e| e.to_string())
    }

    /// The servers by family (comma-separated, as WireGuard's are set) and the search list.
    fn set(&self, luid: u64, servers: &[String], domains: &[String]) -> Result<(), String> {
        let guid = iphlp::guid_of(NET_LUID_LH { Value: luid }).map_err(|e| e.to_string())?;
        let family = |v6: bool| servers.iter().filter(|s| s.contains(':') == v6).cloned().collect::<Vec<_>>().join(",");
        iphlp::set_dns(guid, false, &family(false), Some(&domains.join(","))).map_err(|e| e.to_string())?;
        iphlp::set_dns(guid, true, &family(true), None).map_err(|e| e.to_string())
    }

    /// The adapter with the best default route through a real next hop that is neither virtual nor a VPN's (as the
    /// app's network check chooses it).
    fn physical(&self) -> Option<AdapterNet> {
        let best = net::adapters()
            .ok()?
            .into_iter()
            .filter(|a| a.up && !is_virtual(a.if_type, &a.description))
            .filter(|a| a.gateway.is_some_and(|g| !g.is_unspecified()))
            .min_by_key(|a| a.route_metric)?;
        net::adapters_with_dns().ok()?.iter().find(|a| a.luid == best.luid).map(net_of)
    }

    fn is_ppp(&self, luid: u64) -> bool {
        net::adapters().is_ok_and(|all| all.iter().any(|a| a.luid == luid && a.if_type == IF_TYPE_PPP && a.up))
    }
}

/// The service's DNS manager over the registry, IP Helper and the shared probe.
pub(crate) fn manager() -> Manager {
    Manager::new(
        Box::new(RegistryNrpt),
        Box::new(IpHelperAdapters),
        Box::new(|servers: &[String]| macvpn_core::dns_policy::probe(servers)),
    )
}
