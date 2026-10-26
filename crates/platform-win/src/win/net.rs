//! The network probe of WinVPN: `macvpn_winsys::net`'s reads, filtered by `pure::net` (the physical adapters only:
//! no VPN, tunnel, PPP or loopback adapter is ever the gateway or a connected subnet).

use crate::pure::net::{Adapter, connected, is_wifi, physical_gateway};
use macvpn_core::netaddr::IpPrefix;
use macvpn_platform_api::{Gateway, NetworkProbe, NetworkSnapshot, PlatformError};
use macvpn_winsys::net;
use std::io;
use std::sync::{Mutex, PoisonError};

pub(crate) struct WinNetwork;

fn adapter(raw: net::RawAdapter) -> Adapter {
    Adapter {
        prefixes: raw.unicast.iter().filter_map(|(ip, len)| IpPrefix::new(*ip, *len)).collect(),
        alias: raw.alias,
        if_type: raw.if_type,
        description: raw.description,
        up: raw.up,
        gateway: raw.gateway,
        route_metric: raw.route_metric,
        luid: raw.luid,
        guid: raw.guid,
    }
}

impl NetworkProbe for WinNetwork {
    /// The adapters, then the gateway's MAC (`ResolveIpNetEntry2`: may wait a few seconds when the gateway does not
    /// answer) and, on Wi-Fi, the SSID (unknown without location permission). A MAC or SSID that cannot be read is
    /// `None`, never an error.
    fn snapshot(&self) -> Result<NetworkSnapshot, PlatformError> {
        let adapters: Vec<Adapter> = net::adapters()
            .map_err(|e| PlatformError::Failed(format!("network adapters: {e}")))?
            .into_iter()
            .map(adapter)
            .collect();
        let gateway = physical_gateway(&adapters).and_then(|a| {
            let ip = a.gateway?;
            Some(Gateway {
                ip,
                mac: net::neighbor_mac(a.luid, ip).ok().flatten(),
                interface: a.alias.clone(),
                ssid: if is_wifi(a) { net::wlan_ssid(a.guid).ok().flatten() } else { None },
            })
        });
        Ok(NetworkSnapshot { gateway, connected: connected(&adapters) })
    }

    /// Interface and route changes (`NotifyIpInterfaceChange`, `NotifyRouteChange2`). The system may call from
    /// several threads at once: the callback runs under a lock.
    fn watch(&self, on_change: Box<dyn Fn() + Send>) -> io::Result<Box<dyn Send>> {
        let on_change = Mutex::new(on_change);
        let watch = net::watch(Box::new(move || on_change.lock().unwrap_or_else(PoisonError::into_inner)()))?;
        Ok(Box::new(watch))
    }
}
