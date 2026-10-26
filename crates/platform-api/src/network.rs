//! The physical network as the auto-reconnect sees it: the default gateway (its IP, MAC and the Wi-Fi SSID where
//! readable) and the subnets directly connected to physical interfaces. Tunnel interfaces (VPNs) are never part
//! of it. Each platform implements the probe; the decisions are app-core's.

use crate::PlatformError;
use macvpn_core::netaddr::IpPrefix;
use std::io;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gateway {
    pub ip: IpAddr,
    /// `None`: it could not be resolved.
    pub mac: Option<[u8; 6]>,
    /// The interface the default route leaves through (`en0`, the adapter's alias).
    pub interface: String,
    /// The Wi-Fi network's name; `None` on a wired interface or when the system does not tell (location
    /// permission).
    pub ssid: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkSnapshot {
    /// The default gateway of the physical interface with the best route; `None`: no network.
    pub gateway: Option<Gateway>,
    /// The subnets of the up, physical interfaces (no loopback, link-local or tunnel).
    pub connected: Vec<IpPrefix>,
}

impl NetworkSnapshot {
    pub fn has_network(&self) -> bool {
        self.gateway.is_some()
    }
}

pub trait NetworkProbe: Send + Sync {
    /// Blocking (a few hundred milliseconds at most; the platform bounds its calls).
    fn snapshot(&self) -> Result<NetworkSnapshot, PlatformError>;
    /// Calls `on_change` (on the watcher's thread) when addresses or routes change. Dropping the box stops it.
    fn watch(&self, on_change: Box<dyn Fn() + Send>) -> io::Result<Box<dyn Send>>;
}

/// No probe (tests, the sandbox, a platform without one): never reconnects.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoNetworkProbe;

impl NetworkProbe for NoNetworkProbe {
    fn snapshot(&self) -> Result<NetworkSnapshot, PlatformError> {
        Err(PlatformError::Unsupported { what: "network probe" })
    }

    fn watch(&self, _on_change: Box<dyn Fn() + Send>) -> io::Result<Box<dyn Send>> {
        Ok(Box::new(()))
    }
}
