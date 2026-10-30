//! The physical network for the auto-reconnect (`NetworkProbe`), from NetworkManager.
//!
//! `snapshot` reads NM's devices (each D-Bus call bounded to [`CALL_LIMIT`]), keeps the ethernet and Wi-Fi ones
//! (`pure::net`: never a VPN, WireGuard, tun, PPP or bridge, so LinVPN's own tunnels are never the network), takes the
//! gateway of the activated one with the best default route, its MAC from `/proc/net/arp` and, on Wi-Fi, the active
//! access point's SSID. `watch` follows NM's change events through `lin::nm::client::NmClient::watch`
//! (`NetworkChanged`, `ActiveChanged`).

use crate::lin::nm::client::{NmClient, NmEvent};
use crate::pure::net::{Device, arp_mac, choose, is_physical, ssid_text};
use futures_lite::future;
use macvpn_platform_api::{Gateway, NetworkProbe, NetworkSnapshot, PlatformError};
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;
use zbus::zvariant::{ObjectPath, OwnedValue};

pub struct LinNetwork {
    pub bus: fn() -> zbus::Result<zbus::blocking::Connection>,
}

const NM: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const DEVICE: &str = "org.freedesktop.NetworkManager.Device";
const WIRELESS: &str = "org.freedesktop.NetworkManager.Device.Wireless";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
/// Each NM call's time limit: the probe is blocking and must stay short (`NetworkProbe::snapshot`).
const CALL_LIMIT: Duration = Duration::from_secs(2);

type Props = HashMap<String, OwnedValue>;

fn failed(what: &str, e: impl std::fmt::Display) -> PlatformError {
    PlatformError::Failed(format!("NetworkManager ({what}): {e}"))
}

/// `Properties.GetAll(interface)` of one NM object, within [`CALL_LIMIT`].
fn get_all(conn: &zbus::Connection, path: &str, interface: &str) -> Result<Props, PlatformError> {
    let call = async {
        let reply = conn
            .call_method(Some(NM), path, Some(PROPERTIES), "GetAll", &(interface,))
            .await
            .map_err(|e| failed(interface, e))?;
        reply.body().deserialize::<Props>().map_err(|e| failed(interface, e))
    };
    let limit = async {
        async_io::Timer::after(CALL_LIMIT).await;
        Err(failed(interface, "no answer within 2 s"))
    };
    async_io::block_on(future::or(call, limit))
}

fn u32_of(props: &Props, name: &str) -> Option<u32> {
    props.get(name).and_then(|v| v.downcast_ref::<u32>().ok())
}

fn string_of(props: &Props, name: &str) -> Option<String> {
    props.get(name).and_then(|v| v.downcast_ref::<&str>().ok()).map(str::to_string)
}

/// An object path property; `/` (none) is `None`.
fn path_of(props: &Props, name: &str) -> Option<String> {
    let path = props.get(name).and_then(|v| v.downcast_ref::<ObjectPath<'_>>().ok())?.to_string();
    (path != "/").then_some(path)
}

fn dicts_of(props: &Props, name: &str) -> Vec<Props> {
    props.get(name).and_then(|v| v.try_clone().ok()).and_then(|v| Vec::<Props>::try_from(v).ok()).unwrap_or_default()
}

/// What one `IP4Config`/`IP6Config` adds to a device.
struct IpFacts {
    gateway: Option<IpAddr>,
    default_metric: Option<u32>,
    addresses: Vec<(IpAddr, u8)>,
}

fn ip_facts(props: &Props) -> IpFacts {
    let gateway = string_of(props, "Gateway").and_then(|g| IpAddr::from_str(&g).ok()).filter(|g| !g.is_unspecified());
    let default_metric = dicts_of(props, "RouteData").iter().find_map(|r| {
        let dest = string_of(r, "dest").and_then(|d| IpAddr::from_str(&d).ok())?;
        (dest.is_unspecified() && u32_of(r, "prefix") == Some(0)).then(|| u32_of(r, "metric").unwrap_or(0))
    });
    let addresses = dicts_of(props, "AddressData")
        .iter()
        .filter_map(|a| {
            let addr = string_of(a, "address").and_then(|s| IpAddr::from_str(&s).ok())?;
            let len = u8::try_from(u32_of(a, "prefix")?).ok()?;
            Some((addr, len))
        })
        .collect();
    IpFacts { gateway, default_metric, addresses }
}

/// One device as `pure::net` sees it, and its path; `None` for a device that cannot be the physical network (its IP
/// configuration is then never read).
fn read_device(conn: &zbus::Connection, path: &str) -> Result<Option<Device>, PlatformError> {
    let props = get_all(conn, path, DEVICE)?;
    let device_type = u32_of(&props, "DeviceType").unwrap_or(0);
    if !is_physical(device_type) {
        return Ok(None);
    }
    let mut device = Device {
        interface: string_of(&props, "Interface").unwrap_or_default(),
        device_type,
        state: u32_of(&props, "State").unwrap_or(0),
        gateway: None,
        default_metric: None,
        addresses: Vec::new(),
    };
    for (property, interface) in [
        ("Ip4Config", "org.freedesktop.NetworkManager.IP4Config"),
        ("Ip6Config", "org.freedesktop.NetworkManager.IP6Config"),
    ] {
        let Some(config) = path_of(&props, property) else { continue };
        let facts = ip_facts(&get_all(conn, &config, interface)?);
        // IPv4's gateway first (its MAC can be resolved); IPv6's only when there is no IPv4 one.
        if device.gateway.is_none() && facts.gateway.is_some() {
            device.gateway = facts.gateway;
            device.default_metric = facts.default_metric;
        }
        device.addresses.extend(facts.addresses);
    }
    Ok(Some(device))
}

/// The Wi-Fi device's active access point's name; `None` when it cannot be read.
fn ssid(conn: &zbus::Connection, device_path: &str) -> Option<String> {
    let ap = path_of(&get_all(conn, device_path, WIRELESS).ok()?, "ActiveAccessPoint")?;
    let props = get_all(conn, &ap, "org.freedesktop.NetworkManager.AccessPoint").ok()?;
    let raw = props.get("Ssid").and_then(|v| v.try_clone().ok()).and_then(|v| Vec::<u8>::try_from(v).ok())?;
    ssid_text(&raw)
}

fn gateway_mac(ip: IpAddr) -> Option<[u8; 6]> {
    match ip {
        IpAddr::V4(_) => arp_mac(&std::fs::read_to_string("/proc/net/arp").ok()?, &ip.to_string()),
        // IPv6 neighbours are not in /proc/net/arp.
        IpAddr::V6(_) => None,
    }
}

impl NetworkProbe for LinNetwork {
    /// `Err(Failed)` when NetworkManager is not on the bus or does not answer in time. A MAC or SSID that cannot be
    /// read is `None`, never an error.
    fn snapshot(&self) -> Result<NetworkSnapshot, PlatformError> {
        let bus = (self.bus)().map_err(|e| failed("bus", e))?;
        let conn = bus.inner();
        let root = get_all(conn, NM_PATH, NM)?;
        let paths: Vec<String> = root
            .get("Devices")
            .and_then(|v| v.try_clone().ok())
            .and_then(|v| Vec::<zbus::zvariant::OwnedObjectPath>::try_from(v).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|p| p.to_string())
            .collect();
        let mut devices = Vec::new();
        let mut device_paths = Vec::new();
        for path in &paths {
            if let Some(device) = read_device(conn, path)? {
                devices.push(device);
                device_paths.push(path.as_str());
            }
        }
        let choice = choose(&devices);
        let gateway = choice.gateway.and_then(|d| {
            let ip = d.gateway?;
            let index = devices.iter().position(|x| std::ptr::eq(x, d))?;
            Some(Gateway {
                ip,
                mac: gateway_mac(ip),
                interface: d.interface.clone(),
                ssid: if d.device_type == crate::pure::net::DEVICE_TYPE_WIFI {
                    ssid(conn, device_paths[index])
                } else {
                    None
                },
            })
        });
        Ok(NetworkSnapshot { gateway, connected: choice.connected })
    }

    /// NM's change events through [`NmClient::watch`] (its `NetworkChanged` and `ActiveChanged`: a device's
    /// `StateChanged`, NM's primary connection, connectivity, state, device list and active connections, any change
    /// of an IP configuration). Subscribes before returning (a change right after `watch` is seen); `on_change` runs
    /// on a watcher thread, one call at a time. Dropping the box ends the threads and their subscriptions.
    fn watch(&self, on_change: Box<dyn Fn() + Send>) -> io::Result<Box<dyn Send>> {
        let bus = (self.bus)().map_err(io::Error::other)?;
        // The client reads each subscription on its own thread; the lock makes the calls one at a time.
        let on_change = Mutex::new(on_change);
        let guard = NmClient::new(bus)
            .watch(Box::new(move |event| {
                if matches!(event, NmEvent::NetworkChanged | NmEvent::ActiveChanged | NmEvent::ActiveState { .. }) {
                    (on_change.lock().unwrap_or_else(PoisonError::into_inner))();
                }
            }))
            .map_err(io::Error::other)?;
        Ok(Box::new(guard))
    }
}
