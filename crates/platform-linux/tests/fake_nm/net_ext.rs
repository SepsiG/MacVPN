//! NetworkManager's devices for the network probe's tests (L-b Task 16): the root object's `Devices`, one
//! `…Device` per device (`DeviceType`, `State`, `Interface`, `Ip4Config`, `Ip6Config`), `…Device.Wireless`
//! (`ActiveAccessPoint`) and `…AccessPoint` (`Ssid`) for Wi-Fi, `…IP4Config`/`…IP6Config` (`Gateway`,
//! `AddressData`, `RouteData`), and the signals the probe watches.
//!
//! Self-contained (it owns `org.freedesktop.NetworkManager` on the test's private bus with only these objects), so
//! `tests/net_bus.rs` includes it directly; `tests/fake_nm/mod.rs` (Task 13) declares it too.
#![allow(dead_code)]

use std::collections::HashMap;
use zbus::blocking::Connection;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

pub const NM: &str = "org.freedesktop.NetworkManager";
pub const NM_PATH: &str = "/org/freedesktop/NetworkManager";

/// One IP configuration: `gateway` as NM gives it (`""` for none), addresses with prefix lengths, and the metric of
/// its default route (`None`: NM lists no default route).
#[derive(Debug, Clone)]
pub struct FakeIp {
    pub gateway: String,
    pub addresses: Vec<(String, u32)>,
    pub default_metric: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct FakeDevice {
    pub interface: String,
    pub device_type: u32,
    pub state: u32,
    pub ip4: Option<FakeIp>,
    pub ip6: Option<FakeIp>,
    /// Wi-Fi only: the active access point's `Ssid` bytes.
    pub ssid: Option<Vec<u8>>,
}

pub fn ip(gateway: &str, addresses: &[(&str, u32)], default_metric: Option<u32>) -> FakeIp {
    FakeIp {
        gateway: gateway.to_string(),
        addresses: addresses.iter().map(|(a, l)| (a.to_string(), *l)).collect(),
        default_metric,
    }
}

pub fn device(interface: &str, device_type: u32, state: u32, ip4: Option<FakeIp>, ip6: Option<FakeIp>) -> FakeDevice {
    FakeDevice { interface: interface.to_string(), device_type, state, ip4, ip6, ssid: None }
}

fn path(p: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(p.to_string()).expect("an object path")
}

fn dict(entries: Vec<(&str, Value<'static>)>) -> HashMap<String, OwnedValue> {
    entries.into_iter().map(|(k, v)| (k.to_string(), OwnedValue::try_from(v).expect("a plain value"))).collect()
}

struct Root {
    devices: Vec<OwnedObjectPath>,
}

#[zbus::interface(name = "org.freedesktop.NetworkManager")]
impl Root {
    #[zbus(property, name = "Devices")]
    fn devices(&self) -> Vec<OwnedObjectPath> {
        self.devices.clone()
    }

    #[zbus(property, name = "Version")]
    fn version(&self) -> String {
        "1.54.3".to_string()
    }
}

struct Dev {
    interface: String,
    device_type: u32,
    state: u32,
    ip4: OwnedObjectPath,
    ip6: OwnedObjectPath,
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.Device")]
impl Dev {
    #[zbus(property, name = "Interface")]
    fn interface(&self) -> String {
        self.interface.clone()
    }

    #[zbus(property, name = "DeviceType")]
    fn device_type(&self) -> u32 {
        self.device_type
    }

    #[zbus(property, name = "State")]
    fn state(&self) -> u32 {
        self.state
    }

    #[zbus(property, name = "Ip4Config")]
    fn ip4_config(&self) -> OwnedObjectPath {
        self.ip4.clone()
    }

    #[zbus(property, name = "Ip6Config")]
    fn ip6_config(&self) -> OwnedObjectPath {
        self.ip6.clone()
    }
}

struct Wireless {
    access_point: OwnedObjectPath,
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.Device.Wireless")]
impl Wireless {
    #[zbus(property, name = "ActiveAccessPoint")]
    fn active_access_point(&self) -> OwnedObjectPath {
        self.access_point.clone()
    }
}

struct AccessPoint {
    ssid: Vec<u8>,
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.AccessPoint")]
impl AccessPoint {
    #[zbus(property, name = "Ssid")]
    fn ssid(&self) -> Vec<u8> {
        self.ssid.clone()
    }

    #[zbus(property, name = "Strength")]
    fn strength(&self) -> u8 {
        70
    }
}

struct IpConfig {
    v6: bool,
    ip: FakeIp,
}

impl IpConfig {
    fn address_data(&self) -> Vec<HashMap<String, OwnedValue>> {
        self.ip
            .addresses
            .iter()
            .map(|(a, l)| dict(vec![("address", Value::from(a.clone())), ("prefix", Value::from(*l))]))
            .collect()
    }

    fn route_data(&self) -> Vec<HashMap<String, OwnedValue>> {
        // A route that is not the default one comes first, with a lower metric: it must not count.
        let (any, other, other_len) =
            if self.v6 { ("::", "2001:db8:ffff::", 48u32) } else { ("0.0.0.0", "198.18.0.0", 15u32) };
        let mut routes = vec![dict(vec![
            ("dest", Value::from(other.to_string())),
            ("prefix", Value::from(other_len)),
            ("metric", Value::from(5u32)),
        ])];
        if let Some(metric) = self.ip.default_metric {
            routes.push(dict(vec![
                ("dest", Value::from(any.to_string())),
                ("prefix", Value::from(0u32)),
                ("next-hop", Value::from(self.ip.gateway.clone())),
                ("metric", Value::from(metric)),
            ]));
        }
        routes
    }
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.IP4Config")]
impl IpConfig {
    #[zbus(property, name = "Gateway")]
    fn gateway(&self) -> String {
        self.ip.gateway.clone()
    }

    #[zbus(property, name = "AddressData")]
    fn address_data_property(&self) -> Vec<HashMap<String, OwnedValue>> {
        self.address_data()
    }

    #[zbus(property, name = "RouteData")]
    fn route_data_property(&self) -> Vec<HashMap<String, OwnedValue>> {
        self.route_data()
    }
}

struct Ip6Config(IpConfig);

#[zbus::interface(name = "org.freedesktop.NetworkManager.IP6Config")]
impl Ip6Config {
    #[zbus(property, name = "Gateway")]
    fn gateway(&self) -> String {
        self.0.ip.gateway.clone()
    }

    #[zbus(property, name = "AddressData")]
    fn address_data_property(&self) -> Vec<HashMap<String, OwnedValue>> {
        self.0.address_data()
    }

    #[zbus(property, name = "RouteData")]
    fn route_data_property(&self) -> Vec<HashMap<String, OwnedValue>> {
        self.0.route_data()
    }
}

/// A fake NetworkManager with devices, owning NM's name on the test's private session bus until dropped.
pub struct FakeNet {
    conn: Connection,
    devices: Vec<String>,
}

impl FakeNet {
    pub fn start(devices: Vec<FakeDevice>) -> FakeNet {
        let conn = Connection::session().expect("a private session bus (run under dbus-run-session)");
        let owner = conn.clone();
        let server = owner.object_server();
        let mut paths = Vec::new();
        for (i, d) in devices.into_iter().enumerate() {
            let n = i + 1;
            let dev_path = format!("{NM_PATH}/Devices/{n}");
            let ip4 = match d.ip4 {
                Some(ip) => {
                    let p = format!("{NM_PATH}/IP4Config/{n}");
                    server.at(p.as_str(), IpConfig { v6: false, ip }).expect("serve IP4Config");
                    p
                }
                None => "/".to_string(),
            };
            let ip6 = match d.ip6 {
                Some(ip) => {
                    let p = format!("{NM_PATH}/IP6Config/{n}");
                    server.at(p.as_str(), Ip6Config(IpConfig { v6: true, ip })).expect("serve IP6Config");
                    p
                }
                None => "/".to_string(),
            };
            if let Some(ssid) = d.ssid {
                let ap = format!("{NM_PATH}/AccessPoint/{n}");
                server.at(ap.as_str(), AccessPoint { ssid }).expect("serve AccessPoint");
                server.at(dev_path.as_str(), Wireless { access_point: path(&ap) }).expect("serve Wireless");
            }
            let dev = Dev {
                interface: d.interface,
                device_type: d.device_type,
                state: d.state,
                ip4: path(&ip4),
                ip6: path(&ip6),
            };
            server.at(dev_path.as_str(), dev).expect("serve Device");
            paths.push(dev_path);
        }
        server.at(NM_PATH, Root { devices: paths.iter().map(|p| path(p)).collect() }).expect("serve NM");
        conn.request_name(NM).expect("NetworkManager's name on the private bus");
        FakeNet { conn, devices: paths }
    }

    /// The device's `StateChanged(new, old, reason)`.
    pub fn emit_device_state(&self, index: usize, new: u32, old: u32) {
        self.conn
            .emit_signal(
                None::<()>,
                self.devices[index].as_str(),
                "org.freedesktop.NetworkManager.Device",
                "StateChanged",
                &(new, old, 0u32),
            )
            .expect("emit StateChanged");
    }

    /// `PropertiesChanged` of `interface` on `object` with one changed `u32` property.
    pub fn emit_property_changed(&self, object: &str, interface: &str, name: &str, value: u32) {
        let changed: HashMap<&str, Value<'_>> = HashMap::from([(name, Value::from(value))]);
        self.conn
            .emit_signal(
                None::<()>,
                object,
                "org.freedesktop.DBus.Properties",
                "PropertiesChanged",
                &(interface, changed, Vec::<&str>::new()),
            )
            .expect("emit PropertiesChanged");
    }
}

impl Drop for FakeNet {
    fn drop(&mut self) {
        let _ = self.conn.release_name(NM);
    }
}
