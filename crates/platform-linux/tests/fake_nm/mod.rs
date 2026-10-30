//! A fake NetworkManager and polkit on the test's private session bus (`dbus-run-session`), under the real names
//! (`org.freedesktop.NetworkManager`, `org.freedesktop.PolicyKit1`). It records every call with its D-Bus message
//! flags. Shared by `nm_client.rs`, `nm_engine.rs` and `nm_native.rs`; Tasks 21 and 22 extend it only in their
//! own `*_ext.rs` file (`impl FakeNm { … }` blocks). `net_ext` (Task 16) is a self-contained fake with NM's devices
//! (`FakeNet`), used by `net_bus.rs`.
//!
//! One fake owns the names at a time: [`FakeNm::start`] waits for the previous test's fake of the same binary to
//! drop (the names are released before the next is requested).
#![allow(dead_code)]

pub mod engine_ext;
pub mod native_ext;
pub mod net_ext;

use macvpn_core::nm_plan::{NmAddress, NmValue, NmWgPeer, Settings};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use zbus::blocking::Connection;
use zbus::message::{Flags, Header};
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

pub const NM: &str = "org.freedesktop.NetworkManager";
pub const POLKIT: &str = "org.freedesktop.PolicyKit1";
pub const ROOT: &str = "/org/freedesktop/NetworkManager";
pub const SETTINGS: &str = "/org/freedesktop/NetworkManager/Settings";
pub const AUTHORITY: &str = "/org/freedesktop/PolicyKit1/Authority";

pub type NmSettings = HashMap<String, HashMap<String, OwnedValue>>;

/// polkit's answer to every `CheckAuthorization`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polkit {
    /// `(true, false)`: authorized without a challenge.
    Yes,
    /// `(false, true)`: polkit would ask.
    Challenge,
    /// `(false, false)`.
    No,
}

/// One recorded call.
#[derive(Debug, Clone, Default)]
pub struct Call {
    pub method: String,
    /// The message's `ALLOW_INTERACTIVE_AUTHORIZATION` header flag.
    pub allow_interactive_authorization: bool,
    pub sender: String,
    /// CheckAuthorization: the `flags` argument, the action and the subject `(kind, name)`.
    pub flags_arg: u32,
    pub action: String,
    pub subject: (String, String),
    /// AddAndActivateConnection2: the options as sorted `(key, string value)` pairs.
    pub options: Vec<(String, String)>,
    /// AddAndActivateConnection2: `connection.permissions`.
    pub permissions: Vec<String>,
    /// The object path argument (ActivateConnection, DeactivateConnection) or the called profile (Delete).
    pub path: String,
}

pub struct Profile {
    pub settings: NmSettings,
    pub flags: u32,
}

pub struct Active {
    pub uuid: String,
    pub id: String,
    pub nm_type: String,
    pub state: u32,
    pub vpn: bool,
    pub vpn_state: u32,
    pub connection: String,
    pub ip4_config: String,
    pub devices: Vec<String>,
}

#[derive(Default)]
pub struct State {
    pub polkit: Option<Polkit>,
    pub calls: Vec<Call>,
    pub deleted: Vec<String>,
    /// path → profile
    pub profiles: BTreeMap<String, Profile>,
    /// path → active connection (in activation order by path number)
    pub actives: BTreeMap<String, Active>,
    /// path → `AddressData` addresses
    pub ip4: BTreeMap<String, Vec<String>>,
    /// path → `IpInterface`
    pub devices: BTreeMap<String, String>,
    pub next: u32,
}

pub type Shared = Arc<Mutex<State>>;

fn lock(s: &Shared) -> MutexGuard<'_, State> {
    s.lock().unwrap_or_else(PoisonError::into_inner)
}

fn opath(p: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(p).unwrap()
}

fn owned(v: Value<'_>) -> OwnedValue {
    OwnedValue::try_from(v).unwrap()
}

pub fn clone_settings(s: &NmSettings) -> NmSettings {
    s.iter()
        .map(|(n, keys)| (n.clone(), keys.iter().map(|(k, v)| (k.clone(), v.try_clone().unwrap())).collect()))
        .collect()
}

fn settings_str(s: &NmSettings, setting: &str, key: &str) -> Option<String> {
    String::try_from(s.get(setting)?.get(key)?.try_clone().ok()?).ok()
}

fn settings_strs(s: &NmSettings, setting: &str, key: &str) -> Vec<String> {
    s.get(setting)
        .and_then(|x| x.get(key))
        .and_then(|v| Vec::<String>::try_from(v.try_clone().unwrap()).ok())
        .unwrap_or_default()
}

fn record(state: &Shared, hdr: &Header<'_>, call: Call) {
    let call = Call {
        allow_interactive_authorization: hdr.primary().flags().contains(Flags::AllowInteractiveAuth),
        sender: hdr.sender().map(|s| s.to_string()).unwrap_or_default(),
        ..call
    };
    lock(state).calls.push(call);
}

// ---- NetworkManager ----

struct Root(Shared);

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.NetworkManager")]
enum NmErr {
    #[zbus(error)]
    ZBus(zbus::Error),
    UnknownConnection(String),
    ConnectionNotActive(String),
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.NetworkManager.Settings")]
enum AddErr {
    #[zbus(error)]
    ZBus(zbus::Error),
    /// NM's `NM_SETTINGS_ERROR_UUID_EXISTS`.
    UuidExists(String),
}

#[zbus::interface(name = "org.freedesktop.NetworkManager")]
impl Root {
    async fn add_and_activate_connection2(
        &self,
        settings: NmSettings,
        _device: OwnedObjectPath,
        _specific_object: OwnedObjectPath,
        options: HashMap<String, OwnedValue>,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath, HashMap<String, OwnedValue>), AddErr> {
        let mut opts: Vec<(String, String)> = options
            .iter()
            .map(|(k, v)| (k.clone(), String::try_from(v.try_clone().unwrap()).unwrap_or_else(|_| "?".into())))
            .collect();
        opts.sort();
        let permissions = settings_strs(&settings, "connection", "permissions");
        record(
            &self.0,
            &hdr,
            Call { method: "AddAndActivateConnection2".into(), options: opts, permissions, ..Call::default() },
        );
        let uuid = settings_str(&settings, "connection", "uuid").unwrap_or_default();
        let id = settings_str(&settings, "connection", "id").unwrap_or_default();
        let nm_type = settings_str(&settings, "connection", "type").unwrap_or_default();
        let vpn = nm_type == "vpn";
        let (profile, active) = {
            let mut s = lock(&self.0);
            // NM keeps UUIDs unique among all profiles, whoever's.
            if s.profiles.values().any(|p| settings_str(&p.settings, "connection", "uuid").as_deref() == Some(&uuid)) {
                return Err(AddErr::UuidExists("A connection with this UUID already exists.".into()));
            }
            let profile = new_profile_locked(&mut s, settings, 4 | 1);
            let active = new_active_locked(
                &mut s,
                Active {
                    uuid,
                    id,
                    nm_type,
                    state: 1,
                    vpn,
                    vpn_state: if vpn { 1 } else { 0 },
                    connection: profile.clone(),
                    ip4_config: "/".into(),
                    devices: vec![],
                },
            );
            (profile, active)
        };
        serve_profile(server, &self.0, &profile).await;
        serve_active(server, &self.0, &active, vpn).await;
        Ok((opath(&profile), opath(&active), HashMap::new()))
    }

    async fn activate_connection(
        &self,
        connection: OwnedObjectPath,
        _device: OwnedObjectPath,
        _specific_object: OwnedObjectPath,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> Result<OwnedObjectPath, NmErr> {
        record(
            &self.0,
            &hdr,
            Call { method: "ActivateConnection".into(), path: connection.to_string(), ..Call::default() },
        );
        let (active, vpn) = {
            let mut s = lock(&self.0);
            let Some(p) = s.profiles.get(connection.as_str()) else {
                return Err(NmErr::UnknownConnection(format!("no profile {connection}")));
            };
            let uuid = settings_str(&p.settings, "connection", "uuid").unwrap_or_default();
            let id = settings_str(&p.settings, "connection", "id").unwrap_or_default();
            let nm_type = settings_str(&p.settings, "connection", "type").unwrap_or_default();
            let vpn = nm_type == "vpn";
            let a = Active {
                uuid,
                id,
                nm_type,
                state: 1,
                vpn,
                vpn_state: 1,
                connection: connection.to_string(),
                ip4_config: "/".into(),
                devices: vec![],
            };
            (new_active_locked(&mut s, a), vpn)
        };
        serve_active(server, &self.0, &active, vpn).await;
        Ok(opath(&active))
    }

    async fn deactivate_connection(
        &self,
        active_connection: OwnedObjectPath,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> Result<(), NmErr> {
        record(
            &self.0,
            &hdr,
            Call { method: "DeactivateConnection".into(), path: active_connection.to_string(), ..Call::default() },
        );
        let removed = lock(&self.0).actives.remove(active_connection.as_str());
        let Some(a) = removed else {
            return Err(NmErr::ConnectionNotActive(format!("{active_connection} is not active")));
        };
        let _ = server.remove::<ActiveConn, _>(active_connection.as_str()).await;
        if a.vpn {
            let _ = server.remove::<VpnConn, _>(active_connection.as_str()).await;
        }
        Ok(())
    }

    #[zbus(property)]
    fn version(&self) -> String {
        "1.54.3".into()
    }

    #[zbus(property)]
    fn active_connections(&self) -> Vec<OwnedObjectPath> {
        lock(&self.0).actives.keys().map(|p| opath(p)).collect()
    }
}

struct SettingsObj(Shared);

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.NetworkManager.Settings")]
enum SettingsErr {
    #[zbus(error)]
    ZBus(zbus::Error),
    InvalidConnection(String),
    PermissionDenied(String),
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings")]
impl SettingsObj {
    fn list_connections(&self) -> Vec<OwnedObjectPath> {
        lock(&self.0).profiles.keys().map(|p| opath(p)).collect()
    }

    fn get_connection_by_uuid(&self, uuid: String) -> Result<OwnedObjectPath, SettingsErr> {
        let s = lock(&self.0);
        let (path, p) = s
            .profiles
            .iter()
            .find(|(_, p)| settings_str(&p.settings, "connection", "uuid").as_deref() == Some(uuid.as_str()))
            .ok_or_else(|| SettingsErr::InvalidConnection("No connection with the UUID was found.".into()))?;
        // NM refuses a profile whose permissions leave the caller out; the fake: one marked `hidden`.
        if settings_str(&p.settings, "connection", "id").as_deref() == Some("hidden") {
            return Err(SettingsErr::PermissionDenied("not visible".into()));
        }
        Ok(opath(path))
    }

    #[zbus(signal)]
    async fn new_connection(emitter: &SignalEmitter<'_>, connection: ObjectPath<'_>) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn connection_removed(emitter: &SignalEmitter<'_>, connection: ObjectPath<'_>) -> zbus::Result<()>;
}

struct ProfileObj(Shared, String);

#[zbus::interface(name = "org.freedesktop.NetworkManager.Settings.Connection")]
impl ProfileObj {
    fn get_settings(&self) -> Result<NmSettings, SettingsErr> {
        let s = lock(&self.0);
        let p = s.profiles.get(&self.1).ok_or_else(|| SettingsErr::InvalidConnection("gone".into()))?;
        // NM refuses the settings of a profile the caller cannot see; the fake: one marked `hidden`.
        if settings_str(&p.settings, "connection", "id").as_deref() == Some("hidden") {
            return Err(SettingsErr::PermissionDenied("not visible".into()));
        }
        Ok(clone_settings(&p.settings))
    }

    async fn delete(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> Result<(), SettingsErr> {
        record(&self.0, &hdr, Call { method: "Delete".into(), path: self.1.clone(), ..Call::default() });
        {
            let mut s = lock(&self.0);
            let p = s.profiles.remove(&self.1).ok_or_else(|| SettingsErr::InvalidConnection("gone".into()))?;
            let uuid = settings_str(&p.settings, "connection", "uuid").unwrap_or_default();
            s.deleted.push(uuid);
        }
        let _ = server.remove::<ProfileObj, _>(self.1.as_str()).await;
        Ok(())
    }

    #[zbus(property)]
    fn flags(&self) -> u32 {
        lock(&self.0).profiles.get(&self.1).map(|p| p.flags).unwrap_or(0)
    }

    #[zbus(signal)]
    async fn updated(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

struct ActiveConn(Shared, String);

impl ActiveConn {
    fn with<T>(&self, f: impl FnOnce(&Active) -> T) -> zbus::fdo::Result<T> {
        lock(&self.0).actives.get(&self.1).map(f).ok_or_else(|| zbus::fdo::Error::UnknownObject(self.1.clone()))
    }
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.Connection.Active")]
impl ActiveConn {
    #[zbus(property)]
    fn uuid(&self) -> zbus::fdo::Result<String> {
        self.with(|a| a.uuid.clone())
    }
    #[zbus(property)]
    fn id(&self) -> zbus::fdo::Result<String> {
        self.with(|a| a.id.clone())
    }
    #[zbus(property, name = "Type")]
    fn nm_type(&self) -> zbus::fdo::Result<String> {
        self.with(|a| a.nm_type.clone())
    }
    #[zbus(property)]
    fn state(&self) -> zbus::fdo::Result<u32> {
        self.with(|a| a.state)
    }
    #[zbus(property)]
    fn vpn(&self) -> zbus::fdo::Result<bool> {
        self.with(|a| a.vpn)
    }
    #[zbus(property)]
    fn connection(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        self.with(|a| opath(&a.connection))
    }
    #[zbus(property)]
    fn ip4_config(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        self.with(|a| opath(&a.ip4_config))
    }
    #[zbus(property)]
    fn devices(&self) -> zbus::fdo::Result<Vec<OwnedObjectPath>> {
        self.with(|a| a.devices.iter().map(|d| opath(d)).collect())
    }
}

struct VpnConn(Shared, String);

#[zbus::interface(name = "org.freedesktop.NetworkManager.VPN.Connection")]
impl VpnConn {
    #[zbus(property)]
    fn vpn_state(&self) -> zbus::fdo::Result<u32> {
        lock(&self.0)
            .actives
            .get(&self.1)
            .map(|a| a.vpn_state)
            .ok_or_else(|| zbus::fdo::Error::UnknownObject(self.1.clone()))
    }
}

struct Ip4Config(Shared, String);

#[zbus::interface(name = "org.freedesktop.NetworkManager.IP4Config")]
impl Ip4Config {
    #[zbus(property)]
    fn address_data(&self) -> Vec<HashMap<String, OwnedValue>> {
        lock(&self.0)
            .ip4
            .get(&self.1)
            .map(|list| {
                list.iter()
                    .map(|a| {
                        HashMap::from([
                            ("address".to_string(), owned(Value::from(a.as_str()))),
                            ("prefix".to_string(), owned(Value::from(24u32))),
                        ])
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

struct Device(Shared, String);

#[zbus::interface(name = "org.freedesktop.NetworkManager.Device")]
impl Device {
    #[zbus(property)]
    fn ip_interface(&self) -> String {
        lock(&self.0).devices.get(&self.1).cloned().unwrap_or_default()
    }

    #[zbus(signal)]
    async fn state_changed(
        emitter: &SignalEmitter<'_>,
        new_state: u32,
        old_state: u32,
        reason: u32,
    ) -> zbus::Result<()>;
}

// ---- polkit ----

struct Authority(Shared);

#[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
impl Authority {
    /// The real signature: `((sa{sv})sa{ss}us) → ((bba{ss}))`.
    fn check_authorization(
        &self,
        subject: (String, HashMap<String, OwnedValue>),
        action_id: String,
        _details: HashMap<String, String>,
        flags: u32,
        _cancellation_id: String,
        #[zbus(header)] hdr: Header<'_>,
    ) -> ((bool, bool, HashMap<String, String>),) {
        let name =
            subject.1.get("name").and_then(|v| String::try_from(v.try_clone().unwrap()).ok()).unwrap_or_default();
        record(
            &self.0,
            &hdr,
            Call {
                method: "CheckAuthorization".into(),
                flags_arg: flags,
                action: action_id,
                subject: (subject.0, name),
                ..Call::default()
            },
        );
        let answer = match lock(&self.0).polkit.unwrap_or(Polkit::No) {
            Polkit::Yes => (true, false),
            Polkit::Challenge => (false, true),
            Polkit::No => (false, false),
        };
        ((answer.0, answer.1, HashMap::new()),)
    }
}

// ---- object bookkeeping ----

fn new_profile_locked(s: &mut State, settings: NmSettings, flags: u32) -> String {
    s.next += 1;
    let path = format!("{SETTINGS}/{}", s.next);
    s.profiles.insert(path.clone(), Profile { settings, flags });
    path
}

fn new_active_locked(s: &mut State, a: Active) -> String {
    s.next += 1;
    let path = format!("{ROOT}/ActiveConnection/{}", s.next);
    s.actives.insert(path.clone(), a);
    path
}

async fn serve_profile(server: &zbus::ObjectServer, state: &Shared, path: &str) {
    server.at(path, ProfileObj(state.clone(), path.to_string())).await.unwrap();
}

async fn serve_active(server: &zbus::ObjectServer, state: &Shared, path: &str, vpn: bool) {
    server.at(path, ActiveConn(state.clone(), path.to_string())).await.unwrap();
    if vpn {
        server.at(path, VpnConn(state.clone(), path.to_string())).await.unwrap();
    }
}

/// Serializes the fakes of one test binary: the bus names have one owner.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// No fake for the duration of the guard: NetworkManager and polkit are not on the bus.
pub fn nobody() -> MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner)
}

pub struct FakeNm {
    pub conn: Connection,
    pub state: Shared,
    _turn: MutexGuard<'static, ()>,
}

impl FakeNm {
    /// Serves NM and polkit on the session bus; polkit answers `polkit` to every check.
    pub fn start(polkit: Polkit) -> FakeNm {
        let turn = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
        let state: Shared = Arc::new(Mutex::new(State { polkit: Some(polkit), ..State::default() }));
        let conn = zbus::blocking::connection::Builder::session()
            .unwrap()
            .serve_at(ROOT, Root(state.clone()))
            .unwrap()
            .serve_at(SETTINGS, SettingsObj(state.clone()))
            .unwrap()
            .serve_at(AUTHORITY, Authority(state.clone()))
            .unwrap()
            .name(NM)
            .unwrap()
            .name(POLKIT)
            .unwrap()
            .build()
            .expect("a private session bus (run under dbus-run-session)");
        FakeNm { conn, state, _turn: turn }
    }

    pub fn set_polkit(&self, polkit: Polkit) {
        lock(&self.state).polkit = Some(polkit);
    }

    pub fn calls(&self) -> Vec<Call> {
        lock(&self.state).calls.clone()
    }

    /// The UUIDs of the deleted profiles, in order.
    pub fn deleted(&self) -> Vec<String> {
        lock(&self.state).deleted.clone()
    }

    /// A saved profile (`vpn`, L2TP) with this UUID (also its id), permissions and `Settings.Connection.Flags`.
    pub fn add_profile(&self, uuid: &str, permissions: &[&str], flags: u32) -> String {
        let settings: NmSettings = HashMap::from([
            (
                "connection".to_string(),
                HashMap::from([
                    ("id".to_string(), owned(Value::from(uuid))),
                    ("uuid".to_string(), owned(Value::from(uuid))),
                    ("type".to_string(), owned(Value::from("vpn"))),
                    (
                        "permissions".to_string(),
                        owned(Value::from(permissions.iter().map(|p| p.to_string()).collect::<Vec<_>>())),
                    ),
                ]),
            ),
            (
                "vpn".to_string(),
                HashMap::from([
                    ("service-type".to_string(), owned(Value::from("org.freedesktop.NetworkManager.l2tp"))),
                    (
                        "data".to_string(),
                        owned(Value::from(HashMap::from([("gateway".to_string(), "vpn.example.com".to_string())]))),
                    ),
                ]),
            ),
        ]);
        self.add_profile_settings(settings, flags)
    }

    /// A saved profile with the given settings.
    pub fn add_profile_settings(&self, settings: NmSettings, flags: u32) -> String {
        let path = new_profile_locked(&mut lock(&self.state), settings, flags);
        self.conn.object_server().at(path.as_str(), ProfileObj(self.state.clone(), path.clone())).unwrap();
        path
    }

    fn add_ip4(&self, address: Option<&str>) -> String {
        let Some(address) = address else { return "/".into() };
        let path = {
            let mut s = lock(&self.state);
            s.next += 1;
            let path = format!("{ROOT}/IP4Config/{}", s.next);
            s.ip4.insert(path.clone(), vec![address.to_string()]);
            path
        };
        self.conn.object_server().at(path.as_str(), Ip4Config(self.state.clone(), path.clone())).unwrap();
        path
    }

    /// An active VPN (`Type = vpn`) of a new profile with `service_type`, in `state` and `vpn_state`, with an
    /// IPv4 address in its `Ip4Config` or none. Returns the active connection's path.
    pub fn add_active_vpn(
        &self,
        uuid: &str,
        service_type: &str,
        state: u32,
        vpn_state: u32,
        ip4: Option<&str>,
    ) -> String {
        let settings: NmSettings = HashMap::from([
            (
                "connection".to_string(),
                HashMap::from([
                    ("id".to_string(), owned(Value::from(uuid))),
                    ("uuid".to_string(), owned(Value::from(uuid))),
                    ("type".to_string(), owned(Value::from("vpn"))),
                ]),
            ),
            ("vpn".to_string(), HashMap::from([("service-type".to_string(), owned(Value::from(service_type)))])),
        ]);
        let profile = self.add_profile_settings(settings, 0);
        let ip4_config = self.add_ip4(ip4);
        let path = new_active_locked(
            &mut lock(&self.state),
            Active {
                uuid: uuid.into(),
                id: uuid.into(),
                nm_type: "vpn".into(),
                state,
                vpn: true,
                vpn_state,
                connection: profile,
                ip4_config,
                devices: vec![],
            },
        );
        let server = self.conn.object_server();
        server.at(path.as_str(), ActiveConn(self.state.clone(), path.clone())).unwrap();
        server.at(path.as_str(), VpnConn(self.state.clone(), path.clone())).unwrap();
        path
    }

    /// An active non-VPN connection (`wireguard`, `802-3-ethernet`, …) on a device with interface `iface`.
    pub fn add_active(&self, uuid: &str, nm_type: &str, state: u32, ip4: Option<&str>, iface: &str) -> String {
        let device = {
            let mut s = lock(&self.state);
            s.next += 1;
            let path = format!("{ROOT}/Devices/{}", s.next);
            s.devices.insert(path.clone(), iface.to_string());
            path
        };
        self.conn.object_server().at(device.as_str(), Device(self.state.clone(), device.clone())).unwrap();
        let ip4_config = self.add_ip4(ip4);
        let path = new_active_locked(
            &mut lock(&self.state),
            Active {
                uuid: uuid.into(),
                id: uuid.into(),
                nm_type: nm_type.into(),
                state,
                vpn: false,
                vpn_state: 0,
                connection: "/".into(),
                ip4_config,
                devices: vec![device],
            },
        );
        self.conn.object_server().at(path.as_str(), ActiveConn(self.state.clone(), path.clone())).unwrap();
        path
    }

    /// `VpnStateChanged(state, reason)` from the active connection at `path` (its `VpnState` follows).
    pub fn emit_vpn_state(&self, path: &str, state: u32, reason: u32) {
        if let Some(a) = lock(&self.state).actives.get_mut(path) {
            a.vpn_state = state;
        }
        self.conn
            .emit_signal(
                None::<&str>,
                path,
                "org.freedesktop.NetworkManager.VPN.Connection",
                "VpnStateChanged",
                &(state, reason),
            )
            .unwrap();
    }

    /// Any signal from NM's name (the watcher's other subscriptions).
    pub fn emit<B>(&self, path: &str, iface: &str, member: &str, body: &B)
    where
        B: zbus::export::serde::ser::Serialize + zbus::zvariant::DynamicType,
    {
        self.conn.emit_signal(None::<&str>, path, iface, member, body).unwrap();
    }
}

impl Drop for FakeNm {
    fn drop(&mut self) {
        // Free the names now, before the next test's fake asks for them.
        let _ = self.conn.release_name(NM);
        let _ = self.conn.release_name(POLKIT);
    }
}

/// A WireGuard plan's settings as `nm_plan` writes them, private to `user`.
pub fn wireguard_settings(user: &str) -> Settings {
    let mut s = Settings::new();
    let c = s.entry("connection".into()).or_default();
    c.insert("id".into(), NmValue::Str("Office".into()));
    c.insert("uuid".into(), NmValue::Str("0b7e2a4c-1d3f-8a5b-9c6d-7e8f9a0b1c2d".into()));
    c.insert("type".into(), NmValue::Str("wireguard".into()));
    c.insert("interface-name".into(), NmValue::Str("lvpn0".into()));
    c.insert("autoconnect".into(), NmValue::Bool(false));
    c.insert("permissions".into(), NmValue::StrList(vec![format!("user:{user}")]));
    let wg = s.entry("wireguard".into()).or_default();
    wg.insert("private-key-flags".into(), NmValue::U32(1));
    wg.insert(
        "peers".into(),
        NmValue::WgPeers(vec![NmWgPeer {
            public_key: "x8N2c5yQ6wHn0Vt3sYp4G1rK7bJ9mL2dF5hE8aZ0uW4=".into(),
            endpoint: Some("vpn.example.com:51820".into()),
            allowed_ips: vec!["10.99.0.0/24".into()],
            persistent_keepalive: 25,
            has_preshared_key: true,
        }]),
    );
    let ip4 = s.entry("ipv4".into()).or_default();
    ip4.insert("method".into(), NmValue::Str("manual".into()));
    ip4.insert("address-data".into(), NmValue::Addresses(vec![NmAddress { address: "10.99.12.2".into(), prefix: 32 }]));
    ip4.insert("dns-priority".into(), NmValue::I32(50));
    s
}
