//! NetworkManager over the system bus: add-and-activate (volatile, not bound to this process), deactivate,
//! the active connections with their VPN state, address and interface, the user's profiles, and the change
//! signals.
use crate::lin::nm::polkit::{self, Authorization};
use crate::lin::nm::value::DbusSettings;
use crate::pure::nm::state::{ActiveState, VpnState};
use macvpn_core::l10n;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use zbus::blocking::{Connection, MessageIterator};
use zbus::message::{Message, Type as MessageType};
use zbus::zvariant::{DynamicType, ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{MatchRule, MessageStream};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NmError {
    /// polkit would ask, or said no (localized text).
    NotAuthorized(String),
    /// NetworkManager is not on the bus.
    Unavailable(String),
    Failed(String),
}

impl NmError {
    pub fn message(&self) -> String {
        match self {
            NmError::NotAuthorized(m) | NmError::Unavailable(m) | NmError::Failed(m) => m.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activation {
    pub settings_path: String,
    pub active_path: String,
}

/// One active connection.
#[derive(Debug, Clone, PartialEq)]
pub struct ActiveInfo {
    pub path: String,
    pub uuid: String,
    pub id: String,
    /// `vpn`, `wireguard`, `802-3-ethernet`, …
    pub nm_type: String,
    /// `vpn.service-type` for VPNs.
    pub service_type: Option<String>,
    pub state: ActiveState,
    /// VPN connections only.
    pub vpn_state: Option<VpnState>,
    /// The first IPv4 address of its `Ip4Config` (`10.99.13.5`, no prefix).
    pub ip4: Option<String>,
    /// The device's interface for non-VPN types (`IpInterface`).
    pub ip_iface: Option<String>,
}

/// One saved profile the user can see (system VPNs).
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileInfo {
    pub path: String,
    pub uuid: String,
    pub id: String,
    pub nm_type: String,
    pub service_type: Option<String>,
    pub permissions: Vec<String>,
    /// `vpn.data` (never secrets), or for WireGuard the first peer's endpoint as `endpoint`.
    pub data: BTreeMap<String, String>,
    /// `Settings.Connection.Flags`: 1 unsaved, 2 nm-generated, 4 volatile, 8 external.
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NmEvent {
    /// An active connection appeared, changed state or went away.
    ActiveChanged,
    /// A VPN connection's `VpnStateChanged(state, reason)`.
    VpnState { active_path: String, state: VpnState, reason: u32 },
    /// An active connection's `Connection.Active.StateChanged(state, reason)` (`NMActiveConnectionState`,
    /// `NMActiveConnectionStateReason`): also "an active connection changed state" for the watchers that only need
    /// that; WireGuard's end reason comes only from here (it has no VPN state).
    ActiveState { active_path: String, state: u32, reason: u32 },
    /// A profile was added, changed or removed.
    ProfilesChanged,
    /// NM's primary connection, connectivity, state or device list, a device's state or an IP configuration changed
    /// (the network watcher, `lin::net::LinNetwork::watch`).
    NetworkChanged,
}

pub struct NmClient {
    bus: Connection,
}

/// What `GetConnectionByUuid` said.
enum Lookup {
    Found(OwnedObjectPath),
    Missing,
    /// NM's `PermissionDenied`: a profile the caller may not see.
    Hidden,
}

/// Keeps the signal subscriptions alive; dropping it stops them.
pub struct WatchGuard(pub Box<dyn Send>);

const NM: &str = "org.freedesktop.NetworkManager";
const ROOT: &str = "/org/freedesktop/NetworkManager";
const SETTINGS: &str = "/org/freedesktop/NetworkManager/Settings";
const IF_SETTINGS: &str = "org.freedesktop.NetworkManager.Settings";
const IF_PROFILE: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const IF_ACTIVE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const IF_VPN: &str = "org.freedesktop.NetworkManager.VPN.Connection";
const IF_IP4: &str = "org.freedesktop.NetworkManager.IP4Config";
const IF_IP6: &str = "org.freedesktop.NetworkManager.IP6Config";
const IF_DEVICE: &str = "org.freedesktop.NetworkManager.Device";
const IF_PROPERTIES: &str = "org.freedesktop.DBus.Properties";

/// `Settings.Connection.Flags`: NM_SETTINGS_CONNECTION_FLAG_VOLATILE.
const FLAG_VOLATILE: u32 = 4;

type NmSettings = HashMap<String, HashMap<String, OwnedValue>>;

/// A signal's event, or `None` when it means nothing to LinVPN.
type SignalMap = fn(&Message) -> Option<NmEvent>;

/// One match rule of the watch: `(path, interface, member, map)`; the sender is always NetworkManager.
type Subscription = (Option<&'static str>, &'static str, Option<&'static str>, SignalMap);

fn not_authorized() -> NmError {
    NmError::NotAuthorized(l10n::tr(
        "LinVPN may not change this computer's network settings without asking for a password. Log in at the desktop and try again.",
        &[],
    ))
}

fn unavailable() -> NmError {
    NmError::Unavailable(l10n::tr("NetworkManager is not running.", &[]))
}

/// NM's D-Bus errors: its permission errors (`…PermissionDenied`) → `NotAuthorized`, no owner of NM's name →
/// `Unavailable`, the rest → `Failed` with NM's own message (NM's messages never contain a secret).
fn nm_error(e: zbus::Error) -> NmError {
    let (name, message) = match &e {
        zbus::Error::MethodError(name, message, _) => (name.to_string(), message.clone()),
        zbus::Error::FDO(fdo) => match fdo.as_ref() {
            zbus::fdo::Error::ServiceUnknown(_) | zbus::fdo::Error::NameHasNoOwner(_) => return unavailable(),
            other => return NmError::Failed(other.to_string()),
        },
        _ => return NmError::Failed(e.to_string()),
    };
    if matches!(
        name.as_str(),
        "org.freedesktop.DBus.Error.ServiceUnknown" | "org.freedesktop.DBus.Error.NameHasNoOwner"
    ) {
        return unavailable();
    }
    if name.starts_with("org.freedesktop.NetworkManager") && name.ends_with(".PermissionDenied") {
        return not_authorized();
    }
    NmError::Failed(message.unwrap_or(name))
}

fn object_path(path: &str) -> Result<ObjectPath<'_>, NmError> {
    ObjectPath::try_from(path).map_err(|_| NmError::Failed(format!("not a D-Bus object path: {path}")))
}

fn is_no_object(path: &OwnedObjectPath) -> bool {
    path.as_str() == "/"
}

/// `connection.permissions` entries are `user:<name>` or `user:<name>:` (NM keeps a reserved third field).
fn permission_user(entry: &str) -> Option<&str> {
    let rest = entry.strip_prefix("user:")?;
    Some(rest.strip_suffix(':').unwrap_or(rest))
}

fn string_of(settings: &NmSettings, setting: &str, key: &str) -> Option<String> {
    let v = settings.get(setting)?.get(key)?.try_clone().ok()?;
    String::try_from(v).ok()
}

fn strings_of(settings: &NmSettings, setting: &str, key: &str) -> Vec<String> {
    settings
        .get(setting)
        .and_then(|s| s.get(key))
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| Vec::<String>::try_from(v).ok())
        .unwrap_or_default()
}

/// The `aa{sv}` value of a setting key or property as a list of dictionaries.
fn dict_list(v: OwnedValue) -> Vec<HashMap<String, OwnedValue>> {
    Vec::<HashMap<String, OwnedValue>>::try_from(v).unwrap_or_default()
}

fn dict_string(d: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    d.get(key).and_then(|v| v.try_clone().ok()).and_then(|v| String::try_from(v).ok())
}

impl NmClient {
    pub fn new(bus: Connection) -> NmClient {
        NmClient { bus }
    }

    pub fn bus(&self) -> &Connection {
        &self.bus
    }

    fn call<B>(&self, path: &str, iface: &str, method: &str, body: &B) -> Result<Message, NmError>
    where
        B: zbus::export::serde::ser::Serialize + DynamicType,
    {
        self.bus.call_method(Some(NM), object_path(path)?, Some(iface), method, body).map_err(nm_error)
    }

    fn prop<T: TryFrom<OwnedValue>>(&self, path: &str, iface: &str, name: &str) -> Result<T, NmError> {
        let reply = self.call(path, IF_PROPERTIES, "Get", &(iface, name))?;
        let v: OwnedValue = reply.body().deserialize().map_err(nm_error)?;
        T::try_from(v).map_err(|_| NmError::Failed(format!("NetworkManager: unexpected type of {iface}.{name}")))
    }

    fn get_settings(&self, profile_path: &str) -> Result<NmSettings, NmError> {
        let reply = self.call(profile_path, IF_PROFILE, "GetSettings", &())?;
        reply.body().deserialize().map_err(nm_error)
    }

    /// The polkit pre-check (R1): anything but "authorized without a challenge" refuses, before any write.
    fn authorize(&self) -> Result<(), NmError> {
        match polkit::check_nm_write(&self.bus) {
            Authorization::Authorized => Ok(()),
            Authorization::NeedsPrompt | Authorization::Denied | Authorization::Unknown(_) => Err(not_authorized()),
        }
    }

    /// NM's `Version`.
    pub fn version(&self) -> Option<String> {
        self.prop::<String>(ROOT, NM, "Version").ok()
    }

    /// polkit first (`polkit::check_nm_write`), then `AddAndActivateConnection2(settings, "/", "/",
    /// {persist: volatile})` without the interactive flag. Volatile: NM deletes the profile once it is deactivated.
    /// No `bind-activation`: the tunnel outlives LinVPN's process ("Quit, Keep Them Running", a crash) as on macOS
    /// and Windows; the next launch adopts it (`Engine::adopt`).
    pub fn add_and_activate(&self, settings: &DbusSettings) -> Result<Activation, NmError> {
        self.authorize()?;
        let none = ObjectPath::from_static_str_unchecked("/");
        let options: HashMap<&str, Value<'_>> = HashMap::from([("persist", Value::from("volatile"))]);
        let reply = self.call(ROOT, NM, "AddAndActivateConnection2", &(settings, &none, &none, options))?;
        let (settings_path, active_path, _result): (OwnedObjectPath, OwnedObjectPath, HashMap<String, OwnedValue>) =
            reply.body().deserialize().map_err(nm_error)?;
        Ok(Activation { settings_path: settings_path.to_string(), active_path: active_path.to_string() })
    }

    /// `ActivateConnection(profile, "/", "/")` of an existing profile (a system VPN), after the polkit check.
    pub fn activate_profile(&self, profile_path: &str) -> Result<Activation, NmError> {
        let profile = object_path(profile_path)?;
        self.authorize()?;
        let none = ObjectPath::from_static_str_unchecked("/");
        let reply = self.call(ROOT, NM, "ActivateConnection", &(&profile, &none, &none))?;
        let active_path: OwnedObjectPath = reply.body().deserialize().map_err(nm_error)?;
        Ok(Activation { settings_path: profile_path.to_string(), active_path: active_path.to_string() })
    }

    /// `DeactivateConnection(active)`, after the polkit check.
    pub fn deactivate(&self, active_path: &str) -> Result<(), NmError> {
        let active = object_path(active_path)?;
        self.authorize()?;
        self.call(ROOT, NM, "DeactivateConnection", &(&active,))?;
        Ok(())
    }

    /// Deletes the profile with `uuid` only if it is volatile and private to `user` (a crashed run's leftover).
    /// `Ok(false)`: none.
    pub fn delete_own_volatile(&self, uuid: &str, user: &str) -> Result<bool, NmError> {
        let Some(path) = self.own_volatile(uuid, user)? else { return Ok(false) };
        self.authorize()?;
        self.call(path.as_str(), IF_PROFILE, "Delete", &())?;
        Ok(true)
    }

    /// Whether the profile with `uuid` is volatile and private to `user` (LinVPN's own; the engine adopts only
    /// such a connection, R9).
    pub fn is_own_volatile(&self, uuid: &str, user: &str) -> Result<bool, NmError> {
        Ok(self.own_volatile(uuid, user)?.is_some())
    }

    /// The settings path of the profile with `uuid` if it is volatile and private to `user`.
    pub fn own_volatile_path(&self, uuid: &str, user: &str) -> Result<Option<String>, NmError> {
        Ok(self.own_volatile(uuid, user)?.map(|p| p.to_string()))
    }

    /// Whether a profile with `uuid` exists that is not `user`'s own volatile one: hidden from the user (NM refuses
    /// `GetConnectionByUuid` of a profile whose permissions leave the caller out) or visible but someone else's
    /// (security review L2: another user created a profile with this connection's derived UUID first).
    pub fn uuid_taken_by_another(&self, uuid: &str, user: &str) -> bool {
        match self.profile_by_uuid(uuid) {
            Ok(Lookup::Hidden) => true,
            Ok(Lookup::Found(_)) => !matches!(self.own_volatile(uuid, user), Ok(Some(_))),
            _ => false,
        }
    }

    /// `GetConnectionByUuid`, telling a missing profile from one the caller may not see.
    fn profile_by_uuid(&self, uuid: &str) -> Result<Lookup, NmError> {
        let reply = self.bus.call_method(Some(NM), SETTINGS, Some(IF_SETTINGS), "GetConnectionByUuid", &(uuid,));
        match reply {
            Ok(reply) => Ok(Lookup::Found(reply.body().deserialize().map_err(nm_error)?)),
            Err(zbus::Error::MethodError(name, _, _)) if name.as_str().ends_with("Settings.PermissionDenied") => {
                Ok(Lookup::Hidden)
            }
            Err(e) => match nm_error(e) {
                NmError::Failed(_) => Ok(Lookup::Missing), // no such profile (`…Settings.InvalidConnection`)
                other => Err(other),
            },
        }
    }

    /// The path of the profile with `uuid` if it is volatile and private to `user`.
    fn own_volatile(&self, uuid: &str, user: &str) -> Result<Option<OwnedObjectPath>, NmError> {
        // Another user's profile with this UUID is not ours (and is never deleted, only reported).
        let path = match self.profile_by_uuid(uuid)? {
            Lookup::Found(path) => path,
            Lookup::Missing | Lookup::Hidden => return Ok(None),
        };
        let flags: u32 = self.prop(path.as_str(), IF_PROFILE, "Flags")?;
        if flags & FLAG_VOLATILE == 0 {
            return Ok(None);
        }
        let settings = self.get_settings(path.as_str())?;
        let permissions = strings_of(&settings, "connection", "permissions");
        let ours = string_of(&settings, "connection", "uuid").as_deref() == Some(uuid)
            && permissions.len() == 1
            && permission_user(&permissions[0]) == Some(user);
        Ok(ours.then_some(path))
    }

    /// The active connections; one that goes away while it is read is left out.
    pub fn active(&self) -> Result<Vec<ActiveInfo>, NmError> {
        let paths: Vec<OwnedObjectPath> = self.prop(ROOT, NM, "ActiveConnections")?;
        let mut out = Vec::with_capacity(paths.len());
        for path in paths {
            match self.active_info(path.as_str()) {
                Ok(info) => out.push(info),
                Err(e @ NmError::Unavailable(_)) => return Err(e),
                Err(_) => {}
            }
        }
        Ok(out)
    }

    fn active_info(&self, path: &str) -> Result<ActiveInfo, NmError> {
        let uuid: String = self.prop(path, IF_ACTIVE, "Uuid")?;
        let id: String = self.prop(path, IF_ACTIVE, "Id")?;
        let nm_type: String = self.prop(path, IF_ACTIVE, "Type")?;
        let state: u32 = self.prop(path, IF_ACTIVE, "State")?;
        let vpn: bool = self.prop(path, IF_ACTIVE, "Vpn")?;
        let (vpn_state, service_type) = if vpn {
            let vpn_state = self.prop::<u32>(path, IF_VPN, "VpnState").ok().map(VpnState::from_u32);
            let service_type = self
                .prop::<OwnedObjectPath>(path, IF_ACTIVE, "Connection")
                .ok()
                .filter(|p| !is_no_object(p))
                .and_then(|p| self.get_settings(p.as_str()).ok())
                .and_then(|s| string_of(&s, "vpn", "service-type"));
            (vpn_state, service_type)
        } else {
            (None, None)
        };
        let ip4 = self
            .prop::<OwnedObjectPath>(path, IF_ACTIVE, "Ip4Config")
            .ok()
            .filter(|p| !is_no_object(p))
            .and_then(|p| self.prop::<OwnedValue>(p.as_str(), IF_IP4, "AddressData").ok())
            .and_then(|v| dict_list(v).first().and_then(|d| dict_string(d, "address")));
        let ip_iface = if vpn {
            None
        } else {
            self.prop::<Vec<OwnedObjectPath>>(path, IF_ACTIVE, "Devices")
                .ok()
                .and_then(|devices| devices.into_iter().next())
                .and_then(|d| self.prop::<String>(d.as_str(), IF_DEVICE, "IpInterface").ok())
                .filter(|name| !name.is_empty())
        };
        Ok(ActiveInfo {
            path: path.to_string(),
            uuid,
            id,
            nm_type,
            service_type,
            state: ActiveState::from_u32(state),
            vpn_state,
            ip4,
            ip_iface,
        })
    }

    /// The saved profiles the user can see (NM refuses `GetSettings` of the others; they are left out).
    pub fn profiles(&self) -> Result<Vec<ProfileInfo>, NmError> {
        let reply = self.call(SETTINGS, IF_SETTINGS, "ListConnections", &())?;
        let paths: Vec<OwnedObjectPath> = reply.body().deserialize().map_err(nm_error)?;
        let mut out = Vec::with_capacity(paths.len());
        for path in paths {
            let settings = match self.get_settings(path.as_str()) {
                Ok(s) => s,
                Err(e @ NmError::Unavailable(_)) => return Err(e),
                Err(_) => continue,
            };
            let flags = self.prop::<u32>(path.as_str(), IF_PROFILE, "Flags").unwrap_or(0);
            let mut data: BTreeMap<String, String> = settings
                .get("vpn")
                .and_then(|s| s.get("data"))
                .and_then(|v| v.try_clone().ok())
                .and_then(|v| HashMap::<String, String>::try_from(v).ok())
                .map(|d| d.into_iter().collect())
                .unwrap_or_default();
            if let Some(endpoint) = settings
                .get("wireguard")
                .and_then(|s| s.get("peers"))
                .and_then(|v| v.try_clone().ok())
                .and_then(|v| dict_list(v).first().and_then(|p| dict_string(p, "endpoint")))
            {
                data.insert("endpoint".into(), endpoint);
            }
            out.push(ProfileInfo {
                path: path.to_string(),
                uuid: string_of(&settings, "connection", "uuid").unwrap_or_default(),
                id: string_of(&settings, "connection", "id").unwrap_or_default(),
                nm_type: string_of(&settings, "connection", "type").unwrap_or_default(),
                service_type: string_of(&settings, "vpn", "service-type"),
                permissions: strings_of(&settings, "connection", "permissions"),
                data,
                flags,
            });
        }
        Ok(out)
    }

    /// Subscribes to NM's change signals; each subscription is read on its own thread until the guard drops.
    pub fn watch(&self, on: Box<dyn Fn(NmEvent) + Send + Sync>) -> zbus::Result<WatchGuard> {
        let on: Arc<dyn Fn(NmEvent) + Send + Sync> = Arc::from(on);
        let rules: [Subscription; 6] = [
            (None, IF_PROPERTIES, Some("PropertiesChanged"), properties_changed),
            (None, IF_VPN, Some("VpnStateChanged"), vpn_state),
            (None, IF_ACTIVE, Some("StateChanged"), active_state),
            (Some(SETTINGS), IF_SETTINGS, None, settings_signal),
            (None, IF_PROFILE, Some("Updated"), |_| Some(NmEvent::ProfilesChanged)),
            (None, IF_DEVICE, Some("StateChanged"), |_| Some(NmEvent::NetworkChanged)),
        ];
        let mut stops = Vec::with_capacity(rules.len());
        // Every match rule is in place before `watch` returns, so no signal after it is missed.
        let mut streams = Vec::with_capacity(rules.len());
        for (path, iface, member, map) in rules {
            let mut rule = MatchRule::builder().msg_type(MessageType::Signal).sender(NM)?.interface(iface)?;
            if let Some(path) = path {
                rule = rule.path(path)?;
            }
            if let Some(member) = member {
                rule = rule.member(member)?;
            }
            let stream = MessageIterator::for_match_rule(rule.build(), &self.bus, Some(64))?.into_inner();
            streams.push((stream, map));
        }
        for (stream, map) in streams {
            let (stop, stopped) = async_channel::bounded::<()>(1);
            stops.push(stop);
            let on = on.clone();
            std::thread::Builder::new()
                .name("linvpn-nm-watch".into())
                .spawn(move || pump(stream, stopped, map, on))
                .map_err(|e| zbus::Error::Failure(e.to_string()))?;
        }
        Ok(WatchGuard(Box::new(stops)))
    }
}

/// `Connection.Active.StateChanged(state, reason)` of the active connection at the signal's path.
fn active_state(msg: &Message) -> Option<NmEvent> {
    let (state, reason): (u32, u32) = msg.body().deserialize().ok()?;
    let active_path = msg.header().path()?.to_string();
    Some(NmEvent::ActiveState { active_path, state, reason })
}

/// Reads one subscription until its stop channel closes (the guard dropped) or the bus connection ends.
fn pump(
    mut stream: MessageStream,
    stopped: async_channel::Receiver<()>,
    map: SignalMap,
    on: Arc<dyn Fn(NmEvent) + Send + Sync>,
) {
    use futures_lite::StreamExt;
    async_io::block_on(async move {
        loop {
            let next = futures_lite::future::or(async { Some(stream.next().await) }, async {
                let _ = stopped.recv().await;
                None
            })
            .await;
            match next {
                Some(Some(Ok(msg))) => {
                    if let Some(event) = map(&msg) {
                        on(event);
                    }
                }
                Some(Some(Err(_))) => {}
                Some(None) | None => break,
            }
        }
    });
}

/// A `PropertiesChanged` of NM's: on NM itself the active connections, or the network (primary connection,
/// connectivity, state, the device list); any change of an IP configuration is the network too. The rest (an access
/// point's signal strength, a device's statistics, …) means nothing.
fn properties_changed(msg: &Message) -> Option<NmEvent> {
    let (iface, changed, _invalidated): (String, HashMap<String, OwnedValue>, Vec<String>) =
        msg.body().deserialize().ok()?;
    match iface.as_str() {
        NM if msg.header().path().is_some_and(|p| p.as_str() == ROOT) => {
            if changed.contains_key("ActiveConnections") {
                Some(NmEvent::ActiveChanged)
            } else if ["PrimaryConnection", "Connectivity", "State", "Devices"].iter().any(|k| changed.contains_key(*k))
            {
                Some(NmEvent::NetworkChanged)
            } else {
                None
            }
        }
        IF_IP4 | IF_IP6 => Some(NmEvent::NetworkChanged),
        _ => None,
    }
}

fn vpn_state(msg: &Message) -> Option<NmEvent> {
    let (state, reason): (u32, u32) = msg.body().deserialize().ok()?;
    let active_path = msg.header().path()?.to_string();
    Some(NmEvent::VpnState { active_path, state: VpnState::from_u32(state), reason })
}

fn settings_signal(msg: &Message) -> Option<NmEvent> {
    let member = msg.header().member()?.to_string();
    matches!(member.as_str(), "NewConnection" | "ConnectionRemoved").then_some(NmEvent::ProfilesChanged)
}
