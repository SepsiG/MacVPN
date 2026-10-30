//! Task 21's additions to the fake NetworkManager: an agent manager on the fake's own connection (the fake owns NM's
//! name, so the agent it records is asked by "NM"), the VPN state walk after the next `AddAndActivateConnection2`
//! ([`FakeNm::activate_next`]), and NM asking LinVPN's agent for an activation's secrets
//! ([`FakeNm::as_nm_get_secrets`]).
//!
//! The fakes of one test binary run one at a time (`ONE_AT_A_TIME`), so the registered agent and the last activation
//! are process-wide here.

use super::{
    ActiveConn, FakeNm, Ip4Config, NmSettings, Polkit, ROOT, Shared, VpnConn, clone_settings, lock, settings_str,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zbus::blocking::Connection;
use zbus::zvariant::{ObjectPath, OwnedValue, Value};

const MANAGER_PATH: &str = "/org/freedesktop/NetworkManager/AgentManager";
const AGENT_PATH: &str = "/org/freedesktop/NetworkManager/SecretAgent";
const AGENT_IFACE: &str = "org.freedesktop.NetworkManager.SecretAgent";
const VPN_IFACE: &str = "org.freedesktop.NetworkManager.VPN.Connection";

/// The unique name of the last registered agent.
static AGENT: Mutex<Option<String>> = Mutex::new(None);
/// The agent manager refuses the next registrations as NM refuses a second agent of the user with LinVPN's
/// identifier.
static REFUSE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// `(active path, NM UUID, profile path)` of the last activation the fake walked.
static LAST: Mutex<Option<(String, String, String)>> = Mutex::new(None);

/// Where the next activation ends.
#[derive(Debug, Clone, Copy)]
pub enum Outcome {
    /// `Prepare → Connect → IpConfigGet → Activated` with this address (WireGuard: activated with it).
    Activated { ip4: &'static str },
    /// Activated without an `Ip4Config` yet (WireGuard, IKEv2: the address comes after); [`FakeNm::set_last_ip4`].
    ActivatedAddressLater,
    /// `Prepare → Connect → Failed(reason)`, then NM drops the active connection and the volatile profile.
    Failed { reason: u32 },
    /// `Prepare → Connect`, and it stays there (a CRV1 prompt).
    StayConnecting,
}

/// A temporary folder removed when dropped.
pub struct Tmp(PathBuf);

impl Tmp {
    pub fn new(tag: &str) -> Tmp {
        let dir = std::env::temp_dir().join(format!("linvpn-nm-engine-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Tmp(dir)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// NM's agent manager, served on the fake NM's connection.
pub struct AgentManager;

struct Manager;

/// NM's `org.freedesktop.NetworkManager.AgentManager.*` errors.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.NetworkManager.AgentManager")]
enum ManagerError {
    #[zbus(error)]
    ZBus(zbus::Error),
    PermissionDenied(String),
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.AgentManager")]
impl Manager {
    fn register_with_capabilities(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        _identifier: String,
        _capabilities: u32,
    ) -> Result<(), ManagerError> {
        if REFUSE.load(std::sync::atomic::Ordering::SeqCst) {
            // NM 1.54's `nm-agent-manager.c` text.
            return Err(ManagerError::PermissionDenied(
                "An agent with this ID is already registered for this user.".into(),
            ));
        }
        *AGENT.lock().unwrap_or_else(|p| p.into_inner()) = header.sender().map(|s| s.to_string());
        Ok(())
    }

    fn unregister(&self) {}
}

/// A fake NM (polkit `Yes`) with an agent manager, and a temporary folder.
pub fn with_agent_manager() -> (FakeNm, AgentManager, Tmp) {
    with_agent_manager_polkit(Polkit::Yes)
}

pub fn with_agent_manager_polkit(polkit: Polkit) -> (FakeNm, AgentManager, Tmp) {
    let nm = FakeNm::start(polkit);
    REFUSE.store(false, std::sync::atomic::Ordering::SeqCst);
    *AGENT.lock().unwrap_or_else(|p| p.into_inner()) = None;
    *LAST.lock().unwrap_or_else(|p| p.into_inner()) = None;
    nm.conn.object_server().at(MANAGER_PATH, Manager).unwrap();
    (nm, AgentManager, Tmp::new("t"))
}

impl AgentManager {
    /// From now on the manager refuses registrations as NM refuses a second agent with the same identifier.
    pub fn refuse_registrations(&self) {
        REFUSE.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// One `GetSecrets` answer flattened: `vpn` → its `secrets` dict, another setting → its string keys.
pub type Secrets = BTreeMap<String, String>;

pub struct PendingSecrets(std::thread::JoinHandle<Result<Secrets, String>>);

impl PendingSecrets {
    pub fn join(self) -> Result<Secrets, String> {
        self.0.join().expect("the GetSecrets thread")
    }
}

fn text(v: &Value<'_>) -> Option<String> {
    match v {
        Value::Str(s) => Some(s.to_string()),
        Value::Value(inner) => text(inner),
        _ => None,
    }
}

/// What NM sends for `uuid`, as real NM does: the profile's settings and its path (the last profile with the UUID; a
/// stand-in when there is none).
fn request_for(state: &Shared, uuid: &str) -> (NmSettings, String) {
    let s = lock(state);
    let found =
        s.profiles.iter().rev().find(|(_, p)| settings_str(&p.settings, "connection", "uuid").as_deref() == Some(uuid));
    match found {
        Some((path, p)) => (clone_settings(&p.settings), path.clone()),
        None => {
            let connection: HashMap<String, OwnedValue> = HashMap::from([
                ("uuid".to_string(), OwnedValue::try_from(Value::from(uuid)).unwrap()),
                ("id".to_string(), OwnedValue::try_from(Value::from("test")).unwrap()),
            ]);
            (
                HashMap::from([("connection".to_string(), connection)]),
                "/org/freedesktop/NetworkManager/Settings/0".into(),
            )
        }
    }
}

fn get_secrets(
    conn: &Connection,
    request: (NmSettings, String),
    setting: &str,
    hints: &[String],
) -> Result<Secrets, String> {
    let agent = AGENT.lock().unwrap_or_else(|p| p.into_inner()).clone().ok_or("no agent registered")?;
    let (connection, path) = request;
    let path = ObjectPath::try_from(path.as_str()).unwrap();
    let hints: Vec<&str> = hints.iter().map(String::as_str).collect();
    let reply = conn
        .call_method(
            Some(agent.as_str()),
            AGENT_PATH,
            Some(AGENT_IFACE),
            "GetSecrets",
            &(connection, path, setting, hints, 1u32),
        )
        .map_err(|e| match e {
            zbus::Error::MethodError(name, _, _) => name.to_string(),
            other => other.to_string(),
        })?;
    let map: HashMap<String, HashMap<String, OwnedValue>> = reply.body().deserialize().map_err(|e| e.to_string())?;
    let section = map.get(setting).ok_or("no section")?;
    let mut out = Secrets::new();
    if setting == "vpn" {
        if let Some(Value::Dict(d)) = section.get("secrets").map(|v| &**v) {
            for (k, v) in d.iter() {
                if let (Some(k), Some(v)) = (text(k), text(v)) {
                    out.insert(k, v);
                }
            }
        }
    } else {
        for (k, v) in section {
            if let Some(v) = text(v) {
                out.insert(k.clone(), v);
            }
        }
    }
    Ok(out)
}

const ACTIVE_IFACE: &str = "org.freedesktop.NetworkManager.Connection.Active";

fn emit_vpn(conn: &Connection, state: &Shared, path: &str, vpn_state: u32, reason: u32) {
    if let Some(a) = lock(state).actives.get_mut(path) {
        a.vpn_state = vpn_state;
    }
    let _ = conn.emit_signal(None::<&str>, path, VPN_IFACE, "VpnStateChanged", &(vpn_state, reason));
}

fn pause() {
    std::thread::sleep(Duration::from_millis(30));
}

/// The walk of one activation (the fake's own thread).
fn walk(conn: Connection, state: Shared, path: String, outcome: Outcome) {
    let vpn = lock(&state).actives.get(&path).is_some_and(|a| a.vpn);
    pause();
    if vpn {
        emit_vpn(&conn, &state, &path, 1, 0);
        pause();
        emit_vpn(&conn, &state, &path, 3, 0);
        pause();
    }
    match outcome {
        Outcome::StayConnecting => {}
        Outcome::Activated { ip4 } => {
            if vpn {
                emit_vpn(&conn, &state, &path, 4, 0);
                pause();
            }
            let ip_path = {
                let mut s = lock(&state);
                s.next += 1;
                let ip_path = format!("{ROOT}/IP4Config/{}", s.next);
                s.ip4.insert(ip_path.clone(), vec![ip4.to_string()]);
                ip_path
            };
            conn.object_server().at(ip_path.as_str(), Ip4Config(state.clone(), ip_path.clone())).unwrap();
            if let Some(a) = lock(&state).actives.get_mut(&path) {
                a.ip4_config = ip_path;
                a.state = 2;
            }
            if vpn {
                emit_vpn(&conn, &state, &path, 5, 0);
            }
        }
        Outcome::ActivatedAddressLater => {
            if vpn {
                emit_vpn(&conn, &state, &path, 4, 0);
                pause();
            }
            if let Some(a) = lock(&state).actives.get_mut(&path) {
                a.state = 2;
            }
            if vpn {
                emit_vpn(&conn, &state, &path, 5, 0);
            }
        }
        Outcome::Failed { reason } => end(&conn, &state, &path, 6, reason),
    }
}

/// `vpn_state(reason)` (failed or disconnected), then NM drops the active connection and the volatile profile.
fn end(conn: &Connection, state: &Shared, path: &str, vpn_state: u32, reason: u32) {
    let vpn = lock(state).actives.get(path).is_some_and(|a| a.vpn);
    if vpn {
        emit_vpn(conn, state, path, vpn_state, reason);
    }
    // NM's `Connection.Active.StateChanged(DEACTIVATED, reason)`, for every kind (WireGuard has only this one).
    let _ = conn.emit_signal(None::<&str>, path, ACTIVE_IFACE, "StateChanged", &(4u32, reason));
    std::thread::sleep(Duration::from_millis(150));
    let removed = lock(state).actives.remove(path);
    if let Some(a) = removed {
        lock(state).profiles.remove(&a.connection);
        let server = conn.object_server();
        let _ = server.remove::<ActiveConn, _>(path);
        if a.vpn {
            let _ = server.remove::<VpnConn, _>(path);
        }
    }
}

impl FakeNm {
    /// The next `AddAndActivateConnection2` walks to `outcome` (on the fake's own thread).
    pub fn activate_next(&self, outcome: Outcome) {
        let known: BTreeSet<String> = lock(&self.state).actives.keys().cloned().collect();
        let (conn, state) = (self.conn.clone(), self.state.clone());
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let found = loop {
                let new = lock(&state)
                    .actives
                    .iter()
                    .find(|(p, _)| !known.contains(*p))
                    .map(|(p, a)| (p.clone(), a.uuid.clone(), a.connection.clone()));
                if let Some(found) = new {
                    break found;
                }
                if Instant::now() >= deadline {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let path = found.0.clone();
            *LAST.lock().unwrap_or_else(|p| p.into_inner()) = Some(found);
            walk(conn, state, path, outcome);
        });
    }

    fn last(&self) -> (String, String, String) {
        for _ in 0..400 {
            if let Some(last) = LAST.lock().unwrap_or_else(|p| p.into_inner()).clone() {
                return last;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("no activation was walked")
    }

    /// The NM UUID of the last walked activation.
    pub fn last_uuid(&self) -> String {
        self.last().1
    }

    /// The active path of the last walked activation.
    pub fn last_active_path(&self) -> String {
        self.last().0
    }

    /// The settings LinVPN added for the last walked activation (while NM still has its profile).
    pub fn last_settings(&self) -> NmSettings {
        let profile = self.last().2;
        clone_settings(&lock(&self.state).profiles.get(&profile).expect("the profile").settings)
    }

    /// A string key of the last activation's settings.
    pub fn last_setting_str(&self, setting: &str, key: &str) -> Option<String> {
        settings_str(&self.last_settings(), setting, key)
    }

    /// `vpn.data` of the last activation.
    pub fn last_vpn_data(&self) -> BTreeMap<String, String> {
        let s = self.last_settings();
        s.get("vpn")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.try_clone().ok())
            .and_then(|v| HashMap::<String, String>::try_from(v).ok())
            .map(|d| d.into_iter().collect())
            .unwrap_or_default()
    }

    /// `user.data` of the last activation (the dispatcher script's mark).
    pub fn last_user_data(&self) -> BTreeMap<String, String> {
        let s = self.last_settings();
        s.get("user")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.try_clone().ok())
            .and_then(|v| HashMap::<String, String>::try_from(v).ok())
            .map(|d| d.into_iter().collect())
            .unwrap_or_default()
    }

    /// The last walked activation's VPN state changes to `vpn_state` (its active state stays activated), as when
    /// OpenVPN restarts itself (`Connect`) and comes back (`Activated`).
    pub fn set_last_vpn_state(&self, vpn_state: u32) {
        emit_vpn(&self.conn, &self.state, &self.last_active_path(), vpn_state, 0);
    }

    /// The last walked activation gets its `Ip4Config` with `ip4` (after [`Outcome::ActivatedAddressLater`]).
    pub fn set_last_ip4(&self, ip4: &str) {
        let path = self.last_active_path();
        let ip_path = {
            let mut s = lock(&self.state);
            s.next += 1;
            let ip_path = format!("{ROOT}/IP4Config/{}", s.next);
            s.ip4.insert(ip_path.clone(), vec![ip4.to_string()]);
            ip_path
        };
        self.conn.object_server().at(ip_path.as_str(), Ip4Config(self.state.clone(), ip_path.clone())).unwrap();
        if let Some(a) = lock(&self.state).actives.get_mut(&path) {
            a.ip4_config = ip_path;
        }
    }

    /// The last walked activation is stopped outside LinVPN (GNOME's menu, `nmcli connection down`):
    /// `Disconnected(reason)`, then NM drops it.
    pub fn disconnect_last(&self, reason: u32) {
        end(&self.conn, &self.state, &self.last_active_path(), 7, reason);
    }

    /// The active paths LinVPN deactivated, in order.
    pub fn deactivated(&self) -> Vec<String> {
        self.calls().into_iter().filter(|c| c.method == "DeactivateConnection").map(|c| c.path).collect()
    }

    /// NM asks LinVPN's agent for `uuid`'s secrets of `setting` with `hints` (interaction allowed), with the
    /// profile's settings and path.
    pub fn as_nm_get_secrets(&self, uuid: &str, setting: &str, hints: &[&str]) -> Result<Secrets, String> {
        let hints: Vec<String> = hints.iter().map(|h| h.to_string()).collect();
        get_secrets(&self.conn, request_for(&self.state, uuid), setting, &hints)
    }

    /// [`FakeNm::as_nm_get_secrets`] with the request changed first (another path, other settings: a profile of
    /// someone else's with the same UUID).
    pub fn as_nm_get_secrets_altered(
        &self,
        uuid: &str,
        setting: &str,
        alter: impl FnOnce(&mut NmSettings, &mut String),
    ) -> Result<Secrets, String> {
        let (mut settings, mut path) = request_for(&self.state, uuid);
        alter(&mut settings, &mut path);
        get_secrets(&self.conn, (settings, path), setting, &[])
    }

    /// [`FakeNm::as_nm_get_secrets`] on its own thread (a CRV1 request waits for the user's code).
    pub fn as_nm_get_secrets_async(&self, uuid: &str, setting: &str, hints: &[&str]) -> PendingSecrets {
        let conn = self.conn.clone();
        let request = request_for(&self.state, uuid);
        let setting = setting.to_string();
        let hints: Vec<String> = hints.iter().map(|h| h.to_string()).collect();
        PendingSecrets(std::thread::spawn(move || get_secrets(&conn, request, &setting, &hints)))
    }
}
