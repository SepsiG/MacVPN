//! A fake NetworkManager agent manager on the test's private bus (dbus-run-session): it owns
//! `org.freedesktop.NetworkManager`, serves `AgentManager.RegisterWithCapabilities` (recording the caller), and
//! plays NM asking the registered agent (`GetSecrets`, `CancelGetSecrets`, `SaveSecrets`, `DeleteSecrets`) from the
//! name owner's connection, or from a third connection (an impostor).
//!
//! The tests of one binary share one bus and NM's one name: [`FakeManager::start`] holds a process-wide lock for the
//! test's life. The values the agent answers are test literals; [`Reply`]'s `Debug` still shows only the keys (R8).
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use zbus::blocking::Connection;
use zbus::names::OwnedUniqueName;
use zbus::zvariant::{ObjectPath, OwnedValue, Value};

pub const NM: &str = "org.freedesktop.NetworkManager";
const MANAGER_PATH: &str = "/org/freedesktop/NetworkManager/AgentManager";
const AGENT_PATH: &str = "/org/freedesktop/NetworkManager/SecretAgent";
const AGENT_IFACE: &str = "org.freedesktop.NetworkManager.SecretAgent";

static ONE_NM: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct Seen {
    registered: Option<(String, u32)>,
    agent: Option<OwnedUniqueName>,
}

struct Manager(Arc<Mutex<Seen>>);

#[zbus::interface(name = "org.freedesktop.NetworkManager.AgentManager")]
impl Manager {
    fn register_with_capabilities(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        identifier: String,
        capabilities: u32,
    ) {
        let mut seen = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        seen.registered = Some((identifier, capabilities));
        seen.agent = header.sender().map(|s| s.to_owned().into());
    }

    fn register(&self, #[zbus(header)] header: zbus::message::Header<'_>, identifier: String) {
        self.register_with_capabilities(header, identifier, 0);
    }

    fn unregister(&self) {}
}

/// A value of the agent's answer: a string, a string dict (`vpn.secrets`), or the WireGuard peers.
#[derive(PartialEq)]
pub enum Val {
    Str(String),
    Dict(BTreeMap<String, String>),
    Peers(Vec<BTreeMap<String, String>>),
    Other,
}

/// The kind only: a failing assertion shows no value (R8).
impl fmt::Debug for Val {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Val::Str(_) => write!(f, "Str(…)"),
            Val::Dict(d) => write!(f, "Dict(keys {:?})", d.keys().collect::<Vec<_>>()),
            Val::Peers(p) => write!(f, "Peers({})", p.len()),
            Val::Other => write!(f, "Other"),
        }
    }
}

impl std::ops::Index<&str> for Val {
    type Output = String;
    fn index(&self, key: &str) -> &String {
        match self {
            Val::Dict(d) => d.get(key).unwrap_or_else(|| panic!("no key {key}")),
            _ => panic!("not a dict"),
        }
    }
}

impl PartialEq<&str> for Val {
    fn eq(&self, other: &&str) -> bool {
        matches!(self, Val::Str(s) if s == other)
    }
}

pub type Answer = BTreeMap<String, BTreeMap<String, Val>>;

pub enum Reply {
    Ok(Answer),
    /// The D-Bus error name.
    Err(String),
}

impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reply::Ok(map) => {
                let keys: BTreeMap<&String, Vec<&String>> = map.iter().map(|(k, v)| (k, v.keys().collect())).collect();
                write!(f, "Ok(keys {keys:?})")
            }
            Reply::Err(name) => write!(f, "Err({name})"),
        }
    }
}

pub struct Pending(std::thread::JoinHandle<Reply>);

impl Pending {
    pub fn join(self) -> Reply {
        self.0.join().expect("the GetSecrets thread")
    }
}

pub struct FakeManager {
    conn: Mutex<Connection>,
    seen: Arc<Mutex<Seen>>,
    _one: MutexGuard<'static, ()>,
}

fn own_nm(seen: &Arc<Mutex<Seen>>) -> Connection {
    zbus::blocking::connection::Builder::session()
        .unwrap()
        .name(NM)
        .unwrap()
        .serve_at(MANAGER_PATH, Manager(seen.clone()))
        .unwrap()
        .build()
        .expect("a private session bus (run under dbus-run-session)")
}

/// The object path NM would give the connection's profile.
pub fn profile_path(uuid: &str) -> String {
    let element: String = uuid.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    format!("/org/freedesktop/NetworkManager/Settings/c_{element}")
}

fn connection(uuid: &str) -> HashMap<&'static str, HashMap<&'static str, Value<'_>>> {
    HashMap::from([(
        "connection",
        HashMap::from([("uuid", Value::from(uuid)), ("id", Value::from("test")), ("type", Value::from("vpn"))]),
    )])
}

fn text(v: &Value<'_>) -> Option<String> {
    match v {
        Value::Str(s) => Some(s.to_string()),
        Value::Value(inner) => text(inner),
        _ => None,
    }
}

fn dict(v: &Value<'_>) -> Option<BTreeMap<String, String>> {
    match v {
        Value::Dict(d) => d.iter().map(|(k, v)| Some((text(k)?, text(v)?))).collect(),
        Value::Value(inner) => dict(inner),
        _ => None,
    }
}

fn val(v: &Value<'_>) -> Val {
    if let Some(s) = text(v) {
        return Val::Str(s);
    }
    if let Some(d) = dict(v) {
        return Val::Dict(d);
    }
    match v {
        Value::Array(a) => a.iter().map(dict).collect::<Option<Vec<_>>>().map_or(Val::Other, Val::Peers),
        _ => Val::Other,
    }
}

fn reply(result: zbus::Result<zbus::message::Message>) -> Reply {
    match result {
        Ok(msg) => {
            let body = msg.body();
            if body.signature().to_string().is_empty() {
                return Reply::Ok(Answer::new());
            }
            let map: HashMap<String, HashMap<String, OwnedValue>> = body.deserialize().expect("a{sa{sv}}");
            Reply::Ok(map.into_iter().map(|(s, m)| (s, m.iter().map(|(k, v)| (k.clone(), val(v))).collect())).collect())
        }
        Err(zbus::Error::MethodError(name, _, _)) => Reply::Err(name.to_string()),
        Err(e) => Reply::Err(format!("zbus: {e}")),
    }
}

fn get_secrets(conn: &Connection, agent: &str, uuid: &str, setting: &str, hints: &[&str], flags: u32) -> Reply {
    let path = profile_path(uuid);
    let path = ObjectPath::try_from(path.as_str()).unwrap();
    let hints: Vec<&str> = hints.to_vec();
    reply(conn.call_method(
        Some(agent),
        AGENT_PATH,
        Some(AGENT_IFACE),
        "GetSecrets",
        &(connection(uuid), path, setting, hints, flags),
    ))
}

/// `GetSecrets` from `conn`, whoever it is.
pub fn get_secrets_from(conn: &Connection, agent: &str, uuid: &str, setting: &str) -> Reply {
    get_secrets(conn, agent, uuid, setting, &[], 0x1)
}

impl FakeManager {
    pub fn start() -> FakeManager {
        let one = ONE_NM.lock().unwrap_or_else(PoisonError::into_inner);
        let seen = Arc::new(Mutex::new(Seen::default()));
        let conn = own_nm(&seen);
        FakeManager { conn: Mutex::new(conn), seen, _one: one }
    }

    /// NM restarts: the name gets a new unique owner, which knows no agent yet. Returns the old owner's
    /// connection, still on the bus but no longer NM.
    pub fn restart(&self) -> Connection {
        let mut conn = self.conn.lock().unwrap_or_else(PoisonError::into_inner);
        conn.release_name(NM).expect("release NM's name");
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Seen::default();
        std::mem::replace(&mut *conn, own_nm(&self.seen))
    }

    fn conn(&self) -> Connection {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// The identifier and capabilities of the last registration.
    pub fn registered(&self) -> Option<(String, u32)> {
        self.seen.lock().unwrap_or_else(PoisonError::into_inner).registered.clone()
    }

    /// The unique name of the last registered agent.
    pub fn agent_name(&self) -> String {
        self.agent()
    }

    fn agent(&self) -> String {
        let seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        seen.agent.as_ref().expect("an agent registered").to_string()
    }

    pub fn get_secrets(&self, uuid: &str, setting: &str, hints: &[&str], flags: u32) -> Reply {
        get_secrets(&self.conn(), &self.agent(), uuid, setting, hints, flags)
    }

    pub fn get_secrets_async(&self, uuid: &str, setting: &str, hints: &[&str], flags: u32) -> Pending {
        let (conn, agent) = (self.conn(), self.agent());
        let (uuid, setting) = (uuid.to_string(), setting.to_string());
        let hints: Vec<String> = hints.iter().map(|h| h.to_string()).collect();
        Pending(std::thread::spawn(move || {
            let hints: Vec<&str> = hints.iter().map(String::as_str).collect();
            get_secrets(&conn, &agent, &uuid, &setting, &hints, flags)
        }))
    }

    /// `GetSecrets` from a connection that does not own NM's name.
    pub fn get_secrets_as_impostor(&self, uuid: &str, setting: &str) -> Reply {
        let impostor = Connection::session().unwrap();
        get_secrets(&impostor, &self.agent(), uuid, setting, &[], 0x1)
    }

    pub fn cancel_get_secrets(&self, uuid: &str, setting: &str) -> Reply {
        let path = profile_path(uuid);
        let path = ObjectPath::try_from(path.as_str()).unwrap();
        reply(self.conn().call_method(
            Some(self.agent().as_str()),
            AGENT_PATH,
            Some(AGENT_IFACE),
            "CancelGetSecrets",
            &(path, setting),
        ))
    }

    pub fn save_secrets(&self, uuid: &str) -> Reply {
        self.store_call("SaveSecrets", uuid)
    }

    pub fn delete_secrets(&self, uuid: &str) -> Reply {
        self.store_call("DeleteSecrets", uuid)
    }

    fn store_call(&self, method: &str, uuid: &str) -> Reply {
        let path = profile_path(uuid);
        let path = ObjectPath::try_from(path.as_str()).unwrap();
        reply(self.conn().call_method(
            Some(self.agent().as_str()),
            AGENT_PATH,
            Some(AGENT_IFACE),
            method,
            &(connection(uuid), path),
        ))
    }
}
