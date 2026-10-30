//! LinVPN's NetworkManager secret agent (`org.freedesktop.NetworkManager.SecretAgent`): it answers only the
//! current unique name of `org.freedesktop.NetworkManager`, and only for an activation the engine announced with
//! [`Agent::expect`] and bound to its settings object path ([`Expect::bind`]): a `GetSecrets` is answered only when
//! its `connection_path` is that path and its settings keep the expectation's [`Rules`] (`connection.permissions`
//! exactly `user:<the user>`, the planned `vpn.service-type`). The UUID alone is never enough: anyone may create a
//! profile with any UUID (security review L1). A request that comes before the path is known (NM asks right after
//! `AddAndActivateConnection2` returns) waits for it, at most [`BIND_WAIT`].
//!
//! Static secrets (password, PSK, key password, WireGuard keys) are answered from the expectation; a dynamic
//! challenge (CRV1: the `x-dynamic-challenge[-echo]:challenge-response` hint) becomes a pending
//! [`AuthUIState`] the app polls through [`Agent::challenge`] and answers with [`Agent::respond`], ended by
//! [`Agent::cancel`], the deadline ([`CRV1_DEADLINE_SECS`]) or NM's `CancelGetSecrets`. The agent never saves or
//! deletes anything and never logs: every answer is built from `Zeroizing` values and dropped after the reply (R8).
use crate::pure::nm::agent::{CHALLENGE_RESPONSE, CRV1_DEADLINE_SECS, dynamic_challenge};
use macvpn_core::mfa::{AuthUIMethod, AuthUIState, AuthUIStateKind};
use macvpn_core::nm_plan::SecretKey;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zbus::blocking::Connection;
use zbus::export::serde::{Serialize, Serializer};
use zbus::message::Header;
use zbus::zvariant::{Array, Dict, OwnedObjectPath, OwnedValue, Signature, Type, Value};
use zeroize::Zeroizing;

const NM_NAME: &str = "org.freedesktop.NetworkManager";
const AGENT_PATH: &str = "/org/freedesktop/NetworkManager/SecretAgent";
const MANAGER_PATH: &str = "/org/freedesktop/NetworkManager/AgentManager";
const MANAGER_IFACE: &str = "org.freedesktop.NetworkManager.AgentManager";
/// The agent's identifier at NM's `AgentManager`.
pub const IDENTIFIER: &str = "local.linvpn.agent";
/// `NM_SECRET_AGENT_CAPABILITY_VPN_HINTS`: NM passes the VPN plugin's hints (the CRV1 request among them).
const CAPABILITY_VPN_HINTS: u32 = 0x1;
/// `NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION`: without it the agent may not prompt.
const FLAG_ALLOW_INTERACTION: u32 = 0x1;
/// How long a `GetSecrets` waits for its expectation's settings path ([`Expect::bind`]).
pub const BIND_WAIT: Duration = Duration::from_secs(10);

/// One secret of an expected activation: `(setting, key, value)`; the key is `nm_plan`'s
/// (`Plain("password")`, `WgPeerPsk { … }`).
pub struct Answer {
    pub items: Vec<(&'static str, macvpn_core::nm_plan::SecretKey, Zeroizing<String>)>,
}

#[derive(Clone)]
pub struct Agent {
    inner: Arc<Inner>,
    /// The connection the agent is served on (kept open while the agent lives).
    _bus: Connection,
}

/// What a `GetSecrets`'s settings must say besides the UUID and the path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rules {
    /// `connection.permissions` must be exactly `["user:<user>"]` (LinVPN's own profiles; `None`: not checked, a
    /// system VPN the user activates).
    pub user: Option<String>,
    /// `vpn.service-type` must be this (`None`: not checked; WireGuard has none).
    pub service_type: Option<String>,
}

/// While it lives, the agent answers for its UUID (once bound to the profile's path); dropping it forgets and wipes
/// the answer (only the expectation it created: a newer `expect` of the same UUID stays).
pub struct Expect {
    inner: Weak<Inner>,
    nm_uuid: String,
    generation: u64,
}

impl Expect {
    /// The settings object path NM gave the profile (`AddAndActivateConnection2`'s first result, or the system
    /// profile's): only `GetSecrets` for that path are answered.
    pub fn bind(&self, settings_path: &str) {
        let Some(inner) = self.inner.upgrade() else { return };
        if let Some(e) = inner.entries().get_mut(&self.nm_uuid).filter(|e| e.generation == self.generation) {
            e.path = Some(settings_path.to_string());
        }
    }
}

impl Drop for Expect {
    fn drop(&mut self) {
        let Some(inner) = self.inner.upgrade() else { return };
        let mut entries = inner.entries();
        if entries.get(&self.nm_uuid).is_some_and(|e| e.generation == self.generation) {
            // The answer's `Zeroizing` values are wiped here; a pending request sees its channel close.
            entries.remove(&self.nm_uuid);
        }
    }
}

/// How a pending CRV1 request ends.
enum Outcome {
    Code(Zeroizing<String>),
    /// The user cancelled the prompt ([`Agent::cancel`]).
    User,
    /// NM's `CancelGetSecrets`, or a newer request replaced it.
    Nm,
}

struct Challenge {
    state: AuthUIState,
    /// `None` once answered or ended.
    tx: Option<async_channel::Sender<Outcome>>,
    path: String,
    setting: String,
}

struct Entry {
    generation: u64,
    answer: Answer,
    challenge: Option<Challenge>,
    rules: Rules,
    /// The profile's settings path; `None` until [`Expect::bind`].
    path: Option<String>,
    /// The settings whose stored secrets this activation already got: a second ask is a refused sign-in.
    answered: std::collections::HashSet<String>,
}

#[derive(Default)]
struct Inner {
    entries: Mutex<HashMap<String, Entry>>,
    /// The unique name owning `org.freedesktop.NetworkManager` (`NameOwnerChanged` keeps it current).
    nm_owner: Mutex<Option<String>>,
    generation: AtomicU64,
    seq: AtomicI64,
}

impl Inner {
    fn entries(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn nm_owner(&self) -> MutexGuard<'_, Option<String>> {
        self.nm_owner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Ends a pending challenge: its state becomes `kind` and the waiting `GetSecrets` gets `outcome`.
fn end(challenge: &mut Challenge, kind: AuthUIStateKind, outcome: Outcome) -> bool {
    let Some(tx) = challenge.tx.take() else { return false };
    challenge.state.state = kind;
    tx.try_send(outcome).is_ok()
}

impl Agent {
    /// Exports the agent on `bus` and registers it with NM's `AgentManager` (`RegisterWithCapabilities`,
    /// identifier `local.linvpn.agent`, VPN hints).
    pub fn register(bus: &Connection) -> zbus::Result<Agent> {
        let inner = Arc::new(Inner::default());
        let server = bus.object_server();
        let _ = server.remove::<SecretAgent, _>(AGENT_PATH);
        server.at(AGENT_PATH, SecretAgent(Arc::downgrade(&inner)))?;
        let dbus = zbus::blocking::fdo::DBusProxy::new(bus)?;
        // Subscribed before the owner is read, so no change in between is missed.
        let changes = dbus.receive_name_owner_changed_with_args(&[(0, NM_NAME)])?;
        let owner = dbus.get_name_owner(NM_NAME.try_into()?)?;
        *inner.nm_owner() = Some(owner.to_string());
        register_with_nm(bus)?;
        let weak = Arc::downgrade(&inner);
        let watch_bus = bus.clone();
        std::thread::Builder::new().name("linvpn-nm-agent".into()).spawn(move || {
            for signal in changes {
                // The agent is gone: stop (no re-registration for a dropped agent).
                let Some(inner) = weak.upgrade() else { break };
                let Ok(args) = signal.args() else { continue };
                let new_owner = args.new_owner().as_ref().map(|n| n.to_string());
                let restarted = new_owner.is_some();
                *inner.nm_owner() = new_owner;
                drop(inner);
                if restarted {
                    // NM restarted: its new instance knows no agent.
                    let _ = register_with_nm(&watch_bus);
                }
            }
        })?;
        Ok(Agent { inner, _bus: bus.clone() })
    }

    /// Announces an activation of `nm_uuid` with its secrets; nothing is answered until [`Expect::bind`].
    pub fn expect(&self, nm_uuid: &str, rules: Rules, answer: Answer) -> Expect {
        let generation = self.inner.generation.fetch_add(1, Ordering::Relaxed);
        let entry = Entry { generation, answer, challenge: None, rules, path: None, answered: Default::default() };
        let old = self.inner.entries().insert(nm_uuid.to_string(), entry);
        if let Some(mut challenge) = old.and_then(|e| e.challenge) {
            end(&mut challenge, AuthUIStateKind::Cancelled, Outcome::Nm);
        }
        Expect { inner: Arc::downgrade(&self.inner), nm_uuid: nm_uuid.to_string(), generation }
    }

    /// The pending dynamic challenge (CRV1) of `nm_uuid`, for `AuthStateReader`.
    pub fn challenge(&self, nm_uuid: &str) -> Option<AuthUIState> {
        self.inner.entries().get(nm_uuid)?.challenge.as_ref().map(|c| c.state.clone())
    }

    /// The user's answer to the pending challenge; `false`: none pending.
    pub fn respond(&self, nm_uuid: &str, code: Zeroizing<String>) -> bool {
        let mut entries = self.inner.entries();
        let Some(challenge) = entries.get_mut(nm_uuid).and_then(|e| e.challenge.as_mut()) else { return false };
        end(challenge, AuthUIStateKind::Done, Outcome::Code(code))
    }

    /// The user cancelled the code prompt.
    pub fn cancel(&self, nm_uuid: &str) {
        let mut entries = self.inner.entries();
        if let Some(challenge) = entries.get_mut(nm_uuid).and_then(|e| e.challenge.as_mut()) {
            end(challenge, AuthUIStateKind::Cancelled, Outcome::User);
        }
    }
}

fn register_with_nm(bus: &Connection) -> zbus::Result<()> {
    bus.call_method(
        Some(NM_NAME),
        MANAGER_PATH,
        Some(MANAGER_IFACE),
        "RegisterWithCapabilities",
        &(IDENTIFIER, CAPABILITY_VPN_HINTS),
    )?;
    Ok(())
}

/// The secret agent's D-Bus errors (`org.freedesktop.NetworkManager.SecretAgent.*`). Their messages never hold a
/// secret.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.NetworkManager.SecretAgent")]
enum AgentError {
    #[zbus(error)]
    ZBus(zbus::Error),
    NotAuthorized(String),
    InvalidConnection(String),
    UserCanceled(String),
    AgentCanceled(String),
    NoSecrets(String),
}

fn not_authorized() -> AgentError {
    AgentError::NotAuthorized("only NetworkManager may ask this agent".into())
}

fn no_secrets() -> AgentError {
    AgentError::NoSecrets("LinVPN has no secrets for this request".into())
}

/// An answer to `GetSecrets` (`a{sa{sv}}` with one setting), serialized straight from its `Zeroizing` values:
/// `vpn` → `{"vpn": {"secrets": a{ss}}}`; `wireguard` → `{"wireguard": {<key>: s, "peers": aa{sv}}}`.
struct SecretsReply {
    setting: &'static str,
    plain: Vec<(String, Zeroizing<String>)>,
    /// `(public key, preshared key)`.
    peers: Vec<(String, Zeroizing<String>)>,
}

impl Serialize for SecretsReply {
    // Ordered maps only: zbus serializes a reply more than once (its size, then its bytes), and a `HashMap` built
    // in each pass would iterate in a different order, so the padding and the size would disagree.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut section: BTreeMap<&str, Value<'_>> = BTreeMap::new();
        if self.setting == "vpn" {
            let secrets: BTreeMap<&str, &str> = self.plain.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            section.insert("secrets", Value::Dict(Dict::from(secrets)));
        } else {
            for (k, v) in &self.plain {
                section.insert(k.as_str(), Value::from(v.as_str()));
            }
            if !self.peers.is_empty() {
                let mut peers = Array::new(<BTreeMap<&str, Value<'_>> as Type>::SIGNATURE);
                for (public, psk) in &self.peers {
                    let peer = BTreeMap::from([
                        ("public-key", Value::from(public.as_str())),
                        ("preshared-key", Value::from(psk.as_str())),
                    ]);
                    peers.append(Value::Dict(Dict::from(peer))).map_err(zbus::export::serde::ser::Error::custom)?;
                }
                section.insert("peers", Value::Array(peers));
            }
        }
        BTreeMap::from([(self.setting, section)]).serialize(serializer)
    }
}

impl Type for SecretsReply {
    const SIGNATURE: &'static Signature = <HashMap<String, HashMap<String, OwnedValue>> as Type>::SIGNATURE;
}

/// The exported object: a weak reference, so a dropped [`Agent`] answers nothing.
struct SecretAgent(Weak<Inner>);

impl SecretAgent {
    fn inner(&self) -> Result<Arc<Inner>, AgentError> {
        self.0.upgrade().ok_or_else(no_secrets)
    }

    /// R9: the caller must be the current unique name of `org.freedesktop.NetworkManager`. A sender other than the
    /// cached owner is checked once more against `GetNameOwner` (the cache may lag behind an NM restart; a unique
    /// name is never reused, so a stale cache can only refuse).
    async fn caller_is_nm(&self, header: &Header<'_>, conn: &zbus::Connection) -> Result<Arc<Inner>, AgentError> {
        let inner = self.inner()?;
        let sender = header.sender().ok_or_else(not_authorized)?.to_string();
        if inner.nm_owner().as_deref() == Some(sender.as_str()) {
            return Ok(inner);
        }
        let dbus = zbus::fdo::DBusProxy::new(conn).await.map_err(|_| not_authorized())?;
        let name = NM_NAME.try_into().map_err(|_| not_authorized())?;
        let owner = dbus.get_name_owner(name).await.map_err(|_| not_authorized())?.to_string();
        let matches = owner == sender;
        *inner.nm_owner() = Some(owner);
        if matches { Ok(inner) } else { Err(not_authorized()) }
    }
}

type NmSettings = HashMap<String, HashMap<String, OwnedValue>>;

fn setting_str(connection: &NmSettings, setting: &str, key: &str) -> Option<String> {
    match &**connection.get(setting)?.get(key)? {
        Value::Str(s) => Some(s.to_string()),
        _ => None,
    }
}

fn connection_uuid(connection: &NmSettings) -> Option<String> {
    setting_str(connection, "connection", "uuid")
}

/// `connection.permissions` (`as`); `None` when it has another type.
fn permissions(connection: &NmSettings) -> Option<Vec<String>> {
    let Some(v) = connection.get("connection").and_then(|c| c.get("permissions")) else { return Some(Vec::new()) };
    match &**v {
        Value::Array(a) => a
            .iter()
            .map(|e| match e {
                Value::Str(s) => Some(s.to_string()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

/// Whether a request's settings keep `rules`: exactly one permission, `user:<user>` (or NM's `user:<user>:`), and the
/// planned service type.
fn keeps(rules: &Rules, connection: &NmSettings) -> bool {
    if let Some(user) = &rules.user {
        let Some(list) = permissions(connection) else { return false };
        let ok = list.len() == 1
            && list[0].strip_prefix("user:").map(|r| r.strip_suffix(':').unwrap_or(r)) == Some(user.as_str());
        if !ok {
            return false;
        }
    }
    rules.service_type.as_ref().is_none_or(|st| setting_str(connection, "vpn", "service-type").as_ref() == Some(st))
}

fn not_this_profile() -> AgentError {
    AgentError::NoSecrets("LinVPN has no secrets for this profile".into())
}

/// The expectation's generation for this request, once its path is bound (waiting for it at most [`BIND_WAIT`]),
/// if the path and the rules fit; else the refusal.
async fn admit(inner: &Weak<Inner>, nm_uuid: &str, connection: &NmSettings, path: &str) -> Result<u64, AgentError> {
    let deadline = std::time::Instant::now() + BIND_WAIT;
    loop {
        {
            let inner = inner.upgrade().ok_or_else(no_secrets)?;
            let entries = inner.entries();
            let entry = entries.get(nm_uuid).ok_or_else(no_secrets)?;
            if let Some(bound) = &entry.path {
                if bound != path || !keeps(&entry.rules, connection) {
                    return Err(not_this_profile());
                }
                return Ok(entry.generation);
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(no_secrets());
        }
        async_io::Timer::after(Duration::from_millis(20)).await;
    }
}

fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

#[zbus::interface(name = "org.freedesktop.NetworkManager.SecretAgent")]
impl SecretAgent {
    // NM's signature (five arguments) plus the header and the connection.
    #[allow(clippy::too_many_arguments)]
    async fn get_secrets(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        connection: NmSettings,
        connection_path: OwnedObjectPath,
        setting_name: String,
        hints: Vec<String>,
        flags: u32,
    ) -> Result<SecretsReply, AgentError> {
        let inner = self.caller_is_nm(&header, conn).await?;
        let nm_uuid = connection_uuid(&connection)
            .ok_or_else(|| AgentError::InvalidConnection("the connection has no UUID".into()))?;
        let weak = Arc::downgrade(&inner);
        drop(inner);
        let generation = admit(&weak, &nm_uuid, &connection, connection_path.as_str()).await?;
        let inner = weak.upgrade().ok_or_else(no_secrets)?;

        if let Some((echo, text)) = dynamic_challenge(&hints) {
            if setting_name != "vpn" || flags & FLAG_ALLOW_INTERACTION == 0 {
                return Err(no_secrets());
            }
            let (tx, rx) = async_channel::bounded(1);
            let seq = inner.seq.fetch_add(1, Ordering::Relaxed) + 1;
            {
                let mut entries = inner.entries();
                let entry = entries.get_mut(&nm_uuid).filter(|e| e.generation == generation).ok_or_else(no_secrets)?;
                if let Some(old) = entry.challenge.as_mut() {
                    end(old, AuthUIStateKind::Cancelled, Outcome::Nm);
                }
                let mut state = AuthUIState::new(seq, AuthUIStateKind::Challenge);
                state.method = Some(AuthUIMethod::Crv1);
                state.text = (!text.is_empty()).then_some(text);
                state.echo = Some(echo);
                state.deadline = Some(unix_now() + CRV1_DEADLINE_SECS as f64);
                entry.challenge =
                    Some(Challenge { state, tx: Some(tx), path: connection_path.to_string(), setting: setting_name });
            }
            // No strong reference while waiting: a dropped agent ends the wait (the channel closes).
            let weak = Arc::downgrade(&inner);
            drop(inner);
            let waited = futures_lite::future::or(async { rx.recv().await.ok() }, async {
                async_io::Timer::after(Duration::from_secs(CRV1_DEADLINE_SECS)).await;
                None
            })
            .await;
            return match waited {
                Some(Outcome::Code(code)) => Ok(SecretsReply {
                    setting: "vpn",
                    plain: vec![(CHALLENGE_RESPONSE.to_string(), code)],
                    peers: Vec::new(),
                }),
                Some(Outcome::User) => Err(AgentError::UserCanceled("the user cancelled the code prompt".into())),
                Some(Outcome::Nm) => Err(AgentError::AgentCanceled("the request was cancelled".into())),
                None => {
                    // The deadline passed, or the expectation was dropped.
                    if let Some(inner) = weak.upgrade()
                        && let Some(challenge) = inner.entries().get_mut(&nm_uuid).and_then(|e| e.challenge.as_mut())
                        && challenge.state.seq == seq
                    {
                        end(challenge, AuthUIStateKind::Cancelled, Outcome::Nm);
                    }
                    Err(AgentError::UserCanceled("no code was given in time".into()))
                }
            };
        }

        let mut entries = inner.entries();
        let entry = entries.get_mut(&nm_uuid).filter(|e| e.generation == generation).ok_or_else(no_secrets)?;
        // Asked again for the same stored secrets: the server refused them (NM-openvpn clears the password after
        // OpenVPN's "Verification Failed" and asks anew). Sending them again would loop until NM's timeout; the
        // user's cancel fails the VPN at once with NM's no-secrets reason.
        if entry.answered.contains(&setting_name) {
            return Err(AgentError::UserCanceled("the server refused these credentials".into()));
        }
        let mut reply = SecretsReply { setting: "", plain: Vec::new(), peers: Vec::new() };
        for (setting, key, value) in &entry.answer.items {
            if *setting != setting_name {
                continue;
            }
            reply.setting = setting;
            match key {
                SecretKey::Plain(k) => reply.plain.push((k.clone(), value.clone())),
                SecretKey::WgPeerPsk { public_key } => reply.peers.push((public_key.clone(), value.clone())),
            }
        }
        if reply.setting.is_empty() {
            return Err(no_secrets());
        }
        entry.answered.insert(setting_name);
        Ok(reply)
    }

    async fn cancel_get_secrets(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        connection_path: OwnedObjectPath,
        setting_name: String,
    ) -> Result<(), AgentError> {
        let inner = self.caller_is_nm(&header, conn).await?;
        let path = connection_path.to_string();
        let mut entries = inner.entries();
        for challenge in entries.values_mut().filter_map(|e| e.challenge.as_mut()) {
            if challenge.path == path && challenge.setting == setting_name {
                end(challenge, AuthUIStateKind::Cancelled, Outcome::Nm);
            }
        }
        Ok(())
    }

    /// Nothing is stored: LinVPN keeps its secrets in its own vault.
    async fn save_secrets(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        _connection: HashMap<String, HashMap<String, OwnedValue>>,
        _connection_path: OwnedObjectPath,
    ) -> Result<(), AgentError> {
        self.caller_is_nm(&header, conn).await.map(drop)
    }

    /// Nothing is stored, so nothing is deleted.
    async fn delete_secrets(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        _connection: HashMap<String, HashMap<String, OwnedValue>>,
        _connection_path: OwnedObjectPath,
    ) -> Result<(), AgentError> {
        self.caller_is_nm(&header, conn).await.map(drop)
    }
}
