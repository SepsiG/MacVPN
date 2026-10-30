//! The one NetworkManager engine of the process (resolved point 1). Its trait implementations live in
//! `helper_impl`, `auth`, `native_impl` and `support_impl`; its state is split the same way, so each owner task
//! changes only its own state type.
//!
//! The shared activation path (L-b Task 21; Task 22's managed L2TP / Cisco use it too): [`Engine::nm`] (the NM
//! client and the registered secret agent), [`Engine::caps`] (what the system offers for planning),
//! [`Engine::activate`] (plan, runtime files, secrets for the agent, add and activate, the connection log),
//! [`Engine::deactivate`] and [`Engine::runs`] (the runs with NM's state now). A watcher on NM's signals keeps each
//! run's VPN state facts (connected, reconnecting, the failure reason) and writes them to the connection's log.
//!
//! NM's activations are not bound to LinVPN's process: a tunnel stays up after "Quit, Keep Them Running" or a crash
//! (as on macOS and Windows). [`Engine::adopt`] (once per process, before the first start, stop or status) takes the
//! ones still active back as runs, so app-core finds them connected; a normal quit stops them through `down`.
use crate::lin::nm::agent::{Agent, Answer, Rules};
use crate::lin::nm::client::{NmClient, NmError, NmEvent};
use crate::lin::nm::connlog::{self, ConnLog, Masker};
use crate::lin::nm::files::{RunRecord, RuntimeFiles};
use crate::lin::nm::helper_impl::{CounterSource, HelperState, IfaceSource, Run, Runs};
use crate::lin::nm::logd_client;
use crate::lin::nm::native_impl::NativeState;
use crate::lin::nm::polkit::{self, Authorization};
use crate::lin::nm::value::{self, DbusSettings};
use crate::lin::nm::{files, plugins};
use crate::pure::nm::agent::DEFAULT_SECRET_MODE;
use crate::pure::nm::iface::is_charon_nm_xfrm;
use crate::pure::nm::state::{self, VpnState};
use crate::pure::texts;
use macvpn_core::client_cert::ClientCert;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::{Connection, SecretField, Secrets, VPNKind};
use macvpn_core::nm_plan::{
    self, Caps, ImportedCert, Input, NmPlan, NmValue, SERVICE_STRONGSWAN, SecretItem, SecretKey, SecretMode,
    SecretValue, names,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zbus::zvariant::{OwnedValue, Value};
use zeroize::Zeroizing;

pub struct Engine {
    /// The system bus (production: `lin::bus::system`; tests: their private bus).
    pub bus: fn() -> zbus::Result<zbus::blocking::Connection>,
    pub sandbox: bool,
    pub user: String,
    pub uid: u32,
    /// `$XDG_RUNTIME_DIR` (the runtime files' parent); `None`: unset or invalid, every connect is refused (fail
    /// closed, as the control socket).
    pub runtime: Option<PathBuf>,
    /// `$XDG_DATA_HOME/LinVPN` (logs, plan records, the swanctl folder).
    pub data: PathBuf,
    pub helper: HelperState,
    pub native: NativeState,
}

/// One run as `status`, `liveness` and Task 22 see it.
#[derive(Debug, Clone, PartialEq)]
pub struct RunView {
    pub id: Uuid,
    pub kind: VPNKind,
    pub nm_uuid: String,
    /// `state::root_state`: `"connected"` / `"connecting"`.
    pub state: &'static str,
    pub iface: Option<String>,
    pub ip: Option<String>,
    pub since: f64,
    pub reconnecting_since: Option<u64>,
    pub keepalive: u32,
}

/// How long [`Engine::caps`] keeps what it read.
const CAPS_TTL: Duration = Duration::from_secs(60);
/// How long a run NM no longer reports waits for its VPN state reason (the watcher's `VpnStateChanged`) before it
/// is dropped without one: the reason reaches the log before `status` stops reporting the run.
const REASON_GRACE: Duration = Duration::from_secs(3);
/// charon-nm refuses a shorter pre-shared key at connect (`nm_service.c`: "pre-shared key is too short").
pub const CHARON_NM_PSK_MIN: usize = 20;
/// The watcher keeps at most this many state changes of an active path no run has yet (the run is stored right
/// after `AddAndActivateConnection2` returns; a fast failure can come first).
const ORPHANS_MAX: usize = 32;

fn unix_now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

fn nm_unavailable() -> String {
    l10n::tr("NetworkManager is not running.", &[])
}

/// Why the secret agent could not register: another one of this user holds LinVPN's identifier, else NM is gone.
fn agent_refusal(e: &zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(name, Some(message), _)
            if texts::is_agent_already_registered(name.as_str(), message) =>
        {
            texts::agent_already_registered()
        }
        _ => nm_unavailable(),
    }
}

fn not_authorized() -> String {
    l10n::tr(
        "LinVPN may not change this computer's network settings without asking for a password. Log in at the desktop and try again.",
        &[],
    )
}

/// The localized refusal without `$XDG_RUNTIME_DIR`.
pub fn no_runtime_dir() -> String {
    l10n::tr("LinVPN needs the user's runtime directory ($XDG_RUNTIME_DIR) to connect.", &[])
}

/// The localized refusal of an IKEv2 PSK charon-nm would refuse.
pub fn psk_too_short() -> String {
    l10n::tr(
        "IKEv2 on Linux needs a pre-shared key of at least 20 characters: strongSwan's NetworkManager plugin refuses a shorter one.",
        &[],
    )
}

/// `major.minor` ≥ 2.7 (`2.7.0`, `2.7_rc1`, `2.10.1`).
fn openvpn_at_least_2_7(version: &str) -> bool {
    let mut parts = version.split(['.', '-', '_']);
    let major: Option<u32> = parts.next().and_then(|p| p.parse().ok());
    let minor: Option<u32> = parts.next().and_then(|p| p.parse().ok());
    matches!((major, minor), (Some(a), Some(b)) if (a, b) >= (2, 7))
}

/// Each secret item's value (`Field` from the vault's prepared `secrets`, `Literal` as is); an empty one is left
/// out (the agent then has nothing for it and NM asks no further).
pub fn resolve_secrets(items: &[SecretItem], secrets: &Secrets) -> Vec<(&'static str, SecretKey, Zeroizing<String>)> {
    items
        .iter()
        .filter_map(|item| {
            let value = match &item.value {
                SecretValue::Field(f) => Zeroizing::new(
                    match f {
                        SecretField::Username => secrets.username.as_deref(),
                        SecretField::Password => secrets.password.as_deref(),
                        SecretField::Psk => secrets.psk.as_deref(),
                        SecretField::KeyPassword => secrets.key_password.as_deref(),
                        // No NM secret carries it: the plan writes it as runtime files (`usercert` / `userkey`).
                        SecretField::ClientCert => None,
                    }
                    .unwrap_or("")
                    .to_string(),
                ),
                SecretValue::Literal(v) => v.clone(),
            };
            (!value.is_empty()).then(|| (item.setting, item.key.clone(), value))
        })
        .collect()
}

fn vpn_data(plan: &NmPlan) -> Option<&std::collections::BTreeMap<String, String>> {
    match plan.settings.get("vpn")?.get("data")? {
        NmValue::StrDict(d) => Some(d),
        _ => None,
    }
}

/// charon-nm's PSK rule, checked before anything is written: an IKEv2 PSK (`method = psk`) of fewer than
/// [`CHARON_NM_PSK_MIN`] bytes is refused here with a clear text instead of NM's opaque failure.
pub fn check_ikev2_psk(plan: &NmPlan, values: &[(&'static str, SecretKey, Zeroizing<String>)]) -> Result<(), String> {
    if plan.service_type != Some(SERVICE_STRONGSWAN)
        || vpn_data(plan).and_then(|d| d.get("method")).map(String::as_str) != Some("psk")
    {
        return Ok(());
    }
    let psk = values.iter().find(|(s, k, _)| *s == "vpn" && *k == SecretKey::Plain("password".into()));
    match psk {
        Some((_, _, v)) if v.len() >= CHARON_NM_PSK_MIN => Ok(()),
        _ => Err(psk_too_short()),
    }
}

/// OpenVPN with a user name and password: the vault's user name into `vpn.user-name` and `data.username` (the
/// plan leaves them to the engine unless the config's inline `<auth-user-pass>` named one; Task 7).
pub fn fill_user_name(plan: &mut NmPlan, secrets: &Secrets) {
    if plan.kind != VPNKind::Openvpn {
        return;
    }
    let Some(user) = secrets.username.as_deref().map(str::trim).filter(|u| !u.is_empty()) else { return };
    let Some(vpn) = plan.settings.get_mut("vpn") else { return };
    let Some(NmValue::StrDict(data)) = vpn.get_mut("data") else { return };
    let with_password = matches!(data.get("connection-type").map(String::as_str), Some("password" | "password-tls"));
    if !with_password || data.contains_key("username") {
        return;
    }
    data.insert("username".into(), user.to_string());
    vpn.insert("user-name".into(), NmValue::Str(user.to_string()));
}

/// `SecretMode::Inline` (resolved point 8, branch B): the values go into the in-memory connection right before it
/// is added (`vpn.secrets`, `wireguard.private-key`, each peer's `preshared-key`). The caller drops `settings`
/// right after the call.
fn put_inline(settings: &mut DbusSettings, values: &[(&'static str, SecretKey, Zeroizing<String>)]) {
    let mut vpn_secrets: HashMap<String, String> = HashMap::new();
    for (setting, key, v) in values {
        match (*setting, key) {
            ("vpn", SecretKey::Plain(k)) => {
                vpn_secrets.insert(k.clone(), v.to_string());
            }
            ("wireguard", SecretKey::Plain(k)) => {
                if let Ok(owned) = OwnedValue::try_from(Value::from(v.as_str())) {
                    settings.entry("wireguard".into()).or_default().insert(k.clone(), owned);
                }
            }
            ("wireguard", SecretKey::WgPeerPsk { public_key }) => {
                let Some(wg) = settings.get_mut("wireguard") else { continue };
                let Some(peers) = wg.get("peers").and_then(|p| p.try_clone().ok()) else { continue };
                let Ok(mut peers) = Vec::<HashMap<String, OwnedValue>>::try_from(peers) else { continue };
                for peer in &mut peers {
                    let matches = peer
                        .get("public-key")
                        .and_then(|p| p.try_clone().ok())
                        .and_then(|p| String::try_from(p).ok())
                        .is_some_and(|p| p == *public_key);
                    if matches && let Ok(owned) = OwnedValue::try_from(Value::from(v.as_str())) {
                        peer.insert("preshared-key".into(), owned);
                    }
                }
                if let Ok(owned) = OwnedValue::try_from(Value::from(peers)) {
                    wg.insert("peers".into(), owned);
                }
            }
            _ => {}
        }
    }
    if !vpn_secrets.is_empty()
        && let Ok(owned) = OwnedValue::try_from(Value::from(vpn_secrets))
    {
        settings.entry("vpn".into()).or_default().insert("secrets".into(), owned);
    }
}

/// The `PersistentKeepalive` of the plan's WireGuard peers (the largest; 0: off).
fn keepalive_of(plan: &NmPlan) -> u32 {
    match plan.settings.get("wireguard").and_then(|w| w.get("peers")) {
        Some(NmValue::WgPeers(peers)) => peers.iter().map(|p| p.persistent_keepalive).max().unwrap_or(0),
        _ => 0,
    }
}

/// The debug lines: the summary, the warnings and the effective `vpn.data` (a key protected by `<key>-flags` shows
/// no value; `vpn.data` never holds a secret or a file's content, only paths).
fn debug_lines(plan: &NmPlan) -> Vec<String> {
    let mut out = Vec::new();
    out.extend(plan.summary.iter().cloned());
    out.extend(plan.warnings.iter().cloned());
    if let Some(data) = vpn_data(plan) {
        for (k, v) in data {
            let protected = data.contains_key(&format!("{k}-flags"));
            out.push(format!("vpn.data {k} = {}", if protected { "***" } else { v.as_str() }));
        }
    }
    out
}

impl Engine {
    pub fn new(
        bus: fn() -> zbus::Result<zbus::blocking::Connection>,
        sandbox: bool,
        user: String,
        uid: u32,
        runtime: Option<PathBuf>,
        data: PathBuf,
    ) -> Arc<Engine> {
        Arc::new(Engine {
            bus,
            sandbox,
            user,
            uid,
            runtime,
            data,
            helper: HelperState::default(),
            native: NativeState::default(),
        })
    }

    fn lock_runs(&self) -> MutexGuard<'_, Runs> {
        self.helper.runs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The journal pump's `linvpn-logd` socket (`None`: the installed one).
    fn logd_socket(&self) -> Option<PathBuf> {
        self.helper.logd_socket.read().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// `$XDG_DATA_HOME/LinVPN/logs`.
    pub fn logs_dir(&self) -> PathBuf {
        self.data.join("logs")
    }

    /// The connection's log file (whether or not it exists).
    pub fn log_file(&self, id: &Uuid) -> PathBuf {
        connlog::path(&self.logs_dir(), id)
    }

    /// The NM client and the registered agent (created on first use; the agent registers once per process and
    /// again when NetworkManager restarts).
    pub fn nm(&self) -> Result<(&NmClient, &Agent), String> {
        if let (Some(c), Some(a)) = (self.helper.client.get(), self.helper.agent.get()) {
            return Ok((c, a));
        }
        let _init = self.helper.init.lock().unwrap_or_else(PoisonError::into_inner);
        if self.helper.client.get().is_none() {
            let bus = (self.bus)().map_err(|_| nm_unavailable())?;
            let _ = self.helper.client.set(NmClient::new(bus));
        }
        let client = self.helper.client.get().ok_or_else(nm_unavailable)?;
        if self.helper.agent.get().is_none() {
            let agent = Agent::register(client.bus()).map_err(|e| agent_refusal(&e))?;
            let _ = self.helper.agent.set(agent);
        }
        Ok((client, self.helper.agent.get().ok_or_else(nm_unavailable)?))
    }

    /// What the system offers for planning (OpenVPN's version, the swanctl folder, the secret mode); cached 60 s.
    pub fn caps(&self) -> Caps {
        let mut cached = self.helper.caps.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((at, caps)) = cached.as_ref()
            && at.elapsed() < CAPS_TTL
        {
            return caps.clone();
        }
        let version = self.helper.client.get().and_then(NmClient::version);
        let facts = plugins::facts(version);
        let swanctl = self.data.join("swanctl");
        let mut ca_files: Vec<String> = std::fs::read_dir(swanctl.join("x509ca"))
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| !n.starts_with('.'))
                    .collect()
            })
            .unwrap_or_default();
        ca_files.sort();
        let caps = Caps {
            openvpn_push_visible: facts.openvpn_version.as_deref().is_some_and(openvpn_at_least_2_7),
            secret_mode: DEFAULT_SECRET_MODE,
            swanctl_dir: Some(swanctl),
            swanctl_ca_files: ca_files,
            // The pinned network-manager-strongswan (1.6.4, Ubuntu 26.04) knows `remote-ts` / `local-ts`.
            strongswan_remote_ts: facts.services.iter().any(|s| s == SERVICE_STRONGSWAN),
        };
        *cached = Some((Instant::now(), caps.clone()));
        caps
    }

    /// Plans, writes the runtime files, announces the secrets to the agent (or inlines them), deletes a leftover,
    /// adds and activates, logs; the run is kept under `id`. Errors are the user's message (localized).
    pub fn activate(
        &self,
        id: Uuid,
        connection: &Connection,
        config: &[u8],
        secrets: &Secrets,
        debug: bool,
    ) -> Result<(), String> {
        if self.sandbox {
            return Err(texts::not_yet());
        }
        let Some(runtime) = self.runtime.clone() else { return Err(no_runtime_dir()) };
        self.adopt();
        if self.lock_runs().by_id.contains_key(&id) {
            self.deactivate(&id)?;
        }
        let nm_uuid = names::nm_uuid(self.uid, &id).to_string();
        let runtime_dir = files::dir_for(&runtime, &nm_uuid);
        let caps = self.caps();
        // The IKEv2 client certificate imported in the app (G4): the plan writes it as two private runtime files.
        let stored = secrets.client_cert.as_deref().filter(|s| !s.is_empty() && connection.kind == VPNKind::Strongswan);
        let client_cert = match stored {
            Some(stored) => Some(
                ClientCert::from_stored(stored)
                    .ok_or_else(|| l10n::tr("The imported client certificate cannot be read. Import it again.", &[]))?,
            ),
            None => None,
        };
        // A PKCS#12 file (restored from a Mac): converted to PEM with the key password (asked at connect when not
        // saved), only for this connect's runtime files; the vault keeps it as it is.
        let client_cert = match client_cert {
            Some(ClientCert::Pkcs12 { der }) => {
                let password = secrets.key_password.as_deref().unwrap_or("");
                Some(crate::lin::pkcs12::convert(&der, password)?.cert)
            }
            other => other,
        };
        let input = Input {
            connection,
            config,
            user: &self.user,
            uid: self.uid,
            runtime_dir: &runtime_dir,
            caps: &caps,
            client_cert: client_cert.as_ref().map_or(ImportedCert::None, ImportedCert::Cert),
        };
        let mut plan = nm_plan::plan(&input).map_err(|u| u.to_string())?;
        drop(client_cert);
        let values = resolve_secrets(&plan.secrets, secrets);
        check_ikev2_psk(&plan, &values)?;
        fill_user_name(&mut plan, secrets);

        let (client, agent) = self.nm()?;
        // R1: nothing is written (no file, no NM call) unless NM's writes need no password.
        if polkit::check_nm_write(client.bus()) != Authorization::Authorized {
            return Err(not_authorized());
        }
        client.delete_own_volatile(&nm_uuid, &self.user).map_err(|e| e.message())?;
        // The connection's directory: its certificate files (if any) and the run record the next process adopts it
        // by, should this one end with the tunnel up.
        let since = unix_now();
        let record =
            RunRecord { id, kind: plan.kind, iface: plan.iface.clone(), keepalive: keepalive_of(&plan), since };
        let runtime_files = files::write(&runtime, &nm_uuid, &plan.files)
            .and_then(|written| written.write_record(&record).map(|()| written))
            .map_err(|e| {
                l10n::tr("LinVPN could not write the connection's certificate files: %@", &[Arg::Str(&e.to_string())])
            })?;

        let mut masker = Masker::new(secrets);
        masker.secrets.extend(values.iter().map(|(_, _, v)| v.clone()));
        let mut settings = value::to_dbus(&plan.settings);
        // Only for this run's profile: its path once NM gave it (`bind` below; a request before that waits), LinVPN's
        // own permission and the planned plugin (security review L1).
        let rules = Rules { user: Some(self.user.clone()), service_type: plan.service_type.map(String::from) };
        let expect = match caps.secret_mode {
            SecretMode::Agent => agent.expect(&nm_uuid, rules, Answer { items: values }),
            SecretMode::Inline => {
                put_inline(&mut settings, &values);
                drop(values);
                // CRV1 stays with the agent.
                agent.expect(&nm_uuid, rules, Answer { items: Vec::new() })
            }
        };

        let log = ConnLog::open(&self.logs_dir(), &id);
        let service = plan.service_type.unwrap_or("wireguard");
        log.line(&l10n::tr("Connecting with NetworkManager (%@)", &[Arg::Str(service)]));
        if debug {
            for line in debug_lines(&plan) {
                log.line(&masker.line(&line));
            }
        }
        self.ensure_watch(client);
        // linvpn-logd's reading of NM's active VPNs just before this activation: it lets the plugin lines of this
        // run through once earlier VPNs (which NM logs no end of) are gone.
        logd_client::mark(self.logd_socket().as_deref(), id);
        let activation = client.add_and_activate(&settings);
        drop(settings);
        let activation = match activation {
            Ok(a) => a,
            Err(e) => {
                let message = match &e {
                    NmError::Failed(_) if client.uuid_taken_by_another(&nm_uuid, &self.user) => texts::uuid_squatted(),
                    _ => e.message(),
                };
                log.line(&masker.line(&message));
                return Err(message);
            }
        };
        expect.bind(&activation.settings_path);
        let pump = log.pump_from(id, masker, self.logd_socket().as_deref());
        let run = Run {
            kind: plan.kind,
            nm_uuid,
            active_path: activation.active_path,
            iface: plan.iface.clone(),
            keepalive: record.keepalive,
            since,
            was_activated: false,
            reconnecting_since: None,
            last_reason: None,
            ended: false,
            gone_since: None,
            ip: None,
            ip_unlogged: false,
            files: Some(runtime_files),
            expect: Some(expect),
            log,
            pump: Some(pump),
            log_secrets_missing: false,
        };
        let mut runs = self.lock_runs();
        let path = run.active_path.clone();
        runs.by_id.insert(id, run);
        // State changes that came before the run was stored.
        let early: Vec<(VpnState, u32)> =
            runs.orphans.iter().filter(|(p, _, _)| *p == path).map(|(_, s, r)| (*s, *r)).collect();
        runs.orphans.retain(|(p, _, _)| *p != path);
        for (s, reason) in early {
            apply_vpn_state(&mut runs, &path, s, reason, None);
        }
        Ok(())
    }

    /// Once per process (the first start, stop or status, or the app's setup): takes back the connections an
    /// earlier LinVPN process left up ("Quit, Keep Them Running", a crash), then sweeps the runtime files of the
    /// ones that are gone. A connection is adopted only when its run record's directory is the derived UUID of the
    /// record's id, NM has it active under that UUID, and its profile is volatile and private to this user (R9).
    /// The run gets its log and journal pump again and an agent expectation without secrets (a dynamic challenge
    /// still reaches the app); it reports `connected` with NM's address, so app-core's adoption, liveness and
    /// reconnect take it from there. Without NM's answer nothing is swept (a tunnel may still need its files).
    pub fn adopt(&self) {
        let mut done = self.helper.adopted.lock().unwrap_or_else(PoisonError::into_inner);
        if *done {
            return;
        }
        *done = true;
        if self.sandbox {
            return;
        }
        let Some(runtime) = self.runtime.clone() else { return };
        let Ok((client, agent)) = self.nm() else { return };
        let Ok(active) = client.active() else { return };
        let mut adopted = false;
        for (name, record) in files::records(&runtime) {
            let nm_uuid = names::nm_uuid(self.uid, &record.id).to_string();
            if name != nm_uuid || self.lock_runs().by_id.contains_key(&record.id) {
                continue;
            }
            let Some(info) = active.iter().find(|a| a.uuid == nm_uuid) else { continue };
            let Some(state) = state::root_state(info.state, info.vpn_state) else { continue };
            let Ok(Some(profile_path)) = client.own_volatile_path(&nm_uuid, &self.user) else { continue };
            let log = ConnLog::open(&self.logs_dir(), &record.id);
            let pump = log.pump_from(record.id, Masker::new(&Secrets::default()), self.logd_socket().as_deref());
            let run = Run {
                kind: record.kind,
                nm_uuid: nm_uuid.clone(),
                active_path: info.path.clone(),
                iface: record.iface.clone(),
                keepalive: record.keepalive,
                since: record.since,
                // Already up: no second "Connected" line in the log.
                was_activated: state == "connected",
                reconnecting_since: None,
                last_reason: None,
                ended: false,
                gone_since: None,
                ip: info.ip4.clone(),
                ip_unlogged: false,
                files: RuntimeFiles::adopt(&runtime, &nm_uuid),
                expect: Some({
                    let rules = Rules { user: Some(self.user.clone()), service_type: None };
                    let expect = agent.expect(&nm_uuid, rules, Answer { items: Vec::new() });
                    expect.bind(&profile_path);
                    expect
                }),
                log,
                pump: Some(pump),
                // The secrets are in the vault: app-core hands them over once it is unlocked.
                log_secrets_missing: true,
            };
            self.lock_runs().by_id.insert(record.id, run);
            adopted = true;
        }
        if adopted {
            self.ensure_watch(client);
        }
        let keep: HashSet<String> = active.into_iter().map(|a| a.uuid).collect();
        files::sweep(&runtime, &keep);
    }

    /// Starts the watcher on NM's signals once (before the first add, so no state change of it is missed).
    fn ensure_watch(&self, client: &NmClient) {
        let mut watch = self.helper.watch.lock().unwrap_or_else(PoisonError::into_inner);
        if watch.is_some() {
            return;
        }
        let runs = self.helper.runs.clone();
        let lookup = NmClient::new(client.bus().clone());
        let on = move |event: NmEvent| {
            if let NmEvent::ActiveState { active_path, state, reason } = &event {
                let mut runs = runs.lock().unwrap_or_else(PoisonError::into_inner);
                apply_active_state(&mut runs, active_path, *state, *reason);
                return;
            }
            let NmEvent::VpnState { active_path, state, reason } = event else { return };
            // The address of a newly activated VPN, read before the lock (a D-Bus call).
            let ip = if state == VpnState::Activated {
                lookup.active().ok().and_then(|all| all.into_iter().find(|a| a.path == active_path)).and_then(|a| a.ip4)
            } else {
                None
            };
            let mut runs = runs.lock().unwrap_or_else(PoisonError::into_inner);
            apply_vpn_state(&mut runs, &active_path, state, reason, ip);
        };
        if let Ok(guard) = client.watch(Box::new(on)) {
            *watch = Some(guard);
        }
    }

    /// Deactivates `id`'s run (if any) and drops its files and its agent expectation. Without a run, a leftover
    /// activation of this connection (its derived UUID) is deactivated.
    pub fn deactivate(&self, id: &Uuid) -> Result<(), String> {
        self.adopt();
        let run = self.lock_runs().by_id.remove(id);
        let Some(run) = run else {
            let Some(client) = self.helper.client.get() else { return Ok(()) };
            let nm_uuid = names::nm_uuid(self.uid, id).to_string();
            for a in client.active().unwrap_or_default().into_iter().filter(|a| a.uuid == nm_uuid) {
                client.deactivate(&a.path).map_err(|e| e.message())?;
            }
            return Ok(());
        };
        if let Some(client) = self.helper.client.get() {
            // Already gone (`ConnectionNotActive`), or NM is not there: nothing runs.
            if let Err(NmError::NotAuthorized(m)) = client.deactivate(&run.active_path) {
                self.lock_runs().by_id.insert(*id, run);
                return Err(m);
            }
        }
        run.log.line(state::STOPPED_LINE);
        drop(run);
        Ok(())
    }

    /// The runs with their NM state now (the watcher keeps `reconnecting_since`); vanished ones are dropped with
    /// their reason logged.
    pub fn runs(&self) -> Vec<RunView> {
        self.try_runs().unwrap_or_default()
    }

    /// [`Engine::runs`], or NM's error when it could not be asked.
    pub fn try_runs(&self) -> Result<Vec<RunView>, String> {
        self.adopt();
        if self.lock_runs().by_id.is_empty() {
            return Ok(Vec::new());
        }
        let Some(client) = self.helper.client.get() else { return Ok(Vec::new()) };
        let active = client.active().map_err(|e| e.message())?;
        let mut runs = self.lock_runs();
        let mut views = Vec::new();
        let mut drop_ids = Vec::new();
        for (id, run) in runs.by_id.iter_mut() {
            let info = active.iter().find(|a| a.path == run.active_path);
            match info.and_then(|a| state::root_state(a.state, a.vpn_state)) {
                Some(s) => {
                    run.gone_since = None;
                    run.ip = info.and_then(|a| a.ip4.clone());
                    if s == "connected" {
                        run.connected(None);
                    } else {
                        run.not_connected();
                    }
                    views.push(run.view(*id, s));
                }
                None => {
                    // A run waits briefly for its end reason (the watcher's signal: a VPN's VPN state, WireGuard's
                    // active connection state).
                    let gone_since = *run.gone_since.get_or_insert_with(Instant::now);
                    if run.ended || gone_since.elapsed() >= REASON_GRACE {
                        if !run.ended {
                            run.log.line(state::reason_line(11));
                            run.ended = true;
                        }
                        drop_ids.push(*id);
                    } else {
                        views.push(run.view(*id, "connecting"));
                    }
                }
            }
        }
        for id in drop_ids {
            runs.by_id.remove(&id);
        }
        Ok(views)
    }

    /// The tunnel's counters (`sysfs` in production).
    pub fn counters_of(&self, iface: &str) -> Option<(u64, u64)> {
        (self.helper.counters.read().unwrap_or_else(PoisonError::into_inner))(iface)
    }

    /// The traffic interface of a connected run: LinVPN's own name (WireGuard, OpenVPN), the PPP / tun interface
    /// holding the VPN's address (SSTP, L2TP, Cisco), charon-nm's XFRM interface holding it (IKEv2 with strongSwan 6;
    /// none with an older, policy-based charon-nm: `linvpn-xfrmd` counts its SAs; resolved point 16).
    pub fn traffic_iface(&self, id: &Uuid) -> Option<(String, f64)> {
        let (kind, iface, ip, since) = {
            let runs = self.lock_runs();
            let run = runs.by_id.get(id).filter(|r| r.was_activated && r.gone_since.is_none())?;
            (run.kind, run.iface.clone(), run.ip.clone(), run.since)
        };
        let iface = match kind {
            VPNKind::Wireguard | VPNKind::Openvpn => iface,
            VPNKind::Sstp | VPNKind::L2tp | VPNKind::Cisco | VPNKind::Strongswan => {
                self.vpn_iface_for(kind == VPNKind::Strongswan, ip.as_deref()?)
            }
        }?;
        Some((iface, since))
    }

    /// The tunnel interface holding a plugin VPN's address `ip`: for IKEv2 only charon-nm's XFRM interface.
    pub(crate) fn vpn_iface_for(&self, ikev2: bool, ip: &str) -> Option<String> {
        let ifaces = (self.helper.tunnel_ifaces.read().unwrap_or_else(PoisonError::into_inner))(ip);
        ifaces.into_iter().find(|name| !ikev2 || is_charon_nm_xfrm(name))
    }

    /// Tests only: replaces the "tunnel interfaces holding an address" source (sysfs in production).
    #[doc(hidden)]
    pub fn set_tunnel_ifaces_for_tests(&self, f: IfaceSource) {
        *self.helper.tunnel_ifaces.write().unwrap_or_else(PoisonError::into_inner) = f;
    }

    /// Tests only: replaces the sysfs counter source (the fake bus has no real interface).
    #[doc(hidden)]
    pub fn set_counters_for_tests(&self, f: CounterSource) {
        *self.helper.counters.write().unwrap_or_else(PoisonError::into_inner) = f;
    }
}

/// NM's `NM_ACTIVE_CONNECTION_STATE_DEACTIVATED`.
const ACTIVE_DEACTIVATED: u32 = 4;

/// One `Connection.Active.StateChanged` of `path`: a WireGuard run's end and its reason (a VPN's comes from its VPN
/// state, `apply_vpn_state`), so `nmcli connection down` / GNOME's menu (`USER_DISCONNECTED`) is logged as the
/// user's stop, not as a drop.
fn apply_active_state(runs: &mut Runs, path: &str, state: u32, reason: u32) {
    if state != ACTIVE_DEACTIVATED {
        return;
    }
    let Some((id, run)) = runs.by_id.iter_mut().find(|(_, r)| r.active_path == path && r.kind == VPNKind::Wireguard)
    else {
        return;
    };
    let id = *id;
    run.expect = None;
    run.last_reason = Some(reason);
    if !run.ended {
        run.log.line(state::reason_line(reason));
        run.ended = true;
    }
    if run.gone_since.is_some() {
        runs.by_id.remove(&id);
    }
}

/// One `VpnStateChanged` of `path`: its run's facts and log lines (or kept for the run stored next).
fn apply_vpn_state(runs: &mut Runs, path: &str, state: VpnState, reason: u32, ip: Option<String>) {
    let Some((id, run)) = runs.by_id.iter_mut().find(|(_, r)| r.active_path == path) else {
        if runs.orphans.len() >= ORPHANS_MAX {
            runs.orphans.pop_front();
        }
        runs.orphans.push_back((path.to_string(), state, reason));
        return;
    };
    let id = *id;
    match state {
        VpnState::Activated => {
            if ip.is_some() {
                run.ip = ip;
            }
            run.connected(None);
        }
        VpnState::Failed | VpnState::Disconnected => {
            // The secrets go at once: this activation asks for nothing more (a reconnect announces its own).
            run.expect = None;
            run.last_reason = Some(reason);
            if !run.ended {
                run.log.line(state::reason_line(reason));
                run.ended = true;
            }
            if run.gone_since.is_some() {
                runs.by_id.remove(&id);
            }
        }
        VpnState::Prepare | VpnState::NeedAuth | VpnState::Connect | VpnState::IpConfigGet | VpnState::Unknown => {
            run.not_connected();
        }
    }
}
