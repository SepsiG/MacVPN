//! Auto-reconnect's driver (maintainer decision 4): one thread owns the work around the
//! [`Planner`](macvpn_app_core::reconnect::Planner). It receives the events (connect started, connected, dropped,
//! failed, user disconnect, sleep, wake, network change), probes the physical network when something is due, and
//! runs the planner's actions (a connect, a disconnect of a tunnel on its own network, a notice). Probes, log reads
//! and connects never run on the manager's, the main or a hook's thread. No OS `cfg`: the OS is behind
//! `Platform::network()` and the lifecycle.

use macvpn_app_core::deps::ConnectionRepository;
use macvpn_app_core::reconnect::{self, Action, Planner, fingerprint};
use macvpn_app_core::{ConnectionEvent, ConnectionItem, DisconnectCause};
use macvpn_core::date::Date;
use macvpn_core::log::LogTailer;
use macvpn_core::models::{Connection, ConnectionState, parse_uuid};
use macvpn_core::vpn_networks::VpnNetworks;
use macvpn_platform_api::NetworkSnapshot;
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::platform;
use crate::state::AppState;

/// How often the driver looks at the planner's timers without an event.
const TICK: Duration = Duration::from_secs(1);

pub enum Event {
    /// A connection left `disconnected`/`failed` for `connecting`.
    Started(String),
    Connected(String),
    /// `ConnectionEvent::Dropped` (key, name).
    Dropped(String, String),
    /// `ConnectionEvent::Failed` (key, the manager's reason).
    Failed(String, String),
    UserDisconnected(String),
    /// The connection was deleted.
    Forget(String),
    /// The system is about to sleep: the connected managed keys.
    Sleep(Vec<String>),
    /// The system woke: the connected managed keys before the poller's refresh.
    Wake(Vec<String>),
    NetworkChanged,
}

/// Owned by `AppState` (created with it, so the lifecycle hooks registered before `connect_hooks` can send);
/// [`start`] runs the driver thread. Events sent earlier wait in the channel.
pub struct Reconnect {
    tx: Mutex<Sender<Event>>,
    rx: Mutex<Option<Receiver<Event>>>,
    planner: Mutex<Planner>,
    /// The connections' configs (the VPN's networks).
    store: Arc<dyn ConnectionRepository>,
    /// The network change watcher (outside the sandbox). Dropping it stops it.
    watch: Mutex<Option<Box<dyn Send>>>,
}

impl Reconnect {
    pub fn new(store: Arc<dyn ConnectionRepository>) -> Self {
        let (tx, rx) = channel();
        Reconnect {
            tx: Mutex::new(tx),
            rx: Mutex::new(Some(rx)),
            planner: Mutex::default(),
            store,
            watch: Mutex::new(None),
        }
    }

    pub fn send(&self, e: Event) {
        let _ = self.tx.lock().unwrap_or_else(PoisonError::into_inner).send(e);
    }

    /// The planner's own connect of `key` is running (its failure gets no "connection failed" notice: the planner
    /// posts one "could not reconnect" at the end).
    pub fn is_attempting(&self, key: &str) -> bool {
        self.planner().is_attempting(key)
    }

    /// Quitting: the network watcher stops.
    pub fn stop(&self) {
        drop(self.watch.lock().unwrap_or_else(PoisonError::into_inner).take());
    }

    fn planner(&self) -> MutexGuard<'_, Planner> {
        self.planner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn managed(state: &AppState, key: &str) -> Option<Connection> {
    match state.manager.item(key) {
        Some(ConnectionItem::Managed(c)) => Some(c),
        _ => None,
    }
}

/// The managed connections that are connected now.
pub fn connected_keys(state: &AppState) -> Vec<String> {
    let mut keys: Vec<String> = state
        .manager
        .states()
        .into_iter()
        .filter(|(k, s)| s.is_connected() && managed(state, k).is_some())
        .map(|(k, _)| k)
        .collect();
    keys.sort();
    keys
}

/// The physical network now; `None` when it cannot be read (the sandbox has no probe; a smoke run scripts it).
fn snapshot(state: &AppState) -> Option<NetworkSnapshot> {
    if state.env.sandbox {
        #[cfg(debug_assertions)]
        return platform::smoke_network(state);
        #[cfg(not(debug_assertions))]
        return None;
    }
    platform::get().network().snapshot().ok()
}

/// The VPN's networks: its stored config (a wiped copy), plus OpenVPN's PUSH_REPLY from the current log.
fn networks(state: &AppState, c: &Connection) -> VpnNetworks {
    let config = state.reconnect.store.load_config_wiped(&c.id).map(|z| z.to_string()).unwrap_or_default();
    let mut n = VpnNetworks::from_config(c.kind, &config);
    if let Some(source) = state.helper.log_source(&c.id) {
        n.add_pushed(&LogTailer::with_source(source).read_new());
    }
    n
}

/// Starts the driver thread and the network watcher (outside the sandbox). Once, from `connect_hooks`.
pub fn start(state: &Arc<AppState>) {
    let Some(rx) = state.reconnect.rx.lock().unwrap_or_else(PoisonError::into_inner).take() else { return };
    wire(state);
    if !state.env.sandbox {
        let watching = state.clone();
        match platform::get().network().watch(Box::new(move || watching.reconnect.send(Event::NetworkChanged))) {
            Ok(guard) => *state.reconnect.watch.lock().unwrap_or_else(PoisonError::into_inner) = Some(guard),
            Err(e) => eprintln!("MacVPN: the network watcher did not start ({e}); no reconnect after a network change"),
        }
    }
    let s = state.clone();
    std::thread::Builder::new().name("macvpn-reconnect".into()).spawn(move || run(&s, &rx)).expect("reconnect thread");
}

fn run(state: &Arc<AppState>, rx: &Receiver<Event>) {
    let r = &state.reconnect;
    loop {
        match rx.recv_timeout(TICK) {
            Ok(e) => handle(state, e),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let now = Date::now();
        if r.planner().survivors_due(now) {
            // Probed and read without the planner's lock (the manager's hooks ask it).
            let snap = snapshot(state).unwrap_or_default();
            let connected = connected_keys(state);
            let actions = r.planner().survivors(now, &snap, &connected);
            actions.into_iter().for_each(|a| act(state, a));
        }
        if !r.planner().due(now) {
            continue;
        }
        let Some(snap) = snapshot(state) else { continue };
        let prefs = state.prefs.clone();
        let enabled = move |key: &str| parse_uuid(key).is_some_and(|u| reconnect::is_enabled(prefs.as_ref(), &u));
        let locked = state.manager.is_locked();
        let actions = r.planner().evaluate(now, &snap, &enabled, locked);
        actions.into_iter().for_each(|a| act(state, a));
    }
}

fn handle(state: &Arc<AppState>, e: Event) {
    let r = &state.reconnect;
    let now = Date::now();
    match e {
        Event::Started(key) => {
            if managed(state, &key).is_none() {
                return;
            }
            let ours = r.is_attempting(&key);
            let fp = if ours { None } else { snapshot(state).as_ref().and_then(fingerprint) };
            r.planner().connect_started(&key, fp, ours);
        }
        Event::Connected(key) => {
            let Some(c) = managed(state, &key) else { return };
            let n = networks(state, &c);
            r.planner().connected(&key, n);
        }
        Event::Dropped(key, name) => {
            if managed(state, &key).is_none() {
                return;
            }
            let kind = crate::notifications::classify(state, &key);
            r.planner().dropped(&key, &name, now, kind);
        }
        Event::Failed(key, reason) => {
            if !r.is_attempting(&key) {
                return;
            }
            // A cancelled MFA or credential prompt is the user's answer: no more attempts, no notice.
            if reason == macvpn_app_core::manager::auth_cancelled_reason() || state.manager.credentials_cancelled(&key)
            {
                r.planner().user_disconnected(&key);
                return;
            }
            let kind = crate::notifications::classify(state, &key);
            let actions = r.planner().failed(&key, now, kind);
            actions.into_iter().for_each(|a| act(state, a));
        }
        Event::UserDisconnected(key) => r.planner().user_disconnected(&key),
        Event::Forget(key) => r.planner().forget(&key),
        Event::Sleep(connected) => {
            let fp = snapshot(state).as_ref().and_then(fingerprint);
            r.planner().sleep(&connected, fp);
        }
        Event::Wake(connected) => r.planner().wake(now, &connected),
        Event::NetworkChanged => r.planner().network_changed(now),
    }
}

fn act(state: &Arc<AppState>, action: Action) {
    match action {
        Action::Notify(n) => crate::notifications::notice(state, &n),
        Action::Disconnect(key) => {
            let Some(c) = managed(state, &key) else { return };
            let manager = state.manager.clone();
            // As the user's: leases on it end, and the user-disconnect rule keeps it down.
            std::thread::spawn(move || manager.disconnect_for(&c, DisconnectCause::User));
        }
        Action::Connect(key) => {
            let Some(c) = managed(state, &key) else { return };
            // Already coming up (the user was faster): its outcome ends the attempt (connected or failed).
            if state.manager.state(&key).is_active() {
                return;
            }
            state.notices.lock().unwrap_or_else(PoisonError::into_inner).mark_auto(&key);
            let manager = state.manager.clone();
            std::thread::spawn(move || manager.connect(&c, false));
        }
    }
}

/// The manager's hooks: a connect started (from idle), connected, and the user's disconnects. The listeners only
/// send (they run under the manager's lock).
fn wire(state: &Arc<AppState>) {
    let s = state.clone();
    let last: Mutex<HashMap<String, ConnectionState>> = Mutex::default();
    state.manager.add_state_listener(move |key, new| {
        let previous = last.lock().unwrap_or_else(PoisonError::into_inner).insert(key.to_string(), new.clone());
        let was_idle = !previous.as_ref().is_some_and(ConnectionState::is_active);
        if was_idle && matches!(new, ConnectionState::Connecting) {
            s.reconnect.send(Event::Started(key.to_string()));
        }
        if new.is_connected() && !previous.as_ref().is_some_and(ConnectionState::is_connected) {
            s.reconnect.send(Event::Connected(key.to_string()));
        }
    });
    let s = state.clone();
    state.manager.add_user_disconnect_listener(move |key| s.reconnect.send(Event::UserDisconnected(key.to_string())));
}

/// From the manager's event hook: drops and failed connects.
pub fn event(r: &Reconnect, e: &ConnectionEvent) {
    match e {
        ConnectionEvent::Dropped { connection_id, name } => r.send(Event::Dropped(connection_id.clone(), name.clone())),
        ConnectionEvent::Failed { connection_id, reason, .. } => {
            r.send(Event::Failed(connection_id.clone(), reason.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    /// The connection logs are read through the manager's helper (`AppState::helper`): in a smoke run that is the
    /// stand-in, so nothing asks the real root helper or the installed WinVPN Service. The platform's own helper
    /// is only built once, in `main.rs`.
    #[test]
    fn logs_are_read_through_the_states_helper() {
        let platform_helper = concat!("helper_client", "()");
        for (file, source) in [
            ("reconnect.rs", include_str!("reconnect.rs")),
            ("notifications.rs", include_str!("notifications.rs")),
            ("manage.rs", include_str!("manage.rs")),
        ] {
            assert!(!source.contains(platform_helper), "{file} reads a log through the platform's helper");
        }
        assert_eq!(include_str!("main.rs").matches(platform_helper).count(), 1);
    }
}
