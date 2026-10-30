//! Auto-reconnect's driver (maintainer decision 4): one thread owns the work around the
//! [`Planner`](macvpn_app_core::reconnect::Planner). It receives the events (connect started, connected, dropped,
//! failed, user disconnect, sleep, wake, network change), probes the physical network when something is due, and
//! runs the planner's actions (a connect, a disconnect of a tunnel on its own network or after a long network
//! loss, a notice). After a network change it checks (debounced) whether the connections up or connecting still
//! have a physical network under them; the ones that do not "wait for network" in the rows and the tray
//! ([`Reconnect::waiting_for_network`]). While a network is there it also asks the helper about the connected
//! tunnels (dead-tunnel detection, [`macvpn_app_core::liveness`]): OpenVPN restarting itself shows "Reconnecting…",
//! a dead tunnel is disconnected and, by the planner's rules, reconnected. Probes, log reads, helper polls and
//! connects never run on the manager's, the main or a hook's thread. No OS `cfg`: the OS is behind
//! `Platform::network()`, the helper and the lifecycle.

use macvpn_app_core::deps::ConnectionRepository;
use macvpn_app_core::reconnect::{self, Action, Planner, fingerprint};
use macvpn_app_core::{ConnectionEvent, ConnectionItem, DisconnectCause};
use macvpn_core::date::Date;
use macvpn_core::liveness::Liveness;
use macvpn_core::log::LogTailer;
use macvpn_core::models::{Connection, ConnectionState, VPNKind, parse_uuid};
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
    /// The control API's connect for a lease began (`true`) or returned (`false`); see [`Reconnect::lease_connect`].
    LeaseConnect(String, bool),
    /// The connection was deleted.
    Forget(String),
    /// The system is about to sleep: the connected managed keys.
    Sleep(Vec<String>),
    /// The system woke: the connected managed keys before the poller's refresh.
    Wake(Vec<String>),
    NetworkChanged,
    /// The app's disconnect of a dead tunnel returned (its reconnect may follow).
    DeadDown(String),
    /// The connection went from up or connecting to down (any cause): its lease mark goes.
    Down(String),
    /// Ask the tunnels now (a smoke run; the planner's own schedule otherwise).
    #[cfg(debug_assertions)]
    LivenessNow,
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
    /// A smoke run moves the driver's clock forward (seconds) instead of waiting minutes.
    #[cfg(debug_assertions)]
    skew: Mutex<f64>,
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
            #[cfg(debug_assertions)]
            skew: Mutex::new(0.0),
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

    /// Runs `connect`, the control API's connect of `key` for a lease. The events around it go through the same
    /// channel as the manager's, in order: the `Started` it causes (sent on this thread, from the state listener)
    /// falls between them, so the planner marks the connection as the lease's and never reconnects it.
    pub fn lease_connect<R>(&self, key: &str, connect: impl FnOnce() -> R) -> R {
        self.send(Event::LeaseConnect(key.to_string(), true));
        let result = connect();
        self.send(Event::LeaseConnect(key.to_string(), false));
        result
    }

    /// The connections waiting for network (their rows and the tray say so).
    pub fn waiting_for_network(&self) -> Vec<String> {
        self.planner().waiting_for_network()
    }

    /// OpenVPN restarting itself (their rows show "Reconnecting…").
    pub fn reconnecting(&self) -> Vec<String> {
        self.planner().reconnecting()
    }

    /// The slow tier's next attempts (key, Unix time; their rows show "Retrying in … min").
    pub fn slow_retries(&self) -> Vec<(String, f64)> {
        self.planner().slow_retries().into_iter().map(|(k, d)| (k, d.time_interval_since_1970())).collect()
    }

    /// The tunnels found dead and disconnected (their rows show "Not responding").
    pub fn not_responding(&self) -> Vec<String> {
        self.planner().not_responding()
    }

    /// A smoke run: the driver's clock moves `seconds` forward (the planner's timers with it).
    #[cfg(debug_assertions)]
    pub fn skew(&self, seconds: f64) {
        *self.skew.lock().unwrap_or_else(PoisonError::into_inner) += seconds;
    }

    /// The driver's time.
    fn now(&self) -> Date {
        #[cfg(debug_assertions)]
        return Date::now().adding(*self.skew.lock().unwrap_or_else(PoisonError::into_inner));
        #[cfg(not(debug_assertions))]
        Date::now()
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

/// The managed connections up or connecting (not waiting for authentication: the user is busy with it), with
/// their display names, sorted: the ones that wait for network when there is none.
fn active_items(state: &AppState) -> Vec<(String, String)> {
    let mut items: Vec<(String, String)> = state
        .manager
        .states()
        .into_iter()
        .filter(|(_, s)| matches!(s, ConnectionState::Connecting | ConnectionState::Connected { .. }))
        .filter_map(|(k, _)| managed(state, &k).map(|c| (k, c.name)))
        .collect();
    items.sort();
    items
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
    // Connections a lease started that were left up by "Quit, Keep Them Running": still the leases'.
    state.reconnect.planner().restore_leased(&reconnect::lease_marks(state.prefs.as_ref()));
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
    let mut shown: (Vec<String>, Vec<String>, Vec<String>, Vec<String>) = Default::default();
    loop {
        match rx.recv_timeout(TICK) {
            Ok(e) => handle(state, e),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let now = r.now();
        if r.planner().survivors_due(now) {
            // Probed and read without the planner's lock (the manager's hooks ask it).
            let snap = snapshot(state).unwrap_or_default();
            let connected = connected_keys(state);
            let actions = r.planner().survivors(now, &snap, &connected);
            actions.into_iter().for_each(|a| act(state, a));
        }
        network_loss(state, now);
        liveness(state, now);
        // Decided outside a returning call (a drop that started the slow tier).
        let queued = r.planner().take_actions();
        queued.into_iter().for_each(|a| act(state, a));
        // The rows and the tray follow the connections waiting for network, reconnecting or not responding.
        let retrying: Vec<String> = r.slow_retries().into_iter().map(|(k, at)| format!("{k}@{at}")).collect();
        let now_shown = (r.waiting_for_network(), r.reconnecting(), r.not_responding(), retrying);
        if now_shown != shown {
            shown = now_shown;
            state.publisher.mark();
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

/// The network loss rule: the debounced check of the physical network under the active connections, and the
/// disconnect of those that waited for it too long.
fn network_loss(state: &Arc<AppState>, now: Date) {
    let r = &state.reconnect;
    if r.planner().network_check_due(now) {
        let active = active_items(state);
        // Nothing active: nothing to probe (the check only forgets what waited).
        let snap = if active.is_empty() { None } else { snapshot(state) };
        let actions = r.planner().network_checked(now, snap.as_ref(), &active);
        actions.into_iter().for_each(|a| act(state, a));
    }
    if r.planner().offline_due(now) {
        let prefs = state.prefs.clone();
        let enabled = move |key: &str| parse_uuid(key).is_some_and(|u| reconnect::is_enabled(prefs.as_ref(), &u));
        let actions = r.planner().offline_expired(now, &enabled);
        actions.into_iter().for_each(|a| act(state, a));
    }
}

/// The engines whose tunnels report liveness (the helper's `liveness`); the others' death shows in their state.
/// LinVPN's IKEv2 too: its IPsec SAs' counters (`linvpn-xfrmd`), since charon-nm's own DPD is all it has otherwise.
fn watched(kind: VPNKind) -> bool {
    matches!(kind, VPNKind::Wireguard | VPNKind::Openvpn)
        || (kind == VPNKind::Strongswan && crate::platform::ikev2_reports_liveness())
}

/// Dead-tunnel detection: when due, the connected tunnels are asked (without the planner's lock) and the planner
/// decides.
fn liveness(state: &Arc<AppState>, now: Date) {
    let r = &state.reconnect;
    if !r.planner().liveness_due(now) {
        return;
    }
    let polled: Vec<(String, String, Option<Liveness>)> = connected_keys(state)
        .into_iter()
        .filter_map(|key| managed(state, &key).map(|c| (key, c)))
        .filter(|(_, c)| watched(c.kind))
        .map(|(key, c)| {
            let facts = state.helper.liveness(&c.id);
            (key, c.name, facts)
        })
        .collect();
    let prefs = state.prefs.clone();
    let enabled = move |key: &str| parse_uuid(key).is_some_and(|u| reconnect::is_enabled(prefs.as_ref(), &u));
    // The planner decides with the time of the answers (the polls take a moment).
    let actions = r.planner().liveness_checked(r.now(), &polled, &enabled);
    actions.into_iter().for_each(|a| act(state, a));
}

fn handle(state: &Arc<AppState>, e: Event) {
    let r = &state.reconnect;
    let now = r.now();
    match e {
        Event::Started(key) => {
            let ours = r.is_attempting(&key);
            // A connect the planner did not start (the user's, the control API's): the traffic totals start again;
            // an auto-reconnect keeps them.
            if !ours {
                state.traffic.restart(&key);
            }
            if managed(state, &key).is_none() {
                return;
            }
            let snap = if ours { None } else { snapshot(state) };
            r.planner().connect_started(&key, snap.as_ref().and_then(fingerprint), ours);
            // A lease's connect is marked (kept across a relaunch); the user's own connect takes it over.
            let leased = r.planner().is_leased(&key);
            reconnect::set_lease_mark(state.prefs.as_ref(), &key, leased);
            // Connecting without a network: it waits for one (checked like after a change).
            if snap.is_some_and(|s| !s.has_network()) {
                r.planner().check_network_soon(now);
            }
        }
        Event::Connected(key) => {
            let Some(c) = managed(state, &key) else { return };
            let n = networks(state, &c);
            // Up without a connect the planner saw (already up when the app started): it is up on this network.
            if !r.planner().knows_network(&key) {
                let fp = snapshot(state).as_ref().and_then(fingerprint);
                r.planner().adopt(&key, fp);
            }
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
        Event::LeaseConnect(key, true) => r.planner().lease_connect_began(&key),
        Event::LeaseConnect(key, false) => r.planner().lease_connect_ended(&key),
        Event::Forget(key) => {
            r.planner().forget(&key);
            reconnect::set_lease_mark(state.prefs.as_ref(), &key, false);
        }
        Event::Sleep(connected) => {
            let fp = snapshot(state).as_ref().and_then(fingerprint);
            r.planner().sleep(&connected, fp);
        }
        Event::Wake(connected) => r.planner().wake(now, &connected),
        Event::NetworkChanged => r.planner().network_changed(now),
        Event::DeadDown(key) => r.planner().dead_down(&key, now),
        Event::Down(key) => reconnect::set_lease_mark(state.prefs.as_ref(), &key, false),
        #[cfg(debug_assertions)]
        Event::LivenessNow => r.planner().liveness_soon(),
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
        Action::DisconnectNoNetwork(key) => {
            let Some(c) = managed(state, &key) else { return };
            let manager = state.manager.clone();
            // Not the user's: the planner may reconnect it when the network is back. `down` restores DNS and routes.
            std::thread::spawn(move || manager.disconnect_for(&c, DisconnectCause::NoNetwork));
        }
        Action::DisconnectNotResponding(key) => {
            let Some(c) = managed(state, &key) else { return };
            let s = state.clone();
            // Not the user's: `down` restores DNS and routes, then the planner may reconnect it.
            std::thread::spawn(move || {
                s.manager.disconnect_for(&c, DisconnectCause::NotResponding);
                s.reconnect.send(Event::DeadDown(key));
            });
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
        // Up without a connect seen (a system VPN connected outside the app): a new traffic session.
        if was_idle && new.is_connected() {
            s.traffic.restart(key);
        }
        if !was_idle && !new.is_active() {
            s.reconnect.send(Event::Down(key.to_string()));
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
    use super::*;
    use macvpn_app_core::reconnect::fingerprint;
    use macvpn_platform_api::Gateway;
    use std::io;
    use uuid::Uuid;

    #[test]
    fn ikev2_liveness_is_watched_on_linux_only() {
        assert!(watched(VPNKind::Wireguard) && watched(VPNKind::Openvpn));
        assert_eq!(
            watched(VPNKind::Strongswan),
            crate::platform::ikev2_reports_liveness(),
            "LinVPN's IKEv2 SA counters"
        );
        assert!(!watched(VPNKind::Sstp) && !watched(VPNKind::L2tp));
    }

    struct NoConfigs;
    impl ConnectionRepository for NoConfigs {
        fn list(&self) -> io::Result<Vec<Connection>> {
            Ok(vec![])
        }
        fn save(&self, _: &Connection, _: Option<&str>) -> io::Result<()> {
            Ok(())
        }
        fn load_config(&self, _: &Uuid) -> io::Result<String> {
            Ok(String::new())
        }
        fn delete(&self, _: &Uuid) -> io::Result<()> {
            Ok(())
        }
    }

    /// The control API's connect for a lease: the `Started` its state listener sends on the same thread lands
    /// between the bracket's events, so the planner (fed in channel order, as `handle` does) never reconnects it.
    #[test]
    fn a_lease_connect_is_bracketed_and_its_drop_is_not_reconnected() {
        let r = Reconnect::new(Arc::new(NoConfigs));
        let rx = r.rx.lock().unwrap().take().unwrap();
        let answer = r.lease_connect("k", || {
            r.send(Event::Started("k".into()));
            42
        });
        assert_eq!(answer, 42);
        let home = NetworkSnapshot {
            gateway: Some(Gateway {
                ip: "192.168.1.1".parse().unwrap(),
                mac: Some([2, 0, 0, 0, 0, 1]),
                interface: "en0".into(),
                ssid: None,
            }),
            connected: vec![macvpn_core::netaddr::IpPrefix::parse("192.168.1.0/24").unwrap()],
        };
        let mut order = Vec::new();
        let mut p = Planner::default();
        while let Ok(e) = rx.try_recv() {
            match e {
                Event::LeaseConnect(key, true) => {
                    order.push("began");
                    p.lease_connect_began(&key);
                }
                Event::LeaseConnect(key, false) => {
                    order.push("ended");
                    p.lease_connect_ended(&key);
                }
                Event::Started(key) => {
                    order.push("started");
                    p.connect_started(&key, fingerprint(&home), false);
                }
                _ => order.push("other"),
            }
        }
        assert_eq!(order, ["began", "started", "ended"]);
        let t0 = Date::from_time_interval_since_1970(1_800_000_000.0);
        p.connected("k", VpnNetworks::default());
        p.network_changed(t0);
        p.dropped("k", "Lab", t0.adding(1.0), macvpn_app_core::failure_reason::FailureKind::NetworkLost);
        assert!(!p.due(t0.adding(30.0)), "a connection a lease started is never reconnected");
    }

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
