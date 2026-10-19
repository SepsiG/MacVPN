//! The app orchestration that does not need a UI (the testable parts of the Swift `AppModel`, `AppDelegate`,
//! `QuitPolicy` and `UpdateController`): the polling cadence, the launch sequence, the quit decision and the
//! update-check schedule.

use crate::deps::Clock;
use crate::manager::ConnectionManager;
use macvpn_core::date::Date;
use macvpn_core::update::{Offer, Release, UpdateChecker};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

// MARK: - Polling

/// With an active (or connecting) connection every 3 s, otherwise every 30 s.
pub const ACTIVE_POLL_INTERVAL: f64 = 3.0;
pub const IDLE_POLL_INTERVAL: f64 = 30.0;
/// The poll fallback of the live system VPN list: without a (trusted) change watcher, every 5 s while a MacVPN
/// window (the menu popover, Connections, System Status, Update) is open.
pub const WINDOW_POLL_INTERVAL: f64 = 5.0;
/// The interval is re-evaluated this often: a new connect (`connecting` is active too) switches to the fast pace
/// at once instead of waiting out the 30 s.
pub const POLL_TICK: Duration = Duration::from_secs(1);

/// `live`: a trusted watcher reports system VPN changes (the pace is then the same with a window open).
pub fn poll_interval(has_active: bool, window_open: bool, live: bool) -> f64 {
    if has_active {
        ACTIVE_POLL_INTERVAL
    } else if window_open && !live {
        WINDOW_POLL_INTERVAL
    } else {
        IDLE_POLL_INTERVAL
    }
}

/// What one wait between two interval checks ended with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// The tick elapsed.
    Elapsed,
    /// An immediate refresh was requested (the menu opened, the Mac woke, a window asked).
    Woken,
    /// The poller is stopping.
    Stopped,
}

/// The status poller (the Swift `pollTask`): refresh, then wait until the current interval has passed since that
/// refresh, re-checking the interval every [`POLL_TICK`]. The elapsed time is measured on the wall clock (like
/// Swift's `Date()`), so after the Mac sleeps the next tick refreshes at once – the wake refresh.
pub struct Poller {
    stopped: AtomicBool,
    wake: Mutex<bool>,
    signal: Condvar,
}

impl Default for Poller {
    fn default() -> Self {
        Self::new()
    }
}

impl Poller {
    pub fn new() -> Self {
        Poller { stopped: AtomicBool::new(false), wake: Mutex::new(false), signal: Condvar::new() }
    }

    /// Requests an immediate refresh.
    pub fn wake(&self) {
        *self.wake.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.signal.notify_all();
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.signal.notify_all();
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Waits up to `tick` for a wake request.
    pub fn wait(&self, tick: Duration) -> Tick {
        let mut woken = self.wake.lock().unwrap_or_else(PoisonError::into_inner);
        if !*woken && !self.is_stopped() {
            woken = self.signal.wait_timeout(woken, tick).unwrap_or_else(PoisonError::into_inner).0;
        }
        if self.is_stopped() {
            return Tick::Stopped;
        }
        if std::mem::take(&mut *woken) { Tick::Woken } else { Tick::Elapsed }
    }

    /// The loop; returns when stopped. `tick` waits between two interval checks ([`Self::wait`] in the app).
    /// `window_open` and `live` feed [`poll_interval`]'s poll fallback.
    pub fn run(
        &self,
        refresh: impl Fn(),
        has_active: impl Fn() -> bool,
        window_open: impl Fn() -> bool,
        live: impl Fn() -> bool,
        clock: &dyn Clock,
        mut tick: impl FnMut() -> Tick,
    ) {
        while !self.is_stopped() {
            refresh();
            let started = clock.now();
            loop {
                if self.is_stopped() {
                    return;
                }
                if clock.now().time_interval_since(started) >= poll_interval(has_active(), window_open(), live()) {
                    break;
                }
                match tick() {
                    Tick::Elapsed => {}
                    Tick::Woken => break,
                    Tick::Stopped => return,
                }
            }
        }
    }
}

// MARK: - Launch

/// The launch steps, in the only allowed order (the Swift `AppModel.init` + `start()` + the update scheduler's
/// housekeeping).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchStep {
    /// The one-time move of the Keychain items from the legacy service. First: before any secret is read.
    MigrateKeychain,
    /// The temporary native profiles left from the previous run.
    SweepStagedProfiles,
    /// `profile.mobileconfig` (with password and PSK) that old versions wrote into the connection directories.
    RemoveLegacyProfiles,
    /// The vault (1.2): auto-unlock, else the unlock window; no vault: the create window (migration mode with 1.1
    /// data). After the Keychain move, before the connections are read.
    OpenVault,
    ReloadConnections,
    CheckSetup,
    RequestNotificationAuthorization,
    /// Only from a real app bundle: the leftovers of an interrupted update next to the bundle, then the previous
    /// update's failure notice (once).
    UpdateHousekeeping,
    /// Only when the update source is configured (and from a real bundle).
    StartUpdateScheduler,
    StartPolling,
}

pub const LAUNCH_SEQUENCE: [LaunchStep; 10] = [
    LaunchStep::MigrateKeychain,
    LaunchStep::SweepStagedProfiles,
    LaunchStep::RemoveLegacyProfiles,
    LaunchStep::OpenVault,
    LaunchStep::ReloadConnections,
    LaunchStep::CheckSetup,
    LaunchStep::RequestNotificationAuthorization,
    LaunchStep::UpdateHousekeeping,
    LaunchStep::StartUpdateScheduler,
    LaunchStep::StartPolling,
];

/// Runs the launch sequence. `run_step` performs one step.
pub fn launch(mut run_step: impl FnMut(LaunchStep)) {
    for step in LAUNCH_SEQUENCE {
        run_step(step);
    }
}

// MARK: - Quit

/// How a quit request (menu, Cmd+Q, logout) is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuitDecision {
    /// Nothing to ask, or the quit was already confirmed (menu Quit, update).
    TerminateNow,
    /// The quit questions (unsaved changes, active connections) run; the answer comes asynchronously.
    Ask,
}

/// The Swift `QuitPolicy.decide`.
pub fn quit_decision(already_confirmed: bool, has_unsaved_changes: bool, has_active_connections: bool) -> QuitDecision {
    if already_confirmed {
        return QuitDecision::TerminateNow;
    }
    if has_unsaved_changes || has_active_connections { QuitDecision::Ask } else { QuitDecision::TerminateNow }
}

/// The answer to "There are active VPN connections".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveConnectionsAnswer {
    DisconnectAndQuit,
    KeepRunning,
    Cancel,
}

/// Carries out the answer (the Swift `confirmActiveConnections` after the alert). True: the app may quit (the
/// chosen connections are down by then). Disconnecting stops the active system VPNs not managed by MacVPN too.
pub fn resolve_active_connections(manager: &ConnectionManager, answer: ActiveConnectionsAnswer) -> bool {
    match answer {
        ActiveConnectionsAnswer::DisconnectAndQuit => {
            manager.disconnect_all();
            for s in manager.system_services() {
                if manager.state(&s.id).is_active() {
                    manager.disconnect_system(&s);
                }
            }
            true
        }
        ActiveConnectionsAnswer::KeepRunning => true,
        ActiveConnectionsAnswer::Cancel => false,
    }
}

// MARK: - Update schedule

/// The `UserDefaults` keys of the Swift app (domain `local.macvpn`).
pub const AUTO_CHECK_KEY: &str = "autoCheckUpdates";
pub const DELAY_KEY: &str = "delayUpdates24h";
pub const LAST_CHECK_KEY: &str = "lastUpdateCheck";
pub const NOTICED_HELPER_RUN_KEY: &str = "noticedUpdateHelperRun";
/// An automatic check at launch, then whenever 24 hours passed since the last one.
pub const UPDATE_CHECK_INTERVAL: f64 = 24.0 * 60.0 * 60.0;
/// The scheduler wakes this often to see whether a check is due.
pub const UPDATE_SCHEDULER_WAKE: Duration = Duration::from_secs(3600);

/// Persistent preferences (the app's `UserDefaults`).
pub trait PreferenceStore: Send + Sync {
    fn bool(&self, key: &str) -> Option<bool>;
    fn set_bool(&self, key: &str, value: bool);
    fn date(&self, key: &str) -> Option<Date>;
    fn set_date(&self, key: &str, value: Date);
    fn string(&self, key: &str) -> Option<String>;
    fn set_string(&self, key: &str, value: &str);
    /// Every key of the app's domain (uninstall with the user data: the Swift `removePersistentDomain`).
    fn remove_all(&self);
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UpdatePreferences {
    /// "Check for Updates Automatically" (default on).
    pub auto_check: bool,
    /// "Only Offer Updates Published at Least 24 Hours Ago" (default off).
    pub delay_updates: bool,
    pub last_check: Option<Date>,
}

impl Default for UpdatePreferences {
    fn default() -> Self {
        UpdatePreferences { auto_check: true, delay_updates: false, last_check: None }
    }
}

impl UpdatePreferences {
    /// With the registered defaults (auto check on, delay off).
    pub fn load(store: &dyn PreferenceStore) -> Self {
        UpdatePreferences {
            auto_check: store.bool(AUTO_CHECK_KEY).unwrap_or(true),
            delay_updates: store.bool(DELAY_KEY).unwrap_or(false),
            last_check: store.date(LAST_CHECK_KEY),
        }
    }
}

/// Whether the scheduler checks now: only with the automatic check on; at launch (`first`), then once 24 hours
/// passed since the last successful check (never checked: due).
pub fn update_check_due(first: bool, prefs: &UpdatePreferences, now: Date) -> bool {
    if !prefs.auto_check {
        return false;
    }
    first || prefs.last_check.is_none_or(|last| now.time_interval_since(last) >= UPDATE_CHECK_INTERVAL)
}

/// The latest release as offered (the Swift `available` / `deferred` / `awaitingSignature`): at most one is set.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UpdateOffers {
    pub available: Option<Release>,
    /// Newer, but held back by the 24-hour delay.
    pub deferred: Option<Release>,
    /// Newer, but without an offline signature (`.sig`) yet: not offered.
    pub awaiting_signature: Option<Release>,
}

impl UpdateOffers {
    pub fn apply(&mut self, release: Release, current_version: &str, delayed: bool, now: Date) {
        *self = UpdateOffers::default();
        match UpdateChecker::offer(&release, current_version, delayed, now) {
            Offer::Offer => self.available = Some(release),
            Offer::TooRecent => self.deferred = Some(release),
            Offer::AwaitingSignature => self.awaiting_signature = Some(release),
            Offer::UpToDate => {}
        }
    }

    /// The delay option changed: the known release is judged again.
    pub fn reapply(&mut self, current_version: &str, delayed: bool, now: Date) {
        let known =
            self.available.clone().or_else(|| self.deferred.clone()).or_else(|| self.awaiting_signature.clone());
        if let Some(release) = known {
            self.apply(release, current_version, delayed, now);
        }
    }
}

/// An in-memory [`PreferenceStore`] (tests, and runs without a bundle).
#[derive(Debug, Default)]
pub struct MemoryPreferences {
    values: Mutex<std::collections::HashMap<String, PreferenceValue>>,
}

#[derive(Debug, Clone, PartialEq)]
enum PreferenceValue {
    Bool(bool),
    Date(Date),
    String(String),
}

impl MemoryPreferences {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, key: &str) -> Option<PreferenceValue> {
        self.values.lock().unwrap_or_else(PoisonError::into_inner).get(key).cloned()
    }

    fn put(&self, key: &str, value: PreferenceValue) {
        self.values.lock().unwrap_or_else(PoisonError::into_inner).insert(key.to_string(), value);
    }
}

impl PreferenceStore for MemoryPreferences {
    fn bool(&self, key: &str) -> Option<bool> {
        match self.get(key)? {
            PreferenceValue::Bool(b) => Some(b),
            _ => None,
        }
    }

    fn set_bool(&self, key: &str, value: bool) {
        self.put(key, PreferenceValue::Bool(value));
    }

    fn date(&self, key: &str) -> Option<Date> {
        match self.get(key)? {
            PreferenceValue::Date(d) => Some(d),
            _ => None,
        }
    }

    fn set_date(&self, key: &str, value: Date) {
        self.put(key, PreferenceValue::Date(value));
    }

    fn string(&self, key: &str) -> Option<String> {
        match self.get(key)? {
            PreferenceValue::String(s) => Some(s),
            _ => None,
        }
    }

    fn set_string(&self, key: &str, value: &str) {
        self.put(key, PreferenceValue::String(value.to_string()));
    }

    fn remove_all(&self) {
        self.values.lock().unwrap_or_else(PoisonError::into_inner).clear();
    }
}

// MARK: - Help

/// The user guide for the language (the core `UserGuide`), and only if it is an `https://github.com/` URL made of
/// plain path characters: the only kind of address the app hands to `open`.
pub fn user_guide_url(repo: Option<&str>, language: macvpn_core::l10n::AppLanguage) -> Option<String> {
    let url = macvpn_core::update::UserGuide::url(repo, &[language.raw_value()]);
    is_safe_github_url(&url).then_some(url)
}

/// `https://github.com/` followed by ASCII letters, digits and `/ . _ -` only (no query, fragment, `%`, `..`,
/// whitespace or option-like argument).
pub fn is_safe_github_url(url: &str) -> bool {
    let Some(path) = url.strip_prefix("https://github.com/") else { return false };
    !path.is_empty()
        && !path.contains("..")
        && !path.contains("//")
        && path.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
}
