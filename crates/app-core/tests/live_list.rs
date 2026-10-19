//! The live system VPN list: the debounced reload, the poll fallback's pace, and the editors of a system VPN that
//! was removed from macOS.

mod common;

use common::*;
use macvpn_app_core::app::{Poller, Tick, poll_interval};
use macvpn_app_core::connections::ConnectionsModel;
use macvpn_app_core::deps::{Clock, ManualClock, SystemService};
use macvpn_app_core::editor::{EditorDeps, EditorFields, SystemFields, TextFields};
use macvpn_app_core::live::{Debouncer, LIVE_DEBOUNCE, LIVE_MAX_WAIT, LiveReload};
use macvpn_core::date::Date;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::{Connection, VPNKind, uuid_string};
use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

// MARK: - Debouncer

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

#[test]
fn one_trigger_is_due_after_the_debounce() {
    assert_eq!(LIVE_DEBOUNCE, ms(500));
    let t0 = Instant::now();
    let mut d = Debouncer::default();
    assert!(!d.take_due(t0));
    d.trigger(t0);
    assert!(!d.take_due(t0 + ms(499)));
    assert!(d.take_due(t0 + ms(500)));
    assert!(!d.take_due(t0 + ms(501)), "due once");
    assert!(!d.take_due(t0 + ms(5000)));
}

#[test]
fn a_burst_is_due_once_after_its_last_trigger() {
    let t0 = Instant::now();
    let mut d = Debouncer::default();
    let mut due = Vec::new();
    for i in 0..10 {
        d.trigger(t0 + ms(i * 100));
    }
    // Checked every 50 ms from the start.
    for step in 0..40 {
        let now = t0 + ms(step * 50);
        if d.take_due(now) {
            due.push(step * 50);
        }
    }
    assert_eq!(due, [1400], "500 ms after the last trigger (900 ms)");
}

#[test]
fn a_trigger_after_a_due_is_due_again() {
    let t0 = Instant::now();
    let mut d = Debouncer::default();
    d.trigger(t0);
    assert!(d.take_due(t0 + ms(500)));
    d.trigger(t0 + ms(600));
    assert!(!d.take_due(t0 + ms(1000)));
    assert!(d.take_due(t0 + ms(1100)));
}

/// Notifications that never stop (more often than the debounce) still reload: at most `LIVE_MAX_WAIT` after the
/// first trigger of a burst.
#[test]
fn a_endless_burst_is_due_after_the_maximum_wait() {
    assert_eq!(LIVE_MAX_WAIT, ms(2000));
    let t0 = Instant::now();
    let mut d = Debouncer::default();
    let mut due = Vec::new();
    for step in 0..50 {
        let now = t0 + ms(step * 100);
        d.trigger(now);
        if d.take_due(now) {
            due.push(step * 100);
        }
    }
    assert_eq!(due, [2000, 4100]);
}

#[test]
fn the_deadline_follows_the_last_trigger() {
    let t0 = Instant::now();
    let mut d = Debouncer::default();
    assert_eq!(d.deadline(), None);
    d.trigger(t0);
    d.trigger(t0 + ms(200));
    assert_eq!(d.deadline(), Some(t0 + ms(700)));
}

/// Polls `count` until it reaches `target` (or `limit` passes); returns the last value.
fn wait_for_count(count: &AtomicUsize, target: usize, limit: Duration) -> usize {
    let start = Instant::now();
    loop {
        let value = count.load(Ordering::SeqCst);
        if value >= target || start.elapsed() > limit {
            return value;
        }
        std::thread::sleep(ms(10));
    }
}

/// The reload thread: a burst of triggers wakes the poller once; a later trigger wakes it again; stop ends the
/// thread. Independent of the runner's pace: the debounce's exact timing is covered by the `Debouncer` tests above
/// (explicit instants); here only the order of events is checked, with generous bounds.
#[test]
fn live_reload_wakes_once_per_burst_and_stops() {
    let reload = Arc::new(LiveReload::new());
    let wakes = Arc::new(AtomicUsize::new(0));
    let thread = {
        let (reload, wakes) = (reload.clone(), wakes.clone());
        std::thread::spawn(move || {
            reload.run(|| {
                wakes.fetch_add(1, Ordering::SeqCst);
            })
        })
    };
    let burst = Instant::now();
    for _ in 0..5 {
        reload.trigger();
    }
    let early = wakes.load(Ordering::SeqCst);
    // Only meaningful when the runner did not stall past the debounce meanwhile.
    if burst.elapsed() < LIVE_DEBOUNCE {
        assert_eq!(early, 0, "not before the debounce");
    }
    assert_eq!(wait_for_count(&wakes, 1, Duration::from_secs(5)), 1, "the burst wakes the poller");
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(wakes.load(Ordering::SeqCst), 1, "a burst is one wake");
    reload.trigger();
    assert_eq!(wait_for_count(&wakes, 2, Duration::from_secs(5)), 2, "a later trigger wakes it again");
    let started = Instant::now();
    reload.stop();
    thread.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(5), "stop ends the thread promptly");
}

// MARK: - Poll fallback

#[test]
fn poll_interval_table() {
    // (has_active, window_open, live) -> seconds
    let table = [
        ((true, true, true), 3.0),
        ((true, true, false), 3.0),
        ((true, false, true), 3.0),
        ((true, false, false), 3.0),
        ((false, true, true), 30.0),
        ((false, true, false), 5.0),
        ((false, false, true), 30.0),
        ((false, false, false), 30.0),
    ];
    for ((active, window, live), seconds) in table {
        assert_eq!(poll_interval(active, window, live), seconds, "{active} {window} {live}");
    }
}

/// No watcher and a window open: a refresh every 5 s; once the window is closed (at 20 s), 30 s after the last.
#[test]
fn poller_without_a_watcher_polls_every_5_seconds_while_a_window_is_open() {
    let clock = ManualClock::new(Date::from_time_interval_since_1970(0.0));
    let poller = Poller::new();
    let refreshes = RefCell::new(Vec::new());
    let now = || clock.now().time_interval_since_1970();
    poller.run(
        || refreshes.borrow_mut().push(now()),
        || false,
        || now() < 20.0,
        || false,
        &clock,
        || {
            clock.advance(1.0);
            if now() >= 60.0 { Tick::Stopped } else { Tick::Elapsed }
        },
    );
    assert_eq!(refreshes.into_inner(), [0.0, 5.0, 10.0, 15.0, 45.0]);
}

#[test]
fn poller_with_a_watcher_keeps_the_idle_pace_with_a_window_open() {
    let clock = ManualClock::new(Date::from_time_interval_since_1970(0.0));
    let poller = Poller::new();
    let refreshes = RefCell::new(Vec::new());
    let now = || clock.now().time_interval_since_1970();
    poller.run(
        || refreshes.borrow_mut().push(now()),
        || false,
        || true,
        || true,
        &clock,
        || {
            clock.advance(1.0);
            if now() >= 65.0 { Tick::Stopped } else { Tick::Elapsed }
        },
    );
    assert_eq!(refreshes.into_inner(), [0.0, 30.0, 60.0]);
}

// MARK: - Removed system VPNs

const SERVICE: &str = "6A3F0B1E-2C4D-4E5F-8A9B-0C1D2E3F4A5B";
const OTHER: &str = "7B4F0B1E-2C4D-4E5F-8A9B-0C1D2E3F4A5B";
const REMOVED: &str = "This VPN was removed from macOS";

struct Window {
    fx: Fixture,
    model: Arc<ConnectionsModel>,
    manager: Arc<macvpn_app_core::ConnectionManager>,
}

fn window() -> Window {
    let fx = Fixture::new(AppLanguage::En);
    let manager = fx.manager();
    let deps = EditorDeps {
        manager: manager.clone(),
        store: fx.store.clone(),
        secrets: fx.secrets.clone(),
        secret_writer: fx.secrets.clone(),
        profiles: Arc::new(MockProfiles::default()),
        clock: clock_at(1_000_000.0),
    };
    Window { model: Arc::new(ConnectionsModel::new(deps)), fx, manager }
}

impl Window {
    /// The system services macOS lists now, then a refresh and the window's update (the app's on-change path).
    fn list(&self, ids: &[&str]) {
        let services = ids.iter().map(|id| SystemService::new(id, "Company", "L2TP", "Disconnected")).collect();
        self.fx.native.set_list(Ok(services));
        self.manager.refresh();
        self.model.system_services_changed();
    }
}

fn psk(value: &str) -> EditorFields {
    EditorFields::System(SystemFields { psk: Some(value.into()), ..SystemFields::default() })
}

#[test]
fn a_removed_system_vpn_editor_is_read_only_until_it_returns() {
    let w = window();
    w.list(&[SERVICE, OTHER]);
    assert!(w.model.select(Some(SERVICE.into())));
    let view = w.model.open_editor(SERVICE).unwrap();
    assert!(!view.removed);
    assert!(w.model.update_editor(SERVICE, psk("typed")).unwrap().dirty);
    assert!(!w.model.view().selected_removed);

    // Deleted in System Settings.
    w.list(&[OTHER]);
    assert!(w.model.open_editor(SERVICE).unwrap().removed);
    let manage = w.model.view();
    assert!(manage.selected_removed);
    assert_eq!(manage.selected.as_deref(), Some(SERVICE), "the selection is kept");
    assert_eq!(w.model.update_editor(SERVICE, psk("more")).unwrap_err(), REMOVED);
    assert_eq!(w.model.save_editor(SERVICE, psk("typed")).unwrap_err(), REMOVED);
    let id = macvpn_core::models::parse_uuid(SERVICE).unwrap();
    assert_eq!(w.fx.secrets.count(&id), 0, "nothing was saved");

    // The same service is listed again: editable, with the typed draft.
    w.list(&[SERVICE, OTHER]);
    let view = w.model.open_editor(SERVICE).unwrap();
    assert!(!view.removed && view.dirty);
    assert_eq!(view.fields, psk("typed"));
    assert!(!w.model.view().selected_removed);
    assert!(w.model.save_editor(SERVICE, psk("typed")).unwrap().saved);
}

/// A removed VPN's typed draft cannot be saved: it raises no "Unsaved Changes" question (that could only fail),
/// but stays in memory and counts again once the VPN returns.
#[test]
fn a_removed_draft_is_not_an_unsaved_change() {
    let w = window();
    w.list(&[SERVICE]);
    w.model.select(Some(SERVICE.into()));
    w.model.open_editor(SERVICE).unwrap();
    w.model.update_editor(SERVICE, psk("typed")).unwrap();
    assert!(w.model.has_unsaved_changes());
    w.list(&[]);
    assert!(!w.model.has_unsaved_changes());
    assert!(w.model.view().dirty.is_empty());
    assert!(w.model.save_all_unsaved().is_ok());
    assert!(w.model.should_close_window());
    w.list(&[SERVICE]);
    assert!(w.model.has_unsaved_changes(), "the draft was kept");
    assert_eq!(w.model.view().dirty, [SERVICE]);
    w.list(&[]);
    assert!(w.model.select(None), "no question for the removed draft");
}

/// Deleting is not editing: "Forget saved secrets" works on a removed VPN, and it stays removed.
#[test]
fn a_removed_vpn_can_forget_its_secrets() {
    let w = window();
    let id = macvpn_core::models::parse_uuid(SERVICE).unwrap();
    w.list(&[SERVICE]);
    w.model.select(Some(SERVICE.into()));
    w.model.open_editor(SERVICE).unwrap();
    w.model.save_editor(SERVICE, psk("stored")).unwrap();
    assert_eq!(w.fx.secrets.count(&id), 1);
    w.list(&[]);
    let view = w.model.forget_secrets(SERVICE).unwrap();
    assert!(view.removed && !view.has_stored);
    assert_eq!(w.fx.secrets.count(&id), 0);
    assert!(w.model.view().selected_removed);
}

#[test]
fn a_removed_selection_without_an_editor_is_still_marked() {
    let w = window();
    // IKEv2: no editor (no stored secrets), but the detail is shown.
    w.fx.native.set_list(Ok(vec![SystemService::new(SERVICE, "Corp", "IKEv2", "Disconnected")]));
    w.manager.refresh();
    w.model.system_services_changed();
    w.model.select(Some(SERVICE.into()));
    w.list(&[]);
    assert!(w.model.view().selected_removed);
    // Another selection: the removed one is forgotten.
    w.model.select(None);
    assert!(!w.model.view().selected_removed);
    w.list(&[]);
    assert!(!w.model.view().selected_removed);
}

#[test]
fn a_managed_connection_is_never_marked_removed() {
    let w = window();
    let c = Connection::new("Office", VPNKind::Openvpn);
    w.fx.store.save(&c, Some("client\nremote vpn.example.com 1194\n")).unwrap();
    w.manager.reload();
    w.list(&[SERVICE]);
    let key = uuid_string(&c.id);
    w.model.select(Some(key.clone()));
    let view = w.model.open_editor(&key).unwrap();
    let EditorFields::Text(fields) = view.fields else { panic!("text editor") };
    w.list(&[]);
    assert!(!w.model.open_editor(&key).unwrap().removed);
    assert!(!w.model.view().selected_removed);
    let edited = TextFields { name: "Office 2".into(), ..fields };
    assert!(w.model.update_editor(&key, EditorFields::Text(edited)).is_ok());
}

/// A failed listing keeps the last known list: nothing is marked removed.
#[test]
fn a_failed_listing_marks_nothing() {
    let w = window();
    w.list(&[SERVICE]);
    w.model.select(Some(SERVICE.into()));
    w.model.open_editor(SERVICE).unwrap();
    w.fx.native.set_list(Err("scutil failed"));
    w.manager.refresh();
    w.model.system_services_changed();
    assert!(!w.model.open_editor(SERVICE).unwrap().removed);
    assert!(!w.model.view().selected_removed);
}

// MARK: - Races with a refresh

/// A secret store that runs a hook once, on the next read or write: a refresh landing while a save, a forget or
/// an editor load runs outside the window's lock.
#[derive(Default)]
struct Hooked {
    inner: MemorySecrets,
    hook: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Hooked {
    fn arm(&self, hook: impl FnOnce() + Send + 'static) {
        *self.hook.lock().unwrap() = Some(Box::new(hook));
    }

    fn fire(&self) {
        let hook = self.hook.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
    }
}

impl macvpn_app_core::deps::SecretReader for Hooked {
    fn get(&self, id: &uuid::Uuid, field: macvpn_app_core::deps::SecretField) -> Option<String> {
        self.fire();
        macvpn_app_core::deps::SecretReader::get(&self.inner, id, field)
    }
}

impl macvpn_app_core::deps::SecretWriter for Hooked {
    fn set(&self, value: &str, id: &uuid::Uuid, field: macvpn_app_core::deps::SecretField) {
        self.fire();
        macvpn_app_core::deps::SecretWriter::set(&self.inner, value, id, field);
    }

    fn delete_all(&self, id: &uuid::Uuid) {
        self.fire();
        macvpn_app_core::deps::SecretWriter::delete_all(&self.inner, id);
    }

    fn remove_all(&self) {
        macvpn_app_core::deps::SecretWriter::remove_all(&self.inner);
    }
}

fn hooked_window() -> (Window, Arc<Hooked>) {
    let fx = Fixture::new(AppLanguage::En);
    let secrets = Arc::new(Hooked::default());
    let manager = fx.manager_with(macvpn_app_core::Dependencies::new(
        fx.store.clone(),
        secrets.clone(),
        fx.root.clone(),
        fx.native.clone(),
    ));
    let deps = EditorDeps {
        manager: manager.clone(),
        store: fx.store.clone(),
        secrets: secrets.clone(),
        secret_writer: secrets.clone(),
        profiles: Arc::new(MockProfiles::default()),
        clock: clock_at(1_000_000.0),
    };
    (Window { model: Arc::new(ConnectionsModel::new(deps)), fx, manager }, secrets)
}

/// The service vanishes while the save writes the secrets: the write-back keeps the removed mark.
#[test]
fn a_removal_during_a_save_is_kept() {
    let (w, secrets) = hooked_window();
    w.list(&[SERVICE]);
    w.model.select(Some(SERVICE.into()));
    w.model.open_editor(SERVICE).unwrap();
    let model = w.model.clone();
    secrets.arm(move || model.services_changed(&std::collections::HashSet::new()));
    let _ = w.model.save_editor(SERVICE, psk("typed"));
    assert!(w.model.open_editor(SERVICE).unwrap().removed);
    assert!(w.model.view().selected_removed);
}

/// The same during "Forget saved secrets".
#[test]
fn a_removal_during_a_forget_is_kept() {
    let (w, secrets) = hooked_window();
    w.list(&[SERVICE]);
    w.model.select(Some(SERVICE.into()));
    w.model.open_editor(SERVICE).unwrap();
    let model = w.model.clone();
    secrets.arm(move || model.services_changed(&std::collections::HashSet::new()));
    assert!(w.model.forget_secrets(SERVICE).unwrap().removed);
}

/// The service vanishes while the editor loads (the first open, outside the lock): it opens marked removed.
#[test]
fn a_removal_during_an_editor_load_is_kept() {
    let (w, secrets) = hooked_window();
    w.list(&[SERVICE]);
    w.model.select(Some(SERVICE.into()));
    let model = w.model.clone();
    secrets.arm(move || model.services_changed(&std::collections::HashSet::new()));
    assert!(w.model.open_editor(SERVICE).unwrap().removed);
    assert!(w.model.view().selected_removed);
}

/// A service that a managed connection takes over leaves the system list but is still listed by macOS: the
/// selection is not marked removed.
#[test]
fn a_service_that_becomes_managed_is_not_removed() {
    let w = window();
    w.fx.native.set_list(Ok(vec![SystemService::new(SERVICE, "Office L2TP", "L2TP", "Disconnected")]));
    w.manager.refresh();
    w.model.system_services_changed();
    w.model.select(Some(SERVICE.into()));
    // A managed L2TP connection with the same name now claims the service.
    let mut c = Connection::new("Office L2TP", VPNKind::L2tp);
    c.native = Some(macvpn_core::models::NativeSettings {
        server: "vpn.example.com".into(),
        account: "bob".into(),
        ..Default::default()
    });
    w.fx.store.save(&c, None).unwrap();
    w.manager.reload();
    w.manager.refresh();
    assert!(w.manager.system_services().is_empty(), "the service is managed now");
    w.model.system_services_changed();
    assert!(!w.model.view().selected_removed);
}
