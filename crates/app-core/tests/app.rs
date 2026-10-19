//! The orchestration: `QuitPolicyTests.swift` ported, plus the polling cadence, the launch order, the
//! update-check schedule and offers (the Swift `AppModel` / `UpdateController` logic, untested there).

mod common;

use common::*;
use macvpn_app_core::app::*;
use macvpn_app_core::deps::{Clock, ManualClock, SystemService};
use macvpn_core::date::Date;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::{Connection, ConnectionState, VPNKind, uuid_string};
use macvpn_core::update::{Release, ReleaseAsset};
use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::time::{Duration, Instant};

// MARK: - QuitPolicy (port of QuitPolicyTests.swift)

#[test]
fn already_confirmed_terminates_without_asking() {
    assert_eq!(quit_decision(true, true, true), QuitDecision::TerminateNow);
}

#[test]
fn nothing_to_ask_terminates_now() {
    assert_eq!(quit_decision(false, false, false), QuitDecision::TerminateNow);
}

#[test]
fn unsaved_changes_ask() {
    assert_eq!(quit_decision(false, true, false), QuitDecision::Ask);
}

#[test]
fn active_connections_ask() {
    assert_eq!(quit_decision(false, false, true), QuitDecision::Ask);
}

#[test]
fn disconnect_and_quit_stops_managed_and_system_connections() {
    let f = Fixture::new(AppLanguage::En);
    let c = Connection::new("Iroda", VPNKind::Openvpn);
    f.store.save(&c, Some("remote x\n")).unwrap();
    let svc = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
    f.root.respond(
        "status",
        Ok(&format!(
            r#"[{{"id":"{}","kind":"openvpn","state":"connected","iface":null,"ip":null,"since":null}}]"#,
            uuid_string(&c.id)
        )),
    );
    f.native.set_list(Ok(vec![SystemService::new(svc, "Corp", "IKEv2", "Connected")]));
    let m = f.manager();
    m.refresh();
    assert!(m.has_active());
    assert!(!resolve_active_connections(&m, ActiveConnectionsAnswer::Cancel));
    assert!(f.native.stops().is_empty());
    assert!(resolve_active_connections(&m, ActiveConnectionsAnswer::KeepRunning));
    assert!(!f.root.lines().iter().any(|l| l.starts_with("down ")));
    f.root.respond("status", Ok("[]"));
    assert!(resolve_active_connections(&m, ActiveConnectionsAnswer::DisconnectAndQuit));
    assert!(f.root.lines().contains(&down_line(VPNKind::Openvpn, &c.id)));
    assert_eq!(f.native.stops(), [svc]);
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Disconnected);
}

// MARK: - Polling

#[test]
fn poll_interval_is_3s_active_30s_idle() {
    assert_eq!(poll_interval(true, false, true), 3.0);
    assert_eq!(poll_interval(false, false, true), 30.0);
    assert_eq!(POLL_TICK, Duration::from_secs(1));
}

/// Simulated time: every tick is one second. Returns the times (seconds from the start) of the refreshes.
fn simulate(active: impl Fn(f64) -> bool, seconds: f64, wake_at: &[f64]) -> Vec<f64> {
    let clock = ManualClock::new(Date::from_time_interval_since_1970(0.0));
    let poller = Poller::new();
    let refreshes = RefCell::new(Vec::new());
    let now = || clock.now().time_interval_since_1970();
    poller.run(
        || refreshes.borrow_mut().push(now()),
        || active(now()),
        || false,
        || true,
        &clock,
        || {
            clock.advance(1.0);
            if now() >= seconds {
                return Tick::Stopped;
            }
            if wake_at.contains(&now()) { Tick::Woken } else { Tick::Elapsed }
        },
    );
    refreshes.into_inner()
}

#[test]
fn idle_polls_every_30_seconds() {
    assert_eq!(simulate(|_| false, 95.0, &[]), [0.0, 30.0, 60.0, 90.0]);
}

#[test]
fn active_polls_every_3_seconds() {
    assert_eq!(simulate(|_| true, 10.0, &[]), [0.0, 3.0, 6.0, 9.0]);
}

/// A connect started during an idle wait switches to the fast pace at the next 1-second check.
#[test]
fn a_new_connect_switches_to_the_fast_pace_at_once() {
    assert_eq!(simulate(|t| t >= 10.0, 17.0, &[]), [0.0, 10.0, 13.0, 16.0]);
}

/// Opening the menu (or the Mac waking) refreshes at once.
#[test]
fn wake_refreshes_immediately() {
    assert_eq!(simulate(|_| false, 40.0, &[7.0]), [0.0, 7.0, 37.0]);
}

/// The wall clock jumping (the Mac slept) refreshes at the next tick.
#[test]
fn clock_jump_after_sleep_refreshes() {
    let clock = ManualClock::new(Date::from_time_interval_since_1970(0.0));
    let poller = Poller::new();
    let count = Cell::new(0);
    let ticks = Cell::new(0);
    poller.run(
        || count.set(count.get() + 1),
        || false,
        || false,
        || true,
        &clock,
        || {
            ticks.set(ticks.get() + 1);
            match ticks.get() {
                1 => {
                    clock.advance(3600.0); // slept an hour
                    Tick::Elapsed
                }
                2 => Tick::Stopped,
                _ => Tick::Elapsed,
            }
        },
    );
    assert_eq!(count.get(), 2);
}

#[test]
fn poller_wait_wakes_and_stops() {
    let poller = Arc::new(Poller::new());
    let started = Instant::now();
    assert_eq!(poller.wait(Duration::from_millis(30)), Tick::Elapsed);
    assert!(started.elapsed() >= Duration::from_millis(25));
    poller.wake();
    assert_eq!(poller.wait(Duration::from_secs(5)), Tick::Woken);
    let p = poller.clone();
    let t = std::thread::spawn(move || p.wait(Duration::from_secs(5)));
    std::thread::sleep(Duration::from_millis(20));
    poller.stop();
    assert_eq!(t.join().unwrap(), Tick::Stopped);
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[test]
fn poller_loop_refreshes_the_manager_until_stopped() {
    let f = Fixture::new(AppLanguage::En);
    f.store.save(&Connection::new("Iroda", VPNKind::Openvpn), Some("remote x\n")).unwrap();
    f.root.respond("status", Ok("[]"));
    let m = f.manager();
    let poller = Arc::new(Poller::new());
    let thread = {
        let (m, p) = (m.clone(), poller.clone());
        std::thread::spawn(move || {
            let clock = macvpn_app_core::deps::SystemClock;
            p.run(|| m.refresh(), || m.has_active(), || false, || true, &clock, || p.wait(Duration::from_millis(10)));
        })
    };
    // Ordered by the recorded calls, not by fixed sleeps (a busy runner stretches those).
    f.root.wait_for_call("status", 1);
    poller.wake();
    f.root.wait_for_call("status", 2);
    poller.stop();
    thread.join().unwrap();
    let statuses = f.root.lines().iter().filter(|l| *l == "status").count();
    assert_eq!(statuses, 2, "the first refresh and the woken one");
}

// MARK: - Launch

#[test]
fn launch_order_migrates_the_keychain_first() {
    let mut steps = Vec::new();
    launch(|s| steps.push(s));
    assert_eq!(steps, LAUNCH_SEQUENCE);
    assert_eq!(steps[0], LaunchStep::MigrateKeychain);
    let index = |s: LaunchStep| steps.iter().position(|x| *x == s).unwrap();
    assert!(index(LaunchStep::RemoveLegacyProfiles) < index(LaunchStep::ReloadConnections));
    // The vault opens after the Keychain move and before anything is read from it.
    assert!(index(LaunchStep::MigrateKeychain) < index(LaunchStep::OpenVault));
    assert_eq!(index(LaunchStep::OpenVault) + 1, index(LaunchStep::ReloadConnections));
    assert!(index(LaunchStep::ReloadConnections) < index(LaunchStep::CheckSetup));
    assert!(index(LaunchStep::UpdateHousekeeping) < index(LaunchStep::StartUpdateScheduler));
    assert_eq!(*steps.last().unwrap(), LaunchStep::StartPolling);
}

// MARK: - Update schedule

fn date(unix: f64) -> Date {
    Date::from_time_interval_since_1970(unix)
}

#[test]
fn update_preferences_defaults() {
    let store = MemoryPreferences::new();
    assert_eq!(UpdatePreferences::load(&store), UpdatePreferences::default());
    assert!(UpdatePreferences::default().auto_check);
    assert!(!UpdatePreferences::default().delay_updates);
    store.set_bool(AUTO_CHECK_KEY, false);
    store.set_bool(DELAY_KEY, true);
    store.set_date(LAST_CHECK_KEY, date(5.0));
    assert_eq!(
        UpdatePreferences::load(&store),
        UpdatePreferences { auto_check: false, delay_updates: true, last_check: Some(date(5.0)) }
    );
}

#[test]
fn update_check_due_at_launch_then_after_24_hours() {
    let mut prefs = UpdatePreferences { last_check: Some(date(1000.0)), ..UpdatePreferences::default() };
    assert!(update_check_due(true, &prefs, date(1001.0)), "at launch");
    assert!(!update_check_due(false, &prefs, date(1000.0 + 86_399.0)));
    assert!(update_check_due(false, &prefs, date(1000.0 + 86_400.0)));
    prefs.last_check = None;
    assert!(update_check_due(false, &prefs, date(0.0)), "never checked");
    prefs.auto_check = false;
    assert!(!update_check_due(true, &prefs, date(0.0)), "automatic checks off");
}

fn release(version: &str, published: Option<f64>, signed: bool) -> Release {
    let asset = |name: String| ReleaseAsset {
        name: name.clone(),
        url: format!("https://github.com/SepsiG/MacVPN/releases/download/v{version}/{name}"),
    };
    Release {
        version: version.into(),
        tag: format!("v{version}"),
        notes: String::new(),
        page_url: None,
        published_at: published.map(date),
        dmg: asset(format!("MacVPN-{version}.dmg")),
        checksum: asset(format!("MacVPN-{version}.dmg.sha256")),
        signature: signed.then(|| asset(format!("MacVPN-{version}.dmg.sig"))),
    }
}

#[test]
fn update_offers_follow_the_delay_option() {
    let now = date(1_000_000.0);
    let fresh = release("1.1.0", Some(1_000_000.0 - 3600.0), true);
    let mut offers = UpdateOffers::default();
    offers.apply(fresh.clone(), "1.0.0", false, now);
    assert_eq!(offers.available, Some(fresh.clone()));
    // Turning the 24-hour delay on defers the hour-old release; off again offers it.
    offers.reapply("1.0.0", true, now);
    assert_eq!(offers, UpdateOffers { deferred: Some(fresh.clone()), ..UpdateOffers::default() });
    offers.reapply("1.0.0", false, now);
    assert_eq!(offers.available, Some(fresh));
    let unsigned = release("1.2.0", Some(0.0), false);
    offers.apply(unsigned.clone(), "1.0.0", false, now);
    assert_eq!(offers, UpdateOffers { awaiting_signature: Some(unsigned), ..UpdateOffers::default() });
    offers.apply(release("1.0.0", Some(0.0), true), "1.0.0", false, now);
    assert_eq!(offers, UpdateOffers::default());
}

// MARK: - Help

#[test]
fn user_guide_url_follows_the_language_and_is_safe() {
    assert_eq!(
        user_guide_url(Some("SepsiG/MacVPN"), AppLanguage::Hu).as_deref(),
        Some("https://github.com/SepsiG/MacVPN/blob/main/docs/user-guide.hu.md")
    );
    assert_eq!(
        user_guide_url(None, AppLanguage::En).as_deref(),
        Some("https://github.com/SepsiG/MacVPN/blob/main/docs/user-guide.en.md")
    );
    // An invalid repo falls back to the default one (core `UserGuide`).
    assert_eq!(
        user_guide_url(Some("evil.com/x?y"), AppLanguage::En).as_deref(),
        Some("https://github.com/SepsiG/MacVPN/blob/main/docs/user-guide.en.md")
    );
    for bad in [
        "http://github.com/a",
        "https://github.com.evil.com/a",
        "https://github.com/a?b",
        "https://github.com/a#b",
        "https://github.com/a%2e",
        "https://github.com/../a",
        "https://github.com/",
        "https://github.com/a b",
        "-a https://github.com/a",
    ] {
        assert!(!is_safe_github_url(bad), "{bad}");
    }
}
