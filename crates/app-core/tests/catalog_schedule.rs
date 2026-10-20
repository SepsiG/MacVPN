//! The team catalog refresh schedule (plan Task 12): the pure schedule, and the service's scheduler rounds over
//! the fake fetcher (counting its calls).

mod catalog_support;
mod common;

use catalog_support::*;
use macvpn_app_core::catalog::{RefreshResult, SubscribeInput};
use macvpn_app_core::catalog_schedule::*;
use macvpn_core::catalog::format::CatalogError;
use macvpn_core::catalog::keys::TeamKey;
use macvpn_core::catalog::source::CatalogSource;
use macvpn_core::vault::SubscriptionStatus;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MIN: Duration = Duration::from_secs(60);

// MARK: - pure

#[test]
fn healthy_is_due_15_minutes_after_the_last_attempt() {
    let t = Instant::now();
    assert_eq!(REFRESH_INTERVAL, 15 * MIN);
    assert_eq!(next_attempt(None, 0, 0.0), None, "never attempted: due now");
    assert!(is_due(RefreshTrigger::Timer, None, t));
    let next = next_attempt(Some(t), 0, 0.05);
    assert_eq!(next, Some(t + 15 * MIN), "no jitter while healthy");
    assert!(!is_due(RefreshTrigger::Timer, next, t + 14 * MIN));
    assert!(is_due(RefreshTrigger::Timer, next, t + 15 * MIN));
}

#[test]
fn the_back_off_doubles_from_one_minute_up_to_an_hour() {
    let t = Instant::now();
    let minutes: Vec<u64> = (1..=8).map(|n| (next_attempt(Some(t), n, 0.0).unwrap() - t).as_secs() / 60).collect();
    assert_eq!(minutes, [1, 2, 4, 8, 16, 32, 60, 60]);
    assert_eq!(backoff(u32::MAX), BACKOFF_MAX);
    // Reset after a success: the healthy interval again.
    assert_eq!(next_attempt(Some(t), 0, 0.0), Some(t + REFRESH_INTERVAL));
}

#[test]
fn the_jitter_adds_at_most_ten_percent_of_the_back_off() {
    let t = Instant::now();
    assert_eq!(next_attempt(Some(t), 1, 0.1), Some(t + Duration::from_secs(66)));
    assert_eq!(next_attempt(Some(t), 1, 5.0), Some(t + Duration::from_secs(66)), "clamped");
    assert_eq!(next_attempt(Some(t), 1, -1.0), Some(t + MIN));
    assert_eq!(next_attempt(Some(t), 1, f64::NAN), Some(t + MIN));
    assert_eq!(next_attempt(Some(t), 7, 0.1), Some(t + Duration::from_secs(3960)));
}

#[test]
fn wake_launch_unlock_and_manual_run_despite_the_back_off_and_the_timer_does_not() {
    let t = Instant::now();
    let next = next_attempt(Some(t), 6, 0.0);
    for trigger in [RefreshTrigger::Launch, RefreshTrigger::Unlock, RefreshTrigger::Wake, RefreshTrigger::Manual] {
        assert!(is_due(trigger, next, t + MIN), "{trigger:?}");
    }
    assert!(!is_due(RefreshTrigger::Timer, next, t + MIN));
    assert!(is_due(RefreshTrigger::Timer, next, t + 32 * MIN));
}

// MARK: - the service's rounds

fn subscribed() -> (CatalogFixture, Publisher) {
    let f = CatalogFixture::new();
    let p = Publisher::new();
    f.fetcher.serve(p.seal(1, &payload(&[(1, "One")])));
    let (_, pending) = f
        .service
        .preview(SubscribeInput {
            source: CatalogSource::File(PathBuf::from("/Volumes/Share/acme.macvpncatalog")),
            team_key: TeamKey::from_bytes(p.team.as_bytes()).unwrap(),
            fingerprint: p.admin.public().fingerprint(),
            bearer: None,
            catalog_id: None,
            min_version: None,
        })
        .unwrap();
    f.service.confirm(pending).unwrap();
    (f, p)
}

fn failures(f: &CatalogFixture) -> u32 {
    f.vault.with_read(|v| v.subscription(catalog_id())).unwrap().unwrap().failures
}

#[test]
fn timer_rounds_follow_the_interval_and_the_back_off() {
    let (f, _) = subscribed();
    let t = Instant::now();
    let calls = f.fetcher.calls();
    // Launch: everything once.
    assert_eq!(f.service.tick(RefreshTrigger::Launch, t).len(), 1);
    assert_eq!(f.fetcher.calls(), calls + 1);
    // Healthy: not before 15 minutes.
    assert!(f.service.tick(RefreshTrigger::Timer, t + 14 * MIN).is_empty());
    assert_eq!(f.service.tick(RefreshTrigger::Timer, t + 15 * MIN).len(), 1);
    assert_eq!(f.fetcher.calls(), calls + 2);
    // Failing: 1, then 2 minutes (plus at most 10 %).
    f.fetcher.fail(CatalogError::Unavailable("acme.macvpncatalog".into()));
    let t1 = t + 30 * MIN;
    f.service.tick(RefreshTrigger::Timer, t1);
    assert_eq!(failures(&f), 1);
    assert!(f.service.tick(RefreshTrigger::Timer, t1 + Duration::from_secs(59)).is_empty());
    let t2 = t1 + Duration::from_secs(67);
    assert_eq!(f.service.tick(RefreshTrigger::Timer, t2).len(), 1);
    assert_eq!(failures(&f), 2);
    assert!(f.service.tick(RefreshTrigger::Timer, t2 + Duration::from_secs(110)).is_empty());
    // Wake runs inside the back-off, and the count keeps counting.
    assert_eq!(f.service.tick(RefreshTrigger::Wake, t2 + Duration::from_secs(111)).len(), 1);
    assert_eq!(failures(&f), 3);
    let calls_now = f.fetcher.calls();
    assert_eq!(calls_now, calls + 5);
    // Healthy again: the count resets, the next timer round is 15 minutes later.
    let p = Publisher::new();
    f.fetcher.serve(p.seal(1, &payload(&[(1, "One")])));
    let t3 = t2 + 10 * MIN;
    assert_eq!(f.service.tick(RefreshTrigger::Timer, t3).len(), 1);
    assert_eq!(failures(&f), 0);
    assert!(f.service.tick(RefreshTrigger::Timer, t3 + 14 * MIN).is_empty());
}

#[test]
fn subscribing_and_refresh_now_count_as_the_timers_attempt() {
    // Subscribed: the first download was the subscription's own, so the timer does not fetch again at its next
    // wake (it would race a "Refresh now" and apply a new version behind the user's back).
    let (f, p) = subscribed();
    let t = Instant::now();
    let calls = f.fetcher.calls();
    assert!(f.service.tick(RefreshTrigger::Timer, t).is_empty());
    assert!(f.service.tick(RefreshTrigger::Timer, t + 14 * MIN).is_empty());
    assert_eq!(f.fetcher.calls(), calls);
    // "Refresh now" later: the timer counts from it.
    f.fetcher.serve(p.seal(2, &payload(&[(1, "One")])));
    assert!(matches!(f.service.refresh(catalog_id(), RefreshTrigger::Manual), RefreshResult::Applied(_)));
    let later = Instant::now();
    assert!(f.service.tick(RefreshTrigger::Timer, later).is_empty());
    assert_eq!(f.fetcher.calls(), calls + 1);
    assert_eq!(f.service.tick(RefreshTrigger::Timer, later + 15 * MIN).len(), 1);
}

#[test]
fn a_refused_rollback_keeps_the_normal_schedule() {
    let (f, p) = subscribed();
    f.fetcher.serve(p.seal(2, &payload(&[(1, "One")])));
    let t = Instant::now();
    f.service.tick(RefreshTrigger::Launch, t);
    f.fetcher.serve(p.seal(1, &payload(&[(1, "One")])));
    f.service.tick(RefreshTrigger::Timer, t + 15 * MIN);
    let r = f.vault.with_read(|v| v.subscription(catalog_id())).unwrap().unwrap();
    assert_eq!(r.status, SubscriptionStatus::RollbackRefused { offered: 1 });
    assert_eq!(r.failures, 0);
    assert!(f.service.tick(RefreshTrigger::Timer, t + 16 * MIN).is_empty(), "no back-off retries");
}

#[test]
fn a_locked_vault_fetches_nothing_at_all() {
    let (f, _) = subscribed();
    let calls = f.fetcher.calls();
    f.vault.lock();
    let t = Instant::now();
    for trigger in [RefreshTrigger::Launch, RefreshTrigger::Wake, RefreshTrigger::Unlock, RefreshTrigger::Timer] {
        assert!(f.service.tick(trigger, t).is_empty());
    }
    assert_eq!(f.service.refresh(catalog_id(), RefreshTrigger::Manual), RefreshResult::Locked);
    assert_eq!(f.fetcher.calls(), calls);
}

#[test]
fn the_scheduler_loop_starts_with_launch_and_takes_wake_requests() {
    let (f, _) = subscribed();
    let calls = f.fetcher.calls();
    let t = Instant::now();
    let clock = Cell::new(t);
    // Elapsed (1 min: not due), a wake request, elapsed again (not due), stop.
    let script = RefCell::new(VecDeque::from([Some(None), Some(Some(RefreshTrigger::Wake)), Some(None), None]));
    let waits = Cell::new(0);
    f.service.run_scheduler(
        || clock.get(),
        |d| {
            assert_eq!(d, SCHEDULER_WAKE);
            waits.set(waits.get() + 1);
            clock.set(clock.get() + MIN);
            script.borrow_mut().pop_front().unwrap()
        },
    );
    assert_eq!(waits.get(), 4);
    assert_eq!(f.fetcher.calls(), calls + 2, "the launch round and the wake round");
}

#[test]
fn wait_for_trigger_returns_requests_and_the_stop() {
    let (f, _) = subscribed();
    assert_eq!(f.service.wait_for_trigger(Duration::from_millis(20)), Some(None));
    f.service.wake();
    assert_eq!(f.service.wait_for_trigger(Duration::from_secs(5)), Some(Some(RefreshTrigger::Wake)));
    f.service.unlocked();
    assert_eq!(f.service.wait_for_trigger(Duration::from_secs(5)), Some(Some(RefreshTrigger::Unlock)));
    let service = f.service.clone();
    let waiter = std::thread::spawn(move || service.wait_for_trigger(Duration::from_secs(30)));
    std::thread::sleep(Duration::from_millis(50));
    f.service.wake();
    assert_eq!(waiter.join().unwrap(), Some(Some(RefreshTrigger::Wake)));
    f.service.stop_scheduler();
    assert_eq!(f.service.wait_for_trigger(Duration::from_secs(5)), None);
}

#[test]
fn every_unlocked_round_deletes_removals_that_went_down_meanwhile() {
    for trigger in [RefreshTrigger::Launch, RefreshTrigger::Unlock, RefreshTrigger::Timer] {
        removals_that_went_down_meanwhile(trigger);
    }
}

fn removals_that_went_down_meanwhile(trigger: RefreshTrigger) {
    use macvpn_app_core::catalog::{CatalogDeps, CatalogService};
    use macvpn_app_core::vault_stores::VaultSecrets;
    use macvpn_app_core::{ConnectionManager, Dependencies};
    use std::sync::Arc;
    let (f, p) = subscribed();
    f.root.respond(
        "status",
        Ok(&format!(
            r#"[{{"id":"{}","kind":"openvpn","state":"connected","iface":null,"ip":null,"since":null}}]"#,
            key(1)
        )),
    );
    f.manager.refresh();
    f.fetcher.serve(p.seal(2, &payload(&[(2, "Two")])));
    f.service.refresh(catalog_id(), RefreshTrigger::Manual);
    assert_eq!(f.connection_names(), ["One", "Two"]);
    // The app quits; the tunnel goes down meanwhile. The next run's manager sees it down from the start, so no
    // state listener ever reports the change: the launch round cleans up.
    f.root.respond("status", Ok("[]"));
    let manager = ConnectionManager::new(Dependencies::new(
        Arc::new(VaultRepo(f.vault.clone())),
        Arc::new(VaultSecrets::new(f.vault.clone())),
        f.root.clone(),
        Arc::new(common::MockNative::default()),
    ));
    manager.reload();
    manager.refresh();
    let service = CatalogService::new(CatalogDeps {
        vault: f.vault.clone(),
        https: f.fetcher.clone(),
        file: f.fetcher.clone(),
        manager: manager.clone(),
        clock: f.clock.clone(),
    });
    service.tick(trigger, Instant::now());
    let names: Vec<String> = manager.connections().into_iter().map(|c| c.name).collect();
    assert_eq!(names, ["Two"], "{trigger:?}");
}

#[test]
fn the_scheduler_thread_stops_promptly_and_a_stop_before_the_start_skips_the_launch_round() {
    let (f, _) = subscribed();
    let calls = f.fetcher.calls();
    f.service.stop_scheduler();
    let handle = f.service.start_scheduler();
    let started = Instant::now();
    handle.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(f.fetcher.calls(), calls, "no launch round after a stop");

    let (f, _) = subscribed();
    let calls = f.fetcher.calls();
    let handle = f.service.start_scheduler();
    let deadline = Instant::now() + Duration::from_secs(5);
    while f.fetcher.calls() == calls && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(f.fetcher.calls(), calls + 1, "the launch round");
    let stopping = Instant::now();
    f.service.stop_scheduler();
    handle.join().unwrap();
    assert!(stopping.elapsed() < Duration::from_secs(2), "not after the 30 s wake");
}
