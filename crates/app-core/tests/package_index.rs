//! The daily package-index refresh (macOS: `brew update`): the 24-hour decision, the stored time (only after a
//! success) and the scheduler's rounds. Nothing runs a real package manager: the update is a closure.

use macvpn_app_core::app::{MemoryPreferences, PreferenceStore};
use macvpn_app_core::deps::ManualClock;
use macvpn_app_core::package_index::{
    LAST_PACKAGE_INDEX_UPDATE_KEY, PACKAGE_INDEX_FIRST_DELAY, PACKAGE_INDEX_UPDATE_INTERVAL, PACKAGE_INDEX_WAKE,
    PackageIndexSchedule, package_index_update_due,
};
use macvpn_core::date::Date;
use macvpn_platform_api::PackageIndexUpdate;
use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

const DAY: f64 = 24.0 * 60.0 * 60.0;

fn at(seconds: f64) -> Date {
    Date::from_time_interval_since_1970(seconds)
}

#[test]
fn due_once_24_hours_passed() {
    assert_eq!(PACKAGE_INDEX_UPDATE_INTERVAL, DAY);
    let now = at(1_800_000_000.0);
    assert!(package_index_update_due(None, now), "never run: due");
    assert!(!package_index_update_due(Some(now), now));
    assert!(!package_index_update_due(Some(now.adding(-DAY + 1.0)), now));
    assert!(package_index_update_due(Some(now.adding(-DAY)), now));
    assert!(package_index_update_due(Some(now.adding(-3.0 * DAY)), now));
    // The clock went back past the last run: due (instead of waiting until it catches up).
    assert!(package_index_update_due(Some(now.adding(3600.0)), now));
}

fn schedule(now: Date) -> (PackageIndexSchedule, Arc<MemoryPreferences>, Arc<ManualClock>) {
    let prefs = Arc::new(MemoryPreferences::default());
    let clock = Arc::new(ManualClock::new(now));
    (PackageIndexSchedule::new(prefs.clone(), clock.clone()), prefs, clock)
}

/// Only a success is stored; a failure, a busy round or no package manager are asked again next time.
#[test]
fn only_a_success_is_remembered() {
    let now = at(1_800_000_000.0);
    let (schedule, prefs, clock) = schedule(now);
    for outcome in
        [PackageIndexUpdate::Failed("offline".into()), PackageIndexUpdate::Busy, PackageIndexUpdate::Unavailable]
    {
        assert_eq!(schedule.round(|| outcome.clone()), Some(outcome));
        assert_eq!(prefs.date(LAST_PACKAGE_INDEX_UPDATE_KEY), None);
    }
    assert_eq!(schedule.round(|| PackageIndexUpdate::Updated), Some(PackageIndexUpdate::Updated));
    assert_eq!(schedule.last_run(), Some(now));
    // Not due again within the day: nothing runs.
    clock.advance(DAY - 1.0);
    assert_eq!(schedule.round(|| panic!("not due")), None);
    clock.advance(1.0);
    assert_eq!(schedule.round(|| PackageIndexUpdate::Updated), Some(PackageIndexUpdate::Updated));
    assert_eq!(schedule.last_run(), Some(now.adding(DAY)));
}

/// A recent run (an earlier launch) is honoured at launch.
#[test]
fn a_recent_run_is_not_repeated_at_launch() {
    let now = at(1_800_000_000.0);
    let (schedule, prefs, _) = schedule(now);
    prefs.set_date(LAST_PACKAGE_INDEX_UPDATE_KEY, now.adding(-3600.0));
    assert_eq!(schedule.round(|| panic!("ran within 24 hours")), None);
}

/// The scheduler waits a minute after launch, then wakes hourly; it runs only when due and reports every outcome;
/// a failure is retried at the next wake.
#[test]
fn the_scheduler_runs_daily_and_retries_failures() {
    let start = at(1_800_000_000.0);
    let (schedule, _, clock) = schedule(start);
    let sleeps = RefCell::new(Vec::new());
    let runs = RefCell::new(0);
    let outcomes = RefCell::new(Vec::new());
    // Answers: offline first, then success; afterwards success again.
    let answers = RefCell::new(vec![PackageIndexUpdate::Failed("offline".into()), PackageIndexUpdate::Updated]);
    schedule.run(
        || {
            *runs.borrow_mut() += 1;
            let mut answers = answers.borrow_mut();
            if answers.is_empty() { PackageIndexUpdate::Updated } else { answers.remove(0) }
        },
        |outcome| outcomes.borrow_mut().push(outcome.clone()),
        |wake| {
            sleeps.borrow_mut().push(wake);
            clock.advance(wake.as_secs_f64());
            // The launch delay, then 26 hourly wakes.
            sleeps.borrow().len() < 27
        },
    );
    let sleeps = sleeps.into_inner();
    assert_eq!(sleeps[0], PACKAGE_INDEX_FIRST_DELAY);
    assert!(sleeps[1..].iter().all(|s| *s == PACKAGE_INDEX_WAKE));
    assert_eq!(PACKAGE_INDEX_WAKE, Duration::from_secs(3600));
    // Failed at launch + 1 min, succeeded an hour later, then once more 24 hours after that.
    assert_eq!(
        outcomes.into_inner(),
        [PackageIndexUpdate::Failed("offline".into()), PackageIndexUpdate::Updated, PackageIndexUpdate::Updated]
    );
    assert_eq!(runs.into_inner(), 3);
}

/// Stopped during the launch delay: nothing runs.
#[test]
fn the_scheduler_stops_when_asked() {
    let (schedule, _, _) = schedule(at(1_800_000_000.0));
    schedule.run(|| panic!("ran"), |_| {}, |_| false);
}
