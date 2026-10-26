//! The daily package-index refresh (macOS: `brew update`, so System Status's `brew outdated` check sees the newest
//! versions without the user running it by hand): shortly after launch when the last successful run is more than
//! 24 hours old, then whenever 24 hours passed, waking hourly. A failure (offline, an error, the time limit) or a
//! busy round (an install / upgrade of the app's runs) is retried at the next wake; only a success is stored.
//! The platform decides whether there is anything to run (nothing in the sandbox or without Homebrew; Windows has no
//! index: `Updated` with a usable WinVPN Service, so the check after it asks winget and the service again).

use crate::app::PreferenceStore;
use crate::deps::Clock;
use macvpn_core::date::Date;
use macvpn_platform_api::PackageIndexUpdate;
use std::sync::Arc;
use std::time::Duration;

/// The app preference (non-secret, the app's `UserDefaults` domain) holding the last successful run.
pub const LAST_PACKAGE_INDEX_UPDATE_KEY: &str = "lastBrewUpdate";
/// At most once per this many seconds (24 hours).
pub const PACKAGE_INDEX_UPDATE_INTERVAL: f64 = 24.0 * 60.0 * 60.0;
/// The first round waits this long after launch, so it never competes with the launch itself.
pub const PACKAGE_INDEX_FIRST_DELAY: Duration = Duration::from_secs(60);
/// The scheduler wakes this often to see whether a run is due.
pub const PACKAGE_INDEX_WAKE: Duration = Duration::from_secs(3600);

/// Whether a run is due: never run, 24 hours passed since the last successful one, or the clock went back past it.
pub fn package_index_update_due(last: Option<Date>, now: Date) -> bool {
    last.is_none_or(|last| {
        let elapsed = now.time_interval_since(last);
        !(0.0..PACKAGE_INDEX_UPDATE_INTERVAL).contains(&elapsed)
    })
}

pub struct PackageIndexSchedule {
    prefs: Arc<dyn PreferenceStore>,
    clock: Arc<dyn Clock>,
}

impl PackageIndexSchedule {
    pub fn new(prefs: Arc<dyn PreferenceStore>, clock: Arc<dyn Clock>) -> Self {
        PackageIndexSchedule { prefs, clock }
    }

    pub fn last_run(&self) -> Option<Date> {
        self.prefs.date(LAST_PACKAGE_INDEX_UPDATE_KEY)
    }

    /// One round: when due, runs `update`; a success stores the time. `None`: not due (nothing run).
    pub fn round(&self, update: impl FnOnce() -> PackageIndexUpdate) -> Option<PackageIndexUpdate> {
        if !package_index_update_due(self.last_run(), self.clock.now()) {
            return None;
        }
        let outcome = update();
        if outcome == PackageIndexUpdate::Updated {
            self.prefs.set_date(LAST_PACKAGE_INDEX_UPDATE_KEY, self.clock.now());
        }
        Some(outcome)
    }

    /// The scheduler: waits [`PACKAGE_INDEX_FIRST_DELAY`], then a round every [`PACKAGE_INDEX_WAKE`]; every run's
    /// outcome goes to `on_outcome` (the app logs a failure and checks the system again after a success). `sleep`
    /// returns false to stop. `Unavailable` (no Homebrew yet, the sandbox, no usable WinVPN Service) is asked again at the next wake,
    /// so Homebrew installed meanwhile is picked up.
    pub fn run(
        &self,
        mut update: impl FnMut() -> PackageIndexUpdate,
        mut on_outcome: impl FnMut(&PackageIndexUpdate),
        mut sleep: impl FnMut(Duration) -> bool,
    ) {
        if !sleep(PACKAGE_INDEX_FIRST_DELAY) {
            return;
        }
        loop {
            if let Some(outcome) = self.round(&mut update) {
                on_outcome(&outcome);
            }
            if !sleep(PACKAGE_INDEX_WAKE) {
                return;
            }
        }
    }
}
