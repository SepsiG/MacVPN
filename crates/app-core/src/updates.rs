//! The update controller (port of the Swift `UpdateController`, without the windows): the update source, the
//! persisted "Check for Updates Automatically" and 24-hour delay switches, `check()` and its offer states, the
//! "Check for Updates Now" notices and the scheduler (at launch, then once 24 hours passed, waking hourly), the
//! Update window's state (the offered release, the install stages and error, the previous update's notice) and
//! the install run around the platform's `install_update` (which keeps the step order and asks the quit guard).

use crate::app::{
    AUTO_CHECK_KEY, DELAY_KEY, LAST_CHECK_KEY, NOTICED_HELPER_RUN_KEY, PreferenceStore, UPDATE_SCHEDULER_WAKE,
    UpdateOffers, UpdatePreferences, update_check_due,
};
use crate::deps::Clock;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::update::{Offer, Release, UpdateChecker};
use serde::Serialize;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// GitHub's `releases/latest` and the update source: defined in `macvpn-platform-api` and re-exported here (their
/// old home).
pub use macvpn_platform_api::{ReleaseSource, UpdateSource};

/// What the menu and the Update window show about updates.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateView {
    /// The update source is configured (a real bundle): the update items are shown.
    pub enabled: bool,
    /// The offered release's tag ("Update available: vX").
    pub available: Option<String>,
    pub checking: bool,
    pub auto_check: bool,
    pub delay_updates: bool,
    /// The running app's version ("Installed version: …").
    pub current_version: String,
    /// The offered release (the Update window).
    pub release: Option<ReleaseView>,
    /// The install step being run (`None`: not installing).
    pub install_stage: Option<String>,
    /// Why the last install failed.
    pub install_error: Option<String>,
    /// "The previous update did not complete" (shown once, at launch).
    pub notice: Option<Notice>,
}

/// The offered release in the Update window. The notes are plain text: the UI renders them as text with inline
/// emphasis only (never as HTML).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseView {
    pub tag: String,
    pub notes: String,
    /// "Open the Release on GitHub" is shown (the core accepted the page URL).
    pub has_page: bool,
}

/// How an install run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// The helper runs and waits for the app to quit: quit now, without asking again.
    HelperLaunched,
    /// The quit questions were cancelled; everything was cleaned up.
    Cancelled,
    /// Failed (the error is shown in the Update window).
    Failed,
    /// Nothing offered, or an install is already running.
    NotStarted,
}

/// An alert's text, shown in the popover.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Notice {
    pub title: String,
    pub message: String,
}

/// "Check for Updates Now": an update is offered (the Update window opens), or why not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "camelCase")]
pub enum CheckNowResult {
    Available,
    Notice(Notice),
}

#[derive(Default)]
struct State {
    offers: UpdateOffers,
    checking: bool,
    last_error: Option<String>,
    install_stage: Option<String>,
    install_error: Option<String>,
    notice: Option<Notice>,
}

type Hook = Arc<dyn Fn() + Send + Sync>;

pub struct UpdateController {
    source: Option<UpdateSource>,
    current_version: String,
    prefs: Arc<dyn PreferenceStore>,
    releases: Arc<dyn ReleaseSource>,
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
    on_change: Mutex<Option<Hook>>,
}

impl UpdateController {
    pub fn new(
        source: Option<UpdateSource>,
        current_version: &str,
        prefs: Arc<dyn PreferenceStore>,
        releases: Arc<dyn ReleaseSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        UpdateController {
            source,
            current_version: current_version.to_string(),
            prefs,
            releases,
            clock,
            state: Mutex::new(State::default()),
            on_change: Mutex::new(None),
        }
    }

    pub fn set_on_change(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.on_change.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(hook));
    }

    fn changed(&self) {
        let hook = self.on_change.lock().unwrap_or_else(PoisonError::into_inner).clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn enabled(&self) -> bool {
        self.source.is_some()
    }

    pub fn current_version(&self) -> &str {
        &self.current_version
    }

    pub fn preferences(&self) -> UpdatePreferences {
        UpdatePreferences::load(self.prefs.as_ref())
    }

    pub fn view(&self) -> UpdateView {
        let prefs = self.preferences();
        let state = self.lock();
        UpdateView {
            enabled: self.enabled(),
            available: state.offers.available.as_ref().map(|r| r.tag.clone()),
            checking: state.checking,
            auto_check: prefs.auto_check,
            delay_updates: prefs.delay_updates,
            current_version: self.current_version.clone(),
            release: state.offers.available.as_ref().map(|r| ReleaseView {
                tag: r.tag.clone(),
                notes: r.notes.clone(),
                has_page: r.page_url.is_some(),
            }),
            install_stage: state.install_stage.clone(),
            install_error: state.install_error.clone(),
            notice: state.notice.clone(),
        }
    }

    /// Judges a release obtained elsewhere as if `check` had found it (the development smoke test's mock release).
    pub fn consider(&self, release: Release) {
        let now = self.clock.now();
        let delayed = self.preferences().delay_updates;
        self.lock().offers.apply(release, &self.current_version, delayed, now);
        self.changed();
    }

    /// The offered release's GitHub page (validated by the core's release parser).
    pub fn release_page(&self) -> Option<String> {
        self.lock().offers.available.as_ref().and_then(|r| r.page_url.clone())
    }

    pub fn is_installing(&self) -> bool {
        self.lock().install_stage.is_some()
    }

    /// "Download and Install": runs `run` with the offered release and a stage reporter. Only one install at a
    /// time; the stage stays shown after the helper was launched (the app quits), and is cleared otherwise. A
    /// failure's message is kept for the window.
    pub fn install(
        &self,
        run: impl FnOnce(&Release, &dyn Fn(String)) -> Result<InstallOutcome, String>,
    ) -> InstallOutcome {
        let offered = {
            let mut state = self.lock();
            let Some(release) = state.offers.available.clone() else { return InstallOutcome::NotStarted };
            if state.install_stage.is_some() {
                return InstallOutcome::NotStarted;
            }
            state.install_error = None;
            state.install_stage = Some(String::new());
            release
        };
        self.changed();
        let release = self.newest_offer().unwrap_or(offered);
        let stage = |message: String| {
            self.lock().install_stage = Some(message);
            self.changed();
        };
        let result = run(&release, &stage);
        let outcome = {
            let mut state = self.lock();
            match result {
                Ok(InstallOutcome::HelperLaunched) => InstallOutcome::HelperLaunched,
                Ok(other) => {
                    state.install_stage = None;
                    other
                }
                Err(message) => {
                    state.install_stage = None;
                    state.install_error = Some(message);
                    InstallOutcome::Failed
                }
            }
        };
        self.changed();
        outcome
    }

    /// Right before an install: GitHub's latest release again, so the update goes straight to the newest one (a
    /// release published since the last check replaces the offered one; every release holds all earlier changes).
    /// Only a release that can be offered now replaces it; a failed check, or a newer release still waiting for its
    /// signature or its 24 hours, keeps the offered one.
    fn newest_offer(&self) -> Option<Release> {
        let source = self.source.as_ref()?;
        let latest = self.releases.latest_release(source.repo_id, &source.repo).ok()?;
        let now = self.clock.now();
        let delayed = self.preferences().delay_updates;
        if UpdateChecker::offer(&latest, &self.current_version, delayed, now) != Offer::Offer {
            return None;
        }
        self.prefs.set_date(LAST_CHECK_KEY, now);
        self.lock().offers.available = Some(latest.clone());
        self.changed();
        Some(latest)
    }

    /// The previous update's outcome found at launch (`(run, message)` from the helper's log): remembered as
    /// noticed (`noticedUpdateHelperRun`, so it is shown once) and shown. True: there is a notice to show.
    pub fn show_previous_update_notice(&self, found: Option<(String, String)>) -> bool {
        let Some((run, message)) = found else { return false };
        self.prefs.set_string(NOTICED_HELPER_RUN_KEY, &run);
        self.lock().notice = Some(Notice { title: l10n::tr("The previous update did not complete", &[]), message });
        self.changed();
        true
    }

    /// The run already noticed (the launch check skips it).
    pub fn noticed_helper_run(&self) -> Option<String> {
        self.prefs.string(NOTICED_HELPER_RUN_KEY)
    }

    /// The notice was read (OK).
    pub fn dismiss_notice(&self) {
        self.lock().notice = None;
        self.changed();
    }

    pub fn available(&self) -> Option<Release> {
        self.lock().offers.available.clone()
    }

    pub fn set_auto_check(&self, on: bool) {
        self.prefs.set_bool(AUTO_CHECK_KEY, on);
        self.changed();
    }

    /// The known release is judged again with the new setting.
    pub fn set_delay_updates(&self, on: bool) {
        self.prefs.set_bool(DELAY_KEY, on);
        let now = self.clock.now();
        self.lock().offers.reapply(&self.current_version, on, now);
        self.changed();
    }

    /// True if a newer release is offered. Without a source, or while a check runs, nothing happens. On success
    /// the time is stored (`lastUpdateCheck`); the error is kept for "Check for Updates Now".
    pub fn check(&self) -> bool {
        let Some(source) = &self.source else { return self.available().is_some() };
        {
            let mut state = self.lock();
            if state.checking {
                return state.offers.available.is_some();
            }
            state.checking = true;
        }
        self.changed();
        let result = self.releases.latest_release(source.repo_id, &source.repo);
        let now = self.clock.now();
        let delayed = self.preferences().delay_updates;
        let available = {
            let mut state = self.lock();
            state.checking = false;
            match result {
                Ok(release) => {
                    self.prefs.set_date(LAST_CHECK_KEY, now);
                    state.last_error = None;
                    state.offers.apply(release, &self.current_version, delayed, now);
                }
                Err(e) => state.last_error = Some(e),
            }
            state.offers.available.is_some()
        };
        self.changed();
        available
    }

    /// "Check for Updates Now": if nothing is offered, the reason (the Swift alerts).
    pub fn check_now(&self) -> CheckNowResult {
        if self.check() {
            return CheckNowResult::Available;
        }
        let state = self.lock();
        let notice = if let Some(error) = &state.last_error {
            Notice { title: l10n::tr("The update check failed", &[]), message: error.clone() }
        } else if let Some(release) = &state.offers.awaiting_signature {
            Notice {
                title: l10n::tr("Update waiting for signature", &[]),
                message: l10n::tr(
                    "Version %@ has been published, but it is not signed by the MacVPN maintainer yet. It will be offered once it is signed.",
                    &[Arg::Str(&release.version)],
                ),
            }
        } else if let Some(release) = &state.offers.deferred {
            Notice {
                title: l10n::tr("MacVPN is up to date", &[]),
                message: l10n::tr(
                    "Version %@ was published less than 24 hours ago. It will be offered later, as \"Only Offer Updates Published at Least 24 Hours Ago\" is on.",
                    &[Arg::Str(&release.version)],
                ),
            }
        } else {
            Notice {
                title: l10n::tr("MacVPN is up to date", &[]),
                message: l10n::tr("The installed version (%@) is the latest.", &[Arg::Str(&self.current_version)]),
            }
        };
        CheckNowResult::Notice(notice)
    }

    /// The scheduler (the Swift `startScheduler` task): with the automatic check on, checks at launch and then
    /// whenever 24 hours passed since the last successful check; wakes every hour. `sleep` returns false to stop.
    pub fn run_scheduler(&self, mut sleep: impl FnMut(Duration) -> bool) {
        if !self.enabled() {
            return;
        }
        let mut first = true;
        loop {
            if update_check_due(first, &self.preferences(), self.clock.now()) {
                self.check();
            }
            first = false;
            if !sleep(UPDATE_SCHEDULER_WAKE) {
                return;
            }
        }
    }
}
