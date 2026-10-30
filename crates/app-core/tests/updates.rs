//! The update controller (port of the Swift `UpdateController` minus the alerts' rendering): the persisted
//! auto-check / 24-hour delay switches, `check()` with its offer states, the "Check for Updates Now" notices and
//! the 24-hour schedule.

use macvpn_app_core::app::{
    AUTO_CHECK_KEY, DELAY_KEY, LAST_CHECK_KEY, MemoryPreferences, NOTICED_HELPER_RUN_KEY, PreferenceStore,
};
use macvpn_app_core::deps::{Clock, ManualClock};
use macvpn_app_core::updates::{
    CheckNowResult, InstallOutcome, Notice, ReleaseSource, ReleaseView, UpdateController, UpdateSource, UpdateView,
};
use macvpn_core::date::Date;
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::update::{Release, ReleaseAsset};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NOW: f64 = 1_900_000_000.0;

fn date(unix: f64) -> Date {
    Date::from_time_interval_since_1970(unix)
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
        package: asset(format!("MacVPN-{version}.dmg")),
        checksum: asset(format!("MacVPN-{version}.dmg.sha256")),
        signature: signed.then(|| asset(format!("MacVPN-{version}.dmg.sig"))),
    }
}

#[derive(Default)]
struct Source {
    answer: Mutex<Option<Result<Release, String>>>,
    calls: AtomicUsize,
    seen: Mutex<Vec<(i64, String)>>,
}

impl Source {
    fn answer(&self, answer: Result<Release, &str>) {
        *self.answer.lock().unwrap() = Some(answer.map_err(str::to_string));
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ReleaseSource for Source {
    fn latest_release(&self, repo_id: i64, repo: &str) -> Result<Release, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().unwrap().push((repo_id, repo.to_string()));
        self.answer.lock().unwrap().clone().unwrap_or_else(|| Err("no answer".into()))
    }
}

struct Setup {
    controller: Arc<UpdateController>,
    prefs: Arc<MemoryPreferences>,
    source: Arc<Source>,
    clock: Arc<ManualClock>,
}

fn setup(enabled: bool) -> Setup {
    let prefs = Arc::new(MemoryPreferences::new());
    let source = Arc::new(Source::default());
    let clock = Arc::new(ManualClock::new(date(NOW)));
    let controller = Arc::new(UpdateController::new(
        enabled.then(|| UpdateSource { repo_id: 1_422_472_799, repo: "SepsiG/MacVPN".into() }),
        "1.0.0",
        prefs.clone(),
        source.clone(),
        clock.clone(),
    ));
    Setup { controller, prefs, source, clock }
}

#[test]
fn defaults_and_persisted_switches() {
    let s = setup(true);
    assert_eq!(
        s.controller.view(),
        UpdateView {
            enabled: true,
            available: None,
            checking: false,
            auto_check: true,
            delay_updates: false,
            current_version: "1.0.0".into(),
            release: None,
            install_stage: None,
            install_error: None,
            notice: None,
        }
    );
    s.controller.set_auto_check(false);
    s.controller.set_delay_updates(true);
    assert_eq!(s.prefs.bool(AUTO_CHECK_KEY), Some(false));
    assert_eq!(s.prefs.bool(DELAY_KEY), Some(true));
    let view = s.controller.view();
    assert!(!view.auto_check && view.delay_updates);
    // Existing values (the Swift app's UserDefaults) are read.
    let s2 = setup(true);
    s2.prefs.set_bool(AUTO_CHECK_KEY, false);
    assert!(!s2.controller.view().auto_check);
}

#[test]
fn check_offers_a_signed_newer_release_and_stores_the_time() {
    let s = setup(true);
    let offered = release("1.1.0", Some(NOW - 7.0 * 86_400.0), true);
    s.source.answer(Ok(offered.clone()));
    assert!(s.controller.check());
    assert_eq!(s.controller.available(), Some(offered));
    assert_eq!(s.controller.view().available.as_deref(), Some("v1.1.0"));
    assert_eq!(s.prefs.date(LAST_CHECK_KEY), Some(date(NOW)));
    assert_eq!(*s.source.seen.lock().unwrap(), [(1_422_472_799, "SepsiG/MacVPN".to_string())]);
}

#[test]
fn failed_check_keeps_the_last_check_time_and_reports_the_error() {
    let s = setup(true);
    s.source.answer(Err("HTTP 503"));
    assert!(!s.controller.check());
    assert_eq!(s.prefs.date(LAST_CHECK_KEY), None);
    assert_eq!(
        s.controller.check_now(),
        CheckNowResult::Notice(Notice { title: "The update check failed".into(), message: "HTTP 503".into() })
    );
}

#[test]
fn disabled_without_a_source() {
    let s = setup(false);
    assert!(!s.controller.view().enabled);
    assert!(!s.controller.check());
    assert_eq!(s.source.calls(), 0);
    s.controller.run_scheduler(|_| false);
    assert_eq!(s.source.calls(), 0);
}

#[test]
fn check_now_notices_in_both_languages() {
    with_language(AppLanguage::En, || {
        let s = setup(true);
        s.source.answer(Ok(release("1.0.0", Some(0.0), true)));
        assert_eq!(
            s.controller.check_now(),
            CheckNowResult::Notice(Notice {
                title: "MacVPN is up to date".into(),
                message: "The installed version (1.0.0) is the latest.".into()
            })
        );
        s.source.answer(Ok(release("1.2.0", Some(0.0), false)));
        assert_eq!(
            s.controller.check_now(),
            CheckNowResult::Notice(Notice {
                title: "Update waiting for signature".into(),
                message: "Version 1.2.0 has been published, but it is not signed by the MacVPN maintainer yet. It will be offered once it is signed.".into()
            })
        );
        s.controller.set_delay_updates(true);
        s.source.answer(Ok(release("1.3.0", Some(NOW - 3600.0), true)));
        assert_eq!(
            s.controller.check_now(),
            CheckNowResult::Notice(Notice {
                title: "MacVPN is up to date".into(),
                message: "Version 1.3.0 was published less than 24 hours ago. It will be offered later, as \"Only Offer Updates Published at Least 24 Hours Ago\" is on.".into()
            })
        );
        // Turning the delay off offers the known release at once (no new check).
        let calls = s.source.calls();
        s.controller.set_delay_updates(false);
        assert_eq!(s.controller.view().available.as_deref(), Some("v1.3.0"));
        assert_eq!(s.source.calls(), calls);
        assert_eq!(s.controller.check_now(), CheckNowResult::Available);
    });
    with_language(AppLanguage::Hu, || {
        let s = setup(true);
        s.source.answer(Ok(release("1.0.0", Some(0.0), true)));
        let CheckNowResult::Notice(notice) = s.controller.check_now() else { panic!() };
        assert_eq!(notice.title, "A MacVPN naprakész");
        assert!(notice.message.contains("1.0.0"), "{}", notice.message);
    });
}

#[test]
fn scheduler_checks_at_launch_then_after_24_hours_only_with_auto_check() {
    let s = setup(true);
    s.source.answer(Ok(release("1.0.0", Some(0.0), true)));
    let wakes = AtomicUsize::new(0);
    s.controller.run_scheduler(|d| {
        assert_eq!(d, Duration::from_secs(3600));
        s.clock.advance(3600.0);
        wakes.fetch_add(1, Ordering::SeqCst) < 29 // 30 hours
    });
    assert_eq!(s.source.calls(), 2, "at launch and 24 hours later");
    assert_eq!(s.prefs.date(LAST_CHECK_KEY), Some(date(NOW + 24.0 * 3600.0)));

    let off = setup(true);
    off.controller.set_auto_check(false);
    off.controller.run_scheduler(|_| {
        off.clock.advance(25.0 * 3600.0);
        false
    });
    assert_eq!(off.source.calls(), 0);
}

#[test]
fn a_failed_scheduled_check_is_retried_at_the_next_wake() {
    let s = setup(true);
    s.source.answer(Err("offline"));
    let wakes = AtomicUsize::new(0);
    s.controller.run_scheduler(|_| {
        s.clock.advance(3600.0);
        wakes.fetch_add(1, Ordering::SeqCst) < 2
    });
    // Never succeeded: no last check time, so every wake is due.
    assert_eq!(s.source.calls(), 3);
}

#[test]
fn change_hook_fires_on_check_and_switches() {
    let s = setup(true);
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    s.controller.set_on_change(move || {
        c.fetch_add(1, Ordering::SeqCst);
    });
    s.source.answer(Ok(release("1.0.0", None, true)));
    s.controller.check();
    s.controller.set_auto_check(false);
    assert!(count.load(Ordering::SeqCst) >= 3, "checking on, checking off, switch");
    assert!(!s.controller.view().checking);
    let _ = s.clock.now();
}

// MARK: - Update window and install

fn offered(s: &Setup) -> Release {
    let mut r = release("1.1.0", Some(NOW - 7200.0), true);
    r.notes = "**Fixes** <script>alert(1)</script>".into();
    r.page_url = Some("https://github.com/SepsiG/MacVPN/releases/tag/v1.1.0".into());
    s.source.answer(Ok(r.clone()));
    assert!(s.controller.check());
    r
}

#[test]
fn the_window_shows_the_offered_release() {
    let s = setup(true);
    offered(&s);
    let view = s.controller.view();
    assert_eq!(
        view.release,
        Some(ReleaseView { tag: "v1.1.0".into(), notes: "**Fixes** <script>alert(1)</script>".into(), has_page: true })
    );
    assert_eq!(s.controller.release_page().as_deref(), Some("https://github.com/SepsiG/MacVPN/releases/tag/v1.1.0"));
}

#[test]
fn install_reports_stages_and_keeps_the_last_one_when_quitting() {
    let s = setup(true);
    assert_eq!(s.controller.install(|_, _| panic!("nothing offered")), InstallOutcome::NotStarted);
    offered(&s);
    let seen = Mutex::new(Vec::new());
    let outcome = s.controller.install(|r, stage| {
        assert_eq!(r.version, "1.1.0");
        assert!(s.controller.is_installing());
        assert_eq!(s.controller.install(|_, _| panic!("second")), InstallOutcome::NotStarted, "one at a time");
        stage("Downloading…".into());
        seen.lock().unwrap().push(s.controller.view().install_stage);
        stage("Quitting and restarting…".into());
        Ok(InstallOutcome::HelperLaunched)
    });
    assert_eq!(outcome, InstallOutcome::HelperLaunched);
    assert_eq!(*seen.lock().unwrap(), [Some("Downloading…".to_string())]);
    assert_eq!(s.controller.view().install_stage.as_deref(), Some("Quitting and restarting…"));
}

#[test]
fn a_cancelled_or_failed_install_clears_the_stage() {
    let s = setup(true);
    offered(&s);
    assert_eq!(s.controller.install(|_, _| Ok(InstallOutcome::Cancelled)), InstallOutcome::Cancelled);
    assert_eq!(s.controller.view().install_stage, None);
    assert_eq!(s.controller.install(|_, _| Err("The checksum does not match".into())), InstallOutcome::Failed);
    let view = s.controller.view();
    assert_eq!((view.install_stage, view.install_error.as_deref()), (None, Some("The checksum does not match")));
    // The next attempt clears the old error.
    s.controller.install(|_, _| {
        assert_eq!(s.controller.view().install_error, None);
        Ok(InstallOutcome::Cancelled)
    });
}

#[test]
fn an_update_question_no_window_can_show_ends_the_install() {
    use macvpn_app_core::quit::{AfterInstall, QuitGuard, UpdateQuit};
    let s = setup(true);
    offered(&s);
    let guard = Arc::new(QuitGuard::new());
    let quit = Arc::new(UpdateQuit::new(guard.clone()));
    let controller = s.controller.clone();
    let q = quit.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = controller.install(|_, stage| {
            stage("Waiting for the quit questions…".into());
            // The Update window was closed during the download, and the question could not be shown anywhere.
            if q.confirm(false, true, |_| false, |_| {}) {
                Ok(InstallOutcome::HelperLaunched)
            } else {
                Ok(InstallOutcome::Cancelled)
            }
        });
        let _ = tx.send(outcome);
    });
    let outcome = rx.recv_timeout(Duration::from_secs(2)).expect("the install must not block");
    assert_eq!(outcome, InstallOutcome::Cancelled);
    assert!(!s.controller.is_installing());
    assert_eq!(guard.question(), None);
    assert_eq!(quit.after_install(outcome), AfterInstall::Stay);
}

#[test]
fn previous_update_notice_is_shown_once() {
    let s = setup(true);
    assert!(!s.controller.show_previous_update_notice(None));
    with_language(AppLanguage::En, || {
        assert!(s.controller.show_previous_update_notice(Some(("== run 1 ==".into(), "It failed.".into()))));
    });
    assert_eq!(s.prefs.string(NOTICED_HELPER_RUN_KEY).as_deref(), Some("== run 1 =="));
    assert_eq!(s.controller.noticed_helper_run().as_deref(), Some("== run 1 =="));
    assert_eq!(
        s.controller.view().notice,
        Some(Notice { title: "The previous update did not complete".into(), message: "It failed.".into() })
    );
    s.controller.dismiss_notice();
    assert_eq!(s.controller.view().notice, None);
}

#[test]
fn install_takes_a_release_published_since_the_last_check() {
    let s = setup(true);
    offered(&s);
    s.source.answer(Ok(release("1.3.0", Some(NOW - 7200.0), true)));
    let outcome = s.controller.install(|r, _| {
        assert_eq!(r.version, "1.3.0", "the newest, not the one offered at the last check");
        Ok(InstallOutcome::HelperLaunched)
    });
    assert_eq!(outcome, InstallOutcome::HelperLaunched);
    assert_eq!(s.controller.view().available.as_deref(), Some("v1.3.0"));
}

#[test]
fn install_keeps_the_offered_release_when_the_newest_cannot_be_offered() {
    let s = setup(true);
    offered(&s);
    let installs = |s: &Setup| {
        s.controller.install(|r, _| {
            assert_eq!(r.version, "1.1.0");
            Ok(InstallOutcome::Cancelled)
        })
    };
    // Not signed yet.
    s.source.answer(Ok(release("1.3.0", Some(NOW - 7200.0), false)));
    assert_eq!(installs(&s), InstallOutcome::Cancelled);
    // The check fails.
    s.source.answer(Err("offline"));
    assert_eq!(installs(&s), InstallOutcome::Cancelled);
    // Published within the 24 hours while the delay is on (the offered one is older than that).
    s.source.answer(Ok(release("1.1.0", Some(NOW - 3.0 * 86400.0), true)));
    assert!(s.controller.check());
    s.controller.set_delay_updates(true);
    s.source.answer(Ok(release("1.3.0", Some(NOW - 60.0), true)));
    assert_eq!(installs(&s), InstallOutcome::Cancelled);
    assert_eq!(s.controller.view().available.as_deref(), Some("v1.1.0"));
}
