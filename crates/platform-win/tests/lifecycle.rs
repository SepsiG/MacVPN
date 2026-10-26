//! The lifecycle window (its own test binary: the terminate handler is installed once per process). The messages
//! are sent to the window as Windows would on logoff, suspend, resume and a theme switch. Every test runs on one
//! long-lived thread ([`on_window_thread`]): the window belongs to the thread that creates it (it goes when that
//! thread ends) and the sends from that thread reach its procedure at once.

#![cfg(windows)]

use macvpn_platform_api::{Platform, TerminateReply};
use macvpn_platform_win::WinPlatform;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Arc, Mutex, OnceLock};

type Job = Box<dyn FnOnce() + Send>;

/// Runs `test` on the one thread that owns the lifecycle window (a failure is re-raised here).
fn on_window_thread(test: impl FnOnce() + Send + 'static) {
    static JOBS: OnceLock<Mutex<Sender<Job>>> = OnceLock::new();
    let jobs = JOBS.get_or_init(|| {
        let (tx, rx) = channel::<Job>();
        std::thread::spawn(move || {
            for job in rx {
                job();
            }
        });
        Mutex::new(tx)
    });
    let (done, result) = channel();
    let job: Job = Box::new(move || {
        let _ = done.send(catch_unwind(AssertUnwindSafe(test)));
    });
    jobs.lock().unwrap().send(job).unwrap();
    if let Err(panic) = result.recv().unwrap() {
        resume_unwind(panic);
    }
}

#[test]
fn logoff_asks_the_handler_suspend_sleeps_and_resume_wakes() {
    on_window_thread(logoff_suspend_resume);
}

fn logoff_suspend_resume() {
    let p = WinPlatform::new(true);
    let reply = Arc::new(AtomicUsize::new(0));
    let r = reply.clone();
    let asked = Arc::new(AtomicUsize::new(0));
    let a = asked.clone();
    assert!(p.lifecycle().install_terminate_handler(Box::new(move || {
        a.fetch_add(1, Ordering::SeqCst);
        [TerminateReply::Now, TerminateReply::Cancel, TerminateReply::Later][r.load(Ordering::SeqCst)]
    })));
    assert!(!p.lifecycle().install_terminate_handler(Box::new(|| TerminateReply::Now)), "only once");

    assert_eq!(macvpn_platform_win::lifecycle_query_end_session_for_tests(), Some(1), "Now: Windows may end");
    // The smoke run's wrapper sends the same message.
    #[cfg(debug_assertions)]
    assert_eq!(macvpn_platform_win::smoke::query_end_session(), Some(1), "the smoke wrapper");
    reply.store(1, Ordering::SeqCst);
    assert_eq!(macvpn_platform_win::lifecycle_query_end_session_for_tests(), Some(0), "Cancel: blocked");
    reply.store(2, Ordering::SeqCst);
    assert_eq!(macvpn_platform_win::lifecycle_query_end_session_for_tests(), Some(0), "Later: blocked for now");
    assert_eq!(asked.load(Ordering::SeqCst), if cfg!(debug_assertions) { 4 } else { 3 });
    // The quit flow decided to stay: the block reason goes, the process keeps running.
    p.lifecycle().reply_to_terminate(false);

    let woke = Arc::new(AtomicUsize::new(0));
    let w = woke.clone();
    p.lifecycle().observe_wake(Box::new(move || {
        w.fetch_add(1, Ordering::SeqCst);
    }));
    assert_eq!(macvpn_platform_win::lifecycle_resume_for_tests(), Some(1));
    assert_eq!(woke.load(Ordering::SeqCst), 1);

    let slept = Arc::new(AtomicUsize::new(0));
    let s = slept.clone();
    p.lifecycle().observe_sleep(Box::new(move || {
        s.fetch_add(1, Ordering::SeqCst);
    }));
    assert_eq!(macvpn_platform_win::lifecycle_suspend_for_tests(), Some(1));
    assert_eq!(slept.load(Ordering::SeqCst), 1, "suspend: the sleep observer, once");
    assert_eq!(woke.load(Ordering::SeqCst), 1, "suspend does not wake");
    assert_eq!(macvpn_platform_win::lifecycle_resume_for_tests(), Some(1));
    assert_eq!((slept.load(Ordering::SeqCst), woke.load(Ordering::SeqCst)), (1, 2), "resume does not sleep");

    // WinVPN 2c: a logoff (not a shutdown) runs the logoff observers (the RAS engine hangs up its connections).
    let logged_off = Arc::new(AtomicUsize::new(0));
    let l = logged_off.clone();
    macvpn_platform_win::lifecycle_observe_logoff_for_tests(Box::new(move || {
        l.fetch_add(1, Ordering::SeqCst);
    }));
    assert_eq!(macvpn_platform_win::lifecycle_end_session_for_tests(false), Some(0));
    assert_eq!(logged_off.load(Ordering::SeqCst), 0, "a shutdown is Windows' own");
    assert_eq!(macvpn_platform_win::lifecycle_end_session_for_tests(true), Some(0));
    assert_eq!(logged_off.load(Ordering::SeqCst), 1, "a logoff, once");
}

/// G-7: a taskbar / app theme switch (Settings → Personalization → Colors) broadcasts `WM_SETTINGCHANGE` with
/// "ImmersiveColorSet": the appearance observers run (the app re-applies the tray icon in the new tint).
#[test]
fn a_colour_set_change_calls_the_observer() {
    on_window_thread(|| {
        let p = WinPlatform::new(true);
        let changed = Arc::new(AtomicUsize::new(0));
        let c = changed.clone();
        p.lifecycle().observe_appearance(Box::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }));
        assert_eq!(macvpn_platform_win::lifecycle_setting_change_for_tests(Some("ImmersiveColorSet")), Some(0));
        assert_eq!(changed.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn another_setting_change_does_not() {
    on_window_thread(|| {
        let p = WinPlatform::new(true);
        let changed = Arc::new(AtomicUsize::new(0));
        let c = changed.clone();
        p.lifecycle().observe_appearance(Box::new(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }));
        for area in [Some("Environment"), Some("intl"), Some("ImmersiveColorSetX"), None] {
            assert!(macvpn_platform_win::lifecycle_setting_change_for_tests(area).is_some(), "{area:?}");
        }
        assert_eq!(changed.load(Ordering::SeqCst), 0);
    });
}
