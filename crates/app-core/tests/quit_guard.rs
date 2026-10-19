//! The quit guard: every quit path asks the same questions in the same order (the Swift `QuitPolicy` +
//! `applicationShouldTerminate` + `confirmQuit`), an update waits for the answer, the system's terminate request
//! joins a question already on screen, and the uninstaller only asks about unsaved changes.

use macvpn_app_core::quit::{AfterInstall, QuitAction, QuitGuard, QuitOrigin, QuitQuestion, QuitStep, UpdateQuit};
use macvpn_app_core::updates::InstallOutcome;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

/// Runs `f` on a thread: `None` if it did not return within 2 s (it waits on a question nobody answers).
fn within<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(2)).ok()
}

fn wait_for_question(guard: &QuitGuard) -> QuitQuestion {
    for _ in 0..200 {
        if let Some(q) = guard.question() {
            return q;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("no question");
}

fn finished(proceed: bool, origin: QuitOrigin) -> QuitAction {
    QuitAction::Finished { proceed, origin }
}

#[test]
fn nothing_to_ask_finishes_at_once() {
    let guard = QuitGuard::new();
    assert_eq!(guard.request(QuitOrigin::Menu, false, false).0, finished(true, QuitOrigin::Menu));
    assert_eq!(guard.question(), None);
    let (action, ticket) = guard.request(QuitOrigin::Update, false, false);
    assert_eq!(action, finished(true, QuitOrigin::Update));
    assert!(guard.wait(ticket));
}

#[test]
fn unsaved_changes_first_then_active_connections() {
    let guard = QuitGuard::new();
    assert_eq!(guard.request(QuitOrigin::Menu, true, true).0, QuitAction::Ask(QuitStep::Unsaved));
    assert_eq!(guard.question(), Some(QuitQuestion { origin: QuitOrigin::Menu, step: QuitStep::Unsaved }));
    assert_eq!(guard.active_answered(true), None, "not the question being asked");
    assert_eq!(guard.unsaved_answered(true, true), Some(QuitAction::Ask(QuitStep::ActiveConnections)));
    assert_eq!(guard.question().unwrap().step, QuitStep::ActiveConnections);
    assert_eq!(guard.active_answered(true), Some(finished(true, QuitOrigin::Menu)));
    assert_eq!(guard.question(), None);
}

#[test]
fn saved_changes_without_active_connections_quit() {
    let guard = QuitGuard::new();
    guard.request(QuitOrigin::Menu, true, false);
    assert_eq!(guard.unsaved_answered(true, false), Some(finished(true, QuitOrigin::Menu)));
}

#[test]
fn cancel_at_either_question_stops_the_quit() {
    let guard = QuitGuard::new();
    guard.request(QuitOrigin::Menu, true, true);
    assert_eq!(guard.unsaved_answered(false, true), Some(finished(false, QuitOrigin::Menu)));
    guard.request(QuitOrigin::Menu, false, true);
    assert_eq!(guard.active_answered(false), Some(finished(false, QuitOrigin::Menu)));
    // A window closing with its question cancels too.
    guard.request(QuitOrigin::Menu, true, false);
    assert_eq!(guard.cancel(QuitStep::Unsaved), Some(finished(false, QuitOrigin::Menu)));
    assert_eq!(guard.cancel(QuitStep::Unsaved), None);
}

#[test]
fn confirmed_quits_without_asking() {
    let guard = QuitGuard::new();
    guard.confirm();
    assert!(guard.is_confirmed());
    assert_eq!(guard.request(QuitOrigin::System, true, true).0, finished(true, QuitOrigin::System));
}

#[test]
fn the_uninstaller_asks_only_about_unsaved_changes() {
    let guard = QuitGuard::new();
    assert_eq!(guard.request(QuitOrigin::Uninstall, false, true).0, finished(true, QuitOrigin::Uninstall));
    assert_eq!(guard.request(QuitOrigin::Uninstall, true, true).0, QuitAction::Ask(QuitStep::Unsaved));
    assert_eq!(guard.unsaved_answered(true, true), Some(finished(true, QuitOrigin::Uninstall)));
}

#[test]
fn a_system_request_joins_the_question_on_screen() {
    let guard = QuitGuard::new();
    guard.request(QuitOrigin::Menu, false, true);
    assert_eq!(guard.request(QuitOrigin::System, false, true).0, QuitAction::Joined(QuitStep::ActiveConnections));
    guard.set_system_waiting();
    assert!(guard.take_system_waiting());
    assert!(!guard.take_system_waiting(), "replied once");
    // An update does not queue behind another quit.
    assert_eq!(guard.request(QuitOrigin::Update, false, true).0, finished(false, QuitOrigin::Update));
}

#[test]
fn an_update_waits_for_the_answer() {
    let guard = Arc::new(QuitGuard::new());
    let (action, ticket) = guard.request(QuitOrigin::Update, true, true);
    assert_eq!(action, QuitAction::Ask(QuitStep::Unsaved));
    let waiter = {
        let guard = guard.clone();
        std::thread::spawn(move || guard.wait(ticket))
    };
    std::thread::sleep(Duration::from_millis(50));
    assert!(!waiter.is_finished());
    guard.unsaved_answered(true, true);
    std::thread::sleep(Duration::from_millis(50));
    assert!(!waiter.is_finished(), "still the active-connections question");
    assert_eq!(guard.question(), Some(QuitQuestion { origin: QuitOrigin::Update, step: QuitStep::ActiveConnections }));
    guard.active_answered(true);
    assert!(waiter.join().unwrap());

    let (_, ticket) = guard.request(QuitOrigin::Update, false, true);
    let waiter = {
        let guard = guard.clone();
        std::thread::spawn(move || guard.wait(ticket))
    };
    guard.active_answered(false);
    assert!(!waiter.join().unwrap());
    assert!(!guard.wait(999), "unknown ticket");
}

#[test]
fn change_hook_fires() {
    let guard = QuitGuard::new();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c = count.clone();
    guard.set_on_change(move || {
        c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
    guard.request(QuitOrigin::Menu, false, true);
    guard.active_answered(true);
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
}

// MARK: - An update's quit questions

#[test]
fn a_failed_download_leaves_a_pending_system_quit_to_its_question() {
    let guard = Arc::new(QuitGuard::new());
    // Logout during the download: the system's request asks about the unsaved change, and waits.
    assert_eq!(guard.request(QuitOrigin::System, true, false).0, QuitAction::Ask(QuitStep::Unsaved));
    guard.set_system_waiting();
    // The download (or the checksum, the signature, the mount, the check of the app) fails before the update's
    // own questions ran: the app does not quit, the system's question stays for the user to answer.
    let update = UpdateQuit::new(guard.clone());
    assert_eq!(update.after_install(InstallOutcome::Failed), AfterInstall::Stay);
    assert!(guard.is_system_waiting());
    assert_eq!(guard.question(), Some(QuitQuestion { origin: QuitOrigin::System, step: QuitStep::Unsaved }));
}

#[test]
fn an_update_does_not_take_over_a_pending_system_quit() {
    let guard = Arc::new(QuitGuard::new());
    guard.request(QuitOrigin::System, false, true);
    guard.set_system_waiting();
    // The download succeeded meanwhile: the update's questions are not asked behind the system's.
    let update = UpdateQuit::new(guard.clone());
    let shown = Mutex::new(Vec::new());
    assert!(!update.confirm(
        false,
        true,
        |s| {
            shown.lock().unwrap().push(s);
            true
        },
        |_| {}
    ));
    assert!(shown.lock().unwrap().is_empty());
    assert_eq!(update.after_install(InstallOutcome::Cancelled), AfterInstall::Stay);
    assert_eq!(guard.question().map(|q| q.origin), Some(QuitOrigin::System), "still the system's question");
}

#[test]
fn a_system_quit_that_joined_the_update_quits_when_the_helper_fails() {
    let guard = Arc::new(QuitGuard::new());
    let update = Arc::new(UpdateQuit::new(guard.clone()));
    let worker = {
        let update = update.clone();
        std::thread::spawn(move || update.confirm(false, true, |_| true, |_| {}))
    };
    wait_for_question(&guard);
    assert_eq!(guard.request(QuitOrigin::System, false, true).0, QuitAction::Joined(QuitStep::ActiveConnections));
    guard.set_system_waiting();
    guard.active_answered(true);
    assert!(worker.join().unwrap());
    // The helper could not be launched: the user still said quit.
    assert_eq!(update.after_install(InstallOutcome::Failed), AfterInstall::Quit);
}

#[test]
fn a_menu_quit_that_joined_the_update_quits_when_the_helper_fails() {
    let guard = Arc::new(QuitGuard::new());
    let update = Arc::new(UpdateQuit::new(guard.clone()));
    let worker = {
        let update = update.clone();
        std::thread::spawn(move || update.confirm(true, false, |_| true, |_| {}))
    };
    wait_for_question(&guard);
    assert_eq!(guard.request(QuitOrigin::Menu, true, false).0, QuitAction::Joined(QuitStep::Unsaved));
    assert_eq!(guard.unsaved_answered(true, false), Some(finished(true, QuitOrigin::Update)));
    assert!(worker.join().unwrap());
    assert!(!guard.is_system_waiting());
    assert_eq!(update.after_install(InstallOutcome::Failed), AfterInstall::Quit);
}

#[test]
fn a_failed_helper_without_a_joined_quit_does_not_quit() {
    let guard = Arc::new(QuitGuard::new());
    let update = UpdateQuit::new(guard.clone());
    assert!(update.confirm(false, false, |_| panic!("nothing to ask"), |_| {}));
    assert_eq!(update.after_install(InstallOutcome::Failed), AfterInstall::Stay);
    assert_eq!(update.after_install(InstallOutcome::HelperLaunched), AfterInstall::Quit);
    // A cancelled update question with a system request joined: the system gets no, nothing quits.
    let guard = Arc::new(QuitGuard::new());
    let update = Arc::new(UpdateQuit::new(guard.clone()));
    let worker = {
        let update = update.clone();
        std::thread::spawn(move || update.confirm(false, true, |_| true, |_| {}))
    };
    wait_for_question(&guard);
    guard.request(QuitOrigin::System, false, true);
    guard.set_system_waiting();
    guard.active_answered(false);
    assert!(!worker.join().unwrap());
    assert_eq!(update.after_install(InstallOutcome::Cancelled), AfterInstall::Stay);
}

#[test]
fn an_update_never_waits_on_a_question_no_window_shows() {
    for (unsaved, step) in [(true, QuitStep::Unsaved), (false, QuitStep::ActiveConnections)] {
        let guard = Arc::new(QuitGuard::new());
        let update = UpdateQuit::new(guard.clone());
        let handled = Arc::new(Mutex::new(None));
        let h = handled.clone();
        let asked = within(move || {
            let shown = Mutex::new(None);
            let proceed = update.confirm(
                unsaved,
                true,
                |s| {
                    *shown.lock().unwrap() = Some(s);
                    false
                },
                |action| *h.lock().unwrap() = Some(action),
            );
            (proceed, shown.into_inner().unwrap())
        });
        assert_eq!(asked, Some((false, Some(step))), "the update thread must not block");
        assert_eq!(guard.question(), None, "no question left behind");
        assert_eq!(*handled.lock().unwrap(), Some(finished(false, QuitOrigin::Update)));
    }
}

#[test]
fn closing_the_update_window_cancels_its_question() {
    let guard = Arc::new(QuitGuard::new());
    let update = Arc::new(UpdateQuit::new(guard.clone()));
    let waiting = {
        let update = update.clone();
        std::thread::spawn(move || update.confirm(false, true, |_| true, |_| {}))
    };
    wait_for_question(&guard);
    assert_eq!(guard.cancel_origin(QuitOrigin::Menu), None, "not that window's question");
    assert_eq!(guard.cancel_origin(QuitOrigin::Update), Some(finished(false, QuitOrigin::Update)));
    assert!(!waiting.join().unwrap());
    assert_eq!(update.after_install(InstallOutcome::Cancelled), AfterInstall::Stay);
    assert_eq!(guard.question(), None);
}
