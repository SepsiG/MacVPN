#![cfg(target_os = "linux")]
//! Run under `dbus-run-session` (a private session bus). Nothing here suspends or touches the desktop: logind is a
//! fake served on the private bus.

use macvpn_platform_linux::{Claim, claim_instance_for_tests, watch_sleep_for_tests};
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

#[test]
fn a_second_claim_forwards_its_files() {
    let name = format!("local.linvpn.Sandbox.htest{}", std::process::id());
    let Claim::First(guard) = claim_instance_for_tests(&name, &[], false).unwrap() else { panic!("not first") };
    // A second process is simulated by a second connection (the helper opens its own).
    let files = vec![PathBuf::from("/tmp/a.ovpn")];
    assert!(matches!(claim_instance_for_tests(&name, &files, false).unwrap(), Claim::Forwarded));
    let (tx, rx) = mpsc::channel();
    guard.listen(Box::new(move |paths| tx.send(paths).unwrap()));
    assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), files, "queued before listen");
    // After listen: straight to the listener; no files = "show yourself".
    assert!(matches!(claim_instance_for_tests(&name, &[], false).unwrap(), Claim::Forwarded));
    assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), Vec::<PathBuf>::new());
}

#[test]
fn after_update_waits_for_the_old_process_to_let_go() {
    let name = format!("local.linvpn.Sandbox.hwait{}", std::process::id());
    let Claim::First(old) = claim_instance_for_tests(&name, &[], false).unwrap() else { panic!("not first") };
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(700));
        drop(old);
    });
    assert!(matches!(claim_instance_for_tests(&name, &[], true).unwrap(), Claim::First(_)));
    release.join().unwrap();
}

struct FakeLogind;

#[zbus::interface(name = "org.freedesktop.login1.Manager")]
impl FakeLogind {}

#[test]
fn prepare_for_sleep_reaches_the_watcher() {
    let logind = zbus::blocking::Connection::session().unwrap();
    logind.object_server().at("/org/freedesktop/login1", FakeLogind).unwrap();
    logind.request_name("org.freedesktop.login1").unwrap();
    let (tx, rx) = mpsc::channel();
    let _watcher = watch_sleep_for_tests(Box::new(move |sleeping| tx.send(sleeping).unwrap())).unwrap();
    for sleeping in [true, false] {
        logind
            .emit_signal(
                None::<&str>,
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager",
                "PrepareForSleep",
                &(sleeping,),
            )
            .unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), sleeping);
    }
}
