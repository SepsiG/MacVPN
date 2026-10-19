//! The system VPN change watcher (`SCPreferences` commit / apply notifications on its own run loop thread).
//! Registering for the notifications only reads; nothing here changes the system's network setup.

use macvpn_platform_mac::sc_watch::SystemVpnWatcher;
use std::process::Command;
use std::time::{Duration, Instant};

/// The threads of this process (`ps -M` prints a header line, then one line per thread).
fn thread_count() -> usize {
    let out = Command::new("/bin/ps").args(["-M", "-p", &std::process::id().to_string()]).output().expect("ps");
    String::from_utf8_lossy(&out.stdout).lines().count().saturating_sub(1)
}

/// One test function: the thread count must not be disturbed by other tests of this binary running meanwhile.
#[test]
fn start_and_stop_are_quick_and_leak_no_thread() {
    // Warm-up: SystemConfiguration starts its own helper threads on first use (and keeps them).
    SystemVpnWatcher::start(|| {}).expect("watcher starts").stop();
    std::thread::sleep(Duration::from_millis(200));
    let before = thread_count();
    for _ in 0..50 {
        let watcher = SystemVpnWatcher::start(|| {}).expect("watcher starts");
        let started = Instant::now();
        watcher.stop();
        assert!(started.elapsed() < Duration::from_secs(1), "stop took {:?}", started.elapsed());
    }
    // A watcher that is never stopped explicitly stops when dropped.
    for _ in 0..10 {
        let watcher = SystemVpnWatcher::start(|| {}).expect("watcher starts");
        let started = Instant::now();
        drop(watcher);
        assert!(started.elapsed() < Duration::from_secs(1), "drop took {:?}", started.elapsed());
    }
    std::thread::sleep(Duration::from_millis(200));
    let after = thread_count();
    assert!(after <= before, "threads before {before}, after {after}");
}

/// Manual: run with `cargo test -p macvpn-platform-mac --test sc_watch -- --ignored --nocapture`, then add,
/// rename and delete a VPN in System Settings → VPN within two minutes; each change must print a line within
/// about a second (see docs/superpowers/spikes/2026-10-19-live-system-list.md).
#[test]
#[ignore = "manual: needs a VPN change in System Settings"]
fn manual_prints_a_line_per_system_vpn_change() {
    let started = Instant::now();
    let watcher = SystemVpnWatcher::start(move || {
        println!("change after {:.1} s", started.elapsed().as_secs_f64());
    })
    .expect("watcher starts");
    std::thread::sleep(Duration::from_secs(120));
    watcher.stop();
}
