//! `SniTray` in the real desktop session (`scripts/lin-remote.sh desktop`, at a checkpoint): the shell's
//! StatusNotifierWatcher (GNOME's AppIndicator extension) lists the item, the icon shows in the top bar while the
//! test runs, and it goes away when the tray shuts down. While the screen is locked GNOME disables the extension (no
//! watcher): the item still spawns and the test says so. `LINVPN_TRAY_WAIT=<seconds>` keeps the icon up that long and
//! prints every event, so a double click, a middle click or the menu can be tried by hand (or by Mutter's
//! RemoteDesktop input, as spike L0-2 did).
#![cfg(target_os = "linux")]

use macvpn_core::TargetOs;
use macvpn_core::l10n::TextPlatform;
use macvpn_platform_linux::SniTray;
use std::time::{Duration, Instant};

/// The watcher's list, `None` without a watcher (screen locked, or no SNI host).
fn registered(bus: &zbus::blocking::Connection) -> Option<Vec<String>> {
    let watcher = zbus::blocking::proxy::Builder::<zbus::blocking::Proxy<'_>>::new(bus)
        .destination("org.kde.StatusNotifierWatcher")
        .unwrap()
        .path("/StatusNotifierWatcher")
        .unwrap()
        .interface("org.kde.StatusNotifierWatcher")
        .unwrap()
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .unwrap();
    watcher.get_property("RegisteredStatusNotifierItems").ok()
}

#[test]
#[ignore = "desktop: the icon shows in the top bar for a moment"]
fn desktop_the_shell_lists_the_item() {
    macvpn_core::l10n::set_text_platform(TextPlatform { os: TargetOs::Linux, product: "LinVPN" });
    let bus = zbus::blocking::Connection::session().unwrap();
    let before = registered(&bus);
    let start = Instant::now();
    let rgba = [70u8, 130, 230, 255].repeat(22 * 22);
    let tray = SniTray::spawn(&rgba, 22, 22, "LinVPN (test)", move |event| {
        println!("[{:>6} ms] {event:?}", start.elapsed().as_millis());
    })
    .expect("the item registers");

    let Some(before) = before else {
        println!("no StatusNotifierWatcher (screen locked?): the item spawned and waits for one");
        tray.shutdown();
        return;
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    let pid = format!("StatusNotifierItem-{}-", std::process::id());
    let ours = loop {
        let now = registered(&bus).unwrap_or_default();
        if let Some(n) = now.into_iter().find(|n| !before.contains(n) && n.contains(&pid)) {
            break n;
        }
        assert!(Instant::now() < deadline, "the shell's watcher lists the item");
        std::thread::sleep(Duration::from_millis(50));
    };
    println!("[{:>6} ms] the watcher lists {ours}", start.elapsed().as_millis());

    let wait = std::env::var("LINVPN_TRAY_WAIT").ok().and_then(|s| s.parse().ok()).unwrap_or(1);
    std::thread::sleep(Duration::from_secs(wait));
    tray.shutdown();

    let deadline = Instant::now() + Duration::from_secs(5);
    while registered(&bus).unwrap_or_default().contains(&ours) {
        assert!(Instant::now() < deadline, "the item leaves the watcher's list when it shuts down");
        std::thread::sleep(Duration::from_millis(50));
    }
    println!("[{:>6} ms] gone from the watcher", start.elapsed().as_millis());
}
