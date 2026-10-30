//! `fit_viewport` against a real GTK window in the desktop session (`scripts/lin-remote.sh desktop`, at a
//! checkpoint): a fixed-size window built the way Tauri (tao) builds the prompt and vault windows – a default size,
//! then `resizable(false)` at its first configure event – shrinks and grows to the content height it is given. GTK
//! sizes a window that is not resizable from its default size: `resize` alone leaves it as built (the vault window
//! stayed 360 px tall around about 174 px of content). The window shows for a moment. (This bare test window cannot go
//! below 200 px: GTK's own minimum for it, so the sizes stay above that.)
#![cfg(target_os = "linux")]

use gtk::glib::object::ObjectType;
use gtk::prelude::{ContainerExt, GtkWindowExt, WidgetExt};
use macvpn_platform_api::{NativeWindow, Platform};
use macvpn_platform_linux::LinPlatform;
use std::time::{Duration, Instant};

/// Runs GTK's main loop until `done` or 5 s passed.
fn pump_until(done: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        while gtk::events_pending() {
            gtk::main_iteration_do(false);
        }
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
#[ignore = "desktop: a small window shows for a moment"]
fn desktop_a_fixed_size_window_fits_its_content() {
    gtk::init().expect("a desktop session");
    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title("LinVPN (test)");
    window.add(&gtk::Box::new(gtk::Orientation::Vertical, 0));
    // tao: the inner size as the default size, `resizable(false)` once the window is configured.
    window.set_default_size(360, 360);
    window.connect_configure_event(|w, _| {
        w.set_resizable(false);
        false
    });
    window.show_all();
    assert!(pump_until(|| !window.is_resizable()), "the window was never configured");
    assert!(pump_until(|| window.size() == (360, 360)), "built at {:?}", window.size());

    let platform = LinPlatform::new(true);
    let native = NativeWindow(window.as_ptr().cast());
    for (width, height) in [(320, 240), (320, 300)] {
        let fitted = platform.windows().fit_viewport(native, f64::from(width), f64::from(height), false);
        assert_eq!(fitted, Some(f64::from(height)));
        let reached = pump_until(|| window.size() == (width, height));
        assert!(reached, "fit to {width}×{height}: the window is {:?}", window.size());
        assert!(!window.is_resizable(), "the window stays fixed-size for the user");
    }
    window.close();
    pump_until(|| !window.is_visible());
}
