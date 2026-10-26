//! Every window's corners: once a window exists (the config's popover and every window built in code: Connections,
//! System Status, the vault, backup, prompt, credential and pairing windows), it gets the platform's
//! [`WindowChrome::window_corner_radius`] through [`WindowChrome::round_corners`] (Windows 11: DWM's round corners,
//! Windows 10: square). macOS has none (AppKit rounds its windows; the popover is shaped by `tray::shape_menu`).
//!
//! One hook for all of them: Tauri calls a plugin's `on_window_ready` for every window it creates, so a new
//! window-building path cannot miss it.
//!
//! [`WindowChrome::window_corner_radius`]: macvpn_platform_api::WindowChrome::window_corner_radius
//! [`WindowChrome::round_corners`]: macvpn_platform_api::WindowChrome::round_corners

use tauri::plugin::{Builder, TauriPlugin};
use tauri::{Window, Wry};

use crate::platform;

/// The plugin's name (no commands, no permissions: only the window hook).
pub const PLUGIN: &str = "window-corners";

/// A window just created, as [`round_new_window`] uses it (a fake in the tests).
pub trait NewWindow {
    /// Rounds the window's corners on the main thread (after its pending changes).
    fn round_corners(&self, radius: f64);
}

impl NewWindow for Window<Wry> {
    fn round_corners(&self, radius: f64) {
        let target = self.clone();
        let _ = self.run_on_main_thread(move || {
            if let Some(native) = platform::native_window_of(&target) {
                platform::get().windows().round_corners(native, radius);
            }
        });
    }
}

/// Rounds a new window when the platform rounds every window (`radius`); otherwise leaves it alone.
pub fn round_new_window(window: &impl NewWindow, radius: Option<f64>) {
    if let Some(radius) = radius {
        window.round_corners(radius);
    }
}

/// The hook, registered once on the app's builder (`main`).
pub fn plugin() -> TauriPlugin<Wry> {
    Builder::new(PLUGIN)
        .on_window_ready(|window| round_new_window(&window, platform::get().windows().window_corner_radius()))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct FakeWindow(RefCell<Vec<f64>>);

    impl NewWindow for FakeWindow {
        fn round_corners(&self, radius: f64) {
            self.0.borrow_mut().push(radius);
        }
    }

    #[test]
    fn a_new_window_is_rounded_where_the_platform_rounds_every_window() {
        let window = FakeWindow::default();
        round_new_window(&window, Some(8.0));
        assert_eq!(*window.0.borrow(), [8.0]);
        let window = FakeWindow::default();
        round_new_window(&window, None);
        assert!(window.0.borrow().is_empty(), "macOS: the system's own corners");
    }

    /// Windows 11: every window round (8); macOS: unchanged.
    #[test]
    fn the_platform_decides() {
        let expected = if cfg!(windows) { Some(8.0) } else { None };
        assert_eq!(platform::get().windows().window_corner_radius(), expected);
    }

    /// Every window-building path reaches the hook: the app builder registers the plugin, and every window is
    /// built through Tauri (the config's popover with `WebviewWindowBuilder::from_config`, the others with
    /// `WebviewWindowBuilder::new`), whose window creation calls every plugin's `on_window_ready`.
    #[test]
    fn every_window_building_path_goes_through_the_hook() {
        let main = include_str!("main.rs");
        assert_eq!(main.matches(".plugin(corners::plugin())").count(), 1, "registered once on the app builder");
        let builder = main.find("tauri::Builder::default()").expect("the app builder");
        assert!(main.find(".plugin(corners::plugin())").expect("registered") > builder);
        // The window-building paths: none builds a native window around Tauri.
        let sources: [(&str, &str); 8] = [
            ("tray.rs", include_str!("tray.rs")),
            ("commands.rs", include_str!("commands.rs")),
            ("prompts.rs", include_str!("prompts.rs")),
            ("credentials.rs", include_str!("credentials.rs")),
            ("pairing.rs", include_str!("pairing.rs")),
            ("vault.rs", include_str!("vault.rs")),
            ("backup.rs", include_str!("backup.rs")),
            ("main.rs", main),
        ];
        let mut paths = 0;
        for (name, source) in sources {
            paths += source.matches("WebviewWindowBuilder::new(").count();
            paths += source.matches("WebviewWindowBuilder::from_config(").count();
            for native in ["CreateWindowEx", "tao::", " WindowBuilder::new("] {
                assert!(!source.contains(native), "{name}: a window built outside Tauri ({native})");
            }
        }
        assert_eq!(paths, 7, "a new window-building path: add its file above");
    }
}
