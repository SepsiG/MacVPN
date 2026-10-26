//! Applies the Appearance setting: `AppHandle::set_theme` sets the native theme of every window (macOS:
//! `NSApp.appearance`, which the popover, alerts and web views follow; Windows: each window's title bar and its
//! WebView2's preferred colour scheme, and the event loop's default for windows created later). The web views'
//! `prefers-color-scheme` follows, so the CSS needs nothing. No OS `cfg` here.

use macvpn_app_core::appearance::Appearance;
use std::sync::Arc;
use tauri::plugin::{Builder, TauriPlugin};
use tauri::{AppHandle, Manager, Theme, Wry};

use crate::state::AppState;

/// The plugin's name (no commands, no permissions: only the window hook).
pub const PLUGIN: &str = "appearance";

/// The native theme of a setting: `None` follows the system.
pub fn theme(a: Appearance) -> Option<Theme> {
    match a {
        Appearance::System => None,
        Appearance::Light => Some(Theme::Light),
        Appearance::Dark => Some(Theme::Dark),
    }
}

/// At launch (before the windows are shown) and after a change.
pub fn apply(app: &AppHandle, a: Appearance) {
    app.set_theme(theme(a));
}

/// Every window created later gets the current theme too (`on_window_ready`, like the `corners` plugin).
pub fn plugin() -> TauriPlugin<Wry> {
    Builder::new(PLUGIN)
        .on_window_ready(|window| {
            if let Some(state) = window.app_handle().try_state::<Arc<AppState>>() {
                let _ = window.set_theme(theme(Appearance::load(state.prefs.as_ref())));
            }
        })
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_follows_the_os_and_the_others_force_a_theme() {
        assert_eq!(theme(Appearance::System), None);
        assert_eq!(theme(Appearance::Light), Some(Theme::Light));
        assert_eq!(theme(Appearance::Dark), Some(Theme::Dark));
    }

    /// Registered once on the app builder, and applied in `setup` before the popover is created.
    #[test]
    fn registered_and_applied_before_the_windows() {
        let main = include_str!("main.rs");
        assert_eq!(main.matches(".plugin(appearance::plugin())").count(), 1);
        let applied = main.find("appearance::apply(").expect("applied at launch");
        let popover = main.find("tray::create_menu_window(").expect("the popover");
        assert!(applied < popover, "the theme is set before the first window is shown");
    }
}
