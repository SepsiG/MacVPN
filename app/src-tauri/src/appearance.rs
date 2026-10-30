//! Applies the Appearance setting: `AppHandle::set_theme` sets the native theme of every window (macOS:
//! `NSApp.appearance`, which the popover, alerts and web views follow; Windows: each window's title bar and its
//! WebView2's preferred colour scheme, and the event loop's default for windows created later; Linux: GTK's
//! dark-theme preference, which WebKitGTK's `prefers-color-scheme` follows). The web views' `prefers-color-scheme`
//! follows, so the CSS needs nothing. GTK 3 does not follow the system's light/dark choice by itself: there
//! `System` is the choice the platform reads (`WindowChrome::system_dark`, the desktop portal) and
//! [`system_changed`] applies it again when it changes. No OS `cfg` here.

use macvpn_app_core::appearance::Appearance;
use std::sync::Arc;
use tauri::plugin::{Builder, TauriPlugin};
use tauri::{AppHandle, Manager, Theme, Wry};

use crate::state::AppState;

/// The plugin's name (no commands, no permissions: only the window hook).
pub const PLUGIN: &str = "appearance";

/// The native theme of a setting. `System` follows the system: `None` lets the toolkit do it (macOS, Windows); where
/// the toolkit does not follow it (Linux: `WindowChrome::system_dark`), the system's current choice.
pub fn theme(a: Appearance) -> Option<Theme> {
    theme_with(a, crate::platform::get().windows().system_dark())
}

/// [`theme`] with the system's choice as the platform reports it (`None`: the toolkit follows the system itself).
pub fn theme_with(a: Appearance, system_dark: Option<bool>) -> Option<Theme> {
    match a {
        Appearance::System => system_dark.map(|dark| if dark { Theme::Dark } else { Theme::Light }),
        Appearance::Light => Some(Theme::Light),
        Appearance::Dark => Some(Theme::Dark),
    }
}

/// The system's light/dark choice changed: applied again while the setting is `System` and the platform reports the
/// choice itself (Linux). Nothing on macOS and Windows (their toolkit follows the system).
pub fn system_changed(app: &AppHandle) {
    if crate::platform::get().windows().system_dark().is_none() {
        return;
    }
    if let Some(state) = app.try_state::<Arc<AppState>>()
        && Appearance::load(state.prefs.as_ref()) == Appearance::System
    {
        apply(app, Appearance::System);
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
        assert_eq!(theme_with(Appearance::System, None), None);
        assert_eq!(theme_with(Appearance::System, Some(true)), Some(Theme::Dark));
        assert_eq!(theme_with(Appearance::System, Some(false)), Some(Theme::Light));
        for system in [None, Some(true), Some(false)] {
            assert_eq!(theme_with(Appearance::Light, system), Some(Theme::Light));
            assert_eq!(theme_with(Appearance::Dark, system), Some(Theme::Dark));
        }
    }

    /// The system's choice changes are applied before the tray icon is redrawn.
    #[test]
    fn a_system_change_is_applied_where_the_appearance_is_observed() {
        let main = include_str!("main.rs");
        let observed = main.find("lifecycle.observe_appearance(").expect("observed");
        let changed = main.find("appearance::system_changed(").expect("applied");
        let redraw = main.find("tray::redraw_icon(").expect("redrawn");
        assert!(observed < changed && changed < redraw);
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
