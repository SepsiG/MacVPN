//! Applies the Language setting (System / English / Magyar; `macvpn_app_core::language`). The choice is the core's
//! language layer, so every text built after the switch is in the new language: the windows re-render from the
//! next view model (its `language`), notifications, native dialogs and the root helper's `--lang` read it when they
//! are made. What was built before the switch is re-labelled here: the open windows' native titles, the macOS app
//! menu's Quit item, the tray (the publisher redraws its tooltip and, on Linux, the SNI menu when the language
//! changes) and the System Status report's texts (checked again). No OS `cfg` here.

use macvpn_app_core::language::LanguageSetting;
use std::sync::{Arc, OnceLock};
use tauri::menu::MenuItem;
use tauri::{AppHandle, Manager, Wry};

use crate::state::AppState;

/// The app menu's Quit item (macOS; `install_menu`), re-labelled on a switch.
static QUIT_ITEM: OnceLock<MenuItem<Wry>> = OnceLock::new();

pub fn remember_quit_item(item: MenuItem<Wry>) {
    let _ = QUIT_ITEM.set(item);
}

/// The Quit item's text now (the smoke run's check; `None` without an app menu).
#[cfg(debug_assertions)]
pub fn quit_item_text() -> Option<String> {
    QUIT_ITEM.get().and_then(|item| item.text().ok())
}

/// The menu's Language setting: stored, applied, then everything already built is re-labelled.
pub fn switch(app: &AppHandle, state: &Arc<AppState>, setting: LanguageSetting) {
    let changed = setting.switch(state.prefs.as_ref(), |_| state.publisher.mark());
    if changed {
        relabel(app, state);
    }
}

/// The texts built before the switch, in the new language.
fn relabel(app: &AppHandle, state: &Arc<AppState>) {
    for (label, window) in app.webview_windows() {
        if let Some(title) = window_title(&label) {
            let _ = window.set_title(&title);
        }
    }
    if let Some(quit) = QUIT_ITEM.get() {
        let _ = quit.set_text(macvpn_core::l10n::tr("Quit MacVPN", &[]));
    }
    // The System Status report holds texts (row details, the engine notes) made by the last check.
    if state.setup_checked.load(std::sync::atomic::Ordering::SeqCst) {
        let state = state.clone();
        let _ = std::thread::Builder::new().name("macvpn-language-recheck".into()).spawn(move || {
            crate::system::check(&state);
        });
    }
}

/// The native title of an open window, in the current language; `None`: not translated (the menu popover, the
/// prompt and credential windows: the connection's name).
pub fn window_title(label: &str) -> Option<String> {
    if let Some(title) = crate::commands::translated_window_title(label) {
        return Some(title);
    }
    if let Some(title) = crate::backup::translated_window_title(label) {
        return Some(title);
    }
    if crate::vault::is_vault_window(label) {
        return Some(crate::vault::title(label));
    }
    if crate::pairing::is_pairing_window(label) {
        return Some(crate::pairing::window_title());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use macvpn_core::l10n::{AppLanguage, with_language};

    #[test]
    fn every_titled_window_is_re_titled_in_the_new_language() {
        for label in
            ["manage", "setup", "update", "backup", "restore", "pair-3"].into_iter().chain(crate::vault::VAULT_WINDOWS)
        {
            let en = with_language(AppLanguage::En, || window_title(label)).expect(label);
            let hu = with_language(AppLanguage::Hu, || window_title(label)).expect(label);
            assert_ne!(en, hu, "{label}");
        }
        for label in ["menu", "prompt-1", "cred-1"] {
            assert_eq!(window_title(label), None, "{label}");
        }
    }

    /// Restored in `main` right after the platform's language hooks and before the instance claim (its message),
    /// the state, the windows and the tray.
    #[test]
    fn restored_at_launch_before_any_text() {
        let main = include_str!("main.rs");
        let hooks = main.find("platform.install_core_hooks();").expect("hooks");
        let restored = main.find("LanguageSetting::restore(").expect("restored");
        let claim = main.find("platform::claim_instance()").expect("claim");
        let popover = main.find("tray::create_menu_window(").expect("popover");
        assert!(hooks < restored && restored < claim && claim < popover);
        assert!(main.contains("language::remember_quit_item("));
    }

    /// The publisher redraws the tray when only the language changed (Linux: the SNI menu's labels).
    #[test]
    fn the_tray_follows_the_language() {
        let state = include_str!("state.rs");
        assert!(state.contains("let shown = (vm.tray, vm.tray.tooltip(), vm.language);"));
    }
}
