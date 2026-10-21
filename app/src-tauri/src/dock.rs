//! The Dock icon: shown (macOS `Regular` activation policy, so Cmd+Tab and the Dock reach the app) while at least
//! one of the app's real windows is open – Connections, System Status, Update – and hidden again (`Accessory`, a
//! plain menu bar app) once the last one closes.
//!
//! Neither the menu popover nor the MFA prompt windows count. The popover is a menu, only ever hidden. A prompt
//! floats above every other window (it cannot get lost behind one), lives for at most two minutes, and must never
//! take the focus: a Dock icon popping up (and a policy switch) each time a connection asks for a code while the
//! user works in another app is exactly the kind of interruption the prompt avoids.
//!
//! Races: [`sync`] keeps no count of its own. It runs on the main thread (after a real window is built and when
//! one is destroyed) and reads the windows Tauri has at that moment, so the last sync to run always sees the true
//! state, whatever the order of quick opens and closes (Tauri removes a window from its list before the window's
//! `Destroyed` handlers run). Clicking the Dock icon ([`reopen`]) brings the open real windows forward and never
//! creates one.

use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{AppHandle, Manager};

use crate::backup::{BACKUP_WINDOW, RESTORE_WINDOW};
use crate::manage::MANAGE_WINDOW;
use crate::update_window::UPDATE_WINDOW;

/// The window labels that show the Dock icon, in the order [`reopen`] prefers for the focus.
pub const DOCK_WINDOWS: [&str; 5] = [MANAGE_WINDOW, "setup", UPDATE_WINDOW, BACKUP_WINDOW, RESTORE_WINDOW];

/// Whether a window with this label shows the Dock icon.
pub fn counts(label: &str) -> bool {
    DOCK_WINDOWS.contains(&label)
}

/// One of the real windows is shown: visible and not minimized (`(visible, minimized)` per open window).
pub fn any_shown(windows: impl IntoIterator<Item = (bool, bool)>) -> bool {
    windows.into_iter().any(|(visible, minimized)| visible && !minimized)
}

/// The last [`track_shown`] result (read by the poller from its own thread).
static WINDOWS_SHOWN: AtomicBool = AtomicBool::new(false);

/// Whether a real window was shown at the last window event.
pub fn windows_shown() -> bool {
    WINDOWS_SHOWN.load(Ordering::SeqCst)
}

/// Re-reads which real windows are shown. Main thread only (a window event, [`sync`]): the getters then answer
/// directly, without waiting for the main thread.
pub fn track_shown(app: &AppHandle) {
    let shown = any_shown(
        DOCK_WINDOWS
            .iter()
            .filter_map(|label| app.get_webview_window(label))
            .map(|w| (w.is_visible().unwrap_or(false), w.is_minimized().unwrap_or(false))),
    );
    WINDOWS_SHOWN.store(shown, Ordering::SeqCst);
}

/// Whether the Dock icon should show while these windows are open.
pub fn shows_icon<'a>(open: impl IntoIterator<Item = &'a str>) -> bool {
    open.into_iter().any(counts)
}

/// Shows or hides the Dock icon to match the open windows. Safe from any thread (the work runs on the main
/// thread); call it after a real window is built and when one is destroyed.
pub fn sync(app: &AppHandle) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || apply(&handle));
}

fn apply(app: &AppHandle) {
    track_shown(app);
    // The presence last set (the app starts without a Dock icon, see `platform::configure_app`). Main thread only.
    static SHOWN: AtomicBool = AtomicBool::new(false);
    let windows = app.webview_windows();
    let show = shows_icon(windows.keys().map(String::as_str));
    if SHOWN.swap(show, Ordering::Relaxed) == show {
        return;
    }
    crate::platform::set_window_presence(app, show);
}

/// A click on the Dock icon (`RunEvent::Reopen`): the open real windows come forward (minimized ones too), the one
/// that had the focus (or else the first of [`DOCK_WINDOWS`]) gets it. Opens nothing.
pub fn reopen(app: &AppHandle) {
    let windows: Vec<_> = DOCK_WINDOWS.iter().filter_map(|label| app.get_webview_window(label)).collect();
    let Some(first) = windows.first() else { return };
    let target = windows.iter().find(|w| w.is_focused().unwrap_or(false)).unwrap_or(first);
    for window in &windows {
        let _ = window.unminimize();
        let _ = window.show();
    }
    let _ = target.set_focus();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_windows_show_the_icon() {
        assert!(shows_icon(["manage"]));
        assert!(shows_icon(["setup"]));
        assert!(shows_icon(["update"]));
        assert!(shows_icon(["menu", "update", "prompt-3"]));
    }

    #[test]
    fn the_popover_and_prompts_do_not() {
        assert!(!shows_icon([]));
        assert!(!shows_icon(["menu"]));
        assert!(!shows_icon(["prompt-1"]));
        assert!(!shows_icon(["menu", "prompt-1", "prompt-2"]));
        assert!(!counts("Manage"));
        assert!(!counts("manage "));
        assert!(!counts(""));
    }

    /// Only a visible window that is not minimized counts for the poll fallback.
    #[test]
    fn shown_means_visible_and_not_minimized() {
        assert!(!any_shown([]));
        assert!(any_shown([(true, false)]));
        assert!(!any_shown([(true, true)]));
        assert!(!any_shown([(false, false)]));
        assert!(any_shown([(true, true), (false, false), (true, false)]));
    }

    /// The labels are the ones the windows are created with.
    #[test]
    fn labels_match_the_windows() {
        for label in DOCK_WINDOWS {
            let known = crate::commands::window_title(label).is_ok() || crate::backup::window_title(label).is_ok();
            assert!(known, "{label}");
        }
        assert!(!counts(crate::tray::MENU_WINDOW));
        assert!(!counts(&macvpn_app_core::notify::prompt_window_label(7)));
    }

    /// Open and close in any order: the icon follows the windows open at the moment it is decided.
    #[test]
    fn follows_the_open_set() {
        use std::collections::BTreeSet;
        let mut open = BTreeSet::from(["menu"]);
        let mut shown = Vec::new();
        for (label, opened) in [
            ("manage", true),
            ("setup", true),
            ("manage", false),
            ("prompt-1", true),
            ("setup", false),
            ("prompt-1", false),
            ("update", true),
            ("update", false),
        ] {
            if opened {
                open.insert(label);
            } else {
                open.remove(label);
            }
            shown.push(shows_icon(open.iter().copied()));
        }
        assert_eq!(shown, [true, true, true, true, false, false, true, false]);
    }
}
