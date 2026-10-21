//! Every other target (Windows in phase 1): the `WinPlatform` stub (`macvpn-platform-win`), and the Tauri glue as
//! no-ops. `main` exits at [`supported`] before any window opens.

use macvpn_platform_api::{NativeWindow, Platform};
use macvpn_platform_win::WinPlatform;
use tauri::AppHandle;

static PLATFORM: WinPlatform = WinPlatform;

pub fn init(_sandbox: bool) -> &'static dyn Platform {
    &PLATFORM
}

pub fn get() -> Option<&'static dyn Platform> {
    Some(&PLATFORM)
}

/// The window's `HWND`.
pub fn native_window(w: &tauri::WebviewWindow) -> Option<NativeWindow> {
    w.hwnd().ok().map(|hwnd| NativeWindow(hwnd.0))
}

pub fn configure_app(_app: &mut tauri::App) {}

pub fn set_window_presence(_app: &AppHandle, _shown: bool) {}

/// Windows has no `Reopen` / `Opened` run events. Phase 2 calls the same shared handlers from WinVPN's own events (a
/// taskbar click, the files of a second instance); naming them here keeps them compiled and linted on Windows.
pub fn on_run_event(_app: &AppHandle, _event: &tauri::RunEvent) {
    let _reopen: fn(&AppHandle) = crate::dock::reopen;
    let _opened: fn(&AppHandle, &[tauri::Url]) = crate::open_files::opened;
}

pub fn supported() -> Result<(), String> {
    Err("WinVPN is not available yet".into())
}
