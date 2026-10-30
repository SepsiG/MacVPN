//! macOS: `MacPlatform` (`macvpn-platform-mac`) and the Tauri glue (the `NSWindow`, the activation policy, the
//! `Reopen` / `Opened` run events).

use macvpn_platform_api::{NativeWindow, Platform};
use macvpn_platform_mac::api::MacPlatform;
use std::sync::OnceLock;
use tauri::AppHandle;

static PLATFORM: OnceLock<MacPlatform> = OnceLock::new();

pub fn init(sandbox: bool) -> &'static dyn Platform {
    PLATFORM.get_or_init(|| MacPlatform::new(sandbox))
}

pub fn get() -> Option<&'static dyn Platform> {
    PLATFORM.get().map(|p| p as &'static dyn Platform)
}

/// The `MacPlatform` itself (the smoke run's hooks; debug builds).
#[cfg(debug_assertions)]
pub fn mac() -> &'static MacPlatform {
    #[cfg(test)]
    init(true);
    PLATFORM.get().expect("platform::init runs first in main")
}

pub fn native_window(w: &tauri::WebviewWindow) -> Option<NativeWindow> {
    w.ns_window().ok().map(NativeWindow)
}

pub fn native_window_of(w: &tauri::Window) -> Option<NativeWindow> {
    w.ns_window().ok().map(NativeWindow)
}

pub fn configure_app(app: &mut tauri::App) {
    app.set_activation_policy(tauri::ActivationPolicy::Accessory);
}

pub fn set_window_presence(app: &AppHandle, shown: bool) {
    let policy = if shown { tauri::ActivationPolicy::Regular } else { tauri::ActivationPolicy::Accessory };
    if let Err(e) = app.set_activation_policy(policy) {
        eprintln!("MacVPN: activation policy: {e}");
    }
}

pub fn on_run_event(app: &AppHandle, event: &tauri::RunEvent) {
    match event {
        // A click on the Dock icon (shown while a window is open): that window comes forward; nothing opens.
        tauri::RunEvent::Reopen { .. } => crate::dock::reopen(app),
        // Files opened from Finder (double click, "Open With", a drop on the app icon), at launch too: the import or
        // the team catalog's add dialog, after the unlock if the vault is locked. Paths only; nothing connects.
        tauri::RunEvent::Opened { urls } => crate::open_files::opened(app, urls),
        _ => {}
    }
}

/// macOS has no DLL search to restrict.
pub fn harden_dll_search() {}

pub fn helper_mode() -> Option<i32> {
    None
}

/// The DMG update's helper is a script, never the app itself.
pub fn relaunch() -> bool {
    false
}

/// No supervisor: launchd and LaunchServices own the app's life.
pub fn supervise() -> Option<i32> {
    None
}

pub fn restart_reason() -> Option<String> {
    None
}

#[cfg(debug_assertions)]
pub fn test_install_mode() -> Option<i32> {
    None
}

pub fn supported() -> Result<(), String> {
    Ok(())
}

pub fn claim_instance() -> bool {
    true
}

pub fn uses_app_menu() -> bool {
    true
}

/// Tauri's tray icon (no own one).
pub fn create_own_tray(_app: &AppHandle, _rgba: &[u8], _width: u32, _height: u32, _tooltip: &str) -> bool {
    false
}

pub fn set_own_tray_icon(_rgba: &[u8], _width: u32, _height: u32, _tooltip: &str) -> bool {
    false
}

/// The popover is a plain window at its tray icon (no overlay).
pub fn prepare_menu_window(_window: &tauri::WebviewWindow) {}

pub fn menu_is_overlay() -> bool {
    false
}

pub fn present_menu_overlay(_window: &tauri::WebviewWindow, _activation_token: Option<&str>) -> bool {
    false
}

pub fn set_menu_card(_window: &tauri::WebviewWindow, _card: (f64, f64, f64, f64)) {}

/// The tray icon's rectangle gives the place.
pub fn corner_position(_work_area: (i32, i32, u32, u32), _window: (u32, u32)) -> Option<(i32, i32)> {
    None
}

/// None: a PKCS#12 file is kept as it is (swanctl opens it with the key password).
pub fn pkcs12_converter() -> Option<macvpn_app_core::connections::Pkcs12Converter> {
    None
}

pub fn ikev2_reports_liveness() -> bool {
    false
}

pub fn imports_client_certificates() -> bool {
    true
}

/// Homebrew's `etc/swanctl` (the folder the helper stages the IKEv2 certificates from).
pub fn swanctl_folder() -> Option<std::path::PathBuf> {
    macvpn_platform_mac::setup_checker::SetupChecker::installed_brew_prefix()
        .map(|prefix| std::path::Path::new(&prefix).join("etc/swanctl"))
}
