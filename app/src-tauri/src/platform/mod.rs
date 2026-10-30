//! The app's one door to the operating system (spec 3): it picks the platform crate for the target
//! (`macvpn-platform-mac` on macOS, `macvpn-platform-win` on Windows, `macvpn-platform-linux` on Linux), hands out
//! the one [`Platform`] handle, and holds the Tauri glue that platform-api cannot (it does not depend on Tauri): the
//! native window handle, the activation policy, the macOS-only run events, Linux's own tray icon and its card
//! panel overlay.
//!
//! This module is the only place in the app with `cfg(target_os)`. The smoke driver (`smoke`, debug builds) lives
//! here too; the rest of the app reaches it through the `smoke_*` facades.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as selected;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as selected;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as selected;
#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
compile_error!("no platform layer for this operating system");

mod environment;
#[cfg(debug_assertions)]
pub mod smoke;

pub use environment::Environment;

use macvpn_platform_api::{LoginItems, NativeWindow, Platform};
use tauri::{AppHandle, WebviewWindow};

/// Created once in `main` (`sandbox`: `MACVPN_SANDBOX_HOME`, see [`Environment::sandbox_home`]); a second call
/// returns the first platform.
pub fn init(sandbox: bool) -> &'static dyn Platform {
    selected::init(sandbox)
}

/// The platform `main` created. The unit tests get the sandbox platform (memory stores, never the real Keychain
/// or preferences).
pub fn get() -> &'static dyn Platform {
    #[cfg(test)]
    selected::init(true);
    selected::get().expect("platform::init runs first in main")
}

/// The window's native handle (macOS: the `NSWindow`), for the platform's window calls; main thread only.
pub fn native_window(w: &tauri::WebviewWindow) -> Option<NativeWindow> {
    selected::native_window(w)
}

/// [`native_window`] for a window whose web view is not attached yet (`corners`: a window just created).
pub fn native_window_of(w: &tauri::Window) -> Option<NativeWindow> {
    selected::native_window_of(w)
}

/// At setup: a menu bar app without a Dock icon (macOS: `ActivationPolicy::Accessory`); Windows: this launch's
/// files and the forwarding pipe of later launches.
pub fn configure_app(app: &mut tauri::App) {
    selected::configure_app(app);
}

/// The app's presence while a real window is shown (macOS: the Dock icon, `Regular` / `Accessory`). Main thread
/// only.
pub fn set_window_presence(app: &AppHandle, shown: bool) {
    selected::set_window_presence(app, shown);
}

/// The platform's own run events (macOS: `Reopen`, a Dock click → `dock::reopen`; `Opened`, files from Finder →
/// `open_files::opened`; Windows: none, a second launch arrives through [`configure_app`]'s pipe).
pub fn on_run_event(app: &AppHandle, event: &tauri::RunEvent) {
    selected::on_run_event(app, event);
}

/// Windows: restricts the process' DLL search to System32 (L-5 of the 2.0.0 security review). Linux: the process'
/// GTK program name (the windows' app id) and WebKit's renderer, before any thread. The very first statement of
/// `main`, before any mode. macOS: nothing.
pub fn harden_dll_search() {
    selected::harden_dll_search();
}

/// A helper mode of the app's binary that runs instead of the app (Windows: the elevated step of the OpenVPN
/// install): its exit code, else `None`. Called right after [`harden_dll_search`] in `main`.
pub fn helper_mode() -> Option<i32> {
    selected::helper_mode()
}

/// First thing in `main`: when this process is the updater's relauncher (Windows: a copy of WinVPN.exe started with
/// `--relaunch --target <WinVPN.exe> --msi <msi> --sha256 <hex> --log <msiexec's log>`), does its work (hold the
/// MSI and the log until msiexec has exited, record the outcome, start the new WinVPN; no Tauri, no window, no
/// single-instance claim) and returns `true`. macOS: never.
pub fn relaunch() -> bool {
    selected::relaunch()
}

/// Linux: the installed LinVPN's supervisor (`macvpn_platform_linux::supervise`): `Some(exit code)` when this
/// process supervised the GUI process (`main` exits with it), `None` when this process is the app. Called after the
/// helper modes, before anything starts. macOS and Windows: never.
pub fn supervise() -> Option<i32> {
    selected::supervise()
}

/// Linux: why the supervisor started this GUI process again (`exit code 1`, `signal 9`); `None` for a normal launch.
/// Such a launch opens no window by itself. macOS and Windows: never.
pub fn restart_reason() -> Option<String> {
    selected::restart_reason()
}

/// Debug builds: the updater's install half on a local MSI (Windows, CP2); `Some(exit code)` when this launch was
/// that hook. macOS: never.
#[cfg(debug_assertions)]
pub fn test_install_mode() -> Option<i32> {
    selected::test_install_mode()
}

/// This build can run here (macOS and Windows: yes; an `Err` makes `main` exit 1).
pub fn supported() -> Result<(), String> {
    selected::supported()
}

/// Before Tauri starts: `false` when another instance of this product runs for this user and got this launch's
/// files (`main` then exits 0). macOS: always `true` (LaunchServices keeps one instance).
pub fn claim_instance() -> bool {
    selected::claim_instance()
}

/// Whether the app installs its own menu (macOS: the app menu bar with Quit and Edit; Windows: none, the windows
/// keep their native text shortcuts and Quit is in the popover).
pub fn uses_app_menu() -> bool {
    selected::uses_app_menu()
}

// MARK: - The tray icon and the popover (Linux: the card panel)

/// The tray icon is the platform's own (Linux: a StatusNotifierItem, spike L0-2 variant S), created here with the
/// first icon (RGBA, `width` × `height`) and its tooltip; its clicks reach [`crate::tray`] on the main thread.
/// `true`: done, Tauri's tray icon is not built. macOS, Windows: `false`.
pub fn create_own_tray(app: &AppHandle, rgba: &[u8], width: u32, height: u32, tooltip: &str) -> bool {
    selected::create_own_tray(app, rgba, width, height, tooltip)
}

/// A new icon and tooltip for the platform's own tray; `false`: there is none (Tauri's tray icon is updated
/// instead).
pub fn set_own_tray_icon(rgba: &[u8], width: u32, height: u32, tooltip: &str) -> bool {
    selected::set_own_tray_icon(rgba, width, height, tooltip)
}

/// Once, when the popover window is created (Linux: the overlay's input region, kept on every size allocation).
/// macOS, Windows: nothing.
pub fn prepare_menu_window(window: &WebviewWindow) {
    selected::prepare_menu_window(window);
}

/// Whether the popover is the platform's overlay (Linux on Wayland, spike L0-2 and CP-L0: a transparent window over
/// the whole work area that draws the card at its top-right and takes clicks only there): it is never positioned
/// and never resized to its content; the page reports the card's rectangle instead ([`set_menu_card`]). macOS,
/// Windows: `false`.
pub fn menu_is_overlay() -> bool {
    selected::menu_is_overlay()
}

/// Right before the popover is shown as the overlay: the tray's activation token (focus), the work area
/// (maximized). Main thread. `false`: not shown as an overlay here (macOS, Windows; Linux without its GTK window),
/// the caller places the window itself.
pub fn present_menu_overlay(window: &WebviewWindow, activation_token: Option<&str>) -> bool {
    selected::present_menu_overlay(window, activation_token)
}

/// The card's rectangle in the overlay as the page laid it out (CSS pixels of the window: left, top, width,
/// height): only it takes clicks. Main thread. macOS, Windows: nothing (no overlay).
pub fn set_menu_card(window: &WebviewWindow, card: (f64, f64, f64, f64)) {
    selected::set_menu_card(window, card);
}

/// Where the popover goes when no tray icon position is known (Linux outside the overlay: the work area's top-right
/// corner; `work_area` = (x, y, width, height), physical pixels). macOS, Windows: `None` (their icon gives the
/// place).
pub fn corner_position(work_area: (i32, i32, u32, u32), window: (u32, u32)) -> Option<(i32, i32)> {
    selected::corner_position(work_area, window)
}

/// Whether IKEv2 tunnels report liveness (LinVPN: the IPsec SAs' counters through `linvpn-xfrmd`; macOS' strongSwan
/// and Windows' RAS IKEv2 end a dead connection themselves).
pub fn ikev2_reports_liveness() -> bool {
    selected::ikev2_reports_liveness()
}

/// Whether IKEv2 editors offer **Import Client Certificate…** (G4): macOS' root layer 12 loads the imported key,
/// LinVPN writes it as files for NetworkManager's strongSwan plugin; Windows signs with a computer certificate from
/// its own store.
pub fn imports_client_certificates() -> bool {
    selected::imports_client_certificates()
}

/// LinVPN: the PKCS#12 conversion of that import (strongSwan's NetworkManager plugin reads PEM files only); macOS
/// keeps a PKCS#12 file as it is.
pub fn pkcs12_converter() -> Option<macvpn_app_core::connections::Pkcs12Converter> {
    selected::pkcs12_converter()
}

/// The swanctl folder whose `x509` / `x509ca` certificate files the IKEv2 editor shows (macOS: Homebrew's
/// `etc/swanctl`; LinVPN: its own `$XDG_DATA_HOME/LinVPN/swanctl`; Windows: none, its IKEv2 uses the computer's
/// certificate store).
pub fn swanctl_folder() -> Option<std::path::PathBuf> {
    selected::swanctl_folder()
}

/// The launch-at-login item over the system state (one per use, on the calling thread).
pub fn login_items(env: &Environment) -> Box<dyn LoginItems> {
    get().login_items(&env.home, env.bundle.as_deref(), env.sandbox)
}

/// Opens a validated `https://github.com/…` URL in the default browser (macOS: `/usr/bin/open <url>`; the URL
/// cannot look like an option).
pub fn open_github_url(url: &str) -> Result<(), String> {
    if !macvpn_app_core::app::is_safe_github_url(url) {
        return Err("refused URL".into());
    }
    get().shell().open_url(url).map_err(String::from)
}

// MARK: - The smoke run's facades (debug builds)

#[cfg(debug_assertions)]
pub use facades::*;

#[cfg(debug_assertions)]
mod facades {
    use super::{Environment, smoke};
    use crate::state::AppState;
    use macvpn_app_core::deps::{HelperClient, NativeController};
    use macvpn_app_core::notify::NotificationContent;
    use macvpn_core::update::Release;
    use macvpn_platform_api::{NetworkSnapshot, SetupReport, UpdateOutcome};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tauri::AppHandle;

    /// The smoke run's stand-in for the helper (its connects reach no root helper).
    pub fn smoke_fake_helper(env: &Environment) -> Option<Arc<dyn HelperClient>> {
        smoke::fake_helper(env)
    }

    /// The smoke run's system VPN list, which the driver changes.
    pub fn smoke_fake_native(env: &Environment) -> Option<Arc<dyn NativeController>> {
        smoke::fake_native(env)
    }

    /// The smoke run's System Status report.
    pub fn smoke_setup_report(state: &AppState) -> Option<SetupReport> {
        smoke::setup_report(state)
    }

    /// Seeds the sandbox's old Keychain items for the smoke run's migration (Windows: forces the run's language).
    pub fn smoke_seed_legacy_keychain(env: &Environment) {
        smoke::seed_legacy_keychain(env);
    }

    /// Starts the smoke driver (only with `MACVPN_SMOKE_DIR` in the sandbox).
    pub fn smoke_start(app: &AppHandle, state: &Arc<AppState>) {
        smoke::start(app, state);
    }

    /// The sandbox's update run (`smoke::update_install`); `None`: no sandbox run here.
    pub fn smoke_update_install(
        env: &Environment,
        release: &Release,
        stage: &dyn Fn(String),
        confirm_quit: Box<dyn FnOnce() -> bool + '_>,
    ) -> Option<Result<UpdateOutcome, String>> {
        Some(smoke::update_install(env, release, stage, confirm_quit))
    }

    /// The smoke run's backup file (in place of the save panel).
    pub fn smoke_backup_file(state: &AppState) -> Option<PathBuf> {
        smoke::backup_file(state)
    }

    /// The smoke run's file (in place of an open / save panel).
    pub fn smoke_panel_file(state: &AppState, extension: &str) -> Option<PathBuf> {
        smoke::panel_file(state, extension)
    }

    /// The smoke run's view-model dump.
    pub fn smoke_dump(state: &AppState) {
        smoke::dump(state);
    }

    /// The physical network the smoke run scripts (the sandbox has no probe); `None` outside a smoke run.
    pub fn smoke_network(state: &AppState) -> Option<NetworkSnapshot> {
        smoke::network(state)
    }

    /// A smoke run records the connection notices (the sandbox posts no real notification).
    pub fn smoke_records_notices(state: &AppState) -> bool {
        smoke::records_notices(state)
    }

    /// Records a connection notice in a smoke run (`MacVPN smoke: notice: …`).
    pub fn smoke_notice(state: &AppState, content: &NotificationContent) {
        smoke::notice(state, content);
    }

    /// The smoke run's engines step: the background setup check is not throttled.
    pub fn smoke_recheck_unthrottled() -> bool {
        smoke::recheck_unthrottled()
    }

    /// The created vault's recovery key, for the smoke run's recovery step (never logged).
    pub fn smoke_remember_recovery_key(key: &str) {
        smoke::remember_recovery_key(key);
    }
}
