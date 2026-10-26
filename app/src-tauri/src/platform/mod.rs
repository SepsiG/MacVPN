//! The app's one door to the operating system (spec 3): it picks the platform crate for the target
//! (`macvpn-platform-mac` on macOS, `macvpn-platform-win` on Windows; no other OS yet), hands out the one
//! [`Platform`] handle, and holds the Tauri glue that platform-api cannot (it does not depend on Tauri): the
//! native window handle, the activation policy, the macOS-only run events.
//!
//! This module is the only place in the app with `cfg(target_os)`. The smoke driver (`smoke`, debug builds on
//! macOS and Windows) lives here too; the rest of the app reaches it through the `smoke_*` facades.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as selected;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as selected;
#[cfg(not(any(target_os = "macos", windows)))]
compile_error!("no platform layer for this operating system yet (Linux is phase 4)");

mod environment;
#[cfg(debug_assertions)]
pub mod smoke;

pub use environment::Environment;

use macvpn_platform_api::{LoginItems, NativeWindow, Platform};
use tauri::AppHandle;

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

/// Windows: restricts the process' DLL search to System32 (L-5 of the 2.0.0 security review). The very first
/// statement of `main`, before any mode. macOS: nothing.
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
