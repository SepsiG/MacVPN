//! The app's one door to the operating system (spec 3): it picks the platform crate for the target
//! (`macvpn-platform-mac` on macOS, the `macvpn-platform-win` stub elsewhere), hands out the one
//! [`Platform`] handle, and holds the Tauri glue that platform-api cannot (it does not depend on Tauri): the
//! native window handle, the activation policy, the macOS-only run events.
//!
//! This module is the only place in the app with `cfg(target_os)`. The smoke driver (`smoke`, debug builds on
//! macOS) lives here too; the rest of the app reaches it through the `smoke_*` facades, which do nothing elsewhere.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as selected;
#[cfg(not(target_os = "macos"))]
mod windows;
#[cfg(not(target_os = "macos"))]
use windows as selected;

mod environment;
#[cfg(all(debug_assertions, target_os = "macos"))]
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

/// At setup: a menu bar app without a Dock icon (macOS: `ActivationPolicy::Accessory`).
pub fn configure_app(app: &mut tauri::App) {
    selected::configure_app(app);
}

/// The app's presence while a real window is shown (macOS: the Dock icon, `Regular` / `Accessory`). Main thread
/// only.
pub fn set_window_presence(app: &AppHandle, shown: bool) {
    selected::set_window_presence(app, shown);
}

/// The platform's own run events (macOS: `Reopen`, a Dock click → `dock::reopen`; `Opened`, files from Finder →
/// `open_files::opened`).
pub fn on_run_event(app: &AppHandle, event: &tauri::RunEvent) {
    selected::on_run_event(app, event);
}

/// This build can run here (macOS: yes; Windows in phase 1: `WinVPN is not available yet`, and `main` exits 1).
pub fn supported() -> Result<(), String> {
    selected::supported()
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

// MARK: - The smoke run's facades (debug builds; macOS only, nothing elsewhere)

#[cfg(debug_assertions)]
pub use facades::*;

#[cfg(all(debug_assertions, target_os = "macos"))]
mod facades {
    use super::{Environment, smoke};
    use crate::state::AppState;
    use macvpn_app_core::deps::{HelperClient, NativeController};
    use macvpn_core::update::Release;
    use macvpn_platform_api::{SetupReport, UpdateOutcome};
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

    /// Seeds the sandbox's old Keychain items for the smoke run's migration.
    pub fn smoke_seed_legacy_keychain(env: &Environment) {
        smoke::seed_legacy_keychain(env);
    }

    /// Starts the smoke driver (only with `MACVPN_SMOKE_DIR` in the sandbox).
    pub fn smoke_start(app: &AppHandle, state: &Arc<AppState>) {
        smoke::start(app, state);
    }

    /// The sandbox's update run (the steps of `smoke::SandboxUpdate`); `None`: no sandbox run here.
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

    /// The created vault's recovery key, for the smoke run's recovery step (never logged).
    pub fn smoke_remember_recovery_key(key: &str) {
        smoke::remember_recovery_key(key);
    }
}

#[cfg(all(debug_assertions, not(target_os = "macos")))]
mod facades {
    use super::Environment;
    use crate::state::AppState;
    use macvpn_app_core::deps::{HelperClient, NativeController};
    use macvpn_core::update::Release;
    use macvpn_platform_api::{SetupReport, UpdateOutcome};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tauri::AppHandle;

    pub fn smoke_fake_helper(_: &Environment) -> Option<Arc<dyn HelperClient>> {
        None
    }

    pub fn smoke_fake_native(_: &Environment) -> Option<Arc<dyn NativeController>> {
        None
    }

    pub fn smoke_setup_report(_: &AppState) -> Option<SetupReport> {
        None
    }

    pub fn smoke_seed_legacy_keychain(_: &Environment) {}

    pub fn smoke_start(_: &AppHandle, _: &Arc<AppState>) {}

    pub fn smoke_update_install(
        _: &Environment,
        _: &Release,
        _: &dyn Fn(String),
        _: Box<dyn FnOnce() -> bool + '_>,
    ) -> Option<Result<UpdateOutcome, String>> {
        None
    }

    pub fn smoke_backup_file(_: &AppState) -> Option<PathBuf> {
        None
    }

    pub fn smoke_panel_file(_: &AppState, _: &str) -> Option<PathBuf> {
        None
    }

    pub fn smoke_dump(_: &AppState) {}

    pub fn smoke_remember_recovery_key(_: &str) {}
}
