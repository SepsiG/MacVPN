//! The System Status window's commands (the Swift `SetupView` actions and `AppModel.checkSetup`, `installRoot`,
//! `openBrewInstallInTerminal`, `uninstall`); the texts and the uninstall order are `macvpn_app_core::setup`.
//!
//! The sandbox (`MACVPN_SANDBOX_HOME`) never touches the system: Homebrew's installer script is written but not
//! opened, `brew install` is not run (a short simulated output instead), and the root installer / uninstaller
//! answer as if the administrator prompt had been cancelled.

use macvpn_app_core::quit::QuitOrigin;
use macvpn_app_core::setup::{self, UninstallChoice, UninstallSystem, UserDataStores};
use macvpn_app_core::updates::Notice;
use macvpn_core::l10n;
use macvpn_core::models::VPNKind;
use macvpn_platform_api::{BootstrapTexts, SetupReport};
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};
use tauri::{AppHandle, State, Window};

use crate::state::AppState;

/// The System Status window.
pub const SETUP_WINDOW: &str = "setup";

type Shared<'a> = State<'a, Arc<AppState>>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())
}

/// The system check (the Swift `checkSetup`): Homebrew, the tools, the root layer. Blocking (runs `sudo -n`).
pub fn check(state: &AppState) -> SetupReport {
    #[cfg(debug_assertions)]
    if let Some(report) = crate::platform::smoke_setup_report(state) {
        return store(state, report);
    }
    let report = crate::platform::get().setup().check(state.env.bundled_root_dir().as_deref());
    store(state, report)
}

/// The popover or the Connections window was shown and some kind is unavailable: check again in the background,
/// at most once a minute (an install made outside the app shows up without "Check Again").
pub fn recheck_if_incomplete(state: &Arc<AppState>) {
    if !state.setup_checked.load(Ordering::SeqCst) {
        return;
    }
    let complete = {
        let report = state.setup.read().unwrap_or_else(PoisonError::into_inner);
        // A kind the platform cannot connect at all (WinVPN: Cisco IPsec) is not something a check could change.
        VPNKind::ALL.iter().all(|k| report.is_available(*k) || report.ras_unsupported_reason(*k).is_some())
    };
    if complete {
        return;
    }
    {
        let mut last = state.setup_rechecked.lock().unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|t| t.elapsed() < recheck_interval()) {
            return;
        }
        *last = Some(Instant::now());
    }
    let state = state.clone();
    let _ = std::thread::Builder::new().name("macvpn-setup-recheck".into()).spawn(move || {
        check(&state);
    });
}

/// The shortest time between two checks of [`recheck_if_incomplete`].
const RECHECK_INTERVAL: Duration = Duration::from_secs(60);

/// [`RECHECK_INTERVAL`]; none during the smoke run's engines step (debug builds), which installs an engine "outside
/// the app" and expects the row back at once.
fn recheck_interval() -> Duration {
    #[cfg(debug_assertions)]
    if crate::platform::smoke_recheck_unthrottled() {
        return Duration::ZERO;
    }
    RECHECK_INTERVAL
}

fn store(state: &AppState, report: SetupReport) -> SetupReport {
    *state.setup.write().unwrap_or_else(PoisonError::into_inner) = report.clone();
    state.setup_checked.store(true, Ordering::SeqCst);
    state.publisher.mark();
    report
}

/// "Check Again" (and the window's appearance): the login item state and the system check.
#[tauri::command]
pub async fn setup_check(state: Shared<'_>) -> Result<(), String> {
    let shared = state.inner().clone();
    shared.refresh_login_item();
    blocking(move || {
        check(&shared);
    })
    .await
}

/// "Install…" of Homebrew: the official installer in Terminal, from a script in a fresh private temp directory
/// (it stops if the download fails). A failure comes back as the alert.
#[tauri::command]
pub async fn setup_install_homebrew(window: Window, state: Shared<'_>) -> Result<Option<Notice>, String> {
    crate::guard::only(&window, "setup_install_homebrew", SETUP_WINDOW)?;
    let shared = state.inner().clone();
    blocking(move || {
        let texts = BootstrapTexts {
            start: l10n::tr("Installing Homebrew (with the official installer)…", &[]),
            done: l10n::tr("Done. Go back to MacVPN and click Check Again.", &[]),
            failed: l10n::tr(
                "Could not download the Homebrew installer. Check the internet connection, then try again.",
                &[],
            ),
        };
        let platform = crate::platform::get();
        let parent = if shared.env.sandbox {
            shared.env.staging_parent().ok_or_else(|| "no sandbox temp directory".to_string())
        } else {
            platform.system().temporary_directory().map_err(String::from)
        };
        // Written in a fresh private directory under `parent`; the sandbox writes it but does not open it.
        let result = parent.and_then(|parent| {
            platform.setup().install_package_manager(&texts, &parent, shared.env.sandbox).map_err(String::from)
        });
        result.err().map(|message| Notice { title: l10n::tr("Could not start the Homebrew installer", &[]), message })
    })
    .await
}

/// "Install" of the missing tools: `brew install …` as the user with live output (LinVPN: the clicked kind's
/// NetworkManager plugin through PackageKit); it goes on when the window closes, and the system is checked again at
/// its end.
#[tauri::command]
pub async fn setup_install_tools(window: Window, state: Shared<'_>, engine: Option<String>) -> Result<(), String> {
    crate::guard::only(&window, "setup_install_tools", SETUP_WINDOW)?;
    let mut report = state.setup.read().unwrap_or_else(PoisonError::into_inner).clone();
    // WinVPN's WireGuard row (fix4): only its action goes to the platform.
    if engine.as_deref() == Some("wireguard")
        && let Some(e) = report.engine.as_mut()
    {
        e.openvpn.action = None;
    }
    // LinVPN's NetworkManager rows: only the clicked kind's row keeps its action (its packages go to PackageKit).
    if let Some(nm) = report.nm.as_mut() {
        let kind = engine.as_deref().and_then(VPNKind::from_raw_value).ok_or("no kind")?;
        for (k, row, _) in &mut nm.kinds {
            if *k != kind {
                row.action = None;
            }
        }
        if nm.row(kind).is_none_or(|r| r.action.is_none()) {
            return Err("nothing to install".into());
        }
    } else if !report.engine.as_ref().is_some_and(|e| e.openvpn.action.is_some() || e.wireguard.action.is_some()) {
        // macOS: Homebrew's `brew install`; Windows: the OpenVPN or WireGuard row's action (the engine rows).
        report.package_manager.as_ref().ok_or("no Homebrew")?;
    }
    if !state.brew.lock().unwrap_or_else(PoisonError::into_inner).start() {
        return Err("already running".into());
    }
    state.publisher.mark();
    let shared = state.inner().clone();
    std::thread::Builder::new()
        .name("macvpn-brew".into())
        .spawn(move || {
            let mut output = |text: &str| {
                shared.brew.lock().unwrap_or_else(PoisonError::into_inner).append(text);
                shared.publisher.mark();
            };
            // The sandbox does not run brew (a short simulated output instead).
            let _ = crate::platform::get().setup().install_tools(&report, &mut output);
            shared.brew.lock().unwrap_or_else(PoisonError::into_inner).finish();
            shared.publisher.mark();
            check(&shared);
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// "Authorize": installs or updates the root layer with one administrator prompt (the window showed beforehand
/// that active connections will be disconnected). The error is shown in the window.
#[tauri::command]
pub async fn setup_install_root(window: Window, state: Shared<'_>) -> Result<(), String> {
    crate::guard::only(&window, "setup_install_root", SETUP_WINDOW)?;
    {
        let mut ops = state.setup_ops.lock().unwrap_or_else(PoisonError::into_inner);
        if ops.installing_root || ops.uninstalling {
            return Err("busy".into());
        }
        ops.installing_root = true;
        ops.install_error = None;
    }
    state.publisher.mark();
    let shared = state.inner().clone();
    blocking(move || {
        let result = install_root(&shared);
        {
            let mut ops = shared.setup_ops.lock().unwrap_or_else(PoisonError::into_inner);
            ops.installing_root = false;
            ops.install_error = result.err();
        }
        check(&shared);
    })
    .await
}

fn install_root(state: &AppState) -> Result<(), String> {
    if state.env.sandbox {
        return Err(l10n::tr("Installation cancelled", &[]));
    }
    let dir =
        state.env.bundled_root_dir().ok_or_else(|| l10n::tr("The root scripts were not found in the app", &[]))?;
    let platform = crate::platform::get();
    let user = platform.system().user_name().ok_or("no user name")?;
    platform.setup().install_helper(&dir, &user).map_err(String::from)
}

/// The uninstall's outcome: the final message (its button quits), or the failure alert.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UninstallResult {
    pub done: bool,
    #[serde(flatten)]
    pub notice: Notice,
}

/// Whether the in-app uninstall is refused: only where the app is uninstalled through the system and the platform
/// offers no clean-up of its own (the answer is the system's note). macOS: never (no note); WinVPN: never ("Remove
/// WinVPN from This Account…").
fn uninstall_refusal(system_note: Option<String>, account_cleanup: bool) -> Option<String> {
    system_note.filter(|_| !account_cleanup)
}

/// "Uninstall MacVPN…" (WinVPN: "Remove WinVPN from This Account…") after the confirmation (asked in the window,
/// with "Also delete user data"). WinVPN then opens Settings → Apps → Installed apps for the MSI's uninstall.
#[tauri::command]
pub async fn setup_uninstall(
    window: Window,
    state: Shared<'_>,
    remove_user_data: bool,
) -> Result<UninstallResult, String> {
    crate::guard::only(&window, "setup_uninstall", SETUP_WINDOW)?;
    let platform_setup = crate::platform::get().setup();
    if let Some(note) = uninstall_refusal(platform_setup.system_uninstall_note(), platform_setup.account_cleanup()) {
        return Err(note);
    }
    {
        let mut ops = state.setup_ops.lock().unwrap_or_else(PoisonError::into_inner);
        if ops.installing_root || ops.uninstalling {
            return Err("busy".into());
        }
        ops.uninstalling = true;
    }
    state.publisher.mark();
    let shared = state.inner().clone();
    blocking(move || {
        let system = Uninstaller(&shared);
        let result = setup::uninstall(
            &shared.manager,
            &shared.connections,
            shared.connections.deps().secret_writer.as_ref(),
            &system,
            UserDataStores {
                key_store: shared.vault.lifecycle.key_store().as_ref(),
                legacy_keychain: shared.vault.legacy.keychain.as_ref(),
            },
            UninstallChoice { remove_user_data },
        );
        shared.setup_ops.lock().unwrap_or_else(PoisonError::into_inner).uninstalling = false;
        shared.publisher.mark();
        match result {
            Ok(notice) => {
                shared.uninstalled.store(true, Ordering::SeqCst);
                // WinVPN: the MSI is uninstalled there (nothing on macOS).
                crate::platform::get().setup().open_system_uninstall();
                UninstallResult { done: true, notice }
            }
            Err(notice) => {
                check(&shared);
                UninstallResult { done: false, notice }
            }
        }
    })
    .await
}

/// "Open Installed Apps…" (WinVPN): the system's page for uninstalling apps. No input.
#[tauri::command]
pub async fn setup_open_system_uninstall(window: Window) -> Result<(), String> {
    crate::guard::only(&window, "setup_open_system_uninstall", SETUP_WINDOW)?;
    blocking(|| crate::platform::get().setup().open_system_uninstall()).await
}

/// "Quit MacVPN" of the uninstaller's final message: only the unsaved changes are asked about (the root layer is
/// gone).
#[tauri::command]
pub async fn quit_after_uninstall(app: AppHandle, window: Window, state: Shared<'_>) -> Result<&'static str, String> {
    crate::guard::only(&window, "quit_after_uninstall", SETUP_WINDOW)?;
    if !state.uninstalled.load(Ordering::SeqCst) {
        return Err("not uninstalled".into());
    }
    Ok(crate::commands::request_quit(&app, &state, QuitOrigin::Uninstall))
}

/// The uninstall's system steps over the platform layer.
struct Uninstaller<'a>(&'a AppState);

impl UninstallSystem for Uninstaller<'_> {
    fn uninstall_helper(&self) -> Result<(), String> {
        if self.0.env.sandbox {
            return Err(l10n::tr("Uninstall cancelled", &[]));
        }
        let platform = crate::platform::get();
        let user = platform.system().user_name().ok_or("no user name")?;
        platform.setup().uninstall_helper(&user).map_err(String::from)
    }

    fn stop_polling(&self) {
        self.0.stop_polling();
    }

    fn unregister_login_item(&self) -> Result<(), String> {
        crate::platform::login_items(&self.0.env).unregister_if_registered().map(|_| ()).map_err(String::from)
    }

    /// The per-user LaunchAgent (none in the sandbox).
    fn remove_stale_login_entries(&self) -> Result<(), String> {
        crate::platform::login_items(&self.0.env).remove_stale_entries().map_err(String::from)
    }

    /// macOS: the root layer's script takes the helper's connections down; WinVPN's service stays (the MSI's).
    fn helper_disconnects(&self) -> bool {
        !crate::platform::get().setup().account_cleanup()
    }

    /// The preferences are cleared first: WinVPN keeps them in the data folder (`preferences.json`), and clearing
    /// them writes the (empty) file, which would bring the folder back after its removal.
    fn remove_user_files(&self) {
        let env = &self.0.env;
        let platform = crate::platform::get();
        self.0.prefs.remove_all();
        let _ = macvpn_core::store::remove_user_data(&env.application_support(), platform.product().name);
        if let Some(cache) = platform.updater().cache_directory(&env.home) {
            let _ = std::fs::remove_dir_all(cache);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::uninstall_refusal;

    /// G-9: the command is refused only where the app is uninstalled through the system without a clean-up.
    #[test]
    fn the_uninstall_is_not_refused_when_a_cleanup_is_offered() {
        assert_eq!(uninstall_refusal(None, false), None, "macOS: its own uninstall");
        assert_eq!(uninstall_refusal(Some("Use Settings.".into()), true), None, "WinVPN: the clean-up");
        assert_eq!(uninstall_refusal(Some("Use Settings.".into()), false).as_deref(), Some("Use Settings."));
    }
}
