//! The System Status window's commands (the Swift `SetupView` actions and `AppModel.checkSetup`, `installRoot`,
//! `openBrewInstallInTerminal`, `uninstall`); the texts and the uninstall order are `macvpn_app_core::setup`.
//!
//! The sandbox (`MACVPN_SANDBOX_HOME`) never touches the system: Homebrew's installer script is written but not
//! opened, `brew install` is not run (a short simulated output instead), and the root installer / uninstaller
//! answer as if the administrator prompt had been cancelled.

use macvpn_app_core::quit::QuitOrigin;
use macvpn_app_core::setup::{self, UninstallChoice, UninstallSystem};
use macvpn_app_core::updates::Notice;
use macvpn_core::l10n;
use macvpn_platform_mac::brew::{BrewBootstrap, BrewInstaller};
use macvpn_platform_mac::command::ProcessCommandRunner;
use macvpn_platform_mac::login_item::LaunchAgentLoginItem;
use macvpn_platform_mac::root_installer;
use macvpn_platform_mac::setup_checker::{SetupChecker, SetupReport};
use macvpn_platform_mac::update_installer::UpdateInstaller;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use tauri::{AppHandle, State};

use crate::state::AppState;

type Shared<'a> = State<'a, Arc<AppState>>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())
}

/// The system check (the Swift `checkSetup`): Homebrew, the tools, the root layer. Blocking (runs `sudo -n`).
pub fn check(state: &AppState) -> SetupReport {
    #[cfg(debug_assertions)]
    if let Some(report) = crate::smoke::setup_report(state) {
        return store(state, report);
    }
    let runner = ProcessCommandRunner::default();
    let report = SetupChecker::new(&runner, state.env.bundled_root_dir()).check();
    store(state, report)
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
pub async fn setup_install_homebrew(state: Shared<'_>) -> Result<Option<Notice>, String> {
    let shared = state.inner().clone();
    blocking(move || {
        let start = l10n::tr("Installing Homebrew (with the official installer)…", &[]);
        let done = l10n::tr("Done. Go back to MacVPN and click Check Again.", &[]);
        let failed =
            l10n::tr("Could not download the Homebrew installer. Check the internet connection, then try again.", &[]);
        let parent = if shared.env.sandbox {
            shared.env.staging_parent().ok_or_else(|| "no sandbox temp directory".to_string())
        } else {
            macvpn_platform_mac::temp_dir::temporary_directory().map_err(|e| e.0)
        };
        let written = parent.and_then(|parent| {
            BrewBootstrap::write(|dir| BrewBootstrap::script(&start, &done, &failed, dir), &parent).map_err(|e| e.0)
        });
        let result = written.and_then(|script| {
            if shared.env.sandbox {
                eprintln!("MacVPN (sandbox): Homebrew installer written, not opened: {}", script.display());
                return Ok(());
            }
            crate::platform::open_file(&script)
        });
        result.err().map(|message| Notice { title: l10n::tr("Could not start the Homebrew installer", &[]), message })
    })
    .await
}

/// "Install" of the missing tools: `brew install …` as the user with live output; it goes on when the window
/// closes, and the system is checked again at its end.
#[tauri::command]
pub async fn setup_install_tools(state: Shared<'_>) -> Result<(), String> {
    let prefix = state.setup.read().unwrap_or_else(PoisonError::into_inner).brew_prefix.clone().ok_or("no Homebrew")?;
    if !state.brew.lock().unwrap_or_else(PoisonError::into_inner).start() {
        return Err("already running".into());
    }
    state.publisher.mark();
    let shared = state.inner().clone();
    std::thread::Builder::new()
        .name("macvpn-brew".into())
        .spawn(move || {
            let output = |text: &str| {
                shared.brew.lock().unwrap_or_else(PoisonError::into_inner).append(text);
                shared.publisher.mark();
            };
            if shared.env.sandbox {
                output(&BrewInstaller::header());
                output("(sandbox: brew is not run)\n");
                output(&BrewInstaller::footer(0));
            } else {
                let environment: BTreeMap<String, String> = std::env::vars().collect();
                let _ = BrewInstaller::install(&prefix, &environment, output);
            }
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
pub async fn setup_install_root(state: Shared<'_>) -> Result<(), String> {
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
    let user = root_installer::current_user_name().ok_or("no user name")?;
    root_installer::install(&dir, &user).map_err(|e| installer_message(e, "Installation error"))
}

/// The installer's error as the window shows it: its own messages are localized already; a failure to run
/// `osascript` gets the localized prefix.
fn installer_message(error: root_installer::InstallError, prefix: &str) -> String {
    match error {
        root_installer::InstallError::Message(message) => message,
        root_installer::InstallError::Command(e) => format!("{}: {e}", l10n::tr(prefix, &[])),
    }
}

/// The uninstall's outcome: the final message (its button quits), or the failure alert.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UninstallResult {
    pub done: bool,
    #[serde(flatten)]
    pub notice: Notice,
}

/// "Uninstall MacVPN…" after the confirmation (asked in the window, with "Also delete user data").
#[tauri::command]
pub async fn setup_uninstall(state: Shared<'_>, remove_user_data: bool) -> Result<UninstallResult, String> {
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
            UninstallChoice { remove_user_data },
        );
        shared.setup_ops.lock().unwrap_or_else(PoisonError::into_inner).uninstalling = false;
        shared.publisher.mark();
        match result {
            Ok(notice) => {
                shared.uninstalled.store(true, Ordering::SeqCst);
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

/// "Quit MacVPN" of the uninstaller's final message: only the unsaved changes are asked about (the root layer is
/// gone).
#[tauri::command]
pub async fn quit_after_uninstall(app: AppHandle, state: Shared<'_>) -> Result<&'static str, String> {
    if !state.uninstalled.load(Ordering::SeqCst) {
        return Err("not uninstalled".into());
    }
    Ok(crate::commands::request_quit(&app, &state, QuitOrigin::Uninstall))
}

/// The uninstall's system steps over the platform layer.
struct Uninstaller<'a>(&'a AppState);

impl UninstallSystem for Uninstaller<'_> {
    fn uninstall_root(&self) -> Result<(), String> {
        if self.0.env.sandbox {
            return Err(l10n::tr("Uninstall cancelled", &[]));
        }
        let user = root_installer::current_user_name().ok_or("no user name")?;
        root_installer::uninstall(&user).map_err(|e| installer_message(e, "Uninstall error"))
    }

    fn stop_polling(&self) {
        self.0.stop_polling();
    }

    fn unregister_login_item(&self) -> Result<(), String> {
        crate::platform::login_items(&self.0.env).unregister_if_registered().map(|_| ()).map_err(|e| e.to_string())
    }

    fn remove_launch_agent(&self) -> Result<(), String> {
        if self.0.env.sandbox {
            return Ok(());
        }
        LaunchAgentLoginItem::new(&self.0.env.home).remove().map(|_| ()).map_err(|e| e.to_string())
    }

    fn remove_user_files(&self) {
        let env = &self.0.env;
        let _ = macvpn_core::store::remove_application_support_directory(&env.application_support());
        let _ = std::fs::remove_dir_all(UpdateInstaller::default_cache_directory(&env.home));
        self.0.prefs.remove_all();
    }
}
