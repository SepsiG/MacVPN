//! The Update window's commands (the Swift `UpdateView` and `UpdateController.install`) and the launch
//! housekeeping's notice. The install runs the platform's `Updater::install` (macOS: `install_update`), which
//! keeps the only allowed order (install location → download + SHA-256 + signature → mount → verify the app → helper
//! script → the quit questions → launch the helper) and cleans up on any failure or a cancelled quit. Once the
//! helper runs, the app quits at once, without asking again.

use macvpn_app_core::quit::{AfterInstall, QuitOrigin, UpdateQuit};
use macvpn_app_core::updates::InstallOutcome;
use macvpn_core::update::Release;
use macvpn_platform_api::UpdateOutcome;
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, State};

use crate::state::AppState;

type Shared<'a> = State<'a, Arc<AppState>>;

pub const UPDATE_WINDOW: &str = "update";

/// "Download and Install". The stages and a failure appear in the view model; on success the app quits.
#[tauri::command]
pub async fn update_install(app: AppHandle, state: Shared<'_>) -> Result<(), String> {
    if state.updates.available().is_none() || state.updates.is_installing() {
        return Err("nothing to install".into());
    }
    let state = state.inner().clone();
    std::thread::Builder::new()
        .name("macvpn-update".into())
        .spawn(move || {
            let quit = UpdateQuit::new(state.quit.clone());
            let outcome = state.updates.install(|release, stage| run(&app, &state, &quit, release, stage));
            // Quit at once when the helper runs (it waits for this process to exit), or when a menu or system quit
            // joined the update's questions, was answered yes, and the helper could not start. A failure before the
            // questions never quits: a pending system quit is decided by its own question.
            match quit.after_install(outcome) {
                AfterInstall::Quit => crate::commands::terminate(&app, &state),
                AfterInstall::Stay => {}
            }
        })
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn run(
    app: &AppHandle,
    state: &Arc<AppState>,
    quit: &UpdateQuit,
    release: &Release,
    stage: &dyn Fn(String),
) -> Result<InstallOutcome, String> {
    // The quit questions, on this worker thread: the Connections window or the Update window (opened again if it
    // was closed) answers them; a question no window can show is cancelled at once, so this never waits forever.
    let confirm_quit = || {
        quit.confirm(
            state.connections.has_unsaved_changes(),
            state.manager.has_active(),
            |step| crate::commands::show_quit_question(app, state, step),
            |action| {
                crate::commands::handle_quit(app, state, action);
            },
        )
    };
    #[cfg(debug_assertions)]
    if state.env.sandbox
        && let Some(result) = crate::platform::smoke_update_install(&state.env, release, stage, Box::new(confirm_quit))
    {
        return outcome(result);
    }
    let bundle = state.env.bundle.clone().ok_or("not running from MacVPN.app")?;
    let updater = crate::platform::get().updater();
    outcome(updater.install(release, &bundle, &state.env.home, stage, Box::new(confirm_quit)))
}

fn outcome(result: Result<UpdateOutcome, String>) -> Result<InstallOutcome, String> {
    match result? {
        UpdateOutcome::HelperLaunched => Ok(InstallOutcome::HelperLaunched),
        // The cancelled question was handled where it was answered (a waiting system quit got no there).
        UpdateOutcome::Cancelled => Ok(InstallOutcome::Cancelled),
    }
}

/// "Open the Release on GitHub" (the page URL the core accepted, opened only if it is a plain github.com URL).
#[tauri::command]
pub async fn update_open_page(state: Shared<'_>) -> Result<(), String> {
    let url = state.updates.release_page().ok_or("no release page")?;
    tauri::async_runtime::spawn_blocking(move || crate::platform::open_github_url(&url))
        .await
        .map_err(|e| e.to_string())?
}

/// OK of "The previous update did not complete".
#[tauri::command]
pub async fn update_dismiss_notice(state: Shared<'_>) -> Result<(), String> {
    state.updates.dismiss_notice();
    Ok(())
}

/// The launch housekeeping (bundle only, the Swift `launchHousekeeping`): the leftovers of an interrupted swap
/// next to the bundle, then the previous update's failure, shown once (2 s after launch) in the Update window.
pub fn launch_housekeeping(app: &AppHandle, state: &AppState) {
    let Some(bundle) = &state.env.bundle else { return };
    let noticed = state.updates.noticed_helper_run();
    let (_, notice) = crate::platform::get().updater().launch_housekeeping(bundle, &state.env.home, noticed.as_deref());
    if state.updates.show_previous_update_notice(notice) {
        let app = app.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(2));
            let _ = crate::commands::open(&app, UPDATE_WINDOW);
        });
    }
}

/// The Update window closed: an update's open quit question (either step) is cancelled with it, so the install
/// stops and cleans up; the Connections window's "Unsaved Changes" of that quit goes too (`handle_quit`).
pub fn window_destroyed(app: &AppHandle, state: &AppState) {
    if let Some(action) = state.quit.cancel_origin(QuitOrigin::Update) {
        crate::commands::handle_quit(app, state, action);
    }
}
