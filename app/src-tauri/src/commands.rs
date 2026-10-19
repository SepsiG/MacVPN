//! The web view's whole IPC surface (each command also needs its `allow-<command>` in the capability file).
//! Every argument is validated before use; connection keys must name a listed connection. Commands that reach
//! the system run on the blocking pool (the platform calls are synchronous), never on the main thread.

use macvpn_app_core::ConnectionItem;
use macvpn_app_core::ViewModel;
use macvpn_app_core::app::{ActiveConnectionsAnswer, resolve_active_connections, user_guide_url};
use macvpn_app_core::quit::{QuitAction, QuitOrigin, QuitStep};
use macvpn_app_core::updates::{CheckNowResult, Notice};
use macvpn_core::l10n;
use std::collections::BTreeSet;
use std::sync::Arc;
use tauri::{AppHandle, Manager, State, WebviewUrl, WebviewWindowBuilder};

use crate::state::AppState;
use crate::tray::MENU_WINDOW;

type Shared<'a> = State<'a, Arc<AppState>>;

/// A connection key: a UUID string (managed connections and scutil service IDs alike).
pub fn validate_key(id: &str) -> Result<(), String> {
    let shape = id.len() == 36
        && id.char_indices().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == '-' } else { c.is_ascii_hexdigit() });
    if shape { Ok(()) } else { Err("invalid connection id".into()) }
}

/// A drag in the pinned section: unique source indexes and a destination within the `count` pinned rows.
pub fn validate_move(from: &[usize], to: usize, count: usize) -> Result<BTreeSet<usize>, String> {
    let source: BTreeSet<usize> = from.iter().copied().collect();
    if source.is_empty() || source.len() != from.len() || source.iter().any(|&i| i >= count) || to > count {
        return Err("invalid move".into());
    }
    Ok(source)
}

/// The windows the UI may open.
pub fn window_title(name: &str) -> Result<&'static str, String> {
    match name {
        "manage" => Ok("Connections"),
        "setup" => Ok("System Status"),
        "update" => Ok("Update"),
        _ => Err("unknown window".into()),
    }
}

/// The two update switches of the menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOption {
    AutoCheck,
    DelayUpdates,
}

pub fn parse_update_option(option: &str) -> Result<UpdateOption, String> {
    match option {
        "autoCheck" => Ok(UpdateOption::AutoCheck),
        "delayUpdates" => Ok(UpdateOption::DelayUpdates),
        _ => Err("invalid option".into()),
    }
}

pub fn parse_quit_choice(choice: &str) -> Result<ActiveConnectionsAnswer, String> {
    match choice {
        "disconnectAndQuit" => Ok(ActiveConnectionsAnswer::DisconnectAndQuit),
        "keepRunning" => Ok(ActiveConnectionsAnswer::KeepRunning),
        "cancel" => Ok(ActiveConnectionsAnswer::Cancel),
        _ => Err("invalid choice".into()),
    }
}

/// The popover's content height (points).
pub fn validate_menu_height(height: f64) -> Result<f64, String> {
    if height.is_finite() && (40.0..=900.0).contains(&height) { Ok(height) } else { Err("invalid height".into()) }
}

fn item(state: &AppState, id: &str) -> Result<ConnectionItem, String> {
    validate_key(id)?;
    state.manager.item(id).ok_or_else(|| "unknown connection".to_string())
}

#[tauri::command]
pub async fn get_view_model(state: Shared<'_>) -> Result<ViewModel, String> {
    Ok(state.view_model())
}

/// Connects (`debug`: the Option-click debug mode, managed connections only). The result arrives as state.
#[tauri::command]
pub async fn connect(app: AppHandle, state: Shared<'_>, id: String, debug: bool) -> Result<(), String> {
    let item = item(&state, &id)?;
    if state.manager.state(&id).is_active() {
        return Err("already active".into());
    }
    let shared = state.inner().clone();
    match item {
        ConnectionItem::Managed(c) => {
            if !state.setup.read().map_err(|_| "state")?.is_available(c.kind) {
                return Err("missing tool".into());
            }
            // Option-click debug (the Swift `connect(_:debug:)`): the Connections window opens on the connection's
            // Log tab (through the unsaved-changes check); a native connection's system log is collected meanwhile.
            let collection = if debug {
                state.connections.request_log_tab(&id);
                state.connections.select(Some(id.clone()));
                open(&app, "manage")?;
                c.kind.is_native().then(|| state.native_logs.start(&c.id))
            } else {
                None
            };
            tauri::async_runtime::spawn_blocking(move || {
                shared.manager.connect(&c, debug);
                if let Some((collector, generation)) = collection {
                    let manager = shared.manager.clone();
                    macvpn_app_core::logs::stop_when_settled(
                        &collector,
                        generation,
                        || manager.state(&id),
                        &macvpn_app_core::deps::SystemClock,
                        std::thread::sleep,
                    );
                }
            });
        }
        ConnectionItem::System(s) => {
            tauri::async_runtime::spawn_blocking(move || shared.manager.connect_system(&s));
        }
    }
    Ok(())
}

#[tauri::command]
pub async fn disconnect(state: Shared<'_>, id: String) -> Result<(), String> {
    let item = item(&state, &id)?;
    let shared = state.inner().clone();
    match item {
        ConnectionItem::Managed(c) => tauri::async_runtime::spawn_blocking(move || {
            shared.manager.disconnect(&c);
            shared.native_logs.stop(&c.id);
        }),
        ConnectionItem::System(s) => tauri::async_runtime::spawn_blocking(move || shared.manager.disconnect_system(&s)),
    };
    Ok(())
}

#[tauri::command]
pub async fn pin(state: Shared<'_>, id: String) -> Result<(), String> {
    item(&state, &id)?;
    state.manager.pin(&id);
    Ok(())
}

#[tauri::command]
pub async fn unpin(state: Shared<'_>, id: String) -> Result<(), String> {
    item(&state, &id)?;
    state.manager.unpin(&id);
    Ok(())
}

/// A drag in the pinned section, with the indexes of the pinned rows.
#[tauri::command]
pub async fn move_pinned(state: Shared<'_>, from: Vec<usize>, to: usize) -> Result<(), String> {
    let source = validate_move(&from, to, state.manager.pinned_items().len())?;
    state.manager.move_pinned(&source, to);
    Ok(())
}

#[tauri::command]
pub async fn open_window(app: AppHandle, name: String) -> Result<(), String> {
    open(&app, &name)
}

pub fn open(app: &AppHandle, name: &str) -> Result<(), String> {
    let title = window_title(name)?;
    crate::tray::hide_menu(app);
    let window = match app.get_webview_window(name) {
        Some(window) => window,
        None => {
            let (width, height) = match name {
                "manage" => (900.0, 600.0),
                "setup" => (600.0, 700.0),
                _ => (540.0, 520.0),
            };
            let builder = WebviewWindowBuilder::new(app, name, WebviewUrl::App("index.html".into()))
                .title(l10n::tr(title, &[]))
                .inner_size(width, height)
                .center()
                // Shown below, after the Dock icon.
                .visible(false)
                .on_navigation(crate::navigation::is_allowed);
            // The Connections window as the Swift one: at least 720 × 420 (a list next to a readable detail).
            let builder = match name {
                "manage" => builder.min_inner_size(720.0, 420.0),
                _ => builder.min_inner_size(440.0, 360.0).minimizable(false).maximizable(false),
            };
            builder.build().map_err(|e| e.to_string())?
        }
    };
    // The Dock icon first (queued on the main thread before the show and the focus below), so the app activates
    // as a regular app with its menu bar.
    crate::dock::sync(app);
    let _ = window.show();
    let _ = window.unminimize();
    window.set_focus().map_err(|e| e.to_string())
}

/// Closes one of the app's windows ("Later" / "Close" of the Update window). The Connections window closes through
/// its own close request (the unsaved-changes guard), so it is not closed here.
#[tauri::command]
pub async fn close_window(app: AppHandle, name: String) -> Result<(), String> {
    window_title(&name)?;
    if name == "manage" {
        return Err("not closable here".into());
    }
    if let Some(window) = app.get_webview_window(&name) {
        window.close().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// "Check for Updates Now". The UI opens the Update window when one is available, otherwise shows the notice.
#[tauri::command]
pub async fn check_for_updates(state: Shared<'_>) -> Result<CheckNowResult, String> {
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || shared.updates.check_now()).await.map_err(|e| e.to_string())
}

/// "Check for Updates Automatically" / "Only Offer Updates Published at Least 24 Hours Ago" (persisted).
#[tauri::command]
pub async fn set_update_option(state: Shared<'_>, option: String, on: bool) -> Result<(), String> {
    match parse_update_option(&option)? {
        UpdateOption::AutoCheck => state.updates.set_auto_check(on),
        UpdateOption::DelayUpdates => state.updates.set_delay_updates(on),
    }
    Ok(())
}

/// The "Launch at Login" switch. A failure comes back as the notice to show (the Swift alert).
#[tauri::command]
pub async fn set_launch_at_login(state: Shared<'_>, on: bool) -> Result<Option<Notice>, String> {
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut controller = crate::platform::login_items(&shared.env);
        let result = controller.set_enabled(on);
        *shared.login_item.write().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(crate::platform::login_item_view(controller.state()));
        shared.publisher.mark();
        result.err().map(|e| Notice {
            title: l10n::tr(
                if on { "Could not turn on launch at login" } else { "Could not turn off launch at login" },
                &[],
            ),
            message: e.to_string(),
        })
    })
    .await
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn open_login_items_settings(state: Shared<'_>) -> Result<(), String> {
    let shared = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || crate::platform::login_items(&shared.env).open_system_settings())
        .await
        .map_err(|e| e.to_string())
}

/// Help: the user guide for the current language on GitHub.
#[tauri::command]
pub async fn open_user_guide(app: AppHandle, state: Shared<'_>) -> Result<(), String> {
    let url = user_guide_url(state.env.repo().as_deref(), l10n::AppLanguage::current()).ok_or("refused URL")?;
    crate::tray::hide_menu(&app);
    tauri::async_runtime::spawn_blocking(move || crate::platform::open_github_url(&url))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn set_menu_height(app: AppHandle, height: f64) -> Result<(), String> {
    let height = validate_menu_height(height)?;
    let window = app.get_webview_window(MENU_WINDOW).ok_or("no menu window")?;
    crate::tray::resize_menu(&window, height)
}

/// `choice` absent: the menu's Quit – `ask` when the menu shows the active-connections question, `unsaved` when
/// the Connections window asks first, otherwise the app quits. With the answer to the active-connections
/// question: carried out, then quit (or `cancelled`).
#[tauri::command]
pub async fn quit(app: AppHandle, state: Shared<'_>, choice: Option<String>) -> Result<&'static str, String> {
    let Some(choice) = choice else { return Ok(request_quit(&app, &state, QuitOrigin::Menu)) };
    let answer = parse_quit_choice(&choice)?;
    if state.quit.question().map(|q| q.step) != Some(QuitStep::ActiveConnections) {
        return Err("no question".into());
    }
    let shared = state.inner().clone();
    let (proceed, stopped) = tauri::async_runtime::spawn_blocking(move || {
        // "Disconnect and Quit": the control API detaches first (its clients get `app_quitting`, their leases end
        // without a disconnect of their own), so no lease release races the disconnects. "Quit, Keep Them Running"
        // disconnects nothing: the API stops when the quit really happens (`terminate`).
        let stopped = stops_before_answer(answer) && crate::control::stop_before_disconnect(&shared);
        (resolve_active_connections(&shared.manager, answer), stopped)
    })
    .await
    .map_err(|e| e.to_string())?;
    let reply = match state.quit.active_answered(proceed) {
        Some(action) => Ok(handle_quit(&app, &state, action)),
        None => Err("no question".to_string()),
    };
    // The quit did not happen (yet): the API comes back. An update that goes on stops it again when it quits.
    if stopped && resumes_after(reply.as_deref().ok()) {
        let shared = state.inner().clone();
        tauri::async_runtime::spawn_blocking(move || crate::control::resume_after_quit(&shared));
    }
    reply
}

/// The control API stops before this answer is carried out ("Disconnect and Quit" only: its disconnects must not
/// race the leases' own).
pub fn stops_before_answer(answer: ActiveConnectionsAnswer) -> bool {
    answer == ActiveConnectionsAnswer::DisconnectAndQuit
}

/// After the quit command's `reply` (`None`: an error), a control API stopped before the answer starts again unless
/// the app is terminating.
pub fn resumes_after(reply: Option<&str>) -> bool {
    reply != Some("terminating")
}

/// A quit request from `origin` (the Swift `QuitPolicy` + `applicationShouldTerminate` + `confirmQuit`): the
/// guard asks about unsaved changes (in the Connections window), then about active connections (in the menu, for
/// an update in the Update window), or quits.
pub fn request_quit(app: &AppHandle, state: &AppState, origin: QuitOrigin) -> &'static str {
    let (action, _) = state.quit.request(origin, state.connections.has_unsaved_changes(), state.manager.has_active());
    handle_quit(app, state, action)
}

/// Shows the guard's question in the window that answers it. False: no window could show it (nothing would ever
/// answer it there).
pub fn show_quit_question(app: &AppHandle, state: &AppState, step: QuitStep) -> bool {
    let shown = match step {
        QuitStep::Unsaved => {
            if !state.connections.ask_before_quit() {
                // Saved or discarded in the meantime: nothing to ask, the next question (or the quit) follows.
                if let Some(action) = state.quit.unsaved_answered(true, state.manager.has_active()) {
                    handle_quit(app, state, action);
                }
                return true;
            }
            open(app, "manage").is_ok()
        }
        QuitStep::ActiveConnections => {
            if state.quit.question().is_some_and(|q| q.origin == QuitOrigin::Update) {
                // An update's question is asked in the Update window only (the menu does not show it): the window
                // opens again if it was closed meanwhile.
                open(app, crate::update_window::UPDATE_WINDOW).is_ok()
            } else {
                // The menu shows the question (view model `quit`).
                crate::tray::show_menu(app);
                true
            }
        }
    };
    state.publisher.mark();
    shown
}

/// Carries out what the guard says.
pub fn handle_quit(app: &AppHandle, state: &AppState, action: QuitAction) -> &'static str {
    match action {
        QuitAction::Ask(step) | QuitAction::Joined(step) => {
            // A new question that no window can show is cancelled at once (a joined one is shown already).
            if !show_quit_question(app, state, step)
                && matches!(action, QuitAction::Ask(_))
                && let Some(cancelled) = state.quit.cancel(step)
            {
                return handle_quit(app, state, cancelled);
            }
            match step {
                QuitStep::Unsaved => "unsaved",
                QuitStep::ActiveConnections => "ask",
            }
        }
        QuitAction::Finished { proceed, origin } => {
            // The flow may have ended elsewhere (the Update window closed): the Connections window's quit question
            // goes with it, unless a flow still asks it (this request was only turned away).
            if state.quit.question().is_none_or(|q| q.step != QuitStep::Unsaved) {
                state.connections.quit_question_ended();
            }
            match (proceed, origin) {
                // The update goes on: it launches its helper, then quits.
                (true, QuitOrigin::Update) => "update",
                (true, _) => {
                    terminate(app, state);
                    "terminating"
                }
                (false, _) => {
                    if state.quit.take_system_waiting() {
                        reply_to_system(app, false);
                    }
                    "cancelled"
                }
            }
        }
    }
}

/// Quits now, without asking again. A running control server is stopped first (`StopMode::Detach`, on a worker
/// thread: this may run on the main thread). A system terminate request waiting for the answer gets yes (AppKit
/// then terminates the app); otherwise the event loop is stopped.
pub fn terminate(app: &AppHandle, state: &AppState) {
    // A smoke run leaves the connections for its checks (debug builds, the sandbox only).
    #[cfg(debug_assertions)]
    crate::smoke::dump(state);
    state.quit.confirm();
    state.stop_polling();
    let finish = |app: &AppHandle, state: &AppState| {
        if state.quit.take_system_waiting() {
            reply_to_system(app, true);
        } else {
            app.exit(0);
        }
    };
    state.control.begin_quit();
    if state.control.is_running()
        && let Some(shared) = app.try_state::<Arc<AppState>>()
    {
        let (app, shared) = (app.clone(), shared.inner().clone());
        std::thread::spawn(move || {
            crate::control::stop_for_quit(&shared);
            finish(&app, &shared);
        });
        return;
    }
    finish(app, state);
}

fn reply_to_system(app: &AppHandle, terminate: bool) {
    let _ = app.run_on_main_thread(move || macvpn_platform_mac::app_hooks::reply_to_terminate(terminate));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_must_be_uuid_shaped() {
        assert!(validate_key("38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4").is_ok());
        assert!(validate_key("38b51e6d-5d77-4abe-bfdf-b0e5de45b1c4").is_ok());
        for bad in [
            "",
            "38B51E6D5D774ABEBFDFB0E5DE45B1C4",
            "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C",
            "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4X",
            "38B51E6D_5D77-4ABE-BFDF-B0E5DE45B1C4",
            "../../../../etc/passwd-aaaaaaaaaaaaaaaaa",
            "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1Cé",
        ] {
            assert!(validate_key(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn moves_are_bounded() {
        assert_eq!(validate_move(&[1], 0, 2), Ok(BTreeSet::from([1])));
        assert_eq!(validate_move(&[0, 1], 2, 2), Ok(BTreeSet::from([0, 1])));
        assert!(validate_move(&[], 0, 2).is_err());
        assert!(validate_move(&[2], 0, 2).is_err());
        assert!(validate_move(&[0], 3, 2).is_err());
        assert!(validate_move(&[1, 1], 0, 2).is_err());
        assert!(validate_move(&[usize::MAX], 0, 2).is_err());
    }

    #[test]
    fn only_known_windows() {
        assert_eq!(window_title("manage"), Ok("Connections"));
        assert_eq!(window_title("setup"), Ok("System Status"));
        assert_eq!(window_title("update"), Ok("Update"));
        assert!(window_title("menu").is_err());
        assert!(window_title("https://example.com").is_err());
        for (_, title) in ["manage", "setup", "update"].map(|n| (n, window_title(n).unwrap())) {
            assert!(l10n::hungarian(title).is_some(), "{title}");
        }
    }

    #[test]
    fn quit_choices() {
        assert_eq!(parse_quit_choice("disconnectAndQuit"), Ok(ActiveConnectionsAnswer::DisconnectAndQuit));
        assert_eq!(parse_quit_choice("keepRunning"), Ok(ActiveConnectionsAnswer::KeepRunning));
        assert_eq!(parse_quit_choice("cancel"), Ok(ActiveConnectionsAnswer::Cancel));
        assert!(parse_quit_choice("now").is_err());
    }

    /// Only "Disconnect and Quit" stops the control API before the answer; a quit that then does not terminate
    /// (cancelled, an update going on or staying, an error) starts it again.
    #[test]
    fn the_control_api_survives_a_quit_that_does_not_happen() {
        assert!(stops_before_answer(ActiveConnectionsAnswer::DisconnectAndQuit));
        assert!(!stops_before_answer(ActiveConnectionsAnswer::KeepRunning));
        assert!(!stops_before_answer(ActiveConnectionsAnswer::Cancel));
        assert!(!resumes_after(Some("terminating")));
        for reply in [Some("update"), Some("cancelled"), Some("ask"), Some("unsaved"), None] {
            assert!(resumes_after(reply), "{reply:?}");
        }
    }

    #[test]
    fn update_options() {
        assert_eq!(parse_update_option("autoCheck"), Ok(UpdateOption::AutoCheck));
        assert_eq!(parse_update_option("delayUpdates"), Ok(UpdateOption::DelayUpdates));
        assert!(parse_update_option("lastUpdateCheck").is_err());
        assert!(parse_update_option("").is_err());
    }

    /// Every command is granted exactly where it is used: the prompt, credential and pairing windows only signal and
    /// answer their own prompt / pairing, fit their own height and read the view model; the other windows get everything else; nothing but listening to
    /// events from the core. The build list, the capabilities and `generate_handler!` name the same commands.
    #[test]
    fn capabilities_grant_exactly_the_commands() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let build = std::fs::read_to_string(dir.join("build.rs")).unwrap();
        let list = &build[build.find("const COMMANDS").unwrap()..build.find("];").unwrap()];
        let commands: Vec<String> =
            list.split('"').skip(1).step_by(2).map(|c| format!("allow-{}", c.replace('_', "-"))).collect();
        assert!(commands.len() >= 40, "{commands:?}");
        let read = |name: &str| -> serde_json::Value {
            serde_json::from_str(&std::fs::read_to_string(dir.join("capabilities").join(name)).unwrap()).unwrap()
        };
        let permissions = |v: &serde_json::Value| -> Vec<String> {
            v["permissions"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_string()).collect()
        };
        let (main, prompt, pairing) = (read("main.json"), read("prompt.json"), read("pairing.json"));
        let credentials = read("credentials.json");
        let vault = read("vault.json");
        assert_eq!(vault["windows"], serde_json::json!(crate::vault::VAULT_WINDOWS));
        let vault_permissions = permissions(&vault);
        assert_eq!(
            vault_permissions[..4],
            ["core:event:allow-listen", "core:event:allow-unlisten", "allow-get-view-model", "allow-fit-window"]
        );
        // The vault windows get only vault commands; the menu's vault commands (Lock now, the settings) are main's.
        let vault_only: Vec<String> = vault_permissions[4..].to_vec();
        assert!(vault_only.iter().all(|c| c.starts_with("allow-vault-") && commands.contains(c)), "{vault_only:?}");
        assert_eq!(credentials["windows"], serde_json::json!(["cred-*"]));
        assert_eq!(
            permissions(&credentials),
            [
                "core:event:allow-listen",
                "core:event:allow-unlisten",
                "allow-get-view-model",
                "allow-answer-credentials",
                "allow-credentials-ready",
                "allow-fit-window"
            ]
        );
        assert_eq!(prompt["windows"], serde_json::json!(["prompt-*"]));
        assert_eq!(pairing["windows"], serde_json::json!(["pair-*"]));
        assert_eq!(
            permissions(&pairing),
            [
                "core:event:allow-listen",
                "core:event:allow-unlisten",
                "allow-get-view-model",
                "allow-pairing-answer",
                "allow-pairing-ready",
                "allow-fit-window"
            ]
        );
        assert_eq!(
            permissions(&prompt),
            [
                "core:event:allow-listen",
                "core:event:allow-unlisten",
                "allow-get-view-model",
                "allow-answer-prompt",
                "allow-prompt-ready",
                "allow-fit-window"
            ]
        );
        // The backup and restore windows: the view model, events and the backup commands only; the create-vault
        // window's first-run restore only the restore commands (its other permissions are its own capability's).
        let backup = read("backup.json");
        assert_eq!(backup["windows"], serde_json::json!(["backup", "restore"]));
        let backup_permissions = permissions(&backup);
        assert_eq!(
            backup_permissions,
            [
                "core:event:allow-listen",
                "core:event:allow-unlisten",
                "allow-get-view-model",
                "allow-backup-show-window",
                "allow-backup-close-window",
                "allow-backup-choose-destination",
                "allow-backup-save",
                "allow-restore-choose-file",
                "allow-restore-open",
                "allow-restore-apply",
                "allow-restore-apply-preferences",
                "allow-restore-reinstall-profile",
                "allow-restore-discard"
            ]
        );
        let fresh = read("restore-fresh.json");
        assert_eq!(fresh["windows"], serde_json::json!(["vault-create"]));
        let fresh_permissions = permissions(&fresh);
        assert_eq!(
            fresh_permissions,
            [
                "allow-backup-show-window",
                "allow-restore-choose-file",
                "allow-restore-open",
                "allow-restore-fresh-apply",
                "allow-restore-apply-preferences",
                "allow-restore-reinstall-profile",
                "allow-restore-discard"
            ]
        );
        for permission in backup_permissions.iter().chain(&fresh_permissions) {
            assert!(
                commands.contains(permission) || permission.starts_with("core:event:allow-"),
                "unexpected permission {permission}"
            );
        }
        let main_permissions = permissions(&main);
        for command in &commands {
            let in_main = main_permissions.contains(command);
            let window_only = vault_only.contains(command)
                || [
                    "allow-answer-prompt",
                    "allow-prompt-ready",
                    "allow-pairing-answer",
                    "allow-pairing-ready",
                    "allow-answer-credentials",
                    "allow-credentials-ready",
                    "allow-fit-window",
                    "allow-backup-close-window",
                    "allow-backup-choose-destination",
                    "allow-backup-save",
                    "allow-restore-choose-file",
                    "allow-restore-open",
                    "allow-restore-apply",
                    "allow-restore-fresh-apply",
                    "allow-restore-apply-preferences",
                    "allow-restore-reinstall-profile",
                    "allow-restore-discard",
                ]
                .contains(&command.as_str());
            assert_eq!(in_main, !window_only, "{command}");
        }
        for permission in &main_permissions {
            assert!(
                commands.contains(permission) || permission.starts_with("core:event:allow-"),
                "unexpected permission {permission}"
            );
        }
        let config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("tauri.conf.json")).unwrap()).unwrap();
        assert_eq!(
            config["app"]["security"]["capabilities"],
            serde_json::json!(["main", "prompt", "pairing", "credentials", "vault", "backup", "restore-fresh"])
        );
        // The command list, the generated permissions and the handler agree.
        let main_rs = std::fs::read_to_string(dir.join("src/main.rs")).unwrap();
        let handler = &main_rs[main_rs.find("generate_handler![").unwrap()..];
        let handler = &handler[..handler.find("])").unwrap()];
        let handled: Vec<String> = handler
            .split(|c: char| c == ',' || c == '[' || c.is_whitespace())
            .filter_map(|s| s.rsplit("::").next())
            .filter(|s| !s.is_empty() && *s != "generate_handler!")
            .map(|c| format!("allow-{}", c.replace('_', "-")))
            .collect();
        let mut sorted_handled = handled.clone();
        sorted_handled.sort();
        let mut sorted_commands = commands.clone();
        sorted_commands.sort();
        assert_eq!(sorted_handled, sorted_commands);
        let csp = &config["app"]["security"]["csp"];
        assert_eq!(csp["default-src"], "'self'");
        assert_eq!(csp["script-src"], "'self'");
        assert!(!csp.to_string().contains("unsafe"), "{csp}");
        assert!(config["plugins"].is_null(), "no plugin");
    }

    #[test]
    fn menu_height_bounds() {
        assert_eq!(validate_menu_height(320.0), Ok(320.0));
        assert!(validate_menu_height(f64::NAN).is_err());
        assert!(validate_menu_height(f64::INFINITY).is_err());
        assert!(validate_menu_height(10.0).is_err());
        assert!(validate_menu_height(5000.0).is_err());
    }
}
