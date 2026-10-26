//! The MFA prompt windows (the Swift `AuthPromptPresenter`): one small window per open prompt (`prompt-<id>`),
//! floating, shown without taking the focus or activating the app (a keystroke meant for another app never lands
//! in the code field); a click on it, or on its "authentication needed" notification, makes it key. The window
//! closes when the prompt ends (answered, cancelled, replaced, expired, disconnected); closing it cancels.
//!
//! `answer_prompt` is the only way to answer: validated (prompt ID, action, the code at most 256 bytes without
//! control characters), refused in the first second after the window was ordered on screen and its page was ready
//! (`prompt_ready`) except Cancel, and "Open in Browser" opens the
//! broker's own https URL (validated again), never one from the web view.

use macvpn_app_core::notify::{PromptChanges, prompt_id_of_label, prompt_window_label};
use macvpn_app_core::prompt::{PromptView, parse_answer};
use macvpn_core::mfa::{AuthPromptResult, WebAuthURL};
use std::sync::{Arc, PoisonError};
use std::time::Instant;
use tauri::{AppHandle, Manager, State, WebviewUrl, WebviewWindowBuilder, Window, WindowEvent};

use crate::state::AppState;

type Shared<'a> = State<'a, Arc<AppState>>;

/// The answer of a prompt window (only its own prompt): `code` (with `response`), `openUrl` or `cancel`.
#[tauri::command]
pub async fn answer_prompt(
    window: Window,
    state: Shared<'_>,
    id: u64,
    action: String,
    response: Option<String>,
) -> Result<(), String> {
    if prompt_id_of_label(window.label()) != Some(id) {
        return Err("not this window's prompt".into());
    }
    let answer = parse_answer(&action, response.as_deref())?;
    let url = state.broker.answer_checked(id, answer, Instant::now())?;
    if let Some(url) = url {
        let sandbox = state.env.sandbox;
        tauri::async_runtime::spawn_blocking(move || open_web_auth_url(&url, sandbox))
            .await
            .map_err(|e| e.to_string())??;
    }
    Ok(())
}

/// The prompt window's page is loaded and shown: the one-second input lock counts from the later of this and the
/// window being ordered on screen.
#[tauri::command]
pub async fn prompt_ready(window: Window, state: Shared<'_>, id: u64) -> Result<(), String> {
    if prompt_id_of_label(window.label()) != Some(id) {
        return Err("not this window's prompt".into());
    }
    if state.broker.mark_loaded(id, Instant::now()) { Ok(()) } else { Err("no such prompt".into()) }
}

/// The default browser (macOS: `/usr/bin/open <https URL>`), validated again (https only, strict ASCII, so it
/// cannot look like an option). The sandbox only logs it.
fn open_web_auth_url(url: &str, sandbox: bool) -> Result<(), String> {
    if WebAuthURL::validate(url).as_deref() != Some(url) {
        return Err("refused URL".into());
    }
    if sandbox {
        eprintln!("MacVPN (sandbox): web sign-in not opened: {}", WebAuthURL::display_host(url));
        return Ok(());
    }
    crate::platform::get().shell().open_url(url).map_err(String::from)
}

/// Opens a window for each new prompt and closes the windows of the ended ones (called by the view-model
/// publisher), with the "authentication needed" notifications.
pub fn sync(app: &AppHandle, state: &Arc<AppState>, pending: &[PromptView]) {
    let PromptChanges { opened, closed } =
        state.prompt_tracker.lock().unwrap_or_else(PoisonError::into_inner).update(pending);
    for (id, connection) in closed {
        if let Some(window) = app.get_webview_window(&prompt_window_label(id)) {
            let _ = window.destroy();
        }
        crate::notifications::prompt_closed(state, &connection);
    }
    for prompt in opened {
        if let Err(e) = open_window(app, state, &prompt) {
            eprintln!("MacVPN: prompt window: {e}");
        }
        crate::notifications::prompt_opened(state, &prompt);
    }
}

fn open_window(app: &AppHandle, state: &AppState, prompt: &PromptView) -> Result<(), String> {
    let label = prompt_window_label(prompt.id);
    let height = if prompt.kind == "webAuth" { 330.0 } else { 300.0 };
    let window = WebviewWindowBuilder::new(app, &label, WebviewUrl::App("index.html".into()))
        .title(&prompt.connection_name)
        .inner_size(crate::fit::MFA.width, height)
        .resizable(false)
        .minimizable(false)
        .maximizable(false)
        .always_on_top(true)
        .visible(false)
        .focused(false)
        .center()
        .use_https_scheme(crate::navigation::uses_https_scheme())
        .on_navigation(crate::navigation::is_allowed)
        .build()
        .map_err(|e| e.to_string())?;
    // Shown above the other windows without becoming key and without activating the app; the input lock counts
    // from here (and from the page's ready signal, whichever comes later).
    let target = window.clone();
    let broker = state.broker.clone();
    let id = prompt.id;
    window
        .run_on_main_thread(move || {
            if let Some(native) = crate::platform::native_window(&target) {
                crate::platform::get().windows().order_front_regardless(native);
                broker.mark_shown(id, Instant::now());
            }
        })
        .map_err(|e| e.to_string())
}

/// The connection's open prompt comes forward with the focus (a click on its notification).
pub fn focus(app: &AppHandle, state: &AppState, connection_id: &str) {
    let Some(id) = state.broker.prompt_for_connection(connection_id) else { return };
    if let Some(window) = app.get_webview_window(&prompt_window_label(id)) {
        let _ = window.set_focus();
    }
}

/// The window's close button cancels its prompt.
pub fn on_window_event(window: &Window, event: &WindowEvent) {
    let Some(id) = prompt_id_of_label(window.label()) else { return };
    if let WindowEvent::CloseRequested { .. } = event
        && let Some(state) = window.app_handle().try_state::<Arc<AppState>>()
    {
        state.broker.answer(id, AuthPromptResult::Cancelled);
    }
}

/// Whether a window label is a prompt window's.
pub fn is_prompt_window(label: &str) -> bool {
    prompt_id_of_label(label).is_some()
}
