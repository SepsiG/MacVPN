//! The credential prompt windows (spec `2026-10-19-vault-folders-design.md`, section 4), built exactly like the
//! MFA prompt windows (`prompts.rs`): one small window per open prompt (`cred-<id>`), floating, shown without
//! taking the focus or activating the app; a click on it, or on its "credentials needed" notification, makes it
//! key. The window closes when the prompt ends (answered, cancelled, replaced, expired, disconnected); closing it
//! cancels.
//!
//! `answer_credentials` is the only way to answer: only the window's own prompt; `connect` or `cancel`; the keys
//! only the four field names; refused in the first second after the window was ordered on screen and its page was
//! ready (`credentials_ready`) except Cancel; the values must be exactly the asked fields and pass the value
//! rules (`CredentialBroker::answer_checked`). The typed values move into `Zeroizing` strings at once and go to
//! the connection manager only; they are never logged, never put into the view model or an event.

use macvpn_app_core::credential_prompt::{
    CredentialBroker, CredentialPromptView, RawCredentialAnswer, parse_credential_answer,
};
use macvpn_app_core::notify::{PromptChanges, credential_id_of_label, credential_window_label};
use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError};
use std::time::Instant;
use tauri::{AppHandle, Manager, State, WebviewUrl, WebviewWindowBuilder, Window, WindowEvent};

use crate::state::AppState;

type Shared<'a> = State<'a, Arc<AppState>>;

/// The prompt ID a window may answer: its own, by its label.
fn own_prompt(label: &str, id: u64) -> Result<(), String> {
    if credential_id_of_label(label) == Some(id) { Ok(()) } else { Err("not this window's prompt".into()) }
}

/// The answer of a credential window (only its own prompt): `connect` with the asked fields' values, or `cancel`
/// with none. `save`: store the values once the connection is up.
#[tauri::command]
pub async fn answer_credentials(
    window: Window,
    state: Shared<'_>,
    id: u64,
    action: String,
    values: BTreeMap<String, String>,
    save: bool,
) -> Result<(), String> {
    answer(&state.credential_broker, window.label(), id, &action, values, save, Instant::now())
}

fn answer(
    broker: &CredentialBroker,
    label: &str,
    id: u64,
    action: &str,
    values: BTreeMap<String, String>,
    save: bool,
    now: Instant,
) -> Result<(), String> {
    // The values move into `Zeroizing` strings first, whatever the label check says.
    let parsed = parse_credential_answer(action, values, save);
    own_prompt(label, id)?;
    let answer: RawCredentialAnswer = parsed?;
    broker.answer_checked(id, answer, now)
}

/// The window's page is loaded and shown: the one-second input lock counts from the later of this and the window
/// being ordered on screen.
#[tauri::command]
pub async fn credentials_ready(window: Window, state: Shared<'_>, id: u64) -> Result<(), String> {
    ready(&state.credential_broker, window.label(), id, Instant::now())
}

fn ready(broker: &CredentialBroker, label: &str, id: u64, now: Instant) -> Result<(), String> {
    own_prompt(label, id)?;
    if broker.mark_loaded(id, now) { Ok(()) } else { Err("no such prompt".into()) }
}

/// Opens a window for each new credential prompt and closes the windows of the ended ones (called by the
/// view-model publisher), with the "credentials needed" notifications.
pub fn sync(app: &AppHandle, state: &Arc<AppState>, pending: &[CredentialPromptView]) {
    let PromptChanges { opened, closed } =
        state.credential_tracker.lock().unwrap_or_else(PoisonError::into_inner).update(pending);
    for (id, connection) in closed {
        if let Some(window) = app.get_webview_window(&credential_window_label(id)) {
            let _ = window.destroy();
        }
        crate::notifications::credentials_closed(state, &connection);
    }
    for prompt in opened {
        if let Err(e) = open_window(app, state, &prompt) {
            eprintln!("MacVPN: credential window: {e}");
        }
        crate::notifications::credentials_opened(state, &prompt);
    }
}

/// The window's first height for the fields it shows, before its page measured itself (`fit_window` then sets
/// the content's real height, error and language included).
fn window_height(prompt: &CredentialPromptView) -> f64 {
    let message = if prompt.message.is_some() { 56.0 } else { 0.0 };
    224.0 + 56.0 * prompt.fields.len() as f64 + message
}

fn open_window(app: &AppHandle, state: &AppState, prompt: &CredentialPromptView) -> Result<(), String> {
    let label = credential_window_label(prompt.id);
    let window = WebviewWindowBuilder::new(app, &label, WebviewUrl::App("index.html".into()))
        .title(&prompt.connection_name)
        .inner_size(crate::fit::CREDENTIALS.width, window_height(prompt))
        .resizable(false)
        .minimizable(false)
        .maximizable(false)
        .always_on_top(true)
        .visible(false)
        .focused(false)
        .center()
        .on_navigation(crate::navigation::is_allowed)
        .build()
        .map_err(|e| e.to_string())?;
    // Shown above the other windows without becoming key and without activating the app; the input lock counts
    // from here (and from the page's ready signal, whichever comes later).
    let target = window.clone();
    let broker = state.credential_broker.clone();
    let id = prompt.id;
    window
        .run_on_main_thread(move || {
            if let Ok(ns_window) = target.ns_window() {
                macvpn_platform_mac::app_hooks::order_front_regardless(ns_window);
                broker.mark_shown(id, Instant::now());
            }
        })
        .map_err(|e| e.to_string())
}

/// The connection's open credential prompt comes forward with the focus (a click on its notification).
pub fn focus(app: &AppHandle, state: &AppState, connection_id: &str) {
    let Some(id) = state.credential_broker.prompt_for_connection(connection_id) else { return };
    if let Some(window) = app.get_webview_window(&credential_window_label(id)) {
        let _ = window.set_focus();
    }
}

/// The window's close button cancels its prompt.
pub fn on_window_event(window: &Window, event: &WindowEvent) {
    let Some(id) = credential_id_of_label(window.label()) else { return };
    if let WindowEvent::CloseRequested { .. } = event
        && let Some(state) = window.app_handle().try_state::<Arc<AppState>>()
    {
        let _ = state.credential_broker.answer_checked(id, RawCredentialAnswer::Cancel, Instant::now());
    }
}

/// Whether a window label is a credential window's.
pub fn is_credential_window(label: &str) -> bool {
    credential_id_of_label(label).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_windows_own_prompt() {
        assert_eq!(own_prompt("cred-7", 7), Ok(()));
        for (label, id) in [("cred-7", 8), ("prompt-7", 7), ("pair-7", 7), ("menu", 7), ("cred-", 0), ("cred-07x", 7)] {
            assert!(own_prompt(label, id).is_err(), "{label} {id}");
        }
        assert!(is_credential_window("cred-1"));
        assert!(!is_credential_window("prompt-1"));
    }

    #[test]
    fn heights_grow_with_the_fields() {
        let view = |fields: Vec<&'static str>, message: Option<String>| CredentialPromptView {
            id: 1,
            connection_id: "K".into(),
            connection_name: "Office".into(),
            fields,
            username: None,
            message,
            deadline: 0.0,
        };
        let one = window_height(&view(vec!["password"], None));
        let two = window_height(&view(vec!["username", "password"], None));
        let retry = window_height(&view(vec!["username", "password"], Some("x".into())));
        assert!(one < two && two < retry);
    }

    #[test]
    fn arguments_are_checked_before_the_broker() {
        let state = CredentialBroker::new();
        let values = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
        };
        let now = Instant::now();
        // Another window's prompt, an unknown action or key, values with cancel: refused.
        assert!(answer(&state, "prompt-1", 1, "cancel", values(&[]), false, now).is_err());
        assert!(answer(&state, "cred-1", 2, "cancel", values(&[]), false, now).is_err());
        assert!(answer(&state, "cred-1", 1, "submit", values(&[]), false, now).is_err());
        assert!(answer(&state, "cred-1", 1, "connect", values(&[("code", "1")]), false, now).is_err());
        assert!(answer(&state, "cred-1", 1, "cancel", values(&[("password", "x")]), false, now).is_err());
        // Well-formed, but no such open prompt.
        assert_eq!(answer(&state, "cred-1", 1, "cancel", values(&[]), false, now), Err("no such prompt".to_string()));
        assert!(ready(&state, "pair-1", 1, now).is_err());
        assert_eq!(ready(&state, "cred-1", 1, now), Err("no such prompt".to_string()));
    }
}
