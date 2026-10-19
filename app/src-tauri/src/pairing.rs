//! The pairing windows of the control API (`pair-<id>`), built like the MFA prompt windows (`prompts.rs`): floating,
//! shown without taking the focus or activating the app, no Dock icon (like the prompts: a no-focus-steal question
//! that lives for at most two minutes), the navigation allowlist, and their own capability file
//! (`capabilities/pairing.json`: the view model and these two commands only).
//!
//! The window shows the self-reported name, the full executable path and the connections to allow (none ticked).
//! `pairing_answer` is the only way to answer, and only for the window's own pairing (label check); an approval is
//! refused in the first second after the window was ordered on screen and its page was ready (`pairing_ready`),
//! and must name offered connections only (`PairingBroker::answer`). Closing the window denies; the window's page
//! gives up after two minutes too (the broker and the server each have their own limit).

use macvpn_app_core::pairing::{PairingView, pairing_id_of_label, pairing_window_label};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;
use tauri::{AppHandle, Manager, State, WebviewUrl, WebviewWindowBuilder, Window, WindowEvent};

use crate::state::AppState;

type Shared<'a> = State<'a, Arc<AppState>>;

/// The pairing windows opened so far (their ids), to open new ones once and close ended ones.
#[derive(Default)]
pub struct PairingWindows(Mutex<BTreeSet<u64>>);

/// The window's answer: `None` denies, `Some(keys)` allows those of the offered connections.
#[tauri::command]
pub async fn pairing_answer(
    window: Window,
    state: Shared<'_>,
    id: u64,
    allowed: Option<Vec<String>>,
) -> Result<(), String> {
    if pairing_id_of_label(window.label()) != Some(id) {
        return Err("not this window's pairing".into());
    }
    state.control.pairing.answer(id, allowed, Instant::now())
}

/// The window's page is loaded and shown: the one-second input lock counts from the later of this and the window
/// being ordered on screen.
#[tauri::command]
pub async fn pairing_ready(window: Window, state: Shared<'_>, id: u64) -> Result<(), String> {
    if pairing_id_of_label(window.label()) != Some(id) {
        return Err("not this window's pairing".into());
    }
    if state.control.pairing.mark_loaded(id, Instant::now()) { Ok(()) } else { Err("no such pairing".into()) }
}

/// Opens a window for each new pairing and closes the windows of the ended ones (the view-model publisher).
pub fn sync(app: &AppHandle, state: &Arc<AppState>, pending: &[PairingView]) {
    let (opened, closed) = {
        let mut shown = state.pairing_windows.0.lock().unwrap_or_else(PoisonError::into_inner);
        let ids: BTreeSet<u64> = pending.iter().map(|p| p.id).collect();
        let closed: Vec<u64> = shown.difference(&ids).copied().collect();
        let opened: Vec<&PairingView> = pending.iter().filter(|p| !shown.contains(&p.id)).collect();
        *shown = ids;
        (opened.into_iter().cloned().collect::<Vec<_>>(), closed)
    };
    for id in closed {
        if let Some(window) = app.get_webview_window(&pairing_window_label(id)) {
            let _ = window.destroy();
        }
    }
    for pairing in opened {
        if let Err(e) = open_window(app, state, &pairing) {
            eprintln!("MacVPN: pairing window: {e}");
            // No window can answer it: denied at once rather than after two minutes.
            state.control.pairing.deny(pairing.id);
        }
    }
}

fn open_window(app: &AppHandle, state: &AppState, pairing: &PairingView) -> Result<(), String> {
    let label = pairing_window_label(pairing.id);
    let window = WebviewWindowBuilder::new(app, &label, WebviewUrl::App("index.html".into()))
        .title(macvpn_core::l10n::tr("Allow an App to Control VPNs?", &[]))
        .inner_size(460.0, 470.0)
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
    let broker = state.control.pairing.clone();
    let id = pairing.id;
    window
        .run_on_main_thread(move || {
            if let Ok(ns_window) = target.ns_window() {
                macvpn_platform_mac::app_hooks::order_front_regardless(ns_window);
                broker.mark_shown(id, Instant::now());
            }
        })
        .map_err(|e| e.to_string())
}

/// The window's close button denies its pairing.
pub fn on_window_event(window: &Window, event: &WindowEvent) {
    let Some(id) = pairing_id_of_label(window.label()) else { return };
    if let WindowEvent::CloseRequested { .. } = event
        && let Some(state) = window.app_handle().try_state::<Arc<AppState>>()
    {
        state.control.pairing.deny(id);
    }
}

/// Whether a window label is a pairing window's.
pub fn is_pairing_window(label: &str) -> bool {
    pairing_id_of_label(label).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_windows_are_not_prompts_or_real_windows() {
        assert!(is_pairing_window("pair-1"));
        assert!(!is_pairing_window("prompt-1"));
        assert!(!crate::prompts::is_prompt_window("pair-1"));
        assert!(!crate::dock::counts("pair-1"), "no Dock icon for a pairing window");
        assert!(macvpn_core::l10n::hungarian("Allow an App to Control VPNs?").is_some());
    }
}
