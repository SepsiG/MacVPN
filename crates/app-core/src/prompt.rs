//! The MFA prompt broker (the non-UI half of the Swift `AuthPromptPresenter`): the connection manager's blocking
//! prompt handler parks here until the UI answers, the prompt is dismissed, or its deadline passes. At most one
//! open prompt per connection: a new one cancels the previous. The code only lives in the returned result.
//!
//! The UI's answers are checked here ([`PromptBroker::answer_checked`]): the prompt must be open and of the
//! answer's kind, the code at most 256 bytes without control characters, and no answer but Cancel is taken in
//! the prompt's first second ([`ARM_DELAY`], against a keystroke meant for another app), counted from when its
//! window became visible – the later of the window being ordered on screen ([`PromptBroker::mark_shown`]) and its
//! page's ready signal ([`PromptBroker::mark_loaded`]) – not from when the prompt was opened: a slow window never
//! takes an answer earlier than a second after it appeared. The web sign-in URL to
//! open is the broker's own validated copy, never one sent by the web view.

use macvpn_core::mfa::{self, AuthPrompt, AuthPromptKind, AuthPromptResult, WebAuthURL};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// An open prompt as the UI shows it (no secret in it).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptView {
    /// Answer with this ID ([`PromptBroker::answer`]).
    pub id: u64,
    pub connection_id: String,
    pub connection_name: String,
    /// `code` or `webAuth`.
    pub kind: &'static str,
    pub text: Option<String>,
    pub echo: bool,
    pub from_server: bool,
    pub url: Option<String>,
    /// The web sign-in URL's host, ASCII and lower-case (a punycode name is not decoded).
    pub host: Option<String>,
    /// Unix time (seconds) when the prompt expires.
    pub deadline: f64,
}

/// No answer but Cancel is accepted this soon after a prompt's window became visible.
pub const ARM_DELAY: Duration = Duration::from_secs(1);

/// An answer from the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptAnswer {
    Code(String),
    /// "Open in Browser" of a web sign-in.
    OpenUrl,
    Cancel,
}

/// The `answer_prompt` command's input: `code` (with the code), `openUrl` or `cancel`.
pub fn parse_answer(action: &str, response: Option<&str>) -> Result<PromptAnswer, String> {
    match (action, response) {
        ("code", Some(code)) if mfa::is_valid_code(code, false) => Ok(PromptAnswer::Code(code.to_string())),
        ("openUrl", None) => Ok(PromptAnswer::OpenUrl),
        ("cancel", None) => Ok(PromptAnswer::Cancel),
        _ => Err("invalid answer".into()),
    }
}

impl PromptView {
    fn new(id: u64, prompt: &AuthPrompt) -> Self {
        let (kind, text, echo, from_server, url) = match &prompt.kind {
            AuthPromptKind::Code { text, echo, from_server } => ("code", Some(text.clone()), *echo, *from_server, None),
            AuthPromptKind::WebAuth { url } => ("webAuth", None, false, false, Some(url.clone())),
        };
        let host = url.as_deref().map(WebAuthURL::display_host);
        PromptView {
            id,
            connection_id: prompt.connection_id.clone(),
            connection_name: prompt.connection_name.clone(),
            kind,
            text,
            echo,
            from_server,
            url,
            host,
            deadline: prompt.deadline.end().time_interval_since_1970(),
        }
    }
}

struct Entry {
    view: PromptView,
    result: Option<AuthPromptResult>,
    /// When its window was ordered on screen / its page said it is ready (`None`: not yet, nothing but Cancel is
    /// taken).
    shown: Option<Instant>,
    loaded: Option<Instant>,
}

impl Entry {
    fn armed(&self, now: Instant) -> bool {
        match (self.shown, self.loaded) {
            (Some(shown), Some(loaded)) => now.saturating_duration_since(shown.max(loaded)) >= ARM_DELAY,
            _ => false,
        }
    }
}

#[derive(Default)]
struct State {
    next_id: u64,
    /// By connection key.
    open: HashMap<String, Entry>,
}

type Hook = Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
pub struct PromptBroker {
    state: Mutex<State>,
    changed: Condvar,
    on_change: Mutex<Option<Hook>>,
}

impl PromptBroker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Called when a prompt opens or closes (the UI refreshes its list).
    pub fn set_on_change(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.on_change.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(hook));
    }

    fn notify(&self) {
        let hook = self.on_change.lock().unwrap_or_else(PoisonError::into_inner).clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Blocks until answered, dismissed, replaced or expired. The deadline is measured from now with the
    /// prompt's remaining time (`deadline.end - now`).
    pub fn present(&self, prompt: AuthPrompt, now: macvpn_core::date::Date) -> AuthPromptResult {
        let key = prompt.connection_id.clone();
        let remaining = prompt.deadline.end().time_interval_since(now).max(0.0);
        let until = Instant::now() + Duration::from_secs_f64(remaining.min(24.0 * 3600.0));
        let id = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            state.next_id += 1;
            let id = state.next_id;
            // A previous prompt of the connection is replaced: its waiter sees another ID and returns cancelled.
            state.open.insert(
                key.clone(),
                Entry { view: PromptView::new(id, &prompt), result: None, shown: None, loaded: None },
            );
            id
        };
        self.changed.notify_all();
        self.notify();
        let result = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            loop {
                match state.open.get(&key) {
                    Some(entry) if entry.view.id == id => {
                        if let Some(result) = &entry.result {
                            let result = result.clone();
                            state.open.remove(&key);
                            break result;
                        }
                    }
                    // Replaced by a newer prompt for the same connection, or removed: cancelled.
                    _ => break AuthPromptResult::Cancelled,
                }
                let now = Instant::now();
                if now >= until {
                    state.open.remove(&key);
                    break AuthPromptResult::TimedOut;
                }
                state = self.changed.wait_timeout(state, until - now).unwrap_or_else(PoisonError::into_inner).0;
            }
        };
        self.notify();
        result
    }

    /// The UI's answer. False: no such open prompt (already closed or replaced).
    pub fn answer(&self, id: u64, result: AuthPromptResult) -> bool {
        let found = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            match state.open.values_mut().find(|e| e.view.id == id && e.result.is_none()) {
                Some(entry) => {
                    entry.result = Some(result);
                    true
                }
                None => false,
            }
        };
        if found {
            self.changed.notify_all();
        }
        found
    }

    /// The prompt's window was ordered on screen at `now`. Only the first signal counts. False: no such open
    /// prompt.
    pub fn mark_shown(&self, id: u64, now: Instant) -> bool {
        self.mark(id, |e| {
            e.shown.get_or_insert(now);
        })
    }

    /// The prompt window's page is loaded and showing the prompt (its ready signal) at `now`. Only the first
    /// signal counts. False: no such open prompt.
    pub fn mark_loaded(&self, id: u64, now: Instant) -> bool {
        self.mark(id, |e| {
            e.loaded.get_or_insert(now);
        })
    }

    fn mark(&self, id: u64, f: impl FnOnce(&mut Entry)) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match state.open.values_mut().find(|e| e.view.id == id && e.result.is_none()) {
            Some(entry) => {
                f(entry);
                true
            }
            None => false,
        }
    }

    /// The UI's answer, checked (see the module docs). `Ok(Some(url))`: "Open in Browser" was accepted, the app
    /// opens this (validated again) URL. `now`: the time of the answer.
    pub fn answer_checked(&self, id: u64, answer: PromptAnswer, now: Instant) -> Result<Option<String>, String> {
        let url = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let entry =
                state.open.values_mut().find(|e| e.view.id == id && e.result.is_none()).ok_or("no such prompt")?;
            let armed = entry.armed(now);
            let (result, url) = match answer {
                PromptAnswer::Cancel => (AuthPromptResult::Cancelled, None),
                _ if !armed => return Err("too early".into()),
                PromptAnswer::Code(code) if entry.view.kind == "code" => (AuthPromptResult::Code(code), None),
                PromptAnswer::OpenUrl if entry.view.kind == "webAuth" => {
                    let url = entry.view.url.as_deref().and_then(WebAuthURL::validate).ok_or("invalid URL")?;
                    (AuthPromptResult::OpenedUrl, Some(url))
                }
                _ => return Err("wrong kind of answer".into()),
            };
            entry.result = Some(result);
            url
        };
        self.changed.notify_all();
        Ok(url)
    }

    /// The connection of an open prompt (a notification click brings it forward).
    pub fn prompt_for_connection(&self, connection_id: &str) -> Option<u64> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.open.get(connection_id).filter(|e| e.result.is_none()).map(|e| e.view.id)
    }

    /// Closes the connection's open prompt as cancelled.
    pub fn dismiss(&self, connection_id: &str) {
        let found = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            match state.open.get_mut(connection_id) {
                Some(entry) => {
                    entry.result.get_or_insert(AuthPromptResult::Cancelled);
                    true
                }
                None => false,
            }
        };
        if found {
            self.changed.notify_all();
        }
    }

    /// The open prompts, oldest first.
    pub fn pending(&self) -> Vec<PromptView> {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut views: Vec<PromptView> =
            state.open.values().filter(|e| e.result.is_none()).map(|e| e.view.clone()).collect();
        views.sort_by_key(|v| v.id);
        views
    }
}
