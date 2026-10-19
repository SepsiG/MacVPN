//! The credential prompt broker (spec `2026-10-19-vault-folders-design.md`, section 4), a copy of the MFA
//! [`PromptBroker`](crate::prompt::PromptBroker) pattern for the `cred-<id>` window: the connection manager's
//! blocking credential handler parks here until the window answers, the prompt is dismissed, replaced or its
//! deadline passes. At most one open prompt per connection: a new one cancels the previous.
//!
//! The window's answers are checked here ([`CredentialBroker::answer_checked`]): the prompt must be open; nothing
//! but Cancel is taken in the first second after its window became visible ([`ARM_DELAY`], from the later of
//! [`CredentialBroker::mark_shown`] and [`CredentialBroker::mark_loaded`]); a Connect must carry exactly the asked
//! fields, each passing [`credentials::validate_values`]. An expired prompt answers Cancelled (the user did
//! nothing wrong, and there is no server deadline).
//!
//! The typed values only live in the returned [`CredentialAnswer`] (`Zeroizing` strings); the view
//! ([`CredentialPromptView`]) never carries one.

use macvpn_core::credentials::{
    self, CredentialAnswer, CredentialField, CredentialPrompt, CredentialValues, sign_in_failed_text,
};
use macvpn_core::date::Date;
use macvpn_core::models::VPNKind;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub use crate::prompt::ARM_DELAY;

/// An open credential prompt as the window shows it (no secret in it).
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialPromptView {
    /// Answer with this ID (the window's label is `cred-<id>`).
    pub id: u64,
    pub connection_id: String,
    pub connection_name: String,
    /// `username`, `password`, `psk`, `keyPassword`, in display order.
    pub fields: Vec<&'static str>,
    /// The stored user name, pre-filled.
    pub username: Option<String>,
    /// The localized "Sign-in failed …" line, only on a re-prompt.
    pub message: Option<String>,
    /// Unix time (seconds) when the prompt expires.
    pub deadline: f64,
}

/// An answer from the window before the broker's checks.
pub enum RawCredentialAnswer {
    Connect { values: CredentialValues, save: bool },
    Cancel,
}

impl std::fmt::Debug for RawCredentialAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RawCredentialAnswer::Connect { values, save } => {
                f.debug_struct("Connect").field("values", values).field("save", save).finish()
            }
            RawCredentialAnswer::Cancel => f.write_str("Cancel"),
        }
    }
}

/// The `answer_credentials` command's input: `connect` with the values (keys only from the four field names) or
/// `cancel` with none. The strings move into `Zeroizing` at once, before any check.
pub fn parse_credential_answer(
    action: &str,
    values: BTreeMap<String, String>,
    save: bool,
) -> Result<RawCredentialAnswer, String> {
    let mut parsed = CredentialValues::default();
    let mut unknown = false;
    let count = values.len();
    for (key, value) in values {
        let value = Zeroizing::new(value);
        match CredentialField::from_name(&key) {
            Some(field) => parsed.set(field, value),
            None => unknown = true,
        }
    }
    match action {
        _ if unknown => Err("invalid answer".into()),
        "connect" => Ok(RawCredentialAnswer::Connect { values: parsed, save }),
        "cancel" if count == 0 => Ok(RawCredentialAnswer::Cancel),
        _ => Err("invalid answer".into()),
    }
}

impl CredentialPromptView {
    fn new(id: u64, prompt: &CredentialPrompt) -> Self {
        CredentialPromptView {
            id,
            connection_id: prompt.connection_id.clone(),
            connection_name: prompt.connection_name.clone(),
            fields: prompt.fields.iter().map(|f| f.name()).collect(),
            username: prompt.username.clone().filter(|u| !u.is_empty()),
            message: prompt.retry.then(sign_in_failed_text),
            deadline: prompt.deadline.end().time_interval_since_1970(),
        }
    }
}

struct Entry {
    view: CredentialPromptView,
    kind: VPNKind,
    fields: Vec<CredentialField>,
    result: Option<CredentialAnswer>,
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

    fn is_open(&self) -> bool {
        self.result.is_none()
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
pub struct CredentialBroker {
    state: Mutex<State>,
    changed: Condvar,
    on_change: Mutex<Option<Hook>>,
}

impl CredentialBroker {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Called when a prompt opens or closes (the app opens / closes the window).
    pub fn set_on_change(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.on_change.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(hook));
    }

    fn notify(&self) {
        let hook = self.on_change.lock().unwrap_or_else(PoisonError::into_inner).clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// Blocks until answered, dismissed, replaced or expired (all but an answer: `Cancelled`). The deadline is
    /// measured from now with the prompt's remaining time.
    pub fn present(&self, prompt: CredentialPrompt, now: Date) -> CredentialAnswer {
        let key = prompt.connection_id.clone();
        let remaining = prompt.deadline.end().time_interval_since(now).max(0.0);
        let until = Instant::now() + Duration::from_secs_f64(remaining.min(24.0 * 3600.0));
        let id = {
            let mut state = self.lock();
            state.next_id += 1;
            let id = state.next_id;
            // A previous prompt of the connection is replaced: its waiter sees another ID and returns cancelled.
            state.open.insert(
                key.clone(),
                Entry {
                    view: CredentialPromptView::new(id, &prompt),
                    kind: prompt.kind,
                    fields: prompt.fields.clone(),
                    result: None,
                    shown: None,
                    loaded: None,
                },
            );
            id
        };
        self.changed.notify_all();
        self.notify();
        let answer = {
            let mut state = self.lock();
            loop {
                match state.open.get_mut(&key) {
                    Some(entry) if entry.view.id == id => {
                        if let Some(answer) = entry.result.take() {
                            state.open.remove(&key);
                            break answer;
                        }
                    }
                    _ => break CredentialAnswer::Cancelled,
                }
                let now = Instant::now();
                if now >= until {
                    state.open.remove(&key);
                    break CredentialAnswer::Cancelled;
                }
                state = self.changed.wait_timeout(state, until - now).unwrap_or_else(PoisonError::into_inner).0;
            }
        };
        self.notify();
        answer
    }

    /// The window was ordered on screen at `now`. Only the first signal counts. False: no such open prompt.
    pub fn mark_shown(&self, id: u64, now: Instant) -> bool {
        self.mark(id, |e| {
            e.shown.get_or_insert(now);
        })
    }

    /// The window's page is loaded and showing the prompt at `now`. Only the first signal counts.
    pub fn mark_loaded(&self, id: u64, now: Instant) -> bool {
        self.mark(id, |e| {
            e.loaded.get_or_insert(now);
        })
    }

    fn mark(&self, id: u64, f: impl FnOnce(&mut Entry)) -> bool {
        let mut state = self.lock();
        match state.open.values_mut().find(|e| e.view.id == id && e.is_open()) {
            Some(entry) => {
                f(entry);
                true
            }
            None => false,
        }
    }

    /// The window's answer, checked (see the module docs). `now`: the time of the answer.
    pub fn answer_checked(&self, id: u64, answer: RawCredentialAnswer, now: Instant) -> Result<(), String> {
        {
            let mut state = self.lock();
            let entry = state.open.values_mut().find(|e| e.view.id == id && e.is_open()).ok_or("no such prompt")?;
            let result = match answer {
                RawCredentialAnswer::Cancel => CredentialAnswer::Cancelled,
                RawCredentialAnswer::Connect { .. } if !entry.armed(now) => return Err("too early".into()),
                RawCredentialAnswer::Connect { values, save } => {
                    credentials::validate_values(&values, &entry.fields, entry.kind)?;
                    CredentialAnswer::Provided { values, save }
                }
            };
            entry.result = Some(result);
        }
        self.changed.notify_all();
        Ok(())
    }

    /// The connection's open prompt (a notification click brings it forward).
    pub fn prompt_for_connection(&self, connection_id: &str) -> Option<u64> {
        self.lock().open.get(connection_id).filter(|e| e.is_open()).map(|e| e.view.id)
    }

    /// Closes the connection's open prompt as cancelled.
    pub fn dismiss(&self, connection_id: &str) {
        let found = {
            let mut state = self.lock();
            match state.open.get_mut(connection_id) {
                Some(entry) if entry.is_open() => {
                    entry.result = Some(CredentialAnswer::Cancelled);
                    true
                }
                _ => false,
            }
        };
        if found {
            self.changed.notify_all();
        }
    }

    /// The open prompts, oldest first.
    pub fn pending(&self) -> Vec<CredentialPromptView> {
        let state = self.lock();
        let mut views: Vec<CredentialPromptView> =
            state.open.values().filter(|e| e.is_open()).map(|e| e.view.clone()).collect();
        views.sort_by_key(|v| v.id);
        views
    }
}
