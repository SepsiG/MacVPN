//! The user notifications' content and click routing (the notification parts of the Swift `AppModel`:
//! `notify(_:)`, `notifyAuthNeeded`, `userNotificationCenter(_:didReceive:)`), and the bookkeeping of the open
//! MFA prompts (which prompt windows / "authentication needed" notifications to open and close).
//!
//! The bodies are generic on purpose: a failure's reason (server, user name, system message) would be visible
//! on the lock screen, so it stays in the app.

use crate::manager::ConnectionEvent;
use crate::prompt::PromptView;
use macvpn_core::l10n::{self, Arg};
use std::collections::BTreeMap;

/// The `userInfo` keys of the Swift app (a click on an older notification still works).
pub const CONNECTION_KEY: &str = "connectionID";
pub const AUTH_PROMPT_KEY: &str = "authPrompt";

/// One notification to post.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationContent {
    /// The request identifier (the auth notification's is fixed per connection, so it can be removed).
    pub id: String,
    pub title: String,
    pub body: String,
    /// `userInfo`: one of [`CONNECTION_KEY`] / [`AUTH_PROMPT_KEY`] with the connection's key.
    pub user_info: (&'static str, String),
}

pub fn auth_notification_id(connection_id: &str) -> String {
    format!("auth-{connection_id}")
}

/// A failure or a drop. `unique`: a fresh identifier (every event is its own notification).
pub fn for_event(event: &ConnectionEvent, unique: String) -> NotificationContent {
    let (connection_id, title, body) = match event {
        ConnectionEvent::Failed { connection_id, name, .. } => (
            connection_id,
            l10n::tr("%@: connection failed", &[Arg::Str(name)]),
            l10n::tr("Open MacVPN for details", &[]),
        ),
        ConnectionEvent::Dropped { connection_id, name } => (
            connection_id,
            l10n::tr("%@: the connection dropped", &[Arg::Str(name)]),
            l10n::tr("Click to see the log.", &[]),
        ),
    };
    NotificationContent { id: unique, title, body, user_info: (CONNECTION_KEY, connection_id.clone()) }
}

/// "…: authentication needed" for an open prompt (the prompt window does not take the focus; a click on this
/// brings it forward).
pub fn for_prompt(prompt: &PromptView) -> NotificationContent {
    NotificationContent {
        id: auth_notification_id(&prompt.connection_id),
        title: l10n::tr("%@: authentication needed", &[Arg::Str(&prompt.connection_name)]),
        body: l10n::tr("Click to enter the code or to sign in.", &[]),
        user_info: (AUTH_PROMPT_KEY, prompt.connection_id.clone()),
    }
}

/// What a click on a notification does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClickAction {
    /// The connection's open prompt comes forward (and gets the focus).
    FocusPrompt(String),
    /// The Connections window opens; `select`: the connection to select (a listed one only); `log_tab`: its
    /// detail switches to the Log tab (managed connections).
    ShowConnection { select: Option<String>, log_tab: bool },
}

/// The Swift `userNotificationCenter(_:didReceive:)`. `listed`: whether a key names a listed connection, and
/// whether it is a managed one.
pub fn route_click(user_info: &BTreeMap<String, String>, listed: impl Fn(&str) -> Option<bool>) -> ClickAction {
    if let Some(key) = user_info.get(AUTH_PROMPT_KEY) {
        return ClickAction::FocusPrompt(key.clone());
    }
    match user_info.get(CONNECTION_KEY).and_then(|id| listed(id).map(|managed| (id, managed))) {
        Some((id, managed)) => ClickAction::ShowConnection { select: Some(id.clone()), log_tab: managed },
        None => ClickAction::ShowConnection { select: None, log_tab: false },
    }
}

/// The open prompts the app has shown (windows and notifications): what changed since the last look.
#[derive(Debug, Default)]
pub struct PromptTracker {
    shown: BTreeMap<u64, String>,
}

/// The change of the open prompts.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PromptChanges {
    /// New prompts: a window opens, "authentication needed" is posted.
    pub opened: Vec<PromptView>,
    /// Closed prompts (ID, connection key): the window closes, the delivered notification is removed.
    pub closed: Vec<(u64, String)>,
}

impl PromptTracker {
    pub fn update(&mut self, pending: &[PromptView]) -> PromptChanges {
        let mut changes = PromptChanges::default();
        let ids: Vec<u64> = pending.iter().map(|p| p.id).collect();
        let closed: Vec<u64> = self.shown.keys().filter(|id| !ids.contains(id)).copied().collect();
        for id in closed {
            if let Some(connection) = self.shown.remove(&id) {
                changes.closed.push((id, connection));
            }
        }
        for p in pending {
            if let std::collections::btree_map::Entry::Vacant(entry) = self.shown.entry(p.id) {
                entry.insert(p.connection_id.clone());
                changes.opened.push(p.clone());
            }
        }
        changes
    }
}

/// The prompt window's label (`prompt-<id>`; the capability file allows `prompt-*`).
pub fn prompt_window_label(id: u64) -> String {
    format!("prompt-{id}")
}

/// The prompt ID of a prompt window's label.
pub fn prompt_id_of_label(label: &str) -> Option<u64> {
    let digits = label.strip_prefix("prompt-")?;
    if digits.is_empty() || digits.len() > 19 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}
