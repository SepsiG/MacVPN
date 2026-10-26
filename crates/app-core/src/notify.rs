//! The user notifications' content and click routing (the notification parts of the Swift `AppModel`:
//! `notify(_:)`, `notifyAuthNeeded`, `userNotificationCenter(_:didReceive:)`), and the bookkeeping of the open
//! MFA prompts (which prompt windows / "authentication needed" notifications to open and close).
//!
//! The bodies are generic on purpose: a failure's reason (server, user name, system message) would be visible
//! on the lock screen, so it stays in the app.

use crate::connection_notices::{self, Notice};
use crate::credential_prompt::CredentialPromptView;
use crate::manager::ConnectionEvent;
use crate::prompt::PromptView;
use macvpn_core::l10n::{self, Arg};
use std::collections::BTreeMap;

/// The `userInfo` keys of the Swift app (a click on an older notification still works).
pub const CONNECTION_KEY: &str = "connectionID";
pub const AUTH_PROMPT_KEY: &str = "authPrompt";
/// The credential prompt's notification (new in the Rust app).
pub const CREDENTIAL_PROMPT_KEY: &str = "credentialPrompt";
/// A team catalog notice (updated, refused, team key changed): the catalog id.
pub const CATALOG_KEY: &str = "teamCatalog";

/// One notification to post.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotificationContent {
    /// The request identifier (the auth notification's is fixed per connection, so it can be removed).
    pub id: String,
    pub title: String,
    pub body: String,
    /// `userInfo`: one of [`CONNECTION_KEY`] / [`AUTH_PROMPT_KEY`] / [`CREDENTIAL_PROMPT_KEY`] with the connection's
    /// key, or [`CATALOG_KEY`] with a catalog id.
    pub user_info: (&'static str, String),
}

pub fn auth_notification_id(connection_id: &str) -> String {
    format!("auth-{connection_id}")
}

pub fn credential_notification_id(connection_id: &str) -> String {
    format!("cred-{connection_id}")
}

/// "<name>: …", or without a name (a connection redacted while the vault is locked) the generic text.
fn titled(name: &str, with_name: impl FnOnce(&str) -> String, generic: impl FnOnce() -> String) -> String {
    if name.trim().is_empty() { generic() } else { with_name(name) }
}

/// A failure or a drop of the manager, as a connection notice without a reason (the app adds the log's category
/// through [`crate::connection_notices`]). `unique`: a fresh identifier (every event is its own notification).
pub fn for_event(event: &ConnectionEvent, unique: String) -> NotificationContent {
    let notice = match event {
        ConnectionEvent::Failed { connection_id, name, .. } => {
            Notice::Failed { key: connection_id.clone(), name: name.clone(), reason: None }
        }
        ConnectionEvent::Dropped { connection_id, name } => {
            Notice::Dropped { key: connection_id.clone(), name: name.clone(), reason: None }
        }
    };
    connection_notices::content(&notice, unique)
}

/// "…: authentication needed" for an open prompt (the prompt window does not take the focus; a click on this
/// brings it forward).
pub fn for_prompt(prompt: &PromptView) -> NotificationContent {
    NotificationContent {
        id: auth_notification_id(&prompt.connection_id),
        title: titled(
            &prompt.connection_name,
            |n| l10n::tr("%@: authentication needed", &[Arg::Str(n)]),
            || l10n::tr("A VPN connection needs authentication", &[]),
        ),
        body: l10n::tr("Click to enter the code or to sign in.", &[]),
        user_info: (AUTH_PROMPT_KEY, prompt.connection_id.clone()),
    }
}

/// "…: credentials needed" for an open credential prompt (its window does not take the focus either). The body
/// names no field value.
pub fn for_credential_prompt(prompt: &CredentialPromptView) -> NotificationContent {
    NotificationContent {
        id: credential_notification_id(&prompt.connection_id),
        title: titled(
            &prompt.connection_name,
            |n| l10n::tr("%@: credentials needed", &[Arg::Str(n)]),
            || l10n::tr("Credentials needed", &[]),
        ),
        body: l10n::tr("Click to enter the user name or password.", &[]),
        user_info: (CREDENTIAL_PROMPT_KEY, prompt.connection_id.clone()),
    }
}

/// A team catalog notice (spec 6, plan Task 11). The text names the catalog and counts, never a connection's
/// configuration or a key. `unique`: a fresh identifier.
pub fn for_catalog(catalog_id: &str, text: String, unique: String) -> NotificationContent {
    NotificationContent {
        id: unique,
        title: l10n::tr("Team catalog", &[]),
        body: text,
        user_info: (CATALOG_KEY, catalog_id.to_string()),
    }
}

/// What a click on a notification does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClickAction {
    /// The connection's open prompt comes forward (and gets the focus).
    FocusPrompt(String),
    /// The connection's open credential prompt comes forward (and gets the focus).
    FocusCredentials(String),
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
    if let Some(key) = user_info.get(CREDENTIAL_PROMPT_KEY) {
        return ClickAction::FocusCredentials(key.clone());
    }
    match user_info.get(CONNECTION_KEY).and_then(|id| listed(id).map(|managed| (id, managed))) {
        Some((id, managed)) => ClickAction::ShowConnection { select: Some(id.clone()), log_tab: managed },
        None => ClickAction::ShowConnection { select: None, log_tab: false },
    }
}

/// A prompt the app shows in a window (an MFA prompt or a credential prompt).
pub trait TrackedPrompt: Clone {
    fn prompt_id(&self) -> u64;
    fn connection_key(&self) -> &str;
}

impl TrackedPrompt for PromptView {
    fn prompt_id(&self) -> u64 {
        self.id
    }

    fn connection_key(&self) -> &str {
        &self.connection_id
    }
}

impl TrackedPrompt for CredentialPromptView {
    fn prompt_id(&self) -> u64 {
        self.id
    }

    fn connection_key(&self) -> &str {
        &self.connection_id
    }
}

/// The open prompts the app has shown (windows and notifications): what changed since the last look.
#[derive(Debug)]
pub struct PromptTracker<V = PromptView> {
    shown: BTreeMap<u64, String>,
    _view: std::marker::PhantomData<V>,
}

impl<V> Default for PromptTracker<V> {
    fn default() -> Self {
        PromptTracker { shown: BTreeMap::new(), _view: std::marker::PhantomData }
    }
}

/// The change of the open prompts.
#[derive(Debug, Clone, PartialEq)]
pub struct PromptChanges<V = PromptView> {
    /// New prompts: a window opens, "authentication needed" is posted.
    pub opened: Vec<V>,
    /// Closed prompts (ID, connection key): the window closes, the delivered notification is removed.
    pub closed: Vec<(u64, String)>,
}

impl<V> Default for PromptChanges<V> {
    fn default() -> Self {
        PromptChanges { opened: Vec::new(), closed: Vec::new() }
    }
}

impl<V: TrackedPrompt> PromptTracker<V> {
    pub fn update(&mut self, pending: &[V]) -> PromptChanges<V> {
        let mut changes = PromptChanges::default();
        let ids: Vec<u64> = pending.iter().map(TrackedPrompt::prompt_id).collect();
        let closed: Vec<u64> = self.shown.keys().filter(|id| !ids.contains(id)).copied().collect();
        for id in closed {
            if let Some(connection) = self.shown.remove(&id) {
                changes.closed.push((id, connection));
            }
        }
        for p in pending {
            if let std::collections::btree_map::Entry::Vacant(entry) = self.shown.entry(p.prompt_id()) {
                entry.insert(p.connection_key().to_string());
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

/// The credential window's label (`cred-<id>`; its capability file allows `cred-*`).
pub fn credential_window_label(id: u64) -> String {
    format!("cred-{id}")
}

/// The prompt ID of a credential window's label.
pub fn credential_id_of_label(label: &str) -> Option<u64> {
    let digits = label.strip_prefix("cred-")?;
    if digits.is_empty() || digits.len() > 19 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}
