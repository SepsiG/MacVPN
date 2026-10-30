//! User notifications (the Swift `AppModel`'s `notify`, `notifyAuthNeeded` and notification delegate), over
//! the platform's [`Notifier`](macvpn_platform_api::Notifier). Only from a real app bundle (outside the sandbox), as in the Swift app;
//! otherwise every function here does nothing. The texts are generic (`macvpn_app_core::notify`): the details
//! stay in the app.

use macvpn_app_core::ConnectionEvent;
use macvpn_app_core::ConnectionItem;
use macvpn_app_core::connection_notices::{self, Notice};
use macvpn_app_core::credential_prompt::CredentialPromptView;
use macvpn_app_core::failure_reason::{self, FailureKind};
use macvpn_app_core::notify::{self, ClickAction, NotificationContent};
use macvpn_app_core::prompt::PromptView;
use macvpn_core::log::LogTailer;
use macvpn_core::models::{ConnectionState, parse_uuid, uuid_string};
use std::collections::BTreeMap;
use std::sync::{Arc, PoisonError};
use tauri::{AppHandle, Manager};

use crate::platform;
use crate::state::AppState;

/// The delegate (foreground banners, clicks) and the permission request (the launch step).
pub fn start(app: &AppHandle, state: &AppState) {
    if !state.notifications_enabled() {
        return;
    }
    let app = app.clone();
    platform::get().notifier().start(Box::new(move |info| {
        // The delegate runs on the main thread: the routing goes to a worker.
        let app = app.clone();
        std::thread::spawn(move || clicked(&app, &info));
    }));
}

/// A connection notice: posted where notifications can be posted; a smoke run (debug builds) records it.
fn post_notice(state: &AppState, content: &NotificationContent) {
    if state.notifications_enabled() {
        post(content);
    }
    #[cfg(debug_assertions)]
    platform::smoke_notice(state, content);
}

/// Connection notices can be posted: from a real app bundle, or (debug builds) in a smoke run, which records them.
pub fn notices_possible(state: &AppState) -> bool {
    #[cfg(debug_assertions)]
    if platform::smoke_records_notices(state) {
        return true;
    }
    state.notifications_enabled()
}

fn post(content: &NotificationContent) {
    platform::get().notifier().post(
        &content.id,
        &content.title,
        &content.body,
        (content.user_info.0, &content.user_info.1),
    );
}

/// The category of the connection's current log (its last 256 KiB, the tailer's first window), for a failure's
/// reason in plain words. Reads a file or asks the service: never on the manager's thread.
pub fn classify(state: &AppState, key: &str) -> FailureKind {
    let Some(id) = parse_uuid(key) else { return FailureKind::Unknown };
    let Some(source) = state.helper.log_source(&id) else { return FailureKind::Unknown };
    let lines = LogTailer::with_source(source).read_new();
    failure_reason::classify(&lines)
}

/// The "Connection Notifications" switch, where notifications can be posted at all.
fn switch_on(state: &AppState) -> bool {
    notices_possible(state) && connection_notices::enabled(state.prefs.as_ref())
}

/// A status notice (the tracker's, or the reconnect planner's). The planner's `DisconnectedHere` carries no name:
/// it gets the connection's current one (none when the connection is gone; empty while locked: a generic title).
pub fn notice(state: &AppState, notice: &Notice) {
    if !switch_on(state) {
        return;
    }
    let unique = uuid_string(&uuid::Uuid::new_v4());
    let content = match notice {
        Notice::DisconnectedHere { key, .. } => {
            let Some(item) = state.manager.item(key) else { return };
            connection_notices::content_named(notice, item.name(), unique)
        }
        _ => connection_notices::content(notice, unique),
    };
    post_notice(state, &content);
}

/// A failure or a drop (`ConnectionEvent`), with the reason from the log. A disconnect the user started emits no
/// event, so it posts nothing; neither does one the user stopped outside the app (LinVPN: GNOME's menu).
pub fn event(state: &AppState, event: &ConnectionEvent) {
    if !switch_on(state) {
        return;
    }
    let (ConnectionEvent::Dropped { connection_id, .. } | ConnectionEvent::Failed { connection_id, .. }) = event;
    let kind = classify(state, connection_id);
    if kind == FailureKind::StoppedByUser {
        return;
    }
    let notice = match event {
        ConnectionEvent::Dropped { connection_id, name } => {
            let reason = connection_notices::reason_text(kind, None);
            Notice::Dropped { key: connection_id.clone(), name: name.clone(), reason }
        }
        ConnectionEvent::Failed { connection_id, name, reason } => {
            let reason = connection_notices::reason_text(kind, Some(reason));
            Notice::Failed { key: connection_id.clone(), name: name.clone(), reason }
        }
    };
    self::notice(state, &notice);
}

/// A state change of a managed connection: "connected" / "reconnected" (the tracker decides).
pub fn state_changed(state: &AppState, key: &str, new: &ConnectionState) {
    let Some(item) = state.manager.item(key) else { return };
    if !matches!(item, ConnectionItem::Managed(_)) {
        return;
    }
    let found = state.notices.lock().unwrap_or_else(PoisonError::into_inner).on_state(key, item.name(), new);
    if let Some(n) = found {
        notice(state, &n);
    }
}

/// A team catalog notice (updated, an older version refused, the team key changed, failed): the catalog service's
/// own text, which names the catalog but carries no key, token or content.
pub fn catalog(state: &AppState, content: &NotificationContent) {
    if state.notifications_enabled() {
        post(content);
    }
}

/// The platform's "updated" text once after an update's relaunch (LinVPN: "LinVPN was updated to X.Y.Z."). A
/// click opens the app like any other notice.
pub fn updated(state: &AppState, text: String) {
    if state.notifications_enabled() {
        let id = uuid_string(&uuid::Uuid::new_v4());
        post(&NotificationContent { id, title: text, body: String::new(), user_info: ("update", String::new()) });
    }
}

/// "…: authentication needed" (the prompt window does not take the focus).
pub fn prompt_opened(state: &AppState, prompt: &PromptView) {
    if state.notifications_enabled() {
        post(&notify::for_prompt(prompt));
    }
}

/// The prompt closed: its notification goes too.
pub fn prompt_closed(state: &AppState, connection_id: &str) {
    if state.notifications_enabled() {
        platform::get().notifier().remove_delivered(&notify::auth_notification_id(connection_id));
    }
}

/// "…: credentials needed" (the credential window does not take the focus).
pub fn credentials_opened(state: &AppState, prompt: &CredentialPromptView) {
    if state.notifications_enabled() {
        post(&notify::for_credential_prompt(prompt));
    }
}

/// The credential prompt closed: its notification goes too.
pub fn credentials_closed(state: &AppState, connection_id: &str) {
    if state.notifications_enabled() {
        platform::get().notifier().remove_delivered(&notify::credential_notification_id(connection_id));
    }
}

/// A click: the prompt comes forward, or the Connections window opens on the connection's Log tab.
fn clicked(app: &AppHandle, info: &BTreeMap<String, String>) {
    let Some(state) = app.try_state::<Arc<AppState>>() else { return };
    let state = state.inner().clone();
    let listed = |id: &str| {
        crate::commands::validate_key(id).ok()?;
        state.manager.item(id).map(|item| matches!(item, ConnectionItem::Managed(_)))
    };
    match notify::route_click(info, listed) {
        ClickAction::FocusPrompt(connection) => crate::prompts::focus(app, &state, &connection),
        ClickAction::FocusCredentials(connection) => crate::credentials::focus(app, &state, &connection),
        ClickAction::ShowConnection { select, log_tab } => {
            if let (Some(id), true) = (&select, log_tab) {
                state.connections.request_log_tab(id);
            }
            if select.is_some() {
                state.connections.select(select);
            }
            let _ = crate::commands::open(app, crate::manage::MANAGE_WINDOW);
        }
    }
}
