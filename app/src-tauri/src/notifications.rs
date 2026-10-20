//! User notifications (the Swift `AppModel`'s `notify`, `notifyAuthNeeded` and notification delegate), over
//! `macvpn_platform_mac::notifications`. Only from a real app bundle (outside the sandbox), as in the Swift app;
//! otherwise every function here does nothing. The texts are generic (`macvpn_app_core::notify`): the details
//! stay in the app.

use macvpn_app_core::ConnectionEvent;
use macvpn_app_core::ConnectionItem;
use macvpn_app_core::credential_prompt::CredentialPromptView;
use macvpn_app_core::notify::{self, ClickAction, NotificationContent};
use macvpn_app_core::prompt::PromptView;
use macvpn_core::models::uuid_string;
use macvpn_platform_mac::notifications;
use std::collections::BTreeMap;
use std::sync::Arc;
use tauri::{AppHandle, Manager};

use crate::state::AppState;

/// The delegate (foreground banners, clicks) and the permission request (the launch step).
pub fn start(app: &AppHandle, state: &AppState) {
    if !state.notifications_enabled() {
        return;
    }
    let app = app.clone();
    notifications::start(move |info| {
        // The delegate runs on the main thread: the routing goes to a worker.
        let app = app.clone();
        std::thread::spawn(move || clicked(&app, &info));
    });
}

fn post(content: &NotificationContent) {
    notifications::post(&content.id, &content.title, &content.body, (content.user_info.0, &content.user_info.1));
}

/// A failure or a drop.
pub fn event(state: &AppState, event: &ConnectionEvent) {
    if state.notifications_enabled() {
        post(&notify::for_event(event, uuid_string(&uuid::Uuid::new_v4())));
    }
}

/// A team catalog notice (updated, an older version refused, the team key changed, failed): the catalog service's
/// own text, which names the catalog but carries no key, token or content.
pub fn catalog(state: &AppState, content: &NotificationContent) {
    if state.notifications_enabled() {
        post(content);
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
        notifications::remove_delivered(&notify::auth_notification_id(connection_id));
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
        notifications::remove_delivered(&notify::credential_notification_id(connection_id));
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
