//! The serializable view model of the menu popover (and, later, the other windows): the rows in ranking order
//! with their state, the status error line, the tray icon state and the open MFA prompts.

use crate::connections::ManageView;
use crate::credential_prompt::CredentialPromptView;
use crate::manager::{ConnectionItem, ManagerSnapshot};
use crate::pairing::PairingView;
use crate::prompt::PromptView;
use crate::quit::QuitQuestion;
use crate::setup::SetupView;
use crate::updates::UpdateView;
use macvpn_core::control::protocol::escape_unsafe_text;
use macvpn_core::control::registry::PairedClient;
use macvpn_core::models::{AuthWaitKind, ConnectionState, VPNKind, uuid_string};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

/// The menu bar icon (the Swift `menuBarSymbol`): template glyphs, the system tints them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TrayIcon {
    /// `shield`: nothing active (grey).
    Idle,
    /// `checkmark.shield.fill`: a connection is active (green).
    Active,
    /// `exclamationmark.shield.fill`: a failure or a status error (red).
    Failure,
    /// `key.fill`: waiting for authentication (code or web sign-in).
    Auth,
}

impl TrayIcon {
    pub fn from_snapshot(s: &ManagerSnapshot) -> TrayIcon {
        if s.awaiting_auth {
            TrayIcon::Auth
        } else if s.has_failure || s.status_error.is_some() {
            TrayIcon::Failure
        } else if s.has_active {
            TrayIcon::Active
        } else {
            TrayIcon::Idle
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum RowState {
    Disconnected,
    Connecting,
    Connected {
        ip: Option<String>,
        /// Unix time (seconds).
        since: Option<f64>,
    },
    Disconnecting,
    Failed {
        reason: String,
    },
    AwaitingAuth {
        /// `code`, `web` or `credentials`.
        wait: &'static str,
        deadline: Option<f64>,
    },
}

impl From<&ConnectionState> for RowState {
    fn from(state: &ConnectionState) -> Self {
        match state {
            ConnectionState::Disconnected => RowState::Disconnected,
            ConnectionState::Connecting => RowState::Connecting,
            ConnectionState::Connected { ip, since } => {
                RowState::Connected { ip: ip.clone(), since: since.map(|d| d.time_interval_since_1970()) }
            }
            ConnectionState::Disconnecting => RowState::Disconnecting,
            ConnectionState::Failed(reason) => RowState::Failed { reason: reason.clone() },
            ConnectionState::AwaitingAuth(wait) => RowState::AwaitingAuth {
                wait: match wait.kind {
                    AuthWaitKind::Code => "code",
                    AuthWaitKind::Web => "web",
                    AuthWaitKind::Credentials => "credentials",
                },
                deadline: wait.deadline.map(|d| d.time_interval_since_1970()),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RowView {
    /// The connection's UUID string or the system VPN's scutil service ID.
    pub id: String,
    pub name: String,
    /// `WireGuard`, `OpenVPN`, … or the system VPN's type label.
    pub type_label: String,
    /// False: a system VPN not managed by MacVPN.
    pub managed: bool,
    /// A managed connection's kind (`openvpn`, `wireguard`, …).
    pub kind: Option<&'static str>,
    /// A system VPN whose PSK / password MacVPN can keep (L2TP / Cisco IPsec).
    pub stored_secrets: bool,
    pub pinned: bool,
    /// False: a tool for the type is missing ("Missing tool").
    pub available: bool,
    #[serde(flatten)]
    pub state: RowState,
    /// The switch shows "on" (the state is active).
    pub switch_on: bool,
    /// The switch can be used (available, and not disconnecting).
    pub switch_enabled: bool,
    /// The paired apps holding the connection through the control API ("Held by …"), sorted.
    pub held_by: Vec<String>,
}

/// "Launch at Login" (the platform layer's `LoginItemState`, mapped by the app).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginItemView {
    pub is_on: bool,
    pub can_toggle: bool,
    /// The note under the switch (already translated).
    pub note: Option<String>,
    /// The "Open Login Items Settings…" button.
    pub shows_open_settings: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewModel {
    /// `en` or `hu` (the core's language rule).
    pub language: &'static str,
    pub rows: Vec<RowView>,
    pub status_error: Option<String>,
    pub tray: TrayIcon,
    pub has_active: bool,
    pub prompts: Vec<PromptView>,
    /// The system status check found nothing missing.
    pub setup_complete: bool,
    pub update: UpdateView,
    /// `None` until the system state was read.
    pub login_item: Option<LoginItemView>,
    /// The Connections window: selection, unsaved changes, tab requests, an import's question.
    pub manage: ManageView,
    /// The System Status window.
    pub setup: SetupView,
    /// A quit question being asked (the active-connections question is shown by the menu, and for an update by
    /// the Update window).
    pub quit: Option<QuitQuestion>,
    /// Under the active-connections question: the apps whose sessions quitting ends (`quit::lease_holders_note`).
    pub quit_note: Option<String>,
    /// The control API: the setting, the paired apps, the audit lines.
    pub control: ControlView,
    /// The open pairing requests (each in its `pair-<id>` window).
    pub pairings: Vec<PairingView>,
    /// The open credential prompts (each in its `cred-<id>` window). Never a typed value.
    pub credential_prompts: Vec<CredentialPromptView>,
    /// The app's version (the workspace's Cargo version, which the bundle carries too), shown at the bottom of the
    /// menu as "MacVPN <version>".
    pub app_version: &'static str,
}

/// A paired app in the Connections window's "Paired apps" section. Never the token or its hash.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedAppView {
    pub id: String,
    /// Self-reported at pairing.
    pub name: String,
    /// The pinned executable path.
    pub executable: String,
    /// The connection keys it may use.
    pub allowed: Vec<String>,
    /// Unix time (seconds).
    pub created: f64,
    pub last_used: Option<f64>,
    /// The token was last presented from this other executable (the user re-pairs).
    pub path_changed: Option<String>,
}

impl PairedAppView {
    pub fn new(client: &PairedClient, path_changed: Option<&String>) -> Self {
        PairedAppView {
            id: uuid_string(&client.id),
            name: client.name.clone(),
            executable: escape_unsafe_text(&client.executable),
            allowed: client.allowed.clone(),
            created: client.created.time_interval_since_1970(),
            last_used: client.last_used.map(|d| d.time_interval_since_1970()),
            path_changed: path_changed.map(|p| escape_unsafe_text(p)),
        }
    }
}

/// The control API's part of the view model.
#[derive(Debug, Clone, PartialEq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlView {
    /// "Allow other apps to control VPNs" is on.
    pub enabled: bool,
    /// The server is running.
    pub running: bool,
    /// Why the server could not start (translated), while the setting is on.
    pub error: Option<String>,
    pub clients: Vec<PairedAppView>,
    /// The latest audit lines ("Control API"), oldest first.
    pub activity: Vec<String>,
}

impl ControlView {
    pub fn build(
        enabled: bool,
        running: bool,
        error: Option<String>,
        clients: &[PairedClient],
        path_changes: &HashMap<Uuid, String>,
        activity: Vec<String>,
    ) -> ControlView {
        let clients = clients.iter().map(|c| PairedAppView::new(c, path_changes.get(&c.id))).collect();
        ControlView { enabled, running, error, clients, activity }
    }
}

impl ViewModel {
    /// `available`: whether the tools of a managed connection's type are installed (system VPNs always are).
    pub fn build(
        snapshot: &ManagerSnapshot,
        language: &'static str,
        available: impl Fn(VPNKind) -> bool,
        prompts: Vec<PromptView>,
        setup_complete: bool,
    ) -> ViewModel {
        let rows = snapshot
            .items
            .iter()
            .map(|(item, state, pinned)| {
                let (id, type_label, managed, available) = match item {
                    ConnectionItem::Managed(c) => {
                        (uuid_string(&c.id), c.kind.display_name().to_string(), true, available(c.kind))
                    }
                    ConnectionItem::System(s) => (s.id.clone(), s.type_label.clone(), false, true),
                };
                let (kind, stored_secrets) = match item {
                    ConnectionItem::Managed(c) => (Some(c.kind.raw_value()), false),
                    ConnectionItem::System(s) => (None, s.supports_stored_secrets()),
                };
                RowView {
                    id,
                    name: item.name().to_string(),
                    type_label,
                    managed,
                    kind,
                    stored_secrets,
                    pinned: *pinned,
                    available,
                    state: RowState::from(state),
                    switch_on: state.is_active(),
                    switch_enabled: available && *state != ConnectionState::Disconnecting,
                    held_by: Vec::new(),
                }
            })
            .collect();
        ViewModel {
            language,
            rows,
            status_error: snapshot.status_error.clone(),
            tray: TrayIcon::from_snapshot(snapshot),
            has_active: snapshot.has_active,
            prompts,
            setup_complete,
            update: UpdateView::default(),
            login_item: None,
            manage: ManageView::default(),
            setup: SetupView::default(),
            quit: None,
            quit_note: None,
            control: ControlView::default(),
            pairings: Vec::new(),
            credential_prompts: Vec::new(),
            app_version: macvpn_core::VERSION,
        }
    }

    /// The "Held by …" labels: the lease holder names per connection key (`ControlServer::holders`).
    pub fn set_holders(&mut self, holders: &BTreeMap<String, Vec<String>>) {
        for row in &mut self.rows {
            row.held_by = holders.get(&row.id).cloned().unwrap_or_default();
        }
    }
}
