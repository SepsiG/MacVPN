//! The serializable view model of the menu popover (and, later, the other windows): the rows in ranking order
//! with their state, the status error line, the tray icon state and the open MFA prompts.

use crate::connections::ManageView;
use crate::manager::{ConnectionItem, ManagerSnapshot};
use crate::prompt::PromptView;
use crate::quit::QuitQuestion;
use crate::setup::SetupView;
use crate::updates::UpdateView;
use macvpn_core::models::{AuthWaitKind, ConnectionState, VPNKind, uuid_string};
use serde::Serialize;

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
        /// `code` or `web`.
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
        }
    }
}
