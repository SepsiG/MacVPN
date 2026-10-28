//! Connection status notifications (maintainer decision 2, 2026-10-24): connected, reconnected, disconnected,
//! failed, not reconnected, could not reconnect. The texts are fixed sentences that name only the connection (the
//! lock-screen rule of [`crate::notify`]): a reason is one of the log categories of [`crate::failure_reason`] or one
//! of the manager's own fixed reasons, never a server, user name, address or log line.

use crate::failure_reason::{FailureKind, plain};
use crate::manager::{auth_cancelled_reason, auth_timeout_reason, native_failure_reason, profile_outdated_reason};
use crate::notify::{CONNECTION_KEY, NotificationContent};
use crate::reconnect::Skip;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::ConnectionState;
use macvpn_platform_api::PreferenceStore;
use std::collections::{HashMap, HashSet};

/// The Settings switch (default on). The MFA, credential and team catalog notifications do not depend on it.
pub const ENABLED_KEY: &str = "connectionNotifications";

pub fn enabled(prefs: &dyn PreferenceStore) -> bool {
    prefs.bool(ENABLED_KEY).unwrap_or(true)
}

/// One status notice. `key`: the connection's key (click routing); `name`: its display name (empty while the vault
/// is locked: the title is generic then).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    Connected {
        key: String,
        name: String,
    },
    Reconnected {
        key: String,
        name: String,
    },
    Dropped {
        key: String,
        name: String,
        reason: Option<String>,
    },
    Failed {
        key: String,
        name: String,
        reason: Option<String>,
    },
    NotReconnected {
        key: String,
        name: String,
        why: Skip,
    },
    ReconnectFailed {
        key: String,
        name: String,
        reason: Option<String>,
    },
    /// A tunnel that survived the sleep, disconnected by the app because its network (`why`) is directly reachable
    /// here. The planner does not know names: the app posts it with [`content_named`].
    DisconnectedHere {
        key: String,
        why: Skip,
    },
    /// Disconnected by the app after [`crate::reconnect::OFFLINE_GRACE`] without a network. `reconnects`: it is
    /// reconnected when the network is back ("Reconnect Automatically" on, not a lease's).
    DisconnectedNoNetwork {
        key: String,
        name: String,
        reconnects: bool,
    },
}

/// The last state seen per connection, and the connects started by auto-reconnect. "Connected" is reported only for
/// a transition from connecting / awaiting authentication, so a connection already up at launch or when the vault
/// unlocks posts nothing.
#[derive(Debug, Default)]
pub struct NoticeTracker {
    last: HashMap<String, ConnectionState>,
    auto: HashSet<String>,
}

fn is_connecting(state: &ConnectionState) -> bool {
    matches!(state, ConnectionState::Connecting | ConnectionState::AwaitingAuth(_))
}

impl NoticeTracker {
    /// The next connect of `key` was started by auto-reconnect.
    pub fn mark_auto(&mut self, key: &str) {
        self.auto.insert(key.to_string());
    }

    /// A state of a managed connection (every listener call, repeated states included).
    pub fn on_state(&mut self, key: &str, name: &str, state: &ConnectionState) -> Option<Notice> {
        let previous = self.last.insert(key.to_string(), state.clone());
        if !matches!(state, ConnectionState::Connected { .. }) {
            // The auto mark lives as long as the attempt: a failure or a disconnect ends it.
            if !is_connecting(state) {
                self.auto.remove(key);
            }
            return None;
        }
        if !previous.as_ref().is_some_and(is_connecting) {
            return None;
        }
        let (key, name) = (key.to_string(), name.to_string());
        Some(if self.auto.remove(&key) { Notice::Reconnected { key, name } } else { Notice::Connected { key, name } })
    }
}

/// The body for a failure: the log's category, else a manager reason only if it is one of its fixed texts.
pub fn reason_text(kind: FailureKind, manager_reason: Option<&str>) -> Option<String> {
    plain(kind).or_else(|| {
        let reason = manager_reason?;
        let fixed =
            [auth_timeout_reason(), auth_cancelled_reason(), native_failure_reason(), profile_outdated_reason()];
        fixed.into_iter().find(|f| f == reason)
    })
}

/// Each arm passes a literal key (checked by `tests/l10n_coverage.rs`).
fn skip_text(why: &Skip) -> String {
    match why {
        Skip::DifferentNetwork => l10n::tr("You are on a different network.", &[]),
        Skip::Unidentified => l10n::tr("The network could not be identified.", &[]),
        Skip::DirectlyReachable(_) => l10n::tr("The VPN’s network is directly reachable here.", &[]),
        Skip::DnsDirectlyReachable(_) => l10n::tr("The VPN’s DNS server is directly reachable here.", &[]),
        Skip::VaultLocked => l10n::tr("Unlock the vault to reconnect.", &[]),
    }
}

/// The body of a surviving tunnel's disconnect (a literal key per arm).
fn disconnected_here_text(why: &Skip) -> String {
    match why {
        Skip::DirectlyReachable(_) => {
            l10n::tr("The VPN’s network is directly reachable here, so it was disconnected.", &[])
        }
        Skip::DnsDirectlyReachable(_) => {
            l10n::tr("The VPN’s DNS server is directly reachable here, so it was disconnected.", &[])
        }
        // `surviving_check` gives only the two above.
        other => skip_text(other),
    }
}

/// The notice's own name (`DisconnectedHere` has none).
fn own_name(notice: &Notice) -> &str {
    match notice {
        Notice::Connected { name, .. }
        | Notice::Reconnected { name, .. }
        | Notice::Dropped { name, .. }
        | Notice::Failed { name, .. }
        | Notice::NotReconnected { name, .. }
        | Notice::ReconnectFailed { name, .. }
        | Notice::DisconnectedNoNetwork { name, .. } => name.as_str(),
        Notice::DisconnectedHere { .. } => "",
    }
}

/// The title with the connection's name, or without a name the generic text.
fn title(notice: &Notice, name: &str) -> String {
    let generic = name.trim().is_empty();
    let n = [Arg::Str(name)];
    match (notice, generic) {
        (Notice::Connected { .. }, false) => l10n::tr("%@ connected", &n),
        (Notice::Connected { .. }, true) => l10n::tr("A VPN connection connected", &[]),
        (Notice::Reconnected { .. }, false) => l10n::tr("%@ reconnected", &n),
        (Notice::Reconnected { .. }, true) => l10n::tr("A VPN connection reconnected", &[]),
        (Notice::Dropped { .. }, false) => l10n::tr("%@ disconnected", &n),
        (Notice::Dropped { .. }, true) => l10n::tr("A VPN connection dropped", &[]),
        (Notice::Failed { .. }, false) => l10n::tr("%@: connection failed", &n),
        (Notice::Failed { .. }, true) => l10n::tr("A VPN connection failed", &[]),
        (Notice::NotReconnected { .. }, false) => l10n::tr("%@ not reconnected", &n),
        (Notice::NotReconnected { .. }, true) => l10n::tr("A VPN connection was not reconnected", &[]),
        (Notice::ReconnectFailed { .. }, false) => l10n::tr("%@ could not reconnect", &n),
        (Notice::ReconnectFailed { .. }, true) => l10n::tr("A VPN connection could not reconnect", &[]),
        (Notice::DisconnectedHere { .. }, false) => l10n::tr("%@ disconnected", &n),
        (Notice::DisconnectedHere { .. }, true) => l10n::tr("A VPN connection dropped", &[]),
        (Notice::DisconnectedNoNetwork { .. }, false) => l10n::tr("%@ disconnected", &n),
        (Notice::DisconnectedNoNetwork { .. }, true) => l10n::tr("A VPN connection dropped", &[]),
    }
}

/// The notification of a notice. `unique`: a fresh identifier (every notice is its own notification).
/// `DisconnectedHere` carries no name: it gets the generic title here (the app uses [`content_named`]).
pub fn content(notice: &Notice, unique: String) -> NotificationContent {
    content_named(notice, own_name(notice), unique)
}

/// [`content`] with the connection's display name `name` in the title (empty: the generic title), for a notice
/// that does not carry one (the planner's `DisconnectedHere`).
pub fn content_named(notice: &Notice, name: &str, unique: String) -> NotificationContent {
    let log = || l10n::tr("Click to see the log.", &[]);
    let (key, body) = match notice {
        Notice::Connected { key, .. } | Notice::Reconnected { key, .. } => (key, log()),
        Notice::Dropped { key, reason, .. } | Notice::ReconnectFailed { key, reason, .. } => {
            (key, reason.clone().unwrap_or_else(log))
        }
        Notice::Failed { key, reason, .. } => {
            (key, reason.clone().unwrap_or_else(|| l10n::tr("Open MacVPN for details", &[])))
        }
        Notice::NotReconnected { key, why, .. } => (key, skip_text(why)),
        Notice::DisconnectedHere { key, why } => (key, disconnected_here_text(why)),
        Notice::DisconnectedNoNetwork { key, reconnects: true, .. } => {
            (key, l10n::tr("There was no network for 2 minutes. It reconnects when the network is back.", &[]))
        }
        Notice::DisconnectedNoNetwork { key, reconnects: false, .. } => {
            (key, l10n::tr("There was no network for 2 minutes.", &[]))
        }
    };
    NotificationContent { id: unique, title: title(notice, name), body, user_info: (CONNECTION_KEY, key.clone()) }
}
