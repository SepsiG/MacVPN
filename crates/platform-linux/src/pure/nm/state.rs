//! NetworkManager's states (`NMActiveConnectionState`, `NMVpnConnectionState`) and the VPN state reasons.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveState {
    Unknown,
    Activating,
    Activated,
    Deactivating,
    Deactivated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnState {
    Unknown,
    Prepare,
    NeedAuth,
    Connect,
    IpConfigGet,
    Activated,
    Failed,
    Disconnected,
}

impl ActiveState {
    /// `NMActiveConnectionState`.
    pub fn from_u32(v: u32) -> ActiveState {
        match v {
            1 => ActiveState::Activating,
            2 => ActiveState::Activated,
            3 => ActiveState::Deactivating,
            4 => ActiveState::Deactivated,
            _ => ActiveState::Unknown,
        }
    }
}

impl VpnState {
    /// `NMVpnConnectionState`.
    pub fn from_u32(v: u32) -> VpnState {
        match v {
            1 => VpnState::Prepare,
            2 => VpnState::NeedAuth,
            3 => VpnState::Connect,
            4 => VpnState::IpConfigGet,
            5 => VpnState::Activated,
            6 => VpnState::Failed,
            7 => VpnState::Disconnected,
            _ => VpnState::Unknown,
        }
    }
}

/// The `RootStatus::state` of a LinVPN tunnel: `"connected"`, `"connecting"`, or `None` (down: not reported).
/// WireGuard (no VPN state) is connected when its active connection is; a VPN only when its VPN state is too.
pub fn root_state(active: ActiveState, vpn: Option<VpnState>) -> Option<&'static str> {
    if matches!(vpn, Some(VpnState::Failed | VpnState::Disconnected)) {
        return None;
    }
    match (active, vpn) {
        (ActiveState::Activated, None | Some(VpnState::Activated)) => Some("connected"),
        (ActiveState::Activated | ActiveState::Activating, _) => Some("connecting"),
        (ActiveState::Deactivating | ActiveState::Deactivated | ActiveState::Unknown, _) => None,
    }
}

/// The log line of LinVPN's own disconnect (and of a run gone without a reason, reason 11).
pub const STOPPED_LINE: &str = "NetworkManager: disconnected";

/// The log line for a VPN state reason (`NMVpnConnectionStateReason`, whose numbers are the first twelve of
/// `NMActiveConnectionStateReason`; NM 1.54), with the words app-core's `failure_reason` matches (resolved
/// point 11). Log lines, not UI texts: English only. Reason 2 (`USER_DISCONNECTED`) reaches a run only when the user
/// stopped it outside LinVPN (GNOME's menu, `nmcli connection down`; LinVPN's own stop ends the run first and logs
/// [`STOPPED_LINE`]): app-core's `failure_reason::USER_STOP_LINE`, a stop of the user's, not a drop (audit C1).
pub fn reason_line(reason: u32) -> &'static str {
    match reason {
        2 => "NetworkManager: disconnected by the user",
        11 => STOPPED_LINE,
        4 => "NetworkManager: the VPN plugin did not start (service-stopped)",
        6 => "Connection timed out (NetworkManager)",
        7 => "NetworkManager: the VPN plugin did not start (service-start-timeout)",
        8 => "NetworkManager: the VPN plugin did not start (service-start-failed)",
        9 => "AUTH_FAILED: no secrets were given (NetworkManager)",
        10 => "AUTH_FAILED: the server refused the login (NetworkManager)",
        0 => "NetworkManager: the VPN failed (reason 0)",
        1 => "NetworkManager: the VPN failed (reason 1)",
        3 => "NetworkManager: the VPN failed (reason 3)",
        5 => "NetworkManager: the VPN failed (reason 5)",
        12 => "NetworkManager: the VPN failed (reason 12)",
        13 => "NetworkManager: the VPN failed (reason 13)",
        14 => "NetworkManager: the VPN failed (reason 14)",
        _ => "NetworkManager: the VPN failed (unknown reason)",
    }
}
