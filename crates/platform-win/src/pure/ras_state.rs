//! A RAS connection's life without the Win32 calls (WinVPN 2c): the dial events the `RasEngine` sees (the
//! `RasDialW` callback, `RASCN_Disconnection`, a hang-up WinVPN asked for) become a [`DialState`], the masked
//! log's lines and, for a failure, the mapped error ([`super::ras_errors`]). The state answers as the root layer's
//! status (`RootStatus`, for IKEv2 and SSTP behind the `HelperClient`) and as a `SystemVpn.status` (L2TP and the
//! managed entries behind the `NativeController`).

use super::ras_errors::{self, ErrorContext, RasError};
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::VPNKind;
use macvpn_core::status::RootStatus;
use uuid::Uuid;

/// `RASCONNSTATE` (ras.h, Microsoft Learn): the values Windows documents.
pub mod rascs {
    pub const OPEN_PORT: u32 = 0;
    pub const PORT_OPENED: u32 = 1;
    pub const CONNECT_DEVICE: u32 = 2;
    pub const DEVICE_CONNECTED: u32 = 3;
    pub const ALL_DEVICES_CONNECTED: u32 = 4;
    pub const AUTHENTICATE: u32 = 5;
    pub const AUTH_NOTIFY: u32 = 6;
    pub const AUTH_RETRY: u32 = 7;
    pub const AUTH_CALLBACK: u32 = 8;
    pub const AUTH_CHANGE_PASSWORD: u32 = 9;
    pub const AUTH_PROJECT: u32 = 10;
    pub const AUTH_LINK_SPEED: u32 = 11;
    pub const AUTH_ACK: u32 = 12;
    pub const RE_AUTHENTICATE: u32 = 13;
    pub const AUTHENTICATED: u32 = 14;
    pub const PREPARE_FOR_CALLBACK: u32 = 15;
    pub const WAIT_FOR_MODEM_RESET: u32 = 16;
    pub const WAIT_FOR_CALLBACK: u32 = 17;
    pub const PROJECTED: u32 = 18;
    pub const START_AUTHENTICATION: u32 = 19;
    pub const CALLBACK_COMPLETE: u32 = 20;
    pub const LOGON_NETWORK: u32 = 21;
    pub const SUB_ENTRY_CONNECTED: u32 = 22;
    pub const SUB_ENTRY_DISCONNECTED: u32 = 23;
    pub const APPLY_SETTINGS: u32 = 24;
    /// `RASCS_PAUSED` + 0.
    pub const INTERACTIVE: u32 = 0x1000;
    pub const RETRY_AUTHENTICATION: u32 = 0x1001;
    pub const CALLBACK_SET_BY_CALLER: u32 = 0x1002;
    pub const PASSWORD_EXPIRED: u32 = 0x1003;
    pub const INVOKE_EAP_UI: u32 = 0x1004;
    /// `RASCS_DONE` + 0.
    pub const CONNECTED: u32 = 0x2000;
    pub const DISCONNECTED: u32 = 0x2001;

    /// Every documented value, in order.
    pub const ALL: &[u32] = &[
        OPEN_PORT,
        PORT_OPENED,
        CONNECT_DEVICE,
        DEVICE_CONNECTED,
        ALL_DEVICES_CONNECTED,
        AUTHENTICATE,
        AUTH_NOTIFY,
        AUTH_RETRY,
        AUTH_CALLBACK,
        AUTH_CHANGE_PASSWORD,
        AUTH_PROJECT,
        AUTH_LINK_SPEED,
        AUTH_ACK,
        RE_AUTHENTICATE,
        AUTHENTICATED,
        PREPARE_FOR_CALLBACK,
        WAIT_FOR_MODEM_RESET,
        WAIT_FOR_CALLBACK,
        PROJECTED,
        START_AUTHENTICATION,
        CALLBACK_COMPLETE,
        LOGON_NETWORK,
        SUB_ENTRY_CONNECTED,
        SUB_ENTRY_DISCONNECTED,
        APPLY_SETTINGS,
        INTERACTIVE,
        RETRY_AUTHENTICATION,
        CALLBACK_SET_BY_CALLER,
        PASSWORD_EXPIRED,
        INVOKE_EAP_UI,
        CONNECTED,
        DISCONNECTED,
    ];
}

/// The log line of one `RASCONNSTATE` (`server`: the entry's server, as the plan has it). An undocumented value
/// gives "RAS state <n>" (hexadecimal from `RASCS_PAUSED` on).
pub fn state_line(state: u32, server: &str) -> String {
    use rascs::*;
    let callback = |name: &str| l10n::tr("Callback step (not used by VPNs): %@", &[Arg::Str(name)]);
    match state {
        OPEN_PORT => l10n::tr("Opening port…", &[]),
        PORT_OPENED => l10n::tr("Port opened", &[]),
        CONNECT_DEVICE => l10n::tr("Connecting to %@…", &[Arg::Str(server)]),
        DEVICE_CONNECTED => l10n::tr("Server reached: %@", &[Arg::Str(server)]),
        ALL_DEVICES_CONNECTED => l10n::tr("Link established", &[]),
        AUTHENTICATE | START_AUTHENTICATION => l10n::tr("Authenticating…", &[]),
        AUTH_NOTIFY => l10n::tr("Authentication status received", &[]),
        AUTH_RETRY | RETRY_AUTHENTICATION => l10n::tr("Retrying authentication…", &[]),
        AUTH_CALLBACK => callback("RASCS_AuthCallback"),
        AUTH_CHANGE_PASSWORD => l10n::tr("The server asks for a new password", &[]),
        AUTH_PROJECT => l10n::tr("Projecting (IP configuration)…", &[]),
        AUTH_LINK_SPEED => l10n::tr("Measuring link speed…", &[]),
        AUTH_ACK => l10n::tr("Authentication acknowledged", &[]),
        RE_AUTHENTICATE => l10n::tr("Authenticating again…", &[]),
        AUTHENTICATED => l10n::tr("Authenticated", &[]),
        PREPARE_FOR_CALLBACK => callback("RASCS_PrepareForCallback"),
        WAIT_FOR_MODEM_RESET => callback("RASCS_WaitForModemReset"),
        WAIT_FOR_CALLBACK => callback("RASCS_WaitForCallback"),
        PROJECTED => l10n::tr("IP configuration done", &[]),
        CALLBACK_COMPLETE => callback("RASCS_CallbackComplete"),
        LOGON_NETWORK => l10n::tr("Signing in to the network…", &[]),
        SUB_ENTRY_CONNECTED => l10n::tr("Sub-entry connected", &[]),
        SUB_ENTRY_DISCONNECTED => l10n::tr("Sub-entry disconnected", &[]),
        APPLY_SETTINGS => l10n::tr("Applying settings…", &[]),
        INTERACTIVE => l10n::tr("Waiting for terminal input (not used by VPNs)", &[]),
        CALLBACK_SET_BY_CALLER => callback("RASCS_CallbackSetByCaller"),
        PASSWORD_EXPIRED => l10n::tr("The password has expired", &[]),
        INVOKE_EAP_UI => l10n::tr("Windows asks for EAP input", &[]),
        CONNECTED => l10n::tr("Connected", &[]),
        DISCONNECTED => l10n::tr("Disconnected", &[]),
        other => {
            let value = if other >= INTERACTIVE { format!("{other:#x}") } else { other.to_string() };
            l10n::tr("RAS state %@", &[Arg::Str(&value)])
        }
    }
}

/// Where one RAS connection is. Times are Unix seconds.
#[derive(Debug, Clone, PartialEq)]
pub enum DialState {
    Idle,
    /// `step`: the last `RASCONNSTATE` the dial reported.
    Dialling {
        step: u32,
    },
    Connected {
        ipv4: Option<String>,
        since: f64,
    },
    /// WinVPN asked for the hang-up and waits for it.
    HangingUp,
    /// The dial (or the connection) ended with Windows error `code`.
    Failed {
        code: u32,
        at: f64,
    },
}

impl DialState {
    /// The root layer's status of an IKEv2 or SSTP connection (`kind`): `None` when there is nothing to report
    /// (idle, or hanging up: the manager shows its own "Disconnecting" while `down` runs).
    pub fn root_status(&self, id: Uuid, kind: VPNKind) -> Option<RootStatus> {
        let (state, ip, since) = match self {
            DialState::Idle | DialState::HangingUp => return None,
            DialState::Dialling { .. } => ("connecting", None, None),
            DialState::Connected { ipv4, since } => ("connected", ipv4.clone(), Some(*since)),
            DialState::Failed { .. } => ("failed", None, None),
        };
        Some(RootStatus { id, kind: kind.raw_value().to_string(), state: state.to_string(), iface: None, ip, since })
    }

    /// `SystemVpn.status`: `Connecting`, `Connected`, `Disconnecting` or `Disconnected`.
    pub fn system_status(&self) -> &'static str {
        match self {
            DialState::Idle | DialState::Failed { .. } => "Disconnected",
            DialState::Dialling { .. } => "Connecting",
            DialState::Connected { .. } => "Connected",
            DialState::HangingUp => "Disconnecting",
        }
    }
}

/// What the `RasEngine` observed.
#[derive(Debug, Clone, PartialEq)]
pub enum DialEvent {
    /// `RasDialW` was called.
    Started,
    /// The dial callback's `RASCONNSTATE` (`RASCS_Connected` is reported as [`DialEvent::Connected`], with the
    /// address from `RasGetProjectionInfoEx`; `RASCS_Disconnected` ends the connection like [`DialEvent::Ended`]).
    Step(u32),
    Connected {
        ipv4: Option<String>,
        at: f64,
    },
    /// The dial callback's or `RasGetConnectStatusW`'s error; `windows_text`: `RasGetErrorStringW` (untrusted, in
    /// Windows' display language; for the log only).
    Error {
        code: u32,
        at: f64,
        windows_text: String,
    },
    /// WinVPN calls `RasHangUpW` (the user's disconnect, quit, logoff).
    HangUp,
    /// The connection is gone (`RASCN_Disconnection`, or the hang-up completed).
    Ended,
}

/// One connection's dial: its state and what each event writes to its log (unmasked: the engine passes every
/// line through [`super::ras_log::LogMasker`]).
#[derive(Debug, Clone)]
pub struct Dial {
    state: DialState,
    server: String,
    context: ErrorContext,
    asked_hang_up: bool,
}

impl Dial {
    pub fn new(server: &str, context: ErrorContext) -> Dial {
        Dial { state: DialState::Idle, server: server.to_string(), context, asked_hang_up: false }
    }

    pub fn state(&self) -> &DialState {
        &self.state
    }

    /// The mapped error of a failed dial (the `up` error and the card's reason); `None` otherwise.
    pub fn failure(&self) -> Option<RasError> {
        match self.state {
            DialState::Failed { code, .. } => Some(ras_errors::explain(code, &self.context)),
            _ => None,
        }
    }

    /// Applies one event; returns the log lines it writes.
    pub fn apply(&mut self, event: DialEvent) -> Vec<String> {
        match event {
            DialEvent::Started => {
                self.asked_hang_up = false;
                self.state = DialState::Dialling { step: rascs::OPEN_PORT };
                Vec::new()
            }
            DialEvent::Step(rascs::CONNECTED) => Vec::new(),
            DialEvent::Step(rascs::DISCONNECTED) => self.apply(DialEvent::Ended),
            DialEvent::Step(step) => {
                if matches!(self.state, DialState::Dialling { .. }) {
                    self.state = DialState::Dialling { step };
                }
                vec![state_line(step, &self.server)]
            }
            DialEvent::Connected { ipv4, at } => {
                let line = match &ipv4 {
                    Some(ip) => l10n::tr("Connected, IPv4 %@", &[Arg::Str(ip)]),
                    None => l10n::tr("Connected", &[]),
                };
                self.state = DialState::Connected { ipv4, since: at };
                vec![line]
            }
            DialEvent::Error { code, at, windows_text } => {
                if self.asked_hang_up {
                    // The cancelled dial's own error (631 and the like): the hang-up decides.
                    return Vec::new();
                }
                self.state = DialState::Failed { code, at };
                vec![ras_errors::log_line(code, &windows_text), ras_errors::explain(code, &self.context).text]
            }
            DialEvent::HangUp => {
                self.asked_hang_up = true;
                self.state = DialState::HangingUp;
                vec![l10n::tr("Disconnecting…", &[])]
            }
            DialEvent::Ended => match self.state {
                DialState::Failed { .. } | DialState::Idle => Vec::new(),
                _ if self.asked_hang_up => {
                    self.state = DialState::Idle;
                    vec![l10n::tr("Disconnected", &[])]
                }
                _ => {
                    // Not asked for: the server or the network closed it. A drop is "disconnected", as macOS'
                    // native VPNs (the manager's `native_like` rule), and is said so in the log.
                    self.state = DialState::Idle;
                    vec![l10n::tr("The connection was closed (by the server or the network).", &[])]
                }
            },
        }
    }
}
