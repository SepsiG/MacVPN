//! The Windows native VPNs (WinVPN 2c): how a MacVPN connection becomes a RAS phonebook entry. Pure: no OS call,
//! no I/O, compiled and tested on every OS.
//!
//! One function per kind turns a connection into a [`RasEntryPlan`] (strategy, server, authentication, routing,
//! the IKEv2 IPsec policy, which vault secrets the dial needs), or into [`Unsupported`]: the precise reasons
//! Windows cannot run it (the connection is kept; it still works on macOS). `winsys::ras` encodes a plan into
//! `RASENTRYW` and the phonebook keys; the `RasEngine` writes and dials it.
//!
//! A plan holds no secret: the password, the OTP code and the PSK come from the vault at dial time (`needs` says
//! which), so `Debug` shows a plan whole. The user name and the server are not secrets (as in the macOS profile).
//!
//! The types say what the entry does, not how `RASENTRYW` spells it: the flag values and the IPsec policy's
//! numbers are pinned in `winsys::ras` against the reference entries of the RAS spike (Task 2).

pub mod ikev2;
pub mod l2tp;
pub mod names;
pub mod policy;
pub mod sstp;

pub use ikev2::plan_ikev2;
pub use l2tp::{CISCO_UNSUPPORTED, plan_native};
pub use policy::WindowsPolicy;
pub use sstp::plan_sstp;

use crate::l10n::{self, Arg};
use crate::models::{Connection, VPNKind, ValidationIssue};

/// The RAS VPN strategy (`dwVpnStrategy`): one protocol only, never "automatic".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Strategy {
    /// `VS_L2tpOnly`
    L2tp,
    /// `VS_SstpOnly`
    Sstp,
    /// `VS_Ikev2Only`
    Ikev2,
}

/// How the client authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Auth {
    /// PPP MS-CHAP v2 (L2TP, SSTP); `psk`: L2TP's IPsec pre-shared key (`RASEO2_UsePreSharedKey`).
    MsChapV2 { psk: bool },
    /// IKEv2 with EAP-MSCHAPv2 (the user name and password at dial time).
    EapMsChapV2,
    /// IKEv2 with a pre-shared key (`RASEO2_UsePreSharedKeyForIkev2Initiator`). Not produced by [`plan_ikev2`]:
    /// the RAS spike (Task 2) found no entry form Windows dials with it, so `local auth = psk` is a reason; kept
    /// for a CP1 lab test that may restore it.
    Ikev2Psk,
    /// IKEv2 with a certificate from the computer's Personal store (`RASEO2_RequireMachineCertificates`).
    MachineCertificate,
}

/// Which traffic goes over the VPN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DefaultRoute {
    /// Split tunnel: the default gateway stays on the physical network.
    None,
    /// IPv4 default gateway over the VPN (`RASEO_RemoteDefaultGateway`).
    Ipv4,
    /// IPv4 and IPv6 (`RASEO_RemoteDefaultGateway` + `RASEO2_IPv6RemoteDefaultGateway`).
    Both,
}

/// The vault secrets a dial takes. `user`: the vault's user name is asked for and, when set, used instead of
/// [`RasEntryPlan::user`] (as macOS' start options override the profile's account name).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Needs {
    pub user: bool,
    pub password: bool,
    pub psk: bool,
}

/// What WinVPN writes into its private phonebook for one connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RasEntryPlan {
    pub strategy: Strategy,
    /// `szLocalPhoneNumber`: a host name or address; SSTP adds `:port` when the port is not 443 (`[v6]:port`).
    pub server: String,
    pub auth: Auth,
    pub default_route: DefaultRoute,
    /// IKEv2 split tunnel: the negotiated traffic selectors become routes (`RASEO2_PlumbIKEv2TSAsRoutes`).
    pub ts_as_routes: bool,
    /// IKEv2 fragmentation (off only with `fragmentation = no`); `false` for L2TP and SSTP.
    pub ike_fragmentation: bool,
    /// The explicit IPv4/IPv6 interface metric (`RASEO2_IPv4ExplicitMetric`): SSTP `peer_dns = no` sets 9000 so
    /// the physical adapter's DNS is preferred.
    pub interface_metric: Option<u32>,
    /// IKEv2 only: the custom IPsec policy (the phonebook's `CustomIPSecPolicies`).
    pub policy: Option<WindowsPolicy>,
    /// The user name the connection names (L2TP account, SSTP `user`, IKEv2 `eap_id`); empty when it names none.
    pub user: String,
    pub needs: Needs,
    /// Settings Windows ignores but whose purpose it covers its own way (IKEv2 `dpd_action = restart`,
    /// `start_action`): full sentences in the UI language, for the editor and the log. The connection still runs.
    pub warnings: Vec<String>,
}

/// Why WinVPN cannot make a RAS entry for a connection. Each reason is a full sentence in the UI language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported {
    pub reasons: Vec<String>,
    /// The config (or the native settings) itself is invalid: the reasons are the validator's, not Windows'
    /// limits. The editor shows those as it does on macOS.
    pub invalid_config: bool,
}

impl Unsupported {
    pub(crate) fn windows(reasons: Vec<String>) -> Unsupported {
        Unsupported { reasons, invalid_config: false }
    }

    pub(crate) fn invalid(reasons: Vec<String>) -> Unsupported {
        Unsupported { reasons, invalid_config: true }
    }

    pub(crate) fn from_issues(issues: &[ValidationIssue]) -> Unsupported {
        Unsupported::invalid(issues.iter().map(ValidationIssue::display).collect())
    }
}

impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reasons.join("\n"))
    }
}

impl std::error::Error for Unsupported {}

/// The kinds Windows runs through RAS (the `RasEngine`): L2TP, Cisco IPsec (never connects; option A), SSTP and
/// IKEv2. OpenVPN and WireGuard go through the WinVPN Service.
pub fn is_ras_kind(kind: VPNKind) -> bool {
    matches!(kind, VPNKind::L2tp | VPNKind::Cisco | VPNKind::Sstp | VPNKind::Strongswan)
}

/// The plan of any RAS kind (`config`: the connection's config file; unused for L2TP and Cisco). `None`: not a
/// RAS kind ([`is_ras_kind`]).
pub fn plan_for(connection: &Connection, config: &[u8]) -> Option<Result<RasEntryPlan, Unsupported>> {
    Some(match connection.kind {
        VPNKind::L2tp | VPNKind::Cisco => plan_native(connection),
        VPNKind::Sstp => plan_sstp(config),
        VPNKind::Strongswan => plan_ikev2(config),
        VPNKind::Openvpn | VPNKind::Wireguard => return None,
    })
}

/// The config as text (strict UTF-8, one BOM dropped, as the store loads it).
pub(crate) fn config_text(config: &[u8]) -> Result<String, Unsupported> {
    crate::swift_str::string_from_utf8_data(config.to_vec())
        .ok_or_else(|| Unsupported::invalid(vec![l10n::tr("The config is not UTF-8 text", &[])]))
}

/// The server goes into the phonebook's `PhoneNumber=` line (an INI file that RasMan parses too): a control
/// character (C0, DEL, C1, U+2028/U+2029; CR/LF would add keys to the entry's section) is refused for every kind
/// (security review L-8), as the catalog refuses it in its native fields.
pub(crate) fn server_has_control(server: &str) -> bool {
    crate::mfa::has_control(server)
}

pub(crate) fn server_control_reason() -> String {
    l10n::tr("The server address must not contain control characters", &[])
}

/// At most this many characters of a config value are quoted in a reason.
const MAX_QUOTED_CHARS: usize = 60;

/// A config value as a reason quotes it: at most [`MAX_QUOTED_CHARS`] characters, then `…`. The validated
/// config has no control characters.
pub(crate) fn quoted(value: &str) -> String {
    if value.chars().count() <= MAX_QUOTED_CHARS {
        value.to_string()
    } else {
        value.chars().take(MAX_QUOTED_CHARS).collect::<String>() + "…"
    }
}

/// `key = value` as a reason or warning quotes a setting.
pub(crate) fn setting(key: &str, value: &str) -> String {
    format!("{key} = {}", quoted(value.trim()))
}

/// "Not supported on Windows: `key = value`".
pub(crate) fn not_supported(key: &str, value: &str) -> String {
    l10n::tr("Not supported on Windows: %@", &[Arg::Str(&setting(key, value))])
}
