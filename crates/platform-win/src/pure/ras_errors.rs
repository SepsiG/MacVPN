//! The Windows error codes of a RAS dial (`RasDialW`, `RasGetConnectStatusW`) as WinVPN texts that say what to
//! do (EN + HU), with the administrator step that fixes some of them. Windows' own text (`RasGetErrorStringW`)
//! goes to the log only, behind a fixed "Windows error <code>:" prefix that `failure_reason::classify` (app-core)
//! recognises for the notifications' plain-words reasons.
//!
//! The sign-in failures (691; 13801 with EAP or a PSK) are exactly the root layer's sign-in messages, so
//! `credentials::is_sign_in_failure` asks for the credentials once more, as on macOS.

use macvpn_core::l10n::{self, Arg};
use macvpn_core::ras::{Auth, RasEntryPlan, Strategy, WindowsPolicy};

/// The codes WinVPN explains (raserror.h, winerror.h; Microsoft Learn, *Routing and Remote Access Error Codes*).
pub mod codes {
    /// `ERROR_PORT_DISCONNECTED`: the port was closed before the connection was made.
    pub const PORT_DISCONNECTED: u32 = 619;
    /// `ERROR_DISCONNECTION`: closed by the remote computer before it was complete.
    pub const DISCONNECTION: u32 = 628;
    /// `ERROR_USER_DISCONNECTION`: cancelled on this computer.
    pub const USER_DISCONNECTION: u32 = 631;
    /// `ERROR_AUTHENTICATION_FAILURE`.
    pub const AUTHENTICATION_FAILURE: u32 = 691;
    /// `ERROR_PPP_NO_PROTOCOLS_CONFIGURED`.
    pub const PPP_NO_PROTOCOLS_CONFIGURED: u32 = 720;
    /// `ERROR_PPP_LCP_TERMINATED`.
    pub const PPP_LCP_TERMINATED: u32 = 734;
    /// The L2TP security layer failed in the initial IPsec negotiation.
    pub const IPSEC_NEGOTIATION: u32 = 789;
    /// `ERROR_AUTOMATIC_VPN_FAILED`: no VPN tunnel could be made.
    pub const VPN_FAILED: u32 = 800;
    /// The server did not respond (blocked ports, or L2TP to a server behind NAT).
    pub const VPN_TIMEOUT: u32 = 809;
    /// A policy of the server refused the connection.
    pub const SERVER_POLICY: u32 = 812;
    /// The server did not respond.
    pub const SERVER_NOT_RESPONDING: u32 = 815;
    /// The server's name did not resolve.
    pub const NAME_NOT_RESOLVED: u32 = 868;
    /// `ERROR_IPSEC_IKE_AUTH_FAIL`: IKE authentication credentials are unacceptable.
    pub const IKE_AUTH_FAIL: u32 = 13801;
    /// `ERROR_IPSEC_IKE_NO_CERT`: no certificate for IKE.
    pub const IKE_NO_CERT: u32 = 13806;
    /// `ERROR_IPSEC_IKE_POLICY_MATCH`: no proposal matched.
    pub const IKE_POLICY_MATCH: u32 = 13868;
    /// `CERT_E_UNTRUSTEDROOT`.
    pub const CERT_E_UNTRUSTEDROOT: u32 = 0x800B_0109;
    /// `CRYPT_E_REVOCATION_OFFLINE`.
    pub const CRYPT_E_REVOCATION_OFFLINE: u32 = 0x8009_2013;
    /// `CERT_E_CN_NO_MATCH`.
    pub const CERT_E_CN_NO_MATCH: u32 = 0x800B_010F;
    /// `ERROR_PORT_NOT_OPEN`: one of the codes a dial ends with after WinVPN's own hang-up (cancelled).
    pub const PORT_NOT_OPEN: u32 = 618;
    /// `ERROR_GEN_FAILURE`: as [`PORT_NOT_OPEN`], after WinVPN's own hang-up.
    pub const GEN_FAILURE: u32 = 31;
    /// `ERROR_INVALID_PARAMETER`: an L2TP dial hung up by WinVPN ends with it (Task 2).
    pub const INVALID_PARAMETER: u32 = 87;
    /// `ERROR_PORT_NOT_AVAILABLE`: the VPN device is still in use (the previous connection is still closing).
    pub const PORT_NOT_AVAILABLE: u32 = 633;
    /// `ERROR_DIAL_ALREADY_IN_PROGRESS`.
    pub const DIAL_ALREADY_IN_PROGRESS: u32 = 756;
    /// `ERROR_NO_CERTIFICATE`: for an L2TP PSK entry, Windows has no stored PSK (Task 2).
    pub const NO_CERTIFICATE: u32 = 766;
    /// `HRESULT_FROM_WIN32(WSAETIMEDOUT)`: an SSTP server that did not answer on its port (Task 2: 21 s).
    pub const SSTP_TIMEOUT: u32 = 0x8007_274C;
    /// `E_FAIL`: unspecified (the generic text).
    pub const E_FAIL: u32 = 0x8000_4005;
}

/// A code as the dial callback or a RAS call may hand it over: HRESULTs arrive as negative `i32`
/// (`-2147014836` is `0x8007274C`). Every comparison is on the `u32`.
pub const fn code_from_i32(code: i32) -> u32 {
    code as u32
}

/// Every code [`explain`] maps to its own text.
pub const MAPPED: &[u32] = {
    use codes::*;
    &[
        PORT_DISCONNECTED,
        DISCONNECTION,
        USER_DISCONNECTION,
        AUTHENTICATION_FAILURE,
        PPP_NO_PROTOCOLS_CONFIGURED,
        PPP_LCP_TERMINATED,
        IPSEC_NEGOTIATION,
        VPN_FAILED,
        VPN_TIMEOUT,
        SERVER_POLICY,
        SERVER_NOT_RESPONDING,
        NAME_NOT_RESOLVED,
        IKE_AUTH_FAIL,
        IKE_NO_CERT,
        IKE_POLICY_MATCH,
        CERT_E_UNTRUSTEDROOT,
        CRYPT_E_REVOCATION_OFFLINE,
        CERT_E_CN_NO_MATCH,
        PORT_NOT_AVAILABLE,
        DIAL_ALREADY_IN_PROGRESS,
        NO_CERTIFICATE,
        SSTP_TIMEOUT,
    ]
};

/// What the explanation depends on: the entry's strategy and authentication, an SSTP custom CA (`cert = ca`) and
/// the IKEv2 policy WinVPN offered.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorContext {
    pub strategy: Strategy,
    pub auth: Auth,
    pub sstp_custom_ca: bool,
    pub policy: Option<WindowsPolicy>,
}

impl ErrorContext {
    pub fn for_plan(plan: &RasEntryPlan, sstp_custom_ca: bool) -> ErrorContext {
        ErrorContext {
            strategy: plan.strategy,
            auth: plan.auth,
            sstp_custom_ca: sstp_custom_ca && plan.strategy == Strategy::Sstp,
            policy: plan.policy,
        }
    }
}

/// An administrator step offered with an error (Task 12 runs it with a UAC prompt: `win::admin_steps`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAction {
    /// **Allow L2TP Behind NAT…** (`AssumeUDPEncapsulationContextOnSendRule` = 2).
    AllowL2tpBehindNat,
    /// **Trust This CA in Windows…** (the SSTP custom CA into the computer's Trusted Root store).
    TrustCaInWindows,
}

impl AdminAction {
    /// The action's id for the UI.
    pub fn id(self) -> &'static str {
        match self {
            AdminAction::AllowL2tpBehindNat => "allow-l2tp-behind-nat",
            AdminAction::TrustCaInWindows => "trust-ca-in-windows",
        }
    }

    /// The button's label (Task 12): exactly the name the error text tells the user to use (EN and HU).
    pub fn label(self) -> String {
        match self {
            AdminAction::AllowL2tpBehindNat => l10n::tr("Allow L2TP Behind NAT…", &[]),
            AdminAction::TrustCaInWindows => l10n::tr("Trust This CA in Windows…", &[]),
        }
    }
}

/// A RAS error for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RasError {
    pub code: u32,
    /// WinVPN's text (the `up` error, the card's reason); never Windows' own text.
    pub text: String,
    pub action: Option<AdminAction>,
}

/// A code as Windows writes it: an `HRESULT` (high bit set) in hexadecimal, a Win32 / RAS code in decimal.
pub fn code_label(code: u32) -> String {
    if code >= 0x8000_0000 { format!("{code:#010X}").replacen("0X", "0x", 1) } else { code.to_string() }
}

/// At most this many characters of Windows' text are logged.
const MAX_WINDOWS_TEXT: usize = 512;

/// The log line of an error: "Windows error <code>: <Windows' text>" (the prefix is fixed English, as engines'
/// log lines are, so that `failure_reason::classify` finds it in any UI language). Windows' text is untrusted:
/// control characters become spaces (one line), and it is cut at 512 characters. The engine masks the line.
pub fn log_line(code: u32, windows_text: &str) -> String {
    let text: String =
        windows_text.trim_end().chars().take(MAX_WINDOWS_TEXT).map(|c| if c.is_control() { ' ' } else { c }).collect();
    format!("Windows error {}: {text}", code_label(code))
}

/// WinVPN's explanation of a Windows error code.
pub fn explain(code: u32, context: &ErrorContext) -> RasError {
    use codes::*;
    let mut action = None;
    let text = match code {
        AUTHENTICATION_FAILURE => l10n::tr("Authentication failed (wrong user name or password)", &[]),
        IKE_AUTH_FAIL => match context.auth {
            Auth::EapMsChapV2 => l10n::tr("Authentication failed (EAP)", &[]),
            Auth::MachineCertificate => l10n::tr("The server did not accept the computer certificate.", &[]),
            Auth::Ikev2Psk | Auth::MsChapV2 { .. } => l10n::tr("Authentication failed", &[]),
        },
        // A silent L2TP server also ends with 789 (after 65 s): the text names both causes.
        IPSEC_NEGOTIATION => l10n::tr(
            "The IPsec negotiation with the server failed. Check the pre-shared key and the server’s IPsec settings, or the server did not answer (check the address and that UDP 500/4500 reach it).",
            &[],
        ),
        IKE_NO_CERT => l10n::tr(
            "No computer certificate for IKEv2 was found. An administrator must import it (see the user guide).",
            &[],
        ),
        VPN_TIMEOUT if context.strategy == Strategy::L2tp => {
            action = Some(AdminAction::AllowL2tpBehindNat);
            l10n::tr(
                "The server did not answer on the VPN ports. A firewall may block them, or the server is behind NAT: Windows allows that for L2TP/IPsec only after Allow L2TP Behind NAT… (an administrator confirms).",
                &[],
            )
        }
        VPN_TIMEOUT => l10n::tr("The server did not answer on the VPN ports. A firewall may block them.", &[]),
        SERVER_POLICY => l10n::tr(
            "The server’s policy refused the connection (for example the authentication method). Ask your VPN administrator.",
            &[],
        ),
        IKE_POLICY_MATCH => match &context.policy {
            Some(policy) => l10n::tr(
                "The server accepted none of the IPsec proposals WinVPN offered (%@).",
                &[Arg::Str(&policy.describe())],
            ),
            None => l10n::tr("The server accepted none of the IPsec proposals Windows offered.", &[]),
        },
        CERT_E_UNTRUSTEDROOT if context.sstp_custom_ca => {
            action = Some(AdminAction::TrustCaInWindows);
            l10n::tr("The server’s CA is not trusted by Windows. Use Trust This CA in Windows… in the editor.", &[])
        }
        CERT_E_UNTRUSTEDROOT => {
            l10n::tr("The server’s certificate is not issued by a CA Windows trusts. Ask your VPN administrator.", &[])
        }
        CRYPT_E_REVOCATION_OFFLINE => l10n::tr(
            "Windows could not check whether the server’s certificate was revoked (the revocation server is unreachable).",
            &[],
        ),
        CERT_E_CN_NO_MATCH => l10n::tr(
            "The server’s certificate does not match the server address. Use the name in the certificate as the server address.",
            &[],
        ),
        NAME_NOT_RESOLVED => {
            l10n::tr("The server’s name could not be resolved. Check the server address and your network’s DNS.", &[])
        }
        VPN_FAILED | SERVER_NOT_RESPONDING => {
            l10n::tr("The server did not answer. Check the server address and your network connection.", &[])
        }
        PPP_NO_PROTOCOLS_CONFIGURED | PPP_LCP_TERMINATED => l10n::tr(
            "The PPP negotiation with the server failed. Ask your VPN administrator which authentication and encryption the server needs.",
            &[],
        ),
        // A silent IKEv2 server gives 628 after 5 s.
        DISCONNECTION if context.strategy == Strategy::Ikev2 => {
            l10n::tr("The server did not answer or closed the connection.", &[])
        }
        PORT_DISCONNECTED | DISCONNECTION => l10n::tr("The server closed the connection before it was complete.", &[]),
        SSTP_TIMEOUT => l10n::tr(
            "The server did not answer on its port. Check the server address and your network connection.",
            &[],
        ),
        PORT_NOT_AVAILABLE => l10n::tr("Windows is still closing the previous connection. Try again in a moment.", &[]),
        DIAL_ALREADY_IN_PROGRESS => l10n::tr("This connection is already being dialled.", &[]),
        // Windows' text speaks of a missing computer certificate; for an L2TP PSK entry it means no stored PSK.
        NO_CERTIFICATE
            if context.strategy == Strategy::L2tp && matches!(context.auth, Auth::MsChapV2 { psk: true }) =>
        {
            l10n::tr("Windows has no pre-shared key for this connection. Save it again and reconnect.", &[])
        }
        USER_DISCONNECTION => l10n::tr("The connection was cancelled.", &[]),
        other => l10n::tr("Windows error %@ (see the log)", &[Arg::Str(&code_label(other))]),
    };
    RasError { code, text, action }
}
