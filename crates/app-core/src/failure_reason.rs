//! Why a connection failed or dropped, in plain words: the last log line that matches one of a few patterns decides
//! a category; each category has one fixed sentence. The sentence never quotes the log (a notification is visible
//! on the lock screen: no server, address, user name or system message).

use macvpn_core::l10n;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    ServerNotResponding,
    ServerUnreachable,
    NameNotResolved,
    AuthFailed,
    CertificateProblem,
    NetworkLost,
    Unknown,
}

impl FailureKind {
    /// A reconnect can help (not for a refused password or certificate).
    pub fn worth_retrying(self) -> bool {
        !matches!(self, FailureKind::AuthFailed | FailureKind::CertificateProblem)
    }
}

/// (pattern, category), matched as substrings. Order inside one line: the first pattern wins.
const PATTERNS: &[(&str, FailureKind)] = &[
    ("AUTH_FAILED", FailureKind::AuthFailed),
    ("AUTHENTICATION_FAILED", FailureKind::AuthFailed),
    ("VERIFY ERROR", FailureKind::CertificateProblem),
    ("certificate verify failed", FailureKind::CertificateProblem),
    ("Cannot resolve host address", FailureKind::NameNotResolved),
    ("Inactivity timeout (--ping-restart)", FailureKind::ServerNotResponding),
    ("Inactivity timeout (--ping-exit)", FailureKind::ServerNotResponding),
    ("retransmits", FailureKind::ServerNotResponding),
    ("peer not responding", FailureKind::ServerNotResponding),
    ("TLS key negotiation failed", FailureKind::ServerUnreachable),
    ("Connection refused", FailureKind::ServerUnreachable),
    ("Connection timed out", FailureKind::ServerUnreachable),
    ("Network is unreachable", FailureKind::NetworkLost),
    ("No route to host", FailureKind::NetworkLost),
    // WinVPN's RAS log (`platform-win`'s `ras_errors::log_line`): "Windows error <code>: <Windows' text>".
    ("Windows error 691:", FailureKind::AuthFailed),
    ("Windows error 13801:", FailureKind::AuthFailed),
    ("Windows error 13806:", FailureKind::CertificateProblem),
    ("Windows error 0x800B0109:", FailureKind::CertificateProblem),
    ("Windows error 0x80092013:", FailureKind::CertificateProblem),
    ("Windows error 0x800B010F:", FailureKind::CertificateProblem),
    ("Windows error 868:", FailureKind::NameNotResolved),
    ("Windows error 800:", FailureKind::ServerUnreachable),
    ("Windows error 809:", FailureKind::ServerUnreachable),
    ("Windows error 815:", FailureKind::ServerUnreachable),
    ("Windows error 0x8007274C:", FailureKind::ServerUnreachable),
];

/// The category of the last classified line (scanning from the end).
pub fn classify(lines: &[String]) -> FailureKind {
    lines
        .iter()
        .rev()
        .find_map(|line| PATTERNS.iter().find(|(p, _)| line.contains(p)).map(|(_, k)| *k))
        .unwrap_or(FailureKind::Unknown)
}

/// The fixed sentence; `None` for `Unknown` (the caller keeps its generic text). Each arm passes a literal key, so
/// `tests/l10n_coverage.rs` checks it directly.
pub fn plain(kind: FailureKind) -> Option<String> {
    Some(match kind {
        FailureKind::ServerNotResponding => l10n::tr("The server stopped responding.", &[]),
        FailureKind::ServerUnreachable => l10n::tr("The server could not be reached.", &[]),
        FailureKind::NameNotResolved => l10n::tr("The server’s name could not be resolved.", &[]),
        FailureKind::AuthFailed => l10n::tr("The server refused the sign-in.", &[]),
        FailureKind::CertificateProblem => l10n::tr("A certificate was not accepted.", &[]),
        FailureKind::NetworkLost => l10n::tr("The network connection was lost.", &[]),
        FailureKind::Unknown => return None,
    })
}
