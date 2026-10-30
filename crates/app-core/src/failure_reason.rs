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
    /// Stopped by the user outside the app (LinVPN: GNOME's menu, `nmcli connection down`): no failure, it is off
    /// as after a disconnect in the app ([`USER_STOP_LINE`]).
    StoppedByUser,
    Unknown,
}

impl FailureKind {
    /// A reconnect can help (not for a refused password or certificate, nor after the user's own stop).
    pub fn worth_retrying(self) -> bool {
        !matches!(self, FailureKind::AuthFailed | FailureKind::CertificateProblem | FailureKind::StoppedByUser)
    }
}

/// LinVPN's log line when NetworkManager ended the VPN at the user's request (`USER_DISCONNECTED`) outside LinVPN:
/// `platform-linux`'s `state::reason_line(2)`. LinVPN's own disconnect writes another line.
pub const USER_STOP_LINE: &str = "NetworkManager: disconnected by the user";

/// The log's last own line (not a copied journal line `<time> [tag] …`, not an empty one) is [`USER_STOP_LINE`]: the
/// connection ended at the user's request outside the app. Only the last own line counts, so an older stop says
/// nothing once a later connect wrote its own lines.
pub fn stopped_by_user(lines: &[String]) -> bool {
    lines
        .iter()
        .rev()
        .map(|line| line.trim_end())
        .find(|line| !line.is_empty() && !journal_copy(line))
        .is_some_and(|line| line.ends_with(USER_STOP_LINE))
}

/// LinVPN's copy of a journal line: `YYYY-MM-DD HH:MM:SS [tag] text`.
fn journal_copy(line: &str) -> bool {
    let b = line.as_bytes();
    b.len() > 21 && b[4] == b'-' && b[10] == b' ' && b[13] == b':' && b[19] == b' ' && b[20] == b'['
}

/// (pattern, category), matched as substrings. Order inside one line: the first pattern wins.
const PATTERNS: &[(&str, FailureKind)] = &[
    ("AUTH_FAILED", FailureKind::AuthFailed),
    ("AUTHENTICATION_FAILED", FailureKind::AuthFailed),
    ("VERIFY ERROR", FailureKind::CertificateProblem),
    ("certificate verify failed", FailureKind::CertificateProblem),
    // sstpc (LinVPN's SSTP through NetworkManager).
    ("Verification of server certificate failed", FailureKind::CertificateProblem),
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

/// The category of the last classified line (scanning from the end); [`FailureKind::StoppedByUser`] when
/// [`stopped_by_user`].
pub fn classify(lines: &[String]) -> FailureKind {
    if stopped_by_user(lines) {
        return FailureKind::StoppedByUser;
    }
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
        FailureKind::StoppedByUser | FailureKind::Unknown => return None,
    })
}
