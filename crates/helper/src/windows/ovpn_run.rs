//! The pure parts of one `openvpn.exe` run in the WinVPN Service: what its output says ([`Output`]: the macOS
//! predicates of `shared::ovpn_log`, line by line) and when `up` stops waiting ([`Wait`]: the macOS root layer's
//! `wait_connected` rules and messages, plus the DCO incompatibility of the 2b plan). The engine (`sys/openvpn.rs`)
//! feeds them; nothing here does I/O.
//!
//! Portable (no `cfg`): tested on every OS.

use crate::shared::l10n::tr;
use crate::shared::mask::Masker;
use crate::shared::ovpn_log;
use crate::windows::ovpn_args::Driver;

/// The macOS root layer's limits: 30 s to connect, at most 420 s more while waiting for authentication.
pub const UP_TIMEOUT_SECS: u64 = 30;
pub const MFA_MAX_SECS: u64 = 420;

/// What `openvpn.exe`'s stdout and stderr said so far.
pub struct Output {
    masker: Masker,
    pub done: bool,
    pub auth_failed: bool,
    pub dco_incompatible: bool,
    last: Vec<u8>,
}

impl Output {
    /// `masker`: the connection's secrets (the last line goes into an error message).
    pub fn new(masker: Masker) -> Output {
        Output { masker, done: false, auth_failed: false, dco_incompatible: false, last: Vec::new() }
    }

    /// One line as OpenVPN wrote it (without `\n`; a `\r` before it is dropped). Returns the line for the connection
    /// log (whose sink masks it), or `None` when it must not reach the log (`log_safe`: MFA answers, management
    /// commands with secrets).
    pub fn line(&mut self, raw: &[u8]) -> Option<Vec<u8>> {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if !ovpn_log::log_safe(line) {
            return None;
        }
        // The predicates of macOS over one line (they skip `ECHO:` lines themselves).
        self.done |= ovpn_log::ovpn_done(line);
        self.auth_failed |= ovpn_log::ovpn_auth_failed(line);
        self.dco_incompatible |= ovpn_log::dco_incompatible(line);
        let last = ovpn_log::ovpn_last_line(line);
        if !last.is_empty() {
            self.last = self.masker.line(&last);
        }
        Some(line.to_vec())
    }

    /// The last non-blank real line, masked.
    pub fn last_line(&self) -> String {
        String::from_utf8_lossy(&self.last).into_owned()
    }
}

/// What the wait loop sees at one look.
pub struct Snapshot<'a> {
    pub done: bool,
    pub auth_failed: bool,
    pub dco_incompatible: bool,
    /// `openvpn.exe` has exited (and its output has been read to the end).
    pub exited: bool,
    /// The masked last line (for "openvpn exited:").
    pub last_line: &'a str,
    /// The bridge's strict `mgmt-status`.
    pub mgmt_status: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The bridge's final status: `failed`, `cancelled` or `timeout`.
    Mgmt(&'static str),
    /// OpenVPN's final `AUTH_FAILED`.
    AuthFailed,
    /// A DCO attempt hit an option DCO cannot run (pushed by the server): the engine retries once with TAP-Windows6.
    DcoIncompatible,
    /// `openvpn.exe` ended; its masked last line.
    Exited(String),
    /// The deadline passed while authentication was pending.
    AuthTimeout,
    Timeout,
}

impl Failure {
    /// The localized message `up` answers (the macOS texts).
    pub fn message(&self) -> String {
        match self {
            Failure::Mgmt("cancelled") => tr("Authentication cancelled", &[]),
            Failure::Mgmt("timeout") | Failure::AuthTimeout => tr("Timed out waiting for authentication", &[]),
            Failure::Mgmt(_) => tr("Authentication failed", &[]),
            Failure::AuthFailed => tr("Authentication failed (AUTH_FAILED)", &[]),
            Failure::DcoIncompatible => needs_driver(Driver::TapWindows6),
            Failure::Exited(last) => format!("{} {}", tr("openvpn exited:", &[]), last),
            Failure::Timeout => {
                tr("Timed out: the connection was not established within %@ s", &[&UP_TIMEOUT_SECS.to_string()])
            }
        }
    }
}

/// "This connection needs the <driver> driver. …"
pub fn needs_driver(driver: Driver) -> String {
    tr("This connection needs the %@ driver. Repair OpenVPN Community in System Status.", &[driver.name()])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Connected,
    Failed(Failure),
}

/// The deadline of one attempt (unix seconds): [`UP_TIMEOUT_SECS`] after the start, moved by the bridge's
/// `wait <t>` to `t + 15`, never past [`MFA_MAX_SECS`] more.
pub struct Wait {
    base: u64,
    deadline: u64,
    hard: u64,
    driver: Driver,
}

impl Wait {
    pub fn new(start: u64, driver: Driver) -> Wait {
        let base = start + UP_TIMEOUT_SECS;
        Wait { base, deadline: base, hard: base + MFA_MAX_SECS, driver }
    }

    /// One look (macOS' order): connected; the bridge's final status; a `wait` moving the deadline; a final
    /// `AUTH_FAILED`; a DCO incompatibility (DCO attempts only); `openvpn.exe` gone; the deadline. `None`: wait on.
    pub fn step(&mut self, now: u64, s: &Snapshot<'_>) -> Option<Verdict> {
        if s.done {
            return Some(Verdict::Connected);
        }
        match s.mgmt_status {
            Some(st @ ("failed" | "cancelled" | "timeout")) => {
                let st: &'static str = match st {
                    "failed" => "failed",
                    "cancelled" => "cancelled",
                    _ => "timeout",
                };
                return Some(Verdict::Failed(Failure::Mgmt(st)));
            }
            Some(st) => {
                if let Some(t) = st.strip_prefix("wait ").and_then(|n| n.parse::<u64>().ok()) {
                    self.deadline = self.deadline.max(t.saturating_add(15)).min(self.hard);
                }
            }
            None => {}
        }
        if s.auth_failed {
            return Some(Verdict::Failed(Failure::AuthFailed));
        }
        if s.dco_incompatible && self.driver == Driver::Dco {
            return Some(Verdict::Failed(Failure::DcoIncompatible));
        }
        if s.exited {
            return Some(Verdict::Failed(Failure::Exited(s.last_line.to_string())));
        }
        if now >= self.deadline {
            return Some(Verdict::Failed(if self.deadline > self.base {
                Failure::AuthTimeout
            } else {
                Failure::Timeout
            }));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet() -> Snapshot<'static> {
        Snapshot {
            done: false,
            auth_failed: false,
            dco_incompatible: false,
            exited: false,
            last_line: "",
            mgmt_status: None,
        }
    }

    #[test]
    fn output_lines_are_judged_like_on_macos() {
        let mut o = Output::new(Masker::new([&b"hunter2"[..]]));
        assert_eq!(
            o.line(b"2026-10-22 10:00:00 TCP connection established\r"),
            Some(b"2026-10-22 10:00:00 TCP connection established".to_vec())
        );
        // MFA answers and management commands with secrets never reach the log, nor the last line.
        assert_eq!(o.line(b"x SENT CONTROL [v]: 'CR_RESPONSE,MTEy' (status=1)"), None);
        assert_eq!(o.line(b"x MANAGEMENT: CMD 'password \"Auth\" hunter2'"), None);
        assert_eq!(o.last_line(), "2026-10-22 10:00:00 TCP connection established");
        // The last line is masked (it goes into an error message).
        o.line(b"x password was hunter2");
        assert_eq!(o.last_line(), "x password was ***");
        // A dynamic challenge is not final; an echoed completion is not completion.
        o.line(b"x AUTH_FAILED,CRV1:R:st:Ym9i:PIN");
        o.line(b"2026-10-22 10:00:01 ECHO:msg Initialization Sequence Completed");
        assert!(!o.auth_failed && !o.done);
        o.line(b"OPTIONS ERROR: pushed options are incompatible with data channel offload. Use --disable-dco");
        assert!(o.dco_incompatible);
        o.line(b"2026-10-22 10:00:02 Initialization Sequence Completed\r");
        assert!(o.done);
        o.line(b"2026 AUTH: Received control message: AUTH_FAILED");
        assert!(o.auth_failed);
    }

    #[test]
    fn the_wait_follows_the_macos_rules() {
        let mut w = Wait::new(1000, Driver::Dco);
        assert_eq!(w.step(1001, &quiet()), None);
        assert_eq!(w.step(1030, &quiet()), Some(Verdict::Failed(Failure::Timeout)));
        // A `wait` moves the deadline to t + 15 (at most 420 s more), then the timeout is the authentication's.
        let mut w = Wait::new(1000, Driver::Dco);
        let waiting = Snapshot { mgmt_status: Some("wait 1100"), ..quiet() };
        assert_eq!(w.step(1050, &waiting), None);
        assert_eq!(w.step(1114, &quiet()), None);
        assert_eq!(w.step(1115, &quiet()), Some(Verdict::Failed(Failure::AuthTimeout)));
        let mut w = Wait::new(1000, Driver::Dco);
        assert_eq!(w.step(1001, &Snapshot { mgmt_status: Some("wait 999999"), ..quiet() }), None);
        assert_eq!(w.step(1449, &quiet()), None);
        assert_eq!(w.step(1450, &quiet()), Some(Verdict::Failed(Failure::AuthTimeout)));
        // The bridge's final statuses.
        for (st, f) in [("failed", "failed"), ("cancelled", "cancelled"), ("timeout", "timeout")] {
            let s = Snapshot { mgmt_status: Some(st), ..quiet() };
            assert_eq!(Wait::new(0, Driver::Dco).step(1, &s), Some(Verdict::Failed(Failure::Mgmt(f))));
        }
        // Completion wins over everything; then the status, AUTH_FAILED, the DCO incompatibility, the exit.
        let all = Snapshot {
            done: false,
            auth_failed: true,
            dco_incompatible: true,
            exited: true,
            last_line: "bye",
            mgmt_status: None,
        };
        assert_eq!(Wait::new(0, Driver::Dco).step(1, &Snapshot { done: true, ..all }), Some(Verdict::Connected));
        let all = Snapshot { auth_failed: true, dco_incompatible: true, exited: true, last_line: "bye", ..quiet() };
        assert_eq!(Wait::new(0, Driver::Dco).step(1, &all), Some(Verdict::Failed(Failure::AuthFailed)));
        let s = Snapshot { dco_incompatible: true, exited: true, last_line: "bye", ..quiet() };
        assert_eq!(Wait::new(0, Driver::Dco).step(1, &s), Some(Verdict::Failed(Failure::DcoIncompatible)));
        // A TAP-Windows6 attempt never counts it (no second retry).
        assert_eq!(Wait::new(0, Driver::TapWindows6).step(1, &s), Some(Verdict::Failed(Failure::Exited("bye".into()))));
    }

    #[test]
    fn failures_have_the_macos_messages() {
        assert_eq!(Failure::Mgmt("failed").message(), "Authentication failed");
        assert_eq!(Failure::Mgmt("cancelled").message(), "Authentication cancelled");
        assert_eq!(Failure::Mgmt("timeout").message(), "Timed out waiting for authentication");
        assert_eq!(Failure::AuthTimeout.message(), "Timed out waiting for authentication");
        assert_eq!(Failure::AuthFailed.message(), "Authentication failed (AUTH_FAILED)");
        assert_eq!(Failure::Exited("x ***".into()).message(), "openvpn exited: x ***");
        assert_eq!(Failure::Timeout.message(), "Timed out: the connection was not established within 30 s");
        assert_eq!(
            Failure::DcoIncompatible.message(),
            "This connection needs the TAP-Windows6 driver. Repair OpenVPN Community in System Status."
        );
    }
}
