//! The OpenVPN log predicates: which lines of OpenVPN's own log may reach the user's log, and what they say
//! (connected, a final authentication failure, the last line). Pure; the backends read the logs.

use crate::shared::mask;
use regex::bytes::Regex;
use std::sync::LazyLock;

/// The bash `log_safe`: lines that may carry an MFA code never reach the user's log. `CR_RESPONSE,` lines are
/// dropped, and of the `MANAGEMENT: CMD '…'` lines only `state`, `hold` and `version` are kept.
pub fn log_safe(line: &[u8]) -> bool {
    if mask::find(line, b"CR_RESPONSE,").is_some() {
        return false;
    }
    const CMD: &[u8] = b"MANAGEMENT: CMD '";
    match mask::find(line, CMD) {
        None => true,
        Some(p) => management_kept(&line[p + CMD.len()..]),
    }
}

/// `^(state|hold|version)( [^']*)?'`
fn management_kept(rest: &[u8]) -> bool {
    for word in [&b"state"[..], b"hold", b"version"] {
        if let Some(after) = rest.strip_prefix(word) {
            if after.first() == Some(&b'\'') {
                return true;
            }
            if after.first() == Some(&b' ') && after.contains(&b'\'') {
                return true;
            }
        }
    }
    false
}

pub(crate) static ECHO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?-u)(^|[ :])ECHO(-PULL)?:").expect("valid"));

/// The anchored completion line: a timestamp (plain, with ` us=` above verb 4, or `--machine-readable-output`), then
/// exactly `Initialization Sequence Completed` (possibly `With Errors …`).
pub const OVPN_DONE_RE: &str = r"^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}( us=[0-9]+)? |[0-9]+[.][0-9]+ [0-9A-Fa-f]+ )?Initialization Sequence Completed( With Errors.*)?$";

pub(crate) static DONE: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!("(?-u){OVPN_DONE_RE}")).expect("valid"));
pub(crate) static AUTH_NOT_FINAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?-u)AUTH_FAILED,(CRV1:|TEMP)").expect("valid"));

/// `ovpn_log_real`: OpenVPN's own lines (no `ECHO:` / `ECHO-PULL:`), through [`log_safe`].
pub fn ovpn_real_lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    mask::lines(data).filter(|l| !ECHO.is_match(l) && log_safe(l))
}

/// The root-only openvpn.log says the connection is up.
pub fn ovpn_done(data: &[u8]) -> bool {
    ovpn_real_lines(data).any(|l| DONE.is_match(l))
}

/// OpenVPN's own line that a pushed option cannot run with DCO (OpenVPN 2.7.8, the same wording as 2.6.23: `comp.c`
/// `check_compression_settings_valid`, `init.c` after `dco_check_pull_options`, `ssl.c` `init_key_ctx_bi`). The
/// WinVPN Service retries a DCO attempt once with TAP-Windows6 when its log has one (Task 13). Startup notes ("… disables
/// data channel offload") do not count: OpenVPN then falls back to TAP-Windows6 itself.
pub fn dco_incompatible(line: &[u8]) -> bool {
    const LINES: [&[u8]; 3] = [
        b"Compression or compression stub framing is not allowed since data-channel offloading is enabled",
        b"OPTIONS ERROR: pushed options are incompatible with data channel offload",
        b"FATAL: DCO does not support",
    ];
    !ECHO.is_match(line) && LINES.iter().any(|m| mask::find(line, m).is_some())
}

/// A final `AUTH_FAILED` (not `AUTH_FAILED,CRV1:` – a dynamic challenge – and not `AUTH_FAILED,TEMP`).
pub fn ovpn_auth_failed(data: &[u8]) -> bool {
    ovpn_real_lines(data).any(|l| mask::find(l, b"AUTH_FAILED").is_some() && !AUTH_NOT_FINAL.is_match(l))
}

/// The last non-blank real line (for the "openvpn exited:" message).
pub fn ovpn_last_line(data: &[u8]) -> Vec<u8> {
    ovpn_real_lines(data).filter(|l| !is_blank(l)).last().map(<[u8]>::to_vec).unwrap_or_default()
}

/// `[Pp][Aa][Ss][Ss]|[Aa][Uu][Tt][Hh]`
pub fn mentions_secret(line: &[u8]) -> bool {
    let lower = line.to_ascii_lowercase();
    mask::find(&lower, b"pass").is_some() || mask::find(&lower, b"auth").is_some()
}

/// A line of only ASCII white space (bash `[[:space:]]`).
pub fn is_blank(l: &[u8]) -> bool {
    l.iter().all(|&b| matches!(b, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_pattern() {
        for l in [
            "2026-10-18 15:22:48 Initialization Sequence Completed",
            "2026-10-18 15:42:51 us=411817 Initialization Sequence Completed",
            "Initialization Sequence Completed",
            "1792330971.453131 32000004 Initialization Sequence Completed",
            "2026-10-18 15:42:51 us=5 Initialization Sequence Completed With Errors ( see http://openvpn.net/faq.html#dhcpclientserv )",
        ] {
            assert!(ovpn_done(l.as_bytes()), "{l}");
        }
        for l in [
            "2026-10-18 15:22:48 ECHO:msg x Initialization Sequence Completed",
            "2026-10-18 15:22:48 PUSH: Received control message: 'PUSH_REPLY,echo msg Initialization Sequence Completed'",
            "2026-10-18 15:22:48 us=abc Initialization Sequence Completed",
            "2026-10-17 00:00:00 ECHO:msg Initialization Sequence Completed",
            "2026-10-17 00:00:02 ECHO-PULL:msg Initialization Sequence Completed",
            "Initialization Sequence Completed\r",
        ] {
            assert!(!ovpn_done(l.as_bytes()), "{l}");
        }
    }

    #[test]
    fn management_lines_filtered() {
        assert!(log_safe(b"x MANAGEMENT: CMD 'state on'"));
        assert!(log_safe(b"x MANAGEMENT: CMD 'hold release'"));
        assert!(log_safe(b"x MANAGEMENT: CMD 'version 3'"));
        assert!(log_safe(b"x MANAGEMENT: CMD 'state'"));
        assert!(!log_safe(b"x MANAGEMENT: CMD 'statex'"));
        assert!(!log_safe(b"x MANAGEMENT: CMD 'username \"Auth\" bob'"));
        assert!(!log_safe(b"x MANAGEMENT: CMD 'cr-response MTEy'"));
        assert!(!log_safe(b"x MANAGEMENT: CMD 'state on"));
        assert!(!log_safe(b"x SENT CONTROL [v]: 'CR_RESPONSE,MTEy' (status=1)"));
        assert!(log_safe(b"plain line"));
    }

    #[test]
    fn auth_failed_rules() {
        assert!(ovpn_auth_failed(b"2026 AUTH: Received control message: AUTH_FAILED\n"));
        assert!(!ovpn_auth_failed(b"x AUTH_FAILED,CRV1:R:st:Ym9i:PIN\n"));
        assert!(!ovpn_auth_failed(b"x AUTH_FAILED,TEMP[backoff 2]:busy\n"));
        assert!(!ovpn_auth_failed(b"2026 ECHO:msg AUTH_FAILED\n"));
    }

    #[test]
    fn last_line_skips_blank_and_filtered() {
        let data = b"2026 KEEPLINE\n2026 MANAGEMENT: CMD 'cr-response MTEy'\n  \n";
        assert_eq!(ovpn_last_line(data), b"2026 KEEPLINE".to_vec());
    }

    #[test]
    fn secret_like_lines() {
        assert!(mentions_secret(b"x Password: y"));
        assert!(mentions_secret(b"AUTH: x"));
        assert!(mentions_secret(b"passwd"));
        assert!(!mentions_secret(b"KEEPMARKER"));
    }
}
