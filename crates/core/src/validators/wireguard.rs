//! Allowlist-based WireGuard validation (port of `WireGuardValidator`). The root layer runs it too.
//!
//! Per line: control character -> error; the comment from `#` cut off, trimmed, empty skipped; a `[...]` header
//! must be `[interface]` / `[peer]` (lower-cased), otherwise "Unknown section"; any other line without `=` is an
//! error; key = the part before the first `=`, space/tab trimmed, lower-cased, must match `^[A-Za-z]+$`
//! (otherwise a generic "Key not allowed", without quoting the key); `FORBIDDEN_KEYS` -> "Forbidden key"; what
//! is not in the section's allowlist (or outside a section) -> "Key not allowed". The value format is fixed per
//! key (`is_valid_value`), and no value may start with `-` ("Invalid value: key").

use super::sstp::{is_ipv4, is_ipv6};
use super::{ConfigValidator, control_character_message, has_control_character, matches, numbered_lines};
use crate::l10n::{self, Arg};
use crate::models::ValidationIssue;
use crate::swift_str::{self, ascii_lowercased, trim_space_tab};
use crate::target_os::TargetOs;
use std::collections::HashSet;

pub const FORBIDDEN_KEYS: [&str; 5] = ["preup", "postup", "predown", "postdown", "saveconfig"];
pub const INTERFACE_KEYS: [&str; 7] = ["privatekey", "listenport", "fwmark", "address", "dns", "mtu", "table"];
pub const PEER_KEYS: [&str; 5] = ["publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"];

#[derive(Debug, Clone, Copy, Default)]
pub struct WireGuardValidator;

impl ConfigValidator for WireGuardValidator {
    /// The checks for this OS ([`WireGuardValidator::validate_for`] with [`TargetOs::host`]).
    fn validate(&self, text: &str) -> Vec<ValidationIssue> {
        self.validate_for(TargetOs::host(), text)
    }
}

impl WireGuardValidator {
    /// The checks of [`ConfigValidator::validate`] for `os`. Windows (wireguard-nt): `FwMark` has no equivalent,
    /// `Table` only `auto` or `off`. Only lines without another issue are checked; whole-file issues (line 0)
    /// stay last.
    pub fn validate_for(&self, os: TargetOs, text: &str) -> Vec<ValidationIssue> {
        let mut issues = self.validate_common(text);
        if os == TargetOs::Windows {
            let flagged: HashSet<i64> = issues.iter().map(|i| i.line).collect();
            for (line_no, key, value) in key_values(text) {
                if flagged.contains(&line_no) {
                    continue;
                }
                let unsupported = match key.as_str() {
                    "fwmark" => true,
                    "table" => {
                        let value = ascii_lowercased(value);
                        !(swift_str::eq(&value, "auto") || swift_str::eq(&value, "off"))
                    }
                    _ => false,
                };
                if unsupported {
                    issues.push(ValidationIssue::new(
                        line_no,
                        l10n::tr("Not supported on Windows: %@", &[Arg::Str(&key)]),
                    ));
                }
            }
            issues.sort_by_key(|i| (i.line == 0, i.line));
        }
        issues
    }

    /// The platform-independent checks (the 1.4 validator).
    fn validate_common(&self, text: &str) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();
        let mut section = String::new();
        let (mut interface_count, mut peer_count) = (0, 0);
        let (mut has_private_key, mut has_peer_key) = (false, false);
        for (line_no, raw_line) in numbered_lines(text) {
            if has_control_character(raw_line) {
                issues.push(ValidationIssue::new(line_no, control_character_message()));
                continue;
            }
            let before_comment = swift_str::split(raw_line, "#", 1, false).into_iter().next().unwrap_or("");
            let line = trim_space_tab(before_comment);
            if line.is_empty() {
                continue;
            }
            if swift_str::has_prefix(line, "[") && swift_str::has_suffix(line, "]") {
                let header = ascii_lowercased(line);
                if swift_str::eq(&header, "[interface]") {
                    interface_count += 1;
                    section = "[interface]".into();
                } else if swift_str::eq(&header, "[peer]") {
                    peer_count += 1;
                    section = "[peer]".into();
                } else {
                    section = String::new();
                    issues.push(ValidationIssue::new(line_no, l10n::tr("Unknown section", &[])));
                }
                continue;
            }
            let Some(eq) = swift_str::first_index(line, "=") else {
                issues.push(ValidationIssue::new(line_no, l10n::tr("Invalid line", &[])));
                continue;
            };
            let raw_key = trim_space_tab(&line[..eq]);
            if !matches(raw_key, "^[A-Za-z]+$") {
                issues.push(ValidationIssue::new(line_no, l10n::tr("Key not allowed", &[])));
                continue;
            }
            let key = ascii_lowercased(raw_key);
            if FORBIDDEN_KEYS.contains(&key.as_str()) {
                issues.push(ValidationIssue::new(line_no, l10n::tr("Forbidden key: %@", &[Arg::Str(&key)])));
                continue;
            }
            let ok = (section == "[interface]" && INTERFACE_KEYS.contains(&key.as_str()))
                || (section == "[peer]" && PEER_KEYS.contains(&key.as_str()));
            if !ok {
                issues.push(ValidationIssue::new(line_no, l10n::tr("Key not allowed: %@", &[Arg::Str(&key)])));
                continue;
            }
            let value = trim_space_tab(&line[eq + swift_str::char_len_at(line, eq)..]);
            if !is_valid_value(&key, value) {
                issues.push(ValidationIssue::new(line_no, l10n::tr("Invalid value: %@", &[Arg::Str(&key)])));
                continue;
            }
            if section == "[interface]" && key == "privatekey" {
                has_private_key = true;
            }
            if section == "[peer]" && key == "publickey" {
                has_peer_key = true;
            }
        }
        if interface_count != 1 {
            issues.push(ValidationIssue::new(0, l10n::tr("Exactly one [Interface] section is required", &[])));
        }
        if !has_private_key && interface_count == 1 {
            issues.push(ValidationIssue::new(0, l10n::tr("Missing PrivateKey", &[])));
        }
        if peer_count < 1 || !has_peer_key {
            issues.push(ValidationIssue::new(0, l10n::tr("At least one [Peer] with a PublicKey is required", &[])));
        }
        issues
    }
}

/// `(line number, lower-cased key, trimmed value)` of the `key = value` lines (comments cut, section headers and
/// lines without `=` skipped). Whether a line is valid is [`WireGuardValidator::validate_common`]'s business.
fn key_values(text: &str) -> impl Iterator<Item = (i64, String, &str)> {
    numbered_lines(text).filter_map(|(line_no, raw_line)| {
        let before_comment = swift_str::split(raw_line, "#", 1, false).into_iter().next().unwrap_or("");
        let line = trim_space_tab(before_comment);
        if line.is_empty() || (swift_str::has_prefix(line, "[") && swift_str::has_suffix(line, "]")) {
            return None;
        }
        let eq = swift_str::first_index(line, "=")?;
        let key = ascii_lowercased(trim_space_tab(&line[..eq]));
        let value = trim_space_tab(&line[eq + swift_str::char_len_at(line, eq)..]);
        Some((line_no, key, value))
    })
}

/// The value format per key (the usual forms wg / wg-quick accept).
pub fn is_valid_value(key: &str, value: &str) -> bool {
    if value.is_empty() || swift_str::has_prefix(value, "-") {
        return false;
    }
    let list: Vec<&str> = swift_str::split(value, ",", usize::MAX, false).into_iter().map(trim_space_tab).collect();
    match key {
        "privatekey" | "publickey" | "presharedkey" => matches(value, "^[A-Za-z0-9+/]{43}=$"),
        "address" | "allowedips" => list.iter().all(|s| is_cidr(s)),
        "dns" => list.iter().all(|s| is_ip(s) || matches(s, "^[A-Za-z0-9_]([A-Za-z0-9_-]*)(\\.[A-Za-z0-9_-]+)*\\.?$")),
        "mtu" => is_number(value, 576, 9000),
        "listenport" => is_number(value, 0, 65535),
        "persistentkeepalive" => swift_str::eq(value, "off") || is_number(value, 0, 65535),
        "table" => swift_str::eq(value, "off") || swift_str::eq(value, "auto") || is_number(value, 0, u32::MAX as i64),
        "fwmark" => {
            swift_str::eq(value, "off")
                || matches(value, "^0[xX][0-9A-Fa-f]{1,8}$")
                || is_number(value, 0, u32::MAX as i64)
        }
        "endpoint" => is_endpoint(value),
        _ => false,
    }
}

pub fn is_number(s: &str, lo: i64, hi: i64) -> bool {
    matches(s, "^[0-9]{1,10}$") && s.parse::<i64>().is_ok_and(|n| (lo..=hi).contains(&n))
}

pub fn is_ip(s: &str) -> bool {
    is_ipv4(s) || is_ipv6(s)
}

/// An IPv4 or IPv6 address, with an optional `/prefix` (0–32 or 0–128).
pub fn is_cidr(s: &str) -> bool {
    let parts = swift_str::split(s, "/", usize::MAX, false);
    if parts.len() > 2 {
        return false;
    }
    let v4 = is_ipv4(parts[0]);
    if !(v4 || is_ipv6(parts[0])) {
        return false;
    }
    if parts.len() != 2 {
        return true;
    }
    is_number(parts[1], 0, if v4 { 32 } else { 128 }) && parts[1].len() <= 3
}

/// `host:port` or `[ipv6]:port`, port 1–65535.
pub fn is_endpoint(s: &str) -> bool {
    if swift_str::has_prefix(s, "[") {
        let Some(close) = swift_str::first_index(s, "]") else { return false };
        let address = &s[1..close];
        let rest = &s[close + swift_str::char_len_at(s, close)..];
        if !swift_str::has_prefix(rest, ":") {
            return false;
        }
        return is_ipv6(address) && is_number(&rest[1..], 1, 65535);
    }
    let Some(colon) = swift_str::last_index(s, ":") else { return false };
    let host = &s[..colon];
    let port = &s[colon + swift_str::char_len_at(s, colon)..];
    matches(host, "^[A-Za-z0-9_][A-Za-z0-9_.-]*$") && is_number(port, 1, 65535)
}
