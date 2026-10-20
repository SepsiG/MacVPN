//! SSTP config and validation (port of `SSTP.swift`).
//!
//! The config (`config` file, `.sstp` export/import) is `key=value` per line with an optional `<ca>…</ca>` PEM
//! block. No password in it (Keychain; `mvpn` gets it on stdin).
//!
//! ```text
//! server=vpn.example.com
//! port=443
//! user=alice
//! cert=system            # system | ca | insecure
//! route_all=yes          # yes | no
//! peer_dns=yes           # yes | no
//! <ca>
//! -----BEGIN CERTIFICATE-----
//! …
//! -----END CERTIFICATE-----
//! </ca>
//! ```

use super::{ConfigValidator, control_character_message, has_control_character, matches, numbered_lines};
use crate::l10n::{self, Arg};
use crate::models::ValidationIssue;
use crate::swift_str::{self, ascii_lowercased, trim_space_tab};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CertMode {
    /// sstpc's default CA store (the Homebrew OpenSSL / ca-certificates package).
    #[default]
    System,
    /// Own CA PEM, stored inline in the config (`<ca>` block).
    Ca,
    /// No certificate verification (`sstpc --cert-warn`).
    Insecure,
}

impl CertMode {
    pub const ALL: [CertMode; 3] = [CertMode::System, CertMode::Ca, CertMode::Insecure];

    pub fn raw_value(self) -> &'static str {
        match self {
            CertMode::System => "system",
            CertMode::Ca => "ca",
            CertMode::Insecure => "insecure",
        }
    }

    pub fn from_raw_value(raw: &str) -> Option<CertMode> {
        CertMode::ALL.into_iter().find(|m| swift_str::eq(m.raw_value(), raw))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SSTPConfig {
    pub server: String,
    pub port: i64,
    pub user: String,
    pub cert: CertMode,
    pub route_all: bool,
    pub peer_dns: bool,
    /// PEM text (`-----BEGIN CERTIFICATE-----` …), without a trailing `\n`. In the config only with `cert == Ca`.
    pub ca_pem: String,
}

pub const DEFAULT_PORT: i64 = 443;

impl Default for SSTPConfig {
    fn default() -> Self {
        SSTPConfig {
            server: String::new(),
            port: DEFAULT_PORT,
            user: String::new(),
            cert: CertMode::System,
            route_all: true,
            peer_dns: true,
            ca_pem: String::new(),
        }
    }
}

/// Foundation `CharacterSet.newlines`.
fn is_newline(c: char) -> bool {
    matches!(c, '\u{A}'..='\u{D}' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

impl SSTPConfig {
    /// Lenient parsing for the form: unknown or bad lines are skipped (the validator decides on save).
    pub fn parse(text: &str) -> SSTPConfig {
        let mut c = SSTPConfig::default();
        let mut in_ca = false;
        let mut ca: Vec<&str> = Vec::new();
        for (_, line) in numbered_lines(text) {
            let trimmed = trim_space_tab(line);
            if in_ca {
                if swift_str::eq(trimmed, "</ca>") {
                    in_ca = false;
                } else {
                    ca.push(trimmed);
                }
                continue;
            }
            if swift_str::eq(trimmed, "<ca>") {
                in_ca = true;
                continue;
            }
            if swift_str::has_prefix(trimmed, "#") {
                continue;
            }
            let Some(eq) = swift_str::first_index(trimmed, "=") else { continue };
            let key = ascii_lowercased(trim_space_tab(&trimmed[..eq]));
            let value = trim_space_tab(&trimmed[eq + swift_str::char_len_at(trimmed, eq)..]);
            match key.as_str() {
                "server" => c.server = value.to_string(),
                "port" => c.port = value.parse::<i64>().unwrap_or(DEFAULT_PORT),
                "user" => c.user = value.to_string(),
                "cert" => c.cert = CertMode::from_raw_value(value).unwrap_or(CertMode::System),
                "route_all" => c.route_all = !swift_str::eq(value, "no"),
                "peer_dns" => c.peer_dns = !swift_str::eq(value, "no"),
                _ => {}
            }
        }
        c.ca_pem = ca.join("\n").trim_matches(is_newline).to_string();
        c
    }

    /// The config text. The `<ca>` block only with `cert == Ca`.
    pub fn serialized(&self) -> String {
        let mut lines = vec![
            format!("server={}", self.server),
            format!("port={}", self.port),
            format!("user={}", self.user),
            format!("cert={}", self.cert.raw_value()),
            format!("route_all={}", if self.route_all { "yes" } else { "no" }),
            format!("peer_dns={}", if self.peer_dns { "yes" } else { "no" }),
        ];
        let pem = self.ca_pem.trim_matches(swift_str::is_foundation_whitespace_or_newline);
        if self.cert == CertMode::Ca && !pem.is_empty() {
            lines.push("<ca>".into());
            lines.push(pem.to_string());
            lines.push("</ca>".into());
        }
        lines.join("\n") + "\n"
    }

    /// All `-----BEGIN CERTIFICATE-----` … `-----END CERTIFICATE-----` blocks of the file (without the text between
    /// them, e.g. `subject=` lines), trailing spaces and CR cut. `None` if there is no certificate, or a block has
    /// a non-PEM character.
    pub fn extract_certificates(text: &str) -> Option<String> {
        let mut blocks: Vec<String> = Vec::new();
        let mut current: Option<Vec<&str>> = None;
        for (_, raw) in numbered_lines(text) {
            let line = trim_space_tab(raw);
            if swift_str::eq(line, "-----BEGIN CERTIFICATE-----") {
                current = Some(vec![line]);
                continue;
            }
            let Some(block) = current.as_mut() else { continue };
            if !matches(line, PEM_LINE_PATTERN) {
                return None;
            }
            block.push(line);
            if swift_str::eq(line, "-----END CERTIFICATE-----") {
                blocks.push(block.join("\n"));
                current = None;
            }
        }
        if blocks.is_empty() { None } else { Some(blocks.join("\n")) }
    }

    /// The number of certificates in the PEM text (`components(separatedBy:).count - 1`). Foundation's search
    /// only counts a match that starts and ends on a grapheme cluster boundary (not after a Prepend character,
    /// not before a combining mark).
    pub fn certificate_count(pem: &str) -> usize {
        const MARKER: &str = "-----BEGIN CERTIFICATE-----";
        let mut count = 0;
        let mut from = 0;
        while let Some(i) = pem[from..].find(MARKER).map(|i| i + from) {
            let end = i + MARKER.len();
            if swift_str::is_boundary(pem, i) && swift_str::is_boundary(pem, end) {
                count += 1;
                from = end;
            } else {
                from = i + 1;
            }
        }
        count
    }

    /// Whether the SSTP password is acceptable. The brew sstpc writes the password unescaped into pppd's option
    /// file (`password "%s"`), which pppd reads as root: a `"`, `\` or control character (line end too) could
    /// inject a pppd option. These are rejected, not escaped (`mvpn` does the same on the root side). An empty
    /// password is fine here (not required on save; `mvpn` asks for it when connecting).
    pub fn is_acceptable_password(s: &str) -> bool {
        !s.chars().any(|c| {
            let v = c as u32;
            c == '"' || c == '\\' || v < 0x20 || v == 0x7F || (0x80..=0x9F).contains(&v)
        })
    }

    /// The password rule message (`mvpn` prints the same in English / Hungarian).
    pub fn password_rule_message() -> String {
        l10n::tr("The SSTP password must not contain quotation marks, backslashes or control characters", &[])
    }
}

pub const ALLOWED_KEYS: [&str; 6] = ["server", "port", "user", "cert", "route_all", "peer_dns"];
const HOSTNAME_PATTERN: &str = "^[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}))*\\.?$";
const USER_PATTERN: &str = "^[A-Za-z0-9._@+][A-Za-z0-9._@+-]{0,127}$";
pub(crate) const PEM_LINE_PATTERN: &str = "^[A-Za-z0-9+/= -]*$";

/// Allowlist-based SSTP validation. The root layer runs it too (and before `--sstp-params` / `--sstp-ca`).
///
/// Per line (one trailing CR dropped): control character (except TAB) -> error; any `\` -> error. Inside the
/// `<ca>` block: the trimmed `</ca>` closes it; every other line may only have PEM characters (`[A-Za-z0-9+/= -]`).
/// Outside: empty or `#` lines skipped; the trimmed `<ca>` opens (at most once); any other line is `key=value`,
/// the key only `[a-z_]` and in `ALLOWED_KEYS`, each key at most once. Values: `server` host name / IPv4 / IPv6
/// (at most 253 characters, no leading `-`); `port` 1–65535; `user` `[A-Za-z0-9._@+-]`, 1–128 characters, no
/// leading `-`; `cert` `system|ca|insecure`; `route_all`, `peer_dns` `yes|no`. Required: `server`, `user`;
/// with `cert=ca` a non-empty `<ca>` block with at least one certificate. Messages never quote the value, only
/// the (strict-charset) key name.
#[derive(Debug, Clone, Copy, Default)]
pub struct SSTPValidator;

impl SSTPValidator {
    pub fn is_valid_server(s: &str) -> bool {
        if s.is_empty() || s.len() > 253 {
            return false;
        }
        // The unspecified and the loopback address cannot be an SSTP server (nor because of the /1 routes and
        // the server route).
        if is_ipv4(s) {
            return s != "0.0.0.0" && !swift_str::has_prefix(s, "127.");
        }
        if swift_str::contains(s, ":") {
            return is_ipv6(s) && !is_unspecified_or_loopback_ipv6(s);
        }
        if swift_str::eq(ascii_lowercased(s).trim_matches('.'), "localhost") {
            return false;
        }
        // All digits and dots, but not a valid IPv4 (e.g. 1.2.3 or 999.1.1.1): error.
        if matches(s, "^[0-9.]+$") {
            return false;
        }
        matches(s, HOSTNAME_PATTERN)
    }

    /// Only dots, or ending with a dot, is not allowed.
    pub fn is_valid_user(s: &str) -> bool {
        matches(s, USER_PATTERN) && !swift_str::has_suffix(s, ".") && !matches(s, "^\\.+$")
    }

    pub fn is_valid_port(s: &str) -> bool {
        matches(s, "^[0-9]{1,5}$") && s.parse::<i64>().is_ok_and(|n| (1..=65535).contains(&n))
    }

    /// The message for a `user=` value the config cannot carry (`None`: fine). It does not quote the value.
    pub fn user_error(value: &str) -> Option<String> {
        Self::check("user", value)
    }

    /// Checks one value; `None` = fine. The message does not quote the value.
    fn check(key: &str, value: &str) -> Option<String> {
        match key {
            "server" => (!Self::is_valid_server(value))
                .then(|| l10n::tr("Invalid server: use a host name or an IPv4/IPv6 address, without a port", &[])),
            "port" => (!Self::is_valid_port(value)).then(|| l10n::tr("Invalid port: 1–65535", &[])),
            "user" => (!Self::is_valid_user(value)).then(|| {
                l10n::tr(
                    "Invalid user name: letters, digits and . _ @ + - only (use user@domain instead of DOMAIN\\user)",
                    &[],
                )
            }),
            "cert" => CertMode::from_raw_value(value).is_none().then(|| {
                l10n::tr("Invalid value for %@: allowed: %@", &[Arg::Str(key), Arg::Str("system, ca, insecure")])
            }),
            "route_all" | "peer_dns" => (!(swift_str::eq(value, "yes") || swift_str::eq(value, "no")))
                .then(|| l10n::tr("Invalid value for %@: allowed: %@", &[Arg::Str(key), Arg::Str("yes, no")])),
            _ => Some(l10n::tr("Key not allowed: %@", &[Arg::Str(key)])),
        }
    }

    /// For the root side: the validated, normalized parameters (`--sstp-params`), one per line: server, port,
    /// user, cert, route_all, peer_dns. `None` if the config is invalid.
    pub fn parameters(text: &str) -> Option<Vec<String>> {
        if !SSTPValidator.validate(text).is_empty() {
            return None;
        }
        let c = SSTPConfig::parse(text);
        Some(vec![
            c.server,
            c.port.to_string(),
            c.user,
            c.cert.raw_value().to_string(),
            (if c.route_all { "yes" } else { "no" }).to_string(),
            (if c.peer_dns { "yes" } else { "no" }).to_string(),
        ])
    }

    /// The PEM content of the `<ca>` block (`--sstp-ca`). `None` if the config is invalid or there is no `cert=ca`.
    pub fn ca_pem(text: &str) -> Option<String> {
        if !SSTPValidator.validate(text).is_empty() {
            return None;
        }
        let c = SSTPConfig::parse(text);
        (c.cert == CertMode::Ca && !c.ca_pem.is_empty()).then_some(c.ca_pem)
    }
}

impl ConfigValidator for SSTPValidator {
    fn validate(&self, text: &str) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut values: HashMap<String, String> = HashMap::new();
        let (mut in_ca, mut ca_line, mut ca_count) = (false, 0, 0);
        let mut ca_text: Vec<&str> = Vec::new();
        for (line_no, raw_line) in numbered_lines(text) {
            if has_control_character(raw_line) {
                issues.push(ValidationIssue::new(line_no, control_character_message()));
                continue;
            }
            if raw_line.as_bytes().contains(&0x5C) {
                issues.push(ValidationIssue::new(line_no, l10n::tr("Character not allowed: \\", &[])));
                continue;
            }
            let line = trim_space_tab(raw_line);
            if in_ca {
                if swift_str::eq(line, "</ca>") {
                    in_ca = false;
                } else if matches(line, PEM_LINE_PATTERN) {
                    ca_text.push(line);
                } else {
                    issues
                        .push(ValidationIssue::new(line_no, l10n::tr("Invalid line in the CA certificate block", &[])));
                }
                continue;
            }
            if line.is_empty() || swift_str::has_prefix(line, "#") {
                continue;
            }
            if swift_str::eq(line, "<ca>") {
                ca_count += 1;
                if ca_count > 1 {
                    issues.push(ValidationIssue::new(line_no, l10n::tr("Only one <ca> block is allowed", &[])));
                }
                in_ca = true;
                ca_line = line_no;
                continue;
            }
            let Some(eq) = swift_str::first_index(line, "=") else {
                issues.push(ValidationIssue::new(line_no, l10n::tr("Invalid line", &[])));
                continue;
            };
            let key = trim_space_tab(&line[..eq]);
            let value = trim_space_tab(&line[eq + swift_str::char_len_at(line, eq)..]);
            if !matches(key, "^[a-z_]+$") {
                issues.push(ValidationIssue::new(line_no, l10n::tr("Key not allowed", &[])));
                continue;
            }
            if !ALLOWED_KEYS.contains(&key) {
                issues.push(ValidationIssue::new(line_no, l10n::tr("Key not allowed: %@", &[Arg::Str(key)])));
                continue;
            }
            if !seen.insert(key.to_string()) {
                issues.push(ValidationIssue::new(line_no, l10n::tr("Duplicate key: %@", &[Arg::Str(key)])));
                continue;
            }
            if let Some(message) = Self::check(key, value) {
                issues.push(ValidationIssue::new(line_no, message));
                continue;
            }
            values.insert(key.to_string(), value.to_string());
        }
        if in_ca {
            issues.push(ValidationIssue::new(ca_line, l10n::tr("Unclosed inline block: %@", &[Arg::Str("ca")])));
        }
        if !seen.contains("server") {
            issues.push(ValidationIssue::new(0, l10n::tr("Missing key: %@", &[Arg::Str("server")])));
        }
        if !seen.contains("user") {
            issues.push(ValidationIssue::new(0, l10n::tr("Missing key: %@", &[Arg::Str("user")])));
        }
        if values.get("cert").is_some_and(|v| swift_str::eq(v, "ca")) {
            let pem = ca_text.join("\n");
            if !pem.contains("-----BEGIN CERTIFICATE-----") || !pem.contains("-----END CERTIFICATE-----") {
                issues.push(ValidationIssue::new(
                    0,
                    l10n::tr("cert=ca requires a <ca> block with a PEM certificate", &[]),
                ));
            }
        }
        issues
    }
}

pub fn is_ipv4(s: &str) -> bool {
    let parts = swift_str::split(s, ".", usize::MAX, false);
    parts.len() == 4 && parts.iter().all(|p| matches(p, "^[0-9]{1,3}$") && p.parse::<u32>().is_ok_and(|n| n <= 255))
}

pub fn is_ipv6(s: &str) -> bool {
    matches(s, "^[0-9A-Fa-f:]+$") && s.len() <= 39 && swift_str::contains(s, ":") && inet_pton6(s).is_some()
}

fn is_unspecified_or_loopback_ipv6(s: &str) -> bool {
    let Some(bytes) = inet_pton6(s) else { return false };
    bytes[..15].iter().all(|&b| b == 0) && (bytes[15] == 0 || bytes[15] == 1)
}

/// The BSD `inet_pton(AF_INET4, …)` algorithm (Apple libc): exactly four decimal octets, no leading zeros.
pub(crate) fn inet_pton4(src: &[u8]) -> Option<[u8; 4]> {
    let mut tmp = [0u8; 4];
    let mut tp = 0usize;
    let mut saw_digit = false;
    let mut octets = 0;
    for &ch in src {
        if ch == 0 {
            break;
        }
        if ch.is_ascii_digit() {
            let new = u32::from(tmp[tp]) * 10 + u32::from(ch - b'0');
            if saw_digit && tmp[tp] == 0 {
                return None;
            }
            if new > 255 {
                return None;
            }
            tmp[tp] = new as u8;
            if !saw_digit {
                octets += 1;
                if octets > 4 {
                    return None;
                }
                saw_digit = true;
            }
        } else if ch == b'.' && saw_digit {
            if octets == 4 {
                return None;
            }
            tp += 1;
            tmp[tp] = 0;
            saw_digit = false;
        } else {
            return None;
        }
    }
    if octets < 4 {
        return None;
    }
    Some(tmp)
}

/// The BSD `inet_pton(AF_INET6, …)` algorithm (Apple libc), in safe Rust, including the dotted IPv4 tail.
pub(crate) fn inet_pton6(src: &str) -> Option<[u8; 16]> {
    let src = src.as_bytes();
    let mut tmp = [0u8; 16];
    let mut tp = 0usize;
    let endp = 16usize;
    let mut colonp: Option<usize> = None;
    let mut i = 0usize;
    // Leading :: requires some special handling.
    if src.first() == Some(&b':') {
        i += 1;
        if src.get(i) != Some(&b':') {
            return None;
        }
    }
    let mut curtok = i;
    let mut seen_xdigits = 0;
    let mut val: u32 = 0;
    while i < src.len() {
        let ch = src[i];
        i += 1;
        if ch == 0 {
            break;
        }
        if let Some(digit) = (ch as char).to_digit(16) {
            val = (val << 4) | digit;
            seen_xdigits += 1;
            if seen_xdigits > 4 {
                return None;
            }
            continue;
        }
        if ch == b':' {
            curtok = i;
            if seen_xdigits == 0 {
                if colonp.is_some() {
                    return None;
                }
                colonp = Some(tp);
                continue;
            } else if i >= src.len() || src[i] == 0 {
                return None;
            }
            if tp + 2 > endp {
                return None;
            }
            tmp[tp] = (val >> 8) as u8;
            tmp[tp + 1] = val as u8;
            tp += 2;
            seen_xdigits = 0;
            val = 0;
            continue;
        }
        if ch == b'.'
            && tp + 4 <= endp
            && let Some(v4) = inet_pton4(&src[curtok..])
        {
            tmp[tp..tp + 4].copy_from_slice(&v4);
            tp += 4;
            seen_xdigits = 0;
            break;
        }
        return None;
    }
    if seen_xdigits > 0 {
        if tp + 2 > endp {
            return None;
        }
        tmp[tp] = (val >> 8) as u8;
        tmp[tp + 1] = val as u8;
        tp += 2;
    }
    if let Some(colonp) = colonp {
        // Shift the part after "::" to the end.
        let n = tp - colonp;
        if tp == endp {
            return None;
        }
        for k in 1..=n {
            tmp[endp - k] = tmp[colonp + n - k];
            tmp[colonp + n - k] = 0;
        }
        tp = endp;
    }
    if tp != endp {
        return None;
    }
    Some(tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inet_pton6_like_libc() {
        let ok = |s: &str| inet_pton6(s).is_some();
        for s in [
            "::",
            "::1",
            "1::",
            "1:2:3:4:5:6:7:8",
            "1:2:3:4:5:6:7::",
            "::2:3:4:5:6:7:8",
            "fd00::1",
            "2001:db8::8a2e:370:7334",
        ] {
            assert!(ok(s), "{s}");
        }
        for s in [
            "",
            ":",
            ":1::",
            "1:",
            "1::2::3",
            "1:2:3:4:5:6:7:8::",
            "1:2:3:4:5:6:7:8:9",
            "12345::",
            "::g",
            "2001:db8:::1",
        ] {
            assert!(!ok(s), "{s}");
        }
        assert_eq!(inet_pton6("::1").unwrap()[15], 1);
        assert_eq!(inet_pton6("1::").unwrap()[1], 1);
        assert_eq!(inet_pton6("1:2:3:4:5:6:7::").unwrap()[13], 7);
    }
}
