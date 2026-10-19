//! SECURITY LAYER: these validators keep a config from running commands as root (port of `Validators.swift`
//! and `SSTP.swift`). They are the single source of the rules: the root layer runs the same code, and the app
//! uses it in the editor for quick feedback. Messages never quote raw config content: only the line number, the
//! rule text and directive / key names that passed a strict character set (`[A-Za-z0-9-]`, for setenv names
//! `[A-Za-z0-9_]`). The rules are byte-oriented on purpose (ASCII character sets, no Unicode tricks); where the
//! Swift code relies on `String` semantics (grapheme clusters, canonical equivalence), [`crate::swift_str`] gives
//! the same result.
//!
//! Common rule: per line, one trailing `\r` is dropped; then if the raw line (before comment removal) contains a
//! control character (0x00-0x1F except TAB, or 0x7F), that is an error — inside OpenVPN inline blocks too.

pub mod openvpn;
pub mod sstp;
pub mod strongswan;
pub mod wireguard;

use crate::l10n;
use crate::models::{VPNKind, ValidationIssue};
use regex::Regex;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

pub use openvpn::{OpenVPNTier, OpenVPNValidation, OpenVPNValidator, RiskyFinding};
pub use sstp::{CertMode, SSTPConfig, SSTPValidator};
pub use strongswan::StrongSwanValidator;
pub use wireguard::WireGuardValidator;

pub trait ConfigValidator {
    fn validate(&self, text: &str) -> Vec<ValidationIssue>;
}

/// The validator of a kind; native kinds have none.
pub fn validator(kind: VPNKind) -> Option<Box<dyn ConfigValidator>> {
    match kind {
        VPNKind::Openvpn => Some(Box::new(OpenVPNValidator)),
        VPNKind::Wireguard => Some(Box::new(WireGuardValidator)),
        VPNKind::Strongswan => Some(Box::new(StrongSwanValidator)),
        VPNKind::Sstp => Some(Box::new(SSTPValidator)),
        VPNKind::L2tp | VPNKind::Cisco => None,
    }
}

pub(crate) fn control_character_message() -> String {
    l10n::tr("Control character not allowed", &[])
}

/// Per line, one trailing CR dropped, numbered from 1. The rest of the line is untouched.
pub(crate) fn numbered_lines(text: &str) -> impl Iterator<Item = (i64, &str)> {
    text.split('\n').enumerate().map(|(i, raw)| (i as i64 + 1, raw.strip_suffix('\r').unwrap_or(raw)))
}

/// 0x00-0x1F (except TAB) or 0x7F.
pub(crate) fn has_control_character(s: &str) -> bool {
    s.bytes().any(|b| (b < 0x20 && b != 0x09) || b == 0x7F)
}

static REGEX_CACHE: LazyLock<Mutex<HashMap<&'static str, &'static Regex>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// A compiled (cached) pattern. All patterns are compile-time constants.
pub(crate) fn re(pattern: &'static str) -> &'static Regex {
    let mut cache = REGEX_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    cache.entry(pattern).or_insert_with(|| Box::leak(Box::new(Regex::new(pattern).expect("valid pattern"))))
}

/// Swift `matches(s, pattern)`: `s.range(of: pattern, options: .regularExpression) != nil`.
pub(crate) fn matches(s: &str, pattern: &'static str) -> bool {
    crate::swift_str::matches(s, re(pattern))
}
