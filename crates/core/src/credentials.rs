//! The credential prompt's pure logic (spec `2026-10-19-vault-folders-design.md`, section 4): which credentials a
//! connect needs per kind, which of them are not stored, merging the typed values over the stored ones, checking
//! them, and telling a sign-in failure of the root layer apart from other failures.
//!
//! Typed values only live in [`CredentialValues`] (`Zeroizing` strings, wiped on drop); its `Debug` shows which
//! fields are set, never a value.

use crate::l10n;
use crate::mfa::PromptDeadline;
use crate::models::{Secrets, VPNKind};
use crate::validators::{OpenVPNValidator, SSTPConfig, StrongSwanValidator};
use crate::{importer, swift_str};
use std::collections::BTreeSet;
use zeroize::{Zeroize, Zeroizing};

/// A credential the prompt can ask for. The order is the display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CredentialField {
    Username,
    Password,
    Psk,
    KeyPassword,
}

impl CredentialField {
    pub const ALL: [CredentialField; 4] =
        [CredentialField::Username, CredentialField::Password, CredentialField::Psk, CredentialField::KeyPassword];

    /// The name in the view and in the window's answer.
    pub fn name(self) -> &'static str {
        match self {
            CredentialField::Username => "username",
            CredentialField::Password => "password",
            CredentialField::Psk => "psk",
            CredentialField::KeyPassword => "keyPassword",
        }
    }

    pub fn from_name(name: &str) -> Option<CredentialField> {
        CredentialField::ALL.into_iter().find(|f| f.name() == name)
    }

    /// A secret (shown as a password field); the user name is not.
    pub fn is_secret(self) -> bool {
        self != CredentialField::Username
    }

    fn stored(self, secrets: &Secrets) -> Option<&str> {
        match self {
            CredentialField::Username => secrets.username.as_deref(),
            CredentialField::Password => secrets.password.as_deref(),
            CredentialField::Psk => secrets.psk.as_deref(),
            CredentialField::KeyPassword => secrets.key_password.as_deref(),
        }
    }
}

/// Which fields a connect needs, before looking at what is stored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequiredFields {
    pub fields: BTreeSet<CredentialField>,
}

impl RequiredFields {
    pub fn contains(&self, field: CredentialField) -> bool {
        self.fields.contains(&field)
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

/// Typed values from the prompt; wiped on drop.
#[derive(Default, Clone)]
pub struct CredentialValues {
    pub username: Option<Zeroizing<String>>,
    pub password: Option<Zeroizing<String>>,
    pub psk: Option<Zeroizing<String>>,
    pub key_password: Option<Zeroizing<String>>,
}

impl CredentialValues {
    pub fn get(&self, field: CredentialField) -> Option<&str> {
        match field {
            CredentialField::Username => self.username.as_deref().map(String::as_str),
            CredentialField::Password => self.password.as_deref().map(String::as_str),
            CredentialField::Psk => self.psk.as_deref().map(String::as_str),
            CredentialField::KeyPassword => self.key_password.as_deref().map(String::as_str),
        }
    }

    pub fn set(&mut self, field: CredentialField, value: Zeroizing<String>) {
        let slot = match field {
            CredentialField::Username => &mut self.username,
            CredentialField::Password => &mut self.password,
            CredentialField::Psk => &mut self.psk,
            CredentialField::KeyPassword => &mut self.key_password,
        };
        *slot = Some(value);
    }

    /// The fields that have a value, in display order.
    pub fn fields(&self) -> Vec<CredentialField> {
        CredentialField::ALL.into_iter().filter(|f| self.get(*f).is_some()).collect()
    }
}

impl std::fmt::Debug for CredentialValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let set: Vec<&str> = self.fields().into_iter().map(CredentialField::name).collect();
        f.debug_struct("CredentialValues").field("set", &set).finish()
    }
}

/// A request to the UI's credential window.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialPrompt {
    pub connection_id: String,
    pub connection_name: String,
    /// The connection's kind (the SSTP password has a stricter rule).
    pub kind: VPNKind,
    /// Only the fields to ask for, in display order.
    pub fields: Vec<CredentialField>,
    /// Pre-filled when one is stored (not a secret: the editor shows it too).
    pub username: Option<String>,
    /// The re-prompt after a sign-in failure ("Sign-in failed — check the username and password").
    pub retry: bool,
    pub deadline: PromptDeadline,
}

/// The window's answer.
#[derive(Debug)]
pub enum CredentialAnswer {
    /// `save`: store the values once the connection is up.
    Provided { values: CredentialValues, save: bool },
    /// Cancelled, dismissed or expired.
    Cancelled,
}

/// The credentials `kind` needs, from its config (`None`: unreadable, then only the kind's fixed fields; OpenVPN
/// and IKEv2 have none, the root layer decides).
pub fn required_fields(kind: VPNKind, config: Option<&str>) -> RequiredFields {
    use CredentialField::{Password, Psk, Username};
    let fields: Vec<CredentialField> = match kind {
        VPNKind::Openvpn => config.map(openvpn_fields).unwrap_or_default(),
        VPNKind::Strongswan => match config {
            Some(config) if uses_eap(config) => vec![Username, Password],
            _ => Vec::new(),
        },
        // MacVPN's Cisco profiles always use a shared secret (`mobileconfig.rs`).
        VPNKind::L2tp | VPNKind::Cisco => vec![Username, Password, Psk],
        // The user name is the config's `user=` line (required by the validator).
        VPNKind::Sstp => vec![Password],
        VPNKind::Wireguard => Vec::new(),
    };
    RequiredFields { fields: fields.into_iter().collect() }
}

/// `auth-user-pass` without a file argument and without an inline `<auth-user-pass>` block: user name and
/// password. An encrypted PEM key: its password.
fn openvpn_fields(config: &str) -> Vec<CredentialField> {
    let outline = OpenVPNValidator::outline(config);
    let mut fields = Vec::new();
    let bare_auth_user_pass = outline.directives.iter().any(|d| d[0] == "auth-user-pass" && d.len() == 1);
    if bare_auth_user_pass && !outline.blocks.contains("auth-user-pass") {
        fields.extend([CredentialField::Username, CredentialField::Password]);
    }
    // Only the `<key>` block counts: a marker in a comment or in another block (a certificate) asks nothing.
    if importer::contains_encrypted_key(&outline.key) {
        fields.push(CredentialField::KeyPassword);
    }
    fields
}

/// A `local…` section authenticates with EAP (`auth = eap`, `eap-mschapv2`, …).
fn uses_eap(config: &str) -> bool {
    StrongSwanValidator::local_auth_values(config).iter().any(|v| {
        let v = swift_str::ascii_lowercased(v.trim());
        v == "eap" || v.starts_with("eap-")
    })
}

/// The required fields with no (or an empty) stored value, in display order.
pub fn missing(required: &RequiredFields, stored: &Secrets) -> Vec<CredentialField> {
    required.fields.iter().copied().filter(|f| f.stored(stored).unwrap_or("").is_empty()).collect()
}

/// The stored secrets with the typed values over them, field by field.
/// The result is wiped on drop.
pub fn apply(values: &CredentialValues, base: &Secrets) -> Zeroizing<Secrets> {
    let mut out = Zeroizing::new(base.clone());
    let inner: &mut Secrets = &mut out;
    for (field, slot) in [
        (CredentialField::Username, &mut inner.username),
        (CredentialField::Password, &mut inner.password),
        (CredentialField::Psk, &mut inner.psk),
        (CredentialField::KeyPassword, &mut inner.key_password),
    ] {
        if let Some(v) = values.get(field) {
            // The copied stored value is wiped, not just dropped.
            slot.zeroize();
            *slot = Some(v.to_string());
        }
    }
    out
}

/// At most this many bytes per value.
pub const MAX_VALUE_BYTES: usize = 1024;

/// Every asked field has a non-empty value of at most [`MAX_VALUE_BYTES`] without line breaks or control
/// characters (the [`Secrets::input_error`] rule), the SSTP password also the SSTP rule; no other field is set.
/// The error never quotes a value.
pub fn validate_values(values: &CredentialValues, fields: &[CredentialField], kind: VPNKind) -> Result<(), String> {
    if values.fields().iter().any(|f| !fields.contains(f)) {
        return Err("unexpected field".into());
    }
    for field in fields {
        let value = values.get(*field).unwrap_or("");
        if value.is_empty() {
            return Err("empty field".into());
        }
        if value.len() > MAX_VALUE_BYTES {
            return Err("value too long".into());
        }
    }
    let check = Zeroizing::new(Secrets {
        username: values.get(CredentialField::Username).map(str::to_string),
        password: values.get(CredentialField::Password).map(str::to_string),
        psk: values.get(CredentialField::Psk).map(str::to_string),
        key_password: values.get(CredentialField::KeyPassword).map(str::to_string),
        ..Secrets::default()
    });
    if let Some(message) = check.input_error() {
        Err(message)
    } else if kind == VPNKind::Sstp
        && values.get(CredentialField::Password).is_some_and(|p| !SSTPConfig::is_acceptable_password(p))
    {
        Err(SSTPConfig::password_rule_message())
    } else {
        Ok(())
    }
}

/// The `mvpn` messages that mean a wrong user name or password (`openvpn.rs`, `sstp.rs` of the root layer).
// TODO(1.2, root VERSION 8): add the strongSwan EAP key "Authentication failed (EAP)" here (and to the tests)
// once root layer 8 and its l10n key are merged; root layer 7 has no distinct EAP failure message.
const SIGN_IN_FAILURES: [&str; 3] = [
    "Authentication failed (AUTH_FAILED)",
    "Authentication failed",
    "Authentication failed (wrong user name or password)",
];

/// The root layer's error (its last non-empty stderr line, trimmed) is one of its sign-in failure messages, in
/// English or Hungarian. Nothing else matches.
pub fn is_sign_in_failure(message: &str) -> bool {
    let Some(last) = message.lines().map(str::trim).rfind(|l| !l.is_empty()) else { return false };
    SIGN_IN_FAILURES.iter().any(|key| last == *key || l10n::hungarian(key).is_some_and(|hu| last == hu))
}

/// The re-prompt's line.
pub fn sign_in_failed_text() -> String {
    l10n::tr("Sign-in failed — check the username and password", &[])
}
