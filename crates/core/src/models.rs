//! Port of `Models.swift` (+ `OTPSetting`/`AuthWait` from `MFA.swift`): connection metadata, states, secrets.
//!
//! `meta.json` compatibility: the JSON keys, the ISO 8601 dates, the defaults for absent keys and the leniency
//! rules of the Swift `Decodable` implementations are reproduced exactly (see `tests/compat_swift.rs`).

use crate::date::Date;
use crate::l10n::{self, Arg};
use serde_json::{Map, Value};
use uuid::Uuid;

/// The kinds of VPN connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VPNKind {
    Openvpn,
    Wireguard,
    Strongswan,
    Sstp,
    L2tp,
    Cisco,
}

impl VPNKind {
    /// Swift `CaseIterable` order.
    pub const ALL: [VPNKind; 6] =
        [VPNKind::Openvpn, VPNKind::Wireguard, VPNKind::Strongswan, VPNKind::Sstp, VPNKind::L2tp, VPNKind::Cisco];

    pub fn raw_value(self) -> &'static str {
        match self {
            VPNKind::Openvpn => "openvpn",
            VPNKind::Wireguard => "wireguard",
            VPNKind::Strongswan => "strongswan",
            VPNKind::Sstp => "sstp",
            VPNKind::L2tp => "l2tp",
            VPNKind::Cisco => "cisco",
        }
    }

    /// Exact raw value (Swift `init?(rawValue:)`).
    pub fn from_raw_value(raw: &str) -> Option<VPNKind> {
        VPNKind::ALL.into_iter().find(|k| crate::swift_str::eq(k.raw_value(), raw))
    }

    pub fn display_name(self) -> &'static str {
        match self {
            VPNKind::Openvpn => "OpenVPN",
            VPNKind::Wireguard => "WireGuard",
            VPNKind::Strongswan => "IKEv2",
            VPNKind::Sstp => "SSTP",
            VPNKind::L2tp => "L2TP",
            VPNKind::Cisco => "Cisco IPsec",
        }
    }

    /// Native macOS VPN (scutil + mobileconfig), not run by the root layer.
    pub fn is_native(self) -> bool {
        matches!(self, VPNKind::L2tp | VPNKind::Cisco)
    }
}

/// Native (L2TP / Cisco IPsec) settings. The account name is not a secret; the password and the PSK are in the
/// Keychain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NativeSettings {
    pub server: String,
    pub account: String,
    /// Cisco IPsec group name (LocalIdentifier). Empty for L2TP.
    pub group_name: String,
    pub send_all_traffic: bool,
}

impl Default for NativeSettings {
    fn default() -> Self {
        NativeSettings {
            server: String::new(),
            account: String::new(),
            group_name: String::new(),
            send_all_traffic: true,
        }
    }
}

/// Separator between the password and the one-time code ("code appended to the password").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum OTPSeparator {
    #[default]
    None,
    Comma,
    Colon,
}

impl OTPSeparator {
    pub const ALL: [OTPSeparator; 3] = [OTPSeparator::None, OTPSeparator::Comma, OTPSeparator::Colon];

    pub fn raw_value(self) -> &'static str {
        match self {
            OTPSeparator::None => "none",
            OTPSeparator::Comma => "comma",
            OTPSeparator::Colon => "colon",
        }
    }

    pub fn from_raw_value(raw: &str) -> Option<OTPSeparator> {
        OTPSeparator::ALL.into_iter().find(|s| crate::swift_str::eq(s.raw_value(), raw))
    }

    /// The separator text.
    pub fn string(self) -> &'static str {
        match self {
            OTPSeparator::None => "",
            OTPSeparator::Comma => ",",
            OTPSeparator::Colon => ":",
        }
    }
}

/// Per-connection setting: ask for a one-time code when connecting and append it to the password. Stored in
/// `meta.json` under `otp`; missing (older file): off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct OTPSetting {
    pub enabled: bool,
    pub separator: OTPSeparator,
}

impl OTPSetting {
    pub fn new(enabled: bool, separator: OTPSeparator) -> Self {
        OTPSetting { enabled, separator }
    }

    /// Swift `init(from:)`: absent or `null` fields take the defaults, an unknown separator (newer version) means
    /// no separator; a value of the wrong type is an error.
    pub fn from_json(value: &Value) -> Result<OTPSetting, DecodeError> {
        let obj = value.as_object().ok_or(DecodeError::type_mismatch("otp"))?;
        let enabled = decode_if_present(obj, "enabled", |v| v.as_bool())?.unwrap_or(false);
        let raw = decode_if_present(obj, "separator", |v| v.as_str().map(str::to_string))?.unwrap_or_default();
        Ok(OTPSetting { enabled, separator: OTPSeparator::from_raw_value(&raw).unwrap_or(OTPSeparator::None) })
    }

    pub fn to_json(self) -> Value {
        let mut m = Map::new();
        m.insert("enabled".into(), Value::Bool(self.enabled));
        m.insert("separator".into(), Value::String(self.separator.raw_value().into()));
        Value::Object(m)
    }
}

/// The shared credential a connection's username and password come from (spec 3a), as the credential prompt names
/// it: "Password for Office AD — used by 4 connections". Never the username or the password.
///
/// Defined here (the vault and the secret readers use it without the credential prompt); `credentials.rs`
/// re-exports it next to `CredentialPrompt`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CredentialRef {
    pub name: String,
    /// How many items (managed connections and system VPNs) are linked to it.
    pub used_by: usize,
    /// The team catalog whose credential slot this is (its name; team catalog spec 6): the prompt reads "Office AD
    /// (team catalog “Acme VPN”) — enter your user name and password". `None`: a personal shared credential.
    pub team: Option<String>,
    /// A team slot only: where the catalog comes from, so a catalog named like another cannot pass for it: the
    /// HTTPS source's host, or the short form of the pinned publisher fingerprint (`ABCD-1234`) for a file source.
    pub team_source: Option<String>,
    /// A team slot only: the server the connection sends the slot's password to (display only).
    pub server: Option<String>,
}

/// The secret fields of a connection (or a system VPN): the Keychain account suffix today (`<key>.<raw value>`),
/// the `secrets.field` column in the vault. Ordered as declared (the same order as [`SecretField::ALL`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SecretField {
    Username,
    Password,
    Psk,
    /// The password of an OpenVPN private key (PKCS#12 / encrypted PEM).
    KeyPassword,
}

impl SecretField {
    pub const ALL: [SecretField; 4] =
        [SecretField::Username, SecretField::Password, SecretField::Psk, SecretField::KeyPassword];

    pub fn raw_value(self) -> &'static str {
        match self {
            SecretField::Username => "username",
            SecretField::Password => "password",
            SecretField::Psk => "psk",
            SecretField::KeyPassword => "keypass",
        }
    }

    pub fn from_raw_value(raw: &str) -> Option<SecretField> {
        Self::ALL.into_iter().find(|f| f.raw_value() == raw)
    }
}

/// A JSON decoding failure (Swift `DecodingError`). The message is for logs only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl DecodeError {
    fn type_mismatch(key: &str) -> Self {
        DecodeError(format!("type mismatch: {key}"))
    }

    fn missing(key: &str) -> Self {
        DecodeError(format!("key not found: {key}"))
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DecodeError {}

/// `decodeIfPresent`: absent or `null` -> `None`; present with the wrong type -> error.
fn decode_if_present<T>(
    obj: &Map<String, Value>,
    key: &str,
    get: impl Fn(&Value) -> Option<T>,
) -> Result<Option<T>, DecodeError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => get(v).map(Some).ok_or_else(|| DecodeError::type_mismatch(key)),
    }
}

/// `decode`: absent, `null` or the wrong type -> error.
fn decode<T>(obj: &Map<String, Value>, key: &str, get: impl Fn(&Value) -> Option<T>) -> Result<T, DecodeError> {
    match obj.get(key) {
        None => Err(DecodeError::missing(key)),
        Some(v) => get(v).ok_or_else(|| DecodeError::type_mismatch(key)),
    }
}

fn string_value(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}

/// `UUID(uuidString:)`: exactly `8-4-4-4-12` hex digits, either case.
pub fn parse_uuid(s: &str) -> Option<Uuid> {
    let b = s.as_bytes();
    if b.len() != 36 {
        return None;
    }
    for (i, c) in b.iter().enumerate() {
        let ok = if matches!(i, 8 | 13 | 18 | 23) { *c == b'-' } else { c.is_ascii_hexdigit() };
        if !ok {
            return None;
        }
    }
    Uuid::parse_str(s).ok()
}

/// `uuid.uuidString`: upper-case, hyphenated.
pub fn uuid_string(id: &Uuid) -> String {
    id.hyphenated().encode_upper(&mut Uuid::encode_buffer()).to_string()
}

impl NativeSettings {
    /// Synthesized `Decodable`: every field is required.
    pub fn from_json(value: &Value) -> Result<NativeSettings, DecodeError> {
        let obj = value.as_object().ok_or(DecodeError::type_mismatch("native"))?;
        Ok(NativeSettings {
            server: decode(obj, "server", string_value)?,
            account: decode(obj, "account", string_value)?,
            group_name: decode(obj, "groupName", string_value)?,
            send_all_traffic: decode(obj, "sendAllTraffic", Value::as_bool)?,
        })
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("server".into(), Value::String(self.server.clone()));
        m.insert("account".into(), Value::String(self.account.clone()));
        m.insert("groupName".into(), Value::String(self.group_name.clone()));
        m.insert("sendAllTraffic".into(), Value::Bool(self.send_all_traffic));
        Value::Object(m)
    }
}

/// A managed connection (`meta.json`).
#[derive(Debug, Clone, PartialEq)]
pub struct Connection {
    pub id: Uuid,
    pub name: String,
    pub kind: VPNKind,
    pub created_at: Date,
    /// Native connection: the service name shown by scutil.
    pub native_service_name: Option<String>,
    /// Native connection: the scutil ID of the installed service, once it appeared (bound by name and server
    /// address). From then on start / stop / status use this, not the name.
    pub native_service_id: Option<String>,
    /// Native settings.
    pub native: Option<NativeSettings>,
    /// OpenVPN: the names of the risky directives the user acknowledged, sorted. Missing (older `meta.json`): empty.
    pub acknowledged_risky_directives: Vec<String>,
    /// MFA: one-time code appended to the password when connecting. Missing (older `meta.json`): off.
    pub otp: OTPSetting,
}

impl Connection {
    /// `Connection(name:kind:)`: new random ID, created now, everything else default.
    pub fn new(name: impl Into<String>, kind: VPNKind) -> Connection {
        Connection::with_id(Uuid::new_v4(), name, kind, Date::now())
    }

    pub fn with_id(id: Uuid, name: impl Into<String>, kind: VPNKind, created_at: Date) -> Connection {
        Connection {
            id,
            name: name.into(),
            kind,
            created_at,
            native_service_name: None,
            native_service_id: None,
            native: None,
            acknowledged_risky_directives: Vec::new(),
            otp: OTPSetting::default(),
        }
    }

    /// Swift `init(from:)` (with `.iso8601` dates).
    pub fn from_json(value: &Value) -> Result<Connection, DecodeError> {
        let obj = value.as_object().ok_or(DecodeError::type_mismatch("Connection"))?;
        let id = decode(obj, "id", |v| v.as_str().and_then(parse_uuid))?;
        let name = decode(obj, "name", string_value)?;
        let kind = decode(obj, "kind", |v| v.as_str().and_then(VPNKind::from_raw_value))?;
        let created_at = decode(obj, "createdAt", |v| v.as_str().and_then(Date::parse_iso8601))?;
        let native_service_name = decode_if_present(obj, "nativeServiceName", string_value)?;
        let native_service_id = decode_if_present(obj, "nativeServiceID", string_value)?;
        let native = match obj.get("native") {
            None | Some(Value::Null) => None,
            Some(v) => Some(NativeSettings::from_json(v)?),
        };
        let acknowledged = decode_if_present(obj, "acknowledgedRiskyDirectives", |v| {
            v.as_array()?.iter().map(string_value).collect::<Option<Vec<_>>>()
        })?
        .unwrap_or_default();
        // `(try? c.decodeIfPresent(OTPSetting.self, forKey: .otp)) ?? OTPSetting()`: any problem means off.
        let otp = match obj.get("otp") {
            None | Some(Value::Null) => OTPSetting::default(),
            Some(v) => OTPSetting::from_json(v).unwrap_or_default(),
        };
        Ok(Connection {
            id,
            name,
            kind,
            created_at,
            native_service_name,
            native_service_id,
            native,
            acknowledged_risky_directives: acknowledged,
            otp,
        })
    }

    /// Synthesized `Encodable`: optionals only when present.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".into(), Value::String(uuid_string(&self.id)));
        m.insert("name".into(), Value::String(self.name.clone()));
        m.insert("kind".into(), Value::String(self.kind.raw_value().into()));
        m.insert("createdAt".into(), Value::String(self.created_at.iso8601()));
        if let Some(s) = &self.native_service_name {
            m.insert("nativeServiceName".into(), Value::String(s.clone()));
        }
        if let Some(s) = &self.native_service_id {
            m.insert("nativeServiceID".into(), Value::String(s.clone()));
        }
        if let Some(n) = &self.native {
            m.insert("native".into(), n.to_json());
        }
        m.insert(
            "acknowledgedRiskyDirectives".into(),
            Value::Array(self.acknowledged_risky_directives.iter().cloned().map(Value::String).collect()),
        );
        m.insert("otp".into(), self.otp.to_json());
        Value::Object(m)
    }
}

/// "Waiting for authentication" state of a connection.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AuthWait {
    pub kind: AuthWaitKind,
    pub deadline: Option<Date>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthWaitKind {
    /// Waiting for a code (code prompt).
    Code,
    /// Waiting for a web / push approval.
    Web,
    /// Waiting for the credential prompt (user name, password, PSK or key password).
    Credentials,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected {
        ip: Option<String>,
        since: Option<Date>,
    },
    Disconnecting,
    Failed(String),
    /// Waiting for authentication while connecting (MFA code or web / push approval).
    AwaitingAuth(AuthWait),
}

impl ConnectionState {
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            ConnectionState::Connecting
                | ConnectionState::Connected { .. }
                | ConnectionState::Disconnecting
                | ConnectionState::AwaitingAuth(_)
        )
    }

    pub fn is_connected(&self) -> bool {
        matches!(self, ConnectionState::Connected { .. })
    }
}

/// `line == 0`: an issue of the whole file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidationIssue {
    pub line: i64,
    pub message: String,
}

impl ValidationIssue {
    pub fn new(line: impl TryInto<i64>, message: impl Into<String>) -> Self {
        ValidationIssue { line: line.try_into().unwrap_or(i64::MAX), message: message.into() }
    }

    /// `Line 3: …` in the current language (the message itself is already localized).
    pub fn display(&self) -> String {
        if self.line == 0 {
            self.message.clone()
        } else {
            l10n::tr("Line %ld: %@", &[Arg::Int(self.line), Arg::Str(&self.message)])
        }
    }
}

/// `Debug` shows which fields are set, never a value.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Secrets {
    pub username: Option<String>,
    pub password: Option<String>,
    pub psk: Option<String>,
    /// OpenVPN: the password of the private key (encrypted PEM `<key>` or PKCS#12). `mvpn` passes it as an
    /// `--askpass` file.
    pub key_password: Option<String>,
    /// MFA: the one-time code asked for when connecting (only for masking: `mvpn` also masks it in the log as a
    /// separate secret). Never stored.
    pub one_time_code: Option<String>,
    /// OpenVPN static challenge: `password` is already in SCRV1 / concat form (`challenge=packed`).
    pub challenge_packed: bool,
}

/// Wipes every value (the connect paths call it once the root layer / `SCNetworkConnection` has them). No `Drop`:
/// the struct-update syntax (`..base.clone()`) used across the workspace moves out of `Secrets`.
impl zeroize::Zeroize for Secrets {
    fn zeroize(&mut self) {
        let mut wiped = 0;
        for value in
            [&mut self.username, &mut self.password, &mut self.psk, &mut self.key_password, &mut self.one_time_code]
        {
            if let Some(v) = value.as_mut() {
                wiped += usize::from(!v.is_empty());
                v.zeroize();
            }
            *value = None;
        }
        self.challenge_packed = false;
        WIPED.with(|w| w.set(w.get() + wiped));
    }
}

thread_local! {
    static WIPED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many non-empty secret values [`Secrets::zeroize`] has wiped on this thread (tests check that every connect
/// path wipes its copies, also on early returns).
#[doc(hidden)]
pub fn wiped_secret_values() -> usize {
    WIPED.with(std::cell::Cell::get)
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = |v: &Option<String>| match v {
            None => "none",
            Some(v) if v.is_empty() => "empty",
            Some(_) => "set",
        };
        f.debug_struct("Secrets")
            .field("username", &state(&self.username))
            .field("password", &state(&self.password))
            .field("psk", &state(&self.psk))
            .field("key_password", &state(&self.key_password))
            .field("one_time_code", &state(&self.one_time_code))
            .field("challenge_packed", &self.challenge_packed)
            .finish()
    }
}

impl Secrets {
    /// The rule checked on save for every kind: no line breaks and no control characters (C0, DEL, C1,
    /// U+2028/U+2029). `None`: fine, otherwise the message. (The SSTP password has a stricter rule too.)
    pub fn input_error(&self) -> Option<String> {
        let bad = [&self.username, &self.password, &self.psk, &self.key_password].into_iter().any(|value| {
            value.as_deref().unwrap_or("").chars().any(|c| {
                let v = c as u32;
                v < 0x20 || (0x7F..=0x9F).contains(&v) || v == 0x2028 || v == 0x2029
            })
        });
        bad.then(|| l10n::tr("The user name, password and PSK must not contain line breaks or control characters", &[]))
    }

    /// The `mvpn up` stdin format: `key=value` per line, in a buffer that is wiped on drop. Stripping line breaks
    /// is only a safety net: `input_error` already rejects them on save. Every `\n` and `\r` is removed:
    /// deliberately stricter than Swift, whose `replacingOccurrences` keeps a `\n` / `\r` that a combining mark
    /// follows, which would let a value add a line to the payload.
    pub fn stdin_payload(&self) -> zeroize::Zeroizing<String> {
        let fields = [
            ("username", &self.username),
            ("password", &self.password),
            ("psk", &self.psk),
            ("keypass", &self.key_password),
            ("otp", &self.one_time_code),
        ];
        let is_kept = |c: &char| *c != '\n' && *c != '\r';
        // The exact size first, so the buffer is never reallocated (a reallocation would free an unwiped copy).
        let kept_len = |v: &str| v.chars().filter(is_kept).map(char::len_utf8).sum::<usize>();
        let mut capacity = if self.challenge_packed { "challenge=packed\n".len() } else { 0 };
        for (key, value) in fields {
            let n = value.as_deref().map_or(0, kept_len);
            if n > 0 {
                capacity += key.len() + 1 + n + 1;
            }
        }
        let mut out = zeroize::Zeroizing::new(String::with_capacity(capacity));
        for (key, value) in fields {
            let Some(value) = value.as_deref().filter(|v| kept_len(v) > 0) else { continue };
            out.push_str(key);
            out.push('=');
            for c in value.chars().filter(is_kept) {
                out.push(c);
            }
            out.push('\n');
        }
        if self.challenge_packed {
            out.push_str("challenge=packed\n");
        }
        out
    }
}
