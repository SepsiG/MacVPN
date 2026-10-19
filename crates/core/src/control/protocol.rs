//! The control API wire protocol: newline-delimited JSON, one object per line.
//!
//! Forward compatibility (API v1): later releases may add `state` values and `error` codes to v1 (1.1.0 added
//! `waiting_for_credentials` and `credentials_cancelled`). A client must treat an unknown `state` as "in
//! progress" and an unknown `error` as `failed`.
//!
//! Requests are parsed strictly: unknown fields, duplicate keys (the `op` too), wrong types and over-long lines
//! are `bad_request`; an unknown `op` alone is `unsupported`. A parse error carries the request's `id` when the
//! line is a JSON object with a valid one, so the error reply can echo it. The name and the connection ids are
//! validated here so the server only ever sees well-formed values; the `hello` token's shape is checked by the
//! server, which fails a malformed token like a wrong one. Replies and events are built with `serde_json`, so every
//! string is escaped and a reply is always exactly one line.

use crate::mfa::{AuthText, is_format_character};
use crate::models::{AuthWait, AuthWaitKind, ConnectionState, parse_uuid};
use crate::swift_str;
use serde::Deserialize;
use serde::de::{MapAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

/// Sent in `hello`'s reply (`{"ok":true,"api":1}`).
pub const API_VERSION: u32 = 1;
/// The longest request line in bytes, without its newline.
pub const MAX_LINE: usize = 4096;
/// The longest client name, in characters (grapheme clusters) after sanitizing.
pub const MAX_NAME_CHARACTERS: usize = 64;
/// ... and in UTF-8 bytes (a character may carry any number of combining marks).
pub const MAX_NAME_BYTES: usize = 256;
/// A token: 32 random bytes, base64url without padding.
pub const TOKEN_LENGTH: usize = 43;

/// A client request. Only `pair` and `hello` may omit the `id` (`null` counts as omitted).
///
/// `Debug` never shows the `hello` token.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, tag = "op", rename_all = "snake_case")]
pub enum Request {
    Pair {
        id: Option<u64>,
        name: String,
    },
    Hello {
        id: Option<u64>,
        token: String,
    },
    List {
        id: u64,
    },
    /// `connection` is a key exactly as `list` returned it: keys are compared case-sensitively, so a client must
    /// echo them unchanged (the parser only checks the UUID shape and does not normalize case).
    Up {
        id: u64,
        connection: String,
    },
    /// `connection`: as for [`Request::Up`], exactly as `list` returned it.
    Down {
        id: u64,
        connection: String,
    },
    Status {
        id: u64,
    },
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Request::Pair { id, name } => f.debug_struct("Pair").field("id", id).field("name", name).finish(),
            Request::Hello { id, .. } => {
                f.debug_struct("Hello").field("id", id).field("token", &format_args!("<redacted>")).finish()
            }
            Request::List { id } => f.debug_struct("List").field("id", id).finish(),
            Request::Up { id, connection } => {
                f.debug_struct("Up").field("id", id).field("connection", connection).finish()
            }
            Request::Down { id, connection } => {
                f.debug_struct("Down").field("id", id).field("connection", connection).finish()
            }
            Request::Status { id } => f.debug_struct("Status").field("id", id).finish(),
        }
    }
}

/// A request line that was refused: the code to reply with and the request's `id`, if one could be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError {
    pub id: Option<u64>,
    pub code: ErrorCode,
}

impl Request {
    /// The `id` to echo in the reply.
    pub fn id(&self) -> Option<u64> {
        match self {
            Request::Pair { id, .. } | Request::Hello { id, .. } => *id,
            Request::List { id } | Request::Up { id, .. } | Request::Down { id, .. } | Request::Status { id } => {
                Some(*id)
            }
        }
    }
}

/// The `op` values this version understands; any other is `unsupported`.
const KNOWN_OPS: [&str; 6] = ["pair", "hello", "list", "up", "down", "status"];

/// The generic error codes sent to clients (never raw tool output).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    Unauthorized,
    NotAllowed,
    UnknownConnection,
    Busy,
    SetupRequired,
    MfaCancelled,
    MfaTimeout,
    /// The credential prompt was cancelled (or expired). An addition to API v1 (1.1.0).
    CredentialsCancelled,
    /// The vault is locked (1.2.0): everything that reads it is refused; `down` still works. An addition to API v1.
    Locked,
    Failed,
    AppQuitting,
    Disabled,
    Unsupported,
    BadRequest,
    Denied,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Unauthorized => "unauthorized",
            ErrorCode::NotAllowed => "not_allowed",
            ErrorCode::UnknownConnection => "unknown_connection",
            ErrorCode::Busy => "busy",
            ErrorCode::SetupRequired => "setup_required",
            ErrorCode::MfaCancelled => "mfa_cancelled",
            ErrorCode::MfaTimeout => "mfa_timeout",
            ErrorCode::CredentialsCancelled => "credentials_cancelled",
            ErrorCode::Locked => "locked",
            ErrorCode::Failed => "failed",
            ErrorCode::AppQuitting => "app_quitting",
            ErrorCode::Disabled => "disabled",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::Denied => "denied",
        }
    }
}

/// A connection state as the client sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WireState {
    Disconnected,
    Connecting,
    WaitingForMfa,
    /// MacVPN's credential prompt is open. An addition to API v1 (1.1.0).
    WaitingForCredentials,
    Connected,
    Disconnecting,
    Failed,
}

impl WireState {
    pub fn as_str(self) -> &'static str {
        match self {
            WireState::Disconnected => "disconnected",
            WireState::Connecting => "connecting",
            WireState::WaitingForMfa => "waiting_for_mfa",
            WireState::WaitingForCredentials => "waiting_for_credentials",
            WireState::Connected => "connected",
            WireState::Disconnecting => "disconnecting",
            WireState::Failed => "failed",
        }
    }
}

/// Waiting for a code or a web / push approval is `waiting_for_mfa`, waiting for the credential prompt
/// `waiting_for_credentials`; the IP and the failure reason stay inside.
pub fn wire_state(state: &ConnectionState) -> WireState {
    match state {
        ConnectionState::Disconnected => WireState::Disconnected,
        ConnectionState::Connecting => WireState::Connecting,
        ConnectionState::AwaitingAuth(AuthWait { kind: AuthWaitKind::Credentials, .. }) => {
            WireState::WaitingForCredentials
        }
        ConnectionState::AwaitingAuth(_) => WireState::WaitingForMfa,
        ConnectionState::Connected { .. } => WireState::Connected,
        ConnectionState::Disconnecting => WireState::Disconnecting,
        ConnectionState::Failed(_) => WireState::Failed,
    }
}

/// Parses one request line (its trailing `\n` / `\r\n` may be included).
///
/// An over-long line or invalid UTF-8 is refused before any JSON parsing, so its `id` is unknown. Otherwise the
/// line must be one JSON object without duplicate keys at its top level, then it must match a [`Request`] exactly.
pub fn parse_line(bytes: &[u8]) -> Result<Request, ParseError> {
    let bad = |id| ParseError { id, code: ErrorCode::BadRequest };
    let bytes = bytes.strip_suffix(b"\n").map_or(bytes, |b| b.strip_suffix(b"\r").unwrap_or(b));
    if bytes.len() > MAX_LINE {
        return Err(bad(None));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad(None))?;
    let raw = serde_json::from_str::<RawObject>(text).map_err(|_| bad(None))?;
    let id = raw.fields.get("id").and_then(Value::as_u64);
    if raw.duplicate {
        return Err(bad(id));
    }
    let unknown_op = matches!(raw.fields.get("op"), Some(Value::String(op)) if !KNOWN_OPS.contains(&op.as_str()));
    match Request::deserialize(Value::Object(raw.fields)) {
        Ok(request) => validate(request).map_err(|code| ParseError { id, code }),
        Err(_) if unknown_op => Err(ParseError { id, code: ErrorCode::Unsupported }),
        Err(_) => Err(bad(id)),
    }
}

/// A top-level JSON object read key by key, so that a repeated key is noticed (`serde_json::Value` silently keeps
/// the last one). The first value of a repeated key is kept.
struct RawObject {
    fields: Map<String, Value>,
    duplicate: bool,
}

impl<'de> Deserialize<'de> for RawObject {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;

        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = RawObject;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RawObject, A::Error> {
                let mut fields = Map::new();
                let mut duplicate = false;
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    if fields.contains_key(&key) {
                        duplicate = true;
                    } else {
                        fields.insert(key, value);
                    }
                }
                Ok(RawObject { fields, duplicate })
            }
        }

        deserializer.deserialize_map(ObjectVisitor)
    }
}

fn validate(request: Request) -> Result<Request, ErrorCode> {
    match request {
        Request::Pair { id, name } => Ok(Request::Pair { id, name: sanitize_name(&name)? }),
        Request::Up { connection, .. } | Request::Down { connection, .. } if !is_uuid_shaped(&connection) => {
            Err(ErrorCode::BadRequest)
        }
        // A `hello` token of any shape is passed on: the server fails a malformed one exactly like a wrong one
        // (spec section 5), so the reply never tells which part was wrong.
        other => Ok(other),
    }
}

/// The client's self-reported name cleaned like the MFA texts (control characters to spaces, format characters
/// dropped, trimmed); 1–64 characters and at most 256 bytes must remain. `AuthText::sanitize` leaves no control
/// character, so none is checked for here.
fn sanitize_name(name: &str) -> Result<String, ErrorCode> {
    let clean = AuthText::sanitize(name);
    let count = swift_str::characters(&clean).len();
    if count == 0 || count > MAX_NAME_CHARACTERS || clean.len() > MAX_NAME_BYTES {
        return Err(ErrorCode::BadRequest);
    }
    Ok(clean)
}

/// Exactly 43 characters of the base64url alphabet, no padding. A `hello` with any other token fails like one
/// with a wrong token.
pub fn is_token_shaped(token: &str) -> bool {
    token.len() == TOKEN_LENGTH && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A character that must not appear in a peer's executable path: a control character (C0, DEL, C1), a Unicode
/// format character (Cf: bidi overrides and isolates, zero-width, BOM, soft hyphen) or a line / paragraph
/// separator. Such a path could forge or hide text in an audit line or in the pairing window.
pub fn is_unsafe_text_char(c: char) -> bool {
    c.is_control() || is_format_character(c) || matches!(c, '\u{2028}' | '\u{2029}')
}

/// The path has a character of [`is_unsafe_text_char`]: `pair` and `hello` from it are refused.
pub fn has_unsafe_text_chars(s: &str) -> bool {
    s.chars().any(is_unsafe_text_char)
}

/// `s` with every character of [`is_unsafe_text_char`] written as `\u{…}` (lowercase hex), for an audit line or a
/// display. Text without such characters comes back unchanged.
pub fn escape_unsafe_text(s: &str) -> String {
    if !has_unsafe_text_chars(s) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if is_unsafe_text_char(c) {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

/// `8-4-4-4-12` hex digits, either case (a managed connection's UUID or a system VPN's scutil service ID).
pub fn is_uuid_shaped(key: &str) -> bool {
    parse_uuid(key).is_some()
}

fn line(obj: Map<String, Value>) -> String {
    let mut s = Value::Object(obj).to_string();
    s.push('\n');
    s
}

fn head(id: Option<u64>, ok: bool) -> Map<String, Value> {
    let mut obj = Map::new();
    if let Some(id) = id {
        obj.insert("id".into(), Value::from(id));
    }
    obj.insert("ok".into(), Value::Bool(ok));
    obj
}

/// `{"id":…,"ok":true,…extra}`; `extra` cannot override `id` or `ok`. No `id` key when `id` is `None`.
pub fn reply_ok(id: Option<u64>, extra: Map<String, Value>) -> String {
    let mut obj = head(id, true);
    for (key, value) in extra {
        if key != "id" && key != "ok" {
            obj.insert(key, value);
        }
    }
    line(obj)
}

/// `{"id":…,"ok":false,"error":"<code>","message":…}`; no `message` key when it is `None`.
pub fn reply_err(id: Option<u64>, code: ErrorCode, message: Option<&str>) -> String {
    let mut obj = head(id, false);
    obj.insert("error".into(), Value::from(code.as_str()));
    if let Some(message) = message {
        obj.insert("message".into(), Value::from(message));
    }
    line(obj)
}

/// The unsolicited `{"event":"state","connection":"<key>","state":"…","reason":…}`; no `reason` key when `None`.
pub fn event_state(key: &str, state: WireState, reason: Option<&str>) -> String {
    let mut obj = Map::new();
    obj.insert("event".into(), Value::from("state"));
    obj.insert("connection".into(), Value::from(key));
    obj.insert("state".into(), Value::from(state.as_str()));
    if let Some(reason) = reason {
        obj.insert("reason".into(), Value::from(reason));
    }
    line(obj)
}

/// The unsolicited `{"event":"closing","reason":"disabled"|"app_quitting"}`: the last line an authenticated
/// client gets before the server closes its connection because the setting was turned off or MacVPN quits.
pub fn event_closing(reason: ErrorCode) -> String {
    let mut obj = Map::new();
    obj.insert("event".into(), Value::from("closing"));
    obj.insert("reason".into(), Value::from(reason.as_str()));
    line(obj)
}
