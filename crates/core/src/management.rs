//! The part of the OpenVPN management interface (doc/management-notes.txt, OpenVPN 2.7) the root-side bridge
//! (`mvpn mgmt-bridge`) uses; port of `ManagementProtocol.swift`. Pure, testable logic: parsing input lines (with
//! strict validation) and building the outgoing commands. The outgoing commands come from a closed enum
//! ([`ManagementCommand`]): there is no generic forwarding, no other command can be built.

use crate::mfa::{self, AuthResponseKind, AuthText, WebAuthURL};
use crate::swift_base64;
use crate::swift_str;

/// A static challenge request from `>PASSWORD:Need 'Auth' username/password SC:<flag>,<text>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementStaticRequest {
    pub echo: bool,
    /// FORMAT bit: plain concatenation of the password and the code (otherwise SCRV1).
    pub concat: bool,
    pub text: String,
}

/// Dynamic challenge: `CRV1:<flags>:<state_id>:<username_base64>:<challenge_text>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CRV1Challenge {
    pub echo: bool,
    pub response_required: bool,
    pub state_id: String,
    pub username: String,
    pub text: String,
}

impl CRV1Challenge {
    pub const MAX_STATE_ID_BYTES: usize = 128;
    pub const MAX_USERNAME_BYTES: usize = 255;

    /// `None`: malformed or over the limits (the bridge treats it as an authentication failure).
    pub fn parse(s: &str) -> Option<CRV1Challenge> {
        if !swift_str::has_prefix(s, "CRV1:") {
            return None;
        }
        let rest = &s[5..];
        let parts = swift_str::split(rest, ":", 3, false);
        if parts.len() != 4 {
            return None;
        }
        let flags = swift_str::split(parts[0], ",", usize::MAX, true);
        if !flags.iter().all(|f| swift_str::eq(f, "E") || swift_str::eq(f, "R")) {
            return None;
        }
        let state = parts[1];
        if state.is_empty() || state.len() > Self::MAX_STATE_ID_BYTES || !state.bytes().all(Self::is_state_byte) {
            return None;
        }
        let user64 = parts[2];
        if user64.len() > 400 || !ManagementParser::is_base64(user64, true) {
            return None;
        }
        let user = String::from_utf8(swift_base64::decode(user64)?).ok()?;
        if user.len() > Self::MAX_USERNAME_BYTES || mfa::has_control(&user) {
            return None;
        }
        Some(CRV1Challenge {
            echo: flags.iter().any(|f| swift_str::eq(f, "E")),
            response_required: flags.iter().any(|f| swift_str::eq(f, "R")),
            state_id: state.to_string(),
            username: user,
            text: AuthText::sanitize(parts[3]),
        })
    }

    /// Visible ASCII, without quote, apostrophe, backslash and colon.
    pub fn is_state_byte(b: u8) -> bool {
        (0x21..=0x7E).contains(&b) && b != 0x22 && b != 0x27 && b != 0x5C && b != 0x3A
    }

    /// The answer's password: `CRV1::<state_id>::<answer>`.
    pub fn password(&self, response: &str) -> String {
        format!("CRV1::{}::{response}", self.state_id)
    }
}

/// The meaning of a management line. What is not listed here is `Ignored` (the bridge does not react and does
/// not pass it on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagementEvent {
    Hold,
    /// `>PASSWORD:Need 'Auth' username/password` (with an optional static challenge).
    NeedAuth(Option<ManagementStaticRequest>),
    /// A password the bridge does not give (e.g. 'Private Key', 'HTTP Proxy', user name only).
    NeedOther,
    /// `>PASSWORD:Verification Failed: 'Auth' ['CRV1:…']`: dynamic challenge, answer the next `Need 'Auth'`.
    DynamicChallenge(CRV1Challenge),
    /// Any other authentication failure (a malformed CRV1 too): final.
    AuthFailed,
    /// `SESSION:` (expired auth token: OpenVPN retries with the password) or `TEMP` (temporary server error): not
    /// final.
    AuthRetry,
    /// `>INFOMSG:OPEN_URL:` / `WEB_AUTH:` – only a valid https URL; a non-https URL is dropped (`None`).
    WebAuth(Option<String>),
    /// `>INFOMSG:CR_TEXT:<flags>:<text>`: the answer is `cr-response <base64>`.
    CrText {
        echo: bool,
        text: String,
    },
    /// `>STATE:…,AUTH_PENDING,timeout N,…`
    AuthPending(Option<i64>),
    /// `>STATE:…,CONNECTED,…`
    Connected,
    Fatal,
    Ignored,
}

pub struct ManagementParser;

impl ManagementParser {
    /// A longer input line is dropped (the bridge skips it up to the next line end).
    pub const MAX_LINE_BYTES: usize = 4096;

    pub fn parse(line: &str) -> ManagementEvent {
        if line.len() > Self::MAX_LINE_BYTES {
            return ManagementEvent::Ignored;
        }
        if swift_str::has_prefix(line, ">HOLD:") {
            return ManagementEvent::Hold;
        }
        if swift_str::has_prefix(line, ">FATAL:") {
            return ManagementEvent::Fatal;
        }
        if swift_str::has_prefix(line, ">PASSWORD:") {
            return Self::parse_password(&line[10..]);
        }
        if swift_str::has_prefix(line, ">INFOMSG:") {
            return Self::parse_info(&line[9..]);
        }
        if swift_str::has_prefix(line, ">STATE:") {
            return Self::parse_state(&line[7..]);
        }
        ManagementEvent::Ignored
    }

    fn parse_password(s: &str) -> ManagementEvent {
        // Auth-Token: a secret, never processed or passed on.
        if swift_str::has_prefix(s, "Auth-Token:") {
            return ManagementEvent::Ignored;
        }
        if swift_str::eq(s, "Need 'Auth' username/password") {
            return ManagementEvent::NeedAuth(None);
        }
        const SC_PREFIX: &str = "Need 'Auth' username/password SC:";
        if swift_str::has_prefix(s, SC_PREFIX) {
            let rest = &s[SC_PREFIX.len()..];
            let Some(comma) = swift_str::first_index(rest, ",") else { return ManagementEvent::AuthFailed };
            let Ok(flag) = rest[..comma].parse::<i64>() else { return ManagementEvent::AuthFailed };
            if !(0..=3).contains(&flag) {
                return ManagementEvent::AuthFailed;
            }
            let text = AuthText::sanitize(&rest[comma + 1..]);
            return ManagementEvent::NeedAuth(Some(ManagementStaticRequest {
                echo: flag & 1 == 1,
                concat: flag & 2 == 2,
                text,
            }));
        }
        if swift_str::has_prefix(s, "Need ") {
            return ManagementEvent::NeedOther;
        }
        const FAIL_PREFIX: &str = "Verification Failed: 'Auth' ['";
        if swift_str::has_prefix(s, FAIL_PREFIX) && swift_str::has_suffix(s, "']") {
            let characters = swift_str::characters(s);
            let prefix_len = swift_str::characters(FAIL_PREFIX).len();
            if characters.len() < prefix_len + 2 {
                return ManagementEvent::AuthFailed;
            }
            let inner: String = characters[prefix_len..characters.len() - 2].concat();
            if let Some(challenge) = CRV1Challenge::parse(&inner) {
                return ManagementEvent::DynamicChallenge(challenge);
            }
            if swift_str::has_prefix(&inner, "SESSION:") || swift_str::has_prefix(&inner, "TEMP") {
                return ManagementEvent::AuthRetry;
            }
            return ManagementEvent::AuthFailed;
        }
        if swift_str::has_prefix(s, "Verification Failed") {
            return ManagementEvent::AuthFailed;
        }
        ManagementEvent::Ignored
    }

    fn parse_info(s: &str) -> ManagementEvent {
        if swift_str::has_prefix(s, "OPEN_URL:") {
            return ManagementEvent::WebAuth(WebAuthURL::validate(&s[9..]));
        }
        if swift_str::has_prefix(s, "WEB_AUTH:") {
            // WEB_AUTH:<flags>:<url>; the flags (e.g. proxy=…) do not matter, the URL follows the first colon.
            let rest = &s[9..];
            let Some(colon) = swift_str::first_index(rest, ":") else { return ManagementEvent::WebAuth(None) };
            // The proxy variant (WEB_AUTH:proxy=…;…;user64;pass64,flags:url) would carry a proxy and a password:
            // not supported.
            if swift_str::contains(&rest[..colon], "proxy=") {
                return ManagementEvent::WebAuth(None);
            }
            return ManagementEvent::WebAuth(WebAuthURL::validate(&rest[colon + 1..]));
        }
        if swift_str::has_prefix(s, "CR_TEXT:") {
            let rest = &s[8..];
            let Some(colon) = swift_str::first_index(rest, ":") else { return ManagementEvent::AuthFailed };
            let flags = swift_str::split(&rest[..colon], ",", usize::MAX, true);
            if !flags.iter().all(|f| swift_str::eq(f, "E") || swift_str::eq(f, "R")) {
                return ManagementEvent::AuthFailed;
            }
            return ManagementEvent::CrText {
                echo: flags.iter().any(|f| swift_str::eq(f, "E")),
                text: AuthText::sanitize(&rest[colon + 1..]),
            };
        }
        ManagementEvent::Ignored
    }

    fn parse_state(s: &str) -> ManagementEvent {
        let fields = swift_str::split(s, ",", usize::MAX, false);
        if fields.len() < 2 {
            return ManagementEvent::Ignored;
        }
        if swift_str::eq(fields[1], "AUTH_PENDING") {
            let mut timeout = None;
            if fields.len() >= 3
                && swift_str::has_prefix(fields[2], "timeout ")
                && let Ok(n) = fields[2][8..].parse::<i64>()
                && (0..=86_400).contains(&n)
            {
                timeout = Some(n);
            }
            return ManagementEvent::AuthPending(timeout);
        }
        if swift_str::eq(fields[1], "CONNECTED") {
            return ManagementEvent::Connected;
        }
        ManagementEvent::Ignored
    }

    pub fn is_base64(s: &str, allow_empty: bool) -> bool {
        if s.is_empty() {
            return allow_empty;
        }
        if !s.len().is_multiple_of(4) {
            return false;
        }
        crate::validators::matches(s, "^[A-Za-z0-9+/]+={0,2}$")
    }
}

/// An OpenVPN command token is at most 256 bytes (`OPTION_PARM_SIZE`); a value (user name, password) at most this.
pub const MAX_VALUE_BYTES: usize = 255;
/// OpenVPN's 1024-byte command buffer: bytes beyond it would run as a new command.
pub const MAX_LINE_BYTES: usize = 1023;

/// The complete list of commands the bridge may send. No other management command can be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagementCommand {
    StateOn,
    HoldRelease,
    Username(String),
    Password(String),
    /// `cr-response <base64>` (CR_TEXT answer).
    CrResponse(String),
}

impl ManagementCommand {
    /// The line to send (without line end). `None`: the value cannot be sent (empty user name, control
    /// character, too long).
    pub fn line(&self) -> Option<String> {
        let line = self.unchecked()?;
        (line.len() <= MAX_LINE_BYTES).then_some(line)
    }

    fn unchecked(&self) -> Option<String> {
        match self {
            ManagementCommand::StateOn => Some("state on".into()),
            ManagementCommand::HoldRelease => Some("hold release".into()),
            ManagementCommand::Username(v) => {
                if v.is_empty() {
                    return None;
                }
                Some(format!("username \"Auth\" {}", Self::quote(v)?))
            }
            ManagementCommand::Password(v) => Some(format!("password \"Auth\" {}", Self::quote(v)?)),
            ManagementCommand::CrResponse(v) => {
                let b64 = swift_base64::encode(v.as_bytes());
                (b64.len() <= MAX_VALUE_BYTES).then(|| format!("cr-response {b64}"))
            }
        }
    }

    /// In quotes, `\` and `"` escaped (the management "Command Parsing" rules). A control character, or a value
    /// over `MAX_VALUE_BYTES`: `None`.
    pub fn quote(v: &str) -> Option<String> {
        if v.len() > MAX_VALUE_BYTES || mfa::has_control(v) {
            return None;
        }
        Some(format!("\"{}\"", v.replace('\\', "\\\\").replace('"', "\\\"")))
    }
}

/// The answer `mvpn respond` writes into the run directory (`kind=…`, `response=…`), checked again by the bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagementResponse {
    pub kind: AuthResponseKind,
    pub response: String,
}

impl ManagementResponse {
    pub const MAX_FILE_BYTES: usize = 1024;

    pub fn parse(data: &[u8]) -> Option<ManagementResponse> {
        if data.len() > Self::MAX_FILE_BYTES {
            return None;
        }
        let text = swift_str::string_from_utf8_data(data.to_vec())?;
        let mut kind = None;
        let mut response = String::new();
        for line in swift_str::split(&text, "\n", usize::MAX, true) {
            if swift_str::has_prefix(line, "kind=") {
                kind = Some(AuthResponseKind::from_raw_value(&line[5..])?);
            } else if swift_str::has_prefix(line, "response=") {
                response = line[9..].to_string();
            } else {
                return None;
            }
        }
        let kind = kind?;
        mfa::is_valid_code(&response, true).then_some(ManagementResponse { kind, response })
    }
}

/// The bridge's input from `mvpn` (`$RUN/mgmt-creds`, root 0600, deleted right after reading).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ManagementCredentials {
    pub username: String,
    pub password: String,
    /// The password is already in SCRV1 / concat form (the app handled a static challenge).
    pub packed: bool,
}

impl ManagementCredentials {
    pub fn parse(data: &[u8]) -> Option<ManagementCredentials> {
        if data.len() > 4096 {
            return None;
        }
        let text = swift_str::string_from_utf8_data(data.to_vec())?;
        let mut out = ManagementCredentials::default();
        for line in swift_str::split(&text, "\n", usize::MAX, true) {
            if swift_str::has_prefix(line, "username=") {
                out.username = line[9..].to_string();
            } else if swift_str::has_prefix(line, "password=") {
                out.password = line[9..].to_string();
            } else if swift_str::eq(line, "packed=1") {
                out.packed = true;
            } else if swift_str::eq(line, "packed=0") {
                out.packed = false;
            } else {
                return None;
            }
        }
        Some(out)
    }
}
