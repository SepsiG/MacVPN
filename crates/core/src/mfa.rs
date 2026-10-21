//! MFA (spec 10f), port of `MFA.swift`: one-time code appended to the password, OpenVPN static challenge (SCRV1),
//! the code prompt's time limit, display-text sanitizing, web-auth URL validation and the user-readable state
//! file written by the root-side bridge. The code is never stored (meta.json, Keychain) or logged: it only lives
//! in memory until the connection starts.

use crate::date::Date;
use crate::fsx;
use crate::l10n;
use crate::models::{OTPSeparator, Secrets, VPNKind, uuid_string};
use crate::swift_json;
use crate::swift_str::{self, ascii_lowercased, trim_space_tab};
use crate::validators::openvpn::OpenVPNValidator;
use crate::validators::sstp::SSTPConfig;
use serde_json::{Map, Number, Value};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// OpenVPN `static-challenge "<text>" <echo> [scrv1|concat]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticChallenge {
    pub text: String,
    pub echo: bool,
    pub format: ChallengeFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChallengeFormat {
    #[default]
    Scrv1,
    Concat,
}

impl ChallengeFormat {
    pub fn raw_value(self) -> &'static str {
        match self {
            ChallengeFormat::Scrv1 => "scrv1",
            ChallengeFormat::Concat => "concat",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MFAError {
    InvalidCode,
    SstpPassword,
    TooLong,
}

impl MFAError {
    pub fn message(self) -> String {
        match self {
            MFAError::InvalidCode => l10n::tr(
                "The code must not be empty or contain line breaks or control characters (256 characters at most)",
                &[],
            ),
            MFAError::SstpPassword => l10n::tr(
                "The password with the code must not contain quotation marks, backslashes or control characters (SSTP)",
                &[],
            ),
            MFAError::TooLong => l10n::tr("The password and the code together are too long", &[]),
        }
    }
}

impl std::fmt::Display for MFAError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for MFAError {}

/// The upper limit of the code (and of the `mvpn respond` answer) in bytes; `mvpn` and the bridge check the same.
pub const MAX_CODE_BYTES: usize = 256;
/// The code prompt's time limit (seconds).
pub const CODE_PROMPT_TIMEOUT: f64 = 120.0;
/// How long web authentication is waited for (at most, seconds).
pub const WEB_AUTH_TIMEOUT: f64 = 300.0;

/// Not empty (unless allowed), at most 256 bytes, no line break and no control character (C0, DEL, C1,
/// U+2028/U+2029).
pub fn is_valid_code(code: &str, allow_empty: bool) -> bool {
    if code.is_empty() {
        return allow_empty;
    }
    code.len() <= MAX_CODE_BYTES && !has_control(code)
}

pub fn has_control(s: &str) -> bool {
    s.chars().any(|c| {
        let v = c as u32;
        v < 0x20 || (0x7F..=0x9F).contains(&v) || v == 0x2028 || v == 0x2029
    })
}

/// A user-given name as stored (a folder, a shared credential, and the import metadata naming them): no control
/// character (see [`has_control`]), Unicode format characters dropped, Foundation whitespace trimmed, then 1 to
/// `max_characters` characters (grapheme clusters). `None`: refused.
pub fn clean_name(name: &str, max_characters: usize) -> Option<String> {
    if has_control(name) {
        return None;
    }
    let cleaned: String = name.chars().filter(|&c| !is_format_character(c)).collect();
    let trimmed = cleaned.trim_matches(swift_str::is_foundation_whitespace);
    let count = swift_str::characters(trimmed).len();
    (1..=max_characters).contains(&count).then(|| trimmed.to_string())
}

/// `SCRV1:<base64 password>:<base64 code>` (OpenVPN management-notes, "Static protocol").
pub fn scrv1(password: &str, code: &str) -> String {
    // Built in one exact allocation, the base64 temporaries wiped (no unwiped copy of the password is freed).
    let password = Zeroizing::new(crate::swift_base64::encode(password.as_bytes()));
    let code = Zeroizing::new(crate::swift_base64::encode(code.as_bytes()));
    let mut out = String::with_capacity("SCRV1:".len() + password.len() + 1 + code.len());
    out.push_str("SCRV1:");
    out.push_str(&password);
    out.push(':');
    out.push_str(&code);
    out
}

/// The static challenge password in the config's format (`scrv1`: SCRV1, `concat`: password + code).
pub fn static_challenge_password(password: &str, code: &str, format: ChallengeFormat) -> String {
    match format {
        ChallengeFormat::Concat => concat(&[password, code]),
        ChallengeFormat::Scrv1 => scrv1(password, code),
    }
}

/// Password + separator + code. With an empty password only the code (no separator).
pub fn append_code(password: &str, code: &str, separator: OTPSeparator) -> String {
    if password.is_empty() { code.to_string() } else { concat(&[password, separator.string(), code]) }
}

/// The parts in one exact allocation (a growing `String` would free unwiped copies of a secret).
fn concat(parts: &[&str]) -> String {
    let mut out = String::with_capacity(parts.iter().map(|p| p.len()).sum());
    for part in parts {
        out.push_str(part);
    }
    out
}

/// A copy of `secrets` whose password is `password`; the copied old password is wiped, not just dropped.
fn with_password(secrets: &Secrets, password: &str) -> Zeroizing<Secrets> {
    let mut out = Zeroizing::new(secrets.clone());
    out.password.zeroize();
    out.password = Some(password.to_string());
    out
}

/// Applies "code appended to the password" per kind: for the root kinds (OpenVPN, strongSwan EAP, SSTP) the stdin
/// password, for native L2TP / Cisco IPsec and system VPNs the `SCNetworkConnection` options' password. The SSTP
/// password rule (no `"`, `\`, control character) applies to the combined password too.
pub fn apply_code(
    code: &str,
    separator: OTPSeparator,
    secrets: &Secrets,
    kind: VPNKind,
) -> Result<Zeroizing<Secrets>, MFAError> {
    if !is_valid_code(code, false) {
        return Err(MFAError::InvalidCode);
    }
    let combined = Zeroizing::new(append_code(secrets.password.as_deref().unwrap_or(""), code, separator));
    if kind == VPNKind::Sstp && !SSTPConfig::is_acceptable_password(&combined) {
        return Err(MFAError::SstpPassword);
    }
    let mut out = with_password(secrets, &combined);
    out.one_time_code = Some(code.to_string());
    Ok(out)
}

/// OpenVPN static challenge: the password packed in the config's format, and `mvpn` is told (`challenge=packed`)
/// so the bridge passes it unchanged in the management `password "Auth"` answer.
pub fn apply_static_challenge(
    challenge: &StaticChallenge,
    code: &str,
    secrets: &Secrets,
) -> Result<Zeroizing<Secrets>, MFAError> {
    if !is_valid_code(code, true) {
        return Err(MFAError::InvalidCode);
    }
    let packed =
        Zeroizing::new(static_challenge_password(secrets.password.as_deref().unwrap_or(""), code, challenge.format));
    if packed.len() > crate::management::MAX_VALUE_BYTES {
        return Err(MFAError::TooLong);
    }
    let mut out = with_password(secrets, &packed);
    out.challenge_packed = true;
    if !code.is_empty() {
        out.one_time_code = Some(code.to_string());
    }
    Ok(out)
}

/// The config's `static-challenge` line (top level, outside inline blocks; the last valid one). `None`: none.
/// Tokenized like OpenVPN's `parse_line` (`OpenVPNValidator::tokenize`).
pub fn static_challenge(config: &str) -> Option<StaticChallenge> {
    let mut found = None;
    let mut in_block: Option<String> = None;
    for (_, raw) in crate::validators::numbered_lines(config) {
        let line = trim_space_tab(raw);
        if let Some(block) = &in_block {
            if swift_str::eq(&ascii_lowercased(line), &format!("</{block}>")) {
                in_block = None;
            }
            continue;
        }
        if crate::validators::matches(line, "^<[A-Za-z0-9-]+>$") {
            // The lines of a <connection> block are connection options; static-challenge is not one, so skipped.
            in_block = Some(ascii_lowercased(&line[1..line.len() - 1]));
            continue;
        }
        let Some(tokens) = OpenVPNValidator::tokenize(line) else { continue };
        let Some(head) = tokens.first() else { continue };
        if head.quoted
            || OpenVPNValidator::directive_name(&head.text).as_deref() != Some("static-challenge")
            || !(3..=4).contains(&tokens.len())
        {
            continue;
        }
        let text = &tokens[1].text;
        if text.is_empty() || has_control(text) {
            continue;
        }
        let echo = if swift_str::eq(&tokens[2].text, "0") {
            false
        } else if swift_str::eq(&tokens[2].text, "1") {
            true
        } else {
            continue;
        };
        let mut format = ChallengeFormat::Scrv1;
        if tokens.len() == 4 {
            format = if swift_str::eq(&tokens[3].text, "scrv1") {
                ChallengeFormat::Scrv1
            } else if swift_str::eq(&tokens[3].text, "concat") {
                ChallengeFormat::Concat
            } else {
                continue;
            };
        }
        found = Some(StaticChallenge { text: AuthText::sanitize(text), echo, format });
    }
    found
}

/// The code prompt's time limit (2 minutes), testable logic independent of the window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PromptDeadline {
    pub start: Date,
    pub duration: f64,
}

impl PromptDeadline {
    pub fn new(start: Date) -> Self {
        Self::with_duration(start, CODE_PROMPT_TIMEOUT)
    }

    pub fn with_duration(start: Date, duration: f64) -> Self {
        PromptDeadline { start, duration: f64::max(0.0, duration) }
    }

    /// The bridge's deadline, but at most `maximum` seconds from now.
    pub fn until(start: Date, deadline: Option<Date>, maximum: f64) -> Self {
        let wanted = deadline.map_or(maximum, |d| d.time_interval_since(start));
        PromptDeadline { start, duration: f64::max(0.0, f64::min(wanted, maximum)) }
    }

    pub fn end(&self) -> Date {
        self.start.adding(self.duration)
    }

    pub fn is_expired(&self, now: Date) -> bool {
        now >= self.end()
    }

    /// Whole seconds left (0 when expired).
    pub fn remaining(&self, now: Date) -> i64 {
        i64::max(0, self.end().time_interval_since(now).ceil() as i64)
    }
}

/// Unicode General_Category=Cf (format) ranges, as in Swift's Unicode tables (macOS 27).
const FORMAT_RANGES: &[(u32, u32)] = &[
    (0xAD, 0xAD),
    (0x600, 0x605),
    (0x61C, 0x61C),
    (0x6DD, 0x6DD),
    (0x70F, 0x70F),
    (0x890, 0x891),
    (0x8E2, 0x8E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

pub fn is_format_character(c: char) -> bool {
    let v = c as u32;
    FORMAT_RANGES.iter().any(|&(lo, hi)| (lo..=hi).contains(&v))
}

/// Foundation `CharacterSet.whitespaces`: General_Category Zs and TAB.
fn is_foundation_whitespace(c: char) -> bool {
    swift_str::is_foundation_whitespace(c)
}

/// Texts from the server (or the config) cleaned before display: a space instead of a control character, Unicode
/// format characters (Cf: bidi controls, zero-width, BOM, soft hyphen) dropped, at most `MAX_CHARACTERS`
/// characters (grapheme clusters).
pub struct AuthText;

impl AuthText {
    pub const MAX_CHARACTERS: usize = 200;

    pub fn sanitize(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for c in s.chars().filter(|&c| !is_format_character(c)) {
            let v = c as u32;
            let control = v < 0x20 || (0x7F..=0x9F).contains(&v) || v == 0x2028 || v == 0x2029;
            out.push(if control { ' ' } else { c });
        }
        let trimmed = out.trim_matches(is_foundation_whitespace);
        let characters = swift_str::characters(trimmed);
        if characters.len() > Self::MAX_CHARACTERS {
            let mut cut: String = characters[..Self::MAX_CHARACTERS].concat();
            cut.push('…');
            cut
        } else {
            trimmed.to_string()
        }
    }
}

/// The web authentication URL: `https://` only, at most 1024 bytes, a strict ASCII character set (RFC 3986,
/// without space and control characters). The host comes from the raw text (Foundation would decode punycode
/// to Unicode): an ASCII LDH host name (no trailing dot; a punycode `xn--` label stays, not decoded), an IPv4 or
/// an `[IPv6]` address; no `%` and `@` in the authority. Every other URL is dropped.
pub struct WebAuthURL;

impl WebAuthURL {
    pub const MAX_BYTES: usize = 1024;

    /// The URL's `absoluteString` if it is acceptable.
    pub fn validate(s: &str) -> Option<String> {
        if s.is_empty() || s.len() > Self::MAX_BYTES || !s.bytes().all(Self::is_allowed) {
            return None;
        }
        Self::ascii_host(s)?;
        // `URLComponents(string:)` and `URL(string:)`: they reject a port that is not plain digits (`+443`).
        let u = crate::url::parse(s)?;
        if !u.scheme.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("https"))
            || u.user.is_some()
            || u.password.is_some()
        {
            return None;
        }
        // `URL.absoluteString`: the characters RFC 3986 does not allow there (e.g. `[` in the query) percent-encoded.
        Some(u.absolute_string())
    }

    /// `URL.host` of a validated URL (original case, without IPv6 brackets).
    pub fn host(url: &str) -> Option<String> {
        crate::url::parse(url)?.host
    }

    /// The host to show and log: the original ASCII form in lower case (IPv6 in brackets).
    pub fn display_host(url: &str) -> String {
        Self::ascii_host(url).unwrap_or_default()
    }

    /// The host of an `https://` URL from the raw text, checked and lower-cased; `None` if not allowed.
    pub fn ascii_host(s: &str) -> Option<String> {
        if s.len() > Self::MAX_BYTES || !swift_str::has_prefix(&s.to_lowercase(), "https://") {
            return None;
        }
        let characters = swift_str::characters(s);
        let rest: String = characters.get(8..)?.concat();
        let authority = swift_str::prefix_while(&rest, |c| c != "/" && c != "?" && c != "#");
        if authority.is_empty()
            || swift_str::contains(authority, "%")
            || swift_str::contains(authority, "@")
            || !authority.is_ascii()
        {
            return None;
        }
        let (host, port): (&str, Option<&str>) = if authority.starts_with('[') {
            let close = authority.find(']')?;
            let after = &authority[close + 1..];
            let port = if after.is_empty() { None } else { Some(after.strip_prefix(':')?) };
            (&authority[..=close], port)
        } else if let Some(colon) = authority.rfind(':') {
            (&authority[..colon], Some(&authority[colon + 1..]))
        } else {
            (authority, None)
        };
        if let Some(port) = port {
            // Swift `Int(port)`: an optional sign, then digits.
            let n = port.parse::<i64>().ok()?;
            if !(1..=65535).contains(&n) {
                return None;
            }
        }
        let lower = host.to_lowercase();
        if lower.starts_with('[') {
            crate::validators::sstp::inet_pton6(lower.get(1..lower.len() - 1)?)?;
            return Some(lower);
        }
        Self::is_ldh_hostname(&lower).then_some(lower)
    }

    /// `[a-z0-9-]` labels (1–63, not starting or ending with `-`), at most 253 characters, no trailing dot. An IPv4
    /// address has this shape too.
    pub fn is_ldh_hostname(h: &str) -> bool {
        if h.is_empty() || h.len() > 253 {
            return false;
        }
        h.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    }

    /// `A-Z a-z 0-9 - . _ ~ : / ? # [ ] @ ! $ & ' ( ) * + , ; = %`
    fn is_allowed(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b"-._~:/?#[]@!$&'()*+,;=%".contains(&b)
    }
}

/// The bridge's (`mvpn-mgmt`) state file: `/var/run/macvpn-ui/<id>.json` (the user's, 0600). Only the challenge
/// text, the echo flag, the web URL and the state, never a secret.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthUIState {
    pub v: i64,
    pub seq: i64,
    pub state: AuthUIStateKind,
    pub method: Option<AuthUIMethod>,
    pub text: Option<String>,
    pub echo: Option<bool>,
    pub url: Option<String>,
    /// Unix time; how long the bridge / the server waits.
    pub deadline: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthUIStateKind {
    /// Asks for a code (`method`: crv1, crtext, static).
    Challenge,
    /// Web authentication (`url`: https).
    Webauth,
    /// The server waits for authentication (auth-pending), usable without a URL.
    Pending,
    Failed,
    Cancelled,
    Done,
}

impl AuthUIStateKind {
    const ALL: [AuthUIStateKind; 6] = [
        AuthUIStateKind::Challenge,
        AuthUIStateKind::Webauth,
        AuthUIStateKind::Pending,
        AuthUIStateKind::Failed,
        AuthUIStateKind::Cancelled,
        AuthUIStateKind::Done,
    ];

    pub fn raw_value(self) -> &'static str {
        match self {
            AuthUIStateKind::Challenge => "challenge",
            AuthUIStateKind::Webauth => "webauth",
            AuthUIStateKind::Pending => "pending",
            AuthUIStateKind::Failed => "failed",
            AuthUIStateKind::Cancelled => "cancelled",
            AuthUIStateKind::Done => "done",
        }
    }

    pub fn from_raw_value(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| swift_str::eq(k.raw_value(), s))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthUIMethod {
    Crv1,
    Crtext,
    Static,
    Webauth,
}

impl AuthUIMethod {
    const ALL: [AuthUIMethod; 4] =
        [AuthUIMethod::Crv1, AuthUIMethod::Crtext, AuthUIMethod::Static, AuthUIMethod::Webauth];

    pub fn raw_value(self) -> &'static str {
        match self {
            AuthUIMethod::Crv1 => "crv1",
            AuthUIMethod::Crtext => "crtext",
            AuthUIMethod::Static => "static",
            AuthUIMethod::Webauth => "webauth",
        }
    }

    pub fn from_raw_value(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| swift_str::eq(k.raw_value(), s))
    }
}

/// Swift `JSONDecoder` `Int`: an integral number in range (`1.0` and `1e2` included).
pub(crate) fn json_int(v: &Value) -> Option<i64> {
    if let Some(i) = v.as_i64() {
        return Some(i);
    }
    let f = v.as_f64()?;
    (f.fract() == 0.0 && (-9.223_372_036_854_776e18..9.223_372_036_854_776e18).contains(&f)).then_some(f as i64)
}

impl AuthUIState {
    pub fn new(seq: i64, state: AuthUIStateKind) -> Self {
        AuthUIState { v: 1, seq, state, method: None, text: None, echo: None, url: None, deadline: None }
    }

    /// `<dir>/<id>.json`: `dir` is the platform's state directory (macOS: `mvpn_client::UI_STATE_DIR`, shared with
    /// the helper's `UI_BASE`).
    pub fn path(dir: &std::path::Path, id: &Uuid) -> std::path::PathBuf {
        dir.join(format!("{}.json", uuid_string(id)))
    }

    /// Strict reading: at most 8 KB, known version, the text sanitized, the URL checked again (not https: none).
    pub fn parse(data: &[u8]) -> Option<AuthUIState> {
        if data.len() > 8192 {
            return None;
        }
        let value = swift_json::parse(data).ok()?;
        let obj = value.as_object()?;
        let optional = |key: &str| obj.get(key).filter(|v| !v.is_null());
        let v = json_int(obj.get("v")?)?;
        let seq = json_int(obj.get("seq")?)?;
        let state = AuthUIStateKind::from_raw_value(obj.get("state")?.as_str()?)?;
        let method = match optional("method") {
            None => None,
            Some(m) => Some(AuthUIMethod::from_raw_value(m.as_str()?)?),
        };
        let text = match optional("text") {
            None => None,
            Some(t) => Some(t.as_str()?.to_string()),
        };
        let echo = match optional("echo") {
            None => None,
            Some(e) => Some(e.as_bool()?),
        };
        let url = match optional("url") {
            None => None,
            Some(u) => Some(u.as_str()?.to_string()),
        };
        let deadline = match optional("deadline") {
            None => None,
            Some(d) => Some(d.as_f64()?),
        };
        if v != 1 {
            return None;
        }
        let mut s = AuthUIState { v, seq, state, method, text, echo, url, deadline };
        s.text = s.text.map(|t| AuthText::sanitize(&t));
        if s.url.as_deref().is_some_and(|u| WebAuthURL::validate(u).is_none()) {
            s.url = None;
        }
        if s.state == AuthUIStateKind::Webauth && s.url.is_none() {
            s.state = AuthUIStateKind::Pending;
        }
        Some(s)
    }

    /// `JSONEncoder` with `.sortedKeys` (compact).
    pub fn encoded(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("v".into(), Value::from(self.v));
        m.insert("seq".into(), Value::from(self.seq));
        m.insert("state".into(), Value::String(self.state.raw_value().into()));
        if let Some(method) = self.method {
            m.insert("method".into(), Value::String(method.raw_value().into()));
        }
        if let Some(text) = &self.text {
            m.insert("text".into(), Value::String(text.clone()));
        }
        if let Some(echo) = self.echo {
            m.insert("echo".into(), Value::Bool(echo));
        }
        if let Some(url) = &self.url {
            m.insert("url".into(), Value::String(url.clone()));
        }
        if let Some(deadline) = self.deadline.and_then(Number::from_f64) {
            m.insert("deadline".into(), Value::Number(deadline));
        }
        swift_json::to_compact_sorted(&Value::Object(m)).unwrap_or_default().into_bytes()
    }

    pub fn deadline_date(&self) -> Option<Date> {
        self.deadline.map(Date::from_time_interval_since_1970)
    }

    /// Safe reading: a regular file (no symlink followed, a FIFO never blocks), owned by `expected`, at most 8 KB.
    pub fn read(path: &std::path::Path, expected: &fsx::FileOwner) -> Option<AuthUIState> {
        use std::io::Read;
        let (mut file, meta) = fsx::open_regular(path, fsx::OpenFor::Read, fsx::Follow::No, false).ok()?;
        if fsx::owner(&meta).ok()? != *expected || meta.len() > 8192 {
            return None;
        }
        let mut data = Vec::with_capacity(meta.len() as usize);
        file.read_to_end(&mut data).ok()?;
        if data.len() as u64 != meta.len() {
            return None;
        }
        Self::parse(&data)
    }
}

/// The kind of a `mvpn respond` answer (stdin `kind=`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResponseKind {
    Crv1,
    Static,
    WebauthAck,
    Cancel,
}

impl AuthResponseKind {
    pub const ALL: [AuthResponseKind; 4] =
        [AuthResponseKind::Crv1, AuthResponseKind::Static, AuthResponseKind::WebauthAck, AuthResponseKind::Cancel];

    pub fn raw_value(self) -> &'static str {
        match self {
            AuthResponseKind::Crv1 => "crv1",
            AuthResponseKind::Static => "static",
            AuthResponseKind::WebauthAck => "webauth-ack",
            AuthResponseKind::Cancel => "cancel",
        }
    }

    pub fn from_raw_value(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| swift_str::eq(k.raw_value(), s))
    }

    /// The `mvpn respond` stdin format. The answer is only included for the kinds that carry a code.
    pub fn stdin_payload(self, response: &str) -> Option<String> {
        match self {
            AuthResponseKind::Crv1 | AuthResponseKind::Static => {
                is_valid_code(response, true).then(|| format!("kind={}\nresponse={response}\n", self.raw_value()))
            }
            AuthResponseKind::WebauthAck | AuthResponseKind::Cancel => {
                Some(format!("kind={}\nresponse=\n", self.raw_value()))
            }
        }
    }
}

/// A request to the user interface (code prompt or web confirmation).
#[derive(Debug, Clone, PartialEq)]
pub struct AuthPrompt {
    pub connection_id: String,
    pub connection_name: String,
    pub kind: AuthPromptKind,
    pub deadline: PromptDeadline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthPromptKind {
    /// `echo`: the code in a visible field (otherwise hidden). `from_server`: the text comes from the VPN server
    /// (shown as foreign text, labelled "The VPN server's message:").
    Code { text: String, echo: bool, from_server: bool },
    /// The UI shows the host, asks for confirmation, and only then opens the URL in the browser.
    WebAuth { url: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthPromptResult {
    Code(String),
    /// The web authentication URL was opened in the browser.
    OpenedUrl,
    Cancelled,
    TimedOut,
}
