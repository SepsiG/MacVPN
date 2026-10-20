//! Config import (port of `ConfigImporter.swift`): kind detection, OpenVPN external-file inlining confined to the
//! config's folder (after resolving symlinks), PKCS#12, credential-file candidates, and validation.

use crate::l10n::{self, Arg};
use crate::models::{Secrets, VPNKind, ValidationIssue};
use crate::swift_base64;
use crate::swift_str;
use crate::validators::openvpn::{OpenVPNValidator, RiskyFinding};
use crate::validators::sstp::SSTPConfig;
use regex::{Regex, RegexBuilder};
use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigImportError {
    MissingFile(String),
    /// The referenced file (after resolving symlinks) is not inside the config's folder.
    OutsideBaseDirectory(String),
    FileTooLarge(String),
    /// The file's content is not the format the directive expects (e.g. a PEM certificate for `ca`).
    WrongFormat {
        directive: String,
        file: String,
    },
    Unsupported(String),
    UnknownType,
    /// Native (L2TP / Cisco) export: install it from Finder through macOS Profiles, not into MacVPN.
    NativeProfile,
}

impl ConfigImportError {
    pub fn message(&self) -> String {
        match self {
            ConfigImportError::MissingFile(f) => l10n::tr("Referenced file not found: %@", &[Arg::Str(f)]),
            ConfigImportError::OutsideBaseDirectory(f) => {
                l10n::tr("The referenced file is outside the config's folder: %@", &[Arg::Str(f)])
            }
            ConfigImportError::FileTooLarge(f) => {
                l10n::tr("The referenced file is larger than 1 MB: %@", &[Arg::Str(f)])
            }
            ConfigImportError::WrongFormat { directive, file } => l10n::tr(
                "The file for the %@ directive (%@) does not have the expected format",
                &[Arg::Str(directive), Arg::Str(file)],
            ),
            ConfigImportError::Unsupported(d) => l10n::tr("Directive not supported for import: %@", &[Arg::Str(d)]),
            ConfigImportError::UnknownType => l10n::tr("Cannot detect the config type", &[]),
            ConfigImportError::NativeProfile => l10n::tr(
                "A .mobileconfig profile cannot be imported into MacVPN. Double-click it in Finder: macOS installs it as a profile, then approve it in System Settings → General → Device Management (Profiles).",
                &[],
            ),
        }
    }
}

impl std::fmt::Display for ConfigImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for ConfigImportError {}

/// Credentials from an OpenVPN import's files.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportedCredentials {
    pub username: Option<String>,
    pub password: Option<String>,
    /// The `auth-user-pass` file, if the user name / password came from it.
    pub credentials_file: Option<String>,
    pub key_password: Option<String>,
    /// The `askpass` file, if the key password came from it.
    pub key_password_file: Option<String>,
    /// Referenced but unread (missing, outside the folder, too large, wrong format) secret files.
    pub unread_files: Vec<String>,
}

impl ImportedCredentials {
    /// The secret files that were read (offered to the user for confirmation). The import stores nothing: the
    /// caller (the app) asks, and only after confirmation puts them into the Keychain.
    pub fn candidate_files(&self) -> Vec<String> {
        self.credentials_file.iter().chain(self.key_password_file.iter()).cloned().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedImport {
    pub kind: VPNKind,
    pub config: String,
    pub inlined_files: Vec<String>,
    /// The validator's blocking issues. The import is still saved, so it can be fixed in the editor.
    pub issues: Vec<ValidationIssue>,
    /// OpenVPN: the RISKY directives needing acknowledgement. Not an error: acknowledged in the editor's panel.
    pub risky: Vec<RiskyFinding>,
    /// OpenVPN: secrets read from `auth-user-pass <file>` / `askpass <file>` (to the Keychain, never into the
    /// config) and the files that could not be read.
    pub credentials: ImportedCredentials,
    /// OpenVPN: the config has an encrypted private key (it needs the "Private key password" field).
    pub has_encrypted_key: bool,
    /// The exported metadata line (`# macvpn-meta: …`), removed from `config`; `None` when the file has none (an
    /// older export, or a config from elsewhere) or it is invalid (then it stays in the config as a comment).
    pub meta: Option<ExportMeta>,
}

/// The metadata line at the top of an exported text config (plan B, resolved points "Exported metadata"):
/// `# macvpn-meta: {"credentialName":"Office AD","folder":["Work","Clients"]}`. Both keys are optional; it never
/// carries a secret.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportMeta {
    /// The folder path from the root (Task 16); every component passed the folder-name rule.
    pub folder: Option<Vec<String>>,
    /// The name of the shared credential the connection was linked to (spec 3a). On import it is only offered:
    /// when a credential with exactly this name exists, the user is asked whether to use it for this connection's
    /// server (a file must never send a stored password to a server of its choice by itself).
    pub credential_name: Option<String>,
}

/// The metadata line's prefix.
pub const EXPORT_META_PREFIX: &str = "# macvpn-meta: ";
/// The longest metadata line (without the line break), in bytes.
pub const MAX_EXPORT_META_BYTES: usize = 4096;

/// The longest folder or credential name, in characters (grapheme clusters): the vault's
/// `MAX_FOLDER_NAME_CHARACTERS` and `MAX_CREDENTIAL_NAME_CHARACTERS`.
pub const MAX_META_NAME_CHARACTERS: usize = 64;

/// A folder path component or a credential name in the metadata, through the vault's name rule
/// ([`crate::mfa::clean_name`], as `validate_folder_name` / `validate_credential_name`): the cleaned name, or
/// `None`, which refuses the whole line.
fn meta_name(value: &serde_json::Value) -> Option<String> {
    crate::mfa::clean_name(value.as_str()?, MAX_META_NAME_CHARACTERS)
}

fn parse_export_meta(json: &str) -> Option<ExportMeta> {
    let serde_json::Value::Object(map) = serde_json::from_str::<serde_json::Value>(json).ok()? else { return None };
    let folder = match map.get("folder") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Array(parts)) => Some(parts.iter().map(meta_name).collect::<Option<Vec<_>>>()?),
        Some(_) => return None,
    };
    let credential_name = match map.get("credentialName") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => Some(meta_name(value)?),
    };
    Some(ExportMeta { folder, credential_name })
}

/// Splits a valid metadata line off the top of an imported config: the metadata and the config without it. A
/// missing or invalid line (not strict JSON, wrong types, over [`MAX_EXPORT_META_BYTES`]) gives `None` and the
/// whole text, so the line stays in the config as an ordinary comment. Unknown keys are ignored.
pub fn take_export_meta(content: &str) -> (Option<ExportMeta>, &str) {
    let Some(after) = content.strip_prefix(EXPORT_META_PREFIX) else { return (None, content) };
    let (line, rest) = match after.find('\n') {
        Some(i) => (&after[..i], &after[i + 1..]),
        None => (after, ""),
    };
    let line = line.strip_suffix('\r').unwrap_or(line);
    if EXPORT_META_PREFIX.len() + line.len() > MAX_EXPORT_META_BYTES {
        return (None, content);
    }
    match parse_export_meta(line) {
        Some(meta) => (Some(meta), rest),
        None => (None, content),
    }
}

/// The longest host [`remote_host`] returns, in bytes (a DNS name has at most 253).
pub const MAX_REMOTE_HOST_BYTES: usize = 253;

/// The server a config connects to, for the import question "Use the shared credential 'X' for this connection
/// to <host>?" and the Connections window's search: OpenVPN's first `remote`, WireGuard's first `Endpoint`,
/// strongSwan's first `remote_addrs` entry, SSTP's `server=`. Only the host ([`sanitized_host`]): a user name and a
/// port are stripped; `None` when there is none, or it is not a host name or an IP literal.
pub fn remote_host(kind: VPNKind, config: &str) -> Option<String> {
    let raw = config.lines().find_map(|raw| {
        let line = raw.trim_matches(|c: char| c.is_whitespace());
        if line.starts_with('#') || line.starts_with(';') {
            return None;
        }
        match kind {
            VPNKind::Openvpn => {
                let mut words = line.split_whitespace();
                (words.next()? == "remote").then(|| words.next()).flatten()
            }
            VPNKind::Wireguard => {
                let (key, value) = line.split_once('=')?;
                key.trim().eq_ignore_ascii_case("endpoint").then(|| value.trim())
            }
            VPNKind::Strongswan => {
                let (key, value) = line.split_once('=')?;
                (key.trim() == "remote_addrs").then(|| value.split(',').next().unwrap_or("").trim())
            }
            VPNKind::Sstp => line.strip_prefix("server=").map(str::trim),
            VPNKind::L2tp | VPNKind::Cisco => None,
        }
    })?;
    sanitized_host(raw)
}

/// The host of a server address as a config writes it: `[user[:password]@]host[:port]` or `[v6]:port`. Only a
/// host name (labels of letters, digits, `-` and `_`, not starting or ending with `-`, at most 63 bytes each, the
/// last one not all digits, a trailing root dot dropped) or an IP literal (a v6 one without its brackets) of at most
/// [`MAX_REMOTE_HOST_BYTES`]; anything else (a URL, a path, a CIDR, `%any`, a range, a bad port) is `None`.
pub fn sanitized_host(raw: &str) -> Option<String> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let raw = raw.trim();
    // User info: everything up to the last `@`.
    let hostport = raw.rsplit_once('@').map_or(raw, |(_, h)| h);
    let valid_port = |p: &str| {
        !p.is_empty()
            && p.len() <= 5
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n))
    };
    if let Some(rest) = hostport.strip_prefix('[') {
        let (v6, after) = rest.split_once(']')?;
        if !(after.is_empty() || after.strip_prefix(':').is_some_and(valid_port)) {
            return None;
        }
        return v6.parse::<Ipv6Addr>().ok().map(|_| v6.to_string());
    }
    if hostport.parse::<Ipv6Addr>().is_ok() {
        return Some(hostport.to_string());
    }
    let host = match hostport.split_once(':') {
        Some((host, port)) if valid_port(port) => host,
        Some(_) => return None,
        None => hostport,
    };
    if host.parse::<Ipv4Addr>().is_ok() {
        return Some(host.to_string());
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    };
    // A numeric last label is no host name (`10.0.0.1-10.0.0.9`, `999.1.1.1`): only an IPv4 literal ends in digits.
    let numeric_tail = host.rsplit('.').next().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    let ok = !host.is_empty() && host.len() <= MAX_REMOTE_HOST_BYTES && host.split('.').all(label_ok) && !numeric_tail;
    ok.then(|| host.to_string())
}

/// The server a connection sends its credentials to, for display (the credential prompt of a team slot, the
/// catalog update notice): a native connection's server, else [`remote_host`] of the config. The same display rules
/// as [`remote_host`].
pub fn server_host(kind: VPNKind, native: Option<&crate::models::NativeSettings>, config: &str) -> Option<String> {
    if kind.is_native() {
        let host = native?.server.trim().to_string();
        let ok = !host.is_empty()
            && host.len() <= MAX_REMOTE_HOST_BYTES
            && !crate::mfa::has_control(&host)
            && !host.chars().any(|c| c.is_whitespace() || c == '"' || c == '\'');
        return ok.then_some(host);
    }
    remote_host(kind, config)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineResult {
    pub config: String,
    /// The inlined files, as the config referred to them (in order).
    pub inlined_files: Vec<String>,
    /// The secrets of `auth-user-pass <file>` and `askpass <file>` (not in the config).
    pub credentials: ImportedCredentials,
}

/// The upper size limit of an inlined file.
pub const MAX_INLINE_FILE_SIZE: usize = 1_048_576;
/// The upper size limit of a secret file (`auth-user-pass`, `askpass`).
pub const MAX_CREDENTIALS_FILE_SIZE: usize = 1024;

/// The PEM block type(s) expected per directive (in the `-----BEGIN <type>-----` line).
static EXPECTED_FORMAT: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        ("ca", "CERTIFICATE"),
        ("cert", "CERTIFICATE"),
        ("extra-certs", "CERTIFICATE"),
        ("key", "(?:[A-Z0-9]+ )*PRIVATE KEY"),
        ("tls-auth", "OpenVPN Static key V1"),
        ("tls-crypt", "OpenVPN Static key V1"),
        ("secret", "OpenVPN Static key V1"),
        ("tls-crypt-v2", "OpenVPN tls-crypt-v2 client key"),
        ("dh", "(?:X9\\.42 )?DH PARAMETERS"),
    ])
});

/// The PEM type pattern a directive's file must have (`ca`: `CERTIFICATE`, …).
pub fn expected_format(directive: &str) -> Option<&'static str> {
    EXPECTED_FORMAT.get(directive).copied()
}

/// `(fileName as NSString).pathExtension`.
pub fn path_extension(file_name: &str) -> String {
    let trimmed = file_name.trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or("");
    match last.rfind('.') {
        // The part before the extension may not be empty, `.` or `..` (a hidden file has no extension).
        Some(dot)
            if !matches!(&last[..dot], "" | "." | "..")
                && !last[dot + 1..].chars().any(|c| {
                    matches!(c, ' ' | '/' | '\u{61C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
                }) =>
        {
            last[dot + 1..].to_string()
        }
        _ => String::new(),
    }
}

/// Swift line terminators for `(?m)^` and `.` (besides `\r` and `\n`, which CRLF mode handles): replaced by `\n`,
/// which every class used here treats the same way (`\s`, not `\S`).
fn normalize_terminators(s: &str) -> std::borrow::Cow<'_, str> {
    if s.contains(['\u{B}', '\u{C}', '\u{85}', '\u{2028}', '\u{2029}']) {
        s.replace(['\u{B}', '\u{C}', '\u{85}', '\u{2028}', '\u{2029}'], "\n").into()
    } else {
        s.into()
    }
}

fn multiline(pattern: &str) -> Regex {
    RegexBuilder::new(pattern).multi_line(true).crlf(true).build().expect("valid pattern")
}

/// `content.range(of: pattern, options: .regularExpression) != nil` for the `(?m)` patterns of this module.
fn matches_multiline(content: &str, re: &Regex) -> bool {
    let normalized = normalize_terminators(content);
    swift_str::matches(&normalized, re)
}

/// Kind detection by extension, then by content.
pub fn detect_kind(file_name: &str, content: &str) -> Option<VPNKind> {
    static CONNECTIONS: LazyLock<Regex> = LazyLock::new(|| multiline("^\\s*connections\\s*\\{"));
    static REMOTE: LazyLock<Regex> = LazyLock::new(|| multiline("^\\s*remote\\s+\\S+"));
    static CLIENT: LazyLock<Regex> = LazyLock::new(|| multiline("^\\s*(client|dev\\s+tun)"));
    static SSTP_SERVER: LazyLock<Regex> = LazyLock::new(|| multiline("^[ \\t]*server=[^\\s=]+[ \\t]*\\r?$"));
    static SSTP_KEYS: LazyLock<Regex> = LazyLock::new(|| multiline("^[ \\t]*(user|cert|route_all|peer_dns)="));
    let ext = path_extension(file_name).to_lowercase();
    if ext == "ovpn" {
        return Some(VPNKind::Openvpn);
    }
    if ext == "sstp" {
        return Some(VPNKind::Sstp);
    }
    let lower = content.to_lowercase();
    if swift_str::contains(&lower, "[interface]") && swift_str::contains(&lower, "privatekey") {
        return Some(VPNKind::Wireguard);
    }
    if matches_multiline(content, &CONNECTIONS) {
        return Some(VPNKind::Strongswan);
    }
    if matches_multiline(content, &REMOTE) && matches_multiline(content, &CLIENT) {
        return Some(VPNKind::Openvpn);
    }
    if matches_multiline(content, &SSTP_SERVER) && matches_multiline(content, &SSTP_KEYS) {
        return Some(VPNKind::Sstp);
    }
    None
}

/// Like [`detect_kind`], but says why the file cannot be imported.
pub fn kind(file_name: &str, content: &str) -> Result<VPNKind, ConfigImportError> {
    if path_extension(file_name).to_lowercase() == "mobileconfig" {
        return Err(ConfigImportError::NativeProfile);
    }
    detect_kind(file_name, content).ok_or(ConfigImportError::UnknownType)
}

/// Kind detection, inlining of the referenced files (OpenVPN), then validation.
pub fn prepare(file_name: &str, content: &str, base_directory: &Path) -> Result<PreparedImport, ConfigImportError> {
    let (meta, content) = take_export_meta(content);
    let kind = kind(file_name, content)?;
    if kind == VPNKind::Openvpn {
        let result = inline_openvpn_files(content, base_directory)?;
        let validation = OpenVPNValidator.validate_full(&result.config, &Default::default());
        let has_encrypted_key = contains_encrypted_key(&result.config);
        return Ok(PreparedImport {
            kind,
            config: result.config,
            inlined_files: result.inlined_files,
            issues: validation.issues,
            risky: validation.risky,
            credentials: result.credentials,
            has_encrypted_key,
            meta,
        });
    }
    let issues = crate::validators::validator(kind).map(|v| v.validate(content)).unwrap_or_default();
    Ok(PreparedImport {
        kind,
        config: content.to_string(),
        inlined_files: Vec::new(),
        issues,
        risky: Vec::new(),
        credentials: ImportedCredentials::default(),
        has_encrypted_key: false,
        meta,
    })
}

/// An encrypted PEM private key in the config (PKCS#8 `ENCRYPTED PRIVATE KEY` or legacy `Proc-Type: 4,ENCRYPTED`).
pub fn contains_encrypted_key(config: &str) -> bool {
    swift_str::contains(config, "-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || swift_str::contains(config, "Proc-Type: 4,ENCRYPTED")
}

/// Foundation `CharacterSet.whitespaces` plus `\r` (scalar trimming).
fn is_whitespace_or_cr(c: char) -> bool {
    c == '\r' || swift_str::is_foundation_whitespace(c)
}

/// `trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))`.
fn trim_quotes(s: &str) -> &str {
    s.trim_matches(['"', '\''])
}

/// A secret file's lines (inside the config's folder, read the same way, at most 1 KB, UTF-8, trailing CR cut,
/// no control character). `None`: unreadable or unsuitable.
fn read_credential_lines(path: &str, base: &str) -> Option<Vec<String>> {
    let data = read_inline_data(path, base).ok()?;
    if data.len() > MAX_CREDENTIALS_FILE_SIZE {
        return None;
    }
    let text = swift_str::string_from_utf8_data(data)?;
    let mut lines: Vec<String> = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l).to_string()).collect();
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    if lines.is_empty() || (Secrets { username: Some(lines.concat()), ..Default::default() }).input_error().is_some() {
        return None;
    }
    Some(lines)
}

/// Turns the OpenVPN directives referring to external files into inline blocks. Only a file inside the config's
/// folder (also after resolving symlinks), at most 1 MB, in the directive's format can be inlined.
pub fn inline_openvpn_files(content: &str, base_directory: &Path) -> Result<InlineResult, ConfigImportError> {
    let base = std::fs::canonicalize(base_directory)
        .ok()
        .and_then(|p| p.to_str().map(str::to_string))
        .ok_or_else(|| ConfigImportError::MissingFile(base_directory.to_string_lossy().into_owned()))?;
    let mut out: Vec<String> = Vec::new();
    let mut inlined: Vec<String> = Vec::new();
    let mut credentials = ImportedCredentials::default();
    for raw in content.split('\n') {
        let line = raw.trim_matches(is_whitespace_or_cr);
        let tokens: Vec<&str> = swift_str::split(line, " ", usize::MAX, true)
            .into_iter()
            .flat_map(|t| swift_str::split(t, "\t", usize::MAX, true))
            .collect();
        let first = tokens.first().map(|t| t.to_lowercase());
        let Some(first) = first.filter(|_| tokens.len() >= 2 && !swift_str::eq(tokens[1], "[inline]")) else {
            out.push(raw.to_string());
            continue;
        };
        // User name / password file: never into the config. If it is inside the folder, at most 1 KB and exactly
        // two lines, its content goes to the Keychain (the caller stores it); the line becomes `auth-user-pass`.
        if first == "auth-user-pass" {
            let path = trim_quotes(tokens[1]).to_string();
            match read_credential_lines(&path, &base) {
                Some(lines) if lines.len() == 2 && !lines[0].is_empty() => {
                    credentials.username = Some(lines[0].clone());
                    credentials.password = Some(lines[1].clone());
                    credentials.credentials_file = Some(path);
                }
                _ => credentials.unread_files.push(path),
            }
            out.push("auth-user-pass".into());
            continue;
        }
        // Key password file: its first line is the "Private key password" (Keychain); the line becomes `askpass`
        // (MacVPN passes its own --askpass file).
        if first == "askpass" {
            let path = trim_quotes(tokens[1]).to_string();
            match read_credential_lines(&path, &base) {
                Some(lines) if !lines[0].is_empty() => {
                    credentials.key_password = Some(lines[0].clone());
                    credentials.key_password_file = Some(path);
                }
                _ => credentials.unread_files.push(path),
            }
            out.push("askpass".into());
            continue;
        }
        if first == "pkcs12" {
            let path = trim_quotes(tokens[1]).to_string();
            let data = read_inline_data(&path, &base)?;
            if !is_pkcs12(&data) {
                return Err(ConfigImportError::WrongFormat { directive: first, file: path });
            }
            out.push("<pkcs12>".into());
            out.extend(base64_lines(&data));
            out.push("</pkcs12>".into());
            inlined.push(path);
            continue;
        }
        let Some(format) =
            EXPECTED_FORMAT.get(first.as_str()).filter(|_| !(first == "dh" && swift_str::eq(tokens[1], "none")))
        else {
            out.push(raw.to_string());
            continue;
        };
        let path = trim_quotes(tokens[1]).to_string();
        let data = read_inline_file(&path, &base, &first)?;
        if !has_format(&data, format) {
            return Err(ConfigImportError::WrongFormat { directive: first, file: path });
        }
        out.push(format!("<{first}>"));
        out.push(if swift_str::has_suffix(&data, "\n") { data[..data.len() - 1].to_string() } else { data });
        out.push(format!("</{first}>"));
        inlined.push(path);
        if (first == "tls-auth" || first == "secret") && tokens.len() >= 3 {
            out.push(format!("key-direction {}", tokens[2]));
        }
    }
    Ok(InlineResult { config: out.join("\n"), inlined_files: inlined, credentials })
}

fn read_inline_file(path: &str, base: &str, directive: &str) -> Result<String, ConfigImportError> {
    swift_str::string_from_utf8_data(read_inline_data(path, base)?)
        .ok_or_else(|| ConfigImportError::WrongFormat { directive: directive.to_string(), file: path.to_string() })
}

/// Resolves `path` (relative to `base`, or absolute) and reads it. The resolved path is opened with `O_NOFOLLOW`
/// and the opened file is checked (regular file, size), so the check and the read concern the same file.
fn read_inline_data(path: &str, base: &str) -> Result<Vec<u8>, ConfigImportError> {
    let joined = if swift_str::has_prefix(path, "/") { path.to_string() } else { format!("{base}/{path}") };
    // `realpath` takes a C string: it ends at the first NUL.
    let joined = joined.split('\0').next().unwrap_or_default();
    let Some(resolved) = std::fs::canonicalize(joined).ok().and_then(|p| p.to_str().map(str::to_string)) else {
        // Missing: if it already points outside textually, say that.
        return Err(if lexically_escapes(path) {
            ConfigImportError::OutsideBaseDirectory(path.to_string())
        } else {
            ConfigImportError::MissingFile(path.to_string())
        });
    };
    let prefix = if swift_str::has_suffix(base, "/") { base.to_string() } else { format!("{base}/") };
    if !swift_str::has_prefix(&resolved, &prefix) {
        return Err(ConfigImportError::OutsideBaseDirectory(path.to_string()));
    }
    let missing = || ConfigImportError::MissingFile(path.to_string());
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&resolved)
        .map_err(|_| missing())?;
    let meta = file.metadata().map_err(|_| missing())?;
    if !meta.file_type().is_file() {
        return Err(missing());
    }
    if meta.len() > MAX_INLINE_FILE_SIZE as u64 {
        return Err(ConfigImportError::FileTooLarge(path.to_string()));
    }
    let mut data = Vec::new();
    let _ = file.take(MAX_INLINE_FILE_SIZE as u64 + 1).read_to_end(&mut data);
    if data.len() > MAX_INLINE_FILE_SIZE {
        return Err(ConfigImportError::FileTooLarge(path.to_string()));
    }
    Ok(data)
}

/// DER PKCS#12 (PFX): `SEQUENCE` (short, long or indefinite length), then `INTEGER 3` (the version). Format
/// recognition only: the content is not opened (no password needed here), nothing is imported into a keychain.
pub fn is_pkcs12(data: &[u8]) -> bool {
    if data.len() < 32 || data[0] != 0x30 {
        return false;
    }
    let b = &data[..8];
    let length_bytes = match b[1] {
        0x00..=0x7F => 0,
        0x80 => 0, // indefinite length (BER)
        0x81..=0x84 => usize::from(b[1] - 0x80),
        _ => return false,
    };
    let v = 2 + length_bytes;
    if v + 2 >= b.len() {
        return false;
    }
    b[v] == 0x02 && b[v + 1] == 0x01 && b[v + 2] == 0x03
}

/// Base64 in 64-character lines (OpenVPN's inline `<pkcs12>` form).
pub fn base64_lines(data: &[u8]) -> Vec<String> {
    let encoded = swift_base64::encode(data);
    encoded.as_bytes().chunks(64).map(|c| String::from_utf8_lossy(c).into_owned()).collect()
}

/// A relative path that gets above the starting folder with `..` (an absolute path is checked by realpath).
pub fn lexically_escapes(path: &str) -> bool {
    if swift_str::has_prefix(path, "/") {
        return false;
    }
    let mut depth = 0i64;
    for part in swift_str::split(path, "/", usize::MAX, true) {
        if swift_str::eq(part, "..") {
            depth -= 1;
        } else if !swift_str::eq(part, ".") {
            depth += 1;
        }
        if depth < 0 {
            return true;
        }
    }
    false
}

/// Line terminators for Swift Regex `.` (it matches no line terminator).
fn is_line_terminator(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{B}' | '\u{C}' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// At least one complete PEM block of the directive's type; no PEM block of another type and no line starting
/// with `<` (an inline tag that could close the block).
pub fn has_format(text: &str, pem_type: &str) -> bool {
    has_complete_block(text, pem_type) && all_begin_types_match(text, pem_type) && !has_tag_line(text)
}

fn whole_type_regex(pem_type: &str) -> Regex {
    Regex::new(&format!("^(?:{pem_type})$")).expect("valid pattern")
}

/// `-----BEGIN (type)-----\r?\n(?:(?:[^-\r\n].*)?\r?\n)*?-----END \1-----`, Character-based like Swift. The
/// type cannot contain `-----`, so it is the text up to the next `-----`.
fn has_complete_block(text: &str, pem_type: &str) -> bool {
    let whole = whole_type_regex(pem_type);
    let mut from = 0;
    while let Some(i) = text[from..].find("-----BEGIN ").map(|i| i + from) {
        from = i + 1;
        if !swift_str::is_boundary(text, i) {
            continue;
        }
        let after = &text[i + 11..];
        let Some(j) = after.find("-----") else { continue };
        let candidate = &after[..j];
        if swift_str::matches(candidate, &whole) && block_ends(&after[j + 5..], candidate) {
            return true;
        }
    }
    false
}

/// After `-----BEGIN T-----`: `\n`, then lines (empty, or not starting with `-`, no line terminator inside),
/// until a line that starts with `-----END T-----`. (Swift's `\r?\n` never matches a CRLF line end: `\r\n` is one
/// Character there.)
fn block_ends(body: &str, pem_type: &str) -> bool {
    let end_marker = format!("-----END {pem_type}-----");
    // `\r?\n` cannot match the single Character `\r\n`: a CRLF block does not match in Swift either.
    let Some(mut rest) = body.strip_prefix('\n') else { return false };
    loop {
        if swift_str::has_prefix(rest, &end_marker) {
            return true;
        }
        let Some(nl) = rest.find('\n') else { return false };
        let line = &rest[..nl];
        // `[^-\r\n]` takes the first Character (a U+2028 too), `.*` the rest, which has no line terminator.
        let characters = swift_str::characters(line);
        if let Some((first, others)) = characters.split_first()
            && (*first == "-" || *first == "\r" || others.iter().any(|c| c.chars().any(is_line_terminator)))
        {
            return false;
        }
        rest = &rest[nl + 1..];
    }
}

/// `^-----BEGIN ([^-]+)-----` with `.anchorsMatchLines` (NSRegularExpression, scalar-based): every type must match
/// `^(?:type)$` (Character-based).
fn all_begin_types_match(text: &str, pem_type: &str) -> bool {
    static BEGIN: LazyLock<Regex> = LazyLock::new(|| {
        RegexBuilder::new("^-----BEGIN ([^-]+)-----").multi_line(true).crlf(true).build().expect("valid")
    });
    let whole = whole_type_regex(pem_type);
    let normalized = text.replace(['\u{85}', '\u{2028}', '\u{2029}', '\u{B}', '\u{C}'], "\n");
    BEGIN.captures_iter(&normalized).all(|c| swift_str::matches(&c[1], &whole))
}

/// `(?m)^\s*<`.
fn has_tag_line(text: &str) -> bool {
    static TAG: LazyLock<Regex> = LazyLock::new(|| multiline("^\\s*<"));
    matches_multiline(text, &TAG)
}

/// The editor's starting text per kind.
pub fn template(kind: VPNKind) -> String {
    match kind {
        VPNKind::Openvpn => "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nnobind\npersist-key\npersist-tun\nremote-cert-tls server\nauth-user-pass\n<ca>\n</ca>\n".into(),
        VPNKind::Wireguard => "[Interface]\nPrivateKey =\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey =\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:51820\n".into(),
        VPNKind::Strongswan => "connections {\n  myvpn {\n    remote_addrs = vpn.example.com\n    vips = 0.0.0.0\n    local {\n      auth = eap-mschapv2\n      eap_id = felhasznalo\n    }\n    remote {\n      auth = pubkey\n      id = vpn.example.com\n    }\n    children {\n      myvpn {\n        remote_ts = 0.0.0.0/0\n      }\n    }\n  }\n}\n".into(),
        VPNKind::Sstp => SSTPConfig { server: "vpn.example.com".into(), ..Default::default() }.serialized(),
        VPNKind::L2tp | VPNKind::Cisco => String::new(),
    }
}
