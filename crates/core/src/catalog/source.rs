//! Catalog sources (spec 4, plan Task 5): an HTTPS URL or a file path, and the file source reader.
//!
//! **HTTPS URL** ([`HttpsUrl`]): `https://` only; the host an ASCII LDH name (a Unicode name is converted to
//! punycode with `idna::domain_to_ascii`), an IPv4 literal or a bracketed IPv6 literal; an optional port 1–65535;
//! no user info; no fragment; path and query printable ASCII (`0x21..0x7e`), with `[ ] { }` percent-encoded (curl's
//! URL globbing); at most [`MAX_URL_BYTES`]. Any host is
//! allowed (not the update allowlist). The canonical text is what curl gets after `--`. The parser is stricter
//! than Foundation's (`crate::url::parse`, which percent-encodes what it does not accept); the canonical text is
//! cross-checked with it.
//!
//! **File source** ([`read_catalog_file`]): `O_NOFOLLOW | O_NONBLOCK` (the last component is never a symlink, a
//! FIFO never blocks the open), `fstat` on the descriptor (a regular file of at most [`MAX_CATALOG_BYTES`]), then a
//! read through `take(MAX_CATALOG_BYTES + 1)`. A missing share or a server that went away is
//! [`CatalogError::Unavailable`] (the errnos of spike decision B2), never an error storm.

use super::format::{CatalogError, MAX_CATALOG_BYTES};
use crate::fsx::{self, Follow, OpenFor};
use std::fmt;
use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// The longest URL accepted, in bytes.
pub const MAX_URL_BYTES: usize = 2048;
/// The longest file source path, in bytes.
pub const MAX_PATH_BYTES: usize = 1024;
const DEFAULT_PORT: u16 = 443;

/// Where a subscription fetches its catalog.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum CatalogSource {
    Https(HttpsUrl),
    File(PathBuf),
}

impl CatalogSource {
    /// For logs and the UI: a URL without its query, a file by its file name only.
    pub fn redacted(&self) -> String {
        match self {
            CatalogSource::Https(url) => url.redacted(),
            CatalogSource::File(path) => file_name(path),
        }
    }
}

impl fmt::Debug for CatalogSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CatalogSource::Https(url) => write!(f, "Https({url:?})"),
            CatalogSource::File(path) => write!(f, "File({path:?})"),
        }
    }
}

/// Why a source was refused. Carries no part of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    /// Not `https://`.
    NotHttps,
    /// Not a URL these rules accept (host, port, characters).
    BadUrl,
    /// A user name or password in the URL.
    UserInfo,
    /// A `#fragment`.
    Fragment,
    /// Over [`MAX_URL_BYTES`] or [`MAX_PATH_BYTES`].
    TooLong,
    /// A file path that is not absolute.
    NotAbsolute,
    /// A file path with a NUL or another control character.
    BadPath,
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SourceError::NotHttps => "only https:// addresses are allowed",
            SourceError::BadUrl => "the address is not valid",
            SourceError::UserInfo => "the address must not contain a user name or password",
            SourceError::Fragment => "the address must not contain a # part",
            SourceError::TooLong => "the address is too long",
            SourceError::NotAbsolute => "the file path must be absolute",
            SourceError::BadPath => "the file path contains an invalid character",
        })
    }
}

impl std::error::Error for SourceError {}

/// A canonical `https://` URL (see the module docs).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct HttpsUrl {
    /// Lower case, punycode; an IPv6 literal with its brackets.
    host: String,
    port: u16,
    /// Starts with `/`.
    path: String,
    query: Option<String>,
    text: String,
}

impl fmt::Debug for HttpsUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HttpsUrl({})", self.redacted())
    }
}

fn printable(s: &str) -> bool {
    s.bytes().all(|b| (0x21..0x7f).contains(&b))
}

/// An LDH host name: labels of 1–63 `[a-z0-9-]`, not starting or ending with `-`, at most 253 bytes.
fn is_ldh(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// WHATWG "ends in a number": the last label is all digits or starts with `0x`. Such a name is read as an IPv4
/// address by browsers and some resolvers (`1.2.3.0x4`, `example.123`), so it is refused rather than guessed at.
fn ends_in_a_number(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or("");
    (!last.is_empty() && last.bytes().all(|b| b.is_ascii_digit())) || last.starts_with("0x")
}

fn parse_host(raw: &str) -> Result<String, SourceError> {
    if raw.is_empty() {
        return Err(SourceError::BadUrl);
    }
    if let Some(inner) = raw.strip_prefix('[') {
        let inner = inner.strip_suffix(']').ok_or(SourceError::BadUrl)?;
        let addr: Ipv6Addr = inner.parse().map_err(|_| SourceError::BadUrl)?;
        return Ok(format!("[{addr}]"));
    }
    if raw.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        // Digits and dots only: an IPv4 literal or nothing (no `1.2.3`, no octal, no 999).
        let addr: Ipv4Addr = raw.parse().map_err(|_| SourceError::BadUrl)?;
        return Ok(addr.to_string());
    }
    if raw.bytes().any(|b| b.is_ascii_control() || b == b' ' || b == b'%' || b == b'_') {
        return Err(SourceError::BadUrl);
    }
    let ascii = idna::domain_to_ascii(raw).map_err(|_| SourceError::BadUrl)?.to_ascii_lowercase();
    if !is_ldh(&ascii) || ends_in_a_number(&ascii) {
        return Err(SourceError::BadUrl);
    }
    Ok(ascii)
}

/// Splits `host[:port]`, an IPv6 literal in brackets.
fn split_port(authority: &str) -> Result<(&str, u16), SourceError> {
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or(SourceError::BadUrl)?;
        match &authority[end + 1..] {
            "" => (authority, None),
            rest => (&authority[..=end], Some(rest.strip_prefix(':').ok_or(SourceError::BadUrl)?)),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port {
        None => DEFAULT_PORT,
        Some(p) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(SourceError::BadUrl);
            }
            match p.parse::<u16>() {
                Ok(n) if n > 0 => n,
                _ => return Err(SourceError::BadUrl),
            }
        }
    };
    Ok((host, port))
}

/// Percent-encodes curl's URL globbing characters `[ ] { }` (the host's IPv6 brackets are not passed here).
fn encode_glob(s: &str) -> String {
    s.replace('[', "%5B").replace(']', "%5D").replace('{', "%7B").replace('}', "%7D")
}

/// RFC 3986 section 5.2.4.
fn remove_dot_segments(path: &str) -> String {
    let mut output: Vec<&str> = Vec::new();
    let segments: Vec<&str> = path.split('/').collect();
    let last = segments.len() - 1;
    for (i, segment) in segments.iter().enumerate().skip(1) {
        match *segment {
            "." => {
                if i == last {
                    output.push("");
                }
            }
            ".." => {
                output.pop();
                if i == last {
                    output.push("");
                }
            }
            s => output.push(s),
        }
    }
    format!("/{}", output.join("/"))
}

impl HttpsUrl {
    pub fn parse(input: &str) -> Result<HttpsUrl, SourceError> {
        if input.len() > MAX_URL_BYTES {
            return Err(SourceError::TooLong);
        }
        let (scheme, rest) = input.split_once("://").ok_or(SourceError::BadUrl)?;
        if scheme.is_empty() || !scheme.bytes().all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b)) {
            return Err(SourceError::BadUrl);
        }
        if !scheme.eq_ignore_ascii_case("https") {
            return Err(SourceError::NotHttps);
        }
        if rest.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(SourceError::BadUrl);
        }
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.contains('@') {
            return Err(SourceError::UserInfo);
        }
        if tail.contains('#') {
            return Err(SourceError::Fragment);
        }
        let (raw_host, port) = split_port(authority)?;
        let host = parse_host(raw_host)?;
        let (path, query) = match tail.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (tail, None),
        };
        let path = if path.is_empty() { "/" } else { path };
        if !path.starts_with('/') || !printable(path) || !query.is_none_or(printable) {
            return Err(SourceError::BadUrl);
        }
        // `.` and `..` segments resolved as a redirect target's are (RFC 3986 5.2.4), so one URL has one form.
        // `[ ] { }` are percent-encoded: curl's URL globbing must never see them (a redirect to `x[1-100000000]`
        // would make every subscriber fan out requests), and curl also runs with `--globoff`.
        let normalized = encode_glob(&remove_dot_segments(path));
        let path = normalized.as_str();
        let query = query.filter(|q| !q.is_empty()).map(encode_glob);
        let mut text = format!("https://{host}");
        if port != DEFAULT_PORT {
            text.push_str(&format!(":{port}"));
        }
        text.push_str(path);
        if let Some(q) = &query {
            text.push('?');
            text.push_str(q);
        }
        if text.len() > MAX_URL_BYTES {
            return Err(SourceError::TooLong);
        }
        // Foundation's parser must read the canonical text the same way.
        let foundation = crate::url::parse(&text).ok_or(SourceError::BadUrl)?;
        if foundation.user.is_some() || foundation.fragment.is_some() || foundation.percent_encoded_path != path {
            return Err(SourceError::BadUrl);
        }
        Ok(HttpsUrl { host, port, path: path.to_string(), query, text })
    }

    /// The canonical text, handed to curl after `--`.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The host (lower case, punycode; an IPv6 literal in brackets) and the port (443 by default).
    pub fn origin(&self) -> (String, u16) {
        (self.host.clone(), self.port)
    }

    /// Without the query (which may carry a signed-URL token), for logs and the UI.
    pub fn redacted(&self) -> String {
        match self.port {
            DEFAULT_PORT => format!("https://{}{}", self.host, self.path),
            port => format!("https://{}:{port}{}", self.host, self.path),
        }
    }

    /// A redirect's `Location`, relative or absolute, resolved against this URL (RFC 3986 section 5.2); a
    /// fragment is dropped. Only `https://` targets are accepted.
    pub fn redirect_target(&self, location: &str) -> Result<HttpsUrl, SourceError> {
        let location = location.split('#').next().unwrap_or("");
        if location.is_empty() || location.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(SourceError::BadUrl);
        }
        let scheme_end = location.find(':');
        let first_delimiter = location.find(['/', '?']).unwrap_or(location.len());
        if let Some(colon) = scheme_end
            && colon < first_delimiter
        {
            return HttpsUrl::parse(location);
        }
        if location.starts_with("//") {
            return HttpsUrl::parse(&format!("https:{location}"));
        }
        let (ref_path, query) = match location.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (location, None),
        };
        let path = if ref_path.is_empty() {
            self.path.clone()
        } else if ref_path.starts_with('/') {
            remove_dot_segments(ref_path)
        } else {
            let base_dir = &self.path[..self.path.rfind('/').map_or(0, |i| i + 1)];
            remove_dot_segments(&format!("{base_dir}{ref_path}"))
        };
        let query = match (ref_path.is_empty(), query) {
            (_, Some(q)) => Some(q.to_string()),
            (true, None) => self.query.clone(),
            (false, None) => None,
        };
        let authority = match self.port {
            DEFAULT_PORT => self.host.clone(),
            port => format!("{}:{port}", self.host),
        };
        let mut text = format!("https://{authority}{path}");
        if let Some(q) = query {
            text.push('?');
            text.push_str(&q);
        }
        HttpsUrl::parse(&text)
    }
}

/// An absolute path of at most [`MAX_PATH_BYTES`] without control characters (`~/` is expanded by the caller).
pub fn parse_file_source(input: &str) -> Result<PathBuf, SourceError> {
    if input.len() > MAX_PATH_BYTES {
        return Err(SourceError::TooLong);
    }
    if input.chars().any(char::is_control) {
        return Err(SourceError::BadPath);
    }
    if !input.starts_with('/') {
        return Err(SourceError::NotAbsolute);
    }
    Ok(PathBuf::from(input))
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

fn not_regular() -> CatalogError {
    CatalogError::Io("not a regular file".into())
}

/// The errors that mean "the source cannot be reached right now" (spike decision B2) are
/// [`CatalogError::Unavailable`]; a symlink is "not a regular file".
fn read_error(e: io::Error, path: &Path) -> CatalogError {
    if fsx::is_unavailable(&e) {
        return CatalogError::Unavailable(file_name(path));
    }
    if fsx::is_symlink_refused(&e) {
        return not_regular();
    }
    CatalogError::Io(format!("cannot read the team catalog file ({e})"))
}

/// Reads a catalog file source (see the module docs). The app reads catalog files only through this, on a worker
/// thread with a timeout (Task 10).
pub fn read_catalog_file(path: &Path) -> Result<Vec<u8>, CatalogError> {
    // `open_regular` switches the descriptor back to blocking reads (a network share returns EAGAIN on a
    // non-blocking read).
    let (file, meta) = fsx::open_regular(path, OpenFor::Read, Follow::No, false)
        .map_err(|e| if fsx::is_not_regular_file(&e) { not_regular() } else { read_error(e, path) })?;
    if meta.len() > MAX_CATALOG_BYTES as u64 {
        return Err(CatalogError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_CATALOG_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(|e| read_error(e, path))?;
    if bytes.len() > MAX_CATALOG_BYTES {
        return Err(CatalogError::TooLarge);
    }
    Ok(bytes)
}
