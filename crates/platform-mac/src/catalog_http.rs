//! The HTTPS team catalog source (spec 4, plan Task 9): `/usr/bin/curl` with the updater's pinned options
//! (`CurlHttpClient::base_arguments`: `-q` first, `--proto =https`, `--max-redirs 0`, the fixed environment), so the
//! system trust store checks the certificate and no extra TLS stack is in the app.
//!
//! - **Conditional GET** (spike decision A1): our own `If-None-Match` / `If-Modified-Since` headers from the stored
//!   validators, and the response headers read from `--dump-header` (one block per hop, names in any case, CRLF).
//!   The `--write-out` status decides: a `304` leaves no output file, which is not an error.
//! - **The bearer token** (decision A2) goes on curl's stdin as `--config -` with the line
//!   `header = "Authorization: Bearer <token>"`, built in a `Zeroizing` buffer; never in argv, env or a log line.
//!   It was checked against the RFC 6750 `b64token` rule, so it needs no escaping.
//! - **Redirects** are followed hop by hop, at most [`MAX_REDIRECTS`]; each target goes through
//!   `HttpsUrl::redirect_target` (https only, else refused before it is requested). The token is sent only while the
//!   hop's `origin()` (host and port) equals the subscription URL's; so are the conditional headers.
//! - **No URL globbing:** `--globoff` (in the shared base arguments), and `HttpsUrl` percent-encodes `[ ] { }`.
//! - **No proxy:** curl's environment is cleared (`CurlHttpClient::environment`), so `*_proxy` is never honoured;
//!   a validated proxy setting may come later.
//! - **Size:** `--max-filesize 8388608` (exit 63) and a `take(cap + 1)` read of the body: [`CatalogError::TooLarge`].
//! - Every request runs in a fresh private (0700) temporary directory, removed afterwards.
//!
//! Nothing here logs.

use crate::command::{CommandError, CommandRunner, ProcessCommandRunner};
use crate::http::{CurlHttpClient, remove_output, with_private_directory};
use macvpn_core::catalog::fetch::{CatalogFetcher, FetchOutcome, FetchRequest};
use macvpn_core::catalog::format::{CatalogError, MAX_CATALOG_BYTES};
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl, SourceError};
use macvpn_core::l10n;
use macvpn_core::vault::{SourceValidators, valid_bearer_token};
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// The most redirects one fetch follows.
pub const MAX_REDIRECTS: usize = 5;
/// curl's `--max-time` per request, in seconds.
pub const CATALOG_MAX_TIME: f64 = 60.0;
/// The longest validator value sent back or stored.
pub const MAX_VALIDATOR_BYTES: usize = 256;
/// The header dump is read up to this size.
const MAX_HEADER_DUMP: u64 = 64 * 1024;
const CURL: &str = "/usr/bin/curl";

/// The HTTPS catalog fetcher (see the module docs).
pub struct CurlCatalogFetcher {
    runner: Box<dyn CommandRunner>,
    user_agent: String,
    /// A test CA for the local HTTPS server of the tests (`--cacert`); never set in production.
    test_ca: Option<PathBuf>,
}

impl Default for CurlCatalogFetcher {
    /// The production runner: the request time limit plus a margin, `CurlHttpClient::environment` only.
    fn default() -> Self {
        Self::new(Box::new(
            ProcessCommandRunner::new(CATALOG_MAX_TIME + 30.0).with_environment(CurlHttpClient::environment()),
        ))
    }
}

/// A validator value we send back or store: 1 to 256 bytes of printable ASCII or space (no CR/LF, no control
/// character, nothing that could start another header).
fn valid_validator(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_VALIDATOR_BYTES
        && value.bytes().all(|b| b == b' ' || (0x21..0x7f).contains(&b))
}

fn io(message: &str) -> CatalogError {
    CatalogError::Io(message.to_string())
}

/// curl's exit code (no response) as a catalog error. Transport failures are "unavailable" (no error storm while
/// offline), a certificate that is not trusted and the size cap are not.
fn exit_error(code: i32, host: &str) -> CatalogError {
    match code {
        63 => CatalogError::TooLarge,
        60 => CatalogError::Io(l10n::tr("certificate not trusted", &[])),
        5 | 6 | 7 | 16 | 18 | 28 | 35 | 52 | 55 | 56 | 92 => CatalogError::Unavailable(host.to_string()),
        code => CatalogError::Io(format!("the download failed (curl {code})")),
    }
}

/// `ETag` and `Last-Modified` of the (single) response block in a `--dump-header` file; a value that would not be
/// sent back is dropped.
fn parse_validators(dump: &str) -> SourceValidators {
    let mut validators = SourceValidators::default();
    for line in dump.split('\n').skip(1) {
        let line = line.trim_end_matches('\r');
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim_matches(|c| c == ' ' || c == '\t');
        if !valid_validator(value) {
            continue;
        }
        if name.eq_ignore_ascii_case("etag") {
            validators.etag = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("last-modified") {
            validators.last_modified = Some(value.to_string());
        }
    }
    validators
}

/// A file of the private directory, at most `cap + 1` bytes; a missing file reads as empty (curl writes none for a
/// `304` or an aborted transfer).
fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, CatalogError> {
    let mut bytes = Vec::new();
    match std::fs::File::open(path) {
        Ok(file) => {
            file.take(cap + 1).read_to_end(&mut bytes).map_err(|_| io("cannot read the downloaded team catalog"))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(io("cannot read the downloaded team catalog")),
    }
    Ok(bytes)
}

impl CurlCatalogFetcher {
    pub fn new(runner: Box<dyn CommandRunner>) -> Self {
        CurlCatalogFetcher {
            runner,
            user_agent: format!("MacVPN-Catalog/{}", env!("CARGO_PKG_VERSION")),
            test_ca: None,
        }
    }

    /// Trusts a throwaway CA as well (`--cacert`): the local HTTPS server of the tests only.
    #[cfg(feature = "test-support")]
    pub fn with_test_ca(mut self, ca: PathBuf) -> Self {
        self.test_ca = Some(ca);
        self
    }

    fn arguments(&self, url: &HttpsUrl, dir: &Path, previous: &SourceValidators, with_token: bool) -> Vec<String> {
        let mut args = CurlHttpClient::base_arguments(None, CATALOG_MAX_TIME, &self.user_agent);
        if let Some(ca) = &self.test_ca {
            args.extend(["--cacert".to_string(), ca.to_string_lossy().into_owned()]);
        }
        if with_token {
            args.extend(["--config".to_string(), "-".to_string()]);
        }
        args.extend(["--max-filesize".to_string(), MAX_CATALOG_BYTES.to_string()]);
        args.extend(["--dump-header".to_string(), dir.join("headers").to_string_lossy().into_owned()]);
        args.extend(["--write-out".to_string(), "%{http_code} %{redirect_url}".to_string()]);
        args.extend(["--output".to_string(), dir.join("body").to_string_lossy().into_owned()]);
        if let Some(etag) = previous.etag.as_deref().filter(|v| valid_validator(v)) {
            args.extend(["--header".to_string(), format!("If-None-Match: {etag}")]);
        }
        if let Some(date) = previous.last_modified.as_deref().filter(|v| valid_validator(v)) {
            args.extend(["--header".to_string(), format!("If-Modified-Since: {date}")]);
        }
        args.extend(["--".to_string(), url.as_str().to_string()]);
        args
    }

    /// One fetch of an HTTPS source, in a private directory.
    pub fn fetch_https(
        &self,
        url: &HttpsUrl,
        bearer: Option<&str>,
        previous: &SourceValidators,
    ) -> Result<FetchOutcome, CatalogError> {
        if bearer.is_some_and(|t| !valid_bearer_token(t)) {
            return Err(io("the access token is not valid"));
        }
        let config = bearer.map(|token| Zeroizing::new(format!("header = \"Authorization: Bearer {token}\"\n")));
        with_private_directory("macvpn-catalog", |dir| self.follow(url, config.as_deref(), previous, dir))
            .map_err(|_| io("cannot create a temporary directory"))?
    }

    fn follow(
        &self,
        url: &HttpsUrl,
        config: Option<&String>,
        previous: &SourceValidators,
        dir: &Path,
    ) -> Result<FetchOutcome, CatalogError> {
        let origin = url.origin();
        let mut current = url.clone();
        let mut redirects = 0;
        loop {
            // A previous hop's files are never this hop's.
            for name in ["headers", "body"] {
                remove_output(&dir.join(name)).map_err(|_| io("cannot prepare the download"))?;
            }
            let host = current.origin().0;
            // The token and the validators belong to the subscription's origin: another origin gets neither.
            let same_origin = current.origin() == origin;
            let stdin = config.filter(|_| same_origin).map(String::as_str);
            let none = SourceValidators::default();
            let validators = if same_origin { previous } else { &none };
            let args = self.arguments(&current, dir, validators, stdin.is_some());
            let result = self.runner.run(CURL, &args, stdin).map_err(|e| match e {
                CommandError::TimedOut(_) => CatalogError::Unavailable(host.clone()),
                _ => io("cannot run curl"),
            })?;
            if result.exit_code != 0 {
                return Err(exit_error(result.exit_code, &host));
            }
            let Some((status, redirect)) = CurlHttpClient::parse_trailer(&result.stdout).filter(|(s, _)| *s != 0)
            else {
                return Err(CatalogError::Unavailable(host));
            };
            match status {
                304 => return Ok(FetchOutcome::NotModified),
                200 => {
                    let bytes = read_capped(&dir.join("body"), MAX_CATALOG_BYTES as u64)?;
                    if bytes.len() > MAX_CATALOG_BYTES {
                        return Err(CatalogError::TooLarge);
                    }
                    let dump = read_capped(&dir.join("headers"), MAX_HEADER_DUMP)?;
                    let validators = parse_validators(&String::from_utf8_lossy(&dump));
                    return Ok(FetchOutcome::Fetched { bytes, validators });
                }
                301 | 302 | 303 | 307 | 308 => {
                    if redirects == MAX_REDIRECTS {
                        return Err(io("too many redirects"));
                    }
                    redirects += 1;
                    current = current.redirect_target(&redirect).map_err(|e| match e {
                        SourceError::NotHttps => CatalogError::Io(l10n::tr("redirect to a non-HTTPS address", &[])),
                        _ => io("redirect to an invalid address"),
                    })?;
                }
                401 | 403 => return Err(CatalogError::Io(l10n::tr("access denied (check the access token)", &[]))),
                status => return Err(CatalogError::Io(format!("HTTP {status}"))),
            }
        }
    }
}

impl CatalogFetcher for CurlCatalogFetcher {
    fn fetch(&self, req: &FetchRequest) -> Result<FetchOutcome, CatalogError> {
        match req.source {
            CatalogSource::Https(url) => self.fetch_https(url, req.bearer, req.previous),
            CatalogSource::File(_) => Err(io("not an HTTPS source")),
        }
    }
}
