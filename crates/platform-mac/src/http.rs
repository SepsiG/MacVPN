//! The updater's network layer (port of `HTTPClient` / `URLSessionHTTPClient` in `UpdateChecker.swift`).
//!
//! [`CurlHttpClient`] uses the system `/usr/bin/curl` (the system trust store, no extra TLS stack in the app)
//! and follows redirects itself, one hop at a time, so every target is checked against
//! [`UpdateURLPolicy::is_allowed_redirect`] before it is requested (the URLSession delegate's rule). curl only
//! gets canonical URLs: release assets as [`UpdateURLPolicy::canonical_download_url`], redirect targets as
//! [`canonical_redirect_url`]. Only HTTPS,
//! no cookies, `User-Agent: MacVPN-Updater`, 30 s per request and 600 s per download.

use crate::command::{CommandError, CommandRunner, ProcessCommandRunner};
use crate::temp_dir::{make_private_temp_directory, temporary_directory};
use macvpn_core::update::{UpdateError, UpdateURLPolicy};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: i64,
    pub data: Vec<u8>,
}

impl HttpResponse {
    pub fn new(status: i64, data: &[u8]) -> Self {
        HttpResponse { status, data: data.to_vec() }
    }
}

#[derive(Debug)]
pub enum HttpError {
    Update(UpdateError),
    Command(CommandError),
    Io(std::io::Error),
    /// curl failed (no response): its exit code and message.
    Transport(i32, String),
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Update(e) => e.fmt(f),
            HttpError::Command(e) => e.fmt(f),
            HttpError::Io(e) => e.fmt(f),
            HttpError::Transport(code, message) => {
                if message.is_empty() {
                    write!(f, "curl ({code})")
                } else {
                    f.write_str(message)
                }
            }
        }
    }
}

impl std::error::Error for HttpError {}

/// The network layer (mockable in tests). HTTPS and the allowed hosts only.
pub trait HttpClient: Send + Sync {
    fn get(&self, url: &str) -> Result<HttpResponse, HttpError>;
    /// Downloads into a temporary file; the file belongs to the caller (move or delete it).
    fn download(&self, url: &str) -> Result<(PathBuf, i64), HttpError>;
}

pub struct CurlHttpClient {
    runner: Box<dyn CommandRunner>,
    max_redirects: usize,
}

const CURL: &str = "/usr/bin/curl";
const REQUEST_TIMEOUT: &str = "30";
const RESOURCE_TIMEOUT: f64 = 600.0;

impl Default for CurlHttpClient {
    fn default() -> Self {
        Self::new(Box::new(Self::runner()))
    }
}

impl CurlHttpClient {
    pub fn new(runner: Box<dyn CommandRunner>) -> Self {
        CurlHttpClient { runner, max_redirects: 10 }
    }

    /// curl's whole environment: nothing of the app's, so `SSLKEYLOGFILE`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`,
    /// `*_proxy`, `CURL_HOME` and the like never reach it.
    pub fn environment() -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
        if let Some(home) = crate::system::home_directory() {
            env.insert("HOME".to_string(), home.to_string_lossy().into_owned());
        }
        env.insert("LANG".to_string(), "C".to_string());
        env
    }

    /// The production runner: the download time limit plus a margin, [`Self::environment`] only.
    pub fn runner() -> ProcessCommandRunner {
        ProcessCommandRunner::new(RESOURCE_TIMEOUT + 30.0).with_environment(Self::environment())
    }

    /// The common arguments: HTTPS only, no redirect following by curl, no config file, timeouts, user agent.
    pub fn base_arguments(accept: Option<&str>, max_time: f64) -> Vec<String> {
        let mut args: Vec<String> = [
            "-q",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--max-redirs",
            "0",
            "--connect-timeout",
            REQUEST_TIMEOUT,
            "--max-time",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        args.push(format!("{}", max_time as i64));
        args.push("--user-agent".into());
        args.push("MacVPN-Updater".into());
        if let Some(accept) = accept {
            args.push("--header".into());
            args.push(format!("Accept: {accept}"));
        }
        args
    }

    /// Parses `<status> <redirect url>`, curl's `--write-out` output.
    pub fn parse_trailer(trailer: &str) -> Option<(i64, String)> {
        let line = trailer.trim();
        let (status, rest) = line.split_once(' ').unwrap_or((line, ""));
        Some((status.parse().ok()?, rest.trim().to_string()))
    }

    /// One request without following redirects, the body written to `output`: status and redirect target.
    fn request(
        &self,
        url: &str,
        output: &Path,
        accept: Option<&str>,
        max_time: f64,
    ) -> Result<(i64, String), HttpError> {
        // A previous hop's body (a 3xx page) must never be taken as this hop's data.
        remove_output(output)?;
        let mut args = Self::base_arguments(accept, max_time);
        args.extend(["--write-out".to_string(), "%{http_code} %{redirect_url}".to_string()]);
        args.extend(["--output".to_string(), output.to_string_lossy().into_owned()]);
        args.extend(["--".to_string(), url.to_string()]);
        let result = self.runner.run(CURL, &args, None).map_err(HttpError::Command)?;
        match Self::parse_trailer(&result.stdout) {
            Some((status, redirect)) if result.exit_code == 0 && status != 0 => Ok((status, redirect)),
            _ => Err(HttpError::Transport(result.exit_code, result.stderr.trim().to_string())),
        }
    }

    /// Follows redirects hop by hop while the target is allowed; a disallowed target ends the chain and its 3xx
    /// response is returned (as URLSession does when the delegate declines).
    fn follow(&self, url: &str, output: &Path, accept: Option<&str>, max_time: f64) -> Result<i64, HttpError> {
        let mut current = url.to_string();
        for _ in 0..=self.max_redirects {
            let (status, redirect) = self.request(&current, output, accept, max_time)?;
            if (300..400).contains(&status)
                && let Some(next) = canonical_redirect_url(&redirect)
            {
                current = next;
                continue;
            }
            if (300..400).contains(&status) {
                // A redirect that is not followed: its body is no data.
                remove_output(output)?;
            }
            return Ok(status);
        }
        remove_output(output)?;
        Err(HttpError::Transport(47, "too many redirects".into()))
    }

    /// Runs `body` with a fresh private directory, removed afterwards.
    fn with_private_directory<T>(body: impl FnOnce(&Path) -> Result<T, HttpError>) -> Result<T, HttpError> {
        let base = temporary_directory().map_err(|e| HttpError::Io(std::io::Error::other(e.0)))?;
        let dir = make_private_temp_directory("macvpn-download", &base)
            .map_err(|e| HttpError::Io(std::io::Error::other(e.0)))?;
        let result = body(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        result
    }
}

/// A redirect target as handed to curl: only if [`UpdateURLPolicy::is_allowed_redirect`] accepts it and its host
/// is written as plain ASCII (letters, digits, `-`, `.`; no percent-encoding, no non-ASCII, no IP literal), then
/// re-serialised as `https://<lower-case host><percent-encoded path>[?<query>]` (no port, no user info, no
/// fragment). The query (signed asset URLs carry one) must be printable ASCII.
pub fn canonical_redirect_url(url: &str) -> Option<String> {
    if !UpdateURLPolicy::is_allowed_redirect(url) {
        return None;
    }
    let u = macvpn_core::url::parse(url)?;
    let raw_host = u.authority_without_port.as_deref()?;
    if raw_host.is_empty() || !raw_host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
        return None;
    }
    let host = raw_host.to_ascii_lowercase();
    if u.host.as_deref().map(str::to_ascii_lowercase).as_deref() != Some(host.as_str()) {
        return None;
    }
    let path = &u.percent_encoded_path;
    if !path.starts_with('/') || !path.bytes().all(|b| (0x21..0x7f).contains(&b)) {
        return None;
    }
    let mut out = format!("https://{host}{path}");
    if u.query.is_some() {
        // The query as written (the authority and path cannot contain `?`).
        let raw = &u.original[u.original.find('?')? + 1..];
        let raw = raw.split('#').next().unwrap_or("");
        if !raw.bytes().all(|b| (0x21..0x7f).contains(&b)) {
            return None;
        }
        out.push('?');
        out.push_str(raw);
    }
    Some(out)
}

/// Deletes the output file of a hop (missing is fine).
fn remove_output(output: &Path) -> Result<(), HttpError> {
    match std::fs::remove_file(output) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(HttpError::Io(e)),
    }
}

impl HttpClient for CurlHttpClient {
    fn get(&self, url: &str) -> Result<HttpResponse, HttpError> {
        // A release asset in its canonical form; otherwise (the API) an allowed host written as plain ASCII.
        let Some(url) = UpdateURLPolicy::canonical_download_url(url).or_else(|| canonical_redirect_url(url)) else {
            return Err(HttpError::Update(UpdateError::UntrustedUrl(url.to_string())));
        };
        let url = url.as_str();
        Self::with_private_directory(|dir| {
            let file = dir.join("response");
            let status = self.follow(url, &file, Some("application/vnd.github+json"), 30.0)?;
            let data = std::fs::read(&file).unwrap_or_default();
            Ok(HttpResponse { status, data })
        })
    }

    fn download(&self, url: &str) -> Result<(PathBuf, i64), HttpError> {
        // curl only ever sees `https://github.com<percent-encoded path>`.
        let Some(url) = UpdateURLPolicy::canonical_download_url(url) else {
            return Err(HttpError::Update(UpdateError::UntrustedUrl(url.to_string())));
        };
        let url = url.as_str();
        Self::with_private_directory(|dir| {
            let file = dir.join("download");
            let status = self.follow(url, &file, None, RESOURCE_TIMEOUT)?;
            // The caller owns one plain file (as with URLSession's download task): moved out of the private
            // directory to a unique name.
            let base = temporary_directory().map_err(|e| HttpError::Io(std::io::Error::other(e.0)))?;
            let target = base.join(format!("macvpn-dl-{}", uuid::Uuid::new_v4()));
            if file.exists() { std::fs::rename(&file, &target) } else { std::fs::write(&target, b"") }
                .map_err(HttpError::Io)?;
            Ok((target, status))
        })
    }
}
