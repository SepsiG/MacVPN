//! The updater's network layer (port of `HTTPClient` / `URLSessionHTTPClient` in `UpdateChecker.swift`).
//!
//! [`CurlHttpClient`] uses the system's curl (the flavour's executable: the system trust store, no extra TLS stack in
//! the app) and follows redirects itself, one hop at a time, so every target is checked against
//! [`UpdateURLPolicy::is_allowed_redirect`] before it is requested (the URLSession delegate's rule). curl only
//! gets canonical URLs: release assets as [`UpdateURLPolicy::canonical_download_url`], redirect targets as
//! [`canonical_redirect_url`]. Only HTTPS,
//! no cookies, `User-Agent: MacVPN-Updater`, 30 s per request and 600 s per download.

use super::{CommandError, CommandRunner, Curl};
use macvpn_core::catalog::source::HttpsUrl;
use macvpn_core::update::{UpdateError, UpdateURLPolicy, sha256_of_file};
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
    curl: Curl,
    max_redirects: usize,
    user_agent: String,
}

const REQUEST_TIMEOUT: &str = "30";
/// curl's `--max-time` of a download, in seconds.
pub const RESOURCE_TIMEOUT: f64 = 600.0;
const USER_AGENT: &str = "MacVPN-Updater";
/// The redirects [`CurlHttpClient::download_pinned`] follows (OpenVPN's download host needs one).
pub const PINNED_MAX_REDIRECTS: usize = 5;

impl CurlHttpClient {
    /// The client over `runner` (which brings the environment and the time limit) and this OS' curl, with
    /// MacVPN's user agent (`MacVPN-Updater`).
    pub fn with_curl(runner: Box<dyn CommandRunner>, curl: Curl) -> Self {
        Self::new_with(runner, curl, USER_AGENT.to_string())
    }

    /// [`CurlHttpClient::with_curl`] with the product's own user agent (WinVPN: `WinVPN-Updater/<version>`).
    pub fn new_with(runner: Box<dyn CommandRunner>, curl: Curl, user_agent: String) -> Self {
        CurlHttpClient { runner, curl, max_redirects: 10, user_agent }
    }

    /// The common arguments: HTTPS only, no redirect following by curl, no URL globbing, no config file (`-q`
    /// first), timeouts, the flavour's `extra` arguments (right after `--max-time <n>`), user agent.
    pub fn base_arguments(accept: Option<&str>, max_time: f64, user_agent: &str, extra: &[&str]) -> Vec<String> {
        let mut args: Vec<String> = [
            "-q",
            // A URL is taken literally: `[]` and `{}` are never curl's globbing.
            "--globoff",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--max-redirs",
            "0",
            // No URL globbing: `[ ] { }` in a URL (a redirect target) never fans out into many requests.
            "--globoff",
            "--connect-timeout",
            REQUEST_TIMEOUT,
            "--max-time",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        args.push(format!("{}", max_time as i64));
        args.extend(extra.iter().map(|s| s.to_string()));
        args.push("--user-agent".into());
        args.push(user_agent.into());
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
        limits: &[String],
    ) -> Result<(i64, String), HttpError> {
        // A previous hop's body (a 3xx page) must never be taken as this hop's data.
        remove_output(output).map_err(HttpError::Io)?;
        let mut args = Self::base_arguments(accept, max_time, &self.user_agent, &self.curl.extra_args);
        args.extend(limits.iter().cloned());
        args.extend(["--write-out".to_string(), "%{http_code} %{redirect_url}".to_string()]);
        args.extend(["--output".to_string(), output.to_string_lossy().into_owned()]);
        args.extend(["--".to_string(), url.to_string()]);
        let result = self.runner.run(&self.curl.executable, &args, None).map_err(HttpError::Command)?;
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
            let (status, redirect) = self.request(&current, output, accept, max_time, &[])?;
            if (300..400).contains(&status)
                && let Some(next) = canonical_redirect_url(&redirect)
            {
                current = next;
                continue;
            }
            if (300..400).contains(&status) {
                // A redirect that is not followed: its body is no data.
                remove_output(output).map_err(HttpError::Io)?;
            }
            return Ok(status);
        }
        remove_output(output).map_err(HttpError::Io)?;
        Err(HttpError::Transport(47, "too many redirects".into()))
    }

    /// Downloads a file pinned by its SHA-256 (lower-case hex) from an `https://` URL that is not a release asset
    /// (the OpenVPN Community MSI: 2b plan, Task 17). Any host is acceptable because the content is pinned: the URL
    /// and every redirect target must be canonical `https://` URLs ([`HttpsUrl`]: no user info, no fragment,
    /// curl's globbing characters encoded), at most [`PINNED_MAX_REDIRECTS`] hops; curl stops at `max_bytes`
    /// (`--max-filesize`). The final answer must be 200 and the file's SHA-256 the pin; otherwise the file is
    /// deleted and an error returned. The returned file (in the flavour's `temp_base`) belongs to the caller.
    pub fn download_pinned(&self, url: &str, sha256: &str, max_bytes: u64) -> Result<PathBuf, HttpError> {
        let first = HttpsUrl::parse(url).map_err(|_| HttpError::Update(UpdateError::UntrustedUrl(url.to_string())))?;
        if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(HttpError::Update(UpdateError::ChecksumMismatch));
        }
        self.with_private_directory(|dir| {
            let file = dir.join("download");
            self.https_chain(first, None, &file, RESOURCE_TIMEOUT, max_bytes)?;
            let actual = sha256_of_file(&file).map_err(HttpError::Io)?;
            if actual != sha256 {
                return Err(HttpError::Update(UpdateError::ChecksumMismatch));
            }
            self.move_out(&file)
        })
    }

    /// Downloads a file that is not pinned (2b plan, fix4: the newest official OpenVPN Community MSI, whose
    /// Authenticode signer the caller checks): as [`CurlHttpClient::download_pinned`], but the URL and every
    /// redirect target must be on one of `hosts` (port 443), and nothing is compared. The returned file (in the
    /// flavour's `temp_base`) belongs to the caller.
    pub fn download_from(&self, url: &str, hosts: &[&str], max_bytes: u64) -> Result<PathBuf, HttpError> {
        let first = HttpsUrl::parse(url).map_err(|_| HttpError::Update(UpdateError::UntrustedUrl(url.to_string())))?;
        self.with_private_directory(|dir| {
            let file = dir.join("download");
            self.https_chain(first, Some(hosts), &file, RESOURCE_TIMEOUT, max_bytes)?;
            self.move_out(&file)
        })
    }

    /// A page's body (status 200, at most `max_bytes`, curl's `--max-time` `max_time` per hop) from `hosts` only,
    /// as [`CurlHttpClient::download_from`] (2b plan, fix4: OpenVPN's download page).
    pub fn get_from(&self, url: &str, hosts: &[&str], max_bytes: u64, max_time: f64) -> Result<Vec<u8>, HttpError> {
        let first = HttpsUrl::parse(url).map_err(|_| HttpError::Update(UpdateError::UntrustedUrl(url.to_string())))?;
        self.with_private_directory(|dir| {
            let file = dir.join("response");
            self.https_chain(first, Some(hosts), &file, max_time, max_bytes)?;
            std::fs::read(&file).map_err(HttpError::Io)
        })
    }

    /// Follows `first` hop by hop (at most [`PINNED_MAX_REDIRECTS`] redirects, `https://` targets only and, with
    /// `hosts`, only on those hosts at port 443) into `file`; a target that is not followed ends the chain with its
    /// 3xx. `Ok` only for a final 200 (the body in `file`); otherwise `file` is gone.
    fn https_chain(
        &self,
        first: HttpsUrl,
        hosts: Option<&[&str]>,
        file: &Path,
        max_time: f64,
        max_bytes: u64,
    ) -> Result<(), HttpError> {
        let allowed = |u: &HttpsUrl| {
            let (host, port) = u.origin();
            hosts.is_none_or(|h| port == 443 && h.contains(&host.as_str()))
        };
        if !allowed(&first) {
            return Err(HttpError::Update(UpdateError::UntrustedUrl(first.redacted())));
        }
        let limits = ["--max-filesize".to_string(), max_bytes.to_string()];
        let mut current = first;
        let mut hops = 0;
        let status = loop {
            let (status, redirect) = self.request(current.as_str(), file, None, max_time, &limits)?;
            if !(300..400).contains(&status) {
                break status;
            }
            remove_output(file).map_err(HttpError::Io)?;
            match current.redirect_target(&redirect) {
                Ok(next) if hops < PINNED_MAX_REDIRECTS && allowed(&next) => {
                    hops += 1;
                    current = next;
                }
                Ok(next) if allowed(&next) => return Err(HttpError::Transport(47, "too many redirects".into())),
                _ => break status,
            }
        };
        if status != 200 {
            remove_output(file).map_err(HttpError::Io)?;
            return Err(HttpError::Update(UpdateError::Http(status)));
        }
        Ok(())
    }

    /// Moves a finished download out of its private directory (removed with everything else in it on any error).
    fn move_out(&self, file: &Path) -> Result<PathBuf, HttpError> {
        let base = (self.curl.temp_base)().map_err(|e| HttpError::Io(std::io::Error::other(e)))?;
        let target = base.join(format!("macvpn-dl-{}", uuid::Uuid::new_v4()));
        std::fs::rename(file, &target).map_err(HttpError::Io)?;
        Ok(target)
    }

    /// Runs `body` with a fresh private directory, removed afterwards.
    fn with_private_directory<T>(&self, body: impl FnOnce(&Path) -> Result<T, HttpError>) -> Result<T, HttpError> {
        with_private_directory(&self.curl, "macvpn-download", body)
            .map_err(|e| HttpError::Io(std::io::Error::other(e)))
            .and_then(|r| r)
    }
}

/// Runs `body` with a fresh private (owner-only) directory `<user temp>/<prefix>.<random>` (the flavour's
/// `private_dir`), removed afterwards whatever `body` returned. `Err`: the directory could not be made (the message).
pub fn with_private_directory<T>(curl: &Curl, prefix: &str, body: impl FnOnce(&Path) -> T) -> Result<T, String> {
    let dir = (curl.private_dir)(prefix)?;
    let result = body(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(result)
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
pub fn remove_output(output: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(output) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

impl HttpClient for CurlHttpClient {
    fn get(&self, url: &str) -> Result<HttpResponse, HttpError> {
        // A release asset in its canonical form; otherwise (the API) an allowed host written as plain ASCII.
        let Some(url) = UpdateURLPolicy::canonical_download_url(url).or_else(|| canonical_redirect_url(url)) else {
            return Err(HttpError::Update(UpdateError::UntrustedUrl(url.to_string())));
        };
        let url = url.as_str();
        self.with_private_directory(|dir| {
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
        self.with_private_directory(|dir| {
            let file = dir.join("download");
            let status = self.follow(url, &file, None, RESOURCE_TIMEOUT)?;
            // The caller owns one plain file (as with URLSession's download task): moved out of the private
            // directory to a unique name.
            let base = (self.curl.temp_base)().map_err(|e| HttpError::Io(std::io::Error::other(e)))?;
            let target = base.join(format!("macvpn-dl-{}", uuid::Uuid::new_v4()));
            if file.exists() { std::fs::rename(&file, &target) } else { std::fs::write(&target, b"") }
                .map_err(HttpError::Io)?;
            Ok((target, status))
        })
    }
}
