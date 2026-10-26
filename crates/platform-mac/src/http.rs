//! The updater's network layer on macOS: the shared curl layer (`macvpn_platform_api::curl::http`: the redirect
//! policy, the canonical URLs, the argument list) with the macOS flavour ([`mac_curl`]: `/usr/bin/curl`, no extra
//! arguments, `mkdtemp` directories in the user's private temporary directory) and the macOS runner (curl's fixed
//! environment, the download time limit plus a margin).

use crate::command::{CommandRunner, ProcessCommandRunner};
use crate::temp_dir::{make_private_temp_directory, temporary_directory};
use macvpn_platform_api::curl::Curl;
use macvpn_platform_api::curl::http::{self as shared, RESOURCE_TIMEOUT};
pub use macvpn_platform_api::curl::http::{HttpClient, HttpError, HttpResponse, canonical_redirect_url};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// The macOS flavour: `/usr/bin/curl`, no extra arguments, private directories as `mkdtemp(3)` 0700 directories in
/// the user's private temporary directory.
pub fn mac_curl() -> Curl {
    Curl {
        executable: "/usr/bin/curl".to_string(),
        extra_args: Vec::new(),
        private_dir: private_directory,
        temp_base: || temporary_directory().map_err(|e| e.0),
    }
}

/// A fresh private (0700) directory `<user temp>/<prefix>.XXXXXX`.
fn private_directory(prefix: &str) -> Result<PathBuf, String> {
    let base = temporary_directory().map_err(|e| e.0)?;
    make_private_temp_directory(prefix, &base).map_err(|e| e.0)
}

/// The shared [`shared::CurlHttpClient`] with the macOS flavour.
pub struct CurlHttpClient(shared::CurlHttpClient);

impl Default for CurlHttpClient {
    fn default() -> Self {
        Self::new(Box::new(Self::runner()))
    }
}

impl CurlHttpClient {
    pub fn new(runner: Box<dyn CommandRunner>) -> Self {
        CurlHttpClient(shared::CurlHttpClient::with_curl(runner, mac_curl()))
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

    /// The common arguments of the macOS flavour (no extra arguments): see
    /// [`shared::CurlHttpClient::base_arguments`].
    pub fn base_arguments(accept: Option<&str>, max_time: f64, user_agent: &str) -> Vec<String> {
        shared::CurlHttpClient::base_arguments(accept, max_time, user_agent, &mac_curl().extra_args)
    }

    /// Parses `<status> <redirect url>`, curl's `--write-out` output.
    pub fn parse_trailer(trailer: &str) -> Option<(i64, String)> {
        shared::CurlHttpClient::parse_trailer(trailer)
    }
}

impl HttpClient for CurlHttpClient {
    fn get(&self, url: &str) -> Result<HttpResponse, HttpError> {
        self.0.get(url)
    }

    fn download(&self, url: &str) -> Result<(PathBuf, i64), HttpError> {
        self.0.download(url)
    }
}
