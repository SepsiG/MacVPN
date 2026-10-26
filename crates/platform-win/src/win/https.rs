//! HTTPS team catalogs and the update check on Windows (2b plan, Task 19): the shared curl layer
//! (`macvpn_platform_api::curl`: the conditional GET, the bearer token on stdin and only to its origin, the size
//! cap, the redirect rules) over System32's `curl.exe` ([`windows_curl`], [`WinCurlRunner`]).

use super::curl_runner::{MARGIN_SECS, WinCurlRunner, http_client, windows_curl};
use crate::pure::update_check;
use macvpn_core::update::Release;
use macvpn_platform_api::ReleaseSource;
use macvpn_platform_api::curl::CommandRunner;
use macvpn_platform_api::curl::catalog::{CATALOG_MAX_TIME, CurlCatalogFetcher};
use macvpn_platform_api::curl::http::CurlHttpClient;

/// curl's `--max-time` of the release query (`CurlHttpClient::get`).
const RELEASE_QUERY_MAX_TIME: f64 = 30.0;

/// The catalog fetcher over `runner` with Windows' curl and WinVPN's user agent (`WinVPN-Catalog/<version>`).
pub(crate) fn catalog_fetcher_with(runner: Box<dyn CommandRunner>) -> CurlCatalogFetcher {
    CurlCatalogFetcher::new_with(runner, windows_curl(), format!("WinVPN-Catalog/{}", env!("CARGO_PKG_VERSION")))
}

/// The production catalog fetcher.
pub(crate) fn catalog_fetcher() -> CurlCatalogFetcher {
    catalog_fetcher_with(Box::new(WinCurlRunner::new(CATALOG_MAX_TIME + MARGIN_SECS)))
}

/// GitHub's `releases/latest` through Windows' curl, with WinVPN's MSI for this machine.
pub(crate) struct WinReleases(CurlHttpClient);

impl WinReleases {
    pub(crate) fn new() -> Self {
        WinReleases(http_client(windows_curl(), RELEASE_QUERY_MAX_TIME + MARGIN_SECS))
    }
}

impl ReleaseSource for WinReleases {
    fn latest_release(&self, repo_id: i64, repo: &str) -> Result<Release, String> {
        update_check::latest_release(&self.0, repo_id, repo, std::env::consts::ARCH)
    }
}

/// The sandbox (debug builds, `MACVPN_SANDBOX_HOME`) refuses every HTTPS source, as on macOS: a development run
/// never reaches a team's server.
#[cfg(debug_assertions)]
pub(crate) struct SandboxHttps;

#[cfg(debug_assertions)]
impl macvpn_core::catalog::fetch::CatalogFetcher for SandboxHttps {
    fn fetch(
        &self,
        _req: &macvpn_core::catalog::fetch::FetchRequest,
    ) -> Result<macvpn_core::catalog::fetch::FetchOutcome, macvpn_core::catalog::format::CatalogError> {
        Err(macvpn_core::catalog::format::CatalogError::Io(macvpn_core::l10n::tr(
            "HTTPS sources are not available in the sandbox",
            &[],
        )))
    }
}
