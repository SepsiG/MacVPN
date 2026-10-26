//! The HTTPS team catalog source on macOS: the shared fetcher (`macvpn_platform_api::curl::catalog`: the
//! conditional GET, the bearer token on stdin, the redirect and origin rules, the size cap) with the macOS flavour
//! ([`mac_curl`]) and the macOS runner (curl's fixed environment, `CurlHttpClient::environment`).

use crate::command::{CommandRunner, ProcessCommandRunner};
use crate::http::{CurlHttpClient, mac_curl};
use macvpn_core::catalog::fetch::{CatalogFetcher, FetchOutcome, FetchRequest};
use macvpn_core::catalog::format::CatalogError;
use macvpn_core::catalog::source::HttpsUrl;
use macvpn_core::vault::SourceValidators;
use macvpn_platform_api::curl::catalog as shared;
pub use macvpn_platform_api::curl::catalog::{CATALOG_MAX_TIME, MAX_REDIRECTS, MAX_VALIDATOR_BYTES};
#[cfg(feature = "test-support")]
use std::path::PathBuf;

/// The shared [`shared::CurlCatalogFetcher`] with the macOS flavour.
pub struct CurlCatalogFetcher(shared::CurlCatalogFetcher);

impl Default for CurlCatalogFetcher {
    /// The production runner: the request time limit plus a margin, `CurlHttpClient::environment` only.
    fn default() -> Self {
        Self::new(Box::new(
            ProcessCommandRunner::new(CATALOG_MAX_TIME + 30.0).with_environment(CurlHttpClient::environment()),
        ))
    }
}

impl CurlCatalogFetcher {
    pub fn new(runner: Box<dyn CommandRunner>) -> Self {
        CurlCatalogFetcher(shared::CurlCatalogFetcher::with_curl(runner, mac_curl()))
    }

    /// Trusts a throwaway CA as well (`--cacert`): the local HTTPS server of the tests only.
    #[cfg(feature = "test-support")]
    pub fn with_test_ca(self, ca: PathBuf) -> Self {
        CurlCatalogFetcher(self.0.with_test_ca(ca))
    }

    /// One fetch of an HTTPS source, in a private directory.
    pub fn fetch_https(
        &self,
        url: &HttpsUrl,
        bearer: Option<&str>,
        previous: &SourceValidators,
    ) -> Result<FetchOutcome, CatalogError> {
        self.0.fetch_https(url, bearer, previous)
    }
}

impl CatalogFetcher for CurlCatalogFetcher {
    fn fetch(&self, req: &FetchRequest) -> Result<FetchOutcome, CatalogError> {
        self.0.fetch(req)
    }
}
