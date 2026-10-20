//! Fetching a catalog from its source (plan Tasks 9 and 10): the one trait both sources implement, so the
//! catalog service (app-core) is the same for an HTTPS URL (`macvpn-platform-mac`'s `CurlCatalogFetcher`) and a
//! file path (app-core's `FileCatalogFetcher`).
//!
//! The trait lives here rather than in app-core's `deps.rs`, where the plan puts it, because the platform layer
//! does not depend on app-core; app-core re-exports it from `deps`.

use super::format::CatalogError;
use super::source::CatalogSource;
use crate::vault::SourceValidators;
use std::fmt;

/// One fetch: the source, the bearer token of an HTTPS source (never logged, never in argv or env) and the
/// validators of the last applied catalog (conditional GET, the file source's content hash).
pub struct FetchRequest<'a> {
    pub source: &'a CatalogSource,
    pub bearer: Option<&'a str>,
    pub previous: &'a SourceValidators,
}

impl fmt::Debug for FetchRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchRequest")
            .field("source", &self.source)
            .field("bearer", &self.bearer.map(|_| "<redacted>"))
            .field("previous", &self.previous)
            .finish()
    }
}

/// What a fetch found.
#[derive(PartialEq, Eq)]
pub enum FetchOutcome {
    /// The source has not changed since `previous` (`304`, or the same file content).
    NotModified,
    /// New bytes (at most `MAX_CATALOG_BYTES`) and the validators to store once they were applied.
    Fetched { bytes: Vec<u8>, validators: SourceValidators },
}

impl fmt::Debug for FetchOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FetchOutcome::NotModified => f.write_str("NotModified"),
            FetchOutcome::Fetched { bytes, validators } => {
                f.debug_struct("Fetched").field("bytes", &bytes.len()).field("validators", validators).finish()
            }
        }
    }
}

/// A catalog source. Transport failures (a host down, a missing share, a timeout) are
/// [`CatalogError::Unavailable`], so the service shows "unavailable" without an error notification (spec 4).
pub trait CatalogFetcher: Send + Sync {
    fn fetch(&self, req: &FetchRequest) -> Result<FetchOutcome, CatalogError>;
}

/// The SHA-256 of a fetched file: the file source's change check (spike decision B1) and
/// `OpenedCatalog::content_hash`.
pub fn content_hash(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}
