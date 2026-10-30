//! The curl layer on Linux (LinVPN plan, Task 20): `/usr/bin/curl` (the `.deb` depends on `curl`; the system trust
//! store) as the [`Curl`] flavour over [`LinCommandRunner`], for the update check, the updater's downloads and the
//! HTTPS team catalogs. The security logic is the shared layer's (`macvpn_platform_api::curl`).
//!
//! The layer's private directories are `<base>/<prefix>.<32 hex>`, created new (never an existing one) with mode
//! 0700, where `<base>` is `$XDG_RUNTIME_DIR/linvpn` (created 0700; only when `$XDG_RUNTIME_DIR` is absolute and a
//! directory of this user with no group or other access) or else the temp directory. A finished download is moved
//! into the same base.

use super::command::{LinCommandRunner, MARGIN_SECS};
use crate::pure::update_check;
use macvpn_core::catalog::fetch::{CatalogFetcher, FetchOutcome, FetchRequest};
use macvpn_core::catalog::format::CatalogError;
use macvpn_core::fsx;
use macvpn_core::l10n;
use macvpn_core::update::Release;
use macvpn_platform_api::ReleaseSource;
use macvpn_platform_api::curl::catalog::{CATALOG_MAX_TIME, CurlCatalogFetcher};
use macvpn_platform_api::curl::http::{CurlHttpClient, RESOURCE_TIMEOUT};
use macvpn_platform_api::curl::{CommandRunner, Curl};
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::PathBuf;

const CURL: &str = "/usr/bin/curl";
/// curl's `--max-time` of the release query (`CurlHttpClient::get`).
const RELEASE_QUERY_MAX_TIME: f64 = 30.0;

/// `/usr/bin/curl`, no extra arguments.
pub(crate) fn linux_curl() -> Curl {
    Curl { executable: CURL.into(), extra_args: vec![], private_dir, temp_base }
}

/// LinVPN's user agent for GitHub's API and the downloads (macOS keeps `MacVPN-Updater`).
pub(crate) fn user_agent() -> String {
    format!("LinVPN/{}", env!("CARGO_PKG_VERSION"))
}

/// The HTTP client of the update check and the updater: `/usr/bin/curl` over a runner capped at `cap` seconds.
pub(crate) fn http_client(cap: f64) -> CurlHttpClient {
    CurlHttpClient::new_with(Box::new(LinCommandRunner::new(cap)), linux_curl(), user_agent())
}

/// The updater's client (downloads: curl's 600 s plus the margin).
pub(crate) fn download_client() -> CurlHttpClient {
    http_client(RESOURCE_TIMEOUT + MARGIN_SECS)
}

/// The catalog fetcher over `runner` with `/usr/bin/curl` and LinVPN's user agent (`LinVPN-Catalog/<version>`).
pub(crate) fn catalog_fetcher_with(runner: Box<dyn CommandRunner>) -> CurlCatalogFetcher {
    CurlCatalogFetcher::new_with(runner, linux_curl(), format!("LinVPN-Catalog/{}", env!("CARGO_PKG_VERSION")))
}

/// The production catalog fetcher.
pub(crate) fn catalog_fetcher() -> CurlCatalogFetcher {
    catalog_fetcher_with(Box::new(LinCommandRunner::new(CATALOG_MAX_TIME + MARGIN_SECS)))
}

/// `$XDG_RUNTIME_DIR/linvpn` when `$XDG_RUNTIME_DIR` is absolute, a real directory of this user and private
/// (created 0700 if missing, refused if it is anything but a private directory of this user); else the temp
/// directory.
fn base() -> PathBuf {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|p| p.is_absolute());
    // SAFETY: getuid has no arguments and cannot fail.
    let uid = unsafe { libc::getuid() };
    let private_of_mine = |p: &std::path::Path| {
        std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir() && m.uid() == uid && m.mode() & 0o077 == 0)
    };
    runtime
        .filter(|r| private_of_mine(r))
        .map(|r| r.join("linvpn"))
        .filter(|dir| {
            let _ = std::fs::DirBuilder::new().mode(0o700).create(dir);
            private_of_mine(dir)
        })
        .unwrap_or_else(std::env::temp_dir)
}

/// `<base>/<prefix>.<32 hex>`, new and 0700.
fn private_dir(prefix: &str) -> Result<PathBuf, String> {
    let mut random = [0u8; 16];
    macvpn_unixsys::random::fill(&mut random).map_err(|e| e.to_string())?;
    let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let dir = base().join(format!("{prefix}.{suffix}"));
    // A new directory (a name that exists already is never taken over), owner-only from its creation.
    std::fs::DirBuilder::new().mode(0o700).create(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if let Err(e) = fsx::ensure_private_dir(&dir) {
        let _ = std::fs::remove_dir(&dir);
        return Err(format!("{}: {e}", dir.display()));
    }
    Ok(dir)
}

/// Where a finished download is moved: the same base (private when it is the runtime dir).
fn temp_base() -> Result<PathBuf, String> {
    Ok(base())
}

/// GitHub's `releases/latest` through `/usr/bin/curl`, with LinVPN's `.deb` for this machine.
pub(crate) struct LinReleases(CurlHttpClient);

impl LinReleases {
    pub(crate) fn new() -> Self {
        LinReleases(http_client(RELEASE_QUERY_MAX_TIME + MARGIN_SECS))
    }
}

impl ReleaseSource for LinReleases {
    fn latest_release(&self, repo_id: i64, repo: &str) -> Result<Release, String> {
        update_check::latest_release(&self.0, repo_id, repo, std::env::consts::ARCH)
    }
}

/// The sandbox (debug builds, `MACVPN_SANDBOX_HOME`) refuses every HTTPS source, as on macOS and Windows: a
/// development run never reaches a team's server.
pub(crate) struct SandboxHttps;

impl CatalogFetcher for SandboxHttps {
    fn fetch(&self, _req: &FetchRequest) -> Result<FetchOutcome, CatalogError> {
        Err(CatalogError::Io(l10n::tr("HTTPS sources are not available in the sandbox", &[])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curl_runs_from_usr_bin_with_a_private_directory() {
        let curl = linux_curl();
        assert_eq!(curl.executable, "/usr/bin/curl");
        let runner = LinCommandRunner::new(60.0);
        let r = runner.run(&curl.executable, &["--version".to_string()], None).unwrap();
        assert_eq!(r.exit_code, 0, "{}", r.stderr);
        assert!(r.stdout.starts_with("curl "), "{}", r.stdout);
        // stdin reaches the child (`--config -` reads it): an unknown option fails with curl's own message.
        let r = runner.run(&curl.executable, &["--config".into(), "-".into()], Some("not-an-option\n")).unwrap();
        assert_ne!(r.exit_code, 0);
        let dir = (curl.private_dir)("macvpn-test").unwrap();
        let meta = std::fs::symlink_metadata(&dir).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.mode() & 0o777, 0o700);
        assert_eq!(dir.file_name().unwrap().to_string_lossy().len(), "macvpn-test.".len() + 32);
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn linvpn_names_itself_to_github() {
        assert_eq!(user_agent(), format!("LinVPN/{}", env!("CARGO_PKG_VERSION")));
    }
}
