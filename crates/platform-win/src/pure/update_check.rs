//! WinVPN's update check (2b plan, Task 19): the update source an installed WinVPN names (macOS keeps it in the
//! app's Info.plist; WinVPN's MSI has no such file, so the same keys are compiled in), and the `releases/latest`
//! answer read with WinVPN's MSI for this machine. The download, the verification and the install are the
//! updater's (Task 18). Nothing here touches the network: the caller brings the HTTP client (System32's curl).

use macvpn_core::update::{Info, InfoValue, Release, UpdateChecker};
use macvpn_platform_api::WINVPN;
use macvpn_platform_api::curl::http::HttpClient;

/// The repository's immutable numeric GitHub ID (the query uses it: a renamed or re-created repository with the
/// same name cannot serve an update). The same value as `MacVPNUpdateRepoID` in MacVPN's Info.plist.
pub const UPDATE_REPO_ID: i64 = 1_422_472_799;

/// The update source of an installed WinVPN, under the keys `UpdateChecker` reads (`MacVPNUpdateRepo`, the
/// product's repository, and `MacVPNUpdateRepoID`, as text as in the plist).
pub fn update_info() -> Info {
    Info::from([
        (UpdateChecker::INFO_PLIST_KEY.to_string(), InfoValue::String(WINVPN.repo.to_string())),
        (UpdateChecker::REPO_ID_INFO_PLIST_KEY.to_string(), InfoValue::String(UPDATE_REPO_ID.to_string())),
    ])
}

/// `releases/latest` of `repo_id` through `http`, with WinVPN's MSI for `arch` (`std::env::consts::ARCH`:
/// `WinVPN-<version>-x64.msi` / `-arm64.msi`) as the package. The error is the message shown.
pub fn latest_release(http: &dyn HttpClient, repo_id: i64, repo: &str, arch: &str) -> Result<Release, String> {
    let response = http.get(&UpdateChecker::latest_release_url(repo_id)).map_err(|e| e.to_string())?;
    let asset_for = |version: &str| WINVPN.update_asset(version, arch);
    UpdateChecker::release_from_response(response.status, &response.data, repo, &asset_for).map_err(|e| e.message())
}
