//! LinVPN's update check (LinVPN plan, Task 20): the update source an installed LinVPN names (macOS keeps it in the
//! app's Info.plist; the `.deb` has no such file, so the same keys are compiled in, as WinVPN does), and the
//! `releases/latest` answer read with LinVPN's `.deb` for this machine. The download, the verification and the
//! install are the updater's. Nothing here touches the network: the caller brings the HTTP client (`/usr/bin/curl`).

use macvpn_core::update::{Info, InfoValue, Release, UpdateChecker};
use macvpn_platform_api::LINVPN;
use macvpn_platform_api::curl::http::HttpClient;

/// The repository's immutable numeric GitHub ID (the query uses it: a renamed or re-created repository with the
/// same name cannot serve an update). The same value as `MacVPNUpdateRepoID` in MacVPN's Info.plist and WinVPN's.
pub const UPDATE_REPO_ID: i64 = 1_422_472_799;

/// The update source of an installed LinVPN, under the keys `UpdateChecker` reads (`MacVPNUpdateRepo`, the
/// product's repository, and `MacVPNUpdateRepoID`, as text as in the plist).
pub fn update_info() -> Info {
    Info::from([
        (UpdateChecker::INFO_PLIST_KEY.to_string(), InfoValue::String(LINVPN.repo.to_string())),
        (UpdateChecker::REPO_ID_INFO_PLIST_KEY.to_string(), InfoValue::String(UPDATE_REPO_ID.to_string())),
    ])
}

/// `releases/latest` of `repo_id` through `http`, with LinVPN's `.deb` for `arch` (`std::env::consts::ARCH`:
/// `linvpn_<version>_amd64.deb` / `_arm64.deb`, `deb_update::asset`) as the package. The error is the message shown.
pub fn latest_release(http: &dyn HttpClient, repo_id: i64, repo: &str, arch: &str) -> Result<Release, String> {
    let response = http.get(&UpdateChecker::latest_release_url(repo_id)).map_err(|e| e.to_string())?;
    let asset_for = |version: &str| LINVPN.update_asset(version, arch);
    UpdateChecker::release_from_response(response.status, &response.data, repo, &asset_for).map_err(|e| e.message())
}
