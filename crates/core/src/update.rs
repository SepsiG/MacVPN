//! Updates, the platform-independent part (port of `UpdateChecker.swift`, `UpdateSignature.swift` and the pure
//! functions of `UpdateInstaller.swift`): versions, the GitHub release JSON, the asset-URL policy, the repo-ID
//! source, the 24-hour delay, SHA-256, the `.sha256` file and the maintainer's offline Ed25519 signature.
//! Downloading, mounting and installing are in the platform layer.

use crate::date::Date;
use crate::l10n::{self, AppLanguage, Arg};
use crate::swift_base64;
use crate::swift_json;
use crate::swift_str;
use crate::url::{self, FoundationUrl};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

// MARK: - Errors

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateError {
    InvalidRepo(String),
    Http(i64),
    InvalidResponse,
    MissingAsset(String),
    UntrustedUrl(String),
    InvalidChecksumFile,
    ChecksumMismatch,
    /// The `.sig` is missing, malformed, or valid with none of the embedded keys.
    UnsignedUpdate,
    MountFailed(String),
    InvalidApp(String),
    NotWritable(String),
    HelperFailed(String),
}

impl UpdateError {
    pub fn message(&self) -> String {
        match self {
            UpdateError::InvalidRepo(r) => l10n::tr("Invalid update source: %@", &[Arg::Str(r)]),
            UpdateError::Http(404) => l10n::tr("No release available (HTTP 404)", &[]),
            UpdateError::Http(403) => {
                l10n::tr("GitHub is temporarily limiting requests (HTTP 403). Try again later.", &[])
            }
            UpdateError::Http(code) => l10n::tr("The server returned an error (HTTP %ld)", &[Arg::Int(*code)]),
            UpdateError::InvalidResponse => l10n::tr("Unexpected response from GitHub", &[]),
            UpdateError::MissingAsset(name) => l10n::tr("Missing from the release: %@", &[Arg::Str(name)]),
            UpdateError::UntrustedUrl(url) => l10n::tr("Download address not allowed: %@", &[Arg::Str(url)]),
            UpdateError::InvalidChecksumFile => l10n::tr("Invalid checksum file (.sha256)", &[]),
            UpdateError::ChecksumMismatch => {
                l10n::tr("The checksum (SHA-256) of the downloaded file does not match. Update cancelled.", &[])
            }
            UpdateError::UnsignedUpdate => l10n::tr("The update is not signed by the MacVPN maintainer", &[]),
            UpdateError::MountFailed(m) => l10n::tr("Cannot mount the disk image: %@", &[Arg::Str(m)]),
            UpdateError::InvalidApp(m) => l10n::tr("The app on the disk image is not accepted: %@", &[Arg::Str(m)]),
            UpdateError::NotWritable(p) => l10n::tr(
                "The app's location is not writable: %@. Drag the app to the Applications folder, or update manually from the DMG.",
                &[Arg::Str(p)],
            ),
            UpdateError::HelperFailed(m) => l10n::tr("Cannot start the installer helper script: %@", &[Arg::Str(m)]),
        }
    }
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for UpdateError {}

// MARK: - Versions

/// `X.Y.Z`. The `v` prefix and the pre-release / build part (`-beta.1`, `+abc`) are ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemVer {
    pub major: i64,
    pub minor: i64,
    pub patch: i64,
}

impl SemVer {
    pub fn new(major: i64, minor: i64, patch: i64) -> Self {
        SemVer { major, minor, patch }
    }

    pub fn parse(string: &str) -> Option<SemVer> {
        let mut s: &str = string.trim_matches(is_foundation_whitespace);
        if swift_str::has_prefix(s, "v") || swift_str::has_prefix(s, "V") {
            s = &s[1..];
        }
        if let Some(cut) = swift_str::characters(s).iter().position(|c| *c == "-" || *c == "+") {
            let byte: usize = swift_str::characters(s)[..cut].iter().map(|c| c.len()).sum();
            s = &s[..byte];
        }
        let parts = swift_str::split(s, ".", usize::MAX, false);
        if !(1..=3).contains(&parts.len()) {
            return None;
        }
        let mut numbers = Vec::with_capacity(3);
        for p in parts {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            numbers.push(p.parse::<i64>().ok()?);
        }
        while numbers.len() < 3 {
            numbers.push(0);
        }
        Some(SemVer::new(numbers[0], numbers[1], numbers[2]))
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Foundation `CharacterSet.whitespaces` (General_Category Zs and TAB).
fn is_foundation_whitespace(c: char) -> bool {
    swift_str::is_foundation_whitespace(c)
}

// MARK: - Model

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAsset {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Release {
    /// E.g. `v0.2.0`.
    pub tag: String,
    /// The tag without `v`; must equal the attached app's `CFBundleShortVersionString`.
    pub version: String,
    pub notes: String,
    pub page_url: Option<String>,
    /// GitHub's `published_at` (`None` if missing or unparsable).
    pub published_at: Option<Date>,
    pub dmg: ReleaseAsset,
    pub checksum: ReleaseAsset,
    /// `MacVPN-<version>.dmg.sig`: the maintainer's offline Ed25519 signature. `None`: not signed yet, neither
    /// offered nor installed.
    pub signature: Option<ReleaseAsset>,
}

impl Release {
    /// Published at least `minimum_age` seconds ago. An unknown publication time is enough only with
    /// `minimum_age <= 0`.
    pub fn is_old_enough(&self, minimum_age: f64, now: Date) -> bool {
        if minimum_age <= 0.0 {
            return true;
        }
        match self.published_at {
            None => false,
            Some(p) => now.time_interval_since(p) >= minimum_age,
        }
    }

    pub fn is_newer(&self, current: &str) -> bool {
        match (SemVer::parse(current), SemVer::parse(&self.version)) {
            (Some(mine), Some(theirs)) => theirs > mine,
            _ => false,
        }
    }
}

// MARK: - URL policy

/// Where the updater may download from.
pub struct UpdateURLPolicy;

impl UpdateURLPolicy {
    /// The release asset's `browser_download_url` and the release page (`html_url`) may only point here.
    pub const DOWNLOAD_HOSTS: [&'static str; 1] = ["github.com"];
    /// Redirect (and API) targets. GitHub serves the assets from the `release-assets` host today (earlier from
    /// `objects`); the content is authenticated by the SHA-256 and the signature, the host list is defence in depth.
    pub const REDIRECT_HOSTS: [&'static str; 4] =
        ["github.com", "api.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"];

    fn host_ok(url: &FoundationUrl, hosts: &[&str]) -> bool {
        let host = url.host.as_deref().map(str::to_lowercase).unwrap_or_default();
        url.scheme.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("https"))
            && hosts.contains(&host.as_str())
            && url.user.is_none()
            && url.password.is_none()
            && (url.port.is_none() || url.port == Some(443))
    }

    pub fn is_allowed_download(url: &str) -> bool {
        url::parse(url).is_some_and(|u| Self::host_ok(&u, &Self::DOWNLOAD_HOSTS))
    }

    pub fn is_allowed_redirect(url: &str) -> bool {
        url::parse(url).is_some_and(|u| Self::host_ok(&u, &Self::REDIRECT_HOSTS))
    }

    /// The download URL to hand to the downloader: `https://github.com<path>`, with the canonical lower-case ASCII
    /// host and no port, user info, query or fragment. `None` unless [`Self::is_allowed_download`] accepts the URL
    /// and it has no query or fragment (release assets never have one). A host Foundation maps to `github.com`
    /// (`GitHub.com`, `github%2Ecom`, fullwidth letters, a soft hyphen) comes back as `github.com`, so the
    /// downloader never sees the raw form. The path is Foundation's percent-encoded path.
    pub fn canonical_download_url(url: &str) -> Option<String> {
        let u = url::parse(url)?;
        if !Self::host_ok(&u, &Self::DOWNLOAD_HOSTS) || u.query.is_some() || u.fragment.is_some() {
            return None;
        }
        let host = u.host.as_deref()?.to_lowercase();
        let canonical = Self::DOWNLOAD_HOSTS.iter().find(|h| **h == host)?;
        Some(format!("https://{canonical}{}", u.percent_encoded_path))
    }

    /// The URL's path segments (from the raw, percent-encoded path; `%2F` cannot become a separator). `None` with
    /// a query, a fragment, an empty or `.`/`..` segment.
    pub fn path_segments(url: &str) -> Option<Vec<String>> {
        let u = url::parse(url)?;
        if !Self::host_ok(&u, &Self::DOWNLOAD_HOSTS) || u.query.is_some() || u.fragment.is_some() {
            return None;
        }
        let path = &u.percent_encoded_path;
        if !path.starts_with('/') || path.contains('%') {
            return None;
        }
        let parts: Vec<String> = path[1..].split('/').map(str::to_string).collect();
        if parts.iter().any(|p| p.is_empty() || p == "." || p == "..") {
            return None;
        }
        Some(parts)
    }

    fn same_repo(owner: &str, name: &str, repo: &str) -> bool {
        swift_str::eq(&format!("{owner}/{name}").to_lowercase(), &repo.to_lowercase())
    }

    /// The release asset's exact location: `https://github.com/<owner>/<repo>/releases/download/<tag>/<name>`
    /// (owner/repo case-insensitively, the tag and the name exactly).
    pub fn is_expected_asset(url: &str, repo: &str, tag: &str, name: &str) -> bool {
        let Some(p) = Self::path_segments(url) else { return false };
        p.len() == 6
            && Self::same_repo(&p[0], &p[1], repo)
            && p[2] == "releases"
            && p[3] == "download"
            && swift_str::eq(&p[4], tag)
            && swift_str::eq(&p[5], name)
    }

    /// The release page: `https://github.com/<owner>/<repo>/releases/…`.
    pub fn is_release_page(url: &str, repo: &str) -> bool {
        let Some(p) = Self::path_segments(url) else { return false };
        p.len() >= 3 && Self::same_repo(&p[0], &p[1], repo) && p[2] == "releases"
    }
}

// MARK: - Checking

/// An `Info.plist` value, as Foundation gives it (`String` or `NSNumber`).
#[derive(Debug, Clone, PartialEq)]
pub enum InfoValue {
    String(String),
    Integer(i64),
    Real(f64),
    Boolean(bool),
}

pub type Info = HashMap<String, InfoValue>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    Offer,
    UpToDate,
    /// Newer, but the delay (24 hours) since publication has not passed yet.
    TooRecent,
    /// Newer, but without a `.sig` asset (not signed offline yet): not offered.
    AwaitingSignature,
}

pub struct UpdateChecker;

impl UpdateChecker {
    /// `owner/repo`: the Help and documentation links, and the asset path checks.
    pub const INFO_PLIST_KEY: &'static str = "MacVPNUpdateRepo";
    /// The repo's immutable numeric GitHub ID: the query uses it, so a renamed or deleted and re-created repo
    /// with the same name (repo-jacking) cannot serve an update.
    pub const REPO_ID_INFO_PLIST_KEY: &'static str = "MacVPNUpdateRepoID";
    /// The optional delay: only a release published at least this long ago is offered.
    pub const MINIMUM_RELEASE_AGE: f64 = 24.0 * 60.0 * 60.0;

    /// `MacVPNUpdateRepoID`: a positive integer (as text or number). `None` if missing or invalid; then there is
    /// no update check (no fallback to the name).
    pub fn repo_id_from_info(info: Option<&Info>) -> Option<i64> {
        let text = match info?.get(Self::REPO_ID_INFO_PLIST_KEY)? {
            InfoValue::String(s) => s.trim_matches(is_foundation_whitespace).to_string(),
            InfoValue::Integer(n) => n.to_string(),
            InfoValue::Real(_) | InfoValue::Boolean(_) => return None,
        };
        let count = swift_str::characters(&text).len();
        if !(1..=19).contains(&count) || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        text.parse::<i64>().ok().filter(|&id| id > 0)
    }

    /// The update source: the ID (query) and the name (asset checks) together; either missing disables it.
    pub fn source_from_info(info: Option<&Info>) -> Option<(i64, String)> {
        Some((Self::repo_id_from_info(info)?, Self::repo_from_info(info)?))
    }

    /// Whether the release can be offered: newer than the running one, has a signature asset, and with the delay
    /// on, at least 24 hours old. (The signature itself is verified by the installer against the downloaded
    /// DMG's locally computed hash.)
    pub fn offer(release: &Release, current_version: &str, delayed: bool, now: Date) -> Offer {
        if !release.is_newer(current_version) {
            return Offer::UpToDate;
        }
        if release.signature.is_none() {
            return Offer::AwaitingSignature;
        }
        if delayed && !release.is_old_enough(Self::MINIMUM_RELEASE_AGE, now) {
            return Offer::TooRecent;
        }
        Offer::Offer
    }

    /// `owner/repo`, nothing else.
    pub fn is_valid_repo(repo: &str) -> bool {
        crate::validators::matches(repo, "^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
            && !swift_str::has_suffix(repo, "/.")
            && !swift_str::has_suffix(repo, "/..")
    }

    /// `MacVPNUpdateRepo`; `None` if missing or invalid (then there is no update check).
    pub fn repo_from_info(info: Option<&Info>) -> Option<String> {
        let InfoValue::String(value) = info?.get(Self::INFO_PLIST_KEY)? else { return None };
        let trimmed = value.trim_matches(is_foundation_whitespace);
        Self::is_valid_repo(trimmed).then(|| trimmed.to_string())
    }

    /// Checks the source like the Swift initializer.
    pub fn validate_source(repo_id: i64, repo: &str) -> Result<(), UpdateError> {
        if repo_id <= 0 {
            return Err(UpdateError::InvalidRepo(repo_id.to_string()));
        }
        if !Self::is_valid_repo(repo) {
            return Err(UpdateError::InvalidRepo(repo.to_string()));
        }
        Ok(())
    }

    pub fn latest_release_url(repo_id: i64) -> String {
        format!("https://api.github.com/repositories/{repo_id}/releases/latest")
    }

    /// The `releases/latest` answer: HTTP 200 parsed, anything else an error.
    pub fn release_from_response(status: i64, data: &[u8], repo: &str) -> Result<Release, UpdateError> {
        if status != 200 {
            return Err(UpdateError::Http(status));
        }
        Self::parse_release(data, repo)
    }

    /// GitHub's `releases/latest` JSON. The DMG is `MacVPN-<version>.dmg`, next to it `MacVPN-<version>.dmg.sha256`
    /// and (when signed) `MacVPN-<version>.dmg.sig`. A missing `.sig` is not an error here (`signature` is
    /// `None`, `offer` does not offer it), but if present the same path check applies. Assets may only come from
    /// `https://github.com/<repo>/releases/download/<tag>/<name>`.
    pub fn parse_release(data: &[u8], repo: &str) -> Result<Release, UpdateError> {
        let raw = RawRelease::decode(data).ok_or(UpdateError::InvalidResponse)?;
        if raw.draft == Some(true)
            || raw.prerelease == Some(true)
            || SemVer::parse(&raw.tag_name).is_none()
            || !crate::validators::matches(&raw.tag_name, "^v?[0-9]+(\\.[0-9]+){0,2}$")
        {
            return Err(UpdateError::InvalidResponse);
        }
        let version = if swift_str::has_prefix(&raw.tag_name, "v") {
            raw.tag_name[1..].to_string()
        } else {
            raw.tag_name.clone()
        };
        let dmg_name = format!("MacVPN-{version}.dmg");
        let optional_asset = |name: &str| -> Result<Option<ReleaseAsset>, UpdateError> {
            let Some((asset_name, url)) = raw.assets.iter().find(|(n, _)| swift_str::eq(n, name)) else {
                return Ok(None);
            };
            if url::parse(url).is_none() || !UpdateURLPolicy::is_expected_asset(url, repo, &raw.tag_name, name) {
                return Err(UpdateError::UntrustedUrl(url.clone()));
            }
            Ok(Some(ReleaseAsset { name: asset_name.clone(), url: url.clone() }))
        };
        let asset = |name: &str| optional_asset(name)?.ok_or_else(|| UpdateError::MissingAsset(name.to_string()));
        let page =
            raw.html_url.clone().filter(|u| url::parse(u).is_some() && UpdateURLPolicy::is_release_page(u, repo));
        let published = raw.published_at.as_deref().and_then(Date::parse_iso8601_formatter);
        let dmg = asset(&dmg_name)?;
        let checksum = asset(&format!("{dmg_name}.sha256"))?;
        let signature = optional_asset(&format!("{dmg_name}.sig"))?;
        Ok(Release {
            tag: raw.tag_name.clone(),
            version,
            notes: raw.body.clone().unwrap_or_default(),
            page_url: page,
            published_at: published,
            dmg,
            checksum,
            signature,
        })
    }
}

/// The GitHub release fields MacVPN reads (Swift `Decodable`: unknown keys ignored, `null` = absent).
struct RawRelease {
    tag_name: String,
    body: Option<String>,
    html_url: Option<String>,
    published_at: Option<String>,
    draft: Option<bool>,
    prerelease: Option<bool>,
    assets: Vec<(String, String)>,
}

impl RawRelease {
    fn decode(data: &[u8]) -> Option<RawRelease> {
        let value = swift_json::parse(data).ok()?;
        let obj = value.as_object()?;
        fn opt<T>(
            obj: &serde_json::Map<String, Value>,
            key: &str,
            get: impl Fn(&Value) -> Option<T>,
        ) -> Option<Option<T>> {
            match obj.get(key) {
                None | Some(Value::Null) => Some(None),
                Some(v) => get(v).map(Some),
            }
        }
        let string = |v: &Value| v.as_str().map(str::to_string);
        let mut assets = Vec::new();
        for a in obj.get("assets")?.as_array()? {
            let a = a.as_object()?;
            assets.push((string(a.get("name")?)?, string(a.get("browser_download_url")?)?));
        }
        Some(RawRelease {
            tag_name: string(obj.get("tag_name")?)?,
            body: opt(obj, "body", string)?,
            html_url: opt(obj, "html_url", string)?,
            published_at: opt(obj, "published_at", string)?,
            draft: opt(obj, "draft", Value::as_bool)?,
            prerelease: opt(obj, "prerelease", Value::as_bool)?,
            assets,
        })
    }
}

// MARK: - Help

pub struct UserGuide;

impl UserGuide {
    pub const FALLBACK_REPO: &'static str = "SepsiG/MacVPN";

    /// The same choice as the app's UI: the first Hungarian or English preferred language, otherwise `en`.
    pub fn language<S: AsRef<str>>(preferred: &[S]) -> &'static str {
        AppLanguage::resolve(preferred).raw_value()
    }

    pub fn url<S: AsRef<str>>(repo: Option<&str>, preferred_languages: &[S]) -> String {
        let r = repo.filter(|r| UpdateChecker::is_valid_repo(r)).unwrap_or(Self::FALLBACK_REPO);
        format!("https://github.com/{r}/blob/main/docs/user-guide.{}.md", Self::language(preferred_languages))
    }
}

// MARK: - Signature

/// The releases' offline Ed25519 signature.
///
/// The maintainer signs every release DMG's SHA-256 with an offline key independent of GitHub
/// (`scripts/sign-release.sh`); the signature is the `MacVPN-<version>.dmg.sig` asset. The app installs only if
/// the signature is valid with one of the embedded public keys, so a compromised GitHub account (or CI) cannot
/// publish an update.
///
/// The signed message, byte for byte: `"macvpn-update-v1\n" + version + "\n" + lower-case sha256 hex + "\n"`, the
/// version without `v` (e.g. `0.2.2`). Plain Ed25519 (OpenSSL 3: `pkeyutl -sign -rawin`). The `.sig` is one line:
/// the 64-byte signature in base64, with a trailing newline.
pub struct UpdateSignature;

impl UpdateSignature {
    /// The primary key (in the maintainer's login Keychain). Raw 32 bytes, base64.
    pub const PRIMARY_PUBLIC_KEY_BASE64: &'static str = "KfHXY5gQkjMA3e8bx8rIuPQ4x3zCuSJoMo3PYcMgbFk=";
    /// The backup key (offline, in a password manager), for losing or compromising the primary.
    pub const BACKUP_PUBLIC_KEY_BASE64: &'static str = "QUFfsn9koh06k4EX9lNPognIvQ84/Ox6lgZhShvVrmI=";
    /// The largest `.sig` asset (the real one: 88 characters + newline).
    pub const MAX_SIGNATURE_FILE_SIZE: usize = 1024;
    pub const DOMAIN: &'static str = "macvpn-update-v1";

    /// The embedded, trusted keys (primary, backup), raw 32 bytes each.
    pub fn trusted_keys() -> Vec<[u8; 32]> {
        [Self::PRIMARY_PUBLIC_KEY_BASE64, Self::BACKUP_PUBLIC_KEY_BASE64]
            .iter()
            .filter_map(|b64| swift_base64::decode(b64)?.try_into().ok())
            .filter(|k: &[u8; 32]| VerifyingKey::from_bytes(k).is_ok())
            .collect()
    }

    /// The signed message. `None` if the version is not `X.Y.Z`, or the hash is not 64 lower-case hex digits.
    pub fn message(version: &str, sha256_hex: &str) -> Option<Vec<u8>> {
        if !crate::validators::matches(version, "^[0-9]{1,9}\\.[0-9]{1,9}\\.[0-9]{1,9}$")
            || sha256_hex.len() != 64
            || !sha256_hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        Some(format!("{}\n{version}\n{sha256_hex}\n", Self::DOMAIN).into_bytes())
    }

    /// Verification is strict (`verify_strict`: also rejects small-order keys and non-canonical points), which
    /// every signature made by `scripts/sign-release.sh` passes.
    ///
    /// True if `signature_base64` (the `.sig` content) is a valid Ed25519 signature of the `version` +
    /// `sha256_hex` message with any of `public_keys`. Pure: no network, no file. The hash is the locally computed
    /// SHA-256.
    pub fn verify(version: &str, sha256_hex: &str, signature_base64: &str, public_keys: &[[u8; 32]]) -> bool {
        if signature_base64.len() > Self::MAX_SIGNATURE_FILE_SIZE {
            return false;
        }
        let Some(message) = Self::message(version, sha256_hex) else { return false };
        // One line; a trailing newline (and space) is fine, an inner space or more lines are not.
        let trimmed = signature_base64.trim_matches(swift_str::is_foundation_whitespace_or_newline);
        if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
            return false;
        }
        let Some(bytes) = swift_base64::decode(trimmed) else { return false };
        let Ok(bytes) = <[u8; 64]>::try_from(bytes.as_slice()) else { return false };
        let signature = Signature::from_bytes(&bytes);
        public_keys
            .iter()
            .any(|k| VerifyingKey::from_bytes(k).is_ok_and(|key| key.verify_strict(&message, &signature).is_ok()))
    }

    /// [`Self::verify`] with the embedded keys.
    pub fn verify_trusted(version: &str, sha256_hex: &str, signature_base64: &str) -> bool {
        Self::verify(version, sha256_hex, signature_base64, &Self::trusted_keys())
    }
}

// MARK: - Checksums and the helper log

pub const MAX_CHECKSUM_FILE_SIZE: usize = 4096;

/// Swift `Character.isNewline`.
fn is_newline_character(c: &str) -> bool {
    c == "\r\n" || matches!(c, "\n" | "\r" | "\u{B}" | "\u{C}" | "\u{85}" | "\u{2028}" | "\u{2029}")
}

/// Swift `split(whereSeparator:)` (omitting empty parts) on Characters.
fn split_characters(s: &str, max_splits: usize, is_separator: impl Fn(&str) -> bool) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut splits = 0;
    let indices: Vec<(usize, &str)> = unicode_segmentation::UnicodeSegmentation::grapheme_indices(s, true).collect();
    for (i, g) in &indices {
        if splits >= max_splits {
            break;
        }
        if is_separator(g) {
            if *i > start {
                parts.push(&s[start..*i]);
                splits += 1;
            }
            start = i + g.len();
        }
    }
    if start < s.len() {
        parts.push(&s[start..]);
    }
    parts
}

/// The `.sha256` file: `<64 hex>  <file name>` (`shasum` output; a `*` binary marker is allowed).
pub fn parse_checksum(text: &str, expected_name: &str) -> Result<String, UpdateError> {
    for line in split_characters(text, usize::MAX, is_newline_character) {
        let line = line.trim_matches(is_foundation_whitespace);
        if line.is_empty() {
            continue;
        }
        let parts = split_characters(line, 1, |c| c == " " || c == "\t");
        if parts.len() != 2 {
            continue;
        }
        let hash = parts[0].to_lowercase();
        let mut name = parts[1].trim_matches(is_foundation_whitespace);
        if swift_str::has_prefix(name, "*") {
            name = &name[1..];
        }
        if swift_str::eq(name, expected_name)
            && swift_str::characters(&hash).len() == 64
            && hash.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Ok(hash);
        }
    }
    Err(UpdateError::InvalidChecksumFile)
}

/// Lower-case SHA-256 hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// SHA-256 hex of a file, read in chunks (the DMG can be large).
pub fn sha256_of_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperOutcome {
    Succeeded,
    /// The app did not quit within 30 s, nothing was replaced.
    TimedOut,
    /// The swap stopped with an error; with the log's error line.
    Failed(String),
    /// No result (still running, or an old script writes "done" after opening).
    Unknown,
}

/// The helper script's log (`update.log`), last run: its header line (`=== … ===`, its identifier) and outcome.
/// `None` if the log has no run.
pub fn last_helper_outcome(log: &str) -> Option<(String, HelperOutcome)> {
    let lines: Vec<&str> = split_characters(log, usize::MAX, is_newline_character)
        .into_iter()
        .map(|l| l.trim_matches(is_foundation_whitespace))
        .collect();
    let start = lines.iter().rposition(|l| swift_str::has_prefix(l, "=== ") && swift_str::has_suffix(l, " ==="))?;
    let header = lines[start].to_string();
    let body = &lines[start + 1..];
    if body.iter().any(|l| swift_str::eq(l, "done")) {
        return Some((header, HelperOutcome::Succeeded));
    }
    if body.iter().any(|l| swift_str::contains(l, "did not quit within 30 s")) {
        return Some((header, HelperOutcome::TimedOut));
    }
    let markers = ["failed", "cannot ", "update cancelled"];
    if let Some(line) = body.iter().find(|l| markers.iter().any(|m| swift_str::contains(l, m))) {
        return Some((header, HelperOutcome::Failed(line.to_string())));
    }
    Some((header, HelperOutcome::Unknown))
}
