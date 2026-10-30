//! LinVPN's updater, its portable parts (LinVPN plan, Task 20): the `.deb` of this architecture with its `.sha256`
//! and `.sig`, the download-and-verify flow, the root step's exit codes as outcomes, the outcome notice and the launch
//! housekeeping. `lin::updater` runs them with `/usr/bin/curl`, pkexec and the relaunch.
//!
//! Verification here is for the user's messages: the `.sha256` asset is a convenience check, the gate is the
//! maintainer's Ed25519 signature over the SHA-256 computed here, under LinVPN's domain and the asset's name
//! (`linvpn-update-v1\n<asset>\n<version>\n<sha256>\n`), so neither a MacVPN or WinVPN signature nor one for the
//! other architecture's package passes. The root step `linvpn-install-update` checks all of it again, as root, on its
//! own copy (`macvpn_core::deb_update`), so nothing the user's session could swap afterwards is installed.
//!
//! The notice (`<updates>/notice`, one line): `ok <version>` after an installed update (the relaunched LinVPN), or
//! `failed <version> <code>`. A failure is reported at launch (the Update window's notice is "The previous
//! update did not complete"; the line itself is the run id), a success as "LinVPN was updated to X.Y.Z." (a desktop
//! notification).

use macvpn_core::deb_update::{self, StepError};
use macvpn_core::fsx::{self, Access};
use macvpn_core::l10n::{self, Arg};
use macvpn_core::update::{
    MAX_CHECKSUM_FILE_SIZE, Release, ReleaseAsset, UpdateError, UpdateSignature, UpdateURLPolicy, parse_checksum,
};
use macvpn_platform_api::LINVPN;
use macvpn_platform_api::curl::http::{HttpClient, HttpError};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// The outcome notice for the next launch, in the updates folder.
pub const NOTICE_FILE: &str = "notice";
/// The largest notice read.
const MAX_NOTICE: u64 = 4096;
/// The largest package taken (a real one is a few tens of MB).
pub const MAX_DEB: u64 = 512 << 20;
/// The root step's logs are kept this long.
const LOG_AGE: Duration = Duration::from_secs(7 * 86_400);

/// "This release has no installer for this computer." (WinVPN's text).
pub fn no_package_text() -> String {
    l10n::tr("This release has no installer for this computer.", &[])
}

/// "LinVPN was updated to <version>."
pub fn updated_text(version: &str) -> String {
    l10n::tr("LinVPN was updated to %@.", &[Arg::Str(version)])
}

/// The three assets of an update for one architecture.
#[derive(Debug, Clone, Copy)]
pub struct Assets<'a> {
    pub deb: &'a ReleaseAsset,
    pub sha256: &'a ReleaseAsset,
    pub sig: &'a ReleaseAsset,
}

/// The release's package if it is LinVPN's `.deb` for `arch` (`std::env::consts::ARCH`), with its `.sha256` and
/// `.sig` named after it. `None`: nothing this machine can install (another architecture, not signed yet).
pub fn assets<'a>(release: &'a Release, arch: &str) -> Option<Assets<'a>> {
    let name = LINVPN.update_asset(&release.version, arch)?;
    let sig = release.signature.as_ref()?;
    (release.package.name == name
        && release.checksum.name == format!("{name}.sha256")
        && sig.name == format!("{name}.sig"))
    .then_some(Assets { deb: &release.package, sha256: &release.checksum, sig })
}

// MARK: - Outcome

/// What the root step's exit code (through pkexec) means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Installed,
    /// pkexec's 126 (the dialog was dismissed) or 127 (not authorized): nothing was installed. 127 is also pkexec's
    /// "an error occurred" (a missing program): `lin::updater` checks the step and the polkit action are installed
    /// before the prompt and again after a 127, so a missing helper is its error, not a silent cancel.
    Cancelled,
    /// The localized message.
    Failed(String),
}

/// `exit_code` of `pkexec linvpn-install-update …`.
pub fn outcome(exit_code: i32) -> Outcome {
    match exit_code {
        0 => Outcome::Installed,
        126 | 127 => Outcome::Cancelled,
        code => Outcome::Failed(match StepError::from_code(code) {
            Some(StepError::InstallFailed) => {
                l10n::tr("The update was not installed: apt reported an error (code %lld).", &[Arg::Int(code.into())])
            }
            Some(_) => l10n::tr(
                "The update was not installed: its signature or package did not pass the checks (code %lld).",
                &[Arg::Int(code.into())],
            ),
            None => UpdateError::HelperFailed(format!("pkexec ({code})")).message(),
        }),
    }
}

/// The outcome recorded for the next launch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    Installed { version: String },
    Failed { version: String, code: i32 },
}

/// `ok <version>` / `failed <version> <code>`.
pub fn notice_line(notice: &Notice) -> String {
    match notice {
        Notice::Installed { version } => format!("ok {version}"),
        Notice::Failed { version, code } => format!("failed {version} {code}"),
    }
}

/// [`notice_line`] back (a trailing newline allowed): a plain X.Y.Z version, a code of digits.
pub fn parse_notice(text: &str) -> Option<Notice> {
    if text.len() as u64 > MAX_NOTICE {
        return None;
    }
    let line = text.strip_suffix('\n').unwrap_or(text);
    let parts: Vec<&str> = line.split(' ').collect();
    let valid = |v: &str| deb_update::is_newer(v, None);
    match parts.as_slice() {
        ["ok", version] if valid(version) => Some(Notice::Installed { version: version.to_string() }),
        ["failed", version, code]
            if valid(version) && !code.is_empty() && code.len() <= 9 && code.bytes().all(|b| b.is_ascii_digit()) =>
        {
            Some(Notice::Failed { version: version.to_string(), code: code.parse().ok()? })
        }
        _ => None,
    }
}

// MARK: - Download and verify

/// The verified package and its signature, both in the updates folder (0600), for the root step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Downloaded {
    pub deb: PathBuf,
    pub sig: PathBuf,
    pub sha256: String,
}

fn message(e: UpdateError) -> String {
    e.message()
}

fn http_message(e: HttpError) -> String {
    match e {
        HttpError::Update(u) => u.message(),
        other => other.to_string(),
    }
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// `data` as a new private (0600) file at `path` (a regular file there is replaced; anything else makes it fail).
fn write_new(path: &Path, data: &[u8]) -> std::io::Result<()> {
    remove_if_present(path)?;
    let mut file = fsx::create_new(path, Access::Private)?;
    file.write_all(data)?;
    file.sync_all()
}

/// Copies `from` (the temporary download) into a new private file `to` (a regular file there is replaced), at most
/// [`MAX_DEB`] bytes, and returns the copy's lower-case SHA-256.
fn copy_hashed(from: &Path, to: &Path) -> std::io::Result<String> {
    remove_if_present(to)?;
    let mut source = File::open(from)?.take(MAX_DEB + 1);
    let mut out = fsx::create_new(to, Access::Private)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut total = 0u64;
    loop {
        let n = source.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_DEB {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "the package is too large"));
        }
        hasher.update(&buf[..n]);
        out.write_all(&buf[..n])?;
    }
    out.sync_all()?;
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Downloads the `.sha256`, the `.sig` and the `.deb` of this architecture (`arch`) into `dir` (the private updates
/// folder) and checks them in the one allowed order: canonical github.com URLs only; the `.sha256` names the
/// package; the package copied to `<dir>/<asset>` (0600) and hashed while copied; the hash equals the `.sha256`; the
/// signature verifies under LinVPN's domain with `keys` (production: the embedded keys); the `.sig` is kept as
/// `<dir>/<asset>.sig` (0600) for the root step. Any failure removes both; the error is the localized text.
pub fn download_verified(
    http: &dyn HttpClient,
    release: &Release,
    arch: &str,
    dir: &Path,
    keys: &[[u8; 32]],
) -> Result<Downloaded, String> {
    let assets = assets(release, arch).ok_or_else(no_package_text)?;
    let canonical = |a: &ReleaseAsset| {
        UpdateURLPolicy::canonical_download_url(&a.url).ok_or_else(|| message(UpdateError::UntrustedUrl(a.url.clone())))
    };
    let (deb_url, sum_url, sig_url) = (canonical(assets.deb)?, canonical(assets.sha256)?, canonical(assets.sig)?);
    let name = assets.deb.name.as_str();

    let sum = http.get(&sum_url).map_err(http_message)?;
    if sum.status != 200 {
        return Err(message(UpdateError::Http(sum.status)));
    }
    if sum.data.len() > MAX_CHECKSUM_FILE_SIZE {
        return Err(message(UpdateError::InvalidChecksumFile));
    }
    let text = String::from_utf8(sum.data).map_err(|_| message(UpdateError::InvalidChecksumFile))?;
    let expected = parse_checksum(&text, name).map_err(message)?;
    let signature = download_signature(http, &sig_url)?;

    let (tmp, status) = http.download(&deb_url).map_err(http_message)?;
    let deb = dir.join(name);
    let sig = dir.join(format!("{name}.sig"));
    let copied = (|| {
        if status != 200 {
            return Err(message(UpdateError::Http(status)));
        }
        copy_hashed(&tmp, &deb).map_err(|e| e.to_string())
    })();
    let _ = fs::remove_file(&tmp);
    let verified = copied.and_then(|sha256| {
        if sha256 != expected {
            return Err(message(UpdateError::ChecksumMismatch));
        }
        if !UpdateSignature::verify_for(LINVPN.signature_domain, name, &release.version, &sha256, &signature, keys) {
            return Err(message(UpdateError::UnsignedUpdate));
        }
        write_new(&sig, signature.as_bytes()).map_err(|e| e.to_string())?;
        Ok(Downloaded { deb: deb.clone(), sig: sig.clone(), sha256 })
    });
    if verified.is_err() {
        let _ = fs::remove_file(&deb);
        let _ = fs::remove_file(&sig);
    }
    verified
}

/// The `.sig` (at most 1 KB, UTF-8). 404, too large or not text: not signed.
fn download_signature(http: &dyn HttpClient, url: &str) -> Result<String, String> {
    let response = http.get(url).map_err(http_message)?;
    match response.status {
        200 => {}
        404 => return Err(message(UpdateError::UnsignedUpdate)),
        status => return Err(message(UpdateError::Http(status))),
    }
    if response.data.len() > UpdateSignature::MAX_SIGNATURE_FILE_SIZE {
        return Err(message(UpdateError::UnsignedUpdate));
    }
    String::from_utf8(response.data).map_err(|_| message(UpdateError::UnsignedUpdate))
}

// MARK: - Files of the updates folder

/// `install-<version>.log`: the root step's output (through pkexec).
pub fn log_name(version: &str) -> String {
    format!("install-{version}.log")
}

fn is_log_name(name: &str) -> bool {
    name.strip_prefix("install-")
        .and_then(|r| r.strip_suffix(".log"))
        .is_some_and(|v| !v.is_empty() && v.len() <= 32 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.'))
}

/// A package, its checksum or its signature (`linvpn_*.deb`, `.deb.sha256`, `.deb.sig`).
fn is_package_file(name: &str) -> bool {
    name.starts_with("linvpn_")
        && (name.ends_with(".deb") || name.ends_with(".deb.sha256") || name.ends_with(".deb.sig"))
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

/// The regular files' names in `dir`, sorted.
fn file_names(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else { return Vec::new() };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_regular_file(&dir.join(n)))
        .collect();
    names.sort();
    names
}

/// Before a download: the packages, checksums and signatures of other versions than `asset` (regular files only).
pub fn remove_other_versions(dir: &Path, asset: &str) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    for name in file_names(dir) {
        let current = name == asset || name.strip_prefix(asset).is_some_and(|r| r == ".sha256" || r == ".sig");
        let path = dir.join(&name);
        if is_package_file(&name) && !current && fs::remove_file(&path).is_ok() {
            removed.push(path);
        }
    }
    removed
}

/// Once at launch, in the updates folder `dir`: the previous update's notice (read and removed; a failure not yet
/// `noticed` is returned as `(line, message)`), then the leftovers: every package, checksum and signature, and the
/// root step's logs older than 7 days. Only regular files are touched. Returns what was removed.
pub fn housekeeping(dir: &Path, noticed: Option<&str>, now: SystemTime) -> (Vec<PathBuf>, Option<(String, String)>) {
    let (removed, failure, _) = housekeeping_with_installed(dir, noticed, now);
    (removed, failure)
}

/// [`housekeeping`], and the version of an installed update (`ok <version>`: the relaunched LinVPN says
/// [`updated_text`] once; the notice is removed, so a later launch says nothing).
pub fn housekeeping_with_installed(
    dir: &Path,
    noticed: Option<&str>,
    now: SystemTime,
) -> (Vec<PathBuf>, Option<(String, String)>, Option<String>) {
    let mut removed = Vec::new();
    let mut installed = None;
    let notice_path = dir.join(NOTICE_FILE);
    let mut notice = None;
    if is_regular_file(&notice_path) {
        let line = fs::metadata(&notice_path)
            .ok()
            .filter(|m| m.len() <= MAX_NOTICE)
            .and_then(|_| fs::read_to_string(&notice_path).ok())
            .map(|t| t.strip_suffix('\n').unwrap_or(&t).to_string());
        if fs::remove_file(&notice_path).is_ok() {
            removed.push(notice_path);
        }
        notice = line.filter(|l| noticed != Some(l.as_str())).and_then(|l| match parse_notice(&l)? {
            Notice::Failed { code, .. } => match outcome(code) {
                Outcome::Failed(message) => Some((l, message)),
                _ => None,
            },
            Notice::Installed { version } => {
                installed = Some(version);
                None
            }
        });
    }
    for name in file_names(dir) {
        let path = dir.join(&name);
        let stale_log = is_log_name(&name)
            && fs::metadata(&path)
                .and_then(|m| m.modified())
                .is_ok_and(|t| now.duration_since(t).is_ok_and(|age| age >= LOG_AGE));
        if (is_package_file(&name) || stale_log) && fs::remove_file(&path).is_ok() {
            removed.push(path);
        }
    }
    (removed, notice, installed)
}
