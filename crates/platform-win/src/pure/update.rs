//! The WinVPN updater's portable parts (2b plan, Task 18; decision 1): the release asset of this architecture, the download-and-verify flow, msiexec's parameters, the relauncher's arguments, the outcome notice
//! and the launch housekeeping. `win::updater` runs them with Windows' curl, a deny-write handle, UAC and the
//! relauncher.
//!
//! Verification: the `.sha256` asset is a convenience check; the gate is the maintainer's Ed25519 signature over the
//! SHA-256 computed here, under WinVPN's domain and the asset's name (`winvpn-update-v1\n<asset>\n<version>\n
//! <sha256>\n`, `UpdateSignature::verify_trusted_for(WINVPN.signature_domain, …)`), so neither a MacVPN signature nor
//! one for the other architecture's MSI ever passes. The hash is computed through the handle that holds the file
//! deny-write. That hold lasts until msiexec has exited (security review part 2, P2-L3): before msiexec starts, the
//! relauncher re-opens the MSI deny-write, re-hashes it against the verified SHA-256 ([`Relaunch::sha256`]) and
//! answers [`HELD`]; only then does WinVPN start msiexec, hand the relauncher its PID ([`pid_line`]) and quit once
//! the relauncher answers [`WAITING`]. The relauncher keeps both handles until msiexec has exited.
//!
//! msiexec's verbose log (written by the elevated msiexec, P2-L3): WinVPN creates it itself, new (never a file, link
//! or junction that is already there), in the private updates folder, and the relauncher holds it open (read, no
//! delete sharing) until msiexec has exited, so neither the file nor a folder above it can be renamed, deleted or
//! replaced by a junction: the elevated msiexec writes into exactly the file the user created.

use macvpn_core::l10n::{self, Arg};
use macvpn_core::update::{
    MAX_CHECKSUM_FILE_SIZE, Release, ReleaseAsset, UpdateError, UpdateSignature, UpdateURLPolicy, parse_checksum,
    sha256_hex,
};
use macvpn_platform_api::WINVPN;
use macvpn_platform_api::curl::http::{HttpClient, HttpError};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// `%LOCALAPPDATA%\WinVPN\<UPDATES_DIR>`: the verified MSI, msiexec's logs, the relauncher and the notice.
pub const UPDATES_DIR: &str = "updates";
/// The relauncher's outcome for the next launch.
pub const NOTICE_FILE: &str = "last-update.txt";
/// The copy of `WinVPN.exe` that waits for msiexec (the installer replaces the installed one).
pub const RELAUNCHER: &str = "WinVPN-relaunch.exe";
/// The largest notice file read.
const MAX_NOTICE: usize = 4096;
/// The largest MSI hashed (a real one is about 15 MB).
const MAX_MSI: u64 = 512 << 20;
/// msiexec's logs are kept this long (a failure notice names one).
const LOG_AGE: Duration = Duration::from_secs(7 * 86_400);

/// "This release has no installer for this computer."
pub fn no_installer_text() -> String {
    l10n::tr("This release has no installer for this computer.", &[])
}

/// The three assets of an update for one architecture.
#[derive(Debug, Clone, Copy)]
pub struct Assets<'a> {
    pub msi: &'a ReleaseAsset,
    pub sha256: &'a ReleaseAsset,
    pub sig: &'a ReleaseAsset,
}

/// The release's package if it is WinVPN's MSI for `arch` (`std::env::consts::ARCH`), with its `.sha256` and `.sig`
/// named after it. `None`: nothing this machine can install (another architecture, not signed yet).
pub fn assets<'a>(release: &'a Release, arch: &str) -> Option<Assets<'a>> {
    let name = WINVPN.update_asset(&release.version, arch)?;
    let sig = release.signature.as_ref()?;
    (release.package.name == name
        && release.checksum.name == format!("{name}.sha256")
        && sig.name == format!("{name}.sig"))
    .then_some(Assets { msi: &release.package, sha256: &release.checksum, sig })
}

/// Whether a signature verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verified {
    Yes,
    No,
}

impl From<bool> for Verified {
    fn from(ok: bool) -> Self {
        if ok { Verified::Yes } else { Verified::No }
    }
}

/// The signature of `asset` (`version`, `sha256`) under WinVPN's domain with `keys` (tests: throwaway keys).
pub fn verify(asset: &str, version: &str, sha256: &str, sig: &str, keys: &[[u8; 32]]) -> Verified {
    UpdateSignature::verify_for(WINVPN.signature_domain, asset, version, sha256, sig, keys).into()
}

/// [`verify`] with the embedded maintainer keys (`verify_trusted_for`): what production calls.
pub fn verify_trusted(asset: &str, version: &str, sha256: &str, sig: &str) -> Verified {
    UpdateSignature::verify_trusted_for(WINVPN.signature_domain, asset, version, sha256, sig).into()
}

// MARK: - Download and verify

/// A verified MSI in the updates folder and the handle that holds it (Windows: share mode read only, so nobody
/// writes, renames or deletes it while it is held). Dropping it releases the file.
#[derive(Debug)]
pub struct HeldMsi {
    pub path: PathBuf,
    pub file: File,
    pub sha256: String,
}

/// Opens a file for reading and holding (Windows: `FILE_SHARE_READ` only).
pub type Hold<'a> = &'a dyn Fn(&Path) -> std::io::Result<File>;
/// `(asset, version, sha256, signature)` → verified (production: [`verify_trusted`]).
pub type Verify<'a> = &'a dyn Fn(&str, &str, &str, &str) -> Verified;

fn message(e: impl Into<UpdateError>) -> String {
    e.into().message()
}

fn http_message(e: HttpError) -> String {
    match e {
        HttpError::Update(u) => u.message(),
        other => other.to_string(),
    }
}

/// Downloads the `.sha256`, the `.sig` and the MSI of this architecture (`arch`) into `dir` (the private updates
/// folder) and checks them in the one allowed order: canonical github.com URLs only; the `.sha256` names the
/// package; the MSI moved to `<dir>\<asset>`, opened with `hold`, hashed through that handle; the hash equals the
/// `.sha256`; `verify(asset, version, hash, sig)`. Any failure deletes the package; the error is the localized text.
pub fn download_verified(
    http: &dyn HttpClient,
    release: &Release,
    arch: &str,
    dir: &Path,
    hold: Hold<'_>,
    verify: Verify<'_>,
) -> Result<HeldMsi, String> {
    let assets = assets(release, arch).ok_or_else(no_installer_text)?;
    let canonical = |a: &ReleaseAsset| {
        UpdateURLPolicy::canonical_download_url(&a.url).ok_or_else(|| message(UpdateError::UntrustedUrl(a.url.clone())))
    };
    let (msi_url, sum_url, sig_url) = (canonical(assets.msi)?, canonical(assets.sha256)?, canonical(assets.sig)?);
    let name = assets.msi.name.as_str();

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

    let (tmp, status) = http.download(&msi_url).map_err(http_message)?;
    let dest = dir.join(name);
    let moved = (|| {
        if status != 200 {
            return Err(message(UpdateError::Http(status)));
        }
        remove_if_present(&dest).map_err(|e| e.to_string())?;
        move_file(&tmp, &dest).map_err(|e| e.to_string())
    })();
    let _ = fs::remove_file(&tmp);
    moved?;
    let held = (|| {
        let mut file = hold(&dest).map_err(|e| e.to_string())?;
        let sha256 = hash(&mut file).map_err(|e| e.to_string())?;
        if sha256 != expected {
            return Err(message(UpdateError::ChecksumMismatch));
        }
        // The signature covers the hash computed here, through the handle that holds the file.
        if verify(name, &release.version, &sha256, &signature) != Verified::Yes {
            return Err(message(UpdateError::UnsignedUpdate));
        }
        Ok(HeldMsi { path: dest.clone(), file, sha256 })
    })();
    if held.is_err() {
        let _ = fs::remove_file(&dest);
    }
    held
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

/// The lower-case SHA-256 of what is read from `file` (at most [`MAX_MSI`]), from where it stands (a fresh handle:
/// its start).
pub fn hash(file: &mut File) -> std::io::Result<String> {
    let mut data = Vec::new();
    file.take(MAX_MSI + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MAX_MSI {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "the package is too large"));
    }
    Ok(sha256_hex(&data))
}

fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// A rename, or a copy and a delete across volumes.
fn move_file(from: &Path, to: &Path) -> std::io::Result<()> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    fs::copy(from, to)?;
    fs::remove_file(from)
}

// MARK: - msiexec and the relauncher

/// A drive-absolute Windows path (`C:\…`) without `..`, `.` or empty components, `/`, `"`, `:` after the drive
/// (an alternate data stream) or control characters: never UNC (another machine, and an SMB or WebDAV logon with
/// the caller's token: security review L-3), a device path or a drive-relative one. The text check of
/// `winsys::util::plain_absolute`, on every OS (the elevated steps check their arguments with it before any open).
pub fn is_plain_windows_path(path: &str) -> bool {
    let b = path.as_bytes();
    b.len() > 3
        && b[0].is_ascii_alphabetic()
        && &b[1..3] == b":\\"
        && !path[3..].contains(':')
        && !path.chars().any(|c| c == '/' || c == '"' || c.is_control())
        && path[3..].split('\\').all(|c| !c.is_empty() && c != "." && c != "..")
}

fn file_name(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

/// msiexec's parameters (one string, which msiexec parses itself): install `msi` with the basic UI without a
/// cancel button, no restart, a verbose log. `None` unless both paths are plain absolute paths (no `"`).
pub fn msiexec_parameters(msi: &Path, log: &Path) -> Option<String> {
    let (msi, log) = (msi.to_str()?, log.to_str()?);
    (is_plain_windows_path(msi) && is_plain_windows_path(log))
        .then(|| format!(r#"/i "{msi}" /qb! /norestart /l*v "{log}""#))
}

/// `msiexec-<version>.log` (the version as the release has it, or `test` for the debug hook).
pub fn log_name(version: &str) -> String {
    format!("msiexec-{version}.log")
}

fn is_log_name(name: &str) -> bool {
    name.strip_prefix("msiexec-")
        .and_then(|r| r.strip_suffix(".log"))
        .is_some_and(|v| !v.is_empty() && v.len() <= 32 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.'))
}

/// What the relauncher (`WinVPN-relaunch.exe`, a copy of WinVPN.exe in the updates folder) is started with: the
/// installed `WinVPN.exe` to start afterwards, the verified MSI with its SHA-256, and msiexec's log (both in the
/// relauncher's own folder, checked there).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relaunch {
    pub target: PathBuf,
    pub msi: PathBuf,
    pub sha256: String,
    pub log: PathBuf,
}

/// The relauncher's command line: `--relaunch --target <WinVPN.exe> --msi <msi> --sha256 <hex> --log <log>`.
pub fn relaunch_args(target: &str, msi: &str, sha256: &str, log: &str) -> Vec<String> {
    ["--relaunch", "--target", target, "--msi", msi, "--sha256", sha256, "--log", log].map(str::to_string).to_vec()
}

/// [`relaunch_args`] back, in exactly that shape: a plain absolute target named `WinVPN.exe`, a plain absolute
/// `*.msi`, a lower-case SHA-256, a plain absolute `msiexec-<version>.log`. Anything else: `None` (the app starts
/// normally).
pub fn parse_relaunch(args: &[String]) -> Option<Relaunch> {
    let [flag, t, target, m, msi, h, sha256, l, log] = args else { return None };
    if flag != "--relaunch" || t != "--target" || m != "--msi" || h != "--sha256" || l != "--log" {
        return None;
    }
    let target_ok = is_plain_windows_path(target) && file_name(target).eq_ignore_ascii_case("WinVPN.exe");
    let msi_ok = is_plain_windows_path(msi) && file_name(msi).to_ascii_lowercase().ends_with(".msi");
    let sha_ok = sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let log_ok = is_plain_windows_path(log) && is_log_name(file_name(log));
    (target_ok && msi_ok && sha_ok && log_ok).then(|| Relaunch {
        target: PathBuf::from(target),
        msi: PathBuf::from(msi),
        sha256: sha256.clone(),
        log: PathBuf::from(log),
    })
}

/// The relauncher's first answer on its stdout: it holds the MSI (re-hashed, equal) and the log.
pub const HELD: &str = "held";
/// Its second answer: it has opened msiexec's process (or found it gone) and waits for it.
pub const WAITING: &str = "waiting";

/// What WinVPN writes to the relauncher's stdin once msiexec runs (nothing, then end of input: cancelled).
pub fn pid_line(pid: u32) -> String {
    format!("pid={pid}\n")
}

/// [`pid_line`] back: `pid=` and a PID above 0 without leading zeros, then at most a line end.
pub fn parse_pid_line(line: &str) -> Option<u32> {
    let pid = line.strip_suffix('\n').map_or(line, |l| l.strip_suffix('\r').unwrap_or(l)).strip_prefix("pid=")?;
    if pid.is_empty() || pid.starts_with('0') || !pid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    pid.parse().ok()
}

/// Whether `file` (a Windows path) lies directly in `dir`, compared as Windows does (ASCII case-insensitively).
pub fn in_folder(file: &Path, dir: &Path) -> bool {
    let (Some(file), Some(dir)) = (file.to_str(), dir.to_str()) else { return false };
    match file.rfind('\\') {
        Some(at) => at + 1 < file.len() && file[..at].eq_ignore_ascii_case(dir.trim_end_matches('\\')),
        None => false,
    }
}

/// The update's outcome, written by the relauncher for the next launch: a run ID, msiexec's exit code and its log.
/// Never a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub run: String,
    pub exit_code: u32,
    pub log: String,
}

impl Notice {
    /// 0 (done) and 3010 (done; a restart finishes it).
    pub fn ok(&self) -> bool {
        matches!(self.exit_code, 0 | 3010)
    }

    /// The launch notice of a failure, in the app's language; `None` for a success. msiexec could not open its log
    /// (1622, `ERROR_INSTALL_LOG_FAILURE`) or the package (1619, `ERROR_INSTALL_PACKAGE_OPEN_FAILED`): its own text,
    /// without the log (it is empty then). The elevated msiexec may be another account than the user (a standard
    /// user's UAC prompt asks for an administrator's credentials), which the files must be open to (2.1.1).
    pub fn message(&self) -> Option<String> {
        const PACKAGE_OPEN_FAILED: u32 = 1619;
        const LOG_FAILURE: u32 = 1622;
        let code = self.exit_code.to_string();
        (!self.ok()).then(|| match self.exit_code {
            PACKAGE_OPEN_FAILED | LOG_FAILURE => l10n::tr(
                "The update failed: Windows Installer could not open the update's package or its log (msiexec %@). Check for updates again, or install WinVPN from its release page.",
                &[Arg::Str(&code)],
            ),
            _ => l10n::tr("The update failed (msiexec %@). Details: %@", &[Arg::Str(&code), Arg::Str(&self.log)]),
        })
    }

    pub fn encode(&self) -> String {
        format!("run={}\nexit={}\nlog={}\n", self.run, self.exit_code, self.log)
    }

    /// Exactly three lines `run=`, `exit=`, `log=`, at most 4 KiB.
    pub fn parse(text: &str) -> Option<Notice> {
        if text.len() > MAX_NOTICE {
            return None;
        }
        let mut lines = text.strip_suffix('\n')?.split('\n');
        let run = lines.next()?.strip_prefix("run=")?;
        let exit = lines.next()?.strip_prefix("exit=")?;
        let log = lines.next()?.strip_prefix("log=")?;
        if lines.next().is_some() || run.is_empty() || exit.is_empty() || !exit.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Notice { run: run.to_string(), exit_code: exit.parse().ok()?, log: log.to_string() })
    }
}

// MARK: - Launch housekeeping

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

/// Once at launch, in the updates folder `dir`: the previous update's notice (read and deleted; a failure not yet
/// `noticed` is returned as `(run, message)`), then the leftovers: every `*.msi`, the relauncher copies, msiexec's
/// logs older than 7 days. Only regular files are touched. Returns what was removed.
pub fn housekeeping(dir: &Path, noticed: Option<&str>, now: SystemTime) -> (Vec<PathBuf>, Option<(String, String)>) {
    let mut removed = Vec::new();
    let notice_path = dir.join(NOTICE_FILE);
    let mut notice = None;
    if is_regular_file(&notice_path) {
        let read = fs::metadata(&notice_path)
            .ok()
            .filter(|m| m.len() <= MAX_NOTICE as u64)
            .and_then(|_| fs::read_to_string(&notice_path).ok())
            .and_then(|t| Notice::parse(&t));
        if fs::remove_file(&notice_path).is_ok() {
            removed.push(notice_path);
        }
        notice =
            read.filter(|n| noticed != Some(n.run.as_str())).and_then(|n| n.message().map(|message| (n.run, message)));
    }
    let Ok(entries) = fs::read_dir(dir) else { return (removed, notice) };
    let mut names: Vec<String> = entries.flatten().filter_map(|e| e.file_name().into_string().ok()).collect();
    names.sort();
    for name in names {
        let path = dir.join(&name);
        if !is_regular_file(&path) {
            continue;
        }
        let lower = name.to_ascii_lowercase();
        let stale_log = is_log_name(&name)
            && fs::metadata(&path)
                .and_then(|m| m.modified())
                .is_ok_and(|t| now.duration_since(t).is_ok_and(|age| age >= LOG_AGE));
        let leftover =
            lower.ends_with(".msi") || (lower.starts_with("winvpn-relaunch") && lower.ends_with(".exe")) || stale_log;
        if leftover && fs::remove_file(&path).is_ok() {
            removed.push(path);
        }
    }
    (removed, notice)
}
