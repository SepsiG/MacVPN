//! Downloading, verifying, mounting and installing an update (port of `UpdateInstaller.swift` and the launch
//! housekeeping of the app's `UpdateController.swift`).
//!
//! Flow: DMG + `.sha256` + `.sig` into the cache → SHA-256 → the maintainer's offline Ed25519 signature over the
//! locally computed hash → re-hash, `hdiutil attach -readonly`, the image path confirmed with `hdiutil info` →
//! the attached app's bundle ID, version, symlinks and `codesign --verify --strict` → a helper script in a fresh
//! 0700 directory. The script waits for the app to quit, copies with `ditto` next to the target, swaps with
//! renames (TERM/INT ignored in between), removes the quarantine, detaches the DMG, relaunches the app and deletes
//! itself. No privilege escalation: an unwritable location is an error.

use crate::brew::shell_quote;
use crate::command::CommandRunner;
use crate::http::{HttpClient, HttpError};
use crate::temp_dir::{MessageError, make_private_temp_directory, standardize, temporary_directory, write_script};
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::uuid_string;
use macvpn_core::swift_str;
use macvpn_core::update::{
    HelperOutcome, MAX_CHECKSUM_FILE_SIZE, Release, UpdateError, UpdateSignature, UpdateURLPolicy, last_helper_outcome,
    parse_checksum, sha256_of_file,
};
use regex::Regex;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::LazyLock;

pub const BUNDLE_IDENTIFIER: &str = "local.macvpn";
pub const APP_NAME: &str = "MacVPN.app";
/// `update.log` in the cache directory: the helper script's log.
pub const HELPER_LOG_NAME: &str = "update.log";

/// A verified download: the DMG in its own 0700 directory, and its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDownload {
    pub dmg: PathBuf,
    pub directory: PathBuf,
    pub sha256: String,
}

/// Any failure of the update steps; its message is what the UI shows.
#[derive(Debug)]
pub enum InstallerError {
    Update(UpdateError),
    Http(HttpError),
    Message(String),
}

impl std::fmt::Display for InstallerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallerError::Update(e) => e.fmt(f),
            InstallerError::Http(e) => e.fmt(f),
            InstallerError::Message(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for InstallerError {}

impl InstallerError {
    /// The [`UpdateError`], if it is one (tests and the UI's branching).
    pub fn update_error(&self) -> Option<&UpdateError> {
        match self {
            InstallerError::Update(e) | InstallerError::Http(HttpError::Update(e)) => Some(e),
            _ => None,
        }
    }
}

impl From<UpdateError> for InstallerError {
    fn from(e: UpdateError) -> Self {
        InstallerError::Update(e)
    }
}

impl From<HttpError> for InstallerError {
    fn from(e: HttpError) -> Self {
        match e {
            HttpError::Update(u) => InstallerError::Update(u),
            other => InstallerError::Http(other),
        }
    }
}

impl From<MessageError> for InstallerError {
    fn from(e: MessageError) -> Self {
        InstallerError::Message(e.0)
    }
}

impl From<std::io::Error> for InstallerError {
    fn from(e: std::io::Error) -> Self {
        InstallerError::Message(e.to_string())
    }
}

pub struct UpdateInstaller<'a> {
    http: &'a dyn HttpClient,
    runner: &'a dyn CommandRunner,
    pub cache_directory: PathBuf,
    /// The keys accepted for the `.sig` (raw 32 bytes). In production the embedded primary and backup keys; in
    /// tests a throwaway key.
    public_keys: Vec<[u8; 32]>,
}

static DMG_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^MacVPN-[0-9A-Za-z.]+\.dmg$").expect("valid regex"));

impl<'a> UpdateInstaller<'a> {
    /// `~/Library/Caches/MacVPN`.
    pub fn default_cache_directory(home: &Path) -> PathBuf {
        home.join("Library/Caches/MacVPN")
    }

    /// The production installer: the embedded maintainer keys.
    pub fn new(http: &'a dyn HttpClient, runner: &'a dyn CommandRunner, cache_directory: PathBuf) -> Self {
        Self::with_keys(http, runner, cache_directory, UpdateSignature::trusted_keys())
    }

    pub fn with_keys(
        http: &'a dyn HttpClient,
        runner: &'a dyn CommandRunner,
        cache_directory: PathBuf,
        public_keys: Vec<[u8; 32]>,
    ) -> Self {
        UpdateInstaller { http, runner, cache_directory, public_keys }
    }

    // MARK: Download + verification

    /// Downloads the DMG into a fresh 0700 (mkdtemp) directory under the cache, checks the SHA-256, then the
    /// maintainer's Ed25519 signature over the locally computed hash. On any error the directory is deleted; a
    /// hash mismatch is `ChecksumMismatch`, a missing or invalid signature `UnsignedUpdate`.
    pub fn download_verified(&self, release: &Release) -> Result<VerifiedDownload, InstallerError> {
        // Every URL handed on is the canonical `https://github.com<path>` form (never the release's raw string).
        let canonical = |url: &str| {
            UpdateURLPolicy::canonical_download_url(url).ok_or_else(|| UpdateError::UntrustedUrl(url.to_string()))
        };
        let dmg_url = canonical(&release.dmg.url)?;
        let checksum_url = canonical(&release.checksum.url)?;
        let Some(signature_asset) = &release.signature else { return Err(UpdateError::UnsignedUpdate.into()) };
        let signature_url = canonical(&signature_asset.url)?;
        // The name comes from the release, but only the expected form is accepted (no path components).
        if !DMG_NAME.is_match(&release.dmg.name) {
            return Err(UpdateError::MissingAsset(release.dmg.name.clone()).into());
        }
        let sum = self.http.get(&checksum_url)?;
        if sum.status != 200 {
            return Err(UpdateError::Http(sum.status).into());
        }
        if sum.data.len() > MAX_CHECKSUM_FILE_SIZE {
            return Err(UpdateError::InvalidChecksumFile.into());
        }
        let text = String::from_utf8(sum.data).map_err(|_| UpdateError::InvalidChecksumFile)?;
        let expected = parse_checksum(&text, &release.dmg.name)?;
        let signature = self.download_signature(&signature_url)?;

        self.prepare_cache_directory()?;
        let directory = make_private_temp_directory("download", &self.cache_directory)?;
        let result = (|| -> Result<VerifiedDownload, InstallerError> {
            let (tmp, status) = self.http.download(&dmg_url)?;
            let moved = (|| -> Result<PathBuf, InstallerError> {
                if status != 200 {
                    return Err(UpdateError::Http(status).into());
                }
                let dest = directory.join(&release.dmg.name);
                move_item(&tmp, &dest)?;
                Ok(dest)
            })();
            let _ = fs::remove_file(&tmp);
            let dest = moved?;
            let actual = sha256_of_file(&dest)?;
            if actual != expected {
                return Err(UpdateError::ChecksumMismatch.into());
            }
            // The signature covers the locally computed hash: the `.sha256` asset is only a convenience check.
            if !UpdateSignature::verify(&release.version, &actual, &signature, &self.public_keys) {
                return Err(UpdateError::UnsignedUpdate.into());
            }
            Ok(VerifiedDownload { dmg: dest, directory: directory.clone(), sha256: actual })
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&directory);
        }
        result
    }

    /// The `.sig` (at most 1 KB, UTF-8). 404 (or too large / not text): `UnsignedUpdate`.
    fn download_signature(&self, url: &str) -> Result<String, InstallerError> {
        let response = self.http.get(url)?;
        if response.status == 404 {
            return Err(UpdateError::UnsignedUpdate.into());
        }
        if response.status != 200 {
            return Err(UpdateError::Http(response.status).into());
        }
        if response.data.len() > UpdateSignature::MAX_SIGNATURE_FILE_SIZE {
            return Err(UpdateError::UnsignedUpdate.into());
        }
        String::from_utf8(response.data).map_err(|_| UpdateError::UnsignedUpdate.into())
    }

    fn prepare_cache_directory(&self) -> Result<(), InstallerError> {
        let not_writable =
            || InstallerError::from(UpdateError::NotWritable(self.cache_directory.to_string_lossy().into_owned()));
        fs::DirBuilder::new().recursive(true).mode(0o700).create(&self.cache_directory).map_err(|_| not_writable())?;
        match fs::symlink_metadata(&self.cache_directory) {
            Ok(m) if m.file_type().is_dir() => {}
            _ => return Err(not_writable()),
        }
        let _ = fs::set_permissions(&self.cache_directory, fs::Permissions::from_mode(0o700));
        Ok(())
    }

    // MARK: Mounting

    /// The first mount point (under `/Volumes`) of `hdiutil attach -plist`'s output.
    pub fn parse_mount_point(plist: &[u8]) -> Result<String, UpdateError> {
        let unexpected = || UpdateError::MountFailed(l10n::tr("unexpected hdiutil output", &[]));
        let root = plist::Value::from_reader(std::io::Cursor::new(plist)).map_err(|_| unexpected())?;
        let entities = root
            .as_dictionary()
            .and_then(|d| d.get("system-entities"))
            .and_then(plist::Value::as_array)
            .ok_or_else(unexpected)?;
        // Swift `as? [[String: Any]]`: every element must be a dictionary.
        if entities.iter().any(|e| e.as_dictionary().is_none()) {
            return Err(unexpected());
        }
        for e in entities {
            if let Some(mp) = e.as_dictionary().and_then(|d| d.get("mount-point")).and_then(plist::Value::as_string)
                && mp.starts_with("/Volumes/")
                && !mp.contains("/../")
            {
                return Ok(mp.to_string());
            }
        }
        Err(UpdateError::MountFailed(l10n::tr("no mount point", &[])))
    }

    /// `hdiutil info -plist`: which disk image is attached at the mount point.
    pub fn image_path(mount_point: &str, info_plist: &[u8]) -> Option<String> {
        let root = plist::Value::from_reader(std::io::Cursor::new(info_plist)).ok()?;
        let images = root.as_dictionary()?.get("images")?.as_array()?;
        if images.iter().any(|i| i.as_dictionary().is_none()) {
            return None;
        }
        for image in images {
            let image = image.as_dictionary()?;
            let entities = image.get("system-entities").and_then(plist::Value::as_array);
            let entities: Vec<&plist::Dictionary> = match entities {
                Some(list) if list.iter().all(|e| e.as_dictionary().is_some()) => {
                    list.iter().filter_map(plist::Value::as_dictionary).collect()
                }
                _ => Vec::new(),
            };
            if entities.iter().any(|e| e.get("mount-point").and_then(plist::Value::as_string) == Some(mount_point)) {
                return image.get("image-path").and_then(plist::Value::as_string).map(str::to_string);
            }
        }
        None
    }

    /// Re-hashes right before attaching (TOCTOU), attaches, then checks that the attached image is the hashed file.
    pub fn mount(&self, download: &VerifiedDownload) -> Result<String, InstallerError> {
        if sha256_of_file(&download.dmg)? != download.sha256 {
            return Err(UpdateError::ChecksumMismatch.into());
        }
        let args: Vec<String> = ["attach", "-nobrowse", "-readonly", "-noautoopen", "-plist"]
            .iter()
            .map(|s| s.to_string())
            .chain([download.dmg.to_string_lossy().into_owned()])
            .collect();
        let result =
            self.runner.run("/usr/bin/hdiutil", &args, None).map_err(|e| InstallerError::Message(e.to_string()))?;
        if result.exit_code != 0 {
            return Err(UpdateError::MountFailed(
                result.stderr.trim_matches(swift_str::is_foundation_whitespace_or_newline).to_string(),
            )
            .into());
        }
        let mount_point = Self::parse_mount_point(Self::xml_part(&result.stdout).as_bytes())?;
        let info = self.runner.run("/usr/bin/hdiutil", &["info".to_string(), "-plist".to_string()], None).ok();
        let image = info.and_then(|i| Self::image_path(&mount_point, Self::xml_part(&i.stdout).as_bytes()));
        match image {
            Some(image) if Self::same_path(&image, &download.dmg.to_string_lossy()) => Ok(mount_point),
            _ => {
                self.detach(&mount_point);
                Err(UpdateError::MountFailed(l10n::tr(
                    "the mounted disk image is not the downloaded and verified file",
                    &[],
                ))
                .into())
            }
        }
    }

    /// hdiutil may print other lines before the plist; reading starts at `<?xml`.
    pub fn xml_part(out: &str) -> &str {
        out.find("<?xml").map_or(out, |i| &out[i..])
    }

    /// Both paths with symlinks resolved and standardized.
    pub fn same_path(a: &str, b: &str) -> bool {
        resolve_symlinks(Path::new(a)) == resolve_symlinks(Path::new(b))
    }

    pub fn detach(&self, mount_point: &str) {
        let _ = self.runner.run(
            "/usr/bin/hdiutil",
            &["detach".to_string(), mount_point.to_string(), "-quiet".to_string()],
            None,
        );
    }

    /// The attached app's full check: [`Self::verify_bundle`], then `codesign --verify --strict`. The app is
    /// ad-hoc signed, so this checks integrity (the sealed resources), not the publisher.
    pub fn verify_app(&self, app: &Path, expected_version: &str) -> Result<(), InstallerError> {
        Self::verify_bundle(app, expected_version)?;
        let args = vec!["--verify".to_string(), "--strict".to_string(), app.to_string_lossy().into_owned()];
        let result =
            self.runner.run("/usr/bin/codesign", &args, None).map_err(|e| InstallerError::Message(e.to_string()))?;
        if result.exit_code != 0 {
            let msg = result.stderr.trim_matches(swift_str::is_foundation_whitespace_or_newline);
            return Err(UpdateError::InvalidApp(l10n::tr("signature verification failed: %@", &[Arg::Str(msg)])).into());
        }
        Ok(())
    }

    /// A real directory (not a symlink), the bundle ID, the version, and no symlink under `Contents` pointing
    /// outside the bundle.
    pub fn verify_bundle(app: &Path, expected_version: &str) -> Result<(), UpdateError> {
        match fs::symlink_metadata(app) {
            Ok(m) if m.file_type().is_dir() => {}
            _ => return Err(UpdateError::InvalidApp(l10n::tr("%@ not found", &[Arg::Str(APP_NAME)]))),
        }
        // `Contents` must be a real directory and `Info.plist` a regular file (never followed through a symlink).
        let contents_ok = fs::symlink_metadata(app.join("Contents")).is_ok_and(|m| m.file_type().is_dir());
        let plist_ok = fs::symlink_metadata(app.join("Contents/Info.plist")).is_ok_and(|m| m.file_type().is_file());
        if !contents_ok || !plist_ok {
            return Err(UpdateError::InvalidApp(l10n::tr("cannot read Info.plist", &[])));
        }
        let info = fs::read(app.join("Contents/Info.plist"))
            .ok()
            .and_then(|d| plist::Value::from_reader(std::io::Cursor::new(d)).ok())
            .and_then(plist::Value::into_dictionary)
            .ok_or_else(|| UpdateError::InvalidApp(l10n::tr("cannot read Info.plist", &[])))?;
        let bundle_id = info.get("CFBundleIdentifier").and_then(plist::Value::as_string);
        if bundle_id != Some(BUNDLE_IDENTIFIER) {
            return Err(UpdateError::InvalidApp(l10n::tr(
                "bundle identifier %@, expected: %@",
                &[Arg::Str(bundle_id.unwrap_or("-")), Arg::Str(BUNDLE_IDENTIFIER)],
            )));
        }
        let version = info.get("CFBundleShortVersionString").and_then(plist::Value::as_string);
        if version != Some(expected_version) {
            return Err(UpdateError::InvalidApp(l10n::tr(
                "version %@, expected: %@",
                &[Arg::Str(version.unwrap_or("-")), Arg::Str(expected_version)],
            )));
        }
        Self::check_symlinks(app)
    }

    pub fn check_symlinks(app: &Path) -> Result<(), UpdateError> {
        let bundle = resolve_symlinks(app);
        let mut stack = vec![app.join("Contents")];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                let Ok(meta) = fs::symlink_metadata(&path) else { continue };
                if meta.file_type().is_symlink() {
                    let target = resolve_symlinks(&path);
                    if !target.starts_with(&bundle) || target == bundle {
                        return Err(UpdateError::InvalidApp(l10n::tr(
                            "link pointing outside the bundle: %@",
                            &[Arg::Str(&path.to_string_lossy())],
                        )));
                    }
                } else if meta.is_dir() {
                    stack.push(path);
                }
            }
        }
        Ok(())
    }

    // MARK: Install target

    /// The running app's location (e.g. `/Applications/MacVPN.app`, but it can be anywhere). Unwritable: error.
    pub fn check_install_target(bundle: &Path) -> Result<PathBuf, UpdateError> {
        let target = resolve_symlinks(bundle);
        let not_writable = || UpdateError::NotWritable(target.to_string_lossy().into_owned());
        if target.extension().is_none_or(|e| e != "app") {
            return Err(not_writable());
        }
        let parent = target.parent().unwrap_or(Path::new("/"));
        if !crate::sys::is_writable(parent)
            || !crate::sys::is_writable(&target)
            || target.to_string_lossy().contains("/AppTranslocation/")
        {
            return Err(not_writable());
        }
        Ok(target)
    }

    // MARK: Helper script

    /// The bash script doing the swap. Every path single-quoted and escaped.
    #[allow(clippy::too_many_arguments)]
    pub fn helper_script(
        pid: i32,
        source_app: &str,
        target_app: &str,
        mount_point: &str,
        script_directory: &str,
        download_directory: &str,
        log_file: &str,
        token: &str,
    ) -> String {
        let target = Path::new(target_app);
        let parent = target.parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let base = target.file_name().map(|b| b.to_string_lossy().into_owned()).unwrap_or_default();
        let staged = format!("{}/.{base}.update-{token}", parent.trim_end_matches('/'));
        let old = format!("{}/.{base}.old-{token}", parent.trim_end_matches('/'));
        let q = shell_quote;
        format!(
            r#"#!/bin/bash
# MacVPN update helper (generated by the app). Waits for the app to quit, replaces it, relaunches it.
# Its log (update.log) is a diagnostic file and stays English.
set -u
trap '' HUP
export PATH='/usr/bin:/bin:/usr/sbin:/sbin'
APP_PID={pid}
SRC={src}
DEST={dest}
STAGED={staged}
OLD={old}
MOUNT={mount}
SELF_DIR={self_dir}
DOWNLOAD_DIR={download_dir}
LOG={log}
exec >>"$LOG" 2>&1
echo "=== $(date '+%Y-%m-%d %H:%M:%S') update: $SRC -> $DEST ==="

finish() {{
  /usr/bin/hdiutil detach "$MOUNT" -quiet || /usr/bin/hdiutil detach "$MOUNT" -force -quiet || true
  /bin/rm -rf "$DOWNLOAD_DIR"
  /bin/rm -rf "$SELF_DIR"
}}

# A régi app visszaállítása (ha a cél szabad). Sikertelenség naplózva; ilyenkor nem indítunk semmit.
restore() {{
  if [ -e "$OLD" ]; then
    if [ ! -e "$DEST" ] && /bin/mv "$OLD" "$DEST"; then
      echo "old app restored"
    else
      echo "restore failed: the old app was left here: $OLD"
      return 1
    fi
  fi
  return 0
}}

# Az app kilépésére várunk (legfeljebb 30 mp).
waited=0
while /bin/kill -0 "$APP_PID" 2>/dev/null; do
  if [ "$waited" -ge 60 ]; then
    echo "the app did not quit within 30 s, update cancelled"
    finish
    exit 1
  fi
  /bin/sleep 0.5
  waited=$((waited + 1))
done

/bin/rm -rf "$STAGED"
if ! /usr/bin/ditto "$SRC" "$STAGED"; then
  echo "copy (ditto) failed"
  /bin/rm -rf "$STAGED"
  finish
  /usr/bin/open "$DEST"
  exit 1
fi
# Csere: a két átnevezés között a cél hiányzik. Kijelentkezéskor (SIGTERM) vagy Ctrl-C-re (SIGINT) ne
# haljunk meg itt, különben az app eltűnne; a szakasz rövid (két mv), utána a jelzések visszaállnak.
trap '' TERM INT
if [ -e "$DEST" ] && ! /bin/mv "$DEST" "$OLD"; then
  trap - TERM INT
  echo "cannot rename the old app"
  /bin/rm -rf "$STAGED"
  finish
  /usr/bin/open "$DEST"
  exit 1
fi
if [ -e "$DEST" ]; then
  echo "the target still exists after the rename, update cancelled"
  /bin/rm -rf "$STAGED"
  restore
  trap - TERM INT
  finish
  exit 1
fi
if ! /bin/mv "$STAGED" "$DEST"; then
  echo "cannot move the new app into place, restoring"
  /bin/rm -rf "$STAGED"
  restore && /usr/bin/open "$DEST"
  trap - TERM INT
  finish
  exit 1
fi
trap - TERM INT
/bin/rm -rf "$OLD"
/usr/bin/xattr -dr com.apple.quarantine "$DEST" || true
# A végeredmény a megnyitás előtt kerül a naplóba: az új app induláskor ezt olvassa.
echo "done"
finish
/usr/bin/open "$DEST"
"#,
            src = q(source_app),
            dest = q(target_app),
            staged = q(&staged),
            old = q(&old),
            mount = q(mount_point),
            self_dir = q(script_directory),
            download_dir = q(download_directory),
            log = q(log_file),
        )
    }

    /// A fresh token for the helper's staged / old names (an upper-case UUID, as Swift's default).
    pub fn new_token() -> String {
        uuid_string(&uuid::Uuid::new_v4())
    }

    // MARK: Launch housekeeping

    /// Deletes the `.<App>.update-<token>` and `.<App>.old-<token>` leftovers next to the running bundle (after an
    /// interrupted swap). Does nothing if the bundle itself does not exist. Returns the removed items.
    pub fn sweep_leftovers(bundle: &Path) -> Vec<PathBuf> {
        let bundle = standardize(bundle);
        if fs::symlink_metadata(&bundle).is_err() {
            return Vec::new();
        }
        let (Some(parent), Some(base)) = (bundle.parent(), bundle.file_name()) else { return Vec::new() };
        let Ok(pattern) =
            Regex::new(&format!(r"^\.{}\.(update|old)-[A-Za-z0-9-]+$", regex::escape(&base.to_string_lossy())))
        else {
            return Vec::new();
        };
        let Ok(entries) = fs::read_dir(parent) else { return Vec::new() };
        let mut names: Vec<String> = entries.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        let mut removed = Vec::new();
        for name in names {
            if !pattern.is_match(&name) {
                continue;
            }
            let path = parent.join(&name);
            let ok = match fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => fs::remove_dir_all(&path).is_ok(),
                Ok(_) => fs::remove_file(&path).is_ok(),
                Err(_) => false,
            };
            if ok {
                removed.push(path);
            }
        }
        removed
    }

    /// The last run of the helper's log: its header line and outcome (`None` without a run).
    pub fn last_helper_outcome(log: &str) -> Option<(String, HelperOutcome)> {
        last_helper_outcome(log)
    }

    /// A fresh 0700 directory with the script in it (O_EXCL, O_NOFOLLOW, 0700). The script deletes the directory.
    pub fn write_helper(make_script: impl FnOnce(&Path) -> String) -> Result<PathBuf, InstallerError> {
        let dir = make_private_temp_directory("macvpn-update", &temporary_directory()?)?;
        match write_script(&make_script(&dir), &dir, "update.sh") {
            Ok(path) => Ok(path),
            Err(e) => {
                let _ = fs::remove_dir_all(&dir);
                Err(e.into())
            }
        }
    }

    /// Double fork: the outer bash puts the script in the background under `nohup`, `disown`s it and exits at
    /// once. The script path is a separate argument (`$1`), never part of the command text.
    pub fn helper_launch_arguments(script: &Path) -> Vec<String> {
        vec![
            "-c".into(),
            "/usr/bin/nohup /bin/bash \"$1\" >/dev/null 2>&1 </dev/null & disown".into(),
            "macvpn-update".into(),
            script.to_string_lossy().into_owned(),
        ]
    }

    /// The helper's whole environment (nothing of the app's: no `BASH_ENV`, `DYLD_*` etc.).
    pub fn helper_environment() -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), "/usr/bin:/bin:/usr/sbin:/sbin".to_string());
        if let Some(home) = crate::system::home_directory() {
            env.insert("HOME".to_string(), home.to_string_lossy().into_owned());
        }
        env.insert("LANG".to_string(), "C".to_string());
        env
    }

    /// Starts the script detached (it keeps running after the app quits and is not the app's child).
    pub fn launch_helper(script: &Path) -> Result<(), UpdateError> {
        let mut command = Command::new("/bin/bash");
        crate::sys::close_inherited_fds(&mut command);
        let status = command
            .env_clear()
            .envs(Self::helper_environment())
            .args(Self::helper_launch_arguments(script))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| UpdateError::HelperFailed(e.to_string()))?;
        match status.code() {
            Some(0) => Ok(()),
            code => {
                Err(UpdateError::HelperFailed(l10n::tr("exit code: %d", &[Arg::Int(i64::from(code.unwrap_or(-1)))])))
            }
        }
    }
}

/// The previous update's result for the launch alert (the app's `previousUpdateNotice`): read from the helper's
/// log, only within 14 days, under 1 MB, and only once per run (`noticed_run` is the remembered header; the
/// caller stores the returned run as the new one).
pub fn previous_update_notice(
    log_path: &Path,
    home: &Path,
    noticed_run: Option<&str>,
    now: std::time::SystemTime,
) -> Option<(String, String)> {
    let meta = fs::metadata(log_path).ok()?;
    let modified = meta.modified().ok()?;
    // Swift `Date().timeIntervalSince(modified) < 14 days` (a future time passes too).
    if now.duration_since(modified).is_ok_and(|age| age.as_secs_f64() >= 14.0 * 24.0 * 3600.0) {
        return None;
    }
    if meta.len() >= 1 << 20 {
        return None;
    }
    let text = String::from_utf8(fs::read(log_path).ok()?).ok()?;
    let (run, outcome) = last_helper_outcome(&text)?;
    if noticed_run == Some(run.as_str()) {
        return None;
    }
    let path = log_path.to_string_lossy().replace(&*home.to_string_lossy(), "~");
    match outcome {
        HelperOutcome::Succeeded | HelperOutcome::Unknown => None,
        HelperOutcome::TimedOut => Some((
            run,
            l10n::tr(
                "The update was cancelled because MacVPN did not quit within 30 seconds. The installed version was not changed; you can try again from the menu.",
                &[],
            ),
        )),
        HelperOutcome::Failed(line) => Some((
            run,
            l10n::tr(
                "The update stopped with an error (%@). The installed version was kept. Details: %@",
                &[Arg::Str(&line), Arg::Str(&path)],
            ),
        )),
    }
}

/// What the app does once at launch (from a real bundle): sweep the leftovers next to the running bundle, then
/// the previous update's notice, if any.
pub fn launch_housekeeping(
    bundle: &Path,
    cache_directory: &Path,
    home: &Path,
    noticed_run: Option<&str>,
) -> (Vec<PathBuf>, Option<(String, String)>) {
    let removed = UpdateInstaller::sweep_leftovers(&resolve_symlinks(bundle));
    let notice =
        previous_update_notice(&cache_directory.join(HELPER_LOG_NAME), home, noticed_run, std::time::SystemTime::now());
    (removed, notice)
}

/// `URL.resolvingSymlinksInPath().standardizedFileURL.path`: the real path if it exists; otherwise the existing
/// prefix resolved and the rest appended (a dangling link's target is followed lexically).
pub fn resolve_symlinks(path: &Path) -> PathBuf {
    let path = standardize(path);
    if let Ok(real) = fs::canonicalize(&path) {
        return real;
    }
    // A dangling symlink: resolve its target relative to its (resolved) parent.
    if let Ok(target) = fs::read_link(&path) {
        let parent = path.parent().map(resolve_symlinks).unwrap_or_else(|| PathBuf::from("/"));
        return standardize(&parent.join(target));
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) if parent != path => resolve_symlinks(parent).join(name),
        _ => path,
    }
}

/// `FileManager.moveItem`: rename, or copy + delete across volumes.
fn move_item(from: &Path, to: &Path) -> std::io::Result<()> {
    if fs::symlink_metadata(to).is_ok() {
        return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
    }
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            fs::copy(from, to)?;
            fs::remove_file(from)
        }
        Err(e) => Err(e),
    }
}

// MARK: - The whole update, in the one allowed order

/// The steps of an update, behind a trait so the order can be tested with mocks. [`UpdateInstaller`] is the
/// real implementation.
pub trait UpdateSteps {
    fn check_install_target(&self, bundle: &Path) -> Result<PathBuf, InstallerError>;
    fn download_verified(&self, release: &Release) -> Result<VerifiedDownload, InstallerError>;
    fn mount(&self, download: &VerifiedDownload) -> Result<String, InstallerError>;
    fn verify_app(&self, app: &Path, expected_version: &str) -> Result<(), InstallerError>;
    fn write_helper(&self, make_script: &dyn Fn(&Path) -> String) -> Result<PathBuf, InstallerError>;
    fn launch_helper(&self, script: &Path) -> Result<(), InstallerError>;
    fn detach(&self, mount_point: &str);
    fn cache_directory(&self) -> PathBuf;
}

impl UpdateSteps for UpdateInstaller<'_> {
    fn check_install_target(&self, bundle: &Path) -> Result<PathBuf, InstallerError> {
        Ok(UpdateInstaller::check_install_target(bundle)?)
    }

    fn download_verified(&self, release: &Release) -> Result<VerifiedDownload, InstallerError> {
        UpdateInstaller::download_verified(self, release)
    }

    fn mount(&self, download: &VerifiedDownload) -> Result<String, InstallerError> {
        UpdateInstaller::mount(self, download)
    }

    fn verify_app(&self, app: &Path, expected_version: &str) -> Result<(), InstallerError> {
        UpdateInstaller::verify_app(self, app, expected_version)
    }

    fn write_helper(&self, make_script: &dyn Fn(&Path) -> String) -> Result<PathBuf, InstallerError> {
        UpdateInstaller::write_helper(make_script)
    }

    fn launch_helper(&self, script: &Path) -> Result<(), InstallerError> {
        Ok(UpdateInstaller::launch_helper(script)?)
    }

    fn detach(&self, mount_point: &str) {
        UpdateInstaller::detach(self, mount_point)
    }

    fn cache_directory(&self) -> PathBuf {
        self.cache_directory.clone()
    }
}

/// The step being run, for the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateStage {
    CheckingLocation,
    Downloading,
    Mounting,
    VerifyingApp,
    Preparing,
    Quitting,
}

impl UpdateStage {
    pub fn message(self) -> String {
        let key = match self {
            UpdateStage::CheckingLocation => "Checking the install location…",
            UpdateStage::Downloading => "Downloading…",
            UpdateStage::Mounting => "Mounting the disk image…",
            UpdateStage::VerifyingApp => "Verifying the app…",
            UpdateStage::Preparing => "Preparing the installation…",
            UpdateStage::Quitting => "Quitting and restarting…",
        };
        l10n::tr(key, &[])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// The helper runs and waits for this process: the app must quit now.
    HelperLaunched,
    /// The user declined to quit; everything was cleaned up.
    Cancelled,
}

/// The whole update (the app's `UpdateController.install`), in the only allowed order:
/// `check_install_target` → `download_verified` → `mount` → `verify_app` → `write_helper` → (`confirm_quit`) →
/// `launch_helper`. On any error, or when `confirm_quit` says no, the helper directory, the mount and the download
/// are cleaned up. `pid` is this app's process (the helper waits for it to exit).
pub fn install_update(
    steps: &dyn UpdateSteps,
    release: &Release,
    bundle: &Path,
    pid: i32,
    mut stage: impl FnMut(UpdateStage),
    confirm_quit: impl FnOnce() -> bool,
) -> Result<UpdateOutcome, InstallerError> {
    let mut mount_point: Option<String> = None;
    let mut helper_dir: Option<PathBuf> = None;
    let mut download: Option<VerifiedDownload> = None;
    let cleanup = |mount_point: &Option<String>, helper_dir: &Option<PathBuf>, download: &Option<VerifiedDownload>| {
        if let Some(dir) = helper_dir {
            let _ = fs::remove_dir_all(dir);
        }
        if let Some(mp) = mount_point {
            steps.detach(mp);
        }
        if let Some(d) = download {
            let _ = fs::remove_dir_all(&d.directory);
        }
    };
    let result = (|| -> Result<UpdateOutcome, InstallerError> {
        stage(UpdateStage::CheckingLocation);
        let target = steps.check_install_target(bundle)?;
        stage(UpdateStage::Downloading);
        let verified = steps.download_verified(release)?;
        download = Some(verified.clone());
        stage(UpdateStage::Mounting);
        let mp = steps.mount(&verified)?;
        mount_point = Some(mp.clone());
        stage(UpdateStage::VerifyingApp);
        let source = Path::new(&mp).join(APP_NAME);
        steps.verify_app(&source, &release.version)?;
        stage(UpdateStage::Preparing);
        let log = steps.cache_directory().join(HELPER_LOG_NAME);
        let token = UpdateInstaller::new_token();
        let make = |dir: &Path| {
            UpdateInstaller::helper_script(
                pid,
                &source.to_string_lossy(),
                &target.to_string_lossy(),
                &mp,
                &dir.to_string_lossy(),
                &verified.directory.to_string_lossy(),
                &log.to_string_lossy(),
                &token,
            )
        };
        let script = steps.write_helper(&make)?;
        helper_dir = script.parent().map(Path::to_path_buf);
        stage(UpdateStage::Quitting);
        if !confirm_quit() {
            return Ok(UpdateOutcome::Cancelled);
        }
        steps.launch_helper(&script)?;
        Ok(UpdateOutcome::HelperLaunched)
    })();
    match result {
        Ok(UpdateOutcome::HelperLaunched) => {}
        _ => cleanup(&mount_point, &helper_dir, &download),
    }
    result
}
