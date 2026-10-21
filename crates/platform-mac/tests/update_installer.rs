//! Port of `UpdateInstallerTests` (`UpdateTests.swift`): download + verification, mounting, the bundle check,
//! the install target, the helper script (also run in a sandbox with stubbed `open` / `hdiutil`), the leftover
//! sweep, the helper launch and the launch housekeeping. Throwaway signing keys only; no network.
#![cfg(target_os = "macos")]

mod common;

use common::{Scratch, assert_bash_syntax, chmod, mode};
use ed25519_dalek::{Signer, SigningKey};
use macvpn_core::l10n::AppLanguage;
use macvpn_core::plist_xml::{PlistValue, to_xml};
use macvpn_core::swift_base64;
use macvpn_core::update::{
    HelperOutcome, Release, ReleaseAsset, UpdateError, UpdateSignature, parse_checksum, sha256_hex,
};
use macvpn_platform_mac::brew::shell_quote;
use macvpn_platform_mac::command::CommandResult;
use macvpn_platform_mac::http::HttpResponse;
use macvpn_platform_mac::testing::{MockCommandRunner, MockHttpClient};
use macvpn_platform_mac::update_installer::{
    InstallerError, UpdateInstaller, VerifiedDownload, previous_update_notice, resolve_symlinks,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

const DMG_URL: &str = "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg";
const SUM_URL: &str = "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sha256";
const SIG_URL: &str = "https://github.com/SepsiG/MacVPN/releases/download/v0.2.0/MacVPN-0.2.0.dmg.sig";

fn asset(name: &str, url: &str) -> ReleaseAsset {
    ReleaseAsset { name: name.into(), url: url.into() }
}

fn release() -> Release {
    Release {
        tag: "v0.2.0".into(),
        version: "0.2.0".into(),
        notes: String::new(),
        page_url: None,
        published_at: None,
        package: asset("MacVPN-0.2.0.dmg", DMG_URL),
        checksum: asset("MacVPN-0.2.0.dmg.sha256", SUM_URL),
        signature: Some(asset("MacVPN-0.2.0.dmg.sig", SIG_URL)),
    }
}

/// The throwaway signing key (not the real release key).
fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

/// The `.sig` contents: base64 signature + newline.
fn sig_with(dmg: &[u8], version: &str, key: &SigningKey) -> Vec<u8> {
    let message = UpdateSignature::message(version, &sha256_hex(dmg)).unwrap();
    (swift_base64::encode(&key.sign(&message).to_bytes()) + "\n").into_bytes()
}

fn sig(dmg: &[u8]) -> Vec<u8> {
    sig_with(dmg, "0.2.0", &signing_key())
}

fn sum_file(data: &[u8]) -> Vec<u8> {
    format!("{}  MacVPN-0.2.0.dmg\n", sha256_hex(data)).into_bytes()
}

fn installer<'a>(http: &'a MockHttpClient, runner: &'a MockCommandRunner, cache: &Path) -> UpdateInstaller<'a> {
    UpdateInstaller::with_keys(http, runner, cache.to_path_buf(), vec![signing_key().verifying_key().to_bytes()])
}

fn served(dmg: &[u8]) -> MockHttpClient {
    let http = MockHttpClient::new();
    http.respond(DMG_URL, HttpResponse::new(200, dmg));
    http.respond(SUM_URL, HttpResponse::new(200, &sum_file(dmg)));
    http.respond(SIG_URL, HttpResponse::new(200, &sig(dmg)));
    http
}

fn entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|r| r.map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn update_error(e: &InstallerError) -> Option<UpdateError> {
    e.update_error().cloned()
}

#[test]
fn checksum_parsing() {
    let h = "ab".repeat(32);
    assert_eq!(parse_checksum(&format!("{h}  MacVPN-0.2.0.dmg\n"), "MacVPN-0.2.0.dmg").unwrap(), h);
    assert_eq!(parse_checksum(&format!("{} *MacVPN-0.2.0.dmg", h.to_uppercase()), "MacVPN-0.2.0.dmg").unwrap(), h);
    assert!(parse_checksum(&format!("{h}  Other.dmg"), "MacVPN-0.2.0.dmg").is_err());
    assert!(parse_checksum("abc  MacVPN-0.2.0.dmg", "MacVPN-0.2.0.dmg").is_err());
    assert!(parse_checksum("", "MacVPN-0.2.0.dmg").is_err());
}

/// Every download goes into a fresh 0700 (mkdtemp) directory under the cache.
#[test]
fn download_verifies_checksum_into_fresh_private_directory() {
    let cache = Scratch::unborn("macvpn-update-test");
    let dmg = b"fake dmg contents";
    let runner = MockCommandRunner::new();
    let http = served(dmg);
    let d1 = installer(&http, &runner, cache.path()).download_verified(&release()).unwrap();
    let d2 = installer(&http, &runner, cache.path()).download_verified(&release()).unwrap();
    assert_ne!(d1.directory, d2.directory);
    for d in [&d1, &d2] {
        assert_eq!(d.directory.parent(), Some(cache.path()));
        assert!(d.directory.file_name().unwrap().to_string_lossy().starts_with("download."));
        assert_eq!(d.dmg, d.directory.join("MacVPN-0.2.0.dmg"));
        assert_eq!(std::fs::read(&d.dmg).unwrap(), dmg);
        assert_eq!(d.sha256, sha256_hex(dmg));
        assert_eq!(mode(&d.directory), 0o700);
    }
    assert_eq!(mode(cache.path()), 0o700);
    // The mock's temporary download files were moved, none is left behind.
    assert_eq!(http.requested(), [SUM_URL, SIG_URL, DMG_URL, SUM_URL, SIG_URL, DMG_URL]);
}

#[test]
fn checksum_mismatch_deletes_download() {
    let cache = Scratch::unborn("macvpn-update-test");
    let http = MockHttpClient::new();
    http.respond(DMG_URL, HttpResponse::new(200, b"tampered"));
    http.respond(SUM_URL, HttpResponse::new(200, &sum_file(b"original")));
    http.respond(SIG_URL, HttpResponse::new(200, &sig(b"original")));
    let runner = MockCommandRunner::new();
    let e = installer(&http, &runner, cache.path()).download_verified(&release()).unwrap_err();
    assert_eq!(update_error(&e), Some(UpdateError::ChecksumMismatch));
    assert!(entries(cache.path()).is_empty());
}

#[test]
fn download_http_failure() {
    let cache = Scratch::unborn("macvpn-update-test");
    let http = MockHttpClient::new();
    http.respond(SUM_URL, HttpResponse::new(200, format!("{}  MacVPN-0.2.0.dmg", "0".repeat(64)).as_bytes()));
    http.respond(SIG_URL, HttpResponse::new(200, &sig(b"")));
    let runner = MockCommandRunner::new();
    let e = installer(&http, &runner, cache.path()).download_verified(&release()).unwrap_err();
    assert_eq!(update_error(&e), Some(UpdateError::Http(404)));
    assert!(entries(cache.path()).is_empty());
    // The checksum file itself missing: no download at all.
    let http = MockHttpClient::new();
    let e = installer(&http, &runner, cache.path()).download_verified(&release()).unwrap_err();
    assert_eq!(update_error(&e), Some(UpdateError::Http(404)));
    assert_eq!(http.requested(), [SUM_URL]);
}

#[test]
fn download_rejects_untrusted_urls_and_names() {
    let cache = Scratch::unborn("macvpn-update-test");
    let http = served(b"x");
    let runner = MockCommandRunner::new();
    let mut r = release();
    r.package.url = "https://evil.example.com/MacVPN-0.2.0.dmg".into();
    let e = installer(&http, &runner, cache.path()).download_verified(&r).unwrap_err();
    assert_eq!(update_error(&e), Some(UpdateError::UntrustedUrl("https://evil.example.com/MacVPN-0.2.0.dmg".into())));
    let mut r = release();
    r.package.name = "../MacVPN-0.2.0.dmg".into();
    let e = installer(&http, &runner, cache.path()).download_verified(&r).unwrap_err();
    assert_eq!(update_error(&e), Some(UpdateError::MissingAsset("../MacVPN-0.2.0.dmg".into())));
    assert!(http.requested().is_empty());
}

/// A missing, wrong-key, other-content, oversized or malformed `.sig`: no install, the download is deleted. The
/// signature covers the locally computed hash: a DMG swapped together with its `.sha256` does not pass either.
#[test]
fn download_requires_valid_signature() {
    let cache = Scratch::unborn("macvpn-update-test");
    let dmg: &[u8] = b"fake dmg contents";
    let runner = MockCommandRunner::new();
    let attempt =
        |served: &[u8], sum: &[u8], sig: Option<HttpResponse>, r: Option<Release>| -> Option<InstallerError> {
            let http = MockHttpClient::new();
            http.respond(DMG_URL, HttpResponse::new(200, served));
            http.respond(SUM_URL, HttpResponse::new(200, &sum_file(sum)));
            if let Some(sig) = sig {
                http.respond(SIG_URL, sig);
            }
            installer(&http, &runner, cache.path()).download_verified(&r.unwrap_or_else(release)).err()
        };
    let good = sig(dmg);
    let evil: &[u8] = b"evil dmg";
    let mut oversized = good.clone();
    oversized.extend(std::iter::repeat_n(b'\n', 1024));
    let cases: Vec<(&str, Option<InstallerError>)> = vec![
        ("no .sig asset (404)", attempt(dmg, dmg, None, None)),
        (
            "foreign key",
            attempt(
                dmg,
                dmg,
                Some(HttpResponse::new(200, &sig_with(dmg, "0.2.0", &SigningKey::from_bytes(&[9; 32])))),
                None,
            ),
        ),
        (
            "other version",
            attempt(dmg, dmg, Some(HttpResponse::new(200, &sig_with(dmg, "0.1.9", &signing_key()))), None),
        ),
        ("DMG and .sha256 swapped together", attempt(evil, evil, Some(HttpResponse::new(200, &good)), None)),
        ("too large", attempt(dmg, dmg, Some(HttpResponse::new(200, &oversized)), None)),
        ("not base64", attempt(dmg, dmg, Some(HttpResponse::new(200, b"not base64!\n")), None)),
        ("empty", attempt(dmg, dmg, Some(HttpResponse::new(200, b"")), None)),
        ("not UTF-8", attempt(dmg, dmg, Some(HttpResponse::new(200, &[0xff, 0xfe])), None)),
    ];
    for (name, error) in cases {
        assert_eq!(error.as_ref().and_then(update_error), Some(UpdateError::UnsignedUpdate), "{name}");
    }
    // A release without a `.sig` asset: nothing is downloaded.
    let mut unsigned = release();
    unsigned.signature = None;
    let none = attempt(dmg, dmg, Some(HttpResponse::new(200, &good)), Some(unsigned));
    assert_eq!(none.as_ref().and_then(update_error), Some(UpdateError::UnsignedUpdate));
    // Another HTTP error for the .sig: that one stays.
    let rate_limited = attempt(dmg, dmg, Some(HttpResponse::new(403, b"")), None);
    assert_eq!(rate_limited.as_ref().and_then(update_error), Some(UpdateError::Http(403)));
    assert!(entries(cache.path()).is_empty());
    // The production installer uses the embedded keys: one signed with the throwaway key is rejected.
    let http = served(dmg);
    let e = UpdateInstaller::new(&http, &runner, cache.path().to_path_buf()).download_verified(&release()).unwrap_err();
    assert_eq!(update_error(&e), Some(UpdateError::UnsignedUpdate));
    // And the good signature passes.
    assert!(attempt(dmg, dmg, Some(HttpResponse::new(200, &good)), None).is_none());
}

const ATTACH_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>system-entities</key><array>
<dict><key>content-hint</key><string>GUID_partition_scheme</string><key>dev-entry</key><string>/dev/disk9</string></dict>
<dict><key>dev-entry</key><string>/dev/disk9s1</string><key>mount-point</key><string>/Volumes/MacVPN 1</string></dict>
</array></dict></plist>
"#;

fn info_plist(image_path: &str, mount_point: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>images</key><array>
<dict><key>image-path</key><string>/other/image.dmg</string><key>system-entities</key><array>
  <dict><key>mount-point</key><string>/Volumes/Other</string></dict></array></dict>
<dict><key>image-path</key><string>{image_path}</string><key>system-entities</key><array>
  <dict><key>dev-entry</key><string>/dev/disk9</string></dict>
  <dict><key>mount-point</key><string>{mount_point}</string></dict></array></dict>
</array></dict></plist>
"#
    )
}

fn attach_key(d: &VerifiedDownload) -> String {
    format!("/usr/bin/hdiutil attach -nobrowse -readonly -noautoopen -plist {}", d.dmg.display())
}

fn verified_download(cache: &Path, http: &MockHttpClient, runner: &MockCommandRunner) -> VerifiedDownload {
    installer(http, runner, cache).download_verified(&release()).unwrap()
}

#[test]
fn mount_rehashes_and_checks_image_path() {
    let cache = Scratch::unborn("macvpn-update-test");
    let (http, runner) = (served(b"fake dmg contents"), MockCommandRunner::new());
    let d = verified_download(cache.path(), &http, &runner);
    runner.respond(&attach_key(&d), CommandResult::new(0, &format!("checksum ok\n{ATTACH_PLIST}"), ""));
    runner.respond(
        "/usr/bin/hdiutil info -plist",
        CommandResult::stdout(&info_plist(&d.dmg.to_string_lossy(), "/Volumes/MacVPN 1")),
    );
    let mp = installer(&http, &runner, cache.path()).mount(&d).unwrap();
    assert_eq!(mp, "/Volumes/MacVPN 1");
    assert_eq!(
        runner.calls().iter().map(|c| c.command_line()).collect::<Vec<_>>(),
        [attach_key(&d), "/usr/bin/hdiutil info -plist".into()]
    );
    assert!(UpdateInstaller::parse_mount_point(b"<plist><dict/></plist>").is_err());
}

#[test]
fn parse_mount_point_requires_volumes() {
    let plist = ATTACH_PLIST.replace("/Volumes/MacVPN 1", "/private/tmp/x");
    assert!(UpdateInstaller::parse_mount_point(plist.as_bytes()).is_err());
    let plist = ATTACH_PLIST.replace("/Volumes/MacVPN 1", "/Volumes/../etc");
    assert!(UpdateInstaller::parse_mount_point(plist.as_bytes()).is_err());
    assert!(UpdateInstaller::parse_mount_point(b"not a plist").is_err());
    assert_eq!(UpdateInstaller::xml_part("noise\n<?xml x"), "<?xml x");
    assert_eq!(UpdateInstaller::xml_part("no xml"), "no xml");
}

/// If the file changed between the hash and the attach, there is no attach.
#[test]
fn mount_rejects_file_changed_after_hash() {
    let cache = Scratch::unborn("macvpn-update-test");
    let (http, runner) = (served(b"fake dmg contents"), MockCommandRunner::new());
    let d = verified_download(cache.path(), &http, &runner);
    std::fs::write(&d.dmg, "swapped").unwrap();
    let e = installer(&http, &runner, cache.path()).mount(&d).unwrap_err();
    assert_eq!(update_error(&e), Some(UpdateError::ChecksumMismatch));
    assert!(runner.calls().is_empty());
}

/// If the attached image is not the hashed file, it is detached and an error returned.
#[test]
fn mount_rejects_different_image_path() {
    let cache = Scratch::unborn("macvpn-update-test");
    let (http, runner) = (served(b"fake dmg contents"), MockCommandRunner::new());
    let d = verified_download(cache.path(), &http, &runner);
    runner.respond(&attach_key(&d), CommandResult::stdout(ATTACH_PLIST));
    runner.respond(
        "/usr/bin/hdiutil info -plist",
        CommandResult::stdout(&info_plist("/tmp/evil.dmg", "/Volumes/MacVPN 1")),
    );
    let e = installer(&http, &runner, cache.path()).mount(&d).unwrap_err();
    assert!(matches!(update_error(&e), Some(UpdateError::MountFailed(_))), "{e}");
    assert_eq!(runner.calls().last().unwrap().command_line(), "/usr/bin/hdiutil detach /Volumes/MacVPN 1 -quiet");
}

#[test]
fn image_path_parsing() {
    let info = info_plist("/a/b.dmg", "/Volumes/MacVPN 1");
    assert_eq!(UpdateInstaller::image_path("/Volumes/MacVPN 1", info.as_bytes()).as_deref(), Some("/a/b.dmg"));
    assert_eq!(UpdateInstaller::image_path("/Volumes/Other", info.as_bytes()).as_deref(), Some("/other/image.dmg"));
    assert_eq!(UpdateInstaller::image_path("/Volumes/None", info.as_bytes()), None);
}

#[test]
fn mount_failure() {
    let cache = Scratch::unborn("macvpn-update-test");
    let (http, runner) = (served(b"fake dmg contents"), MockCommandRunner::new());
    let d = verified_download(cache.path(), &http, &runner);
    runner.respond(&attach_key(&d), CommandResult::new(1, "", "hdiutil: attach failed - image not recognized"));
    let e = installer(&http, &runner, cache.path()).mount(&d).unwrap_err();
    assert_eq!(
        update_error(&e),
        Some(UpdateError::MountFailed("hdiutil: attach failed - image not recognized".into()))
    );
}

fn make_app(cache: &Path, bundle_id: &str, version: &str) -> PathBuf {
    let app = cache.join("MacVPN.app");
    let _ = std::fs::remove_dir_all(&app);
    std::fs::create_dir_all(app.join("Contents")).unwrap();
    let mut info = BTreeMap::new();
    info.insert("CFBundleIdentifier".to_string(), PlistValue::String(bundle_id.into()));
    info.insert("CFBundleShortVersionString".to_string(), PlistValue::String(version.into()));
    std::fs::write(app.join("Contents/Info.plist"), to_xml(&PlistValue::Dictionary(info))).unwrap();
    app
}

#[test]
fn verify_bundle() {
    let cache = Scratch::new("macvpn-update-test");
    assert!(UpdateInstaller::verify_bundle(&make_app(cache.path(), "local.macvpn", "0.2.0"), "0.2.0").is_ok());
    assert!(UpdateInstaller::verify_bundle(&make_app(cache.path(), "com.evil", "0.2.0"), "0.2.0").is_err());
    assert!(UpdateInstaller::verify_bundle(&make_app(cache.path(), "local.macvpn", "0.1.9"), "0.2.0").is_err());
    assert!(UpdateInstaller::verify_bundle(&cache.join("Nope.app"), "0.2.0").is_err());
    // A symlink is not accepted.
    let real = make_app(cache.path(), "local.macvpn", "0.2.0");
    let link = cache.join("Link.app");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(UpdateInstaller::verify_bundle(&link, "0.2.0").is_err());
    // A binary Info.plist (what Xcode / Tauri may write) is read too.
    let app = make_app(cache.path(), "local.macvpn", "0.2.0");
    let status = std::process::Command::new("/usr/bin/plutil")
        .args(["-convert", "binary1"])
        .arg(app.join("Contents/Info.plist"))
        .status()
        .unwrap();
    assert!(status.success());
    assert!(UpdateInstaller::verify_bundle(&app, "0.2.0").is_ok());
}

#[test]
fn verify_bundle_messages() {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let cache = Scratch::new("macvpn-update-test");
    let e = UpdateInstaller::verify_bundle(&make_app(cache.path(), "com.evil", "0.2.0"), "0.2.0").unwrap_err();
    assert_eq!(
        e.to_string(),
        "The app on the disk image is not accepted: bundle identifier com.evil, expected: local.macvpn"
    );
    let e = UpdateInstaller::verify_bundle(&make_app(cache.path(), "local.macvpn", "0.1.9"), "0.2.0").unwrap_err();
    assert_eq!(e.to_string(), "The app on the disk image is not accepted: version 0.1.9, expected: 0.2.0");
}

/// A symlink under Contents must not point outside the bundle; an inner (relative) link is fine.
#[test]
fn verify_bundle_rejects_symlinks_escaping_bundle() {
    let cache = Scratch::new("macvpn-update-test");
    let app = make_app(cache.path(), "local.macvpn", "0.2.0");
    let res = app.join("Contents/Resources");
    std::fs::create_dir_all(res.join("root")).unwrap();
    std::os::unix::fs::symlink("root", res.join("inner")).unwrap();
    std::os::unix::fs::symlink("missing-inside", res.join("dangling-inner")).unwrap();
    assert!(UpdateInstaller::verify_bundle(&app, "0.2.0").is_ok());

    std::os::unix::fs::symlink("../../../../", res.join("root/escape")).unwrap();
    assert!(UpdateInstaller::verify_bundle(&app, "0.2.0").is_err());
    std::fs::remove_file(res.join("root/escape")).unwrap();
    std::os::unix::fs::symlink("/etc", res.join("abs")).unwrap();
    assert!(UpdateInstaller::verify_bundle(&app, "0.2.0").is_err());
    std::fs::remove_file(res.join("abs")).unwrap();
    std::os::unix::fs::symlink("/nonexistent/x", res.join("dangling-out")).unwrap();
    assert!(UpdateInstaller::verify_bundle(&app, "0.2.0").is_err());
}

#[test]
fn verify_app_runs_codesign() {
    let cache = Scratch::new("macvpn-update-test");
    let app = make_app(cache.path(), "local.macvpn", "0.2.0");
    let (http, runner) = (MockHttpClient::new(), MockCommandRunner::new());
    let installer = UpdateInstaller::new(&http, &runner, cache.path().to_path_buf());
    let key = format!("/usr/bin/codesign --verify --strict {}", app.display());
    installer.verify_app(&app, "0.2.0").unwrap();
    assert_eq!(runner.calls().iter().map(|c| c.command_line()).collect::<Vec<_>>(), std::slice::from_ref(&key));
    runner.respond(&key, CommandResult::new(1, "", "a sealed resource is missing or invalid"));
    let e = installer.verify_app(&app, "0.2.0").unwrap_err();
    assert!(matches!(update_error(&e), Some(UpdateError::InvalidApp(_))), "{e}");
}

#[test]
fn install_target() {
    let cache = Scratch::new("macvpn-update-test");
    let app = make_app(cache.path(), "local.macvpn", "0.1.0");
    assert_eq!(UpdateInstaller::check_install_target(&app).unwrap(), std::fs::canonicalize(&app).unwrap());
    // Through a symlink: the resolved bundle.
    let link = cache.join("Link.app");
    std::os::unix::fs::symlink(&app, &link).unwrap();
    assert_eq!(UpdateInstaller::check_install_target(&link).unwrap(), std::fs::canonicalize(&app).unwrap());
    assert!(UpdateInstaller::check_install_target(Path::new("/usr/bin")).is_err());
    assert!(UpdateInstaller::check_install_target(Path::new("/System/Applications/Calculator.app")).is_err());
    // Translocated: refused even if writable.
    let trans = cache.join("AppTranslocation/X/d/MacVPN.app");
    std::fs::create_dir_all(&trans).unwrap();
    assert!(UpdateInstaller::check_install_target(&trans).is_err());
}

fn script(target: &str) -> String {
    UpdateInstaller::helper_script(
        4242,
        "/Volumes/MacVPN 1/MacVPN.app",
        target,
        "/Volumes/MacVPN 1",
        "/var/folders/x/T/macvpn-update.AbC123",
        "/Users/o'neil/Library/Caches/MacVPN/download.Xy12",
        "/Users/o'neil/Library/Caches/MacVPN/update.log",
        "T1",
    )
}

#[test]
fn helper_script() {
    let s = script("/Users/o'neil/Apps/MacVPN.app");
    assert!(s.starts_with("#!/bin/bash\n"));
    // Waiting for the pid (kill -0, at most 30 s).
    assert!(s.contains("APP_PID=4242"));
    assert!(s.contains("while /bin/kill -0 \"$APP_PID\""));
    assert!(s.contains("[ \"$waited\" -ge 60 ]") && s.contains("/bin/sleep 0.5"));
    // Paths in single quotes, the ' escaped.
    assert!(s.contains("SRC='/Volumes/MacVPN 1/MacVPN.app'"));
    assert!(s.contains("DEST='/Users/o'\\''neil/Apps/MacVPN.app'"));
    assert!(s.contains("STAGED='/Users/o'\\''neil/Apps/.MacVPN.app.update-T1'"));
    assert!(s.contains("OLD='/Users/o'\\''neil/Apps/.MacVPN.app.old-T1'"));
    assert!(s.contains("MOUNT='/Volumes/MacVPN 1'"));
    assert!(s.contains("SELF_DIR='/var/folders/x/T/macvpn-update.AbC123'"));
    assert!(s.contains("DOWNLOAD_DIR='/Users/o'\\''neil/Library/Caches/MacVPN/download.Xy12'"));
    // The swap: ditto next to the target, rename, target empty?, move in, quarantine, detach, relaunch.
    let steps = [
        "/usr/bin/ditto \"$SRC\" \"$STAGED\"",
        "/bin/mv \"$DEST\" \"$OLD\"",
        "if [ -e \"$DEST\" ]; then",
        "/bin/mv \"$STAGED\" \"$DEST\"",
        "/bin/rm -rf \"$OLD\"",
        "/usr/bin/xattr -dr com.apple.quarantine \"$DEST\"",
        "finish\n/usr/bin/open \"$DEST\"",
    ];
    let mut cursor = 0;
    for step in steps {
        let at = s[cursor..].find(step).unwrap_or_else(|| panic!("{step}"));
        cursor += at + step.len();
    }
    // finish: detach, then the download directory and the script are deleted.
    let finish = s.find("finish() {").unwrap();
    let detach = finish + s[finish..].find("/usr/bin/hdiutil detach \"$MOUNT\"").unwrap();
    let rm_download = detach + s[detach..].find("/bin/rm -rf \"$DOWNLOAD_DIR\"").unwrap();
    assert!(s[rm_download..].contains("/bin/rm -rf \"$SELF_DIR\""));
    assert!(s.contains("restore failed"));
    // Paths appear only through the variables (no unquoted path).
    for line in s.lines().filter(|l| l.contains("/Volumes/") || l.contains("/Users/")) {
        assert!(line.contains("='"), "{line}");
    }
    assert_bash_syntax(&s);
    // A fresh token is an upper-case UUID.
    let token = UpdateInstaller::new_token();
    assert_eq!(token.len(), 36);
    assert_eq!(token, token.to_uppercase());
}

/// A sandbox for the helper: the new app on a "volume", the old one in "apps", stubbed open / hdiutil.
struct HelperSandbox {
    root: PathBuf,
}

impl HelperSandbox {
    fn new(root: PathBuf) -> Self {
        let _ = std::fs::remove_dir_all(&root);
        for (dir, v) in [("vol/MacVPN.app/Contents", "new"), ("apps/MacVPN.app/Contents", "old")] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
            std::fs::write(root.join(dir).join("v"), v).unwrap();
        }
        for d in ["self", "download", "bin"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        // open and hdiutil stubs: they only log.
        for tool in ["open", "hdiutil"] {
            let stub = root.join("bin").join(tool);
            std::fs::write(&stub, format!("#!/bin/bash\necho \"{} $*\"\n", tool.to_uppercase())).unwrap();
            chmod(&stub, 0o755);
        }
        HelperSandbox { root }
    }

    fn script(&self) -> String {
        let p = |s: &str| self.root.join(s).to_string_lossy().into_owned();
        let bin = shell_quote(&p("bin"));
        UpdateInstaller::helper_script(
            999_999,
            &p("vol/MacVPN.app"),
            &p("apps/MacVPN.app"),
            &p("vol"),
            &p("self"),
            &p("download"),
            &p("update.log"),
            "T",
        )
        .replace("/usr/bin/open", &format!("{bin}/open"))
        .replace("/usr/bin/hdiutil", &format!("{bin}/hdiutil"))
    }

    fn run(&self, script: &str) -> String {
        let path = self.root.join("u.sh");
        std::fs::write(&path, script).unwrap();
        std::process::Command::new("/bin/bash").arg(&path).status().unwrap();
        std::fs::read_to_string(self.root.join("update.log")).unwrap_or_default()
    }

    fn version(&self) -> String {
        std::fs::read_to_string(self.root.join("apps/MacVPN.app/Contents/v")).unwrap()
    }
}

/// The helper for real (with stubbed open / hdiutil): swap, rollback, the target taken.
#[test]
fn helper_script_runs_in_sandbox() {
    let cache = Scratch::new("macvpn-update-test");
    let root = cache.join("sandbox o'k");

    // A successful swap.
    let sandbox = HelperSandbox::new(root.clone());
    let log = sandbox.run(&sandbox.script());
    assert_eq!(sandbox.version(), "new", "{log}");
    assert!(log.contains("HDIUTIL detach"), "{log}");
    assert!(log.contains(&format!("OPEN {}", root.join("apps/MacVPN.app").display())), "{log}");
    assert!(!root.join("download").exists());
    assert!(!root.join("self").exists());
    assert_eq!(entries(&root.join("apps")), ["MacVPN.app"]);
    assert_eq!(UpdateInstaller::last_helper_outcome(&log).map(|o| o.1), Some(HelperOutcome::Succeeded));

    // If the target exists again (a race) after the old app was renamed: stop, no swap.
    let sandbox = HelperSandbox::new(root.clone());
    let script =
        sandbox.script().replace("if [ -e \"$DEST\" ]; then", "/bin/mkdir -p \"$DEST\"\nif [ -e \"$DEST\" ]; then");
    let log = sandbox.run(&script);
    assert!(log.contains("the target still exists"), "{log}");
    assert!(!root.join("apps/.MacVPN.app.update-T").exists());
    assert!(!root.join("download").exists());
    assert!(matches!(UpdateInstaller::last_helper_outcome(&log).map(|o| o.1), Some(HelperOutcome::Failed(_))));

    // ditto fails: the old app stays and is reopened.
    let sandbox = HelperSandbox::new(root.clone());
    let script = sandbox.script().replace("/usr/bin/ditto \"$SRC\"", "/usr/bin/false \"$SRC\"");
    let log = sandbox.run(&script);
    assert!(log.contains("copy (ditto) failed"), "{log}");
    assert_eq!(sandbox.version(), "old");
    assert!(log.contains("OPEN "), "{log}");
}

/// In the swap (around the two renames) TERM/INT are ignored, then restored.
#[test]
fn helper_script_traps_term_during_swap() {
    let s = script("/Users/o'neil/Apps/MacVPN.app");
    let ignore = s.find("trap '' TERM INT").unwrap();
    let first_move = s.find("/bin/mv \"$DEST\" \"$OLD\"").unwrap();
    let second_move = s.find("/bin/mv \"$STAGED\" \"$DEST\"").unwrap();
    let ditto = s.find("/usr/bin/ditto \"$SRC\" \"$STAGED\"").unwrap();
    assert!(ditto < ignore);
    assert!(ignore < first_move);
    let restore = second_move + s[second_move..].find("trap - TERM INT").unwrap();
    assert!(s[restore..].contains("/usr/bin/open \"$DEST\""));
    // The successful swap is logged before the relaunch (the new app sees the result at launch).
    assert!(s.find("echo \"done\"").unwrap() < s.find("finish\n/usr/bin/open \"$DEST\"").unwrap());
    assert_bash_syntax(&s);
}

/// For real: a SIGTERM between the two renames does not leave the target without an app.
#[test]
fn helper_script_survives_term_between_renames() {
    let cache = Scratch::new("macvpn-update-test");
    let sandbox = HelperSandbox::new(cache.join("term"));
    // Logging out, simulated: SIGTERM to itself after the first rename.
    let script = sandbox.script().replace("if [ -e \"$DEST\" ]; then", "/bin/kill -TERM $$\nif [ -e \"$DEST\" ]; then");
    let log = sandbox.run(&script);
    assert_eq!(sandbox.version(), "new", "{log}");
    assert_eq!(entries(&cache.join("term/apps")), ["MacVPN.app"]);
    assert!(log.contains("done"), "{log}");
}

/// Launch housekeeping: the `.<App>.update-*` and `.<App>.old-*` leftovers next to the running bundle.
#[test]
fn sweep_leftovers() {
    let cache = Scratch::new("macvpn-update-test");
    let dir = cache.join("Apps");
    std::fs::create_dir_all(&dir).unwrap();
    let bundle = dir.join("MacVPN.app");
    let leftovers = [".MacVPN.app.update-8F1C2D3E-0000-4000-8000-000000000001", ".MacVPN.app.old-T1"];
    let keep = [
        "MacVPN.app",
        "Other.app",
        ".Other.app.old-T1",
        ".MacVPN.app.update-",
        ".MacVPN.app.oldish",
        "MacVPN.app.old-T1",
        ".MacVPN.app.old-a b",
        ".MacVPN.app.old-../x",
    ];
    for name in leftovers.iter().chain(keep.iter()).filter(|n| !n.contains('/')) {
        std::fs::create_dir_all(dir.join(name).join("Contents")).unwrap();
    }
    // A symlink leftover: only the link is deleted, not its target.
    let target = cache.join("linktarget");
    std::fs::create_dir_all(&target).unwrap();
    std::os::unix::fs::symlink(&target, dir.join(".MacVPN.app.old-L")).unwrap();

    let removed = UpdateInstaller::sweep_leftovers(&bundle);
    let mut removed: Vec<String> =
        removed.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect();
    removed.sort();
    let mut expected: Vec<String> =
        leftovers.iter().map(|s| s.to_string()).chain([".MacVPN.app.old-L".to_string()]).collect();
    expected.sort();
    assert_eq!(removed, expected);
    let mut kept: Vec<String> = keep.iter().filter(|n| !n.contains('/')).map(|s| s.to_string()).collect();
    kept.sort();
    assert_eq!(entries(&dir), kept);
    assert!(target.exists());
}

#[test]
fn sweep_skips_when_bundle_missing() {
    let cache = Scratch::new("macvpn-update-test");
    let dir = cache.join("Apps");
    std::fs::create_dir_all(dir.join(".MacVPN.app.old-T1")).unwrap();
    assert!(UpdateInstaller::sweep_leftovers(&dir.join("MacVPN.app")).is_empty());
    assert!(dir.join(".MacVPN.app.old-T1").exists());
    assert!(UpdateInstaller::sweep_leftovers(&cache.join("nope/MacVPN.app")).is_empty());
}

/// The helper log's last run: succeeded, cancelled by the timeout, or failed.
#[test]
fn helper_log_outcome() {
    let ok = "=== 2026-10-01 10:00:00 update: /Volumes/MacVPN/MacVPN.app -> /Applications/MacVPN.app ===\nthe app did not quit within 30 s, update cancelled\n=== 2026-10-02 10:00:00 update: /Volumes/MacVPN/MacVPN.app -> /Applications/MacVPN.app ===\nHDIUTIL detach\ndone\n\n";
    let (run, outcome) = UpdateInstaller::last_helper_outcome(ok).unwrap();
    assert_eq!(outcome, HelperOutcome::Succeeded);
    assert_eq!(run, "=== 2026-10-02 10:00:00 update: /Volumes/MacVPN/MacVPN.app -> /Applications/MacVPN.app ===");
    let timeout = "=== 2026-10-02 10:00:00 update: a -> b ===\ndone\n=== 2026-10-03 11:00:00 update: a -> b ===\nthe app did not quit within 30 s, update cancelled";
    assert_eq!(UpdateInstaller::last_helper_outcome(timeout).unwrap().1, HelperOutcome::TimedOut);
    for line in [
        "copy (ditto) failed",
        "cannot rename the old app",
        "cannot move the new app into place, restoring",
        "the target still exists after the rename, update cancelled",
    ] {
        let failed = format!("=== 2026-10-03 11:00:00 update: a -> b ===\nsome output\n{line}\nold app restored\n");
        assert_eq!(UpdateInstaller::last_helper_outcome(&failed).unwrap().1, HelperOutcome::Failed(line.into()));
    }
    assert_eq!(
        UpdateInstaller::last_helper_outcome("=== 2026-10-03 11:00:00 update: a -> b ===\nHDIUTIL detach\n").unwrap().1,
        HelperOutcome::Unknown
    );
    assert_eq!(UpdateInstaller::last_helper_outcome(""), None);
    assert_eq!(UpdateInstaller::last_helper_outcome("random\n"), None);
}

#[test]
fn write_helper_private() {
    let mut dir_seen = PathBuf::new();
    let path = UpdateInstaller::write_helper(|dir| {
        dir_seen = dir.to_path_buf();
        "#!/bin/bash\necho hi\n".to_string()
    })
    .unwrap();
    let _guard = Scratch(dir_seen.clone());
    assert_eq!(path.parent(), Some(dir_seen.as_path()));
    assert!(dir_seen.file_name().unwrap().to_string_lossy().starts_with("macvpn-update."));
    assert_eq!(mode(&dir_seen), 0o700);
    assert_eq!(mode(&path), 0o700);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "#!/bin/bash\necho hi\n");
}

/// Double fork: the outer bash exits at once, the script keeps running under nohup, detached.
#[test]
fn helper_launch_arguments_detach() {
    assert_eq!(
        UpdateInstaller::helper_launch_arguments(Path::new("/tmp/a b/it's.sh")),
        [
            "-c",
            "/usr/bin/nohup /bin/bash \"$1\" >/dev/null 2>&1 </dev/null & disown",
            "macvpn-update",
            "/tmp/a b/it's.sh"
        ]
    );
}

#[test]
fn launch_helper_survives_launcher() {
    let cache = Scratch::new("macvpn-update-test");
    let marker = cache.join("done");
    let script = cache.join("s.sh");
    std::fs::write(
        &script,
        format!("#!/bin/bash\n/bin/sleep 0.3\necho ok > {}\n", shell_quote(&marker.to_string_lossy())),
    )
    .unwrap();
    UpdateInstaller::launch_helper(&script).unwrap();
    // The launcher has exited; the script keeps running and writes the marker.
    assert!(!marker.exists());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(marker.exists());
}

/// The launch notice of the previous update: only failures and timeouts, once per run, within 14 days.
#[test]
fn previous_update_notice_rules() {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let home = Scratch::new("macvpn-home");
    let cache = home.join("Library/Caches/MacVPN");
    std::fs::create_dir_all(&cache).unwrap();
    let log = cache.join("update.log");
    let now = SystemTime::now();
    assert_eq!(previous_update_notice(&log, home.path(), None, now), None);

    std::fs::write(&log, "=== 2026-10-03 11:00:00 update: a -> b ===\ncopy (ditto) failed\n").unwrap();
    let (run, message) = previous_update_notice(&log, home.path(), None, now).unwrap();
    assert_eq!(run, "=== 2026-10-03 11:00:00 update: a -> b ===");
    assert_eq!(
        message,
        "The update stopped with an error (copy (ditto) failed). The installed version was kept. Details: ~/Library/Caches/MacVPN/update.log"
    );
    // Once per run.
    assert_eq!(previous_update_notice(&log, home.path(), Some(&run), now), None);
    // Older than 14 days: nothing.
    assert_eq!(previous_update_notice(&log, home.path(), None, now + Duration::from_secs(15 * 24 * 3600)), None);

    std::fs::write(&log, "=== x update: a -> b ===\nthe app did not quit within 30 s, update cancelled\n").unwrap();
    let (_, message) = previous_update_notice(&log, home.path(), None, now).unwrap();
    assert!(message.starts_with("The update was cancelled because MacVPN did not quit within 30 seconds."));
    std::fs::write(&log, "=== x update: a -> b ===\ndone\n").unwrap();
    assert_eq!(previous_update_notice(&log, home.path(), None, now), None);
}

#[test]
fn resolve_symlinks_like_foundation() {
    let cache = Scratch::new("macvpn-update-test");
    let real = std::fs::canonicalize(cache.path()).unwrap();
    std::fs::create_dir_all(cache.join("a")).unwrap();
    std::os::unix::fs::symlink("a", cache.join("l")).unwrap();
    assert_eq!(resolve_symlinks(&cache.join("l")), real.join("a"));
    assert_eq!(resolve_symlinks(&cache.join("l/../l/missing")), real.join("a/missing"));
    std::os::unix::fs::symlink("nowhere", cache.join("d")).unwrap();
    assert_eq!(resolve_symlinks(&cache.join("d")), real.join("nowhere"));
    assert!(UpdateInstaller::same_path(&cache.join("l").to_string_lossy(), &real.join("a").to_string_lossy()));
}

/// The helper runs with a cleared environment: PATH, HOME and LANG only (plus what bash itself sets).
#[test]
fn launch_helper_clears_the_environment() {
    let cache = Scratch::new("macvpn-update-test");
    let marker = cache.join("env");
    let script = cache.join("s.sh");
    std::fs::write(
        &script,
        format!("#!/bin/bash\n/usr/bin/env > {}.tmp\n/bin/mv {0}.tmp {0}\n", shell_quote(&marker.to_string_lossy())),
    )
    .unwrap();
    UpdateInstaller::launch_helper(&script).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let text = std::fs::read_to_string(&marker).unwrap();
    let keys: Vec<&str> = text.lines().filter_map(|l| l.split('=').next()).collect();
    for key in &keys {
        assert!(["PATH", "HOME", "LANG", "PWD", "SHLVL", "_", "OLDPWD"].contains(key), "{key}: {text}");
    }
    assert!(text.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin\n"), "{text}");
    assert!(text.contains("LANG=C\n"), "{text}");
    let env = UpdateInstaller::helper_environment();
    assert_eq!(env.keys().cloned().collect::<Vec<_>>(), ["HOME", "LANG", "PATH"]);
}

mod orchestration {
    use super::*;
    use macvpn_platform_mac::update_installer::{
        InstallerError, UpdateOutcome, UpdateStage, UpdateSteps, VerifiedDownload, install_update,
    };
    use std::cell::RefCell;

    /// Records the steps; can fail one of them.
    struct MockSteps {
        log: RefCell<Vec<String>>,
        fail: Option<&'static str>,
        work: PathBuf,
        script: RefCell<String>,
    }

    impl MockSteps {
        fn new(work: &Path, fail: Option<&'static str>) -> Self {
            MockSteps {
                log: RefCell::new(Vec::new()),
                fail,
                work: work.to_path_buf(),
                script: RefCell::new(String::new()),
            }
        }

        fn step(&self, name: &str) -> Result<(), InstallerError> {
            self.log.borrow_mut().push(name.to_string());
            if self.fail == Some(name) { Err(InstallerError::Message(format!("{name} failed"))) } else { Ok(()) }
        }

        fn log(&self) -> Vec<String> {
            self.log.borrow().clone()
        }
    }

    impl UpdateSteps for MockSteps {
        fn check_install_target(&self, bundle: &Path) -> Result<PathBuf, InstallerError> {
            self.step("check_install_target")?;
            Ok(bundle.to_path_buf())
        }

        fn download_verified(&self, _: &Release) -> Result<VerifiedDownload, InstallerError> {
            self.step("download_verified")?;
            let directory = self.work.join("download.X");
            std::fs::create_dir_all(&directory).unwrap();
            Ok(VerifiedDownload { dmg: directory.join("MacVPN-0.2.0.dmg"), directory, sha256: "0".repeat(64) })
        }

        fn mount(&self, _: &VerifiedDownload) -> Result<String, InstallerError> {
            self.step("mount")?;
            Ok("/Volumes/MacVPN".into())
        }

        fn verify_app(&self, app: &Path, version: &str) -> Result<(), InstallerError> {
            self.step(&format!("verify_app {} {version}", app.display())).and_then(|_| self.step("verify_app")).map(
                |_| {
                    self.log.borrow_mut().pop();
                },
            )
        }

        fn write_helper(&self, make_script: &dyn Fn(&Path) -> String) -> Result<PathBuf, InstallerError> {
            self.step("write_helper")?;
            let dir = self.work.join("helper.X");
            std::fs::create_dir_all(&dir).unwrap();
            *self.script.borrow_mut() = make_script(&dir);
            Ok(dir.join("update.sh"))
        }

        fn launch_helper(&self, _: &Path) -> Result<(), InstallerError> {
            self.step("launch_helper")
        }

        fn detach(&self, mount_point: &str) {
            self.log.borrow_mut().push(format!("detach {mount_point}"));
        }

        fn cache_directory(&self) -> PathBuf {
            self.work.join("cache")
        }
    }

    const ORDER: [&str; 6] = [
        "check_install_target",
        "download_verified",
        "mount",
        "verify_app /Volumes/MacVPN/MacVPN.app 0.2.0",
        "write_helper",
        "launch_helper",
    ];

    #[test]
    fn install_update_runs_the_steps_in_order() {
        let work = Scratch::new("macvpn-orchestrate");
        let steps = MockSteps::new(work.path(), None);
        let mut stages = Vec::new();
        let outcome = install_update(
            &steps,
            &release(),
            Path::new("/Applications/MacVPN.app"),
            4242,
            |s| stages.push(s),
            || true,
        )
        .unwrap();
        assert_eq!(outcome, UpdateOutcome::HelperLaunched);
        assert_eq!(steps.log(), ORDER);
        assert_eq!(
            stages,
            [
                UpdateStage::CheckingLocation,
                UpdateStage::Downloading,
                UpdateStage::Mounting,
                UpdateStage::VerifyingApp,
                UpdateStage::Preparing,
                UpdateStage::Quitting
            ]
        );
        // The helper got the right inputs; nothing is cleaned up (the helper owns it now).
        let script = steps.script.borrow().clone();
        assert!(script.contains("APP_PID=4242\n"));
        assert!(script.contains("SRC='/Volumes/MacVPN/MacVPN.app'\n"));
        assert!(script.contains("DEST='/Applications/MacVPN.app'\n"));
        assert!(script.contains(&format!("LOG={}\n", shell_quote(&work.join("cache/update.log").to_string_lossy()))));
        assert!(work.join("download.X").exists() && work.join("helper.X").exists());
        AppLanguage::set_thread_override(Some(AppLanguage::En));
        assert_eq!(UpdateStage::Downloading.message(), "Downloading…");
    }

    /// A failing step stops everything after it and cleans up what was made before it.
    #[test]
    fn a_failing_step_stops_and_cleans_up() {
        for (i, failing) in
            ["check_install_target", "download_verified", "mount", "verify_app", "write_helper", "launch_helper"]
                .into_iter()
                .enumerate()
        {
            let work = Scratch::new("macvpn-orchestrate");
            let steps = MockSteps::new(work.path(), Some(failing));
            let e = install_update(&steps, &release(), Path::new("/Applications/MacVPN.app"), 1, |_| {}, || true)
                .unwrap_err();
            assert_eq!(e.to_string(), format!("{failing} failed"));
            let log = steps.log();
            let ran: Vec<&str> = log.iter().filter(|l| !l.starts_with("detach")).map(String::as_str).collect();
            let mut expected: Vec<&str> = ORDER[..i].to_vec();
            expected.push(if failing == "verify_app" { ORDER[3] } else { failing });
            if failing == "verify_app" {
                expected.push("verify_app");
            }
            assert_eq!(ran, expected, "{failing}");
            // Detached only once it was mounted; the download and helper directories removed.
            assert_eq!(log.iter().any(|l| l == "detach /Volumes/MacVPN"), i > 2, "{failing}: {log:?}");
            assert!(!work.join("download.X").exists(), "{failing}");
            assert!(!work.join("helper.X").exists(), "{failing}");
        }
    }

    /// The user declines to quit: no launch, everything cleaned up.
    #[test]
    fn declined_quit_cleans_up() {
        let work = Scratch::new("macvpn-orchestrate");
        let steps = MockSteps::new(work.path(), None);
        let outcome =
            install_update(&steps, &release(), Path::new("/Applications/MacVPN.app"), 1, |_| {}, || false).unwrap();
        assert_eq!(outcome, UpdateOutcome::Cancelled);
        assert!(!steps.log().iter().any(|l| l == "launch_helper"));
        assert!(steps.log().iter().any(|l| l == "detach /Volumes/MacVPN"));
        assert!(!work.join("download.X").exists() && !work.join("helper.X").exists());
    }
}

/// A symlinked `Contents` (or `Info.plist`) is rejected before anything is read through it.
#[test]
fn verify_bundle_rejects_symlinked_contents() {
    let cache = Scratch::new("macvpn-update-test");
    let elsewhere = make_app(&cache.join("elsewhere"), "local.macvpn", "0.2.0");
    let app = cache.join("MacVPN.app");
    std::fs::create_dir_all(&app).unwrap();
    std::os::unix::fs::symlink(elsewhere.join("Contents"), app.join("Contents")).unwrap();
    let e = UpdateInstaller::verify_bundle(&app, "0.2.0").unwrap_err();
    assert!(matches!(e, UpdateError::InvalidApp(_)), "{e}");
    // Info.plist itself as a symlink.
    let app2 = cache.join("Two.app");
    std::fs::create_dir_all(app2.join("Contents")).unwrap();
    std::os::unix::fs::symlink(elsewhere.join("Contents/Info.plist"), app2.join("Contents/Info.plist")).unwrap();
    assert!(UpdateInstaller::verify_bundle(&app2, "0.2.0").is_err());
    // The real one passes.
    assert!(UpdateInstaller::verify_bundle(&elsewhere, "0.2.0").is_ok());
}

/// Hosts Foundation maps to github.com (`github%2Ecom`, fullwidth, mixed case) reach the HTTP layer only in the
/// canonical `https://github.com/…` form; a disallowed host reaches nothing.
#[test]
fn download_uses_canonical_urls() {
    let cache = Scratch::unborn("macvpn-update-test");
    let dmg: &[u8] = b"fake dmg contents";
    let http = served(dmg);
    let runner = MockCommandRunner::new();
    let mut r = release();
    r.package.url = DMG_URL.replace("github.com", "github%2Ecom");
    r.checksum.url = SUM_URL.replace("github.com", "\u{FF47}\u{FF49}\u{FF54}\u{FF48}\u{FF55}\u{FF42}.com");
    r.signature.as_mut().unwrap().url = SIG_URL.replace("github.com", "GitHub.COM");
    let d = installer(&http, &runner, cache.path()).download_verified(&r).unwrap();
    assert_eq!(std::fs::read(&d.dmg).unwrap(), dmg);
    assert_eq!(http.requested(), [SUM_URL, SIG_URL, DMG_URL]);

    let http = served(dmg);
    for (field, bad) in [
        (0, "https://evil.example.com/MacVPN-0.2.0.dmg"),
        (1, "https://github.com/x.sha256?a=b"),
        (2, "https://github.com.evil.com/x.sig"),
    ] {
        let mut r = release();
        match field {
            0 => r.package.url = bad.into(),
            1 => r.checksum.url = bad.into(),
            _ => r.signature.as_mut().unwrap().url = bad.into(),
        }
        let e = installer(&http, &runner, cache.path()).download_verified(&r).unwrap_err();
        assert_eq!(update_error(&e), Some(UpdateError::UntrustedUrl(bad.into())), "{bad}");
    }
    assert!(http.requested().is_empty(), "nothing reached the HTTP layer");
}
