//! The WinVPN updater's portable parts (every OS): the asset of this architecture, the signature under WinVPN's
//! domain and the asset name, the download-and-verify flow over a scripted HTTP client, the relaunch arguments, the
//! outcome notice and the launch housekeeping. Throwaway Ed25519 keys stand in for the release keys.

use ed25519_dalek::{Signer, SigningKey};
use macvpn_core::l10n::{self, AppLanguage};
use macvpn_core::swift_base64;
use macvpn_core::update::{Release, ReleaseAsset, SignatureDomain, UpdateSignature, sha256_hex};
use macvpn_platform_api::curl::http::{HttpClient, HttpError, HttpResponse};
use macvpn_platform_win::pure::update::{self as up, Notice, Verified};
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

const BASE: &str = "https://github.com/SepsiG/MacVPN/releases/download/v1.6.0";

fn asset(name: &str) -> ReleaseAsset {
    ReleaseAsset { name: name.into(), url: format!("{BASE}/{name}") }
}

/// A release as `UpdateChecker::parse_release` builds it on an x64 machine.
fn release(msi: &str, signed: bool) -> Release {
    Release {
        tag: "v1.6.0".into(),
        version: "1.6.0".into(),
        notes: String::new(),
        page_url: None,
        published_at: None,
        package: asset(msi),
        checksum: asset(&format!("{msi}.sha256")),
        signature: signed.then(|| asset(&format!("{msi}.sig"))),
    }
}

fn test_key() -> (SigningKey, [u8; 32]) {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    (key, public)
}

fn sign(key: &SigningKey, message: &[u8]) -> String {
    swift_base64::encode(&key.sign(message).to_bytes()) + "\n"
}

fn sign_msi(key: &SigningKey, asset: &str, version: &str, sha: &str) -> String {
    sign(key, &UpdateSignature::message_for(SignatureDomain::WinVpnV1, asset, version, sha).unwrap())
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("winvpn-update-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_assets_of_this_architecture_are_chosen() {
    let x64 = release("WinVPN-1.6.0-x64.msi", true);
    let a = up::assets(&x64, "x86_64").unwrap();
    assert_eq!(
        (a.msi.name.as_str(), a.sha256.name.as_str(), a.sig.name.as_str()),
        ("WinVPN-1.6.0-x64.msi", "WinVPN-1.6.0-x64.msi.sha256", "WinVPN-1.6.0-x64.msi.sig")
    );
    assert!(up::assets(&x64, "aarch64").is_none(), "an x64 package is not this arm64 machine's");
    assert!(up::assets(&x64, "x86").is_none(), "no 32-bit WinVPN");
    let arm = release("WinVPN-1.6.0-arm64.msi", true);
    assert_eq!(up::assets(&arm, "aarch64").unwrap().msi.name, "WinVPN-1.6.0-arm64.msi");
    assert!(up::assets(&release("WinVPN-1.6.0-x64.msi", false), "x86_64").is_none(), "unsigned: nothing to install");
    assert!(up::assets(&release("MacVPN-1.6.0.dmg", true), "x86_64").is_none());
    let mut odd = release("WinVPN-1.6.0-x64.msi", true);
    odd.checksum = asset("WinVPN-1.6.0-arm64.msi.sha256");
    assert!(up::assets(&odd, "x86_64").is_none(), "the side files name the same package");
}

#[test]
fn the_signature_is_checked_with_the_winvpn_domain_and_the_asset_name() {
    let (key, public) = test_key();
    let sha = "a".repeat(64);
    let sig = sign_msi(&key, "WinVPN-1.6.0-x64.msi", "1.6.0", &sha);
    assert_eq!(up::verify("WinVPN-1.6.0-x64.msi", "1.6.0", &sha, &sig, &[public]), Verified::Yes);
    // The same signature for the arm64 asset, another version, or under MacVPN's domain, is refused.
    assert_eq!(up::verify("WinVPN-1.6.0-arm64.msi", "1.6.0", &sha, &sig, &[public]), Verified::No);
    assert_eq!(up::verify("WinVPN-1.6.1-x64.msi", "1.6.1", &sha, &sig, &[public]), Verified::No);
    let mac_msg = UpdateSignature::message("1.6.0", &sha).unwrap();
    assert_eq!(up::verify("WinVPN-1.6.0-x64.msi", "1.6.0", &sha, &sign(&key, &mac_msg), &[public]), Verified::No);
    // The production check uses the embedded maintainer keys: a throwaway key never passes it.
    assert_eq!(up::verify_trusted("WinVPN-1.6.0-x64.msi", "1.6.0", &sha, &sig), Verified::No);
}

#[test]
fn the_relaunch_arguments_and_the_notice_round_trip() {
    let target = r"C:\Program Files\WinVPN\WinVPN.exe";
    let msi = r"C:\Users\u\AppData\Local\WinVPN\updates\WinVPN-1.6.0-x64.msi";
    let sha = "0123456789abcdef".repeat(4);
    let log = r"C:\Users\u\AppData\Local\WinVPN\updates\msiexec-1.6.0.log";
    let args = up::relaunch_args(target, msi, &sha, log);
    assert_eq!(args, ["--relaunch", "--target", target, "--msi", msi, "--sha256", &sha, "--log", log]);
    let parsed = up::parse_relaunch(&args).expect("parses");
    assert_eq!(
        parsed,
        up::Relaunch {
            target: PathBuf::from(target),
            msi: PathBuf::from(msi),
            sha256: sha.clone(),
            log: PathBuf::from(log)
        }
    );
    let s = |v: &[&str]| v.iter().map(|a| a.to_string()).collect::<Vec<_>>();
    let with = |i: usize, value: &str| {
        let mut a = args.clone();
        a[i] = value.to_string();
        a
    };
    for bad in [
        with(0, "--relaunch-after"),
        with(2, "WinVPN.exe"),
        with(2, r"C:\Windows\System32\cmd.exe"),
        with(2, r"C:\x\..\WinVPN.exe"),
        with(2, r"\\server\share\WinVPN.exe"),
        with(4, r"C:\u\WinVPN-1.6.0-x64.exe"),
        with(4, "WinVPN-1.6.0-x64.msi"),
        with(4, r#"C:\u\a" /qn x.msi"#),
        with(6, &sha.to_uppercase()),
        with(6, &sha[..63]),
        with(6, &format!("{}g", &sha[..63])),
        with(8, r"C:\x\other.log"),
        with(8, "msiexec-1.6.0.log"),
        s(&["--relaunch", "--target", target, "--msi", msi, "--sha256", &sha]),
        [args.clone(), s(&["extra"])].concat(),
        s(&["--target", target, "--relaunch", "--msi", msi, "--sha256", &sha, "--log", log]),
    ] {
        assert_eq!(up::parse_relaunch(&bad), None, "{bad:?}");
    }

    let n = Notice { run: "r1".into(), exit_code: 1603, log: log.into() };
    assert_eq!(Notice::parse(&n.encode()), Some(n.clone()));
    assert!(!n.ok());
    assert!(Notice { exit_code: 0, ..n.clone() }.ok());
    assert!(Notice { exit_code: 3010, ..n.clone() }.ok(), "3010: done, a restart finishes it");
    assert_eq!(Notice::parse("run=r1\nexit=1603\n"), None);
    assert_eq!(Notice::parse("run=r1\nexit=x\nlog=y\n"), None);
    assert_eq!(Notice::parse(&format!("run=r1\nexit=1\nlog={}\n", "x".repeat(5000))), None, "at most 4 KiB");
    assert_eq!(Notice::parse("run=r1\nexit=1\nlog=a\nb\n"), None);
}

/// The relauncher's handshake over its stdin and stdout (P2-L3): it answers `held` once it holds the MSI (re-hashed)
/// and the log, gets msiexec's PID as one `pid=` line, answers `waiting` once it has opened that process.
#[test]
fn the_relauncher_handshake_lines_are_strict() {
    assert_eq!(up::pid_line(4242), "pid=4242\n");
    assert_eq!(up::parse_pid_line(&up::pid_line(4242)), Some(4242));
    assert_eq!(up::parse_pid_line("pid=4242\r\n"), Some(4242));
    assert_eq!(up::parse_pid_line("pid=4242"), Some(4242));
    for bad in [
        "",
        "\n",
        "pid=",
        "pid=0\n",
        "pid=042\n",
        "pid=x\n",
        "pid=4242 \n",
        " pid=4242\n",
        "pid=99999999999\n",
        "cancel\n",
    ] {
        assert_eq!(up::parse_pid_line(bad), None, "{bad:?}");
    }
    assert_eq!((up::HELD, up::WAITING), ("held", "waiting"));
}

/// The relauncher holds only files in its own folder (the updates folder), compared as Windows does (any case).
#[test]
fn the_relauncher_holds_only_files_in_its_own_folder() {
    let dir = Path::new(r"C:\Users\u\AppData\Local\WinVPN\updates");
    assert!(up::in_folder(Path::new(r"C:\Users\u\AppData\Local\WinVPN\updates\a.msi"), dir));
    assert!(up::in_folder(Path::new(r"c:\users\U\appdata\local\winvpn\UPDATES\a.msi"), dir));
    assert!(!up::in_folder(Path::new(r"C:\Users\u\AppData\Local\WinVPN\updates\sub\a.msi"), dir));
    assert!(!up::in_folder(Path::new(r"C:\Users\u\AppData\Local\WinVPN\a.msi"), dir));
    assert!(!up::in_folder(Path::new(r"C:\Users\u\AppData\Local\WinVPN\updates2\a.msi"), dir));
    assert!(!up::in_folder(Path::new(r"C:\Users\u\AppData\Local\WinVPN\updates"), dir));
}

#[test]
fn the_failure_notice_names_the_code_and_the_log_in_both_languages() {
    let n = Notice { run: "r1".into(), exit_code: 1603, log: r"C:\u\msiexec-1.6.0.log".into() };
    let en = l10n::with_language(AppLanguage::En, || n.message()).unwrap();
    assert_eq!(en, r"The update failed (msiexec 1603). Details: C:\u\msiexec-1.6.0.log");
    let hu = l10n::with_language(AppLanguage::Hu, || n.message()).unwrap();
    assert_eq!(hu, r"A frissítés nem sikerült (msiexec 1603). Részletek: C:\u\msiexec-1.6.0.log");
    assert_eq!(Notice { exit_code: 0, ..n }.message(), None);
    let none = l10n::with_language(AppLanguage::Hu, up::no_installer_text);
    assert_eq!(none, "Ehhez a kiadáshoz nincs telepítő erre a számítógépre.");
}

/// 2.1.1 on a standard user's account: the elevated msiexec (an administrator's account) could not open its log
/// (1622) or the package (1619). Its own text, without the (empty) log.
#[test]
fn a_package_or_log_msiexec_could_not_open_has_its_own_notice() {
    for code in [1619, 1622] {
        let n = Notice { run: "r1".into(), exit_code: code, log: r"C:\u\msiexec-1.6.0.log".into() };
        let en = l10n::with_language(AppLanguage::En, || n.message()).unwrap();
        assert_eq!(
            en,
            format!(
                "The update failed: Windows Installer could not open the update's package or its log (msiexec {code}). \
                 Check for updates again, or install WinVPN from its release page."
            )
        );
        let hu = l10n::with_language(AppLanguage::Hu, || n.message()).unwrap();
        assert!(hu.starts_with("A frissítés nem sikerült: a Windows Installer"), "{hu}");
        assert!(hu.contains(&format!("(msiexec {code})")) && !hu.contains("msiexec-1.6.0.log"), "{hu}");
    }
}

#[test]
fn the_held_package_hashes_from_its_start() {
    let dir = scratch("hash");
    let path = dir.join(MSI);
    std::fs::write(&path, BODY).unwrap();
    let mut file = File::open(&path).unwrap();
    assert_eq!(up::hash(&mut file).unwrap(), sha256_hex(BODY));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn msiexec_gets_the_package_and_the_log_quoted() {
    let p = up::msiexec_parameters(Path::new(r"C:\Users\u v\WinVPN-1.6.0-x64.msi"), Path::new(r"C:\Users\u v\m.log"));
    assert_eq!(
        p.as_deref(),
        Some(r#"/i "C:\Users\u v\WinVPN-1.6.0-x64.msi" /qb! /norestart /l*v "C:\Users\u v\m.log""#)
    );
    assert_eq!(up::msiexec_parameters(Path::new(r#"C:\a"b.msi"#), Path::new(r"C:\m.log")), None);
    assert_eq!(up::msiexec_parameters(Path::new(r"a.msi"), Path::new(r"C:\m.log")), None);
    assert_eq!(up::msiexec_parameters(Path::new(r"C:\a.msi"), Path::new(r"m.log")), None);
    // Security review L-3 (the updater's elevated msiexec too): only a plain local drive path, never UNC (an SMB or
    // WebDAV logon with the administrator's token), a device path, a drive-relative path or a stream.
    for bad in [r"\\attacker\s\a.msi", r"\\?\C:\a.msi", r"\\.\C:\a.msi", r"C:a.msi", r"C:\a.msi:s", r"C:\x\..\a.msi"] {
        assert_eq!(up::msiexec_parameters(Path::new(bad), Path::new(r"C:\m.log")), None, "{bad}");
        assert_eq!(up::msiexec_parameters(Path::new(r"C:\a.msi"), Path::new(bad)), None, "{bad}");
    }
}

// MARK: - Download and verify over a scripted HTTP client

/// Answers by URL; `download` writes the body to a fresh file in `dir`.
struct Scripted {
    dir: PathBuf,
    answers: HashMap<String, (i64, Vec<u8>)>,
    asked: Mutex<Vec<String>>,
}

impl Scripted {
    fn new(dir: &Path) -> Scripted {
        Scripted { dir: dir.to_path_buf(), answers: HashMap::new(), asked: Mutex::new(Vec::new()) }
    }

    fn answer(mut self, name: &str, status: i64, body: &[u8]) -> Scripted {
        self.answers.insert(format!("{BASE}/{name}"), (status, body.to_vec()));
        self
    }
}

impl HttpClient for Scripted {
    fn get(&self, url: &str) -> Result<HttpResponse, HttpError> {
        self.asked.lock().unwrap().push(url.to_string());
        let (status, data) = self.answers.get(url).cloned().unwrap_or((404, Vec::new()));
        Ok(HttpResponse { status, data })
    }

    fn download(&self, url: &str) -> Result<(PathBuf, i64), HttpError> {
        self.asked.lock().unwrap().push(url.to_string());
        let (status, data) = self.answers.get(url).cloned().unwrap_or((404, Vec::new()));
        let file = self.dir.join(format!("dl-{}", self.asked.lock().unwrap().len()));
        std::fs::write(&file, data).unwrap();
        Ok((file, status))
    }
}

const MSI: &str = "WinVPN-1.6.0-x64.msi";
const BODY: &[u8] = b"an MSI package";

fn served(dir: &Path, sha: &str, sig: Option<&str>) -> Scripted {
    let http = Scripted::new(dir).answer(MSI, 200, BODY).answer(
        &format!("{MSI}.sha256"),
        200,
        format!("{sha}  {MSI}\n").as_bytes(),
    );
    match sig {
        Some(s) => http.answer(&format!("{MSI}.sig"), 200, s.as_bytes()),
        None => http,
    }
}

fn run(http: &Scripted, updates: &Path, public: [u8; 32]) -> Result<up::HeldMsi, String> {
    let verify =
        move |asset: &str, version: &str, sha: &str, sig: &str| up::verify(asset, version, sha, sig, &[public]);
    up::download_verified(http, &release(MSI, true), "x86_64", updates, &|p: &Path| File::open(p), &verify)
}

#[test]
fn a_signed_package_is_downloaded_moved_and_held() {
    let (key, public) = test_key();
    let dir = scratch("ok");
    let updates = dir.join("updates");
    std::fs::create_dir(&updates).unwrap();
    let sha = sha256_hex(BODY);
    let http = served(&dir, &sha, Some(&sign_msi(&key, MSI, "1.6.0", &sha)));
    let held = run(&http, &updates, public).unwrap();
    assert_eq!(held.path, updates.join(MSI));
    assert_eq!(held.sha256, sha);
    assert_eq!(std::fs::read(&held.path).unwrap(), BODY);
    // The side files first, then the package; only canonical github.com URLs.
    let asked = http.asked.lock().unwrap().clone();
    assert_eq!(asked, [format!("{BASE}/{MSI}.sha256"), format!("{BASE}/{MSI}.sig"), format!("{BASE}/{MSI}")]);
    // The temporary download is gone (moved).
    let left: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(left, ["updates"]);
    drop(held);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_bad_checksum_or_signature_deletes_the_package() {
    let (key, public) = test_key();
    let sha = sha256_hex(BODY);
    let cases: Vec<(&str, Scripted, String)> = {
        let d = |n: &str| scratch(n);
        let (d1, d2, d3, d4, d5) = (d("sum"), d("sig"), d("mac"), d("nosig"), d("arm"));
        vec![
            (
                "checksum",
                served(&d1, &"b".repeat(64), Some(&sign_msi(&key, MSI, "1.6.0", &"b".repeat(64)))),
                macvpn_core::update::UpdateError::ChecksumMismatch.message(),
            ),
            (
                "signature by another key",
                served(&d2, &sha, Some(&sign_msi(&SigningKey::from_bytes(&[9; 32]), MSI, "1.6.0", &sha))),
                macvpn_core::update::UpdateError::UnsignedUpdate.message(),
            ),
            (
                "MacVPN's domain",
                served(&d3, &sha, Some(&sign(&key, &UpdateSignature::message("1.6.0", &sha).unwrap()))),
                macvpn_core::update::UpdateError::UnsignedUpdate.message(),
            ),
            ("no .sig", served(&d4, &sha, None), macvpn_core::update::UpdateError::UnsignedUpdate.message()),
            (
                "the arm64 asset's signature",
                served(&d5, &sha, Some(&sign_msi(&key, "WinVPN-1.6.0-arm64.msi", "1.6.0", &sha))),
                macvpn_core::update::UpdateError::UnsignedUpdate.message(),
            ),
        ]
    };
    for (what, http, expected) in cases {
        let updates = http.dir.join("updates");
        std::fs::create_dir(&updates).unwrap();
        let err = run(&http, &updates, public).err().unwrap_or_else(|| panic!("{what}: accepted"));
        assert_eq!(err, expected, "{what}");
        assert_eq!(std::fs::read_dir(&updates).unwrap().count(), 0, "{what}: the package is deleted");
        std::fs::remove_dir_all(&http.dir).unwrap();
    }
}

#[test]
fn a_release_without_this_machines_installer_or_with_a_foreign_url_is_refused() {
    let (_, public) = test_key();
    let dir = scratch("refused");
    let http = Scripted::new(&dir);
    let verify = move |a: &str, v: &str, s: &str, g: &str| up::verify(a, v, s, g, &[public]);
    let hold = |p: &Path| File::open(p);
    let err = up::download_verified(&http, &release(MSI, true), "aarch64", &dir, &hold, &verify).err().unwrap();
    assert_eq!(err, up::no_installer_text());
    let mut foreign = release(MSI, true);
    foreign.package.url = format!("https://example.com/{MSI}");
    let err = up::download_verified(&http, &foreign, "x86_64", &dir, &hold, &verify).err().unwrap();
    assert!(err.contains("example.com"), "{err}");
    assert!(http.asked.lock().unwrap().is_empty(), "nothing is requested");
    std::fs::remove_dir_all(&dir).unwrap();
}

// MARK: - Launch housekeeping

#[test]
fn housekeeping_reports_a_failure_once_and_cleans_up() {
    let dir = scratch("house");
    let log = dir.join("msiexec-1.6.0.log");
    let failed = Notice { run: "run-1".into(), exit_code: 1603, log: log.to_string_lossy().into_owned() };
    std::fs::write(dir.join(up::NOTICE_FILE), failed.encode()).unwrap();
    std::fs::write(dir.join(MSI), b"x").unwrap();
    std::fs::write(dir.join(up::RELAUNCHER), b"x").unwrap();
    std::fs::write(&log, b"fresh").unwrap();
    let old = dir.join("msiexec-1.5.9.log");
    std::fs::write(&old, b"old").unwrap();
    File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_secs(8 * 86_400))
        .unwrap();
    std::fs::write(dir.join("unrelated.txt"), b"x").unwrap();

    let (removed, notice) = up::housekeeping(&dir, None, SystemTime::now());
    let (run, message) = notice.unwrap();
    assert_eq!(run, "run-1");
    assert_eq!(message, failed.message().unwrap());
    let mut removed: Vec<String> =
        removed.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect();
    removed.sort();
    assert_eq!(removed, [MSI, up::RELAUNCHER, "last-update.txt", "msiexec-1.5.9.log"]);
    assert!(log.exists(), "a log the notice names stays for 7 days");
    assert!(dir.join("unrelated.txt").exists());

    // Read once: the next launch has nothing to say.
    assert_eq!(up::housekeeping(&dir, Some("run-1"), SystemTime::now()).1, None);
    // A run already noticed, or a success, says nothing either.
    std::fs::write(dir.join(up::NOTICE_FILE), failed.encode()).unwrap();
    assert_eq!(up::housekeeping(&dir, Some("run-1"), SystemTime::now()).1, None);
    let ok = Notice { exit_code: 0, ..failed.clone() };
    std::fs::write(dir.join(up::NOTICE_FILE), ok.encode()).unwrap();
    assert_eq!(up::housekeeping(&dir, None, SystemTime::now()).1, None);
    assert!(!dir.join(up::NOTICE_FILE).exists());
    // A missing folder: nothing.
    assert_eq!(up::housekeeping(&dir.join("none"), None, SystemTime::now()), (Vec::new(), None));
    std::fs::remove_dir_all(&dir).unwrap();
}
