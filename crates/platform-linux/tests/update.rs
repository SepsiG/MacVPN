//! LinVPN's updater, its portable parts (every OS): the `.deb` of this architecture with its `.sha256` and `.sig`,
//! the download-and-verify flow over a scripted HTTP client (throwaway Ed25519 keys stand in for the release keys),
//! the outcome notice, the root step's exit codes as messages, the launch housekeeping and the update source.

use ed25519_dalek::{Signer, SigningKey};
use macvpn_core::TargetOs;
use macvpn_core::deb_update::{self, StepError};
use macvpn_core::l10n::{self, AppLanguage, TextPlatform, with_language};
use macvpn_core::swift_base64;
use macvpn_core::update::{
    InfoValue, Release, ReleaseAsset, SignatureDomain, UpdateChecker, UpdateError, UpdateSignature, sha256_hex,
};
use macvpn_platform_api::LINVPN;
use macvpn_platform_api::curl::http::{HttpClient, HttpError, HttpResponse};
use macvpn_platform_linux::pure::update::{self as up, Notice, Outcome};
use macvpn_platform_linux::pure::update_check;
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

const LINUX: TextPlatform = TextPlatform { os: TargetOs::Linux, product: "LinVPN" };
const BASE: &str = "https://github.com/SepsiG/MacVPN/releases/download/v2.1.0";
const DEB: &str = "linvpn_2.1.0_amd64.deb";
const BODY: &[u8] = b"a .deb package";

fn asset(name: &str) -> ReleaseAsset {
    ReleaseAsset { name: name.into(), url: format!("{BASE}/{name}") }
}

/// A release as `UpdateChecker::parse_release` builds it on an amd64 machine.
fn release(deb: &str, signed: bool) -> Release {
    Release {
        tag: "v2.1.0".into(),
        version: "2.1.0".into(),
        notes: String::new(),
        page_url: None,
        published_at: None,
        package: asset(deb),
        checksum: asset(&format!("{deb}.sha256")),
        signature: signed.then(|| asset(&format!("{deb}.sig"))),
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

fn sign_deb(key: &SigningKey, asset: &str, version: &str, sha: &str) -> String {
    sign(key, &UpdateSignature::message_for(SignatureDomain::LinVpnV1, asset, version, sha).unwrap())
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("linvpn-update-test-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_assets_of_this_architecture_are_chosen() {
    let amd = release(DEB, true);
    let a = up::assets(&amd, "x86_64").unwrap();
    assert_eq!(
        (a.deb.name.as_str(), a.sha256.name.as_str(), a.sig.name.as_str()),
        (DEB, "linvpn_2.1.0_amd64.deb.sha256", "linvpn_2.1.0_amd64.deb.sig")
    );
    assert!(up::assets(&amd, "aarch64").is_none(), "an amd64 package is not this arm64 machine's");
    assert!(up::assets(&amd, "riscv64").is_none());
    let arm = release("linvpn_2.1.0_arm64.deb", true);
    assert_eq!(up::assets(&arm, "aarch64").unwrap().deb.name, "linvpn_2.1.0_arm64.deb");
    assert!(up::assets(&release(DEB, false), "x86_64").is_none(), "unsigned: nothing to install");
    assert!(up::assets(&release("WinVPN-2.1.0-x64.msi", true), "x86_64").is_none());
    let mut odd = release(DEB, true);
    odd.checksum = asset("linvpn_2.1.0_arm64.deb.sha256");
    assert!(up::assets(&odd, "x86_64").is_none(), "the side files name the same package");
}

#[test]
fn the_product_and_the_root_step_name_the_same_asset() {
    for arch in ["x86_64", "aarch64", "riscv64"] {
        assert_eq!(
            LINVPN.update_asset("2.1.0", arch),
            deb_update::deb_arch(arch).map(|a| deb_update::asset("2.1.0", a)),
            "{arch}"
        );
    }
}

#[test]
fn the_notice_round_trips() {
    let ok = Notice::Installed { version: "2.1.0".into() };
    let failed = Notice::Failed { version: "2.1.0".into(), code: 13 };
    assert_eq!(up::notice_line(&ok), "ok 2.1.0");
    assert_eq!(up::notice_line(&failed), "failed 2.1.0 13");
    assert_eq!(up::parse_notice("ok 2.1.0"), Some(ok.clone()));
    assert_eq!(up::parse_notice("ok 2.1.0\n"), Some(ok));
    assert_eq!(up::parse_notice("failed 2.1.0 13\n"), Some(failed));
    for bad in ["", "ok", "ok 2.1", "ok 2.1.0 1", "failed 2.1.0", "failed 2.1.0 x", "failed 2.1.0 -1", "done 2.1.0"] {
        assert_eq!(up::parse_notice(bad), None, "{bad:?}");
    }
    assert_eq!(up::parse_notice(&format!("ok 2.1.0{}", " ".repeat(5000))), None, "too long");
}

#[test]
fn the_root_steps_exit_code_is_the_outcome() {
    l10n::set_text_platform(LINUX);
    assert_eq!(up::outcome(0), Outcome::Installed);
    assert_eq!(up::outcome(126), Outcome::Cancelled, "the dialog was dismissed");
    assert_eq!(up::outcome(127), Outcome::Cancelled, "not authorized");
    let en = |code| with_language(AppLanguage::En, || up::outcome(code));
    assert_eq!(
        en(StepError::BadSignature.code()),
        Outcome::Failed(
            "The update was not installed: its signature or package did not pass the checks (code 13).".into()
        )
    );
    assert_eq!(
        en(StepError::InstallFailed.code()),
        Outcome::Failed("The update was not installed: apt reported an error (code 19).".into())
    );
    assert_eq!(
        with_language(AppLanguage::Hu, || up::outcome(StepError::NotNewer.code())),
        Outcome::Failed(
            "A frissítés nem települt: az aláírása vagy a csomagja nem ment át az ellenőrzésen (kód: 17).".into()
        )
    );
    for code in [1, 2, 9, 125, 255] {
        let Outcome::Failed(message) = en(code) else { panic!("{code}") };
        assert!(message.contains(&code.to_string()), "{message}");
    }
}

#[test]
fn the_success_text_names_the_version() {
    l10n::set_text_platform(LINUX);
    assert_eq!(with_language(AppLanguage::En, || up::updated_text("2.1.0")), "LinVPN was updated to 2.1.0.");
    assert_eq!(
        with_language(AppLanguage::Hu, || up::updated_text("2.1.0")),
        "A LinVPN frissült erre a verzióra: 2.1.0."
    );
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

fn served(dir: &Path, sha: &str, sig: Option<&str>) -> Scripted {
    let http = Scripted::new(dir).answer(DEB, 200, BODY).answer(
        &format!("{DEB}.sha256"),
        200,
        format!("{sha}  {DEB}\n").as_bytes(),
    );
    match sig {
        Some(s) => http.answer(&format!("{DEB}.sig"), 200, s.as_bytes()),
        None => http,
    }
}

fn run(http: &Scripted, updates: &Path, public: [u8; 32]) -> Result<up::Downloaded, String> {
    up::download_verified(http, &release(DEB, true), "x86_64", updates, &[public])
}

#[test]
fn a_signed_package_is_downloaded_and_kept_with_its_signature() {
    let (key, public) = test_key();
    let dir = scratch("ok");
    let updates = dir.join("updates");
    std::fs::create_dir(&updates).unwrap();
    let sha = sha256_hex(BODY);
    let sig = sign_deb(&key, DEB, "2.1.0", &sha);
    let http = served(&dir, &sha, Some(&sig));
    let got = run(&http, &updates, public).unwrap();
    assert_eq!(got.deb, updates.join(DEB));
    assert_eq!(got.sig, updates.join(format!("{DEB}.sig")));
    assert_eq!(got.sha256, sha);
    assert_eq!(std::fs::read(&got.deb).unwrap(), BODY);
    assert_eq!(std::fs::read_to_string(&got.sig).unwrap(), sig);
    #[cfg(unix)]
    for file in [&got.deb, &got.sig] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(file).unwrap().permissions().mode() & 0o777, 0o600, "{}", file.display());
    }
    // The side files first, then the package; only canonical github.com URLs.
    let asked = http.asked.lock().unwrap().clone();
    assert_eq!(asked, [format!("{BASE}/{DEB}.sha256"), format!("{BASE}/{DEB}.sig"), format!("{BASE}/{DEB}")]);
    // The temporary download is gone.
    let left: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(left, ["updates"]);
    // A second run replaces the files of the first.
    let again = run(&http, &updates, public).unwrap();
    assert_eq!(std::fs::read(&again.deb).unwrap(), BODY);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_bad_checksum_or_signature_deletes_the_package() {
    let (key, public) = test_key();
    let sha = sha256_hex(BODY);
    let other = "b".repeat(64);
    let cases: Vec<(&str, Scripted, String)> = vec![
        (
            "checksum",
            served(&scratch("sum"), &other, Some(&sign_deb(&key, DEB, "2.1.0", &other))),
            UpdateError::ChecksumMismatch.message(),
        ),
        (
            "signature by another key",
            served(&scratch("sig"), &sha, Some(&sign_deb(&SigningKey::from_bytes(&[9; 32]), DEB, "2.1.0", &sha))),
            UpdateError::UnsignedUpdate.message(),
        ),
        (
            "WinVPN's domain",
            served(
                &scratch("win"),
                &sha,
                Some(&sign(
                    &key,
                    &UpdateSignature::message_for(SignatureDomain::WinVpnV1, "WinVPN-2.1.0-x64.msi", "2.1.0", &sha)
                        .unwrap(),
                )),
            ),
            UpdateError::UnsignedUpdate.message(),
        ),
        ("no .sig", served(&scratch("nosig"), &sha, None), UpdateError::UnsignedUpdate.message()),
        (
            "the arm64 asset's signature",
            served(&scratch("arm"), &sha, Some(&sign_deb(&key, "linvpn_2.1.0_arm64.deb", "2.1.0", &sha))),
            UpdateError::UnsignedUpdate.message(),
        ),
    ];
    for (what, http, expected) in cases {
        let updates = http.dir.join("updates");
        std::fs::create_dir(&updates).unwrap();
        let err = run(&http, &updates, public).err().unwrap_or_else(|| panic!("{what}: accepted"));
        assert_eq!(err, expected, "{what}");
        assert_eq!(std::fs::read_dir(&updates).unwrap().count(), 0, "{what}: nothing is kept");
        std::fs::remove_dir_all(&http.dir).unwrap();
    }
}

#[test]
fn a_release_without_this_machines_package_or_with_a_foreign_url_is_refused() {
    let (_, public) = test_key();
    let dir = scratch("refused");
    let http = Scripted::new(&dir);
    let err = up::download_verified(&http, &release(DEB, true), "aarch64", &dir, &[public]).err().unwrap();
    assert_eq!(err, up::no_package_text());
    let mut foreign = release(DEB, true);
    foreign.package.url = format!("https://example.com/{DEB}");
    let err = up::download_verified(&http, &foreign, "x86_64", &dir, &[public]).err().unwrap();
    assert!(err.contains("example.com"), "{err}");
    assert!(http.asked.lock().unwrap().is_empty(), "nothing is requested");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn other_versions_are_removed_before_a_download() {
    let dir = scratch("stale");
    for name in [
        "linvpn_2.0.9_amd64.deb",
        "linvpn_2.0.9_amd64.deb.sig",
        "linvpn_2.0.9_amd64.deb.sha256",
        DEB,
        "install-2.0.9.log",
        "notes.txt",
    ] {
        std::fs::write(dir.join(name), b"x").unwrap();
    }
    std::fs::create_dir(dir.join("linvpn_1.0.0_amd64.deb")).unwrap();
    let mut removed: Vec<String> = up::remove_other_versions(&dir, DEB)
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    removed.sort();
    assert_eq!(removed, ["linvpn_2.0.9_amd64.deb", "linvpn_2.0.9_amd64.deb.sha256", "linvpn_2.0.9_amd64.deb.sig"]);
    assert!(dir.join(DEB).exists() && dir.join("install-2.0.9.log").exists() && dir.join("notes.txt").exists());
    assert!(dir.join("linvpn_1.0.0_amd64.deb").is_dir(), "only regular files are touched");
    std::fs::remove_dir_all(&dir).unwrap();
}

// MARK: - Launch housekeeping

#[test]
fn housekeeping_reports_a_failure_once_and_cleans_up() {
    l10n::set_text_platform(LINUX);
    let dir = scratch("house");
    let failed = Notice::Failed { version: "2.1.0".into(), code: 19 };
    std::fs::write(dir.join(up::NOTICE_FILE), up::notice_line(&failed)).unwrap();
    for name in [DEB, "linvpn_2.1.0_amd64.deb.sig", "linvpn_2.1.0_amd64.deb.sha256", "install-2.1.0.log"] {
        std::fs::write(dir.join(name), b"x").unwrap();
    }
    let old = dir.join("install-2.0.9.log");
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
    assert_eq!(run, "failed 2.1.0 19");
    let Outcome::Failed(expected) = up::outcome(19) else { panic!() };
    assert_eq!(message, expected);
    let mut removed: Vec<String> =
        removed.iter().map(|p| p.file_name().unwrap().to_string_lossy().into_owned()).collect();
    removed.sort();
    assert_eq!(
        removed,
        ["install-2.0.9.log", DEB, "linvpn_2.1.0_amd64.deb.sha256", "linvpn_2.1.0_amd64.deb.sig", up::NOTICE_FILE,]
    );
    assert!(dir.join("install-2.1.0.log").exists(), "a fresh log stays for 7 days");
    assert!(dir.join("unrelated.txt").exists());

    // Read once: the next launch has nothing to say.
    assert_eq!(up::housekeeping(&dir, Some(&run), SystemTime::now()).1, None);
    // A run already noticed says nothing either, nor a success (the window's title is "did not complete").
    std::fs::write(dir.join(up::NOTICE_FILE), up::notice_line(&failed)).unwrap();
    assert_eq!(up::housekeeping(&dir, Some(&run), SystemTime::now()).1, None);
    std::fs::write(dir.join(up::NOTICE_FILE), "ok 2.1.0\n").unwrap();
    assert_eq!(up::housekeeping(&dir, None, SystemTime::now()).1, None);
    assert!(!dir.join(up::NOTICE_FILE).exists());
    // The success is the installed version instead ("LinVPN was updated to 2.1.0."), once; a failure is none.
    std::fs::write(dir.join(up::NOTICE_FILE), "ok 2.1.0\n").unwrap();
    let (_, failure, installed) = up::housekeeping_with_installed(&dir, None, SystemTime::now());
    assert_eq!((failure, installed.as_deref()), (None, Some("2.1.0")));
    assert_eq!(up::housekeeping_with_installed(&dir, None, SystemTime::now()).2, None);
    std::fs::write(dir.join(up::NOTICE_FILE), up::notice_line(&failed)).unwrap();
    assert_eq!(up::housekeeping_with_installed(&dir, None, SystemTime::now()).2, None);
    std::fs::write(dir.join(up::NOTICE_FILE), "ok garbage\n").unwrap();
    assert_eq!(up::housekeeping_with_installed(&dir, None, SystemTime::now()).2, None);
    // A missing folder: nothing.
    assert_eq!(up::housekeeping(&dir.join("none"), None, SystemTime::now()), (Vec::new(), None));
    std::fs::remove_dir_all(&dir).unwrap();
}

// MARK: - The update source

#[test]
fn an_installed_linvpn_names_the_repository_and_its_id() {
    let info = update_check::update_info();
    assert_eq!(info.get(UpdateChecker::INFO_PLIST_KEY), Some(&InfoValue::String("SepsiG/MacVPN".into())));
    assert_eq!(
        UpdateChecker::source_from_info(Some(&info)),
        Some((update_check::UPDATE_REPO_ID, "SepsiG/MacVPN".into()))
    );
}

/// GitHub's `releases/latest` answer with both architectures' packages.
fn latest_json() -> String {
    let assets: Vec<String> = ["amd64", "arm64"]
        .iter()
        .flat_map(|a| {
            let deb = format!("linvpn_2.1.0_{a}.deb");
            [deb.clone(), format!("{deb}.sha256"), format!("{deb}.sig")]
        })
        .map(|name| format!(r#"{{"name":"{name}","browser_download_url":"{BASE}/{name}"}}"#))
        .collect();
    format!(
        r#"{{"tag_name":"v2.1.0","body":"","html_url":"https://github.com/SepsiG/MacVPN/releases/tag/v2.1.0","published_at":"2026-10-01T00:00:00Z","assets":[{}]}}"#,
        assets.join(",")
    )
}

struct Latest(Mutex<Vec<String>>);

impl HttpClient for Latest {
    fn get(&self, url: &str) -> Result<HttpResponse, HttpError> {
        self.0.lock().unwrap().push(url.to_string());
        Ok(HttpResponse::new(200, latest_json().as_bytes()))
    }

    fn download(&self, _url: &str) -> Result<(PathBuf, i64), HttpError> {
        unreachable!("the check downloads nothing")
    }
}

#[test]
fn the_latest_release_carries_this_machines_package() {
    let http = Latest(Mutex::new(Vec::new()));
    let r = update_check::latest_release(&http, update_check::UPDATE_REPO_ID, "SepsiG/MacVPN", "aarch64").unwrap();
    assert_eq!(r.version, "2.1.0");
    assert_eq!(r.package.name, "linvpn_2.1.0_arm64.deb");
    assert_eq!(r.checksum.name, "linvpn_2.1.0_arm64.deb.sha256");
    assert_eq!(r.signature.unwrap().name, "linvpn_2.1.0_arm64.deb.sig");
    assert_eq!(*http.0.lock().unwrap(), [UpdateChecker::latest_release_url(update_check::UPDATE_REPO_ID)]);
    assert!(update_check::latest_release(&http, update_check::UPDATE_REPO_ID, "SepsiG/MacVPN", "riscv64").is_err());
}
