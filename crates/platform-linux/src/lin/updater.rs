//! The LinVPN updater (LinVPN plan, Task 20; spec 7: a signed `.deb`, installed through pkexec).
//!
//! `install` (first of all: the root step and the polkit action must be installed, a regular executable file and a
//! regular file; if not, the helper error at once and no download or prompt, since pkexec would answer 127, the same
//! as "not authorized"):
//! 1. the `.deb` of this architecture, its `.sha256` and `.sig` through `/usr/bin/curl` (the shared curl layer:
//!    canonical github.com URLs, checked redirects) into the private updates folder `$XDG_CACHE_HOME/LinVPN/updates`
//!    (0700; the files 0600; other versions' packages removed first);
//! 2. the hash equals the `.sha256` and the maintainer's signature verifies under LinVPN's domain and the asset's
//!    name (`pure::update`), for the user's messages;
//! 3. the quit questions;
//! 4. `/usr/bin/pkexec /usr/libexec/linvpn/linvpn-install-update --deb … --sig … --version … --asset …` (the polkit
//!    action `local.linvpn.update`, the administrator's password), its output appended to `install-<version>.log`
//!    in the updates folder. The root step trusts none of this: it copies the package into a root-owned folder and
//!    checks signature, name, architecture and version again on its copy before `apt-get install`;
//! 5. exit 0: the notice `ok <version>` for the next launch, `/usr/bin/linvpn --after-update` started detached (its
//!    own process group, no stdio), `HelperLaunched` (the app quits now; the new process waits for the single
//!    instance name). pkexec's 126 (dismissed) or 127 (not authorized, with the step and the action still in place):
//!    `Cancelled`, nothing installed; 127 with either gone is the helper error. Another code:
//!    the root step's refusal or apt's failure as the localized error (shown at once, so no launch notice).
//!
//! The package and its signature are removed after pkexec returns; the launch housekeeping removes any leftover.

use super::curl_runner;
use crate::pure::paths::Xdg;
use crate::pure::update::{self as up, Notice, Outcome};
use macvpn_core::deb_update;
use macvpn_core::fsx::{self, Access};
use macvpn_core::l10n;
use macvpn_core::update::{Release, UpdateError, UpdateSignature};
use macvpn_platform_api::curl::http::HttpClient;
use macvpn_platform_api::{UpdateOutcome, Updater};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock, PoisonError};

const PKEXEC: &str = "/usr/bin/pkexec";
/// The root step (the `.deb`'s file; the polkit action's `exec.path`).
const STEP: &str = "/usr/libexec/linvpn/linvpn-install-update";
/// The polkit action the step runs under (the `.deb`'s file).
const ACTION: &str = "/usr/share/polkit-1/actions/local.linvpn.update.policy";
/// The installed LinVPN, started again after the update.
const RELAUNCH: &str = "/usr/bin/linvpn";
/// The new process's argument (it waits for this one's single-instance name).
pub(crate) const AFTER_UPDATE: &str = "--after-update";

/// The updater of an installed LinVPN.
pub(crate) struct LinUpdater {
    pkexec: PathBuf,
    step: PathBuf,
    action: PathBuf,
    relaunch: PathBuf,
    keys: Vec<[u8; 32]>,
    http: Box<dyn HttpClient>,
    /// The updates folder from `Xdg::sandbox(home)` instead of the environment (tests).
    home_only: bool,
    /// The version the launch housekeeping found installed (`ok <version>`), until it is taken.
    updated: Mutex<Option<String>>,
}

/// The production updater (one per process).
pub(crate) fn installed() -> &'static LinUpdater {
    static UPDATER: OnceLock<LinUpdater> = OnceLock::new();
    UPDATER.get_or_init(|| LinUpdater {
        pkexec: PKEXEC.into(),
        step: STEP.into(),
        action: ACTION.into(),
        relaunch: RELAUNCH.into(),
        keys: UpdateSignature::trusted_keys(),
        http: Box::new(curl_runner::download_client()),
        home_only: false,
        updated: Mutex::new(None),
    })
}

impl LinUpdater {
    /// Tests: fake pkexec, root step, polkit action and relaunch, throwaway keys, a scripted HTTP client, everything under `home`.
    #[doc(hidden)]
    #[cfg(test)]
    pub(crate) fn for_tests(
        pkexec: PathBuf,
        step: PathBuf,
        action: PathBuf,
        relaunch: PathBuf,
        keys: Vec<[u8; 32]>,
        http: Box<dyn HttpClient>,
    ) -> LinUpdater {
        LinUpdater { pkexec, step, action, relaunch, keys, http, home_only: true, updated: Mutex::new(None) }
    }

    /// `$XDG_CACHE_HOME/LinVPN/updates`.
    fn updates_dir(&self, home: &Path) -> PathBuf {
        let xdg = if self.home_only { Xdg::sandbox(home) } else { Xdg::from_env(home, |k| std::env::var_os(k)) };
        xdg.updates_dir()
    }

    /// The root step (a regular, executable file) and its polkit action (a regular file) are installed; else the
    /// helper error naming the missing one (`HelperFailed`, the existing text).
    fn installed_parts(&self) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;
        let check = |path: &Path, executable: bool| match std::fs::metadata(path) {
            Ok(m) if m.is_file() && (!executable || m.permissions().mode() & 0o111 != 0) => Ok(()),
            Ok(_) => Err(UpdateError::HelperFailed(format!("{}: not usable", path.display())).message()),
            Err(e) => Err(UpdateError::HelperFailed(format!("{}: {e}", path.display())).message()),
        };
        check(&self.step, true)?;
        check(&self.action, false)
    }

    /// pkexec and the root step; the step's exit code (`-1`: ended by a signal).
    fn run_step(&self, got: &up::Downloaded, release: &Release, asset: &str, log: &Path) -> Result<i32, String> {
        let failed = |e: std::io::Error| UpdateError::HelperFailed(e.to_string()).message();
        let out = fsx::open_append(log, Access::Private).map_err(failed)?;
        let err = out.try_clone().map_err(failed)?;
        let status = Command::new(&self.pkexec)
            .arg(&self.step)
            .args(deb_update::step_args(&got.deb, &got.sig, &release.version, asset))
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(out)
            .stderr(err)
            .status()
            .map_err(|e| UpdateError::HelperFailed(format!("{}: {e}", self.pkexec.display())).message())?;
        Ok(status.code().unwrap_or(-1))
    }

    /// The notice `ok <version>` in the updates folder `dir`, for the next launch.
    fn record_installed(&self, dir: &Path, version: &str) {
        let notice = up::notice_line(&Notice::Installed { version: version.to_string() });
        if let Err(e) = fsx::atomic_write(&dir.join(up::NOTICE_FILE), notice.as_bytes(), Access::Private) {
            eprintln!("LinVPN: the update's outcome could not be recorded: {e}");
        }
    }

    /// The package was upgraded (or downgraded) to `version` from outside the app (`lin::package_watch`): the same
    /// notice and relaunch as an installed update; the caller quits.
    pub(crate) fn restart_after_package(&self, home: &Path, version: &str) {
        let dir = self.updates_dir(home);
        match prepare(&dir) {
            Ok(()) => self.record_installed(&dir, version),
            Err(e) => eprintln!("LinVPN: the update's outcome could not be recorded: {e}"),
        }
        self.relaunch();
    }

    /// `/usr/bin/linvpn --after-update`, detached (its own process group, no stdio).
    fn relaunch(&self) {
        let started = Command::new(&self.relaunch)
            .arg(AFTER_UPDATE)
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn();
        if let Err(e) = started {
            eprintln!("LinVPN: the updated app could not be started ({}): {e}", self.relaunch.display());
        }
    }
}

/// The updates folder, created private (0700); anything but a directory of this user there is refused.
fn prepare(dir: &Path) -> Result<(), String> {
    let refused = |e: std::io::Error| format!("{}: {e}", dir.display());
    fsx::create_private_dir_all(dir).map_err(refused)?;
    fsx::ensure_private_dir(dir).map(|_| ()).map_err(refused)
}

impl Updater for LinUpdater {
    fn install(
        &self,
        release: &Release,
        _app: &Path,
        home: &Path,
        stage: &dyn Fn(String),
        confirm_quit: Box<dyn FnOnce() -> bool + '_>,
    ) -> Result<UpdateOutcome, String> {
        let arch = std::env::consts::ARCH;
        let asset = up::assets(release, arch).ok_or_else(up::no_package_text)?.deb.name.clone();
        self.installed_parts()?;
        let dir = self.updates_dir(home);
        prepare(&dir)?;
        up::remove_other_versions(&dir, &asset);
        stage(l10n::tr("Downloading…", &[]));
        let got = up::download_verified(self.http.as_ref(), release, arch, &dir, &self.keys)?;
        let remove = || {
            let _ = std::fs::remove_file(&got.deb);
            let _ = std::fs::remove_file(&got.sig);
        };
        stage(l10n::tr("Quitting and restarting…", &[]));
        if !confirm_quit() {
            remove();
            return Ok(UpdateOutcome::Cancelled);
        }
        stage(l10n::tr("Installing…", &[]));
        let code = self.run_step(&got, release, &asset, &dir.join(up::log_name(&release.version)));
        remove();
        let code = code?;
        if code == 127 {
            // pkexec's 127 is also "the program could not be run": only a refusal while both parts are in place.
            self.installed_parts()?;
        }
        match up::outcome(code) {
            Outcome::Installed => {
                self.record_installed(&dir, &release.version);
                self.relaunch();
                Ok(UpdateOutcome::HelperLaunched)
            }
            Outcome::Cancelled => Ok(UpdateOutcome::Cancelled),
            Outcome::Failed(message) => Err(message),
        }
    }

    fn launch_housekeeping(
        &self,
        _app: &Path,
        home: &Path,
        noticed: Option<&str>,
    ) -> (Vec<PathBuf>, Option<(String, String)>) {
        let (removed, failure, installed) =
            up::housekeeping_with_installed(&self.updates_dir(home), noticed, std::time::SystemTime::now());
        if installed.is_some() {
            *self.updated.lock().unwrap_or_else(PoisonError::into_inner) = installed;
        }
        (removed, failure)
    }

    /// "LinVPN was updated to X.Y.Z." once after the relaunch (an in-app update, or a package installed with apt).
    fn take_updated_notice(&self) -> Option<String> {
        let version = self.updated.lock().unwrap_or_else(PoisonError::into_inner).take()?;
        Some(up::updated_text(&version))
    }

    /// `$XDG_CACHE_HOME/LinVPN/updates`.
    fn cache_directory(&self, home: &Path) -> Option<PathBuf> {
        Some(self.updates_dir(home))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use macvpn_core::update::{ReleaseAsset, SignatureDomain, sha256_hex};
    use macvpn_platform_api::LINVPN;
    use macvpn_platform_api::curl::http::{HttpError, HttpResponse};
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    const BASE: &str = "https://github.com/SepsiG/MacVPN/releases/download/v2.1.0";
    const BODY: &[u8] = b"a .deb package";

    fn deb() -> String {
        LINVPN.update_asset("2.1.0", std::env::consts::ARCH).expect("an amd64 or arm64 machine")
    }

    fn asset(name: &str) -> ReleaseAsset {
        ReleaseAsset { name: name.into(), url: format!("{BASE}/{name}") }
    }

    fn release() -> Release {
        let deb = deb();
        Release {
            tag: "v2.1.0".into(),
            version: "2.1.0".into(),
            notes: String::new(),
            page_url: None,
            published_at: None,
            package: asset(&deb),
            checksum: asset(&format!("{deb}.sha256")),
            signature: Some(asset(&format!("{deb}.sig"))),
        }
    }

    /// Serves the package, its `.sha256` (`sha`) and a signature with the throwaway key; downloads land in `dir`.
    struct Served {
        dir: PathBuf,
        answers: HashMap<String, Vec<u8>>,
    }

    impl Served {
        fn new(dir: &Path, sha: &str) -> Served {
            let deb = deb();
            let key = SigningKey::from_bytes(&[7; 32]);
            let real = sha256_hex(BODY);
            let message = UpdateSignature::message_for(SignatureDomain::LinVpnV1, &deb, "2.1.0", &real).unwrap();
            let sig = macvpn_core::swift_base64::encode(&key.sign(&message).to_bytes()) + "\n";
            let answers = HashMap::from([
                (format!("{BASE}/{deb}"), BODY.to_vec()),
                (format!("{BASE}/{deb}.sha256"), format!("{sha}  {deb}\n").into_bytes()),
                (format!("{BASE}/{deb}.sig"), sig.into_bytes()),
            ]);
            Served { dir: dir.to_path_buf(), answers }
        }
    }

    impl HttpClient for Served {
        fn get(&self, url: &str) -> Result<HttpResponse, HttpError> {
            Ok(match self.answers.get(url) {
                Some(data) => HttpResponse::new(200, data),
                None => HttpResponse::new(404, b""),
            })
        }

        fn download(&self, url: &str) -> Result<(PathBuf, i64), HttpError> {
            let file = self.dir.join(format!("dl-{}", uuid::Uuid::new_v4()));
            let (status, data) = self.answers.get(url).map_or((404, &[][..]), |d| (200, d.as_slice()));
            std::fs::write(&file, data).unwrap();
            Ok((file, status))
        }
    }

    struct Case {
        root: PathBuf,
        home: PathBuf,
        updater: LinUpdater,
    }

    /// A temp home, a fake pkexec that records its arguments and exits with `exit`, a fake relaunch that records its
    /// own, and a server whose `.sha256` says `sha` (default: the right one).
    fn case(exit: i32, sha: Option<&str>) -> Case {
        case_with(exit, sha, "")
    }

    /// [`case`], the fake pkexec running `before_exit` (shell) first.
    fn case_with(exit: i32, sha: Option<&str>, before_exit: &str) -> Case {
        let root = std::env::temp_dir().join(format!("linvpn-updater-{}", uuid::Uuid::new_v4()));
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let script = |name: &str, body: String| {
            let path = root.join(name);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            path
        };
        let record =
            |file: &str| format!("printf '%s\\n' \"$@\" > '{}.tmp' && mv '{0}.tmp' '{0}'", root.join(file).display());
        let pkexec = script("pkexec", format!("{}\n{before_exit}\nexit {exit}", record("pkexec.args")));
        let step = script("linvpn-install-update", "exit 99".into());
        let action = root.join("local.linvpn.update.policy");
        std::fs::write(&action, "<policyconfig/>\n").unwrap();
        let relaunch = script("linvpn", record("relaunch.args"));
        let public = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        let real = sha256_hex(BODY);
        let http = Box::new(Served::new(&root, sha.unwrap_or(&real)));
        Case {
            root: root.clone(),
            home,
            updater: LinUpdater::for_tests(pkexec, step, action, relaunch, vec![public], http),
        }
    }

    impl Case {
        fn install(&self, quit: bool) -> Result<UpdateOutcome, String> {
            self.updater.install(&release(), Path::new("/usr/bin/linvpn"), &self.home, &|_| {}, Box::new(move || quit))
        }

        fn updates(&self) -> PathBuf {
            self.updater.updates_dir(&self.home)
        }

        fn recorded(&self, file: &str) -> Option<Vec<String>> {
            std::fs::read_to_string(self.root.join(file)).ok().map(|t| t.lines().map(String::from).collect())
        }
    }

    impl Drop for Case {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn an_approved_update_relaunches_with_a_notice() {
        let c = case(0, None);
        assert_eq!(c.install(true), Ok(UpdateOutcome::HelperLaunched));
        let updates = c.updates();
        assert_eq!(updates, c.home.join(".cache/LinVPN/updates"));
        assert_eq!(std::fs::metadata(&updates).unwrap().permissions().mode() & 0o777, 0o700);
        let deb = deb();
        assert_eq!(
            c.recorded("pkexec.args").unwrap(),
            [
                c.updater.step.display().to_string(),
                "--deb".into(),
                updates.join(&deb).display().to_string(),
                "--sig".into(),
                updates.join(format!("{deb}.sig")).display().to_string(),
                "--version".into(),
                "2.1.0".into(),
                "--asset".into(),
                deb.clone(),
            ]
        );
        assert_eq!(std::fs::read_to_string(updates.join(up::NOTICE_FILE)).unwrap(), "ok 2.1.0");
        let log = updates.join("install-2.1.0.log");
        assert_eq!(std::fs::metadata(&log).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!updates.join(&deb).exists() && !updates.join(format!("{deb}.sig")).exists(), "removed after");
        // The relaunch runs detached: wait for it.
        let started = Instant::now();
        while c.recorded("relaunch.args").is_none() && started.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(c.recorded("relaunch.args").unwrap(), [AFTER_UPDATE]);
        // The next launch: a success is no "did not complete" notice but "updated" once, and the notice is gone.
        let (removed, notice) = c.updater.launch_housekeeping(Path::new("/usr/bin/linvpn"), &c.home, None);
        assert_eq!(notice, None);
        assert!(removed.contains(&updates.join(up::NOTICE_FILE)));
        assert_eq!(c.updater.take_updated_notice(), Some(up::updated_text("2.1.0")));
        assert_eq!(c.updater.take_updated_notice(), None, "once");
        c.updater.launch_housekeeping(Path::new("/usr/bin/linvpn"), &c.home, None);
        assert_eq!(c.updater.take_updated_notice(), None, "not at a later launch");
        assert_eq!(c.updater.cache_directory(&c.home), Some(updates));
    }

    #[test]
    fn a_package_upgraded_outside_the_app_relaunches_with_the_same_notice() {
        let c = case(0, None);
        c.updater.restart_after_package(&c.home, "2.0.9");
        let updates = c.updates();
        assert_eq!(std::fs::metadata(&updates).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::read_to_string(updates.join(up::NOTICE_FILE)).unwrap(), "ok 2.0.9");
        let started = Instant::now();
        while c.recorded("relaunch.args").is_none() && started.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(c.recorded("relaunch.args").unwrap(), [AFTER_UPDATE]);
        assert!(c.recorded("pkexec.args").is_none(), "no pkexec");
        let (_, notice) = c.updater.launch_housekeeping(Path::new("/usr/bin/linvpn"), &c.home, None);
        assert_eq!(notice, None);
        assert_eq!(c.updater.take_updated_notice(), Some(up::updated_text("2.0.9")));
    }

    #[test]
    fn a_dismissed_or_unauthorized_dialog_cancels() {
        for code in [126, 127] {
            let c = case(code, None);
            assert_eq!(c.install(true), Ok(UpdateOutcome::Cancelled), "{code}");
            assert!(c.recorded("pkexec.args").is_some());
            assert!(!c.updates().join(up::NOTICE_FILE).exists());
            assert!(!c.updates().join(deb()).exists());
            std::thread::sleep(Duration::from_millis(200));
            assert!(c.recorded("relaunch.args").is_none(), "nothing is relaunched");
        }
    }

    #[test]
    fn a_refusal_of_the_root_step_is_the_error() {
        let c = case(13, None);
        let err = c.install(true).unwrap_err();
        assert!(err.contains("13"), "{err}");
        let Outcome::Failed(expected) = up::outcome(13) else { panic!() };
        assert_eq!(err, expected);
        assert!(!c.updates().join(up::NOTICE_FILE).exists(), "shown now, not again at launch");
        std::thread::sleep(Duration::from_millis(200));
        assert!(c.recorded("relaunch.args").is_none());
    }

    #[test]
    fn a_bad_checksum_never_starts_pkexec() {
        let c = case(0, Some(&"b".repeat(64)));
        assert_eq!(c.install(true), Err(UpdateError::ChecksumMismatch.message()));
        assert!(c.recorded("pkexec.args").is_none());
        assert_eq!(std::fs::read_dir(c.updates()).unwrap().count(), 0);
    }

    #[test]
    fn declining_to_quit_never_starts_pkexec() {
        let c = case(0, None);
        assert_eq!(c.install(false), Ok(UpdateOutcome::Cancelled));
        assert!(c.recorded("pkexec.args").is_none());
        assert_eq!(std::fs::read_dir(c.updates()).unwrap().count(), 0, "the package is removed");
    }

    /// LA-8: a missing root step or polkit action is the helper error before any prompt, not pkexec's silent 127.
    #[test]
    fn a_missing_root_step_or_action_is_an_error_not_a_cancel() {
        for missing in ["step", "action"] {
            let c = case(127, None);
            let path = if missing == "step" { c.updater.step.clone() } else { c.updater.action.clone() };
            std::fs::remove_file(&path).unwrap();
            let err = c.install(true).unwrap_err();
            assert!(err.starts_with(&UpdateError::HelperFailed(String::new()).message()), "{missing}: {err}");
            assert!(err.contains(&path.display().to_string()), "{missing}: {err}");
            assert!(c.recorded("pkexec.args").is_none(), "{missing}: no prompt");
            assert!(!c.updates().join(deb()).exists(), "{missing}: the package is removed");
        }
    }

    #[test]
    fn a_step_that_is_gone_when_pkexec_answers_127_is_an_error() {
        let c = case_with(127, None, "rm -f \"$1\"");
        let err = c.install(true).unwrap_err();
        assert!(err.contains(&c.updater.step.display().to_string()), "{err}");
        assert!(c.recorded("pkexec.args").is_some());
    }

    #[test]
    fn a_step_that_is_not_executable_is_an_error() {
        let c = case(0, None);
        std::fs::set_permissions(&c.updater.step, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(c.install(true).is_err());
        assert!(c.recorded("pkexec.args").is_none());
    }
}
