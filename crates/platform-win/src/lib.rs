//! The Windows platform (WinVPN). OpenVPN and WireGuard through the WinVPN Service (`\\.\pipe\WinVPN`,
//! `win::service_client`); L2TP, IKEv2 and SSTP through RAS in the app's own process (`win::ras_engine`, 2c).
//!
//! `pure`: the logic without system calls (texts, System Status from the service's facts, the Mark-of-the-Web
//! parser, date formats, …), compiled and tested on every OS. `win`: the Windows implementation (Win32 through
//! `windows-sys` and `macvpn-winsys`), Windows only. The storage identifiers (the credential `local.winvpn.vault`,
//! the Run value `WinVPN`, the pipe and mutex names) are literals here and never derive from `Product`.

pub mod pure;

#[cfg(windows)]
#[allow(unsafe_code)]
mod win;

#[cfg(windows)]
pub use win::instance::{Claim, InstanceGuard, claim, show_claim_failure};
#[cfg(windows)]
pub use win::platform::WinPlatform;

/// The smoke run's hooks (debug builds only; `app/src-tauri/src/platform/smoke`).
#[cfg(all(windows, debug_assertions))]
pub mod smoke {
    use macvpn_platform_api::NativeWindow;

    /// Sends `WM_QUERYENDSESSION` to the app's lifecycle window, as Windows does at a logoff: the terminate handler
    /// answers (`Some(0)`: blocked for now or for good, `Some(1)`: Windows may end; `None`: no window).
    pub fn query_end_session() -> Option<isize> {
        crate::win::lifecycle::query_end_session_for_tests()
    }

    /// Whether the window holds Windows 11's round corners (DWM's corner preference; Windows 10: `false`).
    pub fn corners_round(w: NativeWindow) -> bool {
        crate::win::chrome::corners_round(w)
    }
}

/// Restricts the process' DLL search to System32 (`macvpn_winsys::dll::harden_process_search`: no application
/// folder, current directory or `PATH`); aborts if it cannot. `WinVPN.exe` calls it first thing in `main`, before
/// any mode (the elevated steps and the relauncher included).
#[cfg(windows)]
pub fn harden_dll_search() {
    macvpn_winsys::dll::harden_process_search();
}

/// The elevated step of the OpenVPN install (`WinVPN.exe --winvpn-openvpn-step …`, started elevated by System
/// Status: `pure::openvpn_install`): its exit code when `args` (without the program name) are such a step, else
/// `None` (the app starts normally). The app calls it first thing, before any window or instance check.
#[cfg(windows)]
pub fn openvpn_elevated_step(args: &[String]) -> Option<u32> {
    win::openvpn_install::elevated_main(args)
}

/// The elevated step of **Trust This CA in Windows…** (`WinVPN.exe --winvpn-trust-ca-step <file>`, started
/// elevated by the app: `pure::admin_steps`): its exit code when `args` (without the program name) are that step,
/// else `None`. The app calls it first thing, before any window or instance check.
#[cfg(windows)]
pub fn trust_ca_elevated_step(args: &[String]) -> Option<u32> {
    win::admin_steps::elevated_trust_main(args)
}

/// Tests only: the OpenVPN MSI's signer check (the pinned `OPENVPN_SIGNER`), as the install runs it before any
/// elevation.
#[cfg(windows)]
#[doc(hidden)]
pub fn verify_openvpn_msi_for_tests(path: &std::path::Path) -> Result<(), String> {
    win::openvpn_install::verify_signer(path)
}

/// Tests only: [`openvpn_elevated_step`] copying the MSI into `<root>\installer\…` (a private folder of this user;
/// production: `C:\ProgramData\WinVPN`, Administrators only) and calling `msiexec` with msiexec's parameters
/// instead of running it (its exit code, or `None`: not started).
#[cfg(windows)]
#[doc(hidden)]
pub fn openvpn_elevated_step_staged_for_tests(
    args: &[String],
    root: &std::path::Path,
    msiexec: &dyn Fn(&str) -> Option<u32>,
) -> Option<u32> {
    win::openvpn_install::elevated_main_with(args, || win::openvpn_install::Staging::for_tests(root), msiexec)
}

/// Tests only: the elevated step's copy of `source` into `<root>\installer\<random>\` (see
/// [`openvpn_elevated_step_staged_for_tests`]): its path; the folder is removed when the guard drops.
#[cfg(windows)]
#[doc(hidden)]
pub fn stage_openvpn_msi_for_tests(
    source: &std::path::Path,
    root: &std::path::Path,
) -> std::io::Result<(std::path::PathBuf, Box<dyn std::any::Any>)> {
    let bytes = std::fs::read(source)?;
    let staged = win::openvpn_install::stage(source, &bytes, &win::openvpn_install::Staging::for_tests(root)?)?;
    Ok((staged.msi.clone(), Box::new(staged)))
}

/// Tests only: a Credential Manager key store over the generic credential `target` (user name `dek`). The tests
/// use `local.winvpn.test.<uuid>` and delete it; never the production target.
#[cfg(windows)]
#[doc(hidden)]
pub fn credential_key_store_for_tests(target: &str) -> Box<dyn macvpn_core::vault::KeyStore> {
    assert!(target != win::keystore::VAULT_TARGET, "tests never touch the production credential");
    Box::new(win::keystore::CredentialKeyStore::new(target, win::keystore::VAULT_USER))
}

/// Tests only: writes, reads and deletes a string and a binary value under `HKCU\Software\WinVPN-test-<random>`
/// (the key is removed afterwards); whether every step matched.
#[cfg(windows)]
#[doc(hidden)]
pub fn registry_round_trip_for_tests() -> bool {
    win::registry::round_trip_for_tests()
}

/// Tests only: the launch-at-login item over the Run value `value` (`WinVPN-test-…`, never WinVPN's own).
#[cfg(windows)]
#[doc(hidden)]
pub fn run_key_item_for_tests(exe: &std::path::Path, value: &str) -> Box<dyn macvpn_platform_api::LoginItems> {
    assert_test_value(value);
    Box::new(win::login_item::RunKeyItem { exe: exe.to_path_buf(), value: value.to_owned() })
}

#[cfg(windows)]
fn assert_test_value(value: &str) {
    assert!(value.starts_with("WinVPN-test-"), "tests never touch WinVPN's own Run value");
}

/// Tests only: the Run value `value` (`WinVPN-test-…`).
#[cfg(windows)]
#[doc(hidden)]
pub fn run_value_for_tests(value: &str) -> Option<String> {
    assert_test_value(value);
    win::registry::read_string(win::login_item::RUN, value)
}

/// Tests only: writes the Run value `value` (`WinVPN-test-…`).
#[cfg(windows)]
#[doc(hidden)]
pub fn set_run_value_for_tests(value: &str, data: &str) {
    assert_test_value(value);
    win::registry::write_string(win::login_item::RUN, value, data).expect("the test Run value");
}

/// Tests only: sets (`Some`) or deletes the StartupApproved value `value` (`WinVPN-test-…`), as Settings does.
#[cfg(windows)]
#[doc(hidden)]
pub fn startup_approved_for_tests(value: &str, data: Option<&[u8]>) {
    assert_test_value(value);
    match data {
        Some(d) => win::registry::write_binary(win::login_item::APPROVED, value, d).expect("the test value"),
        None => win::registry::delete_value(win::login_item::APPROVED, value).expect("the test value"),
    }
}

/// Tests only: removes the Run and StartupApproved values `value` (`WinVPN-test-…`).
#[cfg(windows)]
#[doc(hidden)]
pub fn remove_run_values_for_tests(value: &str) {
    assert_test_value(value);
    let _ = win::registry::delete_value(win::login_item::RUN, value);
    let _ = win::registry::delete_value(win::login_item::APPROVED, value);
}

/// Tests only: what the lifecycle window answers to `WM_QUERYENDSESSION` (`None`: no window yet).
#[cfg(windows)]
#[doc(hidden)]
pub fn lifecycle_query_end_session_for_tests() -> Option<isize> {
    win::lifecycle::query_end_session_for_tests()
}

/// Tests only: what the lifecycle window answers to a resume (`WM_POWERBROADCAST`, `PBT_APMRESUMEAUTOMATIC`).
#[cfg(windows)]
#[doc(hidden)]
pub fn lifecycle_resume_for_tests() -> Option<isize> {
    win::lifecycle::resume_for_tests()
}

/// Tests only: what the lifecycle window answers to a suspend (`WM_POWERBROADCAST`, `PBT_APMSUSPEND`).
#[cfg(windows)]
#[doc(hidden)]
pub fn lifecycle_suspend_for_tests() -> Option<isize> {
    win::lifecycle::suspend_for_tests()
}

/// Tests only: `WM_ENDSESSION` for a logoff (`true`) or a shutdown (`false`), as Windows sends it after the session
/// was allowed to end.
#[cfg(windows)]
#[doc(hidden)]
pub fn lifecycle_end_session_for_tests(logoff: bool) -> Option<isize> {
    win::lifecycle::end_session_for_tests(logoff)
}

/// Tests only: `WM_SETTINGCHANGE` with the changed area `area` (its `lParam` string; `None`: no string), as Windows
/// broadcasts it to top-level windows.
#[cfg(windows)]
#[doc(hidden)]
pub fn lifecycle_setting_change_for_tests(area: Option<&str>) -> Option<isize> {
    win::lifecycle::setting_change_for_tests(area)
}

/// Tests only: registers a logoff observer (the RAS engine's hang-up registers itself the same way).
#[cfg(windows)]
#[doc(hidden)]
pub fn lifecycle_observe_logoff_for_tests(on_logoff: Box<dyn Fn() + Send + Sync>) {
    win::lifecycle::observe_logoff(on_logoff);
}

/// Tests only: whether the clipboard now offers the three formats that keep a secret out of clipboard monitors,
/// Windows' clipboard history and cloud sync.
#[cfg(windows)]
#[doc(hidden)]
pub fn clipboard_excludes_for_tests() -> [bool; 3] {
    use win::clipboard::{CLOUD, EXCLUDE_FROM_MONITORS, HISTORY, has_format};
    [has_format(EXCLUDE_FROM_MONITORS), has_format(HISTORY), has_format(CLOUD)]
}

/// Tests only: the control transport over the pipe `name` (not the production `WinVPN-control-<SID>`), with the
/// choice of network logons (the Windows test machine runs the tests over SSH, a network logon that the production
/// DACL refuses).
#[cfg(windows)]
#[doc(hidden)]
pub fn control_transport_for_tests(
    name: &str,
    network: macvpn_winsys::pipe::NetworkLogons,
) -> std::sync::Arc<dyn macvpn_platform_api::ControlTransport> {
    std::sync::Arc::new(win::control::PipeTransport::with_name(name, network))
}

/// Tests only: a RAS engine over a test data directory (its phonebook, profiles and logs live there), with the
/// platform traits the app uses it through. Entries are named `WinVPN-<UUID>` of the test's own connections.
#[cfg(windows)]
#[doc(hidden)]
pub struct RasEngineForTests(std::sync::Arc<win::ras_engine::RasEngine>);

#[cfg(windows)]
impl RasEngineForTests {
    pub fn controller(&self) -> &dyn macvpn_platform_api::NativeController {
        &*self.0
    }

    pub fn profiles(&self) -> &dyn macvpn_platform_api::NativeProfiles {
        &*self.0
    }

    pub fn support(&self) -> &dyn macvpn_platform_api::NativeSupport {
        &*self.0
    }

    /// The app's `HelperClient` with this engine; the WinVPN Service part points at a test pipe nobody serves.
    pub fn helper(&self) -> Box<dyn macvpn_platform_api::HelperClient> {
        let mut random = [0u8; 16];
        macvpn_winsys::random::fill(&mut random).expect("system randomness");
        let pipe = format!(r"\\.\pipe\WinVPN-test-{}", uuid::Uuid::from_bytes(random));
        Box::new(win::ras_engine::RasHelper {
            service: win::service_client::ServiceClient::trusting_system(&pipe),
            ras: self.0.clone(),
        })
    }

    pub fn phonebook(&self) -> std::path::PathBuf {
        self.0.phonebook_path().expect("the test engine is ready")
    }

    pub fn log_path(&self, id: &uuid::Uuid) -> std::path::PathBuf {
        self.0.log_path(id).expect("the test engine is ready")
    }

    pub fn hang_up_all(&self) {
        self.0.hang_up_all();
    }

    /// The `CustomIPSecPolicies` hex the engine writes for `policy`.
    pub fn policy_hex(policy: &macvpn_core::ras::WindowsPolicy) -> String {
        win::ras_engine::ipsec_policy(policy).to_hex()
    }
}

/// Tests only: the RAS engine over the test data directory `data` (made private here, as WinVPN's own).
#[cfg(windows)]
#[doc(hidden)]
pub fn ras_engine_for_tests(data: &std::path::Path) -> RasEngineForTests {
    ras_engine_with_system_books_for_tests(data, Vec::new())
}

/// Tests only: [`ras_engine_for_tests`] whose user's own Windows VPNs are the entries of the phonebook files
/// `books` (temp files standing in for Windows' default phonebooks; none: no system VPN).
#[cfg(windows)]
#[doc(hidden)]
pub fn ras_engine_with_system_books_for_tests(
    data: &std::path::Path,
    books: Vec<std::path::PathBuf>,
) -> RasEngineForTests {
    let private = data.join(macvpn_core::ras::names::PHONEBOOK_DIR).join(macvpn_core::ras::names::PHONEBOOK_FILE);
    let system = win::system_vpns::SystemVpns::for_test(books, Some(private));
    RasEngineForTests(std::sync::Arc::new(win::ras_engine::RasEngine::with_system(Some(data), system)))
}

/// Tests only: the WinVPN Service's client as the app uses it, over a test pipe.
#[cfg(windows)]
#[doc(hidden)]
pub struct ServiceClientForTests(win::service_client::ServiceClient);

#[cfg(windows)]
impl ServiceClientForTests {
    pub fn helper(&self) -> &dyn macvpn_platform_api::HelperClient {
        &self.0
    }

    pub fn auth_state(&self) -> &dyn macvpn_platform_api::AuthStateReader {
        &self.0
    }

    /// What System Status learns from the service.
    pub fn reach(&self) -> pure::engine::Reach {
        self.0.reach()
    }

    /// The service's wireguard-nt check (fix4).
    pub fn wireguard_check(&self) -> pure::wireguard_update::Offer {
        self.0.wireguard_check()
    }

    /// The service's wireguard-nt update (fix4).
    pub fn wireguard_update(&self) -> Result<String, String> {
        self.0.wireguard_update()
    }
}

#[cfg(windows)]
fn assert_test_pipe(pipe: &str) {
    assert!(pipe.starts_with(r"\\.\pipe\WinVPN-test-"), "tests never use the service's own pipe");
}

/// Tests only (debug builds): the client of the service's console mode on `pipe` (`\\.\pipe\WinVPN-test-…`), which
/// this user owns. The production client trusts only SYSTEM ([`service_client_trusting_system_for_tests`]).
#[cfg(all(windows, debug_assertions))]
#[doc(hidden)]
pub fn service_client_for_tests(pipe: &str) -> ServiceClientForTests {
    assert_test_pipe(pipe);
    ServiceClientForTests(win::service_client::ServiceClient::trusting_this_user(pipe))
}

/// Tests only: the production client (it trusts only a SYSTEM-owned pipe) on a test pipe name.
#[cfg(windows)]
#[doc(hidden)]
pub fn service_client_trusting_system_for_tests(pipe: &str) -> ServiceClientForTests {
    assert_test_pipe(pipe);
    ServiceClientForTests(win::service_client::ServiceClient::trusting_system(pipe))
}

/// Tests only (debug builds): the helper's debug `mvpn.exe`, which has the service's console mode: next to this
/// test binary's directory (`target/<triple>/debug/deps/…` → `target/<triple>/debug/mvpn.exe`). Build it first
/// (`cargo build -p macvpn-helper`; `scripts/win-remote.sh test` builds it with the helper's tests).
#[cfg(all(windows, debug_assertions))]
#[doc(hidden)]
pub fn helper_console_for_tests() -> std::path::PathBuf {
    let exe = std::env::current_exe().expect("the test binary");
    let dir = exe.parent().and_then(std::path::Path::parent).expect("target/<profile>");
    let mvpn = dir.join("mvpn.exe");
    assert!(mvpn.is_file(), "{} is missing: cargo build -p macvpn-helper first", mvpn.display());
    mvpn
}

/// The updater's relauncher (`WinVPN-relaunch.exe --relaunch --target <exe> --msi <msi> --sha256 <hex> --log <log>`,
/// parsed by `pure::update::parse_relaunch`): holds the MSI (re-hashed) and msiexec's log until msiexec has exited,
/// records the outcome for the next launch, starts the new WinVPN. The app calls it first thing in `main` (no Tauri,
/// no window, no single-instance claim).
#[cfg(windows)]
pub fn relaunch_after(relaunch: &pure::update::Relaunch) {
    win::updater::relaunch_after(relaunch);
}

/// Debug builds only (CP2): installs a local MSI as an update would (held deny-write, msiexec elevated through UAC,
/// the relauncher), without download or signature. The message says what happened.
#[cfg(all(windows, debug_assertions))]
#[doc(hidden)]
pub fn test_install_msi(msi: &std::path::Path) -> Result<String, String> {
    win::updater::test_install_msi(msi)
}

/// Tests only: opens `path` as the updater holds a verified MSI (share mode read only, no reparse point).
#[cfg(windows)]
#[doc(hidden)]
pub fn hold_for_tests(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    win::updater::hold(path)
}

/// Tests only: creates msiexec's log as the updater does and returns its hold (read, no delete sharing).
#[cfg(windows)]
#[doc(hidden)]
pub fn create_log_for_tests(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    win::updater::create_log(path)
}

/// Tests only: the relauncher's wait for process `pid` named `image`: `Some(exit code)`, or `None` when it is gone,
/// another program or still running after `timeout`.
#[cfg(windows)]
#[doc(hidden)]
pub fn wait_for_exit_for_tests(pid: u32, image: &str, timeout: std::time::Duration) -> Result<u32, String> {
    match win::updater::wait_for(pid, image, timeout) {
        win::updater::Waited::Exited(code) => Ok(code),
        other => Err(format!("{other:?}")),
    }
}

/// Tests only: the relauncher's notice, written into `dir` (a test folder).
#[cfg(windows)]
#[doc(hidden)]
pub fn write_notice_for_tests(
    dir: &std::path::Path,
    exit_code: u32,
    log: &std::path::Path,
) -> std::io::Result<pure::update::Notice> {
    win::updater::write_notice(dir, exit_code, log)
}

/// Tests only: the curl flavour WinVPN uses (System32's `curl.exe`, `--ssl-revoke-best-effort`).
#[cfg(windows)]
#[doc(hidden)]
pub fn windows_curl_for_tests() -> macvpn_platform_api::curl::Curl {
    win::curl_runner::windows_curl()
}

/// Tests only: the Windows runner of the curl layer with a time limit of `timeout` seconds.
#[cfg(windows)]
#[doc(hidden)]
pub fn curl_runner_for_tests(timeout: f64) -> Box<dyn macvpn_platform_api::curl::CommandRunner> {
    Box::new(win::curl_runner::WinCurlRunner::new(timeout))
}

/// Tests only: the production HTTPS catalog fetcher (System32's `curl.exe`).
#[cfg(windows)]
#[doc(hidden)]
pub fn catalog_fetcher_for_tests() -> std::sync::Arc<dyn macvpn_core::catalog::fetch::CatalogFetcher> {
    std::sync::Arc::new(win::https::catalog_fetcher())
}

/// One recorded run: the executable, the arguments and stdin.
#[cfg(windows)]
#[doc(hidden)]
pub type RecordedRun = (String, Vec<String>, Option<String>);

/// Tests only: the production catalog fetcher over a runner that records every run and answers `200` without
/// starting anything.
#[cfg(windows)]
#[doc(hidden)]
pub fn catalog_fetcher_recording_for_tests()
-> (std::sync::Arc<dyn macvpn_core::catalog::fetch::CatalogFetcher>, std::sync::Arc<std::sync::Mutex<Vec<RecordedRun>>>)
{
    use macvpn_platform_api::curl::{CommandError, CommandResult, CommandRunner};
    use std::sync::{Arc, Mutex};

    struct Recorder(Arc<Mutex<Vec<RecordedRun>>>);

    impl CommandRunner for Recorder {
        fn run(&self, exe: &str, args: &[String], stdin: Option<&str>) -> Result<CommandResult, CommandError> {
            self.0.lock().unwrap().push((exe.to_string(), args.to_vec(), stdin.map(String::from)));
            Ok(CommandResult::stdout("200 "))
        }
    }

    let seen = Arc::new(Mutex::new(Vec::new()));
    (Arc::new(win::https::catalog_fetcher_with(Box::new(Recorder(seen.clone())))), seen)
}

/// Tests only: the system VPNs over the phonebook files `books` (temp files standing in for Windows' default
/// phonebooks), with `private` as WinVPN's own phonebook (never listed).
#[cfg(windows)]
#[doc(hidden)]
pub fn system_vpns_for_tests(
    books: Vec<std::path::PathBuf>,
    private: Option<std::path::PathBuf>,
) -> std::sync::Arc<dyn macvpn_platform_api::NativeController> {
    std::sync::Arc::new(win::system_vpns::SystemVpns::for_test(books, private))
}

/// Tests only: the live system VPN list's watch over the folders `dirs` (test folders).
#[cfg(windows)]
#[doc(hidden)]
pub fn system_vpn_watch_for_tests(dirs: Vec<std::path::PathBuf>) -> Box<dyn macvpn_platform_api::SystemVpnWatch> {
    Box::new(win::ras_watch::RasWatch { dirs })
}

/// Tests only: the folders the production watch watches (Windows' two default phonebook folders, WinVPN's `ras`).
#[cfg(windows)]
#[doc(hidden)]
pub fn system_vpn_watch_folders_for_tests() -> Vec<std::path::PathBuf> {
    win::ras_watch::folders()
}

/// Tests only: the production system VPNs (Windows' default phonebooks), WinVPN's private phonebook skipped.
#[cfg(windows)]
#[doc(hidden)]
pub fn system_vpns_production_for_tests() -> std::sync::Arc<dyn macvpn_platform_api::NativeController> {
    std::sync::Arc::new(win::system_vpns::SystemVpns::new(None))
}

/// Tests only: the administrator steps (2c Task 12) without a platform object (the trust and NAT steps prompt for
/// UAC: only the desktop-ignored tests call them).
#[cfg(windows)]
#[doc(hidden)]
pub fn admin_steps_for_tests() -> std::sync::Arc<dyn macvpn_platform_api::AdminSteps> {
    std::sync::Arc::new(win::admin_steps::WinAdminSteps { trust_exe: None })
}

/// Tests only: the administrator steps with `exe` (the installed `WinVPN.exe`) as the program of the elevated trust
/// step, instead of the test's own exe.
#[cfg(windows)]
#[doc(hidden)]
pub fn admin_steps_with_trust_exe_for_tests(
    exe: &std::path::Path,
) -> std::sync::Arc<dyn macvpn_platform_api::AdminSteps> {
    std::sync::Arc::new(win::admin_steps::WinAdminSteps { trust_exe: Some(exe.to_path_buf()) })
}

/// Tests only: the CA file the trust step reads, staged in `dir` as `trust_ca` stages it: its path and the guard that
/// holds it (dropping the guard deletes it).
#[cfg(windows)]
#[doc(hidden)]
pub fn stage_ca_for_tests(
    dir: &std::path::Path,
    der: &[u8],
) -> Result<(std::path::PathBuf, Box<dyn std::any::Any>), String> {
    let staged = win::admin_steps::StagedCa::write_in(dir, der)?;
    Ok((staged.path.clone(), Box::new(staged)))
}

/// Tests only: the PSK step of a system VPN's start for the entry `name` of the phonebook `book` (a temp file):
/// whether WinVPN's stored PSK `stored` was written into Windows' RAS credential store.
#[cfg(windows)]
#[doc(hidden)]
pub fn system_vpn_provide_psk_for_tests(
    book: &std::path::Path,
    name: &str,
    stored: Option<&str>,
) -> Result<bool, String> {
    let book = macvpn_winsys::ras::Phonebook::at(book).map_err(|e| e.to_string())?;
    let entry = book.read(name).map_err(|e| e.to_string())?;
    win::system_vpns::provide_psk(&book, &entry, stored).map_err(|e| e.to_string())
}
