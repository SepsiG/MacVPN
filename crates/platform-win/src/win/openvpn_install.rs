//! System Status' "Install" / "Repair" / "Update" of OpenVPN Community (2b plan, Task 17; decision 4): winget when
//! it exists (machine scope, `openvpn.exe`, DCO and TAP-Windows6 through `--override`, checked afterwards through
//! the WinVPN Service), else — or when a driver is still missing afterwards — the pinned MSI after its SHA-256 and
//! Authenticode signer matched, installed by the elevated step (`pure::openvpn_install`: one UAC confirmation; it
//! checks the MSI again, copies it into a new admin-only folder under `C:\ProgramData\WinVPN\installer` and checks
//! the copy, runs msiexec on the copy and, on an installation WinVPN made, disables, stops and checks OpenVPN's
//! Interactive Service). The output streams into System Status; the app checks the system again afterwards.
//!
//! The WinVPN Service's own trust check of `openvpn.exe` (signer, admin-only path, version) stays the gate for
//! using what was installed, whichever way it came.
//!
//! Since fix4 (decision 4 as amended again 2026-10-24) the MSI path's MSI is the newest official one OpenVPN's
//! download page links when that is a newer OpenVPN than the pin (`pure::openvpn_install::pick_msi`): downloaded
//! from OpenVPN's hosts only and trusted on its name and Authenticode signer (here and again in the elevated step,
//! which also requires its MSI database to name OpenVPN Community of this machine not older than the pin); the
//! pinned MSI stays the fallback and the minimum.

use super::curl_runner::{MARGIN_SECS, http_client, windows_curl};
use super::elevate::run_elevated;
use super::service_client::ServiceClient;
use super::{registry, system};
use crate::pure::engine::Reach;
use crate::pure::openvpn_install::{
    self as oi, Action, First, Interactive, MsiPick, OfficialMsi, Outcome, Step, StepError, StepResult, Upgrade,
};
use crate::pure::openvpn_pins::{
    OPENVPN_INTERACTIVE_SERVICE, OPENVPN_SIGNER, OPENVPN_SIGNER_CA_SPKI_SHA256, OPENVPN_VERSION,
};
use macvpn_core::service_proto::{OpenVpnFacts, Version};
use macvpn_platform_api::curl::Curl;
use macvpn_platform_api::curl::http::RESOURCE_TIMEOUT;
use macvpn_platform_api::{PlatformError, SetupReport, WINVPN};
use macvpn_winsys::file::{self as wfile, Protection};
use macvpn_winsys::sid::Sid;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

/// The largest OpenVPN MSI WinVPN downloads (2.7.8's are about 10 MB).
const MAX_MSI_BYTES: u64 = 64 << 20;
/// How long the elevated step waits for the Interactive Service to stop.
const STOP_WAIT: Duration = Duration::from_secs(30);

/// One line of System Status' output.
fn say(output: &mut dyn FnMut(&str), text: &str) {
    output(&format!("{text}\n"));
}

/// OpenVPN's facts from the WinVPN Service (`None`: no trusted answer).
fn openvpn_facts() -> Option<OpenVpnFacts> {
    match ServiceClient::production().reach() {
        Reach::Facts(f) => Some(f.openvpn),
        _ => None,
    }
}

/// OpenVPN has recorded an `openvpn.exe` on this machine (the value the service's detection reads).
fn openvpn_registered() -> bool {
    registry::read_machine_string(oi::OPENVPN_KEY, oi::OPENVPN_EXE_VALUE).is_some_and(|s| !s.is_empty())
}

/// WinVPN's marker: an earlier install of OpenVPN was WinVPN's.
fn marker() -> bool {
    registry::read_machine_dword(oi::MARKER_KEY, oi::MARKER_VALUE) == Some(1)
}

/// `%LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe` (an app execution alias), never through `PATH`.
fn winget() -> Option<PathBuf> {
    let exe = system::local_app_data()?.join(r"Microsoft\WindowsApps\winget.exe");
    std::fs::symlink_metadata(&exe).is_ok().then_some(exe)
}

/// `%LOCALAPPDATA%\WinVPN\downloads` (private).
fn downloads_dir() -> Result<PathBuf, String> {
    let root = system::local_app_data().ok_or_else(|| PlatformError::Unsupported { what: "known folder" }.message())?;
    let dir = WINVPN.data_dir(&root).join("downloads");
    if let Some(parent) = dir.parent() {
        macvpn_core::fsx::create_missing_private_dirs(parent).map_err(|e| e.to_string())?;
    }
    macvpn_core::fsx::ensure_private_dir(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

/// The install of `report`'s OpenVPN action, its progress and result in `output`. `Err`: the failure (also the
/// last line of the output).
pub(crate) fn install(report: &SetupReport, output: &mut dyn FnMut(&str)) -> Result<(), String> {
    let result = run(report, output);
    if let Err(e) = &result {
        say(output, e);
    }
    result
}

fn run(report: &SetupReport, output: &mut dyn FnMut(&str)) -> Result<(), String> {
    let Some(action) = report.engine.as_ref().and_then(|e| e.openvpn.action).and_then(Action::parse) else {
        return Ok(());
    };
    let unsupported = || PlatformError::Unsupported { what: "OpenVPN for this processor" }.message();
    let (_, _, features) = oi::pinned_msi(std::env::consts::ARCH).ok_or_else(unsupported)?;
    let pinned = oi::pinned_official(std::env::consts::ARCH).ok_or_else(unsupported)?;
    let installed = openvpn_facts().and_then(|f| f.version);
    let installed_version = installed.as_deref().and_then(Version::parse);
    let absent_before = !openvpn_registered();
    let winget = winget();
    let mut restart = false;
    // The MSI path's MSI (fix4): the newest official one, asked now; nothing found = the pin. "Repair" of the
    // pinned version keeps the pinned MSI (a maintenance install of the same version).
    let pick = match action {
        Action::Repair if installed_version == Some(pinned.version) => MsiPick::Pinned(pinned),
        _ => oi::pick_msi(discover(), pinned),
    };
    let msi_version = pick.msi().version.to_string();
    let first = match (action, installed_version) {
        // The newest of winget's offer and the official MSI, asked again now (the row may be older).
        (Action::Update, Some(v)) => oi::update_first(&upgrade_with(v, true, &msi_version), winget.is_some()),
        _ => oi::first_step(action, installed.as_deref(), &msi_version, winget.is_some()),
    };
    let winget_first = matches!(first, First::Winget { .. });
    let need_msi = match first {
        First::Refuse(text) => return Err(text),
        First::Msi => true,
        First::Winget { update } => {
            // winget's newest OpenVPN (decision 4 as amended 2026-10-24), not the pin.
            say(output, &oi::installing_with_winget());
            let exe = winget.as_deref().ok_or_else(oi::installer_not_started)?;
            match run_winget(exe, &oi::winget_args(update, features), output).map(oi::outcome) {
                Ok(done @ (Outcome::Done | Outcome::DoneRestartNeeded)) => {
                    restart = done == Outcome::DoneRestartNeeded;
                    // winget cannot say which features it installed: the service tells.
                    let after = openvpn_facts();
                    if after.as_ref().is_some_and(oi::drivers_complete) {
                        false
                    } else if oi::msi_fallback_allowed(
                        after.and_then(|f| f.version).or(installed).as_deref(),
                        &msi_version,
                    ) {
                        say(output, &oi::winget_missed_drivers());
                        true
                    } else {
                        // Newer than the pin: the pinned MSI would be a downgrade.
                        return Err(oi::add_drivers_in_settings());
                    }
                }
                Ok(Outcome::Cancelled) => return Err(oi::cancelled()),
                Ok(Outcome::Failed(code)) if oi::msi_fallback_allowed(installed.as_deref(), &msi_version) => {
                    say(output, &oi::winget_failed(code));
                    true
                }
                Ok(Outcome::Failed(code)) => return Err(oi::installer_failed(code)),
                Err(_) if oi::msi_fallback_allowed(installed.as_deref(), &msi_version) => {
                    say(output, &oi::winget_failed(u32::MAX));
                    true
                }
                Err(_) => return Err(oi::installer_not_started()),
            }
        }
    };
    if need_msi {
        say(output, &oi::installing(&msi_version));
    }
    let lines = if need_msi {
        let result = install_msi(&pick)?;
        let mut lines = oi::after_step(&result)?;
        // The elevated MSI step decides from what it sees (security review L-2): after winget installed OpenVPN
        // here, it finds OpenVPN present. The Interactive step (a second prompt) then does what decision 4 asks.
        if absent_before && result.interactive == Interactive::Untouched && winget_first {
            lines.splice(0..0, disable_interactive_after_winget(absent_before));
        }
        lines
    } else {
        after_winget(absent_before)
    };
    for line in lines {
        say(output, &line);
    }
    // winget's restart request (the MSI path reports msiexec's in its lines).
    if restart && !need_msi {
        say(output, &oi::restart_needed());
    }
    Ok(())
}

/// System Status' update check of an installed OpenVPN (`installed`: the service's `openvpn.exe` version; decision 4
/// as amended 2026-10-24): the newest of winget's offer and the pinned MSI ([`oi::choose_update`]). winget's answer
/// ([`oi::winget_check_args`], read-only) is asked only when winget exists and `ask_winget`; otherwise, or on a
/// failure, an unexpected output or no answer within [`oi::WINGET_CHECK_SECS`], it is [`Upgrade::Unknown`] (with
/// winget) or [`Upgrade::None`] (without), and only a newer pin can be offered.
pub(crate) fn upgrade(installed: Version, ask_winget: bool) -> Upgrade {
    // The official page is asked next to winget (fix4); without asking (the launch) the pin stands for it.
    let (discovered, from_winget) = std::thread::scope(|scope| {
        let page = ask_winget.then(|| scope.spawn(discover));
        let from_winget = winget_offer(installed, ask_winget);
        (page.and_then(|p| p.join().ok()).flatten(), from_winget)
    });
    let msi = match oi::pinned_official(std::env::consts::ARCH) {
        Some(pinned) => oi::pick_msi(discovered, pinned).msi().version.to_string(),
        None => OPENVPN_VERSION.to_string(),
    };
    oi::choose_update(&from_winget, installed, &msi)
}

/// [`upgrade`] with the newest official MSI's version already known (the "Update" action asked the page itself).
fn upgrade_with(installed: Version, ask_winget: bool, msi_version: &str) -> Upgrade {
    oi::choose_update(&winget_offer(installed, ask_winget), installed, msi_version)
}

/// winget's offer for the installed OpenVPN (see [`upgrade`]).
fn winget_offer(installed: Version, ask_winget: bool) -> Upgrade {
    match winget() {
        Some(exe) if ask_winget => match winget_answer(&exe, &oi::winget_check_args()) {
            Some((code, text)) => oi::parse_winget_check(code, &text, installed),
            None => Upgrade::Unknown,
        },
        Some(_) => Upgrade::Unknown,
        None => Upgrade::None,
    }
}

/// The newest official MSI for this machine on OpenVPN's download page (fix4), through System32's curl from
/// `openvpn.net` only, within [`oi::OFFICIAL_PAGE_SECS`]; `None` on any failure (then the pin is used: never an
/// error row).
fn discover() -> Option<OfficialMsi> {
    let client = http_client(windows_curl(), oi::OFFICIAL_PAGE_SECS + MARGIN_SECS);
    let page = client
        .get_from(oi::OFFICIAL_PAGE, oi::OFFICIAL_PAGE_HOSTS, oi::OFFICIAL_PAGE_MAX_BYTES, oi::OFFICIAL_PAGE_SECS)
        .ok()?;
    oi::parse_official_page(&String::from_utf8_lossy(&page), std::env::consts::ARCH)
}

/// winget's exit code and output (at most [`oi::WINGET_CHECK_MAX_BYTES`]), no window, no input; `None` when it
/// could not start or did not finish within [`oi::WINGET_CHECK_SECS`] (then it is killed).
fn winget_answer(exe: &Path, args: &[String]) -> Option<(u32, String)> {
    let mut child = Command::new(exe)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(oi::WINGET_CHECK_MAX_BYTES as u64).read_to_end(&mut bytes);
        bytes
    });
    let deadline = Instant::now() + Duration::from_secs(oi::WINGET_CHECK_SECS);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let bytes = reader.join().ok()?;
    // An exit code is a u32 (winget's are HRESULTs); `code()` gives its bits as an i32.
    Some((status.code()? as u32, String::from_utf8_lossy(&bytes).into_owned()))
}

/// After winget installed OpenVPN: the Interactive Service on an installation WinVPN made (a second UAC prompt:
/// winget elevated only its installer). A declined prompt or a failure is a line; the install counts as done.
fn after_winget(absent_before: bool) -> Vec<String> {
    let mut lines = disable_interactive_after_winget(absent_before);
    lines.push(oi::installed());
    lines
}

/// The Interactive step after winget (see [`after_winget`]): its lines, without "installed".
fn disable_interactive_after_winget(absent_before: bool) -> Vec<String> {
    let mut lines = Vec::new();
    if oi::disable_interactive(absent_before, marker()) {
        let r = oi::step_parameters(&Step::Interactive { absent_before })
            .ok_or(())
            .and_then(|p| run_step(&p).map_err(|_| ()));
        match r.as_ref().map(oi::after_step) {
            Ok(Ok(more)) => lines.extend(more),
            _ => lines.push(oi::interactive_not_disabled()),
        }
    }
    lines
}

/// The chosen MSI: downloaded, checked (the pinned one: SHA-256 and signer; the newest official one: OpenVPN's
/// hosts, its name and the signer), held deny-write while the elevated step copies, checks and installs it, then
/// deleted. The elevated step's result.
fn install_msi(pick: &MsiPick) -> Result<StepResult, String> {
    let url = pick.msi().url.as_str();
    let name = oi::msi_file_name(url).ok_or_else(oi::installer_not_started)?;
    let dir = downloads_dir().map_err(|e| oi::download_failed(&e))?;
    let curl = Curl { temp_base: downloads_temp_base, ..windows_curl() };
    let client = http_client(curl, RESOURCE_TIMEOUT + MARGIN_SECS);
    let (_, sha256, _) = oi::pinned_msi(std::env::consts::ARCH).ok_or_else(oi::installer_not_started)?;
    let downloaded = match pick {
        MsiPick::Pinned(_) => client.download_pinned(url, sha256, MAX_MSI_BYTES),
        MsiPick::Official(_) => client.download_from(url, oi::OFFICIAL_MSI_HOSTS, MAX_MSI_BYTES),
    }
    .map_err(|e| oi::download_failed(&e.to_string()))?;
    let msi = dir.join(name);
    let result = hand_over(&downloaded, &msi, pick, sha256).and_then(|(_held, step)| {
        let params = oi::step_parameters(&step).ok_or_else(oi::installer_not_started)?;
        run_step(&params)
    });
    let _ = std::fs::remove_file(&msi);
    result
}

/// The downloaded MSI moved to `msi` and made ready for the elevated step: readable by the account the step runs
/// as ([`readable_by_the_elevated_step`]), then held deny-write and checked ([`open_verified`] / [`open_official`]).
/// The held handle and the step that installs it.
pub(crate) fn hand_over(downloaded: &Path, msi: &Path, pick: &MsiPick, sha256: &str) -> Result<(File, Step), String> {
    let _ = std::fs::remove_file(msi);
    if let Err(e) = std::fs::rename(downloaded, msi) {
        let _ = std::fs::remove_file(downloaded);
        return Err(oi::download_failed(&e.to_string()));
    }
    readable_by_the_elevated_step(msi).map_err(|e| oi::download_failed(&e.to_string()))?;
    let path = msi.to_str().ok_or_else(oi::installer_not_started)?.to_string();
    Ok(match pick {
        MsiPick::Pinned(_) => (open_verified(msi, sha256)?, Step::Msi { path }),
        MsiPick::Official(_) => (open_official(msi)?, Step::OfficialMsi { path }),
    })
}

/// The elevated step reads the MSI from this user's downloads folder, but it need not run as this user: a standard
/// user's UAC prompt asks for an administrator's credentials, and the step then runs as that administrator. The
/// folder and what is downloaded into it are private (this user and SYSTEM only), so that account could not open
/// the MSI at all (2.1.0: "not signed by OpenVPN Inc."). The MSI alone gets [`Protection::Shared`] (`BUILTIN\Users`,
/// which every interactive account is a member of, may read it; only this user and SYSTEM may change it): it is
/// OpenVPN's public installer, and nobody else can change it, so the elevated step's checks still decide.
fn readable_by_the_elevated_step(msi: &Path) -> io::Result<()> {
    let f = wfile::open(
        msi,
        wfile::Open {
            read: false,
            write: true,
            append: false,
            disposition: wfile::Disposition::OpenExisting,
            protection: None,
            no_follow: true,
        },
    )?;
    wfile::set_protection(&f, Protection::Shared, false)
}

/// The downloads folder as the curl flavour's `temp_base` (where a finished download is moved).
fn downloads_temp_base() -> Result<PathBuf, String> {
    downloads_dir()
}

/// Runs the elevated step: this process' own `WinVPN.exe`, only when administrators alone can change it (an
/// installed WinVPN in Program Files), so the elevated code is the installed code.
fn run_step(parameters: &str) -> Result<StepResult, String> {
    let exe = std::env::current_exe().map_err(|_| oi::only_installed_winvpn())?;
    if !matches!(macvpn_winsys::acl_check::is_admin_only(&exe), Ok(true)) {
        return Err(oi::only_installed_winvpn());
    }
    match run_elevated(&exe, parameters) {
        Ok(code) => StepResult::from_code(code).ok_or_else(|| oi::installer_failed(code)),
        Err(code) if oi::outcome(code) == Outcome::Cancelled => Err(oi::cancelled()),
        Err(_) => Err(oi::installer_not_started()),
    }
}

/// Opens the MSI so that nobody can change, rename or delete it while the handle is open (share mode
/// `FILE_SHARE_READ` only), checks its SHA-256 through that handle and its Authenticode signer.
fn open_verified(path: &Path, sha256: &str) -> Result<File, String> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|_| oi::installer_not_started())?;
    let mut bytes = Vec::new();
    (&mut file).take(MAX_MSI_BYTES + 1).read_to_end(&mut bytes).map_err(|_| oi::installer_not_started())?;
    if bytes.len() as u64 > MAX_MSI_BYTES || macvpn_core::update::sha256_hex(&bytes) != sha256 {
        return Err(macvpn_core::update::UpdateError::ChecksumMismatch.message());
    }
    verify_signer(path)?;
    Ok(file)
}

/// A newest official MSI (fix4: no pin): opened deny-write like [`open_verified`]; its name must be an official MSI
/// name of this machine, not older than the pin, and its Authenticode signer the pinned OpenVPN signer.
fn open_official(path: &Path) -> Result<File, String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|_| oi::installer_not_started())?;
    let size = file.metadata().map_err(|_| oi::installer_not_started())?.len();
    if size > MAX_MSI_BYTES || !oi::official_msi_name_ok(path, std::env::consts::ARCH, OPENVPN_VERSION) {
        return Err(oi::not_signed_by(OPENVPN_SIGNER));
    }
    verify_signer(path)?;
    Ok(file)
}

/// The Authenticode signer must be the pinned OpenVPN signer, under one of the pinned CA keys (M-1 of the 2.0.0
/// security review: an `OpenVPN Inc.` certificate from a root an operator or a TLS-inspection product added to the
/// machine is refused).
pub(crate) fn verify_signer(path: &Path) -> Result<(), String> {
    let cas: Vec<&str> = OPENVPN_SIGNER_CA_SPKI_SHA256.split(',').collect();
    match macvpn_winsys::trust::verify_signature(path) {
        Ok(signer) if signer.is_pinned(OPENVPN_SIGNER, &cas) => Ok(()),
        _ => Err(oi::not_signed_by(OPENVPN_SIGNER)),
    }
}

/// winget as the user (it asks for elevation itself), no window, its output lines streamed; its exit code.
fn run_winget(exe: &Path, args: &[String], output: &mut dyn FnMut(&str)) -> std::io::Result<u32> {
    let mut child = Command::new(exe)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stderr = child.stderr.take().map(|mut e| {
        std::thread::spawn(move || {
            let mut s = Vec::new();
            let _ = e.read_to_end(&mut s);
            s
        })
    });
    if let Some(stdout) = child.stdout.take() {
        for line in BufReader::new(stdout).split(b'\n') {
            let Ok(line) = line else { break };
            if let Some(text) = oi::winget_line(&String::from_utf8_lossy(&line)) {
                say(output, &text);
            }
        }
    }
    let status = child.wait()?;
    if let Some(Ok(err)) = stderr.map(std::thread::JoinHandle::join) {
        for line in String::from_utf8_lossy(&err).lines() {
            if let Some(text) = oi::winget_line(line) {
                say(output, &text);
            }
        }
    }
    // An exit code is a u32 (winget's are HRESULTs such as 0x8A15002B); `code()` gives its bits as an i32.
    Ok(status.code().map_or(u32::MAX, |c| c as u32))
}

// MARK: - The elevated step (in `WinVPN.exe --winvpn-openvpn-step …`, elevated)

/// The elevated step's exit code when `args` (without the program name) start with `STEP_ARG`, else `None`.
pub(crate) fn elevated_main(args: &[String]) -> Option<u32> {
    elevated_main_with(args, Staging::production, &run_msiexec)
}

/// [`elevated_main`] with where the MSI is copied to and what runs msiexec (its parameters; its exit code, or `None`
/// when it could not start) given: the tests copy into a folder of their own and never run msiexec.
pub(crate) fn elevated_main_with(
    args: &[String],
    staging: impl FnOnce() -> io::Result<Staging>,
    msiexec: &dyn Fn(&str) -> Option<u32>,
) -> Option<u32> {
    if args.first().map(String::as_str) != Some(oi::STEP_ARG) {
        return None;
    }
    let result = match oi::parse_step(args) {
        Some(step) => step_result(step, staging, msiexec),
        None => StepResult { msi: None, interactive: Interactive::Untouched, error: Some(StepError::Arguments) },
    };
    Some(result.code())
}

/// `%SystemRoot%\System32\msiexec.exe` with `params` (one string, which msiexec parses itself); its exit code.
fn run_msiexec(params: &str) -> Option<u32> {
    let msiexec = system::system32()?.join("msiexec.exe");
    let status = Command::new(msiexec).raw_arg(params).status().ok()?;
    Some(status.code().map_or(u32::MAX, |c| c as u32))
}

fn step_result(
    step: Step,
    staging: impl FnOnce() -> io::Result<Staging>,
    msiexec: &dyn Fn(&str) -> Option<u32>,
) -> StepResult {
    let failed = |e| StepResult { msi: None, interactive: Interactive::Untouched, error: Some(e) };
    let official = matches!(step, Step::OfficialMsi { .. });
    let path = match step {
        Step::Interactive { absent_before } => {
            return StepResult { msi: None, interactive: interactive(absent_before), error: None };
        }
        Step::Msi { path } | Step::OfficialMsi { path } => PathBuf::from(path),
    };
    let Some((_, sha256, features)) = oi::pinned_msi(std::env::consts::ARCH) else {
        return failed(StepError::Arguments);
    };
    // Whether OpenVPN was there before is this process' own finding, before anything runs (security review L-2).
    let absent = !openvpn_registered();
    // Checked again here (the unelevated app's checks are not trusted), first on the file the app named, through a
    // deny-write handle: nothing that fails is copied.
    let bytes = match read_source(&path, official, sha256) {
        Ok(bytes) => bytes,
        Err(e) => return failed(e),
    };
    // Then copied into a new folder only administrators can change, and the copy checked and installed: the path
    // the app named may be re-pointed (a junction) after the checks, the copy cannot (security review L-1).
    let Ok(staged) = staging().and_then(|s| stage(&path, &bytes, &s)) else { return failed(StepError::NotStaged) };
    if let Err(e) = verify_copy(&staged, official.then_some(bytes.as_slice()), sha256) {
        return failed(e);
    }
    let Some(params) = oi::msiexec_parameters(&staged.msi, features) else { return failed(StepError::Arguments) };
    let Some(code) = msiexec(&params) else { return failed(StepError::NoMsiexec) };
    drop(staged);
    let interactive = match oi::outcome(code) {
        Outcome::Done | Outcome::DoneRestartNeeded => interactive(absent),
        _ => Interactive::Untouched,
    };
    StepResult { msi: Some(code), interactive, error: None }
}

/// The bytes of the MSI the app named, read through a deny-write handle, when they pass the checks that need no
/// copy: the pinned MSI's SHA-256; an official MSI's name and size; and the signer. A file this account may not
/// open (access denied) is [`StepError::NotReadable`], never a verdict on its signer: nothing was checked. Any
/// other failure is [`StepError::NotVerified`].
fn read_source(path: &Path, official: bool, sha256: &str) -> Result<Vec<u8>, StepError> {
    // The open the checks below repeat, alone: whether this account may read the file at all.
    if let Err(e) = std::fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(path)
        && e.kind() == io::ErrorKind::PermissionDenied
    {
        return Err(StepError::NotReadable);
    }
    let checked = if official { open_official(path) } else { open_verified(path, sha256) };
    let mut held = checked.map_err(|_| StepError::NotVerified)?;
    held.rewind().map_err(|_| StepError::NotVerified)?;
    let mut bytes = Vec::new();
    (&held).take(MAX_MSI_BYTES + 1).read_to_end(&mut bytes).map_err(|_| StepError::NotVerified)?;
    if bytes.len() as u64 > MAX_MSI_BYTES {
        return Err(StepError::NotVerified);
    }
    Ok(bytes)
}

/// Where the elevated step copies the MSI (security review L-1): `<root>\installer\<random>\<name>`.
pub(crate) struct Staging {
    /// `C:\ProgramData\WinVPN`, the WinVPN Service's data folder (created here when missing, as the service would).
    root: PathBuf,
    protection: Protection,
    /// The owner of every folder and file the step creates.
    owner: Sid,
    /// Who may own `root` and `installer` when they exist.
    owners: Vec<Sid>,
}

impl Staging {
    /// SYSTEM and Administrators only, owned by Administrators (never the user: an owner may rewrite the DACL, and
    /// the same user's unelevated processes carry the user's SID).
    fn production() -> io::Result<Staging> {
        Ok(Staging {
            root: macvpn_winsys::known::program_data()?.join("WinVPN"),
            protection: Protection::Admins,
            owner: Sid::builtin_administrators(),
            owners: vec![Sid::local_system(), Sid::builtin_administrators()],
        })
    }

    /// Tests: a private folder of this user (a standard user cannot make Administrators the owner).
    pub(crate) fn for_tests(root: &Path) -> io::Result<Staging> {
        let me = Sid::current_user()?;
        Ok(Staging { root: root.to_path_buf(), protection: Protection::Private, owner: me.clone(), owners: vec![me] })
    }

    /// `dir` exists as a real directory (no reparse point) owned by one of `owners`, with exactly the protection;
    /// created with them when missing. Anything else is refused, never repaired.
    fn ensure_dir(&self, dir: &Path) -> io::Result<()> {
        match wfile::open_metadata(dir, false) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                match wfile::create_dir_owned(dir, self.protection, &self.owner) {
                    Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
                    _ => {}
                }
            }
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        let f = wfile::open_metadata(dir, false)?;
        let info = wfile::info(&f)?;
        let ok = info.reparse_tag.is_none()
            && info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            && self.owners.contains(&info.owner)
            && wfile::has_protection(&f, self.protection, true)?;
        if ok { Ok(()) } else { Err(io::Error::new(io::ErrorKind::PermissionDenied, "unsafe installer folder")) }
    }
}

/// The MSI's copy in its own new folder, held deny-write; the folder is removed on drop.
pub(crate) struct Staged {
    dir: PathBuf,
    pub(crate) msi: PathBuf,
    held: Option<File>,
}

impl Drop for Staged {
    fn drop(&mut self) {
        self.held = None;
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Copies `bytes` (the MSI `source` names, already read) into `<root>\installer\<random>\<source's name>`: every
/// level a real directory with the staging's owner and protection, the folder and the file created new (never
/// through a link), the file then held deny-write and checked (no reparse point, one link, the owner and the
/// protection).
pub(crate) fn stage(source: &Path, bytes: &[u8], staging: &Staging) -> io::Result<Staged> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "not an MSI name");
    let name = source.file_name().and_then(|n| n.to_str()).ok_or_else(invalid)?;
    if oi::msi_file_name(name) != Some(name) {
        return Err(invalid());
    }
    let installer = staging.root.join("installer");
    staging.ensure_dir(&staging.root)?;
    staging.ensure_dir(&installer)?;
    let mut random = [0u8; 16];
    macvpn_winsys::random::fill(&mut random)?;
    let dir = installer.join(random.iter().map(|b| format!("{b:02x}")).collect::<String>());
    wfile::create_dir_owned(&dir, staging.protection, &staging.owner)?;
    let mut staged = Staged { msi: dir.join(name), dir, held: None };
    staging.ensure_dir(&staged.dir)?;
    let mut f = wfile::create_new_owned(&staged.msi, staging.protection, &staging.owner)?;
    f.write_all(bytes)?;
    f.flush()?;
    drop(f);
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&staged.msi)?;
    let info = wfile::info(&held)?;
    let ok = info.reparse_tag.is_none()
        && info.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        && info.links == 1
        && info.owner == staging.owner
        && wfile::has_protection(&held, staging.protection, false)?;
    if !ok {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "unsafe installer copy"));
    }
    staged.held = Some(held);
    Ok(staged)
}

/// The copy's checks, through its held handle and its admin-only path: the same bytes (an official MSI's `source`)
/// or the pinned SHA-256; the pinned signer; and its database naming OpenVPN Community of this machine, not older
/// than the pin ([`oi::msi_properties_ok`], security review L-2).
fn verify_copy(staged: &Staged, source: Option<&[u8]>, sha256: &str) -> Result<(), StepError> {
    let mut held = staged.held.as_ref().ok_or(StepError::NotStaged)?;
    held.rewind().map_err(|_| StepError::NotStaged)?;
    let mut bytes = Vec::new();
    held.take(MAX_MSI_BYTES + 1).read_to_end(&mut bytes).map_err(|_| StepError::NotStaged)?;
    let same = match source {
        Some(source) => bytes == source,
        None => macvpn_core::update::sha256_hex(&bytes) == sha256,
    };
    if !same || verify_signer(&staged.msi).is_err() {
        return Err(StepError::NotVerified);
    }
    let props = macvpn_winsys::msi::properties(&staged.msi).map_err(|_| StepError::NotOpenVpn)?;
    oi::msi_properties_ok(&props, std::env::consts::ARCH, OPENVPN_VERSION).ok_or(StepError::NotOpenVpn)?;
    Ok(())
}

/// Decision 4: on an installation WinVPN made, OpenVPN's Interactive Service is disabled, stopped and checked,
/// and the marker written (an MSI upgrade registers the service as automatic again, so later updates repeat this).
fn interactive(absent_before: bool) -> Interactive {
    if !oi::disable_interactive(absent_before, marker()) {
        return Interactive::Untouched;
    }
    let disabled = macvpn_winsys::scm::disable_and_stop(OPENVPN_INTERACTIVE_SERVICE, STOP_WAIT)
        .and_then(|_| macvpn_winsys::scm::query(OPENVPN_INTERACTIVE_SERVICE))
        .is_ok_and(|s| s.is_disabled_and_stopped());
    let marked = registry::write_machine_dword(oi::MARKER_KEY, oi::MARKER_VALUE, 1).is_ok();
    match (disabled, marked) {
        (false, _) => Interactive::NotDisabled,
        (true, false) => Interactive::MarkerNotWritten,
        (true, true) => Interactive::Disabled,
    }
}
