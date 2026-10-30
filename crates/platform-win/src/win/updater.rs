//! The WinVPN updater (2b plan, Task 18; maintainer decision 1: a UAC prompt from the app runs msiexec).
//!
//! `install`: the MSI of this architecture, its `.sha256` and `.sig` through System32's `curl.exe` (the shared
//! curl layer: canonical github.com URLs, checked redirects); the package moved into the private
//! `%LOCALAPPDATA%\WinVPN\updates`, opened with share mode `FILE_SHARE_READ` only (nobody writes, renames or
//! deletes it while WinVPN holds it) and hashed through that handle; the hash equals the `.sha256` and the
//! maintainer's signature verifies under WinVPN's domain and the asset's name (`pure::update`). Then the quit
//! questions. WinVPN must not hold `WinVPN.exe` while the installer replaces it, but the MSI must stay as verified
//! until msiexec is done (security review part 2, P2-L3), so a copy of WinVPN from the updates folder (the
//! relauncher: `--relaunch --target <WinVPN.exe> --msi <msi> --sha256 <hex> --log <log>`) takes over the hold:
//! 1. WinVPN creates msiexec's log new in the updates folder (never a file, link or junction already there) and
//!    holds it (read, no delete sharing);
//! 2. it starts the relauncher, which re-opens the MSI deny-write, re-hashes it, opens the log the same way and
//!    answers `held` (no answer within 20 s, or another one: nothing is installed);
//! 3. `ShellExecuteExW(runas, <System32>\msiexec.exe, /i "<msi>" /qb! /norestart /l*v "<log>")` without waiting
//!    (UAC declined: the relauncher's stdin is closed, it exits, cancelled, nothing installed);
//! 4. msiexec's PID to the relauncher, which opens the process and answers `waiting`; WinVPN quits.
//!
//! The relauncher holds both files until msiexec has exited (neither can be written, renamed or deleted, nor a
//! folder above them renamed: the elevated msiexec reads the verified package and writes the log the user created),
//! records the outcome for the next launch and starts the new `WinVPN.exe`. The MSI's own ServiceControl stops and
//! restarts the WinVPN Service.
//!
//! The elevated msiexec is another account on a standard user's computer (over-the-shoulder UAC: an
//! administrator's credentials, that administrator's process; `win::elevate`). 2.1.1 left both files with the
//! private folder's inherited DACL (this user and SYSTEM), so that msiexec could not even open its log ("error
//! opening the installation log file", 1622) nor the package. The folder stays private; the files themselves are
//! opened to it: the MSI [`Protection::Shared`] (`BUILTIN\Users` read: WinVPN's public, signed installer, re-hashed
//! by the relauncher, changeable only by this user and SYSTEM) before it is held and hashed, the log
//! [`Protection::AdminsReadWrite`] as it is created (Administrators read and write, never delete or `WRITE_DAC`).
//! The relauncher refuses to answer `held` unless both have exactly these DACLs, so nothing is elevated that the
//! administrator could not open.
//!
//! Same-user malware could hijack any UAC prompt the user approves; the deny-write handle is defence in depth, not a
//! boundary (2a's threat model, question 1).

use super::{curl_runner, elevate, system};
use crate::pure::update::{self as up, HeldMsi, Notice};
use macvpn_core::fsx;
use macvpn_core::l10n;
use macvpn_core::update::{Release, UpdateError};
use macvpn_platform_api::curl::http::{CurlHttpClient, RESOURCE_TIMEOUT};
use macvpn_platform_api::{UpdateOutcome, Updater, WINVPN};
use macvpn_winsys::file::{self as wfile, Protection};
#[cfg(debug_assertions)]
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Mutex;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;
use windows_sys::Win32::Foundation::{ERROR_CANCELLED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, DETACHED_PROCESS, GetExitCodeProcess, GetProcessId, OpenProcess, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW, WaitForSingleObject,
};
#[cfg(debug_assertions)]
use windows_sys::Win32::UI::Shell::FOLDERID_ProgramFiles;

/// The relauncher waits for msiexec at most this long (a stuck installer: WinVPN is then started by hand).
const MSIEXEC_WAIT: Duration = Duration::from_secs(30 * 60);
/// WinVPN waits this long for each of the relauncher's answers.
const ANSWER_WAIT: Duration = Duration::from_secs(20);
/// The longest line read from the relauncher's stdin.
const MAX_PID_LINE: u64 = 32;

/// What lives until WinVPN exits: the verified MSI's deny-write handle, the log's hold and msiexec's process handle
/// (its PID is not reused while the handle is open, so the relauncher opens the right process).
static KEPT: Mutex<Vec<Kept>> = Mutex::new(Vec::new());

#[allow(dead_code)] // Held for their `Drop`, never read.
enum Kept {
    File(File),
    Process(OwnedHandle),
}

fn keep(item: Kept) {
    KEPT.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(item);
}

/// `<home>\AppData\Local` in the sandbox, else `FOLDERID_LocalAppData` (as `WinPlatform::app_data_root`).
fn app_data_root(home: &Path, sandbox: bool) -> PathBuf {
    let default = || home.join("AppData").join("Local");
    if sandbox { default() } else { system::local_app_data().unwrap_or_else(default) }
}

/// `%LOCALAPPDATA%\WinVPN\updates`.
pub(crate) fn updates_dir(home: &Path, sandbox: bool) -> PathBuf {
    WINVPN.data_dir(&app_data_root(home, sandbox)).join(up::UPDATES_DIR)
}

/// The updates folder, created private (owner and SYSTEM only); a reparse point or a file there is refused.
fn prepare(dir: &Path) -> Result<(), String> {
    let not_writable = |_| UpdateError::NotWritable(dir.to_string_lossy().into_owned()).message();
    if let Some(parent) = dir.parent() {
        fsx::create_missing_private_dirs(parent).map_err(not_writable)?;
    }
    fsx::ensure_private_dir(dir).map(|_| ()).map_err(not_writable)
}

/// Opens `path` for reading with share mode `FILE_SHARE_READ` only (no writer, no delete, no rename while held),
/// never through a reparse point; a regular file only.
pub(crate) fn hold(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(fsx::not_regular_file());
    }
    Ok(file)
}

/// The verified MSI as msiexec will open it: opened to the elevated account for reading
/// ([`elevate::readable_by_the_elevated_step`], [`Protection::Shared`]), then held ([`hold`]) and checked through that
/// handle to have exactly that DACL. The download flow hashes and verifies it through the returned handle.
pub(crate) fn hold_for_msiexec(path: &Path) -> io::Result<File> {
    elevate::readable_by_the_elevated_step(path)?;
    let file = hold(path)?;
    if !wfile::has_protection(&file, Protection::Shared, false)? {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the package is not readable by the installer"));
    }
    Ok(file)
}

/// Opens msiexec's log for holding: read, share read and write (msiexec writes it), never delete (nobody renames or
/// deletes it, nor renames a folder above it, while held), never through a reparse point; a regular file only.
pub(crate) fn hold_log(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file()
        || std::os::windows::fs::MetadataExt::file_attributes(&meta) & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(fsx::not_regular_file());
    }
    Ok(file)
}

/// Creates msiexec's log at `path` (in the private updates folder) and returns its hold ([`hold_log`]): a regular file
/// left by an earlier attempt is removed first; anything else there (a folder, a junction, a link) stays and makes
/// the creation fail. Created new, never through a reparse point, and at once opened to the elevated msiexec
/// ([`elevate::writable_by_the_elevated_step`]: Administrators read and write; it may be another account than this
/// user); the write handle is closed only once the read hold is open, so the file is never unheld.
pub(crate) fn create_log(path: &Path) -> io::Result<File> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file()) {
        fs::remove_file(path)?;
    }
    let created = OpenOptions::new()
        .write(true)
        .access_mode(FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
        .create_new(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let opened = elevate::writable_by_the_elevated_step(&created);
    if let Err(e) = opened {
        drop(created);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    let held = hold_log(path)?;
    drop(created);
    Ok(held)
}

fn random_hex(bytes: usize) -> io::Result<String> {
    let mut buf = vec![0u8; bytes];
    macvpn_winsys::random::fill(&mut buf)?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

fn http() -> CurlHttpClient {
    curl_runner::http_client(curl_runner::windows_curl(), RESOURCE_TIMEOUT + curl_runner::MARGIN_SECS)
}

// MARK: - The installer

/// The relauncher as WinVPN sees it: its stdin (msiexec's PID, then the end) and its stdout's lines.
struct Relauncher {
    child: Child,
    stdin: Option<ChildStdin>,
    answers: Receiver<String>,
}

impl Relauncher {
    /// The next line within [`ANSWER_WAIT`], or `None`.
    fn answer(&self) -> Option<String> {
        self.answers.recv_timeout(ANSWER_WAIT).ok()
    }

    /// Ends the relauncher before msiexec ran: the end of its input (it then releases its holds and exits), then a
    /// short wait for it to go; still there: killed.
    fn cancel(mut self) {
        drop(self.stdin.take());
        for _ in 0..50 {
            if !matches!(self.child.try_wait(), Ok(None)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A copy of the running `WinVPN.exe` in the updates folder, started detached with the relaunch arguments, its stdin
/// and stdout piped (the handshake, `pure::update::HELD`).
fn start_relauncher(dir: &Path, args: &[String]) -> io::Result<Relauncher> {
    let exe = std::env::current_exe()?;
    let mut copy = dir.join(up::RELAUNCHER);
    let _ = fs::remove_file(&copy);
    if fs::copy(&exe, &copy).is_err() {
        // The previous relauncher may still be exiting.
        copy = dir.join(format!("WinVPN-relaunch-{}.exe", random_hex(4)?));
        fs::copy(&exe, &copy)?;
    }
    let mut child = Command::new(&copy)
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()?;
    let (stdin, stdout) = (child.stdin.take(), child.stdout.take());
    let (send, answers) = mpsc::channel();
    if let Some(stdout) = stdout {
        std::thread::spawn(move || {
            for line in BufReader::new(stdout.take(4096)).lines() {
                let Ok(line) = line else { break };
                if send.send(line).is_err() {
                    break;
                }
            }
        });
    }
    Ok(Relauncher { child, stdin, answers })
}

/// Steps 4–6 on a held, verified MSI: msiexec's log created and held, the relauncher holding both (`held`), msiexec
/// elevated (UAC), its PID to the relauncher (`waiting`), `HelperLaunched` (the app quits now, which frees
/// `WinVPN.exe`). UAC declined: the relauncher ends, the MSI is removed, `Cancelled`.
fn install_held(held: HeldMsi, log: &Path, target: &Path) -> Result<UpdateOutcome, String> {
    let dir = held.path.parent().map(Path::to_path_buf).unwrap_or_default();
    let refused = |what: &str| UpdateError::HelperFailed(what.to_string()).message();
    let remove = |held: HeldMsi| {
        let path = held.path.clone();
        drop(held);
        let _ = fs::remove_file(path);
    };
    let Some(parameters) = up::msiexec_parameters(&held.path, log) else {
        remove(held);
        return Err(refused("msiexec parameters"));
    };
    let args = up::relaunch_args(
        &target.to_string_lossy(),
        &held.path.to_string_lossy(),
        &held.sha256,
        &log.to_string_lossy(),
    );
    // The relauncher would refuse its own command line: refuse it before anything starts.
    if up::parse_relaunch(&args).is_none() {
        remove(held);
        return Err(refused("relaunch target"));
    }
    let Some(msiexec) = system::system32().map(|dir| dir.join("msiexec.exe")) else {
        remove(held);
        return Err(refused("System32"));
    };
    let log_hold = match create_log(log) {
        Ok(file) => file,
        Err(e) => {
            remove(held);
            return Err(UpdateError::NotWritable(format!("{} ({e})", log.display())).message());
        }
    };
    let relauncher = match start_relauncher(&dir, &args) {
        Ok(r) => r,
        Err(e) => {
            remove(held);
            return Err(UpdateError::HelperFailed(format!("relauncher: {e}")).message());
        }
    };
    // Nothing elevated runs until the relauncher holds the package (re-hashed) and the log.
    if relauncher.answer().as_deref() != Some(up::HELD) {
        relauncher.cancel();
        remove(held);
        return Err(refused("the relauncher did not hold the package"));
    }
    let process = match elevate::start_elevated(&msiexec, &parameters) {
        Ok(process) => process,
        Err(code) => {
            relauncher.cancel();
            remove(held);
            if code == ERROR_CANCELLED {
                return Ok(UpdateOutcome::Cancelled);
            }
            return Err(UpdateError::HelperFailed(io::Error::from_raw_os_error(code as i32).to_string()).message());
        }
    };
    // SAFETY: a valid process handle owned by `process`.
    let pid = unsafe { GetProcessId(process.as_raw_handle()) };
    keep(Kept::File(held.file));
    keep(Kept::File(log_hold));
    keep(Kept::Process(process));
    // msiexec runs now: the app must quit even if the relauncher does not answer (WinVPN is then started by hand).
    let mut relauncher = relauncher;
    // The PID, then the end of the relauncher's input.
    let sent = relauncher.stdin.take().is_some_and(|mut s| s.write_all(up::pid_line(pid).as_bytes()).is_ok());
    if !sent || relauncher.answer().as_deref() != Some(up::WAITING) {
        eprintln!("WinVPN: the update's relauncher did not take over msiexec {pid}");
    }
    Ok(UpdateOutcome::HelperLaunched)
}

/// The Windows updater (`sandbox`: the updates folder under the sandbox home, as `app_data_root`).
pub(crate) struct WinUpdater {
    pub(crate) sandbox: bool,
}

impl Updater for WinUpdater {
    fn install(
        &self,
        release: &Release,
        app: &Path,
        home: &Path,
        stage: &dyn Fn(String),
        confirm_quit: Box<dyn FnOnce() -> bool + '_>,
    ) -> Result<UpdateOutcome, String> {
        stage(l10n::tr("Downloading…", &[]));
        let dir = updates_dir(home, self.sandbox);
        prepare(&dir)?;
        let verify = |asset: &str, version: &str, sha: &str, sig: &str| up::verify_trusted(asset, version, sha, sig);
        let held = up::download_verified(&http(), release, std::env::consts::ARCH, &dir, &hold_for_msiexec, &verify)?;
        stage(l10n::tr("Preparing the installation…", &[]));
        let log = dir.join(up::log_name(&release.version));
        stage(l10n::tr("Quitting and restarting…", &[]));
        if !confirm_quit() {
            let path = held.path.clone();
            drop(held);
            let _ = fs::remove_file(path);
            return Ok(UpdateOutcome::Cancelled);
        }
        install_held(held, &log, &app.join("WinVPN.exe"))
    }

    fn launch_housekeeping(
        &self,
        _app: &Path,
        home: &Path,
        noticed: Option<&str>,
    ) -> (Vec<PathBuf>, Option<(String, String)>) {
        up::housekeeping(&updates_dir(home, self.sandbox), noticed, std::time::SystemTime::now())
    }

    /// `%LOCALAPPDATA%\WinVPN\updates`.
    fn cache_directory(&self, home: &Path) -> Option<PathBuf> {
        Some(updates_dir(home, self.sandbox))
    }
}

// MARK: - The relauncher

/// How waiting for a process ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Waited {
    Exited(u32),
    /// No such process (it ended and its PID is gone), or it cannot be opened.
    Gone,
    /// The PID is another program now.
    NotIt,
    TimedOut,
}

/// Opens process `pid` for waiting if its image is named `image` (case-insensitive); otherwise how waiting ends.
fn open_process(pid: u32, image: &str) -> Result<OwnedHandle, Waited> {
    // SAFETY: plain arguments; a null handle is the failure.
    let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        return Err(Waited::Gone);
    }
    // SAFETY: a fresh handle this function owns.
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut name = vec![0u16; 32_768];
    let mut len = name.len() as u32;
    // SAFETY: a valid process handle; `name` holds `len` u16s and `len` is updated to the length written.
    if unsafe { QueryFullProcessImageNameW(process.as_raw_handle(), PROCESS_NAME_WIN32, name.as_mut_ptr(), &mut len) }
        == 0
    {
        return Err(Waited::Gone);
    }
    let path = PathBuf::from(String::from_utf16_lossy(&name[..len as usize]));
    if !path.file_name().is_some_and(|n| n.eq_ignore_ascii_case(image)) {
        return Err(Waited::NotIt);
    }
    Ok(process)
}

/// Waits for an opened process at most `timeout`.
fn wait_process(process: &OwnedHandle, timeout: Duration) -> Waited {
    let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
    // SAFETY: a valid process handle opened with SYNCHRONIZE.
    match unsafe { WaitForSingleObject(process.as_raw_handle(), ms) } {
        WAIT_OBJECT_0 => {
            let mut code = 0u32;
            // SAFETY: a valid handle with PROCESS_QUERY_LIMITED_INFORMATION; `code` is a valid out pointer.
            if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } == 0 {
                Waited::Gone
            } else {
                Waited::Exited(code)
            }
        }
        WAIT_TIMEOUT => Waited::TimedOut,
        _ => Waited::Gone,
    }
}

/// Waits for process `pid` whose image is named `image` (case-insensitive) at most `timeout`.
pub(crate) fn wait_for(pid: u32, image: &str, timeout: Duration) -> Waited {
    match open_process(pid, image) {
        Ok(process) => wait_process(&process, timeout),
        Err(waited) => waited,
    }
}

/// Writes the outcome notice into `dir` (private, atomically).
pub(crate) fn write_notice(dir: &Path, exit_code: u32, log: &Path) -> io::Result<Notice> {
    let notice = Notice { run: random_hex(16)?, exit_code, log: log.to_string_lossy().into_owned() };
    fsx::atomic_write(&dir.join(up::NOTICE_FILE), notice.encode().as_bytes(), fsx::Access::Private)?;
    Ok(notice)
}

/// One answer to WinVPN on stdout (a closed pipe is ignored: WinVPN may have quit).
fn answer(line: &str) {
    let mut out = io::stdout().lock();
    let _ = out.write_all(format!("{line}\n").as_bytes());
    let _ = out.flush();
}

/// The MSI (`relaunch.msi`, re-opened deny-write and re-hashed against `relaunch.sha256`) and msiexec's log, both
/// in `dir` (the relauncher's own folder, the updates folder), held. Each must have exactly the DACL that opens it
/// to the elevated msiexec, which may be another account (the MSI [`Protection::Shared`], the log
/// [`Protection::AdminsReadWrite`]): otherwise msiexec would fail to open them (1619, 1622) after the UAC prompt.
pub(crate) fn hold_both(relaunch: &up::Relaunch, dir: &Path) -> Result<(File, File), String> {
    if !up::in_folder(&relaunch.msi, dir) || !up::in_folder(&relaunch.log, dir) {
        return Err("the package or the log is not in the updates folder".into());
    }
    let mut msi = hold(&relaunch.msi).map_err(|e| format!("cannot hold the package ({e})"))?;
    let sha256 = up::hash(&mut msi).map_err(|e| format!("cannot hash the package ({e})"))?;
    if sha256 != relaunch.sha256 {
        return Err("the package is not the verified one".into());
    }
    if !wfile::has_protection(&msi, Protection::Shared, false).unwrap_or(false) {
        return Err("the package is not readable by the installer's account".into());
    }
    let log = hold_log(&relaunch.log).map_err(|e| format!("cannot hold the log ({e})"))?;
    if !wfile::has_protection(&log, Protection::AdminsReadWrite, false).unwrap_or(false) {
        return Err("the log is not writable by the installer's account".into());
    }
    Ok((msi, log))
}

/// The relauncher (`WinVPN-relaunch.exe --relaunch --target <exe> --msi <msi> --sha256 <hex> --log <log>`, a copy of
/// WinVPN.exe in the updates folder): holds the MSI (deny-write, re-hashed: it must be the verified one) and
/// msiexec's log and answers `held`; reads msiexec's PID from stdin (the end of input instead: the update was
/// cancelled, it exits), opens that process and answers `waiting`; waits for msiexec (at most 30 minutes) with both
/// files held, records its exit code in its own folder for the next launch, and starts the new `target`. msiexec
/// already gone or the PID another program: no notice, `target` is started. Still running after 30 minutes:
/// nothing is started (the installer may still be replacing it).
pub(crate) fn relaunch_after(relaunch: &up::Relaunch) {
    let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) else { return };
    let holds = match hold_both(relaunch, &dir) {
        Ok(holds) => holds,
        Err(why) => {
            answer(&format!("refused: {why}"));
            return;
        }
    };
    answer(up::HELD);
    let mut line = String::new();
    let _ = io::stdin().lock().take(MAX_PID_LINE).read_line(&mut line);
    let Some(pid) = up::parse_pid_line(&line) else { return };
    let process = open_process(pid, "msiexec.exe");
    answer(up::WAITING);
    let waited = match &process {
        Ok(process) => wait_process(process, MSIEXEC_WAIT),
        Err(_) => Waited::Gone,
    };
    drop(holds);
    match waited {
        Waited::TimedOut => return,
        Waited::Exited(code) => {
            if let Err(e) = write_notice(&dir, code, &relaunch.log) {
                eprintln!("WinVPN: the update's outcome could not be recorded: {e}");
            }
        }
        Waited::Gone | Waited::NotIt => {}
    }
    let target = &relaunch.target;
    let _ = Command::new(target)
        .current_dir(target.parent().unwrap_or(Path::new(r"C:\")))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS)
        .spawn();
}

/// Debug builds (CP2): steps 4–6 on a local MSI, without download or signature: the MSI is copied into the updates
/// folder, held and hashed (the relauncher re-hashes it), msiexec runs elevated, the relauncher waits and then starts
/// the installed `<Program Files>\WinVPN\WinVPN.exe`. Quit WinVPN first (no quit question here).
#[cfg(debug_assertions)]
pub(crate) fn test_install_msi(msi: &Path) -> Result<String, String> {
    let name = msi.file_name().and_then(OsStr::to_str).ok_or("not a file name")?;
    if !msi.is_absolute() || !name.to_ascii_lowercase().ends_with(".msi") || !msi.is_file() {
        return Err(format!("not an absolute path of an .msi file: {}", msi.display()));
    }
    let home = system::profile().ok_or("no user profile")?;
    let dir = updates_dir(&home, false);
    prepare(&dir)?;
    let dest = dir.join(name);
    if !dest.as_os_str().eq_ignore_ascii_case(msi.as_os_str()) {
        let _ = fs::remove_file(&dest);
        fs::copy(msi, &dest).map_err(|e| e.to_string())?;
    }
    let mut file = hold_for_msiexec(&dest).map_err(|e| e.to_string())?;
    let sha256 = up::hash(&mut file).map_err(|e| e.to_string())?;
    let held = HeldMsi { path: dest.clone(), file, sha256 };
    let program_files = system::known_folder(&FOLDERID_ProgramFiles).ok_or("no Program Files folder")?;
    let target = program_files.join("WinVPN").join("WinVPN.exe");
    let log = dir.join(up::log_name("test"));
    match install_held(held, &log, &target)? {
        UpdateOutcome::HelperLaunched => Ok(format!(
            "msiexec runs ({}); log {}; the relauncher starts {} afterwards",
            dest.display(),
            log.display(),
            target.display()
        )),
        UpdateOutcome::Cancelled => Ok("cancelled (UAC declined); nothing installed".into()),
    }
}
