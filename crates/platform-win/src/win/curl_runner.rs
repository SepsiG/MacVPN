//! The curl layer on Windows (2b plan, Tasks 17, 18 and 19: the OpenVPN download, the updater, the HTTPS catalogs
//! and the update check): System32's `curl.exe` (Schannel, the system trust store) as the [`Curl`] flavour, and
//! the [`CommandRunner`] that starts it.
//!
//! - **The executable** comes from `FOLDERID_System`, never `PATH`; the runner refuses a relative path.
//! - **The environment** is `SystemRoot` (Winsock needs it) and `PATH=<System32>` only: no `*_proxy`, no
//!   `CURL_HOME` / `APPDATA` (`-q` also skips `.curlrc`), nothing of the app's.
//! - **No console window** (`CREATE_NO_WINDOW`).
//! - **Stdin** (the bearer token's `--config -`) is written from memory on a thread and the pipe closed; the token is
//!   never in the argv (Task Manager's command line column) or a log line. Without stdin the child gets `NUL`.
//! - **A time limit** after which the child is killed and [`CommandError::TimedOut`] returned: the argv's
//!   `--max-time` plus 30 s (60 s without one), never more than the runner's own cap (curl's own `--max-time` ends
//!   it first; this is the backstop).
//! - **Output caps**: stdout and stderr are kept up to 1 MiB each, the rest drained.
//! - **Private directories** for the layer's files: `<user temp>\<prefix>.<32 hex>`, created fresh (never an
//!   existing one) with the owner-only DACL, then checked by `fsx::ensure_private_dir` (protected DACL, no reparse
//!   point).

use super::system;
use macvpn_core::fsx;
use macvpn_platform_api::curl::http::CurlHttpClient;
use macvpn_platform_api::curl::{CommandError, CommandResult, CommandRunner, Curl};
use std::io::{self, Read, Write};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

/// The flavour's extra argument: Schannel otherwise fails when a CRL server cannot be reached; a certificate that is
/// known to be revoked is still refused.
const REVOKE_BEST_EFFORT: &str = "--ssl-revoke-best-effort";
/// How often the runner looks at the child.
const POLL: Duration = Duration::from_millis(20);
/// At most this much of stdout and of stderr is kept (curl writes its `--write-out` trailer and a message); the rest
/// is read and dropped so the child never blocks on a full pipe.
const OUTPUT_CAP: u64 = 1024 * 1024;
/// The runner's margin over curl's own `--max-time`.
pub(crate) const MARGIN_SECS: f64 = 30.0;
/// curl's `--max-time` assumed when the argv has none.
const DEFAULT_MAX_TIME: u64 = 30;

/// System32's `curl.exe` with `--ssl-revoke-best-effort`. Without System32 (it cannot be read) the executable is
/// empty, which the runner refuses (fail closed).
pub(crate) fn windows_curl() -> Curl {
    let executable =
        system::system32().map(|dir| dir.join("curl.exe").to_string_lossy().into_owned()).unwrap_or_default();
    Curl { executable, extra_args: vec![REVOKE_BEST_EFFORT], private_dir, temp_base }
}

/// WinVPN's user agent for GitHub's API and the downloads (macOS keeps `MacVPN-Updater`).
pub(crate) fn user_agent() -> String {
    format!("WinVPN-Updater/{}", env!("CARGO_PKG_VERSION"))
}

/// The HTTP client of the update check, the updater and the OpenVPN download: `curl` (normally [`windows_curl`])
/// over a [`WinCurlRunner`] capped at `cap` seconds, with WinVPN's [`user_agent`].
pub(crate) fn http_client(curl: Curl, cap: f64) -> CurlHttpClient {
    CurlHttpClient::new_with(Box::new(WinCurlRunner::new(cap)), curl, user_agent())
}

/// `<user temp>\<prefix>.<32 hex>`, new and owner-only.
fn private_dir(prefix: &str) -> Result<PathBuf, String> {
    let mut random = [0u8; 16];
    macvpn_winsys::random::fill(&mut random).map_err(|e| e.to_string())?;
    let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("{prefix}.{suffix}"));
    // A new directory (a name that exists already is never taken over), owner-only from its creation.
    macvpn_winsys::file::create_dir(&dir, Some(macvpn_winsys::file::Protection::Private))
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    if let Err(e) = fsx::ensure_private_dir(&dir) {
        let _ = std::fs::remove_dir(&dir);
        return Err(format!("{}: {e}", dir.display()));
    }
    Ok(dir)
}

/// Where a finished download is moved: the user's temp folder (inside the profile, the user's own).
fn temp_base() -> Result<PathBuf, String> {
    Ok(std::env::temp_dir())
}

/// The time limit of one curl run: its `--max-time` plus [`MARGIN_SECS`] (60 s without one), so curl's own limit
/// ends it first and the runner only stops a curl that hangs.
pub(crate) fn time_limit(args: &[String]) -> Duration {
    let max_time = args
        .iter()
        .position(|a| a == "--max-time")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MAX_TIME);
    Duration::from_secs(max_time.saturating_add(MARGIN_SECS as u64))
}

/// The Windows runner of the curl layer (see the module docs).
pub(crate) struct WinCurlRunner {
    cap: Duration,
}

impl WinCurlRunner {
    /// `cap`: seconds after which the child is killed at the latest (each run's own limit is [`time_limit`] of its
    /// argv, if shorter).
    pub(crate) fn new(cap: f64) -> Self {
        WinCurlRunner { cap: Duration::from_secs_f64(cap.max(0.0)) }
    }

    fn start(&self, executable: &str, arguments: &[String], with_stdin: bool) -> io::Result<Child> {
        if !Path::new(executable).is_absolute() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("not an absolute path: {executable}")));
        }
        let (Some(root), Some(system32)) = (system::windows_dir(), system::system32()) else {
            return Err(io::Error::new(io::ErrorKind::NotFound, "the Windows folder cannot be read"));
        };
        Command::new(executable)
            .args(arguments)
            .env_clear()
            .env("SystemRoot", root)
            .env("PATH", system32)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(if with_stdin { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    }

    fn run_with(
        &self,
        executable: &str,
        arguments: &[String],
        stdin: Option<&[u8]>,
    ) -> Result<CommandResult, CommandError> {
        let mut child = self.start(executable, arguments, stdin.is_some()).map_err(CommandError::Io)?;
        let input = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let deadline = Instant::now() + self.cap.min(time_limit(arguments));
        std::thread::scope(|scope| {
            if let (Some(mut pipe), Some(bytes)) = (input, stdin) {
                // A child that exits without reading closes the pipe: the write fails, which is not an error here.
                scope.spawn(move || {
                    let _ = pipe.write_all(bytes);
                });
            }
            let out = scope.spawn(move || read_capped(stdout));
            let err = scope.spawn(move || read_capped(stderr));
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Ok(status),
                    Ok(None) if Instant::now() >= deadline => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break Err(CommandError::TimedOut(executable.to_string()));
                    }
                    Ok(None) => std::thread::sleep(POLL),
                    Err(e) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        break Err(CommandError::Io(e));
                    }
                }
            };
            // The pipes close with the child, so the readers end.
            let stdout = out.join().unwrap_or_default();
            let stderr = err.join().unwrap_or_default();
            let status = status?;
            Ok(CommandResult {
                exit_code: status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&stdout).into_owned(),
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
            })
        })
    }
}

/// Everything the pipe brings, the first [`OUTPUT_CAP`] bytes kept.
fn read_capped(pipe: Option<impl Read>) -> Vec<u8> {
    let mut kept = Vec::new();
    if let Some(mut pipe) = pipe {
        let _ = pipe.by_ref().take(OUTPUT_CAP).read_to_end(&mut kept);
        let _ = io::copy(&mut pipe, &mut io::sink());
    }
    kept
}

impl CommandRunner for WinCurlRunner {
    fn run(&self, executable: &str, arguments: &[String], stdin: Option<&str>) -> Result<CommandResult, CommandError> {
        self.run_with(executable, arguments, stdin.map(str::as_bytes))
    }

    fn run_bytes(&self, executable: &str, arguments: &[String], stdin: &[u8]) -> Result<CommandResult, CommandError> {
        self.run_with(executable, arguments, Some(stdin))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limit_follows_max_time() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(time_limit(&args(&["--max-time", "600", "--", "https://x"])), Duration::from_secs(630));
        assert_eq!(time_limit(&args(&["--max-time", "x"])), Duration::from_secs(60));
        assert_eq!(time_limit(&args(&[])), Duration::from_secs(60));
    }

    #[test]
    fn curl_runs_from_system32_with_a_bare_environment() {
        let curl = windows_curl();
        assert!(curl.executable.to_ascii_lowercase().ends_with(r"\system32\curl.exe"), "{}", curl.executable);
        let runner = WinCurlRunner::new(60.0);
        let r = runner.run(&curl.executable, &["--version".to_string()], None).unwrap();
        assert_eq!(r.exit_code, 0, "{}", r.stderr);
        assert!(r.stdout.starts_with("curl "), "{}", r.stdout);
        // stdin reaches the child (`--config -` reads it): an unknown option fails with curl's own message.
        let r = runner.run(&curl.executable, &["--config".into(), "-".into()], Some("not-an-option\n")).unwrap();
        assert_ne!(r.exit_code, 0);
        let dir = (curl.private_dir)("macvpn-test").unwrap();
        assert!(dir.is_dir());
        assert_eq!(dir.file_name().unwrap().to_string_lossy().len(), "macvpn-test.".len() + 32);
        std::fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn winvpn_names_itself_to_github() {
        assert_eq!(user_agent(), format!("WinVPN-Updater/{}", env!("CARGO_PKG_VERSION")));
    }
}
