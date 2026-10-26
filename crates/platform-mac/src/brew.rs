//! Homebrew (port of `BrewBootstrap.swift` and the app's `BrewInstaller.swift`): the Terminal `.command` script
//! that runs the official installer, the minimal environment for `brew install`, running it (and `brew upgrade`)
//! with live output, `brew outdated`, the daily `brew update`, and the guard that keeps MacVPN's brew commands
//! from overlapping.

use crate::command::CommandRunner;
use crate::setup_checker::SetupChecker;
use crate::temp_dir::{MessageError, SecureTempDirectory, tr1};
use macvpn_core::l10n::{self, Arg};
use macvpn_platform_api::{OutdatedPackage, PackageIndexUpdate};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError, TryLockError, mpsc};
use std::time::{Duration, Instant};

/// Environment for `brew install`: only what Homebrew needs, so nothing from the app's environment (for example a
/// `HOMEBREW_*` override pointing at another tap or remote, or `DYLD_*` / `RUBYOPT`) reaches it.
pub struct BrewEnvironment;

impl BrewEnvironment {
    pub const PASSED: [&'static str; 5] = ["HOME", "USER", "LOGNAME", "TMPDIR", "LANG"];

    pub fn make(environment: &BTreeMap<String, String>, brew_prefix: &str) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        for key in Self::PASSED {
            if let Some(value) = environment.get(key) {
                env.insert(key.to_string(), value.clone());
            }
        }
        env.insert("PATH".into(), format!("{brew_prefix}/bin:{brew_prefix}/sbin:/usr/bin:/bin:/usr/sbin:/sbin"));
        env.insert("HOMEBREW_NO_ENV_HINTS".into(), "1".into());
        env
    }
}

/// The Terminal `.command` script that runs the official Homebrew installer.
pub struct BrewBootstrap;

pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

impl BrewBootstrap {
    pub const INSTALLER_URL: &'static str = "https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh";
    pub const DIRECTORY_PREFIX: &'static str = "macvpn-brew.";

    /// The installer is downloaded first; if `curl` fails the script stops with `failed` instead of running an
    /// empty or partial script. The script deletes its own directory when it exits.
    pub fn script(start: &str, done: &str, failed: &str, cleanup_directory: &str) -> String {
        format!(
            "#!/bin/bash\ntrap {} EXIT\necho {}\ns=$(/usr/bin/curl -fsSL {}) || {{ echo {}; exit 1; }}\n/bin/bash -c \"$s\"\necho; echo {}\n",
            shell_quote(&format!("rm -rf -- {}", shell_quote(cleanup_directory))),
            shell_quote(start),
            Self::INSTALLER_URL,
            shell_quote(failed),
            shell_quote(done),
        )
    }

    /// Writes the script (built from its directory's path) into a fresh `mkdtemp` 0700 directory in `parent`,
    /// created with O_EXCL | O_NOFOLLOW and mode 0700. Every error is returned.
    pub fn write(script: impl FnOnce(&str) -> String, parent: &Path) -> Result<PathBuf, MessageError> {
        let dir = SecureTempDirectory::make(Self::DIRECTORY_PREFIX, parent)?;
        let path = dir.join("install-homebrew.command");
        let cleanup = |e: MessageError| {
            SecureTempDirectory::remove_if_owned(&dir, Self::DIRECTORY_PREFIX);
            e
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| cleanup(MessageError(tr1("Cannot write: %@", &path.to_string_lossy()))))?;
        file.write_all(script(&dir.to_string_lossy()).as_bytes()).map_err(|e| cleanup(MessageError(e.to_string())))?;
        drop(file);
        // The umask may have narrowed it: exactly 0700 (executable for Terminal).
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|_| cleanup(MessageError(tr1("Cannot set the permissions: %@", &path.to_string_lossy()))))?;
        Ok(path)
    }
}

/// `brew install …` (and `brew upgrade …`) as the user, with live output (the app's `BrewInstaller`).
pub struct BrewInstaller;

impl BrewInstaller {
    /// The first output line.
    pub fn header() -> String {
        Self::command_line(&Self::install_arguments())
    }

    /// The first output line of `brew upgrade <formulae>`.
    pub fn upgrade_header(formulae: &[String]) -> String {
        Self::command_line(&Self::upgrade_arguments(formulae))
    }

    fn command_line(arguments: &[String]) -> String {
        format!("$ brew {}\n", arguments.join(" "))
    }

    fn install_arguments() -> Vec<String> {
        std::iter::once("install").chain(SetupChecker::BREW_PACKAGES).map(str::to_string).collect()
    }

    /// Only the formulae MacVPN installs (anything else in `formulae` is dropped), so the action never upgrades
    /// what the user installed for other reasons.
    fn upgrade_arguments(formulae: &[String]) -> Vec<String> {
        std::iter::once("upgrade".to_string())
            .chain(
                SetupChecker::BREW_PACKAGES.iter().filter(|p| formulae.iter().any(|f| f == *p)).map(|p| p.to_string()),
            )
            .collect()
    }

    /// The last output line for an exit status.
    pub fn footer(status: i32) -> String {
        if status == 0 {
            format!("\n✓ {}\n", l10n::tr("Done.", &[]))
        } else {
            format!("\n✗ {}\n", l10n::tr("brew error (%d)", &[Arg::Int(i64::from(status))]))
        }
    }

    /// Runs `<prefix>/bin/brew install <packages>` with [`BrewEnvironment`] built from `environment`; stdout and
    /// stderr are one pipe, every chunk goes to `output` in order (the header first, the footer last, after both
    /// EOF and the exit). Returns the exit status.
    pub fn install(
        brew_prefix: &str,
        environment: &BTreeMap<String, String>,
        mut output: impl FnMut(&str),
    ) -> std::io::Result<i32> {
        let arguments = Self::install_arguments();
        Self::run(&format!("{brew_prefix}/bin/brew"), &arguments, brew_prefix, environment, Self::TIMEOUT, &mut output)
    }

    /// Runs `<prefix>/bin/brew upgrade <formulae>` (only those of [`SetupChecker::BREW_PACKAGES`]) like
    /// [`Self::install`]: the same environment, header and footer, and time limit. Homebrew updates its taps first
    /// (its own auto-update), so the newest version is installed.
    pub fn upgrade(
        brew_prefix: &str,
        formulae: &[String],
        environment: &BTreeMap<String, String>,
        mut output: impl FnMut(&str),
    ) -> std::io::Result<i32> {
        Self::upgrade_at(&format!("{brew_prefix}/bin/brew"), formulae, brew_prefix, environment, &mut output)
    }

    fn upgrade_at(
        executable: &str,
        formulae: &[String],
        brew_prefix: &str,
        environment: &BTreeMap<String, String>,
        output: &mut dyn FnMut(&str),
    ) -> std::io::Result<i32> {
        let arguments = Self::upgrade_arguments(formulae);
        // A bare `brew upgrade` would upgrade everything the user has: never.
        if arguments.len() < 2 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "no formula to upgrade"));
        }
        Self::run(executable, &arguments, brew_prefix, environment, Self::TIMEOUT, output)
    }

    /// `brew install` may take long (bottles, builds), but not forever.
    pub const TIMEOUT: Duration = Duration::from_secs(30 * 60);

    fn run(
        executable: &str,
        arguments: &[String],
        brew_prefix: &str,
        environment: &BTreeMap<String, String>,
        timeout: Duration,
        output: &mut dyn FnMut(&str),
    ) -> std::io::Result<i32> {
        output(&Self::command_line(arguments));
        let (mut reader, writer) = std::io::pipe()?;
        let mut command = Command::new(executable);
        crate::sys::close_inherited_fds(&mut command);
        let spawned = command
            .args(arguments)
            .env_clear()
            .envs(BrewEnvironment::make(environment, brew_prefix))
            .stdin(Stdio::null())
            .stdout(writer.try_clone()?)
            .stderr(writer)
            .spawn();
        // The command holds the parent's copies of the pipe's write end: drop it, or the read never sees EOF.
        drop(command);
        let mut child = match spawned {
            Ok(child) => child,
            Err(e) => {
                output(&format!("✗ {e}\n"));
                return Err(e);
            }
        };
        // Our copies of the write end are gone (moved into the child's stdio), so the read reaches EOF. One thread
        // reads; this one passes the chunks on in order and watches the time limit.
        let (tx, rx) = mpsc::channel::<std::io::Result<Vec<u8>>>();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 8192];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => return,
                    Ok(n) => {
                        if tx.send(Ok(buffer[..n].to_vec())).is_err() {
                            return;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => {
                        let _ = tx.send(Err(e));
                        return;
                    }
                }
            }
        });
        let deadline = Instant::now() + timeout;
        let mut killed_at: Option<Instant> = None;
        let mut pending: Vec<u8> = Vec::new();
        let mut read_error: Option<std::io::Error> = None;
        loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Ok(chunk)) => {
                    pending.extend_from_slice(&chunk);
                    // Only whole UTF-8 sequences are passed on.
                    let valid = match std::str::from_utf8(&pending) {
                        Ok(_) => pending.len(),
                        Err(e) if e.error_len().is_none() => e.valid_up_to(),
                        Err(_) => pending.len(),
                    };
                    if valid > 0 {
                        output(&String::from_utf8_lossy(&pending[..valid]));
                        pending.drain(..valid);
                    }
                }
                Ok(Err(e)) => {
                    read_error = Some(e);
                    break;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if Instant::now() >= deadline {
                match killed_at {
                    None => {
                        crate::sys::kill(child.id() as i32, crate::sys::SIGTERM);
                        killed_at = Some(Instant::now());
                    }
                    Some(at) if at.elapsed() >= Duration::from_secs(2) => {
                        let _ = child.kill();
                    }
                    Some(_) => {}
                }
                // Stop waiting for EOF once the child itself is gone (a grandchild may keep the pipe open).
                if killed_at.is_some() && child.try_wait().ok().flatten().is_some() {
                    break;
                }
            }
        }
        if !pending.is_empty() {
            output(&String::from_utf8_lossy(&pending));
        }
        // Always reaped, also after a read error (killed then, so the wait cannot hang).
        if read_error.is_some() {
            let _ = child.kill();
        }
        let status = child.wait()?;
        if let Some(e) = read_error {
            return Err(e);
        }
        let code = status.code().or_else(|| status.signal()).unwrap_or(-1);
        output(&Self::footer(code));
        Ok(code)
    }

    #[doc(hidden)]
    pub fn run_for_tests(
        executable: &str,
        brew_prefix: &str,
        environment: &BTreeMap<String, String>,
        timeout: Duration,
        mut output: impl FnMut(&str),
    ) -> std::io::Result<i32> {
        Self::run(executable, &Self::install_arguments(), brew_prefix, environment, timeout, &mut output)
    }

    #[doc(hidden)]
    pub fn run_upgrade_for_tests(
        executable: &str,
        formulae: &[String],
        brew_prefix: &str,
        environment: &BTreeMap<String, String>,
        mut output: impl FnMut(&str),
    ) -> std::io::Result<i32> {
        Self::upgrade_at(executable, formulae, brew_prefix, environment, &mut output)
    }
}

/// `brew outdated --json=v2 --formula <BREW_PACKAGES>`: which of MacVPN's formulae have a newer version in the
/// local tap state. Homebrew's auto-update is switched off for it (`HOMEBREW_NO_AUTO_UPDATE=1`): the check is quick
/// and needs no network; the taps are updated by MacVPN's daily [`BrewUpdate`] and by Homebrew whenever the user
/// runs `brew install` / `brew upgrade` (also the System Status window's "Install" / "Update").
pub struct BrewOutdated;

impl BrewOutdated {
    /// Seconds; past it the answer is unknown (no update offered).
    pub const TIMEOUT: f64 = 20.0;

    pub fn arguments() -> Vec<String> {
        ["outdated", "--json=v2", "--formula"]
            .into_iter()
            .chain(SetupChecker::BREW_PACKAGES)
            .map(str::to_string)
            .collect()
    }

    /// [`BrewEnvironment`] with Homebrew's auto-update off.
    pub fn environment(environment: &BTreeMap<String, String>, brew_prefix: &str) -> BTreeMap<String, String> {
        let mut env = BrewEnvironment::make(environment, brew_prefix);
        env.insert("HOMEBREW_NO_AUTO_UPDATE".into(), "1".into());
        env
    }

    /// Runs `<prefix>/bin/brew outdated …` with `runner` (which carries [`Self::environment`] and
    /// [`Self::TIMEOUT`]). Any failure (cannot run, timeout, output that is not the expected JSON) is "unknown":
    /// an empty list. The exit status is not looked at: with named formulae `brew outdated` exits 1 when one is
    /// outdated.
    pub fn check(runner: &dyn CommandRunner, brew_prefix: &str) -> Vec<OutdatedPackage> {
        match runner.run(&format!("{brew_prefix}/bin/brew"), &Self::arguments(), None) {
            Ok(result) => Self::parse(&result.stdout).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    /// The `formulae` of `brew outdated --json=v2`: those of [`SetupChecker::BREW_PACKAGES`], not pinned, with an
    /// installed and a current version (the highest installed one when several are). In
    /// [`SetupChecker::BREW_PACKAGES`]' order. `None`: not the expected JSON.
    pub fn parse(json: &str) -> Option<Vec<OutdatedPackage>> {
        let json = json.trim();
        // Anything printed before the document (a tap's warning on stdout) is skipped.
        let start = json.find('{')?;
        let value: serde_json::Value = serde_json::from_str(&json[start..]).ok()?;
        let formulae = value.get("formulae")?.as_array()?;
        let mut found: Vec<OutdatedPackage> = Vec::new();
        for formula in formulae {
            let Some(name) = formula.get("name").and_then(|n| n.as_str()) else { continue };
            if !SetupChecker::BREW_PACKAGES.contains(&name) || found.iter().any(|f| f.name == name) {
                continue;
            }
            if formula.get("pinned").and_then(|p| p.as_bool()).unwrap_or(false) {
                continue;
            }
            let installed = formula
                .get("installed_versions")
                .and_then(|v| v.as_array())
                .and_then(|v| v.iter().filter_map(|v| v.as_str()).rfind(|v| !v.is_empty()));
            let current = formula.get("current_version").and_then(|v| v.as_str()).filter(|v| !v.is_empty());
            let (Some(installed), Some(current)) = (installed, current) else { continue };
            if installed == current {
                continue;
            }
            found.push(OutdatedPackage { name: name.into(), installed: installed.into(), available: current.into() });
        }
        found.sort_by_key(|f| SetupChecker::BREW_PACKAGES.iter().position(|p| *p == f.name));
        Some(found)
    }
}

/// One brew command of MacVPN's at a time (in this process): `brew install` / `brew upgrade` wait for a running
/// `brew update` ([`Self::lock`]); the daily `brew update` skips its round while one runs ([`Self::try_lock`]).
/// `brew outdated` (read-only, no auto-update) is not guarded.
#[derive(Debug, Default)]
pub struct BrewGuard(Mutex<()>);

/// The app's guard.
pub static BREW_GUARD: BrewGuard = BrewGuard::new();

impl BrewGuard {
    pub const fn new() -> Self {
        BrewGuard(Mutex::new(()))
    }

    /// Waits until no other guarded command runs.
    pub fn lock(&self) -> MutexGuard<'_, ()> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `None`: another guarded command runs.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, ()>> {
        match self.0.try_lock() {
            Ok(guard) => Some(guard),
            Err(TryLockError::Poisoned(e)) => Some(e.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        }
    }
}

/// `brew update` as the user, at most once a day (app-core's `package_index` schedule), so `brew outdated` (which
/// does not update the taps itself) sees the newest versions. Quiet: its output is not shown, a failure is only
/// logged.
pub struct BrewUpdate;

impl BrewUpdate {
    /// Seconds.
    pub const TIMEOUT: f64 = 120.0;

    pub fn arguments() -> Vec<String> {
        vec!["update".to_string()]
    }

    /// [`BrewEnvironment`], nothing more.
    pub fn environment(environment: &BTreeMap<String, String>, brew_prefix: &str) -> BTreeMap<String, String> {
        BrewEnvironment::make(environment, brew_prefix)
    }

    /// Runs `<prefix>/bin/brew update` with `runner` (which carries [`Self::environment`] and [`Self::TIMEOUT`])
    /// while holding `guard`; `Busy` without running when another guarded command runs. Exit 0: `Updated`;
    /// anything else (cannot run, timeout, non-zero exit) is `Failed` with a message for the log.
    pub fn run(runner: &dyn CommandRunner, brew_prefix: &str, guard: &BrewGuard) -> PackageIndexUpdate {
        let Some(_held) = guard.try_lock() else { return PackageIndexUpdate::Busy };
        match runner.run(&format!("{brew_prefix}/bin/brew"), &Self::arguments(), None) {
            Ok(result) if result.exit_code == 0 => PackageIndexUpdate::Updated,
            Ok(result) => {
                let detail = result.stderr.lines().rfind(|l| !l.trim().is_empty()).unwrap_or("").trim();
                PackageIndexUpdate::Failed(format!("brew update exited with {}: {detail}", result.exit_code))
            }
            Err(e) => PackageIndexUpdate::Failed(e.to_string()),
        }
    }
}
