//! Homebrew (port of `BrewBootstrap.swift` and the app's `BrewInstaller.swift`): the Terminal `.command` script
//! that runs the official installer, the minimal environment for `brew install`, and running it with live output.

use crate::setup_checker::SetupChecker;
use crate::temp_dir::{MessageError, SecureTempDirectory, tr1};
use macvpn_core::l10n::{self, Arg};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
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

/// `brew install …` as the user, with live output (the app's `BrewInstaller`).
pub struct BrewInstaller;

impl BrewInstaller {
    /// The first output line.
    pub fn header() -> String {
        format!("$ brew install {}\n", SetupChecker::BREW_PACKAGES.join(" "))
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
        Self::run(&format!("{brew_prefix}/bin/brew"), brew_prefix, environment, Self::TIMEOUT, &mut output)
    }

    /// `brew install` may take long (bottles, builds), but not forever.
    pub const TIMEOUT: Duration = Duration::from_secs(30 * 60);

    fn run(
        executable: &str,
        brew_prefix: &str,
        environment: &BTreeMap<String, String>,
        timeout: Duration,
        output: &mut dyn FnMut(&str),
    ) -> std::io::Result<i32> {
        output(&Self::header());
        let (mut reader, writer) = std::io::pipe()?;
        let mut command = Command::new(executable);
        crate::sys::close_inherited_fds(&mut command);
        let spawned = command
            .arg("install")
            .args(SetupChecker::BREW_PACKAGES)
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
        Self::run(executable, brew_prefix, environment, timeout, &mut output)
    }
}
