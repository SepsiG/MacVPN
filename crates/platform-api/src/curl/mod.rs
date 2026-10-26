//! The curl layer shared by macOS (`/usr/bin/curl`) and Windows (System32's `curl.exe`): the update check, the
//! download ([`http`]) and the HTTPS team catalog fetch ([`catalog`]). The security logic (the redirect policy, the
//! canonical URLs, the size caps, the conditional GET, the token-only-to-its-origin rule, the bearer token on stdin)
//! exists once here; a [`Curl`] flavour names what differs per OS (the executable, extra arguments, private
//! directories). The runner (how a process is started, its environment and time limit) is the platform crate's.
//!
//! [`CommandRunner`], [`CommandResult`] and [`CommandError`] moved here from `macvpn-platform-mac`'s `command`
//! module (port of `CommandRunner.swift`), which re-exports them.

pub mod catalog;
pub mod http;

use macvpn_core::l10n::{self, Arg};
use std::io;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandResult {
    pub fn new(exit_code: i32, stdout: &str, stderr: &str) -> Self {
        CommandResult { exit_code, stdout: stdout.to_string(), stderr: stderr.to_string() }
    }

    pub fn exit(exit_code: i32) -> Self {
        CommandResult { exit_code, ..Default::default() }
    }

    pub fn stdout(stdout: &str) -> Self {
        CommandResult { stdout: stdout.to_string(), ..Default::default() }
    }
}

#[derive(Debug)]
pub enum CommandError {
    /// Stopped after the runner's timeout (the executable path).
    TimedOut(String),
    /// Stopped by the runner's cancel token (macOS: `CancelToken::cancel`; Swift `CancellationError`).
    Cancelled,
    /// The process could not be started or watched.
    Io(io::Error),
}

impl PartialEq for CommandError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (CommandError::TimedOut(a), CommandError::TimedOut(b)) => a == b,
            (CommandError::Cancelled, CommandError::Cancelled) => true,
            (CommandError::Io(a), CommandError::Io(b)) => a.kind() == b.kind(),
            _ => false,
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandError::TimedOut(executable) => {
                f.write_str(&l10n::tr("The command was stopped after a timeout: %@", &[Arg::Str(executable)]))
            }
            // Swift's `CancellationError` description.
            CommandError::Cancelled => {
                f.write_str("The operation couldn’t be completed. (Swift.CancellationError error 1.)")
            }
            CommandError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CommandError {}

/// Runs one command. Behind a trait so tests (and the UI) can substitute recorded answers.
pub trait CommandRunner: Send + Sync {
    fn run(&self, executable: &str, arguments: &[String], stdin: Option<&str>) -> Result<CommandResult, CommandError>;

    /// [`CommandRunner::run`] with raw bytes on stdin (`mvpn up`'s framed config). The real runner writes them as
    /// they are, without a copy; the default (test doubles) passes them on as (lossy) text.
    fn run_bytes(&self, executable: &str, arguments: &[String], stdin: &[u8]) -> Result<CommandResult, CommandError> {
        self.run(executable, arguments, Some(&String::from_utf8_lossy(stdin)))
    }
}

/// Where curl is and how it runs on this OS.
#[derive(Debug, Clone)]
pub struct Curl {
    /// Absolute (`/usr/bin/curl`; `C:\Windows\System32\curl.exe`).
    pub executable: String,
    /// Arguments after the shared base arguments (`--ssl-revoke-best-effort` on Windows; none on macOS).
    pub extra_args: Vec<&'static str>,
    /// Makes a fresh private (owner-only) directory `<temp>/<prefix>.<random>` and returns it; the caller removes it.
    pub private_dir: fn(prefix: &str) -> Result<PathBuf, String>,
    /// The directory where a finished download is moved (`<user temp>`).
    pub temp_base: fn() -> Result<PathBuf, String>,
}
