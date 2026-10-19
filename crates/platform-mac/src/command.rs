//! Running external commands (port of `CommandRunner.swift`).
//!
//! [`ProcessCommandRunner`] never blocks on a pipe: one loop `poll`s the child's stdin (while there is payload
//! left), stdout and stderr, all non-blocking, and checks the exit, the timeout and the cancellation flag between
//! rounds. The result is produced once the child exits; output a background grandchild keeps writing to the
//! inherited pipes afterwards is not waited for. A timeout or a cancellation sends SIGTERM, then SIGKILL after 2 s.

use crate::sys;
use macvpn_core::l10n::{self, Arg};
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

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
    /// Stopped by [`CancelToken::cancel`] (Swift `CancellationError`).
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
}

/// The runners' time limits (seconds).
pub struct RunnerTimeouts;

impl RunnerTimeouts {
    /// Default: install, update, `mvpn down` (it may wait for the lock too), system status.
    pub const STANDARD: f64 = 90.0;
    /// `mvpn up`: in the worst case 45 s lock wait + taking down the earlier run + 30 s connecting + snapshots, with
    /// MFA at most another 420 s waiting for authentication (`mvpn`'s MFA_MAX: web login + code).
    pub const UP: f64 = 600.0;
    /// Frequent, quick queries: `mvpn status`, `scutil --nc …`.
    pub const QUICK: f64 = 20.0;
}

/// Cancels the runs of the runners sharing it (Swift task cancellation).
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// The real runner: `std::process` with the polling loop described in the module documentation.
#[derive(Debug, Clone)]
pub struct ProcessCommandRunner {
    pub timeout: f64,
    cancel: Option<CancelToken>,
    /// `Some`: the child gets exactly these variables (`env_clear` first); `None`: it inherits ours.
    environment: Option<BTreeMap<String, String>>,
}

impl Default for ProcessCommandRunner {
    fn default() -> Self {
        Self::new(RunnerTimeouts::STANDARD)
    }
}

/// SIGTERM, then SIGKILL after this long.
const KILL_GRACE: Duration = Duration::from_secs(2);
const POLL_INTERVAL_MS: i32 = 20;

impl ProcessCommandRunner {
    pub fn new(timeout: f64) -> Self {
        ProcessCommandRunner { timeout, cancel: None, environment: None }
    }

    /// The same runner, its children getting only `environment` (nothing of the app's environment).
    pub fn with_environment(mut self, environment: BTreeMap<String, String>) -> Self {
        self.environment = Some(environment);
        self
    }

    /// The same runner, stopping its runs when `token` is cancelled.
    pub fn with_cancel(mut self, token: CancelToken) -> Self {
        self.cancel = Some(token);
        self
    }
}

impl CommandRunner for ProcessCommandRunner {
    fn run(&self, executable: &str, arguments: &[String], stdin: Option<&str>) -> Result<CommandResult, CommandError> {
        if self.cancel.as_ref().is_some_and(CancelToken::is_cancelled) {
            return Err(CommandError::Cancelled);
        }
        let mut command = Command::new(executable);
        sys::close_inherited_fds(&mut command);
        if let Some(environment) = &self.environment {
            command.env_clear().envs(environment);
        }
        let mut child = command
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(CommandError::Io)?;
        let outcome = Job::new(&mut child, stdin.unwrap_or("").as_bytes(), executable).run(self);
        // Never leave a running child or a zombie behind if watching it failed (`Child` knows whether it was
        // already reaped, so this cannot signal a reused pid).
        if matches!(outcome, Err(CommandError::Io(_))) {
            let _ = child.kill();
            let _ = child.wait();
        }
        outcome
    }
}

/// The state of one run.
struct Job<'a> {
    child: &'a mut Child,
    executable: &'a str,
    payload: &'a [u8],
    written: usize,
    stdin: Option<std::process::ChildStdin>,
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
    out: Vec<u8>,
    err: Vec<u8>,
}

enum Stop {
    TimedOut,
    Cancelled,
}

impl<'a> Job<'a> {
    fn new(child: &'a mut Child, payload: &'a [u8], executable: &'a str) -> Self {
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        Job { child, executable, payload, written: 0, stdin, stdout, stderr, out: Vec::new(), err: Vec::new() }
    }

    fn run(mut self, runner: &ProcessCommandRunner) -> Result<CommandResult, CommandError> {
        for fd in [self.stdout.as_ref().map(|p| p.as_raw_fd()), self.stderr.as_ref().map(|p| p.as_raw_fd())]
            .into_iter()
            .flatten()
        {
            sys::set_nonblocking(fd).map_err(CommandError::Io)?;
        }
        if let Some(input) = &self.stdin {
            // A child that does not read gets EPIPE on our side, never a SIGPIPE in this process.
            sys::set_nosigpipe(input.as_raw_fd());
            sys::set_nonblocking(input.as_raw_fd()).map_err(CommandError::Io)?;
        }
        if self.payload.is_empty() {
            self.stdin = None;
        }

        let started = Instant::now();
        let timeout = Duration::from_secs_f64(runner.timeout.max(0.0));
        let mut stop: Option<(Stop, Instant)> = None;
        let pid = self.child.id() as i32;
        let status = loop {
            if let Some(status) = self.child.try_wait().map_err(CommandError::Io)? {
                break status;
            }
            match &stop {
                None => {
                    let reason = if runner.cancel.as_ref().is_some_and(CancelToken::is_cancelled) {
                        Some(Stop::Cancelled)
                    } else if started.elapsed() >= timeout {
                        Some(Stop::TimedOut)
                    } else {
                        None
                    };
                    if let Some(reason) = reason {
                        sys::kill(pid, sys::SIGTERM);
                        stop = Some((reason, Instant::now()));
                    }
                }
                Some((_, since)) if since.elapsed() >= KILL_GRACE => {
                    sys::kill(pid, sys::SIGKILL);
                }
                Some(_) => {}
            }
            self.pump(POLL_INTERVAL_MS).map_err(CommandError::Io)?;
        };
        // The child is gone: whatever is already in the pipes is read, nothing more is waited for.
        self.stdin = None;
        self.drain(true);
        self.drain(false);
        match stop {
            Some((Stop::TimedOut, _)) => Err(CommandError::TimedOut(self.executable.to_string())),
            Some((Stop::Cancelled, _)) => Err(CommandError::Cancelled),
            None => Ok(CommandResult {
                exit_code: exit_code(status),
                stdout: String::from_utf8_lossy(&self.out).into_owned(),
                stderr: String::from_utf8_lossy(&self.err).into_owned(),
            }),
        }
    }

    /// One `poll` round: writes what the stdin pipe takes, reads what stdout / stderr have.
    fn pump(&mut self, timeout_ms: i32) -> io::Result<()> {
        let mut fds = Vec::new();
        let in_fd = self.stdin.as_ref().map(|p| p.as_raw_fd());
        let out_fd = self.stdout.as_ref().map(|p| p.as_raw_fd());
        let err_fd = self.stderr.as_ref().map(|p| p.as_raw_fd());
        if let Some(fd) = in_fd {
            fds.push((fd, sys::POLLOUT));
        }
        if let Some(fd) = out_fd {
            fds.push((fd, sys::POLLIN));
        }
        if let Some(fd) = err_fd {
            fds.push((fd, sys::POLLIN));
        }
        if fds.is_empty() {
            std::thread::sleep(Duration::from_millis(timeout_ms as u64));
            return Ok(());
        }
        let revents = sys::poll(&fds, timeout_ms)?;
        let ready = |fd: Option<i32>| fd.and_then(|fd| fds.iter().position(|(f, _)| *f == fd)).map(|i| revents[i] != 0);
        if ready(in_fd) == Some(true) {
            self.write_stdin();
        }
        if ready(out_fd) == Some(true) {
            self.drain(true);
        }
        if ready(err_fd) == Some(true) {
            self.drain(false);
        }
        Ok(())
    }

    fn write_stdin(&mut self) {
        let Some(input) = self.stdin.as_mut() else { return };
        loop {
            if self.written >= self.payload.len() {
                self.stdin = None; // closes the pipe: EOF for the child
                return;
            }
            match input.write(&self.payload[self.written..]) {
                Ok(0) => return,
                Ok(n) => self.written += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                // EPIPE: the child does not read its input, that is fine.
                Err(_) => {
                    self.stdin = None;
                    return;
                }
            }
        }
    }

    /// Non-blocking read until EAGAIN or EOF (EOF closes our end).
    fn drain(&mut self, stdout: bool) {
        let mut buffer = [0u8; 65536];
        loop {
            let result = if stdout {
                match self.stdout.as_mut() {
                    Some(p) => p.read(&mut buffer),
                    None => return,
                }
            } else {
                match self.stderr.as_mut() {
                    Some(p) => p.read(&mut buffer),
                    None => return,
                }
            };
            match result {
                Ok(0) => {
                    if stdout {
                        self.stdout = None;
                    } else {
                        self.stderr = None;
                    }
                    return;
                }
                Ok(n) => {
                    if stdout {
                        self.out.extend_from_slice(&buffer[..n]);
                    } else {
                        self.err.extend_from_slice(&buffer[..n]);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            }
        }
    }
}

/// Foundation `Process.terminationStatus`: the exit code, or the signal number for a signalled process.
fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.code().or_else(|| status.signal()).unwrap_or(-1)
}
