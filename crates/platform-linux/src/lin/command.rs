//! The [`CommandRunner`] of the curl layer on Linux (LinVPN plan, Task 20), as WinVPN's runner:
//!
//! - **The executable** must be an absolute path (`/usr/bin/curl`); `PATH` is never searched.
//! - **The environment** is `PATH=/usr/bin:/bin`, `HOME` (from the user database, for curl's own lookups) and
//!   `LC_ALL=C` only: no `*_proxy`, no `CURL_HOME`, no `LD_*`, nothing of the app's (`-q` also skips `.curlrc`).
//! - **Stdin** (the bearer token's `--config -`) is written from memory on a thread and the pipe closed; the token is
//!   never in the argv (`/proc/<pid>/cmdline`) or a log line. Without stdin the child gets `/dev/null`.
//! - **A time limit** after which the child is killed and [`CommandError::TimedOut`] returned: the argv's
//!   `--max-time` plus 30 s (60 s without one), never more than the runner's own cap.
//! - **Output caps**: stdout and stderr are read on two threads and kept up to 1 MiB each, the rest drained.

use super::system;
use macvpn_platform_api::curl::{CommandError, CommandResult, CommandRunner};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// How often the runner looks at the child.
const POLL: Duration = Duration::from_millis(20);
/// At most this much of stdout and of stderr is kept.
const OUTPUT_CAP: u64 = 1024 * 1024;
/// The runner's margin over curl's own `--max-time`.
pub(crate) const MARGIN_SECS: f64 = 30.0;
/// curl's `--max-time` assumed when the argv has none.
const DEFAULT_MAX_TIME: u64 = 30;

/// The time limit of one run: its `--max-time` plus [`MARGIN_SECS`] (60 s without one), so curl's own limit ends it
/// first and the runner only stops a curl that hangs.
pub(crate) fn time_limit(args: &[String]) -> Duration {
    let max_time = args
        .iter()
        .position(|a| a == "--max-time")
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MAX_TIME);
    Duration::from_secs(max_time.saturating_add(MARGIN_SECS as u64))
}

/// The Linux runner (see the module docs).
pub(crate) struct LinCommandRunner {
    cap: Duration,
}

impl LinCommandRunner {
    /// `cap`: seconds after which the child is killed at the latest (each run's own limit is [`time_limit`] of its
    /// argv, if shorter).
    pub(crate) fn new(cap: f64) -> Self {
        LinCommandRunner { cap: Duration::from_secs_f64(cap.max(0.0)) }
    }

    fn start(&self, executable: &str, arguments: &[String], with_stdin: bool) -> io::Result<Child> {
        if !Path::new(executable).is_absolute() {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("not an absolute path: {executable}")));
        }
        let mut command = Command::new(executable);
        command.args(arguments).env_clear().env("PATH", "/usr/bin:/bin").env("LC_ALL", "C");
        if let Some(home) = system::home() {
            command.env("HOME", home);
        }
        command
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
            // The pipes close with the child (a grandchild that kept them open is not waited for: the readers are
            // scoped, so they end when the pipes do).
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

impl CommandRunner for LinCommandRunner {
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

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_limit_follows_max_time() {
        assert_eq!(time_limit(&args(&["--max-time", "600", "--", "https://x"])), Duration::from_secs(630));
        assert_eq!(time_limit(&args(&["--max-time", "x"])), Duration::from_secs(60));
        assert_eq!(time_limit(&args(&[])), Duration::from_secs(60));
    }

    #[test]
    fn output_and_stdin_reach_the_caller() {
        let runner = LinCommandRunner::new(60.0);
        let r = runner.run("/bin/echo", &args(&["hi"]), None).unwrap();
        assert_eq!((r.exit_code, r.stdout.as_str()), (0, "hi\n"));
        let r = runner.run_bytes("/bin/cat", &[], b"from stdin").unwrap();
        assert_eq!(r.stdout, "from stdin");
        let r = runner.run("/bin/sh", &args(&["-c", "echo oops >&2; exit 3"]), None).unwrap();
        assert_eq!((r.exit_code, r.stderr.as_str()), (3, "oops\n"));
    }

    #[test]
    fn a_hanging_command_is_stopped() {
        let started = Instant::now();
        let r = LinCommandRunner::new(1.0).run("/bin/sleep", &args(&["5"]), None);
        assert_eq!(r, Err(CommandError::TimedOut("/bin/sleep".into())));
        assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
    }

    #[test]
    fn the_environment_is_bare_and_the_path_absolute() {
        let r = LinCommandRunner::new(60.0).run("/usr/bin/env", &[], None).unwrap();
        assert_eq!(r.exit_code, 0);
        assert!(r.stdout.lines().any(|l| l == "PATH=/usr/bin:/bin"), "{}", r.stdout);
        assert!(r.stdout.lines().any(|l| l == "LC_ALL=C"), "{}", r.stdout);
        for line in r.stdout.lines() {
            let name = line.split('=').next().unwrap_or_default();
            assert!(["PATH", "HOME", "LC_ALL"].contains(&name), "{line}");
            assert!(!name.starts_with("MACVPN_") && !name.starts_with("LD_"), "{line}");
        }
        let e = LinCommandRunner::new(60.0).run("env", &[], None).unwrap_err();
        assert!(matches!(e, CommandError::Io(ref io) if io.kind() == io::ErrorKind::NotFound), "{e:?}");
    }
}
