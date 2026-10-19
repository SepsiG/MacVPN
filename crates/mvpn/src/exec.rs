//! Starting child processes with a fixed, minimal environment.
//!
//! As root every child gets a cleared environment with only `PATH=/usr/bin:/bin:/usr/sbin:/sbin` and `LC_ALL=C`
//! (plus what the caller adds explicitly, e.g. the brew bin for `wg-quick`). Secrets never go into an
//! environment. In test mode (not root) the caller's environment is inherited, as the bash `mvpn` did, so the
//! fake tools still see their `FAKE_*` switches; `PATH` and `LC_ALL` are forced in both modes.

use crate::paths::PATH;
use std::ffi::{OsStr, OsString};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// How the environment of a child is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvMode {
    /// Root: `env_clear` + the minimal environment.
    Minimal,
    /// Test mode: the caller's environment, with `PATH` / `LC_ALL` forced.
    Inherit,
    /// Always cleared, only the explicit variables (the bash `env -i …`).
    Empty,
}

/// A command with its display form for the log (`$ …`) and the dry-run output (`DRY: …`).
#[derive(Debug, Clone)]
pub struct Cmd {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    /// The program as the bash `mvpn` printed it (e.g. `dscacheutil` for `/usr/bin/dscacheutil`).
    pub shown: String,
    /// The displayed arguments (a password replaced by `***`).
    pub shown_args: Option<Vec<String>>,
    pub env: Vec<(OsString, OsString)>,
    pub path: Option<String>,
    pub cwd: Option<PathBuf>,
    pub arg0: Option<OsString>,
}

impl Cmd {
    pub fn new(program: impl Into<PathBuf>) -> Cmd {
        let program = program.into();
        let shown = program.display().to_string();
        Cmd { program, args: Vec::new(), shown, shown_args: None, env: Vec::new(), path: None, cwd: None, arg0: None }
    }

    /// A system tool started by absolute path but logged by its name, as bash (with a fixed PATH) showed it.
    pub fn system(program: &str) -> Cmd {
        let mut c = Cmd::new(program);
        c.shown = Path::new(program).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        c
    }

    pub fn arg(mut self, a: impl AsRef<OsStr>) -> Cmd {
        self.args.push(a.as_ref().to_os_string());
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Cmd
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        for a in args {
            self.args.push(a.as_ref().to_os_string());
        }
        self
    }

    pub fn env(mut self, k: impl AsRef<OsStr>, v: impl AsRef<OsStr>) -> Cmd {
        self.env.push((k.as_ref().to_os_string(), v.as_ref().to_os_string()));
        self
    }

    /// The bash `$*` of the command line.
    pub fn display(&self) -> String {
        let mut s = self.shown.clone();
        match &self.shown_args {
            Some(a) => {
                for x in a {
                    s.push(' ');
                    s.push_str(x);
                }
            }
            None => {
                for a in &self.args {
                    s.push(' ');
                    s.push_str(&a.to_string_lossy());
                }
            }
        }
        s
    }

    /// The `std` command with the environment rules applied; the child inherits no descriptor beyond 0-2.
    pub fn command(&self, mode: EnvMode) -> Command {
        let mut c = Command::new(&self.program);
        crate::sys::close_inherited_fds(&mut c);
        c.args(&self.args);
        if let Some(a0) = &self.arg0 {
            use std::os::unix::process::CommandExt;
            c.arg0(a0);
        }
        match mode {
            EnvMode::Minimal | EnvMode::Empty => {
                c.env_clear();
            }
            EnvMode::Inherit => {}
        }
        if mode != EnvMode::Empty {
            c.env("PATH", self.path.as_deref().unwrap_or(PATH));
            c.env("LC_ALL", "C");
        }
        for (k, v) in &self.env {
            c.env(k, v);
        }
        if let Some(d) = &self.cwd {
            c.current_dir(d);
        }
        c
    }
}

/// The bash `[ -x p ]`.
pub fn is_executable(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

/// Runs a command with stdin `/dev/null`, stderr discarded, and returns its exit success and stdout (at most
/// `max` bytes are kept).
pub fn capture(cmd: &Cmd, mode: EnvMode, max: usize) -> Option<(bool, Vec<u8>)> {
    capture_with(cmd, mode, max, false)
}

/// Like [`capture`], with stderr merged into the output (`2>&1`).
pub fn capture_merged(cmd: &Cmd, mode: EnvMode, max: usize) -> Option<(bool, Vec<u8>)> {
    capture_with(cmd, mode, max, true)
}

fn capture_with(cmd: &Cmd, mode: EnvMode, max: usize, merge: bool) -> Option<(bool, Vec<u8>)> {
    use std::io::Read;
    let (reader, writer) = std::io::pipe().ok()?;
    let stderr = if merge { Stdio::from(writer.try_clone().ok()?) } else { Stdio::null() };
    let mut child = cmd.command(mode).stdin(Stdio::null()).stdout(Stdio::from(writer)).stderr(stderr).spawn().ok()?;
    let mut out = Vec::new();
    let mut so = reader;
    let mut buf = [0u8; 8192];
    loop {
        match so.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() < max {
                    let take = n.min(max - out.len());
                    out.extend_from_slice(&buf[..take]);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let status = child.wait().ok()?;
    Some((status.success(), out))
}

/// Runs a command with stdin `/dev/null` and stdout/stderr discarded; its exit success.
pub fn quiet(cmd: &Cmd, mode: EnvMode) -> bool {
    cmd.command(mode)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Sleeps in short slices. `interruptible`: returns `false` as soon as SIGTERM arrives (the main flow then
/// stops; cleanup sleeps are not interruptible).
pub fn sleep_ms(ms: u64, interruptible: bool) -> bool {
    let end = std::time::Instant::now() + std::time::Duration::from_millis(ms);
    loop {
        if interruptible && crate::sys::terminated() {
            return false;
        }
        let now = std::time::Instant::now();
        if now >= end {
            return true;
        }
        std::thread::sleep((end - now).min(std::time::Duration::from_millis(100)));
    }
}

/// Unix time in seconds (`date +%s`).
pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envs(c: &Command) -> Vec<(String, Option<String>)> {
        c.get_envs()
            .map(|(k, v)| (k.to_string_lossy().into_owned(), v.map(|v| v.to_string_lossy().into_owned())))
            .collect()
    }

    #[test]
    fn root_children_get_only_the_minimal_environment() {
        let cmd = Cmd::new("/usr/bin/true").arg("x");
        let c = cmd.command(EnvMode::Minimal);
        let mut e = envs(&c);
        e.sort();
        assert_eq!(
            e,
            vec![("LC_ALL".into(), Some("C".into())), ("PATH".into(), Some("/usr/bin:/bin:/usr/sbin:/sbin".into()))]
        );
        assert!(capture(&Cmd::new("/usr/bin/env"), EnvMode::Minimal, 4096).is_some_and(|(ok, out)| {
            let s = String::from_utf8_lossy(&out);
            ok && s.lines().count() == 2 && s.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin") && s.contains("LC_ALL=C")
        }));
    }

    #[test]
    fn empty_mode_passes_only_explicit_variables() {
        let cmd = Cmd::new("/usr/bin/env").env("script_type", "up");
        let (ok, out) = capture(&cmd, EnvMode::Empty, 4096).unwrap();
        assert!(ok);
        assert_eq!(String::from_utf8_lossy(&out), "script_type=up\n");
    }

    #[test]
    fn display_hides_secret_arguments() {
        let mut c = Cmd::new("/opt/homebrew/sbin/sstpc").args(["--password", "pw", "host"]);
        assert_eq!(c.display(), "/opt/homebrew/sbin/sstpc --password pw host");
        c.shown_args = Some(vec!["--password".into(), "***".into(), "host".into()]);
        assert_eq!(c.display(), "/opt/homebrew/sbin/sstpc --password *** host");
        assert_eq!(Cmd::system("/usr/sbin/netstat").arg("-rn").display(), "netstat -rn");
    }
}
