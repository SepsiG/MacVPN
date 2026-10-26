//! The state of one `up` / `down` / `respond` run and the primitives every subsystem uses: messages, `die`,
//! running tools with logged and masked output, tool discovery.

use crate::macos::exec::{self, Cmd, EnvMode};
use crate::macos::lock::Lock;
use crate::macos::log::Log;
use crate::macos::paths::Settings;
use crate::macos::sstp::SstpParams;
use crate::shared::cli::Args;
use crate::shared::framing::Secrets;
use crate::shared::mask::Masker;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// A finished run with its exit code (the bash `exit <n>`); cleanup happens on the way out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exit(pub i32);

pub type R<T = ()> = Result<T, Exit>;

/// The localized text of `key` (an English message of the `strings.json` table), `%@` filled in order.
pub use crate::shared::l10n::tr;

pub struct Ctx {
    pub s: Settings,
    pub a: Args,
    /// The kind being handled (`down` takes it from the run directory).
    pub kind: String,
    pub id: String,
    pub log: Log,
    /// The run directory once `prepare_run` / `down` set it.
    pub run: Option<PathBuf>,
    pub secrets: Secrets,
    pub lock: Lock,
    /// The connection is up; from here on an exit does not clean up.
    pub up_done: bool,
    /// Output to stdout/stderr suppressed (the bash `( … ) >/dev/null 2>&1` of the failed-up cleanup).
    pub quiet: bool,
    /// SSTP: the validated parameters, once loaded.
    pub sstp: Option<SstpParams>,
    /// WireGuard: `wg-quick` needs the brew bin in PATH (the bash `export PATH=…`, which then applied to every
    /// later command of the run).
    pub brew_path: bool,
    /// `--debug` for wg-quick (the bash `export LOG_LEVEL=debug`).
    pub wg_debug_env: bool,
}

impl Ctx {
    pub fn new(s: Settings, a: Args) -> Ctx {
        Ctx {
            kind: a.kind.clone(),
            id: a.id.clone(),
            s,
            a,
            log: Log::none(),
            run: None,
            secrets: Secrets::default(),
            lock: Lock::default(),
            up_done: false,
            quiet: false,
            sstp: None,
            brew_path: false,
            wg_debug_env: false,
        }
    }

    pub fn dry(&self) -> bool {
        self.a.dry_run
    }

    /// The bash `die`: `✗ <msg>` in the log, the message on stderr, exit 1.
    pub fn die(&self, msg: impl AsRef<str>) -> Exit {
        let msg = msg.as_ref();
        self.log.line(&format!("✗ {msg}"));
        if !self.quiet {
            err!("{msg}");
        }
        Exit(1)
    }

    /// SIGTERM arrived: `✗ interrupted (SIGTERM)` and exit 143 (cleanup follows on the way out).
    pub fn check_term(&self) -> R {
        if crate::macos::sys::terminated() {
            self.log.line(&format!("✗ {}", tr("interrupted (SIGTERM)", &[])));
            return Err(Exit(143));
        }
        Ok(())
    }

    /// An interruptible sleep of the main flow.
    pub fn sleep_ms(&self, ms: u64) -> R {
        exec::sleep_ms(ms, true);
        self.check_term()
    }

    /// Prints a line to stdout (the bash `echo "DRY: …"`), unless quiet.
    pub fn say(&self, s: &str) {
        if !self.quiet {
            out!("{s}");
        }
    }

    pub fn masker(&self) -> Masker {
        self.secrets.masker()
    }

    /// The run directory (set before any tool runs).
    pub fn run(&self) -> &Path {
        self.run.as_deref().unwrap_or(Path::new("/nonexistent"))
    }

    pub fn env_mode(&self) -> EnvMode {
        if self.s.test_mode { EnvMode::Inherit } else { EnvMode::Minimal }
    }

    /// Applies the run's PATH / wg-quick settings to a tool command.
    fn prepared(&self, cmd: &Cmd) -> Cmd {
        let mut c = cmd.clone();
        if self.brew_path
            && let Some(b) = &self.s.brew
        {
            c.path = Some(format!("{}:{}/bin:{}/sbin", crate::macos::paths::PATH, b.display(), b.display()));
        }
        if self.wg_debug_env {
            c = c.env("LOG_LEVEL", "debug");
        }
        c
    }

    /// `run_logged`: the command line in the log; the output (stdout and stderr) masked into the log.
    pub fn run_logged(&self, cmd: &Cmd) -> R<bool> {
        self.run_logged_scan(cmd, |_| false).map(|(ok, _)| ok)
    }

    /// [`Ctx::run_logged`] that also reports whether `pred` matched any (masked) line of the command's own output.
    /// The decision comes from the in-memory stream, never from the log file (which the user can write).
    pub fn run_logged_scan(&self, cmd: &Cmd, pred: impl Fn(&[u8]) -> bool + Send + 'static) -> R<(bool, bool)> {
        self.log.cmd(&cmd.display());
        if self.dry() {
            self.say(&format!("DRY: {}", cmd.display()));
            return Ok((true, false));
        }
        let Ok((reader, writer)) = std::io::pipe() else { return Ok((false, false)) };
        let Ok(writer2) = writer.try_clone() else { return Ok((false, false)) };
        let spawned = self
            .prepared(cmd)
            .command(self.env_mode())
            .stdin(Stdio::null())
            .stdout(Stdio::from(writer))
            .stderr(Stdio::from(writer2))
            .spawn();
        let mut child = match spawned {
            Ok(c) => c,
            Err(e) => {
                self.log.line(&format!("{}: {e}", cmd.shown));
                return Ok((false, false));
            }
        };
        let matched = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = matched.clone();
        // Streamed line by line through the masker into the log (live, bounded memory). A daemonizing child may
        // keep the pipe open: after the child exits the reader gets a short grace period, then it is left behind.
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let (log, masker) = (self.log.clone(), self.masker());
        let spawned_reader = std::thread::Builder::new().spawn(move || {
            masker.stream_lines(reader, crate::shared::mask::MAX_LINE, |l| {
                if pred(l) {
                    seen.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                log.bytes(l);
                true
            });
            let _ = done_tx.send(());
        });
        let ok = child.wait().is_ok_and(|s| s.success());
        if spawned_reader.is_ok() {
            let _ = done_rx.recv_timeout(std::time::Duration::from_millis(500));
        }
        Ok((ok, matched.load(std::sync::atomic::Ordering::SeqCst)))
    }

    /// `run_direct`: stdin `/dev/null`, output into the log (no secret in it), waits for the exit.
    pub fn run_direct(&self, cmd: &Cmd) -> R<bool> {
        self.log.cmd(&cmd.display());
        if self.dry() {
            self.say(&format!("DRY: {}", cmd.display()));
            return Ok(true);
        }
        let Some(child) = self.spawn_to_log(cmd) else { return Ok(false) };
        let mut child = child;
        Ok(child.wait().is_ok_and(|s| s.success()))
    }

    /// `run_direct --bg`: started in the background without the caller's pipes; its pid.
    pub fn run_bg(&self, cmd: &Cmd) -> R<Option<u32>> {
        self.log.cmd(&format!("{} &", cmd.display()));
        if self.dry() {
            self.say(&format!("DRY: {}", cmd.display()));
            return Ok(None);
        }
        Ok(self.spawn_to_log(cmd).map(|c| c.id()))
    }

    fn spawn_to_log(&self, cmd: &Cmd) -> Option<std::process::Child> {
        let out = self.log.file();
        let err = out.as_ref().and_then(|f| f.try_clone().ok());
        let stdout = out.map(Stdio::from).unwrap_or_else(Stdio::null);
        let stderr = err.map(Stdio::from).unwrap_or_else(Stdio::null);
        match self.prepared(cmd).command(self.env_mode()).stdin(Stdio::null()).stdout(stdout).stderr(stderr).spawn() {
            Ok(c) => Some(c),
            Err(e) => {
                self.log.line(&format!("{}: {e}", cmd.shown));
                None
            }
        }
    }

    /// `find_tool`: `$BREW/bin/<t>` or `$BREW/sbin/<t>`; under dry-run a placeholder path.
    pub fn find_tool(&self, t: &str) -> Option<PathBuf> {
        if let Some(b) = &self.s.brew {
            for c in [b.join("bin").join(t), b.join("sbin").join(t)] {
                if exec::is_executable(&c) {
                    return Some(c);
                }
            }
        }
        if self.dry() {
            let dir = if t == "sstpc" { "sbin" } else { "bin" };
            return Some(PathBuf::from(format!("/opt/homebrew/{dir}/{t}")));
        }
        None
    }

    /// `find_charon`
    pub fn find_charon(&self) -> Option<PathBuf> {
        if let Some(b) = &self.s.brew {
            for c in [b.join("opt/strongswan/libexec/ipsec/charon"), b.join("opt/strongswan/libexec/charon")] {
                if exec::is_executable(&c) {
                    return Some(c);
                }
            }
        }
        self.dry().then(|| PathBuf::from("/opt/homebrew/opt/strongswan/libexec/ipsec/charon"))
    }

    /// The user the connection belongs to.
    pub fn user(&self) -> Option<crate::macos::sys::User> {
        if !crate::shared::cli::is_user_name(&self.s.target_user) {
            return None;
        }
        crate::macos::sys::user_by_name(&self.s.target_user)
    }

    /// The uid that owns user-facing files (only as root; in test mode they stay the caller's).
    pub fn owner_uid(&self) -> Option<u32> {
        if self.s.test_mode { None } else { self.user().map(|u| u.uid) }
    }

    /// `no running connection`
    pub fn no_running(&self) {
        self.log.step(&tr("no running connection", &[]));
    }

    /// This connection gives up DNS (the DNS manager restores the originals, or the DNS of the newest other
    /// connection holding DNS). A `dns-backup` of an older root layer goes through the DNS hook
    /// (`<libexec>/mvpn hook ovpn-dns <run> <log>` with `script_type=down`) as before.
    pub fn dns_restore(&self) {
        let run = self.run().to_path_buf();
        if crate::macos::paths::is_file(&run.join("dns-backup")) {
            let cmd = Cmd::new(self.s.hook_program())
                .args(["hook", "ovpn-dns"])
                .arg(&run)
                .arg(self.log.path().unwrap_or(Path::new("/dev/null")))
                .env("script_type", "down");
            let mut c = cmd.command(self.env_mode());
            c.stdin(Stdio::null());
            if self.quiet {
                c.stdout(Stdio::null()).stderr(Stdio::null());
            }
            let _ = c.status();
        }
        if !self.dry()
            && let Some(m) = crate::macos::dns::manager(&self.s)
        {
            m.release(&self.id, &self.log);
        }
    }

    /// This connection takes DNS (WireGuard; OpenVPN and SSTP go through the DNS hook).
    pub fn dns_set(&self, dns: &crate::macos::dns::Dns) {
        match crate::macos::dns::manager(&self.s) {
            Some(m) => m.acquire(&self.id, dns, &self.log),
            None => self.log.step(&tr("not running as root: DNS not changed", &[])),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::testmode::TestEnv;

    fn ctx(log: &Path) -> Ctx {
        let s = Settings::resolve(true, TestEnv::default(), String::new());
        let mut c = Ctx::new(s, Args::default());
        c.log = Log::at(log.to_path_buf());
        c.secrets = Secrets { pass: zeroize::Zeroizing::new(b"pw1secret".to_vec()), ..Secrets::default() };
        c
    }

    fn tmp_log() -> PathBuf {
        std::env::temp_dir().join(format!("mvpn-ctx-{}.log", uuid::Uuid::new_v4()))
    }

    #[test]
    fn logged_output_is_streamed_and_masked() {
        let log = tmp_log();
        let c = ctx(&log);
        // The command line itself goes into the log too: the markers are only produced by the output.
        let cmd = Cmd::new("/bin/sh")
            .args(["-c", "printf 'L1 %s\\n' \"$S\"; sleep 2; printf 'L%s\\n' 2"])
            .env("S", "pw1secret");
        let watcher = {
            let log = log.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(1200));
                std::fs::read_to_string(&log).unwrap_or_default()
            })
        };
        assert!(c.run_logged(&cmd).unwrap());
        let early = watcher.join().unwrap();
        assert!(early.contains("L1 ***"), "not live: {early:?}");
        assert!(!early.contains("L2"));
        let all = std::fs::read_to_string(&log).unwrap();
        assert!(all.contains("L2\n") && !all.contains("pw1secret"), "{all}");
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn scan_sees_only_the_masked_output_stream() {
        let log = tmp_log();
        let c = ctx(&log);
        let eap = |l: &[u8]| crate::shared::mask::find(l, b"EAP_FAILURE").is_some();
        let out = Cmd::new("/bin/sh").args(["-c", "echo x; echo 'received EAP_FAILURE' >&2; exit 1"]);
        assert_eq!(c.run_logged_scan(&out, eap).unwrap(), (false, true));
        // Written into the log by the child itself (as another process could): not seen.
        let direct =
            Cmd::new("/bin/sh").args(["-c", "echo 'EAP_FAILURE' >>\"$L\"; echo y"]).env("L", log.to_str().unwrap());
        assert_eq!(c.run_logged_scan(&direct, eap).unwrap(), (true, false));
        assert!(std::fs::read_to_string(&log).unwrap().contains("EAP_FAILURE"));
        // The predicate sees masked lines: a secret never reaches it.
        let secret = Cmd::new("/bin/sh").args(["-c", "echo pw1secret"]);
        assert_eq!(
            c.run_logged_scan(&secret, |l| crate::shared::mask::find(l, b"pw1secret").is_some()).unwrap(),
            (true, false)
        );
        let _ = std::fs::remove_file(&log);
    }

    #[test]
    fn a_daemonizing_child_does_not_hang() {
        let log = tmp_log();
        let c = ctx(&log);
        let start = std::time::Instant::now();
        let cmd = Cmd::new("/bin/sh").args(["-c", "(sleep 5 &); echo started"]);
        assert!(c.run_logged(&cmd).unwrap());
        assert!(start.elapsed() < std::time::Duration::from_secs(3), "{:?}", start.elapsed());
        assert!(std::fs::read_to_string(&log).unwrap().contains("started"));
        let _ = std::fs::remove_file(&log);
    }
}
