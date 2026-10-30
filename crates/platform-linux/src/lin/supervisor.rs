//! The installed LinVPN's supervisor (`pure::supervisor`): `/usr/bin/linvpn` starts itself again as the GUI process
//! (`--supervised`) and only waits for it; when it ends abnormally while the graphical session lives, it starts it
//! again. No GTK, no Tauri, no single-instance name, no tray: a few `stat`s, `fork`/`exec` and `waitpid`.
//!
//! A launch while LinVPN runs (`linvpn file.ovpn`, the dock icon) is not supervised: the instance name has an owner,
//! so this process goes on as a plain launch that hands its files to the running LinVPN and exits. `--after-update`
//! (the updater's and the package watch's relaunch) is supervised even though the old process still owns the name:
//! its GUI waits for the name as before.
//!
//! SIGTERM, SIGINT and SIGHUP to the supervisor are not passed on (a logout or Ctrl-C reaches the GUI too, as the
//! whole scope or process group gets them; a second SIGTERM would only run the GUI's quit twice): from then on the
//! GUI's end is not restarted.

use crate::pure::instance::bus_name;
use crate::pure::supervisor::{
    self as sv, Decision, Ended, MAX_RESTARTS, RESTART_DELAY, RESTART_WINDOW, Restarts, is_supervised,
};
use std::ffi::OsString;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const INSTALLED_BINARY: &str = "/usr/bin/linvpn";

static STOPPING: AtomicBool = AtomicBool::new(false);

/// `main`'s first step on Linux: `Some(exit code)` when this process was the supervisor (the GUI process has ended
/// for good), `None` when it goes on as the app (the GUI process itself, a development build or the sandbox, a
/// launch that forwards to a running LinVPN, or no supervisor could start).
pub fn supervise(sandbox: bool) -> Option<i32> {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if sandbox || is_supervised(&args) {
        return None;
    }
    if std::env::current_exe().ok()? != Path::new(INSTALLED_BINARY) {
        return None;
    }
    let after_update = args.iter().any(|a| a == super::updater::AFTER_UPDATE);
    if !after_update && instance_running() {
        return None;
    }
    if let Err(e) = install_stop_handlers() {
        eprintln!("LinVPN: the supervisor cannot start ({e}); running unsupervised");
        return None;
    }
    Some(run(Path::new(INSTALLED_BINARY), &args, &session_alive, RESTART_DELAY, &STOPPING))
}

/// Whether the installed LinVPN's instance name has an owner (a fresh connection, closed again; no bus: `false`).
fn instance_running() -> bool {
    let ask = || -> zbus::Result<bool> {
        let bus = zbus::blocking::Connection::session()?;
        let name = zbus::names::BusName::try_from(bus_name(None))?;
        Ok(zbus::blocking::fdo::DBusProxy::new(&bus)?.name_has_owner(name)?)
    };
    ask().unwrap_or(false)
}

extern "C" fn on_stop_signal(_: libc::c_int) {
    STOPPING.store(true, Ordering::SeqCst);
}

fn install_stop_handlers() -> std::io::Result<()> {
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: a zeroed sigaction with an async-signal-safe handler (one atomic store), an empty mask and
        // SA_RESTART; `sigaction` only reads it.
        let rc = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_stop_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            libc::sigaction(signal, &action, std::ptr::null_mut())
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Starts `program` with the launch's `args` and again after each abnormal end (`pure::supervisor`); returns the
/// supervisor's exit code (the GUI's last one).
fn run(
    program: &Path,
    args: &[OsString],
    session_alive: &dyn Fn() -> bool,
    delay: Duration,
    stopping: &AtomicBool,
) -> i32 {
    let mut restarts = Restarts::default();
    let mut previous: Option<Ended> = None;
    loop {
        let started = Command::new(program).args(sv::child_args(args, previous)).spawn();
        let mut child = match started {
            Ok(c) => c,
            Err(e) => {
                eprintln!("LinVPN: the supervisor could not start {}: {e}", program.display());
                return 1;
            }
        };
        let status = match child.wait() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("LinVPN: the supervisor lost the app process: {e}");
                return 1;
            }
        };
        let ended = match (status.code(), status.signal()) {
            (Some(code), _) => Ended::Code(code),
            (None, Some(signal)) => Ended::Signal(signal),
            (None, None) => Ended::Code(1),
        };
        let stop = stopping.load(Ordering::SeqCst);
        match restarts.decide(ended, stop, session_alive(), Instant::now()) {
            Decision::Stop => {
                if ended.abnormal() && !stop {
                    eprintln!("LinVPN: the app ended ({}) with the desktop session; not restarting it", ended.reason());
                }
                return ended.exit_code();
            }
            Decision::GiveUp => {
                eprintln!(
                    "LinVPN: the app ended unexpectedly ({}), the {}th time in {} minutes; not restarting it again",
                    ended.reason(),
                    MAX_RESTARTS + 1,
                    RESTART_WINDOW.as_secs() / 60
                );
                return ended.exit_code();
            }
            Decision::Restart => {
                eprintln!("LinVPN: the app ended unexpectedly ({}); restarting it", ended.reason());
                let until = Instant::now() + delay;
                while Instant::now() < until && !stopping.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(50).min(delay));
                }
                if stopping.load(Ordering::SeqCst) || !session_alive() {
                    return ended.exit_code();
                }
                previous = Some(ended);
            }
        }
    }
}

/// The graphical session still runs: its display socket is there and logind does not say the session is closing.
fn session_alive() -> bool {
    display_socket_alive() && logind_session_alive()
}

fn display_socket_alive() -> bool {
    let is_socket = |p: &Path| std::fs::metadata(p).is_ok_and(|m| m.file_type().is_socket());
    if let Some(wayland) = std::env::var_os("WAYLAND_DISPLAY").filter(|v| !v.is_empty()) {
        let path = PathBuf::from(&wayland);
        if path.is_absolute() {
            return is_socket(&path);
        }
        return std::env::var_os("XDG_RUNTIME_DIR").is_some_and(|dir| is_socket(&Path::new(&dir).join(path)));
    }
    if let Some(display) = std::env::var("DISPLAY").ok().filter(|v| !v.is_empty()) {
        // A display without a local socket (`host:0`): nothing to check.
        return sv::x11_socket(&display).is_none_or(|s| is_socket(Path::new(&s)));
    }
    false
}

fn logind_session_alive() -> bool {
    let valid = |id: &str| !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric());
    let id = std::env::var("XDG_SESSION_ID").ok().filter(|id| valid(id)).or_else(|| {
        // SAFETY: getuid cannot fail.
        let uid = unsafe { libc::getuid() };
        let text = std::fs::read_to_string(format!("/run/systemd/users/{uid}")).ok()?;
        sv::user_display_session(&text).filter(|id| valid(id))
    });
    match id {
        None => true,
        Some(id) => {
            sv::session_state_alive(std::fs::read_to_string(format!("/run/systemd/sessions/{id}")).ok().as_deref())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const TICK: Duration = Duration::from_millis(10);

    /// A fake GUI: appends its arguments to `runs`, then ends as the next line of `script` says (`exit N` or
    /// `kill -SIG $$`); the last line repeats.
    struct Fake {
        dir: PathBuf,
        program: PathBuf,
    }

    impl Fake {
        fn new(script: &[&str]) -> Fake {
            let dir = std::env::temp_dir().join(format!("linvpn-supervisor-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("script"), script.join("\n") + "\n").unwrap();
            let program = dir.join("fake-linvpn");
            let body = format!(
                "#!/bin/sh\nd='{d}'\necho \"$*\" >> \"$d/runs\"\nn=$(wc -l < \"$d/runs\")\n\
                 line=$(sed -n \"${{n}}p\" \"$d/script\")\n[ -n \"$line\" ] || line=$(tail -n 1 \"$d/script\")\neval \"$line\"\n",
                d = dir.display()
            );
            std::fs::write(&program, body).unwrap();
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
            Fake { dir, program }
        }

        fn run(&self, args: &[&str], alive: bool) -> i32 {
            let args: Vec<OsString> = args.iter().map(OsString::from).collect();
            run(&self.program, &args, &move || alive, TICK, &AtomicBool::new(false))
        }

        fn runs(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.join("runs")).unwrap_or_default().lines().map(str::to_string).collect()
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn exit_1_is_restarted_without_the_files() {
        let fake = Fake::new(&["exit 1", "exit 0"]);
        assert_eq!(fake.run(&["/home/u/a.ovpn"], true), 0);
        assert_eq!(fake.runs(), ["/home/u/a.ovpn --supervised", "--supervised --restarted=exit code 1"]);
    }

    #[test]
    fn exit_0_is_not_restarted() {
        let fake = Fake::new(&["exit 0"]);
        assert_eq!(fake.run(&["--after-update"], true), 0);
        assert_eq!(fake.runs(), ["--after-update --supervised"]);
    }

    #[test]
    fn sigterm_is_not_restarted_sigkill_is() {
        let fake = Fake::new(&["kill -KILL $$", "kill -TERM $$"]);
        assert_eq!(fake.run(&[], true), 143);
        assert_eq!(fake.runs(), ["--supervised", "--supervised --restarted=signal 9"]);
    }

    #[test]
    fn no_restart_without_the_session() {
        let fake = Fake::new(&["exit 1"]);
        assert_eq!(fake.run(&[], false), 1);
        assert_eq!(fake.runs().len(), 1);
    }

    #[test]
    fn it_gives_up_after_five_restarts() {
        let fake = Fake::new(&["exit 1"]);
        assert_eq!(fake.run(&[], true), 1);
        assert_eq!(fake.runs().len(), MAX_RESTARTS + 1);
    }

    #[test]
    fn a_stop_signal_ends_the_supervision() {
        let fake = Fake::new(&["exit 1"]);
        let stopping = AtomicBool::new(true);
        assert_eq!(run(&fake.program, &[], &|| true, TICK, &stopping), 1);
        assert_eq!(fake.runs().len(), 1);
    }
}
