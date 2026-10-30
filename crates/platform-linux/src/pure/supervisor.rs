//! The installed LinVPN's supervisor (`lin::supervisor`): what it does when the GUI process it started has ended.
//!
//! GTK 3 ends the process with `_exit(1)` when the compositor closes its Wayland connection (GDK: "Error reading
//! events from display: Broken pipe"; seen on GNOME when a remote desktop session stopped), and a crash or the OOM
//! killer ends it with a signal; the tunnels stay up in NetworkManager, but the tray icon and the secret agent are
//! gone. The supervisor starts it again, `RESTART_DELAY` later, while the graphical session lives: at most
//! `MAX_RESTARTS` times in `RESTART_WINDOW`, then it gives up. A normal end is never restarted: exit 0 (Quit, the
//! update's and the package watch's hand-over to the new `linvpn --after-update`, SIGTERM through the exit hook) or
//! SIGTERM / SIGINT / SIGHUP that the GUI did not handle (a logout, a terminal closed).
//!
//! The command line: the supervisor starts the GUI with its own arguments and [`SUPERVISED`]; a restart gets only
//! [`SUPERVISED`] and [`RESTARTED`]`=<reason>` (no files: they were opened; no `--after-update`: nothing to wait
//! for). The GUI's launch skips its windows after a restart ([`restart_reason`]).

use std::collections::VecDeque;
use std::ffi::OsString;
use std::time::{Duration, Instant};

/// The GUI process' argument: the supervisor started it (it does not supervise itself).
pub const SUPERVISED: &str = "--supervised";
/// The GUI process' argument after a restart: `--restarted=<reason>`.
pub const RESTARTED: &str = "--restarted";

pub const RESTART_DELAY: Duration = Duration::from_secs(2);
pub const MAX_RESTARTS: usize = 5;
pub const RESTART_WINDOW: Duration = Duration::from_secs(600);

// Linux' numbers (the module compiles on every OS).
const SIGHUP: i32 = 1;
const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

/// How the GUI process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    Code(i32),
    Signal(i32),
}

impl Ended {
    /// The supervisor's own exit code for it (a signal: 128 + its number, as a shell reports it).
    pub fn exit_code(self) -> i32 {
        match self {
            Ended::Code(c) => c,
            Ended::Signal(s) => 128 + s,
        }
    }

    /// For the log and [`RESTARTED`]: `exit code 1`, `signal 9`.
    pub fn reason(self) -> String {
        match self {
            Ended::Code(c) => format!("exit code {c}"),
            Ended::Signal(s) => format!("signal {s}"),
        }
    }

    /// Not a normal end: a non-zero exit code, or a signal other than SIGTERM, SIGINT and SIGHUP.
    pub fn abnormal(self) -> bool {
        match self {
            Ended::Code(c) => c != 0,
            Ended::Signal(s) => !matches!(s, SIGHUP | SIGINT | SIGTERM),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The supervisor ends with the GUI's exit code.
    Stop,
    /// Start the GUI again after `RESTART_DELAY`.
    Restart,
    /// Too many restarts in `RESTART_WINDOW`: the supervisor ends (and says so).
    GiveUp,
}

/// The restarts of the last `RESTART_WINDOW`.
#[derive(Debug, Default)]
pub struct Restarts(VecDeque<Instant>);

impl Restarts {
    /// What to do after the GUI ended with `ended` at `now`. `stopping`: the supervisor itself got SIGTERM, SIGINT
    /// or SIGHUP (passed on to the GUI); `session_alive`: the graphical session still runs (its display socket is
    /// there and logind does not say it is closing). A restart is recorded.
    pub fn decide(&mut self, ended: Ended, stopping: bool, session_alive: bool, now: Instant) -> Decision {
        if stopping || !ended.abnormal() || !session_alive {
            return Decision::Stop;
        }
        while self.0.front().is_some_and(|t| now.saturating_duration_since(*t) >= RESTART_WINDOW) {
            self.0.pop_front();
        }
        if self.0.len() >= MAX_RESTARTS {
            return Decision::GiveUp;
        }
        self.0.push_back(now);
        Decision::Restart
    }
}

/// The GUI's arguments: the first start gets the launch's own (`args`, without the program), a restart only the
/// marks.
pub fn child_args(args: &[OsString], restart: Option<Ended>) -> Vec<OsString> {
    match restart {
        None => {
            let mut v = args.to_vec();
            v.push(SUPERVISED.into());
            v
        }
        Some(ended) => vec![SUPERVISED.into(), format!("{RESTARTED}={}", ended.reason()).into()],
    }
}

/// Whether this launch is the GUI process the supervisor started.
pub fn is_supervised(args: &[OsString]) -> bool {
    args.iter().any(|a| a == SUPERVISED)
}

/// The reason this GUI process was restarted (`--restarted=<reason>`), if it was.
pub fn restart_reason(args: &[OsString]) -> Option<String> {
    let prefix = format!("{RESTARTED}=");
    args.iter().find_map(|a| a.to_str().and_then(|s| s.strip_prefix(&prefix)).map(str::to_string))
}

/// The logind session's state file (`/run/systemd/sessions/<id>`): alive unless its `STATE=` is `closing`.
/// Unreadable or without `STATE=`: alive (the display socket decides).
pub fn session_state_alive(text: Option<&str>) -> bool {
    let Some(text) = text else { return true };
    !text.lines().any(|l| l.trim() == "STATE=closing")
}

/// The graphical session of the user's state file (`/run/systemd/users/<uid>`, its `DISPLAY=<session id>`).
pub fn user_display_session(text: &str) -> Option<String> {
    text.lines().find_map(|l| l.trim().strip_prefix("DISPLAY=")).filter(|s| !s.is_empty()).map(str::to_string)
}

/// The X server's socket for `DISPLAY` (`:0`, `:1.0`; a remote display such as `host:0` has none).
pub fn x11_socket(display: &str) -> Option<String> {
    let rest = display.strip_prefix(':')?;
    let number = rest.split('.').next()?;
    (!number.is_empty() && number.chars().all(|c| c.is_ascii_digit())).then(|| format!("/tmp/.X11-unix/X{number}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn only_an_abnormal_end_restarts() {
        let now = Instant::now();
        for ended in [Ended::Code(1), Ended::Code(101), Ended::Signal(9), Ended::Signal(11), Ended::Signal(6)] {
            assert_eq!(Restarts::default().decide(ended, false, true, now), Decision::Restart, "{ended:?}");
        }
        for ended in [Ended::Code(0), Ended::Signal(15), Ended::Signal(2), Ended::Signal(1)] {
            assert_eq!(Restarts::default().decide(ended, false, true, now), Decision::Stop, "{ended:?}");
        }
    }

    #[test]
    fn no_restart_when_stopping_or_the_session_is_gone() {
        let now = Instant::now();
        assert_eq!(Restarts::default().decide(Ended::Code(1), true, true, now), Decision::Stop);
        assert_eq!(Restarts::default().decide(Ended::Code(1), false, false, now), Decision::Stop);
    }

    #[test]
    fn five_restarts_in_ten_minutes_then_it_gives_up() {
        let start = Instant::now();
        let mut r = Restarts::default();
        for i in 0..5 {
            assert_eq!(r.decide(Ended::Code(1), false, true, start + Duration::from_secs(i * 60)), Decision::Restart);
        }
        assert_eq!(r.decide(Ended::Code(1), false, true, start + Duration::from_secs(300)), Decision::GiveUp);
        // The first restart leaves the window 10 minutes after it.
        assert_eq!(r.decide(Ended::Code(1), false, true, start + Duration::from_secs(600)), Decision::Restart);
        assert_eq!(r.decide(Ended::Code(1), false, true, start + Duration::from_secs(601)), Decision::GiveUp);
    }

    #[test]
    fn reasons_and_exit_codes() {
        assert_eq!(Ended::Code(1).reason(), "exit code 1");
        assert_eq!(Ended::Signal(9).reason(), "signal 9");
        assert_eq!(Ended::Code(3).exit_code(), 3);
        assert_eq!(Ended::Signal(15).exit_code(), 143);
    }

    #[test]
    fn the_first_start_keeps_the_arguments_a_restart_gets_only_the_marks() {
        let args = os(&["/home/u/a.ovpn", "--after-update"]);
        assert_eq!(child_args(&args, None), os(&["/home/u/a.ovpn", "--after-update", "--supervised"]));
        assert_eq!(child_args(&args, Some(Ended::Code(1))), os(&["--supervised", "--restarted=exit code 1"]));
        assert!(is_supervised(&child_args(&args, None)));
        assert!(!is_supervised(&args));
        assert_eq!(restart_reason(&child_args(&args, Some(Ended::Signal(9)))).as_deref(), Some("signal 9"));
        assert_eq!(restart_reason(&child_args(&args, None)), None);
    }

    #[test]
    fn session_files() {
        assert!(session_state_alive(None));
        assert!(session_state_alive(Some("UID=1001\nSTATE=active\nACTIVE=1\n")));
        assert!(session_state_alive(Some("STATE=online\n")));
        assert!(!session_state_alive(Some("UID=1001\nSTATE=closing\n")));
        assert_eq!(user_display_session("NAME=u\nSTATE=active\nDISPLAY=11\n").as_deref(), Some("11"));
        assert_eq!(user_display_session("NAME=u\nDISPLAY=\n"), None);
        assert_eq!(user_display_session("NAME=u\n"), None);
    }

    #[test]
    fn x11_sockets() {
        assert_eq!(x11_socket(":0").as_deref(), Some("/tmp/.X11-unix/X0"));
        assert_eq!(x11_socket(":12.0").as_deref(), Some("/tmp/.X11-unix/X12"));
        assert_eq!(x11_socket("host:0"), None);
        assert_eq!(x11_socket(":"), None);
    }
}
