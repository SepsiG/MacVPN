//! The Windows backend: the WinVPN Service (spec 4.1). The request handling ([`service`], [`logs`]), the WireGuard
//! and OpenVPN pure parts compile and are tested on every OS; `sys` (Windows only) holds the service host, the pipe
//! server and the engines.

pub mod diagnostics;
pub mod install_dir;
pub mod logs;
pub mod ras_logoff;
pub mod recovery;
pub mod service;

pub mod wg_nt;
pub mod wg_pins;
pub mod wg_plan;
pub mod wg_update;

pub mod bridge_state;
pub mod ovpn_args;
pub mod ovpn_pins;
pub mod ovpn_run;

#[cfg(windows)]
#[allow(unsafe_code)]
mod sys;

/// The Windows helper's entry point: `service` (started by the SCM), `console` (debug builds: the tests); returns
/// the exit code.
#[cfg(windows)]
pub fn main() -> i32 {
    sys::main(&std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>())
}

/// Linux (phase 4) and any other target: no backend.
#[cfg(not(windows))]
pub fn main() -> i32 {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr(), "{}", crate::shared::l10n::tr("Not available on this system yet", &[]));
    1
}
