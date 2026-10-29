//! The macOS backend of the helper: `mvpn`, the MacVPN root layer, one binary for what were the bash `mvpn`,
//! `ovpn-dns`, and the Swift `mvpn-validate` and `mvpn-mgmt`. Installed as `/usr/local/libexec/macvpn/mvpn` (root:wheel
//! 755), called by the app through `sudo -n` (`/etc/sudoers.d/macvpn`).
//!
//! ```text
//! mvpn up      <openvpn|wireguard|strongswan|sstp> <id> [--debug] [--dry-run] [--accept-risky a,b]
//!                    (stdin: the config, then the secrets — see below)
//! mvpn down    <openvpn|wireguard|strongswan|sstp> <id> [--dry-run]
//! mvpn respond openvpn <id>   (stdin: kind=crv1|static|webauth-ack|cancel, response=<value>)
//! mvpn status                  (also restores the DNS of connections that no longer run, see `dns`)
//! mvpn dns-reconcile           (only that)
//! mvpn liveness <id>           (root layer 10: the tunnel's liveness facts for dead-tunnel detection, see `liveness`)
//! mvpn traffic <id>            (root layer 11: a strongSwan connection's CHILD_SA byte counters, see `traffic`)
//! mvpn version
//!   any of them: --lang <en|hu>
//! mvpn validate …              (the old mvpn-validate, see `validate`; the config on stdin, no secrets)
//! mvpn hook ovpn-dns <run> <log>   (OpenVPN --up/--down; internal)
//! mvpn mgmt-bridge …           (the MFA bridge, started by `up`; also as argv[0] `mvpn-mgmt`; internal)
//! ```
//!
//! Not as root (test mode) the `MVPN_*` environment hooks of the bash version apply; as root never.
//!
//! **stdin of `up` (root layer 8).** The root layer opens no file of the user: the app sends the config itself,
//! length-prefixed, followed by the secret lines, and closes stdin:
//!
//! ```text
//! config <len>\n            <len> = the config's exact byte length: ASCII decimal, no sign, no leading zero,
//! <len bytes of config>      1 ≤ len ≤ 1048576 (1 MB); the config is UTF-8 without NUL bytes
//! username=<v>\n             then, in any order and each at most once, only complete lines of these keys
//! password=<v>\n             (empty ones may be left out; no other line, no empty line, the last line ends
//! psk=<v>\n                  in \n); the whole stdin is at most 1 MB + 64 KiB + 16 bytes
//! keypass=<v>\n
//! otp=<v>\n
//! challenge=packed\n
//! ```
//!
//! The config may contain lines such as `password=…`: only the length decides where it ends. Refusals (exit 1,
//! the message on stderr and in the log, no run directory left): no `config` header first → `Config not
//! provided`; a malformed header or secrets section, a length that does not match → `Invalid input`; len above
//! 1 MB → `The config is too large (1 MB at most)` (refused before the body is read); fewer bytes than len →
//! `The config is incomplete`; a NUL byte → `The config must not contain NUL bytes`. `mvpn validate` takes the
//! same frame with nothing after the config. `down`, `respond` and `status` read no config. The parser is
//! [`crate::shared::framing::parse_framed`]; the config is written only into the root-only run directory
//! (`run_dir::prepare`) and validated there exactly as before.

#![cfg(target_os = "macos")]

/// `println!` without the panic when stdout is closed (the caller went away): output is best effort.
macro_rules! out {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), $($t)*);
    }};
}

/// `eprintln!` without the panic when stderr is closed.
macro_rules! err {
    ($($t:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($t)*);
    }};
}

mod ctx;
mod dns;
mod exec;
mod fsx;
mod hook_dns;
mod liveness;
mod lock;
mod log;
mod mgmt_bridge;
mod openvpn;
mod paths;
mod procs;
mod respond;
mod run_dir;
mod sstp;
mod status;
mod strongswan;
mod sys;
mod testmode;
mod traffic;
mod updown;
mod validate;
mod wireguard;

use crate::shared::framing::{self, FrameError, Framed};
use crate::shared::{cli, mask};
use ctx::{Ctx, tr};
use macvpn_core::l10n::AppLanguage;
use std::io::Read;

/// The root layer's version (`mvpn version`, the installed `VERSION` file).
pub const VERSION: &str = include_str!("../../VERSION");

/// Internal subcommands must not be reachable through the sudoers rule: as root, a `SUDO_COMMAND` in the
/// environment means a user ran it via sudo (mvpn starts these with a cleared environment).
fn refuse_via_sudo() -> bool {
    sys::geteuid() == 0 && std::env::var_os("SUDO_COMMAND").is_some()
}

/// As root the hook only acts on an active run of the root layer: `<run>` is `/var/run/macvpn/<uuid>`, a real
/// directory owned by root with no access for others, whose `kind` is openvpn or sstp (the kinds that use the
/// hook), and `<log>` is that connection's log. A user cannot create such a directory, so this is the hook's
/// unforgeable marker; it does not depend on the environment (a config's `setenv SUDO_*` cannot switch the hook
/// off and leak DNS). Through sudo the hook is harmless anyway: sudo's env_reset drops `script_type`.
fn hook_paths_ok(args: &[String]) -> bool {
    use std::os::unix::fs::MetadataExt;
    if sys::geteuid() != 0 {
        return true;
    }
    let (Some(run), Some(log)) = (args.first(), args.get(1)) else { return false };
    let id = run.strip_prefix(&format!("{}/", paths::RUN_BASE)).unwrap_or_default();
    if !cli::is_uuid(id) || *log != format!("{}/{id}.log", paths::LOG_BASE) {
        return false;
    }
    let run = std::path::Path::new(run);
    let root_private =
        std::fs::symlink_metadata(run).is_ok_and(|m| m.file_type().is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0);
    root_private && matches!(fsx::cat(&run.join("kind")).as_str(), "openvpn" | "sstp")
}

/// The macOS root layer's entry point (`mvpn`, also as `mvpn-mgmt`); returns the exit code.
pub fn main() -> i32 {
    sys::umask(0o077);
    let argv: Vec<String> = std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect();
    let name = argv.first().map(|a| a.rsplit('/').next().unwrap_or(a).to_string()).unwrap_or_default();
    let rest = argv.get(1..).unwrap_or_default();

    // The bridge runs as `mvpn-mgmt` (its process name tells it apart from other mvpn processes).
    if name == openvpn::BRIDGE_NAME {
        if refuse_via_sudo() {
            return 2;
        }
        return mgmt_bridge::main(rest);
    }
    match rest.first().map(String::as_str) {
        Some("mgmt-bridge") => {
            if refuse_via_sudo() {
                return 2;
            }
            return mgmt_bridge::main(&rest[1..]);
        }
        Some("hook") => {
            if rest.get(1).map(String::as_str) != Some("ovpn-dns") || !hook_paths_ok(&rest[2..]) {
                return 2;
            }
            return hook_dns::main(&rest[2..]);
        }
        Some("validate") => {
            if refuse_via_sudo() {
                return 2;
            }
            return validate::main(&rest[1..]);
        }
        Some("mask-stream") => {
            if refuse_via_sudo() {
                return 2;
            }
            let s = paths::Settings::load();
            return sstp::mask_stream(&s, rest.get(1).map(String::as_str).unwrap_or_default());
        }
        _ => {}
    }

    let a = cli::Args::parse(rest);
    AppLanguage::set_override(Some(a.language()));
    let s = paths::Settings::load();
    let mut ctx = Ctx::new(s, a);
    match ctx.a.cmd.as_str() {
        "version" => {
            out!("{}", VERSION.trim());
            0
        }
        "status" => {
            // The app asks for the status at start (also after a reboot) and on every refresh: DNS held by a
            // connection that no longer runs is restored here (skipped if the DNS ledger is busy).
            dns::reconcile(&ctx.s, false);
            out_raw(&status::render(&ctx.s));
            0
        }
        "dns-reconcile" => {
            dns::reconcile(&ctx.s, true);
            0
        }
        macvpn_core::liveness::LIVENESS => liveness::main(&ctx),
        macvpn_core::traffic::TRAFFIC => traffic::main(&ctx),
        "respond" => {
            if ctx.kind != "openvpn" {
                return ctx.die(tr("Usage: mvpn respond openvpn <id>", &[])).0;
            }
            if !cli::is_uuid(&ctx.id) {
                return ctx.die(tr("Invalid ID", &[])).0;
            }
            match respond::run(&mut ctx) {
                Ok(()) => 0,
                Err(e) => e.0,
            }
        }
        "up" | "down" => updown::main(&mut ctx),
        "__mask" => test_only(&ctx, || {
            let get = |k: &str| std::env::var_os(k).map(|v| v.into_encoded_bytes()).unwrap_or_default();
            let m = mask::Masker::new(
                [get("MVPN_MASK_1"), get("MVPN_MASK_2"), get("MVPN_MASK_3"), get("MVPN_MASK_4")].iter().map(Vec::as_slice),
            );
            m.stream(std::io::stdin().lock(), std::io::stdout().lock());
            0
        }),
        "__ovpn-done" => test_only(&ctx, || {
            let mut data = Vec::new();
            let _ = std::io::stdin().lock().take(1 << 20).read_to_end(&mut data);
            i32::from(!log::ovpn_done(&data))
        }),
        _ => ctx.die(tr(
            "Usage: mvpn up|down <openvpn|wireguard|strongswan|sstp> <id> [--debug] [--dry-run] [--accept-risky a,b] [--lang en|hu] | respond openvpn <id> | status | version",
            &[],
        ))
        .0,
    }
}

/// Writes text to stdout as is (best effort).
pub(crate) fn out_raw(s: &str) {
    use std::io::Write as _;
    let mut o = std::io::stdout();
    let _ = o.write_all(s.as_bytes()).and_then(|_| o.flush());
}

/// The test-only commands (`__mask`, `__ovpn-done`) exist only when not root.
fn test_only(ctx: &Ctx, f: impl FnOnce() -> i32) -> i32 {
    if !ctx.s.test_mode {
        return ctx.die(tr("Test mode only", &[])).0;
    }
    f()
}

/// [`framing::read_framed`] on this process's stdin; a terminal is `Missing` (nothing is read from it). fd 0 is read
/// directly, not through `std::io::stdin()`, whose buffer would keep a copy of the config.
pub fn read_framed_stdin(secrets: bool) -> Result<Framed, FrameError> {
    if sys::stdin_is_tty() {
        return Err(FrameError::Missing);
    }
    framing::read_framed(&mut *sys::stdin_fd(), secrets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_10() {
        assert_eq!(VERSION.trim(), "11");
    }
}
