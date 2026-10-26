//! Fixed locations and limits of the root layer, and the resolved settings of one invocation.
//!
//! As root every value is the constant below. Only in test mode (effective uid != 0, see [`crate::macos::testmode`])
//! may the `MVPN_*` environment variables of the bash `mvpn` override them.

use crate::macos::sys;
use crate::macos::testmode::TestEnv;
use std::path::{Path, PathBuf};

pub const LIBEXEC: &str = "/usr/local/libexec/macvpn";
pub const RUN_BASE: &str = "/var/run/macvpn";
pub const LOG_BASE: &str = "/var/log/macvpn";
/// The DNS manager's persistent, root-only ledger (the original DNS of each network service and the connections
/// holding DNS), kept across a reboot like the `networksetup` change itself.
pub const DNS_BASE: &str = "/var/db/macvpn/dns";
pub const NETWORKSETUP: &str = "/usr/sbin/networksetup";
/// `wg-quick` keeps the interface → utun mapping here.
pub const WG_RUN: &str = "/var/run/wireguard";
/// The user's connection log is at most 5 MiB, plus one rotated `.1` copy of at most 5 MiB (see
/// [`crate::macos::log`]).
pub const LOG_MAX: u64 = 5_242_880;
/// The source config is at most 1 MB.
pub use crate::shared::limits::SRC_MAX;
/// SSTP: sstpc starts this fixed macOS pppd.
pub const PPPD: &str = "/usr/sbin/pppd";
/// SSTP: sstpc/pppd need it (brew caveat); created when missing.
pub const PPP_OPTIONS: &str = "/etc/ppp/options";
pub const ROUTE: &str = "/sbin/route";
/// OpenVPN/SSTP: the connection must be up within this many seconds.
pub const UP_TIMEOUT: u64 = 30;
/// SSTP: sstpc writes its own `sstp-pppd.XXXXXX` option file here.
pub const SSTP_TMP_DIRS: &str = "/private/tmp /var/run/sstpc";
/// MFA: the bridge's state files (`<id>.json`, the user's, 0600); root 755.
pub const UI_BASE: &str = "/var/run/macvpn-ui";
/// MFA: waiting for authentication extends `UP_TIMEOUT` by at most this much.
pub const MFA_MAX: u64 = 420;
/// 90 × 0.5 s = 45 s waiting for the lock.
pub const LOCK_TRIES: u64 = 90;

/// The fixed PATH of every child process.
pub const PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// The settings of one invocation.
#[derive(Debug, Clone)]
pub struct Settings {
    pub test_mode: bool,
    pub libexec: PathBuf,
    pub run_base: PathBuf,
    pub log_base: PathBuf,
    pub dns_base: PathBuf,
    /// `networksetup`; in test mode only a fake (`MVPN_NETWORKSETUP`), otherwise the DNS is never changed.
    pub networksetup: Option<PathBuf>,
    /// The user the connection belongs to (`SUDO_USER` as root, the caller in test mode); unvalidated.
    pub target_user: String,
    pub wg_run: PathBuf,
    pub lock_tries: u64,
    pub log_max: u64,
    pub up_timeout: u64,
    pub pppd: PathBuf,
    pub ppp_options: PathBuf,
    pub route: PathBuf,
    pub sstp_tmp_dirs: Vec<PathBuf>,
    pub ui_base: PathBuf,
    pub mfa_max: u64,
    /// The Homebrew prefix (`/opt/homebrew` or `/usr/local`), or the test's fake brew directory.
    pub brew: Option<PathBuf>,
    /// The program the MFA bridge runs from (`$LIBEXEC/mvpn`; `MVPN_MGMT` in test mode).
    pub mgmt: PathBuf,
    pub test: TestEnv,
}

impl Settings {
    /// Reads the environment overrides only in test mode.
    pub fn load() -> Settings {
        let test_mode = sys::geteuid() != 0;
        let test = if test_mode { TestEnv::from_env() } else { TestEnv::default() };
        Self::resolve(test_mode, test, std::env::var("SUDO_USER").unwrap_or_default())
    }

    /// Pure resolution (unit-tested): `test` is ignored unless `test_mode`.
    pub fn resolve(test_mode: bool, test: TestEnv, sudo_user: String) -> Settings {
        let test = if test_mode { test } else { TestEnv::default() };
        let pick = |v: &Option<String>, d: &str| PathBuf::from(v.as_deref().unwrap_or(d));
        let libexec = pick(&test.libexec, LIBEXEC);
        let target_user =
            if test_mode { sys::user_by_uid(sys::geteuid()).map(|u| u.name).unwrap_or_default() } else { sudo_user };
        let mut brew = ["/opt/homebrew", "/usr/local"]
            .iter()
            .map(PathBuf::from)
            .find(|p| crate::macos::exec::is_executable(&p.join("bin/brew")));
        if let Some(b) = &test.brew {
            brew = Some(PathBuf::from(b));
        }
        let mgmt = match &test.mgmt {
            Some(m) => PathBuf::from(m),
            None => libexec.join("mvpn"),
        };
        Settings {
            test_mode,
            run_base: pick(&test.run_base, RUN_BASE),
            log_base: pick(&test.log_base, LOG_BASE),
            dns_base: pick(&test.dns_base, DNS_BASE),
            networksetup: if test_mode {
                test.networksetup.as_deref().map(PathBuf::from)
            } else {
                Some(PathBuf::from(NETWORKSETUP))
            },
            target_user,
            wg_run: pick(&test.wg_run, WG_RUN),
            lock_tries: test.lock_tries.unwrap_or(LOCK_TRIES),
            log_max: test.log_max.unwrap_or(LOG_MAX),
            up_timeout: test.up_timeout.unwrap_or(UP_TIMEOUT),
            pppd: pick(&test.pppd, PPPD),
            ppp_options: pick(&test.ppp_options, PPP_OPTIONS),
            route: pick(&test.route, ROUTE),
            sstp_tmp_dirs: test
                .sstp_tmp
                .as_deref()
                .unwrap_or(SSTP_TMP_DIRS)
                .split([' ', '\t', '\n'])
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect(),
            ui_base: pick(&test.ui_base, UI_BASE),
            mfa_max: test.mfa_max.unwrap_or(MFA_MAX),
            brew,
            mgmt,
            libexec,
            test,
        }
    }

    /// The root layer's own binary: the DNS hook and the long-running output masker run from it.
    pub fn self_binary(&self) -> PathBuf {
        if self.test_mode
            && let Ok(p) = std::env::current_exe()
        {
            return p;
        }
        self.libexec.join("mvpn")
    }

    /// The DNS hook command (`<libexec>/mvpn hook ovpn-dns`), which OpenVPN runs as `--up` / `--down`.
    pub fn hook_program(&self) -> PathBuf {
        self.libexec.join("mvpn")
    }

    pub fn run_dir(&self, id: &str) -> PathBuf {
        self.run_base.join(id)
    }

    pub fn log_file(&self, id: &str) -> PathBuf {
        self.log_base.join(format!("{id}.log"))
    }
}

/// `true` if `p` is a symlink (never follows it).
pub fn is_symlink(p: &Path) -> bool {
    std::fs::symlink_metadata(p).map(|m| m.file_type().is_symlink()).unwrap_or(false)
}

/// The bash `[ -f p ]`: a regular file, symlinks followed.
pub fn is_file(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false)
}

/// The bash `[ -d p ]`: a directory, symlinks followed.
pub fn is_dir(p: &Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false)
}

/// The bash `[ -e p ]`.
pub fn exists(p: &Path) -> bool {
    std::fs::metadata(p).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_ignores_every_override() {
        let t = TestEnv {
            run_base: Some("/tmp/x".into()),
            libexec: Some("/tmp/l".into()),
            lock_tries: Some(1),
            brew: Some("/tmp/b".into()),
            mgmt: Some("/tmp/m".into()),
            dns_base: Some("/tmp/d".into()),
            networksetup: Some("/tmp/n".into()),
            ..TestEnv::default()
        };
        let s = Settings::resolve(false, t, "alice".into());
        assert_eq!(s.dns_base, PathBuf::from(DNS_BASE));
        assert_eq!(s.networksetup, Some(PathBuf::from(NETWORKSETUP)));
        assert_eq!(s.run_base, PathBuf::from(RUN_BASE));
        assert_eq!(s.libexec, PathBuf::from(LIBEXEC));
        assert_eq!(s.mgmt, PathBuf::from("/usr/local/libexec/macvpn/mvpn"));
        assert_eq!(s.lock_tries, LOCK_TRIES);
        assert_ne!(s.brew, Some(PathBuf::from("/tmp/b")));
        assert_eq!(s.target_user, "alice");
        assert!(!s.test.allow_up && !s.test.allow_down);
        assert_eq!(s.sstp_tmp_dirs, vec![PathBuf::from("/private/tmp"), PathBuf::from("/var/run/sstpc")]);
    }

    #[test]
    fn test_mode_uses_overrides() {
        let t = TestEnv { run_base: Some("/tmp/x".into()), lock_tries: Some(2), ..TestEnv::default() };
        let s = Settings::resolve(true, t, "ignored".into());
        assert_eq!(s.run_base, PathBuf::from("/tmp/x"));
        assert_eq!(s.lock_tries, 2);
        assert_ne!(s.target_user, "ignored");
        assert_eq!(s.networksetup, None, "test mode never runs the real networksetup");
        let t = TestEnv {
            networksetup: Some("/tmp/fake-ns".into()),
            dns_base: Some("/tmp/d".into()),
            ..TestEnv::default()
        };
        let s = Settings::resolve(true, t, String::new());
        assert_eq!(s.networksetup, Some(PathBuf::from("/tmp/fake-ns")));
        assert_eq!(s.dns_base, PathBuf::from("/tmp/d"));
    }
}
