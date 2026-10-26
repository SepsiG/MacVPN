//! Test mode: the `MVPN_*` environment hooks of the bash `mvpn`, honoured ONLY when the effective uid is not 0.
//!
//! As root none of these variables is ever read ([`crate::macos::paths::Settings::load`] does not call
//! [`TestEnv::from_env`]). Not as root, `up` and `down` only run with `--dry-run`, or with an explicit
//! `MVPN_TEST_ALLOW_UP` / `MVPN_TEST_ALLOW_DOWN` and a fake brew directory, so a test never starts a real VPN tool;
//! and a non-root process can only affect the caller's own processes anyway.

/// The overrides (the bash `${MVPN_X:-default}`: an empty value counts as unset; numbers must be `^[0-9]+$`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestEnv {
    pub run_base: Option<String>,
    pub log_base: Option<String>,
    /// `MVPN_DNS_BASE`: the DNS ledger directory.
    pub dns_base: Option<String>,
    /// `MVPN_NETWORKSETUP`: a fake `networksetup`; without it test mode never changes DNS.
    pub networksetup: Option<String>,
    pub libexec: Option<String>,
    pub wg_run: Option<String>,
    pub lock_tries: Option<u64>,
    pub log_max: Option<u64>,
    pub up_timeout: Option<u64>,
    pub pppd: Option<String>,
    pub ppp_options: Option<String>,
    pub route: Option<String>,
    pub sstp_tmp: Option<String>,
    pub ui_base: Option<String>,
    pub mfa_max: Option<u64>,
    /// `MVPN_BREW`: the fake tool directory.
    pub brew: Option<String>,
    /// `MVPN_MGMT`: the program the MFA bridge runs from.
    pub mgmt: Option<String>,
    /// `MVPN_TEST_ALLOW_UP=1`
    pub allow_up: bool,
    /// `MVPN_TEST_ALLOW_DOWN=1`
    pub allow_down: bool,
    /// `MVPN_TEST_IFACE_OK=1`: the fake sstpc creates no ppp interface; treat it as existing.
    pub iface_ok: bool,
}

impl TestEnv {
    pub fn from_env() -> TestEnv {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> TestEnv {
        let s = |k: &str| get(k).filter(|v| !v.is_empty());
        let n = |k: &str| get(k).filter(|v| is_digits(v)).and_then(|v| v.parse::<u64>().ok());
        let one = |k: &str| get(k).as_deref() == Some("1");
        TestEnv {
            run_base: s("MVPN_RUN_BASE"),
            log_base: s("MVPN_LOG_BASE"),
            dns_base: s("MVPN_DNS_BASE"),
            networksetup: s("MVPN_NETWORKSETUP"),
            libexec: s("MVPN_LIBEXEC"),
            wg_run: s("MVPN_WG_RUN"),
            lock_tries: n("MVPN_LOCK_TRIES"),
            log_max: n("MVPN_LOG_MAX"),
            up_timeout: n("MVPN_UP_TIMEOUT"),
            pppd: s("MVPN_PPPD"),
            ppp_options: s("MVPN_PPP_OPTIONS"),
            route: s("MVPN_ROUTE"),
            sstp_tmp: s("MVPN_SSTP_TMP"),
            ui_base: s("MVPN_UI_BASE"),
            mfa_max: n("MVPN_MFA_MAX"),
            brew: s("MVPN_BREW"),
            mgmt: s("MVPN_MGMT"),
            allow_up: one("MVPN_TEST_ALLOW_UP"),
            allow_down: one("MVPN_TEST_ALLOW_DOWN"),
            iface_ok: one("MVPN_TEST_IFACE_OK"),
        }
    }
}

/// `^[0-9]+$`
pub fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bash_override_semantics() {
        let env = |k: &str| match k {
            "MVPN_RUN_BASE" => Some("/tmp/r".to_string()),
            "MVPN_LOG_BASE" => Some(String::new()),
            "MVPN_LOCK_TRIES" => Some("2".into()),
            "MVPN_UP_TIMEOUT" => Some("3s".into()),
            "MVPN_TEST_ALLOW_UP" => Some("1".into()),
            "MVPN_TEST_ALLOW_DOWN" => Some("yes".into()),
            _ => None,
        };
        let t = TestEnv::from_lookup(env);
        assert_eq!(t.run_base.as_deref(), Some("/tmp/r"));
        assert_eq!(t.log_base, None);
        assert_eq!(t.lock_tries, Some(2));
        assert_eq!(t.up_timeout, None);
        assert!(t.allow_up);
        assert!(!t.allow_down);
    }
}
