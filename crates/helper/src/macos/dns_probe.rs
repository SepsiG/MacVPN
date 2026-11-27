//! The DNS probe of the root layer: the shared probe (`macvpn_core::dns_policy::probe`, since root layer 20) behind
//! the test-mode switch. In test mode no socket is ever opened: `MVPN_DNS_PROBE=ok|fail` is the result, and
//! without it the probe is not run.

use crate::macos::dns_plan::Probe;
use crate::macos::paths::Settings;
use std::time::Duration;

/// The probe of `servers` (the effective VPN servers, IP literals): in test mode only `MVPN_DNS_PROBE` (`ok`,
/// `fail`; `slow-ok` / `slow-fail` take a second, as a real probe takes its time).
pub fn probe(s: &Settings, servers: &[String]) -> (Probe, String) {
    if s.test_mode {
        let mut v = s.dns_probe.as_deref();
        if let Some(rest) = v.and_then(|v| v.strip_prefix("slow-")) {
            std::thread::sleep(Duration::from_secs(1));
            v = Some(rest);
        }
        return match v {
            Some("ok") => (Probe::Ok, "test: ok".into()),
            Some("fail") => (Probe::Failed, "test: fail".into()),
            _ => (Probe::NotRun, String::new()),
        };
    }
    macvpn_core::dns_policy::probe(servers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_never_opens_a_socket() {
        let mut s = Settings::resolve(true, Default::default(), String::new());
        assert_eq!(probe(&s, &["127.0.0.1".into()]).0, Probe::NotRun);
        s.dns_probe = Some("ok".into());
        assert_eq!(probe(&s, &[]).0, Probe::Ok);
        s.dns_probe = Some("fail".into());
        assert_eq!(probe(&s, &[]).0, Probe::Failed);
    }
}
