//! The WinVPN Service's recovery settings: what the SCM does when the service fails. The service sets them itself
//! at every start (`sys::host`, through `macvpn_winsys::scm`): Windows Installer cannot (its
//! MsiServiceConfigFailureActions fails a restart action with error 1939, 2b plan Task 15, fix2).

/// The service's name (the MSI's ServiceInstall).
pub const SERVICE_NAME: &str = "WinVPN";
/// The failure count goes back to 0 after a day without a failure.
pub const RESET_PERIOD_SECS: u32 = 86_400;
/// The first failure: restart after 5 s; the second: after 30 s; from the third on (within a day): nothing.
/// `Some(ms)`: restart after `ms`; `None`: no action.
pub const ACTIONS: [Option<u32>; 3] = [Some(5_000), Some(30_000), None];
/// Also when the service stops itself with an error (not LocalSystem, no job), not only when its process dies.
pub const ON_NON_CRASH_FAILURES: bool = true;

#[cfg(test)]
mod tests {
    use super::*;

    /// What Task 15's MSI asked for (ResetPeriod 86400, Actions 1[~]1[~]0, DelayActions 5000[~]30000[~]0), and
    /// never more than two restarts a day.
    #[test]
    fn restart_twice_then_nothing_reset_after_a_day() {
        assert_eq!(SERVICE_NAME, "WinVPN");
        assert_eq!(RESET_PERIOD_SECS, 24 * 60 * 60);
        assert_eq!(ACTIONS, [Some(5_000), Some(30_000), None]);
        assert_eq!(ACTIONS.iter().filter(|a| a.is_some()).count(), 2);
        assert_eq!(ACTIONS.last(), Some(&None), "the last action repeats: it must be no action");
    }
}
