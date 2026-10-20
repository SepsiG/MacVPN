//! The refresh schedule of team catalogs (spec 4, plan Task 12), pure: at launch and on unlock, every 15 minutes,
//! on wake from sleep and on demand ("Refresh now"), with an exponential back-off while a source is failing.
//!
//! - Healthy: the next attempt is [`REFRESH_INTERVAL`] after the last one.
//! - After n ≥ 1 consecutive failures (unavailable or failed): `min(BACKOFF_START · 2^(n−1), BACKOFF_MAX)`, plus up
//!   to 10 % jitter (injected, so many subscribers of one source do not retry in step).
//! - A refused rollback or a changed team key is not a transport failure: the failure count is 0 and the normal
//!   15-minute schedule applies.
//! - `Launch`, `Unlock` and `Wake` refresh every subscription once, whatever the back-off (the failure count keeps
//!   counting); `Manual` always runs; `Timer` respects [`next_attempt`]. While the vault is locked nothing runs (the
//!   service checks that).

use std::time::{Duration, Instant};

/// The healthy interval.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// The first back-off step.
pub const BACKOFF_START: Duration = Duration::from_secs(60);
/// The longest back-off.
pub const BACKOFF_MAX: Duration = Duration::from_secs(60 * 60);
/// The largest jitter, as a fraction of the back-off.
pub const MAX_JITTER: f64 = 0.1;
/// The scheduler thread wakes this often to see whether a refresh is due.
pub const SCHEDULER_WAKE: Duration = Duration::from_secs(30);

/// What started a refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefreshTrigger {
    /// The app launched.
    Launch,
    /// The scheduler's interval.
    Timer,
    /// The Mac woke from sleep.
    Wake,
    /// The vault was unlocked.
    Unlock,
    /// "Refresh now".
    Manual,
}

/// The back-off after `failures` (≥ 1) consecutive failures, without jitter.
pub fn backoff(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    BACKOFF_START.saturating_mul(1 << doublings).min(BACKOFF_MAX)
}

/// When the next timer refresh is due; `None`: never attempted in this run, due now. `jitter` is clamped to
/// `0..=MAX_JITTER` and applies to the back-off only.
pub fn next_attempt(last_attempt: Option<Instant>, failures: u32, jitter: f64) -> Option<Instant> {
    let last = last_attempt?;
    if failures == 0 {
        return Some(last + REFRESH_INTERVAL);
    }
    let jitter = if jitter.is_finite() { jitter.clamp(0.0, MAX_JITTER) } else { 0.0 };
    Some(last + backoff(failures).mul_f64(1.0 + jitter))
}

/// Whether a subscription is refreshed now.
pub fn is_due(trigger: RefreshTrigger, next: Option<Instant>, now: Instant) -> bool {
    match trigger {
        RefreshTrigger::Launch | RefreshTrigger::Unlock | RefreshTrigger::Wake | RefreshTrigger::Manual => true,
        RefreshTrigger::Timer => next.is_none_or(|next| now >= next),
    }
}
