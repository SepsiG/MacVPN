//! The live system VPN list: a change notification from macOS (the platform's watcher) reloads the list once a
//! burst of notifications is over. The reload is the status poller's own refresh ([`crate::app::Poller::wake`]):
//! one refresh path, with its epoch rules, re-lists the system services and rebinds the managed native ones.

use std::sync::{Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The quiet time after the last notification of a burst before the list is reloaded.
pub const LIVE_DEBOUNCE: Duration = Duration::from_millis(500);
/// A burst that never goes quiet still reloads this long after its first notification.
pub const LIVE_MAX_WAIT: Duration = Duration::from_secs(2);

/// Whether a running watcher is trusted to report every change, so the poll fallback can stay at its idle pace.
/// The spike (docs/superpowers/spikes/2026-10-19-live-system-list.md) could not add, rename and delete real
/// system VPNs, so the fallback stays on until the manual checks confirm the watcher on real Macs.
pub const WATCHER_TRUSTED: bool = false;

/// Collapses a burst of triggers into one reload, [`LIVE_DEBOUNCE`] after the last one but at most
/// [`LIVE_MAX_WAIT`] after the first (pure; the clock is passed).
#[derive(Debug, Default, Clone)]
pub struct Debouncer {
    /// The first and the last trigger of the pending burst.
    burst: Option<(Instant, Instant)>,
}

impl Debouncer {
    pub fn trigger(&mut self, now: Instant) {
        self.burst = Some(self.burst.map_or((now, now), |(first, _)| (first, now)));
    }

    /// `true` once per burst: [`LIVE_DEBOUNCE`] after its last trigger, or [`LIVE_MAX_WAIT`] after its first.
    pub fn take_due(&mut self, now: Instant) -> bool {
        match self.deadline() {
            Some(deadline) if now >= deadline => {
                self.burst = None;
                true
            }
            _ => false,
        }
    }

    /// When the pending reload is due; `None`: nothing pending.
    pub fn deadline(&self) -> Option<Instant> {
        self.burst.map(|(first, last)| (last + LIVE_DEBOUNCE).min(first + LIVE_MAX_WAIT))
    }
}

/// The reload thread's state: [`Self::trigger`] from any thread (the watcher's), [`Self::run`] on its own thread.
#[derive(Default)]
pub struct LiveReload {
    state: Mutex<(Debouncer, bool)>,
    signal: Condvar,
}

impl LiveReload {
    pub fn new() -> Self {
        Self::default()
    }

    /// A change notification.
    pub fn trigger(&self) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).0.trigger(Instant::now());
        self.signal.notify_all();
    }

    pub fn stop(&self) {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).1 = true;
        self.signal.notify_all();
    }

    /// Calls `reload` once per burst until stopped. `reload` runs outside the lock.
    pub fn run(&self, reload: impl Fn()) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if state.1 {
                return;
            }
            let now = Instant::now();
            if state.0.take_due(now) {
                drop(state);
                reload();
                state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            state = match state.0.deadline() {
                None => self.signal.wait(state).unwrap_or_else(PoisonError::into_inner),
                Some(deadline) => {
                    self.signal
                        .wait_timeout(state, deadline.saturating_duration_since(now))
                        .unwrap_or_else(PoisonError::into_inner)
                        .0
                }
            };
        }
    }
}
