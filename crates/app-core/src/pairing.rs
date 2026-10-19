//! The pairing window's broker (the control API's [`ControlHost::ask_pairing`]): the server's pairing thread parks
//! here until the window answers, the window is closed, the server stops, or [`PAIRING_TIMEOUT`] passes. It works
//! like the MFA prompt broker ([`crate::prompt::PromptBroker`]):
//!
//! - the window is shown without taking the focus, and nothing but Deny is taken in its first second after it
//!   became visible ([`ARM_DELAY`], counted from the later of [`PairingBroker::mark_shown`] and
//!   [`PairingBroker::mark_loaded`]), against a keystroke or a click meant for another app;
//! - the answer is checked here ([`PairingBroker::answer`]): an approval must name at least one of the offered
//!   connections, each once, and nothing else ([`validate_allowed`]).
//!
//! The view ([`PairingView`]) carries no secret: the token is created by the server only after the approval and
//! never passes through the UI.
//!
//! [`ControlHost::ask_pairing`]: crate::control::ControlHost::ask_pairing

use crate::control::{PairingAnswer, PairingRequest};
use macvpn_core::control::protocol::escape_unsafe_text;
use macvpn_core::date::Date;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

pub use crate::prompt::ARM_DELAY;

/// The window closes (as timed out) after this long (spec: 2 minutes; the server has the same limit).
pub const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);

/// One connection the window offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingItem {
    /// The connection key (`ConnectionItem::id()`).
    pub id: String,
    pub name: String,
}

/// An open pairing as the window shows it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingView {
    /// Answer with this ID (the window's label is `pair-<id>`).
    pub id: u64,
    /// Self-reported by the client (sanitized by the protocol parser).
    pub name: String,
    /// The peer's executable path: the identity the pairing pins.
    pub executable: String,
    /// The connections that can be allowed, in the app's order; none is ticked at first.
    pub items: Vec<PairingItem>,
    /// Unix time (seconds) when the window gives up.
    pub deadline: f64,
}

/// The `pairing_answer` command's `allowed`: at least one key, each one offered, none twice.
pub fn validate_allowed(offered: &[PairingItem], keys: &[String]) -> Result<Vec<String>, String> {
    if keys.is_empty() {
        return Err("no connection allowed".into());
    }
    let mut seen = HashSet::new();
    for key in keys {
        if !offered.iter().any(|i| &i.id == key) {
            return Err("not an offered connection".into());
        }
        if !seen.insert(key.as_str()) {
            return Err("repeated connection".into());
        }
    }
    Ok(keys.to_vec())
}

/// The pairing window's label.
pub fn pairing_window_label(id: u64) -> String {
    format!("pair-{id}")
}

/// The pairing ID of a pairing window's label (`pair-<digits>`).
pub fn pairing_id_of_label(label: &str) -> Option<u64> {
    let digits = label.strip_prefix("pair-")?;
    if digits.is_empty() || digits.len() > 19 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

struct Entry {
    view: PairingView,
    result: Option<PairingAnswer>,
    shown: Option<Instant>,
    loaded: Option<Instant>,
}

impl Entry {
    fn armed(&self, now: Instant) -> bool {
        match (self.shown, self.loaded) {
            (Some(shown), Some(loaded)) => now.saturating_duration_since(shown.max(loaded)) >= ARM_DELAY,
            _ => false,
        }
    }
}

#[derive(Default)]
struct State {
    next_id: u64,
    open: BTreeMap<u64, Entry>,
}

type Hook = Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
pub struct PairingBroker {
    state: Mutex<State>,
    changed: Condvar,
    on_change: Mutex<Option<Hook>>,
}

impl PairingBroker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Called when a pairing opens or closes (the UI opens or closes its window).
    pub fn set_on_change(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.on_change.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(hook));
    }

    fn notify(&self) {
        let hook = self.on_change.lock().unwrap_or_else(PoisonError::into_inner).clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Opens a pairing and blocks until it is answered, denied (window closed, [`Self::deny_all`]) or `timeout`
    /// passes (`TimedOut`). `now`: the wall clock, for the window's countdown.
    pub fn present(&self, request: PairingRequest, now: Date, timeout: Duration) -> PairingAnswer {
        let until = Instant::now() + timeout;
        let id = {
            let mut state = self.lock();
            state.next_id += 1;
            let id = state.next_id;
            let view = PairingView {
                id,
                name: request.name,
                executable: escape_unsafe_text(&request.executable),
                items: request.items.into_iter().map(|(id, name)| PairingItem { id, name }).collect(),
                deadline: now.time_interval_since_1970() + timeout.as_secs_f64(),
            };
            state.open.insert(id, Entry { view, result: None, shown: None, loaded: None });
            id
        };
        self.notify();
        let answer = {
            let mut state = self.lock();
            loop {
                match state.open.get(&id) {
                    Some(Entry { result: Some(result), .. }) => {
                        let result = result.clone();
                        state.open.remove(&id);
                        break result;
                    }
                    Some(_) => {}
                    None => break PairingAnswer::Denied,
                }
                let now = Instant::now();
                if now >= until {
                    state.open.remove(&id);
                    break PairingAnswer::TimedOut;
                }
                state = self.changed.wait_timeout(state, until - now).unwrap_or_else(PoisonError::into_inner).0;
            }
        };
        self.notify();
        answer
    }

    /// The open pairings, oldest first.
    pub fn pending(&self) -> Vec<PairingView> {
        self.lock().open.values().filter(|e| e.result.is_none()).map(|e| e.view.clone()).collect()
    }

    fn mark(&self, id: u64, f: impl FnOnce(&mut Entry)) -> bool {
        match self.lock().open.get_mut(&id).filter(|e| e.result.is_none()) {
            Some(entry) => {
                f(entry);
                true
            }
            None => false,
        }
    }

    /// The window was ordered on screen at `now` (only the first signal counts). False: no such open pairing.
    pub fn mark_shown(&self, id: u64, now: Instant) -> bool {
        self.mark(id, |e| {
            e.shown.get_or_insert(now);
        })
    }

    /// The window's page is loaded and shows the pairing (`pairing_ready`; only the first signal counts).
    pub fn mark_loaded(&self, id: u64, now: Instant) -> bool {
        self.mark(id, |e| {
            e.loaded.get_or_insert(now);
        })
    }

    /// The window's answer: `None` denies (taken at any time), `Some(keys)` approves those connections (only
    /// once the window is armed, and only offered keys: [`validate_allowed`]).
    pub fn answer(&self, id: u64, allowed: Option<Vec<String>>, now: Instant) -> Result<(), String> {
        {
            let mut state = self.lock();
            let entry = state.open.get_mut(&id).filter(|e| e.result.is_none()).ok_or("no such pairing")?;
            let result = match allowed {
                None => PairingAnswer::Denied,
                Some(_) if !entry.armed(now) => return Err("too early".into()),
                Some(keys) => PairingAnswer::Approved(validate_allowed(&entry.view.items, &keys)?),
            };
            entry.result = Some(result);
        }
        self.changed.notify_all();
        Ok(())
    }

    /// The window was closed: denied. False: no such open pairing.
    pub fn deny(&self, id: u64) -> bool {
        let found = self.mark(id, |e| e.result = Some(PairingAnswer::Denied));
        if found {
            self.changed.notify_all();
        }
        found
    }

    /// Every open pairing is denied (the control server stops).
    pub fn deny_all(&self) {
        for entry in self.lock().open.values_mut() {
            entry.result.get_or_insert(PairingAnswer::Denied);
        }
        self.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> PairingRequest {
        PairingRequest {
            name: "Remote Desktop".into(),
            executable: "/Applications/Remote Desktop.app/Contents/MacOS/Remote Desktop".into(),
            items: vec![("K1".into(), "Office".into()), ("K2".into(), "Lab".into())],
        }
    }

    fn open(broker: &Arc<PairingBroker>, timeout: Duration) -> (std::thread::JoinHandle<PairingAnswer>, u64) {
        let b = broker.clone();
        let waiter =
            std::thread::spawn(move || b.present(request(), Date::from_time_interval_since_1970(1000.0), timeout));
        let start = Instant::now();
        loop {
            if let Some(v) = broker.pending().first() {
                return (waiter, v.id);
            }
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn arm(broker: &PairingBroker, id: u64) -> Instant {
        let t = Instant::now();
        assert!(broker.mark_shown(id, t));
        assert!(broker.mark_loaded(id, t));
        t + ARM_DELAY
    }

    #[test]
    fn the_view_escapes_control_and_format_characters_in_the_path() {
        let broker = Arc::new(PairingBroker::new());
        let b = broker.clone();
        let mut req = request();
        req.executable = "/tmp/a\n\u{202E}b".into();
        let waiter = std::thread::spawn(move || {
            b.present(req, Date::from_time_interval_since_1970(0.0), Duration::from_secs(60))
        });
        let start = Instant::now();
        let view = loop {
            if let Some(v) = broker.pending().first() {
                break v.clone();
            }
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(view.executable, "/tmp/a\\u{a}\\u{202e}b");
        assert!(broker.deny(view.id));
        assert_eq!(waiter.join().unwrap(), PairingAnswer::Denied);
    }

    #[test]
    fn the_view_shows_the_request() {
        let broker = Arc::new(PairingBroker::new());
        let (waiter, id) = open(&broker, Duration::from_secs(60));
        let view = broker.pending()[0].clone();
        assert_eq!(view.name, "Remote Desktop");
        assert!(view.executable.ends_with("MacOS/Remote Desktop"));
        assert_eq!(view.items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), ["K1", "K2"]);
        assert_eq!(view.deadline, 1060.0);
        assert!(broker.deny(id));
        assert_eq!(waiter.join().unwrap(), PairingAnswer::Denied);
        assert!(broker.pending().is_empty());
    }

    #[test]
    fn approval_needs_the_input_lock_to_pass() {
        let broker = Arc::new(PairingBroker::new());
        let (waiter, id) = open(&broker, Duration::from_secs(60));
        let keys = Some(vec!["K2".to_string()]);
        // Not shown / not loaded yet: too early.
        assert_eq!(broker.answer(id, keys.clone(), Instant::now() + Duration::from_secs(10)), Err("too early".into()));
        let armed = arm(&broker, id);
        assert_eq!(broker.answer(id, keys.clone(), armed - Duration::from_millis(1)), Err("too early".into()));
        assert_eq!(broker.answer(id, keys, armed), Ok(()));
        assert_eq!(waiter.join().unwrap(), PairingAnswer::Approved(vec!["K2".into()]));
    }

    #[test]
    fn deny_is_taken_at_once() {
        let broker = Arc::new(PairingBroker::new());
        let (waiter, id) = open(&broker, Duration::from_secs(60));
        assert_eq!(broker.answer(id, None, Instant::now()), Ok(()));
        assert_eq!(waiter.join().unwrap(), PairingAnswer::Denied);
        assert_eq!(broker.answer(id, None, Instant::now()), Err("no such pairing".into()));
    }

    #[test]
    fn only_offered_keys_each_once() {
        let broker = Arc::new(PairingBroker::new());
        let (waiter, id) = open(&broker, Duration::from_secs(60));
        let armed = arm(&broker, id);
        for bad in [vec![], vec!["K3"], vec!["K1", "K1"], vec!["K1", "k2"]] {
            let keys = bad.iter().map(|s| s.to_string()).collect();
            assert!(broker.answer(id, Some(keys), armed).is_err(), "{bad:?}");
        }
        assert_eq!(broker.answer(id + 1, None, armed), Err("no such pairing".into()));
        assert_eq!(broker.answer(id, Some(vec!["K2".into(), "K1".into()]), armed), Ok(()));
        assert_eq!(waiter.join().unwrap(), PairingAnswer::Approved(vec!["K2".into(), "K1".into()]));
    }

    #[test]
    fn times_out_and_deny_all() {
        let broker = Arc::new(PairingBroker::new());
        let (waiter, _) = open(&broker, Duration::from_millis(100));
        assert_eq!(waiter.join().unwrap(), PairingAnswer::TimedOut);
        assert!(broker.pending().is_empty());
        let (waiter, _) = open(&broker, Duration::from_secs(60));
        broker.deny_all();
        assert_eq!(waiter.join().unwrap(), PairingAnswer::Denied);
    }

    #[test]
    fn labels() {
        assert_eq!(pairing_window_label(7), "pair-7");
        assert_eq!(pairing_id_of_label("pair-7"), Some(7));
        for bad in ["pair-", "pair-x", "pair--1", "prompt-7", "pair-7 ", "pair-99999999999999999999", "pair-1/2"] {
            assert_eq!(pairing_id_of_label(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_view_has_no_secret_fields() {
        let view = PairingView {
            id: 1,
            name: "n".into(),
            executable: "/x".into(),
            items: vec![PairingItem { id: "K".into(), name: "N".into() }],
            deadline: 0.0,
        };
        let json = serde_json::to_value(&view).unwrap();
        let keys: Vec<&String> = json.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["deadline", "executable", "id", "items", "name"]);
    }
}
