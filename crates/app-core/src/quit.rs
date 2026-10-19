//! The quit guard: every way of quitting goes through the same questions (the Swift `QuitPolicy`,
//! `AppDelegate.applicationShouldTerminate`, `AppModel.confirmQuit` / `confirmUnsaved` / `terminateConfirmed`).
//!
//! First "Unsaved Changes" (asked in the Connections window), then "There are active VPN connections" (asked in
//! the menu, and for an update in the Update window too). The questions are answered asynchronously by the UI;
//! the guard keeps the one flow in progress and tells the app what to do next ([`QuitAction`]). An update waits
//! for the answer on its worker thread ([`QuitGuard::wait`]).
//!
//! Origins:
//! - `Menu`: the menu's Quit and Cmd+Q (the app's own menu item);
//! - `System`: `applicationShouldTerminate` (logout, restart, shutdown, a quit Apple Event): the system waits for
//!   the answer (`NSTerminateLater`), the app replies once the flow ends;
//! - `Update`: "Download and Install" before the helper is launched; on success the update itself quits;
//! - `Uninstall`: after the uninstaller's final message; only unsaved changes are asked about (the root layer is
//!   gone, there is nothing to disconnect).

use macvpn_core::l10n::{self, Arg};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum QuitOrigin {
    Menu,
    System,
    Update,
    Uninstall,
}

/// The question being asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum QuitStep {
    /// "Unsaved Changes" in the Connections window (its pending action is `quit`).
    Unsaved,
    /// "There are active VPN connections".
    ActiveConnections,
}

/// The note under "There are active VPN connections" naming the apps that hold connections through the control
/// API (`ControlServer::holder_names`); `None` when no app does.
pub fn lease_holders_note(names: &[String]) -> Option<String> {
    if names.is_empty() {
        return None;
    }
    Some(l10n::tr(
        "Used by other apps through MacVPN: %@. Quitting ends their sessions.",
        &[Arg::Str(&names.join(", "))],
    ))
}

/// What the app does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuitAction {
    /// Show this question.
    Ask(QuitStep),
    /// A flow is already asking this question: show it again (the request joined it).
    Joined(QuitStep),
    /// The flow ended. `proceed`: quit (for an update: launch the helper, which then quits); otherwise nothing
    /// happens (a waiting system request is answered no).
    Finished { proceed: bool, origin: QuitOrigin },
}

/// The question as the UI shows it (part of the view model).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuitQuestion {
    pub origin: QuitOrigin,
    pub step: QuitStep,
}

#[derive(Debug, Clone, Copy)]
struct Flow {
    origin: QuitOrigin,
    step: QuitStep,
    ticket: u64,
    /// A menu or system quit request joined this flow (its answer is theirs too).
    joined: bool,
}

/// How a finished flow ended ([`QuitGuard::wait_end`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowEnd {
    /// Quit (for an update: launch the helper).
    pub proceed: bool,
    /// A menu or system quit request joined the flow: its user wanted to quit too.
    pub joined: bool,
}

#[derive(Default)]
struct Inner {
    flow: Option<Flow>,
    next_ticket: u64,
    /// The outcomes of finished flows by ticket (the last few, for [`QuitGuard::wait`]).
    outcomes: Vec<(u64, FlowEnd)>,
}

type Hook = Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
pub struct QuitGuard {
    inner: Mutex<Inner>,
    finished: Condvar,
    /// The quit was confirmed (the menu's Quit after the questions, an update's helper launched, the uninstaller):
    /// no further question.
    confirmed: AtomicBool,
    /// `applicationShouldTerminate` returned "later": the system waits for the reply.
    system_waiting: AtomicBool,
    on_change: Mutex<Option<Hook>>,
}

impl QuitGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_on_change(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.on_change.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(hook));
    }

    fn changed(&self) {
        let hook = self.on_change.lock().unwrap_or_else(PoisonError::into_inner).clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn is_confirmed(&self) -> bool {
        self.confirmed.load(Ordering::SeqCst)
    }

    /// The app is quitting now (after the questions, or without any).
    pub fn confirm(&self) {
        self.confirmed.store(true, Ordering::SeqCst);
    }

    /// The question being asked, if any.
    pub fn question(&self) -> Option<QuitQuestion> {
        self.lock().flow.map(|f| QuitQuestion { origin: f.origin, step: f.step })
    }

    /// The system's terminate request waits for a reply (`NSTerminateLater` was returned).
    pub fn set_system_waiting(&self) {
        self.system_waiting.store(true, Ordering::SeqCst);
    }

    /// The system waits for a reply.
    pub fn is_system_waiting(&self) -> bool {
        self.system_waiting.load(Ordering::SeqCst)
    }

    /// Takes the pending system reply: true if the system waits for one (the app replies instead of exiting).
    pub fn take_system_waiting(&self) -> bool {
        self.system_waiting.swap(false, Ordering::SeqCst)
    }

    /// A quit request. `unsaved` / `active`: whether there are unsaved changes / active connections now.
    /// Returns the action and the flow's ticket (for [`Self::wait`]).
    pub fn request(&self, origin: QuitOrigin, unsaved: bool, active: bool) -> (QuitAction, u64) {
        let (action, ticket) = {
            let mut inner = self.lock();
            inner.next_ticket += 1;
            let ticket = inner.next_ticket;
            if self.is_confirmed() {
                return (QuitAction::Finished { proceed: true, origin }, ticket);
            }
            if let Some(flow) = inner.flow.as_mut() {
                return match origin {
                    // The question on screen answers this request too.
                    QuitOrigin::Menu | QuitOrigin::System => {
                        flow.joined = true;
                        (QuitAction::Joined(flow.step), flow.ticket)
                    }
                    // An update or the uninstaller does not wait behind another quit: not now.
                    QuitOrigin::Update | QuitOrigin::Uninstall => {
                        (QuitAction::Finished { proceed: false, origin }, ticket)
                    }
                };
            }
            let ask_active = active && origin != QuitOrigin::Uninstall;
            let step = if unsaved {
                Some(QuitStep::Unsaved)
            } else if ask_active {
                Some(QuitStep::ActiveConnections)
            } else {
                None
            };
            match step {
                Some(step) => {
                    inner.flow = Some(Flow { origin, step, ticket, joined: false });
                    (QuitAction::Ask(step), ticket)
                }
                None => {
                    Self::record(&mut inner, ticket, FlowEnd { proceed: true, joined: false });
                    (QuitAction::Finished { proceed: true, origin }, ticket)
                }
            }
        };
        self.changed();
        (action, ticket)
    }

    /// The answer to "Unsaved Changes" (saved or discarded: `proceed`; cancelled or the save failed: not).
    /// `active`: whether connections are active now.
    pub fn unsaved_answered(&self, proceed: bool, active: bool) -> Option<QuitAction> {
        let action = {
            let mut inner = self.lock();
            let flow = inner.flow.filter(|f| f.step == QuitStep::Unsaved)?;
            if proceed && active && flow.origin != QuitOrigin::Uninstall {
                inner.flow = Some(Flow { step: QuitStep::ActiveConnections, ..flow });
                QuitAction::Ask(QuitStep::ActiveConnections)
            } else {
                Self::finish(&mut inner, flow, proceed)
            }
        };
        self.finished.notify_all();
        self.changed();
        Some(action)
    }

    /// The answer to "There are active VPN connections", after it was carried out (`proceed`: disconnected or
    /// kept running; not: cancelled).
    pub fn active_answered(&self, proceed: bool) -> Option<QuitAction> {
        let action = {
            let mut inner = self.lock();
            let flow = inner.flow.filter(|f| f.step == QuitStep::ActiveConnections)?;
            Self::finish(&mut inner, flow, proceed)
        };
        self.finished.notify_all();
        self.changed();
        Some(action)
    }

    /// Ends the flow in progress as cancelled (its window closed).
    pub fn cancel(&self, step: QuitStep) -> Option<QuitAction> {
        match step {
            QuitStep::Unsaved => self.unsaved_answered(false, false),
            QuitStep::ActiveConnections => self.active_answered(false),
        }
    }

    /// Ends the flow of `origin` in progress as cancelled, whatever its step (its window closed).
    pub fn cancel_origin(&self, origin: QuitOrigin) -> Option<QuitAction> {
        self.cancel_where(|f| f.origin == origin)
    }

    /// Ends the flow of `ticket` as cancelled, if it is still in progress.
    pub fn cancel_ticket(&self, ticket: u64) -> Option<QuitAction> {
        self.cancel_where(|f| f.ticket == ticket)
    }

    fn cancel_where(&self, matches: impl Fn(&Flow) -> bool) -> Option<QuitAction> {
        let action = {
            let mut inner = self.lock();
            let flow = inner.flow.filter(|f| matches(f))?;
            Self::finish(&mut inner, flow, false)
        };
        self.finished.notify_all();
        self.changed();
        Some(action)
    }

    fn finish(inner: &mut Inner, flow: Flow, proceed: bool) -> QuitAction {
        inner.flow = None;
        Self::record(inner, flow.ticket, FlowEnd { proceed, joined: flow.joined });
        QuitAction::Finished { proceed, origin: flow.origin }
    }

    /// Only the recent outcomes are kept (a waiter reads its own right after it is pushed).
    fn record(inner: &mut Inner, ticket: u64, end: FlowEnd) {
        inner.outcomes.push((ticket, end));
        let excess = inner.outcomes.len().saturating_sub(16);
        inner.outcomes.drain(..excess);
    }

    /// Blocks until the flow of `ticket` ended; its outcome (true: quit). An unknown ticket is false.
    pub fn wait(&self, ticket: u64) -> bool {
        self.wait_end(ticket).proceed
    }

    /// Blocks until the flow of `ticket` ended; how it ended. An unknown ticket did not proceed.
    pub fn wait_end(&self, ticket: u64) -> FlowEnd {
        let mut inner = self.lock();
        loop {
            if let Some(&(_, end)) = inner.outcomes.iter().find(|(t, _)| *t == ticket) {
                return end;
            }
            if inner.flow.is_none_or(|f| f.ticket != ticket) {
                return FlowEnd { proceed: false, joined: false };
            }
            inner = self.finished.wait(inner).unwrap_or_else(PoisonError::into_inner);
        }
    }

    #[cfg(test)]
    fn outcome_count(&self) -> usize {
        self.lock().outcomes.len()
    }
}

/// What the app does once an update's install ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterInstall {
    /// Quit now, without asking again.
    Quit,
    /// Nothing: the app goes on (a quit question still pending is answered by its user).
    Stay,
}

/// The quit questions of one update install, asked on its worker thread just before the helper is launched
/// (the Swift `UpdateController.install` + `confirmQuit`), and what the app does once the install ended.
pub struct UpdateQuit {
    guard: Arc<QuitGuard>,
    ended: Mutex<Option<FlowEnd>>,
}

impl UpdateQuit {
    pub fn new(guard: Arc<QuitGuard>) -> Self {
        UpdateQuit { guard, ended: Mutex::new(None) }
    }

    /// The update's `confirm_quit`: true to launch the helper. `unsaved` / `active`: as for
    /// [`QuitGuard::request`]. `show` shows a question in a window that can answer it (false: no window could be
    /// shown, so the question is cancelled at once: the worker never waits on a question nobody sees); `handle`
    /// carries out a flow ended here (a system request that joined it gets its reply).
    pub fn confirm(
        &self,
        unsaved: bool,
        active: bool,
        show: impl FnOnce(QuitStep) -> bool,
        handle: impl FnOnce(QuitAction),
    ) -> bool {
        let (action, ticket) = self.guard.request(QuitOrigin::Update, unsaved, active);
        let end = match action {
            QuitAction::Finished { proceed, .. } => FlowEnd { proceed, joined: false },
            QuitAction::Ask(step) => {
                if !show(step)
                    && let Some(action) = self.guard.cancel_ticket(ticket)
                {
                    handle(action);
                }
                self.guard.wait_end(ticket)
            }
            // An update does not join another flow (`request` answers it `Finished`).
            QuitAction::Joined(_) => FlowEnd { proceed: false, joined: false },
        };
        *self.ended.lock().unwrap_or_else(PoisonError::into_inner) = Some(end);
        end.proceed
    }

    /// The install ended with `outcome`. The helper runs: quit. Otherwise only if the update's own questions
    /// ended with "quit" and a menu or system quit had joined them (the helper could not be launched, but that
    /// user still asked to quit). A failure before the questions (download, checksum, signature, mount, the
    /// app's check) never quits: a quit request still pending is decided by its own question.
    pub fn after_install(&self, outcome: crate::updates::InstallOutcome) -> AfterInstall {
        use crate::updates::InstallOutcome;
        let ended = *self.ended.lock().unwrap_or_else(PoisonError::into_inner);
        match outcome {
            InstallOutcome::HelperLaunched => AfterInstall::Quit,
            _ if ended == Some(FlowEnd { proceed: true, joined: true }) => AfterInstall::Quit,
            _ => AfterInstall::Stay,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_holders_are_named_in_the_quit_note() {
        assert_eq!(lease_holders_note(&[]), None);
        let note = l10n::with_language(l10n::AppLanguage::En, || {
            lease_holders_note(&["Remote Desktop".into(), "Backup".into()])
        })
        .unwrap();
        assert!(note.contains("Remote Desktop, Backup"), "{note}");
        let hu = l10n::with_language(l10n::AppLanguage::Hu, || lease_holders_note(&["Remote Desktop".into()])).unwrap();
        assert!(hu.contains("Remote Desktop"), "{hu}");
        assert_ne!(hu, note);
    }

    #[test]
    fn outcomes_stay_bounded_on_every_path() {
        let guard = QuitGuard::new();
        for _ in 0..100 {
            guard.request(QuitOrigin::Menu, false, true);
            guard.active_answered(false);
        }
        assert!(guard.outcome_count() <= 16, "{}", guard.outcome_count());
        // Nothing to ask: finished at once.
        for _ in 0..100 {
            guard.request(QuitOrigin::Menu, false, false);
        }
        assert!(guard.outcome_count() <= 16, "{}", guard.outcome_count());
    }
}
