//! A yes / no question asked from a worker thread and answered by the UI (the Swift app's modal `NSAlert` during
//! an import: "Use the credentials from … for this connection?" with Use / Ignore). The asking thread blocks until
//! the answer arrives or the question is cancelled (the window closed: the answer is no).

use serde::Serialize;
use std::sync::{Condvar, Mutex, PoisonError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuestionView {
    pub id: u64,
    pub title: String,
    pub message: String,
    /// The affirmative and the negative button.
    pub yes: String,
    pub no: String,
}

#[derive(Default)]
struct State {
    next_id: u64,
    current: Option<QuestionView>,
    answer: Option<(u64, bool)>,
}

#[derive(Default)]
pub struct QuestionBroker {
    state: Mutex<State>,
    signal: Condvar,
    on_change: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl QuestionBroker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_on_change(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.on_change.lock().unwrap_or_else(PoisonError::into_inner) = Some(Box::new(hook));
    }

    fn changed(&self) {
        if let Some(hook) = self.on_change.lock().unwrap_or_else(PoisonError::into_inner).as_ref() {
            hook();
        }
    }

    /// The question being asked.
    pub fn current(&self) -> Option<QuestionView> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).current.clone()
    }

    /// Asks and waits for the answer (one question at a time; a second asker waits for the first).
    pub fn ask(&self, title: String, message: String, yes: String, no: String) -> bool {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        while s.current.is_some() {
            s = self.signal.wait(s).unwrap_or_else(PoisonError::into_inner);
        }
        s.next_id += 1;
        let id = s.next_id;
        s.current = Some(QuestionView { id, title, message, yes, no });
        s.answer = None;
        drop(s);
        self.changed();
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let answer = loop {
            if let Some((answered, value)) = s.answer
                && answered == id
            {
                break value;
            }
            if s.current.as_ref().is_none_or(|q| q.id != id) {
                break false;
            }
            s = self.signal.wait(s).unwrap_or_else(PoisonError::into_inner);
        };
        s.current = None;
        s.answer = None;
        drop(s);
        self.signal.notify_all();
        self.changed();
        answer
    }

    /// The UI's answer to question `id`. False if that question is not being asked.
    pub fn answer(&self, id: u64, value: bool) -> bool {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if s.current.as_ref().is_none_or(|q| q.id != id) {
            return false;
        }
        s.answer = Some((id, value));
        drop(s);
        self.signal.notify_all();
        true
    }

    /// The window closed: the question being asked is answered no.
    pub fn cancel(&self) {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(q) = &s.current {
            s.answer = Some((q.id, false));
        }
        drop(s);
        self.signal.notify_all();
    }
}
