//! A yes / no question asked from a worker thread and answered by the UI (the Swift app's modal `NSAlert` during
//! an import: "Use the credentials from … for this connection?" with Use / Ignore). The asking thread blocks until
//! the answer arrives or the question is cancelled (the window closed: the answer is no).
//!
//! A question can also offer a choice ([`QuestionBroker::ask_choice`]): the import's "pick a shared credential"
//! shows the options in a pop-up menu, the affirmative button takes the chosen one, the negative one none.

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
    /// A choice question's options (shown as a pop-up menu; the affirmative button takes the chosen one). Empty
    /// for a yes / no question.
    pub options: Vec<String>,
}

#[derive(Default)]
struct State {
    next_id: u64,
    current: Option<QuestionView>,
    /// The answer to question `.0`: `Some(i)` the affirmative button with option `i` (0 for a yes / no
    /// question), `None` the negative one.
    answer: Option<(u64, Option<usize>)>,
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
        self.ask_with(QuestionView { id: 0, title, message, yes, no, options: Vec::new() }).is_some()
    }

    /// Asks to pick one of `options` (`yes`) or none (`no`) and waits: the chosen index, `None` for `no` or a
    /// cancelled question.
    pub fn ask_choice(
        &self,
        title: String,
        message: String,
        options: Vec<String>,
        yes: String,
        no: String,
    ) -> Option<usize> {
        self.ask_with(QuestionView { id: 0, title, message, yes, no, options })
    }

    fn ask_with(&self, mut question: QuestionView) -> Option<usize> {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        while s.current.is_some() {
            s = self.signal.wait(s).unwrap_or_else(PoisonError::into_inner);
        }
        s.next_id += 1;
        let id = s.next_id;
        question.id = id;
        s.current = Some(question);
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
                break None;
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
        self.answer_choice(id, value.then_some(0))
    }

    /// The UI's answer to choice question `id`: an option's index, or `None` (the negative button). False if that
    /// question is not being asked or the index is not one of its options (a yes / no question takes 0).
    pub fn answer_choice(&self, id: u64, choice: Option<usize>) -> bool {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(q) = s.current.as_ref().filter(|q| q.id == id) else { return false };
        if choice.is_some_and(|i| i >= q.options.len().max(1)) {
            return false;
        }
        s.answer = Some((id, choice));
        drop(s);
        self.signal.notify_all();
        true
    }

    /// The window closed: the question being asked is answered no.
    pub fn cancel(&self) {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(q) = &s.current {
            s.answer = Some((q.id, None));
        }
        drop(s);
        self.signal.notify_all();
    }
}
