//! The credential prompt broker: the window's answers are checked (armed after a second from when the window became
//! visible, exactly the asked fields, the value rules), one open prompt per connection, dismiss and expiry cancel,
//! and the view never carries a typed value. Plus the window label helpers and the prompt bookkeeping.

use macvpn_app_core::credential_prompt::{
    ARM_DELAY, CredentialBroker, CredentialPromptView, RawCredentialAnswer, parse_credential_answer,
};
use macvpn_app_core::notify::{
    CREDENTIAL_PROMPT_KEY, ClickAction, PromptTracker, credential_id_of_label, credential_window_label,
    for_credential_prompt, route_click,
};
use macvpn_core::credentials::{CredentialAnswer, CredentialField, CredentialPrompt, CredentialValues};
use macvpn_core::date::Date;
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::mfa::PromptDeadline;
use macvpn_core::models::VPNKind;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use CredentialField::{Password, Psk, Username};

fn prompt(key: &str, fields: Vec<CredentialField>, retry: bool, seconds: f64) -> CredentialPrompt {
    CredentialPrompt {
        connection_id: key.into(),
        connection_name: "Office".into(),
        kind: VPNKind::Openvpn,
        fields,
        username: Some("alice".into()),
        retry,
        deadline: PromptDeadline::with_duration(Date::now(), seconds),
    }
}

fn present(
    broker: &Arc<CredentialBroker>,
    p: CredentialPrompt,
) -> (JoinHandle<CredentialAnswer>, CredentialPromptView) {
    let b = broker.clone();
    let key = p.connection_id.clone();
    let before: Vec<u64> = broker.pending().iter().map(|v| v.id).collect();
    let waiting = std::thread::spawn(move || b.present(p, Date::now()));
    let start = Instant::now();
    loop {
        if let Some(v) = broker.pending().into_iter().find(|v| v.connection_id == key && !before.contains(&v.id)) {
            return (waiting, v);
        }
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn connect(pairs: &[(&str, &str)], save: bool) -> RawCredentialAnswer {
    parse_credential_answer("connect", values(pairs), save).unwrap()
}

fn armed(broker: &CredentialBroker, id: u64) -> Instant {
    let now = Instant::now();
    assert!(broker.mark_shown(id, now) && broker.mark_loaded(id, now));
    now + ARM_DELAY
}

fn provided(answer: CredentialAnswer) -> (CredentialValues, bool) {
    match answer {
        CredentialAnswer::Provided { values, save } => (values, save),
        CredentialAnswer::Cancelled => panic!("cancelled"),
    }
}

fn is_cancelled(answer: &CredentialAnswer) -> bool {
    matches!(answer, CredentialAnswer::Cancelled)
}

#[test]
fn answer_reaches_the_caller_and_the_view_has_no_value() {
    let broker = Arc::new(CredentialBroker::new());
    let (waiting, view) = present(&broker, prompt("K", vec![Username, Password], false, 60.0));
    assert_eq!(view.fields, ["username", "password"]);
    assert_eq!(view.username.as_deref(), Some("alice"));
    assert_eq!(view.message, None);
    assert_eq!(broker.prompt_for_connection("K"), Some(view.id));
    let at = armed(&broker, view.id);
    broker.answer_checked(view.id, connect(&[("username", "bob"), ("password", "typed-secret-42")], true), at).unwrap();
    let json = serde_json::to_string(&broker.pending()).unwrap();
    assert!(!json.contains("typed-secret-42"), "{json}");
    let (values, save) = provided(waiting.join().unwrap());
    assert!(save);
    assert_eq!(values.get(Username), Some("bob"));
    assert_eq!(values.get(Password), Some("typed-secret-42"));
    assert!(broker.pending().is_empty());
    assert_eq!(broker.prompt_for_connection("K"), None);
    let json = serde_json::to_string(&view).unwrap();
    assert!(json.contains("\"connectionName\"") && !json.contains("typed-secret-42"));
}

#[test]
fn the_retry_prompt_carries_the_message() {
    with_language(AppLanguage::En, || {
        let broker = Arc::new(CredentialBroker::new());
        let (waiting, view) = present(&broker, prompt("K", vec![Username, Password], true, 60.0));
        assert_eq!(view.message.as_deref(), Some("Sign-in failed — check the username and password"));
        broker.dismiss("K");
        assert!(is_cancelled(&waiting.join().unwrap()));
    });
}

#[test]
fn only_cancel_in_the_first_second() {
    let broker = Arc::new(CredentialBroker::new());
    let (waiting, view) = present(&broker, prompt("K", vec![Password], false, 60.0));
    let now = Instant::now();
    assert!(broker.mark_shown(view.id, now) && broker.mark_loaded(view.id, now));
    assert_eq!(broker.answer_checked(view.id, connect(&[("password", "x")], true), now), Err("too early".into()));
    assert_eq!(broker.answer_checked(view.id, RawCredentialAnswer::Cancel, now), Ok(()));
    assert!(is_cancelled(&waiting.join().unwrap()));
    assert!(broker.answer_checked(view.id, RawCredentialAnswer::Cancel, now).is_err(), "closed");
}

#[test]
fn the_lock_counts_from_shown_and_loaded() {
    let broker = Arc::new(CredentialBroker::new());
    let (waiting, view) = present(&broker, prompt("K", vec![Password], false, 60.0));
    let later = Instant::now() + Duration::from_secs(10);
    assert_eq!(
        broker.answer_checked(view.id, connect(&[("password", "x")], false), later),
        Err("too early".into()),
        "neither"
    );
    assert!(broker.mark_shown(view.id, Instant::now()));
    assert_eq!(
        broker.answer_checked(view.id, connect(&[("password", "x")], false), later),
        Err("too early".into()),
        "shown, not loaded"
    );
    broker.dismiss("K");
    waiting.join().unwrap();

    let (waiting, view) = present(&broker, prompt("K", vec![Password], false, 60.0));
    assert!(broker.mark_loaded(view.id, Instant::now()));
    assert_eq!(
        broker.answer_checked(view.id, connect(&[("password", "x")], false), later),
        Err("too early".into()),
        "loaded, not shown"
    );
    let shown = Instant::now() + Duration::from_secs(3);
    broker.mark_shown(view.id, shown);
    assert!(broker.answer_checked(view.id, connect(&[("password", "x")], false), shown + ARM_DELAY / 2).is_err());
    assert_eq!(broker.answer_checked(view.id, connect(&[("password", "x")], false), shown + ARM_DELAY), Ok(()));
    let (values, save) = provided(waiting.join().unwrap());
    assert!(!save);
    assert_eq!(values.get(Password), Some("x"));
}

#[test]
fn the_answer_must_name_exactly_the_asked_fields() {
    let broker = Arc::new(CredentialBroker::new());
    let (waiting, view) = present(&broker, prompt("K", vec![Username, Password], false, 60.0));
    let at = armed(&broker, view.id);
    for bad in [
        vec![("username", "bob")],
        vec![("username", "bob"), ("password", "pw"), ("psk", "k")],
        vec![("username", "bob"), ("password", "")],
        vec![("username", "bob"), ("password", "a\nb")],
    ] {
        assert!(broker.answer_checked(view.id, connect(&bad, true), at).is_err(), "{bad:?}");
    }
    assert!(broker.prompt_for_connection("K").is_some(), "still open");
    broker.answer_checked(view.id, connect(&[("username", "bob"), ("password", "pw")], true), at).unwrap();
    provided(waiting.join().unwrap());
}

#[test]
fn parse_rejects_unknown_keys_and_actions() {
    assert!(parse_credential_answer("connect", values(&[("code", "1")]), true).is_err());
    assert!(parse_credential_answer("connect", values(&[("Password", "1")]), true).is_err());
    assert!(parse_credential_answer("cancel", values(&[("password", "1")]), false).is_err());
    assert!(parse_credential_answer("submit", values(&[]), false).is_err());
    assert!(matches!(parse_credential_answer("cancel", values(&[]), false), Ok(RawCredentialAnswer::Cancel)));
    match parse_credential_answer("connect", values(&[("psk", "k"), ("keyPassword", "kp")]), false).unwrap() {
        RawCredentialAnswer::Connect { values, save } => {
            assert!(!save);
            assert_eq!(values.fields(), [Psk, CredentialField::KeyPassword]);
        }
        RawCredentialAnswer::Cancel => panic!(),
    }
}

#[test]
fn a_second_prompt_for_the_connection_cancels_the_first() {
    let broker = Arc::new(CredentialBroker::new());
    let (first, view1) = present(&broker, prompt("K", vec![Password], false, 60.0));
    let (second, view2) = present(&broker, prompt("K", vec![Password], false, 60.0));
    assert_ne!(view1.id, view2.id);
    assert!(is_cancelled(&first.join().unwrap()));
    assert_eq!(broker.pending().len(), 1);
    let at = armed(&broker, view2.id);
    assert!(broker.answer_checked(view1.id, RawCredentialAnswer::Cancel, at).is_err(), "the old one is gone");
    broker.answer_checked(view2.id, connect(&[("password", "pw")], true), at).unwrap();
    provided(second.join().unwrap());
}

#[test]
fn dismiss_and_deadline_cancel() {
    let broker = Arc::new(CredentialBroker::new());
    let (waiting, _) = present(&broker, prompt("K", vec![Password], false, 60.0));
    broker.dismiss("K");
    assert!(is_cancelled(&waiting.join().unwrap()));

    let b = broker.clone();
    let start = Instant::now();
    let answer = std::thread::spawn(move || b.present(prompt("K", vec![Password], false, 0.2), Date::now()));
    assert!(is_cancelled(&answer.join().unwrap()));
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(broker.pending().is_empty());
}

#[test]
fn on_change_fires_when_a_prompt_opens_and_closes() {
    let broker = Arc::new(CredentialBroker::new());
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c = count.clone();
    broker.set_on_change(move || {
        c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    });
    let (waiting, _) = present(&broker, prompt("K", vec![Password], false, 60.0));
    broker.dismiss("K");
    waiting.join().unwrap();
    assert!(count.load(std::sync::atomic::Ordering::SeqCst) >= 2);
}

#[test]
fn values_are_zeroizing() {
    // The typed strings move into `Zeroizing` at once (a type check: this only compiles with `Zeroizing`).
    let v = CredentialValues { password: Some(Zeroizing::new("x".into())), ..CredentialValues::default() };
    assert_eq!(v.get(Password), Some("x"));
}

#[test]
fn credential_window_labels() {
    assert_eq!(credential_window_label(12), "cred-12");
    assert_eq!(credential_id_of_label("cred-12"), Some(12));
    for bad in ["cred-", "cred-x", "prompt-1", "cred--1", "cred-1 ", "cred-99999999999999999999", "pair-1"] {
        assert_eq!(credential_id_of_label(bad), None, "{bad}");
    }
}

fn view(id: u64, connection: &str) -> CredentialPromptView {
    CredentialPromptView {
        id,
        connection_id: connection.into(),
        connection_name: "Office".into(),
        fields: vec!["password"],
        username: None,
        message: None,
        deadline: 0.0,
    }
}

#[test]
fn credential_notification_and_tracking() {
    with_language(AppLanguage::En, || {
        let n = for_credential_prompt(&view(3, "K"));
        assert_eq!(n.id, "cred-K");
        assert_eq!(
            (n.title.as_str(), n.body.as_str()),
            ("Office: credentials needed", "Click to enter the user name or password.")
        );
        assert_eq!(n.user_info, (CREDENTIAL_PROMPT_KEY, "K".to_string()));
    });
    let info = BTreeMap::from([(CREDENTIAL_PROMPT_KEY.to_string(), "K".to_string())]);
    assert_eq!(route_click(&info, |_| None), ClickAction::FocusCredentials("K".into()));
    let mut tracker: PromptTracker<CredentialPromptView> = PromptTracker::default();
    let changes = tracker.update(&[view(1, "A")]);
    assert_eq!(changes.opened.len(), 1);
    let changes = tracker.update(&[]);
    assert_eq!(changes.closed, [(1, "A".to_string())]);
}
