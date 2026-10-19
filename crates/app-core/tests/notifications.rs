//! The MFA prompt answers as the UI sends them (validated, armed after a second, the web sign-in URL from the
//! broker only), the notifications' content and click routing (the Swift `AppModel` notification code), and the
//! prompt bookkeeping that opens and closes the prompt windows.

mod common;

use common::*;
use macvpn_app_core::notify::*;
use macvpn_app_core::prompt::{ARM_DELAY, PromptAnswer, PromptBroker, PromptView, parse_answer};
use macvpn_core::date::Date;
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::mfa::{AuthPrompt, AuthPromptKind, AuthPromptResult, PromptDeadline};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn answers_are_validated() {
    assert_eq!(parse_answer("code", Some("123456")), Ok(PromptAnswer::Code("123456".into())));
    assert_eq!(parse_answer("openUrl", None), Ok(PromptAnswer::OpenUrl));
    assert_eq!(parse_answer("cancel", None), Ok(PromptAnswer::Cancel));
    for (action, response) in [
        ("code", None),
        ("code", Some("")),
        ("code", Some("12\n34")),
        ("code", Some("12\u{0}")),
        ("code", Some("\u{85}")),
        ("code", Some("\u{2028}")),
        ("openUrl", Some("https://evil.example")),
        ("cancel", Some("x")),
        ("Code", Some("1")),
        ("webauth-ack", None),
    ] {
        assert!(parse_answer(action, response).is_err(), "{action} {response:?}");
    }
    let long = "1".repeat(257);
    assert!(parse_answer("code", Some(&long)).is_err());
    assert!(parse_answer("code", Some(&long[..256])).is_ok());
}

fn present(
    broker: &Arc<PromptBroker>,
    kind: AuthPromptKind,
) -> (std::thread::JoinHandle<AuthPromptResult>, PromptView) {
    let b = broker.clone();
    let prompt = AuthPrompt {
        connection_id: "K".into(),
        connection_name: "Office".into(),
        kind,
        deadline: PromptDeadline::with_duration(Date::now(), 60.0),
    };
    let waiting = std::thread::spawn(move || b.present(prompt, Date::now()));
    let start = Instant::now();
    loop {
        if let Some(p) = broker.pending().first() {
            return (waiting, p.clone());
        }
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn no_answer_but_cancel_in_the_first_second() {
    let broker = Arc::new(PromptBroker::new());
    let (waiting, view) = present(&broker, AuthPromptKind::Code { text: "PIN".into(), echo: false, from_server: true });
    let now = Instant::now();
    assert!(broker.mark_shown(view.id, now) && broker.mark_loaded(view.id, now));
    assert_eq!(broker.answer_checked(view.id, PromptAnswer::Code("1".into()), now), Err("too early".into()));
    assert_eq!(
        broker.answer_checked(view.id, PromptAnswer::OpenUrl, now + ARM_DELAY),
        Err("wrong kind of answer".into())
    );
    assert_eq!(broker.answer_checked(view.id, PromptAnswer::Code("4242".into()), now + ARM_DELAY), Ok(None));
    assert_eq!(waiting.join().unwrap(), AuthPromptResult::Code("4242".into()));
    assert!(broker.answer_checked(view.id, PromptAnswer::Cancel, now).is_err(), "closed");

    let (waiting, view) = present(&broker, AuthPromptKind::Code { text: "PIN".into(), echo: true, from_server: false });
    assert_eq!(broker.answer_checked(view.id, PromptAnswer::Cancel, Instant::now()), Ok(None), "cancel at once");
    assert_eq!(waiting.join().unwrap(), AuthPromptResult::Cancelled);
}

#[test]
fn the_input_lock_counts_from_when_the_window_is_visible() {
    let broker = Arc::new(PromptBroker::new());
    let (waiting, view) = present(&broker, AuthPromptKind::Code { text: "PIN".into(), echo: false, from_server: true });
    let code = || PromptAnswer::Code("4242".into());
    // The window appears late (a slow window or page load): a second after `present` it still takes no code.
    assert_eq!(broker.answer_checked(view.id, code(), Instant::now() + ARM_DELAY), Err("too early".into()));
    let shown = Instant::now() + Duration::from_secs(5);
    assert!(broker.mark_shown(view.id, shown));
    assert_eq!(broker.answer_checked(view.id, code(), shown + ARM_DELAY), Err("too early".into()), "page not ready");
    // The page says it is ready later still: the second counts from then.
    let loaded = shown + Duration::from_secs(3);
    assert!(broker.mark_loaded(view.id, loaded));
    assert!(broker.mark_loaded(view.id, loaded + Duration::from_secs(60)), "a second signal is harmless");
    assert!(broker.mark_shown(view.id, loaded + Duration::from_secs(60)));
    assert_eq!(broker.answer_checked(view.id, code(), loaded + ARM_DELAY / 2), Err("too early".into()));
    assert_eq!(broker.answer_checked(view.id, code(), loaded + ARM_DELAY), Ok(None));
    assert_eq!(waiting.join().unwrap(), AuthPromptResult::Code("4242".into()));
    assert!(!broker.mark_loaded(view.id, loaded), "closed");

    // Ready first, ordered on screen later: from the window.
    let (waiting, view) = present(&broker, AuthPromptKind::Code { text: "PIN".into(), echo: false, from_server: true });
    let loaded = Instant::now();
    let shown = loaded + Duration::from_secs(2);
    broker.mark_loaded(view.id, loaded);
    broker.mark_shown(view.id, shown);
    assert_eq!(broker.answer_checked(view.id, code(), loaded + ARM_DELAY), Err("too early".into()));
    assert_eq!(broker.answer_checked(view.id, code(), shown + ARM_DELAY), Ok(None));
    waiting.join().unwrap();
}

#[test]
fn web_sign_in_opens_only_the_brokers_url() {
    let broker = Arc::new(PromptBroker::new());
    let url = "https://sso.example.com/auth?x=1".to_string();
    let (waiting, view) = present(&broker, AuthPromptKind::WebAuth { url: url.clone() });
    assert_eq!((view.kind, view.host.as_deref()), ("webAuth", Some("sso.example.com")));
    assert!(broker.mark_shown(view.id, Instant::now()) && broker.mark_loaded(view.id, Instant::now()));
    let later = Instant::now() + Duration::from_secs(2);
    assert!(broker.answer_checked(view.id, PromptAnswer::Code("1".into()), later).is_err());
    assert_eq!(broker.answer_checked(view.id, PromptAnswer::OpenUrl, later), Ok(Some(url)));
    assert_eq!(waiting.join().unwrap(), AuthPromptResult::OpenedUrl);

    // A URL that does not pass the check again is never opened.
    let (waiting, view) = present(&broker, AuthPromptKind::WebAuth { url: "http://sso.example.com/".into() });
    assert!(broker.mark_shown(view.id, Instant::now()) && broker.mark_loaded(view.id, Instant::now()));
    assert_eq!(broker.answer_checked(view.id, PromptAnswer::OpenUrl, later), Err("invalid URL".into()));
    broker.dismiss("K");
    assert_eq!(waiting.join().unwrap(), AuthPromptResult::Cancelled);
}

#[test]
fn notification_texts_are_generic() {
    with_language(AppLanguage::En, || {
        let n = for_event(&failed("ID", "Office", "AUTH_FAILED for alice at vpn.example.com"), "U1".into());
        assert_eq!((n.title.as_str(), n.body.as_str()), ("Office: connection failed", "Open MacVPN for details"));
        assert_eq!((n.id.as_str(), n.user_info.0, n.user_info.1.as_str()), ("U1", CONNECTION_KEY, "ID"));
        assert!(!n.body.contains("alice"));
        let n = for_event(&dropped("ID", "Office"), "U2".into());
        assert_eq!((n.title.as_str(), n.body.as_str()), ("Office: the connection dropped", "Click to see the log."));
    });
    with_language(AppLanguage::Hu, || {
        let n = for_event(&failed("ID", "Iroda", "x"), "U".into());
        assert_eq!(n.title, "Iroda: sikertelen csatlakozás");
    });
}

fn view(id: u64, connection: &str) -> PromptView {
    PromptView {
        id,
        connection_id: connection.into(),
        connection_name: "Office".into(),
        kind: "code",
        text: Some("PIN".into()),
        echo: false,
        from_server: true,
        url: None,
        host: None,
        deadline: 0.0,
    }
}

#[test]
fn auth_notification_and_prompt_tracking() {
    with_language(AppLanguage::En, || {
        let n = for_prompt(&view(3, "K"));
        assert_eq!(n.id, "auth-K");
        assert_eq!(
            (n.title.as_str(), n.body.as_str()),
            ("Office: authentication needed", "Click to enter the code or to sign in.")
        );
        assert_eq!(n.user_info, (AUTH_PROMPT_KEY, "K".to_string()));
    });
    let mut tracker = PromptTracker::default();
    let changes = tracker.update(&[view(1, "A"), view(2, "B")]);
    assert_eq!(changes.opened.iter().map(|p| p.id).collect::<Vec<_>>(), [1, 2]);
    assert!(changes.closed.is_empty());
    assert_eq!(tracker.update(&[view(1, "A"), view(2, "B")]), PromptChanges::default());
    let changes = tracker.update(&[view(2, "B"), view(3, "A")]);
    assert_eq!(changes.closed, [(1, "A".to_string())]);
    assert_eq!(changes.opened.iter().map(|p| p.id).collect::<Vec<_>>(), [3]);
}

#[test]
fn prompt_window_labels() {
    assert_eq!(prompt_window_label(42), "prompt-42");
    assert_eq!(prompt_id_of_label("prompt-42"), Some(42));
    for bad in ["prompt-", "prompt-x", "prompt--1", "menu", "prompt-1 ", "prompt-99999999999999999999"] {
        assert_eq!(prompt_id_of_label(bad), None, "{bad}");
    }
}

#[test]
fn clicks_route_to_the_prompt_or_the_log() {
    let info = |k: &str, v: &str| BTreeMap::from([(k.to_string(), v.to_string())]);
    let listed = |id: &str| match id {
        "M" => Some(true),
        "S" => Some(false),
        _ => None,
    };
    assert_eq!(route_click(&info(AUTH_PROMPT_KEY, "M"), listed), ClickAction::FocusPrompt("M".into()));
    assert_eq!(
        route_click(&info(CONNECTION_KEY, "M"), listed),
        ClickAction::ShowConnection { select: Some("M".into()), log_tab: true }
    );
    assert_eq!(
        route_click(&info(CONNECTION_KEY, "S"), listed),
        ClickAction::ShowConnection { select: Some("S".into()), log_tab: false }
    );
    assert_eq!(
        route_click(&info(CONNECTION_KEY, "gone"), listed),
        ClickAction::ShowConnection { select: None, log_tab: false }
    );
    assert_eq!(route_click(&BTreeMap::new(), listed), ClickAction::ShowConnection { select: None, log_tab: false });
}
