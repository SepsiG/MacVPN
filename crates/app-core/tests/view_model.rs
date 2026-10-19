//! The view model (the Swift `MenuContentView` / `MenuRow` / `menuBarSymbol` decisions), the prompt broker
//! (the non-UI half of `AuthPromptPresenter`), and the l10n keys the manager uses.

mod common;

use common::*;
use macvpn_app_core::deps::SystemService;
use macvpn_app_core::prompt::PromptBroker;
use macvpn_app_core::{ManagerSnapshot, RowState, TrayIcon, ViewModel};
use macvpn_core::date::Date;
use macvpn_core::l10n::{self, AppLanguage};
use macvpn_core::mfa::{AuthPrompt, AuthPromptKind, AuthPromptResult, PromptDeadline};
use macvpn_core::models::{AuthWait, AuthWaitKind, Connection, ConnectionState, VPNKind, uuid_string};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn snapshot(states: &[ConnectionState], status_error: Option<&str>) -> ManagerSnapshot {
    ManagerSnapshot {
        items: Vec::new(),
        status_error: status_error.map(str::to_string),
        has_active: states.iter().any(ConnectionState::is_active),
        has_failure: states.iter().any(|s| matches!(s, ConnectionState::Failed(_))),
        awaiting_auth: states.iter().any(|s| matches!(s, ConnectionState::AwaitingAuth(_))),
    }
}

#[test]
fn tray_icon_priority_auth_then_failure_then_active() {
    let wait = ConnectionState::AwaitingAuth(AuthWait { kind: AuthWaitKind::Code, deadline: None });
    let failed = ConnectionState::Failed("x".into());
    let up = ConnectionState::Connected { ip: None, since: None };
    assert_eq!(TrayIcon::from_snapshot(&snapshot(&[], None)), TrayIcon::Idle);
    assert_eq!(TrayIcon::from_snapshot(&snapshot(std::slice::from_ref(&up), None)), TrayIcon::Active);
    assert_eq!(TrayIcon::from_snapshot(&snapshot(&[ConnectionState::Connecting], None)), TrayIcon::Active);
    assert_eq!(TrayIcon::from_snapshot(&snapshot(std::slice::from_ref(&up), Some("e"))), TrayIcon::Failure);
    assert_eq!(TrayIcon::from_snapshot(&snapshot(&[up.clone(), failed.clone()], None)), TrayIcon::Failure);
    assert_eq!(TrayIcon::from_snapshot(&snapshot(&[failed, wait], Some("e"))), TrayIcon::Auth);
}

#[test]
fn view_model_rows_follow_the_order_and_availability() {
    let f = Fixture::new(AppLanguage::En);
    let wg = Connection::new("Home WG", VPNKind::Wireguard);
    let ovpn = Connection::new("Office", VPNKind::Openvpn);
    f.store.save(&wg, Some("x")).unwrap();
    f.store.save(&ovpn, Some("remote x\n")).unwrap();
    let svc = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
    f.root.respond(
        "status",
        Ok(&format!(
            r#"[{{"id":"{}","kind":"openvpn","state":"connected","iface":"utun4","ip":"10.8.0.2","since":1800000000}}]"#,
            uuid_string(&ovpn.id)
        )),
    );
    f.native.set_list(Ok(vec![SystemService::new(svc, "Corp", "IKEv2", "Disconnecting")]));
    let m = f.manager();
    m.refresh();
    m.pin(svc);
    let vm = ViewModel::build(&m.snapshot(), "en", |k| k != VPNKind::Wireguard, Vec::new(), false);
    assert_eq!(vm.rows.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), ["Corp", "Home WG", "Office"]);
    let corp = &vm.rows[0];
    assert!(corp.pinned && !corp.managed && corp.available);
    assert_eq!(corp.type_label, "IKEv2");
    assert_eq!(corp.state, RowState::Disconnecting);
    assert!(corp.switch_on && !corp.switch_enabled, "no toggling while disconnecting");
    let home = &vm.rows[1];
    assert!(!home.available && !home.switch_enabled && !home.switch_on);
    assert_eq!(home.type_label, "WireGuard");
    let office = &vm.rows[2];
    assert_eq!(office.state, RowState::Connected { ip: Some("10.8.0.2".into()), since: Some(1_800_000_000.0) });
    assert!(office.switch_on && office.switch_enabled);
    assert_eq!(vm.tray, TrayIcon::Active);
    assert!(vm.has_active);

    let json = serde_json::to_value(&vm).unwrap();
    assert_eq!(json["rows"][2]["state"], "connected");
    assert_eq!(json["rows"][2]["ip"], "10.8.0.2");
    assert_eq!(json["rows"][2]["switchOn"], true);
    assert_eq!(json["rows"][0]["typeLabel"], "IKEv2");
    assert_eq!(json["tray"], "active");
    assert_eq!(json["statusError"], serde_json::Value::Null);
    assert_eq!(json["update"]["enabled"], false);
    assert_eq!(json["loginItem"], serde_json::Value::Null);
    assert_eq!(json["logRequest"], serde_json::Value::Null);
}

#[test]
fn row_state_serialization() {
    let json = |s: &ConnectionState| serde_json::to_value(RowState::from(s)).unwrap();
    assert_eq!(json(&ConnectionState::Failed("nope".into())), serde_json::json!({"state": "failed", "reason": "nope"}));
    assert_eq!(
        json(&ConnectionState::AwaitingAuth(AuthWait {
            kind: AuthWaitKind::Web,
            deadline: Some(Date::from_time_interval_since_1970(10.0))
        })),
        serde_json::json!({"state": "awaitingAuth", "wait": "web", "deadline": 10.0})
    );
    assert_eq!(json(&ConnectionState::Disconnected), serde_json::json!({"state": "disconnected"}));
}

#[test]
fn events_serialize_for_the_ui() {
    assert_eq!(
        serde_json::to_value(failed("A", "B", "C")).unwrap(),
        serde_json::json!({"type": "failed", "connectionId": "A", "name": "B", "reason": "C"})
    );
    assert_eq!(
        serde_json::to_value(dropped("A", "B")).unwrap(),
        serde_json::json!({"type": "dropped", "connectionId": "A", "name": "B"})
    );
}

// MARK: - Prompt broker

fn prompt(key: &str, seconds: f64) -> AuthPrompt {
    AuthPrompt {
        connection_id: key.into(),
        connection_name: "Office".into(),
        kind: AuthPromptKind::Code { text: "PIN".into(), echo: false, from_server: true },
        deadline: PromptDeadline::with_duration(Date::now(), seconds),
    }
}

fn wait_for_prompt(broker: &PromptBroker) -> u64 {
    let start = Instant::now();
    loop {
        if let Some(p) = broker.pending().first() {
            return p.id;
        }
        assert!(start.elapsed() < Duration::from_secs(5), "no prompt");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn broker_answer_reaches_the_waiting_handler() {
    let broker = Arc::new(PromptBroker::new());
    let b = broker.clone();
    let waiting = std::thread::spawn(move || b.present(prompt("K", 60.0), Date::now()));
    let id = wait_for_prompt(&broker);
    let view = broker.pending()[0].clone();
    assert_eq!((view.kind, view.text.as_deref(), view.from_server), ("code", Some("PIN"), true));
    assert!(broker.answer(id, AuthPromptResult::Code("4242".into())));
    assert_eq!(waiting.join().unwrap(), AuthPromptResult::Code("4242".into()));
    assert!(broker.pending().is_empty());
    assert!(!broker.answer(id, AuthPromptResult::Cancelled), "already closed");
}

#[test]
fn broker_dismiss_cancels_and_deadline_times_out() {
    let broker = Arc::new(PromptBroker::new());
    let b = broker.clone();
    let waiting = std::thread::spawn(move || b.present(prompt("K", 60.0), Date::now()));
    wait_for_prompt(&broker);
    broker.dismiss("K");
    assert_eq!(waiting.join().unwrap(), AuthPromptResult::Cancelled);
    let started = Instant::now();
    assert_eq!(broker.present(prompt("K", 0.05), Date::now()), AuthPromptResult::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn broker_keeps_one_prompt_per_connection() {
    let broker = Arc::new(PromptBroker::new());
    let b = broker.clone();
    let first = std::thread::spawn(move || b.present(prompt("K", 60.0), Date::now()));
    let first_id = wait_for_prompt(&broker);
    let b = broker.clone();
    let second = std::thread::spawn(move || b.present(prompt("K", 60.0), Date::now()));
    assert_eq!(first.join().unwrap(), AuthPromptResult::Cancelled, "replaced");
    let start = Instant::now();
    while broker.pending().first().map(|p| p.id) == Some(first_id) || broker.pending().is_empty() {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(5));
    }
    let id = broker.pending()[0].id;
    broker.answer(id, AuthPromptResult::OpenedUrl);
    assert_eq!(second.join().unwrap(), AuthPromptResult::OpenedUrl);
}

#[test]
fn manager_prompt_through_broker_and_dismissed_on_disconnect() {
    let f = Fixture::new(AppLanguage::En);
    let mut c = Connection::new("S", VPNKind::Strongswan);
    c.otp.enabled = true;
    f.store.save(&c, Some("x")).unwrap();
    f.root.respond("status", Ok("[]"));
    let m = f.manager();
    let broker = Arc::new(PromptBroker::new());
    {
        let b = broker.clone();
        m.set_prompt_handler(move |p| b.present(p, Date::now()));
        let b = broker.clone();
        m.set_dismiss_prompt(move |key| b.dismiss(key));
    }
    let connecting = spawn(AppLanguage::En, {
        let (m, c) = (m.clone(), c.clone());
        move || m.connect(&c, false)
    });
    wait_for_prompt(&broker);
    assert!(matches!(m.state(&uuid_string(&c.id)), ConnectionState::AwaitingAuth(_)));
    m.disconnect(&c);
    connecting.join().unwrap();
    assert!(broker.pending().is_empty());
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Disconnected);
    assert!(!f.root.lines().iter().any(|l| l.starts_with("up ")));
}

// MARK: - L10n

/// Every text the manager translates is in the table (a missing key would silently stay English).
#[test]
fn manager_texts_are_in_the_table() {
    let source = include_str!("../src/manager.rs");
    let mut keys = Vec::new();
    let mut rest = source;
    while let Some(start) = rest.find("l10n::tr(") {
        rest = &rest[start + "l10n::tr(".len()..];
        let open = rest.find('"').unwrap();
        let after = &rest[open + 1..];
        let close = after.find('"').unwrap();
        keys.push(after[..close].to_string());
        rest = &after[close..];
    }
    assert!(keys.len() >= 12, "{keys:?}");
    for key in keys {
        assert!(l10n::hungarian(&key).is_some(), "missing from strings.json: {key}");
    }
}
