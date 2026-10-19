//! Port of `MFAConnectionTests.swift`: the code asked before connecting ("code after the password", static
//! challenge), the bridge's state file watched during `up` (dynamic challenge, web authentication), cancel and
//! expiry. (`testRespondArguments` tests the `MvpnClient` command line: ported in `macvpn-platform-mac`'s
//! `respond_sends_code_on_stdin_only`.)

mod common;

use common::*;
use macvpn_app_core::deps::{AuthStateReader, SecretField, SecretReader, SystemService};
use macvpn_app_core::{ConnectionManager, Dependencies};
use macvpn_core::date::Date;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::mfa::{
    AuthPrompt, AuthPromptKind, AuthPromptResult, AuthUIMethod, AuthUIState, AuthUIStateKind, MFAError,
};
use macvpn_core::models::{
    AuthWaitKind, Connection, ConnectionState, NativeSettings, OTPSeparator, OTPSetting, VPNKind, uuid_string,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uuid::Uuid;

const EN: AppLanguage = AppLanguage::En;

type ReadFn = Box<dyn Fn(&Uuid) -> Option<AuthUIState> + Send + Sync>;

struct FnReader(ReadFn);

impl AuthStateReader for FnReader {
    fn read(&self, id: &Uuid) -> Option<AuthUIState> {
        (self.0)(id)
    }
}

fn manager(f: &Fixture) -> Arc<ConnectionManager> {
    manager_with_reader(f, |_| None)
}

fn manager_with_reader(
    f: &Fixture,
    reader: impl Fn(&Uuid) -> Option<AuthUIState> + Send + Sync + 'static,
) -> Arc<ConnectionManager> {
    let mut deps: Dependencies = f.deps();
    deps.auth_state = Arc::new(FnReader(Box::new(reader)));
    let m = f.manager_with(deps);
    m.set_auth_poll_interval(Duration::from_millis(50));
    m
}

/// Records the prompts and answers each with `answer`; `state` records the connection's state during the
/// prompt.
struct Prompts {
    prompts: Arc<Mutex<Vec<AuthPrompt>>>,
    states: Arc<Mutex<Vec<ConnectionState>>>,
}

fn answer_with(m: &Arc<ConnectionManager>, key: &str, answer: AuthPromptResult) -> Prompts {
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let states = Arc::new(Mutex::new(Vec::new()));
    let (p, s, weak, key) = (prompts.clone(), states.clone(), Arc::downgrade(m), key.to_string());
    m.set_prompt_handler(move |prompt| {
        p.lock().unwrap().push(prompt);
        if let Some(m) = weak.upgrade() {
            s.lock().unwrap().push(m.state(&key));
        }
        answer.clone()
    });
    Prompts { prompts, states }
}

impl Prompts {
    fn prompts(&self) -> Vec<AuthPrompt> {
        self.prompts.lock().unwrap().clone()
    }

    fn kinds(&self) -> Vec<AuthPromptKind> {
        self.prompts().into_iter().map(|p| p.kind).collect()
    }

    fn first_state(&self) -> Option<ConnectionState> {
        self.states.lock().unwrap().first().cloned()
    }
}

fn up_call(f: &Fixture, c: &Connection) -> Option<Call> {
    f.root.calls().into_iter().find(|call| call.line == up_line(c.kind, &c.id))
}

fn respond_calls(f: &Fixture, c: &Connection) -> Vec<String> {
    f.root.calls().into_iter().filter(|call| call.line == respond_line(&c.id)).filter_map(|c| c.stdin).collect()
}

fn with_otp(name: &str, kind: VPNKind, otp: OTPSetting) -> Connection {
    let mut c = Connection::new(name, kind);
    c.otp = otp;
    c
}

fn unix_in(seconds: f64) -> f64 {
    Date::now().adding(seconds).time_interval_since_1970()
}

#[test]
fn otp_appended_on_stdin() {
    let f = Fixture::new(EN);
    let c = with_otp("Office", VPNKind::Openvpn, OTPSetting::new(true, OTPSeparator::Comma));
    f.store.save(&c, Some("client\nremote vpn.example.com 1194\nauth-user-pass\n")).unwrap();
    f.secrets.set("bob", &c.id, SecretField::Username);
    f.secrets.set("pass", &c.id, SecretField::Password);
    let m = manager(&f);
    let prompts = answer_with(&m, &uuid_string(&c.id), AuthPromptResult::Code("123456".into()));
    m.connect(&c, false);
    let all = prompts.prompts();
    assert_eq!(all.len(), 1);
    // Our own text: not "the VPN server's message".
    match &all[0].kind {
        AuthPromptKind::Code { echo, from_server, .. } => {
            assert!(*echo);
            assert!(!*from_server);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(all[0].deadline.duration, 120.0);
    match prompts.first_state() {
        Some(ConnectionState::AwaitingAuth(wait)) => assert_eq!(wait.kind, AuthWaitKind::Code),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        up_call(&f, &c).and_then(|c| c.stdin).as_deref(),
        Some("username=bob\npassword=pass,123456\notp=123456\n")
    );
    // The code is not stored.
    assert_eq!(f.secrets.get(&c.id, SecretField::Password).as_deref(), Some("pass"));
}

#[test]
fn prompt_cancelled_does_not_connect() {
    let f = Fixture::new(EN);
    let c = with_otp("Office", VPNKind::Strongswan, OTPSetting::new(true, OTPSeparator::None));
    f.store.save(&c, Some("x")).unwrap();
    let m = manager(&f);
    let events = record_events(&m);
    answer_with(&m, &uuid_string(&c.id), AuthPromptResult::Cancelled);
    m.connect(&c, false);
    assert!(up_call(&f, &c).is_none());
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Disconnected);
    assert!(events_of(&events).is_empty());
}

#[test]
fn prompt_timeout_fails() {
    let f = Fixture::new(EN);
    let c = with_otp("Office", VPNKind::Sstp, OTPSetting::new(true, OTPSeparator::None));
    f.store.save(&c, Some("server=vpn.example.com\nuser=bob\n")).unwrap();
    let m = manager(&f);
    let events = record_events(&m);
    answer_with(&m, &uuid_string(&c.id), AuthPromptResult::TimedOut);
    m.connect(&c, false);
    assert!(up_call(&f, &c).is_none());
    assert_eq!(
        m.state(&uuid_string(&c.id)),
        ConnectionState::Failed("Authentication was not completed in time".into())
    );
    assert_eq!(events_of(&events).len(), 1);
}

#[test]
fn sstp_code_must_keep_password_rule() {
    let f = Fixture::new(EN);
    let c = with_otp("S", VPNKind::Sstp, OTPSetting::new(true, OTPSeparator::None));
    f.store.save(&c, Some("server=vpn.example.com\nuser=bob\n")).unwrap();
    f.secrets.set("pw", &c.id, SecretField::Password);
    let m = manager(&f);
    answer_with(&m, &uuid_string(&c.id), AuthPromptResult::Code("12\"3".into()));
    m.connect(&c, false);
    assert!(up_call(&f, &c).is_none());
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Failed(MFAError::SstpPassword.message()));
}

#[test]
fn static_challenge_packed_on_stdin() {
    let f = Fixture::new(EN);
    let c = with_otp("Office", VPNKind::Openvpn, OTPSetting::new(true, OTPSeparator::Colon));
    f.store
        .save(&c, Some("client\nremote vpn.example.com 1194\nauth-user-pass\nstatic-challenge \"Enter OTP\" 1\n"))
        .unwrap();
    f.secrets.set("bob", &c.id, SecretField::Username);
    f.secrets.set("StatPass", &c.id, SecretField::Password);
    let m = manager(&f);
    let prompts = answer_with(&m, &uuid_string(&c.id), AuthPromptResult::Code("246810".into()));
    m.connect(&c, false);
    // The static challenge wins: one prompt, with the config's text and echo.
    assert_eq!(prompts.kinds(), [AuthPromptKind::Code { text: "Enter OTP".into(), echo: true, from_server: false }]);
    assert_eq!(
        up_call(&f, &c).and_then(|c| c.stdin).as_deref(),
        Some("username=bob\npassword=SCRV1:U3RhdFBhc3M=:MjQ2ODEw\notp=246810\nchallenge=packed\n")
    );
}

#[test]
fn native_otp_in_start_options() {
    let f = Fixture::new(EN);
    let mut c = with_otp("Office L2TP", VPNKind::L2tp, OTPSetting::new(true, OTPSeparator::Colon));
    c.native_service_name = Some("Office L2TP".into());
    c.native = Some(NativeSettings { server: "vpn.example.com".into(), account: "bob".into(), ..Default::default() });
    c.native_service_id = Some("38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4".into());
    f.store.save(&c, None).unwrap();
    f.secrets.set("bob", &c.id, SecretField::Username);
    f.secrets.set("pw", &c.id, SecretField::Password);
    f.native.set_list(Ok(vec![SystemService::new(
        "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4",
        "Office L2TP",
        "L2TP",
        "Disconnected",
    )]));
    let m = manager(&f);
    answer_with(&m, &uuid_string(&c.id), AuthPromptResult::Code("4711".into()));
    m.connect(&c, false);
    let options = f.native.starts().first().and_then(|s| s.options.clone()).expect("options");
    assert_eq!(options.get("PPP").and_then(|p| p.get("AuthPassword")).map(String::as_str), Some("pw:4711"));
}

#[test]
fn system_service_otp() {
    let f = Fixture::new(EN);
    let sid = "052ED352-624D-4F75-BD84-D3E278CFD84F";
    let s = SystemService::new(sid, "Corp", "Cisco IPsec", "Disconnected");
    f.secrets.set("pw", &s.secret_id().unwrap(), SecretField::Password);
    let m = manager(&f);
    m.set_system_otp(OTPSetting::new(true, OTPSeparator::None), sid);
    assert_eq!(m.system_otp_setting(sid), OTPSetting::new(true, OTPSeparator::None));
    answer_with(&m, sid, AuthPromptResult::Code("8080".into()));
    m.connect_system(&s);
    let options = f.native.starts().first().and_then(|s| s.options.clone()).expect("options");
    assert_eq!(options.get("IPSec").and_then(|p| p.get("XAuthPassword")).map(String::as_str), Some("pw8080"));
    m.set_system_otp(OTPSetting::default(), sid);
    assert_eq!(m.system_otp(), HashMap::new());
}

/// Dynamic challenge during `up`: by the bridge's state file it asks for a code and answers with
/// `mvpn respond`.
#[test]
fn dynamic_challenge_during_up() {
    let f = Fixture::new(EN);
    let c = Connection::new("Office", VPNKind::Openvpn);
    f.store.save(&c, Some("client\nremote vpn.example.com 1194\n")).unwrap();
    f.root.delay(&up_line(VPNKind::Openvpn, &c.id), 1.0);
    let deadline = unix_in(60.0);
    let id = c.id;
    let m = manager_with_reader(&f, move |read| {
        (*read == id).then(|| AuthUIState {
            method: Some(AuthUIMethod::Crv1),
            text: Some("Enter PIN".into()),
            echo: Some(false),
            deadline: Some(deadline),
            ..AuthUIState::new(1, AuthUIStateKind::Challenge)
        })
    });
    let prompts = answer_with(&m, &uuid_string(&c.id), AuthPromptResult::Code("4242".into()));
    m.connect(&c, false);
    // The text from the bridge is the server's: the prompt says so.
    assert_eq!(prompts.kinds(), [AuthPromptKind::Code { text: "Enter PIN".into(), echo: false, from_server: true }]);
    assert!(prompts.prompts()[0].deadline.duration <= 60.0);
    assert!(matches!(prompts.first_state(), Some(ConnectionState::AwaitingAuth(_))), "{:?}", prompts.first_state());
    assert_eq!(respond_calls(&f, &c), ["kind=crv1\nresponse=4242\n"]);
    assert_eq!(up_call(&f, &c).and_then(|c| c.stdin).as_deref(), Some(""));
}

#[test]
fn expired_state_is_ignored() {
    let f = Fixture::new(EN);
    let c = Connection::new("Office", VPNKind::Openvpn);
    f.store.save(&c, Some("client\nremote vpn.example.com 1194\n")).unwrap();
    let m = manager(&f);
    let prompts = answer_with(&m, &uuid_string(&c.id), AuthPromptResult::Code("1".into()));
    m.handle_auth_state(
        &AuthUIState {
            method: Some(AuthUIMethod::Crv1),
            text: Some("old".into()),
            deadline: Some(unix_in(-10.0)),
            ..AuthUIState::new(1, AuthUIStateKind::Challenge)
        },
        &c,
    );
    assert!(prompts.prompts().is_empty());
    assert!(respond_calls(&f, &c).is_empty());
}

#[test]
fn static_fallback_and_cancel_responses() {
    let f = Fixture::new(EN);
    let c = Connection::new("Office", VPNKind::Openvpn);
    f.store.save(&c, Some("client\nremote vpn.example.com 1194\n")).unwrap();
    let m = manager(&f);
    answer_with(&m, &uuid_string(&c.id), AuthPromptResult::Code("1".into()));
    m.handle_auth_state(
        &AuthUIState {
            method: Some(AuthUIMethod::Static),
            text: Some("OTP".into()),
            echo: Some(true),
            ..AuthUIState::new(1, AuthUIStateKind::Challenge)
        },
        &c,
    );
    answer_with(&m, &uuid_string(&c.id), AuthPromptResult::TimedOut);
    m.handle_auth_state(
        &AuthUIState {
            method: Some(AuthUIMethod::Crtext),
            text: Some("x".into()),
            ..AuthUIState::new(2, AuthUIStateKind::Challenge)
        },
        &c,
    );
    assert_eq!(respond_calls(&f, &c), ["kind=static\nresponse=1\n", "kind=cancel\nresponse=\n"]);
}

#[test]
fn web_auth_confirmation_and_http_dropped() {
    let f = Fixture::new(EN);
    let c = Connection::new("Office", VPNKind::Openvpn);
    f.store.save(&c, Some("client\nremote vpn.example.com 1194\n")).unwrap();
    let m = manager(&f);
    let key = uuid_string(&c.id);
    let prompts = answer_with(&m, &key, AuthPromptResult::OpenedUrl);
    let web = |seq: i64, url: &str| AuthUIState {
        method: Some(AuthUIMethod::Webauth),
        url: Some(url.into()),
        ..AuthUIState::new(seq, AuthUIStateKind::Webauth)
    };
    m.handle_auth_state(&web(1, "https://sso.example.com/a"), &c);
    assert_eq!(prompts.kinds(), [AuthPromptKind::WebAuth { url: "https://sso.example.com/a".into() }]);
    assert_eq!(prompts.prompts()[0].deadline.duration, 300.0);
    assert_eq!(respond_calls(&f, &c), ["kind=webauth-ack\nresponse=\n"]);
    // After opening, the connection "waits for web authentication".
    match m.state(&key) {
        ConnectionState::AwaitingAuth(wait) => assert_eq!(wait.kind, AuthWaitKind::Web),
        other => panic!("{other:?}"),
    }
    // Not an https URL: no prompt, no answer.
    m.handle_auth_state(&web(2, "http://evil.example.com/"), &c);
    assert_eq!(prompts.prompts().len(), 1);
    // Declined: cancel.
    answer_with(&m, &key, AuthPromptResult::Cancelled);
    m.handle_auth_state(&web(3, "https://sso.example.com/b"), &c);
    assert_eq!(respond_calls(&f, &c).last().map(String::as_str), Some("kind=cancel\nresponse=\n"));
}

/// Disconnect while connecting: the open prompt is closed, and the bridge is told to cancel before `down`.
#[test]
fn disconnect_while_connecting_cancels_via_bridge() {
    let f = Fixture::new(EN);
    let c = Connection::new("Office", VPNKind::Openvpn);
    f.store.save(&c, Some("client\nremote vpn.example.com 1194\n")).unwrap();
    f.root.delay(&up_line(VPNKind::Openvpn, &c.id), 0.5);
    f.root.respond("status", Ok("[]"));
    let m = manager(&f);
    let dismissed = Arc::new(Mutex::new(Vec::<String>::new()));
    {
        let dismissed = dismissed.clone();
        m.set_dismiss_prompt(move |key| dismissed.lock().unwrap().push(key.to_string()));
    }
    let connecting = spawn(EN, {
        let (m, c) = (m.clone(), c.clone());
        move || m.connect(&c, false)
    });
    f.root.wait_for_call(&up_line(VPNKind::Openvpn, &c.id), 1);
    m.disconnect(&c);
    connecting.join().unwrap();
    let lines = f.root.lines();
    let respond = lines.iter().position(|l| *l == respond_line(&c.id)).expect("respond");
    let down = lines.iter().position(|l| *l == down_line(VPNKind::Openvpn, &c.id)).expect("down");
    assert!(respond < down);
    assert_eq!(respond_calls(&f, &c), ["kind=cancel\nresponse=\n"]);
    assert!(dismissed.lock().unwrap().contains(&uuid_string(&c.id)));
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Disconnected);
}

/// Rust-specific: a pending state (`AUTH_PENDING`) marks the connection as waiting for web approval while `up`
/// runs, and the watcher is stopped (the state cleared) when `up` returns.
#[test]
fn pending_state_during_up_and_cleared_after() {
    let f = Fixture::new(EN);
    let c = Connection::new("Office", VPNKind::Openvpn);
    f.store.save(&c, Some("client\nremote vpn.example.com 1194\n")).unwrap();
    f.root.delay(&up_line(VPNKind::Openvpn, &c.id), 1.0);
    f.root.respond("status", Ok("[]"));
    let m = manager_with_reader(&f, |_| Some(AuthUIState::new(1, AuthUIStateKind::Pending)));
    let key = uuid_string(&c.id);
    let connecting = spawn(EN, {
        let (m, c) = (m.clone(), c.clone());
        move || m.connect(&c, false)
    });
    // Polled while `up` runs (its 1 s delay), not a fixed sleep: the watcher's first read may come late on a busy
    // runner.
    let mut state = m.state(&key);
    while !matches!(state, ConnectionState::AwaitingAuth(_)) && !connecting.is_finished() {
        std::thread::sleep(Duration::from_millis(5));
        state = m.state(&key);
    }
    match state {
        ConnectionState::AwaitingAuth(wait) => assert_eq!(wait.kind, AuthWaitKind::Web),
        other => panic!("{other:?}"),
    }
    connecting.join().unwrap();
    assert!(!matches!(m.state(&key), ConnectionState::AwaitingAuth(_)));
}
