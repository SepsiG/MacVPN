//! The credential prompt in the connection manager (spec `2026-10-19-vault-folders-design.md`, section 4): the
//! missing credentials are asked before the root layer / `SCNetworkConnection` is called, "Save" writes only after
//! the connection came up, a sign-in failure re-prompts once, Cancel ends silently.

mod common;

use common::*;
use macvpn_app_core::ConnectionManager;
use macvpn_app_core::deps::{SecretField, SecretReader, SystemService};
use macvpn_core::credentials::{CredentialAnswer, CredentialField, CredentialPrompt, CredentialValues};
use macvpn_core::l10n::AppLanguage;
use macvpn_core::mfa::{AuthPromptKind, AuthPromptResult};
use macvpn_core::models::{AuthWaitKind, Connection, ConnectionState, NativeSettings, VPNKind, uuid_string};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

use CredentialField::{KeyPassword, Password, Psk, Username};

const EN: AppLanguage = AppLanguage::En;
const SVC: &str = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
const OVPN: &str = "client\ndev tun\nremote vpn.example.com 1194\nauth-user-pass\n";
const AUTH_FAILED: &str = "Authentication failed (AUTH_FAILED)";

/// One scripted answer of the credential window.
#[derive(Clone)]
enum Reply {
    Provide(Vec<(CredentialField, &'static str)>, bool),
    Cancel,
}

#[derive(Clone, Default)]
struct Window {
    prompts: Arc<Mutex<Vec<CredentialPrompt>>>,
    states: Arc<Mutex<Vec<ConnectionState>>>,
    order: Arc<Mutex<Vec<&'static str>>>,
    dismissed: Arc<Mutex<Vec<String>>>,
}

impl Window {
    fn prompts(&self) -> Vec<CredentialPrompt> {
        self.prompts.lock().unwrap().clone()
    }

    fn fields(&self) -> Vec<Vec<CredentialField>> {
        self.prompts().into_iter().map(|p| p.fields).collect()
    }
}

/// The credential window answers from `replies` (then Cancel); it also records the connection's state while open.
fn window(m: &Arc<ConnectionManager>, replies: Vec<Reply>) -> Window {
    let w = Window::default();
    let queue = Arc::new(Mutex::new(VecDeque::from(replies)));
    let (prompts, states, order, weak) = (w.prompts.clone(), w.states.clone(), w.order.clone(), Arc::downgrade(m));
    m.set_credential_handler(move |prompt| {
        order.lock().unwrap().push("credentials");
        if let Some(m) = weak.upgrade() {
            states.lock().unwrap().push(m.state(&prompt.connection_id));
        }
        prompts.lock().unwrap().push(prompt);
        match queue.lock().unwrap().pop_front().unwrap_or(Reply::Cancel) {
            Reply::Provide(pairs, save) => {
                let mut values = CredentialValues::default();
                for (field, value) in pairs {
                    values.set(field, Zeroizing::new(value.to_string()));
                }
                CredentialAnswer::Provided { values, save }
            }
            Reply::Cancel => CredentialAnswer::Cancelled,
        }
    });
    let dismissed = w.dismissed.clone();
    m.set_dismiss_credentials(move |key| dismissed.lock().unwrap().push(key.to_string()));
    w
}

fn status_json(c: &Connection, state: &str) -> String {
    format!(
        r#"[{{"id":"{}","kind":"{}","state":"{state}","iface":null,"ip":null,"since":null}}]"#,
        uuid_string(&c.id),
        c.kind.raw_value()
    )
}

fn manager(f: &Fixture) -> Arc<ConnectionManager> {
    let mut deps = f.deps();
    deps.secret_writer = Some(f.secrets.clone());
    f.manager_with(deps)
}

fn openvpn(f: &Fixture, config: &str) -> Connection {
    let c = Connection::new("Office", VPNKind::Openvpn);
    f.store.save(&c, Some(config)).unwrap();
    c
}

fn up_stdins(f: &Fixture, c: &Connection) -> Vec<String> {
    f.root.calls().into_iter().filter(|call| call.line == up_line(c.kind, &c.id)).filter_map(|c| c.stdin).collect()
}

#[test]
fn missing_credentials_are_asked_and_saved_after_success() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let key = uuid_string(&c.id);
    let m = manager(&f);
    let w = window(&m, vec![Reply::Provide(vec![(Username, "alice"), (Password, "s3cret")], true)]);
    // The first status (right after `up`) still says connecting: nothing is saved yet.
    f.root.respond("status", Ok(&status_json(&c, "connecting")));
    m.connect(&c, false);
    assert_eq!(w.fields(), [vec![Username, Password]]);
    let p = &w.prompts()[0];
    assert_eq!((p.connection_id.as_str(), p.connection_name.as_str(), p.retry), (key.as_str(), "Office", false));
    assert_eq!(p.username, None);
    assert_eq!(p.deadline.duration, 120.0);
    assert_eq!(up_stdins(&f, &c), ["username=alice\npassword=s3cret\n"]);
    m.flush_saves();
    assert!(f.secrets.writes().is_empty(), "nothing is written before the connection is up");
    f.root.respond("status", Ok(&status_json(&c, "connected")));
    m.refresh();
    assert!(m.state(&key).is_connected());
    m.flush_saves();
    assert_eq!(f.secrets.get(&c.id, SecretField::Username).as_deref(), Some("alice"));
    m.flush_saves();
    assert_eq!(f.secrets.get(&c.id, SecretField::Password).as_deref(), Some("s3cret"));
    m.flush_saves();
    assert_eq!(f.secrets.writes().len(), 2);
    m.refresh();
    m.flush_saves();
    assert_eq!(f.secrets.writes().len(), 2, "saved once");
}

#[test]
fn without_save_nothing_is_written() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let m = manager(&f);
    window(&m, vec![Reply::Provide(vec![(Username, "alice"), (Password, "pw")], false)]);
    f.root.respond("status", Ok(&status_json(&c, "connected")));
    m.connect(&c, false);
    assert!(m.state(&uuid_string(&c.id)).is_connected());
    m.flush_saves();
    assert!(f.secrets.writes().is_empty());
    m.flush_saves();
    assert_eq!(f.secrets.get(&c.id, SecretField::Password), None);
}

#[test]
fn a_stored_user_name_is_prefilled_and_not_asked() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    f.secrets.set("alice", &c.id, SecretField::Username);
    let m = manager(&f);
    let w = window(&m, vec![Reply::Provide(vec![(Password, "pw")], true)]);
    m.connect(&c, false);
    assert_eq!(w.fields(), [vec![Password]]);
    assert_eq!(w.prompts()[0].username.as_deref(), Some("alice"));
    assert_eq!(up_stdins(&f, &c), ["username=alice\npassword=pw\n"]);
}

#[test]
fn everything_stored_means_no_prompt() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    f.secrets.set("alice", &c.id, SecretField::Username);
    f.secrets.set("pw", &c.id, SecretField::Password);
    let m = manager(&f);
    let w = window(&m, vec![]);
    m.connect(&c, false);
    assert!(w.prompts().is_empty());
    assert_eq!(up_stdins(&f, &c).len(), 1);
}

#[test]
fn no_handler_connects_with_the_stored_secrets() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let m = manager(&f);
    m.connect(&c, false);
    assert_eq!(up_stdins(&f, &c), [""]);
}

#[test]
fn cancel_ends_silently() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let m = manager(&f);
    let events = record_events(&m);
    let w = window(&m, vec![Reply::Cancel]);
    m.connect(&c, false);
    assert_eq!(w.prompts().len(), 1);
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Disconnected);
    assert!(events_of(&events).is_empty());
    assert!(up_stdins(&f, &c).is_empty());
    m.flush_saves();
    assert!(f.secrets.writes().is_empty());
}

/// Lock Now while the credential window is open (review 1.2.0 M2): the prompt is dismissed, and the connect ends
/// before anything else is asked or the root layer is called, whatever the window answers.
#[test]
fn a_lock_while_the_credential_prompt_is_open_ends_the_connect() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let key = uuid_string(&c.id);
    let m = manager(&f);
    let dismissed = Arc::new(Mutex::new(Vec::<String>::new()));
    let weak = Arc::downgrade(&m);
    m.set_credential_handler(move |_prompt| {
        if let Some(m) = weak.upgrade() {
            m.enter_locked();
        }
        let mut values = CredentialValues::default();
        values.set(Username, Zeroizing::new("alice".into()));
        values.set(Password, Zeroizing::new("s3cret".into()));
        CredentialAnswer::Provided { values, save: true }
    });
    let seen = dismissed.clone();
    m.set_dismiss_credentials(move |key| seen.lock().unwrap().push(key.to_string()));
    m.connect(&c, false);
    assert_eq!(*dismissed.lock().unwrap(), std::slice::from_ref(&key));
    assert!(up_stdins(&f, &c).is_empty(), "the root layer was not called");
    assert!(!m.state(&key).is_active());
    m.flush_saves();
    assert!(f.secrets.writes().is_empty());
}

#[test]
fn waiting_for_credentials_while_the_window_is_open() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let m = manager(&f);
    let w = window(&m, vec![Reply::Cancel]);
    m.connect(&c, false);
    match w.states.lock().unwrap().first() {
        Some(ConnectionState::AwaitingAuth(wait)) => {
            assert_eq!(wait.kind, AuthWaitKind::Credentials);
            assert!(wait.deadline.is_some());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn credentials_come_before_the_static_challenge() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, &format!("{OVPN}static-challenge \"PIN\" 1\n"));
    f.secrets.set("alice", &c.id, SecretField::Username);
    let m = manager(&f);
    let w = window(&m, vec![Reply::Provide(vec![(Password, "pw")], false)]);
    let order = w.order.clone();
    m.set_prompt_handler(move |p| {
        assert!(matches!(p.kind, AuthPromptKind::Code { .. }));
        order.lock().unwrap().push("code");
        AuthPromptResult::Code("123456".into())
    });
    m.connect(&c, false);
    assert_eq!(*w.order.lock().unwrap(), ["credentials", "code"]);
    let stdin = up_stdins(&f, &c).pop().unwrap();
    assert!(stdin.contains("challenge=packed"), "{stdin}");
}

#[test]
fn kinds_without_credentials_never_prompt() {
    let f = Fixture::new(EN);
    let wg = Connection::new("WG", VPNKind::Wireguard);
    f.store.save(&wg, Some(&macvpn_core::importer::template(VPNKind::Wireguard))).unwrap();
    let ike = Connection::new("IKE", VPNKind::Strongswan);
    let pubkey = macvpn_core::importer::template(VPNKind::Strongswan).replace("auth = eap-mschapv2", "auth = pubkey");
    f.store.save(&ike, Some(&pubkey)).unwrap();
    let inline = openvpn(&f, &format!("{OVPN}<auth-user-pass>\nalice\npw\n</auth-user-pass>\n"));
    let m = manager(&f);
    let w = window(&m, vec![]);
    m.connect(&wg, false);
    m.connect(&ike, false);
    m.connect(&inline, false);
    assert!(w.prompts().is_empty());
}

#[test]
fn ikev2_eap_and_sstp_ask_their_fields() {
    let f = Fixture::new(EN);
    let ike = Connection::new("IKE", VPNKind::Strongswan);
    f.store.save(&ike, Some(&macvpn_core::importer::template(VPNKind::Strongswan))).unwrap();
    let sstp = Connection::new("SSTP", VPNKind::Sstp);
    f.store.save(&sstp, Some(&macvpn_core::importer::template(VPNKind::Sstp))).unwrap();
    let m = manager(&f);
    let w = window(&m, vec![Reply::Cancel, Reply::Cancel]);
    m.connect(&ike, false);
    m.connect(&sstp, false);
    assert_eq!(w.fields(), [vec![Username, Password], vec![Password]]);
}

fn managed_l2tp(f: &Fixture) -> Connection {
    let mut c = Connection::new("Office L2TP", VPNKind::L2tp);
    c.native_service_name = Some("Office L2TP".into());
    c.native_service_id = Some(SVC.into());
    c.native = Some(NativeSettings { server: "vpn.example.com".into(), account: "bob".into(), ..Default::default() });
    f.store.save(&c, None).unwrap();
    f.native.set_list(Ok(vec![SystemService::new(SVC, "Office L2TP", "L2TP", "Disconnected")]));
    c
}

#[test]
fn managed_l2tp_asks_for_the_missing_psk() {
    let f = Fixture::new(EN);
    let c = managed_l2tp(&f);
    f.secrets.set("pw", &c.id, SecretField::Password);
    let m = manager(&f);
    let w = window(&m, vec![Reply::Provide(vec![(Psk, "shared")], true)]);
    m.connect(&c, false);
    assert_eq!(w.fields(), [vec![Psk]], "the account counts as the user name");
    assert_eq!(w.prompts()[0].username.as_deref(), Some("bob"));
    let options = f.native.starts().first().and_then(|s| s.options.clone()).expect("options");
    assert_eq!(options.get("IPSec").and_then(|e| e.get("SharedSecret")).map(String::as_str), Some("shared"));
    m.flush_saves();
    assert!(f.secrets.writes().is_empty());
    f.native.set_list(Ok(vec![SystemService::new(SVC, "Office L2TP", "L2TP", "Connected")]));
    m.refresh();
    assert!(m.state(&uuid_string(&c.id)).is_connected());
    m.flush_saves();
    assert_eq!(f.secrets.get(&c.id, SecretField::Psk).as_deref(), Some("shared"));
}

#[test]
fn a_typed_native_user_name_becomes_the_account() {
    let f = Fixture::new(EN);
    let mut c = managed_l2tp(&f);
    c.native.as_mut().unwrap().account = String::new();
    f.store.save(&c, None).unwrap();
    f.secrets.set("pw", &c.id, SecretField::Password);
    f.secrets.set("k", &c.id, SecretField::Psk);
    let m = manager(&f);
    let w = window(&m, vec![Reply::Provide(vec![(Username, "carol")], true)]);
    m.connect(&c, false);
    assert_eq!(w.fields(), [vec![Username]]);
    f.native.set_list(Ok(vec![SystemService::new(SVC, "Office L2TP", "L2TP", "Connected")]));
    m.refresh();
    m.flush_saves();
    assert_eq!(f.secrets.get(&c.id, SecretField::Username).as_deref(), Some("carol"));
    let saved = f.store.list().unwrap().into_iter().find(|x| x.id == c.id).unwrap();
    assert_eq!(saved.native.unwrap().account, "carol");
    assert_eq!(m.connections().iter().find(|x| x.id == c.id).unwrap().native.as_ref().unwrap().account, "carol");
}

#[test]
fn system_vpns_get_no_prompt() {
    let f = Fixture::new(EN);
    let s = SystemService::new(SVC, "Corp", "L2TP", "Disconnected");
    f.native.set_list(Ok(vec![s.clone()]));
    let m = manager(&f);
    let w = window(&m, vec![]);
    m.refresh();
    m.connect_system(&s);
    assert!(w.prompts().is_empty());
    assert_eq!(f.native.starts().len(), 1);
}

#[test]
fn a_sign_in_failure_reprompts_once() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let key = uuid_string(&c.id);
    let m = manager(&f);
    let w = window(
        &m,
        vec![
            Reply::Provide(vec![(Username, "alice"), (Password, "wrong")], true),
            Reply::Provide(vec![(Username, "alice"), (Password, "right")], true),
        ],
    );
    f.root.respond_once(&up_line(c.kind, &c.id), Err(AUTH_FAILED));
    f.root.respond("status", Ok(&status_json(&c, "connected")));
    m.connect(&c, false);
    let prompts = w.prompts();
    assert_eq!(prompts.len(), 2);
    assert!(!prompts[0].retry && prompts[1].retry);
    assert_eq!(prompts[1].fields, [Username, Password]);
    assert_eq!(up_stdins(&f, &c), ["username=alice\npassword=wrong\n", "username=alice\npassword=right\n"]);
    assert!(m.state(&key).is_connected());
    m.flush_saves();
    assert_eq!(f.secrets.get(&c.id, SecretField::Password).as_deref(), Some("right"), "only the right one");
}

#[test]
fn a_second_sign_in_failure_fails_without_a_third_prompt() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    f.secrets.set("alice", &c.id, SecretField::Username);
    f.secrets.set("pw", &c.id, SecretField::Password);
    let m = manager(&f);
    let events = record_events(&m);
    let w = window(&m, vec![Reply::Provide(vec![(Username, "alice"), (Password, "pw2")], true)]);
    f.root.respond(&up_line(c.kind, &c.id), Err(AUTH_FAILED));
    m.connect(&c, false);
    assert_eq!(w.prompts().len(), 1, "stored credentials: only the re-prompt");
    assert!(w.prompts()[0].retry);
    assert_eq!(w.prompts()[0].username.as_deref(), Some("alice"));
    assert_eq!(up_stdins(&f, &c).len(), 2);
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Failed(AUTH_FAILED.into()));
    assert_eq!(events_of(&events), [failed(&uuid_string(&c.id), "Office", AUTH_FAILED)]);
    m.flush_saves();
    assert!(f.secrets.writes().is_empty(), "a failed connect saves nothing");
    m.flush_saves();
    assert_eq!(f.secrets.get(&c.id, SecretField::Password).as_deref(), Some("pw"));
}

#[test]
fn the_reprompt_does_not_ask_a_stored_key_password_again() {
    let f = Fixture::new(EN);
    let config = format!(
        "{OVPN}<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n</key>\n"
    );
    let c = openvpn(&f, &config);
    f.secrets.set("alice", &c.id, SecretField::Username);
    f.secrets.set("pw", &c.id, SecretField::Password);
    f.secrets.set("kp", &c.id, SecretField::KeyPassword);
    let m = manager(&f);
    let w = window(&m, vec![Reply::Cancel]);
    f.root.respond_once(&up_line(c.kind, &c.id), Err(AUTH_FAILED));
    m.connect(&c, false);
    assert_eq!(w.fields(), [vec![Username, Password]]);
    assert!(!w.fields()[0].contains(&KeyPassword));
}

/// Root layer 8: strongSwan's EAP authentication failure is a sign-in failure too.
#[test]
fn an_ikev2_eap_failure_reprompts_once() {
    let f = Fixture::new(EN);
    let c = Connection::new("IKE", VPNKind::Strongswan);
    f.store.save(&c, Some(&macvpn_core::importer::template(VPNKind::Strongswan))).unwrap();
    f.secrets.set("alice", &c.id, SecretField::Username);
    f.secrets.set("wrong", &c.id, SecretField::Password);
    let m = manager(&f);
    let w = window(&m, vec![Reply::Provide(vec![(Username, "alice"), (Password, "right")], true)]);
    f.root.respond_once(&up_line(c.kind, &c.id), Err("Authentication failed (EAP)"));
    f.root.respond("status", Ok(&status_json(&c, "connected")));
    m.connect(&c, false);
    assert_eq!(w.prompts().len(), 1, "stored credentials: only the re-prompt");
    assert!(w.prompts()[0].retry);
    assert_eq!(up_stdins(&f, &c), ["username=alice\npassword=wrong\n", "username=alice\npassword=right\n"]);
    assert!(m.state(&uuid_string(&c.id)).is_connected());
    m.flush_saves();
    assert_eq!(f.secrets.get(&c.id, SecretField::Password).as_deref(), Some("right"));
}

#[test]
fn other_failures_do_not_reprompt() {
    let f = Fixture::new(EN);
    let c = Connection::new("IKE", VPNKind::Strongswan);
    f.store.save(&c, Some(&macvpn_core::importer::template(VPNKind::Strongswan))).unwrap();
    f.secrets.set("alice", &c.id, SecretField::Username);
    f.secrets.set("pw", &c.id, SecretField::Password);
    let m = manager(&f);
    let w = window(&m, vec![]);
    let message = "IKE negotiation failed (details in the log)";
    f.root.respond(&up_line(c.kind, &c.id), Err(message));
    m.connect(&c, false);
    assert!(w.prompts().is_empty());
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Failed(message.into()));
}

#[test]
fn a_cancelled_reprompt_ends_silently() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    f.secrets.set("alice", &c.id, SecretField::Username);
    f.secrets.set("pw", &c.id, SecretField::Password);
    let m = manager(&f);
    let events = record_events(&m);
    let w = window(&m, vec![Reply::Cancel]);
    f.root.respond(&up_line(c.kind, &c.id), Err(AUTH_FAILED));
    m.connect(&c, false);
    assert_eq!(w.prompts().len(), 1);
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Disconnected);
    assert!(events_of(&events).is_empty());
    assert_eq!(up_stdins(&f, &c).len(), 1);
}

#[test]
fn disconnecting_while_the_window_is_open_dismisses_it() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let m = manager(&f);
    let w = Window::default();
    let (weak, conn, prompts) = (Arc::downgrade(&m), c.clone(), w.prompts.clone());
    m.set_credential_handler(move |prompt| {
        prompts.lock().unwrap().push(prompt);
        // The user switches the connection off while the window is open.
        weak.upgrade().unwrap().disconnect(&conn);
        CredentialAnswer::Cancelled
    });
    let dismissed = w.dismissed.clone();
    m.set_dismiss_credentials(move |key| dismissed.lock().unwrap().push(key.to_string()));
    m.connect(&c, false);
    assert_eq!(w.prompts().len(), 1);
    assert_eq!(*w.dismissed.lock().unwrap(), [uuid_string(&c.id)]);
    assert!(up_stdins(&f, &c).is_empty());
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Disconnected);
}

#[test]
fn a_failed_connect_after_save_writes_nothing() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let m = manager(&f);
    window(&m, vec![Reply::Provide(vec![(Username, "alice"), (Password, "pw")], true)]);
    f.root.respond(&up_line(c.kind, &c.id), Err("Cannot reach the server"));
    m.connect(&c, false);
    m.refresh();
    m.flush_saves();
    assert!(f.secrets.writes().is_empty());
    // A later successful connect without a prompt does not save the old values either.
    f.root.respond(&up_line(c.kind, &c.id), Ok(""));
    f.root.respond("status", Ok(&status_json(&c, "connected")));
    window(&m, vec![Reply::Provide(vec![(Username, "alice"), (Password, "pw")], false)]);
    m.connect(&c, false);
    assert!(m.state(&uuid_string(&c.id)).is_connected());
    m.flush_saves();
    assert!(f.secrets.writes().is_empty());
}

// MARK: - Typed secrets are wiped on every path (`Zeroizing<Secrets>` end to end)

fn wiped() -> usize {
    macvpn_core::models::wiped_secret_values()
}

#[test]
fn typed_secrets_are_wiped_after_up() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let m = manager(&f);
    window(&m, vec![Reply::Provide(vec![(Username, "alice"), (Password, "pw")], false)]);
    let before = wiped();
    m.connect(&c, false);
    assert_eq!(up_stdins(&f, &c).len(), 1);
    // The merged copy and the one sent to `up`, each with the user name and the password.
    assert!(wiped() - before >= 4, "{}", wiped() - before);
}

#[test]
fn typed_secrets_are_wiped_when_the_connect_is_superseded() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let m = manager(&f);
    let (weak, conn) = (Arc::downgrade(&m), c.clone());
    m.set_credential_handler(move |_| {
        // The user switches it off while typing, then the window still answers: `keep_save` refuses.
        weak.upgrade().unwrap().disconnect(&conn);
        let mut values = CredentialValues::default();
        values.set(Username, Zeroizing::new("alice".into()));
        values.set(Password, Zeroizing::new("pw".into()));
        CredentialAnswer::Provided { values, save: true }
    });
    let before = wiped();
    m.connect(&c, false);
    assert!(up_stdins(&f, &c).is_empty());
    assert!(wiped() - before >= 2, "the merged secrets of the early return: {}", wiped() - before);
}

#[test]
fn typed_secrets_are_wiped_when_the_code_prompt_is_cancelled() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, &format!("{OVPN}static-challenge \"PIN\" 1\n"));
    let m = manager(&f);
    window(&m, vec![Reply::Provide(vec![(Username, "alice"), (Password, "pw")], false)]);
    m.set_prompt_handler(|_| AuthPromptResult::Cancelled);
    let before = wiped();
    m.connect(&c, false);
    assert!(up_stdins(&f, &c).is_empty());
    assert!(wiped() - before >= 2, "{}", wiped() - before);
}

// MARK: - "Save" never overrides a later change

#[test]
fn an_editor_change_during_the_connect_wins() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let m = manager(&f);
    window(&m, vec![Reply::Provide(vec![(Username, "alice"), (Password, "typed")], true)]);
    f.root.respond("status", Ok(&status_json(&c, "connecting")));
    m.connect(&c, false);
    // The editor saves another password before the connection is up.
    macvpn_app_core::deps::SecretWriter::set(&*f.secrets, "edited", &c.id, SecretField::Password);
    f.root.respond("status", Ok(&status_json(&c, "connected")));
    m.refresh();
    m.flush_saves();
    assert_eq!(f.secrets.get(&c.id, SecretField::Password).as_deref(), Some("edited"));
    assert_eq!(f.secrets.get(&c.id, SecretField::Username).as_deref(), Some("alice"), "the unchanged field is saved");
}

#[test]
fn the_native_account_patches_the_fresh_meta() {
    let f = Fixture::new(EN);
    let mut c = managed_l2tp(&f);
    c.native.as_mut().unwrap().account = String::new();
    f.store.save(&c, None).unwrap();
    f.secrets.set("pw", &c.id, SecretField::Password);
    f.secrets.set("k", &c.id, SecretField::Psk);
    let m = manager(&f);
    window(&m, vec![Reply::Provide(vec![(Username, "carol")], true)]);
    m.connect(&c, false);
    // Edited and saved meanwhile (another setting): the save keeps it.
    let mut edited = c.clone();
    edited.native.as_mut().unwrap().send_all_traffic = false;
    f.store.save(&edited, None).unwrap();
    f.native.set_list(Ok(vec![SystemService::new(SVC, "Office L2TP", "L2TP", "Connected")]));
    m.refresh();
    m.flush_saves();
    let saved = f.store.list().unwrap().into_iter().find(|x| x.id == c.id).unwrap().native.unwrap();
    assert_eq!(saved.account, "carol");
    assert!(!saved.send_all_traffic, "the edit made during the connect stays");
}

#[test]
fn a_changed_native_account_is_not_overwritten() {
    let f = Fixture::new(EN);
    let mut c = managed_l2tp(&f);
    c.native.as_mut().unwrap().account = String::new();
    f.store.save(&c, None).unwrap();
    f.secrets.set("pw", &c.id, SecretField::Password);
    f.secrets.set("k", &c.id, SecretField::Psk);
    let m = manager(&f);
    window(&m, vec![Reply::Provide(vec![(Username, "carol")], true)]);
    m.connect(&c, false);
    let mut edited = c.clone();
    edited.native.as_mut().unwrap().account = "dave".into();
    f.store.save(&edited, None).unwrap();
    f.native.set_list(Ok(vec![SystemService::new(SVC, "Office L2TP", "L2TP", "Connected")]));
    m.refresh();
    m.flush_saves();
    let saved = f.store.list().unwrap().into_iter().find(|x| x.id == c.id).unwrap().native.unwrap();
    assert_eq!(saved.account, "dave");
}

#[test]
fn a_deleted_connection_gets_no_saved_items() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let m = manager(&f);
    window(&m, vec![Reply::Provide(vec![(Username, "alice"), (Password, "pw")], true)]);
    f.root.respond("status", Ok(&status_json(&c, "connecting")));
    m.connect(&c, false);
    // Deleted while connecting (the order of `ConnectionsModel::delete`).
    m.forget_saves(&c.id);
    f.store.delete(&c.id).unwrap();
    m.reload();
    f.root.respond("status", Ok(&status_json(&c, "connected")));
    m.refresh();
    m.flush_saves();
    assert!(f.secrets.writes().is_empty());
    assert_eq!(f.secrets.count(&c.id), 0);
}

#[test]
fn a_ready_save_of_a_deleted_connection_is_dropped() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let m = manager(&f);
    window(&m, vec![Reply::Provide(vec![(Username, "alice"), (Password, "pw")], true)]);
    f.root.respond("status", Ok(&status_json(&c, "connecting")));
    m.connect(&c, false);
    // Still listed, but marked deleted before the write runs.
    m.forget_saves(&c.id);
    f.root.respond("status", Ok(&status_json(&c, "connected")));
    m.refresh();
    m.flush_saves();
    assert!(f.secrets.writes().is_empty());
}

/// A Keychain write that waits (a macOS access prompt) until released.
struct SlowWriter(Mutex<bool>, std::sync::Condvar, Arc<MemorySecrets>);

impl macvpn_app_core::deps::SecretWriter for SlowWriter {
    fn set(&self, value: &str, id: &uuid::Uuid, field: SecretField) {
        let mut open = self.0.lock().unwrap();
        while !*open {
            open = self.1.wait(open).unwrap();
        }
        macvpn_app_core::deps::SecretWriter::set(&*self.2, value, id, field);
    }
    fn delete_all(&self, _: &uuid::Uuid) {}
    fn remove_all(&self) {}
}

/// Records which write the manager uses: the prompt's "Save" must go through `save_prompted` (which may update a
/// linked shared credential), never the editors' `set`.
#[derive(Default)]
struct WriteKinds(Mutex<Vec<(&'static str, SecretField)>>);

impl macvpn_app_core::deps::SecretWriter for WriteKinds {
    fn set(&self, _: &str, _: &uuid::Uuid, field: SecretField) {
        self.0.lock().unwrap().push(("set", field));
    }
    fn save_prompted(&self, _: &str, _: &uuid::Uuid, field: SecretField) {
        self.0.lock().unwrap().push(("save_prompted", field));
    }
    fn delete_all(&self, _: &uuid::Uuid) {}
    fn remove_all(&self) {}
}

#[test]
fn save_writes_through_save_prompted() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let writer = Arc::new(WriteKinds::default());
    let mut deps = f.deps();
    deps.secret_writer = Some(writer.clone());
    let m = f.manager_with(deps);
    window(&m, vec![Reply::Provide(vec![(Username, "alice"), (Password, "pw")], true)]);
    f.root.respond("status", Ok(&status_json(&c, "connected")));
    m.connect(&c, false);
    m.flush_saves();
    assert_eq!(
        *writer.0.lock().unwrap(),
        [("save_prompted", SecretField::Username), ("save_prompted", SecretField::Password)]
    );
}

#[test]
fn saving_does_not_block_the_refresh() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let slow = Arc::new(SlowWriter(Mutex::new(false), std::sync::Condvar::new(), f.secrets.clone()));
    let mut deps = f.deps();
    deps.secret_writer = Some(slow.clone());
    let m = f.manager_with(deps);
    window(&m, vec![Reply::Provide(vec![(Username, "alice"), (Password, "pw")], true)]);
    f.root.respond("status", Ok(&status_json(&c, "connected")));
    // `connect` refreshes after `up`, which hands the save to the writer: it returns although the write waits.
    m.connect(&c, false);
    assert!(m.state(&uuid_string(&c.id)).is_connected());
    assert!(f.secrets.writes().is_empty());
    *slow.0.lock().unwrap() = true;
    slow.1.notify_all();
    m.flush_saves();
    assert_eq!(f.secrets.get(&c.id, SecretField::Password).as_deref(), Some("pw"));
}

#[test]
fn a_cancelled_prompt_is_recorded_until_the_next_connect() {
    let f = Fixture::new(EN);
    let c = openvpn(&f, OVPN);
    let key = uuid_string(&c.id);
    let m = manager(&f);
    window(&m, vec![Reply::Cancel, Reply::Provide(vec![(Username, "a"), (Password, "p")], false)]);
    m.connect(&c, false);
    assert!(m.credentials_cancelled(&key));
    m.connect(&c, false);
    assert!(!m.credentials_cancelled(&key));
}
