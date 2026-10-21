//! The manager's state-listener fan-out (`add_state_listener`), the user-disconnect listeners with the
//! disconnect cause, and the MFA cancel reason (the control API's inputs).

mod common;

use common::*;
use macvpn_app_core::deps::SystemVpn;
use macvpn_app_core::manager::auth_cancelled_reason;
use macvpn_app_core::{ConnectionManager, DisconnectCause};
use macvpn_core::date::Date;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::mfa::{AuthPromptResult, AuthUIMethod, AuthUIState, AuthUIStateKind};
use macvpn_core::models::{Connection, ConnectionState, VPNKind, uuid_string};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const EN: AppLanguage = AppLanguage::En;
const SVC: &str = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";

type Seen = Arc<Mutex<Vec<(String, ConnectionState)>>>;

fn record_states(m: &ConnectionManager) -> Seen {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    m.add_state_listener(move |key, state| sink.lock().unwrap().push((key.to_string(), state.clone())));
    seen
}

fn record_user_disconnects(m: &ConnectionManager) -> Arc<Mutex<Vec<String>>> {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    m.add_user_disconnect_listener(move |key| sink.lock().unwrap().push(key.to_string()));
    seen
}

fn states_of(seen: &Seen, key: &str) -> Vec<ConnectionState> {
    seen.lock().unwrap().iter().filter(|(k, _)| k == key).map(|(_, s)| s.clone()).collect()
}

fn connected_status(c: &Connection) -> String {
    format!(
        r#"[{{"id":"{}","kind":"wireguard","state":"connected","iface":null,"ip":null,"since":null}}]"#,
        uuid_string(&c.id)
    )
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn listeners_see_each_change_in_order() {
    let f = Fixture::new(EN);
    let c = Connection::new("WG", VPNKind::Wireguard);
    f.store.save(&c, Some("x")).unwrap();
    f.helper.respond("status", Ok(&connected_status(&c)));
    let m = f.manager();
    let first = record_states(&m);
    let second = record_states(&m);
    m.connect(&c, false);
    let key = uuid_string(&c.id);
    let expected = [ConnectionState::Connecting, ConnectionState::Connected { ip: None, since: None }];
    assert_eq!(states_of(&first, &key), expected);
    assert_eq!(states_of(&second, &key), expected);
    // A refresh without a change delivers nothing.
    m.refresh();
    assert_eq!(states_of(&first, &key).len(), 2);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_failure_reaches_the_listeners() {
    let f = Fixture::new(EN);
    let c = Connection::new("WG", VPNKind::Wireguard);
    f.store.save(&c, Some("x")).unwrap();
    f.helper.respond(&up_line(VPNKind::Wireguard, &c.id), Err("boom"));
    f.helper.respond("status", Ok("[]"));
    let m = f.manager();
    let seen = record_states(&m);
    m.connect(&c, false);
    assert_eq!(
        states_of(&seen, &uuid_string(&c.id)),
        [ConnectionState::Connecting, ConnectionState::Failed("boom".into())]
    );
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn only_a_user_disconnect_reaches_the_user_listeners() {
    let f = Fixture::new(EN);
    let c = Connection::new("WG", VPNKind::Wireguard);
    f.store.save(&c, Some("x")).unwrap();
    f.helper.respond("status", Ok("[]"));
    f.native.set_list(Ok(vec![SystemVpn::new(SVC, "Office", "L2TP", "Disconnected")]));
    let m = f.manager();
    m.refresh();
    let s = m.system_services().first().cloned().unwrap();
    let users = record_user_disconnects(&m);
    let seen = record_states(&m);
    let key = uuid_string(&c.id);

    m.disconnect_for(&c, DisconnectCause::Lease);
    m.disconnect_system_for(&s, DisconnectCause::Lease);
    assert!(users.lock().unwrap().is_empty());
    // The same path: the state still goes through `disconnecting`.
    assert_eq!(states_of(&seen, &key), [ConnectionState::Disconnecting, ConnectionState::Disconnected]);

    m.disconnect(&c);
    m.disconnect_system(&s);
    assert_eq!(*users.lock().unwrap(), [key.clone(), SVC.to_string()]);
    assert!(f.helper.lines().contains(&down_line(VPNKind::Wireguard, &c.id)));
}

/// The user listener runs before the state changes, so the control API can tell the user's disconnect from a
/// drop.
#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn user_listener_runs_before_the_state_changes() {
    let f = Fixture::new(EN);
    let c = Connection::new("WG", VPNKind::Wireguard);
    f.store.save(&c, Some("x")).unwrap();
    f.helper.respond("status", Ok(&connected_status(&c)));
    let m = f.manager();
    m.refresh();
    let key = uuid_string(&c.id);
    let at_hook = Arc::new(Mutex::new(None));
    let (sink, weak) = (at_hook.clone(), Arc::downgrade(&m));
    m.add_user_disconnect_listener(move |k| *sink.lock().unwrap() = weak.upgrade().map(|m| m.state(k)));
    f.helper.respond("status", Ok("[]"));
    m.disconnect(&c);
    assert_eq!(*at_hook.lock().unwrap(), Some(ConnectionState::Connected { ip: None, since: None }));
    assert_eq!(m.state(&key), ConnectionState::Disconnected);
}

/// Declining the server's code prompt makes the failing `up` report the cancel, not the tool's message.
#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn cancelled_dynamic_challenge_fails_with_the_cancel_reason() {
    let f = Fixture::new(EN);
    let c = Connection::new("Office", VPNKind::Openvpn);
    f.store.save(&c, Some("client\nremote vpn.example.com 1194\n")).unwrap();
    f.helper.delay(&up_line(VPNKind::Openvpn, &c.id), 1.0);
    f.helper.respond(&up_line(VPNKind::Openvpn, &c.id), Err("bridge said no"));
    let deadline = Date::now().adding(60.0).time_interval_since_1970();
    let id = c.id;
    let mut deps = f.deps();
    deps.auth_state = Arc::new(Reader(Box::new(move |read| {
        (*read == id).then(|| AuthUIState {
            method: Some(AuthUIMethod::Crv1),
            text: Some("PIN".into()),
            echo: Some(false),
            deadline: Some(deadline),
            ..AuthUIState::new(1, AuthUIStateKind::Challenge)
        })
    })));
    let m = f.manager_with(deps);
    m.set_auth_poll_interval(Duration::from_millis(50));
    m.set_prompt_handler(|_| AuthPromptResult::Cancelled);
    m.connect(&c, false);
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Failed(auth_cancelled_reason()));
    assert_eq!(auth_cancelled_reason(), "Authentication cancelled");

    // The next connect starts clean: its own failure keeps its own message.
    f.helper.delay(&up_line(VPNKind::Openvpn, &c.id), 0.0);
    m.set_prompt_handler(|_| AuthPromptResult::Code("1".into()));
    m.connect(&c, false);
    assert_eq!(m.state(&uuid_string(&c.id)), ConnectionState::Failed("bridge said no".into()));
}

type ReadFn = Box<dyn Fn(&uuid::Uuid) -> Option<AuthUIState> + Send + Sync>;

struct Reader(ReadFn);

impl macvpn_app_core::deps::AuthStateReader for Reader {
    fn read(&self, id: &uuid::Uuid) -> Option<AuthUIState> {
        (self.0)(id)
    }
}
