//! The example client (`examples/macvpn-control-client`) against the real control server: the reusable `Client`
//! and `Lease` walk through pair → hello → list → up → drop → disconnect over a real socket, with the fake host
//! and transport of `control_support`.

mod control_support;

use control_support::*;
use macvpn_app_core::control::{ControlLimits, PairingAnswer};
use macvpn_control_client::{Client, Error, ErrorCode, Lease, State, StateEvent};
use macvpn_core::models::ConnectionState;
use std::time::Duration;

/// Pairs through the example client with the user approving `keys`; returns the token.
fn pair(h: &Harness, keys: &[&str]) -> String {
    h.host.answers.lock().unwrap().push_back(PairingAnswer::Approved(keys.iter().map(|k| k.to_string()).collect()));
    let pairing = Client::pair(&h.socket(), "Remote Desktop").expect("pairing");
    assert_eq!(pairing.token.len(), 43);
    assert!(!format!("{pairing:?}").contains(&pairing.token));
    pairing.token
}

fn states(events: &[StateEvent]) -> Vec<&str> {
    events.iter().map(|e| e.state.as_str()).collect()
}

#[test]
fn pair_hello_list_up_drop_disconnects() {
    let h = Harness::new();
    let (key, item) = managed("Office");
    h.host.add(item);
    let (_, other) = managed("Not allowed");
    h.host.add(other);
    h.host.script(
        &key,
        vec![Step::State(ConnectionState::Connecting), Step::State(awaiting()), Step::State(connected())],
    );

    let token = pair(&h, &[&key]);
    assert_eq!(h.server().clients().len(), 1);

    let mut client = Client::open(&h.socket(), &token).expect("hello");
    let list = client.list().unwrap();
    assert_eq!(list.len(), 1, "only the allowed connection");
    assert_eq!(
        (list[0].id.as_str(), list[0].name.as_str(), list[0].kind.as_str()),
        (key.as_str(), "Office", "openvpn")
    );
    assert_eq!(list[0].state, State::Disconnected);

    let mut events = Vec::new();
    client.up(&key, |e| events.push(e.clone())).expect("connected");
    assert_eq!(states(&events), ["connecting", "waiting_for_mfa", "connected"]);
    assert!(events.iter().all(|e| e.connection == key));
    assert_eq!(h.host.count(&format!("connect {key}")), 1);
    assert_eq!(h.server().holder_names(), ["Remote Desktop"]);

    // The session ends: dropping the client closes the socket, and the lease's VPN goes down.
    drop(client);
    wait_until("the disconnect", || h.host.count(&format!("disconnect {key}")) == 1);
    wait_until("no holders", || h.server().holders().is_empty());
}

#[test]
fn a_lease_ends_when_its_session_is_closed_from_another_thread() {
    let h = Harness::new();
    let (key, item) = managed("Office");
    h.host.add(item);
    let token = pair(&h, &[&key]);
    let mut lease = Lease::acquire(&h.socket(), &token, &key, |_| {}).expect("connected");
    assert_eq!(lease.connection(), key);
    let closer = lease.closer().unwrap();
    let ender = std::thread::spawn(move || closer.close());
    // Blocks until the other thread ends the session (or sees that it already has).
    assert_eq!(lease.next_change().unwrap(), None);
    ender.join().unwrap();
    wait_until("the disconnect", || h.host.count(&format!("disconnect {key}")) == 1);
}

#[test]
fn release_waits_for_the_disconnect() {
    let h = Harness::new();
    let (key, item) = managed("Office");
    h.host.add(item);
    let token = pair(&h, &[&key]);
    let lease = Lease::acquire(&h.socket(), &token, &key, |_| {}).unwrap();
    lease.release().unwrap();
    assert_eq!(h.host.count(&format!("disconnect {key}")), 1);
}

#[test]
fn a_user_disconnect_is_seen_by_the_holder() {
    let h = Harness::new();
    let (key, item) = managed("Office");
    h.host.add(item);
    let token = pair(&h, &[&key]);
    let mut lease = Lease::acquire(&h.socket(), &token, &key, |_| {}).unwrap();
    h.host.user_disconnect(&key);
    assert_eq!(lease.next_change().unwrap().unwrap().state, State::Disconnecting);
    let down = lease.next_change().unwrap().unwrap();
    assert!(down.state.is_down());
    drop(lease);
    // The user won: nothing reconnects, and the lease end does not disconnect again.
    wait_until("the session end", || h.host.logs().iter().any(|l| l.contains("closed the connection")));
    assert_eq!(h.host.calls(), [format!("connect {key}")]);
}

#[test]
fn a_preexisting_connection_stays_up() {
    let h = Harness::new();
    let (key, item) = managed("Office");
    h.host.add(item);
    h.host.set(&key, connected());
    let token = pair(&h, &[&key]);
    let mut events = Vec::new();
    let lease = Lease::acquire(&h.socket(), &token, &key, |e| events.push(e.clone())).unwrap();
    assert!(events.is_empty(), "already connected: the reply comes at once");
    drop(lease);
    wait_until("the session end", || h.host.logs().iter().any(|l| l.contains("closed the connection")));
    assert!(h.host.calls().is_empty(), "{:?}", h.host.calls());
}

#[test]
fn api_errors_reach_the_caller_as_codes() {
    let h = Harness::new();
    let (key, item) = managed("Office");
    let (other, other_item) = managed("Other");
    h.host.add(item);
    h.host.add(other_item);
    h.host.script(
        &key,
        vec![Step::State(ConnectionState::Connecting), Step::State(ConnectionState::Failed("No route".into()))],
    );
    let token = pair(&h, &[&key]);
    let mut client = Client::open(&h.socket(), &token).unwrap();
    assert_eq!(client.up(&other, |_| {}).unwrap_err().code(), Some(ErrorCode::NotAllowed));
    // Keys are case-sensitive: echo them exactly as `list` returned them.
    assert_eq!(client.up(&key.to_lowercase(), |_| {}).unwrap_err().code(), Some(ErrorCode::NotAllowed));
    match client.up(&key, |_| {}) {
        Err(Error::Api { code: ErrorCode::Failed, wire, message }) => {
            assert_eq!((wire.as_str(), message.as_deref()), ("failed", Some("No route")));
        }
        other => panic!("{other:?}"),
    }
    h.host.setup_missing.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(client.up(&key, |_| {}).unwrap_err().code(), Some(ErrorCode::SetupRequired));
    // The connection is still served after errors.
    assert_eq!(client.list().unwrap().len(), 1);
}

#[test]
fn denied_pairing_and_a_wrong_token() {
    let h = Harness::with_limits(ControlLimits { hello_failure_delay: Duration::from_millis(10), ..fast_limits() });
    h.host.answers.lock().unwrap().push_back(PairingAnswer::Denied);
    assert_eq!(Client::pair(&h.socket(), "Remote Desktop").unwrap_err().code(), Some(ErrorCode::Denied));
    let token = pair(&h, &[]);
    // Another executable path than the paired one: unauthorized (the user re-pairs).
    h.transport.set_executable(Some("/Users/dev/build/Remote Desktop"));
    let err = Client::open(&h.socket(), &token).err().unwrap();
    assert_eq!(err.code(), Some(ErrorCode::Unauthorized));
}

#[test]
fn status_events_are_queued_for_next_event() {
    let h = Harness::new();
    let (key, item) = managed("Office");
    h.host.add(item);
    let token = pair(&h, &[&key]);
    let mut client = Client::open(&h.socket(), &token).unwrap();
    client.status().unwrap();
    h.host.set(&key, connected());
    // A request in between: an event that arrives while it waits for its reply is kept, not lost.
    assert_eq!(client.list().unwrap()[0].state, State::Connected);
    let event = client.next_event().unwrap().unwrap();
    assert_eq!((event.connection.as_str(), event.state), (key.as_str(), State::Connected));
}

#[test]
fn the_closing_event_tells_the_holder_why() {
    use macvpn_app_core::control::StopMode;
    for (mode, reason) in [(StopMode::EndLeases, "disabled"), (StopMode::Detach, "app_quitting")] {
        let mut h = Harness::new();
        let (key, item) = managed("Office");
        h.host.add(item);
        let token = pair(&h, &[&key]);
        let mut lease = Lease::acquire(&h.socket(), &token, &key, |_| {}).unwrap();
        assert_eq!(lease.closing_reason(), None);
        h.server.as_mut().unwrap().stop(mode);
        // The state events of the lease end may come first; then the socket closes, with the reason known.
        while lease.next_change().unwrap().is_some() {}
        assert_eq!(lease.closing_reason(), Some(reason));
        assert_eq!(lease.client().closing_reason(), Some(reason));
    }
}
