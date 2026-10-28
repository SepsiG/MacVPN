//! The control server over a real Unix socket in a short temp directory (Unix) or a real named pipe (Windows), and
//! over TCP loopback (every test runs over both, see `over_both!`), with a fake host whose connections follow a
//! script, and a fake transport (the peer identity is set by the test). The harness is in `control_support`.

mod common;
mod control_support;

use macvpn_app_core::ConnectionItem;
use macvpn_app_core::control::{
    Accepted, ControlHost, ControlLimits, ControlOptions, ControlRelay, ControlServer, ControlTransport, PairingAnswer,
    PairingRequest, PeerUser, StopMode,
};
use macvpn_app_core::deps::SystemVpn;
use macvpn_app_core::manager::{auth_cancelled_reason, auth_timeout_reason};
use macvpn_core::control::protocol::ErrorCode;
use macvpn_core::control::registry::Registry;
use macvpn_core::models::{Connection, ConnectionState, VPNKind, uuid_string};
use serde_json::json;
use std::io::{BufRead, Write};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use control_support::*;

// MARK: - Pairing and hello

fn pair_approved_then_token_works_in_hello(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    let token = h.pair(&[&key]);
    assert_eq!(token.len(), 43);
    let requests = h.host.pairing_requests.lock().unwrap().clone();
    assert_eq!(
        requests,
        [PairingRequest {
            name: "Remote Desktop".into(),
            executable: EXE.into(),
            items: vec![(key.clone(), "Office".into())]
        }]
    );
    // Only the hash is stored; the token is in no file and no log line.
    let saved = std::fs::read_to_string(Registry::path(&h.dir.0)).unwrap();
    assert!(!saved.contains(&token));
    let registry = Registry::load(&h.dir.0).unwrap();
    assert_eq!(registry.clients().len(), 1);
    assert_eq!(registry.clients()[0].allowed, std::slice::from_ref(&key));
    let mut c = h.hello(&token);
    c.send(json!({"id":1,"op":"list"}));
    assert_eq!(c.read()["connections"][0]["id"], key.as_str());
    assert!(h.host.logs().iter().all(|l| !l.contains(&token)), "{:?}", h.host.logs());
    assert!(h.host.logs().iter().any(|l| l.contains("paired “Remote Desktop”") && l.contains(EXE)));
    assert!(Registry::load(&h.dir.0).unwrap().clients()[0].last_used.is_some());
}

fn approved_keys_are_limited_to_the_offered_ones(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    h.pair(&[&key, "00000000-0000-0000-0000-000000000000"]);
    assert_eq!(h.server().clients()[0].allowed, [key]);
}

fn pair_denied_three_times_blocks_pairing(t: Kind) {
    let h = Harness::over(t);
    for answer in [PairingAnswer::Denied, PairingAnswer::TimedOut, PairingAnswer::Denied] {
        h.host.answers.lock().unwrap().push_back(answer);
        let mut c = h.connect();
        c.send(json!({"op":"pair","id":7,"name":"Remote Desktop"}));
        assert_eq!(c.read(), json!({"id":7,"ok":false,"error":"denied"}));
        c.expect_closed();
    }
    h.host.answers.lock().unwrap().push_back(PairingAnswer::Approved(vec![]));
    let mut c = h.connect();
    c.send(json!({"op":"pair","name":"Remote Desktop"}));
    assert_eq!(c.read(), json!({"ok":false,"error":"denied"}));
    assert_eq!(h.host.asks.load(Ordering::SeqCst), 3, "no window while blocked");
    assert!(h.server().clients().is_empty());
    assert!(!Registry::path(&h.dir.0).exists(), "nothing to save");
}

fn a_second_pairing_while_one_is_pending_is_busy(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    h.host.hold_pairing.store(true, Ordering::SeqCst);
    h.host.answers.lock().unwrap().push_back(PairingAnswer::Approved(vec![key]));
    let mut first = h.connect();
    first.send(json!({"op":"pair","name":"Remote Desktop"}));
    wait_until("the pairing window", || h.host.pairing_open.load(Ordering::SeqCst));
    let mut second = h.connect();
    second.send(json!({"op":"pair","name":"Other"}));
    assert_eq!(second.read(), json!({"ok":false,"error":"busy"}));
    second.expect_closed();
    h.host.release_pairing();
    assert_eq!(first.read()["ok"], true);
}

fn wrong_token_is_unauthorized_after_the_delay(t: Kind) {
    let h =
        Harness::over_with_limits(t, ControlLimits { hello_failure_delay: Duration::from_secs(1), ..fast_limits() });
    assert_eq!(ControlLimits::default().hello_failure_delay, Duration::from_secs(1));
    h.pair(&[]);
    let mut c = h.connect();
    let started = Instant::now();
    c.send(json!({"op":"hello","id":1,"token":"A".repeat(43)}));
    assert_eq!(c.read(), json!({"id":1,"ok":false,"error":"unauthorized"}));
    assert!(started.elapsed() >= Duration::from_secs(1), "{:?}", started.elapsed());
    c.expect_closed();
    assert!(h.host.logs().iter().any(|l| l.starts_with("hello failed from") && l.contains(EXE)));
    assert!(h.host.logs().iter().all(|l| !l.contains(&"A".repeat(43))));
}

/// A token that is not 43 base64url characters fails exactly like a wrong one: `unauthorized` after the same
/// delay, the connection closed, and "hello failed" in the audit. The reply never says which part was wrong.
fn a_malformed_token_fails_like_a_wrong_one(t: Kind) {
    let delay = Duration::from_millis(300);
    let h = Harness::over_with_limits(t, ControlLimits { hello_failure_delay: delay, ..fast_limits() });
    h.pair(&[]);
    let long = "A".repeat(44);
    let padded = format!("{}=", "A".repeat(42));
    for (n, token) in ["", "short", &long, &padded, "A+/".repeat(15).as_str()].into_iter().enumerate() {
        let failures = h.host.logs().iter().filter(|l| l.starts_with("hello failed from")).count();
        let mut c = h.connect();
        let started = Instant::now();
        c.send(json!({"op":"hello","id":n,"token":token}));
        assert_eq!(c.read(), json!({"id":n,"ok":false,"error":"unauthorized"}), "{token:?}");
        assert!(started.elapsed() >= delay, "{token:?}: {:?}", started.elapsed());
        c.expect_closed();
        let logs = h.host.logs();
        assert_eq!(logs.iter().filter(|l| l.starts_with("hello failed from")).count(), failures + 1, "{token:?}");
        assert!(token.len() < 3 || logs.iter().all(|l| !l.contains(token)), "{token:?}");
    }
    assert!(h.server().path_changes().is_empty());
    // A structurally invalid hello is still `bad_request`, at once, and the connection stays open.
    let mut c = h.connect();
    c.send(json!({"op":"hello","id":9,"token":5}));
    assert_eq!(c.read(), json!({"id":9,"ok":false,"error":"bad_request"}));
    c.send(json!({"op":"hello","id":10,"token":"A".repeat(43),"extra":1}));
    assert_eq!(c.read(), json!({"id":10,"ok":false,"error":"bad_request"}));
    c.send(json!({"op":"hello","id":11,"token":"A".repeat(43)}));
    assert_eq!(c.read(), json!({"id":11,"ok":false,"error":"unauthorized"}));
    c.expect_closed();
}

fn another_executable_path_is_unauthorized(t: Kind) {
    let h = Harness::over(t);
    let token = h.pair(&[]);
    h.transport.set_executable(Some("/Users/dev/build/Remote Desktop"));
    let mut c = h.connect();
    c.send(json!({"op":"hello","token":token}));
    assert_eq!(c.read(), json!({"ok":false,"error":"unauthorized"}));
    c.expect_closed();
    // No path at all: the same.
    h.transport.set_executable(None);
    let mut c = h.connect();
    c.send(json!({"op":"hello","token":token}));
    assert_eq!(c.read(), json!({"ok":false,"error":"unauthorized"}));
}

fn a_moved_executable_is_flagged_until_a_good_hello(t: Kind) {
    let h = Harness::over(t);
    let token = h.pair(&[]);
    let id = h.server().clients()[0].id;
    assert!(h.server().path_changes().is_empty());
    // A wrong token from another path flags nothing.
    h.transport.set_executable(Some("/Users/dev/build/Remote Desktop"));
    let mut c = h.connect();
    c.send(json!({"op":"hello","token":"A".repeat(43)}));
    assert_eq!(c.read()["error"], "unauthorized");
    assert!(h.server().path_changes().is_empty());
    // The right token from another path: unauthorized, and flagged with the new path.
    let mut c = h.connect();
    c.send(json!({"op":"hello","token":token}));
    assert_eq!(c.read(), json!({"ok":false,"error":"unauthorized"}));
    assert_eq!(h.server().path_changes().get(&id).map(String::as_str), Some("/Users/dev/build/Remote Desktop"));
    assert!(h.host.logs().iter().any(|l| l.contains("not the executable it was paired from")));
    assert!(h.host.logs().iter().all(|l| !l.contains(&token)));
    // Back at the pinned path: the flag goes.
    h.transport.set_executable(Some(EXE));
    let _c = h.hello(&token);
    assert!(h.server().path_changes().is_empty());
    // Flagged again, then revoked: gone with the client.
    h.transport.set_executable(Some("/tmp/rd"));
    let mut c = h.connect();
    c.send(json!({"op":"hello","token":token}));
    assert_eq!(c.read()["error"], "unauthorized");
    assert_eq!(h.server().path_changes().len(), 1);
    assert!(h.server().revoke(id).unwrap());
    assert!(h.server().path_changes().is_empty());
}

fn a_peer_of_another_user_is_closed_at_once(t: Kind) {
    let h = Harness::over(t);
    h.transport.peer.same_user.store(false, Ordering::SeqCst);
    let mut c = h.connect();
    c.send(json!({"op":"pair","name":"x"}));
    c.expect_closed();
    assert_eq!(h.host.asks.load(Ordering::SeqCst), 0);
    // The 1.4.0 audit line, word for word.
    let line = format!("closed a connection from another user ({}, pid 4242)", peer_user(t));
    assert!(h.host.logs().contains(&line), "{:?}", h.host.logs());
    assert!(h.server().holders().is_empty());
}

fn requests_before_hello_are_unauthorized(t: Kind) {
    let h = Harness::over(t);
    let mut c = h.connect();
    c.send(json!({"id":3,"op":"list"}));
    assert_eq!(c.read(), json!({"id":3,"ok":false,"error":"unauthorized"}));
    c.expect_closed();
}

fn malformed_and_unknown_requests_get_their_codes(t: Kind) {
    let h = Harness::over(t);
    let mut c = h.authed(&[]);
    c.send(json!({"id":4,"op":"reboot"}));
    assert_eq!(c.read(), json!({"id":4,"ok":false,"error":"unsupported"}));
    c.send(json!({"id":5,"op":"list","extra":1}));
    assert_eq!(c.read(), json!({"id":5,"ok":false,"error":"bad_request"}));
    c.send(json!({"id":6,"op":"up","connection":"not-a-uuid"}));
    assert_eq!(c.read(), json!({"id":6,"ok":false,"error":"bad_request"}));
    // Still served.
    c.send(json!({"id":7,"op":"list"}));
    assert_eq!(c.read(), json!({"id":7,"ok":true,"connections":[]}));
    // An over-long line ends the connection.
    c.send_raw(&format!("{}\n", "x".repeat(5000)));
    assert_eq!(c.read(), json!({"ok":false,"error":"bad_request"}));
    c.expect_closed();
}

// MARK: - list / up / down

fn list_shows_only_the_allowed_connections_in_order(t: Kind) {
    let h = Harness::over(t);
    let (a, item_a) = managed("Alpha");
    let (b, item_b) = managed("Beta");
    h.host.add(item_a);
    h.host.add(item_b);
    h.host.add(ConnectionItem::System(SystemVpn::new(SYSTEM_KEY, "Office L2TP", "L2TP", "Connected")));
    h.host.add(ConnectionItem::System(SystemVpn::new("not-a-uuid", "Odd", "VPN", "Disconnected")));
    h.host.set(SYSTEM_KEY, connected());
    let mut c = h.authed(&[SYSTEM_KEY, &a, "not-a-uuid"]);
    c.send(json!({"id":1,"op":"list"}));
    assert_eq!(
        c.read(),
        json!({"id":1,"ok":true,"connections":[
            {"id":a,"name":"Alpha","kind":"openvpn","state":"disconnected"},
            {"id":SYSTEM_KEY,"name":"Office L2TP","kind":"system","state":"connected"},
        ]})
    );
    assert!(!c.read_nothing_pending(&b));
}

fn up_streams_progress_then_replies_connected(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    h.host.script(
        &key,
        vec![
            Step::State(ConnectionState::Connecting),
            Step::State(awaiting()),
            Step::State(ConnectionState::Connecting),
            Step::State(connected()),
        ],
    );
    let mut c = h.authed(&[&key]);
    c.send(json!({"id":2,"op":"up","connection":key}));
    let (events, reply) = c.reply_to(2);
    assert_eq!(states(&events), ["connecting", "waiting_for_mfa", "connecting", "connected"]);
    assert_eq!(events[0], json!({"event":"state","connection":key,"state":"connecting"}));
    assert_eq!(reply, json!({"id":2,"ok":true,"state":"connected"}));
    assert_eq!(h.host.calls(), [format!("connect {key}")]);
    assert_eq!(h.server().holders().get(&key).cloned(), Some(vec!["Remote Desktop".to_string()]));
    assert_eq!(h.server().holder_names(), ["Remote Desktop"]);
}

fn up_checks_allowlist_existence_and_setup(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    let (other, other_item) = managed("Other");
    h.host.add(item);
    h.host.add(other_item);
    let mut c = h.authed(&[&key]);
    // An allowed key that no longer exists (the connection was deleted).
    let id = h.server().clients()[0].id;
    h.server().set_allowed(id, vec![key.clone(), "00000000-0000-0000-0000-000000000001".into()]).unwrap();
    c.send(json!({"id":1,"op":"up","connection":other}));
    assert_eq!(c.read(), json!({"id":1,"ok":false,"error":"not_allowed"}));
    c.send(json!({"id":2,"op":"up","connection":"00000000-0000-0000-0000-000000000001"}));
    assert_eq!(c.read(), json!({"id":2,"ok":false,"error":"unknown_connection"}));
    // Keys are case-sensitive.
    c.send(json!({"id":3,"op":"up","connection":key.to_lowercase()}));
    assert_eq!(c.read(), json!({"id":3,"ok":false,"error":"not_allowed"}));
    h.host.setup_missing.store(true, Ordering::SeqCst);
    c.send(json!({"id":4,"op":"up","connection":key}));
    assert_eq!(c.read(), json!({"id":4,"ok":false,"error":"setup_required"}));
    assert!(h.host.calls().is_empty());
}

/// Without a VPN engine (WinVPN 2a) every `up` that has to start a connection, of any type, is `failed` with the
/// engine's answer as the message, and nothing starts (not `setup_required`: there is nothing to set up). A
/// connection that is already up would be joined as usual (none can be, without an engine).
fn without_an_engine_up_fails_with_the_engine_note(t: Kind) {
    let h = Harness::over(t);
    let (openvpn, item) = managed("Office");
    h.host.add(item);
    let l2tp_conn = Connection::new("Branch", VPNKind::L2tp);
    let l2tp = uuid_string(&l2tp_conn.id);
    h.host.add(ConnectionItem::Managed(l2tp_conn));
    h.host.add(ConnectionItem::System(SystemVpn::new(SYSTEM_KEY, "Office IKEv2", "IKEv2", "Disconnected")));
    let mut c = h.authed(&[&openvpn, &l2tp, SYSTEM_KEY]);
    *h.host.engine_missing.lock().unwrap() = Some("Later.".into());
    for (id, key) in [(1, &openvpn), (2, &l2tp), (3, &SYSTEM_KEY.to_string())] {
        c.send(json!({"id":id,"op":"up","connection":key}));
        assert_eq!(c.read(), json!({"id":id,"ok":false,"error":"failed","message":"Later."}));
    }
    assert!(h.host.calls().is_empty());
}

/// WinVPN 2b: an `up` of a kind that comes later (a native VPN) is `failed` with the kind's reason, and nothing
/// starts; the other kinds are not affected.
fn a_later_kind_fails_with_its_reason(t: Kind) {
    let h = Harness::over(t);
    let l2tp_conn = Connection::new("Branch", VPNKind::L2tp);
    let l2tp = uuid_string(&l2tp_conn.id);
    h.host.add(ConnectionItem::Managed(l2tp_conn));
    let mut c = h.authed(&[&l2tp]);
    h.host.later.lock().unwrap().insert(l2tp.clone(), "Later.".into());
    c.send(json!({"id":1,"op":"up","connection":l2tp}));
    assert_eq!(c.read(), json!({"id":1,"ok":false,"error":"failed","message":"Later."}));
    assert!(h.host.calls().is_empty());
}

/// `setup_required` only for a connection that needs Homebrew and the root layer to start: a system VPN and a
/// native L2TP / Cisco connection start without them, and a connection that is already up (or already coming up
/// for another lease) is joined without any setup check.
fn setup_required_only_when_the_connect_needs_the_setup(t: Kind) {
    let h = Harness::over(t);
    let (openvpn, item) = managed("Office");
    h.host.add(item);
    let l2tp_conn = Connection::new("Branch", VPNKind::L2tp);
    let l2tp = uuid_string(&l2tp_conn.id);
    h.host.add(ConnectionItem::Managed(l2tp_conn));
    h.host.add(ConnectionItem::System(SystemVpn::new(SYSTEM_KEY, "Office IKEv2", "IKEv2", "Disconnected")));
    let (up_already, up_item) = managed("Already up");
    h.host.add(up_item);
    h.host.set(&up_already, connected());
    let mut c = h.authed(&[&openvpn, &l2tp, SYSTEM_KEY, &up_already]);
    h.host.setup_missing.store(true, Ordering::SeqCst);

    // A root-layer connection that is down: nothing starts.
    c.send(json!({"id":1,"op":"up","connection":openvpn}));
    assert_eq!(c.read(), json!({"id":1,"ok":false,"error":"setup_required"}));
    assert_eq!(h.host.count(&format!("connect {openvpn}")), 0);
    // A system VPN and a native connection start.
    c.send(json!({"id":2,"op":"up","connection":SYSTEM_KEY}));
    assert_eq!(c.reply_to(2).1, json!({"id":2,"ok":true,"state":"connected"}));
    c.send(json!({"id":3,"op":"up","connection":l2tp}));
    assert_eq!(c.reply_to(3).1, json!({"id":3,"ok":true,"state":"connected"}));
    // Already up (pre-existing): `connected` at once, and the lease is pre-existing (never disconnected).
    c.send(json!({"id":4,"op":"up","connection":up_already}));
    assert_eq!(c.read(), json!({"id":4,"ok":true,"state":"connected"}));
    assert_eq!(h.host.count(&format!("connect {up_already}")), 0);

    // A connection another client brought up while the setup was complete: joining it needs no setup.
    h.host.setup_missing.store(false, Ordering::SeqCst);
    let mut other = h.authed(&[&openvpn]);
    other.send(json!({"id":1,"op":"up","connection":openvpn}));
    assert_eq!(other.reply_to(1).1["ok"], true);
    h.host.setup_missing.store(true, Ordering::SeqCst);
    c.send(json!({"id":5,"op":"up","connection":openvpn}));
    assert_eq!(c.reply_to(5).1, json!({"id":5,"ok":true,"state":"connected"}));
    assert_eq!(h.host.count(&format!("connect {openvpn}")), 1);

    c.send(json!({"id":6,"op":"down","connection":up_already}));
    assert_eq!(c.reply_to(6).1["ok"], true);
    assert_eq!(h.host.count(&format!("disconnect {up_already}")), 0);
}

fn down_releases_and_disconnects(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    let mut c = h.authed(&[&key]);
    c.send(json!({"id":1,"op":"up","connection":key}));
    c.reply_to(1);
    c.send(json!({"id":2,"op":"down","connection":key}));
    let (events, reply) = c.reply_to(2);
    assert_eq!(reply, json!({"id":2,"ok":true}));
    // A holder sees its own connection go down while it still holds it ... and no more once released.
    assert!(states(&events).iter().all(|s| *s != "connected"));
    assert_eq!(h.host.count(&format!("disconnect {key}")), 1);
    assert!(h.server().holders().is_empty());
    assert!(h.host.logs().iter().any(|l| l.starts_with(&format!("down {key} by “Remote Desktop”"))));
}

/// Locked (1.2): `pair`, `hello`, `list`, `up` and `status` answer `locked`; the session and its lease stay, and
/// `down` still releases; after the unlock `hello` works again.
fn locked_refuses_everything_but_down(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    let token = h.pair(&[&key]);
    let mut c = h.hello(&token);
    c.send(json!({"id":1,"op":"up","connection":key}));
    c.reply_to(1);
    h.host.locked.store(true, Ordering::SeqCst);
    for (id, op) in [(2, json!({"id":2,"op":"list"})), (3, json!({"id":3,"op":"status"}))] {
        c.send(op);
        assert_eq!(c.reply_to(id).1, json!({"id":id,"ok":false,"error":"locked"}));
    }
    c.send(json!({"id":4,"op":"up","connection":key}));
    assert_eq!(c.reply_to(4).1, json!({"id":4,"ok":false,"error":"locked"}));
    // A new client: `hello` and `pair` are refused and the connection ends.
    let mut other = h.connect();
    other.send(json!({"id":1,"op":"hello","token":token}));
    assert_eq!(other.read(), json!({"id":1,"ok":false,"error":"locked"}));
    other.expect_closed();
    let mut pairing = h.connect();
    pairing.send(json!({"op":"pair","name":"Other"}));
    assert_eq!(pairing.read(), json!({"ok":false,"error":"locked"}));
    pairing.expect_closed();
    assert_eq!(h.host.asks.load(Ordering::SeqCst), 1, "no pairing window while locked");
    // The lease survived the lock; `down` releases it.
    assert_eq!(h.server().holders().len(), 1);
    c.send(json!({"id":5,"op":"down","connection":key}));
    assert_eq!(c.reply_to(5).1, json!({"id":5,"ok":true}));
    assert_eq!(h.host.count(&format!("disconnect {key}")), 1);
    // Unlocked: `hello` works again.
    h.host.locked.store(false, Ordering::SeqCst);
    let mut again = h.hello(&token);
    again.send(json!({"id":1,"op":"list"}));
    assert_eq!(again.read()["connections"][0]["id"], key.as_str());
}

fn client_eof_disconnects(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    let mut c = h.authed(&[&key]);
    c.send(json!({"id":1,"op":"up","connection":key}));
    c.reply_to(1);
    c.close();
    wait_until("the disconnect", || h.host.count(&format!("disconnect {key}")) == 1);
    wait_until("the lease end log", || h.host.logs().iter().any(|l| l.contains("ended: connection closed")));
}

fn client_killed_mid_connect_disconnects(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    h.host.script(&key, vec![Step::State(ConnectionState::Connecting), Step::Pause, Step::State(connected())]);
    let mut c = h.authed(&[&key]);
    c.send(json!({"id":1,"op":"up","connection":key}));
    assert_eq!(c.read()["state"], "connecting");
    wait_until("the paused connect", || h.host.is_paused(&key));
    c.close();
    wait_until("the disconnect", || h.host.count(&format!("disconnect {key}")) == 1);
    h.host.resume(&key);
}

fn two_clients_disconnect_only_after_both_close(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    let token = h.pair(&[&key]);
    let mut first = h.hello(&token);
    let mut second = h.hello(&token);
    first.send(json!({"id":1,"op":"up","connection":key}));
    first.reply_to(1);
    second.send(json!({"id":1,"op":"up","connection":key}));
    assert_eq!(second.read(), json!({"id":1,"ok":true,"state":"connected"}));
    assert_eq!(h.host.count(&format!("connect {key}")), 1);
    first.close();
    wait_until("the first lease end", || {
        h.host.logs().iter().filter(|l| l.contains("ended: connection closed")).count() == 1
    });
    assert_eq!(h.host.count(&format!("disconnect {key}")), 0);
    second.close();
    wait_until("the disconnect", || h.host.count(&format!("disconnect {key}")) == 1);
}

fn a_second_client_joins_a_connect_in_progress(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    h.host.script(&key, vec![Step::State(ConnectionState::Connecting), Step::Pause, Step::State(connected())]);
    let token = h.pair(&[&key]);
    let mut first = h.hello(&token);
    let mut second = h.hello(&token);
    first.send(json!({"id":1,"op":"up","connection":key}));
    wait_until("the paused connect", || h.host.is_paused(&key));
    // Leased: not busy, it waits for the same connect.
    second.send(json!({"id":9,"op":"up","connection":key}));
    assert_eq!(second.read()["state"], "connecting");
    h.host.resume(&key);
    assert_eq!(first.reply_to(1).1["ok"], true);
    assert_eq!(second.reply_to(9).1, json!({"id":9,"ok":true,"state":"connected"}));
    assert_eq!(h.host.count(&format!("connect {key}")), 1);
}

fn a_preexisting_connection_is_not_disconnected(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    h.host.set(&key, connected());
    let mut c = h.authed(&[&key]);
    c.send(json!({"id":1,"op":"up","connection":key}));
    assert_eq!(c.read(), json!({"id":1,"ok":true,"state":"connected"}));
    c.send(json!({"id":2,"op":"down","connection":key}));
    assert_eq!(c.reply_to(2).1["ok"], true);
    c.close();
    wait_until("the session end", || h.host.logs().iter().any(|l| l.contains("closed the connection")));
    assert!(h.host.calls().is_empty(), "{:?}", h.host.calls());
}

fn a_connecting_key_without_a_lease_is_busy(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    let mut c = h.authed(&[&key]);
    for (n, state) in [ConnectionState::Connecting, ConnectionState::Disconnecting, awaiting()].into_iter().enumerate()
    {
        h.host.set(&key, state);
        c.send(json!({"id":n,"op":"up","connection":key}));
        assert_eq!(c.read(), json!({"id":n,"ok":false,"error":"busy"}));
    }
    assert!(h.host.calls().is_empty());
    assert!(h.server().holders().is_empty());
}

fn a_synchronous_connect_error_fails_and_ends_the_lease(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    h.host.sync_errors.lock().unwrap().insert(key.clone(), ErrorCode::UnknownConnection);
    let mut c = h.authed(&[&key]);
    c.send(json!({"id":1,"op":"up","connection":key}));
    assert_eq!(c.reply_to(1).1, json!({"id":1,"ok":false,"error":"unknown_connection"}));
    assert!(h.server().holders().is_empty());
    // The lease is gone, so the next `up` connects again.
    c.send(json!({"id":2,"op":"up","connection":key}));
    assert_eq!(c.reply_to(2).1, json!({"id":2,"ok":true,"state":"connected"}));
    assert_eq!(h.host.count(&format!("connect {key}")), 2);
}

fn a_failed_connect_replies_failed_and_a_later_up_reconnects(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    h.host.script(
        &key,
        vec![Step::State(ConnectionState::Connecting), Step::State(ConnectionState::Failed("No route".into()))],
    );
    let mut c = h.authed(&[&key]);
    c.send(json!({"id":1,"op":"up","connection":key}));
    let (events, reply) = c.reply_to(1);
    assert_eq!(states(&events), ["connecting", "failed"]);
    assert_eq!(events[1]["reason"], "No route");
    assert_eq!(reply, json!({"id":1,"ok":false,"error":"failed","message":"No route"}));
    assert!(h.server().holders().is_empty());
    c.send(json!({"id":2,"op":"up","connection":key}));
    assert_eq!(c.reply_to(2).1, json!({"id":2,"ok":true,"state":"connected"}));
    assert_eq!(h.host.count(&format!("connect {key}")), 2);
    // That lease is the client's: closing ends it.
    c.close();
    wait_until("the disconnect", || h.host.count(&format!("disconnect {key}")) == 1);
}

fn mfa_timeout_and_cancel_get_their_codes(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    let mut c = h.authed(&[&key]);
    let cases = [
        (vec![Step::State(awaiting()), Step::State(ConnectionState::Failed(auth_timeout_reason()))], "mfa_timeout"),
        (vec![Step::State(awaiting()), Step::State(ConnectionState::Failed(auth_cancelled_reason()))], "mfa_cancelled"),
        // A cancelled code prompt before connecting ends `disconnected` (the manager's `abandon_connect`).
        (
            vec![
                Step::State(awaiting()),
                Step::State(ConnectionState::Connecting),
                Step::State(ConnectionState::Disconnected),
            ],
            "mfa_cancelled",
        ),
        (vec![Step::State(ConnectionState::Connecting), Step::State(ConnectionState::Disconnected)], "failed"),
    ];
    for (n, (steps, code)) in cases.into_iter().enumerate() {
        h.host.script(&key, steps);
        c.send(json!({"id":n,"op":"up","connection":key}));
        let (_, reply) = c.reply_to(n as u64);
        assert_eq!(reply["error"], code, "{reply}");
        assert!(h.server().holders().is_empty());
    }
}

fn up_waits_for_credentials_then_connects(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    h.host.script(
        &key,
        vec![
            Step::State(ConnectionState::Connecting),
            Step::State(awaiting_credentials()),
            Step::State(ConnectionState::Connecting),
            Step::State(connected()),
        ],
    );
    let mut c = h.authed(&[&key]);
    c.send(json!({"id":2,"op":"up","connection":key}));
    let (events, reply) = c.reply_to(2);
    assert_eq!(states(&events), ["connecting", "waiting_for_credentials", "connecting", "connected"]);
    assert_eq!(reply, json!({"id":2,"ok":true,"state":"connected"}));
}

fn cancelled_credentials_get_their_code_and_release_the_lease(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    let mut c = h.authed(&[&key]);
    let cases = [
        (
            vec![
                Step::State(awaiting_credentials()),
                Step::CredentialsCancelled,
                Step::State(ConnectionState::Connecting),
                Step::State(ConnectionState::Disconnected),
            ],
            "credentials_cancelled",
        ),
        (
            vec![
                Step::State(awaiting_credentials()),
                Step::CredentialsCancelled,
                Step::State(ConnectionState::Disconnected),
            ],
            "credentials_cancelled",
        ),
        // Credentials given, then the tunnel did not come up: a plain failure, not a cancel.
        (
            vec![
                Step::State(awaiting_credentials()),
                Step::State(ConnectionState::Connecting),
                Step::State(ConnectionState::Disconnected),
            ],
            "failed",
        ),
        // Credentials given, then the MFA code prompt cancelled.
        (
            vec![
                Step::State(awaiting_credentials()),
                Step::State(ConnectionState::Connecting),
                Step::State(awaiting()),
                Step::State(ConnectionState::Connecting),
                Step::State(ConnectionState::Disconnected),
            ],
            "mfa_cancelled",
        ),
    ];
    for (n, (steps, code)) in cases.into_iter().enumerate() {
        h.host.script(&key, steps);
        c.send(json!({"id":n,"op":"up","connection":key}));
        let (events, reply) = c.reply_to(n as u64);
        assert!(states(&events).contains(&"waiting_for_credentials"), "{events:?}");
        assert_eq!(reply["error"], code, "{reply}");
        assert!(h.server().holders().is_empty(), "no leftover holder");
    }
}

fn user_disconnect_ends_the_lease_without_reconnect(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    let mut c = h.authed(&[&key]);
    c.send(json!({"id":1,"op":"up","connection":key}));
    c.reply_to(1);
    h.host.user_disconnect(&key);
    assert_eq!(c.read(), json!({"event":"state","connection":key,"state":"disconnecting"}));
    assert_eq!(c.read(), json!({"event":"state","connection":key,"state":"disconnected"}));
    assert!(h.server().holders().is_empty());
    // Nothing reconnects, and closing the socket does not disconnect again.
    c.close();
    wait_until("the session end", || h.host.logs().iter().any(|l| l.contains("closed the connection")));
    assert_eq!(h.host.calls(), [format!("connect {key}")]);
    assert!(h.host.logs().iter().any(|l| l.contains("ended: disconnected by the user")));
}

fn user_disconnect_during_up_answers_it(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    h.host.script(&key, vec![Step::State(ConnectionState::Connecting), Step::Pause]);
    let mut c = h.authed(&[&key]);
    c.send(json!({"id":1,"op":"up","connection":key}));
    wait_until("the paused connect", || h.host.is_paused(&key));
    h.host.user_disconnect(&key);
    let (_, reply) = c.reply_to(1);
    assert_eq!(reply["error"], "failed");
    assert!(reply["message"].is_string());
    h.host.resume(&key);
}

fn a_drop_is_reported_to_the_holders(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    let mut c = h.authed(&[&key]);
    c.send(json!({"id":1,"op":"up","connection":key}));
    c.reply_to(1);
    h.host.set(&key, ConnectionState::Failed("The connection dropped".into()));
    assert_eq!(c.read(), json!({"event":"state","connection":key,"state":"failed","reason":"The connection dropped"}));
    assert!(h.server().holders().is_empty());
}

fn status_subscribes_to_the_allowed_connections(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    let (other, other_item) = managed("Other");
    h.host.add(item);
    h.host.add(other_item);
    let mut c = h.authed(&[&key]);
    c.send(json!({"id":1,"op":"status"}));
    assert_eq!(c.read(), json!({"id":1,"ok":true}));
    h.host.set(&other, connected());
    h.host.set(&key, connected());
    h.host.set(&key, connected()); // a repeat is not sent again
    h.host.set(&key, ConnectionState::Disconnected);
    assert_eq!(c.read(), json!({"event":"state","connection":key,"state":"connected"}));
    assert_eq!(c.read(), json!({"event":"state","connection":key,"state":"disconnected"}));
}

fn revoke_closes_the_socket_and_disconnects(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    let token = h.pair(&[&key]);
    let mut c = h.hello(&token);
    c.send(json!({"id":1,"op":"up","connection":key}));
    c.reply_to(1);
    let id = h.server().clients()[0].id;
    assert!(h.server().revoke(id).unwrap());
    c.expect_closed();
    wait_until("the disconnect", || h.host.count(&format!("disconnect {key}")) == 1);
    assert!(Registry::load(&h.dir.0).unwrap().clients().is_empty());
    let mut again = h.connect();
    again.send(json!({"op":"hello","token":token}));
    assert_eq!(again.read()["error"], "unauthorized");
}

// MARK: - Limits

fn the_ninth_client_is_refused(t: Kind) {
    let h = Harness::over(t);
    let clients: Vec<TestClient> = (0..8).map(|_| h.connect()).collect();
    // The accept thread registers them in order; wait for all eight before the ninth.
    let mut probe = clients;
    for c in probe.iter_mut() {
        c.send(json!({"id":1,"op":"reboot"}));
        assert_eq!(c.read()["error"], "unsupported");
    }
    let mut ninth = h.connect();
    ninth.expect_closed();
    assert!(h.host.logs().iter().any(|l| l.contains("too many clients")));
    drop(probe);
}

fn a_silent_client_is_closed_after_the_auth_timeout(t: Kind) {
    let h = Harness::over_with_limits(t, short_auth_limits());
    let started = Instant::now();
    let mut c = h.connect();
    c.expect_closed();
    assert!(started.elapsed() >= SHORT_AUTH_TIMEOUT);
    wait_until("the log line", || h.host.logs().iter().any(|l| l.contains("no pair or hello in time")));
}

fn a_connection_that_says_nothing_and_closes_is_not_logged(t: Kind) {
    // The harness's long deadline: only the close can end the silent connection.
    let h = Harness::over(t);
    let before = h.host.logs().len();
    let c = h.connect();
    c.close();
    // Then a client that does talk, so the first one has certainly been handled.
    let mut probe = h.connect();
    probe.send(json!({"id":1,"op":"reboot"}));
    probe.read();
    probe.close();
    wait_until("the probe's close", || h.host.logs().iter().any(|l| l.contains("closed the connection")));
    let logs = h.host.logs();
    assert_eq!(logs.len() - before, 1, "{logs:?}");
}

fn a_flood_is_closed(t: Kind) {
    let h = Harness::over(t);
    let mut c = h.authed(&[]);
    let burst: String = (0..40).map(|n| format!("{{\"id\":{n},\"op\":\"list\"}}\n")).collect();
    c.send_raw(&burst);
    let mut replies = 0;
    loop {
        let mut line = String::new();
        match c.reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => replies += 1,
        }
    }
    assert!(replies <= 20, "{replies}");
    assert!(h.host.logs().iter().any(|l| l.contains("too many requests")));
}

// MARK: - Stop, quit, registry

fn stop_closes_everything_and_removes_the_socket(t: Kind) {
    let mut h = Harness::over(t);
    let (key, item) = managed("Office");
    let (slow, slow_item) = managed("Slow");
    h.host.add(item);
    h.host.add(slow_item);
    h.host.script(&slow, vec![Step::State(ConnectionState::Connecting), Step::Pause]);
    let mut c = h.authed(&[&key, &slow]);
    c.send(json!({"id":1,"op":"up","connection":key}));
    c.reply_to(1);
    c.send(json!({"id":2,"op":"up","connection":slow}));
    wait_until("the paused connect", || h.host.is_paused(&slow));
    let resumer = {
        let host = h.host.clone();
        let slow = slow.clone();
        std::thread::spawn(move || {
            wait_until("the slow disconnect", || host.count(&format!("disconnect {slow}")) == 1);
            host.resume(&slow);
        })
    };
    let mut unauthenticated = h.connect();
    h.server.as_mut().unwrap().stop(StopMode::EndLeases);
    let (_, reply) = c.reply_to(2);
    assert_eq!(reply, json!({"id":2,"ok":false,"error":"disabled"}));
    // One last event before the close, so the client knows why (only to an authenticated client).
    assert_eq!(c.read(), json!({"event":"closing","reason":"disabled"}));
    c.expect_closed();
    unauthenticated.expect_closed();
    assert!(!h.socket().exists());
    // The leases ended before stop returned.
    assert_eq!(h.host.count(&format!("disconnect {key}")), 1);
    resumer.join().unwrap();
    assert!(h.try_connect().is_err());
    // It can be started again.
    h.start(fast_limits());
    assert!(h.socket().exists());
}

fn a_registry_that_cannot_be_read_stops_the_start_and_is_kept(t: Kind) {
    let dir = Scratch::new();
    std::fs::create_dir(Registry::path(&dir.0)).unwrap();
    let mut options = ControlOptions::new(dir.0.join("control"), dir.0.clone());
    options.limits = fast_limits();
    let result = ControlServer::start(options, Arc::new(FakeHost::default()), FakeTransport::over(t));
    assert!(result.is_err());
    assert!(Registry::path(&dir.0).is_dir());
    assert!(!dir.0.join("control/macvpn.sock").exists());
}

// MARK: - Review fixes

/// The connect gap: the lease's connect has not reached the manager yet when the lease ends. The disconnect must
/// wait for it, otherwise the connect starts afterwards and the VPN comes up with no lease.
fn connect_gap(t: Kind, end: impl FnOnce(&Harness, &mut TestClient, &str)) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    h.host.script(&key, vec![Step::Pause, Step::State(ConnectionState::Connecting), Step::State(connected())]);
    let mut c = h.authed(&[&key]);
    c.send(json!({"id":1,"op":"up","connection":key}));
    wait_until("the paused connect", || h.host.is_paused(&key));
    end(&h, &mut c, &key);
    // Let the disconnect start (it must wait), then let the connect reach the manager.
    std::thread::sleep(Duration::from_millis(30));
    h.host.resume(&key);
    wait_until("the connect to return", || h.host.connects_done.load(Ordering::SeqCst) == 1);
    wait_until("the disconnect", || h.host.count(&format!("disconnect {key}")) == 1);
    wait_until("the connection down", || h.host.state(&key) == ConnectionState::Disconnected);
    assert!(h.server().holders().is_empty());
}

fn down_of_the_key_in_the_connect_gap_leaves_nothing_up(t: Kind) {
    connect_gap(t, |_, c, key| {
        c.send(json!({"id":2,"op":"down","connection":key}));
    });
}

fn close_in_the_connect_gap_leaves_nothing_up(t: Kind) {
    connect_gap(t, |_, c, _| {
        let _ = c.stream.shutdown(std::net::Shutdown::Both);
    });
}

/// The harness's limits give a client that is slow to speak (a loaded CI runner or VM descheduling the test thread
/// between its connect and its `hello`) plenty of time: only the auth deadline tests use a short one
/// (`short_auth_limits`). With a 300 ms deadline for every test, `hello` raced the deadline under load and the
/// server closed the connection with the line unread (Windows: os error 10053 at the client's read).
fn a_client_slow_to_say_hello_is_not_closed_by_the_test_limits(t: Kind) {
    let h = Harness::over(t);
    let token = h.pair(&[]);
    let mut c = h.connect();
    std::thread::sleep(Duration::from_millis(600));
    c.send(json!({"op":"hello","token":token}));
    assert_eq!(c.read(), json!({"ok":true,"api":1}));
}

/// The auth deadline ends at `hello`: an authenticated client that stays quiet for longer is still served (the
/// reader's clone of the stream must see the timeout cleared).
fn an_authenticated_client_outlives_the_auth_deadline(t: Kind) {
    let h = Harness::over_with_limits(t, short_auth_limits());
    let mut c = h.authed(&[]);
    std::thread::sleep(SHORT_AUTH_TIMEOUT * 2);
    c.send(json!({"id":1,"op":"list"}));
    assert_eq!(c.reply_to(1).1["ok"], true);
    assert!(!h.host.logs().iter().any(|l| l.contains("no pair or hello in time")), "{:?}", h.host.logs());
}

/// `stop` closes a client that has not said `hello` yet at once: it does not wait for the client's auth deadline
/// (the shutdown must wake the session's blocked read).
fn stop_does_not_wait_for_the_auth_deadline_of_a_silent_client(t: Kind) {
    let mut h = Harness::over(t);
    let mut silent = h.connect();
    // Answered, so its session is up and back in its read (with the harness's 30 s auth deadline).
    silent.send(json!({"id":1,"op":"reboot"}));
    assert_eq!(silent.read()["error"], "unsupported");
    let started = Instant::now();
    h.server.as_mut().unwrap().stop(StopMode::EndLeases);
    let took = started.elapsed();
    assert!(took < fast_limits().stop_timeout / 2, "stop took {took:?}");
    silent.expect_closed();
}

fn a_dripping_client_is_closed_at_the_auth_deadline(t: Kind) {
    let h = Harness::over_with_limits(t, short_auth_limits());
    let mut c = h.connect();
    let started = Instant::now();
    let mut closed = false;
    // Until the generous WAIT (the auth deadline is 300 ms here; without it a dripping client stays open for good).
    while started.elapsed() < WAIT {
        // One byte at a time, well inside the per-read timeout but never a full line.
        if c.stream.write_all(b"{").is_err() {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
        if h.host.logs().iter().any(|l| l.contains("no pair or hello in time")) {
            closed = true;
            break;
        }
    }
    assert!(closed, "still open after {:?}", started.elapsed());
    c.expect_closed();
}

fn the_server_times_the_pairing_window_out(t: Kind) {
    let h =
        Harness::over_with_limits(t, ControlLimits { pairing_timeout: Duration::from_millis(200), ..fast_limits() });
    let (key, item) = managed("Office");
    h.host.add(item);
    h.host.hold_pairing.store(true, Ordering::SeqCst);
    let mut c = h.connect();
    c.send(json!({"op":"pair","name":"Remote Desktop"}));
    assert_eq!(c.read(), json!({"ok":false,"error":"denied"}));
    c.expect_closed();
    // A late approval is ignored ...
    h.host.answers.lock().unwrap().push_back(PairingAnswer::Approved(vec![key.clone()]));
    h.host.release_pairing();
    wait_until("the late answer", || h.host.answered.load(Ordering::SeqCst) == 1);
    assert!(h.server().clients().is_empty());
    // ... and the next pairing is possible.
    h.host.hold_pairing.store(false, Ordering::SeqCst);
    h.pair(&[&key]);
    assert_eq!(h.server().clients().len(), 1);
    assert!(h.host.logs().iter().any(|l| l.contains("timed out")));
}

fn a_client_gone_before_the_approval_is_not_paired(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    h.host.hold_pairing.store(true, Ordering::SeqCst);
    h.host.answers.lock().unwrap().push_back(PairingAnswer::Approved(vec![key]));
    let mut c = h.connect();
    c.send(json!({"op":"pair","name":"Remote Desktop"}));
    wait_until("the pairing window", || h.host.pairing_open.load(Ordering::SeqCst));
    c.close();
    h.host.release_pairing();
    wait_until("the log line", || h.host.logs().iter().any(|l| l.contains("the client is gone")));
    assert!(h.server().clients().is_empty());
    assert!(!Registry::path(&h.dir.0).exists());
}

fn a_duplicate_pending_up_is_busy_and_pending_ups_are_capped(t: Kind) {
    let h = Harness::over(t);
    let keys: Vec<String> = (0..17)
        .map(|n| {
            let (key, item) = managed(&format!("C{n:02}"));
            h.host.add(item);
            h.host.script(&key, vec![Step::State(ConnectionState::Connecting), Step::Pause, Step::State(connected())]);
            key
        })
        .collect();
    let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    let mut c = h.authed(&refs);
    c.send(json!({"id":100,"op":"up","connection":keys[0]}));
    wait_until("the paused connect", || h.host.is_paused(&keys[0]));
    c.send(json!({"id":101,"op":"up","connection":keys[0]}));
    assert_eq!(c.reply_to(101).1, json!({"id":101,"ok":false,"error":"busy"}));
    for (n, key) in keys.iter().enumerate().take(16).skip(1) {
        c.send(json!({"id":n,"op":"up","connection":key}));
        wait_until("the paused connect", || h.host.is_paused(key));
    }
    c.send(json!({"id":200,"op":"up","connection":keys[16]}));
    assert_eq!(c.reply_to(200).1, json!({"id":200,"ok":false,"error":"busy"}));
    for key in &keys {
        h.host.resume(key);
    }
    assert_eq!(c.reply_to(100).1["ok"], true);
}

fn stop_detach_keeps_the_connections_up(t: Kind) {
    let mut h = Harness::over(t);
    let (key, item) = managed("Office");
    let (slow, slow_item) = managed("Slow");
    h.host.add(item);
    h.host.add(slow_item);
    h.host.script(&slow, vec![Step::State(ConnectionState::Connecting), Step::Pause, Step::State(connected())]);
    let mut c = h.authed(&[&key, &slow]);
    c.send(json!({"id":1,"op":"up","connection":key}));
    c.reply_to(1);
    c.send(json!({"id":2,"op":"up","connection":slow}));
    wait_until("the paused connect", || h.host.is_paused(&slow));
    h.server.as_mut().unwrap().stop(StopMode::Detach);
    assert_eq!(c.reply_to(2).1, json!({"id":2,"ok":false,"error":"app_quitting"}));
    assert_eq!(c.read(), json!({"event":"closing","reason":"app_quitting"}));
    c.expect_closed();
    assert!(!h.socket().exists());
    h.host.resume(&slow);
    wait_until("the slow connect", || h.host.connects_done.load(Ordering::SeqCst) == 2);
    assert_eq!(h.host.count(&format!("disconnect {key}")), 0);
    assert_eq!(h.host.count(&format!("disconnect {slow}")), 0);
    assert_eq!(h.host.state(&key), connected());
    assert!(h.host.logs().iter().any(|l| l.contains("MacVPN is quitting")));
}

/// Turning the setting off: every authenticated client, idle or holding a lease, gets the `closing` event before
/// the close, not just an end of file.
fn stop_tells_every_authenticated_client_why_it_closes(t: Kind) {
    for (mode, reason) in [(StopMode::EndLeases, "disabled"), (StopMode::Detach, "app_quitting")] {
        let mut h = Harness::over(t);
        let (key, item) = managed("Office");
        h.host.add(item);
        let mut holder = h.authed(&[&key]);
        holder.send(json!({"id":1,"op":"up","connection":key}));
        assert_eq!(holder.reply_to(1).1["ok"], true);
        let mut idle = h.authed(&[]);
        let mut silent = h.connect();
        h.server.as_mut().unwrap().stop(mode);
        let mut events = Vec::new();
        let closing = loop {
            let v = holder.read();
            if v["event"] == "closing" {
                break v;
            }
            events.push(v);
        };
        assert!(events.iter().all(|e| e["event"] == "state"), "{events:?}");
        assert_eq!(closing, json!({"event":"closing","reason":reason}));
        holder.expect_closed();
        assert_eq!(idle.read(), json!({"event":"closing","reason":reason}));
        idle.expect_closed();
        silent.expect_closed();
    }
}

fn stop_ends_the_accept_thread_without_the_socket_file(t: Kind) {
    let mut h = Harness::over(t);
    std::fs::remove_file(h.socket()).unwrap();
    let mut server = h.server.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        server.stop(StopMode::EndLeases);
        tx.send(()).unwrap();
    });
    rx.recv_timeout(WAIT).expect("stop returned");
}

/// The relay is registered on the manager once; a server is plugged in and out of it.
fn the_relay_forwards_manager_changes_to_the_current_server(t: Kind) {
    let f = common::Fixture::new(macvpn_core::l10n::AppLanguage::En);
    let c = Connection::new("WG", VPNKind::Wireguard);
    f.store.save(&c, Some("x")).unwrap();
    f.helper.respond(
        "status",
        Ok(&format!(
            r#"[{{"id":"{}","kind":"wireguard","state":"connected","iface":null,"ip":null,"since":null}}]"#,
            uuid_string(&c.id)
        )),
    );
    let m = f.manager();
    let relay = ControlRelay::attach(&m);
    let h = Harness::over(t);
    let key = h.host.add(ConnectionItem::Managed(c.clone()));
    *h.host.notifier.lock().unwrap() = None;
    relay.set(Some(h.server().notifier()));
    let mut client = h.authed(&[&key]);
    client.send(json!({"id":1,"op":"status"}));
    client.read();
    m.connect(&c, false);
    assert_eq!(client.read()["state"], "connecting");
    assert_eq!(client.read()["state"], "connected");
    relay.set(None);
    f.helper.respond("status", Ok("[]"));
    m.refresh();
    assert!(!client.read_nothing_pending(&key));
}

// MARK: - Lock order

/// `setup_ready_for` takes the app's setup lock, so `up` never asks it under the server's mutex: a state change
/// (which takes that mutex) started from inside `setup_ready_for` finishes at once.
fn up_asks_the_setup_outside_the_server_lock(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    let mut c = h.authed(&[&key]);
    let notifier = h.server().notifier();
    let probes = Arc::new(Mutex::new(Vec::new()));
    let seen = probes.clone();
    *h.host.setup_hook.lock().unwrap() = Some(Arc::new(move || {
        let n = notifier.clone();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            n.state_changed("lock-probe", &ConnectionState::Disconnected);
            let _ = tx.send(());
        });
        seen.lock().unwrap().push(rx.recv_timeout(Duration::from_secs(2)).is_ok());
    }));
    c.send(json!({"id":1,"op":"up","connection":key}));
    assert_eq!(c.reply_to(1).1, json!({"id":1,"ok":true,"state":"connected"}));
    assert_eq!(*probes.lock().unwrap(), [true], "setup_ready_for ran under the server's mutex");
}

/// The 1.1.0 review's deadlock: the view model held the setup's read guard and asked the server (its mutex),
/// `up` held the server's mutex and read the setup, and a queued writer (a system check) kept the new reader out.
/// Now `up` reads the setup without the mutex, so all three finish.
fn up_and_a_setup_reader_asking_the_server_do_not_deadlock_with_a_queued_writer(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    let mut c = h.authed(&[&key]);
    let notifier = h.server().notifier();
    let (entered_tx, entered_rx) = mpsc::channel::<()>();
    let entered_tx = Mutex::new(entered_tx);
    *h.host.setup_hook.lock().unwrap() = Some(Arc::new(move || {
        let _ = entered_tx.lock().unwrap().send(());
    }));

    // The "view model": holds the setup's read guard ...
    let host = h.host.clone();
    let (reader_ready_tx, reader_ready_rx) = mpsc::channel::<()>();
    let (asked_tx, asked_rx) = mpsc::channel::<bool>();
    let reader = thread::spawn(move || {
        let guard = host.setup_lock.read().unwrap();
        reader_ready_tx.send(()).unwrap();
        entered_rx.recv_timeout(WAIT).expect("up asked the setup");
        // ... and then asks the server (takes its mutex), with the guard still held.
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            notifier.state_changed("lock-probe", &ConnectionState::Disconnected);
            let _ = tx.send(());
        });
        let finished = rx.recv_timeout(Duration::from_secs(3)).is_ok();
        drop(guard); // Unblocks a deadlocked run so the test fails instead of hanging.
        asked_tx.send(finished).unwrap();
    });
    reader_ready_rx.recv_timeout(WAIT).unwrap();
    // A writer queues up behind the reader (std's RwLock then keeps new readers out).
    let host = h.host.clone();
    let writer = thread::spawn(move || {
        *host.setup_lock.write().unwrap() = ();
    });
    thread::sleep(Duration::from_millis(100));

    c.send(json!({"id":1,"op":"up","connection":key}));
    assert!(asked_rx.recv_timeout(WAIT).unwrap(), "the reader could not take the server's mutex: deadlock");
    assert_eq!(c.reply_to(1).1, json!({"id":1,"ok":true,"state":"connected"}));
    reader.join().unwrap();
    writer.join().unwrap();
}

// MARK: - Peer path sanitizing

/// A peer path with a control or format character could forge audit lines or reorder text in the pairing window:
/// `pair` is `denied` and `hello` is `unauthorized` (the generic replies), and the log shows the path escaped.
fn a_peer_path_with_control_or_format_characters_cannot_pair_or_hello(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    // A normal path pairs and says hello.
    let token = h.pair(&[&key]);
    let mut ok = h.hello(&token);
    ok.send(json!({"id":1,"op":"list"}));
    assert_eq!(ok.read()["connections"][0]["id"], key.as_str());
    ok.close();

    let newline = "/tmp/a\n2026-10-19T00:00:00Z  paired “Admin” (/Applications/Admin.app)";
    let rlo = "/tmp/evil\u{202E}ppa.exe";
    for (path, escaped) in [
        (newline, "/tmp/a\\u{a}2026-10-19T00:00:00Z  paired “Admin” (/Applications/Admin.app)"),
        (rlo, "/tmp/evil\\u{202e}ppa.exe"),
    ] {
        h.transport.set_executable(Some(path));
        let asks = h.host.asks.load(Ordering::SeqCst);
        h.host.answers.lock().unwrap().push_back(PairingAnswer::Approved(vec![key.clone()]));
        let mut c = h.connect();
        c.send(json!({"op":"pair","id":1,"name":"Remote Desktop"}));
        assert_eq!(c.read(), json!({"id":1,"ok":false,"error":"denied"}), "{path:?}");
        c.expect_closed();
        assert_eq!(h.host.asks.load(Ordering::SeqCst), asks, "no pairing window for {path:?}");
        h.host.answers.lock().unwrap().clear();

        let mut c = h.connect();
        c.send(json!({"op":"hello","id":2,"token":token}));
        assert_eq!(c.read(), json!({"id":2,"ok":false,"error":"unauthorized"}), "{path:?}");
        c.expect_closed();

        let logs = h.host.logs();
        assert!(logs.iter().all(|l| !l.contains(path)), "{path:?} raw in {logs:?}");
        assert!(logs.iter().all(|l| !l.contains('\n') && !l.contains('\u{202E}')), "{logs:?}");
        assert!(logs.iter().any(|l| l.starts_with("pairing refused for") && l.contains(escaped)), "{logs:?}");
        assert!(logs.iter().any(|l| l.starts_with("hello refused from") && l.contains(escaped)), "{logs:?}");
        assert!(h.server().path_changes().is_empty(), "{path:?}");
    }
    assert_eq!(h.server().clients().len(), 1);
}

fn forget_keys_prunes_the_allowlists_and_saves_them(t: Kind) {
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    let (other, other_item) = managed("Other");
    h.host.add(item);
    h.host.add(other_item);
    let _c = h.authed(&[&key, &other]);
    h.server().forget_keys(std::slice::from_ref(&key)).unwrap();
    assert_eq!(h.server().clients()[0].allowed, std::slice::from_ref(&other));
    let saved = Registry::load(&h.dir.0).unwrap();
    assert_eq!(saved.clients()[0].allowed, std::slice::from_ref(&other));
    // While the server is off: the file itself.
    macvpn_app_core::control::forget_keys_in_registry(&h.dir.0, &[other]).unwrap();
    let saved = Registry::load(&h.dir.0).unwrap();
    assert!(saved.clients()[0].allowed.is_empty());
    // A missing registry is nothing to do.
    let empty = std::env::temp_dir().join(format!("macvpn-no-registry-{}", uuid::Uuid::new_v4()));
    macvpn_app_core::control::forget_keys_in_registry(&empty, &[key]).unwrap();
    assert!(!empty.exists());
}

#[cfg(unix)]
fn forget_keys_keeps_the_pruned_allowlist_even_when_saving_fails(t: Kind) {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::over(t);
    let (key, item) = managed("Office");
    h.host.add(item);
    let _c = h.authed(&[&key]);
    std::fs::set_permissions(&h.dir.0, std::fs::Permissions::from_mode(0o500)).unwrap();
    let result = h.server().forget_keys(std::slice::from_ref(&key));
    std::fs::set_permissions(&h.dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err(), "the failed save is reported");
    assert!(h.server().clients()[0].allowed.is_empty(), "fails closed: the key is gone from memory");
}

// MARK: - Transport

#[test]
fn a_peer_user_displays_as_in_the_audit_log() {
    assert_eq!(PeerUser::Uid(501).to_string(), "uid 501");
    assert_eq!(PeerUser::Sid("S-1-5-21-1-2-3-1001".into()).to_string(), "sid S-1-5-21-1-2-3-1001");
}

/// The stream's `peer_connected`: true while the client waits, false once it has closed.
fn peer_connected_follows_the_client(t: Kind) {
    let dir = Scratch::new();
    let transport = FakeTransport::over(t);
    let endpoint = transport.bind(&dir.0.join("control")).unwrap();
    let h = Harness { dir, host: Arc::new(FakeHost::default()), transport, server: None };
    let client = h.try_connect().unwrap();
    let stream = loop {
        match endpoint.listener.accept(Duration::from_millis(5)).unwrap() {
            Accepted::Client { stream, peer } => {
                assert_eq!(peer.unwrap().pid, 4242);
                break stream;
            }
            Accepted::Idle => {}
        }
    };
    assert!(stream.peer_connected());
    assert!(stream.peer_connected(), "the check consumes nothing it needs");
    drop(client);
    wait_until("the close", || !stream.peer_connected());
}

/// `stop` removes the endpoint's `socket_file`; an endpoint without one (a named pipe) has nothing removed.
fn stop_removes_only_the_endpoints_socket_file(t: Kind) {
    let mut h = Harness::over(t);
    assert_eq!(h.server().socket_file(), Some(h.socket().as_path()));
    h.server.as_mut().unwrap().stop(StopMode::EndLeases);
    assert!(!h.socket().exists());

    let transport = FakeTransport::over(Kind::Loopback);
    let mut h = Harness { dir: Scratch::new(), host: Arc::new(FakeHost::default()), transport, server: None };
    h.transport.socket_file.store(false, Ordering::SeqCst);
    h.start(fast_limits());
    assert_eq!(h.server().socket_file(), None);
    let addr = h.transport.addr.lock().unwrap().unwrap().to_string();
    assert_eq!(h.server().endpoint(), addr);
    assert!(h.host.logs().contains(&format!("listening on {addr}")));
    // A file at the old socket path is not the server's.
    std::fs::write(h.socket(), "").unwrap();
    h.server.as_mut().unwrap().stop(StopMode::EndLeases);
    assert!(h.socket().exists());
    assert!(!h.host.logs().iter().any(|l| l.contains("could not remove")), "{:?}", h.host.logs());
}

#[cfg(unix)]
#[test]
fn the_unix_endpoint_is_displayed_as_its_path() {
    let h = Harness::new();
    let path = h.socket().display().to_string();
    assert_eq!(h.server().endpoint(), path);
    assert!(h.host.logs().contains(&format!("listening on {path}")));
}

/// Every test above runs over TCP loopback (every OS) and over the real local endpoint: the Unix socket (Unix) or a
/// named pipe (Windows).
macro_rules! over_both {
    ($($(#[$attr:meta])* $name:ident),* $(,)?) => {
        #[cfg(unix)]
        mod unix {
            use super::*;
            $( $(#[$attr])* #[test] fn $name() { super::$name(Kind::Unix) } )*
        }
        mod loopback {
            use super::*;
            $( $(#[$attr])* #[test] fn $name() { super::$name(Kind::Loopback) } )*
        }
        #[cfg(windows)]
        mod pipe {
            use super::*;
            $( $(#[$attr])* #[test] fn $name() { super::$name(Kind::Pipe) } )*
        }
    };
}

over_both!(
    pair_approved_then_token_works_in_hello,
    approved_keys_are_limited_to_the_offered_ones,
    pair_denied_three_times_blocks_pairing,
    a_second_pairing_while_one_is_pending_is_busy,
    wrong_token_is_unauthorized_after_the_delay,
    a_malformed_token_fails_like_a_wrong_one,
    another_executable_path_is_unauthorized,
    a_moved_executable_is_flagged_until_a_good_hello,
    a_peer_of_another_user_is_closed_at_once,
    requests_before_hello_are_unauthorized,
    malformed_and_unknown_requests_get_their_codes,
    list_shows_only_the_allowed_connections_in_order,
    up_streams_progress_then_replies_connected,
    up_checks_allowlist_existence_and_setup,
    setup_required_only_when_the_connect_needs_the_setup,
    without_an_engine_up_fails_with_the_engine_note,
    a_later_kind_fails_with_its_reason,
    down_releases_and_disconnects,
    locked_refuses_everything_but_down,
    client_eof_disconnects,
    client_killed_mid_connect_disconnects,
    two_clients_disconnect_only_after_both_close,
    a_second_client_joins_a_connect_in_progress,
    a_preexisting_connection_is_not_disconnected,
    a_connecting_key_without_a_lease_is_busy,
    a_synchronous_connect_error_fails_and_ends_the_lease,
    a_failed_connect_replies_failed_and_a_later_up_reconnects,
    mfa_timeout_and_cancel_get_their_codes,
    up_waits_for_credentials_then_connects,
    cancelled_credentials_get_their_code_and_release_the_lease,
    user_disconnect_ends_the_lease_without_reconnect,
    user_disconnect_during_up_answers_it,
    a_drop_is_reported_to_the_holders,
    status_subscribes_to_the_allowed_connections,
    revoke_closes_the_socket_and_disconnects,
    the_ninth_client_is_refused,
    a_silent_client_is_closed_after_the_auth_timeout,
    a_connection_that_says_nothing_and_closes_is_not_logged,
    a_flood_is_closed,
    stop_closes_everything_and_removes_the_socket,
    a_registry_that_cannot_be_read_stops_the_start_and_is_kept,
    down_of_the_key_in_the_connect_gap_leaves_nothing_up,
    close_in_the_connect_gap_leaves_nothing_up,
    a_dripping_client_is_closed_at_the_auth_deadline,
    a_client_slow_to_say_hello_is_not_closed_by_the_test_limits,
    an_authenticated_client_outlives_the_auth_deadline,
    stop_does_not_wait_for_the_auth_deadline_of_a_silent_client,
    the_server_times_the_pairing_window_out,
    a_client_gone_before_the_approval_is_not_paired,
    a_duplicate_pending_up_is_busy_and_pending_ups_are_capped,
    stop_detach_keeps_the_connections_up,
    stop_tells_every_authenticated_client_why_it_closes,
    stop_ends_the_accept_thread_without_the_socket_file,
    the_relay_forwards_manager_changes_to_the_current_server,
    up_asks_the_setup_outside_the_server_lock,
    up_and_a_setup_reader_asking_the_server_do_not_deadlock_with_a_queued_writer,
    a_peer_path_with_control_or_format_characters_cannot_pair_or_hello,
    forget_keys_prunes_the_allowlists_and_saves_them,
    #[cfg(unix)]
    forget_keys_keeps_the_pruned_allowlist_even_when_saving_fails,
    peer_connected_follows_the_client,
    stop_removes_only_the_endpoints_socket_file
);
