#![cfg(target_os = "linux")]
//! LinVPN's NetworkManager secret agent against a fake NM agent manager on the test's private bus
//! (dbus-run-session): only NM's unique name gets an answer, only for an announced activation.

use macvpn_core::mfa::AuthUIStateKind;
use macvpn_core::nm_plan::SecretKey;
use macvpn_platform_linux::lin_for_tests::nm::agent::{Agent, Answer, Expect, Rules};
use zeroize::Zeroizing;

mod fake_agent_manager; // tests/fake_agent_manager/mod.rs (this task's)
use fake_agent_manager::{FakeManager, Reply, profile_path};

/// An expectation bound to the path the fake NM sends for `uuid`, without further rules.
fn expect(agent: &Agent, uuid: &str, answer: Answer) -> Expect {
    let e = agent.expect(uuid, Rules::default(), answer);
    e.bind(&profile_path(uuid));
    e
}

fn answer(pw: &str) -> Answer {
    Answer { items: vec![("vpn", SecretKey::Plain("password".into()), Zeroizing::new(pw.into()))] }
}

#[test]
fn registers_with_vpn_hints_and_answers_nm_for_an_expected_activation() {
    let nm = FakeManager::start();
    let agent = Agent::register(&zbus::blocking::Connection::session().unwrap()).unwrap();
    assert_eq!(nm.registered(), Some(("local.linvpn.agent".to_string(), 1)));
    let _e = expect(&agent, "uuid-1", answer("s3cret"));
    match nm.get_secrets("uuid-1", "vpn", &[], 0x1) {
        Reply::Ok(map) => assert_eq!(map["vpn"]["secrets"]["password"], "s3cret"),
        other => panic!("{other:?}"),
    }
}

/// A refused sign-in: NM-openvpn clears the password after OpenVPN's "Verification Failed" and asks again. The agent
/// answers an activation's stored secrets once: the same password again would loop until NM's 60 s timeout
/// (classified "server could not be reached" and reconnected; L-b lab). The second ask is the user's cancel, so NM
/// fails the VPN at once with its no-secrets reason (logged as `AUTH_FAILED`).
#[test]
fn stored_secrets_are_answered_once_per_activation() {
    let nm = FakeManager::start();
    let agent = Agent::register(&zbus::blocking::Connection::session().unwrap()).unwrap();
    let _e = expect(&agent, "uuid-1", answer("s3cret"));
    assert!(matches!(nm.get_secrets("uuid-1", "vpn", &[], 0x1), Reply::Ok(_)));
    assert!(
        matches!(nm.get_secrets("uuid-1", "vpn", &["password"], 0x1), Reply::Err(n) if n.ends_with("SecretAgent.UserCanceled"))
    );
    // A new activation (a new expectation) is answered again.
    drop(_e);
    let _e = expect(&agent, "uuid-1", answer("s3cret"));
    assert!(matches!(nm.get_secrets("uuid-1", "vpn", &[], 0x1), Reply::Ok(_)));
}

#[test]
fn an_impostor_and_an_unknown_connection_get_nothing() {
    let nm = FakeManager::start();
    let agent = Agent::register(&zbus::blocking::Connection::session().unwrap()).unwrap();
    let _e = expect(&agent, "uuid-1", answer("s3cret"));
    assert!(
        matches!(nm.get_secrets_as_impostor("uuid-1", "vpn"), Reply::Err(n) if n.ends_with("SecretAgent.NotAuthorized") || n.ends_with("AccessDenied"))
    );
    assert!(
        matches!(nm.get_secrets("uuid-other", "vpn", &[], 0x1), Reply::Err(n) if n.ends_with("SecretAgent.NoSecrets"))
    );
}

#[test]
fn a_dropped_expectation_is_forgotten() {
    let nm = FakeManager::start();
    let agent = Agent::register(&zbus::blocking::Connection::session().unwrap()).unwrap();
    drop(expect(&agent, "uuid-1", answer("s3cret")));
    assert!(matches!(nm.get_secrets("uuid-1", "vpn", &[], 0x1), Reply::Err(_)));
}

#[test]
fn crv1_waits_for_the_users_code() {
    let nm = FakeManager::start();
    let agent = Agent::register(&zbus::blocking::Connection::session().unwrap()).unwrap();
    let _e = expect(&agent, "uuid-1", answer("s3cret"));
    let pending = nm.get_secrets_async(
        "uuid-1",
        "vpn",
        &["x-vpn-message:Code?", "x-dynamic-challenge-echo:challenge-response"],
        0x1 | 0x2,
    );
    let state = wait(|| agent.challenge("uuid-1"));
    assert_eq!(state.state, AuthUIStateKind::Challenge);
    assert_eq!(state.text.as_deref(), Some("Code?"));
    assert_eq!(state.echo, Some(true));
    assert!(agent.respond("uuid-1", Zeroizing::new("123456".into())));
    match pending.join() {
        Reply::Ok(map) => assert_eq!(map["vpn"]["secrets"]["challenge-response"], "123456"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn cancel_get_secrets_ends_the_prompt() {
    let nm = FakeManager::start();
    let agent = Agent::register(&zbus::blocking::Connection::session().unwrap()).unwrap();
    let _e = expect(&agent, "uuid-1", answer("s3cret"));
    let pending = nm.get_secrets_async("uuid-1", "vpn", &["x-dynamic-challenge:challenge-response"], 0x3);
    wait(|| agent.challenge("uuid-1"));
    nm.cancel_get_secrets("uuid-1", "vpn");
    assert!(matches!(pending.join(), Reply::Err(_)));
    assert_eq!(agent.challenge("uuid-1").map(|s| s.state), Some(AuthUIStateKind::Cancelled));
}

#[test]
fn save_and_delete_store_nothing() {
    let nm = FakeManager::start();
    let _agent = Agent::register(&zbus::blocking::Connection::session().unwrap()).unwrap();
    assert!(matches!(nm.save_secrets("uuid-1"), Reply::Ok(_)));
    assert!(matches!(nm.delete_secrets("uuid-1"), Reply::Ok(_)));
}

#[test]
fn wireguard_gets_its_private_key_and_peer_psks() {
    let nm = FakeManager::start();
    let agent = Agent::register(&zbus::blocking::Connection::session().unwrap()).unwrap();
    let _e = expect(
        &agent,
        "uuid-wg",
        Answer {
            items: vec![
                ("wireguard", SecretKey::Plain("private-key".into()), Zeroizing::new("PRIV".into())),
                ("wireguard", SecretKey::WgPeerPsk { public_key: "PUB".into() }, Zeroizing::new("PSK".into())),
                ("vpn", SecretKey::Plain("password".into()), Zeroizing::new("not-this".into())),
            ],
        },
    );
    let Reply::Ok(map) = nm.get_secrets("uuid-wg", "wireguard", &[], 0x1) else { panic!("no answer") };
    assert_eq!(map.keys().collect::<Vec<_>>(), ["wireguard"], "only the asked setting");
    assert_eq!(map["wireguard"]["private-key"], "PRIV");
    let fake_agent_manager::Val::Peers(peers) = &map["wireguard"]["peers"] else { panic!("no peers") };
    assert_eq!(peers.len(), 1);
    assert_eq!((peers[0]["public-key"].as_str(), peers[0]["preshared-key"].as_str()), ("PUB", "PSK"));
    assert!(
        matches!(nm.get_secrets("uuid-wg", "802-1x", &[], 0x1), Reply::Err(n) if n.ends_with("SecretAgent.NoSecrets"))
    );
}

#[test]
fn the_users_cancel_ends_the_prompt() {
    let nm = FakeManager::start();
    let agent = Agent::register(&zbus::blocking::Connection::session().unwrap()).unwrap();
    let _e = expect(&agent, "uuid-1", answer("s3cret"));
    assert!(!agent.respond("uuid-1", Zeroizing::new("1".into())), "nothing pending yet");
    let pending = nm.get_secrets_async("uuid-1", "vpn", &["x-dynamic-challenge:challenge-response"], 0x3);
    wait(|| agent.challenge("uuid-1"));
    agent.cancel("uuid-1");
    assert!(matches!(pending.join(), Reply::Err(n) if n.ends_with("SecretAgent.UserCanceled")));
    assert_eq!(agent.challenge("uuid-1").map(|s| s.state), Some(AuthUIStateKind::Cancelled));
    assert!(!agent.respond("uuid-1", Zeroizing::new("1".into())), "the prompt is over");
}

#[test]
fn a_restarted_networkmanager_gets_the_agent_again_and_the_old_name_nothing() {
    let nm = FakeManager::start();
    let agent = Agent::register(&zbus::blocking::Connection::session().unwrap()).unwrap();
    let _e = expect(&agent, "uuid-1", answer("s3cret"));
    let old_nm = nm.restart();
    wait(|| nm.registered());
    match nm.get_secrets("uuid-1", "vpn", &[], 0x1) {
        Reply::Ok(map) => assert_eq!(map["vpn"]["secrets"]["password"], "s3cret"),
        other => panic!("{other:?}"),
    }
    let old = fake_agent_manager::get_secrets_from(&old_nm, &nm.agent_name(), "uuid-1", "vpn");
    assert!(matches!(old, Reply::Err(n) if n.ends_with("SecretAgent.NotAuthorized")), "the old owner lost NM's name");
}

fn wait<T>(f: impl Fn() -> Option<T>) -> T {
    for _ in 0..100 {
        if let Some(v) = f() {
            return v;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("timed out")
}

#[test]
fn another_profile_path_with_the_same_uuid_gets_nothing() {
    let nm = FakeManager::start();
    let agent = Agent::register(&zbus::blocking::Connection::session().unwrap()).unwrap();
    let e = agent.expect("uuid-1", Rules::default(), answer("s3cret"));
    e.bind("/org/freedesktop/NetworkManager/Settings/42");
    assert!(matches!(nm.get_secrets("uuid-1", "vpn", &[], 0x1), Reply::Err(n) if n.ends_with("SecretAgent.NoSecrets")));
}

#[test]
fn a_request_before_the_path_is_known_waits_for_it() {
    let nm = FakeManager::start();
    let agent = Agent::register(&zbus::blocking::Connection::session().unwrap()).unwrap();
    let e = agent.expect("uuid-1", Rules::default(), answer("s3cret"));
    let pending = nm.get_secrets_async("uuid-1", "vpn", &[], 0x1);
    std::thread::sleep(std::time::Duration::from_millis(200));
    e.bind(&profile_path("uuid-1"));
    match pending.join() {
        Reply::Ok(map) => assert_eq!(map["vpn"]["secrets"]["password"], "s3cret"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_profile_without_the_users_permission_or_with_another_plugin_gets_nothing() {
    let nm = FakeManager::start();
    let agent = Agent::register(&zbus::blocking::Connection::session().unwrap()).unwrap();
    // The fake's settings carry no permissions and no vpn.service-type.
    for rules in [
        Rules { user: Some("linvpn-dev".into()), service_type: None },
        Rules { user: None, service_type: Some("org.freedesktop.NetworkManager.openvpn".into()) },
    ] {
        let e = agent.expect("uuid-1", rules.clone(), answer("s3cret"));
        e.bind(&profile_path("uuid-1"));
        assert!(matches!(nm.get_secrets("uuid-1", "vpn", &[], 0x1), Reply::Err(_)), "{rules:?}");
    }
}
