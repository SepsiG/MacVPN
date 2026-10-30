#![cfg(target_os = "linux")]
//! The NM client against a fake NetworkManager and polkit on the test's private bus (dbus-run-session).

mod fake_nm; // tests/fake_nm/mod.rs: the fake above (shared with nm_engine.rs and nm_native.rs)

use fake_nm::{FakeNm, Polkit};
use macvpn_platform_linux::lin_for_tests::nm::client::{NmClient, NmError, NmEvent};
use macvpn_platform_linux::lin_for_tests::nm::polkit::{self, ACTIONS, Authorization};
use macvpn_platform_linux::lin_for_tests::nm::value::to_dbus;
use macvpn_platform_linux::pure::nm::state::{ActiveState, VpnState};
use std::sync::mpsc;
use std::time::Duration;

fn session() -> zbus::blocking::Connection {
    zbus::blocking::Connection::session().unwrap()
}

#[test]
fn add_and_activate_checks_polkit_first_and_asks_for_a_volatile_unbound_activation() {
    let nm = FakeNm::start(Polkit::Yes);
    let client = NmClient::new(session());
    let settings = to_dbus(&fake_nm::wireguard_settings("linvpn-dev"));
    let a = client.add_and_activate(&settings).unwrap();
    assert!(a.active_path.starts_with("/org/freedesktop/NetworkManager/ActiveConnection/"));
    assert!(a.settings_path.starts_with("/org/freedesktop/NetworkManager/Settings/"));
    let calls = nm.calls();
    let me = client.bus().unique_name().unwrap().to_string();
    // One CheckAuthorization per action, both before the write.
    for (i, action) in ACTIONS.iter().enumerate() {
        assert_eq!(calls[i].method, "CheckAuthorization");
        assert_eq!(calls[i].action, *action);
        assert_eq!(calls[i].flags_arg, 0, "never interactive");
        assert!(!calls[i].allow_interactive_authorization);
        assert_eq!(calls[i].subject, ("system-bus-name".to_string(), me.clone()), "our own unique name");
    }
    let add = &calls[ACTIONS.len()];
    assert_eq!(add.method, "AddAndActivateConnection2");
    // Volatile (NM deletes the profile once it is deactivated) and not bound to this D-Bus client: the tunnel
    // outlives LinVPN's process ("Quit, Keep Them Running", a crash), as on macOS and Windows.
    assert_eq!(add.options, [("persist".to_string(), "volatile".to_string())]);
    assert!(!add.allow_interactive_authorization, "the message flag is off");
    assert_eq!(add.permissions, vec!["user:linvpn-dev".to_string()]);
    assert_eq!(add.sender, me, "sent from this client's connection");
    assert_eq!(calls.len(), ACTIONS.len() + 1);
}

#[test]
fn without_polkit_consent_nothing_is_written() {
    for answer in [Polkit::Challenge, Polkit::No] {
        let nm = FakeNm::start(answer);
        let client = NmClient::new(session());
        let e = client.add_and_activate(&to_dbus(&fake_nm::wireguard_settings("u"))).unwrap_err();
        assert!(matches!(e, NmError::NotAuthorized(_)), "{e:?}");
        assert!(e.message().contains("without asking for a password"), "{e:?}");
        assert!(matches!(
            client.activate_profile("/org/freedesktop/NetworkManager/Settings/9"),
            Err(NmError::NotAuthorized(_))
        ));
        assert!(matches!(
            client.deactivate("/org/freedesktop/NetworkManager/ActiveConnection/9"),
            Err(NmError::NotAuthorized(_))
        ));
        assert!(nm.calls().iter().all(|c| c.method == "CheckAuthorization"), "{:?}", nm.calls());
        let expected = if answer == Polkit::Challenge { Authorization::NeedsPrompt } else { Authorization::Denied };
        assert_eq!(polkit::check_nm_write(client.bus()), expected);
    }
}

#[test]
fn polkit_answers_with_the_real_reply_signature() {
    let _nm = FakeNm::start(Polkit::Yes);
    let bus = session();
    let subject = ("system-bus-name", std::collections::HashMap::from([("name", zbus::zvariant::Value::from(":1.1"))]));
    let details: std::collections::HashMap<&str, &str> = Default::default();
    let reply = bus
        .call_method(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            Some("org.freedesktop.PolicyKit1.Authority"),
            "CheckAuthorization",
            &(subject, ACTIONS[0], details, 0u32, ""),
        )
        .unwrap();
    assert_eq!(reply.body().signature().to_string(), "(bba{ss})", "one struct, as polkitd answers");
    assert_eq!(polkit::check_nm_write(&bus), Authorization::Authorized);
}

#[test]
fn polkit_unreachable_fails_closed() {
    // No fake: nobody owns org.freedesktop.PolicyKit1 on the private bus.
    let _turn = fake_nm::nobody();
    let client = NmClient::new(session());
    assert!(matches!(polkit::check_nm_write(client.bus()), Authorization::Unknown(_)));
    let e = client.add_and_activate(&to_dbus(&fake_nm::wireguard_settings("u"))).unwrap_err();
    assert!(matches!(e, NmError::NotAuthorized(_)), "{e:?}");
    assert!(matches!(client.active(), Err(NmError::Unavailable(_))), "NM not on the bus");
    assert_eq!(client.version(), None);
}

#[test]
fn activate_and_deactivate_go_through_polkit() {
    let nm = FakeNm::start(Polkit::Yes);
    let profile = nm.add_profile("sys-1", &[], 0);
    let client = NmClient::new(session());
    let a = client.activate_profile(&profile).unwrap();
    assert_eq!(a.settings_path, profile);
    client.deactivate(&a.active_path).unwrap();
    let methods: Vec<String> = nm.calls().into_iter().map(|c| c.method).collect();
    assert_eq!(
        methods,
        [
            "CheckAuthorization",
            "CheckAuthorization",
            "ActivateConnection",
            "CheckAuthorization",
            "CheckAuthorization",
            "DeactivateConnection"
        ]
    );
    assert!(nm.calls().iter().all(|c| !c.allow_interactive_authorization));
    let e = client.deactivate(&a.active_path).unwrap_err();
    assert!(matches!(e, NmError::Failed(ref m) if m.contains("is not active")), "NM's message: {e:?}");
}

#[test]
fn active_connections_carry_state_address_and_type() {
    let nm = FakeNm::start(Polkit::Yes);
    nm.add_active_vpn("u-1", "org.freedesktop.NetworkManager.linvpn-openvpn", 2, 5, Some("10.99.11.6"));
    nm.add_active("u-wg", "wireguard", 1, None, "lvpn0");
    let client = NmClient::new(session());
    assert_eq!(client.version().as_deref(), Some("1.54.3"));
    let a = client.active().unwrap();
    assert_eq!(a.len(), 2);
    assert_eq!(a[0].uuid, "u-1");
    assert_eq!(a[0].nm_type, "vpn");
    assert_eq!(a[0].service_type.as_deref(), Some("org.freedesktop.NetworkManager.linvpn-openvpn"));
    assert_eq!(a[0].state, ActiveState::Activated);
    assert_eq!(a[0].vpn_state, Some(VpnState::Activated));
    assert_eq!(a[0].ip4.as_deref(), Some("10.99.11.6"));
    assert_eq!(a[0].ip_iface, None, "a VPN's device is the underlying one");
    assert_eq!(a[1].uuid, "u-wg");
    assert_eq!(a[1].nm_type, "wireguard");
    assert_eq!((a[1].service_type.as_deref(), a[1].vpn_state), (None, None));
    assert_eq!(a[1].state, ActiveState::Activating);
    assert_eq!(a[1].ip4, None);
    assert_eq!(a[1].ip_iface.as_deref(), Some("lvpn0"));
}

#[test]
fn profiles_are_the_visible_ones_with_their_data() {
    let nm = FakeNm::start(Polkit::Yes);
    nm.add_profile("p-1", &["user:linvpn-dev"], 0);
    nm.add_profile("hidden", &["user:someone"], 0);
    let client = NmClient::new(session());
    let p = client.profiles().unwrap();
    assert_eq!(p.len(), 1, "NM refuses the settings of a profile the user cannot see: {p:?}");
    assert_eq!(p[0].uuid, "p-1");
    assert_eq!(p[0].nm_type, "vpn");
    assert_eq!(p[0].service_type.as_deref(), Some("org.freedesktop.NetworkManager.l2tp"));
    assert_eq!(p[0].permissions, vec!["user:linvpn-dev".to_string()]);
    assert_eq!(p[0].data.get("gateway").map(String::as_str), Some("vpn.example.com"));
    assert_eq!(p[0].flags, 0);
}

#[test]
fn only_our_own_volatile_leftover_is_deleted() {
    let nm = FakeNm::start(Polkit::Yes);
    nm.add_profile("ours", &["user:linvpn-dev"], 4 | 1);
    nm.add_profile("ours-nm-form", &["user:linvpn-dev:"], 4);
    nm.add_profile("saved", &["user:linvpn-dev"], 0);
    nm.add_profile("other", &["user:someone"], 4 | 1);
    nm.add_profile("shared", &["user:linvpn-dev", "user:someone"], 4 | 1);
    nm.add_profile("everyone", &[], 4 | 1);
    let client = NmClient::new(session());
    assert!(client.delete_own_volatile("ours", "linvpn-dev").unwrap());
    assert!(client.delete_own_volatile("ours-nm-form", "linvpn-dev").unwrap());
    assert!(!client.delete_own_volatile("saved", "linvpn-dev").unwrap());
    assert!(!client.delete_own_volatile("other", "linvpn-dev").unwrap());
    assert!(!client.delete_own_volatile("shared", "linvpn-dev").unwrap());
    assert!(!client.delete_own_volatile("everyone", "linvpn-dev").unwrap());
    assert!(!client.delete_own_volatile("missing", "linvpn-dev").unwrap());
    assert_eq!(nm.deleted(), vec!["ours".to_string(), "ours-nm-form".to_string()]);
}

#[test]
fn a_leftover_is_not_deleted_without_polkit_consent() {
    let nm = FakeNm::start(Polkit::Challenge);
    nm.add_profile("ours", &["user:linvpn-dev"], 4 | 1);
    let client = NmClient::new(session());
    assert!(matches!(client.delete_own_volatile("ours", "linvpn-dev"), Err(NmError::NotAuthorized(_))));
    assert!(nm.deleted().is_empty());
}

#[test]
fn vpn_state_signals_reach_the_watcher() {
    let nm = FakeNm::start(Polkit::Yes);
    let path = nm.add_active_vpn("u-2", "org.freedesktop.NetworkManager.l2tp", 1, 3, None);
    let client = NmClient::new(session());
    let (tx, rx) = mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    let _guard = client
        .watch(Box::new(move |e| {
            let _ = tx.lock().unwrap().send(e);
        }))
        .unwrap();
    nm.emit_vpn_state(&path, 6, 9);
    let e = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(e, NmEvent::VpnState { active_path: path, state: VpnState::Failed, reason: 9 });
}

#[test]
fn the_other_signals_map_to_their_events() {
    use std::collections::HashMap;
    use zbus::zvariant::{ObjectPath, OwnedValue, Value};
    let nm = FakeNm::start(Polkit::Yes);
    let client = NmClient::new(session());
    let (tx, rx) = mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    let guard = client
        .watch(Box::new(move |e| {
            let _ = tx.lock().unwrap().send(e);
        }))
        .unwrap();
    let next = || rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let changed = |key: &str| {
        let v: HashMap<String, OwnedValue> =
            HashMap::from([(key.to_string(), OwnedValue::try_from(Value::from(1u32)).unwrap())]);
        ("org.freedesktop.NetworkManager".to_string(), v, Vec::<String>::new())
    };
    let props = "org.freedesktop.DBus.Properties";
    nm.emit(fake_nm::ROOT, props, "PropertiesChanged", &changed("ActiveConnections"));
    assert_eq!(next(), NmEvent::ActiveChanged);
    nm.emit(fake_nm::ROOT, props, "PropertiesChanged", &changed("Connectivity"));
    assert_eq!(next(), NmEvent::NetworkChanged);
    nm.emit(fake_nm::ROOT, props, "PropertiesChanged", &changed("Devices"));
    assert_eq!(next(), NmEvent::NetworkChanged);
    // An IP configuration's change is the network; an access point's signal strength is nothing.
    let of = |iface: &str, key: &str| {
        let (_, v, invalidated) = changed(key);
        (iface.to_string(), v, invalidated)
    };
    nm.emit(
        "/org/freedesktop/NetworkManager/AccessPoint/2",
        props,
        "PropertiesChanged",
        &of("org.freedesktop.NetworkManager.AccessPoint", "Strength"),
    );
    nm.emit(
        "/org/freedesktop/NetworkManager/IP6Config/5",
        props,
        "PropertiesChanged",
        &of("org.freedesktop.NetworkManager.IP6Config", "Gateway"),
    );
    assert_eq!(next(), NmEvent::NetworkChanged);
    let profile = ObjectPath::from_static_str_unchecked("/org/freedesktop/NetworkManager/Settings/7");
    nm.emit(fake_nm::SETTINGS, "org.freedesktop.NetworkManager.Settings", "NewConnection", &(&profile,));
    assert_eq!(next(), NmEvent::ProfilesChanged);
    nm.emit(fake_nm::SETTINGS, "org.freedesktop.NetworkManager.Settings", "ConnectionRemoved", &(&profile,));
    assert_eq!(next(), NmEvent::ProfilesChanged);
    nm.emit(
        "/org/freedesktop/NetworkManager/Devices/3",
        "org.freedesktop.NetworkManager.Device",
        "StateChanged",
        &(100u32, 30u32, 0u32),
    );
    assert_eq!(next(), NmEvent::NetworkChanged);
    nm.emit(
        "/org/freedesktop/NetworkManager/ActiveConnection/4",
        "org.freedesktop.NetworkManager.Connection.Active",
        "StateChanged",
        &(2u32, 0u32),
    );
    assert_eq!(
        next(),
        NmEvent::ActiveState {
            active_path: "/org/freedesktop/NetworkManager/ActiveConnection/4".into(),
            state: 2,
            reason: 0
        }
    );

    // Not NM's: another sender's identical signal is ignored.
    let other = zbus::blocking::Connection::session().unwrap();
    other.emit_signal(None::<&str>, fake_nm::ROOT, props, "PropertiesChanged", &changed("ActiveConnections")).unwrap();
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err(), "only NetworkManager's own signals count");

    // After the guard drops, nothing more arrives.
    drop(guard);
    std::thread::sleep(Duration::from_millis(200));
    nm.emit(fake_nm::ROOT, props, "PropertiesChanged", &changed("ActiveConnections"));
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err(), "the watch stopped");
}

#[test]
#[ignore = "desktop: reads the real NetworkManager (read-only)"]
fn desktop_nm_reads_the_real_networkmanager() {
    let client = NmClient::new(zbus::blocking::Connection::system().unwrap());
    assert!(client.version().is_some_and(|v| v.starts_with("1.")));
    let _ = client.active().unwrap();
    let _ = client.profiles().unwrap();
}
