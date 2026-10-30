#![cfg(target_os = "linux")]
//! The NetworkManager engine (`HelperClient`, `AuthStateReader`) against the fake NM, polkit and agent manager on the
//! test's private bus (dbus-run-session).
mod fake_nm;

use fake_nm::engine_ext::{Outcome, Tmp, with_agent_manager, with_agent_manager_polkit};
use macvpn_app_core::failure_reason::FailureKind;
use macvpn_core::liveness::Liveness;
use macvpn_core::models::{Secrets, VPNKind};
use macvpn_platform_api::{AuthStateReader, HelperClient, HelperTunnel};
use macvpn_platform_linux::lin_for_tests::nm::engine::Engine;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const WG: &str = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.99.13.5/32\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 10.99.0.0/24\nPersistentKeepalive = 25\n";
const OVPN: &str = "client\ndev tun\nremote vpn.example.com 1194\nauth-user-pass\n<ca>\nC\n</ca>\n";

fn engine(tmp: &Tmp) -> Arc<Engine> {
    let e = Engine::new(
        zbus::blocking::Connection::session,
        false,
        "linvpn-dev".into(),
        1001,
        Some(tmp.path().join("run")),
        tmp.path().join("data"),
    );
    // No journal lines from the host's linvpn-logd: the logs here are the engine's own.
    e.set_logd_socket_for_tests(tmp.path().join("no-logd.sock"));
    e
}

fn swan(local: &str, remote: &str) -> String {
    format!(
        "connections {{\n  lab {{\n    remote_addrs = vpn.example.com\n    vips = 0.0.0.0\n    local {{\n      {local}\n    }}\n    remote {{\n      {remote}\n      id = vpn.example.com\n    }}\n    children {{\n      lab {{\n      }}\n    }}\n  }}\n}}\n"
    )
}

fn wait<T>(f: impl Fn() -> Option<T>) -> T {
    for _ in 0..200 {
        if let Some(v) = f() {
            return v;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out")
}

fn connected(e: &Engine, id: &Uuid) -> macvpn_core::status::RootStatus {
    wait(|| e.status().unwrap().into_iter().find(|s| s.id == *id && s.state == "connected"))
}

#[test]
fn wireguard_up_reports_connecting_then_connected_with_its_interface_and_down_removes_everything() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "10.99.13.5" });
    e.up(VPNKind::Wireguard, &id, WG.as_bytes(), &Secrets::default(), false, &[]).unwrap();
    let s = connected(&e, &id);
    assert_eq!(s.kind, "wireguard");
    assert!(!e.wants_log_secrets(&id), "a fresh connect's log has its secrets");
    assert!(s.iface.as_deref().is_some_and(|i| i.starts_with("lvw")), "{:?}", s.iface);
    assert_eq!(s.ip.as_deref(), Some("10.99.13.5"));
    let add = nm.calls().into_iter().find(|c| c.method == "AddAndActivateConnection2").unwrap();
    assert_eq!(add.permissions, vec!["user:linvpn-dev".to_string()]);
    assert!(!add.allow_interactive_authorization);
    // The agent answers NM with the private key for this activation only.
    let answer = nm.as_nm_get_secrets(&nm.last_uuid(), "wireguard", &[]).unwrap();
    assert!(answer.contains_key("private-key"));
    // The private key never reaches NM's settings.
    assert!(nm.last_setting_str("wireguard", "private-key").is_none());
    e.down(VPNKind::Wireguard, &id).unwrap();
    assert!(nm.deactivated().contains(&nm.last_active_path()));
    assert!(e.status().unwrap().iter().all(|s| s.id != id));
    assert!(nm.as_nm_get_secrets(&nm.last_uuid(), "wireguard", &[]).is_err(), "forgotten after down");
    assert!(!tmp.path().join("run/linvpn/nm").join(nm.last_uuid()).exists());
    let log = std::fs::read_to_string(e.log_path(&id).unwrap()).unwrap();
    assert!(log.contains("Connecting with NetworkManager (wireguard)"), "{log}");
    assert!(log.contains("Connected, IPv4 10.99.13.5"), "{log}");
}

#[test]
fn an_openvpn_failure_is_logged_with_failure_reason_words() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Failed { reason: 9 });
    let secrets = Secrets { username: Some("alice".into()), password: Some("pw".into()), ..Secrets::default() };
    e.up(VPNKind::Openvpn, &id, OVPN.as_bytes(), &secrets, true, &[]).unwrap();
    wait(|| e.status().unwrap().iter().all(|s| s.id != id).then_some(()));
    let log = std::fs::read_to_string(e.log_path(&id).unwrap()).unwrap();
    assert!(log.contains("AUTH_FAILED"), "{log}");
    assert!(!log.contains("pw"), "no secret in the log");
    // Debug: the effective vpn.data, the password's value never.
    assert!(log.contains("vpn.data connection-type = password"), "{log}");
    // The runtime files (the inline CA) are gone with the run.
    assert!(!tmp.path().join("run/linvpn/nm").join(nm.last_uuid()).exists());
}

fn log_lines(e: &Engine, id: &Uuid) -> Vec<String> {
    std::fs::read_to_string(e.log_path(id).unwrap()).unwrap().lines().map(str::to_string).collect()
}

/// Audit C1: GNOME's menu or `nmcli connection down` (VPN reason 2, `USER_DISCONNECTED`) is the user's stop in the
/// log (app-core shows it off, never reconnects it, posts nothing); LinVPN's own disconnect logs its own line.
#[test]
fn a_stop_outside_linvpn_is_logged_as_the_users_and_linvpns_own_stop_is_not() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let secrets = Secrets { username: Some("alice".into()), password: Some("pw".into()), ..Secrets::default() };
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "198.51.100.7" });
    e.up(VPNKind::Openvpn, &id, OVPN.as_bytes(), &secrets, false, &[]).unwrap();
    connected(&e, &id);
    nm.disconnect_last(2);
    wait(|| e.status().unwrap().iter().all(|s| s.id != id).then_some(()));
    let lines = log_lines(&e, &id);
    assert!(macvpn_app_core::failure_reason::stopped_by_user(&lines), "{lines:?}");
    assert_eq!(macvpn_app_core::failure_reason::classify(&lines), FailureKind::StoppedByUser);
    // Another end outside LinVPN (the profile removed, reason 11) is a drop as before.
    let other = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "198.51.100.8" });
    e.up(VPNKind::Openvpn, &other, OVPN.as_bytes(), &secrets, false, &[]).unwrap();
    connected(&e, &other);
    nm.disconnect_last(11);
    wait(|| e.status().unwrap().iter().all(|s| s.id != other).then_some(()));
    assert!(!macvpn_app_core::failure_reason::stopped_by_user(&log_lines(&e, &other)));
    // LinVPN's own disconnect (also of the first connection again): not the user's stop outside LinVPN.
    nm.activate_next(Outcome::Activated { ip4: "198.51.100.7" });
    e.up(VPNKind::Openvpn, &id, OVPN.as_bytes(), &secrets, false, &[]).unwrap();
    connected(&e, &id);
    e.down(VPNKind::Openvpn, &id).unwrap();
    let lines = log_lines(&e, &id);
    assert!(!macvpn_app_core::failure_reason::stopped_by_user(&lines), "{lines:?}");
    assert!(lines.last().is_some_and(|l| l.ends_with("NetworkManager: disconnected")), "{lines:?}");
}

/// The same for WireGuard, which has no VPN state: NM's `Connection.Active.StateChanged(DEACTIVATED, 2)` is the
/// user's stop (L-b lab: `nmcli connection down` of a WireGuard tunnel was logged as a plain drop and reconnected).
#[test]
fn a_wireguard_stop_outside_linvpn_is_the_users_and_a_drop_is_not() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "10.99.13.5" });
    e.up(VPNKind::Wireguard, &id, WG.as_bytes(), &Secrets::default(), false, &[]).unwrap();
    connected(&e, &id);
    nm.disconnect_last(2);
    wait(|| e.status().unwrap().iter().all(|s| s.id != id).then_some(()));
    let lines = log_lines(&e, &id);
    assert_eq!(macvpn_app_core::failure_reason::classify(&lines), FailureKind::StoppedByUser, "{lines:?}");
    let other = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "10.99.13.6" });
    e.up(VPNKind::Wireguard, &other, WG.as_bytes(), &Secrets::default(), false, &[]).unwrap();
    connected(&e, &other);
    nm.disconnect_last(3);
    wait(|| e.status().unwrap().iter().all(|s| s.id != other).then_some(()));
    assert!(!macvpn_app_core::failure_reason::stopped_by_user(&log_lines(&e, &other)));
}

#[test]
fn openvpn_gets_the_vaults_user_name_and_its_ca_file() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "10.99.14.2" });
    let secrets = Secrets { username: Some("alice".into()), password: Some("pw-123".into()), ..Secrets::default() };
    e.up(VPNKind::Openvpn, &id, OVPN.as_bytes(), &secrets, false, &[]).unwrap();
    connected(&e, &id);
    assert_eq!(nm.last_setting_str("vpn", "user-name").as_deref(), Some("alice"));
    let data = nm.last_vpn_data();
    assert_eq!(data.get("username").map(String::as_str), Some("alice"));
    assert_eq!(data.get("password-flags").map(String::as_str), Some("1"));
    assert!(!data.values().any(|v| v.contains("pw-123")));
    let ca = std::path::PathBuf::from(&data["ca"]);
    assert_eq!(std::fs::read_to_string(&ca).unwrap(), "C\n");
    let answer = nm.as_nm_get_secrets(&nm.last_uuid(), "vpn", &[]).unwrap();
    assert_eq!(answer["password"], "pw-123");
    e.down(VPNKind::Openvpn, &id).unwrap();
    assert!(!ca.exists());
}

#[test]
fn crv1_goes_through_auth_state_and_respond() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::StayConnecting);
    e.up(
        VPNKind::Openvpn,
        &id,
        OVPN.as_bytes(),
        &Secrets { password: Some("pw".into()), ..Secrets::default() },
        false,
        &[],
    )
    .unwrap();
    wait(|| e.status().unwrap().into_iter().find(|s| s.id == id && s.state == "connecting"));
    let pending = nm.as_nm_get_secrets_async(
        &nm.last_uuid(),
        "vpn",
        &["x-vpn-message:Code?", "x-dynamic-challenge:challenge-response"],
    );
    let state = wait(|| e.read(&id));
    assert_eq!(state.text.as_deref(), Some("Code?"));
    assert!(e.respond(&id, macvpn_core::mfa::AuthResponseKind::Crv1, "bad\ncode").is_err());
    e.respond(&id, macvpn_core::mfa::AuthResponseKind::Crv1, "424242").unwrap();
    assert_eq!(pending.join().unwrap()["challenge-response"], "424242");
    assert!(e.respond(&id, macvpn_core::mfa::AuthResponseKind::Crv1, "1").is_err(), "nothing pending any more");
    e.down(VPNKind::Openvpn, &id).unwrap();
}

/// WireGuard and IKEv2 get their address after NM reports them activated: "Connected" first, the address in a line
/// of its own once NM has it (not "Connected, IPv4 -").
#[test]
fn an_address_that_comes_after_the_activation_gets_its_own_log_line() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::ActivatedAddressLater);
    e.up(VPNKind::Wireguard, &id, WG.as_bytes(), &Secrets::default(), false, &[]).unwrap();
    let s = connected(&e, &id);
    assert_eq!(s.ip, None);
    let log = || std::fs::read_to_string(e.log_path(&id).unwrap()).unwrap();
    assert!(log().contains("Connected (IPv4 address not known yet)"), "{}", log());
    assert!(!log().contains("IPv4 -"), "{}", log());
    nm.set_last_ip4("100.64.3.4");
    wait(|| e.status().unwrap().into_iter().find(|s| s.id == id && s.ip.as_deref() == Some("100.64.3.4")));
    assert_eq!(log().matches("IPv4 address: 100.64.3.4").count(), 1, "{}", log());
    e.status().unwrap();
    assert_eq!(log().matches("IPv4 address: 100.64.3.4").count(), 1, "once: {}", log());
    assert!(!log().contains("Connected, IPv4"), "{}", log());
    e.down(VPNKind::Wireguard, &id).unwrap();
}

/// NM allows one secret agent per identifier and user: with another LinVPN (or a test) of the user registered, the
/// connect says so instead of "NetworkManager is not running.".
#[test]
fn a_second_agent_of_the_user_is_named_not_a_missing_networkmanager() {
    let (nm, am, tmp) = with_agent_manager();
    am.refuse_registrations();
    let e = engine(&tmp);
    let err = e.up(VPNKind::Wireguard, &Uuid::new_v4(), WG.as_bytes(), &Secrets::default(), false, &[]).unwrap_err();
    assert!(err.starts_with("Another LinVPN (or a LinVPN test) is already registered"), "{err}");
    assert!(nm.calls().iter().all(|c| c.method != "AddAndActivateConnection2"));
}

#[test]
fn liveness_and_traffic_come_from_the_tunnel_counters() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "10.99.13.5" });
    e.up(VPNKind::Wireguard, &id, WG.as_bytes(), &Secrets::default(), false, &[]).unwrap();
    connected(&e, &id);
    // The fake has no real interface: the engine's counter source is swapped for tests.
    e.set_counters_for_tests(Box::new(|i| i.starts_with("lvw").then_some((100, 444))));
    assert_eq!(e.liveness(&id), Some(Liveness::Counters { rx: 100, tx: 444, keepalive: 25 }));
    let t = HelperTunnel { id: &id, kind: VPNKind::Wireguard, iface: None, ip: None, since: Some(1.0) };
    let r = e.traffic(&t).unwrap();
    assert_eq!((r.rx, r.tx, r.from_zero), (100, 444, true));
    e.down(VPNKind::Wireguard, &id).unwrap();
    assert_eq!(e.liveness(&id), None);
    assert!(e.traffic(&t).is_none());
}

/// OpenVPN restarting itself (`ping-restart`) under an activated VPN: NM's VPN state goes back to `Connect`, the
/// run reports `Liveness::OpenVpn { reconnecting_since }` (app-core's "Reconnecting…", dead after its limit) and
/// `connecting`; back at `Activated` it is connected again with the counters. Were NM to keep the VPN `Activated`
/// through the restart, the counters stay the facts (app-core's counter rule decides).
#[test]
fn openvpn_restarting_itself_reports_reconnecting_then_counters_again() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "198.51.100.9" });
    let secrets = Secrets { username: Some("alice".into()), password: Some("pw".into()), ..Secrets::default() };
    e.up(VPNKind::Openvpn, &id, OVPN.as_bytes(), &secrets, false, &[]).unwrap();
    connected(&e, &id);
    e.set_counters_for_tests(Box::new(|i| i.starts_with("lvo").then_some((500, 700))));
    assert_eq!(e.liveness(&id), Some(Liveness::Counters { rx: 500, tx: 700, keepalive: 0 }));

    let before = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    nm.set_last_vpn_state(3);
    let since = wait(|| match e.liveness(&id) {
        Some(Liveness::OpenVpn { reconnecting_since: Some(t) }) => Some(t),
        _ => None,
    });
    assert!(since >= before, "{since} < {before}");
    assert!(e.status().unwrap().iter().any(|s| s.id == id && s.state == "connecting"));
    // Polled again while still restarting: the same start time (the limit counts from it).
    e.status().unwrap();
    assert_eq!(e.liveness(&id), Some(Liveness::OpenVpn { reconnecting_since: Some(since) }));
    let t = HelperTunnel { id: &id, kind: VPNKind::Openvpn, iface: None, ip: None, since: Some(1.0) };
    assert!(e.traffic(&t).is_some(), "the interface keeps counting through the restart");

    nm.set_last_vpn_state(5);
    connected(&e, &id);
    wait(|| matches!(e.liveness(&id), Some(Liveness::Counters { .. })).then_some(()));
    let log = std::fs::read_to_string(e.log_path(&id).unwrap()).unwrap();
    assert!(log.contains("Reconnecting (NetworkManager)"), "{log}");
    assert_eq!(log.matches("Connected, IPv4 198.51.100.9").count(), 2, "{log}");
    e.down(VPNKind::Openvpn, &id).unwrap();
}

#[test]
fn an_ikev2_psk_shorter_than_charon_nm_takes_is_refused_before_anything_is_written() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let config = swan("auth = psk\n      id = client.example.com", "auth = psk");
    let short = Secrets { psk: Some("short-psk".into()), ..Secrets::default() };
    let err = e.up(VPNKind::Strongswan, &Uuid::new_v4(), config.as_bytes(), &short, false, &[]).unwrap_err();
    assert!(err.contains("20"), "{err}");
    assert!(nm.calls().iter().all(|c| c.method != "AddAndActivateConnection2"));

    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "10.99.15.2" });
    let long = Secrets { psk: Some("a-pre-shared-key-of-24ch".into()), ..Secrets::default() };
    e.up(VPNKind::Strongswan, &id, config.as_bytes(), &long, false, &[]).unwrap();
    connected(&e, &id);
    assert_eq!(nm.as_nm_get_secrets(&nm.last_uuid(), "vpn", &[]).unwrap()["password"], "a-pre-shared-key-of-24ch");
    // IKEv2 through charon-nm has no tunnel interface: its SAs' counters come from linvpn-xfrmd; without an answer
    // (no service, a refusal) there is no traffic and no liveness.
    let t = HelperTunnel { id: &id, kind: VPNKind::Strongswan, iface: None, ip: None, since: None };
    e.set_xfrm_for_tests(Box::new(|_| None));
    assert!(e.traffic(&t).is_none() && e.liveness(&id).is_none());
    let own = macvpn_core::xfrmd::Target::Linvpn(id);
    e.set_xfrm_for_tests(Box::new(move |t| (*t == own).then_some((9000, 300))));
    assert_eq!(e.liveness(&id), Some(Liveness::Counters { rx: 9000, tx: 300, keepalive: 0 }), "no keepalive");
    let r = e.traffic(&t).unwrap();
    assert_eq!((r.rx, r.tx, r.from_zero), (9000, 300, true));
    assert_eq!(e.traffic(&t).unwrap().generation, r.generation, "the same run");
    // A tunnel interface holding the address that is not charon-nm's XFRM interface is not the IKEv2 tunnel.
    e.set_tunnel_ifaces_for_tests(Box::new(|ip| if ip == "10.99.15.2" { vec!["ppp0".into()] } else { vec![] }));
    e.set_counters_for_tests(Box::new(|i| (i == "ppp0").then_some((1, 2))));
    assert_eq!(e.liveness(&id), Some(Liveness::Counters { rx: 9000, tx: 300, keepalive: 0 }), "still the SAs'");
    e.down(VPNKind::Strongswan, &id).unwrap();
    assert!(e.traffic(&t).is_none() && e.liveness(&id).is_none(), "down: nothing");
}

/// strongSwan 6's charon-nm gives NM an XFRM interface (`nm-xfrm-*`) holding the virtual IP: its sysfs counters are
/// the traffic and the liveness facts, and linvpn-xfrmd is not asked.
#[test]
fn ikev2_with_charon_nms_xfrm_interface_counts_the_interface() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let config = swan("auth = psk\n      id = client.example.com", "auth = psk");
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "100.64.7.2" });
    let psk = Secrets { psk: Some("a-pre-shared-key-of-24ch".into()), ..Secrets::default() };
    e.up(VPNKind::Strongswan, &id, config.as_bytes(), &psk, false, &[]).unwrap();
    connected(&e, &id);
    let asked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = asked.clone();
    e.set_xfrm_for_tests(Box::new(move |_| {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
        Some((1, 1))
    }));
    e.set_tunnel_ifaces_for_tests(Box::new(|ip| {
        if ip == "100.64.7.2" { vec!["ppp3".into(), "nm-xfrm-1804289".into()] } else { vec![] }
    }));
    e.set_counters_for_tests(Box::new(|i| (i == "nm-xfrm-1804289").then_some((4321, 1234))));
    assert_eq!(e.liveness(&id), Some(Liveness::Counters { rx: 4321, tx: 1234, keepalive: 0 }), "no keepalive");
    let t = HelperTunnel { id: &id, kind: VPNKind::Strongswan, iface: None, ip: None, since: None };
    let r = e.traffic(&t).unwrap();
    assert_eq!((r.rx, r.tx, r.from_zero), (4321, 1234, true));
    assert_eq!(e.traffic(&t).unwrap().generation, r.generation, "the same run");
    assert!(!asked.load(std::sync::atomic::Ordering::SeqCst), "linvpn-xfrmd is not asked");
    // The interface unreadable (gone): no reading rather than the SAs' (a different counter).
    e.set_counters_for_tests(Box::new(|_| None));
    assert!(e.traffic(&t).is_none() && e.liveness(&id).is_none());
    e.down(VPNKind::Strongswan, &id).unwrap();
    assert!(e.traffic(&t).is_none() && e.liveness(&id).is_none(), "down: nothing");
}

#[test]
fn an_ikev2_client_key_gets_the_vaults_key_passphrase() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "10.99.15.3" });
    let config = swan("auth = pubkey\n      certs = client.pem\n      id = client.example.com", "auth = pubkey");
    let secrets =
        Secrets { key_password: Some("key-pass".into()), password: Some("other".into()), ..Secrets::default() };
    e.up(VPNKind::Strongswan, &id, config.as_bytes(), &secrets, false, &[]).unwrap();
    connected(&e, &id);
    let data = nm.last_vpn_data();
    assert_eq!(data.get("method").map(String::as_str), Some("key"));
    assert!(data["userkey"].ends_with("/swanctl/private/client.key"), "{data:?}");
    assert_eq!(nm.as_nm_get_secrets(&nm.last_uuid(), "vpn", &[]).unwrap()["password"], "key-pass");
    e.down(VPNKind::Strongswan, &id).unwrap();
}

#[test]
fn an_imported_ikev2_client_certificate_becomes_private_runtime_files_until_down() {
    use macvpn_core::client_cert::{self, ClientCert, fixtures};
    use std::os::unix::fs::PermissionsExt;
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "198.51.100.4" });
    let imported = client_cert::import(&[fixtures::pem_pair().as_bytes()]).unwrap().cert;
    let config = swan("auth = pubkey\n      id = client.example.com", "auth = pubkey");
    let secrets = Secrets {
        client_cert: Some(imported.stored().to_string()),
        key_password: Some("key-pass".into()),
        ..Secrets::default()
    };
    e.up(VPNKind::Strongswan, &id, config.as_bytes(), &secrets, true, &[]).unwrap();
    connected(&e, &id);
    let data = nm.last_vpn_data();
    assert_eq!(data.get("method").map(String::as_str), Some("key"));
    let cert = std::path::PathBuf::from(&data["usercert"]);
    let key = std::path::PathBuf::from(&data["userkey"]);
    let dir = tmp.path().join("run/linvpn/nm").join(nm.last_uuid());
    assert_eq!((cert.parent(), key.parent()), (Some(dir.as_path()), Some(dir.as_path())));
    let ClientCert::Pem { cert: der, key: key_pem, .. } = &imported else { panic!() };
    assert_eq!(std::fs::read_to_string(&cert).unwrap(), macvpn_core::x509::to_pem(der));
    assert_eq!(std::fs::read_to_string(&key).unwrap(), key_pem.as_str());
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!((mode(&cert), mode(&key), mode(&dir)), (0o600, 0o600, 0o700));
    // The key's passphrase is the agent's `password` secret; no key material in NM's settings or the log.
    assert_eq!(nm.as_nm_get_secrets(&nm.last_uuid(), "vpn", &[]).unwrap()["password"], "key-pass");
    assert!(!data.values().any(|v| v.contains("-----")), "{data:?}");
    let log = std::fs::read_to_string(e.log_path(&id).unwrap()).unwrap();
    assert!(log.contains("vpn.data userkey = "), "debug shows the path: {log}");
    assert!(!log.contains("PRIVATE KEY") && !log.contains("key-pass"), "{log}");
    e.down(VPNKind::Strongswan, &id).unwrap();
    assert!(!cert.exists() && !key.exists() && !dir.exists(), "removed at down");
}

#[test]
fn an_unreadable_or_pkcs12_client_certificate_refuses_the_ikev2_start_without_writing() {
    use macvpn_core::client_cert::{self, fixtures};
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let config = swan("auth = pubkey\n      id = client.example.com", "auth = pubkey");
    let broken = Secrets { client_cert: Some("pem:not-base64".into()), ..Secrets::default() };
    let err = e.up(VPNKind::Strongswan, &Uuid::new_v4(), config.as_bytes(), &broken, false, &[]).unwrap_err();
    assert!(err.contains("Import it again"), "{err}");
    let p12 = client_cert::import(&[&fixtures::p12()]).unwrap().cert;
    let p12 = Secrets { client_cert: Some(p12.stored().to_string()), ..Secrets::default() };
    let err = e.up(VPNKind::Strongswan, &Uuid::new_v4(), config.as_bytes(), &p12, false, &[]).unwrap_err();
    assert!(err.contains("PKCS#12"), "an unreadable PKCS#12 file: {err}");
    // Without any client certificate the reason names both ways.
    let err = e.up(VPNKind::Strongswan, &Uuid::new_v4(), config.as_bytes(), &Secrets::default(), false, &[]);
    assert!(err.unwrap_err().contains("Import Client Certificate"));
    assert!(nm.calls().iter().all(|c| c.method != "AddAndActivateConnection2"));
    assert!(!tmp.path().join("run/linvpn").exists(), "no runtime file written");
}

/// A PKCS#12 file restored from a Mac is converted at connect (the real `/usr/bin/openssl`) with the key password,
/// only into the runtime files; a wrong password refuses the start before anything is written.
#[test]
fn a_restored_pkcs12_client_certificate_is_converted_at_connect() {
    use std::process::Command;
    let (nm, _am, tmp) = with_agent_manager();
    let work = tmp.path().join("p12");
    std::fs::create_dir_all(&work).unwrap();
    let ok = |args: &[&str]| Command::new("/usr/bin/openssl").current_dir(&work).args(args).status().unwrap().success();
    assert!(ok(&[
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-noenc",
        "-keyout",
        "c.key",
        "-out",
        "c.crt",
        "-days",
        "30",
        "-subj",
        "/CN=client.example.com",
    ]));
    assert!(ok(&[
        "pkcs12",
        "-export",
        "-inkey",
        "c.key",
        "-in",
        "c.crt",
        "-out",
        "c.p12",
        "-passout",
        "pass:p12-pass"
    ]));
    let der = std::fs::read(work.join("c.p12")).unwrap();
    let stored = format!("p12:{}", base64_encode(&der));
    assert!(macvpn_core::client_cert::ClientCert::from_stored(&stored).is_some());
    let e = engine(&tmp);
    let config = swan("auth = pubkey\n      id = client.example.com", "auth = pubkey");
    let wrong = Secrets { client_cert: Some(stored.clone()), key_password: Some("nope".into()), ..Secrets::default() };
    let err = e.up(VPNKind::Strongswan, &Uuid::new_v4(), config.as_bytes(), &wrong, false, &[]).unwrap_err();
    assert_eq!(err, "The PKCS#12 password is wrong.");
    assert!(!tmp.path().join("run/linvpn").exists(), "no runtime file written");

    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "198.51.100.5" });
    let right = Secrets { client_cert: Some(stored), key_password: Some("p12-pass".into()), ..Secrets::default() };
    e.up(VPNKind::Strongswan, &id, config.as_bytes(), &right, false, &[]).unwrap();
    connected(&e, &id);
    let data = nm.last_vpn_data();
    let key = std::fs::read_to_string(&data["userkey"]).unwrap();
    assert!(key.contains("ENCRYPTED PRIVATE KEY"), "the key keeps its password");
    assert!(std::fs::read_to_string(&data["usercert"]).unwrap().contains("BEGIN CERTIFICATE"));
    assert_eq!(nm.as_nm_get_secrets(&nm.last_uuid(), "vpn", &[]).unwrap()["password"], "p12-pass");
    e.down(VPNKind::Strongswan, &id).unwrap();
    assert!(!std::path::Path::new(&data["userkey"]).exists());
}

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[test]
fn polkit_refusal_and_a_missing_runtime_dir_refuse_the_start_without_writing() {
    let (nm, _am, tmp) = with_agent_manager_polkit(fake_nm::Polkit::Challenge);
    let e = engine(&tmp);
    let err = e.up(VPNKind::Openvpn, &Uuid::new_v4(), OVPN.as_bytes(), &Secrets::default(), false, &[]).unwrap_err();
    assert!(err.contains("password"), "{err}");
    assert!(nm.calls().iter().all(|c| c.method != "AddAndActivateConnection2"));
    assert!(!tmp.path().join("run/linvpn").exists(), "no runtime file written");
    let e2 = Engine::new(zbus::blocking::Connection::session, false, "u".into(), 1001, None, tmp.path().join("d"));
    let err = e2.up(VPNKind::Wireguard, &Uuid::new_v4(), WG.as_bytes(), &Secrets::default(), false, &[]).unwrap_err();
    assert!(err.contains("XDG_RUNTIME_DIR"), "{err}");
}

#[test]
fn a_linux_refusal_is_the_start_error() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let ovpn = "client\ndev tun\nremote vpn.example.com 1194\npeer-fingerprint AB:CD\n";
    let err = e.up(VPNKind::Openvpn, &Uuid::new_v4(), ovpn.as_bytes(), &Secrets::default(), false, &[]).unwrap_err();
    assert!(err.contains("peer-fingerprint"), "{err}");
    let err = e.up(VPNKind::L2tp, &Uuid::new_v4(), b"", &Secrets::default(), false, &[]).unwrap_err();
    assert!(!err.is_empty());
    assert!(nm.calls().iter().all(|c| c.method != "AddAndActivateConnection2"));
}

#[test]
fn the_sandbox_refuses_and_the_log_clears_in_place() {
    let (_nm, _am, tmp) = with_agent_manager();
    let sandbox = Engine::new(
        zbus::blocking::Connection::session,
        true,
        "linvpn-dev".into(),
        1001,
        Some(tmp.path().join("run")),
        tmp.path().join("data"),
    );
    assert!(sandbox.up(VPNKind::Wireguard, &Uuid::new_v4(), WG.as_bytes(), &Secrets::default(), false, &[]).is_err());

    let e = engine(&tmp);
    let id = Uuid::new_v4();
    let path = e.log_path(&id).unwrap();
    assert!(path.ends_with(format!("data/logs/{}.log", id.hyphenated().to_string().to_uppercase())));
    e.clear_log(&id, "═══ cleared ═══").unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "old line\n").unwrap();
    e.clear_log(&id, "═══ cleared ═══").unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "═══ cleared ═══\n");
}

/// LinVPN's process ends without taking its tunnels down ("Quit, Keep Them Running", or a crash): the engine is
/// never dropped (it lives in a static), so nothing of it runs any more. The test leaks it the same way.
fn quit_keeping_the_tunnels(e: Arc<Engine>) {
    std::mem::forget(e);
}

#[test]
fn a_tunnel_left_running_is_adopted_at_the_next_start_and_a_normal_quit_takes_it_down() {
    let (nm, _am, tmp) = with_agent_manager();
    let first = engine(&tmp);
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "10.99.13.5" });
    first.up(VPNKind::Wireguard, &id, WG.as_bytes(), &Secrets::default(), false, &[]).unwrap();
    connected(&first, &id);
    let (uuid, path) = (nm.last_uuid(), nm.last_active_path());
    quit_keeping_the_tunnels(first);
    // Not bound to the old process: NM keeps it.
    assert!(nm.deactivated().is_empty());

    // The next launch: found by its derived UUID among NM's active connections, reported connected.
    let e = engine(&tmp);
    let s = connected(&e, &id);
    assert_eq!(s.kind, "wireguard");
    assert!(s.iface.as_deref().is_some_and(|i| i.starts_with("lvw")), "{:?}", s.iface);
    assert_eq!(s.ip.as_deref(), Some("10.99.13.5"));
    assert_eq!(e.runs()[0].nm_uuid, uuid);
    e.set_counters_for_tests(Box::new(|i| i.starts_with("lvw").then_some((7, 9))));
    assert_eq!(e.liveness(&id), Some(Liveness::Counters { rx: 7, tx: 9, keepalive: 25 }));
    let t = HelperTunnel { id: &id, kind: VPNKind::Wireguard, iface: None, ip: None, since: None };
    assert_eq!(e.traffic(&t).map(|r| (r.rx, r.tx)), Some((7, 9)));
    // Its runtime directory (and run record) stayed for it.
    assert!(tmp.path().join("run/linvpn/nm").join(&uuid).is_dir());

    // Adopted without the vault's secrets: its log asks for them once, a fresh connect never does.
    assert!(e.wants_log_secrets(&id));
    e.set_log_secrets(&id, &Secrets { password: Some("pw".into()), ..Secrets::default() });
    assert!(!e.wants_log_secrets(&id));

    // A normal quit (app-core's "Disconnect and Quit") goes through `down`.
    e.down(VPNKind::Wireguard, &id).unwrap();
    assert_eq!(nm.deactivated(), vec![path]);
    assert!(e.status().unwrap().is_empty());
    assert!(!tmp.path().join("run/linvpn/nm").join(&uuid).exists(), "its runtime directory goes with it");
}

#[test]
fn adoption_keeps_an_active_connections_certificate_files_and_sweeps_the_rest() {
    let (nm, _am, tmp) = with_agent_manager();
    let first = engine(&tmp);
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "10.99.14.2" });
    let secrets = Secrets { username: Some("alice".into()), password: Some("pw-123".into()), ..Secrets::default() };
    first.up(VPNKind::Openvpn, &id, OVPN.as_bytes(), &secrets, false, &[]).unwrap();
    connected(&first, &id);
    let ca = std::path::PathBuf::from(&nm.last_vpn_data()["ca"]);
    quit_keeping_the_tunnels(first);
    // A crashed run's leftover of a connection NM no longer has.
    let stale = tmp.path().join("run/linvpn/nm").join(Uuid::new_v4().to_string());
    std::fs::create_dir(&stale).unwrap();
    std::fs::write(stale.join("ca.pem"), "old").unwrap();

    let e = engine(&tmp);
    let s = connected(&e, &id);
    assert_eq!(s.kind, "openvpn");
    assert_eq!(std::fs::read_to_string(&ca).unwrap(), "C\n", "OpenVPN may read its files again on a restart");
    assert!(!stale.exists());
    // A dynamic challenge of the adopted tunnel (a renegotiation) still reaches the app.
    let pending = nm.as_nm_get_secrets_async(
        &nm.last_uuid(),
        "vpn",
        &["x-vpn-message:Code?", "x-dynamic-challenge:challenge-response"],
    );
    assert_eq!(wait(|| e.read(&id)).text.as_deref(), Some("Code?"));
    e.respond(&id, macvpn_core::mfa::AuthResponseKind::Crv1, "424242").unwrap();
    assert_eq!(pending.join().unwrap()["challenge-response"], "424242");
    e.down(VPNKind::Openvpn, &id).unwrap();
    assert!(!ca.exists());
}

#[test]
fn only_our_own_volatile_connection_with_the_derived_uuid_is_adopted() {
    use macvpn_platform_linux::lin_for_tests::nm::files::{self, RunRecord};
    let (nm, _am, tmp) = with_agent_manager();
    let runtime = tmp.path().join("run");
    std::fs::create_dir_all(&runtime).unwrap();
    let record =
        |id: Uuid| RunRecord { id, kind: VPNKind::Wireguard, iface: Some("lvw1".into()), keepalive: 0, since: 1.0 };
    let derived = |id: &Uuid| macvpn_core::nm_plan::names::nm_uuid(1001, id).to_string();

    // Active with the derived UUID, but another user's profile (not volatile, not private to us).
    let foreign = Uuid::new_v4();
    nm.add_profile(&derived(&foreign), &["user:someone-else"], 0);
    nm.add_active(&derived(&foreign), "wireguard", 2, Some("10.99.13.7"), "lvw1");
    let dir = files::write(&runtime, &derived(&foreign), &[]).unwrap();
    dir.write_record(&record(foreign)).unwrap();
    std::mem::forget(dir);
    // A record whose directory is not the derived UUID of its id.
    let misnamed = Uuid::new_v4();
    nm.add_profile(&derived(&misnamed), &["user:linvpn-dev"], 4);
    nm.add_active(&derived(&misnamed), "wireguard", 2, Some("10.99.13.8"), "lvw2");
    let dir = files::write(&runtime, &derived(&misnamed), &[]).unwrap();
    dir.write_record(&record(Uuid::new_v4())).unwrap();
    std::mem::forget(dir);

    let e = engine(&tmp);
    assert!(e.status().unwrap().is_empty());
    assert!(e.runs().is_empty());
    assert!(nm.deactivated().is_empty(), "nothing of anyone else is touched");
}

// ---- the secret agent's binding (security review L1) and a squatted UUID (L2) ----

fn owned_str(v: &str) -> zbus::zvariant::OwnedValue {
    zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::from(v)).unwrap()
}

#[test]
fn the_agent_answers_only_the_runs_own_profile_path_permissions_and_plugin() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "100.64.14.2" });
    let secrets = Secrets { username: Some("alice".into()), password: Some("pw-123".into()), ..Secrets::default() };
    e.up(VPNKind::Openvpn, &id, OVPN.as_bytes(), &secrets, false, &[]).unwrap();
    connected(&e, &id);
    let uuid = nm.last_uuid();
    // NM's own `user:<name>:` form is the same permission (the activation's one answer).
    let r = nm.as_nm_get_secrets_altered(&uuid, "vpn", |s, _| {
        let v = zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::from(vec!["user:linvpn-dev:"])).unwrap();
        s.get_mut("connection").unwrap().insert("permissions".into(), v);
    });
    assert_eq!(r.unwrap()["password"], "pw-123");
    // Another profile with the same UUID (another path): nothing.
    let other_path = nm.as_nm_get_secrets_altered(&uuid, "vpn", |_, path| {
        *path = "/org/freedesktop/NetworkManager/Settings/999".into();
    });
    assert!(other_path.is_err(), "{other_path:?}");
    // The run's path but other permissions or another plugin: nothing.
    for permissions in [vec!["user:someone-else".to_string()], vec![], vec!["user:linvpn-dev".into(), "user:x".into()]]
    {
        let r = nm.as_nm_get_secrets_altered(&uuid, "vpn", |s, _| {
            let v = zbus::zvariant::OwnedValue::try_from(zbus::zvariant::Value::from(permissions.clone())).unwrap();
            s.get_mut("connection").unwrap().insert("permissions".into(), v);
        });
        assert!(r.is_err(), "{permissions:?}: {r:?}");
    }
    let r = nm.as_nm_get_secrets_altered(&uuid, "vpn", |s, _| {
        s.get_mut("vpn").unwrap().insert("service-type".into(), owned_str("org.freedesktop.NetworkManager.l2tp"));
    });
    assert!(r.is_err(), "another plugin: {r:?}");
    // The run's own profile asking again: the stored secrets are answered once per activation (a refused sign-in).
    let again = nm.as_nm_get_secrets(&uuid, "vpn", &["password"]);
    assert!(again.as_ref().is_err_and(|e| e.contains("UserCanceled")), "{again:?}");
    e.down(VPNKind::Openvpn, &id).unwrap();
}

#[test]
fn the_secrets_are_gone_once_the_run_failed() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    nm.activate_next(Outcome::Activated { ip4: "100.64.14.3" });
    let secrets = Secrets { username: Some("alice".into()), password: Some("pw-9".into()), ..Secrets::default() };
    e.up(VPNKind::Openvpn, &id, OVPN.as_bytes(), &secrets, false, &[]).unwrap();
    connected(&e, &id);
    let uuid = nm.last_uuid();
    assert!(nm.as_nm_get_secrets(&uuid, "vpn", &[]).is_ok());
    // NM reports Failed; its profile is still there (NM drops it a moment later).
    nm.set_last_vpn_state(6);
    wait(|| nm.as_nm_get_secrets(&uuid, "vpn", &[]).is_err().then_some(()));
}

#[test]
fn another_users_profile_with_the_derived_uuid_gets_a_clear_error_and_is_not_touched() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    let derived = macvpn_core::nm_plan::names::nm_uuid(1001, &id).to_string();
    // Hidden from this user (its permissions leave us out): NM refuses even the lookup.
    let settings = std::collections::HashMap::from([(
        "connection".to_string(),
        std::collections::HashMap::from([
            ("id".to_string(), owned_str("hidden")),
            ("uuid".to_string(), owned_str(&derived)),
            ("type".to_string(), owned_str("wireguard")),
        ]),
    )]);
    nm.add_profile_settings(settings, 0);
    let err = e.up(VPNKind::Wireguard, &id, WG.as_bytes(), &Secrets::default(), false, &[]).unwrap_err();
    assert!(err.contains("Another user's NetworkManager connection uses this connection's ID"), "{err}");
    assert!(nm.deleted().is_empty(), "another user's profile is never deleted");
}

#[test]
fn another_users_visible_profile_with_the_derived_uuid_gets_the_same_error() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    let derived = macvpn_core::nm_plan::names::nm_uuid(1001, &id).to_string();
    nm.add_profile(&derived, &["user:someone-else"], 4 | 1);
    let err = e.up(VPNKind::Wireguard, &id, WG.as_bytes(), &Secrets::default(), false, &[]).unwrap_err();
    assert!(err.contains("Another user's NetworkManager connection"), "{err}");
    assert!(nm.deleted().is_empty());
}
