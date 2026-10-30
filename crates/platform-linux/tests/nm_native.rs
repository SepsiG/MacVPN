#![cfg(target_os = "linux")]
//! Managed L2TP and Cisco IPsec (`NativeProfiles` + `NativeController`, resolved point 2) against the fake NM,
//! polkit and agent manager on the test's private bus (dbus-run-session).
mod fake_nm;

use fake_nm::engine_ext::{Outcome, Tmp, with_agent_manager};
use macvpn_core::models::{Connection, NativeSettings, Secrets, VPNKind};
use macvpn_core::native::NativeKind;
use macvpn_platform_api::{NativeController, NativeProfiles};
use macvpn_platform_linux::lin_for_tests::nm::engine::Engine;
use macvpn_platform_linux::lin_for_tests::nm::plan_store;
use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

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

fn native(kind: VPNKind, group: &str) -> Connection {
    let mut c = Connection::new("Office", kind);
    c.native = Some(NativeSettings {
        server: "vpn.example.com".into(),
        account: "alice".into(),
        group_name: group.into(),
        send_all_traffic: false,
    });
    c
}

fn secrets() -> Secrets {
    Secrets { password: Some("pass-word-1".into()), psk: Some("shared-secret-2".into()), ..Secrets::default() }
}

fn service(id: &Uuid) -> String {
    format!("linvpn-{}", id.hyphenated().to_string().to_uppercase())
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

/// `build` + `install`, as the editor's Save does.
fn save(e: &Engine, c: &Connection) {
    let profile = e.build(c, "shared-secret-2").unwrap();
    e.install(&c.id, &profile.data, &profile.file_name, false).unwrap();
}

#[test]
fn the_profile_is_a_secret_free_record_written_private() {
    let (_nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let c = native(VPNKind::L2tp, "");
    let profile = e.build(&c, "shared-secret-2").unwrap();
    let data = String::from_utf8(profile.data.to_vec()).unwrap();
    assert!(!data.contains("psk") && !data.contains("shared-secret-2"), "{data}");
    assert!(data.contains("\"kind\":\"l2tp\"") && data.contains("\"server\":\"vpn.example.com\""), "{data}");
    e.install(&c.id, &profile.data, &profile.file_name, false).unwrap();
    let dir = tmp.path().join("data/nm");
    let file = dir.join(format!("{}.json", c.id));
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::read(&file).unwrap(), profile.data.to_vec());
    // An unchanged install leaves the file alone; a changed one rewrites it.
    e.install(&c.id, &profile.data, &profile.file_name, true).unwrap();
    let mut changed = c.clone();
    changed.native.as_mut().unwrap().server = "vpn2.example.com".into();
    save(&e, &changed);
    assert!(std::fs::read_to_string(&file).unwrap().contains("vpn2.example.com"));
    assert!(e.removes_profiles() && !e.needs_approval());
    // Not a native kind, or no settings.
    assert!(e.build(&Connection::new("W", VPNKind::Wireguard), "").is_err());
    assert!(e.build(&Connection::new("L", VPNKind::L2tp), "").is_err());
}

#[test]
fn a_record_is_parsed_strictly_and_must_be_ours_and_private() {
    let (_nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    for bad in [
        r#"{"v":1,"kind":"l2tp","name":"O","server":"s","account":"a","group":"","sendAll":true,"psk":"x"}"#,
        r#"{"v":2,"kind":"l2tp","name":"O","server":"s","account":"a","group":"","sendAll":true}"#,
        r#"{"v":1,"kind":"openvpn","name":"O","server":"s","account":"a","group":"","sendAll":true}"#,
        r#"{"v":1,"kind":"l2tp","name":"O","server":"s\nx","account":"a","group":"","sendAll":true}"#,
        r#"{"v":1,"kind":"l2tp","name":"O","server":"s","account":"a","group":"","sendAll":"yes"}"#,
        r#"[1]"#,
        "",
    ] {
        assert!(e.install(&id, bad.as_bytes(), "x.json", false).is_err(), "{bad}");
    }
    let mut big = vec![b' '; 17 * 1024];
    big.extend_from_slice(br#"{"v":1,"kind":"l2tp","name":"O","server":"s","account":"a","group":"","sendAll":true}"#);
    assert!(e.install(&id, &big, "x.json", false).is_err(), "over 16 KiB");

    let c = native(VPNKind::L2tp, "");
    save(&e, &c);
    let dir = tmp.path().join("data/nm");
    let file = dir.join(format!("{}.json", c.id));
    assert!(plan_store::read(&dir, &c.id).is_ok());
    // A record readable by others is refused (R9).
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(plan_store::read(&dir, &c.id).is_err());
    assert!(e.list().unwrap().iter().all(|v| v.id != service(&c.id)));
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    // A folder open to others is refused too.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(plan_store::read(&dir, &c.id).is_err());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A symlinked record is never followed.
    let other = Uuid::new_v4();
    std::os::unix::fs::symlink(&file, dir.join(format!("{other}.json"))).unwrap();
    assert!(plan_store::read(&dir, &other).is_err());
    assert!(plan_store::read(&dir, &c.id).is_ok());
}

#[test]
fn a_managed_l2tp_lists_starts_with_the_agents_secrets_and_stops() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let c = native(VPNKind::L2tp, "");
    save(&e, &c);
    let sid = service(&c.id);
    assert_eq!(e.managed_service_id(&c.id), Some(sid.clone()));
    let row = e.list().unwrap().into_iter().find(|v| v.id == sid).expect("listed");
    assert_eq!(
        (row.name.as_str(), row.type_label.as_str(), row.status.as_str()),
        (sid.as_str(), "L2TP", "Disconnected")
    );
    assert_eq!(e.remote_address(&sid), Some("vpn.example.com".into()));

    nm.activate_next(Outcome::Activated { ip4: "10.99.14.7" });
    e.start(&sid, Some(NativeKind::L2tp), &secrets()).unwrap();
    let add = nm.calls().into_iter().find(|c| c.method == "AddAndActivateConnection2").unwrap();
    assert_eq!(add.permissions, vec!["user:linvpn-dev".to_string()]);
    assert!(!add.allow_interactive_authorization);
    assert_eq!(nm.last_setting_str("vpn", "service-type").as_deref(), Some("org.freedesktop.NetworkManager.l2tp"));
    let data = nm.last_vpn_data();
    assert_eq!(data.get("gateway").map(String::as_str), Some("vpn.example.com"));
    assert!(data.values().all(|v| !v.contains("pass-word-1") && !v.contains("shared-secret-2")));
    // A split tunnel: the mark that makes `90-linvpn-route` add the class-based route.
    assert_eq!(nm.last_user_data().get("linvpn.classful").map(String::as_str), Some("1"));
    let answer = nm.as_nm_get_secrets(&nm.last_uuid(), "vpn", &[]).unwrap();
    assert_eq!(answer.get("password").map(String::as_str), Some("pass-word-1"));
    assert_eq!(answer.get("ipsec-psk").map(String::as_str), Some("shared-secret-2"));

    wait(|| e.list().unwrap().into_iter().find(|v| v.id == sid && v.status == "Connected"));
    assert_eq!(e.address(&sid), Some("10.99.14.7".into()));
    // No PPP interface holds the fake's address: no traffic (the real one is read from sysfs).
    assert!(e.traffic(&sid).is_none());
    // The helper side never reports a native kind.
    assert!(macvpn_platform_api::HelperClient::status(&*e).unwrap().iter().all(|s| s.id != c.id));

    e.stop(&sid).unwrap();
    assert!(nm.deactivated().contains(&nm.last_active_path()));
    let row = e.list().unwrap().into_iter().find(|v| v.id == sid).unwrap();
    assert_eq!(row.status, "Disconnected");
    assert!(nm.as_nm_get_secrets(&nm.last_uuid(), "vpn", &[]).is_err(), "forgotten after stop");
    let log =
        std::fs::read_to_string(tmp.path().join("data/logs").join(format!("{}.log", c.id.to_string().to_uppercase())));
    assert!(log.is_ok_and(|l| l.contains("Connecting with NetworkManager (org.freedesktop.NetworkManager.l2tp)")));
}

#[test]
fn a_managed_cisco_answers_the_vpnc_keys() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let c = native(VPNKind::Cisco, "Staff");
    save(&e, &c);
    let sid = service(&c.id);
    let row = e.list().unwrap().into_iter().find(|v| v.id == sid).unwrap();
    assert_eq!(row.type_label, "Cisco IPsec");
    nm.activate_next(Outcome::Activated { ip4: "10.99.15.9" });
    e.start(&sid, Some(NativeKind::CiscoIPSec), &secrets()).unwrap();
    assert_eq!(nm.last_setting_str("vpn", "service-type").as_deref(), Some("org.freedesktop.NetworkManager.vpnc"));
    assert_eq!(nm.last_vpn_data().get("IPSec ID").map(String::as_str), Some("Staff"));
    assert!(nm.last_user_data().is_empty(), "Cisco: the server's split networks, no class-based route");
    let answer = nm.as_nm_get_secrets(&nm.last_uuid(), "vpn", &[]).unwrap();
    assert_eq!(answer.get("Xauth password").map(String::as_str), Some("pass-word-1"));
    assert_eq!(answer.get("IPSec secret").map(String::as_str), Some("shared-secret-2"));
    e.stop(&sid).unwrap();
}

#[test]
fn a_missing_record_is_refused_without_touching_nm() {
    let (nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let err = e.start(&service(&Uuid::new_v4()), Some(NativeKind::L2tp), &secrets()).unwrap_err();
    assert!(err.contains("save it again"), "{err}");
    assert!(nm.calls().iter().all(|c| c.method != "AddAndActivateConnection2"));
}

#[test]
fn remove_and_reconcile_delete_records() {
    let (_nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let (a, b, c) = (native(VPNKind::L2tp, ""), native(VPNKind::L2tp, ""), native(VPNKind::Cisco, "G"));
    for x in [&a, &b, &c] {
        save(&e, x);
    }
    let dir = tmp.path().join("data/nm");
    e.remove(&a.id);
    assert!(!dir.join(format!("{}.json", a.id)).exists());
    e.remove(&Uuid::new_v4()); // nothing there: nothing happens
    e.reconcile(&HashSet::from([b.id]));
    assert!(dir.join(format!("{}.json", b.id)).exists());
    assert!(!dir.join(format!("{}.json", c.id)).exists());
    let ids: Vec<String> = e.list().unwrap().into_iter().map(|v| v.id).filter(|i| i.starts_with("linvpn-")).collect();
    assert_eq!(ids, vec![service(&b.id)]);
}

#[test]
fn the_log_is_the_connection_log() {
    let (_nm, _am, tmp) = with_agent_manager();
    let e = engine(&tmp);
    let id = Uuid::new_v4();
    let logs = tmp.path().join("data/logs");
    std::fs::create_dir_all(&logs).unwrap();
    std::fs::set_permissions(&logs, std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = logs.join(format!("{}.log", id.to_string().to_uppercase()));
    std::fs::write(&file, "2026-10-30 10:00:00 Connecting\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut source = e.log_source(&id).expect("a log source");
    let read = source.read(0, 4096).expect("readable");
    assert!(String::from_utf8_lossy(&read.data).contains("Connecting"));
    assert_eq!(e.clear_log(&id, "Cleared"), Ok(true));
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(!text.contains("Connecting") && text.contains("Cleared"), "{text}");
}
