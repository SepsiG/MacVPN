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
        ..ManagerSnapshot::default()
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
fn held_by_labels_follow_the_lease_holders() {
    let f = Fixture::new(AppLanguage::En);
    let a = Connection::new("Office", VPNKind::Openvpn);
    let b = Connection::new("Lab", VPNKind::Openvpn);
    f.store.save(&a, Some("remote x\n")).unwrap();
    f.store.save(&b, Some("remote x\n")).unwrap();
    let m = f.manager();
    m.reload();
    let mut vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    assert!(vm.rows.iter().all(|r| r.held_by.is_empty()));
    let holders = std::collections::BTreeMap::from([(
        uuid_string(&a.id),
        vec!["Backup".to_string(), "Remote Desktop".to_string()],
    )]);
    vm.set_holders(&holders);
    let office = vm.rows.iter().find(|r| r.name == "Office").unwrap();
    assert_eq!(office.held_by, ["Backup", "Remote Desktop"]);
    assert!(vm.rows.iter().find(|r| r.name == "Lab").unwrap().held_by.is_empty());
    let json = serde_json::to_value(&vm).unwrap();
    assert!(
        json["rows"].as_array().unwrap().iter().any(|r| r["heldBy"] == serde_json::json!(["Backup", "Remote Desktop"]))
    );
    // Nothing held any more: the labels go.
    vm.set_holders(&Default::default());
    assert!(vm.rows.iter().all(|r| r.held_by.is_empty()));
}

/// The paired apps reach the UI without their token hash (and the token never exists here).
#[test]
fn rows_carry_the_server_host_only_for_the_search() {
    let f = Fixture::new(AppLanguage::En);
    let mut native = Connection::new("Branch", VPNKind::L2tp);
    native.native = Some(macvpn_core::models::NativeSettings {
        server: " l2tp.example.com ".into(),
        account: "bob-account".into(),
        ..Default::default()
    });
    let ovpn = Connection::new("Office", VPNKind::Openvpn);
    let wg = Connection::new("Home", VPNKind::Wireguard);
    let ikev2 = Connection::new("Lab", VPNKind::Strongswan);
    let sstp = Connection::new("Shop", VPNKind::Sstp);
    let bare = Connection::new("Bare", VPNKind::Openvpn);
    f.store.save(&native, None).unwrap();
    let ovpn_config = "client\n# remote commented.example.com\nremote ovpn-a.example.com 1194 udp\nremote ovpn-b.example.com 443 tcp\n\
                       auth-user-pass\n<ca>\n-----BEGIN CERTIFICATE-----\nSECRETCERTDATA\n</ca>\n";
    f.store.save(&ovpn, Some(ovpn_config)).unwrap();
    f.store
        .save(&wg, Some("[Interface]\nPrivateKey = WGPRIVATEKEYSECRET=\n[Peer]\nEndpoint = wg.example.com:51820\n"))
        .unwrap();
    f.store
        .save(&ikev2, Some("connections {\n  lab {\n    remote_addrs = ike.example.com, ike2.example.com\n"))
        .unwrap();
    f.store.save(&sstp, Some("server=sstp.example.com\nport=443\nuser=alice-user\n")).unwrap();
    f.store.save(&bare, Some("client\ndev tun\n")).unwrap();
    let m = f.manager();
    m.reload();
    let mut vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    vm.set_server_hosts(&m.server_hosts());
    let server = |id| vm.rows.iter().find(|r| r.id == uuid_string(id)).unwrap().server.clone();
    assert_eq!(server(&native.id).as_deref(), Some("l2tp.example.com"));
    assert_eq!(
        server(&ovpn.id).as_deref(),
        Some("ovpn-a.example.com"),
        "the first live remote, without port or protocol"
    );
    assert_eq!(server(&wg.id).as_deref(), Some("wg.example.com"));
    assert_eq!(server(&ikev2.id).as_deref(), Some("ike.example.com"));
    assert_eq!(server(&sstp.id).as_deref(), Some("sstp.example.com"));
    assert_eq!(server(&bare.id), None);
    let json = serde_json::to_string(&vm).unwrap();
    assert!(json.contains(r#""server":"ovpn-a.example.com""#));
    for leaked in [
        "bob-account",
        "1194",
        "51820",
        "remote ",
        "ovpn-b",
        "commented",
        "auth-user-pass",
        "SECRETCERTDATA",
        "WGPRIVATEKEYSECRET",
        "alice-user",
        "ike2",
        "Endpoint",
        "server=",
    ] {
        assert!(!json.contains(leaked), "{leaked} leaked into the view model");
    }

    // A changed config is read again with the reload that follows every save; a deleted connection leaves.
    f.store.save(&ovpn, Some("client\nremote moved.example.com 1194\n")).unwrap();
    f.store.delete(&wg.id).unwrap();
    m.reload();
    let hosts = m.server_hosts();
    assert_eq!(hosts.get(&uuid_string(&ovpn.id)).map(String::as_str), Some("moved.example.com"));
    assert!(!hosts.contains_key(&uuid_string(&wg.id)), "deleted");
    assert!(!hosts.contains_key(&uuid_string(&native.id)), "a native server comes from the snapshot");
    // Locked: the hosts go with the rows.
    m.enter_locked();
    assert!(m.server_hosts().is_empty());
}

/// A store that counts the config reads.
struct CountingStore {
    inner: Arc<macvpn_core::store::ConnectionStore>,
    reads: std::sync::atomic::AtomicUsize,
}

impl macvpn_app_core::deps::ConnectionRepository for CountingStore {
    fn list(&self) -> std::io::Result<Vec<Connection>> {
        self.inner.list()
    }
    fn save(&self, c: &Connection, config: Option<&str>) -> std::io::Result<()> {
        self.inner.save(c, config)
    }
    fn load_config(&self, id: &uuid::Uuid) -> std::io::Result<String> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.load_config(id)
    }
    fn delete(&self, id: &uuid::Uuid) -> std::io::Result<()> {
        self.inner.delete(id)
    }
}

/// The view model is built from what the reload (after a save, an import, a catalog apply, the unlock) left: no
/// config is read while building it, however often it is built.
#[test]
fn building_the_view_model_reads_no_config() {
    let f = Fixture::new(AppLanguage::En);
    for i in 0..5 {
        let c = Connection::new(format!("C{i}"), VPNKind::Openvpn);
        f.store.save(&c, Some(&format!("client\nremote host{i}.example.com 1194\n"))).unwrap();
    }
    let store = Arc::new(CountingStore { inner: f.store.clone(), reads: Default::default() });
    let mut deps = f.deps();
    deps.store = store.clone();
    let m = f.manager_with(deps);
    let after_reload = store.reads.load(std::sync::atomic::Ordering::SeqCst);
    for _ in 0..10 {
        let mut vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
        vm.set_server_hosts(&m.server_hosts());
        assert_eq!(vm.rows.iter().filter(|r| r.server.is_some()).count(), 5);
    }
    assert_eq!(store.reads.load(std::sync::atomic::Ordering::SeqCst), after_reload, "the view model read a config");
}

#[test]
fn control_view_never_carries_the_token_or_its_hash() {
    use macvpn_app_core::view_model::ControlView;
    use macvpn_core::control::registry::{PairedClient, new_token};
    let token = new_token([7; 32]);
    let mut client = PairedClient::new(
        uuid::Uuid::new_v4(),
        "Remote Desktop".into(),
        &token,
        "/Applications/Remote Desktop.app/Contents/MacOS/Remote Desktop".into(),
        vec!["38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4".into()],
        Date::from_time_interval_since_1970(1_800_000_000.0),
    );
    client.last_used = Some(Date::from_time_interval_since_1970(1_800_000_100.0));
    let changes = std::collections::HashMap::from([(client.id, "/tmp/rd".to_string())]);
    let view = ControlView::build(true, true, None, std::slice::from_ref(&client), &changes, vec!["hello".into()]);
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains(&token));
    assert!(!json.contains(&client.token_sha256));
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let app = &value["clients"][0];
    let mut keys: Vec<&String> = app.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["allowed", "created", "executable", "id", "lastUsed", "name", "pathChanged"]);
    assert_eq!(app["pathChanged"], "/tmp/rd");
    assert_eq!(app["lastUsed"], 1_800_000_100.0);
    assert_eq!(value["enabled"], true);
    assert_eq!(value["activity"], serde_json::json!(["hello"]));
}

/// Defence in depth: a pinned path (from an older registry) or a "path changed" note with a control or format
/// character reaches the UI escaped, never raw.
#[test]
fn control_view_escapes_control_and_format_characters_in_paths() {
    use macvpn_app_core::view_model::ControlView;
    use macvpn_core::control::registry::{PairedClient, new_token};
    let client = PairedClient::new(
        uuid::Uuid::new_v4(),
        "Remote Desktop".into(),
        &new_token([7; 32]),
        "/tmp/a\nb".into(),
        vec![],
        Date::from_time_interval_since_1970(1_800_000_000.0),
    );
    let changes = std::collections::HashMap::from([(client.id, "/tmp/evil\u{202E}ppa.exe".to_string())]);
    let view = ControlView::build(true, true, None, std::slice::from_ref(&client), &changes, vec![]);
    assert_eq!(view.clients[0].executable, "/tmp/a\\u{a}b");
    assert_eq!(view.clients[0].path_changed.as_deref(), Some("/tmp/evil\\u{202e}ppa.exe"));
    let normal = PairedClient { executable: "/Applications/X.app/Contents/MacOS/X".into(), ..client };
    let view = ControlView::build(true, true, None, std::slice::from_ref(&normal), &Default::default(), vec![]);
    assert_eq!(view.clients[0].executable, "/Applications/X.app/Contents/MacOS/X");
}

/// The menu's "MacVPN <version>": the Cargo version, the same as the bundle's (`tauri.conf.json`), never a
/// version of the UI's own.
#[test]
fn view_model_carries_the_app_version() {
    let vm = ViewModel::build(&snapshot(&[], None), "en", |_| true, Vec::new(), false);
    assert_eq!(vm.app_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(vm.app_version, macvpn_core::VERSION);
    assert_eq!(serde_json::to_value(&vm).unwrap()["appVersion"], env!("CARGO_PKG_VERSION"));
    let conf: serde_json::Value = serde_json::from_str(include_str!("../../../app/src-tauri/tauri.conf.json")).unwrap();
    assert_eq!(conf["version"], vm.app_version);
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

#[test]
fn catalog_connections_carry_the_team_badge() {
    use macvpn_app_core::catalog::CatalogBadge;
    let f = Fixture::new(AppLanguage::En);
    let a = Connection::new("Office", VPNKind::Openvpn);
    let b = Connection::new("Own", VPNKind::Openvpn);
    f.store.save(&a, Some("remote x\n")).unwrap();
    f.store.save(&b, Some("remote x\n")).unwrap();
    let m = f.manager();
    let mut vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    assert!(vm.rows.iter().all(|r| r.catalog.is_none()));
    let badge = CatalogBadge {
        catalog_id: "11111111-1111-4111-8111-111111111111".into(),
        name: "Acme VPN".into(),
        pending_removal: true,
        profile_outdated: false,
    };
    vm.set_catalog_badges(&std::collections::HashMap::from([(uuid_string(&a.id), badge.clone())]));
    assert_eq!(vm.rows.iter().find(|r| r.name == "Office").unwrap().catalog, Some(badge));
    assert_eq!(vm.rows.iter().find(|r| r.name == "Own").unwrap().catalog, None);
    let json = serde_json::to_value(&vm).unwrap();
    let office = json["rows"].as_array().unwrap().iter().find(|r| r["name"] == "Office").unwrap().clone();
    assert_eq!(
        office["catalog"],
        serde_json::json!({"catalogId":"11111111-1111-4111-8111-111111111111","name":"Acme VPN","pendingRemoval":true,"profileOutdated":false})
    );
}
