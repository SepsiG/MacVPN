//! The view model (the Swift `MenuContentView` / `MenuRow` / `menuBarSymbol` decisions), the prompt broker
//! (the non-UI half of `AuthPromptPresenter`), and the l10n keys the manager uses.

mod common;

use common::*;
use macvpn_app_core::deps::SystemVpn;
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
        connecting: states.iter().any(|s| matches!(s, ConnectionState::Connecting)),
        ..ManagerSnapshot::default()
    }
}

fn icon(states: &[ConnectionState], status_error: Option<&str>) -> TrayIcon {
    TrayIcon::from_snapshot(&snapshot(states, status_error))
}

#[test]
fn tray_icon_priority_auth_then_failure_then_connecting_then_connected() {
    let wait = ConnectionState::AwaitingAuth(AuthWait { kind: AuthWaitKind::Code, deadline: None });
    let failed = ConnectionState::Failed("x".into());
    let up = ConnectionState::Connected { ip: None, since: None };
    let connecting = ConnectionState::Connecting;
    assert_eq!(icon(&[], None), TrayIcon::Idle);
    assert_eq!(icon(&[ConnectionState::Disconnected], None), TrayIcon::Idle);
    assert_eq!(icon(std::slice::from_ref(&up), None), TrayIcon::Active);
    assert_eq!(icon(std::slice::from_ref(&up), Some("e")), TrayIcon::Failure);
    assert_eq!(icon(&[up.clone(), failed.clone()], None), TrayIcon::Failure);
    assert_eq!(icon(&[failed.clone(), wait.clone()], Some("e")), TrayIcon::Auth);
    // The maintainer's report (2026-10-28): a connection still connecting is not shown as connected.
    assert_eq!(icon(std::slice::from_ref(&connecting), None), TrayIcon::Connecting);
    // One up, another still connecting (or reconnecting): the icon says something is in progress.
    assert_eq!(icon(&[up.clone(), connecting.clone()], None), TrayIcon::Connecting);
    assert_eq!(icon(&[connecting.clone(), ConnectionState::Disconnected], None), TrayIcon::Connecting);
    // A failure and a status error still win (as before), and a code / credential wait shows the key.
    assert_eq!(icon(&[connecting.clone(), failed], None), TrayIcon::Failure);
    assert_eq!(icon(std::slice::from_ref(&connecting), Some("e")), TrayIcon::Failure);
    assert_eq!(icon(&[connecting, wait, up], None), TrayIcon::Auth);
    // Disconnecting: the tunnel is still up until it is gone.
    assert_eq!(icon(&[ConnectionState::Disconnecting], None), TrayIcon::Active);
}

#[test]
fn the_tray_tooltip_says_what_the_icon_shows() {
    // WinVPN on Windows (the product name in the resolved text).
    let tip = |language, icon: TrayIcon| {
        l10n::with_language(language, || icon.tooltip()).map(|t| t.replace("WinVPN", "MacVPN"))
    };
    assert_eq!(tip(AppLanguage::En, TrayIcon::Connecting).as_deref(), Some("MacVPN – Connecting…"));
    assert_eq!(tip(AppLanguage::En, TrayIcon::Active).as_deref(), Some("MacVPN – Connected"));
    assert_eq!(tip(AppLanguage::En, TrayIcon::Auth).as_deref(), Some("MacVPN – Waiting for authentication"));
    assert_eq!(tip(AppLanguage::En, TrayIcon::Idle), None, "the product name");
    assert_eq!(tip(AppLanguage::En, TrayIcon::Failure), None, "the product name");
    assert_eq!(tip(AppLanguage::Hu, TrayIcon::Connecting).as_deref(), Some("MacVPN – Csatlakozás…"));
    assert_eq!(tip(AppLanguage::Hu, TrayIcon::Active).as_deref(), Some("MacVPN – Csatlakozva"));
    assert_eq!(tip(AppLanguage::Hu, TrayIcon::Auth).as_deref(), Some("MacVPN – Hitelesítésre vár"));
}

/// Network loss (maintainer report, 2026-10-28): the rows of the connections waiting for network say so, and the
/// tray shows the half-filled shield with its own tooltip, never the connected one.
#[test]
fn connections_waiting_for_network_never_show_connected() {
    let f = Fixture::new(AppLanguage::En);
    let svc = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
    let other = "48B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
    f.native.set_list(Ok(vec![
        SystemVpn::new(svc, "Corp", "IKEv2", "Connected"),
        SystemVpn::new(other, "Lab", "IKEv2", "Disconnected"),
    ]));
    let m = f.manager();
    m.refresh();
    let build = || ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), false);
    let mut vm = build();
    assert_eq!(vm.tray, TrayIcon::Active);
    // Nothing waits: nothing changes.
    vm.set_waiting_for_network(&[]);
    assert_eq!(vm.tray, TrayIcon::Active);
    // A key that is not up (or unknown) changes nothing either.
    vm.set_waiting_for_network(&[other.to_string(), "nope".to_string()]);
    assert_eq!(vm.tray, TrayIcon::Active);
    vm.set_waiting_for_network(&[svc.to_string()]);
    assert_eq!(vm.tray, TrayIcon::WaitingForNetwork);
    let row = |vm: &ViewModel, id: &str| vm.rows.iter().find(|r| r.id == id).unwrap().clone();
    assert_eq!(row(&vm, svc).state, RowState::WaitingForNetwork);
    assert!(row(&vm, svc).switch_on, "it can still be switched off");
    assert_eq!(row(&vm, other).state, RowState::Disconnected);
    let json = serde_json::to_value(&vm).unwrap();
    assert_eq!(json["tray"], "waitingForNetwork");
    assert_eq!(json["rows"].as_array().unwrap().iter().find(|r| r["id"] == svc).unwrap()["state"], "waitingForNetwork");
    // Connecting is overlaid too.
    f.native.set_list(Ok(vec![SystemVpn::new(svc, "Corp", "IKEv2", "Connecting")]));
    m.refresh();
    let mut vm = build();
    vm.set_waiting_for_network(&[svc.to_string()]);
    assert_eq!((vm.tray, row(&vm, svc).state), (TrayIcon::WaitingForNetwork, RowState::WaitingForNetwork));
    // A failure (here a status error) still wins.
    f.native.set_list(Ok(vec![SystemVpn::new(svc, "Corp", "IKEv2", "Connected")]));
    m.refresh();
    let mut snap = m.snapshot();
    snap.status_error = Some("e".into());
    let mut vm = ViewModel::build(&snap, "en", |_| true, Vec::new(), false);
    vm.set_waiting_for_network(&[svc.to_string()]);
    assert_eq!((vm.tray, row(&vm, svc).state), (TrayIcon::Failure, RowState::WaitingForNetwork));
}

#[test]
fn the_waiting_for_network_tooltip() {
    let tip = |language| {
        l10n::with_language(language, || TrayIcon::WaitingForNetwork.tooltip()).map(|t| t.replace("WinVPN", "MacVPN"))
    };
    assert_eq!(tip(AppLanguage::En).as_deref(), Some("MacVPN – Waiting for network…"));
    assert_eq!(tip(AppLanguage::Hu).as_deref(), Some("MacVPN – Hálózatra vár…"));
}

#[test]
fn a_connecting_system_vpn_shows_the_connecting_icon() {
    let f = Fixture::new(AppLanguage::En);
    let svc = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
    f.native.set_list(Ok(vec![SystemVpn::new(svc, "Corp", "IKEv2", "Connecting")]));
    let m = f.manager();
    m.refresh();
    let snapshot = m.snapshot();
    assert!(snapshot.connecting);
    let vm = ViewModel::build(&snapshot, "en", |_| true, Vec::new(), false);
    assert_eq!(vm.tray, TrayIcon::Connecting);
    assert_eq!(serde_json::to_value(&vm).unwrap()["tray"], "connecting");
    f.native.set_list(Ok(vec![SystemVpn::new(svc, "Corp", "IKEv2", "Connected")]));
    m.refresh();
    assert!(!m.snapshot().connecting);
    assert_eq!(ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), false).tray, TrayIcon::Active);
}

#[test]
fn view_model_rows_follow_the_order_and_availability() {
    let f = Fixture::new(AppLanguage::En);
    let wg = Connection::new("Home WG", VPNKind::Wireguard);
    let ovpn = Connection::new("Office", VPNKind::Openvpn);
    f.store.save(&wg, Some("x")).unwrap();
    f.store.save(&ovpn, Some("remote x\n")).unwrap();
    let svc = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
    f.helper.respond(
        "status",
        Ok(&format!(
            r#"[{{"id":"{}","kind":"openvpn","state":"connected","iface":"utun4","ip":"10.8.0.2","since":1800000000}}]"#,
            uuid_string(&ovpn.id)
        )),
    );
    f.native.set_list(Ok(vec![SystemVpn::new(svc, "Corp", "IKEv2", "Disconnecting")]));
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

/// Without a VPN engine (WinVPN: no usable WinVPN Service) every row, of every type, is unavailable with the
/// engine's answer; with an engine (macOS) the rows and their JSON are unchanged.
#[test]
fn without_an_engine_every_row_carries_the_engine_note() {
    let f = Fixture::new(AppLanguage::En);
    let ovpn = Connection::new("Office", VPNKind::Openvpn);
    let l2tp = Connection::new("Branch", VPNKind::L2tp);
    f.store.save(&ovpn, Some("remote x\n")).unwrap();
    f.store.save(&l2tp, None).unwrap();
    f.native.set_list(Ok(vec![SystemVpn::new(
        "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4",
        "Corp",
        "IKEv2",
        "Disconnected",
    )]));
    let m = f.manager();
    m.refresh();
    let mut vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    let before = serde_json::to_value(&vm).unwrap();
    assert!(before["rows"].as_array().unwrap().iter().all(|r| r.get("unavailableReason").is_none()));
    vm.set_engine_missing(None);
    assert_eq!(serde_json::to_value(&vm).unwrap(), before, "macOS: nothing changes");
    vm.set_engine_missing(Some("Later."));
    assert_eq!(vm.rows.len(), 3);
    for row in &vm.rows {
        assert!(!row.available && !row.switch_enabled, "{}", row.name);
        assert_eq!(row.unavailable_reason.as_deref(), Some("Later."));
    }
    let json = serde_json::to_value(&vm).unwrap();
    assert_eq!(json["rows"][0]["unavailableReason"], "Later.");
}

/// WinVPN 2b: the kinds that come later (the native VPNs) are unavailable with their reason; the other rows and the
/// system VPNs keep theirs. An empty list (macOS) changes nothing.
#[test]
fn later_kinds_carry_their_reason() {
    let f = Fixture::new(AppLanguage::En);
    let ovpn = Connection::new("Office", VPNKind::Openvpn);
    let l2tp = Connection::new("Branch", VPNKind::L2tp);
    f.store.save(&ovpn, Some("remote x\n")).unwrap();
    f.store.save(&l2tp, None).unwrap();
    f.native.set_list(Ok(vec![SystemVpn::new(
        "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4",
        "Corp",
        "IKEv2",
        "Disconnected",
    )]));
    let m = f.manager();
    m.refresh();
    let mut vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    let before = serde_json::to_value(&vm).unwrap();
    vm.set_later_kinds(&[]);
    assert_eq!(serde_json::to_value(&vm).unwrap(), before, "macOS: nothing changes");
    vm.set_later_kinds(&[(VPNKind::L2tp, "Later.".into()), (VPNKind::Sstp, "Later.".into())]);
    assert_eq!(vm.rows.len(), 3);
    for row in &vm.rows {
        if row.kind == Some("l2tp") {
            assert!(!row.available && !row.switch_enabled);
            assert_eq!(row.unavailable_reason.as_deref(), Some("Later."));
        } else {
            assert!(row.available && row.switch_enabled, "{}", row.name);
            assert_eq!(row.unavailable_reason, None);
        }
    }
}

/// Missing engines (2.0): the rows of a kind whose engine is not installed are unavailable with the setup report's
/// label and the System Status link; other kinds, system VPNs and rows already unavailable for another reason (the
/// engine-missing or later text) keep theirs. `setupLink` is absent from the JSON when false.
#[test]
fn unavailable_kinds_show_their_label_and_the_setup_link() {
    let f = Fixture::new(AppLanguage::En);
    let ovpn = Connection::new("Office", VPNKind::Openvpn);
    let l2tp = Connection::new("Branch", VPNKind::L2tp);
    let sstp = Connection::new("Remote", VPNKind::Sstp);
    f.store.save(&ovpn, Some("remote x\n")).unwrap();
    f.store.save(&l2tp, None).unwrap();
    f.store.save(&sstp, Some("x")).unwrap();
    f.native.set_list(Ok(vec![SystemVpn::new(
        "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4",
        "Corp",
        "IKEv2",
        "Disconnected",
    )]));
    let m = f.manager();
    m.refresh();
    let mut vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    let before = serde_json::to_value(&vm).unwrap();
    vm.set_unavailable_kinds(&|_| None);
    assert_eq!(serde_json::to_value(&vm).unwrap(), before, "everything available: nothing changes");
    vm.set_later_kinds(&[(VPNKind::Sstp, "Later.".into())]);
    vm.set_unavailable_kinds(&|kind| {
        matches!(kind, VPNKind::Openvpn | VPNKind::Sstp).then(|| ("Not installed: OpenVPN".to_string(), true))
    });
    let row = |kind: &str| vm.rows.iter().find(|r| r.kind == Some(kind)).unwrap();
    let office = row("openvpn");
    assert!(!office.available && !office.switch_enabled && office.setup_link);
    assert_eq!(office.unavailable_reason.as_deref(), Some("Not installed: OpenVPN"));
    let branch = row("l2tp");
    assert!(branch.available && branch.switch_enabled && !branch.setup_link);
    assert_eq!(branch.unavailable_reason, None);
    let later = row("sstp");
    assert_eq!(later.unavailable_reason.as_deref(), Some("Later."), "an earlier reason stays");
    assert!(!later.setup_link);
    let corp = vm.rows.iter().find(|r| !r.managed).unwrap();
    assert!(corp.available && !corp.setup_link);
    let json = serde_json::to_value(&vm).unwrap();
    let rows = json["rows"].as_array().unwrap();
    let by_kind = |kind: &str| rows.iter().find(|r| r["kind"] == kind).unwrap();
    assert_eq!(by_kind("openvpn")["setupLink"], true);
    assert_eq!(by_kind("openvpn")["unavailableReason"], "Not installed: OpenVPN");
    assert!(by_kind("l2tp").get("setupLink").is_none());
    assert!(by_kind("sstp").get("setupLink").is_none());
}

/// "Reconnect Automatically" (decision 4): set by the app on managed rows only; absent from the JSON until set and
/// on system VPN rows.
#[test]
fn the_auto_reconnect_switch_is_on_managed_rows_only_when_set() {
    let f = Fixture::new(AppLanguage::En);
    let office = Connection::new("Office", VPNKind::Openvpn);
    let home = Connection::new("Home", VPNKind::Wireguard);
    f.store.save(&office, Some("remote x\n")).unwrap();
    f.store.save(&home, Some("[Interface]\n")).unwrap();
    f.native.set_list(Ok(vec![SystemVpn::new(
        "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4",
        "Corp",
        "IKEv2",
        "Disconnected",
    )]));
    let m = f.manager();
    m.refresh();
    let mut vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    let json = serde_json::to_value(&vm).unwrap();
    assert!(json["rows"].as_array().unwrap().iter().all(|r| r.get("autoReconnect").is_none()));
    let off = uuid_string(&office.id);
    vm.set_auto_reconnect(&|id| id != off);
    let row = |id: &str| vm.rows.iter().find(|r| r.id == id).unwrap();
    assert_eq!(row(&off).auto_reconnect, Some(false));
    assert_eq!(row(&uuid_string(&home.id)).auto_reconnect, Some(true));
    assert_eq!(vm.rows.iter().find(|r| !r.managed).unwrap().auto_reconnect, None);
    let json = serde_json::to_value(&vm).unwrap();
    let rows = json["rows"].as_array().unwrap();
    assert_eq!(rows.iter().find(|r| r["id"] == off.as_str()).unwrap()["autoReconnect"], false);
    assert!(rows.iter().find(|r| r["managed"] == false).unwrap().get("autoReconnect").is_none());
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
    f.helper.respond("status", Ok("[]"));
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
    assert!(!f.helper.lines().iter().any(|l| l.starts_with("up ")));
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

/// WinVPN 2c: a connection the platform cannot connect with its settings is unavailable with that reason; other
/// rows, system VPNs and rows already unavailable keep theirs. Empty (macOS): nothing changes.
#[test]
fn a_per_connection_reason_makes_the_row_unavailable() {
    let f = Fixture::new(AppLanguage::En);
    let tls = Connection::new("TLS", VPNKind::Strongswan);
    let eap = Connection::new("EAP", VPNKind::Strongswan);
    let sstp = Connection::new("Remote", VPNKind::Sstp);
    f.store.save(&tls, Some("x")).unwrap();
    f.store.save(&eap, Some("x")).unwrap();
    f.store.save(&sstp, Some("x")).unwrap();
    f.native.set_list(Ok(vec![SystemVpn::new(
        "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4",
        "Corp",
        "IKEv2",
        "Disconnected",
    )]));
    let m = f.manager();
    m.refresh();
    let mut vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    let before = serde_json::to_value(&vm).unwrap();
    vm.set_unsupported(&std::collections::HashMap::new());
    assert_eq!(serde_json::to_value(&vm).unwrap(), before, "macOS: nothing changes");
    vm.set_later_kinds(&[(VPNKind::Sstp, "Later.".into())]);
    let reasons = std::collections::HashMap::from([
        (uuid_string(&tls.id), "Not supported on Windows: local auth = eap-tls".to_string()),
        (uuid_string(&sstp.id), "Other.".to_string()),
        ("38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4".to_string(), "Never for a system VPN.".to_string()),
    ]);
    vm.set_unsupported(&reasons);
    let row = |name: &str| vm.rows.iter().find(|r| r.name == name).unwrap();
    assert!(!row("TLS").available && !row("TLS").switch_enabled && !row("TLS").setup_link);
    assert_eq!(row("TLS").unavailable_reason.as_deref(), Some("Not supported on Windows: local auth = eap-tls"));
    assert!(row("EAP").available && row("EAP").switch_enabled && row("EAP").unavailable_reason.is_none());
    assert_eq!(row("Remote").unavailable_reason.as_deref(), Some("Later."), "an earlier reason stays");
    assert!(row("Corp").available && row("Corp").unavailable_reason.is_none());
}

/// WinVPN 2c: a missing WinVPN Service greys only the rows that need it (`SetupReport::needs_service`): the RAS
/// kinds and the system VPNs keep their switches; `set_engine_missing` (every row) is unchanged.
#[test]
fn a_missing_service_greys_only_the_rows_that_need_it() {
    let f = Fixture::new(AppLanguage::En);
    let ovpn = Connection::new("Office", VPNKind::Openvpn);
    let l2tp = Connection::new("Branch", VPNKind::L2tp);
    f.store.save(&ovpn, Some("remote x\n")).unwrap();
    f.store.save(&l2tp, None).unwrap();
    f.native.set_list(Ok(vec![SystemVpn::new(
        "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4",
        "Corp",
        "IKEv2",
        "Disconnected",
    )]));
    let m = f.manager();
    m.refresh();
    let vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    let mut all = vm.clone();
    all.set_engine_missing_where(Some("No service."), &|_| true);
    let mut legacy = vm.clone();
    legacy.set_engine_missing(Some("No service."));
    assert_eq!(serde_json::to_value(&all).unwrap(), serde_json::to_value(&legacy).unwrap());
    let mut some = vm.clone();
    some.set_engine_missing_where(Some("No service."), &|kind| kind == Some(VPNKind::Openvpn));
    let row = |name: &str| some.rows.iter().find(|r| r.name == name).unwrap().clone();
    assert_eq!(row("Office").unavailable_reason.as_deref(), Some("No service."));
    assert!(!row("Office").switch_enabled);
    assert!(row("Branch").available && row("Branch").unavailable_reason.is_none());
    assert!(row("Corp").available && row("Corp").switch_enabled);
}

/// WinVPN 2c Task 11: a failed row whose reason names an administrator step (`AdminSteps::offered_action`) offers
/// its button; other rows and states offer none, and macOS (no step) leaves the JSON as it was.
#[test]
fn a_failed_row_offers_the_administrator_step_its_reason_names() {
    let f = Fixture::new(AppLanguage::En);
    let branch = Connection::new("Branch", VPNKind::L2tp);
    let remote = Connection::new("Remote", VPNKind::Sstp);
    let lab = Connection::new("Lab", VPNKind::L2tp);
    f.store.save(&branch, None).unwrap();
    f.store.save(&remote, Some("x")).unwrap();
    f.store.save(&lab, None).unwrap();
    let m = f.manager();
    m.refresh();
    let mut vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    for row in vm.rows.iter_mut().filter(|r| r.name != "Lab") {
        row.state = RowState::Failed { reason: format!("{} failed. Use Step One… first.", row.name) };
    }
    let before = serde_json::to_value(&vm).unwrap();
    vm.set_admin_actions(&|_| None);
    assert_eq!(serde_json::to_value(&vm).unwrap(), before, "macOS: nothing changes");
    assert!(!serde_json::to_string(&vm).unwrap().contains("adminAction"));

    vm.set_admin_actions(&|reason| reason.contains("Step One…").then_some("allow-l2tp-behind-nat"));
    let row = |name: &str| vm.rows.iter().find(|r| r.name == name).unwrap();
    assert_eq!(row("Branch").admin_action, Some("allow-l2tp-behind-nat"));
    assert_eq!(row("Remote").admin_action, Some("allow-l2tp-behind-nat"));
    assert_eq!(row("Lab").admin_action, None, "not failed");
    let json = serde_json::to_value(&vm).unwrap();
    let branch_json = json["rows"].as_array().unwrap().iter().find(|r| r["name"] == "Branch").unwrap();
    assert_eq!(branch_json["adminAction"], "allow-l2tp-behind-nat");
}
