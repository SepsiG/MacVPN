//! Connection status notices (features 2.0, maintainer decision 2): which state transitions post one, and their
//! fixed texts (only the connection's name, never a server, user name, address or log line).

use macvpn_app_core::connection_notices::{
    DeadOutcome, ENABLED_KEY, Notice, NoticeTracker, content, content_named, enabled, reason_text,
};
use macvpn_app_core::failure_reason::FailureKind;
use macvpn_app_core::manager::{ConnectionEvent, auth_timeout_reason};
use macvpn_app_core::notify::{CONNECTION_KEY, for_event};
use macvpn_app_core::reconnect::Skip;
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::models::ConnectionState;
use macvpn_platform_api::{MemoryPreferences, PreferenceStore};

fn connected() -> ConnectionState {
    ConnectionState::Connected { ip: None, since: None }
}

#[test]
fn connected_only_after_a_seen_connect() {
    let mut t = NoticeTracker::default();
    // First sight (launch, unlock): no notice.
    assert_eq!(t.on_state("k", "Office VPN", &connected()), None);
    assert_eq!(t.on_state("k", "Office VPN", &ConnectionState::Disconnected), None);
    assert_eq!(t.on_state("k", "Office VPN", &ConnectionState::Connecting), None);
    assert_eq!(
        t.on_state("k", "Office VPN", &connected()),
        Some(Notice::Connected { key: "k".into(), name: "Office VPN".into() })
    );
    // Staying connected: nothing more.
    assert_eq!(t.on_state("k", "Office VPN", &connected()), None);
}

#[test]
fn an_auto_attempt_is_reported_as_reconnected() {
    let mut t = NoticeTracker::default();
    t.on_state("k", "Office VPN", &ConnectionState::Disconnected);
    t.mark_auto("k");
    t.on_state("k", "Office VPN", &ConnectionState::Connecting);
    assert_eq!(
        t.on_state("k", "Office VPN", &connected()),
        Some(Notice::Reconnected { key: "k".into(), name: "Office VPN".into() })
    );
    t.on_state("k", "Office VPN", &ConnectionState::Disconnected);
    t.on_state("k", "Office VPN", &ConnectionState::Connecting);
    assert!(matches!(t.on_state("k", "Office VPN", &connected()), Some(Notice::Connected { .. })));
}

#[test]
fn a_failed_auto_attempt_does_not_mark_the_next_connect() {
    let mut t = NoticeTracker::default();
    t.on_state("k", "Office VPN", &ConnectionState::Disconnected);
    t.mark_auto("k");
    t.on_state("k", "Office VPN", &ConnectionState::Connecting);
    t.on_state("k", "Office VPN", &ConnectionState::Failed("x".into()));
    t.on_state("k", "Office VPN", &ConnectionState::Connecting);
    assert!(matches!(t.on_state("k", "Office VPN", &connected()), Some(Notice::Connected { .. })));
}

#[test]
fn texts_are_plain_and_name_only_the_connection() {
    with_language(AppLanguage::En, || {
        let dropped = content(
            &Notice::Dropped {
                key: "k".into(),
                name: "Office VPN".into(),
                reason: reason_text(FailureKind::ServerNotResponding, None),
            },
            "u".into(),
        );
        assert_eq!(dropped.title, "Office VPN disconnected");
        assert_eq!(dropped.body, "The server stopped responding.");
        assert_eq!(dropped.user_info, (CONNECTION_KEY, "k".to_string()));
        assert_eq!(dropped.id, "u");
        let unknown = content(
            &Notice::Dropped {
                key: "k".into(),
                name: "Office VPN".into(),
                reason: reason_text(FailureKind::Unknown, None),
            },
            "u".into(),
        );
        assert_eq!(unknown.body, "Click to see the log.");
        let skipped = content(
            &Notice::NotReconnected { key: "k".into(), name: "Office VPN".into(), why: Skip::DifferentNetwork },
            "u".into(),
        );
        assert_eq!(skipped.title, "Office VPN not reconnected");
        assert_eq!(skipped.body, "You are on a different network.");
        let prefix = macvpn_core::netaddr::IpPrefix::parse("10.20.30.0/24").unwrap();
        let reachable = content(
            &Notice::NotReconnected {
                key: "k".into(),
                name: "Office VPN".into(),
                why: Skip::DirectlyReachable(prefix),
            },
            "u".into(),
        );
        assert_eq!(reachable.body, "The VPN’s network is directly reachable here.");
        assert!(!reachable.body.contains("10.20.30"));
        let dns = content(
            &Notice::NotReconnected {
                key: "k".into(),
                name: "Office VPN".into(),
                why: Skip::DnsDirectlyReachable("10.20.30.53".parse().unwrap()),
            },
            "u".into(),
        );
        assert_eq!(dns.body, "The VPN’s DNS server is directly reachable here.");
        let connected = content(&Notice::Connected { key: "k".into(), name: "Office VPN".into() }, "u".into());
        assert_eq!(
            (connected.title.as_str(), connected.body.as_str()),
            ("Office VPN connected", "Click to see the log.")
        );
        let again = content(&Notice::Reconnected { key: "k".into(), name: "Office VPN".into() }, "u".into());
        assert_eq!(again.title, "Office VPN reconnected");
        let failed = content(&Notice::Failed { key: "k".into(), name: "Office VPN".into(), reason: None }, "u".into());
        assert_eq!(
            (failed.title.as_str(), failed.body.as_str()),
            ("Office VPN: connection failed", "Open MacVPN for details")
        );
        let gave_up = content(
            &Notice::ReconnectFailed {
                key: "k".into(),
                name: "Office VPN".into(),
                reason: reason_text(FailureKind::AuthFailed, None),
            },
            "u".into(),
        );
        assert_eq!(
            (gave_up.title.as_str(), gave_up.body.as_str()),
            ("Office VPN could not reconnect", "The server refused the sign-in.")
        );
    });
    with_language(AppLanguage::Hu, || {
        let n = content(&Notice::Connected { key: "k".into(), name: "Iroda".into() }, "u".into());
        assert_eq!(n.title, "Iroda: csatlakozva");
        let n = content(
            &Notice::NotReconnected { key: "k".into(), name: "Iroda".into(), why: Skip::VaultLocked },
            "u".into(),
        );
        assert_eq!(n.body, "Az újracsatlakozáshoz oldd fel a széfet.");
    });
}

/// A connection redacted while the vault is locked has no name: the titles are generic, never " connected".
#[test]
fn a_connection_without_a_name_gets_a_generic_title() {
    with_language(AppLanguage::En, || {
        let title = |n: Notice| content(&n, "u".into()).title;
        assert_eq!(
            title(Notice::Dropped { key: "k".into(), name: "".into(), reason: None }),
            "A VPN connection dropped"
        );
        assert_eq!(
            title(Notice::Failed { key: "k".into(), name: " ".into(), reason: None }),
            "A VPN connection failed"
        );
        assert_eq!(title(Notice::Connected { key: "k".into(), name: "".into() }), "A VPN connection connected");
        assert_eq!(title(Notice::Reconnected { key: "k".into(), name: "".into() }), "A VPN connection reconnected");
        assert_eq!(
            title(Notice::NotReconnected { key: "k".into(), name: "".into(), why: Skip::Unidentified }),
            "A VPN connection was not reconnected"
        );
        assert_eq!(
            title(Notice::ReconnectFailed { key: "k".into(), name: "".into(), reason: None }),
            "A VPN connection could not reconnect"
        );
    });
}

#[test]
fn a_manager_reason_is_shown_only_when_it_is_one_of_the_fixed_texts() {
    with_language(AppLanguage::En, || {
        assert_eq!(reason_text(FailureKind::Unknown, Some(&auth_timeout_reason())), Some(auth_timeout_reason()));
        assert_eq!(reason_text(FailureKind::Unknown, Some("openvpn: vpn.example.com 192.0.2.1 refused")), None);
        assert_eq!(
            reason_text(FailureKind::AuthFailed, Some("anything")).as_deref(),
            Some("The server refused the sign-in.")
        );
    });
}

/// `notify::for_event` (the path the app posts manager events through) goes through the notices.
#[test]
fn manager_events_use_the_notice_texts() {
    with_language(AppLanguage::En, || {
        let dropped = ConnectionEvent::Dropped { connection_id: "ID".into(), name: "Office VPN".into() };
        let n = for_event(&dropped, "U".into());
        assert_eq!((n.title.as_str(), n.body.as_str()), ("Office VPN disconnected", "Click to see the log."));
        assert_eq!(n.user_info, (CONNECTION_KEY, "ID".to_string()));
        let failed = ConnectionEvent::Failed {
            connection_id: "ID".into(),
            name: "Office VPN".into(),
            reason: "AUTH_FAILED for alice at vpn.example.com".into(),
        };
        let n = for_event(&failed, "U".into());
        assert_eq!((n.title.as_str(), n.body.as_str()), ("Office VPN: connection failed", "Open MacVPN for details"));
    });
}

#[test]
fn the_switch_defaults_to_on() {
    let prefs = MemoryPreferences::new();
    assert!(enabled(&prefs));
    prefs.set_bool(ENABLED_KEY, false);
    assert!(!enabled(&prefs));
    prefs.set_bool(ENABLED_KEY, true);
    assert!(enabled(&prefs));
}

/// A surviving tunnel the app disconnected on its own network (the planner's notice; the app adds the name).
#[test]
fn a_tunnel_disconnected_here_names_the_connection_and_not_the_network() {
    let prefix = macvpn_core::netaddr::IpPrefix::parse("10.20.30.0/24").unwrap();
    let net = Notice::DisconnectedHere { key: "k".into(), why: Skip::DirectlyReachable(prefix) };
    let dns =
        Notice::DisconnectedHere { key: "k".into(), why: Skip::DnsDirectlyReachable("10.20.30.53".parse().unwrap()) };
    with_language(AppLanguage::En, || {
        let n = content_named(&net, "Office VPN", "u".into());
        assert_eq!(
            (n.title.as_str(), n.body.as_str()),
            ("Office VPN disconnected", "The VPN’s network is directly reachable here, so it was disconnected.")
        );
        assert_eq!(n.user_info, (CONNECTION_KEY, "k".to_string()));
        assert_eq!(n.id, "u");
        assert!(!n.body.contains("10.20.30"));
        let n = content_named(&dns, "Office VPN", "u".into());
        assert_eq!(n.body, "The VPN’s DNS server is directly reachable here, so it was disconnected.");
        assert!(!n.body.contains("10.20.30"));
        // Without a name (a locked vault, or `content`): the generic title.
        assert_eq!(content(&net, "u".into()).title, "A VPN connection dropped");
        assert_eq!(content_named(&net, " ", "u".into()).title, "A VPN connection dropped");
        // `content_named` names any notice.
        let failed = Notice::Failed { key: "k".into(), name: "".into(), reason: None };
        assert_eq!(content_named(&failed, "Office VPN", "u".into()).title, "Office VPN: connection failed");
    });
    with_language(AppLanguage::Hu, || {
        let n = content_named(&net, "Iroda", "u".into());
        assert_eq!(n.body, "A VPN hálózata itt közvetlenül elérhető, ezért a kapcsolat bontva lett.");
        let n = content_named(&dns, "Iroda", "u".into());
        assert_eq!(n.body, "A VPN DNS-szervere itt közvetlenül elérhető, ezért a kapcsolat bontva lett.");
    });
}

/// A connection the app disconnected after two minutes without a network (the planner's notice).
#[test]
fn a_disconnect_without_a_network_says_whether_it_reconnects() {
    let back = Notice::DisconnectedNoNetwork { key: "k".into(), name: "Office VPN".into(), reconnects: true };
    let gone = Notice::DisconnectedNoNetwork { key: "k".into(), name: "Office VPN".into(), reconnects: false };
    with_language(AppLanguage::En, || {
        let n = content(&back, "u".into());
        assert_eq!(
            (n.title.as_str(), n.body.as_str()),
            ("Office VPN disconnected", "There was no network for 2 minutes. It reconnects when the network is back.")
        );
        assert_eq!(n.user_info, (CONNECTION_KEY, "k".to_string()));
        assert_eq!(content(&gone, "u".into()).body, "There was no network for 2 minutes.");
        let unnamed = Notice::DisconnectedNoNetwork { key: "k".into(), name: "".into(), reconnects: false };
        assert_eq!(content(&unnamed, "u".into()).title, "A VPN connection dropped");
    });
    with_language(AppLanguage::Hu, || {
        assert_eq!(
            content(&back, "u".into()).body,
            "2 percig nem volt hálózat. Újracsatlakozik, amikor visszajön a hálózat."
        );
        assert_eq!(content(&gone, "u".into()).body, "2 percig nem volt hálózat.");
    });
}

/// A dead tunnel the app disconnected (dead-tunnel detection): whether it is reconnected, stays down, or was given up.
#[test]
fn a_dead_tunnel_says_what_happens_to_it() {
    let notice = |outcome| Notice::NotResponding { key: "k".into(), name: "Office VPN".into(), outcome };
    with_language(AppLanguage::En, || {
        let n = content(&notice(DeadOutcome::Reconnects), "u".into());
        assert_eq!(
            (n.title.as_str(), n.body.as_str()),
            ("Office VPN stopped responding", "The VPN server stopped answering. It is being reconnected.")
        );
        assert_eq!(n.user_info, (CONNECTION_KEY, "k".to_string()));
        assert_eq!(
            content(&notice(DeadOutcome::Disconnected), "u".into()).body,
            "The VPN server stopped answering, so it was disconnected."
        );
        assert_eq!(
            content(&notice(DeadOutcome::KeepsTrying), "u".into()).body,
            "It stopped responding again after 3 reconnects. It is tried again every 5 minutes for up to an hour."
        );
        let unnamed = Notice::NotResponding { key: "k".into(), name: "".into(), outcome: DeadOutcome::KeepsTrying };
        assert_eq!(content(&unnamed, "u".into()).title, "A VPN connection stopped responding");
    });
    with_language(AppLanguage::Hu, || {
        let n = content(&notice(DeadOutcome::Reconnects), "u".into());
        assert_eq!(n.title, "Office VPN: nem válaszol");
        assert_eq!(n.body, "A VPN-szerver nem válaszol. A kapcsolat újracsatlakozik.");
    });
    assert_eq!(macvpn_app_core::reconnect::MAX_DEAD_RECONNECTS, 3, "the notice names 3");
    // The slow tier: one notice when it starts (after the last failure's reason), one when the hour is over.
    with_language(AppLanguage::En, || {
        let start = Notice::KeepsTrying {
            key: "k".into(),
            name: "Office VPN".into(),
            reason: Some("The server could not be reached.".into()),
        };
        let n = content(&start, "u".into());
        assert_eq!(
            (n.title.as_str(), n.body.as_str()),
            (
                "Office VPN could not reconnect",
                "The server could not be reached. It is tried again every 5 minutes for up to an hour."
            )
        );
        let end = Notice::RetriesEnded { key: "k".into(), name: "Office VPN".into() };
        assert_eq!(
            content(&end, "u".into()).body,
            "It was tried for an hour. Connect it again when the server is back."
        );
    });
    with_language(AppLanguage::Hu, || {
        let end = Notice::RetriesEnded { key: "k".into(), name: "Office VPN".into() };
        assert_eq!(content(&end, "u".into()).title, "Office VPN: nem sikerült újracsatlakozni");
    });
    assert_eq!((macvpn_app_core::reconnect::SLOW_RETRY, macvpn_app_core::reconnect::SLOW_FOR), (300.0, 3600.0));
}

#[test]
fn the_switch_field_is_absent_until_the_app_sets_it() {
    let mut vm = macvpn_app_core::ViewModel::build(
        &macvpn_app_core::ManagerSnapshot::default(),
        "en",
        |_| true,
        Vec::new(),
        true,
    );
    let json = serde_json::to_value(&vm).unwrap();
    assert!(json.get("connectionNotifications").is_none());
    vm.connection_notifications = Some(false);
    let json = serde_json::to_value(&vm).unwrap();
    assert_eq!(json.get("connectionNotifications").and_then(|v| v.as_bool()), Some(false));
}
