//! The RAS entry plans (WinVPN 2c Task 3): one row of the per-kind table per test, one test per IKEv2 rule.

use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::models::{Connection, NativeSettings, VPNKind};
use macvpn_core::ras::policy::{DhGroup, EspCipher, EspIntegrity, IkeCipher, IkeIntegrity, WindowsPolicy};
use macvpn_core::ras::{self, Auth, DefaultRoute, Needs, Strategy};

fn l2tp(all: bool) -> Connection {
    let mut c = Connection::new("Office VPN", VPNKind::L2tp);
    c.native = Some(NativeSettings {
        server: "vpn.example.com".into(),
        account: "alice".into(),
        group_name: String::new(),
        send_all_traffic: all,
    });
    c
}

// --- L2TP and Cisco -------------------------------------------------------------------------------------------

#[test]
fn l2tp_is_psk_mschapv2_with_the_default_gateway_as_set() {
    let p = ras::plan_native(&l2tp(true)).unwrap();
    assert_eq!(p.strategy, Strategy::L2tp);
    assert_eq!(p.server, "vpn.example.com");
    assert_eq!(p.auth, Auth::MsChapV2 { psk: true });
    assert_eq!(p.default_route, DefaultRoute::Both);
    assert_eq!(p.user, "alice");
    assert_eq!(p.needs, Needs { user: true, password: true, psk: true });
    assert!(!p.ts_as_routes);
    assert!(!p.ike_fragmentation);
    assert_eq!(p.interface_metric, None);
    assert_eq!(p.policy, None);
    assert_eq!(ras::plan_native(&l2tp(false)).unwrap().default_route, DefaultRoute::None);
}

#[test]
fn l2tp_without_server_or_account_is_an_invalid_connection() {
    let mut c = l2tp(true);
    c.native.as_mut().unwrap().server = "  ".into();
    let e = ras::plan_native(&c).unwrap_err();
    assert!(e.invalid_config, "{e:?}");
    assert_eq!(e.reasons, vec!["Server and account name are required".to_string()]);
    let mut c = l2tp(true);
    c.native = None;
    assert!(ras::plan_native(&c).unwrap_err().invalid_config);
}

/// Security review L-8: the server goes into the phonebook's `PhoneNumber=` (an INI line), so a control character
/// (CR/LF would add keys to the entry's section) is refused for every kind, as the catalog refuses it.
#[test]
fn a_server_with_a_control_character_is_an_invalid_connection() {
    for server in
        ["vpn.example.com\r\nPhoneNumber=evil", "vpn\nx", "vpn\u{1}x", "vpn\u{7f}x", "vpn\u{85}x", "a\u{2028}b"]
    {
        let mut c = l2tp(true);
        c.native.as_mut().unwrap().server = server.into();
        let e = with_language(AppLanguage::En, || ras::plan_native(&c)).unwrap_err();
        assert!(e.invalid_config, "{server:?}: {e:?}");
        assert_eq!(e.reasons, vec!["The server address must not contain control characters".to_string()], "{server:?}");
    }
    let mut c = l2tp(true);
    c.native.as_mut().unwrap().server = "vpn\u{1}x".into();
    let e = with_language(AppLanguage::Hu, || ras::plan_native(&c)).unwrap_err();
    assert_eq!(e.reasons, vec!["A szerver címe nem tartalmazhat vezérlőkaraktert".to_string()]);
    // SSTP and IKEv2 refuse it too (whichever check sees it first).
    assert!(ras::plan_sstp(b"server=vpn\x01x.example.com\nuser=alice\n").is_err());
    let text = EAP.replace("remote_addrs = vpn.example.com", "remote_addrs = vpn\u{1}.example.com");
    assert!(ras::plan_ikev2(text.as_bytes()).is_err());
    let text = EAP.replace("remote_addrs = vpn.example.com", "remote_addrs = vpn\u{85}.example.com");
    assert!(ras::plan_ikev2(text.as_bytes()).is_err());
}

#[test]
fn cisco_is_not_supported_on_windows() {
    let mut c = l2tp(true);
    c.kind = VPNKind::Cisco;
    let e = ras::plan_native(&c).unwrap_err();
    assert!(!e.invalid_config);
    assert!(e.reasons[0].starts_with("Cisco IPsec is not supported by Windows."), "{e:?}");
    assert_eq!(e.reasons[0], macvpn_core::l10n::tr(ras::CISCO_UNSUPPORTED, &[]));
}

#[test]
fn plan_native_refuses_the_helper_kinds() {
    let mut c = l2tp(true);
    c.kind = VPNKind::Sstp;
    assert!(ras::plan_native(&c).unwrap_err().invalid_config);
}

// --- names ----------------------------------------------------------------------------------------------------

#[test]
fn entry_names_come_from_the_id_only() {
    let c = l2tp(true);
    let name = ras::names::entry_name(&c.id);
    assert_eq!(name, format!("WinVPN-{}", macvpn_core::models::uuid_string(&c.id)));
    assert_eq!(name.len(), 43);
    assert_eq!(ras::names::connection_id(&name), Some(c.id));
    for other in [
        "WinVPN-",
        "WinVPN-x",
        "winvpn-6F1C…",
        "Office VPN",
        "WinVPN-6f1c2a3b-0000-0000-0000-00000000000g",
        " WinVPN-6F1C2A3B-0000-0000-0000-000000000000",
        "WinVPN-6F1C2A3B-0000-0000-0000-000000000000 ",
        "WinVPN-test-6F1C2A3B-0000-0000-0000-000000000000",
    ] {
        assert_eq!(ras::names::connection_id(other), None, "{other}");
    }
    // Only the exact form WinVPN writes (upper case) is WinVPN's.
    assert_eq!(ras::names::connection_id(&name.to_lowercase().replacen("winvpn-", "WinVPN-", 1)), None);
    assert_eq!(ras::names::PHONEBOOK_DIR, "ras");
    assert_eq!(ras::names::PHONEBOOK_FILE, "WinVPN.pbk");
}

// --- SSTP -----------------------------------------------------------------------------------------------------

#[test]
fn sstp_insecure_is_not_supported_on_windows() {
    let cfg = "server=vpn.example.com\nport=443\nuser=alice\ncert=insecure\nroute_all=yes\npeer_dns=yes\n";
    let e = ras::plan_sstp(cfg.as_bytes()).unwrap_err();
    assert!(!e.invalid_config);
    assert!(e.reasons[0].contains("Windows always checks the SSTP server's certificate"), "{e:?}");
}

#[test]
fn sstp_port_goes_into_the_server_and_peer_dns_off_raises_the_metric() {
    let cfg = "server=vpn.example.com\nport=8443\nuser=alice\ncert=system\nroute_all=no\npeer_dns=no\n";
    let p = ras::plan_sstp(cfg.as_bytes()).unwrap();
    assert_eq!(p.server, "vpn.example.com:8443");
    assert_eq!(p.interface_metric, Some(9000));
    assert_eq!(p.default_route, DefaultRoute::None);
}

#[test]
fn sstp_on_443_with_route_all_and_peer_dns() {
    let cfg = "server=vpn.example.com\nport=443\nuser=alice\ncert=system\nroute_all=yes\npeer_dns=yes\n";
    let p = ras::plan_sstp(cfg.as_bytes()).unwrap();
    assert_eq!(p.strategy, Strategy::Sstp);
    assert_eq!(p.server, "vpn.example.com");
    assert_eq!(p.auth, Auth::MsChapV2 { psk: false });
    assert_eq!(p.default_route, DefaultRoute::Both);
    assert_eq!(p.interface_metric, None);
    assert_eq!(p.user, "alice");
    assert_eq!(p.needs, Needs { user: false, password: true, psk: false });
    assert_eq!(p.policy, None);
}

#[test]
fn sstp_ipv6_literal_gets_brackets_with_a_port() {
    let cfg = "server=2001:db8::1\nport=8443\nuser=alice\ncert=system\nroute_all=yes\npeer_dns=yes\n";
    assert_eq!(ras::plan_sstp(cfg.as_bytes()).unwrap().server, "[2001:db8::1]:8443");
    let cfg = cfg.replace("8443", "443");
    assert_eq!(ras::plan_sstp(cfg.as_bytes()).unwrap().server, "2001:db8::1");
}

#[test]
fn sstp_own_ca_is_planned() {
    let cfg = "server=vpn.example.com\nport=443\nuser=alice\ncert=ca\nroute_all=yes\npeer_dns=yes\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n";
    assert!(ras::plan_sstp(cfg.as_bytes()).is_ok());
}

#[test]
fn sstp_invalid_config_is_the_validators_error() {
    let e = ras::plan_sstp(b"server=\nuser=alice\n").unwrap_err();
    assert!(e.invalid_config, "{e:?}");
    assert!(!e.reasons.is_empty());
    let e = ras::plan_sstp(b"server=vpn.example.com\xff\n").unwrap_err();
    assert!(e.invalid_config, "{e:?}");
}

// --- IKEv2 ----------------------------------------------------------------------------------------------------

const EAP: &str = r#"connections {
  office {
    version = 2
    remote_addrs = vpn.example.com
    vips = 0.0.0.0
    proposals = aes256-sha256-modp2048
    local { auth = eap-mschapv2
            eap_id = alice }
    remote { auth = pubkey
             id = vpn.example.com }
    children { net { remote_ts = 10.0.0.0/8
                     esp_proposals = aes256-sha256 } }
  }
}
"#;

fn ikev2(text: &str) -> ras::RasEntryPlan {
    ras::plan_ikev2(text.as_bytes()).unwrap_or_else(|e| panic!("{e:?}\n{text}"))
}

fn ikev2_err(text: &str) -> ras::Unsupported {
    match ras::plan_ikev2(text.as_bytes()) {
        Ok(p) => panic!("planned: {p:?}\n{text}"),
        Err(e) => e,
    }
}

fn has_reason(e: &ras::Unsupported, reason: &str) -> bool {
    e.reasons.iter().any(|r| r.contains(reason))
}

#[test]
fn ikev2_eap_split_tunnel_with_its_proposals() {
    let p = ikev2(EAP);
    assert_eq!(p.strategy, Strategy::Ikev2);
    assert_eq!(p.server, "vpn.example.com");
    assert_eq!(p.auth, Auth::EapMsChapV2);
    assert_eq!(p.default_route, DefaultRoute::None);
    assert!(p.ts_as_routes);
    assert!(p.ike_fragmentation);
    assert_eq!(p.user, "alice");
    assert_eq!(p.needs, Needs { user: true, password: true, psk: false });
    assert_eq!(p.policy.unwrap().describe(), "AES-256, SHA-256, DH group 14; ESP AES-256, SHA-256");
}

#[test]
fn ikev2_rules_name_the_key_and_value() {
    for (from, to, reason) in [
        ("auth = eap-mschapv2", "auth = eap-tls", "Not supported on Windows: local auth = eap-tls"),
        ("version = 2", "version = 1", "Not supported on Windows: version = 1 (IKEv1)"),
        ("id = vpn.example.com", "id = gw.example.com", "On Windows the server's identity must be its address"),
        (
            "proposals = aes256-sha256-modp2048",
            "proposals = aes256-sha256-modp4096",
            "Windows supports none of these IKE proposals: aes256-sha256-modp4096",
        ),
    ] {
        let e = ikev2_err(&EAP.replace(from, to));
        assert!(!e.invalid_config);
        assert!(has_reason(&e, reason), "{to}: {e:?}");
    }
}

#[test]
fn ikev2_collects_every_reason() {
    let text = EAP.replace("version = 2", "version = 1").replace("auth = eap-mschapv2", "auth = xauth");
    let e = ikev2_err(&text);
    assert_eq!(e.reasons.len(), 2, "{e:?}");
}

#[test]
fn ikev2_without_proposals_uses_aes256_sha256_group14() {
    let text = EAP
        .replace("    proposals = aes256-sha256-modp2048\n", "")
        .replace("\n                     esp_proposals = aes256-sha256", "");
    let p = ikev2(&text);
    assert_eq!(p.policy, Some(ras::policy::WINDOWS_DEFAULT_FOR_STRONGSWAN));
    assert_eq!(
        ras::policy::WINDOWS_DEFAULT_FOR_STRONGSWAN,
        WindowsPolicy {
            ike_cipher: IkeCipher::Aes256,
            ike_integrity: IkeIntegrity::Sha256,
            dh_group: DhGroup::Group14,
            esp_cipher: EspCipher::Aes256,
            esp_integrity: EspIntegrity::Sha256128,
            pfs: None,
        }
    );
}

#[test]
fn ikev2_eap_without_eap_id_takes_the_vault_user_name() {
    let p = ikev2(&EAP.replace("\n            eap_id = alice", ""));
    assert_eq!(p.user, "");
    assert!(p.needs.user);
    let p = ikev2(&EAP.replace("eap_id = alice", "eap_id = %any"));
    assert_eq!(p.user, "");
    // Plain `eap` (the server picks the method): Windows offers EAP-MSCHAPv2.
    assert_eq!(ikev2(&EAP.replace("auth = eap-mschapv2", "auth = eap")).auth, Auth::EapMsChapV2);
}

#[test]
fn ikev2_psk_is_not_supported_on_windows() {
    // The RAS spike (Task 2): Windows' IKEv2 client has no PSK entry form that dials.
    let text = EAP.replace("auth = eap-mschapv2", "auth = psk").replace("auth = pubkey", "auth = psk");
    let e = ikev2_err(&text);
    assert!(!e.invalid_config);
    assert_eq!(e.reasons.len(), 1, "{e:?}");
    assert!(
        has_reason(&e, "Not supported on Windows: local auth = psk (the Windows IKEv2 client cannot sign in"),
        "{e:?}"
    );
    let e = ikev2_err(&EAP.replace("auth = eap-mschapv2", "auth = psk"));
    assert!(has_reason(&e, "Not supported on Windows: local auth = psk"), "{e:?}");
}

#[test]
fn ikev2_client_certificate_is_the_machine_certificate() {
    let p = ikev2(&EAP.replace("auth = eap-mschapv2", "auth = pubkey"));
    assert_eq!(p.auth, Auth::MachineCertificate);
    assert_eq!(p.needs, Needs::default());
    // No `auth` at all is strongSwan's default: pubkey.
    let p = ikev2(&EAP.replace("auth = eap-mschapv2", "id = alice@example.com"));
    assert_eq!(p.auth, Auth::MachineCertificate);
}

#[test]
fn ikev2_other_local_auths_are_not_supported() {
    for auth in ["eap-tls", "eap-md5", "eap-gtc", "eap-radius", "xauth", "xauth-generic", "eap-ttls"] {
        let e = ikev2_err(&EAP.replace("auth = eap-mschapv2", &format!("auth = {auth}")));
        assert!(has_reason(&e, &format!("Not supported on Windows: local auth = {auth}")), "{auth}: {e:?}");
    }
    let e = ikev2_err(&EAP.replace("auth = pubkey", "auth = eap-mschapv2"));
    assert!(has_reason(&e, "Not supported on Windows: remote auth = eap-mschapv2"), "{e:?}");
}

#[test]
fn ikev2_more_than_one_round_is_not_supported() {
    let e = ikev2_err(&EAP.replace("eap_id = alice }", "eap_id = alice\n            round = 2 }"));
    assert!(has_reason(&e, "Not supported on Windows: local round = 2"), "{e:?}");
    let e = ikev2_err(&EAP.replace("    remote {", "    local-2 { auth = xauth }\n    remote {"));
    assert!(has_reason(&e, "Not supported on Windows: more than one authentication round"), "{e:?}");
    let e = ikev2_err(&EAP.replace("    remote {", "    remote-2 { auth = eap }\n    remote {"));
    assert!(has_reason(&e, "Not supported on Windows: more than one authentication round"), "{e:?}");
    assert!(ras::plan_ikev2(EAP.replace("eap_id = alice }", "eap_id = alice\n round = 1 }").as_bytes()).is_ok());
}

#[test]
fn ikev2_server_is_one_host() {
    for (value, reason) in [
        (
            "vpn.example.com, vpn2.example.com",
            "Not supported on Windows: remote_addrs = vpn.example.com, vpn2.example.com",
        ),
        ("192.0.2.1-192.0.2.9", "Not supported on Windows: remote_addrs = 192.0.2.1-192.0.2.9"),
        ("192.0.2.0/24", "Not supported on Windows: remote_addrs = 192.0.2.0/24"),
        ("%any", "Not supported on Windows: remote_addrs = %any"),
    ] {
        let e = ikev2_err(&EAP.replace("remote_addrs = vpn.example.com", &format!("remote_addrs = {value}")));
        assert!(has_reason(&e, reason), "{value}: {e:?}");
    }
    let e = ikev2_err(&EAP.replace("    remote_addrs = vpn.example.com\n", ""));
    assert!(has_reason(&e, "On Windows the server address is required"), "{e:?}");
    // A host name with a hyphen is not a range; an IP literal is fine (its identity is then the address).
    let p = ikev2(&EAP.replace("vpn.example.com", "vpn-1.example.com"));
    assert_eq!(p.server, "vpn-1.example.com");
    let p = ikev2(&EAP.replace("vpn.example.com", "192.0.2.1"));
    assert_eq!(p.server, "192.0.2.1");
}

#[test]
fn ikev2_remote_identity_forms() {
    assert!(ras::plan_ikev2(EAP.replace("id = vpn.example.com", "id = @VPN.example.com").as_bytes()).is_ok());
    assert!(ras::plan_ikev2(EAP.replace("id = vpn.example.com", "id = %any").as_bytes()).is_ok());
    assert!(ras::plan_ikev2(EAP.replace("\n             id = vpn.example.com", "").as_bytes()).is_ok());
    let e = ikev2_err(&EAP.replace("id = vpn.example.com", "id = \"CN=vpn.example.com\""));
    assert!(has_reason(&e, "On Windows the server's identity must be its address"), "{e:?}");
}

#[test]
fn ikev2_full_tunnel_from_the_traffic_selectors() {
    let no_ts = EAP.replace("remote_ts = 10.0.0.0/8\n                     ", "");
    let p = ikev2(&no_ts);
    assert_eq!(p.default_route, DefaultRoute::Ipv4);
    assert!(!p.ts_as_routes);
    let p = ikev2(&EAP.replace("remote_ts = 10.0.0.0/8", "remote_ts = 0.0.0.0/0"));
    assert_eq!(p.default_route, DefaultRoute::Ipv4);
    let p = ikev2(&EAP.replace("remote_ts = 10.0.0.0/8", "remote_ts = 0.0.0.0/0, ::/0"));
    assert_eq!(p.default_route, DefaultRoute::Both);
    let p = ikev2(&EAP.replace("remote_ts = 10.0.0.0/8", "remote_ts = 10.0.0.0/8,192.168.1.0/24, fd00::/64"));
    assert_eq!(p.default_route, DefaultRoute::None);
    assert!(p.ts_as_routes);
    let p = ikev2(&EAP.replace("remote_ts = 10.0.0.0/8", "remote_ts = dynamic"));
    assert_eq!(p.default_route, DefaultRoute::Ipv4);
    let e = ikev2_err(&EAP.replace("remote_ts = 10.0.0.0/8", "remote_ts = ::/0"));
    assert!(has_reason(&e, "Not supported on Windows: remote_ts = ::/0 without 0.0.0.0/0"), "{e:?}");
    let e = ikev2_err(&EAP.replace("remote_ts = 10.0.0.0/8", "remote_ts = 10.0.0.0/8[tcp/80]"));
    assert!(has_reason(&e, "Not supported on Windows: remote_ts = 10.0.0.0/8[tcp/80]"), "{e:?}");
}

#[test]
fn ikev2_local_ts_must_be_dynamic() {
    for ok in ["dynamic", "0.0.0.0/0", "0.0.0.0/0, ::/0"] {
        let text = EAP.replace("remote_ts = 10.0.0.0/8", &format!("remote_ts = 10.0.0.0/8\n local_ts = {ok}"));
        assert!(ras::plan_ikev2(text.as_bytes()).is_ok(), "{ok}");
    }
    let text = EAP.replace("remote_ts = 10.0.0.0/8", "remote_ts = 10.0.0.0/8\n local_ts = 192.168.5.0/24");
    assert!(has_reason(&ikev2_err(&text), "Not supported on Windows: local_ts = 192.168.5.0/24"));
}

/// The keys whose non-default values change behaviour Windows cannot reproduce: (section, key, a bad value, the
/// default value that is accepted).
const BEHAVIOUR_KEYS: &[(&str, &str, &str, &str)] = &[
    ("child", "mode", "transport", "tunnel"),
    ("child", "dpd_action", "trap", "clear"),
    ("child", "close_action", "start", "none"),
    ("child", "if_id_in", "42", "0"),
    ("child", "if_id_out", "42", "0"),
    ("child", "mark_in", "42", "0"),
    ("child", "mark_in_sa", "yes", "no"),
    ("child", "mark_out", "42", "0"),
    ("child", "set_mark_in", "42", "0"),
    ("child", "set_mark_out", "42", "0"),
    ("child", "hostaccess", "yes", "no"),
    ("conn", "if_id_in", "42", "0"),
    ("conn", "if_id_out", "42", "0"),
    ("conn", "ppk_id", "ppk1", ""),
    ("conn", "ppk_required", "yes", "no"),
    ("conn", "remote_port", "4500", "500"),
    ("conn", "vips", "10.9.0.5", "0.0.0.0"),
];

fn with_key(section: &str, key: &str, value: &str) -> String {
    match section {
        "child" => EAP.replace("remote_ts = 10.0.0.0/8", &format!("remote_ts = 10.0.0.0/8\n {key} = {value}")),
        _ => EAP.replace("    vips = 0.0.0.0\n", "").replace("version = 2", &format!("version = 2\n {key} = {value}")),
    }
}

#[test]
fn ikev2_behaviour_keys_windows_cannot_reproduce() {
    for (section, key, bad, default) in BEHAVIOUR_KEYS {
        let e = ikev2_err(&with_key(section, key, bad));
        assert!(has_reason(&e, &format!("Not supported on Windows: {key} = {bad}")), "{section} {key}: {e:?}");
        if !default.is_empty() {
            let text = with_key(section, key, default);
            assert!(ras::plan_ikev2(text.as_bytes()).is_ok(), "{section} {key} = {default}");
        }
    }
}

#[test]
fn ikev2_restart_and_start_actions_are_warnings() {
    assert!(ikev2(EAP).warnings.is_empty());
    let p = ikev2(&with_key("child", "dpd_action", "restart"));
    assert_eq!(p.warnings, ["Ignored on Windows: dpd_action = restart (Windows itself redials a dropped connection)"]);
    for value in ["trap", "start"] {
        let p = ikev2(&with_key("child", "start_action", value));
        assert_eq!(
            p.warnings,
            [format!("Ignored on Windows: start_action = {value} (the connection starts when you connect it)")]
        );
    }
    let text =
        EAP.replace("remote_ts = 10.0.0.0/8", "remote_ts = 10.0.0.0/8\n dpd_action = restart\n start_action = trap");
    assert_eq!(ikev2(&text).warnings.len(), 2);
    // A reason still wins: no plan, so no warnings to show.
    assert!(ras::plan_ikev2(text.replace("version = 2", "version = 1").as_bytes()).is_err());
}

#[test]
fn ikev2_other_allowed_keys_are_ignored() {
    let text = EAP.replace(
        "remote_ts = 10.0.0.0/8",
        "remote_ts = 10.0.0.0/8\n rekey_time = 1h\n dpd_action = clear\n start_action = none",
    );
    let text = text.replace("version = 2", "version = 2\n mobike = no\n dpd_delay = 30s\n encap = yes");
    assert!(ras::plan_ikev2(text.as_bytes()).is_ok());
    let text = EAP.replace("    remote {", "    remote { cacerts = ca.pem }\n    remote {");
    assert!(ras::plan_ikev2(text.as_bytes()).is_ok());
}

#[test]
fn ikev2_fragmentation_off_only_with_no() {
    assert!(!ikev2(&EAP.replace("version = 2", "version = 2\n fragmentation = no")).ike_fragmentation);
    assert!(ikev2(&EAP.replace("version = 2", "version = 2\n fragmentation = force")).ike_fragmentation);
}

#[test]
fn ikev2_version_any_is_fine() {
    assert!(ras::plan_ikev2(EAP.replace("version = 2", "version = 0").as_bytes()).is_ok());
    assert!(ras::plan_ikev2(EAP.replace("    version = 2\n", "").as_bytes()).is_ok());
}

#[test]
fn ikev2_invalid_config_is_the_validators_error() {
    let e = ras::plan_ikev2(EAP.replace("vips = 0.0.0.0", "updown = /bin/sh").as_bytes()).unwrap_err();
    assert!(e.invalid_config, "{e:?}");
    let e = ras::plan_ikev2(b"connections {\n}\n").unwrap_err();
    assert!(e.invalid_config, "{e:?}");
}

#[test]
fn ikev2_only_the_first_connection_and_child_count() {
    let text =
        EAP.replace("children { net {", "children { other { remote_ts = 192.0.2.0/24[udp]\n mode = pass }\n x {");
    // `other` is the first child now: it decides.
    assert!(ras::plan_ikev2(text.as_bytes()).is_err());
    let second = format!("{EAP}connections {{ two {{ version = 1\n children {{ c {{ mode = transport }} }} }} }}\n");
    assert!(ras::plan_ikev2(second.as_bytes()).is_ok());
}

#[test]
fn ikev2_values_in_reasons_are_shortened() {
    let long = "a".repeat(300);
    let e = ikev2_err(&EAP.replace("auth = eap-mschapv2", &format!("auth = eap-{long}")));
    assert!(e.reasons.iter().all(|r| r.chars().count() < 160), "{e:?}");
    assert!(e.reasons[0].ends_with('…'), "{e:?}");
}

// --- the IPsec policy -------------------------------------------------------------------------------------------

fn policy_of(ike: &str, esp: &str) -> WindowsPolicy {
    let text = EAP
        .replace("proposals = aes256-sha256-modp2048", &format!("proposals = {ike}"))
        .replace("esp_proposals = aes256-sha256", &format!("esp_proposals = {esp}"));
    ikev2(&text).policy.unwrap()
}

#[test]
fn policy_first_fully_mappable_proposal_wins() {
    let p = policy_of("aes256-sha256-modp4096,aes128-sha1-modp1024", "aes256-sha512, aes128-sha1");
    assert_eq!(
        (p.ike_cipher, p.ike_integrity, p.dh_group, p.esp_cipher, p.esp_integrity, p.pfs),
        (IkeCipher::Aes128, IkeIntegrity::Sha1, DhGroup::Group2, EspCipher::Aes128, EspIntegrity::Sha196, None)
    );
    // Within one proposal any combination is acceptable: the first Windows algorithm of each type.
    let p = policy_of("chacha20poly1305-aes192-sha512-sha384-curve25519-ecp384", "3des-sha256-modp2048s256");
    assert_eq!((p.ike_cipher, p.ike_integrity, p.dh_group), (IkeCipher::Aes192, IkeIntegrity::Sha384, DhGroup::Ecp384));
    assert_eq!(
        (p.esp_cipher, p.esp_integrity, p.pfs),
        (EspCipher::TripleDes, EspIntegrity::Sha256128, Some(DhGroup::Group24))
    );
}

#[test]
fn policy_gcm_takes_the_prf_for_ike_and_the_gcm_tag_for_esp() {
    let p = policy_of("aes256gcm16-prfsha384-ecp384", "aes256gcm16-ecp384");
    assert_eq!(
        (p.ike_cipher, p.ike_integrity, p.dh_group, p.esp_cipher, p.esp_integrity, p.pfs),
        (
            IkeCipher::Aes256Gcm16,
            IkeIntegrity::Sha384,
            DhGroup::Ecp384,
            EspCipher::Aes256Gcm16,
            EspIntegrity::Gcm256,
            Some(DhGroup::Ecp384)
        )
    );
    assert_eq!(p.describe(), "AES-256-GCM, SHA-384, DH group 20; ESP AES-256-GCM, PFS group 20");
    let p = policy_of("aes128gcm-prfsha256-ecp256", "aes192gcm16");
    assert_eq!(
        (p.ike_cipher, p.ike_integrity, p.dh_group),
        (IkeCipher::Aes128Gcm16, IkeIntegrity::Sha256, DhGroup::Ecp256)
    );
    assert_eq!((p.esp_cipher, p.esp_integrity), (EspCipher::Aes192Gcm16, EspIntegrity::Gcm192));
}

#[test]
fn policy_prf_must_match_the_integrity() {
    // Windows uses the integrity hash as the PRF: with a `prf…` list it must be in it.
    let p = policy_of("aes256-sha256-sha384-prfsha384-modp2048", "aes256-sha256");
    assert_eq!(p.ike_integrity, IkeIntegrity::Sha384);
    let e = ikev2_err(&EAP.replace("aes256-sha256-modp2048", "aes256-sha256-prfsha512-modp2048"));
    assert!(has_reason(&e, "Windows supports none of these IKE proposals"), "{e:?}");
}

#[test]
fn policy_refuses_weak_and_missing_algorithms() {
    for ike in ["aes256-md5-modp2048", "aes256-sha256-modp768", "aes256gcm16-modp2048", "aes256-sha256"] {
        let e = ikev2_err(&EAP.replace("aes256-sha256-modp2048", ike));
        assert!(has_reason(&e, &format!("Windows supports none of these IKE proposals: {ike}")), "{ike}: {e:?}");
    }
    for esp in ["aes256-md5", "aes256-sha384", "chacha20poly1305", "aes256-sha256-esn"] {
        let e = ikev2_err(&EAP.replace("esp_proposals = aes256-sha256", &format!("esp_proposals = {esp}")));
        assert!(has_reason(&e, &format!("Windows supports none of these ESP proposals: {esp}")), "{esp}: {e:?}");
    }
    assert!(ras::plan_ikev2(EAP.replace("aes256-sha256 }", "aes256-sha256-esn-noesn }").as_bytes()).is_ok());
}

#[test]
fn policy_reason_names_what_windows_offers() {
    let e = ikev2_err(&EAP.replace("aes256-sha256-modp2048", "aes256-sha256-modp4096"));
    let r = e.reasons.iter().find(|r| r.contains("IKE proposals")).unwrap();
    assert!(r.contains("Windows offers: "), "{r}");
    assert!(r.contains("modp2048") && r.contains("ecp384") && r.contains("aes256gcm16"), "{r}");
}

#[test]
fn policy_default_keyword_and_missing_esp() {
    let p = policy_of("default", "default");
    assert_eq!(p, ras::policy::WINDOWS_DEFAULT_FOR_STRONGSWAN);
    let text = EAP.replace("\n                     esp_proposals = aes256-sha256", "");
    let p = ikev2(&text.replace("aes256-sha256-modp2048", "aes128-sha256-ecp256")).policy.unwrap();
    assert_eq!((p.ike_cipher, p.dh_group), (IkeCipher::Aes128, DhGroup::Ecp256));
    assert_eq!((p.esp_cipher, p.esp_integrity, p.pfs), (EspCipher::Aes256, EspIntegrity::Sha256128, None));
}

#[test]
fn policy_descriptions() {
    let d = ras::policy::WINDOWS_DEFAULT_FOR_STRONGSWAN.describe();
    assert_eq!(d, "AES-256, SHA-256, DH group 14; ESP AES-256, SHA-256");
    let p = policy_of("3des-sha1-modp1024", "aes128-sha1-modp2048");
    assert_eq!(p.describe(), "3DES, SHA-1, DH group 2; ESP AES-128, SHA-1, PFS group 14");
    let hu =
        with_language(AppLanguage::Hu, || d.clone() + " | " + &ras::policy::WINDOWS_DEFAULT_FOR_STRONGSWAN.describe());
    assert!(hu.contains("DH-csoport 14"), "{hu}");
}

// --- the entry point and the texts -------------------------------------------------------------------------------

#[test]
fn plan_for_dispatches_by_kind() {
    assert!(ras::is_ras_kind(VPNKind::L2tp));
    assert!(ras::is_ras_kind(VPNKind::Cisco));
    assert!(ras::is_ras_kind(VPNKind::Sstp));
    assert!(ras::is_ras_kind(VPNKind::Strongswan));
    assert!(!ras::is_ras_kind(VPNKind::Openvpn));
    assert!(!ras::is_ras_kind(VPNKind::Wireguard));

    let c = l2tp(true);
    assert_eq!(ras::plan_for(&c, b"").unwrap().unwrap().strategy, Strategy::L2tp);
    let mut c = Connection::new("Office VPN", VPNKind::Strongswan);
    assert_eq!(ras::plan_for(&c, EAP.as_bytes()).unwrap().unwrap().strategy, Strategy::Ikev2);
    c.kind = VPNKind::Sstp;
    let sstp = "server=vpn.example.com\nport=443\nuser=alice\ncert=system\nroute_all=yes\npeer_dns=yes\n";
    assert_eq!(ras::plan_for(&c, sstp.as_bytes()).unwrap().unwrap().strategy, Strategy::Sstp);
    c.kind = VPNKind::Openvpn;
    assert!(ras::plan_for(&c, b"client\n").is_none());
}

#[test]
fn reasons_are_translated() {
    let cfg = "server=vpn.example.com\nport=443\nuser=alice\ncert=insecure\nroute_all=yes\npeer_dns=yes\n";
    let hu = with_language(AppLanguage::Hu, || ras::plan_sstp(cfg.as_bytes()).unwrap_err());
    assert!(!hu.reasons[0].contains("Windows always checks"), "{hu:?}");
    let hu = with_language(AppLanguage::Hu, || ikev2_err(&EAP.replace("version = 2", "version = 1")));
    assert!(hu.reasons[0].starts_with("Windowson nem támogatott: version = 1"), "{hu:?}");
    let mut c = l2tp(true);
    c.kind = VPNKind::Cisco;
    let hu = with_language(AppLanguage::Hu, || ras::plan_native(&c).unwrap_err());
    assert!(!hu.reasons[0].starts_with("Cisco IPsec is not supported"), "{hu:?}");
}

#[test]
fn plans_hold_no_secret_and_debug_shows_them_whole() {
    // A plan carries names and switches only: `needs` says which vault secrets the dial takes.
    let p = ikev2(EAP);
    let debug = format!("{p:?}");
    assert!(debug.contains("vpn.example.com") && debug.contains("EapMsChapV2"), "{debug}");
}
