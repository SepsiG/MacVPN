//! The `RasEngine`'s pure decisions (WinVPN 2c Task 8): the saved L2TP profile, the credentials of one dial (the
//! OTP code reaches the password as the manager appends it), the per-connection reasons, System Status. Every OS.

use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::mfa;
use macvpn_core::models::{Connection, NativeSettings, OTPSeparator, Secrets, VPNKind};
use macvpn_core::ras::{self, Strategy};
use macvpn_platform_api::{EngineRow, SetupReport};
use macvpn_platform_win::pure::ras_connect::{self as rc};
use uuid::Uuid;

fn en<T>(f: impl FnOnce() -> T) -> T {
    with_language(AppLanguage::En, f)
}

fn l2tp(server: &str, account: &str, all: bool) -> Connection {
    let mut c = Connection::new("Office VPN", VPNKind::L2tp);
    c.native = Some(NativeSettings {
        server: server.into(),
        account: account.into(),
        group_name: String::new(),
        send_all_traffic: all,
    });
    c
}

const SSTP: &[u8] = b"server=vpn.example.com\nport=443\nuser=alice\ncert=system\nroute_all=yes\npeer_dns=yes\n";
const EAP: &str = "connections {\n  office {\n    remote_addrs = vpn.example.com\n    local {\n      auth = eap-mschapv2\n      eap_id = alice\n    }\n    remote {\n      auth = pubkey\n      id = vpn.example.com\n    }\n    children {\n      net {\n        remote_ts = 10.0.0.0/8\n      }\n    }\n  }\n}\n";

#[test]
fn the_l2tp_profile_round_trips_to_the_same_plan() {
    for all in [true, false] {
        let c = l2tp("vpn.example.com", "alice", all);
        let plan = ras::plan_for(&c, b"").unwrap();
        let bytes = rc::encode_profile(&plan);
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(text.starts_with("winvpn-ras-profile 1\n"), "{text}");
        assert_eq!(rc::decode_profile(&bytes), Ok(plan.unwrap()));
    }
    // A value never adds a line: escaped and restored.
    let c = l2tp("vpn.example.com", "a%b\nstrategy=sstp", true);
    let plan = ras::plan_for(&c, b"").unwrap().unwrap();
    let bytes = rc::encode_profile(&Ok(plan.clone()));
    assert_eq!(String::from_utf8(bytes.to_vec()).unwrap().lines().count(), 5);
    assert_eq!(rc::decode_profile(&bytes).unwrap().user, "a%b\nstrategy=sstp");
}

#[test]
fn a_cisco_profile_carries_its_reason_and_garbage_is_refused() {
    en(|| {
        let mut c = l2tp("vpn.example.com", "alice", true);
        c.kind = VPNKind::Cisco;
        let bytes = rc::encode_profile(&ras::plan_for(&c, b"").unwrap());
        let reason = rc::decode_profile(&bytes).unwrap_err();
        assert!(reason.starts_with("Cisco IPsec is not supported by Windows."), "{reason}");

        let damaged = rc::entry_damaged();
        for bad in [
            &b""[..],
            b"[WinVPN-x]\nPhoneNumber=vpn.example.com\n",
            b"winvpn-ras-profile 1\nstrategy=sstp\nserver=a\nuser=b\nroute=none\n",
            b"winvpn-ras-profile 1\nstrategy=l2tp\nserver=\nuser=b\nroute=none\n",
            b"winvpn-ras-profile 1\nstrategy=l2tp\nserver=a\nuser=b\nroute=sideways\n",
            b"winvpn-ras-profile 1\nstrategy=l2tp\nserver=a%41\nuser=b\nroute=none\n",
            b"winvpn-ras-profile 1\nstrategy=l2tp\nserver=a\nuser=b\nroute=none\npsk=secret\n",
            b"winvpn-ras-profile 1\nstrategy=l2tp\nserver=\xff\nuser=b\nroute=none\n",
        ] {
            assert_eq!(rc::decode_profile(bad), Err(damaged.clone()), "{}", String::from_utf8_lossy(bad));
        }
        assert_eq!(rc::decode_profile(&vec![b'a'; 20_000]), Err(damaged));
    });
}

#[test]
fn the_profile_has_no_secret() {
    let c = l2tp("vpn.example.com", "alice", true);
    let bytes = rc::encode_profile(&ras::plan_for(&c, b"").unwrap());
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert_eq!(
        text.lines().map(|l| l.split('=').next().unwrap()).collect::<Vec<_>>(),
        ["winvpn-ras-profile 1", "strategy", "server", "user", "route"]
    );
}

/// The `Secrets` the manager builds with the OTP code appended (`mfa::apply_code`) reach the dial's password
/// as they are: `password + separator + code`.
#[test]
fn otp_is_appended_to_the_password() {
    let c = l2tp("vpn.example.com", "alice", true);
    let plan = ras::plan_for(&c, b"").unwrap().unwrap();
    let base = Secrets { password: Some("hunter22".into()), psk: Some("presharedkey".into()), ..Secrets::default() };
    for (sep, expected) in [
        (OTPSeparator::Comma, "hunter22,123456"),
        (OTPSeparator::None, "hunter22123456"),
        (OTPSeparator::Colon, "hunter22:123456"),
    ] {
        let prepared = mfa::apply_code("123456", sep, &base, VPNKind::L2tp).unwrap();
        assert_eq!(rc::dial_password(&plan, &prepared).as_str(), expected);
        assert_eq!(rc::dial_psk(&plan, &prepared), Ok(Some("presharedkey")), "the PSK carries no code");
    }
}

#[test]
fn the_dial_user_and_the_psk() {
    en(|| {
        let c = l2tp("vpn.example.com", "account", true);
        let plan = ras::plan_for(&c, b"").unwrap().unwrap();
        let none = Secrets::default();
        assert_eq!(rc::dial_user(&plan, &none), "account");
        let typed = Secrets { username: Some("alice@example.com".into()), ..Secrets::default() };
        assert_eq!(rc::dial_user(&plan, &typed), "alice@example.com", "the vault's user name overrides");
        assert_eq!(rc::dial_psk(&plan, &none), Err("Missing: Pre-shared key (PSK)".to_string()));
        assert_eq!(rc::dial_password(&plan, &none).as_str(), "");

        // SSTP names its user in the config: a vault user name does not override it, and no PSK is taken.
        let sstp = ras::plan_sstp(SSTP).unwrap();
        assert_eq!(rc::dial_user(&sstp, &typed), "alice");
        assert_eq!(rc::dial_psk(&sstp, &typed), Ok(None));

        // IKEv2 EAP: the vault's user name (eap_id) when set.
        let eap = ras::plan_ikev2(EAP.as_bytes()).unwrap();
        assert_eq!(rc::dial_user(&eap, &none), "alice");
        assert_eq!(rc::dial_user(&eap, &typed), "alice@example.com");
    });
}

#[test]
fn unsupported_reasons_are_windows_limits_only() {
    en(|| {
        let insecure = b"server=vpn.example.com\nport=443\nuser=alice\ncert=insecure\nroute_all=yes\npeer_dns=yes\n";
        let sstp = Connection::new("S", VPNKind::Sstp);
        assert_eq!(
            rc::unsupported_reason(&sstp, insecure).as_deref(),
            Some("Windows always checks the SSTP server's certificate. Choose System CA or Custom CA file.")
        );
        assert_eq!(rc::unsupported_reason(&sstp, SSTP), None);
        // An invalid config is the editor's matter, not a Windows reason.
        assert_eq!(rc::unsupported_reason(&sstp, b"server=\n"), None);

        let ike = Connection::new("I", VPNKind::Strongswan);
        let psk = EAP.replace("auth = eap-mschapv2", "auth = psk").replace("auth = pubkey", "auth = psk");
        assert!(rc::unsupported_reason(&ike, psk.as_bytes()).unwrap().contains("local auth = psk"));
        assert_eq!(rc::unsupported_reason(&ike, EAP.as_bytes()), None);

        let mut cisco = l2tp("vpn.example.com", "alice", true);
        cisco.kind = VPNKind::Cisco;
        assert!(rc::unsupported_reason(&cisco, b"").unwrap().starts_with("Cisco IPsec is not supported"));
        // The same text as Task 12's `cisco::unsupported` (System Status, the editor).
        assert_eq!(rc::unsupported_reason(&cisco, b""), Some(macvpn_platform_win::pure::cisco::unsupported()));
        assert_eq!(rc::unsupported_reason(&l2tp("vpn.example.com", "alice", true), b""), None);
        assert_eq!(rc::unsupported_reason(&Connection::new("O", VPNKind::Openvpn), b"client\n"), None);
    });
}

#[test]
fn the_sstp_error_context_knows_a_custom_ca() {
    let ca = b"server=vpn.example.com\nport=443\nuser=alice\ncert=ca\nroute_all=yes\npeer_dns=yes\n<ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n";
    let plan = ras::plan_sstp(ca).unwrap();
    assert!(rc::error_context(&plan, ca).sstp_custom_ca);
    let plan = ras::plan_sstp(SSTP).unwrap();
    assert!(!rc::error_context(&plan, SSTP).sstp_custom_ca);
}

#[test]
fn kinds_labels_and_the_log_shapes() {
    assert_eq!(rc::kind_of(Strategy::Ikev2), VPNKind::Strongswan);
    assert_eq!(rc::kind_of(Strategy::Sstp), VPNKind::Sstp);
    assert_eq!(rc::kind_of(Strategy::L2tp), VPNKind::L2tp);
    assert_eq!([Strategy::L2tp, Strategy::Sstp, Strategy::Ikev2].map(rc::type_label), ["L2TP", "SSTP", "IKEv2"]);
    assert!(rc::is_helper_kind(VPNKind::Strongswan) && rc::is_helper_kind(VPNKind::Sstp));
    assert!(!rc::is_helper_kind(VPNKind::L2tp) && !rc::is_helper_kind(VPNKind::Openvpn));
    let id = Uuid::parse_str("12345678-9abc-def0-1234-56789abcdef0").unwrap();
    assert_eq!(
        rc::header("2026-10-25 10:00:00", VPNKind::Sstp, &id, true),
        "═══ 2026-10-25 10:00:00 up sstp 12345678-9ABC-DEF0-1234-56789ABCDEF0 (debug) ═══"
    );
    assert_eq!(rc::timestamp((2026, 1, 2, 3, 4, 5)), "2026-01-02 03:04:05");
    assert!(
        macvpn_core::log::LogLine::new(rc::error_line("Windows error 691: x")).kind
            == macvpn_core::log::LogLineKind::Error
    );
}

#[test]
fn system_status_has_the_windows_vpn_client_row() {
    en(|| {
        let later = |k: VPNKind| (k, "later".to_string());
        let mut report = SetupReport {
            engine_missing: Some("The WinVPN Service is missing".into()),
            later_kinds: [VPNKind::L2tp, VPNKind::Cisco, VPNKind::Strongswan, VPNKind::Sstp].map(later).to_vec(),
            ..SetupReport::unknown()
        };
        rc::complete_report(&mut report);
        assert_eq!(report.later_kinds, vec![later(VPNKind::Cisco)], "Cisco keeps its own answer");
        assert_eq!(
            report.ras,
            Some(EngineRow { ok: true, usable: true, detail: "Built into Windows".into(), action: None })
        );
        // The native kinds need no WinVPN Service; OpenVPN still does.
        for kind in [VPNKind::L2tp, VPNKind::Strongswan, VPNKind::Sstp] {
            assert!(report.is_available(kind), "{kind:?}");
        }
        assert!(!report.is_available(VPNKind::Openvpn));
    });
}

/// fix 2.0.1: since 2.0 no path of System Status says a kind comes "in a later version of WinVPN": the full check
/// (the service's rows, the Windows VPN client row, a disabled RAS service) of every service state gives each kind
/// its 2.0 answer.
#[test]
fn no_kind_comes_later_in_any_service_state() {
    use macvpn_core::service_proto::{EngineFacts, OpenVpnFacts, SERVICE_VERSION, WireGuardFacts};
    use macvpn_platform_win::pure::engine::{self, Reach};
    use macvpn_platform_win::pure::openvpn_install::Upgrade;
    use macvpn_platform_win::pure::system_vpn;
    use macvpn_platform_win::pure::wireguard_update::Offer;
    en(|| {
        let facts = EngineFacts {
            service_version: SERVICE_VERSION,
            problem: None,
            openvpn: OpenVpnFacts {
                version: Some("2.7.8".into()),
                path: None,
                dco: Some("2.8.13.0".into()),
                tap_windows6: Some("9.27.0.0".into()),
                problem: None,
            },
            wireguard: WireGuardFacts { dll_version: Some("0.10.1".into()), problem: None },
        };
        let reaches =
            [Reach::Absent, Reach::Unreachable("The WinVPN Service is not reachable.".into()), Reach::Facts(facts)];
        for reach in reaches {
            for disabled in [false, true] {
                let mut report = engine::report(reach.clone(), "2.7.8", &Upgrade::Unknown, &Offer::Unknown);
                rc::complete_report(&mut report);
                system_vpn::apply_ras_row(&mut report, |name| disabled && name == "RasMan");
                assert!(report.later_kinds.is_empty(), "{reach:?}");
                for kind in VPNKind::ALL {
                    let texts = [report.unavailable_text(kind), report.start_refusal(Some(kind))];
                    for text in texts.into_iter().flatten() {
                        assert!(!text.contains("later"), "{reach:?} {disabled} {kind:?}: {text}");
                    }
                }
                for kind in [VPNKind::L2tp, VPNKind::Strongswan, VPNKind::Sstp] {
                    assert_eq!(report.is_available(kind), !disabled, "{reach:?} {kind:?}");
                }
            }
        }
    });
}

/// fix 2.0.1: the RAS plans of the kinds the `RasEngine` does not run (never asked for: the `HelperClient` sends
/// only IKEv2 and SSTP to it, and only native connections get a profile) are internal errors, never "later".
#[test]
fn the_plans_of_kinds_ras_does_not_run_are_internal_errors() {
    en(|| {
        for kind in [VPNKind::Openvpn, VPNKind::Wireguard, VPNKind::L2tp, VPNKind::Cisco] {
            let e = rc::helper_plan(kind, b"").unwrap_err();
            assert!(e.starts_with("Internal error:") && !e.contains("later"), "{kind:?}: {e}");
        }
        let sstp = "server=vpn.example.com\nport=443\nuser=alice\ncert=system\nroute_all=yes\npeer_dns=yes\n";
        assert_eq!(rc::helper_plan(VPNKind::Sstp, sstp.as_bytes()).unwrap().strategy, Strategy::Sstp);
        assert!(rc::helper_plan(VPNKind::Strongswan, b"nonsense").is_err());
        for kind in [VPNKind::Openvpn, VPNKind::Wireguard] {
            let reasons = rc::profile_plan(&Connection::new("Other", kind)).unwrap_err().reasons;
            assert_eq!(reasons.len(), 1);
            assert!(reasons[0].starts_with("Internal error:") && !reasons[0].contains("later"), "{kind:?}");
        }
        assert!(rc::profile_plan(&l2tp("vpn.example.com", "alice", true)).is_ok());
        let cisco = rc::profile_plan(&Connection::new("Cisco", VPNKind::Cisco)).unwrap_err().reasons;
        assert!(!cisco.iter().any(|r| r.contains("later")), "{cisco:?}");
    });
}
