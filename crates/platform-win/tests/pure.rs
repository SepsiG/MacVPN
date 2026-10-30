//! platform-win's pure logic (compiled and tested on every OS).

use macvpn_core::l10n::{self, AppLanguage};
use macvpn_platform_win::pure::{dates, forward, instance, run_key, texts, toast, zone};
use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn zone_ids_three_and_up_are_downloads() {
    assert!(zone::marks_download(b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/\r\n"));
    assert!(zone::marks_download(b"[ZoneTransfer]\nZoneId=4\n"));
    assert!(!zone::marks_download(b"[ZoneTransfer]\r\nZoneId=0\r\n"));
    assert!(!zone::marks_download(b"[ZoneTransfer]\r\nZoneId=2\r\n"));
    assert!(!zone::marks_download(b"[zonetransfer]\r\n zoneid = 1 \r\n"));
}

#[test]
fn an_unreadable_zone_stream_is_a_download() {
    assert!(zone::marks_download(b""));
    assert!(zone::marks_download(b"[ZoneTransfer]\r\nZoneId=x\r\n"));
    assert!(zone::marks_download(b"[Other]\r\nZoneId=0\r\n"));
    assert!(zone::marks_download(&[0xff, 0xfe, 0xff]));
}

#[test]
fn a_utf16_zone_stream_is_read() {
    let text: Vec<u8> = "\u{feff}[ZoneTransfer]\r\nZoneId=1\r\n".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(!zone::marks_download(&text));
}

/// On Unix the stream name is an ordinary file name, so the reader is tested here too.
#[test]
fn the_mark_is_read_from_the_stream_next_to_the_file() {
    let dir = std::env::temp_dir().join(format!("zone-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("a.ovpn");
    assert!(!zone::is_marked(&file), "a missing file is not marked");
    fs::write(&file, b"client\n").unwrap();
    assert!(!zone::is_marked(&file), "no stream: not marked");
    fs::write(dir.join("a.ovpn:Zone.Identifier"), b"[ZoneTransfer]\r\nZoneId=3\r\n").unwrap();
    assert!(zone::is_marked(&file));
    fs::write(dir.join("a.ovpn:Zone.Identifier"), vec![b'x'; 5000]).unwrap();
    assert!(zone::is_marked(&file), "too large: fail closed");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn dates_have_the_macos_formats() {
    assert_eq!(dates::date((2026, 10, 18)), "2026-10-18");
    assert_eq!(dates::date_time((2026, 10, 18, 14, 3, 5), AppLanguage::Hu), "2026. 10. 18. 14:03:05");
    assert_eq!(dates::date_time((2026, 10, 18, 14, 3, 5), AppLanguage::En), "10/18/2026, 2:03:05\u{202f}PM");
    assert_eq!(dates::date_time((2026, 1, 2, 0, 7, 9), AppLanguage::En), "1/2/2026, 12:07:09\u{202f}AM");
}

#[test]
fn the_not_yet_texts_are_translated() {
    l10n::with_language(AppLanguage::Hu, || {
        assert_eq!(texts::closing(), "A WinVPN bezárása…");
        assert_eq!(texts::startup_disabled(), "Kikapcsolva: Gépház → Alkalmazások → Indítás.");
        assert!(texts::uninstall_in_settings().starts_with("A WinVPN-t a Windowsban távolíthatod el"));
    });
}

#[test]
fn the_run_value_quotes_the_executable() {
    assert_eq!(
        run_key::command(Path::new(r"C:\Program Files\WinVPN\WinVPN.exe")),
        "\"C:\\Program Files\\WinVPN\\WinVPN.exe\""
    );
}

#[test]
fn only_an_absolute_executable_without_quotes_is_registered() {
    let good = if cfg!(windows) { r"C:\Program Files\WinVPN\WinVPN.exe" } else { "/Applications/WinVPN.exe" };
    assert!(run_key::usable(Path::new(good)));
    assert!(!run_key::usable(Path::new("WinVPN.exe")));
    assert!(!run_key::usable(Path::new(&format!("{good}\" -x"))));
    assert!(!run_key::usable(Path::new(&format!("{good}\n"))));
}

#[test]
fn startup_approved_odd_first_byte_is_disabled() {
    assert!(!run_key::disabled_in_settings(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    assert!(run_key::disabled_in_settings(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    assert!(!run_key::disabled_in_settings(&[]));
}

fn absolute(name: &str) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(format!(r"C:\Users\a\Downloads\{name}"))
    } else {
        PathBuf::from(format!("/Users/a/{name}"))
    }
}

#[test]
fn forwarded_paths_round_trip_and_only_absolute_ones_count() {
    let paths = vec![absolute("office.ovpn"), absolute("team.macvpncatalog")];
    let bytes = forward::encode(&paths).unwrap();
    assert_eq!(forward::decode(&bytes), paths);
    assert_eq!(forward::decode(b"relative.ovpn\n"), Vec::<PathBuf>::new());
    assert_eq!(forward::decode(b""), Vec::<PathBuf>::new(), "empty: show the running app");
    assert_eq!(forward::encode(&[]).unwrap(), Vec::<u8>::new());
    assert_eq!(forward::decode(&vec![b'/'; forward::MAX_BYTES + 1]), Vec::<PathBuf>::new(), "too large: nothing");
    assert!(forward::encode(&[PathBuf::from("a\nb")]).is_err());
    assert!(forward::encode(&[PathBuf::from("a\rb")]).is_err());
}

#[test]
fn a_forwarded_message_with_one_bad_line_is_dropped_as_a_whole() {
    let good = absolute("office.ovpn");
    let mixed = format!("{}\nrelative.ovpn\n", good.display());
    assert_eq!(forward::decode(mixed.as_bytes()), Vec::<PathBuf>::new());
    let nul = format!("{}\0x\n", good.display());
    assert_eq!(forward::decode(nul.as_bytes()), Vec::<PathBuf>::new());
    assert_eq!(forward::decode(&[0xff, b'\n']), Vec::<PathBuf>::new(), "not UTF-8");
}

#[test]
fn forwarded_paths_are_bounded_in_count() {
    let many: Vec<PathBuf> = (0..=forward::MAX_PATHS).map(|i| absolute(&format!("{i}.ovpn"))).collect();
    assert!(forward::encode(&many).is_err());
    let text: String = many.iter().map(|p| format!("{}\n", p.display())).collect();
    assert_eq!(forward::decode(text.as_bytes()), Vec::<PathBuf>::new());
    let most = &many[..forward::MAX_PATHS];
    assert_eq!(forward::decode(&forward::encode(most).unwrap()), most.to_vec());
}

#[test]
fn device_and_verbatim_paths_are_not_forwarded() {
    assert_eq!(forward::decode(b"\\\\.\\pipe\\x\n"), Vec::<PathBuf>::new());
    assert_eq!(forward::decode(b"\\\\?\\C:\\x.ovpn\n"), Vec::<PathBuf>::new());
    assert_eq!(forward::decode(b"//./pipe/x\n"), Vec::<PathBuf>::new());
}

#[test]
fn toast_xml_escapes_everything() {
    let xml = toast::xml("Office <VPN> & \"more\"", "it's 'connected'");
    assert_eq!(
        xml,
        "<toast><visual><binding template=\"ToastGeneric\"><text>Office &lt;VPN&gt; &amp; &quot;more&quot;</text>\
         <text>it&apos;s &apos;connected&apos;</text></binding></visual></toast>"
    );
}

#[test]
fn toast_tags_fit_the_64_character_limit() {
    assert_eq!(toast::tag("auth-1234"), "auth-1234");
    let long = "x".repeat(100);
    let t = toast::tag(&long);
    assert_eq!(t.len(), 32);
    assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(t, toast::tag(&long), "stable");
}

/// An existing single-instance mutex is WinVPN's own only when this user owns it; another owner is its own error
/// (not "already running": nothing is forwarded), and the message box says so (review L3).
#[test]
fn a_foreign_single_instance_mutex_is_squatted_not_running() {
    assert!(instance::existing_mutex(true).is_ok());
    let e = instance::existing_mutex(false).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(instance::is_squatted(&e));
    assert!(!instance::is_squatted(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)));
    let squatted = instance::failure_message_in(AppLanguage::En, &e);
    assert!(squatted.contains("another user"), "{squatted}");
    assert!(instance::failure_message_in(AppLanguage::Hu, &e).contains("másik felhasználó"));
    let other = std::io::Error::from(std::io::ErrorKind::TimedOut);
    assert!(instance::failure_message_in(AppLanguage::En, &other).contains("did not answer"));
    assert!(instance::failure_message_in(AppLanguage::Hu, &other).contains("nem válaszol"));
    l10n::with_language(AppLanguage::Hu, || assert!(instance::failure_message(&e).starts_with("A WinVPN nem tud")));
}

// MARK: - System Status from the WinVPN Service's `engine` facts (Task 16)

mod engine_report {
    use macvpn_core::l10n::{self, AppLanguage};
    use macvpn_core::models::VPNKind;
    use macvpn_core::service_proto::{EngineFacts, OpenVpnFacts, SERVICE_VERSION, Version, WireGuardFacts};
    use macvpn_platform_api::PackageIndexUpdate;
    use macvpn_platform_win::pure::cisco;
    use macvpn_platform_win::pure::engine::{Reach, index_refresh, report, update_check_for};
    use macvpn_platform_win::pure::openvpn_install::{Upgrade, Via};
    use macvpn_platform_win::pure::texts;
    use macvpn_platform_win::pure::wireguard_update::{self as wu, Offer};

    const PINNED: &str = "2.7.8";

    fn offer(v: &str) -> Upgrade {
        Upgrade::Available { shown: v.into(), version: Version::parse(v).unwrap(), via: Via::Winget }
    }

    fn facts(openvpn_problem: Option<&str>, wg_problem: Option<&str>) -> EngineFacts {
        EngineFacts {
            service_version: SERVICE_VERSION,
            problem: None,
            openvpn: OpenVpnFacts {
                version: openvpn_problem.is_none().then(|| "2.7.8".into()),
                path: None,
                dco: openvpn_problem.is_none().then(|| "2.8.13.0".into()),
                tap_windows6: openvpn_problem.is_none().then(|| "9.27.0.0".into()),
                problem: openvpn_problem.map(String::from),
            },
            wireguard: WireGuardFacts {
                dll_version: wg_problem.is_none().then(|| "0.10.1".into()),
                problem: wg_problem.map(String::from),
            },
        }
    }

    #[test]
    fn a_reachable_service_gives_three_rows() {
        let r = report(Reach::Facts(facts(None, None)), PINNED, &Upgrade::Unknown, &Offer::Unknown);
        let e = r.engine.as_ref().unwrap();
        assert!(e.service.ok && e.openvpn.ok && e.wireguard.ok);
        assert_eq!((e.openvpn.action, e.wireguard.action, e.service.action), (None, None, None));
        assert_eq!(r.engine_missing, None);
        assert!(r.is_complete());
        assert!(r.is_available(VPNKind::Openvpn) && r.is_available(VPNKind::Wireguard));
        // WinVPN 2.0: no kind comes "later" (the native kinds follow the Windows VPN client row).
        assert!(r.later_kinds.is_empty());
        // Cisco IPsec (2c Task 12, option A): never available on Windows, with its own reason.
        assert!(!r.is_available(VPNKind::Cisco));
        assert_eq!(r.later_reason(VPNKind::Cisco), None);
        assert_eq!(r.ras_unsupported_reason(VPNKind::Cisco), Some(cisco::unsupported().as_str()));
        assert_eq!(r.unavailable_text(VPNKind::Cisco), Some(cisco::unsupported()));
        // The OpenVPN row names its version and both drivers (decision 4: DCO and TAP-Windows6, never Wintun).
        assert!(e.openvpn.detail.contains("2.7.8"), "{}", e.openvpn.detail);
        assert!(e.openvpn.detail.contains("OpenVPN DCO 2.8.13.0"), "{}", e.openvpn.detail);
        assert!(e.openvpn.detail.contains("TAP-Windows6 9.27.0.0"), "{}", e.openvpn.detail);
        assert!(!e.openvpn.detail.contains("Wintun"));
        assert_eq!(e.wireguard.detail, "wireguard-nt 0.10.1");
        assert!(e.service.detail.contains(&SERVICE_VERSION.to_string()));
    }

    #[test]
    fn missing_openvpn_offers_install_and_an_old_one_update() {
        let r = report(
            Reach::Facts(facts(Some("OpenVPN Community is not installed."), None)),
            PINNED,
            &Upgrade::Unknown,
            &Offer::Unknown,
        );
        let row = &r.engine.as_ref().unwrap().openvpn;
        assert_eq!((row.ok, row.usable, row.action), (false, false, Some("install")));
        assert_eq!(row.detail, "OpenVPN Community is not installed.");
        assert!(!r.is_available(VPNKind::Openvpn) && r.is_available(VPNKind::Wireguard));
        // OpenVPN is optional (2.0): not installed alone leaves the report complete (no "!", no window at launch).
        assert!(r.is_complete());
        // Older than the pin but no update known (winget's answer decides, decision 4 as amended 2026-10-24):
        // green, usable, no action.
        let mut old = facts(None, None);
        old.openvpn.version = Some("2.6.3".into());
        let row = report(Reach::Facts(old), PINNED, &Upgrade::Unknown, &Offer::Unknown).engine.unwrap().openvpn;
        assert_eq!((row.ok, row.usable, row.action), (true, true, None));
        // Refused by the service with a version below the pin (too old): "Update"; at the pin (e.g. a wrong
        // signer): "Repair".
        let mut refused = facts(None, None);
        refused.openvpn.version = Some("2.5.9".into());
        refused.openvpn.problem = Some("too old".into());
        let row =
            report(Reach::Facts(refused.clone()), PINNED, &Upgrade::Unknown, &Offer::Unknown).engine.unwrap().openvpn;
        assert_eq!((row.ok, row.usable, row.action, row.detail.as_str()), (false, false, Some("update"), "too old"));
        refused.openvpn.version = Some("2.7.8".into());
        assert_eq!(
            report(Reach::Facts(refused), PINNED, &Upgrade::Unknown, &Offer::Unknown).engine.unwrap().openvpn.action,
            Some("repair")
        );
        // A missing driver: "repair", still usable for the other driver's connections.
        let mut no_tap = facts(None, None);
        no_tap.openvpn.tap_windows6 = None;
        let row = report(Reach::Facts(no_tap), PINNED, &Upgrade::Unknown, &Offer::Unknown).engine.unwrap().openvpn;
        assert_eq!((row.ok, row.usable, row.action), (false, true, Some("repair")));
        assert!(row.detail.contains("TAP-Windows6") && row.detail.contains("OpenVPN DCO 2.8.13.0"), "{}", row.detail);
        // Neither driver: nothing can connect.
        let mut none = facts(None, None);
        none.openvpn.tap_windows6 = None;
        none.openvpn.dco = None;
        let r = report(Reach::Facts(none), PINNED, &Upgrade::Unknown, &Offer::Unknown);
        let row = r.engine.as_ref().unwrap().openvpn.clone();
        assert_eq!((row.ok, row.usable, row.action), (false, false, Some("repair")));
        assert!(!r.is_available(VPNKind::Openvpn));
        // Installed but not ready: still incomplete.
        assert!(!r.is_complete());
    }

    #[test]
    fn a_green_row_with_an_update_stays_green_and_offers_update() {
        let mut f = facts(None, None);
        f.openvpn.version = Some("2.7.7".into());
        assert_eq!(update_check_for(&Reach::Facts(f.clone())), Some(Version(2, 7, 7)));
        let r = report(Reach::Facts(f.clone()), PINNED, &offer("2.7.8"), &Offer::Unknown);
        let row = r.engine.as_ref().unwrap().openvpn.clone();
        assert_eq!((row.ok, row.usable, row.action), (true, true, Some("update")));
        assert!(row.detail.ends_with("Update available: 2.7.7 → 2.7.8"), "{}", row.detail);
        assert!(row.detail.contains("OpenVPN DCO 2.8.13.0"), "{}", row.detail);
        assert!(r.is_complete() && r.is_available(VPNKind::Openvpn));
        // Nothing newer, or no answer: green, no action, no update text.
        for upgrade in [Upgrade::None, Upgrade::Unknown] {
            let row = report(Reach::Facts(f.clone()), PINNED, &upgrade, &Offer::Unknown).engine.unwrap().openvpn;
            assert_eq!((row.ok, row.usable, row.action), (true, true, None), "{upgrade:?}");
            assert!(!row.detail.contains("Update"), "{}", row.detail);
        }
        // Newer than the pin (winget's newest): green, and winget's update still offered.
        f.openvpn.version = Some("2.7.9".into());
        let row = report(Reach::Facts(f), PINNED, &offer("2.8.0"), &Offer::Unknown).engine.unwrap().openvpn;
        assert_eq!((row.ok, row.action), (true, Some("update")));
        l10n::with_language(AppLanguage::Hu, || {
            assert_eq!(texts::update_available("2.7.7", "2.7.8"), "Frissítés elérhető: 2.7.7 → 2.7.8");
        });
    }

    #[test]
    fn repair_takes_precedence_over_an_update() {
        let mut no_tap = facts(None, None);
        no_tap.openvpn.version = Some("2.7.7".into());
        no_tap.openvpn.tap_windows6 = None;
        // No update check is asked for a row that needs a repair, and an answer given anyway does not change it.
        assert_eq!(update_check_for(&Reach::Facts(no_tap.clone())), None);
        let row = report(Reach::Facts(no_tap), PINNED, &offer("2.7.8"), &Offer::Unknown).engine.unwrap().openvpn;
        assert_eq!((row.ok, row.usable, row.action), (false, true, Some("repair")));
        assert!(!row.detail.contains("Update available"), "{}", row.detail);
        // Refused by the service (too old): its own action, never the update check's.
        let mut refused = facts(None, None);
        refused.openvpn.version = Some("2.5.9".into());
        refused.openvpn.problem = Some("too old".into());
        assert_eq!(update_check_for(&Reach::Facts(refused.clone())), None);
        let row = report(Reach::Facts(refused), PINNED, &Upgrade::None, &Offer::Unknown).engine.unwrap().openvpn;
        assert_eq!((row.ok, row.action, row.detail.as_str()), (false, Some("update"), "too old"));
        // Not installed, no service, a degraded service: no check.
        assert_eq!(update_check_for(&Reach::Facts(facts(Some("not installed"), None))), None);
        assert_eq!(update_check_for(&Reach::Absent), None);
        let mut degraded = facts(None, None);
        degraded.problem = Some("unsafe folder".into());
        assert_eq!(update_check_for(&Reach::Facts(degraded)), None);
    }

    /// fix 2.0.1: a service that names no problem and no readable version is not "not installed" (OpenVPN's
    /// optional state, which keeps the report complete): the row is "Not ready" without an action, and the report
    /// is incomplete (the "!" mark, System Status opens at launch).
    #[test]
    fn an_unreadable_openvpn_version_is_not_ready_and_incomplete() {
        l10n::with_language(AppLanguage::En, || {
            for version in [None, Some("2.7"), Some("x")] {
                let mut f = facts(None, None);
                f.openvpn.version = version.map(String::from);
                let r = report(Reach::Facts(f), PINNED, &Upgrade::Unknown, &Offer::Unknown);
                let row = &r.engine.as_ref().unwrap().openvpn;
                assert_eq!((row.ok, row.usable, row.action), (false, false, None), "{version:?}");
                assert!(!r.is_complete(), "{version:?}");
                assert_eq!(
                    r.unavailable_text(VPNKind::Openvpn).as_deref(),
                    Some("Not ready: OpenVPN Community"),
                    "{version:?}"
                );
            }
            // Truly not installed stays optional.
            let r = report(
                Reach::Facts(facts(Some("OpenVPN Community is not installed."), None)),
                PINNED,
                &Upgrade::Unknown,
                &Offer::Unknown,
            );
            assert!(r.is_complete());
            assert_eq!(r.unavailable_text(VPNKind::Openvpn).as_deref(), Some("Not installed: OpenVPN Community"));
        });
    }

    #[test]
    fn facts_without_a_problem_or_a_version_fail_closed() {
        // No problem but no (readable) version: never green.
        for version in [None, Some("2.7"), Some("x")] {
            let mut f = facts(None, None);
            f.openvpn.version = version.map(String::from);
            let r = report(Reach::Facts(f), PINNED, &Upgrade::Unknown, &Offer::Unknown);
            let row = &r.engine.as_ref().unwrap().openvpn;
            assert!(!row.ok && !row.usable, "{version:?}");
            assert!(!r.is_available(VPNKind::Openvpn));
        }
        let mut f = facts(None, None);
        f.wireguard.dll_version = None;
        let r = report(Reach::Facts(f), PINNED, &Upgrade::Unknown, &Offer::Unknown);
        assert!(!r.engine.as_ref().unwrap().wireguard.usable && !r.is_available(VPNKind::Wireguard));
        let r = report(
            Reach::Facts(facts(None, Some("Not available on this system yet"))),
            PINNED,
            &Upgrade::Unknown,
            &Offer::Unknown,
        );
        let row = &r.engine.as_ref().unwrap().wireguard;
        assert_eq!((row.ok, row.usable, row.detail.as_str()), (false, false, "Not available on this system yet"));
    }

    #[test]
    fn no_service_or_another_version_is_engine_missing() {
        for reach in [Reach::Absent, Reach::Unreachable(texts::service_unreachable())] {
            let r = report(reach, PINNED, &Upgrade::Unknown, &Offer::Unknown);
            assert!(r.engine_missing.is_some() && r.engine.is_none());
            assert!(!r.is_available(VPNKind::Openvpn) && !r.is_available(VPNKind::Wireguard));
            assert!(r.later_kinds.is_empty());
            assert_eq!(r.start_refusal(Some(VPNKind::Cisco)), Some(cisco::unsupported()));
        }
        assert_eq!(
            report(Reach::Absent, PINNED, &Upgrade::Unknown, &Offer::Unknown).engine_missing,
            Some(texts::service_missing())
        );
        assert_eq!(
            report(Reach::Unreachable(texts::service_unreachable()), PINNED, &Upgrade::Unknown, &Offer::Unknown)
                .engine_missing,
            Some(texts::service_unreachable())
        );
        for v in [0, SERVICE_VERSION + 1] {
            let mut other = facts(None, None);
            other.service_version = v;
            assert_eq!(
                report(Reach::Facts(other), PINNED, &Upgrade::Unknown, &Offer::Unknown).engine_missing,
                Some(texts::service_missing())
            );
        }
        let mut degraded = facts(None, None);
        degraded.problem = Some("unsafe folder".into());
        let r = report(Reach::Facts(degraded), PINNED, &Upgrade::Unknown, &Offer::Unknown);
        assert_eq!(r.engine_missing.as_deref(), Some("unsafe folder"));
        assert!(r.engine.is_none() && !r.is_available(VPNKind::Openvpn));
    }

    /// G-1: the daily background refresh. Windows has no package index: the "refresh" is the next check asking
    /// winget and the service again, worth it only with a usable service and never in the sandbox.
    #[test]
    fn index_refresh_is_unavailable_without_the_service_and_in_the_sandbox() {
        assert_eq!(index_refresh(&Reach::Absent, false), PackageIndexUpdate::Unavailable);
        assert_eq!(index_refresh(&Reach::Unreachable("no answer".into()), false), PackageIndexUpdate::Unavailable);
        let mut other = facts(None, None);
        other.service_version = SERVICE_VERSION + 1;
        assert_eq!(index_refresh(&Reach::Facts(other), false), PackageIndexUpdate::Unavailable);
        let mut degraded = facts(None, None);
        degraded.problem = Some("unsafe folder".into());
        assert_eq!(index_refresh(&Reach::Facts(degraded), false), PackageIndexUpdate::Unavailable);
        assert_eq!(index_refresh(&Reach::Facts(facts(None, None)), true), PackageIndexUpdate::Unavailable);
    }

    #[test]
    fn index_refresh_asks_for_a_check_when_the_service_is_usable() {
        assert_eq!(index_refresh(&Reach::Facts(facts(None, None)), false), PackageIndexUpdate::Updated);
        // A missing OpenVPN or wireguard-nt is the check's business (its rows), not a reason to skip the refresh.
        let missing = facts(Some("OpenVPN Community is not installed."), Some("missing"));
        assert_eq!(index_refresh(&Reach::Facts(missing), false), PackageIndexUpdate::Updated);
    }

    #[test]
    fn the_service_texts_are_translated() {
        l10n::with_language(AppLanguage::Hu, || {
            assert!(texts::service_missing().starts_with("A WinVPN szolgáltatás hiányzik"));
            assert_eq!(texts::service_unreachable(), "A WinVPN szolgáltatás nem érhető el.");
            assert_eq!(texts::service_running("1"), "Fut (1. verzió)");
            assert_eq!(texts::upgrade_disconnects(), "A WinVPN frissítése bontja az aktív VPN-kapcsolatokat.");
            assert_eq!(
                texts::openvpn_ok("2.7.8", &[("OpenVPN DCO", Some("2.8.13.0".into()))]),
                "2.7.8. verzió · illesztőprogramok: OpenVPN DCO 2.8.13.0"
            );
            assert_eq!(texts::drivers_missing("TAP-Windows6"), "Hiányzik: TAP-Windows6. A Javítás telepíti őket.");
        });
        l10n::with_language(AppLanguage::En, || {
            assert_eq!(texts::service_running("1"), "Running (version 1)");
        });
    }
    /// fix 2.0.1: OpenVPN and wireguard-nt both offering "Update" are two buttons, one per row (Setup.svelte). The
    /// OpenVPN row's button sends the report as it is: OpenVPN; the WireGuard row's sends it without the OpenVPN
    /// action (app `setup_install_tools`): wireguard-nt. Neither click runs the other row's update.
    #[test]
    fn each_engine_rows_button_runs_its_own_update() {
        use macvpn_platform_win::pure::engine::{ToolsTarget, tools_target};
        let mut f = facts(None, None);
        f.openvpn.version = Some("2.7.7".into());
        let both = Offer::Available { installed: "0.10.1".into(), available: "0.11.0".into() };
        let r = report(Reach::Facts(f), PINNED, &offer("2.7.8"), &both);
        let e = r.engine.as_ref().unwrap();
        assert_eq!((e.openvpn.action, e.wireguard.action), (Some("update"), Some("update")));
        assert_eq!(tools_target(&r), ToolsTarget::OpenVpn);
        let mut wireguard_button = r.clone();
        wireguard_button.engine.as_mut().unwrap().openvpn.action = None;
        assert_eq!(tools_target(&wireguard_button), ToolsTarget::WireGuard);
        // Only OpenVPN's action, or none (the installer answers): OpenVPN.
        let mut openvpn_only = r.clone();
        openvpn_only.engine.as_mut().unwrap().wireguard.action = None;
        assert_eq!(tools_target(&openvpn_only), ToolsTarget::OpenVpn);
        assert_eq!(tools_target(&macvpn_platform_api::SetupReport::unknown()), ToolsTarget::OpenVpn);
    }

    #[test]
    fn the_wireguard_row_offers_the_services_update_and_stays_green() {
        let f = facts(None, None);
        let offer = Offer::Available { installed: "0.10.1".into(), available: "1.2.0".into() };
        l10n::with_language(AppLanguage::En, || {
            let row = report(Reach::Facts(f.clone()), PINNED, &Upgrade::Unknown, &offer).engine.unwrap().wireguard;
            assert!(row.ok && row.usable);
            assert_eq!(row.detail, "wireguard-nt 0.10.1 Update available: 0.10.1 → 1.2.0");
            assert_eq!(row.action, Some("update"));
        });
        for none in [Offer::None, Offer::Unknown] {
            let row = report(Reach::Facts(f.clone()), PINNED, &Upgrade::Unknown, &none).engine.unwrap().wireguard;
            assert_eq!((row.ok, row.action, row.detail.as_str()), (true, None, "wireguard-nt 0.10.1"));
        }
        // A refused DLL keeps its red row without "Update" (the service's message: repair WinVPN).
        let broken = facts(None, Some("wireguard.dll does not match its pinned version. Repair WinVPN."));
        let row = report(Reach::Facts(broken.clone()), PINNED, &Upgrade::Unknown, &offer).engine.unwrap().wireguard;
        assert!(!row.ok && row.action.is_none());
        // Only a green row is checked.
        assert!(wu::check_for(&Reach::Facts(f.clone())));
        assert!(!wu::check_for(&Reach::Facts(broken)));
        assert!(!wu::check_for(&Reach::Absent));
        let mut degraded = f.clone();
        degraded.problem = Some("unsafe folder".into());
        assert!(!wu::check_for(&Reach::Facts(degraded)));
        let mut other = f;
        other.service_version = SERVICE_VERSION + 1;
        assert!(!wu::check_for(&Reach::Facts(other)));
    }

    #[test]
    fn the_services_answers_map_to_offers_and_outcomes() {
        let ok = |s: &str| wu::offer_from(Some((0, s.as_bytes())));
        assert_eq!(
            ok(r#"{"installed":"1.1.0","available":"1.2.0"}"#),
            Offer::Available { installed: "1.1.0".into(), available: "1.2.0".into() }
        );
        assert_eq!(ok(r#"{"installed":"1.1.0","available":null}"#), Offer::None);
        // Not this shape, a failure, an older service's usage error, no answer: unknown.
        assert_eq!(ok(r#"{"installed":null,"available":"1.2.0"}"#), Offer::Unknown);
        assert_eq!(ok("garbage"), Offer::Unknown);
        assert_eq!(wu::offer_from(Some((1, b"".as_slice()))), Offer::Unknown);
        assert_eq!(wu::offer_from(Some((2, b"".as_slice()))), Offer::Unknown);
        assert_eq!(wu::offer_from(None), Offer::Unknown);
        let unreachable = || "unreachable".to_string();
        l10n::with_language(AppLanguage::En, || {
            let done = wu::update_outcome(
                Some((0, br#"{"installed":"1.2.0","available":null}"#.as_slice(), "")),
                unreachable(),
            );
            assert_eq!(done, Ok("wireguard-nt 1.2.0 is installed.".to_string()));
        });
        assert_eq!(
            wu::update_outcome(Some((3, b"".as_slice(), "busy text\n")), unreachable()),
            Err("busy text".into())
        );
        assert_eq!(wu::update_outcome(Some((1, b"".as_slice(), "failed")), unreachable()), Err("failed".into()));
        assert_eq!(wu::update_outcome(Some((1, b"".as_slice(), " ")), unreachable()), Err("unreachable".into()));
        assert_eq!(wu::update_outcome(Some((0, b"x".as_slice(), "")), unreachable()), Err("unreachable".into()));
        assert_eq!(wu::update_outcome(None, unreachable()), Err("unreachable".into()));
        l10n::with_language(AppLanguage::Hu, || {
            assert_eq!(wu::updating(), "A wireguard-nt frissítése…");
            assert_eq!(wu::installed("1.2.0"), "A(z) 1.2.0 wireguard-nt telepítve.");
        });
    }
}

// MARK: - OpenVPN Community install (Task 17)

mod openvpn_install {
    use macvpn_core::l10n::{self, AppLanguage};
    use macvpn_core::service_proto::OpenVpnFacts;
    use macvpn_core::service_proto::Version;
    use macvpn_platform_win::pure::openvpn_install::{
        self as oi, Action, First, Interactive, Outcome, Step, StepError, StepResult, Upgrade, Via,
    };
    use macvpn_platform_win::pure::openvpn_pins as pins;
    use std::path::Path;

    const FEATURES: &str = "OpenVPN,Drivers,Drivers.OvpnDco,Drivers.TAPWindows6";

    #[test]
    fn the_winget_command_line_is_fixed() {
        assert_eq!(
            oi::winget_args(false, FEATURES),
            [
                "install",
                "--id",
                "OpenVPNTechnologies.OpenVPN",
                "--exact",
                "--source",
                "winget",
                "--scope",
                "machine",
                "--silent",
                "--accept-package-agreements",
                "--accept-source-agreements",
                "--disable-interactivity",
                "--override",
                "/qn /norestart ADDLOCAL=OpenVPN,Drivers,Drivers.OvpnDco,Drivers.TAPWindows6",
            ]
        );
        assert_eq!(oi::winget_args(true, "OpenVPN")[0], "upgrade");
    }

    #[test]
    fn the_msiexec_parameters_quote_only_a_checked_path() {
        let p = Path::new(r"C:\ProgramData\WinVPN\installer\0123abcd\OpenVPN-2.7.8-I001-amd64.msi");
        assert_eq!(
            oi::msiexec_parameters(p, "OpenVPN,Drivers.OvpnDco,Drivers.TAPWindows6").unwrap(),
            r#"/i "C:\ProgramData\WinVPN\installer\0123abcd\OpenVPN-2.7.8-I001-amd64.msi" /qb! /norestart ADDLOCAL=OpenVPN,Drivers.OvpnDco,Drivers.TAPWindows6"#
        );
        assert!(oi::msiexec_parameters(Path::new(r"C:\dir\"), "OpenVPN").is_none(), "a trailing \\ escapes the quote");
        assert!(oi::msiexec_parameters(Path::new(r#"C:\x" /qn TRANSFORMS="evil.mst"#), "OpenVPN").is_none());
        assert!(oi::msiexec_parameters(Path::new("relative.msi"), "OpenVPN").is_none());
        assert!(oi::msiexec_parameters(Path::new("C:\\a\nb.msi"), "OpenVPN").is_none());
        // Security review L-3: only a plain path on a local drive letter (no UNC, no device path, no drive-relative
        // or Unix path, no `.`/`..`, no `/`, no stream).
        for bad in [
            r"\\attacker\s\x.msi",
            r"\\?\C:\x.msi",
            r"\\.\C:\x.msi",
            r"\??\C:\x.msi",
            r"C:x.msi",
            r"C:\a\..\x.msi",
            r"C:\a\.\x.msi",
            r"C:\a\\x.msi",
            r"C:/a/x.msi",
            r"C:\a/x.msi",
            r"C:\x.msi:stream",
            "/tmp/o.msi",
        ] {
            assert!(oi::msiexec_parameters(Path::new(bad), "OpenVPN").is_none(), "{bad}");
        }
        for features in ["OpenVPN TRANSFORMS=x", "", "OpenVPN\"", "A;B"] {
            assert!(oi::msiexec_parameters(p, features).is_none(), "{features}");
        }
    }

    #[test]
    fn exit_codes_map_to_outcomes() {
        assert_eq!(oi::outcome(0), Outcome::Done);
        assert_eq!(oi::outcome(3010), Outcome::DoneRestartNeeded);
        assert_eq!(oi::outcome(1602), Outcome::Cancelled);
        assert_eq!(oi::outcome(1223), Outcome::Cancelled);
        assert_eq!(oi::outcome(1603), Outcome::Failed(1603));
        assert_eq!(oi::code_text(1603), "1603");
        assert_eq!(oi::code_text(0x8A15_002B), "0x8A15002B");
    }

    #[test]
    fn each_action_starts_on_its_path() {
        let pinned = pins::OPENVPN_VERSION;
        assert_eq!(oi::first_step(Action::Install, None, pinned, true), First::Winget { update: false });
        assert_eq!(oi::first_step(Action::Install, None, pinned, false), First::Msi);
        assert_eq!(oi::first_step(Action::Update, Some("2.6.12"), pinned, true), First::Winget { update: true });
        assert_eq!(oi::first_step(Action::Update, Some("2.6.12"), pinned, false), First::Msi);
        // Repair of the pinned version: a maintenance install of the pinned MSI adds the features, winget or not.
        assert_eq!(oi::first_step(Action::Repair, Some(pinned), pinned, true), First::Msi);
        assert_eq!(oi::first_step(Action::Repair, Some(pinned), pinned, false), First::Msi);
        // Of another version: winget's upgrade, or the user adds the drivers in Settings.
        assert_eq!(oi::first_step(Action::Repair, Some("2.7.9"), pinned, true), First::Winget { update: true });
        assert_eq!(
            oi::first_step(Action::Repair, Some("2.7.9"), pinned, false),
            First::Refuse(oi::add_drivers_in_settings())
        );
        assert_eq!(oi::first_step(Action::Repair, None, pinned, false), First::Refuse(oi::add_drivers_in_settings()));
        assert_eq!(Action::parse("repair"), Some(Action::Repair));
        assert_eq!(Action::parse("install"), Some(Action::Install));
        assert_eq!(Action::parse("update"), Some(Action::Update));
        assert_eq!(Action::parse("Install"), None);
    }

    #[test]
    fn the_interactive_service_is_touched_only_on_winvpns_installation() {
        assert!(oi::disable_interactive(true, false), "absent before: WinVPN's install");
        assert!(oi::disable_interactive(false, true), "the marker: an earlier install was WinVPN's");
        assert!(oi::disable_interactive(true, true));
        assert!(!oi::disable_interactive(false, false), "the user's own installation is never touched");
        assert_eq!(pins::OPENVPN_INTERACTIVE_SERVICE, "OpenVPNServiceInteractive");
        assert_eq!((oi::MARKER_KEY, oi::MARKER_VALUE), (r"SOFTWARE\WinVPN", "OpenVpnInstalledByWinVpn"));
    }

    #[test]
    fn both_drivers_are_needed() {
        let facts = |dco: Option<&str>, tap: Option<&str>| OpenVpnFacts {
            version: Some("2.7.8".into()),
            dco: dco.map(String::from),
            tap_windows6: tap.map(String::from),
            path: None,
            problem: None,
        };
        assert!(oi::drivers_complete(&facts(Some("2.8.13.0"), Some("9.27.0.0"))));
        assert!(!oi::drivers_complete(&facts(Some("2.8.13.0"), None)));
        assert!(!oi::drivers_complete(&facts(None, Some("9.27.0.0"))));
    }

    #[test]
    fn the_pinned_msi_of_each_architecture() {
        let (url, sha, features) = oi::pinned_msi("x86_64").unwrap();
        assert_eq!((url, sha, features), (pins::OPENVPN_MSI_X64_URL, pins::OPENVPN_MSI_X64_SHA256, FEATURES));
        assert_eq!(oi::msi_file_name(url), Some("OpenVPN-2.7.8-I001-amd64.msi"));
        let (url, ..) = oi::pinned_msi("aarch64").unwrap();
        assert_eq!(oi::msi_file_name(url), Some("OpenVPN-2.7.8-I001-arm64.msi"));
        assert!(oi::pinned_msi("x86").is_none());
        assert_eq!(oi::msi_file_name("https://x/a b.msi"), None);
        assert_eq!(oi::msi_file_name("https://x/..msi"), None);
        assert_eq!(oi::msi_file_name("https://x/setup.exe"), None);
        assert_eq!(oi::msi_file_name("https://x/.msi"), None);
    }

    #[test]
    fn the_step_arguments_round_trip_and_nothing_else_parses() {
        let args = |s: &str| -> Vec<String> {
            // CommandLineToArgvW's reading of these simple lines: quotes group, nothing is escaped.
            let mut out = Vec::new();
            let (mut cur, mut quoted) = (String::new(), false);
            for c in s.chars() {
                match c {
                    '"' => quoted = !quoted,
                    ' ' if !quoted => out.push(std::mem::take(&mut cur)),
                    c => cur.push(c),
                }
            }
            out.push(cur);
            out
        };
        let path = r"C:\Users\bob\AppData\Local\WinVPN\downloads\O p.msi";
        for step in [
            Step::Msi { path: path.into() },
            Step::OfficialMsi { path: path.into() },
            Step::Interactive { absent_before: true },
            Step::Interactive { absent_before: false },
        ] {
            let line = oi::step_parameters(&step).unwrap();
            assert!(line.starts_with(oi::STEP_ARG));
            assert!(!line.contains("absent") || matches!(step, Step::Interactive { .. }), "{line}");
            assert_eq!(oi::parse_step(&args(&line)), Some(step));
        }
        assert_eq!(oi::step_parameters(&Step::Msi { path: "C:\\x\" y".into() }), None);
        assert_eq!(oi::step_parameters(&Step::Msi { path: "rel.msi".into() }), None);
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let msi = r"C:\d\o.msi";
        assert_eq!(oi::parse_step(&s(&[oi::STEP_ARG, "msi", msi])), Some(Step::Msi { path: msi.into() }));
        assert_eq!(oi::parse_step(&s(&[])), None);
        assert_eq!(oi::parse_step(&s(&["--other", "msi", msi])), None);
        assert_eq!(oi::parse_step(&s(&[oi::STEP_ARG, "msi"])), None);
        // Security review L-2: whether OpenVPN was absent is the elevated process' own finding, never an argument.
        assert_eq!(oi::parse_step(&s(&[oi::STEP_ARG, "msi", msi, "absent"])), None);
        assert_eq!(oi::parse_step(&s(&[oi::STEP_ARG, "msi-official", msi, "present"])), None);
        assert_eq!(oi::parse_step(&s(&[oi::STEP_ARG, "msi", "rel.msi"])), None);
        assert_eq!(oi::parse_step(&s(&[oi::STEP_ARG, "interactive", msi, "absent"])), None);
        assert_eq!(oi::parse_step(&s(&[oi::STEP_ARG, "interactive", "yes"])), None);
        assert_eq!(oi::parse_step(&s(&[oi::STEP_ARG, "interactive", "absent", "x"])), None);
        assert_eq!(oi::parse_step(&s(&[oi::STEP_ARG, "exec", msi])), None);
        // Security review L-3: a UNC path (an SMB or WebDAV logon with the administrator's token) and every other
        // path that is not a plain local drive path are refused before anything is opened.
        for bad in [r"\\attacker\s\x.msi", r"\\?\UNC\attacker\s\x.msi", r"\\.\pipe\x", r"C:x.msi", "/tmp/o.msi"] {
            assert_eq!(oi::parse_step(&s(&[oi::STEP_ARG, "msi", bad])), None, "{bad}");
            assert_eq!(oi::parse_step(&s(&[oi::STEP_ARG, "msi-official", bad])), None, "{bad}");
            assert_eq!(oi::step_parameters(&Step::Msi { path: bad.into() }), None, "{bad}");
        }
    }

    #[test]
    fn the_step_result_round_trips_through_its_exit_code() {
        let all_interactive =
            [Interactive::Untouched, Interactive::Disabled, Interactive::NotDisabled, Interactive::MarkerNotWritten];
        let all_errors = [
            None,
            Some(StepError::Arguments),
            Some(StepError::NotVerified),
            Some(StepError::NoMsiexec),
            Some(StepError::NotOpenVpn),
            Some(StepError::NotStaged),
            Some(StepError::NotReadable),
        ];
        for msi in [None, Some(0), Some(3010), Some(1602), Some(1603)] {
            for interactive in all_interactive {
                for error in all_errors {
                    let r = StepResult { msi, interactive, error };
                    let code = r.code();
                    assert_ne!(code & (1 << 29), 0);
                    assert!(i32::try_from(code).is_ok(), "an exit code a process can return");
                    assert_eq!(StepResult::from_code(code), Some(r));
                }
            }
        }
        // Not the step's: success, a crash, UAC's ERROR_CANCELLED, msiexec's own codes, stray bits.
        for code in
            [0, 1, 1223, 1602, 3010, 0xC000_0005, 0x2000_0001, 0x2008_0000, 0x6000_0000, 0x2080_0000, 0x2070_0000]
        {
            assert_eq!(StepResult::from_code(code), None, "{code:#x}");
        }
    }

    #[test]
    fn the_texts_after_the_step() {
        let ok = |msi, interactive| StepResult { msi, interactive, error: None };
        assert_eq!(oi::after_step(&ok(Some(0), Interactive::Disabled)), Ok(vec![oi::installed()]));
        assert_eq!(
            oi::after_step(&ok(Some(3010), Interactive::Untouched)),
            Ok(vec![oi::installed(), oi::restart_needed()])
        );
        // A failed disable is a line, and the install still counts as done.
        assert_eq!(
            oi::after_step(&ok(Some(0), Interactive::NotDisabled)),
            Ok(vec![oi::interactive_not_disabled(), oi::installed()])
        );
        assert_eq!(oi::after_step(&ok(None, Interactive::MarkerNotWritten)), Ok(vec![oi::marker_not_written()]));
        assert_eq!(oi::after_step(&ok(None, Interactive::Disabled)), Ok(vec![]));
        assert_eq!(oi::after_step(&ok(Some(1602), Interactive::Untouched)), Err(oi::cancelled()));
        assert_eq!(oi::after_step(&ok(Some(1603), Interactive::Untouched)), Err(oi::installer_failed(1603)));
        let failed = |e| StepResult { msi: None, interactive: Interactive::Untouched, error: Some(e) };
        assert_eq!(oi::after_step(&failed(StepError::NotVerified)), Err(oi::not_signed_by("OpenVPN Inc.")));
        assert_eq!(oi::after_step(&failed(StepError::NoMsiexec)), Err(oi::installer_not_started()));
        assert_eq!(oi::after_step(&failed(StepError::NotStaged)), Err(oi::installer_not_started()));
        assert_eq!(oi::after_step(&failed(StepError::NotOpenVpn)), Err(oi::not_openvpn(pins::OPENVPN_VERSION)));
        // 2.1.0: a source the step's account could not open was reported as "not signed by OpenVPN Inc.".
        assert_eq!(oi::after_step(&failed(StepError::NotReadable)), Err(oi::not_readable_elevated()));
        assert_ne!(oi::not_readable_elevated(), oi::not_signed_by("OpenVPN Inc."));
        let hu = l10n::with_language(AppLanguage::Hu, oi::not_readable_elevated);
        assert_eq!(hu, "A rendszergazdai fiók nem tudta olvasni a letöltött OpenVPN-telepítőt.");
        let en = l10n::with_language(AppLanguage::En, || oi::not_openvpn("2.7.8"));
        assert_eq!(en, "The OpenVPN installer is not OpenVPN Community 2.7.8 or newer.");
        let hu = l10n::with_language(AppLanguage::Hu, || oi::not_openvpn("2.7.8"));
        assert_eq!(hu, "Az OpenVPN telepítője nem OpenVPN Community (legalább 2.7.8).");
    }

    /// Security review L-2: the elevated step reads what the MSI database says it installs (its `Property`
    /// table), not the file name. The values of OpenVPN's own MSIs, read on the Windows test machine (2026-10-25,
    /// `WindowsInstaller.Installer`, read-only): 2.7.8-I001 amd64 / arm64, and 2.6.15-I001 amd64.
    #[test]
    fn the_msi_database_must_name_openvpn_community_at_or_above_the_pin() {
        let props = |name: &str, version: &str, code: &str, maker: &str| -> Vec<(String, String)> {
            [("ProductName", name), ("ProductVersion", version), ("UpgradeCode", code), ("Manufacturer", maker)]
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .chain([("ProductLanguage".to_string(), "1033".to_string())])
                .collect()
        };
        const AMD64: &str = "{461BDF86-D389-4471-BF36-99806B64C127}";
        const ARM64: &str = "{1E8C4DDC-9E93-4AE2-9495-DF86821EAA3A}";
        const X86: &str = "{1195A47B-A37A-4055-9D34-B7A691F7E97B}";
        const INC: &str = "OpenVPN, Inc.";
        let ok = |p: &[(String, String)], arch| oi::msi_properties_ok(p, arch, "2.7.8");
        assert_eq!(ok(&props("OpenVPN", "2.7.801", AMD64, INC), "x86_64"), Some(Version(2, 7, 8)));
        assert_eq!(ok(&props("OpenVPN", "2.7.801", ARM64, INC), "aarch64"), Some(Version(2, 7, 8)));
        assert_eq!(ok(&props("OpenVPN", "2.7.1002", AMD64, INC), "x86_64"), Some(Version(2, 7, 10)));
        assert_eq!(ok(&props("OpenVPN 2.8.0-I001 amd64", "2.8.001", AMD64, INC), "x86_64"), Some(Version(2, 8, 0)));
        assert_eq!(ok(&props("OpenVPN", "2.7.801", &AMD64.to_lowercase(), INC), "x86_64"), Some(Version(2, 7, 8)));
        // An older OpenVPN (2.6.15, renamed to a newer file name), another machine's or another product's MSI.
        assert_eq!(ok(&props("OpenVPN 2.6.15-I001 amd64", "2.6.1501", AMD64, INC), "x86_64"), None);
        assert_eq!(ok(&props("OpenVPN", "2.7.701", AMD64, INC), "x86_64"), None);
        assert_eq!(ok(&props("OpenVPN", "2.7.801", ARM64, INC), "x86_64"), None);
        assert_eq!(ok(&props("OpenVPN", "2.7.801", X86, INC), "x86_64"), None);
        assert_eq!(ok(&props("OpenVPN", "2.7.801", AMD64, INC), "x86"), None);
        assert_eq!(ok(&props("OpenVPN Connect", "3.7.801", AMD64, INC), "x86_64"), None);
        assert_eq!(ok(&props("OpenVPNx", "2.7.801", AMD64, INC), "x86_64"), None);
        assert_eq!(ok(&props("OpenVPN", "2.7.801", AMD64, "Someone else"), "x86_64"), None);
        assert_eq!(ok(&props("OpenVPN", "2.7.801", "{00000000-0000-0000-0000-000000000000}", INC), "x86_64"), None);
        assert_eq!(ok(&props("OpenVPN", "x", AMD64, INC), "x86_64"), None);
        // A property missing or given twice.
        let mut p = props("OpenVPN", "2.7.801", AMD64, INC);
        p.retain(|(k, _)| k != "UpgradeCode");
        assert_eq!(ok(&p, "x86_64"), None);
        let mut p = props("OpenVPN", "2.7.801", AMD64, INC);
        p.push(("ProductVersion".into(), "9.9.901".into()));
        assert_eq!(ok(&p, "x86_64"), None);
    }

    // Captured on the Windows 11 test machine (winget 1.29.380, OpenVPN 2.7.7 installed by winget, 2026-10-24).
    /// `winget list --id OpenVPNTechnologies.OpenVPN --exact --source winget --upgrade-available …`: no upgrade.
    const NO_UPGRADE: &str = "No installed package found matching input criteria.\r\n";
    /// `winget list --source winget --upgrade-available …` (every package with an upgrade; localized names).
    const ALL_UPGRADES: &str = "Name                                      Id                               Version        Available\r\n\
--------------------------------------------------------------------------------------------------------\r\n\
Git                                       Git.Git                          2.55.0.5       2.56.0.3\r\n\
Total Commander 64-bit (Remove or Repair) Ghisler.TotalCommander           11.56          11.58\r\n\
Windows terminál                          Microsoft.WindowsTerminal        1.24.12741.0   1.25.2733.0\r\n\
6 upgrades available.\r\n";
    /// `winget list --id OpenVPNTechnologies.OpenVPN --exact --source winget` (the installed row; winget lists the
    /// MSI's ProductVersion).
    const INSTALLED_ROW: &str = "Name                     Id                          Version\r\n\
------------------------------------------------------------\r\n\
OpenVPN 2.7.7-I001 amd64 OpenVPNTechnologies.OpenVPN 2.7.701\r\n";

    #[test]
    fn the_winget_update_check_is_read_only_and_fixed() {
        let args = oi::winget_check_args();
        assert_eq!(
            args.join(" "),
            "list --id OpenVPNTechnologies.OpenVPN --exact --source winget --upgrade-available \
             --disable-interactivity --accept-source-agreements"
        );
        assert!(!args.iter().any(|a| a == "install" || a == "upgrade"));
        assert_eq!(oi::WINGET_CHECK_SECS, 30);
        // The install path names no version: winget's newest (decision 4 as amended 2026-10-24).
        for update in [false, true] {
            assert!(!oi::winget_args(update, FEATURES).iter().any(|a| a == "--version" || a == "-v"));
        }
    }

    #[test]
    fn winget_versions_map_to_openvpn_versions() {
        assert_eq!(oi::openvpn_version_of_winget("2.7.701"), Some(Version(2, 7, 7)));
        assert_eq!(oi::openvpn_version_of_winget("2.7.801"), Some(Version(2, 7, 8)));
        assert_eq!(oi::openvpn_version_of_winget("2.6.2302"), Some(Version(2, 6, 23)));
        assert_eq!(oi::openvpn_version_of_winget("2.7.017"), Some(Version(2, 7, 0)));
        assert_eq!(oi::openvpn_version_of_winget("2.7.8"), Some(Version(2, 7, 8)));
        assert_eq!(oi::openvpn_version_of_winget("2.6.10"), Some(Version(2, 6, 10)));
        for bad in ["2.56.0.3", "Unknown", "< 2.7.7", "", "2.7"] {
            assert_eq!(oi::openvpn_version_of_winget(bad), None, "{bad}");
        }
    }

    #[test]
    fn winget_update_answers_are_parsed_defensively() {
        let installed = Version(2, 7, 7);
        // Captured: no upgrade (exit 0, one message line, no table).
        assert_eq!(oi::parse_winget_check(0, NO_UPGRADE, installed), Upgrade::None);
        assert_eq!(oi::parse_winget_check(oi::WINGET_NO_APPLICATIONS_FOUND, NO_UPGRADE, installed), Upgrade::None);
        // Captured table, OpenVPN's row added in the same layout: the available version, mapped.
        let with_openvpn = ALL_UPGRADES.replace(
            "6 upgrades",
            "OpenVPN 2.7.7-I001 amd64                  OpenVPNTechnologies.OpenVPN      2.7.701        2.7.801\r\n6 upgrades",
        );
        assert_eq!(oi::parse_winget_check(0, &with_openvpn, installed), winget("2.7.8", Version(2, 7, 8)));
        // With a Source column (no --source) and LF line ends.
        let with_source =
            "Name Id Version Available Source\n----\nOpenVPN OpenVPNTechnologies.OpenVPN 2.7.701 2.8.101 winget\n";
        assert_eq!(oi::parse_winget_check(0, with_source, installed), winget("2.8.1", Version(2, 8, 1)));
        // A localized table (German winget wording; constructed: the test machine's winget prints English).
        let german = "Name                     ID                          Version Verfügbar\r\n\
-----------------------------------------------------------------------\r\n\
OpenVPN 2.7.7-I001 amd64 OpenVPNTechnologies.OpenVPN 2.7.701 2.7.901\r\n\
1 Aktualisierungen verfügbar.\r\n";
        assert_eq!(oi::parse_winget_check(0, german, installed), winget("2.7.9", Version(2, 7, 9)));
        let german_none = "Es wurde kein installiertes Paket gefunden, das den Eingabekriterien entspricht.\r\n";
        assert_eq!(oi::parse_winget_check(0, german_none, installed), Upgrade::None);
        // A rebuilt installer of the same OpenVPN: winget's own version is shown.
        let rebuilt = INSTALLED_ROW.replace("2.7.701", "2.7.701 2.7.702");
        assert_eq!(oi::parse_winget_check(0, &rebuilt, installed), winget("2.7.702", Version(2, 7, 7)));
        // Unknown: a table without OpenVPN's row (truncated or another package's), OpenVPN's row without an
        // available version, an unreadable version, any other exit code (captured: 0x8A15002B, no upgrade
        // applicable from `winget upgrade`; 2: bad arguments).
        assert_eq!(oi::parse_winget_check(0, ALL_UPGRADES, installed), Upgrade::Unknown);
        assert_eq!(oi::parse_winget_check(0, INSTALLED_ROW, installed), Upgrade::Unknown);
        let truncated = INSTALLED_ROW.replace("OpenVPNTechnologies.OpenVPN", "OpenVPNTechnologies.Op…");
        assert_eq!(oi::parse_winget_check(0, &truncated, installed), Upgrade::Unknown);
        let garbled = INSTALLED_ROW.replace("2.7.701", "2.7.701 Unknown");
        assert_eq!(oi::parse_winget_check(0, &garbled, installed), Upgrade::Unknown);
        for code in [0x8A15_002B, 2, 1, u32::MAX] {
            assert_eq!(oi::parse_winget_check(code, NO_UPGRADE, installed), Upgrade::Unknown, "{code:#x}");
        }
        assert_eq!(oi::parse_winget_check(0, "", installed), Upgrade::None);
    }

    fn winget(shown: &str, version: Version) -> Upgrade {
        Upgrade::Available { shown: shown.into(), version, via: Via::Winget }
    }

    fn pin(version: Version) -> Upgrade {
        Upgrade::Available { shown: version.to_string(), version, via: Via::Msi }
    }

    #[test]
    fn the_newest_of_winget_and_the_pin_is_offered() {
        let pinned = "2.7.8";
        let (v277, v278, v279) = (Version(2, 7, 7), Version(2, 7, 8), Version(2, 7, 9));
        // winget has nothing newer (the CP2 machine: winget's newest 2.7.7 installed), or no answer: the newer pin.
        for w in [Upgrade::None, Upgrade::Unknown] {
            assert_eq!(oi::choose_update(&w, v277, pinned), pin(v278), "{w:?}");
        }
        // Without winget (`None`) the same.
        assert_eq!(oi::choose_update(&Upgrade::None, Version(2, 6, 23), pinned), pin(v278));
        // winget offers the pin's version: winget.
        assert_eq!(oi::choose_update(&winget("2.7.8", v278), v277, pinned), winget("2.7.8", v278));
        // winget offers more than the pin: winget.
        assert_eq!(oi::choose_update(&winget("2.7.9", v279), v277, pinned), winget("2.7.9", v279));
        assert_eq!(oi::choose_update(&winget("2.7.9", v279), v278, pinned), winget("2.7.9", v279));
        // winget offers less than the pin (or a rebuilt installer of the installed version): the pin.
        assert_eq!(oi::choose_update(&winget("2.7.7", v277), Version(2, 7, 6), pinned), pin(v278));
        assert_eq!(oi::choose_update(&winget("2.7.702", v277), v277, pinned), pin(v278));
        // Installed at or above the pin: winget's answer stands (never the pin: no downgrade).
        assert_eq!(oi::choose_update(&Upgrade::None, v278, pinned), Upgrade::None);
        assert_eq!(oi::choose_update(&Upgrade::None, v279, pinned), Upgrade::None);
        assert_eq!(oi::choose_update(&Upgrade::Unknown, v279, pinned), Upgrade::Unknown);
        assert_eq!(oi::choose_update(&winget("2.7.702", v278), v278, pinned), winget("2.7.702", v278));
        assert_eq!(oi::choose_update(&Upgrade::None, v277, "bad"), Upgrade::None);
    }

    #[test]
    fn update_starts_where_the_offer_comes_from() {
        let v278 = Version(2, 7, 8);
        assert_eq!(oi::update_first(&pin(v278), true), First::Msi);
        assert_eq!(oi::update_first(&pin(v278), false), First::Msi);
        assert_eq!(oi::update_first(&winget("2.7.9", Version(2, 7, 9)), true), First::Winget { update: true });
        // No offer known when the action runs: winget's upgrade when winget exists (Task 17), else the pinned MSI.
        for u in [Upgrade::None, Upgrade::Unknown] {
            assert_eq!(oi::update_first(&u, true), First::Winget { update: true });
            assert_eq!(oi::update_first(&u, false), First::Msi);
        }
    }

    #[test]
    fn the_pinned_msi_never_downgrades() {
        assert!(oi::msi_fallback_allowed(None, "2.7.8"));
        assert!(oi::msi_fallback_allowed(Some("2.7.7"), "2.7.8"));
        assert!(oi::msi_fallback_allowed(Some("2.7.8"), "2.7.8"));
        assert!(!oi::msi_fallback_allowed(Some("2.7.9"), "2.7.8"));
        assert!(!oi::msi_fallback_allowed(Some("x"), "2.7.8"), "an unreadable version: fail closed");
    }

    #[test]
    fn winget_progress_is_not_output() {
        assert_eq!(oi::winget_line("   - \\ | / "), None);
        assert_eq!(oi::winget_line(""), None);
        assert_eq!(oi::winget_line("  ██████▒▒▒▒  "), None);
        assert_eq!(
            oi::winget_line("\r - \rFound OpenVPN [OpenVPNTechnologies.OpenVPN] Version 2.7.8"),
            Some("Found OpenVPN [OpenVPNTechnologies.OpenVPN] Version 2.7.8".into())
        );
        assert_eq!(oi::winget_line("Successfully installed\r"), Some("Successfully installed".into()));
    }

    #[test]
    fn the_install_texts_are_translated() {
        l10n::with_language(AppLanguage::Hu, || {
            assert_eq!(oi::installing("2.7.8"), "Az OpenVPN Community 2.7.8 telepítése…");
            assert_eq!(
                oi::winget_failed(1603),
                "A winget nem tudta telepíteni az OpenVPN-t (1603); a hivatalos telepítővel próbálom."
            );
            assert_eq!(oi::installed(), "Az OpenVPN Community telepítve.");
            assert_eq!(oi::cancelled(), "Megszakítva");
            assert_eq!(oi::not_signed_by("OpenVPN Inc."), "Az OpenVPN telepítőjét nem a(z) OpenVPN Inc. írta alá.");
        });
        let texts: [fn() -> String; 10] = [
            oi::installing_with_winget,
            oi::winget_missed_drivers,
            oi::add_drivers_in_settings,
            || oi::download_failed("x"),
            || oi::installer_failed(1),
            oi::installer_not_started,
            oi::only_installed_winvpn,
            oi::restart_needed,
            oi::interactive_not_disabled,
            oi::marker_not_written,
        ];
        for text in texts {
            let (en, hu) = (l10n::with_language(AppLanguage::En, text), l10n::with_language(AppLanguage::Hu, text));
            assert!(!hu.is_empty() && hu != en, "{en}");
        }
    }

    // MARK: - The newest official MSI (fix4)

    /// OpenVPN's download page as captured on 2026-10-24 (the parts around its MSI links; 2.7.8-I002).
    const PAGE: &str = include_str!("fixtures/openvpn-community-2026-10-24-excerpt.html");

    #[test]
    fn the_official_page_names_the_newest_msi_per_architecture() {
        let amd = oi::parse_official_page(PAGE, "x86_64").unwrap();
        assert_eq!(
            amd,
            oi::OfficialMsi {
                version: Version(2, 7, 8),
                installer: 2,
                url: "https://swupdate.openvpn.org/community/releases/OpenVPN-2.7.8-I002-amd64.msi".into()
            }
        );
        let arm = oi::parse_official_page(PAGE, "aarch64").unwrap();
        assert_eq!(arm.url, "https://swupdate.openvpn.org/community/releases/OpenVPN-2.7.8-I002-arm64.msi");
        assert_eq!(oi::parse_official_page(PAGE, "x86"), None);
        // The highest version, then the highest installer build; `.asc`, other hosts and odd names do not count.
        let page = r#"href="https://swupdate.openvpn.org/community/releases/OpenVPN-2.7.9-I001-amd64.msi.asc"
            href="https://evil.example/community/releases/OpenVPN-9.9.9-I001-amd64.msi"
            href="https://swupdate.openvpn.org/community/releases/OpenVPN-2.7.10-I001-amd64.msi"
            href="https://swupdate.openvpn.org/community/releases/OpenVPN-2.7.10-I003-amd64.msi"
            href="https://swupdate.openvpn.org/community/releases/OpenVPN-2.7.10-I002-amd64.msi"
            href="https://swupdate.openvpn.org/community/releases/OpenVPN-3.0-I001-amd64.msi"
            href="https://swupdate.openvpn.org/community/releases/OpenVPN-2.8.0-I0001x-amd64.msi"
            href="https://swupdate.openvpn.org/community/releases/OpenVPN-2.9.0-I00001-amd64.msi"
            href="https://swupdate.openvpn.org/community/releases/../OpenVPN-2.9.9-I001-amd64.msi"
            "#;
        let m = oi::parse_official_page(page, "x86_64").unwrap();
        assert_eq!((m.version, m.installer), (Version(2, 7, 10), 3));
        assert_eq!(m.url, "https://swupdate.openvpn.org/community/releases/OpenVPN-2.7.10-I003-amd64.msi");
        assert_eq!(oi::parse_official_page("", "x86_64"), None);
        assert_eq!(oi::parse_official_page("<html>maintenance</html>", "x86_64"), None);
    }

    #[test]
    fn the_newest_official_msi_is_used_only_for_a_newer_openvpn() {
        let pinned = oi::pinned_official("x86_64").unwrap();
        assert_eq!((pinned.version, pinned.installer), (Version::parse(pins::OPENVPN_VERSION).unwrap(), 1));
        assert_eq!(pinned.url, pins::OPENVPN_MSI_X64_URL);
        assert!(oi::pinned_official("aarch64").is_some() && oi::pinned_official("x86").is_none());
        let msi = |v: Version, i: u16| oi::OfficialMsi { version: v, installer: i, url: format!("https://x/{i}") };
        let newer = msi(Version(2, 7, 9), 1);
        assert_eq!(oi::pick_msi(Some(newer.clone()), pinned.clone()), oi::MsiPick::Official(newer));
        // The pin's version again (a rebuilt installer), an older one, nothing found: the pinned MSI.
        for found in [Some(msi(pinned.version, 2)), Some(msi(Version(2, 6, 23), 9)), None] {
            assert_eq!(oi::pick_msi(found, pinned.clone()), oi::MsiPick::Pinned(pinned.clone()));
        }
    }

    #[test]
    fn the_elevated_step_takes_an_official_msi_only_by_its_official_name() {
        // A downloads folder of this OS (`C:\…` is a path only on Windows).
        let ok = |name: &str| {
            let p = if cfg!(windows) { format!(r"C:\Users\bob\downloads\{name}") } else { format!("/d/{name}") };
            oi::official_msi_name_ok(Path::new(&p), "x86_64", "2.7.8")
        };
        assert!(ok("OpenVPN-2.7.9-I001-amd64.msi"));
        assert!(ok("OpenVPN-2.7.8-I002-amd64.msi"), "the pin's version, another build");
        assert!(!ok("OpenVPN-2.7.7-I001-amd64.msi"), "older than the pin");
        assert!(!ok("OpenVPN-2.7.9-I001-arm64.msi"), "another machine");
        assert!(!ok("evil.msi"));
        assert!(!ok("OpenVPN-2.7.9-I001-amd64.msi.exe"));
        assert_eq!(oi::parse_msi_name("OpenVPN-2.7.8-I001-amd64.msi", "x86_64"), Some((Version(2, 7, 8), 1)));
        assert_eq!(oi::parse_msi_name("OpenVPN-2.7.8-I001-amd64.msi", "aarch64"), None);
        // The step's arguments round-trip; the mode names it.
        let path = r"C:\d\OpenVPN-2.7.9-I001-amd64.msi";
        let step = Step::OfficialMsi { path: path.into() };
        let line = oi::step_parameters(&step).unwrap();
        assert!(line.contains(" msi-official \""), "{line}");
        let args: Vec<String> = [oi::STEP_ARG, "msi-official", path].iter().map(|s| s.to_string()).collect();
        assert_eq!(oi::parse_step(&args), Some(step));
        let bad: Vec<String> = [oi::STEP_ARG, "msi-official", "rel.msi"].iter().map(|s| s.to_string()).collect();
        assert_eq!(oi::parse_step(&bad), None);
    }
}

mod net {
    use macvpn_core::netaddr::IpPrefix;
    use macvpn_platform_win::pure::net::{Adapter, connected, is_wifi, physical_gateway};

    fn adapter(name: &str, if_type: u32, description: &str, gw: Option<&str>, metric: u32) -> Adapter {
        Adapter {
            alias: name.into(),
            if_type,
            description: description.into(),
            up: true,
            gateway: gw.map(|g| g.parse().unwrap()),
            route_metric: metric,
            prefixes: vec![],
            luid: 1,
            guid: [0; 16],
        }
    }

    fn prefix(text: &str) -> IpPrefix {
        IpPrefix::parse(text).unwrap()
    }

    #[test]
    fn the_physical_gateway_skips_vpn_adapters() {
        let list = vec![
            adapter("WinVPN-1a2b3c4d", 53, "WireGuard Tunnel", Some("0.0.0.0"), 0),
            adapter("OpenVPN TAP", 6, "TAP-Windows Adapter V9", Some("10.8.0.1"), 1),
            adapter("OpenVPN DCO", 53, "OpenVPN Data Channel Offload", Some("10.8.0.1"), 1),
            adapter("Wi-Fi", 71, "Intel(R) Wi-Fi 6E AX211 160MHz", Some("192.168.1.1"), 25),
            adapter("Ethernet", 6, "Realtek USB GbE Family Controller", Some("192.168.2.1"), 35),
        ];
        let a = physical_gateway(&list).unwrap();
        assert_eq!(a.alias, "Wi-Fi");
        assert!(is_wifi(a));
    }

    #[test]
    fn no_physical_route_is_no_gateway() {
        let list = vec![adapter("WinVPN-1a2b3c4d", 53, "WireGuard Tunnel", Some("0.0.0.0"), 0)];
        assert!(physical_gateway(&list).is_none());
    }

    #[test]
    fn a_down_adapter_or_one_without_a_real_next_hop_is_no_gateway() {
        let mut down = adapter("Ethernet", 6, "Intel(R) Ethernet", Some("192.168.1.1"), 5);
        down.up = false;
        let on_link = adapter("Ethernet 2", 6, "Intel(R) Ethernet", Some("::"), 5);
        let none = adapter("Ethernet 3", 6, "Intel(R) Ethernet", None, 5);
        let ppp = adapter("Dial-up", 23, "WAN Miniport (PPP)", Some("10.0.0.1"), 1);
        let wintun = adapter("Other VPN", 6, "Wintun Userspace Tunnel", Some("10.9.0.1"), 1);
        assert!(physical_gateway(&[down, on_link, none, ppp, wintun]).is_none());
    }

    #[test]
    fn the_connected_subnets_are_the_physical_adapters_without_link_local() {
        let mut wifi = adapter("Wi-Fi", 71, "Intel(R) Wi-Fi", Some("192.168.1.1"), 25);
        wifi.prefixes = vec![prefix("192.168.1.0/24"), prefix("169.254.0.0/16"), prefix("fe80::/64")];
        let mut eth = adapter("Ethernet", 6, "Realtek", None, 0);
        eth.prefixes = vec![prefix("10.20.30.0/24"), prefix("2001:db8::/64"), prefix("192.168.1.0/24")];
        let mut tap = adapter("OpenVPN TAP", 6, "TAP-Windows Adapter V9", Some("10.8.0.1"), 1);
        tap.prefixes = vec![prefix("10.8.0.0/24")];
        let mut lo = adapter("Loopback", 24, "Software Loopback Interface 1", None, 0);
        lo.prefixes = vec![prefix("127.0.0.0/8"), prefix("::1/128")];
        assert_eq!(
            connected(&[wifi, eth, tap, lo]),
            vec![prefix("192.168.1.0/24"), prefix("10.20.30.0/24"), prefix("2001:db8::/64")]
        );
    }
}

/// "Clear Log…" through the WinVPN Service: exit 0 is done; an older service (2.0.x) does not know `clear-log` and
/// answers its usage error (exit 2): "update WinVPN", never the raw usage text; any other failure is its message.
#[test]
fn a_clear_log_answer_of_an_older_service_says_to_update() {
    use macvpn_platform_win::pure::engine::clear_log_answer;
    l10n::with_language(AppLanguage::En, || {
        assert_eq!(clear_log_answer(0, ""), Ok(()));
        let old = clear_log_answer(2, "Usage: up|down <openvpn|wireguard> <id> …").unwrap_err();
        assert_eq!(old, texts::service_cannot_clear_log());
        assert!(old.contains("WinVPN") && !old.contains("Usage"), "{old}");
        assert_eq!(clear_log_answer(1, "Invalid ID"), Err("Invalid ID".to_string()));
        assert_eq!(clear_log_answer(1, ""), Err("mvpn error (exit code: 1)".to_string()));
    });
    l10n::with_language(AppLanguage::Hu, || {
        assert!(clear_log_answer(2, "Használat: …").unwrap_err().starts_with("A WinVPN Service"));
    });
}
