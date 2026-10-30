//! The setup report's decisions: which kinds can start, and whether anything is left to set up.

use macvpn_core::l10n::{self, AppLanguage};
use macvpn_core::models::VPNKind;
use macvpn_platform_api::setup::{EngineReport, EngineRow};
use macvpn_platform_api::{MissingEngine, SetupReport};

/// A platform without a VPN engine (WinVPN 2a): no kind can start, the native ones included.
#[test]
fn without_an_engine_no_kind_is_available() {
    let report = SetupReport { engine_missing: Some("Later.".into()), ..SetupReport::unknown() };
    assert!(VPNKind::ALL.iter().all(|k| !report.is_available(*k)));
}

/// Without the engine (WinVPN 2.0: the WinVPN Service the MSI installs is missing or unusable) the setup is not
/// complete: System Status opens by itself at launch with the service's text and its popover tile has a "!" mark
/// (both read `is_complete`), even with a green RAS row.
#[test]
fn without_an_engine_the_setup_is_incomplete() {
    let report = SetupReport { engine_missing: Some("No service.".into()), ..SetupReport::unknown() };
    assert!(!report.is_complete());
    let ras = EngineRow { ok: true, usable: true, detail: String::new(), action: None };
    let with_ras = SetupReport { ras: Some(ras), ..report };
    assert!(!with_ras.is_complete());
    // The native kinds still connect (G-4): only the service's kinds are refused.
    assert!(with_ras.is_available(VPNKind::L2tp) && with_ras.is_available(VPNKind::Sstp));
    assert_eq!(with_ras.start_refusal(Some(VPNKind::Strongswan)), None);
    assert_eq!(with_ras.start_refusal(None), None);
    assert!(!with_ras.is_available(VPNKind::Openvpn) && !with_ras.is_available(VPNKind::Wireguard));
}

/// The report of a platform with an engine (macOS) decides as before: the native kinds need nothing, the others
/// need the package manager, the root layer and their tools.
#[test]
fn with_an_engine_the_report_decides_as_before() {
    let unknown = SetupReport::unknown();
    assert_eq!(unknown.engine_missing, None);
    assert!(!unknown.is_complete());
    assert!(unknown.is_available(VPNKind::L2tp) && unknown.is_available(VPNKind::Cisco));
    assert!(!unknown.is_available(VPNKind::Openvpn));
}

fn row(ok: bool) -> EngineRow {
    EngineRow { ok, usable: ok, detail: String::new(), action: None }
}

/// WinVPN 2b: the service's engine rows decide per kind; the native kinds are "later".
#[test]
fn an_engine_report_decides_availability_per_kind() {
    let r = SetupReport {
        engine: Some(EngineReport { service: row(true), openvpn: row(false), wireguard: row(true) }),
        later_kinds: vec![
            (VPNKind::L2tp, "later".into()),
            (VPNKind::Cisco, "later".into()),
            (VPNKind::Strongswan, "later".into()),
            (VPNKind::Sstp, "later".into()),
        ],
        ..SetupReport::unknown()
    };
    assert!(r.is_available(VPNKind::Wireguard));
    assert!(!r.is_available(VPNKind::Openvpn));
    assert!(!r.is_available(VPNKind::L2tp) && !r.is_available(VPNKind::Sstp));
    assert_eq!(r.later_reason(VPNKind::Cisco), Some("later"));
    assert_eq!(r.later_reason(VPNKind::Wireguard), None);
    // OpenVPN missing is something the user can install: not complete.
    assert!(!r.is_complete());
    let all = SetupReport {
        engine: Some(EngineReport { service: row(true), openvpn: row(true), wireguard: row(true) }),
        ..r.clone()
    };
    assert!(all.is_complete());
    // A missing driver: red with "repair", but OpenVPN still usable.
    let repair = EngineRow { ok: false, usable: true, detail: String::new(), action: Some("repair") };
    let r2 = SetupReport {
        engine: Some(EngineReport { service: row(true), openvpn: repair, wireguard: row(true) }),
        ..r.clone()
    };
    assert!(r2.is_available(VPNKind::Openvpn) && !r2.is_complete());
    // A service that cannot be used makes neither kind available.
    let down = SetupReport {
        engine: Some(EngineReport {
            service: EngineRow { ok: false, usable: false, detail: String::new(), action: None },
            openvpn: row(true),
            wireguard: row(true),
        }),
        ..r.clone()
    };
    assert!(!down.is_available(VPNKind::Openvpn) && !down.is_available(VPNKind::Wireguard));
    // The engine-missing state still wins over the rows.
    let missing = SetupReport { engine_missing: Some("Missing.".into()), ..all };
    assert!(!missing.is_available(VPNKind::Wireguard) && !missing.is_complete());
}

/// WinVPN 2.0: OpenVPN Community is one optional engine among several. A row whose only problem is that it is not
/// installed (red, "Install") leaves the report complete: System Status does not open at launch and its tile has no
/// "!" mark (the row stays red with "Install" in the window, and OpenVPN stays unavailable). An installed OpenVPN that
/// needs a repair or an update, or any other red row, still makes it incomplete.
#[test]
fn a_missing_openvpn_alone_leaves_the_report_complete() {
    let with = |openvpn: EngineRow, wireguard: EngineRow, service: EngineRow| SetupReport {
        engine: Some(EngineReport { service, openvpn, wireguard }),
        ..SetupReport::unknown()
    };
    let not_installed = EngineRow { ok: false, usable: false, detail: String::new(), action: Some("install") };
    let r = with(not_installed.clone(), row(true), row(true));
    assert!(r.is_complete());
    assert!(!r.is_available(VPNKind::Openvpn) && r.is_available(VPNKind::Wireguard));
    assert_eq!(
        r.missing_engine(VPNKind::Openvpn),
        Some(MissingEngine { name: "OpenVPN Community".into(), installed: false })
    );
    // Installed but refused or incomplete: "Repair" / "Update" keep the report incomplete.
    for action in ["repair", "update"] {
        for usable in [false, true] {
            let broken = EngineRow { ok: false, usable, detail: String::new(), action: Some(action) };
            assert!(!with(broken, row(true), row(true)).is_complete(), "{action} {usable}");
        }
    }
    // A red row without an action, a red WireGuard row or an unusable service row: incomplete, whatever OpenVPN.
    assert!(!with(row(false), row(true), row(true)).is_complete());
    assert!(!with(not_installed.clone(), row(false), row(true)).is_complete());
    let down = EngineRow { ok: false, usable: false, detail: String::new(), action: Some("install") };
    assert!(!with(row(true), row(true), down.clone()).is_complete());
    assert!(!with(not_installed.clone(), row(true), down).is_complete());
    // A red RAS row (WinVPN 2c) still counts.
    let ras_down = SetupReport { ras: Some(row(false)), ..with(not_installed, row(true), row(true)) };
    assert!(!ras_down.is_complete());
}

#[test]
fn macos_reports_are_unchanged() {
    let r = SetupReport::unknown();
    assert_eq!(r.engine, None);
    assert!(r.later_kinds.is_empty());
    assert_eq!(r.later_reason(VPNKind::L2tp), None);
}

fn mac_ready() -> SetupReport {
    SetupReport {
        package_manager: Some("/opt/homebrew".into()),
        required_tools: &[
            (VPNKind::Openvpn, &["openvpn"]),
            (VPNKind::Wireguard, &["wg", "wg-quick", "wireguard-go", "bash"]),
            (VPNKind::Strongswan, &["swanctl", "charon"]),
            (VPNKind::Sstp, &["sstpc"]),
        ],
        installed_root_version: Some("8".into()),
        bundled_root_version: Some("8".into()),
        sudo_works: true,
        ..SetupReport::default()
    }
}

fn engine(name: &str, installed: bool) -> Option<MissingEngine> {
    Some(MissingEngine { name: name.into(), installed })
}

/// macOS names the Homebrew package a kind lacks (bash alone when only bash is missing: wg-quick needs it).
#[test]
fn macos_names_the_missing_package() {
    let r = SetupReport { missing_tools: vec!["openvpn".into(), "bash".into()], ..mac_ready() };
    assert_eq!(r.missing_engine(VPNKind::Openvpn), engine("OpenVPN", false));
    assert_eq!(r.missing_engine(VPNKind::Wireguard), engine("bash", false));
    assert_eq!(r.missing_engine(VPNKind::Strongswan), None);
    assert_eq!(r.missing_engine(VPNKind::L2tp), None);
    let r = SetupReport { missing_tools: vec!["wg".into(), "bash".into()], ..mac_ready() };
    assert_eq!(r.missing_engine(VPNKind::Wireguard), engine("WireGuard tools", false));
    let r = SetupReport { missing_tools: vec!["charon".into()], ..mac_ready() };
    assert_eq!(r.missing_engine(VPNKind::Strongswan), engine("strongSwan", false));
}

/// Homebrew and the root layer come before the tools; the native kinds never miss an engine.
#[test]
fn macos_homebrew_and_the_root_layer_come_first() {
    l10n::with_language(AppLanguage::En, || {
        let no_brew = SetupReport { package_manager: None, ..mac_ready() };
        assert_eq!(no_brew.missing_engine(VPNKind::Sstp), engine("Homebrew", false));
        let old_root = SetupReport { installed_root_version: Some("7".into()), ..mac_ready() };
        assert_eq!(old_root.missing_engine(VPNKind::Openvpn), engine("Permissions (root scripts + sudoers)", true));
        assert_eq!(old_root.missing_engine(VPNKind::Cisco), None);
        let no_root = SetupReport { installed_root_version: None, ..mac_ready() };
        assert!(!no_root.missing_engine(VPNKind::Openvpn).unwrap().installed);
    });
}

/// Windows: the engine rows decide; a row whose action is "install" is not installed, any other is not ready.
#[test]
fn windows_engine_rows_decide() {
    let row =
        |usable: bool, action: Option<&'static str>| EngineRow { ok: usable, usable, detail: String::new(), action };
    let r = SetupReport {
        engine: Some(EngineReport {
            service: row(true, None),
            openvpn: row(false, Some("install")),
            wireguard: row(true, None),
        }),
        ..SetupReport::default()
    };
    assert_eq!(r.missing_engine(VPNKind::Openvpn), engine("OpenVPN Community", false));
    assert_eq!(r.missing_engine(VPNKind::Wireguard), None);
    let repair = SetupReport {
        engine: Some(EngineReport {
            service: row(true, None),
            openvpn: row(false, Some("repair")),
            wireguard: row(false, None),
        }),
        ..SetupReport::default()
    };
    assert_eq!(repair.missing_engine(VPNKind::Openvpn), engine("OpenVPN Community", true));
    assert_eq!(repair.missing_engine(VPNKind::Wireguard), engine("WireGuard", true));
    // A later kind is not an engine that is missing.
    let later = SetupReport { later_kinds: vec![(VPNKind::Sstp, "Later.".into())], ..repair };
    assert_eq!(later.missing_engine(VPNKind::Sstp), None);
}

/// The row's label: the engine-missing text, then the later text, then "Not installed: …" / "Not ready: …"; `None`
/// exactly when the kind is available.
#[test]
fn unavailable_text_orders_the_sources() {
    l10n::with_language(AppLanguage::En, || {
        let r = SetupReport { missing_tools: vec!["sstpc".into()], ..mac_ready() };
        assert_eq!(r.unavailable_text(VPNKind::Sstp).as_deref(), Some("Not installed: sstp-client"));
        assert_eq!(r.unavailable_text(VPNKind::Openvpn), None);
        let old_root = SetupReport { installed_root_version: Some("7".into()), ..mac_ready() };
        assert_eq!(
            old_root.unavailable_text(VPNKind::Wireguard).as_deref(),
            Some("Not ready: Permissions (root scripts + sudoers)")
        );
        let later = SetupReport { later_kinds: vec![(VPNKind::L2tp, "Later.".into())], ..mac_ready() };
        assert_eq!(later.unavailable_text(VPNKind::L2tp).as_deref(), Some("Later."));
        let none = SetupReport {
            engine_missing: Some("No service.".into()),
            later_kinds: vec![(VPNKind::L2tp, "Later.".into())],
            ..mac_ready()
        };
        assert_eq!(none.unavailable_text(VPNKind::Openvpn).as_deref(), Some("No service."));
        assert_eq!(none.unavailable_text(VPNKind::L2tp).as_deref(), Some("No service."));
        let reports =
            [r, old_root, later, none, SetupReport::unknown(), SetupReport { package_manager: None, ..mac_ready() }];
        for report in &reports {
            for kind in VPNKind::ALL {
                assert_eq!(report.unavailable_text(kind).is_none(), report.is_available(kind), "{kind:?} {report:?}");
            }
        }
    });
}

/// Hungarian labels.
#[test]
fn unavailable_text_is_localized() {
    l10n::with_language(AppLanguage::Hu, || {
        let r = SetupReport { missing_tools: vec!["openvpn".into()], ..mac_ready() };
        assert_eq!(r.unavailable_text(VPNKind::Openvpn).as_deref(), Some("Nincs telepítve: OpenVPN"));
        let old_root = SetupReport { installed_root_version: Some("7".into()), ..mac_ready() };
        assert!(old_root.unavailable_text(VPNKind::Openvpn).unwrap().starts_with("Nem használható: "));
    });
}

/// macOS' answers, pinned before WinVPN 2c's RAS row: every kind of the reports macOS produces (unknown, ready,
/// a missing tool, an old root layer) and of the engine-missing report (macOS never has one; since WinVPN 2.0 it is
/// incomplete: the WinVPN Service is missing).
#[test]
fn macos_report_is_unchanged() {
    use VPNKind::*;
    let cases: [(SetupReport, bool, &[VPNKind]); 5] = [
        (SetupReport::default(), false, &[L2tp, Cisco]),
        (mac_ready(), true, &[Openvpn, Wireguard, Strongswan, Sstp, L2tp, Cisco]),
        (
            SetupReport { missing_tools: vec!["sstpc".into()], ..mac_ready() },
            false,
            &[Openvpn, Wireguard, Strongswan, L2tp, Cisco],
        ),
        (SetupReport { installed_root_version: Some("7".into()), ..mac_ready() }, false, &[L2tp, Cisco]),
        (SetupReport { engine_missing: Some("No engine.".into()), ..mac_ready() }, false, &[]),
    ];
    for (report, complete, available) in &cases {
        assert_eq!(report.ras, None);
        assert!(report.ras_unsupported_kinds.is_empty());
        assert_eq!(report.is_complete(), *complete, "{report:?}");
        for kind in VPNKind::ALL {
            assert_eq!(report.is_available(kind), available.contains(&kind), "{kind:?} {report:?}");
            assert_eq!(report.ras_unsupported_reason(kind), None);
        }
    }
}

fn ras(usable: bool) -> Option<EngineRow> {
    Some(EngineRow { ok: usable, usable, detail: String::new(), action: None })
}

fn windows_2c(service_missing: bool, ras_usable: bool) -> SetupReport {
    SetupReport {
        engine_missing: service_missing.then(|| "No service.".to_string()),
        engine: (!service_missing).then(|| EngineReport {
            service: row(true),
            openvpn: row(true),
            wireguard: row(true),
        }),
        ras: ras(ras_usable),
        ras_unsupported_kinds: vec![(VPNKind::Cisco, "Cisco is not supported.".into())],
        ..SetupReport::unknown()
    }
}

/// WinVPN 2c: L2TP, IKEv2 and SSTP run through the Windows VPN client, not the WinVPN Service: a missing service
/// does not grey them, the RAS row does; Cisco IPsec follows `ras_unsupported_kinds`.
#[test]
fn native_kinds_do_not_need_the_service() {
    use VPNKind::*;
    l10n::with_language(AppLanguage::En, || {
        let r = windows_2c(true, true);
        for kind in [L2tp, Strongswan, Sstp] {
            assert!(r.is_available(kind), "{kind:?}");
            assert_eq!(r.unavailable_text(kind), None);
        }
        assert!(!r.is_available(Openvpn) && !r.is_available(Wireguard));
        assert_eq!(r.unavailable_text(Openvpn).as_deref(), Some("No service."));
        assert!(!r.is_available(Cisco));
        assert_eq!(r.ras_unsupported_reason(Cisco), Some("Cisco is not supported."));
        assert_eq!(r.unavailable_text(Cisco).as_deref(), Some("Cisco is not supported."));
        assert_eq!(r.missing_engine(Cisco), None);
        // The service is missing: the setup is incomplete ("!", System Status at launch), though the RAS kinds
        // above still connect.
        assert!(!r.is_complete());

        // A RAS row that cannot be used: the RAS kinds are "Not ready: Windows VPN client", whatever the service.
        for service_missing in [true, false] {
            let r = windows_2c(service_missing, false);
            for kind in [L2tp, Strongswan, Sstp] {
                assert!(!r.is_available(kind));
                assert_eq!(
                    r.missing_engine(kind),
                    Some(MissingEngine { name: "Windows VPN client".into(), installed: true })
                );
                assert_eq!(r.unavailable_text(kind).as_deref(), Some("Not ready: Windows VPN client"));
            }
            assert!(!r.is_complete());
        }
        // With the service: OpenVPN and WireGuard follow their rows as before.
        let r = windows_2c(false, true);
        assert!(r.is_available(Openvpn) && r.is_available(Wireguard) && r.is_available(L2tp));
        assert!(r.is_complete());
        for report in
            [windows_2c(true, true), windows_2c(true, false), windows_2c(false, true), windows_2c(false, false)]
        {
            for kind in VPNKind::ALL {
                assert_eq!(report.unavailable_text(kind).is_none(), report.is_available(kind), "{kind:?} {report:?}");
            }
        }
    });
    l10n::with_language(AppLanguage::Hu, || {
        assert_eq!(
            windows_2c(false, false).unavailable_text(VPNKind::Sstp).as_deref(),
            Some("Nem használható: Windows VPN-kliens")
        );
    });
}

/// G-4: a start is refused outright only for what the RAS row does not cover: with a RAS row, a missing service
/// refuses OpenVPN and WireGuard, not the RAS kinds and not the system VPNs (`None`); Cisco gets its own reason.
#[test]
fn a_missing_service_does_not_refuse_ras_kinds_or_system_vpns() {
    use VPNKind::*;
    let r = windows_2c(true, true);
    assert_eq!(r.start_refusal(None), None);
    for kind in [L2tp, Strongswan, Sstp] {
        assert_eq!(r.start_refusal(Some(kind)), None, "{kind:?}");
    }
    assert_eq!(r.start_refusal(Some(Openvpn)).as_deref(), Some("No service."));
    assert_eq!(r.start_refusal(Some(Wireguard)).as_deref(), Some("No service."));
    assert_eq!(r.start_refusal(Some(Cisco)).as_deref(), Some("Cisco is not supported."));
    let r = windows_2c(false, true);
    assert_eq!(r.start_refusal(Some(Openvpn)), None);
    assert_eq!(r.start_refusal(Some(Cisco)).as_deref(), Some("Cisco is not supported."));
}

/// macOS (and WinVPN before 2c) refuse exactly as the old gates did: the engine-missing text for every start, a
/// system VPN's included, then a later kind's text; nothing otherwise.
#[test]
fn macos_refusals_are_unchanged() {
    for report in
        [SetupReport::default(), mac_ready(), SetupReport { missing_tools: vec!["sstpc".into()], ..mac_ready() }]
    {
        assert_eq!(report.start_refusal(None), None);
        for kind in VPNKind::ALL {
            assert_eq!(report.start_refusal(Some(kind)), None);
        }
    }
    let missing = SetupReport {
        engine_missing: Some("No engine.".into()),
        later_kinds: vec![(VPNKind::L2tp, "Later.".into())],
        ..mac_ready()
    };
    assert_eq!(missing.start_refusal(None).as_deref(), Some("No engine."));
    for kind in VPNKind::ALL {
        assert_eq!(missing.start_refusal(Some(kind)).as_deref(), Some("No engine."));
    }
    let later = SetupReport { later_kinds: vec![(VPNKind::Sstp, "Later.".into())], ..mac_ready() };
    assert_eq!(later.start_refusal(Some(VPNKind::Sstp)).as_deref(), Some("Later."));
    assert_eq!(later.start_refusal(Some(VPNKind::Openvpn)), None);
    assert_eq!(later.start_refusal(None), None);
}

// LinVPN (L-b): NetworkManager and the plugin each kind needs decide (resolved point 17).

use macvpn_platform_api::setup::NmReport;

fn nm_row(ok: bool, action: Option<&'static str>) -> EngineRow {
    EngineRow { ok, usable: ok, detail: String::new(), action }
}

fn linux(l2tp_ok: bool) -> SetupReport {
    SetupReport {
        package_manager: Some("PackageKit".into()),
        nm: Some(NmReport {
            networkmanager: nm_row(true, None),
            kinds: vec![
                (VPNKind::Wireguard, nm_row(true, None), String::new()),
                (VPNKind::Openvpn, nm_row(true, None), "network-manager-openvpn".into()),
                (VPNKind::L2tp, nm_row(l2tp_ok, (!l2tp_ok).then_some("install")), "network-manager-l2tp".into()),
                (VPNKind::Strongswan, nm_row(true, None), "network-manager-strongswan".into()),
                (VPNKind::Cisco, nm_row(true, None), "network-manager-vpnc".into()),
                (VPNKind::Sstp, nm_row(true, None), "network-manager-sstp".into()),
            ],
            openvpn_push_visible: true,
        }),
        ..SetupReport::unknown()
    }
}

#[test]
fn linux_kinds_follow_their_plugin_rows() {
    let r = linux(false);
    assert!(r.is_available(VPNKind::Wireguard));
    assert!(r.is_available(VPNKind::Cisco), "Cisco works on Linux");
    assert!(!r.is_available(VPNKind::L2tp));
    assert!(!r.is_complete());
    let m = r.missing_engine(VPNKind::L2tp).unwrap();
    assert!(!m.installed);
    assert!(m.name.contains("L2TP"));
    assert!(linux(true).is_complete());
}

#[test]
fn without_networkmanager_nothing_starts_and_system_vpns_are_refused() {
    let mut r = linux(true);
    r.nm.as_mut().unwrap().networkmanager = nm_row(false, None);
    assert!(VPNKind::ALL.iter().all(|k| !r.is_available(*k)));
    assert!(r.start_refusal(None).is_some());
}

#[test]
fn macos_and_windows_reports_are_unaffected() {
    assert!(SetupReport::unknown().nm.is_none());
}

/// The rest of the Linux decisions: a red row without "install" needs a repair ("Not ready"), NetworkManager missing
/// names NetworkManager, no kind needs the WinVPN Service, and a kind without a row cannot start.
#[test]
fn linux_names_the_missing_engine_and_needs_no_service() {
    let mut r = linux(true);
    let nm = r.nm.as_mut().unwrap();
    nm.kinds[1].1 = nm_row(false, None);
    nm.kinds.retain(|(k, _, _)| *k != VPNKind::Sstp);
    assert_eq!(
        r.missing_engine(VPNKind::Openvpn),
        Some(MissingEngine { name: "LinVPN OpenVPN service".into(), installed: true })
    );
    assert!(!r.is_available(VPNKind::Sstp), "no row: not available");
    assert!(VPNKind::ALL.iter().all(|k| !r.needs_service(Some(*k))));
    assert!(!r.needs_service(None));
    assert_eq!(r.start_refusal(None), None, "NetworkManager usable: a system VPN may start");
    assert_eq!(r.start_refusal(Some(VPNKind::Openvpn)), None, "the setup check decides");
    let mut down = linux(true);
    down.nm.as_mut().unwrap().networkmanager =
        EngineRow { ok: false, usable: false, detail: "NetworkManager is not running.".into(), action: None };
    assert_eq!(
        down.missing_engine(VPNKind::Wireguard),
        Some(MissingEngine { name: "NetworkManager".into(), installed: false })
    );
    assert_eq!(down.start_refusal(None).as_deref(), Some("NetworkManager is not running."));
    assert!(!down.is_complete());
}
