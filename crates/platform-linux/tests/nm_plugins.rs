//! System Status' NetworkManager rows from the plugin facts (resolved point 17); pure, runs on every OS.

use macvpn_core::models::VPNKind;
use macvpn_core::nm_plan::{
    SERVICE_L2TP, SERVICE_OPENVPN, SERVICE_OPENVPN_STOCK, SERVICE_SSTP, SERVICE_STRONGSWAN, SERVICE_VPNC,
};
use macvpn_platform_api::{EngineRow, NmReport};
use macvpn_platform_linux::pure::nm::plugins::{
    Facts, PACKAGES, is_installable, openvpn_version, packages, report, service_of,
};

fn facts() -> Facts {
    Facts {
        nm_version: Some("1.54.3".into()),
        services: [SERVICE_OPENVPN_STOCK, SERVICE_OPENVPN, SERVICE_L2TP, SERVICE_STRONGSWAN, SERVICE_VPNC]
            .map(String::from)
            .to_vec(),
        linvpn_openvpn: true,
        openvpn_version: Some("2.7.0".into()),
        eap_mschapv2: true,
        eap_identity: true,
    }
}

fn kind(r: &NmReport, kind: VPNKind) -> (&EngineRow, &str) {
    r.kinds.iter().find(|(k, _, _)| *k == kind).map(|(_, row, p)| (row, p.as_str())).expect("a row per kind")
}

#[test]
fn the_vm_without_sstp() {
    let r = report(&facts());
    assert!(r.networkmanager.ok && r.networkmanager.usable);
    assert_eq!(r.networkmanager.detail, "NetworkManager 1.54.3");
    let order: Vec<VPNKind> = r.kinds.iter().map(|(k, _, _)| *k).collect();
    assert_eq!(
        order,
        [VPNKind::Wireguard, VPNKind::Openvpn, VPNKind::L2tp, VPNKind::Strongswan, VPNKind::Cisco, VPNKind::Sstp]
    );

    let (wg, wg_packages) = kind(&r, VPNKind::Wireguard);
    assert!(wg.ok && wg.usable && wg.action.is_none());
    assert_eq!(wg.detail, "Built into NetworkManager");
    assert_eq!(wg_packages, "");

    let (ovpn, ovpn_packages) = kind(&r, VPNKind::Openvpn);
    assert!(ovpn.ok && ovpn.usable && ovpn.action.is_none());
    assert_eq!(ovpn.detail, "OpenVPN 2.7.0 · follows the server's redirect-gateway");
    assert_eq!(ovpn_packages, "network-manager-openvpn");

    for (k, p) in [
        (VPNKind::L2tp, "network-manager-l2tp"),
        (VPNKind::Strongswan, "network-manager-strongswan libcharon-extauth-plugins libcharon-extra-plugins"),
        (VPNKind::Cisco, "network-manager-vpnc"),
    ] {
        let (row, row_packages) = kind(&r, k);
        assert!(row.ok && row.usable && row.action.is_none(), "{k:?}");
        assert_eq!(row.detail, "Installed", "{k:?}");
        assert_eq!(row_packages, p, "{k:?}");
    }

    let (sstp, sstp_packages) = kind(&r, VPNKind::Sstp);
    assert!(!sstp.ok && !sstp.usable);
    assert_eq!(sstp.action, Some("install"));
    assert_eq!(sstp_packages, "network-manager-sstp");
    assert_eq!(sstp.detail, "Not installed: network-manager-sstp");

    let mut all = facts();
    all.services.push(SERVICE_SSTP.into());
    let r = report(&all);
    assert!(r.kinds.iter().all(|(_, row, _)| row.ok && row.usable && row.action.is_none()));
}

#[test]
fn without_networkmanager_no_row_is_usable() {
    let r = report(&Facts { nm_version: None, ..facts() });
    assert!(!r.networkmanager.ok && !r.networkmanager.usable);
    assert_eq!(r.networkmanager.detail, "NetworkManager is not running.");
    assert!(r.kinds.iter().all(|(_, row, _)| !row.usable));
}

#[test]
fn an_old_networkmanager_is_red() {
    for old in ["1.35.9", "1.22.10", "garbage", ""] {
        let r = report(&Facts { nm_version: Some(old.into()), ..facts() });
        assert!(!r.networkmanager.ok && !r.networkmanager.usable, "{old}");
        assert_eq!(r.networkmanager.detail, "NetworkManager 1.36 or later is needed.", "{old}");
        assert!(r.kinds.iter().all(|(_, row, _)| !row.usable), "{old}");
    }
    let r = report(&Facts { nm_version: Some("1.36.0".into()), ..facts() });
    assert!(r.networkmanager.ok);
    let r = report(&Facts { nm_version: Some("1.55.1-dev".into()), ..facts() });
    assert!(r.networkmanager.ok);
}

#[test]
fn openvpn_before_2_7_cannot_follow_the_server() {
    let r = report(&Facts { openvpn_version: Some("2.6.14".into()), ..facts() });
    let (ovpn, _) = kind(&r, VPNKind::Openvpn);
    assert!(ovpn.ok && ovpn.usable && ovpn.action.is_none());
    assert_eq!(ovpn.detail, "OpenVPN 2.6.14 · split tunnel unless set to Always (needs 2.7 to follow the server)");
    let r = report(&Facts { openvpn_version: Some("2.10.1".into()), ..facts() });
    assert_eq!(kind(&r, VPNKind::Openvpn).0.detail, "OpenVPN 2.10.1 · follows the server's redirect-gateway");
}

#[test]
fn without_linvpns_service_openvpn_is_red_without_an_install() {
    let r = report(&Facts { linvpn_openvpn: false, ..facts() });
    let (ovpn, _) = kind(&r, VPNKind::Openvpn);
    assert!(!ovpn.ok && !ovpn.usable);
    assert_eq!(ovpn.action, None);
    assert_eq!(ovpn.detail, "LinVPN's OpenVPN service is missing: reinstall LinVPN.");
}

#[test]
fn without_the_stock_plugin_or_openvpn_itself_openvpn_offers_its_package() {
    let mut f = facts();
    f.services.retain(|s| s != SERVICE_OPENVPN_STOCK);
    for f in [f, Facts { openvpn_version: None, ..facts() }] {
        let r = report(&f);
        let (ovpn, p) = kind(&r, VPNKind::Openvpn);
        assert!(!ovpn.ok && !ovpn.usable);
        assert_eq!(ovpn.action, Some("install"));
        assert_eq!(p, "network-manager-openvpn");
        assert_eq!(ovpn.detail, "Not installed: network-manager-openvpn");
    }
}

#[test]
fn ikev2_without_eap_works_but_offers_the_eap_plugins() {
    let r = report(&Facts { eap_mschapv2: false, eap_identity: false, ..facts() });
    let (ike, p) = kind(&r, VPNKind::Strongswan);
    assert!(ike.ok && ike.usable);
    assert_eq!(ike.action, Some("install"));
    assert_eq!(p, "libcharon-extauth-plugins libcharon-extra-plugins");
    assert_eq!(ike.detail, "EAP needs libcharon-extauth-plugins, libcharon-extra-plugins");
}

#[test]
fn ikev2_eap_without_the_eap_identity_plugin_offers_it_alone() {
    // Ubuntu 26.04 lab: with only the extauth plugins charon-nm NAKs a server's EAP-Identity request.
    let r = report(&Facts { eap_identity: false, ..facts() });
    let (ike, p) = kind(&r, VPNKind::Strongswan);
    assert!(ike.ok && ike.usable);
    assert_eq!(ike.action, Some("install"));
    assert_eq!(p, "libcharon-extra-plugins");
    assert_eq!(ike.detail, "EAP needs libcharon-extra-plugins");
    let r = report(&Facts { eap_mschapv2: false, ..facts() });
    let (ike, p) = kind(&r, VPNKind::Strongswan);
    assert_eq!((ike.detail.as_str(), p), ("EAP needs libcharon-extauth-plugins", "libcharon-extauth-plugins"));
}

#[test]
fn a_missing_plugin_offers_its_packages() {
    let mut f = facts();
    f.services.retain(|s| s != SERVICE_STRONGSWAN && s != SERVICE_L2TP);
    let r = report(&f);
    let (l2tp, p) = kind(&r, VPNKind::L2tp);
    assert!(!l2tp.ok && !l2tp.usable);
    assert_eq!((l2tp.action, p), (Some("install"), "network-manager-l2tp"));
    let (ike, p) = kind(&r, VPNKind::Strongswan);
    assert!(!ike.ok && !ike.usable);
    assert_eq!((ike.action, p), (Some("install"), "network-manager-strongswan"));
    assert_eq!(ike.detail, "Not installed: network-manager-strongswan");
    f.eap_mschapv2 = false;
    let r = report(&f);
    let (ike, p) = kind(&r, VPNKind::Strongswan);
    assert_eq!(p, "network-manager-strongswan libcharon-extauth-plugins");
    assert_eq!(ike.detail, "Not installed: network-manager-strongswan, libcharon-extauth-plugins");
    f.eap_identity = false;
    let r = report(&f);
    let (ike, p) = kind(&r, VPNKind::Strongswan);
    assert_eq!(p, "network-manager-strongswan libcharon-extauth-plugins libcharon-extra-plugins");
    assert_eq!(
        ike.detail,
        "Not installed: network-manager-strongswan, libcharon-extauth-plugins, libcharon-extra-plugins"
    );
}

#[test]
fn only_the_fixed_packages_are_installable() {
    assert_eq!(
        PACKAGES,
        [
            "network-manager-openvpn",
            "network-manager-l2tp",
            "network-manager-strongswan",
            "libcharon-extauth-plugins",
            "libcharon-extra-plugins",
            "network-manager-vpnc",
            "network-manager-sstp",
        ]
    );
    for p in PACKAGES {
        assert!(is_installable(p), "{p}");
    }
    for bad in ["", "network-manager-foo", "network-manager-sstp ", "network-manager-sstp;1.0;amd64;", "sudo"] {
        assert!(!is_installable(bad), "{bad:?}");
    }
    assert!(packages(VPNKind::Wireguard).is_empty());
    assert_eq!(
        packages(VPNKind::Strongswan),
        ["network-manager-strongswan", "libcharon-extauth-plugins", "libcharon-extra-plugins"]
    );
    assert!(VPNKind::ALL.iter().flat_map(|k| packages(*k)).all(|p| is_installable(p)));
}

#[test]
fn a_name_file_gives_its_service() {
    let text = "[VPN Connection]\nname=sstp\nservice=org.freedesktop.NetworkManager.sstp\nprogram=/usr/lib/x\n";
    assert_eq!(service_of(text).as_deref(), Some("org.freedesktop.NetworkManager.sstp"));
    assert_eq!(service_of(" service = org.freedesktop.NetworkManager.l2tp \r\n").as_deref(), Some(SERVICE_L2TP));
    assert_eq!(service_of("[VPN Connection]\nname=x\n"), None);
    assert_eq!(service_of("service=\n"), None);
    assert_eq!(service_of("# service=org.freedesktop.NetworkManager.vpnc\n"), None);
    assert_eq!(service_of("service=bad name\n"), None, "not a bus name");
}

#[test]
fn openvpns_version_line() {
    let out = "OpenVPN 2.7.0 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL]\nlibrary versions: OpenSSL\n";
    assert_eq!(openvpn_version(out).as_deref(), Some("2.7.0"));
    assert_eq!(openvpn_version("OpenVPN 2.6.14 arm\n").as_deref(), Some("2.6.14"));
    assert_eq!(openvpn_version("OpenVPN 2.7_rc1 x\n").as_deref(), Some("2.7_rc1"));
    assert_eq!(openvpn_version(""), None);
    assert_eq!(openvpn_version("openvpn: not found\n"), None);
    assert_eq!(openvpn_version("OpenVPN $(x) y\n"), None);
}
