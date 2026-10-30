//! L2TP and Cisco IPsec through NM plugins (L-b Task 8).
use macvpn_core::models::{Connection, NativeSettings, SecretField, VPNKind};
use macvpn_core::nm_plan::{self, Caps, Input, NmValue, SecretKey, SecretMode, SecretValue, names};
use std::path::Path;

fn conn(kind: VPNKind, group: &str, all: bool) -> Connection {
    let mut c = Connection::new("Native", kind);
    c.native = Some(NativeSettings {
        server: "vpn.example.com".into(),
        account: "alice".into(),
        group_name: group.into(),
        send_all_traffic: all,
    });
    c
}
fn plan_with(c: &Connection, caps: &Caps) -> Result<nm_plan::NmPlan, nm_plan::Unsupported> {
    nm_plan::plan(&Input {
        connection: c,
        config: b"",
        user: "linvpn-dev",
        uid: 1001,
        runtime_dir: Path::new("/r"),
        caps,
        client_cert: nm_plan::ImportedCert::None,
    })
}
fn plan(c: &Connection) -> Result<nm_plan::NmPlan, nm_plan::Unsupported> {
    plan_with(c, &Caps::default())
}
fn data(p: &nm_plan::NmPlan) -> std::collections::BTreeMap<String, String> {
    let NmValue::StrDict(d) = &p.settings["vpn"]["data"] else { panic!() };
    d.clone()
}
fn has(p: &nm_plan::NmPlan, key: &str, field: SecretField) -> bool {
    p.secrets
        .iter()
        .any(|s| s.key == SecretKey::Plain(key.into()) && matches!(s.value, SecretValue::Field(f) if f == field))
}

#[test]
fn l2tp_uses_ipsec_psk_and_mschapv2_only() {
    let p = plan(&conn(VPNKind::L2tp, "", true)).unwrap();
    assert_eq!(p.service_type, Some(nm_plan::SERVICE_L2TP));
    let d = data(&p);
    assert_eq!(d["gateway"], "vpn.example.com");
    assert_eq!(d["user"], "alice");
    assert_eq!(d["ipsec-enabled"], "yes");
    for k in ["refuse-pap", "refuse-chap", "refuse-mschap", "refuse-eap"] {
        assert_eq!(d[k], "yes", "{k}");
    }
    assert_eq!(d["password-flags"], "1");
    assert_eq!(d["ipsec-psk-flags"], "1");
    assert!(has(&p, "password", SecretField::Password) && has(&p, "ipsec-psk", SecretField::Psk));
    assert_eq!(p.settings["ipv4"]["never-default"], NmValue::Bool(false));
    assert!(!p.settings.contains_key("user"), "all traffic: no class-based route");
}

#[test]
fn l2tp_split_tunnel() {
    let p = plan(&conn(VPNKind::L2tp, "", false)).unwrap();
    assert_eq!(p.settings["ipv4"]["never-default"], NmValue::Bool(true));
    // The dispatcher script's mark: the class-based route of the VPN address (Windows and macOS parity).
    let data = std::collections::BTreeMap::from([("linvpn.classful".to_string(), "1".to_string())]);
    assert_eq!(p.settings["user"]["data"], NmValue::StrDict(data));
    assert_eq!(nm_plan::CLASSFUL_ROUTE_KEY, "linvpn.classful");
}

#[test]
fn cisco_ipsec_runs_through_vpnc() {
    let p = plan(&conn(VPNKind::Cisco, "labgroup", true)).unwrap();
    assert_eq!(p.service_type, Some(nm_plan::SERVICE_VPNC));
    let d = data(&p);
    assert_eq!(d["IPSec gateway"], "vpn.example.com");
    assert_eq!(d["IPSec ID"], "labgroup");
    assert_eq!(d["Xauth username"], "alice");
    assert_eq!(d["IPSec secret-flags"], "1");
    assert_eq!(d["Xauth password-flags"], "1");
    assert!(has(&p, "IPSec secret", SecretField::Psk) && has(&p, "Xauth password", SecretField::Password));
}

#[test]
fn server_and_account_are_required_and_control_characters_refused() {
    let mut c = conn(VPNKind::L2tp, "", true);
    c.native.as_mut().unwrap().server = "".into();
    assert!(plan(&c).unwrap_err().invalid_config);
    let mut c = conn(VPNKind::Cisco, "g", true);
    c.native.as_mut().unwrap().server = "a\nb".into();
    assert!(plan(&c).unwrap_err().invalid_config);
}

#[test]
fn account_and_group_are_checked_too() {
    let mut c = conn(VPNKind::L2tp, "", true);
    c.native.as_mut().unwrap().account = "  ".into();
    assert!(plan(&c).unwrap_err().invalid_config);
    let mut c = conn(VPNKind::L2tp, "", true);
    c.native.as_mut().unwrap().account = "alice\nrefuse-eap no".into();
    assert!(plan(&c).unwrap_err().invalid_config);
    let mut c = conn(VPNKind::Cisco, "", true);
    assert!(plan(&c).unwrap_err().invalid_config, "Cisco needs a group");
    c.native.as_mut().unwrap().group_name = "g\nVendor netscreen".into();
    assert!(plan(&c).unwrap_err().invalid_config);
    let mut c = Connection::new("No settings", VPNKind::Cisco);
    c.native = None;
    assert!(plan(&c).unwrap_err().invalid_config);
}

#[test]
fn vpnc_pins_the_macos_proposal() {
    let p = plan(&conn(VPNKind::Cisco, "labgroup", false)).unwrap();
    let d = data(&p);
    assert_eq!(d["NAT Traversal Mode"], "natt");
    assert_eq!(d["Vendor"], "cisco");
    assert_eq!(d["Perfect Forward Secrecy"], "server");
    assert_eq!(d["IKE DH Group"], "dh2");
    assert_eq!(p.settings["ipv4"]["never-default"], NmValue::Bool(true));
    assert!(!p.settings.contains_key("user"), "Cisco: the server pushes the split networks");
}

#[test]
fn common_sections_are_private_and_hold_no_secret() {
    for (kind, group) in [(VPNKind::L2tp, ""), (VPNKind::Cisco, "labgroup")] {
        let c = conn(kind, group, true);
        let p = plan(&c).unwrap();
        assert_eq!(p.kind, kind);
        let s = &p.settings["connection"];
        assert_eq!(s["type"], NmValue::Str("vpn".into()));
        assert_eq!(s["permissions"], NmValue::StrList(vec!["user:linvpn-dev".into()]));
        assert_eq!(s["uuid"], NmValue::Str(names::nm_uuid(1001, &c.id).to_string()));
        assert_eq!(p.settings["vpn"]["user-name"], NmValue::Str("alice".into()));
        assert_eq!(p.settings["vpn"]["persistent"], NmValue::Bool(false));
        assert_eq!(p.settings["ipv4"]["method"], NmValue::Str("auto".into()));
        assert_eq!(p.settings["ipv6"]["method"], NmValue::Str("auto".into()));
        assert!(!p.settings["vpn"].contains_key("secrets"));
        assert!(p.files.is_empty() && p.iface.is_none() && p.warnings.is_empty());
        assert_eq!(p.secrets.len(), 2);
        assert!(p.secrets.iter().all(|s| s.setting == "vpn"));
        let d = data(&p);
        assert!(!d.contains_key("password") && !d.contains_key("ipsec-psk"));
        assert!(!d.contains_key("IPSec secret") && !d.contains_key("Xauth password"));
    }
}

#[test]
fn inline_secret_mode_clears_the_flags() {
    let caps = Caps { secret_mode: SecretMode::Inline, ..Caps::default() };
    let d = data(&plan_with(&conn(VPNKind::L2tp, "", true), &caps).unwrap());
    assert_eq!((d["password-flags"].as_str(), d["ipsec-psk-flags"].as_str()), ("0", "0"));
    let d = data(&plan_with(&conn(VPNKind::Cisco, "g", true), &caps).unwrap());
    assert_eq!((d["IPSec secret-flags"].as_str(), d["Xauth password-flags"].as_str()), ("0", "0"));
}

#[test]
fn the_summary_names_the_backend() {
    let p = plan(&conn(VPNKind::L2tp, "", true)).unwrap();
    assert_eq!(p.summary.as_deref(), Some("On Linux: NetworkManager L2TP/IPsec (MS-CHAPv2)"));
    let p = plan(&conn(VPNKind::Cisco, "g", true)).unwrap();
    assert_eq!(p.summary.as_deref(), Some("On Linux: NetworkManager vpnc (Cisco IPsec)"));
}

#[test]
fn server_and_account_are_trimmed() {
    let mut c = conn(VPNKind::L2tp, "", true);
    c.native.as_mut().unwrap().server = " vpn.example.com ".into();
    c.native.as_mut().unwrap().account = " alice ".into();
    let d = data(&plan(&c).unwrap());
    assert_eq!((d["gateway"].as_str(), d["user"].as_str()), ("vpn.example.com", "alice"));
}
