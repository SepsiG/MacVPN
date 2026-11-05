//! Per-connection DNS settings (root layer 15): model, JSON, validation, the `up` frame lines, the tunnel hint.
use macvpn_core::date::Date;
use macvpn_core::dns_settings::{DnsMode, DnsRequest, DnsSetting, full_tunnel_hint};
use macvpn_core::models::{Connection, VPNKind};
use serde_json::json;
use uuid::Uuid;

fn conn() -> Connection {
    Connection::with_id(Uuid::nil(), "Office", VPNKind::Openvpn, Date::parse_iso8601("2026-11-04T10:00:00Z").unwrap())
}

fn targeted() -> DnsSetting {
    DnsSetting {
        mode: DnsMode::Targeted,
        servers: vec!["10.0.0.53".into()],
        domains: vec!["corp.example".into()],
        override_vpn: true,
    }
}

#[test]
fn default_is_automatic_without_own_dns() {
    let d = DnsSetting::default();
    assert_eq!(d.mode, DnsMode::Automatic);
    assert!(d.servers.is_empty() && d.domains.is_empty() && !d.override_vpn);
    assert!(d.is_default());
    assert_eq!(d.request(), None, "the default sends nothing");
    assert_eq!(conn().dns, d);
}

#[test]
fn json_round_trip_and_default_omitted() {
    let c = conn();
    assert!(c.to_json().get("dns").is_none(), "the default is not written");
    let mut c2 = conn();
    c2.dns = targeted();
    let j = c2.to_json();
    assert_eq!(j["dns"], json!({"mode":"targeted","servers":["10.0.0.53"],"domains":["corp.example"],"override":true}));
    assert_eq!(Connection::from_json(&j).unwrap(), c2);
}

#[test]
fn lenient_decode() {
    let mut j = conn().to_json();
    for bad in [json!("x"), json!({"servers": "10.0.0.1"}), json!({"override": 1}), json!({"mode": 3}), json!(null)] {
        j["dns"] = bad.clone();
        assert_eq!(Connection::from_json(&j).unwrap().dns, DnsSetting::default(), "{bad}");
    }
    // An unknown (newer) mode is Automatic; domains are normalized.
    let d = DnsSetting::from_json(&json!({"mode": "future", "domains": ["Corp.Example."]})).unwrap();
    assert_eq!(d.mode, DnsMode::Automatic);
    assert_eq!(d.domains, ["corp.example"]);
}

#[test]
fn validation() {
    let ok = targeted();
    assert_eq!(ok.validate(), Ok(()));
    let with = |f: fn(&mut DnsSetting)| {
        let mut d = targeted();
        f(&mut d);
        d.validate()
    };
    assert!(with(|d| d.servers = vec!["10.0.0.256".into()]).is_err());
    assert!(with(|d| d.servers = vec!["dns.example".into()]).is_err());
    assert!(with(|d| d.servers = (0..17).map(|i| format!("10.0.0.{i}")).collect()).is_err());
    assert!(with(|d| d.servers = vec!["fd00::53".into()]).is_ok());
    assert!(with(|d| d.domains = vec!["bad domain".into()]).is_err());
    assert!(with(|d| d.domains = vec!["-x.example".into()]).is_err());
    assert!(with(|d| d.domains = (0..33).map(|i| format!("d{i}.example")).collect()).is_err());
    assert!(with(|d| d.servers.clear()).is_err(), "override without servers");
    assert!(
        with(|d| {
            d.servers.clear();
            d.override_vpn = false;
        })
        .is_ok()
    );
}

#[test]
fn frame_lines_round_trip() {
    let r = targeted().request().unwrap();
    let lines = r.frame_lines();
    assert_eq!(lines, "dns-mode=targeted\ndns-servers=10.0.0.53\ndns-domains=corp.example\ndns-override=1\n");
    assert_eq!(DnsRequest::from_frame_lines(&lines), Some(r));
    let strict = DnsRequest { mode: DnsMode::Strict, ..Default::default() };
    assert_eq!(strict.frame_lines(), "dns-mode=strict\n");
    assert_eq!(DnsRequest::from_frame_lines(&strict.frame_lines()), Some(strict));
    let two = DnsRequest {
        servers: vec!["10.0.0.1".into(), "fd00::1".into()],
        domains: vec!["a.example".into(), "b.example".into()],
        ..Default::default()
    };
    assert_eq!(DnsRequest::from_frame_lines(&two.frame_lines()), Some(two));
}

#[test]
fn frame_lines_refuse_garbage() {
    for bad in [
        "dns-mode=sometimes\n",
        "dns-servers=10.0.0.1;touch /tmp/x\n",
        "dns-servers=\n",
        "dns-servers=10.0.0.1,\n",
        "dns-domains=Corp.Example\n",
        "dns-domains=a b\n",
        "dns-override=yes\n",
        "dns-override=1\n",
        "dns-mode=full\ndns-mode=full\n",
        "dns-other=1\n",
        "dns-mode\n",
    ] {
        assert_eq!(DnsRequest::from_frame_lines(bad), None, "{bad:?}");
    }
}

#[test]
fn full_tunnel_hint_from_the_config() {
    let ovpn = "client\nremote vpn.example.com 1194\n";
    assert_eq!(full_tunnel_hint(VPNKind::Openvpn, &format!("{ovpn}redirect-gateway def1\n")), Some(true));
    assert_eq!(full_tunnel_hint(VPNKind::Openvpn, &format!("{ovpn}route-nopull\n")), Some(false));
    assert_eq!(full_tunnel_hint(VPNKind::Openvpn, ovpn), None, "the server decides");
    let wg = "[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\nAllowedIPs = 10.0.0.0/8, 0.0.0.0/0\n";
    assert_eq!(full_tunnel_hint(VPNKind::Wireguard, wg), Some(true));
    assert_eq!(full_tunnel_hint(VPNKind::Wireguard, &wg.replace(", 0.0.0.0/0", "")), Some(false));
    assert_eq!(full_tunnel_hint(VPNKind::Sstp, "server=vpn.example.com\nroute_all=yes\n"), Some(true));
    assert_eq!(full_tunnel_hint(VPNKind::Sstp, "server=vpn.example.com\nroute_all=no\n"), Some(false));
    assert_eq!(full_tunnel_hint(VPNKind::Strongswan, ""), None);
}
