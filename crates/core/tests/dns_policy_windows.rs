//! WinVPN's pure DNS pieces: OpenVPN's `PUSH_REPLY` read for its DNS, and the local NRPT rules a layout needs.

use macvpn_core::dns_policy::nrpt::{NrptRule, key_prefix, rules};
use macvpn_core::dns_policy::push_reply::{Push, parse_push_reply};
use macvpn_core::dns_policy::{Effective, Layout};

#[test]
fn push_reply_gives_servers_domains_and_routes() {
    let line = "PUSH: Received control message: 'PUSH_REPLY,route 10.99.0.0 255.255.255.0,dhcp-option DNS 10.99.0.53,dhcp-option DOMAIN lab.test,dhcp-option DOMAIN-SEARCH corp.example,dhcp-option DNS6 fd00::53,dns server 0 resolve-domains internal.example,route-gateway 10.99.11.1,ping 10,peer-id 0'";
    let p = parse_push_reply(line).unwrap();
    assert_eq!(p.servers, ["10.99.0.53", "fd00::53"]);
    assert_eq!(p.search, ["lab.test", "corp.example"]);
    assert_eq!(p.resolve, ["internal.example"]);
    assert_eq!(p.routes.len(), 1);
    assert!(parse_push_reply("some other line").is_none());
}

#[test]
fn push_reply_takes_dns_server_addresses_of_openvpn_2_6() {
    let p = parse_push_reply("PUSH: Received control message: 'PUSH_REPLY,dns server 0 address 10.0.0.1 10.0.0.2,dns search-domains a.example b.example'").unwrap();
    assert_eq!(p.servers, ["10.0.0.1", "10.0.0.2"]);
    assert_eq!(p.search, ["a.example", "b.example"]);
}

#[test]
fn push_reply_strips_ports_drops_junk_and_dedups() {
    let p = parse_push_reply(
        "PUSH: Received control message: 'PUSH_REPLY,dns server 1 address [fd00::1]:5353 10.0.0.1:53 not-an-ip,dhcp-option DNS 10.0.0.1,dhcp-option DOMAIN Lab.Test.,dhcp-option DOMAIN lab.test,dhcp-option DOMAIN bad/domain,route 10.1.0.0 255.0.255.0'",
    )
    .unwrap();
    assert_eq!(p.servers, ["fd00::1", "10.0.0.1"]);
    assert_eq!(p.search, ["lab.test"]);
    assert!(p.routes.is_empty(), "a non-contiguous netmask is no route");
}

fn eff() -> Effective {
    Effective {
        servers: vec!["10.99.0.53".into()],
        search: vec!["lab.test".into()],
        resolve: vec!["internal.example".into()],
        zones: vec!["0.99.10.in-addr.arpa".into()],
    }
}

#[test]
fn vpn_layout_catches_every_name_and_keeps_local_names_local() {
    let r = rules(
        "ID",
        Layout::Vpn { local: true },
        &eff(),
        Some((&["home.lan".to_string()], &["192.168.1.1".to_string()])),
    );
    assert_eq!(
        r[0],
        NrptRule { key: "WinVPN-ID-0".into(), names: vec![".".into()], servers: vec!["10.99.0.53".into()] }
    );
    assert_eq!(
        r[1],
        NrptRule { key: "WinVPN-ID-1".into(), names: vec![".home.lan".into()], servers: vec!["192.168.1.1".into()] }
    );
    assert_eq!(r.len(), 2);
    assert!(r.iter().all(|x| x.key.starts_with(&key_prefix("ID"))));
}

#[test]
fn strict_has_only_the_catch_all() {
    let r = rules(
        "ID",
        Layout::Vpn { local: false },
        &eff(),
        Some((&["home.lan".to_string()], &["192.168.1.1".to_string()])),
    );
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].names, ["."]);
}

#[test]
fn split_and_fallback_route_only_the_vpn_names() {
    for layout in [Layout::Split, Layout::Fallback] {
        let r = rules("ID", layout, &eff(), None);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].names, [".lab.test", ".internal.example", ".0.99.10.in-addr.arpa"]);
        assert_eq!(r[0].servers, ["10.99.0.53"]);
    }
}

#[test]
fn a_local_domain_the_vpn_also_has_stays_with_the_vpn() {
    let r = rules(
        "ID",
        Layout::Vpn { local: true },
        &eff(),
        Some((&["lab.test".to_string()], &["192.168.1.1".to_string()])),
    );
    assert_eq!(r.len(), 1);
}

#[test]
fn no_local_servers_no_local_rule() {
    let r = rules("ID", Layout::Vpn { local: true }, &eff(), Some((&["home.lan".to_string()], &[])));
    assert_eq!(r.len(), 1);
}

#[test]
fn split_without_names_has_no_rule() {
    let e = Effective { servers: vec!["10.99.0.53".into()], ..Effective::default() };
    assert!(rules("ID", Layout::Split, &e, None).is_empty());
}

#[test]
fn no_layout_no_rules() {
    assert!(rules("ID", Layout::None, &eff(), None).is_empty());
}

#[test]
fn a_push_tells_a_full_tunnel_by_redirect_gateway_without_ipv4_excluded() {
    let full = |opts: &str| {
        Push::from_line(&format!("PUSH: Received control message: 'PUSH_REPLY,{opts},ping 10'"))
            .unwrap()
            .redirect_gateway
    };
    assert!(full("redirect-gateway def1 bypass-dhcp"));
    assert!(full("redirect-gateway"));
    assert!(full("redirect-gateway local def1"));
    assert!(!full("redirect-gateway !ipv4 ipv6"), "IPv6 only is no full tunnel (as the config's routing)");
    assert!(!full("redirect-private def1"));
    assert!(!full("route 10.0.0.0 255.0.0.0"));
    assert!(Push::from_line("redirect-gateway def1").is_none(), "only a PUSH_REPLY line");
}

#[test]
fn a_push_gives_the_tunnel_address() {
    let local =
        |opts: &str| Push::from_line(&format!("PUSH: Received control message: 'PUSH_REPLY,{opts}'")).unwrap().local;
    assert_eq!(local("ifconfig 10.8.0.6 255.255.255.0"), Some("10.8.0.6".parse().unwrap()));
    assert_eq!(local("ifconfig 10.8.0.6 10.8.0.5"), Some("10.8.0.6".parse().unwrap()));
    assert_eq!(local("ifconfig-ipv6 fd00::1000/64 fd00::1"), Some("fd00::1000".parse().unwrap()));
    assert_eq!(
        local("ifconfig-ipv6 fd00::1000/64 fd00::1,ifconfig 10.8.0.6 255.255.255.0"),
        Some("10.8.0.6".parse().unwrap()),
        "IPv4 first"
    );
    assert_eq!(local("ifconfig nonsense 255.255.255.0"), None);
    assert_eq!(local("ping 10"), None);
}

#[test]
fn a_long_push_in_several_messages_is_merged() {
    let mut p = Push::from_line(
        "PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.0.0.1,dhcp-option DOMAIN a.example,route 10.1.0.0 255.255.0.0,push-continuation 2'",
    )
    .unwrap();
    assert!(p.continues);
    p.merge(
        Push::from_line(
            "PUSH: Received control message: 'PUSH_REPLY,dhcp-option DNS 10.0.0.1,dhcp-option DNS 10.0.0.2,dhcp-option DOMAIN b.example,redirect-gateway def1,ifconfig 10.8.0.6 255.255.255.0,route 10.1.0.0 255.255.0.0,push-continuation 1'",
        )
        .unwrap(),
    );
    assert!(!p.continues, "push-continuation 1 is the last part");
    assert_eq!(p.dns.servers, ["10.0.0.1", "10.0.0.2"]);
    assert_eq!(p.dns.search, ["a.example", "b.example"]);
    assert_eq!(p.dns.routes.len(), 1, "a route once");
    assert!(p.redirect_gateway);
    assert_eq!(p.local, Some("10.8.0.6".parse().unwrap()));
    assert_eq!(parse_push_reply("PUSH: Received control message: 'PUSH_REPLY,ping 10'"), Some(Default::default()));
}
