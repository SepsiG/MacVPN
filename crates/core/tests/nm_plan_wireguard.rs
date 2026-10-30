//! WireGuard through NM's built-in `wireguard` type (LinVPN L-b Task 5).

use macvpn_core::models::{Connection, VPNKind};
use macvpn_core::nm_plan::{self, Caps, Input, NmValue, SecretKey, SecretMode, SecretValue, names};
use std::path::Path;

const KEY_A: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const PUB_B: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
const PSK: &str = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=";

fn conf(extra_iface: &str, allowed: &str) -> String {
    format!(
        "[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.99.13.5/32\nDNS = 10.99.0.53, lab.test\n{extra_iface}\n\
         [Peer]\nPublicKey = {PUB_B}\nPresharedKey = {PSK}\nEndpoint = vpn.example.com:51820\nAllowedIPs = {allowed}\nPersistentKeepalive = 25\n"
    )
}

fn plan(text: &str, caps: &Caps) -> Result<nm_plan::NmPlan, nm_plan::Unsupported> {
    let c = Connection::new("Lab WG", VPNKind::Wireguard);
    let input = Input {
        connection: &c,
        config: text.as_bytes(),
        user: "linvpn-dev",
        uid: 1001,
        runtime_dir: Path::new("/run/user/1001/linvpn/nm/x"),
        caps,
        client_cert: nm_plan::ImportedCert::None,
    };
    nm_plan::plan(&input)
}

#[test]
fn a_split_tunnel_becomes_a_private_wireguard_connection_without_secrets_in_settings() {
    let p = plan(&conf("", "10.99.0.0/24"), &Caps::default()).unwrap();
    assert_eq!(p.service_type, None);
    let iface = p.iface.clone().unwrap();
    assert!(iface.starts_with(names::IFACE_WIREGUARD));
    assert_eq!(p.settings["connection"]["type"], NmValue::Str("wireguard".into()));
    assert_eq!(p.settings["connection"]["interface-name"], NmValue::Str(iface));
    let wg = &p.settings["wireguard"];
    assert_eq!(wg["private-key-flags"], NmValue::U32(1));
    let NmValue::WgPeers(peers) = &wg["peers"] else { panic!() };
    assert_eq!(peers[0].public_key, PUB_B);
    assert_eq!(peers[0].endpoint.as_deref(), Some("vpn.example.com:51820"));
    assert_eq!(peers[0].allowed_ips, vec!["10.99.0.0/24".to_string()]);
    assert_eq!(peers[0].persistent_keepalive, 25);
    assert!(peers[0].has_preshared_key);
    let ipv4 = &p.settings["ipv4"];
    assert_eq!(ipv4["method"], NmValue::Str("manual".into()));
    assert_eq!(ipv4["never-default"], NmValue::Bool(true));
    assert_eq!(ipv4["dns-data"], NmValue::StrList(vec!["10.99.0.53".into()]));
    assert_eq!(ipv4["dns-search"], NmValue::StrList(vec!["~lab.test".into()]));
    let shown = format!("{:?}", p.settings);
    assert!(!shown.contains(KEY_A) && !shown.contains(PSK), "no secret in settings");
    // The secrets: the private key and the peer's PSK, as literals the agent answers.
    assert_eq!(p.secrets.len(), 2);
    assert!(p.secrets.iter().any(|s| s.key == SecretKey::Plain("private-key".into())
        && matches!(&s.value, SecretValue::Literal(v) if v.as_str() == KEY_A)));
    assert!(p.secrets.iter().any(|s| s.key == SecretKey::WgPeerPsk { public_key: PUB_B.into() }));
}

#[test]
fn allowed_ips_with_the_default_route_make_a_full_tunnel_with_all_dns() {
    let p = plan(&conf("", "0.0.0.0/0, ::/0"), &Caps::default()).unwrap();
    assert_eq!(p.settings["ipv4"]["never-default"], NmValue::Bool(false));
    assert_eq!(p.settings["ipv4"]["dns-priority"], NmValue::I32(nm_plan::dns::FULL_PRIORITY));
}

#[test]
fn inline_mode_sets_flags_zero() {
    let caps = Caps { secret_mode: SecretMode::Inline, ..Caps::default() };
    let p = plan(&conf("", "10.99.0.0/24"), &caps).unwrap();
    assert_eq!(p.settings["wireguard"]["private-key-flags"], NmValue::U32(0));
}

#[test]
fn mtu_port_fwmark_and_table_off_map_to_nm() {
    let p =
        plan(&conf("MTU = 1380\nListenPort = 51900\nFwMark = 0x1234\nTable = off", "10.99.0.0/24"), &Caps::default())
            .unwrap();
    let wg = &p.settings["wireguard"];
    assert_eq!(wg["mtu"], NmValue::U32(1380));
    assert_eq!(wg["listen-port"], NmValue::U32(51900));
    assert_eq!(wg["fwmark"], NmValue::U32(0x1234));
    assert_eq!(wg["peer-routes"], NmValue::Bool(false));
}

#[test]
fn an_invalid_config_is_the_validators_error() {
    let e = plan("[Interface]\nPrivateKey = nope\n", &Caps::default()).unwrap_err();
    assert!(e.invalid_config);
}

#[test]
fn table_with_a_number_is_not_supported_on_linux() {
    let e = plan(&conf("Table = 1234", "10.99.0.0/24"), &Caps::default()).unwrap_err();
    assert!(!e.invalid_config);
    assert!(e.reasons[0].contains("Table"), "{:?}", e.reasons);
}

#[test]
fn ipv6_addresses_and_dns_go_to_ipv6_and_ipv4_dns_without_an_ipv4_address_is_a_warning() {
    let text = format!(
        "[Interface]\nPrivateKey = {KEY_A}\nAddress = fd00::5/64\nDNS = fd00::53, 10.99.0.53\n\
         [Peer]\nPublicKey = {PUB_B}\nAllowedIPs = fd00::/64\n"
    );
    let p = plan(&text, &Caps::default()).unwrap();
    let ipv6 = &p.settings["ipv6"];
    assert_eq!(ipv6["method"], NmValue::Str("manual".into()));
    assert_eq!(
        ipv6["address-data"],
        NmValue::Addresses(vec![nm_plan::NmAddress { address: "fd00::5".into(), prefix: 64 }])
    );
    assert_eq!(ipv6["dns-data"], NmValue::StrList(vec!["fd00::53".into()]));
    assert_eq!(p.settings["ipv4"]["method"], NmValue::Str("disabled".into()));
    assert_eq!(p.warnings.len(), 1);
    assert!(p.warnings[0].contains("10.99.0.53"), "{:?}", p.warnings);
    assert_eq!(p.secrets.len(), 1, "no PSK: only the private key");
}

#[test]
fn a_repeated_key_or_a_numeric_endpoint_host_is_an_invalid_config() {
    let twice = format!("[Interface]\nPrivateKey = {KEY_A}\nMTU = 1400\nMTU = 1380\n[Peer]\nPublicKey = {PUB_B}\n");
    assert!(plan(&twice, &Caps::default()).unwrap_err().invalid_config);
    let numeric = conf("", "10.99.0.0/24").replace("vpn.example.com:51820", "1.2.3:51820");
    assert!(plan(&numeric, &Caps::default()).unwrap_err().invalid_config);
}
