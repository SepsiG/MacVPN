//! Port of `ValidatorArgumentTests.swift`: OpenVPN directive arguments and `<connection>` blocks, the strongSwan
//! default-deny key list and the WireGuard value formats.

mod common;

use common::*;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::ValidationIssue;
use macvpn_core::validators::OpenVPNValidator;

fn ovpn(body: &str) -> Vec<ValidationIssue> {
    ovpn_args(&format!("remote a 1\n{body}"))
}

/// The host's issues apart from the Linux tier's acknowledgements: the argument rules are the same on every OS; on
/// Linux the names NetworkManager ignores are RISKY (`openvpn_tiers.rs` tests that), so a Linux host acknowledges
/// them here. On macOS and Windows this is `ovpn_all`.
fn ovpn_args(text: &str) -> Vec<ValidationIssue> {
    use macvpn_core::TargetOs;
    use macvpn_core::validators::openvpn::platform_reasons;
    let ack: std::collections::HashSet<String> = if TargetOs::host() == TargetOs::Linux {
        platform_reasons(TargetOs::Linux).keys().map(|d| d.to_string()).collect()
    } else {
        Default::default()
    };
    OpenVPNValidator.validate_full(text, &ack).all_issues()
}

#[track_caller]
fn ok(body: &str) {
    assert_eq!(ovpn(&format!("{body}\n")), [], "{body}");
}

#[track_caller]
fn bad(body: &str) {
    assert_eq!(lines(&ovpn(&format!("{body}\n"))), [2], "{body}");
}

fn en() {
    lang(AppLanguage::En);
}

#[test]
fn every_allowed_directive_has_an_argument_spec() {
    en();
    for d in OpenVPNValidator::allowed() {
        assert!(OpenVPNValidator::has_argument_spec(d), "{d}");
    }
    assert_eq!(OpenVPNValidator::allowed(), OpenVPNValidator::argument_spec_names());
}

#[test]
fn dev_and_dev_type() {
    en();
    for d in ["dev tun", "dev tap", "dev utun", "dev utun7", "dev tun0", "dev tap3", "dev-type tun", "dev-type tap"] {
        ok(d);
    }
    for d in [
        "dev /dev/disk0",
        "dev ../../dev/disk0",
        "dev disk0",
        "dev -x",
        "dev tun extra",
        "dev",
        "dev \"/dev/rdisk0\"",
        "dev-type null",
        "dev-type /dev/x",
        "setenv opt dev /dev/disk0",
    ] {
        bad(d);
    }
}

#[test]
fn remote_proto_port() {
    en();
    for d in [
        "remote vpn.example.com",
        "remote 1.2.3.4 1194",
        "remote x 443 tcp",
        "remote x 1194 udp4",
        "remote fd00::1 1194 udp6",
        "proto tcp-client",
        "port 1194",
        "lport 0",
        "rport 65535",
    ] {
        ok(d);
    }
    for d in [
        "remote -x 1194",
        "remote x 99999",
        "remote x 1194 icmp",
        "remote x 1194 udp extra",
        "remote /tmp/x",
        "proto bogus",
        "port abc",
        "lport 70000",
        "rport",
    ] {
        bad(d);
    }
}

#[test]
fn ciphers_and_auth() {
    en();
    for d in [
        "cipher AES-256-GCM",
        "data-ciphers AES-256-GCM:AES-128-GCM:?CHACHA20-POLY1305",
        "data-ciphers-fallback AES-256-CBC",
        "auth SHA512",
        "auth none",
        "tls-cipher DEFAULT:@SECLEVEL=0",
        "tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384",
        "tls-groups X25519:secp256r1",
        "tls-version-min 1.2 or-highest",
    ] {
        ok(d);
    }
    for d in ["cipher /etc/passwd", "cipher -x", "auth a b", "data-ciphers", "tls-version-min 1.2 or-lowest"] {
        bad(d);
    }
}

#[test]
fn numeric_options() {
    en();
    for d in [
        "verb 3",
        "mute 20",
        "ping 10",
        "ping-restart 60",
        "ping-exit 120",
        "keepalive 10 60",
        "reneg-sec 0",
        "tun-mtu 1500",
        "mssfix 1450",
        "mssfix",
        "connect-retry 5 300",
        "inactive 3600",
    ] {
        ok(d);
    }
    for d in ["verb 99", "verb x", "mute -1", "ping x", "keepalive 10", "keepalive a b"] {
        bad(d);
    }
}

#[test]
fn routes_and_redirect() {
    en();
    for d in [
        "route 10.0.0.0 255.0.0.0",
        "route 10.0.0.0 255.0.0.0 vpn_gateway 5",
        "route remote_host 255.255.255.255 net_gateway",
        "route-ipv6 2000::/3",
        "route-ipv6 ::/0 default 10",
        "ifconfig 10.8.0.2 10.8.0.1",
        "ifconfig-ipv6 fd00::2/64 fd00::1",
        "redirect-gateway def1 bypass-dhcp",
        "redirect-gateway ipv6 !ipv4",
        "redirect-gateway",
        "route-gateway dhcp",
    ] {
        ok(d);
    }
    for d in [
        "route /etc/x",
        "route 10.0.0.0 /x",
        "redirect-gateway /tmp/x",
        "redirect-gateway evil",
        "ifconfig a b",
        "route-ipv6 ../x",
        "route-gateway /x",
    ] {
        bad(d);
    }
}

#[test]
fn quoted_text_arguments() {
    en();
    for d in [
        "verify-x509-name \"C=US, O=Example, CN=vpn\" subject",
        "verify-x509-name vpn.example.com name",
        "verify-x509-name 'vpn' name-prefix",
        "verify-x509-name CN=us1234.nordvpn.com",
        "pull-filter ignore \"route-ipv6\"",
        "pull-filter reject \"dhcp-option DNS\"",
        "static-challenge \"Enter Google Authenticator Code\" 1",
        "dhcp-option DNS 1.1.1.1",
        "dhcp-option DOMAIN corp.example",
        "remote-cert-tls server",
        "remote-cert-eku \"TLS Web Server Authentication\"",
    ] {
        ok(d);
    }
    for d in [
        "verify-x509-name x bogus",
        "pull-filter allow x",
        "pull-filter ignore",
        "static-challenge \"x\" 5",
        "dhcp-option EVIL x",
        "dhcp-option DNS /etc/x",
        "verify-x509-name \"unterminated",
        "remote-cert-tls both",
    ] {
        bad(d);
    }
}

#[test]
fn proxies() {
    en();
    for d in [
        "http-proxy proxy.example 8080",
        "http-proxy p 8080 auto",
        "http-proxy p 8080 [inline] basic",
        "socks-proxy p 1080",
        "socks-proxy p",
    ] {
        ok(d);
    }
    for d in ["http-proxy -p 8080", "http-proxy p port", "http-proxy p 8080 auto bogus", "socks-proxy p x"] {
        bad(d);
    }
}

#[test]
fn backslash_comments_and_extra_args() {
    en();
    bad("dev tu\\n");
    bad("cipher \"AES\\\"");
    ok("remote b 1194 # backup server");
    ok("remote b 1194 ; backup server");
    bad("persist-key now");
    bad("client yes");
}

#[test]
fn messages_name_the_directive_not_the_value() {
    en();
    assert_eq!(ovpn("dev /dev/SECRET42\n")[0].message, "Invalid argument: dev");
    assert_eq!(ovpn("keepalive 10\n")[0].message, "Wrong number of arguments: keepalive");
    assert!(!ovpn("verify-x509-name SECRET42 bogus\n")[0].display().contains("SECRET42"));
}

pub const NORD: &str = "client
dev tun
proto udp
remote 185.1.2.3 1194
resolv-retry infinite
remote-random
nobind
tun-mtu 1500
tun-mtu-extra 32
mssfix 1450
persist-key
persist-tun
ping 15
ping-restart 0
ping-timer-rem
reneg-sec 0
comp-lzo no
verify-x509-name CN=us1234.nordvpn.com
remote-cert-tls server
auth-user-pass
verb 3
pull
fast-io
cipher AES-256-CBC
auth SHA512
<ca>
X
</ca>
key-direction 1
<tls-auth>
X
</tls-auth>";

const PIA: &str = "client
dev tun
proto udp
remote us-east.privacy.network 1198
resolv-retry infinite
nobind
persist-key
persist-tun
cipher aes-128-cbc
auth sha1
tls-client
remote-cert-tls server
auth-user-pass
compress
verb 1
reneg-sec 0
disable-occ
<crl-verify>
X
</crl-verify>
<ca>
X
</ca>";

const PFSENSE: &str = "dev tun
persist-tun
persist-key
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-CBC
auth SHA256
tls-client
client
resolv-retry infinite
remote 203.0.113.1 1194 udp4
nobind
verify-x509-name \"pfSense-server-cert\" name
auth-user-pass
remote-cert-tls server
explicit-exit-notify
lport 0
<ca>
X
</ca>
setenv opt block-outside-dns
<tls-crypt>
X
</tls-crypt>";

const PROTON: &str = "client
dev tun
proto udp
remote 185.159.1.1 80
remote 185.159.1.1 51820
remote-random
resolv-retry infinite
nobind
cipher AES-256-GCM
setenv CLIENT_CERT 0
tun-mtu 1500
mssfix 0
persist-key
persist-tun
reneg-sec 0
remote-cert-tls server
auth-user-pass
pull
fast-io
<ca>
X
</ca>
<tls-crypt>
X
</tls-crypt>";

const ACCESS_SERVER: &str = "client
server-poll-timeout 4
nobind
remote vpn.example.com 1194 udp
remote vpn.example.com 443 tcp
dev tun
dev-type tun
remote-cert-tls server
tls-version-min 1.2
reneg-sec 604800
tun-mtu 1420
auth-user-pass
verb 3
push-peer-info
static-challenge \"Enter Authenticator Code\" 1
setenv opt tls-cipher DEFAULT:@SECLEVEL=0
ignore-unknown-option block-outside-dns
block-outside-dns
<ca>
X
</ca>
key-direction 1
<tls-auth>
X
</tls-auth>";

#[test]
fn realistic_provider_profiles() {
    en();
    for (name, profile) in
        [("nord", NORD), ("pia", PIA), ("pfsense", PFSENSE), ("proton", PROTON), ("access server", ACCESS_SERVER)]
    {
        assert_eq!(ovpn_args(profile), [], "{name}");
    }
}

// MARK: <connection>

#[test]
fn connection_block_satisfies_remote() {
    en();
    let text = "client\ndev tun\n<connection>\nremote a 1194 udp\nnobind\n</connection>\n<connection>\nremote b 443 tcp\n</connection>\n";
    assert_eq!(ovpn_all(text), []);
}

#[test]
fn connection_inner_lines_are_validated() {
    en();
    let text = "client\n<connection>\nremote a 1194\nup /tmp/x\ndev /dev/disk0\nca [inline]\nport x\n# comment\n</connection>\n";
    let issues = ovpn_all(text);
    assert_eq!(lines(&issues), [4, 5, 6, 7]);
    assert!(issues[0].message.starts_with("Forbidden directive: up"));
    assert_eq!(issues[2].message, "Directive not allowed in a <connection> block: ca");
}

#[test]
fn connection_invalid_remote_does_not_satisfy() {
    en();
    assert_eq!(lines(&ovpn_all("client\n<connection>\nremote -x 1194\n</connection>\n")), [3, 0]);
}

#[test]
fn connection_nested_blocks() {
    en();
    // Only the inline block of a connection option may be in it; no other block and no nested <connection>.
    let allowed = "<connection>\nremote a 1\nhttp-proxy p 8080 [inline]\n<http-proxy-user-pass>\nu\np\n</http-proxy-user-pass>\n</connection>\n";
    assert_eq!(ovpn_all(allowed), []);
    let ca = "<connection>\nremote a 1\n<ca>\nup /x\n</ca>\n</connection>\n";
    assert_eq!(lines(&ovpn_all(ca)), [3]);
    let nested = "<connection>\nremote a 1\n<connection>\nremote b 1\n</connection>\n</connection>\n";
    assert!(!ovpn_all(nested).is_empty());
    assert!(lines(&ovpn_all(nested)).contains(&3));
}

#[test]
fn connection_unclosed_and_bad_close() {
    en();
    assert_eq!(messages(&ovpn_all("<connection>\nremote a 1\n")), ["Unclosed inline block: connection"]);
    assert_eq!(lines(&ovpn_all("remote a 1\n<connection>\nremote a 1\n</ca>\n</connection>\n")), [4]);
}

// MARK: WireGuard values

const PRIVATE_KEY: &str = "bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=";
const PUBLIC_KEY: &str = "bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=";

fn wg(interface: &[&str], peer: &[&str]) -> Vec<ValidationIssue> {
    let private = format!("PrivateKey = {PRIVATE_KEY}");
    let public = format!("PublicKey = {PUBLIC_KEY}");
    let mut parts: Vec<&str> = vec!["[Interface]", &private];
    parts.extend(interface);
    parts.extend(["[Peer]", &public, "AllowedIPs = 0.0.0.0/0"]);
    parts.extend(peer);
    // The shared (macOS) rules on every host: the Windows tier (`FwMark`, `Table`) has its own tests.
    macvpn_core::validators::WireGuardValidator.validate_for(macvpn_core::target_os::TargetOs::MacOs, &parts.join("\n"))
}

#[test]
fn wireguard_valid_values() {
    en();
    let psk = format!("PresharedKey = {PUBLIC_KEY}");
    assert_eq!(
        wg(
            &[
                "Address = 10.0.0.2/32, fd00::2/128",
                "DNS = 1.1.1.1, 2606:4700::1111, corp.example",
                "MTU = 1420",
                "ListenPort = 51820",
                "Table = off",
                "FwMark = 0x1234"
            ],
            &[
                "Endpoint = vpn.example.com:51820",
                "PersistentKeepalive = 25",
                &psk,
                "AllowedIPs = 10.0.0.0/8,192.168.1.0/24, ::/0"
            ]
        ),
        []
    );
    assert_eq!(
        wg(
            &["Table = auto", "Table = 1234", "FwMark = off", "FwMark = 51820", "Address = 10.0.0.2"],
            &["Endpoint = [2001:db8::1]:51820", "Endpoint = 203.0.113.5:1", "PersistentKeepalive = off"]
        ),
        []
    );
}

#[test]
fn wireguard_invalid_values() {
    en();
    let long_private = format!("PrivateKey = {PRIVATE_KEY}x");
    let interface_cases = [
        "Address = 10.0.0.2/33",
        "Address = 10.0.0.256/32",
        "Address = -x",
        "Address = /etc/x",
        "Address =",
        "DNS = -1.1.1.1",
        "DNS = a/b",
        "MTU = 70000",
        "MTU = x",
        "ListenPort = 65536",
        "ListenPort = -1",
        "Table = maybe",
        "FwMark = 0xZZ",
        "FwMark = 0x123456789",
        "PrivateKey = short",
        &long_private,
    ];
    for c in interface_cases {
        assert_eq!(lines(&wg(&[c], &[])), [3], "{c}");
    }
    let short_psk = format!("PresharedKey = {}", &PUBLIC_KEY[..PUBLIC_KEY.len() - 1]);
    let peer_cases = [
        "Endpoint = vpn.example.com",
        "Endpoint = vpn.example.com:0",
        "Endpoint = -x:1",
        "Endpoint = [::1:1",
        "Endpoint = a b:1",
        "PersistentKeepalive = 70000",
        "AllowedIPs = 0.0.0.0/0, x",
        "PublicKey = -abc",
        &short_psk,
    ];
    for c in peer_cases {
        assert_eq!(lines(&wg(&[], &[c])), [6], "{c}");
    }
    assert_eq!(wg(&["MTU = 70000"], &[])[0].message, "Invalid value: mtu");
}

// MARK: strongSwan allowlist

/// `connections { c { <conn> local { <local> } remote { <remote> } children { n { <child> } } } }` + extra.
fn swan(conn: &str, local: &str, remote: &str, child: &str, extra: &str) -> String {
    format!(
        "connections {{\n  c {{\n    remote_addrs = vpn.example.com\n    {conn}\n    local {{\n      auth = eap-mschapv2\n      {local}\n    }}\n    remote {{\n      auth = pubkey\n      {remote}\n    }}\n    children {{\n      n {{\n        remote_ts = 0.0.0.0/0\n        {child}\n      }}\n    }}\n  }}\n}}\n{extra}"
    )
}

fn conn(s: &str) -> String {
    swan(s, "", "", "", "")
}
fn local(s: &str) -> String {
    swan("", s, "", "", "")
}
fn remote(s: &str) -> String {
    swan("", "", s, "", "")
}
fn child(s: &str) -> String {
    swan("", "", "", s, "")
}
fn extra(s: &str) -> String {
    swan("", "", "", "", s)
}

fn swan_lines(text: &str) -> Vec<i64> {
    lines(&swan_all(text))
}

/// `ConfigImporter.template(for: .strongswan)` (Swift; the importer is ported in Task 1.3).
const STRONGSWAN_TEMPLATE: &str = "connections {
  myvpn {
    remote_addrs = vpn.example.com
    vips = 0.0.0.0
    local {
      auth = eap-mschapv2
      eap_id = felhasznalo
    }
    remote {
      auth = pubkey
      id = vpn.example.com
    }
    children {
      myvpn {
        remote_ts = 0.0.0.0/0
      }
    }
  }
}
";

#[test]
fn strongswan_realistic_configs() {
    en();
    let full = swan(
        "version = 2\n    vips = 0.0.0.0,::\n    proposals = aes256-sha256-modp2048, default\n    send_certreq = yes",
        "eap_id = john.smith\n      id = \"C=CH, O=Example, CN=john\"\n      certs = john.pem",
        "id = vpn.example.com\n      cacerts = ca.pem, intermediate.crt\n      revocation = relaxed",
        "esp_proposals = aes256gcm16\n        start_action = none\n        dpd_action = restart",
        "secrets {\n  ike-1 {\n    id = vpn.example.com\n    secret = 0sYWJjZA==\n  }\n}\npools {\n  p {\n    addrs = 10.3.0.0/24\n    dns = 1.1.1.1\n  }\n}\nauthorities {\n  corp {\n    cacert = corp-ca.pem\n    cert_uri_base = http://ca.example/certs\n  }\n}",
    );
    assert_eq!(swan_all(&full), []);
    assert_eq!(swan_all(STRONGSWAN_TEMPLATE), []);
}

#[test]
fn strongswan_value_tokens_named_like_forbidden_keys_are_fine() {
    en();
    // False alarms of the old word-based search: these are values, not keys.
    assert_eq!(swan_lines(&swan("", "id = file", "id = updown.example.com", "label = include", "")), Vec::<i64>::new());
    assert_eq!(swan_lines(&local("eap_id = include")), Vec::<i64>::new());
}

#[test]
fn strongswan_path_keys_only_take_file_names() {
    en();
    for value in ["/etc/master.passwd", "../../../etc/master.passwd", ".hidden", "a/b.pem", "ok.pem, /etc/x"] {
        assert_eq!(swan_lines(&local(&format!("certs = {value}"))), [7], "{value}");
        assert_eq!(swan_lines(&remote(&format!("cacerts = {value}"))), [11], "{value}");
        assert_eq!(swan_lines(&local(&format!("pubkeys = \"{value}\""))), [7], "{value}");
        assert_eq!(
            swan_lines(&extra(&format!("authorities {{\n  a {{\n    cacert = {value}\n  }}\n}}"))),
            [23],
            "{value}"
        );
    }
    assert_eq!(swan_all(&local("certs = /etc/x"))[0].message, "Only a file name is allowed, no path: certs");
}

#[test]
fn strongswan_forbidden_keys() {
    en();
    assert_eq!(swan_lines(&child("updown = /tmp/x")), [16]);
    assert_eq!(swan_lines(&local("cert-1 {\n        file = /etc/x\n      }")), [8]);
    assert_eq!(
        swan_lines(&extra(
            "authorities {\n  a {\n    crl_uris = http://x/crl\n    ocsp_uris = http://x/ocsp\n    file = /etc/x\n  }\n}"
        )),
        [23, 24, 25]
    );
    assert_eq!(swan_lines(&extra("secrets {\n  private-1 {\n    file = /etc/key\n  }\n}")), [23]);
    assert_eq!(swan_lines(&conn("include /etc/x")), [4]);
    assert_eq!(swan_all(&child("updown = /tmp/x"))[0].message, "Forbidden key: updown");
}

#[test]
fn strongswan_file_uris_rejected() {
    en();
    assert_eq!(swan_lines(&extra("authorities {\n  a {\n    cert_uri_base = file:///etc/\n  }\n}")), [23]);
    assert_eq!(swan_lines(&remote("id = \"FILE:/etc/x\"")), [11]);
}

#[test]
fn strongswan_unknown_keys_and_sections_are_denied() {
    en();
    assert_eq!(swan_lines(&conn("foo = bar")), [4]);
    assert_eq!(swan_lines(&local("remote_ts = 0.0.0.0/0")), [7]); // right key, wrong section
    assert_eq!(swan_lines(&extra("evil {\n  x = y\n}")), [21]);
    assert_eq!(swan_lines(&child("sub {\n        x = y\n        }")), [16]);
    assert_eq!(swan_all(&conn("foo = bar"))[0].message, "Key not allowed");
    assert_eq!(swan_all(&local("remote_ts = 1"))[0].message, "Key not allowed: remote_ts");
    assert_eq!(swan_all(&extra("children {\n}"))[0].message, "Section not allowed: children");
}

#[test]
fn strongswan_braces_are_tracked() {
    en();
    assert_eq!(swan_lines(&extra("}")), [21]);
    assert_eq!(swan_lines("connections {\n  c {\n    children {\n      n {\n      }\n    }\n"), [2, 1]);
}

#[test]
fn strongswan_ambiguous_values_rejected() {
    en();
    // A standalone `=` or `{` in a value is suspicious (attempted key smuggling), so an error.
    assert_eq!(swan_lines(&child("esp_proposals = \"x\" updown = /tmp/x")), [16]);
    assert_eq!(swan_lines(&child("esp_proposals = a{b")), [16]);
    assert_eq!(swan_lines(&local("id = CN=vpn.example.com")), Vec::<i64>::new());
}

/// Parity-review hardening: a connection or child name may not start with `-` (it is passed to `swanctl
/// --initiate`), and `names()` never returns one.
#[test]
fn strongswan_names_cannot_start_with_a_dash() {
    use macvpn_core::validators::StrongSwanValidator;
    lang(AppLanguage::En);
    let conn = "connections {\n  -c {\n    remote_addrs = vpn.example.com\n    children {\n      n { remote_ts = 0.0.0.0/0 }\n    }\n  }\n}\n";
    let issues = swan_all(conn);
    // The rejected connection's content is not checked further, so its children block does not count (line 0).
    assert_eq!(lines(&issues), [2, 0]);
    assert_eq!(issues[0].message, "A connection or child name must not start with \"-\"");
    assert_eq!(StrongSwanValidator::names(conn), None);
    let child = "connections {\n  c {\n    remote_addrs = vpn.example.com\n    children {\n      --child { remote_ts = 0.0.0.0/0 }\n    }\n  }\n}\n";
    assert_eq!(lines(&swan_all(child)), [5]);
    assert_eq!(StrongSwanValidator::names(child), None);
    lang(AppLanguage::Hu);
    assert_eq!(swan_all(child)[0].message, "A kapcsolat és a child neve nem kezdődhet „-” jellel");
    // A dash inside the name is still fine.
    let ok = "connections {\n  my-vpn {\n    remote_addrs = vpn.example.com\n    children {\n      net-1 { remote_ts = 0.0.0.0/0 }\n    }\n  }\n}\n";
    assert_eq!(swan_all(ok), []);
    assert_eq!(StrongSwanValidator::names(ok), Some(("my-vpn".to_string(), "net-1".to_string())));
}
