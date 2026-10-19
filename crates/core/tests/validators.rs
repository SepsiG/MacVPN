//! Port of `ValidatorsTests.swift` (Hungarian messages: the language is fixed, not the machine's locale).

mod common;

use common::*;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::ValidationIssue;
use macvpn_core::validators::{OpenVPNValidator, StrongSwanValidator};

const GOOD_OVPN: &str = "client
dev tun
remote vpn.example.com 1194
auth-user-pass
tls-auth [inline] 1
<ca>
up /tmp/evil.sh
</ca>
# up /tmp/commented.sh
; script-security 3";

const GOOD_WG: &str = "[Interface]
PrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=
Address = 10.0.0.2/32
# PostUp = rm -rf /

[Peer]
PublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:51820";

const GOOD_SWAN: &str = "connections {
  office {
    remote_addrs = vpn.example.com
    local { auth = eap-mschapv2 }
    children {
      office-net { remote_ts = 0.0.0.0/0 }
    }
  }
}";

fn hu() {
    lang(AppLanguage::Hu);
}

fn ovpn(body: &str) -> Vec<ValidationIssue> {
    ovpn_all(&format!("remote a 1\n{body}"))
}

#[test]
fn openvpn_accepts_inline_and_comments() {
    hu();
    assert_eq!(ovpn_all(GOOD_OVPN), []);
}

#[test]
fn openvpn_rejects_every_forbidden_directive() {
    hu();
    for d in macvpn_core::validators::openvpn::FORBIDDEN.iter() {
        let issues = ovpn_all(&format!("remote a 1\n  {} x\n", d.to_uppercase()));
        assert_eq!(lines(&issues), [2], "not forbidden: {d}");
    }
}

#[test]
fn openvpn_rejects_double_dash_form() {
    hu();
    assert_eq!(lines(&ovpn_all("remote a\n--up /x\n")), [2]);
}

#[test]
fn openvpn_rejects_external_files() {
    hu();
    assert_eq!(lines(&ovpn_all("remote a\nca ca.crt\nauth-user-pass creds.txt\n")), [2, 3]);
}

#[test]
fn openvpn_requires_remote() {
    hu();
    assert_eq!(lines(&ovpn_all("client\n")), [0]);
}

#[test]
fn wireguard_accepts_valid() {
    hu();
    assert_eq!(wg_all(GOOD_WG), []);
}

#[test]
fn wireguard_rejects_hooks() {
    hu();
    for key in ["PreUp", "postup", "PreDown", "PostDown", "SaveConfig"] {
        let text = GOOD_WG.replace("Address = 10.0.0.2/32", &format!("{key} = echo hi"));
        assert_eq!(lines(&wg_all(&text)), [3], "not forbidden: {key}");
    }
}

#[test]
fn wireguard_requires_sections() {
    hu();
    assert_eq!(lines(&wg_all("[Interface]\nAddress = 1.2.3.4/32\n")), [0, 0]);
}

#[test]
fn strongswan_accepts_valid() {
    hu();
    assert_eq!(swan_all(GOOD_SWAN), []);
}

#[test]
fn strongswan_rejects_updown_include_file() {
    hu();
    let text = format!("{GOOD_SWAN}\ninclude /etc/x.conf\nsecrets {{\n  private {{ file = /etc/key }}\n}}\n");
    let with_updown = text.replace("remote_ts = 0.0.0.0/0", "updown = /tmp/x");
    assert_eq!(lines(&swan_all(&with_updown)), [6, 10, 12]);
}

#[test]
fn strongswan_requires_connections_and_children() {
    hu();
    assert_eq!(lines(&swan_all("secrets {\n}\n")), [0, 0]);
}

#[test]
fn strongswan_extracts_names() {
    hu();
    let names = StrongSwanValidator::names(GOOD_SWAN);
    assert_eq!(names, Some(("office".to_string(), "office-net".to_string())));
}

// MARK: Hardening regressions

#[test]
fn openvpn_rejects_bad_closing_tag() {
    hu();
    assert_eq!(lines(&ovpn("<ca>\nX\n</ca>x\nscript-security 2\nup /tmp/e.sh\n")), [4, 5, 6]);
}

#[test]
fn openvpn_rejects_quoted_directives() {
    hu();
    assert_eq!(lines(&ovpn("\"script-security\" 2\n\"up\" /tmp/e.sh\n")), [2, 3]);
    assert_eq!(lines(&ovpn("script-securit\\y 2\n")), [2]);
}

#[test]
fn openvpn_rejects_control_characters() {
    hu();
    assert_eq!(lines(&ovpn("up\u{0B}/tmp/e.sh\n")), [2]);
    assert_eq!(lines(&ovpn("<ca>\nX\u{01}\n</ca>\n")), [3]);
    assert_eq!(lines(&ovpn("dev\u{7F}tun\n")), [2]);
}

#[test]
fn openvpn_rejects_new_forbidden_and_unknown() {
    hu();
    assert!(ovpn("pkcs11-providers /tmp/evil.dylib\n")[0].message.starts_with("Tiltott"));
    assert_eq!(ovpn("foo-bar 1\n")[0].message, "Kockázatos direktíva, tudomásulvétel szükséges: foo-bar");
}

#[test]
fn openvpn_rejects_unknown_block_and_skips_content() {
    hu();
    assert_eq!(lines(&ovpn("<up>\n/tmp/e.sh\n</up>\n")), [2]);
}

#[test]
fn openvpn_rejects_unclosed_block() {
    hu();
    assert_eq!(messages(&ovpn("<ca>\nX\n")), ["Lezáratlan inline blokk: ca"]);
}

#[test]
fn openvpn_allows_quoted_arguments() {
    hu();
    assert_eq!(ovpn("verify-x509-name \"CN=vpn\" name\n"), []);
}

#[test]
fn strongswan_rejects_hash_in_quotes_bypass() {
    hu();
    // Default-deny: the unknown `x` section (line 10) is an error too; the point is that line 11's updown does not slip through.
    let text = format!("{GOOD_SWAN}\nx {{\n  esp_proposals = \"#\" }} net2 {{ updown = /tmp/x\n}}\n");
    assert!(lines(&swan_all(&text)).contains(&11));
}

#[test]
fn strongswan_rejects_include_anywhere() {
    hu();
    let text = format!("{GOOD_SWAN}\nnet {{ include /tmp/e.conf\n}}\n");
    assert_eq!(lines(&swan_all(&text)), [10]);
}

#[test]
fn strongswan_rejects_control_characters() {
    hu();
    let text = GOOD_SWAN.replace("remote_addrs", "remote\u{0B}_addrs");
    assert_eq!(lines(&swan_all(&text)), [3]);
}

#[test]
fn strongswan_ignores_equals_in_quotes() {
    hu();
    let text = GOOD_SWAN.replace("remote_addrs = vpn.example.com", "proposals = \"a=b\"");
    assert_eq!(swan_all(&text), []);
}

#[test]
fn wireguard_rejects_control_unknown_key_and_section() {
    hu();
    let ctrl = GOOD_WG.replace("Address = 10.0.0.2/32", "\u{0B}PostUp = id");
    assert_eq!(lines(&wg_all(&ctrl)), [3]);
    let foo = GOOD_WG.replace("Address = 10.0.0.2/32", "Foo = 1");
    assert_eq!(lines(&wg_all(&foo)), [3]);
    let evil = format!("{GOOD_WG}\n[Evil]\nAddress = 1\n");
    assert_eq!(lines(&wg_all(&evil)), [10, 11]);
    let no_eq = GOOD_WG.replace("Address = 10.0.0.2/32", "garbage");
    assert_eq!(lines(&wg_all(&no_eq)), [3]);
    let outside = format!("Address = 1\n{GOOD_WG}");
    assert_eq!(lines(&wg_all(&outside)), [1]);
}

#[test]
fn strongswan_rejects_backslash() {
    hu();
    let text = format!("{GOOD_SWAN}\nx = \"a\\\" # y\n");
    assert_eq!(lines(&swan_all(&text)), [10]);
}

#[test]
fn strongswan_rejects_include_as_key() {
    hu();
    let text = format!("{GOOD_SWAN}\nnet {{ include=/tmp/e.conf }}\n");
    assert_eq!(lines(&swan_all(&text)), [10]);
}

#[test]
fn strongswan_rejects_unbalanced_quote_bypass() {
    hu();
    let text = "connections {\n office {\n  remote_addrs = v\n  children {\n   net { esp_proposals = \"aes\nx\" } n2 { a = \"#\" } n3 { updown = /tmp/x }\n  }\n }\n}\n";
    let l = lines(&swan_all(text));
    assert!(l.contains(&5) || l.contains(&6), "{l:?}");
    let text2 = format!("{GOOD_SWAN}\nnet {{ esp_proposals = \"x\" updown = /tmp/x }}\n");
    assert!(lines(&swan_all(&text2)).contains(&10));
}

#[test]
fn strongswan_quoted_values_still_fine() {
    hu();
    let text = GOOD_SWAN.replace("remote_addrs = vpn.example.com", "remote_addrs = \"file # updown\" # c");
    assert_eq!(swan_all(&text), []);
}

const ACCESS_SERVER: &str = "client
dev tun
remote x 1194 udp
nobind
setenv FORWARD_COMPATIBLE 1
setenv UV_ID abc123
setenv PUSH_PEER_INFO
auth-user-pass
remote-cert-tls server
cipher AES-256-CBC
verb 3
<ca>
-----BEGIN CERTIFICATE-----
</ca>
<tls-crypt>
KEY
</tls-crypt>";

const PROVIDER: &str = "client
dev tun
proto udp
remote a 1194
remote b 1194
remote-random
resolv-retry infinite
nobind
persist-key
persist-tun
ping-timer-rem
setenv CLIENT_CERT 0
setenv opt block-outside-dns
<crl-verify>
X
</crl-verify>
<ca>
X
</ca>";

#[test]
fn openvpn_accepts_realistic_profiles() {
    hu();
    assert_eq!(ovpn_all(ACCESS_SERVER), []);
    assert_eq!(ovpn_all(PROVIDER), []);
}

#[test]
fn openvpn_setenv_and_http_proxy_negatives() {
    hu();
    assert_eq!(lines(&ovpn("setenv BASH_ENV /tmp/x\n")), [2]);
    assert_eq!(lines(&ovpn("setenv opt up /x\n")), [2]);
    assert_eq!(lines(&ovpn("setenv opt ca /x\n")), [2]);
    assert_eq!(lines(&ovpn("setenv\n")), [2]);
    assert_eq!(lines(&ovpn("setenv opt\n")), [2]);
    assert_eq!(lines(&ovpn("http-proxy p 8080 /etc/creds\n")), [2]);
    assert_eq!(ovpn("http-proxy p 8080 auto\nhttp-proxy p 8080\n"), []);
    assert!(ovpn("up /x\n")[0].message.ends_with("töröld vagy tedd megjegyzésbe (#) a sort"));
}

#[test]
fn openvpn_socks_proxy_authfile() {
    hu();
    assert_eq!(lines(&ovpn("socks-proxy p 1080 /etc/creds\n")), [2]);
    assert_eq!(lines(&ovpn("socks-proxy p 1080 creds.txt\n")), [2]);
    assert_eq!(ovpn("socks-proxy p 1080 [inline]\nsocks-proxy p 1080\nsocks-proxy p\n"), []);
}

/// Messages may never quote raw config content (the root validator's output reaches the user).
#[test]
fn issues_never_echo_raw_content() {
    hu();
    let secret = "SECRET123";
    let cases = [
        format!("abc={secret}"),
        format!("x{secret}=1"),
        format!("ab c={secret}"),
        format!("\"up\" {secret}"),
        format!("setenv abc={secret} x"),
        format!("setenv opt abc={secret}"),
        format!("<ca={secret}>"),
        format!("[{secret}]"),
        format!("a\u{0B}{secret}"),
        format!("{secret}!=1"),
        format!("socks-proxy p 1 {secret}"),
        format!("http-proxy p 1 {secret}"),
        format!("ca {secret}"),
        format!("include {secret}"),
        format!("updown = {secret}"),
        format!("x = \"{secret}"),
        format!("a\\{secret}"),
    ];
    for line in &cases {
        let mut all = ovpn_all(&format!("remote a 1\n{line}\n"));
        all.extend(wg_all(&format!("{GOOD_WG}\n{line}\n")));
        all.extend(swan_all(&format!("{GOOD_SWAN}\n{line}\n")));
        for issue in all {
            assert!(!issue.display().contains(secret), "quoted: {line} -> {}", issue.display());
        }
    }
    // Names of the allowed character set are still shown.
    assert!(ovpn("setenv LD_PRELOAD x\n")[0].message.starts_with("Nem engedélyezett setenv: LD_PRELOAD"));
    assert!(ovpn("setenv a=b x\n")[0].message.starts_with("Nem engedélyezett setenv – "));
    let wg = wg_all(&GOOD_WG.replace("Address = 10.0.0.2/32", "a b = 1"));
    assert_eq!(wg[0].message, "Nem engedélyezett kulcs");
}

#[test]
fn validator_for_kind() {
    use macvpn_core::models::VPNKind;
    use macvpn_core::validators::validator;
    for kind in [VPNKind::Openvpn, VPNKind::Wireguard, VPNKind::Strongswan, VPNKind::Sstp] {
        assert!(validator(kind).is_some(), "{kind:?}");
    }
    assert!(validator(VPNKind::L2tp).is_none());
    assert!(validator(VPNKind::Cisco).is_none());
    assert_eq!(validator(VPNKind::Openvpn).unwrap().validate("client\n").len(), 1);
    let _ = OpenVPNValidator;
}
