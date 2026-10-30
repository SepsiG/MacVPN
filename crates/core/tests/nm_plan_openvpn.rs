//! OpenVPN through LinVPN's NM service (L-b Task 7; L0-1's mapping, decision 8).
use macvpn_core::models::{Connection, SecretField, VPNKind};
use macvpn_core::nm_plan::{self, Caps, Input, NmValue, SecretKey, SecretValue};
use std::path::Path;

const CA: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
fn base(extra: &str) -> String {
    format!(
        "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nauth-user-pass\nremote-cert-tls server\ndata-ciphers AES-256-GCM:CHACHA20-POLY1305\n<ca>\n{CA}\n</ca>\n{extra}"
    )
}
fn caps27() -> Caps {
    Caps { openvpn_push_visible: true, ..Caps::default() }
}
fn plan(text: &str, caps: &Caps) -> Result<nm_plan::NmPlan, nm_plan::Unsupported> {
    let c = Connection::new("Office", VPNKind::Openvpn);
    let input = Input {
        connection: &c,
        config: text.as_bytes(),
        user: "linvpn-dev",
        uid: 1001,
        runtime_dir: Path::new("/run/user/1001/linvpn/nm/u"),
        caps,
        client_cert: nm_plan::ImportedCert::None,
    };
    nm_plan::plan(&input)
}
fn data(p: &nm_plan::NmPlan) -> std::collections::BTreeMap<String, String> {
    let NmValue::StrDict(d) = &p.settings["vpn"]["data"] else { panic!() };
    d.clone()
}

#[test]
fn a_password_profile_uses_linvpns_service_and_agent_secrets() {
    let p = plan(&base(""), &caps27()).unwrap();
    assert_eq!(p.service_type, Some(nm_plan::SERVICE_OPENVPN));
    assert_eq!(p.settings["vpn"]["service-type"], NmValue::Str(nm_plan::SERVICE_OPENVPN.into()));
    let d = data(&p);
    assert_eq!(d["connection-type"], "password");
    assert_eq!(d["remote"], "vpn.example.com:1194:udp");
    assert_eq!(d["ca"], "/run/user/1001/linvpn/nm/u/ca.pem");
    assert_eq!(d["password-flags"], "1");
    assert_eq!(d["challenge-response-flags"], "2");
    assert_eq!(d["remote-cert-tls"], "server");
    assert_eq!(d["data-ciphers"], "AES-256-GCM:CHACHA20-POLY1305");
    assert_eq!(d["reneg-seconds"], "3600", "NM's default is 0: set OpenVPN's");
    assert!(d.contains_key("dev") && d["dev"].starts_with("lvo"));
    assert_eq!(d["dev-type"], "tun", "a name OpenVPN cannot type by its prefix needs dev-type");
    assert_eq!(p.iface.as_deref(), Some(d["dev"].as_str()));
    assert_eq!(p.files.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), ["ca.pem"]);
    assert_eq!(&p.files[0].data[..], format!("{CA}\n").as_bytes());
    assert!(p.secrets.iter().any(|s| s.key == SecretKey::Plain("password".into())
        && matches!(s.value, SecretValue::Field(SecretField::Password))));
    assert_eq!(
        p.settings["ipv4"]["never-default"],
        NmValue::Bool(false),
        "server decides: the plugin sends NEVER_DEFAULT"
    );
    assert_eq!(p.settings["ipv6"]["never-default"], NmValue::Bool(false));
    assert_eq!(p.settings["connection"]["type"], NmValue::Str("vpn".into()));
    assert_eq!(p.settings["connection"]["permissions"], NmValue::StrList(vec!["user:linvpn-dev".into()]));
    assert!(
        !p.settings["connection"].contains_key("interface-name"),
        "a VPN's interface-name would bind it to a parent"
    );
    assert!(p.summary.as_deref().is_some_and(|s| s.contains("server decides")), "{:?}", p.summary);
}

#[test]
fn routing_always_and_never_reach_openvpn_through_linvpn_keys() {
    let always = plan(&base("redirect-gateway def1 ipv6\n"), &caps27()).unwrap();
    assert_eq!(data(&always)["linvpn-redirect-gateway"], "def1 ipv6");
    assert_eq!(always.settings["ipv4"]["never-default"], NmValue::Bool(false));
    let never = plan(&base("pull-filter ignore \"redirect-gateway\"\n"), &caps27()).unwrap();
    assert_eq!(data(&never)["linvpn-pull-filter"], "ignore \"redirect-gateway\"");
    assert_eq!(never.settings["ipv4"]["never-default"], NmValue::Bool(true), "belt and braces");
    assert_eq!(never.settings["ipv6"]["never-default"], NmValue::Bool(true));
    let nopull = plan(&base("route-nopull\n"), &caps27()).unwrap();
    assert_eq!(data(&nopull)["linvpn-route-nopull"], "yes");
    assert_eq!(nopull.settings["ipv4"]["ignore-auto-routes"], NmValue::Bool(true));
    assert_eq!(nopull.settings["ipv4"]["ignore-auto-dns"], NmValue::Bool(true));
    let server = plan(&base(""), &caps27()).unwrap();
    let d = data(&server);
    assert!(!d.contains_key("linvpn-redirect-gateway") && !d.contains_key("linvpn-pull-filter"));
    assert!(!d.contains_key("linvpn-route-nopull"));
}

#[test]
fn a_bare_redirect_gateway_passes_def1() {
    let p = plan(&base("redirect-gateway\n"), &caps27()).unwrap();
    assert_eq!(data(&p)["linvpn-redirect-gateway"], "def1");
}

#[test]
fn other_pull_filters_pass_to_openvpn_when_the_service_accepts_them() {
    let p = plan(&base("pull-filter ignore \"route-ipv6\"\npull-filter accept \"route 10.99.\"\n"), &caps27()).unwrap();
    assert_eq!(data(&p)["linvpn-pull-filter"], "ignore \"route-ipv6\"\naccept \"route 10.99.\"");
    assert_eq!(p.settings["ipv4"]["never-default"], NmValue::Bool(false), "not a routing choice");
}

#[test]
fn without_openvpn_2_7_server_decides_is_a_split_tunnel() {
    let p = plan(&base(""), &Caps::default()).unwrap();
    assert_eq!(p.settings["ipv4"]["never-default"], NmValue::Bool(true));
    assert!(p.warnings.iter().any(|w| w.contains("2.7")), "{:?}", p.warnings);
    let full = plan(&base("redirect-gateway def1\n"), &Caps::default()).unwrap();
    assert_eq!(full.settings["ipv4"]["never-default"], NmValue::Bool(false));
    assert!(!full.warnings.iter().any(|w| w.contains("2.7")));
}

#[test]
fn routes_and_dns_from_the_profile_go_to_ipv4() {
    let p = plan(
        &base("route 10.99.20.0 255.255.255.0\nroute 10.99.21.0 255.255.255.0 vpn_gateway\nroute-metric 77\ndhcp-option DNS 10.99.0.53\ndhcp-option DOMAIN lab.test\n"),
        &caps27(),
    )
    .unwrap();
    let NmValue::Routes(r) = &p.settings["ipv4"]["route-data"] else { panic!() };
    assert_eq!((r[0].dest.as_str(), r[0].prefix, r[0].next_hop.as_deref()), ("10.99.20.0", 24, None));
    assert_eq!((r[1].dest.as_str(), r[1].next_hop.as_deref()), ("10.99.21.0", None));
    assert_eq!(p.settings["ipv4"]["route-metric"], NmValue::I64(77));
    assert_eq!(p.settings["ipv4"]["dns-data"], NmValue::StrList(vec!["10.99.0.53".into()]));
    assert_eq!(p.settings["ipv4"]["dns-search"], NmValue::StrList(vec!["~lab.test".into()]));
}

#[test]
fn ipv6_routes_gateways_metrics_and_the_2_6_dns_option() {
    let p = plan(
        &base("route 192.0.2.0 255.255.255.0 10.8.0.1 5\nroute-ipv6 2001:db8::/32\ndns server 0 address 10.99.0.53 2001:db8::53\ndns server 0 resolve-domains corp.example.com\ndhcp-option DNS6 2001:db8::54\n"),
        &caps27(),
    )
    .unwrap();
    let NmValue::Routes(r) = &p.settings["ipv4"]["route-data"] else { panic!() };
    assert_eq!((r[0].next_hop.as_deref(), r[0].metric), (Some("10.8.0.1"), Some(5)));
    let NmValue::Routes(r6) = &p.settings["ipv6"]["route-data"] else { panic!() };
    assert_eq!((r6[0].dest.as_str(), r6[0].prefix), ("2001:db8::", 32));
    assert_eq!(p.settings["ipv4"]["dns-data"], NmValue::StrList(vec!["10.99.0.53".into()]));
    assert_eq!(p.settings["ipv6"]["dns-data"], NmValue::StrList(vec!["2001:db8::53".into(), "2001:db8::54".into()]));
    assert_eq!(p.settings["ipv4"]["dns-search"], NmValue::StrList(vec!["~corp.example.com".into()]));
}

#[test]
fn a_full_tunnel_takes_every_dns_query() {
    let p = plan(&base("redirect-gateway def1\ndhcp-option DOMAIN corp.example.com\n"), &caps27()).unwrap();
    assert_eq!(p.settings["ipv4"]["dns-search"], NmValue::StrList(vec!["corp.example.com".into(), "~.".into()]));
    assert_eq!(p.settings["ipv4"]["dns-priority"], NmValue::I32(nm_plan::dns::FULL_PRIORITY));
}

#[test]
fn the_static_challenge_answers_the_packed_password() {
    let p = plan(&base("static-challenge \"Enter code\" 1\n"), &caps27()).unwrap();
    let d = data(&p);
    assert!(!d.contains_key("static-challenge"), "NM-openvpn has no such key");
    assert!(p.secrets.iter().any(|s| s.key == SecretKey::Plain("password".into())));
}

#[test]
fn the_eight_linux_refusals_are_reasons_not_invalid_configs() {
    for (extra, needle) in [
        ("peer-fingerprint AB:CD\n", "peer-fingerprint"),
        ("verify-hash AB:CD\n", "verify-hash"),
        ("remote-cert-ku a0\n", "remote-cert-ku"),
        ("remote-cert-eku \"TLS Web Server Authentication\"\n", "remote-cert-eku"),
        ("route 203.0.113.0 255.255.255.0 net_gateway\n", "net_gateway"),
        ("route-ipv6 2001:db8::/32 remote_host\n", "remote_host"),
        // Deviation from the plan's table: the merged service passes any text of `[A-Za-z0-9 _.:/-]{1,64}`
        // (e.g. "ifconfig"), so only a text outside that rule is a refusal.
        ("pull-filter ignore \"dhcp-option PROXY_HTTP=x\"\n", "pull-filter"),
        ("compress stub-v2\n", "compress"),
        ("<connection>\nremote a.example.com 1194\nconnect-retry 5\n</connection>\n", "<connection>"),
        ("<peer-fingerprint>\nAB:CD\n</peer-fingerprint>\n", "peer-fingerprint"),
    ] {
        let e = plan(&base(extra), &caps27()).unwrap_err();
        assert!(!e.invalid_config, "{extra}");
        assert!(
            e.reasons.iter().any(|r| r.contains(needle) && r.starts_with("Not supported on Linux")),
            "{extra}: {:?}",
            e.reasons
        );
    }
}

#[test]
fn more_pull_filters_than_the_service_takes_are_refused() {
    let many: String = (0..17).map(|i| format!("pull-filter ignore \"route 10.{i}.\"\n")).collect();
    let e = plan(&base(&many), &caps27()).unwrap_err();
    assert!(e.reasons.iter().any(|r| r.contains("pull-filter")), "{:?}", e.reasons);
}

#[test]
fn an_invalid_config_is_the_validators_issue() {
    let e = plan(&base("up /bin/sh\n"), &caps27()).unwrap_err();
    assert!(e.invalid_config);
}

/// A name NetworkManager drops is the validator's RISKY finding on Linux (Task 6), so the plan does not say it again;
/// the names the validator keeps SAFE are no-ops and silent too. The warning names only what the tiers cannot see:
/// arguments and routes NM cannot express.
#[test]
fn ignored_directives_are_said_once() {
    let p = plan(
        &base("sndbuf 393216\nfast-io\nnobind\npersist-key\npersist-tun\nlport 0\nverb 3\nblock-outside-dns\nredirect-private\n"),
        &caps27(),
    )
    .unwrap();
    assert!(!p.warnings.iter().any(|w| w.starts_with("Ignored by NetworkManager on Linux")), "{:?}", p.warnings);
    assert_eq!(data(&p)["linvpn-verb"], "3", "the profile's verb reaches the journal");

    let p = plan(
        &base("redirect-gateway def1 block-local\ndns server 0 address 10.99.0.53\ndns server 0 dnssec yes\ndns server 0 transport DoT\ndns server 0 sni dns.example.com\nroute vpn.example.com\n"),
        &caps27(),
    )
    .unwrap();
    let w = p.warnings.iter().find(|w| w.starts_with("Ignored by NetworkManager on Linux")).expect("a warning");
    for part in
        ["redirect-gateway block-local", "dns server … dnssec", "dns server … transport", "dns server … sni", "route"]
    {
        assert!(w.contains(part), "{part}: {w}");
    }
    assert_eq!(data(&p)["linvpn-redirect-gateway"], "def1 block-local", "the service routes it as a full tunnel");
}

#[test]
fn key_and_tls_crypt_blobs_become_private_runtime_files_and_the_key_password_a_secret() {
    let p = plan(
        &base("<cert>\nC\n</cert>\n<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nK\n-----END ENCRYPTED PRIVATE KEY-----\n</key>\n<tls-crypt>\nT\n</tls-crypt>\n"),
        &caps27(),
    )
    .unwrap();
    let names: Vec<_> = p.files.iter().map(|f| f.name.clone()).collect();
    assert_eq!(names, ["ca.pem", "cert.pem", "key.pem", "tls-crypt.key"]);
    let d = data(&p);
    assert_eq!(d["connection-type"], "password-tls");
    assert_eq!(d["cert-pass-flags"], "1");
    assert_eq!(d["key"], "/run/user/1001/linvpn/nm/u/key.pem");
    assert_eq!(d["tls-crypt"], "/run/user/1001/linvpn/nm/u/tls-crypt.key");
    assert!(p.secrets.iter().any(|s| s.key == SecretKey::Plain("cert-pass".into())
        && matches!(s.value, SecretValue::Field(SecretField::KeyPassword))));
    assert!(!format!("{p:?}").contains("BEGIN ENCRYPTED"), "no key in Debug");
}

#[test]
fn tls_auth_static_keys_and_inline_mode_settings() {
    let tls = "client\ndev tap\nremote vpn.example.com 443 tcp-client\nkey-direction 1\n<ca>\nA\n</ca>\n<cert>\nC\n</cert>\n<key>\nK\n</key>\n<tls-auth>\nT\n</tls-auth>\n";
    let p = plan(tls, &caps27()).unwrap();
    let d = data(&p);
    assert_eq!(d["connection-type"], "tls");
    assert_eq!(d["remote"], "vpn.example.com:443:tcp");
    assert_eq!(d["dev-type"], "tap");
    assert_eq!(d["ta"], "/run/user/1001/linvpn/nm/u/tls-auth.key");
    assert_eq!(d["ta-dir"], "1");
    assert!(!d.contains_key("password-flags"));
    assert_eq!(d["cert-pass-flags"], "4", "a plain key needs no password");
    assert!(p.secrets.is_empty());
    let sk = plan(
        "dev tun\nremote vpn.example.com\nifconfig 10.8.0.2 10.8.0.1\n<secret>\nS\n</secret>\nkey-direction 0\n",
        &caps27(),
    )
    .unwrap();
    let d = data(&sk);
    assert_eq!(d["connection-type"], "static-key");
    assert_eq!(d["static-key"], "/run/user/1001/linvpn/nm/u/static.key");
    assert_eq!(d["static-key-direction"], "0");
    assert_eq!((d["local-ip"].as_str(), d["remote-ip"].as_str()), ("10.8.0.2", "10.8.0.1"));
    assert_eq!(d["remote"], "vpn.example.com:1194:udp");
}

#[test]
fn transport_link_and_crypto_options_use_nm_openvpns_keys() {
    let p = plan(
        &base("port 1195\nremote b.example.com\nremote 2001:db8::1 1196 tcp\nremote-random\nfloat\nkeepalive 10 60\ntun-mtu 1400\nmssfix\nfragment 1300\nmtu-disc yes\nreneg-sec 0\ncipher AES-256-CBC\nncp-ciphers AES-128-GCM\nauth SHA256\ntls-version-min 1.2 or-highest\nverify-x509-name server.example.com name\ncomp-lzo\nallow-compression asym\nhttp-proxy proxy.example.com 3128\nhttp-proxy-retry\nconnect-timeout 15\nmax-routes 200\npush-peer-info\nallow-pull-fqdn\ntun-ipv6\n"),
        &caps27(),
    )
    .unwrap();
    let d = data(&p);
    assert_eq!(d["remote"], "vpn.example.com:1194:udp, b.example.com:1195:udp, [2001:db8::1]:1196:tcp");
    for (k, v) in [
        ("remote-random", "yes"),
        ("float", "yes"),
        ("ping", "10"),
        ("ping-restart", "60"),
        ("tunnel-mtu", "1400"),
        ("mssfix", "yes"),
        ("fragment-size", "1300"),
        ("mtu-disc", "yes"),
        ("reneg-seconds", "0"),
        ("cipher", "AES-256-CBC"),
        ("auth", "SHA256"),
        ("tls-version-min", "1.2"),
        ("tls-version-min-or-highest", "yes"),
        ("verify-x509-name", "name:server.example.com"),
        ("comp-lzo", "adaptive"),
        ("allow-compression", "asym"),
        ("proxy-type", "http"),
        ("proxy-server", "proxy.example.com"),
        ("proxy-port", "3128"),
        ("proxy-retry", "yes"),
        ("connect-timeout", "15"),
        ("max-routes", "200"),
        ("push-peer-info", "yes"),
        ("allow-pull-fqdn", "yes"),
        ("tun-ipv6", "yes"),
    ] {
        assert_eq!(d.get(k).map(String::as_str), Some(v), "{k}");
    }
    assert_eq!(d["data-ciphers"], "AES-128-GCM", "the last of data-ciphers / ncp-ciphers wins");
}

#[test]
fn flattenable_connection_blocks_join_the_remote_list() {
    let t = "client\nproto tcp\n<connection>\nremote a.example.com 443\n</connection>\n<connection>\nremote b.example.com\nport 1195\nproto udp\nnobind\n</connection>\nauth-user-pass\n<ca>\nA\n</ca>\n";
    let p = plan(t, &caps27()).unwrap();
    assert_eq!(data(&p)["remote"], "a.example.com:443:tcp, b.example.com:1195:udp");
}

#[test]
fn inline_credentials_become_the_user_name_and_a_literal_password() {
    let t = base("<auth-user-pass>\nalice\ns3cret-pw\n</auth-user-pass>\n")
        .replace("auth-user-pass\nremote-cert", "remote-cert");
    let p = plan(&t, &caps27()).unwrap();
    assert_eq!(data(&p)["username"], "alice");
    assert_eq!(p.settings["vpn"]["user-name"], NmValue::Str("alice".into()));
    assert!(
        p.secrets
            .iter()
            .any(|s| s.key == SecretKey::Plain("password".into()) && matches!(s.value, SecretValue::Literal(_)))
    );
    assert!(!format!("{p:?}").contains("s3cret"), "no password in Debug");
}

#[test]
fn pkcs12_is_decoded_to_a_binary_file_and_needs_its_password() {
    let p = plan(&base("<pkcs12>\nAAEC\nAwQ=\n</pkcs12>\n"), &caps27()).unwrap();
    let f = p.files.iter().find(|f| f.name == "pkcs12.p12").unwrap();
    assert_eq!(&f.data[..], &[0, 1, 2, 3, 4]);
    let d = data(&p);
    assert_eq!(d["cert"], "/run/user/1001/linvpn/nm/u/pkcs12.p12");
    assert_eq!(d["cert-pass-flags"], "1");
}

/// A fixture PKCS#12 of `crates/core/tests/fixtures/certs` as an OpenVPN `<pkcs12>` block.
fn pkcs12_block(name: &str) -> String {
    use base64::Engine;
    let der = std::fs::read(format!("{}/tests/fixtures/certs/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: String = b64.as_bytes().chunks(64).map(|c| format!("{}\n", std::str::from_utf8(c).unwrap())).collect();
    format!("<pkcs12>\n{lines}</pkcs12>\n")
}

#[test]
fn a_pkcs12_without_a_password_asks_for_none() {
    // pfSense "Archive" exports: the MAC verifies with an empty password. An agent-owned `cert-pass` with no value
    // would end in NO_SECRETS (or GNOME's dialog); NOT_REQUIRED tells NetworkManager not to ask.
    for name in ["empty.p12", "empty-sha1.p12", "plain.p12"] {
        let p = plan(&base(&pkcs12_block(name)), &caps27()).unwrap();
        let d = data(&p);
        assert_eq!(d["cert-pass-flags"], "4", "{name}");
        assert!(!p.secrets.iter().any(|s| s.key == SecretKey::Plain("cert-pass".into())), "{name}");
    }
}

#[test]
fn a_pkcs12_with_a_password_asks_for_the_key_password() {
    for name in ["secret.p12", "secret-sha1.p12"] {
        let p = plan(&base(&pkcs12_block(name)), &caps27()).unwrap();
        assert_eq!(data(&p)["cert-pass-flags"], "1", "{name}");
        assert!(
            p.secrets.iter().any(|s| s.key == SecretKey::Plain("cert-pass".into())
                && matches!(s.value, SecretValue::Field(SecretField::KeyPassword))),
            "{name}"
        );
    }
}

#[test]
fn an_unencrypted_key_or_a_bare_askpass_asks_for_no_key_password() {
    let key = "<cert>\nC\n</cert>\n<key>\n-----BEGIN PRIVATE KEY-----\nK\n-----END PRIVATE KEY-----\n</key>\n";
    for extra in [key.to_string(), format!("askpass\n{key}")] {
        let p = plan(&base(&extra), &caps27()).unwrap();
        assert_eq!(data(&p)["cert-pass-flags"], "4", "{extra}");
        assert!(!p.secrets.iter().any(|s| s.key == SecretKey::Plain("cert-pass".into())), "{extra}");
    }
    // `askpass` with an encrypted key: the key password (from the imported askpass file) is the secret.
    let encrypted = "<cert>\nC\n</cert>\n<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nK\n-----END ENCRYPTED PRIVATE KEY-----\n</key>\n";
    let p = plan(&base(&format!("askpass\n{encrypted}")), &caps27()).unwrap();
    assert_eq!(data(&p)["cert-pass-flags"], "1");
}

#[test]
fn inline_mode_secret_flags_follow_the_caps() {
    let caps = Caps { openvpn_push_visible: true, secret_mode: nm_plan::SecretMode::Inline, ..Caps::default() };
    let p = plan(&base(""), &caps).unwrap();
    assert_eq!(data(&p)["password-flags"], "0");
    assert_eq!(data(&p)["challenge-response-flags"], "2", "CRV1 is always asked");
}

#[test]
fn every_repository_fixture_plans_or_says_why() {
    // L0-1: the real profiles plan; wiki-extras is refused (net_gateway). Each goes through the importer first,
    // as a stored config does (file references inlined).
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Tests/Fixtures");
    let mut ok = 0;
    for entry in walk(&root) {
        if entry.extension().is_none_or(|e| e != "ovpn") {
            continue;
        }
        let text = std::fs::read_to_string(&entry).unwrap();
        let name = entry.file_name().unwrap().to_string_lossy().into_owned();
        let Ok(prepared) = macvpn_core::importer::prepare(&name, &text, entry.parent().unwrap()) else {
            // Its referenced key files are not in the repository (MikroTik's wiki example, the pfSense archive's
            // `.p12`): as stored, the file references are the validator's issue on every OS.
            assert!(plan(&text, &caps27()).unwrap_err().invalid_config, "{}", entry.display());
            continue;
        };
        match plan(&prepared.config, &caps27()) {
            Ok(_) => ok += 1,
            Err(e) if name.contains("wiki-extras") => {
                assert!(!e.invalid_config && e.reasons.iter().any(|r| r.contains("net_gateway")), "{:?}", e.reasons)
            }
            Err(e) => panic!("{}: {:?}", entry.display(), e.reasons),
        }
    }
    assert!(ok >= 11, "{ok}: every importable fixture but wiki-extras");
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}
