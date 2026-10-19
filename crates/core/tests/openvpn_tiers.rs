//! Port of `OpenVPNTierTests.swift`, `SecurityReviewTests.swift` and `OpenVPN27AndMikroTikTests.swift` (the
//! validator parts; the importer, `MvpnClient`, `ConnectionManager` and Keychain parts belong to later tasks).

mod common;

use common::*;
use macvpn_core::l10n::{self, AppLanguage};
use macvpn_core::validators::openvpn::{self, FORBIDDEN, REASON_LISTENS, REASON_UNKNOWN, RISKY_REASONS};
use macvpn_core::validators::{OpenVPNTier, OpenVPNValidation, OpenVPNValidator, RiskyFinding};
use std::collections::HashSet;

const BASE: &str = "client\ndev tun\nremote vpn.example.com 1194\n";

fn en() {
    lang(AppLanguage::En);
}

fn check(body: &str, ack: &[&str]) -> OpenVPNValidation {
    OpenVPNValidator.validate_full(&format!("{BASE}{body}\n"), &set(ack))
}

fn tier(d: &str) -> OpenVPNTier {
    OpenVPNValidator::tier(d)
}

fn docs() -> String {
    std::fs::read_to_string(repo_root().join("docs/openvpn-directives.md")).unwrap()
}

fn fixture(path: &str) -> String {
    std::fs::read_to_string(repo_root().join("Tests/Fixtures").join(path)).unwrap()
}

fn fixture_names(path: &str) -> Vec<String> {
    fixture(path).split('\n').filter(|l| !l.is_empty() && !l.starts_with('#')).map(str::to_string).collect()
}

fn has_explicit_tier(name: &str) -> bool {
    name == "setenv"
        || OpenVPNValidator::has_argument_spec(name)
        || RISKY_REASONS.contains_key(name)
        || FORBIDDEN.contains(name)
}

// MARK: The user's examples

#[test]
fn user_examples_import_without_friction() {
    en();
    assert_eq!(ovpn_all(&format!("{BASE}setenv CONFIG_VERSION \"2.0.4\"\n")), []);
    assert_eq!(ovpn_all(&format!("{BASE}remap-usr1 SIGTERM\nremap-usr1 SIGHUP\n")), []);
    let r = check("user nobody\ngroup nogroup\nuser\ngroup", &[]);
    assert_eq!(r.issues, []);
    assert_eq!(r.unacknowledged, ["group", "user"]);
    assert_eq!(r.risky.iter().map(|f| f.line).collect::<Vec<_>>(), [4, 5, 6, 7]);
    assert_eq!(lines(&r.all_issues()), [4, 5, 6, 7]);
    assert_eq!(r.all_issues()[0].message, "Risky directive, acknowledgement required: user");
    assert_eq!(check("user nobody\ngroup nogroup", &["user", "group"]).all_issues(), []);
}

#[test]
fn remap_usr1_rejects_other_signals() {
    en();
    assert_eq!(lines(&check("remap-usr1 SIGKILL", &[]).issues), [4]);
}

// MARK: The table

#[test]
fn tiers_are_disjoint() {
    en();
    let safe: HashSet<&str> = OpenVPNValidator::allowed();
    let risky: HashSet<&str> = RISKY_REASONS.keys().copied().collect();
    assert!(safe.is_disjoint(&risky), "{:?}", safe.intersection(&risky).collect::<Vec<_>>());
    assert!(safe.is_disjoint(&FORBIDDEN), "{:?}", safe.intersection(&FORBIDDEN).collect::<Vec<_>>());
    assert!(risky.is_disjoint(&FORBIDDEN), "{:?}", risky.intersection(&FORBIDDEN).collect::<Vec<_>>());
    for d in &safe {
        assert_eq!(tier(d), OpenVPNTier::Safe, "{d}");
    }
    for d in &risky {
        assert_eq!(tier(d), OpenVPNTier::Risky, "{d}");
    }
    for d in FORBIDDEN.iter() {
        assert_eq!(tier(d), OpenVPNTier::Forbidden, "{d}");
    }
    assert_eq!(tier("setenv"), OpenVPNTier::Safe);
    assert_eq!(tier("some-future-option"), OpenVPNTier::Risky);
}

#[test]
fn notable_decisions() {
    en();
    for d in ["chroot", "echo", "pkcs11-id", "syslog", "capath", "genkey", "dns-updown", "iproute", "script-security"] {
        assert_eq!(tier(d), OpenVPNTier::Forbidden, "{d}");
    }
    for d in
        ["user", "group", "route-noexec", "ifconfig-noexec", "win-sys", "service", "mode", "allow-recursive-routing"]
    {
        assert_eq!(tier(d), OpenVPNTier::Risky, "{d}");
    }
    for d in ["askpass", "pkcs12", "dns", "machine-readable-output", "register-dns", "block-outside-dns", "disable-dco"]
    {
        assert_eq!(tier(d), OpenVPNTier::Safe, "{d}");
    }
}

/// The `docs/openvpn-directives.md` table names every directive of the tables.
#[test]
fn documentation_lists_every_directive() {
    en();
    let doc = docs();
    let mut names: HashSet<&str> = OpenVPNValidator::allowed();
    names.extend(RISKY_REASONS.keys());
    names.extend(FORBIDDEN.iter());
    for name in names {
        assert!(doc.contains(&format!("`{name}`")), "{name}");
    }
    for reason in RISKY_REASONS.values().collect::<HashSet<_>>() {
        assert!(doc.contains(reason), "{reason}");
    }
}

#[test]
fn every_reason_is_translated() {
    en();
    let mut reasons: HashSet<&str> = RISKY_REASONS.values().copied().collect();
    reasons.insert(REASON_UNKNOWN);
    for key in reasons {
        assert!(l10n::hungarian(key).is_some(), "{key}");
    }
}

#[test]
fn forbidden_stays_forbidden_even_when_acknowledged() {
    en();
    for d in FORBIDDEN.iter() {
        let r = check(&format!("{d} x"), &[d]);
        assert_eq!(lines(&r.issues), [4], "{d}");
        assert!(r.issues[0].message.starts_with(&format!("Forbidden directive: {d}")), "{d}");
    }
}

#[test]
fn unknown_names_that_look_like_hooks_or_files_are_forbidden() {
    en();
    for d in [
        "foo-verify",
        "pre-up",
        "client-script",
        "state-dir",
        "cache-file",
        "pool-persist",
        "management-new",
        "pkcs11-x",
    ] {
        assert_eq!(tier(d), OpenVPNTier::Forbidden, "{d}");
        assert_eq!(lines(&check(&format!("{d} x"), &[d]).issues), [4], "{d}");
    }
}

// MARK: RISKY / unknown arguments

#[test]
fn unknown_directive_is_risky_with_harmless_arguments() {
    en();
    let r = check("future-option 3 abc \"quoted text\" 10.0.0.0/24", &[]);
    assert_eq!(r.issues, []);
    assert_eq!(r.risky, [RiskyFinding { directive: "future-option".into(), line: 4, reason_key: REASON_UNKNOWN }]);
    assert_eq!(check("future-option 3", &["future-option"]).all_issues(), []);
}

#[test]
fn risky_arguments_cannot_smuggle_files() {
    en();
    let bad = [
        "/etc/master.passwd",
        "../x",
        "a/../b",
        "etc/master.passwd",
        "file:x",
        "FILE:/x",
        "-x",
        "--up",
        "~/x",
        "a$b",
        "a`b`",
        "a;b",
        "a|b",
        "a&b",
        "\"a<b\"",
        "\"a>b\"",
    ];
    for arg in bad {
        let r = check(&format!("future-option {arg}"), &["future-option"]);
        assert_eq!(lines(&r.issues), [4], "{arg}");
        assert_eq!(r.risky, [], "{arg}");
        assert_eq!(lines(&check(&format!("user {arg}"), &["user"]).issues), [4], "{arg}");
    }
}

#[test]
fn risky_is_not_allowed_in_connection_block() {
    en();
    let r = OpenVPNValidator
        .validate_full("client\n<connection>\nremote a 1\nuser nobody\n</connection>\n", &set(&["user"]));
    assert_eq!(lines(&r.issues), [4]);
}

#[test]
fn acknowledgement_is_per_name() {
    en();
    let r = check("user nobody\ngroup nogroup\nfuture-option 1", &["user"]);
    assert_eq!(r.unacknowledged, ["future-option", "group"]);
    assert_eq!(r.risky_names(), ["future-option", "group", "user"]);
    assert_eq!(lines(&r.all_issues()), [5, 6]);
}

#[test]
fn all_issues_keeps_whole_file_issues_last() {
    en();
    let r = OpenVPNValidator.validate_full("client\nuser nobody\nup /x\n", &HashSet::new());
    assert_eq!(lines(&r.all_issues()), [2, 3, 0]);
}

// MARK: setenv

#[test]
fn setenv_accepts_any_shell_name() {
    en();
    for line in [
        "setenv CONFIG_VERSION \"2.0.4\"",
        "setenv foo bar",
        "setenv _X 1",
        "setenv UV_ID abc",
        "setenv PUSH_PEER_INFO",
        "setenv FORWARD_COMPATIBLE 1",
        "setenv opt remap-usr1 SIGTERM",
    ] {
        assert_eq!(ovpn_all(&format!("{BASE}{line}\n")), [], "{line}");
    }
}

#[test]
fn setenv_denylist() {
    en();
    let exact = [
        "BASH_ENV",
        "ENV",
        "PATH",
        "IFS",
        "SHELLOPTS",
        "BASHOPTS",
        "PS4",
        "CDPATH",
        "GLOBIGNORE",
        "HOME",
        "TMPDIR",
        "OPENSSL_CONF",
        "TZDIR",
        "LANG",
        "NLSPATH",
        "path",
        "script_type",
        "dev",
        "ifconfig_local",
    ];
    let prefixed = [
        "BASH_FUNC_x%%",
        "DYLD_INSERT_LIBRARIES",
        "LD_PRELOAD",
        "MALLOC_CHECK_",
        "PYTHONPATH",
        "PERL5LIB",
        "RUBYOPT",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "LC_ALL",
        "LC_CTYPE",
        "MallocStackLogging",
        "NSObjCMessageLoggingEnabled",
        "CFFIXED_USER_HOME",
        "OBJC_DEBUG",
        "foreign_option_1",
        "SUDO_COMMAND",
        "sudo_user",
    ];
    for name in exact.iter().chain(prefixed.iter()) {
        let issues = ovpn_all(&format!("{BASE}setenv {name} x\n"));
        assert_eq!(lines(&issues), [4], "{name}");
    }
    assert!(!OpenVPNValidator::is_denied_setenv_name("CONFIG_VERSION"));
    assert!(!OpenVPNValidator::is_denied_setenv_name("NAME"));
}

#[test]
fn setenv_shape_and_recursion() {
    en();
    assert_eq!(lines(&ovpn_all(&format!("{BASE}setenv 1X a\n"))), [4]);
    assert_eq!(lines(&ovpn_all(&format!("{BASE}setenv A b c\n"))), [4]);
    let r = check("setenv opt user nobody", &[]);
    assert_eq!(r.issues, []);
    assert_eq!(r.unacknowledged, ["user"]);
    assert_eq!(lines(&check("setenv opt chroot /x", &["chroot"]).issues), [4]);
}

// MARK: New SAFE directives

#[test]
fn expanded_safe_directives() {
    en();
    let lines_ok = [
        "machine-readable-output",
        "mute 10",
        "connect-timeout 10",
        "explicit-exit-notify 2",
        "persist-local-ip",
        "route-nopull",
        "pull-filter ignore \"route-ipv6\"",
        "allow-pull-fqdn",
        "push-peer-info",
        "auth-nocache",
        "auth-retry nointeract",
        "tls-cert-profile preferred",
        "ignore-unknown-option block-outside-dns",
        "data-ciphers AES-256-GCM",
        "verify-x509-name vpn name",
        "remote-cert-tls server",
        "sndbuf 0",
        "mssfix 1400",
        "fragment 1300",
        "mtu-disc yes",
        "tun-mtu 1500",
        "keepalive 10 60",
        "inactive 0",
        "server-poll-timeout 4",
        "hand-window 70",
        "tran-window 3600",
        "reneg-sec 0",
        "key-direction 1",
        "dhcp-option DNS 10.0.0.1",
        "block-outside-dns",
        "register-dns",
        "redirect-gateway def1",
        "route 10.0.0.0 255.0.0.0",
        "ifconfig-nowarn",
        "route-delay 2",
        "route-metric 5",
        "float",
        "nobind",
        "resolv-retry infinite",
        "connect-retry 2 30",
        "proto-force udp",
        "mark 1",
        "bind-dev utun3",
        "disable-dco",
        "compress lz4-v2",
        "comp-lzo no",
        "allow-compression no",
        "tls-version-min 1.2",
        "tls-groups X25519",
        "ecdh-curve secp384r1",
        "cipher AES-256-CBC",
        "auth SHA256",
        "peer-fingerprint [inline]",
        "verify-hash AB:CD SHA256",
        "x509-username-field CN",
        "x509-track +CN",
        "auth-token-user dXNlcg==",
        "http-proxy p 8080",
        "http-proxy-option AGENT \"Mozilla 5\"",
        "socks-proxy p 1080",
        "askpass",
        "dns server 1 address 10.0.0.53",
        "dns search-domains corp.example",
        "nice -5",
        "mlock",
        "remap-usr1 SIGHUP",
        "local 0.0.0.0",
        "socket-flags TCP_NODELAY",
        "keying-material-exporter EXPORTER-x 32",
    ];
    for line in lines_ok {
        assert_eq!(ovpn_all(&format!("{BASE}{line}\n")), [], "{line}");
    }
}

#[test]
fn askpass_with_file_is_rejected() {
    en();
    assert_eq!(lines(&ovpn_all(&format!("{BASE}askpass pass.txt\n"))), [4]);
    assert_eq!(lines(&ovpn_all(&format!("{BASE}askpass /etc/master.passwd\n"))), [4]);
}

// MARK: Realistic provider profiles

#[test]
fn tier_realistic_provider_profiles() {
    en();
    let nord_style = "client\ndev tun\nproto udp\nremote 1.2.3.4 1194\nresolv-retry infinite\nremote-random\nnobind\ntun-mtu 1500\ntun-mtu-extra 32\nmssfix 1450\npersist-key\npersist-tun\nping 15\nping-restart 0\nping-timer-rem\nreneg-sec 0\ncomp-lzo no\nverify-x509-name CN=us1234.nordvpn.com\nremote-cert-tls server\nauth-user-pass\nverb 3\npull\nfast-io\ncipher AES-256-CBC\nauth SHA512\n<ca>\nX\n</ca>\nkey-direction 1\n<tls-auth>\nX\n</tls-auth>";
    let proton_style = "client\ndev tun\nproto udp\nremote a.protonvpn.net 80\nremote a.protonvpn.net 51820\nserver-poll-timeout 20\nremote-random\nresolv-retry infinite\nnobind\ncipher AES-256-GCM\nsetenv CLIENT_CERT 0\ntun-mtu 1500\nmssfix 0\npersist-key\npersist-tun\nreneg-sec 0\nremote-cert-tls server\nauth-user-pass\nscript-security 2";
    let pia_style = "client\ndev tun\nproto udp\nremote x.privacy.network 1198\nresolv-retry infinite\nnobind\npersist-key\npersist-tun\ncipher aes-128-cbc\nauth sha1\ntls-client\nremote-cert-tls server\nauth-user-pass\ncompress\nverb 1\nreneg-sec 0\ndisable-occ\nuser nobody\ngroup nogroup\nsetenv CONFIG_VERSION \"2.0.4\"\nremap-usr1 SIGTERM";
    let access_server = "setenv FORWARD_COMPATIBLE 1\nclient\nserver-poll-timeout 4\nnobind\nremote vpn.example.com 1194 udp\nremote vpn.example.com 443 tcp\ndev tun\ndev-type tun\nremote-cert-tls server\ntls-version-min 1.2\nreneg-sec 604800\ntun-mtu 1420\nverb 3\npush-peer-info\nsetenv UV_ID abc123\nsetenv UV_PLAT_REL 2.0\nstatic-challenge \"Enter Authenticator Code\" 1\nauth-user-pass\n<ca>\nX\n</ca>\n<tls-crypt-v2>\nX\n</tls-crypt-v2>";
    assert_eq!(ovpn_all(nord_style), []);
    assert_eq!(ovpn_all(access_server), []);
    // The ProtonVPN profile's `script-security 2` line stays forbidden (MacVPN sets it itself).
    assert_eq!(lines(&ovpn_all(proton_style)), [19]);
    let pia = OpenVPNValidator.validate_full(pia_style, &HashSet::new());
    assert_eq!(pia.issues, []);
    assert_eq!(pia.unacknowledged, ["group", "user"]);
    assert_eq!(OpenVPNValidator.validate_full(pia_style, &set(&["user", "group"])).all_issues(), []);
}

// MARK: SecurityReviewTests (M1, L1–L4, L6)

const SR_BASE: &str = "client\nremote a 1194\n";

fn sr_check(body: &str, ack: &[&str]) -> OpenVPNValidation {
    OpenVPNValidator.validate_full(&format!("{SR_BASE}{body}\n"), &set(ack))
}

#[test]
fn parameter_is_an_echo_alias_and_forbidden() {
    en();
    assert_eq!(tier("parameter"), OpenVPNTier::Forbidden);
    let r = sr_check("parameter msg Initialization Sequence Completed", &["parameter"]);
    assert_eq!(lines(&r.issues), [3]);
    assert!(r.issues[0].message.starts_with("Forbidden directive: parameter"));
}

/// Every name OpenVPN 2.7.8's `options.c` accepts (`streq(p[0], "…")`) is explicitly classified and documented.
#[test]
fn every_option_name_in_the_source_is_classified_and_documented() {
    en();
    let names = fixture_names("openvpn/openvpn-2.7.8-source-options.txt");
    assert_eq!(names.len(), 315);
    let doc = docs();
    for name in &names {
        // `connection` is allowed only as an inline block (`<connection>`); its one-line form is invalid (L6).
        let explicit = name == "connection" || has_explicit_tier(name);
        assert!(explicit, "no explicit tier: {name}");
        assert!(doc.contains(&format!("`{name}`")), "not documented: {name}");
    }
}

#[test]
fn source_aliases_are_classified_like_their_target() {
    en();
    assert_eq!(tier("udp-mtu"), OpenVPNTier::Safe);
    assert_eq!(tier("ip-remote-hint"), OpenVPNTier::Safe);
    assert_eq!(sr_check("udp-mtu 1500", &[]).all_issues(), []);
    assert_eq!(sr_check("ip-remote-hint 1.2.3.4", &[]).all_issues(), []);
    assert_eq!(sr_check("preresolve skip-remote", &[]).all_issues(), []);
}

#[test]
fn script_security_low_levels_not_in_connection_block() {
    en();
    let text = "client\n<connection>\nremote a 1194\nscript-security 1\n</connection>\n";
    assert_eq!(lines(&ovpn_all(text)), [4]);
}

#[test]
fn more_hook_environment_names_are_denied() {
    en();
    for name in ["POSIXLY_CORRECT", "TMOUT", "PATH_LOCALE", "GREP_OPTIONS", "OPENSSL_MODULES", "OPENSSL_ENGINES"] {
        assert!(OpenVPNValidator::is_denied_setenv_name(name), "{name}");
        assert_eq!(lines(&sr_check(&format!("setenv {name} 1"), &[]).issues), [3], "{name}");
    }
}

#[test]
fn risky_argument_slash_only_in_real_cidr() {
    en();
    for arg in ["10.0.0.0/24", "fd00::/64", "1.2.3.4/32"] {
        assert_eq!(sr_check(&format!("future-option {arg}"), &["future-option"]).all_issues(), [], "{arg}");
    }
    for arg in ["./123", "a/1", "dead.beef/42", "10.0.0.0/33", "1.2.3/24", "::/129", "/24", "10.0.0.0/"] {
        assert_eq!(lines(&sr_check(&format!("future-option {arg}"), &["future-option"]).issues), [3], "{arg}");
    }
}

#[test]
fn listening_server_options_have_their_own_reason() {
    en();
    for d in ["mode", "server", "server-bridge", "server-ipv6", "tls-server", "client-to-client"] {
        assert_eq!(RISKY_REASONS.get(d), Some(&REASON_LISTENS), "{d}");
    }
    assert_eq!(REASON_LISTENS, "Makes this Mac accept incoming VPN connections (listens on the network as root)");
    assert!(l10n::hungarian(REASON_LISTENS).is_some());
}

#[test]
fn single_line_connection_and_bare_dash_dash() {
    en();
    let r = sr_check("connection remote-a", &["connection"]);
    assert_eq!(lines(&r.issues), [3]);
    assert_eq!(r.risky, []);
    let dashes = sr_check("--", &[]);
    assert_eq!(lines(&dashes.issues), [3]);
    assert_eq!(dashes.issues[0].message, "Invalid directive");
    assert_eq!(sr_check("-- x", &[]).issues[0].message, "Invalid directive");
}

// MARK: OpenVPN 2.7.8 coverage

#[test]
fn every_openvpn_278_option_is_classified_and_documented() {
    en();
    let options = fixture_names("openvpn/openvpn-2.7.8-help-options.txt");
    assert_eq!(options.len(), 234);
    let doc = docs();
    for name in &options {
        assert!(has_explicit_tier(name), "no explicit tier: {name}");
        assert!(doc.contains(&format!("`{name}`")), "not in docs/openvpn-directives.md: {name}");
    }
}

#[track_caller]
fn ok27(line: &str) {
    assert_eq!(ovpn_all(&format!("client\nremote a 1194\n{line}\n")), [], "{line}");
}

#[track_caller]
fn bad27(line: &str) {
    assert_eq!(lines(&ovpn_all(&format!("client\nremote a 1194\n{line}\n"))), [3], "{line}");
}

#[test]
fn dns_directive_forms() {
    en();
    for line in [
        "dns search-domains corp.example lab.example",
        "dns server 0 address 10.0.0.53",
        "dns server 1 address 10.0.0.53:5353 [fd00::53]:53 fd00::54",
        "dns server -5 address 1.1.1.1",
        "dns server 1 resolve-domains corp.example",
        "dns server 1 dnssec optional",
        "dns server 1 transport DoT",
        "dns server 1 transport DoH",
        "dns server 1 sni dns.example",
    ] {
        ok27(line);
    }
    for line in ["dns", "dns server", "dns server 1 address /etc/x", "dns resolver 1", "dns server 1 address `x`"] {
        bad27(line);
    }
    assert_eq!(tier("dns-updown"), OpenVPNTier::Forbidden);
    assert_eq!(tier("tls-export-cert"), OpenVPNTier::Forbidden);
}

#[test]
fn arguments_openvpn27_accepts() {
    en();
    let lines_ok = [
        "data-ciphers AES-256-GCM:AES-128-GCM:?CHACHA20-POLY1305:aes-256-cbc",
        "tls-groups X25519:secp256r1:X448",
        "tls-cert-profile legacy",
        "tls-cert-profile preferred",
        "tls-cert-profile suiteb",
        "tls-cert-profile insecure",
        "verify-x509-name \"CN=vpn\" subject",
        "verify-x509-name vpn.example name",
        "verify-x509-name vpn name-prefix",
        "remote a 1194 tcp-client",
        "remote a 1194 udp6",
        "proto tcp-client",
        "proto udp4",
        "proto udp6",
        "proto tcp4-client",
        "proto tcp6-client",
        "redirect-gateway def1 bypass-dhcp ipv6 !ipv4",
        "redirect-gateway local autolocal block-local bypass-dns",
        "dhcp-option DNS 10.0.0.1",
        "dhcp-option DNS6 fd00::1",
        "dhcp-option DOMAIN corp.example",
        "dhcp-option DOMAIN-SEARCH a.example",
        "dhcp-option ADAPTER_DOMAIN_SUFFIX a.example",
        "dhcp-option NTP 10.0.0.2",
        "dhcp-option WINS 10.0.0.3",
        "dhcp-option NBS 10.0.0.4",
        "dhcp-option NBT 2",
        "dhcp-option NBDD 10.0.0.5",
        "dhcp-option DISABLE-NBT",
        "dhcp-option PROXY_HTTP proxy.example 8080",
        "dhcp-option PROXY_AUTO_CONFIG_URL http://wpad.example/proxy.pac",
        "dhcp-option PROXY_BYPASS a.example b.example",
        "route 10.0.0.0 255.0.0.0 net_gateway",
        "route 10.0.0.0 255.0.0.0 vpn_gateway 50",
        "route remote_host 255.255.255.255 net_gateway",
        "route 10.1.0.0 255.255.0.0 10.8.0.1 default",
        "auth sha1",
        "auth SHA256",
        "auth sha512",
        "cipher BF-CBC",
        "cipher bf-cbc",
        "cipher AES-128-CBC",
        "cipher aes-128-cbc",
        "cipher AES-256-GCM",
        "ifconfig-ipv6 fd00::2/64",
        "ifconfig-ipv6 fd00::2/64 fd00::1",
        "route-ipv6-gateway fd00::1",
        "force-tls-key-material-export",
        "push-peer-info",
        "disable-dco",
        "ncp-disable",
        "comp-lzo",
        "comp-lzo no",
        "comp-lzo adaptive",
        "tls-cipher DEFAULT:@SECLEVEL=0",
        "compress stub-v2",
    ];
    for line in lines_ok {
        ok27(line);
    }
    assert_eq!(tier("client-nat"), OpenVPNTier::Risky);
}

#[test]
fn dhcp_option_case_folding_is_ascii_only() {
    en();
    ok27("dhcp-option dns 10.0.0.1");
    ok27("dhcp-option proxy_http proxy.example 8080");
    // Foundation does not fold U+017F (long s) or U+212A (Kelvin) into the ASCII letters.
    bad27("dhcp-option DN\u{17F} 10.0.0.1");
    bad27("dhcp-option PROXY_\u{212A} x");
}

#[test]
fn script_security_levels() {
    en();
    ok27("script-security 0");
    ok27("script-security 1");
    for line in ["script-security 2", "script-security 3", "script-security", "script-security 1 x"] {
        bad27(line);
    }
    let r = OpenVPNValidator.validate_full("client\nremote a\nscript-security 2\n", &set(&["script-security"]));
    assert_eq!(lines(&r.issues), [3]);
}

// MARK: MikroTik (validator part of MikroTikImportTests; the importer is Task 1.3)

#[test]
fn routeros_exports_are_safe_without_acknowledgement() {
    en();
    for name in [
        "routeros-v7-export-udp.ovpn",
        "routeros-v7-export-tcp.ovpn",
        "routeros-v7-export-tls-crypt.ovpn",
        "routeros-wiki-extras.ovpn",
        "routeros-v6-imported.ovpn",
    ] {
        let text = fixture(&format!("mikrotik/{name}"));
        let result = OpenVPNValidator.validate_full(&text, &HashSet::new());
        assert_eq!(result.issues, [], "{name}");
        assert_eq!(result.risky, [], "{name}");
        assert_eq!(ovpn_all(&text), [], "{name}");
    }
}

/// The v6 wiki profile references external files: as written (before the importer inlines them) the
/// validator must reject exactly those lines.
#[test]
fn routeros_v6_wiki_references_files() {
    en();
    let text = fixture("mikrotik/routeros-v6-wiki.ovpn");
    let issues = OpenVPNValidator.validate_full(&text, &HashSet::new()).issues;
    assert!(!issues.is_empty());
    for issue in &issues {
        assert!(issue.message.starts_with("External file reference, use an inline block: "), "{}", issue.display());
    }
}

#[test]
fn hint_and_hungarian_reason() {
    lang(AppLanguage::Hu);
    let r = check("user nobody", &[]);
    assert_eq!(r.risky[0].reason(), l10n::hungarian(openvpn::REASON_PRIVILEGE_DROP).unwrap());
}
