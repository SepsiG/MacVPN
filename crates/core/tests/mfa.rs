//! Port of `MFATests.swift` (the OTP-setting and system-OTP store cases are in models.rs / ranking.rs).

mod common;

use common::*;
use macvpn_core::date::Date;
use macvpn_core::mfa::*;
use macvpn_core::models::{OTPSeparator, Secrets, VPNKind, parse_uuid};
use macvpn_core::native::{self, NativeKind};

fn secrets(username: &str, password: &str) -> Secrets {
    Secrets { username: Some(username.into()), password: Some(password.into()), ..Default::default() }
}

// MARK: SCRV1 and static challenge

/// The management-notes.txt example: "bar" + "8675309".
#[test]
fn scrv1_format() {
    assert_eq!(scrv1("bar", "8675309"), "SCRV1:YmFy:ODY3NTMwOQ==");
    assert_eq!(scrv1("", ""), "SCRV1::");
    assert_eq!(scrv1("jó:jelszó", "1"), "SCRV1:asOzOmplbHN6w7M=:MQ==");
    assert_eq!(static_challenge_password("bar", "8675309", ChallengeFormat::Concat), "bar8675309");
    assert_eq!(static_challenge_password("bar", "8675309", ChallengeFormat::Scrv1), "SCRV1:YmFy:ODY3NTMwOQ==");
}

fn sc(text: &str, echo: bool, format: ChallengeFormat) -> Option<StaticChallenge> {
    Some(StaticChallenge { text: text.into(), echo, format })
}

#[test]
fn static_challenge_parse() {
    let base = "client\nremote vpn.example.com 1194\nauth-user-pass\n";
    let p = |body: &str| static_challenge(&format!("{base}{body}"));
    assert_eq!(static_challenge(base), None);
    assert_eq!(p("static-challenge \"Enter OTP\" 1\n"), sc("Enter OTP", true, ChallengeFormat::Scrv1));
    assert_eq!(p("static-challenge 'Token code' 0 concat\n"), sc("Token code", false, ChallengeFormat::Concat));
    assert_eq!(p("--static-challenge PIN 0 scrv1\n"), sc("PIN", false, ChallengeFormat::Scrv1));
    // The last valid line counts; malformed lines are skipped.
    assert_eq!(p("static-challenge \"A\" 1\nstatic-challenge \"B\" 0\n").map(|c| c.text), Some("B".into()));
    assert_eq!(p("static-challenge \"A\" 2\n"), None);
    assert_eq!(p("static-challenge \"A\" 1 other\n"), None);
    assert_eq!(p("static-challenge \"A\"\n"), None);
    assert_eq!(p("# static-challenge \"A\" 1\n"), None);
    assert_eq!(p("static-challenge \"unterminated 1\n"), None);
    // The content of an inline block is not a directive.
    assert_eq!(p("<ca>\nstatic-challenge \"A\" 1\n</ca>\n"), None);
    assert_eq!(p("<connection>\nremote x\nstatic-challenge \"A\" 1\n</connection>\n"), None);
    assert_eq!(
        static_challenge("<ca>\nx\n</ca>\nstatic-challenge \"After\" 1\n").map(|c| c.text),
        Some("After".into())
    );
}

#[test]
fn apply_static_challenge_packs() {
    let challenge = StaticChallenge { text: "OTP".into(), echo: true, format: ChallengeFormat::Scrv1 };
    let s = apply_static_challenge(&challenge, "246810", &secrets("bob", "StatPass")).unwrap();
    assert_eq!(s.password.as_deref(), Some("SCRV1:U3RhdFBhc3M=:MjQ2ODEw"));
    assert!(s.challenge_packed);
    assert_eq!(s.one_time_code.as_deref(), Some("246810"));
    assert_eq!(
        s.stdin_payload().as_str(),
        "username=bob\npassword=SCRV1:U3RhdFBhc3M=:MjQ2ODEw\notp=246810\nchallenge=packed\n"
    );
    let concat = StaticChallenge { text: "x".into(), echo: false, format: ChallengeFormat::Concat };
    assert_eq!(apply_static_challenge(&concat, "1", &secrets("bob", "p")).unwrap().password.as_deref(), Some("p1"));
    let only_password = |p: &str| Secrets { password: Some(p.into()), ..Default::default() };
    assert_eq!(apply_static_challenge(&challenge, "1\n2", &only_password("p")), Err(MFAError::InvalidCode));
    assert_eq!(apply_static_challenge(&challenge, "1", &only_password(&"x".repeat(200))), Err(MFAError::TooLong));
}

// MARK: Code appended to the password

#[test]
fn append_code_separators() {
    assert_eq!(append_code("pw", "123456", OTPSeparator::None), "pw123456");
    assert_eq!(append_code("pw", "123456", OTPSeparator::Comma), "pw,123456");
    assert_eq!(append_code("pw", "123456", OTPSeparator::Colon), "pw:123456");
    assert_eq!(append_code("", "123456", OTPSeparator::Colon), "123456");
}

#[test]
fn apply_code_for_each_kind() {
    let base = Secrets {
        username: Some("bob".into()),
        password: Some("pw".into()),
        psk: Some("k".into()),
        ..Default::default()
    };
    for kind in [VPNKind::Openvpn, VPNKind::Strongswan, VPNKind::Sstp, VPNKind::L2tp, VPNKind::Cisco] {
        let s = apply_code("123456", OTPSeparator::Comma, &base, kind).unwrap();
        assert_eq!(s.password.as_deref(), Some("pw,123456"), "{kind:?}");
        assert_eq!(s.username.as_deref(), Some("bob"));
        assert_eq!(s.psk.as_deref(), Some("k"));
        assert_eq!(s.one_time_code.as_deref(), Some("123456"));
        assert!(!s.challenge_packed);
    }
    // Root kinds: stdin; the code separately too (only for masking).
    let root = apply_code("777", OTPSeparator::Colon, &base, VPNKind::Strongswan).unwrap();
    assert_eq!(root.stdin_payload().as_str(), "username=bob\npassword=pw:777\npsk=k\notp=777\n");
    // Native L2TP / Cisco IPsec: in the SCNetworkConnection options.
    let l2tp = apply_code("999", OTPSeparator::None, &base, VPNKind::L2tp).unwrap();
    let options = native::start_options(NativeKind::L2tp, &l2tp).unwrap();
    assert_eq!(options[native::ENT_PPP][native::PPP_AUTH_PASSWORD], "pw999");
    let cisco = apply_code("999", OTPSeparator::Colon, &base, VPNKind::Cisco).unwrap();
    let options = native::start_options(NativeKind::CiscoIPSec, &cisco).unwrap();
    assert_eq!(options[native::ENT_IPSEC][native::IPSEC_XAUTH_PASSWORD], "pw:999");
    // SSTP: the password rule applies to the combined password too.
    assert_eq!(apply_code("12\"3", OTPSeparator::None, &base, VPNKind::Sstp), Err(MFAError::SstpPassword));
    assert!(apply_code("12\\3", OTPSeparator::None, &base, VPNKind::Sstp).is_err());
    assert!(apply_code("12\"3", OTPSeparator::None, &base, VPNKind::Openvpn).is_ok());
    // Invalid code: empty, line break, control character, too long.
    let long = "1".repeat(257);
    for bad in ["", "1\n2", "1\r2", "1\u{7}2", "1\u{85}2", "1\u{2028}2", long.as_str()] {
        assert_eq!(apply_code(bad, OTPSeparator::None, &base, VPNKind::Openvpn), Err(MFAError::InvalidCode), "{bad:?}");
    }
    assert!(apply_code(&"1".repeat(256), OTPSeparator::None, &base, VPNKind::Openvpn).is_ok());
}

#[test]
fn mfa_error_messages() {
    use macvpn_core::l10n::AppLanguage;
    lang(AppLanguage::Hu);
    assert_eq!(MFAError::TooLong.message(), "A jelszó és a kód együtt túl hosszú");
    lang(AppLanguage::En);
    assert_eq!(
        MFAError::SstpPassword.message(),
        "The password with the code must not contain quotation marks, backslashes or control characters (SSTP)"
    );
}

// MARK: Time limit

#[test]
fn prompt_deadline() {
    let t0 = Date::from_time_interval_since_1970(1_000.0);
    let d = PromptDeadline::new(t0);
    assert_eq!(d.duration, 120.0);
    assert_eq!(d.remaining(t0), 120);
    assert_eq!(d.remaining(t0.adding(119.2)), 1);
    assert!(!d.is_expired(t0.adding(119.9)));
    assert!(d.is_expired(t0.adding(120.0)));
    assert_eq!(d.remaining(t0.adding(500.0)), 0);
    // The bridge's deadline, but at most the maximum; a past deadline expires at once.
    assert_eq!(PromptDeadline::until(t0, Some(t0.adding(30.0)), 120.0).duration, 30.0);
    assert_eq!(PromptDeadline::until(t0, Some(t0.adding(900.0)), 300.0).duration, 300.0);
    assert_eq!(PromptDeadline::until(t0, None, 300.0).duration, 300.0);
    assert!(PromptDeadline::until(t0, Some(t0.adding(-5.0)), 120.0).is_expired(t0));
}

// MARK: Text, URL, state file

#[test]
fn auth_text_sanitize() {
    assert_eq!(AuthText::sanitize("Enter\u{1b}[31m PIN\u{7}"), "Enter [31m PIN");
    assert_eq!(AuthText::sanitize(&"x".repeat(500)).chars().count(), 201);
    assert_eq!(AuthText::sanitize("  a\u{2028}b "), "a b");
    // Unicode format characters (Cf: bidi, zero-width, BOM) are dropped.
    assert_eq!(AuthText::sanitize("Enter\u{202E}NIP\u{202C} code"), "EnterNIP code");
    assert_eq!(AuthText::sanitize("a\u{200B}b\u{200F}c\u{2066}d\u{2069}e\u{FEFF}f\u{00AD}g"), "abcdefg");
    assert!(!AuthText::sanitize("x\u{061C}y\u{2060}z").chars().any(is_format_character));
    // The limit counts Characters (grapheme clusters), like Swift.
    assert_eq!(AuthText::sanitize(&"e\u{301}".repeat(250)), format!("{}…", "e\u{301}".repeat(200)));
}

#[test]
fn web_auth_url_validation() {
    assert_eq!(
        WebAuthURL::validate("https://sso.example.com/auth?session=abc&x=1#f")
            .and_then(|u| WebAuthURL::host(&u))
            .as_deref(),
        Some("sso.example.com")
    );
    assert!(WebAuthURL::validate("HTTPS://SSO.example.com:8443/p").is_some());
    assert!(WebAuthURL::validate("https://[2001:db8::1]/x").is_some());
    let long_path = format!("https://sso.example.com/{}", "a".repeat(1010));
    let long_label = format!("https://{}.com/", "a".repeat(64));
    let bad = [
        "http://sso.example.com/",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "ftp://x/",
        "https://",
        "https:///path",
        "https://user:pw@sso.example.com/",
        "https://sso.example.com/a b",
        "https://sso.example.com/\"x",
        "https://sso.example.com/<x>",
        "https://sso.example.com/é",
        "https://sso.example.com/\n",
        "//sso.example.com",
        "",
        long_path.as_str(),
        // Percent-encoded host (homograph, line break, bidi), userinfo trick, Unicode, trailing dot, bad labels.
        "https://%D0%B0pple.com/",
        "https://a%0Ab.com/",
        "https://%E2%80%AEx.com/",
        "https://apple.com%40evil.com/",
        "https://apple.com@evil.com/",
        "https://аpple.com/",
        "https://sso.example.com./",
        "https://-x.example.com/",
        "https://x-.example.com/",
        "https://a..b.com/",
        "https://a_b.example.com/",
        "https://sso.example.com:0/",
        "https://sso.example.com:99999/",
        "https://sso.example.com:/",
        "https://[zz::1]/",
        long_label.as_str(),
        // Foundation rejects a signed port (Swift's `Int` accepts it in the host check).
        "https://sso.example.com:+443/",
    ];
    for b in bad {
        assert_eq!(WebAuthURL::validate(b), None, "{b}");
    }
}

/// The shown and logged host is the original ASCII form in lower case (no punycode decoding).
#[test]
fn web_auth_display_host() {
    let puny = WebAuthURL::validate("https://XN--pple-43d.Example.COM/login?x=1").unwrap();
    assert_eq!(WebAuthURL::display_host(&puny), "xn--pple-43d.example.com");
    assert_eq!(puny, "https://XN--pple-43d.Example.COM/login?x=1");
    assert_eq!(
        WebAuthURL::display_host(&WebAuthURL::validate("https://[2001:DB8::1]:8443/x").unwrap()),
        "[2001:db8::1]"
    );
    assert_eq!(WebAuthURL::display_host(&WebAuthURL::validate("https://10.0.0.1/").unwrap()), "10.0.0.1");
    assert_eq!(WebAuthURL::ascii_host("https://%D0%B0pple.com/"), None);
    assert_eq!(WebAuthURL::ascii_host("https://[::ffff:1.2.3.4]/").as_deref(), Some("[::ffff:1.2.3.4]"));
}

#[test]
fn auth_ui_state_parse() {
    let mut challenge = AuthUIState::new(3, AuthUIStateKind::Challenge);
    challenge.method = Some(AuthUIMethod::Crv1);
    challenge.text = Some("Enter PIN".into());
    challenge.echo = Some(false);
    challenge.deadline = Some(1_760_000_000.0);
    assert_eq!(AuthUIState::parse(&challenge.encoded()), Some(challenge.clone()));
    assert_eq!(
        String::from_utf8(challenge.encoded()).unwrap(),
        r#"{"deadline":1760000000,"echo":false,"method":"crv1","seq":3,"state":"challenge","text":"Enter PIN","v":1}"#
    );
    // A non-https URL is dropped on reading too; the webauth state then becomes pending.
    let mut web = AuthUIState::new(1, AuthUIStateKind::Webauth);
    web.method = Some(AuthUIMethod::Webauth);
    web.url = Some("http://evil.example.com/".into());
    let parsed = AuthUIState::parse(&web.encoded()).unwrap();
    assert_eq!(parsed.url, None);
    assert_eq!(parsed.state, AuthUIStateKind::Pending);
    assert_eq!(
        AuthUIState::parse(br#"{"v":1,"seq":1,"state":"challenge","text":"a\u001bb"}"#).and_then(|s| s.text).as_deref(),
        Some("a b")
    );
    assert_eq!(AuthUIState::parse(br#"{"v":2,"seq":1,"state":"done"}"#), None);
    assert_eq!(AuthUIState::parse(br#"{"v":1,"seq":1,"state":"hacked"}"#), None);
    assert_eq!(AuthUIState::parse(&[0x20; 9000]), None);
    assert_eq!(AuthUIState::parse(b"not json"), None);
    assert_eq!(
        AuthUIState::path(&parse_uuid("11111111-2222-3333-4444-555555555555").unwrap()),
        "/var/run/macvpn-ui/11111111-2222-3333-4444-555555555555.json"
    );
}

#[test]
fn auth_ui_state_reader_rejects_symlink() {
    use std::os::unix::fs::MetadataExt;
    let tmp = TempDir::new();
    std::fs::create_dir_all(tmp.path()).unwrap();
    let file = tmp.path().join("a.json");
    std::fs::write(&file, AuthUIState::new(1, AuthUIStateKind::Pending).encoded()).unwrap();
    let uid = std::fs::metadata(&file).unwrap().uid();
    assert_eq!(AuthUIState::read(&file, uid).map(|s| s.state), Some(AuthUIStateKind::Pending));
    assert_eq!(AuthUIState::read(&file, uid + 1), None, "another owner");
    let link = tmp.path().join("b.json");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert_eq!(AuthUIState::read(&link, uid), None);
    assert_eq!(AuthUIState::read(&tmp.path().join("missing.json"), uid), None);
}

#[test]
fn respond_payload() {
    assert_eq!(AuthResponseKind::Crv1.stdin_payload("123").as_deref(), Some("kind=crv1\nresponse=123\n"));
    assert_eq!(AuthResponseKind::Static.stdin_payload("").as_deref(), Some("kind=static\nresponse=\n"));
    assert_eq!(AuthResponseKind::Cancel.stdin_payload("ignored").as_deref(), Some("kind=cancel\nresponse=\n"));
    assert_eq!(AuthResponseKind::WebauthAck.stdin_payload("").as_deref(), Some("kind=webauth-ack\nresponse=\n"));
    assert_eq!(AuthResponseKind::Crv1.stdin_payload("1\nkind=cancel"), None);
    assert_eq!(AuthResponseKind::Crv1.stdin_payload(&"1".repeat(257)), None);
    assert_eq!(AuthResponseKind::ALL.map(AuthResponseKind::raw_value), ["crv1", "static", "webauth-ack", "cancel"]);
}
