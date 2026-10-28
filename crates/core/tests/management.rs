//! Port of `ManagementProtocolTests.swift`.

use macvpn_core::management::*;
use macvpn_core::mfa::AuthResponseKind;
use regex::Regex;

fn parse(line: &str) -> ManagementEvent {
    ManagementParser::parse(line)
}

fn web(url: &str) -> ManagementEvent {
    ManagementEvent::WebAuth(Some(url.to_string()))
}

#[test]
fn hold_state_and_ignored_lines() {
    assert_eq!(parse(">HOLD:Waiting for hold release:10"), ManagementEvent::Hold);
    assert_eq!(parse(">FATAL:Cannot open TUN/TAP dev"), ManagementEvent::Fatal);
    assert_eq!(parse(">STATE:1760000000,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,1194,,"), ManagementEvent::Connected);
    assert_eq!(parse(">STATE:1760000000,AUTH_PENDING,timeout 120,,,,,"), ManagementEvent::AuthPending(Some(120)));
    assert_eq!(parse(">STATE:1760000000,AUTH_PENDING,,,,,,"), ManagementEvent::AuthPending(None));
    assert_eq!(parse(">STATE:1760000000,AUTH_PENDING,timeout x,,,,,"), ManagementEvent::AuthPending(None));
    assert_eq!(parse(">STATE:1760000000,RECONNECTING,ping-restart,,,,,"), ManagementEvent::Reconnecting);
    assert_eq!(parse(">STATE:1760000000,RECONNECTING,SIGUSR1,,,,,"), ManagementEvent::Reconnecting);
    let long = format!(">HOLD:{}", "x".repeat(5000));
    for line in [
        ">STATE:1760000000,WAIT,,,,,,",
        ">STATE:1760000000,EXITING,ping-exit,,,,,",
        ">ECHO:1760000000,Initialization Sequence Completed",
        ">LOG:1760000000,I,Initialization Sequence Completed",
        ">INFO:OpenVPN Management Interface Version 5",
        ">BYTECOUNT:1,2",
        ">NEED-OK:Need 'token-insertion-request' confirmation MSG:x",
        "SUCCESS: hold release succeeded",
        "ERROR: unknown command",
        "END",
        ">CLIENT:CONNECT,0,1",
        ">PASSWORD:Auth-Token:T0kenS3cret",
        ">INFOMSG:SOMETHING:else",
        ">STATE:x",
        "Initialization Sequence Completed",
        long.as_str(),
    ] {
        assert_eq!(parse(line), ManagementEvent::Ignored, "{line}");
    }
}

#[test]
fn password_requests() {
    assert_eq!(parse(">PASSWORD:Need 'Auth' username/password"), ManagementEvent::NeedAuth(None));
    for (flag, echo, concat) in [(0, false, false), (1, true, false), (2, false, true), (3, true, true)] {
        assert_eq!(
            parse(&format!(">PASSWORD:Need 'Auth' username/password SC:{flag},Enter OTP, please")),
            ManagementEvent::NeedAuth(Some(ManagementStaticRequest { echo, concat, text: "Enter OTP, please".into() }))
        );
    }
    assert_eq!(parse(">PASSWORD:Need 'Auth' username/password SC:4,x"), ManagementEvent::AuthFailed);
    assert_eq!(parse(">PASSWORD:Need 'Auth' username/password SC:x"), ManagementEvent::AuthFailed);
    assert_eq!(
        parse(">PASSWORD:Need 'Auth' username/password SC:1,a\u{1b}b"),
        ManagementEvent::NeedAuth(Some(ManagementStaticRequest { echo: true, concat: false, text: "a b".into() }))
    );
    for other in [
        "Need 'Private Key' password",
        "Need 'HTTP Proxy' username/password",
        "Need 'Auth' username",
        "Need 'Auth' password",
    ] {
        assert_eq!(parse(&format!(">PASSWORD:{other}")), ManagementEvent::NeedOther, "{other}");
    }
    assert_eq!(parse(">PASSWORD:Verification Failed: 'Auth'"), ManagementEvent::AuthFailed);
    assert_eq!(parse(">PASSWORD:Verification Failed: 'Private Key'"), ManagementEvent::AuthFailed);
    assert_eq!(parse(">PASSWORD:Verification Failed: 'Auth' ['denied by policy']"), ManagementEvent::AuthFailed);
    // Expired auth token and temporary error: OpenVPN retries, not final.
    assert_eq!(parse(">PASSWORD:Verification Failed: 'Auth' ['SESSION: token expired']"), ManagementEvent::AuthRetry);
    assert_eq!(parse(">PASSWORD:Verification Failed: 'Auth' ['TEMP[backoff 30]:busy']"), ManagementEvent::AuthRetry);
}

#[test]
fn crv1() {
    let event = parse(
        ">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Y3Ix:Please enter token PIN']",
    );
    let ManagementEvent::DynamicChallenge(c) = event else { panic!("{event:?}") };
    assert_eq!(
        c,
        CRV1Challenge {
            echo: true,
            response_required: true,
            state_id: "Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l".into(),
            username: "cr1".into(),
            text: "Please enter token PIN".into()
        }
    );
    // The management-notes example answer.
    assert_eq!(
        ManagementCommand::Password(c.password("8675309")).line().as_deref(),
        Some(r#"password "Auth" "CRV1::Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l::8675309""#)
    );
    assert_eq!(ManagementCommand::Username(c.username.clone()).line().as_deref(), Some(r#"username "Auth" "cr1""#));
    // The text may contain colons; an empty flag list and an empty user name are valid.
    assert_eq!(CRV1Challenge::parse("CRV1::st::Code: 6 digits").map(|c| c.text).as_deref(), Some("Code: 6 digits"));
    assert_eq!(CRV1Challenge::parse("CRV1::st::x").map(|c| c.username).as_deref(), Some(""));
    assert_eq!(
        CRV1Challenge::parse(&format!("CRV1:R:st:Ym9i:{}", "x".repeat(300))).map(|c| c.text.chars().count()),
        Some(201)
    );
    let long_state = format!("CRV1:R:{}:Ym9i:t", "s".repeat(129));
    let control_user = format!("CRV1:R:st:{}:t", macvpn_core::swift_base64::encode(b"a\nb"));
    for bad in [
        "CRV1:X:st:Ym9i:t",
        "CRV1:R:st\"x:Ym9i:t",
        "CRV1:R::Ym9i:t",
        "CRV1:R:st:not base64!:t",
        "CRV1:R:st:Ym9",
        "CRV1:R:st",
        "XRV1:R:st:Ym9i:t",
        long_state.as_str(),
        control_user.as_str(),
        "CRV1:R:s\\t:Ym9i:t",
    ] {
        assert_eq!(CRV1Challenge::parse(bad), None, "{bad}");
        assert_eq!(
            parse(&format!(">PASSWORD:Verification Failed: 'Auth' ['{bad}']")),
            ManagementEvent::AuthFailed,
            "{bad}"
        );
    }
}

#[test]
fn info_messages() {
    assert_eq!(parse(">INFOMSG:OPEN_URL:https://sso.example.com/a?b=c"), web("https://sso.example.com/a?b=c"));
    assert_eq!(parse(">INFOMSG:OPEN_URL:http://sso.example.com/"), ManagementEvent::WebAuth(None));
    assert_eq!(parse(">INFOMSG:OPEN_URL:javascript:alert(1)"), ManagementEvent::WebAuth(None));
    assert_eq!(parse(">INFOMSG:WEB_AUTH::https://sso.example.com/x"), web("https://sso.example.com/x"));
    assert_eq!(parse(">INFOMSG:WEB_AUTH:external,hidden:https://sso.example.com/x"), web("https://sso.example.com/x"));
    assert_eq!(
        parse(">INFOMSG:WEB_AUTH:proxy=10.0.0.1;8080;dXNlcg==;cGFzcw==,external:https://sso.example.com/x"),
        ManagementEvent::WebAuth(None)
    );
    assert_eq!(parse(">INFOMSG:WEB_AUTH:https"), ManagementEvent::WebAuth(None));
    assert_eq!(
        parse(">INFOMSG:CR_TEXT:R,E:Enter the code"),
        ManagementEvent::CrText { echo: true, text: "Enter the code".into() }
    );
    assert_eq!(
        parse(">INFOMSG:CR_TEXT:R:Code: 6 digits"),
        ManagementEvent::CrText { echo: false, text: "Code: 6 digits".into() }
    );
    assert_eq!(parse(">INFOMSG:CR_TEXT:Q:x"), ManagementEvent::AuthFailed);
    assert_eq!(parse(">INFOMSG:CR_TEXT:nocolon"), ManagementEvent::AuthFailed);
}

/// Only the allowlisted commands can be built, and each is a single line without control characters.
#[test]
fn command_builder_allowlist() {
    assert_eq!(ManagementCommand::StateOn.line().as_deref(), Some("state on"));
    assert_eq!(ManagementCommand::HoldRelease.line().as_deref(), Some("hold release"));
    assert_eq!(ManagementCommand::Username("bob".into()).line().as_deref(), Some(r#"username "Auth" "bob""#));
    assert_eq!(
        ManagementCommand::Password(r#"p"a\ss"#.into()).line().as_deref(),
        Some(r#"password "Auth" "p\"a\\ss""#)
    );
    assert_eq!(ManagementCommand::Password(String::new()).line().as_deref(), Some(r#"password "Auth" """#));
    assert_eq!(ManagementCommand::CrResponse("112233".into()).line().as_deref(), Some("cr-response MTEyMjMz"));
    assert_eq!(ManagementCommand::Username(String::new()).line(), None);
    for bad in ["a\nsignal SIGTERM", "a\rb", "a\u{0}b", "a\u{7f}b", "a\u{85}b"] {
        assert_eq!(ManagementCommand::Username(bad.into()).line(), None, "{bad:?}");
        assert_eq!(ManagementCommand::Password(bad.into()).line(), None, "{bad:?}");
    }
    assert!(ManagementCommand::Password("x".repeat(255)).line().is_some());
    assert_eq!(ManagementCommand::Password("x".repeat(256)).line(), None);
    assert_eq!(ManagementCommand::CrResponse("x".repeat(200)).line(), None);
    // OpenVPN would run the part after byte 1024 as a new command: every line built is shorter.
    let worst = [
        ManagementCommand::Username("\"".repeat(255)),
        ManagementCommand::Password("\\".repeat(255)),
        ManagementCommand::Password("é".repeat(127)),
        ManagementCommand::CrResponse("9".repeat(189)),
        ManagementCommand::Username("x".repeat(255)),
    ];
    for command in &worst {
        let line = command.line().unwrap_or_else(|| panic!("{command:?}"));
        assert!(line.len() < 1024);
    }
    let allowed = Regex::new(
        r#"^(state on|hold release|username "Auth" "([^"\\]|\\.)+"|password "Auth" "([^"\\]|\\.)*"|cr-response [A-Za-z0-9+/=]+)$"#,
    )
    .unwrap();
    let samples = [
        ManagementCommand::StateOn,
        ManagementCommand::HoldRelease,
        ManagementCommand::Username("u s\"e\\r".into()),
        ManagementCommand::Password("signal SIGTERM\" kill".into()),
        ManagementCommand::Password("x\"\nexit".into()),
        ManagementCommand::CrResponse("9 9".into()),
        ManagementCommand::Username("hold release".into()),
        // Unlike Swift, a quote or backslash that a combining mark follows is escaped too.
        ManagementCommand::Password("x\"\u{301} signal SIGTERM \\\u{301}".into()),
    ];
    for command in &samples {
        let Some(line) = command.line() else { continue };
        assert!(!line.contains('\n'));
        assert_eq!(allowed.find_iter(&line).count(), 1, "{line}");
    }
}

#[test]
fn response_file_parse() {
    let r = |s: &str| ManagementResponse::parse(s.as_bytes());
    assert_eq!(
        r("kind=crv1\nresponse=123456\n"),
        Some(ManagementResponse { kind: AuthResponseKind::Crv1, response: "123456".into() })
    );
    assert_eq!(
        r("kind=cancel\nresponse=\n"),
        Some(ManagementResponse { kind: AuthResponseKind::Cancel, response: String::new() })
    );
    assert_eq!(
        r("kind=webauth-ack\n"),
        Some(ManagementResponse { kind: AuthResponseKind::WebauthAck, response: String::new() })
    );
    let long = format!("kind=crv1\nresponse={}\n", "1".repeat(257));
    for bad in [
        "kind=password\nresponse=x\n",
        "kind=crv1\nresponse=1\nextra=2\n",
        "response=1\n",
        "",
        "kind=crv1\nresponse=1\u{7}2\n",
        long.as_str(),
        "kind=crv1 \nresponse=1\n",
    ] {
        assert_eq!(r(bad), None, "{bad:?}");
    }
    assert_eq!(ManagementResponse::parse(&[0x41; 2000]), None);
}

#[test]
fn credentials_file_parse() {
    assert_eq!(
        ManagementCredentials::parse(b"username=bob\npassword=p=w\npacked=1\n"),
        Some(ManagementCredentials { username: "bob".into(), password: "p=w".into(), packed: true })
    );
    assert_eq!(ManagementCredentials::parse(b"username=bob\npassword=x\npacked=0\n").map(|c| c.packed), Some(false));
    assert_eq!(ManagementCredentials::parse(b"username=bob\nevil=1\n"), None);
}

#[test]
fn base64_check() {
    assert!(ManagementParser::is_base64("Ym9i", false));
    assert!(ManagementParser::is_base64("Ym8=", false));
    assert!(ManagementParser::is_base64("", true));
    assert!(!ManagementParser::is_base64("", false));
    assert!(!ManagementParser::is_base64("Ym9", false));
    assert!(!ManagementParser::is_base64("Ym9i\n", false));
    assert!(!ManagementParser::is_base64("Y===", false));
}

/// Parity-review hardening: unlike Swift (whose grapheme-based escaping misses a `"` or `\` followed by a
/// combining mark or a tag character), every `"` and `\` is escaped, so the value stays one quoted token.
#[test]
fn quoting_escapes_every_quote_and_backslash() {
    for value in ["\"\u{301}x", "\\\u{301}x", "a\"\u{E0041}b", "a\\\u{E0041}b", "\"\u{301} signal SIGTERM \\\u{301}"] {
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        assert_eq!(
            ManagementCommand::Password(value.into()).line(),
            Some(format!("password \"Auth\" \"{escaped}\"")),
            "{value:?}"
        );
        assert_eq!(
            ManagementCommand::Username(value.into()).line(),
            Some(format!("username \"Auth\" \"{escaped}\"")),
            "{value:?}"
        );
        // Inside the quotes no `"` is left unescaped, so OpenVPN sees exactly one value token.
        let line = ManagementCommand::Password(value.into()).line().unwrap();
        let inner = &line["password \"Auth\" \"".len()..line.len() - 1];
        let bytes = inner.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' => i += 2,
                b'"' => panic!("unescaped quote in {line:?}"),
                _ => i += 1,
            }
        }
        // cr-response is base64: no quote or backslash at all.
        let cr = ManagementCommand::CrResponse(value.into()).line().unwrap();
        assert!(!cr.contains('"') && !cr.contains('\\'), "{cr}");
        assert_eq!(cr, format!("cr-response {}", macvpn_core::swift_base64::encode(value.as_bytes())));
    }
}
