//! The control API wire protocol: the strict request parser and the reply builders.

use macvpn_core::control::protocol::*;
use macvpn_core::models::{AuthWait, AuthWaitKind, ConnectionState};
use serde_json::{Map, Value, json};

const UUID: &str = "0F8E3A4C-1B2D-4E5F-8A9B-0C1D2E3F4A5B";
const TOKEN: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO-_";

fn parse(s: &str) -> Result<Request, ErrorCode> {
    parse_line(s.as_bytes()).map_err(|e| e.code)
}

fn parse_err(s: &str) -> ParseError {
    parse_line(s.as_bytes()).unwrap_err()
}

fn err(id: Option<u64>, code: ErrorCode) -> ParseError {
    ParseError { id, code }
}

// MARK: Requests

#[test]
fn each_op_parses() {
    assert_eq!(
        parse(r#"{"op":"pair","name":"Remote Desktop"}"#),
        Ok(Request::Pair { id: None, name: "Remote Desktop".into() })
    );
    assert_eq!(
        parse(r#"{"id":7,"op":"pair","name":"Remote Desktop"}"#),
        Ok(Request::Pair { id: Some(7), name: "Remote Desktop".into() })
    );
    assert_eq!(
        parse(&format!(r#"{{"op":"hello","token":"{TOKEN}"}}"#)),
        Ok(Request::Hello { id: None, token: TOKEN.into() })
    );
    assert_eq!(
        parse(&format!(r#"{{"id":0,"op":"hello","token":"{TOKEN}"}}"#)),
        Ok(Request::Hello { id: Some(0), token: TOKEN.into() })
    );
    assert_eq!(parse(r#"{"id":1,"op":"list"}"#), Ok(Request::List { id: 1 }));
    assert_eq!(
        parse(&format!(r#"{{"id":2,"op":"up","connection":"{UUID}"}}"#)),
        Ok(Request::Up { id: 2, connection: UUID.into() })
    );
    assert_eq!(
        parse(&format!(r#"{{"id":3,"op":"down","connection":"{UUID}"}}"#)),
        Ok(Request::Down { id: 3, connection: UUID.into() })
    );
    assert_eq!(parse(r#"{"id":4,"op":"status"}"#), Ok(Request::Status { id: 4 }));
    // The line's own newline (and a CR before it) is fine.
    assert_eq!(parse("{\"id\":4,\"op\":\"status\"}\r\n"), Ok(Request::Status { id: 4 }));
    assert_eq!(parse(r#"{"id":18446744073709551615,"op":"list"}"#), Ok(Request::List { id: u64::MAX }));
}

#[test]
fn request_id_accessor() {
    assert_eq!(parse(r#"{"op":"pair","name":"x"}"#).unwrap().id(), None);
    assert_eq!(parse(r#"{"id":9,"op":"list"}"#).unwrap().id(), Some(9));
}

#[test]
fn unknown_field_is_rejected() {
    assert_eq!(parse(r#"{"id":1,"op":"list","extra":1}"#), Err(ErrorCode::BadRequest));
    assert_eq!(parse(r#"{"op":"pair","name":"x","token":"y"}"#), Err(ErrorCode::BadRequest));
    // `connection` belongs to up/down only.
    assert_eq!(parse(&format!(r#"{{"id":1,"op":"status","connection":"{UUID}"}}"#)), Err(ErrorCode::BadRequest));
}

#[test]
fn malformed_requests_are_bad_request() {
    for s in [
        "",
        "null",
        "[]",
        "\"list\"",
        "{}",
        r#"{"id":1}"#,
        r#"{"id":1,"op":5}"#,
        r#"{"op":"list"}"#,
        r#"{"id":-1,"op":"list"}"#,
        r#"{"id":1.5,"op":"list"}"#,
        r#"{"id":"1","op":"list"}"#,
        r#"{"id":null,"op":"list"}"#,
        r#"{"id":1,"op":"up"}"#,
        r#"{"id":1,"op":"list"} {"id":2,"op":"list"}"#,
        r#"{"id":1,"op":"list","id":2}"#,
        r#"{"id":1,"op":"list",}"#,
        "\u{feff}{\"id\":1,\"op\":\"list\"}",
        r#"{"op":"pair"}"#,
        r#"{"op":"hello"}"#,
    ] {
        assert_eq!(parse(s), Err(ErrorCode::BadRequest), "{s:?}");
    }
}

#[test]
fn unknown_op_is_unsupported() {
    assert_eq!(parse(r#"{"id":1,"op":"reboot"}"#), Err(ErrorCode::Unsupported));
    assert_eq!(parse(r#"{"id":1,"op":"reboot","anything":true}"#), Err(ErrorCode::Unsupported));
    assert_eq!(parse(r#"{"op":"LIST","id":1}"#), Err(ErrorCode::Unsupported));
}

#[test]
fn line_length_limit() {
    let base = r#"{"id":1,"op":"list"}"#;
    let fit = format!("{base}{}", " ".repeat(MAX_LINE - base.len()));
    assert_eq!(fit.len(), MAX_LINE);
    assert_eq!(parse(&fit), Ok(Request::List { id: 1 }));
    let long = format!("{base}{}", " ".repeat(MAX_LINE + 1 - base.len()));
    assert_eq!(long.len(), 4097);
    assert_eq!(parse(&long), Err(ErrorCode::BadRequest));
}

#[test]
fn bad_utf8_is_bad_request() {
    let mut bytes = br#"{"op":"pair","name":"x"#.to_vec();
    bytes.extend_from_slice(&[0xFF, 0xFE]);
    bytes.extend_from_slice(br#""}"#);
    assert_eq!(parse_line(&bytes), Err(err(None, ErrorCode::BadRequest)));
    assert_eq!(parse_line(&[0xC3]), Err(err(None, ErrorCode::BadRequest)));
}

#[test]
fn bad_uuid_is_bad_request() {
    for c in [
        "",
        "not-a-uuid",
        "0F8E3A4C1B2D4E5F8A9B0C1D2E3F4A5B",
        "0F8E3A4C-1B2D-4E5F-8A9B-0C1D2E3F4A5",
        "0F8E3A4C-1B2D-4E5F-8A9B-0C1D2E3F4A5BC",
        "0F8E3A4C-1B2D-4E5F-8A9B-0C1D2E3F4A5G",
        "{0F8E3A4C-1B2D-4E5F-8A9B-0C1D2E3F4A5}",
        "0F8E3A4C-1B2D-4E5F-8A9B0-C1D2E3F4A5B",
        "../../../../etc/passwd/xxxxxxxxxxxxxx",
    ] {
        assert_eq!(parse(&format!(r#"{{"id":2,"op":"up","connection":"{c}"}}"#)), Err(ErrorCode::BadRequest), "{c}");
        assert_eq!(parse(&format!(r#"{{"id":2,"op":"down","connection":"{c}"}}"#)), Err(ErrorCode::BadRequest), "{c}");
    }
    // Lower case is UUID-shaped too.
    let lower = UUID.to_lowercase();
    assert_eq!(
        parse(&format!(r#"{{"id":2,"op":"up","connection":"{lower}"}}"#)),
        Ok(Request::Up { id: 2, connection: lower })
    );
}

/// A malformed token is not a parse error: the server answers it like a wrong one (`unauthorized` after the
/// delay), so the reply never tells which part was wrong. Only the token's shape is checked, by the server.
#[test]
fn a_malformed_token_still_parses() {
    let short = &TOKEN[..42];
    let long = format!("{TOKEN}A");
    let padded = format!("{}=", &TOKEN[..42]);
    let standard_alphabet = format!("{}+", &TOKEN[..42]);
    let slash = format!("{}/", &TOKEN[..42]);
    let space = format!("{} ", &TOKEN[..42]);
    let unicode = format!("{}é", &TOKEN[..41]);
    for t in ["", short, &long, &padded, &standard_alphabet, &slash, &space, &unicode] {
        assert_eq!(
            parse(&format!(r#"{{"op":"hello","token":"{t}"}}"#)),
            Ok(Request::Hello { id: None, token: t.to_string() }),
            "{t:?}"
        );
        assert!(!is_token_shaped(t), "{t:?}");
    }
    assert!(is_token_shaped(TOKEN));
    // A structurally invalid hello is still a bad request.
    assert_eq!(parse(r#"{"op":"hello","token":5}"#), Err(ErrorCode::BadRequest));
    assert_eq!(parse(r#"{"op":"hello"}"#), Err(ErrorCode::BadRequest));
    assert_eq!(parse(&format!(r#"{{"op":"hello","token":"{TOKEN}","x":1}}"#)), Err(ErrorCode::BadRequest));
}

#[test]
fn name_is_sanitized_or_rejected() {
    // A control character becomes a space; a bidi override (Cf) is dropped; the ends are trimmed.
    assert_eq!(
        parse(r#"{"op":"pair","name":"Remote\tDesk\u0007top"}"#),
        Ok(Request::Pair { id: None, name: "Remote Desk top".into() })
    );
    assert_eq!(
        parse(r#"{"op":"pair","name":"\u202Egnp.exe\u200B"}"#),
        Ok(Request::Pair { id: None, name: "gnp.exe".into() })
    );
    assert_eq!(parse(r#"{"op":"pair","name":"  x \n"}"#), Ok(Request::Pair { id: None, name: "x".into() }));
    // Nothing printable left, or too long.
    for name in [r#""#, r#"   "#, r#"\u202E\u200B"#, r#"\n\t"#] {
        assert_eq!(parse(&format!(r#"{{"op":"pair","name":"{name}"}}"#)), Err(ErrorCode::BadRequest), "{name}");
    }
    let n64 = "é".repeat(64);
    assert_eq!(parse(&format!(r#"{{"op":"pair","name":"{n64}"}}"#)), Ok(Request::Pair { id: None, name: n64.clone() }));
    let n65 = "a".repeat(65);
    assert_eq!(parse(&format!(r#"{{"op":"pair","name":"{n65}"}}"#)), Err(ErrorCode::BadRequest));
    assert_eq!(parse(r#"{"op":"pair","name":null}"#), Err(ErrorCode::BadRequest));
}

#[test]
fn debug_output_redacts_the_token() {
    let req = parse(&format!(r#"{{"id":3,"op":"hello","token":"{TOKEN}"}}"#)).unwrap();
    let text = format!("{req:?}");
    assert!(!text.contains(TOKEN), "{text}");
    assert!(text.contains("Hello") && text.contains("redacted"), "{text}");
    // The other requests still show their fields.
    let up = format!("{:?}", Request::Up { id: 2, connection: UUID.into() });
    assert!(up.contains(UUID), "{up}");
    let pair = format!("{:?}", Request::Pair { id: None, name: "Remote Desktop".into() });
    assert!(pair.contains("Remote Desktop"), "{pair}");
}

#[test]
fn parse_errors_carry_the_id() {
    assert_eq!(parse_err(r#"{"id":5,"op":"foo"}"#), err(Some(5), ErrorCode::Unsupported));
    assert_eq!(parse_err(r#"{"id":6,"op":"list","extra":1}"#), err(Some(6), ErrorCode::BadRequest));
    assert_eq!(parse_err(r#"{"id":7,"op":"up","connection":"nope"}"#), err(Some(7), ErrorCode::BadRequest));
    assert_eq!(parse_err(r#"{"id":8,"op":"hello","token":5}"#), err(Some(8), ErrorCode::BadRequest));
    assert_eq!(parse_err(r#"{"id":9,"op":"pair","name":"   "}"#), err(Some(9), ErrorCode::BadRequest));
    assert_eq!(parse_err(r#"{"op":"pair","name":"   "}"#), err(None, ErrorCode::BadRequest));
    assert_eq!(parse_err(r#"{"id":"x","op":"list"}"#), err(None, ErrorCode::BadRequest));
    assert_eq!(parse_err("not json"), err(None, ErrorCode::BadRequest));
    // An over-long line is not parsed at all, so its id is unknown.
    let long = format!(r#"{{"id":1,"op":"list"}}{}"#, " ".repeat(MAX_LINE));
    assert_eq!(parse_err(&long), err(None, ErrorCode::BadRequest));
}

#[test]
fn duplicate_keys_are_always_bad_request() {
    for s in [
        r#"{"id":1,"op":"list","op":"list"}"#,
        r#"{"id":1,"op":"list","op":"foo"}"#,
        r#"{"id":1,"op":"foo","op":"list"}"#,
        r#"{"id":1,"op":"foo","op":"bar"}"#,
        r#"{"id":1,"op":"foo","x":1,"x":2}"#,
    ] {
        assert_eq!(parse_err(s), err(Some(1), ErrorCode::BadRequest), "{s}");
    }
    assert_eq!(parse_err(r#"{"id":1,"id":2,"op":"list"}"#), err(Some(1), ErrorCode::BadRequest));
}

#[test]
fn id_edge_cases() {
    // One past u64::MAX and a float are not ids.
    assert_eq!(parse_err(r#"{"id":18446744073709551616,"op":"list"}"#), err(None, ErrorCode::BadRequest));
    assert_eq!(parse_err(r#"{"id":1e2,"op":"list"}"#), err(None, ErrorCode::BadRequest));
    // `null` is an absent id where the id is optional.
    assert_eq!(parse(r#"{"id":null,"op":"pair","name":"x"}"#), Ok(Request::Pair { id: None, name: "x".into() }));
    assert_eq!(
        parse(&format!(r#"{{"id":null,"op":"hello","token":"{TOKEN}"}}"#)),
        Ok(Request::Hello { id: None, token: TOKEN.into() })
    );
}

#[test]
fn nested_unknown_field_is_bad_request() {
    assert_eq!(parse_err(r#"{"id":1,"op":"list","extra":{"a":1}}"#), err(Some(1), ErrorCode::BadRequest));
    assert_eq!(
        parse_err(r#"{"id":1,"op":"up","connection":{"id":"0F8E3A4C-1B2D-4E5F-8A9B-0C1D2E3F4A5B"}}"#),
        err(Some(1), ErrorCode::BadRequest)
    );
    assert_eq!(parse_err(r#"{"id":1,"op":"list","op2":["list"]}"#), err(Some(1), ErrorCode::BadRequest));
}

#[test]
fn name_byte_cap() {
    // 64 characters of 4 bytes each: exactly 256 bytes.
    let name: String = std::iter::repeat_n('\u{1F600}', 64).collect();
    assert_eq!(name.len(), 256);
    assert_eq!(parse(&format!(r#"{{"op":"pair","name":"{name}"}}"#)), Ok(Request::Pair { id: None, name }));
    // 64 characters, each with stacked combining marks: within 64 characters but over 256 bytes.
    let heavy: String = (0..64).map(|_| "e\u{301}\u{301}\u{301}\u{301}").collect();
    assert_eq!(heavy.chars().filter(|c| *c == 'e').count(), 64);
    assert!(heavy.len() > 256);
    assert_eq!(parse(&format!(r#"{{"op":"pair","name":"{heavy}"}}"#)), Err(ErrorCode::BadRequest));
}

// MARK: Replies

fn decode(line: &str) -> Value {
    assert!(line.ends_with('\n'), "{line:?}");
    assert_eq!(line.matches('\n').count(), 1, "{line:?}");
    serde_json::from_str(line).unwrap()
}

#[test]
fn reply_ok_round_trips() {
    let mut extra = Map::new();
    extra.insert("api".into(), json!(API_VERSION));
    assert_eq!(decode(&reply_ok(None, extra)), json!({"ok": true, "api": 1}));

    let mut extra = Map::new();
    extra.insert("state".into(), json!("connected"));
    // `extra` cannot override `id` or `ok`.
    extra.insert("ok".into(), json!(false));
    extra.insert("id".into(), json!(99));
    assert_eq!(decode(&reply_ok(Some(2), extra)), json!({"id": 2, "ok": true, "state": "connected"}));
    assert_eq!(decode(&reply_ok(Some(5), Map::new())), json!({"id": 5, "ok": true}));
}

#[test]
fn reply_err_round_trips() {
    assert_eq!(decode(&reply_err(None, ErrorCode::Unauthorized, None)), json!({"ok": false, "error": "unauthorized"}));
    assert_eq!(
        decode(&reply_err(Some(2), ErrorCode::Failed, Some("TLS handshake failed"))),
        json!({"id": 2, "ok": false, "error": "failed", "message": "TLS handshake failed"})
    );
}

#[test]
fn error_codes_are_snake_case() {
    let all = [
        (ErrorCode::Unauthorized, "unauthorized"),
        (ErrorCode::NotAllowed, "not_allowed"),
        (ErrorCode::UnknownConnection, "unknown_connection"),
        (ErrorCode::Busy, "busy"),
        (ErrorCode::SetupRequired, "setup_required"),
        (ErrorCode::MfaCancelled, "mfa_cancelled"),
        (ErrorCode::MfaTimeout, "mfa_timeout"),
        (ErrorCode::CredentialsCancelled, "credentials_cancelled"),
        (ErrorCode::Failed, "failed"),
        (ErrorCode::AppQuitting, "app_quitting"),
        (ErrorCode::Disabled, "disabled"),
        (ErrorCode::Unsupported, "unsupported"),
        (ErrorCode::BadRequest, "bad_request"),
        (ErrorCode::Denied, "denied"),
    ];
    for (code, s) in all {
        assert_eq!(code.as_str(), s);
        assert_eq!(decode(&reply_err(Some(1), code, None))["error"], json!(s));
    }
}

#[test]
fn event_state_round_trips() {
    assert_eq!(
        decode(&event_state(UUID, WireState::WaitingForMfa, None)),
        json!({"event": "state", "connection": UUID, "state": "waiting_for_mfa"})
    );
    assert_eq!(
        decode(&event_state(UUID, WireState::Failed, Some("Timed out"))),
        json!({"event": "state", "connection": UUID, "state": "failed", "reason": "Timed out"})
    );
    let states = [
        (WireState::Disconnected, "disconnected"),
        (WireState::Connecting, "connecting"),
        (WireState::WaitingForMfa, "waiting_for_mfa"),
        (WireState::WaitingForCredentials, "waiting_for_credentials"),
        (WireState::Connected, "connected"),
        (WireState::Disconnecting, "disconnecting"),
        (WireState::Failed, "failed"),
    ];
    for (state, s) in states {
        assert_eq!(state.as_str(), s);
        assert_eq!(decode(&event_state(UUID, state, None))["state"], json!(s));
    }
}

#[test]
fn event_closing_names_the_reason() {
    assert_eq!(decode(&event_closing(ErrorCode::Disabled)), json!({"event": "closing", "reason": "disabled"}));
    assert_eq!(decode(&event_closing(ErrorCode::AppQuitting)), json!({"event": "closing", "reason": "app_quitting"}));
    assert!(event_closing(ErrorCode::Disabled).ends_with('\n'));
}

#[test]
fn quote_and_newline_stay_on_one_line() {
    let nasty = "Remote \"Desktop\"\n{\"event\":\"state\"}\r\u{2028}";
    let line = reply_err(Some(1), ErrorCode::Failed, Some(nasty));
    assert_eq!(decode(&line)["message"], json!(nasty));
    let line = event_state(UUID, WireState::Failed, Some(nasty));
    assert_eq!(decode(&line)["reason"], json!(nasty));
    let mut extra = Map::new();
    extra.insert("name".into(), json!(nasty));
    assert_eq!(decode(&reply_ok(Some(1), extra))["name"], json!(nasty));
}

#[test]
fn wire_state_mapping() {
    let wait = |kind| ConnectionState::AwaitingAuth(AuthWait { kind, deadline: None });
    assert_eq!(wire_state(&ConnectionState::Disconnected), WireState::Disconnected);
    assert_eq!(wire_state(&ConnectionState::Connecting), WireState::Connecting);
    assert_eq!(wire_state(&wait(AuthWaitKind::Code)), WireState::WaitingForMfa);
    assert_eq!(wire_state(&wait(AuthWaitKind::Web)), WireState::WaitingForMfa);
    assert_eq!(wire_state(&wait(AuthWaitKind::Credentials)), WireState::WaitingForCredentials);
    assert_eq!(wire_state(&ConnectionState::Connected { ip: None, since: None }), WireState::Connected);
    assert_eq!(wire_state(&ConnectionState::Disconnecting), WireState::Disconnecting);
    assert_eq!(wire_state(&ConnectionState::Failed("x".into())), WireState::Failed);
}

#[test]
fn unsafe_path_characters_are_detected_and_escaped() {
    let normal = "/Applications/Remote Desktop.app/Contents/MacOS/Remote Desktop";
    assert!(!has_unsafe_text_chars(normal));
    assert_eq!(escape_unsafe_text(normal), normal);
    // Accented letters and other ordinary non-ASCII text are fine.
    assert!(!has_unsafe_text_chars("/Users/x/Fejlesztés/ügyfél"));

    let newline = "/tmp/a\n2026-10-19T00:00:00Z  hello from “Fake”";
    assert!(has_unsafe_text_chars(newline));
    assert_eq!(escape_unsafe_text(newline), "/tmp/a\\u{a}2026-10-19T00:00:00Z  hello from “Fake”");

    let rlo = "/tmp/evil\u{202E}gpj.app";
    assert!(has_unsafe_text_chars(rlo));
    assert_eq!(escape_unsafe_text(rlo), "/tmp/evil\\u{202e}gpj.app");

    for c in
        ['\u{0}', '\u{1b}', '\u{7f}', '\u{85}', '\u{9b}', '\u{200b}', '\u{2066}', '\u{feff}', '\u{2028}', '\u{e0041}']
    {
        assert!(is_unsafe_text_char(c), "{:x}", c as u32);
    }
}
