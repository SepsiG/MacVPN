//! The WinVPN Service's pipe envelope (see `macvpn_core::service_proto`).

use std::io::Read;

use macvpn_core::service_proto::{
    self as proto, EngineFacts, LogSlice, OpenVpnFacts, ProtoError, Request, Response, WireGuardFacts,
};

fn request_bytes(args: &[&str], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    proto::write_request(&mut out, args, body).unwrap();
    out
}

#[test]
fn a_request_round_trips() {
    let body = b"config 7\nclient\n\npassword=x\n";
    let bytes = request_bytes(&["up", "openvpn", "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "--lang", "hu"], body);
    assert!(bytes.starts_with(b"winvpn 1\nargs 5\nup\nopenvpn\n"));
    let Request { args, body: got } = proto::read_request(&mut bytes.as_slice()).unwrap();
    assert_eq!(args, ["up", "openvpn", "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "--lang", "hu"]);
    assert_eq!(got.as_slice(), body);
}

#[test]
fn a_response_round_trips() {
    let r = Response { code: 1, stdout: b"[]\n".to_vec(), stderr: "Érvénytelen azonosító\n".as_bytes().to_vec() };
    let mut out = Vec::new();
    proto::write_response(&mut out, &r).unwrap();
    assert!(out.starts_with(b"winvpn 1\nexit 1\nstdout 3\n[]\nstderr "));
    assert_eq!(proto::read_response(&mut out.as_slice()).unwrap(), r);
    let negative = Response { code: -1, stdout: vec![], stderr: vec![] };
    let mut out = Vec::new();
    proto::write_response(&mut out, &negative).unwrap();
    assert_eq!(proto::read_response(&mut out.as_slice()).unwrap(), negative);
}

#[test]
fn arguments_are_restricted() {
    for bad in ["", "a b", "a\nb", "ä", "a;b", "../x", "a\\b", "\"x\""] {
        assert!(!proto::is_valid_arg(bad), "{bad:?}");
        let mut sink = Vec::new();
        assert!(proto::write_request(&mut sink, &[bad], b"").is_err(), "{bad:?}");
    }
    for good in ["up", "--accept-risky", "a,b-c", "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "--lang=hu", "12345"] {
        assert!(proto::is_valid_arg(good), "{good}");
    }
    assert!(!proto::is_valid_arg(&"a".repeat(proto::ARG_MAX + 1)));
    let many: Vec<&str> = std::iter::repeat_n("x", proto::MAX_ARGS + 1).collect();
    assert!(proto::write_request(&mut Vec::new(), &many, b"").is_err());
    // A request names its command: no arguments at all is refused both ways.
    assert!(proto::write_request(&mut Vec::new(), &[], b"").is_err());
    assert!(proto::read_request(&mut &b"winvpn 1\nargs 0\nbody 0\n"[..]).is_err());
}

#[test]
fn malformed_requests_are_refused() {
    let cases: &[&[u8]] = &[
        b"",
        b"winvpn 2\nargs 0\nbody 0\n",
        b"winvpn 1\nargs 01\nx\nbody 0\n",
        b"winvpn 1\nargs 1\nx\nbody 1\n",
        b"winvpn 1\nargs 1\nx y\nbody 0\n",
        b"winvpn 1\nargs 17\n",
        b"winvpn 1\nargs 0\nbody 0\nextra",
        b"winvpn 1\r\nargs 0\nbody 0\n",
        b"winvpn 1\nargs 0\nbody -1\n",
        b"winvpn 1\nargs 0\nbody 99999999999\n",
    ];
    for c in cases {
        assert!(proto::read_request(&mut &c[..]).is_err(), "{:?}", String::from_utf8_lossy(c));
    }
}

#[test]
fn an_oversized_body_is_refused_before_it_is_read() {
    let header = format!("winvpn 1\nargs 1\nstatus\nbody {}\n", proto::BODY_MAX + 1);
    let mut src = std::io::Cursor::new(header.into_bytes()).chain(std::io::repeat(b'#'));
    assert_eq!(proto::read_request(&mut src).err(), Some(ProtoError::TooLarge));
}

#[test]
fn the_body_never_appears_in_debug() {
    let bytes = request_bytes(&["respond", "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0"], b"otp=SECRET123\n");
    let request = proto::read_request(&mut bytes.as_slice()).unwrap();
    let shown = format!("{request:?}");
    assert!(!shown.contains("SECRET123") && !shown.contains("83, 69, 67"), "{shown}");
    assert!(shown.contains("respond"), "{shown}");
}

#[test]
fn trailing_bytes_after_the_body_are_not_read() {
    // One request per connection: the reader stops after the body (the server then answers).
    let mut bytes = request_bytes(&["status"], b"");
    bytes.extend_from_slice(b"junk");
    let mut slice = bytes.as_slice();
    assert!(proto::read_request(&mut slice).is_ok());
    assert_eq!(slice, b"junk");
}

#[test]
fn engine_facts_round_trip_as_json() {
    let facts = EngineFacts {
        service_version: proto::SERVICE_VERSION,
        problem: None,
        openvpn: OpenVpnFacts {
            version: Some("2.6.14".into()),
            path: Some(r"C:\Program Files\OpenVPN\bin\openvpn.exe".into()),
            dco: Some("2.6.1".into()),
            tap_windows6: Some("9.27.0".into()),
            problem: None,
        },
        wireguard: WireGuardFacts { dll_version: Some("1.1.0".into()), problem: None },
    };
    let json = facts.to_json();
    assert_eq!(EngineFacts::parse(json.as_bytes()), Some(facts));
    assert_eq!(EngineFacts::parse(b"{}"), None);
    assert_eq!(EngineFacts::parse(&vec![b' '; proto::FACTS_MAX + 1]), None);
}

#[test]
fn openvpn_facts_round_trip_as_json() {
    let facts = OpenVpnFacts {
        version: Some("2.7.8".into()),
        path: Some(r"C:\Program Files\OpenVPN\bin\openvpn.exe".into()),
        dco: Some("2.8.13.0".into()),
        tap_windows6: None,
        problem: None,
    };
    assert_eq!(OpenVpnFacts::parse(facts.to_json().as_bytes()), Some(facts));
    assert_eq!(OpenVpnFacts::parse(b"[]"), None);
    assert_eq!(
        OpenVpnFacts::parse(br#"{"version":null,"path":null,"dco":null,"tapWindows6":null,"problem":null,"x":1}"#),
        None
    );
    assert_eq!(OpenVpnFacts::parse(&vec![b' '; proto::FACTS_MAX + 1]), None);
}

#[test]
fn log_slices_round_trip() {
    let s = LogSlice { generation: 7, size: 300, start: 290, data: b"0123456789".to_vec() };
    let bytes = s.encode();
    assert_eq!(&bytes[..12], b"7 300 290\n01");
    assert_eq!(LogSlice::parse(&bytes), Some(s));
    for bad in [&b""[..], b"7 300\nx", b"x 1 1\n", b"1 1 2\n", b"1 5 0\n123456", b"01 1 0\nx"] {
        assert_eq!(LogSlice::parse(bad), None, "{:?}", String::from_utf8_lossy(bad));
    }
}

#[test]
fn engine_updates_round_trip_with_plain_versions_only() {
    use macvpn_core::service_proto::EngineUpdate;
    let u = EngineUpdate { installed: Some("1.1.0".into()), available: Some("1.2.0".into()) };
    assert_eq!(EngineUpdate::parse(u.to_json().as_bytes()), Some(u));
    let none = EngineUpdate { installed: Some("1.1.0".into()), available: None };
    assert_eq!(none.to_json(), r#"{"installed":"1.1.0","available":null}"#);
    assert_eq!(EngineUpdate::parse(none.to_json().as_bytes()), Some(none));
    for bad in [
        &br#"{"installed":"1.1.0","available":"1.2 <b>"}"#[..],
        br#"{"installed":"","available":null}"#,
        br#"{"installed":"1.1.0","available":null,"x":1}"#,
        b"[]",
    ] {
        assert_eq!(EngineUpdate::parse(bad), None, "{}", String::from_utf8_lossy(bad));
    }
    assert!(proto::is_valid_arg(proto::WIREGUARD_CHECK) && proto::is_valid_arg(proto::WIREGUARD_UPDATE));
    assert_eq!(proto::UPDATE_BUSY, 3);
}
