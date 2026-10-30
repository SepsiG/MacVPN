//! linvpn-logd's pure rules (L-b Task 10, resolved points 3, 9, 10; the trusted senders: Task 18).
use macvpn_core::logd::{self, Entry, Request, Response, Senders, Source};
use macvpn_core::nm_plan::names;
use uuid::Uuid;

const ID: &str = "0b5f7c1e-2d3a-4b5c-8d6e-7f8091a2b3c4";
/// `names::nm_uuid(1001, ID)`, written into the fixtures by hand.
const NM_1001: &str = "93959792-b4e2-8e81-ae54-6ed8d08d927d";
/// The fixtures' `nm-openvpn` uid.
const SENDERS: Senders = Senders { nm_openvpn_uid: Some(984) };

fn entries(name: &str) -> Vec<Entry> {
    let text = std::fs::read_to_string(format!("{}/tests/fixtures/logd/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap();
    text.lines().filter_map(logd::parse_entry).collect()
}

#[test]
fn the_fixtures_use_the_derived_uuid() {
    assert_eq!(names::nm_uuid(1001, &Uuid::parse_str(ID).unwrap()).to_string(), NM_1001);
    for f in ["own.jsonl", "shared.jsonl"] {
        let text = std::fs::read_to_string(format!("{}/tests/fixtures/logd/{f}", env!("CARGO_MANIFEST_DIR"))).unwrap();
        assert_eq!(entries(f).len(), text.lines().count(), "{f}: every fixture line parses");
    }
}

#[test]
fn a_request_round_trips_and_strict_parsing_refuses_anything_else() {
    let r = Request {
        connection: Uuid::parse_str(ID).unwrap(),
        since_usec: 1_700_000_000_000_000,
        cursor: Some("s=abc;i=1f;b=00ff;m=12;t=34;x=56".into()),
    };
    assert_eq!(Request::parse(&r.encode()), Some(r.clone()));
    for bad in [
        "",
        "linvpn-logd-v1\n",
        "linvpn-logd-v2 x 0 -\n",
        &r.encode().replace("s=abc", "s=a b"),
        &format!("{}junk", r.encode()),
    ] {
        assert_eq!(Request::parse(bad), None, "{bad:?}");
    }
    assert!(r.encode().len() <= logd::MAX_REQUEST);
}

#[test]
fn a_request_without_a_cursor_round_trips_and_odd_forms_are_refused() {
    let r = Request { connection: Uuid::parse_str(ID).unwrap(), since_usec: 0, cursor: None };
    assert_eq!(r.encode(), format!("linvpn-logd-v1 {ID} 0 -\n"));
    assert_eq!(Request::parse(&r.encode()), Some(r));
    let upper = ID.to_uppercase();
    let long = "a".repeat(257);
    for bad in [
        format!("linvpn-logd-v1 {upper} 0 -\n"),
        format!("linvpn-logd-v1 {ID} 01 -\n"),
        format!("linvpn-logd-v1 {ID} -1 -\n"),
        format!("linvpn-logd-v1 {ID} 99999999999999999999 -\n"),
        format!("linvpn-logd-v1 {ID} 0 -"),
        format!("linvpn-logd-v1 {ID} 0 -\r\n"),
        format!("linvpn-logd-v1  {ID} 0 -\n"),
        format!("linvpn-logd-v1 {ID} 0 {long}\n"),
        format!("linvpn-logd-v1 {ID} 0 a/b\n"),
        format!("linvpn-logd-v1 {ID} 0 - x\n"),
    ] {
        assert_eq!(Request::parse(&bad), None, "{bad:?}");
    }
}

#[test]
fn only_the_callers_own_lines_are_returned() {
    let nm = names::nm_uuid(1001, &Uuid::parse_str(ID).unwrap()).to_string();
    let out = logd::select(&entries("own.jsonl"), &entries("own.jsonl"), &[], &nm, 0, &SENDERS);
    assert!(out.lines.iter().any(|l| l.source == Source::NetworkManager));
    assert!(out.lines.iter().any(|l| l.source == Source::OpenVpn));
    assert!(out.lines.iter().any(|l| matches!(&l.source, Source::Plugin(p) if p == "nm-openvpn-serv")));
    assert!(out.lines.iter().all(|l| !l.text.contains("OTHER")), "another connection's lines never pass");
    assert!(!out.withheld);
}

#[test]
fn the_selection_is_sorted_carries_the_last_cursor_and_honours_since() {
    let all = entries("own.jsonl");
    let out = logd::select(&all, &all, &[], NM_1001, 0, &SENDERS);
    assert_eq!(out.lines.len(), 7);
    assert!(out.lines.windows(2).all(|w| w[0].usec <= w[1].usec));
    let last = all.iter().find(|e| e.usec == out.lines.last().unwrap().usec).unwrap();
    assert_eq!(out.cursor.as_deref(), Some(last.cursor.as_str()));
    let bytes = out.lines.iter().find(|l| l.text.starts_with("TLS: Initial packet")).unwrap();
    assert!(bytes.text.ends_with('\u{FFFD}'), "a byte-array MESSAGE is decoded lossily: {:?}", bytes.text);
    let later = logd::select(&all, &all, &[], NM_1001, 1_700_000_001_250_000, &SENDERS);
    assert!(later.lines.iter().all(|l| l.usec >= 1_700_000_001_250_000));
    assert!(!later.lines.is_empty());
}

#[test]
fn plugin_lines_are_withheld_when_another_vpn_shares_the_window() {
    let nm = names::nm_uuid(1001, &Uuid::parse_str(ID).unwrap()).to_string();
    let out = logd::select(&entries("shared.jsonl"), &entries("shared.jsonl"), &[], &nm, 0, &SENDERS);
    assert!(out.withheld);
    assert!(out.lines.iter().all(|l| !matches!(l.source, Source::Plugin(_))));
    assert!(out.lines.iter().any(|l| l.source == Source::NetworkManager), "own NM lines still pass");
}

#[test]
fn the_message_fallback_attributes_nm_lines_without_the_field() {
    let line = |usec: u64, msg: &str| {
        let j = serde_json::json!({"__REALTIME_TIMESTAMP": usec.to_string(), "__CURSOR": format!("i={usec}"), "SYSLOG_IDENTIFIER": "NetworkManager", "MESSAGE": msg, "_UID": "0", "_SYSTEMD_UNIT": "NetworkManager.service", "_COMM": "NetworkManager"});
        logd::parse_entry(&j.to_string()).unwrap()
    };
    let plugin = logd::parse_entry(r#"{"__REALTIME_TIMESTAMP":"15","__CURSOR":"p","SYSLOG_IDENTIFIER":"charon-nm","MESSAGE":"establishing CHILD_SA","_UID":"0","_COMM":"charon-nm"}"#).unwrap();
    let own = vec![
        line(10, &format!("vpn[0x55d0c0ffee00,{NM_1001},\"Work\"]: starting strongswan")),
        plugin,
        line(20, &format!("<info>  [1700000000.0000] policy: set 'Work' ({NM_1001}) as default")),
        line(30, &format!("vpn[0x55d0c0ffee00,{NM_1001}x,\"Work\"]: not ours")),
        line(40, &format!("activating ({})", NM_1001.to_uppercase())),
    ];
    let out = logd::select(&own, &own, &[], NM_1001, 0, &SENDERS);
    assert_eq!(out.lines.iter().map(|l| l.usec).collect::<Vec<_>>(), [10, 20], "NM's lines by their text");
    assert!(out.withheld, "without NM's VPN domain and start no plugin line can be attributed");
}

#[test]
fn a_malformed_uuid_selects_nothing() {
    let all = entries("own.jsonl");
    for bad in ["", "x", &NM_1001.to_uppercase(), &format!("{NM_1001} ")] {
        let out = logd::select(&all, &all, &[], bad, 0, &SENDERS);
        assert!(out.lines.is_empty() && !out.withheld && out.cursor.is_none(), "{bad:?}");
    }
}

#[test]
fn another_uid_derives_another_uuid_so_it_sees_nothing() {
    let other = names::nm_uuid(1002, &Uuid::parse_str(ID).unwrap()).to_string();
    let out = logd::select(&entries("own.jsonl"), &entries("own.jsonl"), &[], &other, 0, &SENDERS);
    assert!(out.lines.is_empty());
}

#[test]
fn a_response_is_bounded_and_round_trips() {
    let nm = names::nm_uuid(1001, &Uuid::parse_str(ID).unwrap()).to_string();
    let out = logd::select(&entries("own.jsonl"), &entries("own.jsonl"), &[], &nm, 0, &SENDERS);
    let wire = out.encode();
    assert!(wire.len() <= logd::MAX_RESPONSE);
    assert_eq!(Response::parse(&wire), Some(out));
    let shared = logd::select(&entries("shared.jsonl"), &entries("shared.jsonl"), &[], &nm, 0, &SENDERS);
    assert!(shared.encode().contains("\nW\nC "));
    assert_eq!(Response::parse(&shared.encode()), Some(shared));
    let empty = Response::default();
    assert_eq!(empty.encode(), "C -\nE\n");
    assert_eq!(Response::parse("C -\nE\n"), Some(empty));
}

#[test]
fn a_large_selection_keeps_the_newest_lines_within_the_bounds() {
    let mut all = Vec::new();
    let msg = "y".repeat(5000);
    for i in 0..3000u64 {
        let j = serde_json::json!({"__REALTIME_TIMESTAMP": (1000 + i).to_string(), "__CURSOR": format!("i={i}"), "SYSLOG_IDENTIFIER": "NetworkManager", "NM_CONNECTION": NM_1001, "NM_LOG_DOMAINS": "VPN", "MESSAGE": format!("{i} {msg}"), "_UID": "0", "_SYSTEMD_UNIT": "NetworkManager.service", "_COMM": "NetworkManager"});
        all.push(logd::parse_entry(&j.to_string()).unwrap());
    }
    let out = logd::select(&all, &all, &[], NM_1001, 0, &SENDERS);
    assert!(out.lines.len() <= logd::MAX_LINES);
    let wire = out.encode();
    assert!(wire.len() <= logd::MAX_RESPONSE, "{}", wire.len());
    assert_eq!(out.lines.last().unwrap().usec, 3999, "the newest line is kept");
    assert_eq!(out.cursor.as_deref(), Some("i=2999"));
    assert!(out.lines.iter().all(|l| l.text.len() <= logd::MAX_TEXT && l.text.ends_with('…')));
    assert_eq!(Response::parse(&wire), Some(out));

    let few: Vec<Entry> = all.iter().map(|e| Entry { message: "short".into(), ..e.clone() }).collect();
    let out = logd::select(&few, &few, &[], NM_1001, 0, &SENDERS);
    assert_eq!(out.lines.len(), logd::MAX_LINES);
    assert_eq!(out.lines[0].usec, 1000 + 3000 - logd::MAX_LINES as u64);
}

#[test]
fn a_response_parse_refuses_anything_else() {
    for bad in [
        "",
        "C -\n",
        "E\n",
        "C -\nE\nL 1 nm x\n",
        "L 1 nm x\nC -\nE",
        "L 01 nm x\nC -\nE\n",
        "L 1 bogus x\nC -\nE\n",
        "L 1 plugin:Bad x\nC -\nE\n",
        "L 1 plugin: x\nC -\nE\n",
        "L 1 nm a\u{1b}b\nC -\nE\n",
        "L 1 nm a\u{85}b\nC -\nE\n",
        "L 1 nm a\u{2028}b\nC -\nE\n",
        "W\nL 1 nm x\nC -\nE\n",
        "W\nW\nC -\nE\n",
        "C a b\nE\n",
        "C a/b\nE\n",
        "L 1 nm x\r\nC -\nE\n",
    ] {
        assert_eq!(Response::parse(bad), None, "{bad:?}");
    }
    let long = format!("L 1 nm {}\nC -\nE\n", "x".repeat(logd::MAX_TEXT + 1));
    assert_eq!(Response::parse(&long), None);
    assert!(Response::parse("L 1 plugin:xl2tpd hello world\nL 2 openvpn \nW\nC i=1\nE\n").is_some());
}

#[test]
fn control_characters_in_messages_are_escaped() {
    let e = logd::parse_entry(r#"{"__REALTIME_TIMESTAMP":"1","__CURSOR":"c","SYSLOG_IDENTIFIER":"NetworkManager","NM_CONNECTION":"x","MESSAGE":"a\u001b[31mb\nc"}"#).unwrap();
    assert_eq!(e.message, "a\\x1b[31mb\\x0ac");
    assert_eq!(logd::escape_text("\u{7f}\u{85}\u{2028}\u{2029}é"), "\\x7f\\u{0085}\\u{2028}\\u{2029}é");
}

#[test]
fn a_long_message_is_cut_on_a_character_boundary() {
    let text = format!("{}{}", "a".repeat(2040), "é".repeat(10));
    let cut = logd::escape_text(&text);
    assert!(cut.len() <= logd::MAX_TEXT && cut.ends_with('…'));
    assert!(cut.starts_with(&"a".repeat(2040)));
    let esc = logd::escape_text(&"\u{1}".repeat(1000));
    assert!(esc.len() <= logd::MAX_TEXT && esc.ends_with("\\x01…"), "an escape is never split");
}

#[test]
fn unusable_journal_lines_are_skipped() {
    for bad in [
        "",
        "not json",
        "[]",
        r#"{"__CURSOR":"c","SYSLOG_IDENTIFIER":"NetworkManager","MESSAGE":"m"}"#,
        r#"{"__REALTIME_TIMESTAMP":"x1","__CURSOR":"c","SYSLOG_IDENTIFIER":"NetworkManager","MESSAGE":"m"}"#,
        r#"{"__REALTIME_TIMESTAMP":"1","SYSLOG_IDENTIFIER":"NetworkManager","MESSAGE":"m"}"#,
        r#"{"__REALTIME_TIMESTAMP":"1","__CURSOR":"c d","SYSLOG_IDENTIFIER":"NetworkManager","MESSAGE":"m"}"#,
        r#"{"__REALTIME_TIMESTAMP":"1","__CURSOR":"c","MESSAGE":"m"}"#,
        r#"{"__REALTIME_TIMESTAMP":"1","__CURSOR":"c","SYSLOG_IDENTIFIER":"NetworkManager"}"#,
        r#"{"__REALTIME_TIMESTAMP":"1","__CURSOR":"c","SYSLOG_IDENTIFIER":"NetworkManager","MESSAGE":["a","b"]}"#,
        r#"{"__REALTIME_TIMESTAMP":"1","__CURSOR":"c","SYSLOG_IDENTIFIER":"NetworkManager","NM_CONNECTION":["a","b"],"MESSAGE":"m"}"#,
    ] {
        assert!(logd::parse_entry(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn the_journalctl_arguments_are_fixed() {
    let nm = Uuid::parse_str(NM_1001).unwrap();
    let args = logd::journalctl_args(nm, 1_700_000_000_000_042, Some("s=abc;i=1f"));
    let mut want: Vec<String> = [
        "--no-pager",
        "-o",
        "json",
        "--output-fields=__REALTIME_TIMESTAMP,__CURSOR,SYSLOG_IDENTIFIER,MESSAGE,NM_CONNECTION,NM_LOG_DOMAINS,CODE_FUNC,_UID,\
         _SYSTEMD_UNIT,_COMM",
        "--after-cursor=s=abc;i=1f",
        "-n",
        "20000",
        "_SYSTEMD_UNIT=NetworkManager.service",
        "+",
        "SYSLOG_IDENTIFIER=linvpn-ovpn-93959792-b4e2-8e81-ae54-6ed8d08d927d",
    ]
    .map(String::from)
    .to_vec();
    for p in [
        "charon-nm",
        "nm-l2tp-service",
        "xl2tpd",
        "pppd",
        "nm-sstp-service",
        "sstpc",
        "nm-vpnc-service",
        "vpnc",
        "nm-openvpn",
        "nm-openvpn-serv",
    ] {
        want.push("+".into());
        want.push(format!("SYSLOG_IDENTIFIER={p}"));
    }
    assert_eq!(args, want);
    assert!(args.iter().all(|a| !a.chars().any(char::is_whitespace)));
    // journalctl refuses `--since` with `--after-cursor`: a pump's every query after its first failed.
    assert!(args.iter().all(|a| !a.starts_with("--since")), "never both");
    let no_cursor = logd::journalctl_args(nm, 5, None);
    assert!(no_cursor.iter().all(|a| !a.starts_with("--after-cursor")));
    assert!(no_cursor.contains(&"--since=@0.000005".to_string()));
    let bad_cursor = logd::journalctl_args(nm, 5, Some("a b"));
    assert_eq!(bad_cursor, no_cursor, "an invalid cursor is never passed");
}

/// One journal entry with the given ident, trusted fields and message (at `usec`).
fn entry(usec: u64, ident: &str, uid: Option<&str>, unit: Option<&str>, comm: Option<&str>, msg: &str) -> Entry {
    let mut j = serde_json::json!({"__REALTIME_TIMESTAMP": usec.to_string(), "__CURSOR": format!("i={usec}"), "SYSLOG_IDENTIFIER": ident, "MESSAGE": msg});
    if ident == "NetworkManager" {
        j["NM_CONNECTION"] = NM_1001.into();
        j["NM_LOG_DOMAINS"] = "VPN".into();
    }
    for (k, v) in [("_UID", uid), ("_SYSTEMD_UNIT", unit), ("_COMM", comm)] {
        if let Some(v) = v {
            j[k] = v.into();
        }
    }
    logd::parse_entry(&j.to_string()).unwrap()
}

fn nm(usec: u64) -> Entry {
    entry(usec, "NetworkManager", Some("0"), Some("NetworkManager.service"), Some("NetworkManager"), "own")
}

/// The lines picked from `all`, with NM's start and the caller's activation before them in the history.
fn picked(all: &[Entry], senders: &Senders) -> Vec<u64> {
    let mut history = vec![nm_start(0), vpn(1, NM_1001, "starting openvpn")];
    history.extend(all.iter().cloned());
    logd::select(all, &history, &[], NM_1001, 0, senders).lines.iter().map(|l| l.usec).collect()
}

#[test]
fn a_forged_line_from_another_uid_is_dropped() {
    let out = logd::select(&entries("own.jsonl"), &entries("own.jsonl"), &[], NM_1001, 0, &SENDERS);
    assert!(out.lines.iter().all(|l| !l.text.contains("FORGED")), "{:?}", out.lines);
    assert!(out.lines.iter().all(|l| !l.text.contains("OTHER")), "a forged NM line does not widen the window");
    assert_eq!(out.lines.len(), 7);

    let ovpn = format!("linvpn-ovpn-{NM_1001}");
    let forged = [
        entry(20, &ovpn, Some("1002"), Some("session-7.scope"), Some("logger"), "FORGED"),
        entry(21, &ovpn, Some("1002"), Some("session-7.scope"), Some("openvpn"), "FORGED: comm renamed"),
        entry(22, "NetworkManager", Some("1002"), Some("session-7.scope"), Some("logger"), "FORGED"),
        entry(23, "NetworkManager", Some("1002"), Some("NetworkManager.service"), Some("NetworkManager"), "FORGED"),
        entry(24, "NetworkManager", Some("0"), Some("session-7.scope"), Some("NetworkManager"), "FORGED: other unit"),
        entry(25, "xl2tpd", Some("1002"), None, Some("xl2tpd"), "FORGED"),
        entry(26, "charon-nm", Some("984"), None, Some("charon-nm"), "FORGED: nm-openvpn sends no strongSwan line"),
        entry(27, "pppd", Some("0"), None, Some("logger"), "FORGED: root, but not pppd"),
        entry(28, "nm-openvpn", Some("1002"), None, Some("openvpn"), "FORGED"),
    ];
    let mut all = vec![nm(10)];
    all.extend(forged);
    all.push(nm(40));
    assert_eq!(picked(&all, &SENDERS), [10, 40]);
}

#[test]
fn the_expected_senders_pass() {
    let ovpn = format!("linvpn-ovpn-{NM_1001}");
    let all = vec![
        nm(10),
        entry(11, &ovpn, Some("0"), Some("NetworkManager.service"), Some("openvpn"), "root, before the drop"),
        entry(12, &ovpn, Some("984"), None, Some("openvpn"), "after --user nm-openvpn"),
        entry(13, "nm-openvpn-serv", Some("0"), None, Some("nm-openvpn-serv"), "service"),
        entry(14, "nm-openvpn-serv", Some("984"), None, Some("nm-openvpn-serv"), "helper after the drop"),
        entry(15, "nm-openvpn", Some("984"), None, Some("openvpn"), "stock plugin's OpenVPN"),
        entry(16, "charon-nm", Some("0"), None, Some("charon-nm"), "strongSwan"),
        entry(17, "nm-l2tp-service", Some("0"), None, Some("nm-l2tp-service"), "l2tp"),
        entry(18, "pppd", Some("0"), None, Some("pppd"), "ppp"),
        nm(40),
    ];
    assert_eq!(picked(&all, &SENDERS), [10, 11, 12, 13, 14, 15, 16, 17, 18, 40]);
    // Without an `nm-openvpn` user only root's lines count.
    assert_eq!(picked(&all, &Senders::default()), [10, 11, 13, 16, 17, 18, 40]);
}

#[test]
fn a_line_without_its_trusted_fields_is_dropped() {
    let ovpn = format!("linvpn-ovpn-{NM_1001}");
    let all = vec![
        nm(10),
        entry(11, "NetworkManager", None, Some("NetworkManager.service"), Some("NetworkManager"), "no uid"),
        entry(12, "NetworkManager", Some("0"), None, Some("NetworkManager"), "no unit"),
        entry(13, &ovpn, None, None, Some("openvpn"), "no uid"),
        entry(14, &ovpn, Some("0"), None, None, "no comm"),
        entry(15, "xl2tpd", None, None, Some("xl2tpd"), "no uid"),
        entry(16, "xl2tpd", Some("0"), None, None, "no comm"),
        nm(40),
    ];
    assert_eq!(picked(&all, &SENDERS), [10, 40]);
    // An untrusted activation line opens no window, so no plugin line either.
    let untrusted =
        entry(10, "NetworkManager", None, None, None, &format!("vpn[0x1,{NM_1001},\"W\"]: starting openvpn"));
    let lone = vec![nm_start(0), untrusted, entry(11, "xl2tpd", Some("0"), None, Some("xl2tpd"), "x")];
    assert!(logd::select(&lone, &lone, &[], NM_1001, 0, &SENDERS).lines.is_empty());
}

#[test]
fn malformed_trusted_fields_make_the_entry_unusable() {
    for uid in [r#""x""#, r#""-1""#, r#""01""#, r#""4294967296""#, "0", r#"["0","1"]"#] {
        let j = format!(
            r#"{{"__REALTIME_TIMESTAMP":"1","__CURSOR":"c","SYSLOG_IDENTIFIER":"NetworkManager","MESSAGE":"m","_UID":{uid}}}"#
        );
        assert!(logd::parse_entry(&j).is_none(), "{uid}");
    }
    for k in ["_SYSTEMD_UNIT", "_COMM"] {
        let j = format!(
            r#"{{"__REALTIME_TIMESTAMP":"1","__CURSOR":"c","SYSLOG_IDENTIFIER":"x","MESSAGE":"m","{k}":["a","b"]}}"#
        );
        assert!(logd::parse_entry(&j).is_none(), "{k}");
    }
    let e = logd::parse_entry(
        r#"{"__REALTIME_TIMESTAMP":"1","__CURSOR":"c","SYSLOG_IDENTIFIER":"x","MESSAGE":"m","_UID":"4294967295"}"#,
    )
    .unwrap();
    assert_eq!(e.uid, Some(u32::MAX));
}

#[test]
fn a_forged_line_cannot_end_another_tunnel_or_start_the_callers() {
    let forged = |usec: u64, uuid: &str, rest: &str| {
        let msg = format!("vpn[0x1,{uuid},\"W\"]: {rest}");
        let j = serde_json::json!({"__REALTIME_TIMESTAMP": usec.to_string(), "__CURSOR": format!("f={usec}"), "SYSLOG_IDENTIFIER": "NetworkManager", "MESSAGE": msg, "NM_CONNECTION": uuid, "NM_LOG_DOMAINS": "VPN", "_UID": "1002", "_SYSTEMD_UNIT": "session-7.scope", "_COMM": "logger"});
        logd::parse_entry(&j.to_string()).unwrap()
    };
    let all = vec![
        nm_start(1),
        vpn(5, NM_B, "starting strongswan"),
        forged(8, NM_B, "set state: disconnected (was activated)"),
        vpn(10, NM_1001, "starting strongswan"),
        charon(11, "B: still up"),
    ];
    let out = logd::select(&all, &all, &[], NM_1001, 0, &SENDERS);
    assert!(plugin_texts(&out).is_empty() && out.withheld);
    let all = vec![nm_start(1), forged(10, NM_1001, "starting strongswan"), charon(11, "someone's")];
    assert!(plugin_texts(&logd::select(&all, &all, &[], NM_1001, 0, &SENDERS)).is_empty());
}

#[test]
fn every_plugin_ident_names_its_senders() {
    for p in logd::PLUGIN_IDENTS {
        let (comms, _) = logd::plugin_senders(p).unwrap_or_else(|| panic!("{p}"));
        assert!(!comms.is_empty() && comms.iter().all(|c| c.len() <= 15), "{p}: a kernel process name");
    }
    assert!(logd::plugin_senders("NetworkManager").is_none());
    assert!(logd::plugin_senders(&format!("linvpn-ovpn-{NM_1001}")).is_none());
}

// ---- plugin lines: NetworkManager's VPN history (the security review's M1) ----

/// Another user's derived UUID.
const NM_B: &str = "4afc4c01-0988-87e3-a22c-93b84ad56c54";

fn nm_start(usec: u64) -> Entry {
    let j = serde_json::json!({"__REALTIME_TIMESTAMP": usec.to_string(), "__CURSOR": format!("start={usec}"), "SYSLOG_IDENTIFIER": "NetworkManager", "MESSAGE": "<info>  [1.0] NetworkManager (version 1.54.3) is starting... (boot:x)", "NM_LOG_DOMAINS": "CORE", "CODE_FUNC": "main", "_UID": "0", "_SYSTEMD_UNIT": "NetworkManager.service", "_COMM": "NetworkManager"});
    logd::parse_entry(&j.to_string()).unwrap()
}

/// A NetworkManager VPN line of `uuid` (connection name `name`) with the message `rest`.
fn vpn_named(usec: u64, uuid: &str, name: &str, rest: &str) -> Entry {
    let msg = format!("<info>  [1.0] vpn[0x55d0c0ffee00,{uuid},\"{name}\"]: {rest}");
    let j = serde_json::json!({"__REALTIME_TIMESTAMP": usec.to_string(), "__CURSOR": format!("nm={usec}"), "SYSLOG_IDENTIFIER": "NetworkManager", "MESSAGE": msg, "NM_CONNECTION": uuid, "NM_LOG_DOMAINS": "VPN", "_UID": "0", "_SYSTEMD_UNIT": "NetworkManager.service", "_COMM": "NetworkManager"});
    logd::parse_entry(&j.to_string()).unwrap()
}

fn vpn(usec: u64, uuid: &str, rest: &str) -> Entry {
    vpn_named(usec, uuid, "Work", rest)
}

fn charon(usec: u64, msg: &str) -> Entry {
    let j = serde_json::json!({"__REALTIME_TIMESTAMP": usec.to_string(), "__CURSOR": format!("p={usec}"), "SYSLOG_IDENTIFIER": "charon-nm", "MESSAGE": msg, "_UID": "0", "_COMM": "charon-nm"});
    logd::parse_entry(&j.to_string()).unwrap()
}

fn plugin_texts(out: &Response) -> Vec<String> {
    out.lines.iter().filter(|l| matches!(l.source, Source::Plugin(_))).map(|l| l.text.clone()).collect()
}

#[test]
fn a_single_users_plugin_lines_inside_its_activation_are_returned() {
    let all = vec![
        nm_start(1),
        charon(5, "before: not ours"),
        vpn(10, NM_1001, "starting strongswan"),
        charon(11, "OWN establishing CHILD_SA"),
        vpn(12, NM_1001, "dbus: state changed: started (4)"),
        charon(13, "OWN rekeying"),
        vpn(20, NM_1001, "set state: disconnected (was deactivating)"),
        vpn(21, NM_1001, "dbus: state changed: stopped (6)"),
        charon(30, "after: not ours"),
    ];
    let out = logd::select(&all, &all, &[], NM_1001, 0, &SENDERS);
    assert_eq!(plugin_texts(&out), ["OWN establishing CHILD_SA", "OWN rekeying"]);
    assert!(!out.withheld);
}

#[test]
fn another_users_tunnel_up_before_and_after_the_callers_window_is_never_returned() {
    // The attack: B's IKEv2 tunnel is up before A's window and stays up; B's charon-nm writes rekeys and EAP
    // identities while A activates its own connection twice. Nothing of B's VPN domain falls inside A's window.
    let all = vec![
        nm_start(1),
        vpn(5, NM_B, "starting strongswan"),
        vpn(6, NM_B, "set state: activated (was ip-config-get)"),
        vpn(10, NM_1001, "starting openvpn"),
        charon(11, "B: EAP identity alice@example.org"),
        vpn(15, NM_1001, "set state: failed (was connect)"),
        charon(16, "B: rekeying, 100.64.9.7"),
        vpn(20, NM_1001, "starting openvpn"),
        charon(21, "B: CHILD_SA rekeyed"),
        vpn(25, NM_1001, "set state: disconnected (was activated)"),
    ];
    let out = logd::select(&all, &all, &[], NM_1001, 0, &SENDERS);
    assert!(plugin_texts(&out).is_empty(), "{:?}", plugin_texts(&out));
    assert!(out.withheld, "the caller learns that plugin lines were held back");
    assert!(out.lines.iter().any(|l| l.source == Source::NetworkManager), "its own NM lines still pass");
    // B's history only in the separate history query (older than the request's `since`): the same.
    let lines: Vec<Entry> = all.iter().filter(|e| e.usec >= 10).cloned().collect();
    let out = logd::select(&lines, &all, &[], NM_1001, 10, &SENDERS);
    assert!(plugin_texts(&out).is_empty());
}

#[test]
fn another_tunnel_that_ended_before_the_activation_does_not_withhold() {
    let all = vec![
        nm_start(1),
        vpn(5, NM_B, "starting strongswan"),
        vpn(8, NM_B, "set state: disconnected (was activated)"),
        // NM's trailing lines after the end do not bring it back.
        vpn(9, NM_B, "dbus: name owner for org.freedesktop.NetworkManager.strongswan disappeared"),
        vpn(10, NM_1001, "starting strongswan"),
        charon(11, "OWN established"),
    ];
    let out = logd::select(&all, &all, &[], NM_1001, 0, &SENDERS);
    assert_eq!(plugin_texts(&out), ["OWN established"]);
    assert!(!out.withheld);
}

#[test]
fn a_connection_name_or_a_quoted_text_cannot_fake_another_tunnels_end() {
    let fake_end = "set state: disconnected (was activated)";
    let all = vec![
        nm_start(1),
        vpn_named(5, NM_B, &format!("x\"]: {fake_end}"), "starting strongswan"),
        vpn_named(6, NM_B, &format!("x\"]: {fake_end}"), "set state: activated (was ip-config-get)"),
        // Texts NM quotes inside a message that is no end.
        vpn(7, NM_B, &format!("config: failed to look up VPN interface index for \"x\"]: {fake_end}\"")),
        vpn(8, NM_B, "invalid IP4 config received: address is zero\"]: dbus: failure: login-failed (1)"),
        vpn(10, NM_1001, "starting strongswan"),
        charon(11, "B: still B's"),
    ];
    let out = logd::select(&all, &all, &[], NM_1001, 0, &SENDERS);
    assert!(plugin_texts(&out).is_empty());
    assert!(out.withheld);
}

#[test]
fn without_networkmanagers_start_in_the_history_no_plugin_line_passes() {
    let all = vec![vpn(10, NM_1001, "starting strongswan"), charon(11, "OWN?")];
    let out = logd::select(&all, &all, &[], NM_1001, 0, &SENDERS);
    assert!(plugin_texts(&out).is_empty());
    assert!(out.withheld);
    // A forged start line (another user's logger) does not count either.
    let forged = logd::parse_entry(r#"{"__REALTIME_TIMESTAMP":"1","__CURSOR":"f","SYSLOG_IDENTIFIER":"NetworkManager","MESSAGE":"NetworkManager (version 9) is starting...","CODE_FUNC":"main","_UID":"1002","_SYSTEMD_UNIT":"session-7.scope","_COMM":"logger"}"#).unwrap();
    let mut with_forged = all.clone();
    with_forged.push(forged);
    assert!(plugin_texts(&logd::select(&with_forged, &with_forged, &[], NM_1001, 0, &SENDERS)).is_empty());
}

#[test]
fn a_tunnel_up_before_networkmanagers_restart_no_longer_counts_and_a_new_activation_does() {
    let all = vec![
        nm_start(1),
        vpn(5, NM_B, "starting strongswan"),
        nm_start(8),
        vpn(10, NM_1001, "starting strongswan"),
        charon(11, "OWN after the restart"),
        vpn(12, NM_B, "starting strongswan"),
        charon(13, "B again"),
    ];
    let out = logd::select(&all, &all, &[], NM_1001, 0, &SENDERS);
    assert_eq!(plugin_texts(&out), ["OWN after the restart"]);
    assert!(out.withheld, "B's new activation holds back the line after it");
}

#[test]
fn the_history_query_is_fixed() {
    let a = logd::history_args();
    assert!(a.contains(&"NM_LOG_DOMAINS=VPN".to_string()) && a.contains(&"CODE_FUNC=main".to_string()));
    assert!(a.iter().all(|x| !x.starts_with("--since") && !x.starts_with("--after-cursor") && x != "-b"));
    assert_eq!(a.iter().filter(|x| *x == "_SYSTEMD_UNIT=NetworkManager.service").count(), 2);
}

// ---- NetworkManager 1.54.3 at its default level: no state lines, failure lines and logd's own readings ----

use macvpn_core::logd::Observation;

/// A reading of NM's active VPN connections taken in `[before, after]`.
fn seen(before: u64, after: u64, active: &[&str]) -> Observation {
    Observation::new(before, after, active.iter().map(|u| u.to_string())).unwrap()
}

fn sstpc(usec: u64, msg: &str) -> Entry {
    let j = serde_json::json!({"__REALTIME_TIMESTAMP": usec.to_string(), "__CURSOR": format!("s={usec}"), "SYSLOG_IDENTIFIER": "sstpc", "MESSAGE": msg, "_UID": "0", "_COMM": "sstpc"});
    logd::parse_entry(&j.to_string()).unwrap()
}

/// A third user's connection.
const NM_C: &str = "0c7e9f12-5a3b-8c4d-9e6f-a1b2c3d4e5f6";

#[test]
fn networkmanagers_warning_level_end_lines_end_a_connection() {
    // Each message NM 1.54.3's nm-vpn-connection.c writes at the default level only as a connection fails.
    for end in [
        "dbus: failure: connect-failed (1)",
        "dbus: failure: login-failed (0)",
        "failed to connect: 'The VPN service failed to start.'",
        "connect: failed to connect interactively: 'x'",
        "did not receive valid IP config information",
        "connect timeout exceeded",
        "plugin NeedSecrets request #1 failed: No agents were available for this request.",
        "final secrets request failed to provide sufficient secrets",
        "sending new secrets to the plugin failed: x",
        "secrets: failed to request VPN secrets #3: No agents were available for this request.",
        "starting: timed out waiting for the service to start",
        "starting: timed out waiting for the VPN to activate",
        "starting: failure to start VPN service: x",
        "set state: failed (was connect)",
        "dbus: state changed: stopped (6)",
    ] {
        let all = vec![
            nm_start(1),
            vpn(5, NM_B, "starting strongswan"),
            vpn(8, NM_B, end),
            vpn(10, NM_1001, "starting sstp"),
            sstpc(11, "OWN certificate verify failed"),
        ];
        let out = logd::select(&all, &all, &[], NM_1001, 0, &SENDERS);
        assert_eq!(plugin_texts(&out), ["OWN certificate verify failed"], "{end}");
        assert!(!out.withheld, "{end}");
    }
    // NM's prefix after IP configuration: `,if:<n>,dev:<n>:(<iface>)` before `]: `.
    let all = vec![
        nm_start(1),
        vpn(5, NM_B, "starting sstp"),
        vpn_named(8, NM_B, "Work\",if:9,dev:2:(ppp0)", "dbus: failure: connect-failed (1)"),
        vpn(10, NM_1001, "starting sstp"),
        sstpc(11, "OWN"),
    ];
    assert_eq!(plugin_texts(&logd::select(&all, &all, &[], NM_1001, 0, &SENDERS)), ["OWN"]);
    // Near misses are no end.
    for not_end in [
        "dbus: failure: connect-failed",
        "failed to connect: 'x",
        "plugin NeedSecrets request #x failed: y",
        "starting: VPN service has PID 4242",
        "config: no VPN gateway address received",
    ] {
        let all = vec![
            nm_start(1),
            vpn(5, NM_B, "starting strongswan"),
            vpn(8, NM_B, not_end),
            vpn(10, NM_1001, "starting sstp"),
            sstpc(11, "B's?"),
        ];
        assert!(plugin_texts(&logd::select(&all, &all, &[], NM_1001, 0, &SENDERS)).is_empty(), "{not_end}");
    }
}

#[test]
fn earlier_failed_and_finished_vpns_do_not_withhold_a_later_single_users_lines() {
    // The lab: NM writes no end line for a finished connection, only `dbus: failure` for a failed one. logd's
    // reading taken just before the caller's activation (the engine's mark) shows the finished ones gone.
    let history = vec![
        nm_start(1),
        vpn(5, NM_B, "starting strongswan"),
        vpn(6, NM_C, "starting l2tp"),
        vpn(7, NM_C, "dbus: failure: connect-failed (1)"),
        vpn(10, NM_B, "starting strongswan"),
        vpn(30, NM_1001, "starting sstp"),
    ];
    let lines = vec![
        vpn(30, NM_1001, "starting sstp"),
        sstpc(31, "OWN sstpc: certificate verify failed"),
        vpn(32, NM_1001, "dbus: failure: connect-failed (1)"),
        sstpc(33, "after the end: not ours"),
    ];
    let mark = [seen(28, 29, &[])];
    let out = logd::select(&lines, &history, &mark, NM_1001, 0, &SENDERS);
    assert_eq!(plugin_texts(&out), ["OWN sstpc: certificate verify failed"]);
    assert!(!out.withheld);
    // The same for IKEv2 and L2TP plugin lines: a retry of the caller's own connection after its own failure.
    let lines = vec![
        vpn(40, NM_1001, "starting strongswan"),
        charon(41, "OWN IKE_SA established"),
        entry_plugin(42, "xl2tpd", "OWN xl2tpd up"),
    ];
    let mut history2 = history.clone();
    history2.extend(lines.iter().cloned());
    let out = logd::select(&lines, &history2, &mark, NM_1001, 0, &SENDERS);
    assert_eq!(plugin_texts(&out), ["OWN IKE_SA established", "OWN xl2tpd up"]);
    // Without any reading every earlier connection may still be up: withheld (fail closed).
    let out = logd::select(&lines, &history2, &[], NM_1001, 0, &SENDERS);
    assert!(plugin_texts(&out).is_empty() && out.withheld);
}

fn entry_plugin(usec: u64, ident: &str, msg: &str) -> Entry {
    let j = serde_json::json!({"__REALTIME_TIMESTAMP": usec.to_string(), "__CURSOR": format!("{ident}={usec}"), "SYSLOG_IDENTIFIER": ident, "MESSAGE": msg, "_UID": "0", "_COMM": ident});
    logd::parse_entry(&j.to_string()).unwrap()
}

#[test]
fn the_m1_attack_stays_closed_with_readings() {
    // B's tunnel is up before A's window and through it; A connects twice and asks as often as it likes.
    let all = vec![
        nm_start(1),
        vpn(5, NM_B, "starting strongswan"),
        vpn(10, NM_1001, "starting openvpn"),
        charon(11, "B: EAP identity alice@example.org"),
        vpn(15, NM_1001, "dbus: failure: connect-failed (1)"),
        vpn(20, NM_1001, "starting openvpn"),
        charon(21, "B: CHILD_SA rekeyed"),
        charon(40, "B: after A's window"),
    ];
    // A's readings: B up at the mark, during the window, and gone only long after.
    let readings = [seen(8, 9, &[NM_B]), seen(12, 13, &[NM_B, NM_1001]), seen(19, 19, &[NM_B]), seen(60, 61, &[])];
    for n in 0..=readings.len() {
        let out = logd::select(&all, &all, &readings[..n], NM_1001, 0, &SENDERS);
        assert!(plugin_texts(&out).is_empty(), "{n} readings: {:?}", plugin_texts(&out));
        assert!(out.withheld);
    }
    // B's tunnel never seen at all by a reading before it is gone (A never asked while it was up): its activation
    // line keeps it up until the first reading without it, after A's window.
    let out = logd::select(&all, &all, &[seen(60, 61, &[])], NM_1001, 0, &SENDERS);
    assert!(plugin_texts(&out).is_empty());
    // A reading begun before B's activation line cannot end it (B may have started during the reading).
    let late =
        vec![nm_start(1), vpn(9, NM_B, "starting strongswan"), vpn(10, NM_1001, "starting openvpn"), charon(11, "B")];
    assert!(plugin_texts(&logd::select(&late, &late, &[seen(8, 9, &[])], NM_1001, 0, &SENDERS)).is_empty());
}

#[test]
fn a_reading_that_still_sees_a_connection_voids_its_earlier_end_line() {
    // B's plugin reported a failure but its connection was still active at a later reading (no new activation):
    // that end did not happen, so B's lines in between stay withheld.
    let all = vec![
        nm_start(1),
        vpn(5, NM_B, "starting strongswan"),
        vpn(8, NM_B, "dbus: failure: connect-failed (1)"),
        vpn(10, NM_1001, "starting openvpn"),
        charon(11, "B: still up"),
    ];
    let out = logd::select(&all, &all, &[seen(20, 21, &[NM_B, NM_1001])], NM_1001, 0, &SENDERS);
    assert!(plugin_texts(&out).is_empty() && out.withheld);
    // A new activation after the end explains the later sighting: the end stands for the time before it.
    let mut again = all.clone();
    again.push(vpn(15, NM_B, "starting strongswan"));
    let out = logd::select(&again, &again, &[seen(20, 21, &[NM_B, NM_1001])], NM_1001, 0, &SENDERS);
    assert_eq!(plugin_texts(&out), ["B: still up"]);
}

#[test]
fn a_connection_a_reading_sees_without_an_activation_line_counts_since_the_last_known_inactive_moment() {
    // journald's rate limit dropped B's activation line: the reading that sees B holds back everything since NM's
    // start (or the last reading without it).
    let all = vec![nm_start(1), vpn(10, NM_1001, "starting openvpn"), charon(11, "B: rekey")];
    let out = logd::select(&all, &all, &[seen(30, 31, &[NM_B, NM_1001])], NM_1001, 0, &SENDERS);
    assert!(plugin_texts(&out).is_empty() && out.withheld);
    let out = logd::select(&all, &all, &[seen(9, 9, &[]), seen(30, 31, &[NM_B, NM_1001])], NM_1001, 0, &SENDERS);
    assert!(plugin_texts(&out).is_empty(), "B may have come up after the reading at 9");
    let out = logd::select(&all, &all, &[seen(12, 12, &[]), seen(30, 31, &[NM_B, NM_1001])], NM_1001, 0, &SENDERS);
    assert_eq!(plugin_texts(&out), ["B: rekey"], "B was not up at 12 or before: the line at 11 is the caller's");
}

#[test]
fn readings_round_trip_strictly_and_only_logds_own_lines_count() {
    let o = seen(5, 7, &[NM_B, NM_1001]);
    assert_eq!(o.encode(), format!("linvpn-logd-vpns-v1 5 7 {NM_B},{NM_1001}"));
    assert_eq!(o.record_line(), format!("<5>{}", o.encode()));
    assert_eq!(Observation::parse(&o.encode()), Some(o.clone()));
    assert_eq!(Observation::parse("linvpn-logd-vpns-v1 5 7 -"), Some(seen(5, 7, &[])));
    for bad in [
        "linvpn-logd-vpns-v1 7 5 -",
        "linvpn-logd-vpns-v1 5 7",
        "linvpn-logd-vpns-v1 5 7 - x",
        "linvpn-logd-vpns-v1 05 7 -",
        &format!("linvpn-logd-vpns-v1 5 7 {NM_1001},{NM_B}"),
        &format!("linvpn-logd-vpns-v1 5 7 {NM_B},{NM_B}"),
        "linvpn-logd-vpns-v1 5 7 a;b",
        "linvpn-logd-vpns-v1 5 7 ",
    ] {
        assert_eq!(Observation::parse(bad), None, "{bad:?}");
    }
    assert!(Observation::new(1, 2, (0..=logd::MAX_OBSERVED).map(|i| format!("u{i}"))).is_none());
    let line = |unit: &str, ident: &str| {
        let j = serde_json::json!({"__REALTIME_TIMESTAMP": "9", "__CURSOR": "o", "SYSLOG_IDENTIFIER": ident, "MESSAGE": o.encode(), "_UID": "61234", "_SYSTEMD_UNIT": unit});
        logd::parse_entry(&j.to_string()).unwrap()
    };
    let got = logd::observations(&[
        line("linvpn-logd@3-4242-1001.service", "linvpn-logd"),
        line("user@1002.service", "linvpn-logd"),
        line("session-7.scope", "linvpn-logd"),
        line("linvpn-logd@3-4242-1001.service", "logger"),
        line("linvpn-logd.socket", "linvpn-logd"),
    ]);
    assert_eq!(got, [o]);
    let a = logd::observation_args();
    assert!(a.contains(&"SYSLOG_IDENTIFIER=linvpn-logd".to_string()) && a.contains(&"PRIORITY=5".to_string()));
    assert!(a.iter().all(|x| !x.starts_with("--since") && !x.starts_with("--after-cursor") && x != "+"));
}

#[test]
fn a_reading_is_recorded_only_when_it_says_something_new() {
    let history = vec![nm_start(1), vpn(5, NM_B, "starting strongswan")];
    let live = seen(20, 21, &[NM_B]);
    assert!(logd::should_record(&history, &[], &live), "the first since NM's start");
    assert!(!logd::should_record(&history, &[seen(10, 11, &[NM_B])], &live), "nothing new");
    assert!(logd::should_record(&history, &[seen(10, 11, &[])], &live), "another set");
    assert!(logd::should_record(&history, &[seen(4, 5, &[NM_B])], &live), "an activation since it began");
    assert!(
        logd::should_record(&[nm_start(1), nm_start(12)], &[seen(10, 11, &[])], &seen(20, 21, &[])),
        "NM restarted"
    );
    assert!(!logd::should_record(&[vpn(5, NM_B, "starting strongswan")], &[], &live), "no NM start: useless");
}
