//! Port of `LogTests.swift` and the status cases of `MvpnClientTests.swift`.

mod common;

use common::*;
use macvpn_core::date::Date;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::log::*;
use macvpn_core::models::ConnectionState;
use macvpn_core::status::parse_status;
use std::fs;
use std::io::Write;

#[test]
fn classify() {
    assert_eq!(LogLine::new("═══ 2026-10-16 up openvpn ═══").kind, LogLineKind::Header);
    assert_eq!(LogLine::new("▶ [mvpn] config másolása").kind, LogLineKind::Step);
    assert_eq!(LogLine::new("$ /opt/homebrew/sbin/openvpn --config x").kind, LogLineKind::Command);
    assert_eq!(LogLine::new("[#] ifconfig utun5 inet 10.0.0.2").kind, LogLineKind::Command);
    assert_eq!(LogLine::new("✗ időtúllépés").kind, LogLineKind::Error);
    assert_eq!(LogLine::new("2026-10-16 AUTH_FAILED").kind, LogLineKind::Error);
    assert_eq!(LogLine::new("TLS: Initial packet").kind, LogLineKind::Output);
}

#[test]
fn filter() {
    let lines: Vec<LogLine> = ["$ a", "out", "✗ bad", "▶ [mvpn] x"].into_iter().map(LogLine::new).collect();
    let texts = |f: LogFilter| lines.iter().filter(|l| l.matches(f)).map(|l| l.text.clone()).collect::<Vec<_>>();
    assert_eq!(texts(LogFilter::Commands), ["$ a", "▶ [mvpn] x"]);
    assert_eq!(texts(LogFilter::Errors), ["✗ bad"]);
    assert_eq!(texts(LogFilter::All).len(), 4);
    lang(AppLanguage::Hu);
    assert_eq!(LogFilter::ALL.map(LogFilter::title), ["Minden", "Parancsok", "Hibák"]);
}

fn append(path: &std::path::Path, data: &[u8]) {
    fs::OpenOptions::new().append(true).open(path).unwrap().write_all(data).unwrap();
}

#[test]
fn tailer_returns_only_complete_new_lines() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let path = tmp.path().join("x.log");
    let mut tailer = LogTailer::new(&path);
    assert!(tailer.read_new().is_empty());
    fs::write(&path, "egy\nket").unwrap();
    assert_eq!(tailer.read_new(), ["egy"]);
    append(&path, "tő\nhárom\n".as_bytes());
    assert_eq!(tailer.read_new(), ["kettő", "három"]);
    assert!(tailer.read_new().is_empty());
    // Truncation (same inode, `write` without atomic replace).
    fs::OpenOptions::new().write(true).truncate(true).open(&path).unwrap().write_all("új\n".as_bytes()).unwrap();
    assert_eq!(tailer.read_new(), ["új"]);
}

#[test]
fn first_read_is_bounded_to_last_256kb() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let path = tmp.path().join("x.log");
    let line = format!("{}\n", "x".repeat(99)); // 100 bytes
    fs::write(&path, line.repeat(10_000)).unwrap();
    let lines = LogTailer::new(&path).read_new();
    assert!(lines.len() <= 256 * 1024 / 100);
    assert!(lines.len() > 256 * 1024 / 100 - 3);
    assert!(lines.iter().all(|l| l.len() == 99), "the partial first line must be dropped");
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn inode_replacement_resets() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let path = tmp.path().join("x.log");
    let other = tmp.path().join("y.log");
    fs::write(&path, "a\nb\n").unwrap();
    let mut tailer = LogTailer::new(&path);
    assert_eq!(tailer.read_new(), ["a", "b"]);
    fs::write(&other, "c\nd\ne\nf\n").unwrap();
    fs::rename(&other, &path).unwrap();
    assert_eq!(tailer.read_new(), ["c", "d", "e", "f"]);
}

#[test]
fn overlong_line_without_newline_is_flushed() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let path = tmp.path().join("x.log");
    fs::write(&path, "y".repeat(100_000)).unwrap();
    let lines = LogTailer::new(&path).read_new();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].len(), 100_000);
}

#[test]
fn partial_flush_never_splits_multibyte_character() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let path = tmp.path().join("x.log");
    let mut data = vec![b'a'; 70_000];
    data.push(0xC3); // the first byte of "é"
    fs::write(&path, &data).unwrap();
    let mut tailer = LogTailer::new(&path);
    assert_eq!(tailer.read_new(), ["a".repeat(70_000)]);
    append(&path, &[0xA9, 0x0A]);
    assert_eq!(tailer.read_new(), ["é"]);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn inode_replacement_reapplies_window() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let path = tmp.path().join("x.log");
    let other = tmp.path().join("y.log");
    fs::write(&path, "a\n").unwrap();
    let mut tailer = LogTailer::new(&path);
    let _ = tailer.read_new();
    fs::write(&other, format!("{}\n", "x".repeat(99)).repeat(10_000)).unwrap();
    fs::rename(&other, &path).unwrap();
    assert!(tailer.read_new().len() <= 256 * 1024 / 100);
}

#[test]
fn complete_utf8_prefix_cases() {
    assert_eq!(complete_utf8_prefix(b"abc"), 3);
    assert_eq!(complete_utf8_prefix(&[b'a', 0xC3]), 1);
    assert_eq!(complete_utf8_prefix(&[b'a', 0xC3, 0xA9]), 3);
    assert_eq!(complete_utf8_prefix(&[0xF0, 0x9F, 0x98]), 0);
    assert_eq!(complete_utf8_prefix(&[0x80, 0x80, 0x80, 0x80]), 4);
}

// MARK: MvpnClientTests (status)

#[test]
fn parse_status_cases() {
    let json = r#"[{"id":"11111111-2222-3333-4444-555555555555","kind":"openvpn","state":"connected","iface":"utun5","ip":"10.8.0.2","since":1700000000},
     {"id":"11111111-2222-3333-4444-555555555556","kind":"strongswan","state":"connecting","iface":null,"ip":null,"since":null}]"#;
    let list = parse_status(json).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(
        list[0].connection_state(),
        ConnectionState::Connected {
            ip: Some("10.8.0.2".into()),
            since: Some(Date::from_time_interval_since_1970(1_700_000_000.0))
        }
    );
    assert_eq!(list[1].connection_state(), ConnectionState::Connecting);
    assert!(parse_status("[]\n").unwrap().is_empty());
    assert!(parse_status("{}").is_err());
    assert!(parse_status(r#"[{"id":"x","kind":"openvpn","state":"connected"}]"#).is_err());
}

#[test]
fn failed_status_maps_to_failed() {
    lang(AppLanguage::Hu);
    let s = parse_status(
        r#"[{"id":"11111111-2222-3333-4444-555555555555","kind":"openvpn","state":"failed","iface":null,"ip":null,"since":null}]"#,
    )
    .unwrap();
    assert_eq!(s[0].connection_state(), ConnectionState::Failed("A kapcsolat megszakadt".into()));
}
