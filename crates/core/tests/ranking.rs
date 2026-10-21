//! Port of `ConnectionRankingTests.swift` and `MFATests.testSystemOTPStore`.

mod common;

use common::TempDir;
#[cfg(unix)]
use common::mode;
use macvpn_core::collation;
use macvpn_core::date::Date;
#[cfg(unix)]
use macvpn_core::models::{OTPSeparator, OTPSetting};
use macvpn_core::ranking::{ConnectionRanking, ConnectionRankingStore, HALF_LIFE};
use macvpn_core::system_otp::SystemOTPStore;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

const DAY: f64 = 24.0 * 60.0 * 60.0;

fn t0() -> Date {
    Date::from_time_interval_since_1970(1_800_000_000.0)
}

fn close(a: f64, b: f64, eps: f64) {
    assert!((a - b).abs() <= eps, "{a} != {b}");
}

fn ids(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

#[test]
fn score_halves_every_fourteen_days() {
    let mut r = ConnectionRanking::default();
    r.record_success("a", t0());
    close(r.score("a", t0()), 1.0, 1e-12);
    close(r.score("a", t0().adding(14.0 * DAY)), 0.5, 1e-12);
    close(r.score("a", t0().adding(28.0 * DAY)), 0.25, 1e-12);
    close(r.score("a", t0().adding(7.0 * DAY)), 0.5f64.powf(0.5), 1e-12);
    assert_eq!(r.score("missing", t0()), 0.0);
    assert_eq!(HALF_LIFE, 14.0 * DAY);
}

#[test]
fn record_success_decays_then_adds_one() {
    let mut r = ConnectionRanking::default();
    r.record_success("a", t0());
    r.record_success("a", t0());
    close(r.score("a", t0()), 2.0, 1e-12);
    r.record_success("a", t0().adding(14.0 * DAY));
    close(r.score("a", t0().adding(14.0 * DAY)), 2.0, 1e-12);
    assert_eq!(r.usage()["a"].last_updated, t0().adding(14.0 * DAY));
    close(r.score("a", t0().adding(28.0 * DAY)), 1.0, 1e-12);
}

#[test]
fn clock_going_backwards_does_not_inflate_the_score() {
    let mut r = ConnectionRanking::default();
    r.record_success("a", t0());
    close(r.score("a", t0().adding(-DAY)), 1.0, 1e-12);
    r.record_success("a", t0().adding(-DAY));
    assert_eq!(r.usage()["a"].last_updated, t0());
    close(r.score("a", t0()), 2.0, 1e-12);
}

#[test]
fn recent_use_outranks_old_heavy_use() {
    let mut r = ConnectionRanking::default();
    for _ in 0..3 {
        r.record_success("old", t0());
    }
    r.record_success("new", t0().adding(60.0 * DAY));
    assert_eq!(r.order(&ids(&["old", "new"]), t0().adding(60.0 * DAY), |s| s.to_string()), ["new", "old"]);
}

#[test]
fn pinned_first_in_their_order_then_score_then_name() {
    let mut r = ConnectionRanking::default();
    r.record_success("busy", t0());
    r.record_success("busy", t0());
    r.record_success("used", t0());
    r.record_success("pinB", t0());
    r.pin("pinB");
    r.pin("pinA");
    let names: HashMap<&str, &str> = [
        ("busy", "Zulu"),
        ("used", "Yankee"),
        ("pinA", "Alpha"),
        ("pinB", "Bravo"),
        ("x", "éjszakai"),
        ("y", "Ember"),
        ("z", "alpha"),
    ]
    .into();
    let order = r.order(&ids(&["x", "busy", "pinA", "y", "used", "z", "pinB"]), t0(), |id| names[id].to_string());
    assert_eq!(order[..2], ["pinB", "pinA"], "pinned, in the user's order, regardless of score");
    assert_eq!(order[2..4], ["busy", "used"], "then by score");
    // Ties (score 0): case-insensitive, localized name order (alpha < éjszakai < Ember is not ASCII order).
    let tail = &order[4..];
    let mut expected = ids(&["z", "x", "y"]);
    expected.sort_by(|a, b| collation::localized_case_insensitive_compare(names[a.as_str()], names[b.as_str()]));
    assert_eq!(tail, expected);
    assert_eq!(tail[0], "z");
    assert_eq!(tail, ["z", "x", "y"]);
}

#[test]
fn equal_names_and_scores_are_stable() {
    let r = ConnectionRanking::default();
    assert_eq!(r.order(&ids(&["b", "a"]), t0(), |_| "Same".into()), ["a", "b"]);
    assert_eq!(r.order(&ids(&["a", "b"]), t0(), |_| "Same".into()), ["a", "b"]);
}

#[test]
fn pinned_but_missing_ids_are_skipped() {
    let mut r = ConnectionRanking::default();
    r.pin("gone");
    r.pin("a");
    assert_eq!(r.order(&ids(&["b", "a"]), t0(), |s| s.to_string()), ["a", "b"]);
}

#[test]
fn pin_unpin() {
    let mut r = ConnectionRanking::default();
    r.pin("a");
    r.pin("b");
    r.pin("a");
    assert_eq!(r.pinned(), ["a", "b"]);
    r.unpin("a");
    assert_eq!(r.pinned(), ["b"]);
    assert!(!r.is_pinned("a"));
    assert_eq!(r.order(&ids(&["a", "b"]), t0(), |s| s.to_string()), ["b", "a"]);
}

fn set(v: &[usize]) -> BTreeSet<usize> {
    v.iter().copied().collect()
}

#[test]
fn move_pinned_like_on_move() {
    let mut r = ConnectionRanking::new(ids(&["a", "b", "c", "d"]), HashMap::new());
    r.move_pinned(&ids(&["a", "b", "c", "d"]), &set(&[0]), 3);
    assert_eq!(r.pinned(), ["b", "c", "a", "d"]);
    let visible = r.pinned().to_vec();
    r.move_pinned(&visible, &set(&[3]), 0);
    assert_eq!(r.pinned(), ["d", "b", "c", "a"]);
    let visible = r.pinned().to_vec();
    r.move_pinned(&visible, &set(&[0, 2]), 4);
    assert_eq!(r.pinned(), ["b", "a", "d", "c"]);
}

#[test]
fn move_pinned_keeps_hidden_pins_at_the_end() {
    let mut r = ConnectionRanking::new(ids(&["a", "hidden", "b"]), HashMap::new());
    r.move_pinned(&ids(&["a", "b"]), &set(&[1]), 0);
    assert_eq!(r.pinned(), ["b", "a", "hidden"]);
}

#[test]
fn prune_removes_deleted_connections() {
    let mut r = ConnectionRanking::default();
    r.record_success("keep", t0());
    r.record_success("gone", t0());
    r.pin("gone");
    r.pin("keep");
    let keep: HashSet<String> = ["keep".to_string(), "new".to_string()].into();
    assert!(r.prune(&keep));
    assert_eq!(r.pinned(), ["keep"]);
    assert_eq!(r.usage().keys().collect::<Vec<_>>(), ["keep"]);
    assert!(!r.prune(&["keep".to_string()].into()), "nothing to remove");
}

#[cfg(unix)]
#[test]
fn store_round_trip_with_0600_file() {
    let tmp = TempDir::new();
    let store = ConnectionRankingStore::new(tmp.path().join("MacVPN/connection-order.json"));
    assert_eq!(store.load(), ConnectionRanking::default(), "missing file: empty");
    let mut r = ConnectionRanking::default();
    r.record_success("a", t0());
    r.record_success("a", t0().adding(3.0 * DAY));
    r.pin("b");
    store.save(&r).unwrap();
    let loaded = store.load();
    assert_eq!(loaded.pinned(), ["b"]);
    close(loaded.score("a", t0().adding(10.0 * DAY)), r.score("a", t0().adding(10.0 * DAY)), 1e-9);
    assert_eq!(mode(&store.path), 0o600);
    assert_eq!(mode(store.path.parent().unwrap()), 0o700);
}

#[test]
fn corrupt_file_loads_empty() {
    let tmp = TempDir::new();
    std::fs::create_dir_all(tmp.path()).unwrap();
    let store = ConnectionRankingStore::new(tmp.path().join("connection-order.json"));
    std::fs::write(&store.path, "{not json").unwrap();
    assert_eq!(store.load(), ConnectionRanking::default());
}

#[test]
fn default_location_is_application_support() {
    let support = Path::new("/Users/x/Library/Application Support/MacVPN");
    let path = ConnectionRankingStore::default_path(support);
    assert_eq!(path.file_name().unwrap(), "connection-order.json");
    assert_eq!(path.parent().unwrap(), support);
    let otp = SystemOTPStore::default_path(support);
    assert_eq!(otp.file_name().unwrap(), "system-otp.json");
    assert_eq!(otp.parent().unwrap(), support);
}

#[cfg(unix)]
#[test]
fn system_otp_store() {
    let tmp = TempDir::new();
    let store = SystemOTPStore::new(tmp.path().join("system-otp.json"));
    assert!(store.load().is_empty());
    let map: HashMap<String, OTPSetting> =
        [("A".to_string(), OTPSetting::new(true, OTPSeparator::Comma)), ("B".to_string(), OTPSetting::default())]
            .into();
    store.save(&map).unwrap();
    let expected: HashMap<String, OTPSetting> = [("A".to_string(), OTPSetting::new(true, OTPSeparator::Comma))].into();
    assert_eq!(store.load(), expected);
    assert_eq!(mode(&store.path), 0o600);
}
