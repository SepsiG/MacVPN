//! Live traffic: the totals across counter restarts, the smoothed rate and the texts (EN and HU).

use macvpn_app_core::traffic::{RATE_WINDOW, Traffic, TrafficBook, format_bytes, format_rate, texts};
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_platform_api::{CounterWidth, TrafficReading};

fn r(generation: u64, rx: u64, tx: u64) -> TrafficReading {
    TrafficReading { generation, rx, tx, width: CounterWidth::Bits64, from_zero: true }
}

fn totals(book: &TrafficBook, key: &str, now: f64) -> (u64, u64) {
    let t = book.get(key, now).expect("traffic known");
    (t.rx, t.tx)
}

#[test]
fn a_fresh_tunnels_first_reading_counts_whole() {
    let mut b = TrafficBook::default();
    b.observe("A", 100.0, r(1, 5000, 700));
    assert_eq!(totals(&b, "A", 100.0), (5000, 700));
    b.observe("A", 101.0, r(1, 6000, 900));
    assert_eq!(totals(&b, "A", 101.0), (6000, 900));
}

#[test]
fn a_persistent_adapter_counts_from_its_first_reading() {
    let mut b = TrafficBook::default();
    let p = |rx, tx| TrafficReading { from_zero: false, ..r(9, rx, tx) };
    b.observe("A", 100.0, p(1_000_000, 500_000));
    assert!(b.get("A", 100.0).is_none(), "only the baseline so far");
    b.observe("A", 101.0, p(1_000_400, 500_100));
    assert_eq!(totals(&b, "A", 101.0), (400, 100));
}

#[test]
fn a_counter_restart_within_the_session_keeps_the_totals() {
    let mut b = TrafficBook::default();
    b.observe("A", 100.0, r(1, 5000, 700));
    // The interface was recreated with the same index: the counters went down.
    b.observe("A", 101.0, r(1, 300, 20));
    assert_eq!(totals(&b, "A", 101.0), (5300, 720));
    b.observe("A", 102.0, r(1, 400, 30));
    assert_eq!(totals(&b, "A", 102.0), (5400, 730));
}

#[test]
fn a_new_generation_adds_its_counters_whole() {
    let mut b = TrafficBook::default();
    b.observe("A", 100.0, r(1, 5000, 700));
    // A reconnect: another interface whose counters are already above the old ones.
    b.observe("A", 105.0, r(2, 9000, 800));
    assert_eq!(totals(&b, "A", 105.0), (14000, 1500));
}

#[test]
fn a_new_generation_of_a_persistent_adapter_starts_from_its_first_reading() {
    let mut b = TrafficBook::default();
    let p = |g, rx, tx| TrafficReading { generation: g, rx, tx, width: CounterWidth::Bits64, from_zero: false };
    b.observe("A", 100.0, p(1, 1000, 1000));
    b.observe("A", 101.0, p(1, 3000, 1500));
    b.observe("A", 110.0, p(2, 8000, 9000));
    b.observe("A", 111.0, p(2, 8100, 9010));
    assert_eq!(totals(&b, "A", 111.0), (2100, 510));
}

#[test]
fn a_32_bit_counter_wraps_instead_of_restarting() {
    let mut b = TrafficBook::default();
    let w = |rx: u64, tx: u64| TrafficReading { width: CounterWidth::Bits32, ..r(4, rx, tx) };
    b.observe("A", 100.0, w(u64::from(u32::MAX) - 99, 10));
    b.observe("A", 101.0, w(50, 20));
    assert_eq!(totals(&b, "A", 101.0), (u64::from(u32::MAX) + 51, 20));
}

#[test]
fn a_32_bit_counter_that_falls_within_its_lower_half_restarted() {
    let mut b = TrafficBook::default();
    let w = |rx: u64, tx: u64| TrafficReading { width: CounterWidth::Bits32, ..r(4, rx, tx) };
    b.observe("A", 100.0, w(900_000, 3_000_000_000));
    b.observe("A", 101.0, w(1_000, 3_000_000_100));
    assert_eq!(totals(&b, "A", 101.0), (901_000, 3_000_000_100));
}

#[test]
fn a_restart_of_the_session_starts_the_totals_again() {
    let mut b = TrafficBook::default();
    b.observe("A", 100.0, r(1, 5000, 700));
    b.restart("A");
    assert!(b.get("A", 100.0).is_none());
    b.observe("A", 200.0, r(2, 10, 20));
    assert_eq!(totals(&b, "A", 200.0), (10, 20));
}

#[test]
fn counters_that_never_moved_show_nothing() {
    // A driver that keeps no statistics reads zero: never shown as "0 B".
    let mut b = TrafficBook::default();
    b.observe("A", 100.0, r(1, 0, 0));
    b.observe("A", 101.0, r(1, 0, 0));
    assert!(b.get("A", 101.0).is_none());
    b.observe("A", 102.0, r(1, 0, 64));
    assert_eq!(totals(&b, "A", 102.0), (0, 64));
}

#[test]
fn a_persistent_adapter_that_never_moved_shows_nothing() {
    let mut b = TrafficBook::default();
    let p = |rx, tx| TrafficReading { from_zero: false, ..r(9, rx, tx) };
    b.observe("A", 100.0, p(1000, 1000));
    assert!(b.get("A", 100.0).is_none(), "no movement seen yet");
    b.observe("A", 101.0, p(1000, 1100));
    assert_eq!(totals(&b, "A", 101.0), (0, 100));
}

#[test]
fn the_rate_is_smoothed_over_the_window() {
    let mut b = TrafficBook::default();
    b.observe("A", 100.0, r(1, 0, 0));
    assert_eq!(b.get("A", 100.0), None);
    b.observe("A", 101.0, r(1, 1000, 100));
    let t = b.get("A", 101.0).unwrap();
    assert_eq!((t.rx_rate, t.tx_rate), (Some(1000.0), Some(100.0)));
    b.observe("A", 102.0, r(1, 4000, 200));
    b.observe("A", 103.0, r(1, 4000, 300));
    // Over the last 3 s: 4000 B and 300 B.
    let t = b.get("A", 103.0).unwrap();
    assert_eq!(t.rx_rate.map(|v| v.round()), Some((4000.0f64 / 3.0).round()));
    assert_eq!(t.tx_rate, Some(100.0));
    // Idle: the rate goes to zero once the window holds no change.
    for s in 104..=107 {
        b.observe("A", f64::from(s), r(1, 4000, 300));
    }
    let t = b.get("A", 107.0).unwrap();
    assert_eq!((t.rx_rate, t.tx_rate), (Some(0.0), Some(0.0)));
    assert_eq!(RATE_WINDOW, 3.0);
}

#[test]
fn the_rate_needs_two_readings_apart_and_recent() {
    let mut b = TrafficBook::default();
    b.observe("A", 100.0, r(1, 1000, 1000));
    assert_eq!(b.get("A", 100.0).unwrap().rx_rate, None, "one reading");
    b.observe("A", 100.2, r(1, 1500, 1000));
    assert_eq!(b.get("A", 100.2).unwrap().rx_rate, None, "too close together");
    // The background reading 3 s earlier anchors the first reading of an opened window.
    b.observe("A", 103.0, r(1, 4000, 1000));
    assert_eq!(b.get("A", 103.0).unwrap().rx_rate, Some(1000.0));
    // Nothing read for a long time: the rate is not known (the totals are).
    let t = b.get("A", 120.0).unwrap();
    assert_eq!((t.rx, t.rx_rate), (4000, None));
}

#[test]
fn a_restart_never_makes_the_rate_negative() {
    let mut b = TrafficBook::default();
    b.observe("A", 100.0, r(1, 9000, 9000));
    b.observe("A", 101.0, r(1, 100, 100));
    let t = b.get("A", 101.0).unwrap();
    assert!(t.rx_rate.unwrap() >= 0.0 && t.tx_rate.unwrap() >= 0.0);
}

#[test]
fn retain_forgets_the_others() {
    let mut b = TrafficBook::default();
    b.observe("A", 100.0, r(1, 5, 5));
    b.observe("B", 100.0, r(2, 5, 5));
    b.retain(&["B"]);
    assert!(b.get("A", 100.0).is_none());
    assert!(b.get("B", 100.0).is_some());
}

#[test]
fn bytes_in_si_units_with_one_decimal_under_100() {
    let en = |n| format_bytes(n, AppLanguage::En);
    assert_eq!(en(0), "0 B");
    assert_eq!(en(999), "999 B");
    assert_eq!(en(1000), "1.0 kB");
    assert_eq!(en(1049), "1.0 kB");
    assert_eq!(en(12_400_000), "12.4 MB");
    assert_eq!(en(99_940), "99.9 kB");
    assert_eq!(en(99_960), "100 kB");
    assert_eq!(en(350_400), "350 kB");
    assert_eq!(en(999_400), "999 kB");
    assert_eq!(en(999_600), "1.0 MB");
    assert_eq!(en(1_500_000_000), "1.5 GB");
    assert_eq!(en(2_000_000_000_000), "2.0 TB");
    assert_eq!(en(123_456_000_000_000), "123 TB");
    assert_eq!(en(u64::MAX), "18446744 TB");
}

#[test]
fn hungarian_uses_a_decimal_comma() {
    assert_eq!(format_bytes(12_400_000, AppLanguage::Hu), "12,4 MB");
    assert_eq!(format_bytes(350_000, AppLanguage::Hu), "350 kB");
    assert_eq!(format_rate(350_000.0, AppLanguage::Hu), "350 kB/s");
    assert_eq!(format_rate(1_260.0, AppLanguage::Hu), "1,3 kB/s");
}

#[test]
fn rates_round_to_whole_bytes() {
    assert_eq!(format_rate(0.0, AppLanguage::En), "0 B/s");
    assert_eq!(format_rate(0.4, AppLanguage::En), "0 B/s");
    assert_eq!(format_rate(512.6, AppLanguage::En), "513 B/s");
    assert_eq!(format_rate(20_000.0, AppLanguage::En), "20.0 kB/s");
    assert_eq!(format_rate(-5.0, AppLanguage::En), "0 B/s");
}

#[test]
fn the_texts_in_english_and_hungarian() {
    let t = Traffic { rx: 12_400_000, tx: 1_200_000, rx_rate: Some(350_000.0), tx_rate: Some(20_000.0) };
    let en = with_language(AppLanguage::En, || texts(&t));
    assert_eq!(en.totals, "↓ 12.4 MB  ↑ 1.2 MB");
    assert_eq!(en.rates.as_deref(), Some("↓ 350 kB/s  ↑ 20.0 kB/s"));
    assert_eq!(en.tooltip, "Since connecting: 12.4 MB down, 1.2 MB up · Now: 350 kB/s down, 20.0 kB/s up");
    let hu = with_language(AppLanguage::Hu, || texts(&t));
    assert_eq!(hu.totals, "↓ 12,4 MB  ↑ 1,2 MB");
    assert_eq!(hu.rates.as_deref(), Some("↓ 350 kB/s  ↑ 20,0 kB/s"));
    assert_eq!(hu.tooltip, "A kapcsolódás óta: le 12,4 MB, fel 1,2 MB · Most: le 350 kB/s, fel 20,0 kB/s");
    let quiet = Traffic { rx_rate: None, tx_rate: None, ..t };
    let en = with_language(AppLanguage::En, || texts(&quiet));
    assert_eq!(en.rates, None);
    assert_eq!(en.tooltip, "Since connecting: 12.4 MB down, 1.2 MB up");
}
