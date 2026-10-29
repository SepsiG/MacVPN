//! Live traffic of the connected tunnels (maintainer request 2026-10-29): next to a live connection's address and
//! connected time, the bytes received and sent since the connection came up and the current rate.
//!
//! The platform reads counters ([`TrafficReading`]: an interface's or a RAS connection's); this module turns them
//! into a session's totals and a smoothed rate, and formats both:
//!
//! - **Totals** accumulate across counter restarts within one session (an interface recreated, an engine or the
//!   app reconnecting): a new [`TrafficReading::generation`] adds its counters whole (or from its first reading for
//!   a persistent adapter), a 64-bit counter that went down restarted from zero, a 32-bit one wrapped. They never go
//!   down. A fresh user connect starts a new session ([`TrafficBook::restart`]).
//! - **Rate**: the totals' change over the last [`RATE_WINDOW`] seconds of readings (about one per second while a
//!   window shows them, one per status poll otherwise).
//! - Counters that never moved in the session show nothing (a driver that keeps no statistics reads zero; never
//!   "0 B" for it).
//! - **Units**: SI steps of 1000 (B, kB, MB, GB, TB) as macOS shows sizes; one decimal under 100, none from 100;
//!   the language's decimal separator (Hungarian: a comma).

use macvpn_core::l10n::{self, AppLanguage, Arg};
use macvpn_platform_api::{CounterWidth, TrafficReading};
use std::collections::{HashMap, VecDeque};

/// The rate is the change over this many seconds of readings.
pub const RATE_WINDOW: f64 = 3.0;
/// Two readings closer than this give no rate.
const MIN_SPAN: f64 = 0.5;
/// A newest reading older than this (seconds) leaves the rate unknown.
const STALE_AFTER: f64 = 2.0 * RATE_WINDOW;
/// Readings older than this (behind the newest) are dropped.
const KEEP: f64 = 10.0;

/// A session's traffic: the totals in bytes and the rates in bytes per second (`None`: not known yet).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Traffic {
    pub rx: u64,
    pub tx: u64,
    pub rx_rate: Option<f64>,
    pub tx_rate: Option<f64>,
}

/// Half of a 32-bit counter's range.
const HALF: u64 = 1 << 31;

/// One direction's counter within a session.
#[derive(Debug, Clone, Copy, Default)]
struct Counter {
    total: u64,
    last: u64,
}

impl Counter {
    /// The first reading of a generation.
    fn start(&mut self, value: u64, from_zero: bool) {
        if from_zero {
            self.total = self.total.saturating_add(value);
        }
        self.last = value;
    }

    /// A later reading of the same generation.
    fn step(&mut self, value: u64, width: CounterWidth) {
        let added = if value >= self.last {
            value - self.last
        } else {
            match width {
                // Wrapped at 2³²: from the upper half to the lower one (a fall within a half, or from a value
                // that is not 32-bit, is a restart).
                CounterWidth::Bits32 if (HALF..=u64::from(u32::MAX)).contains(&self.last) && value < HALF => {
                    (1u64 << 32) - self.last + value
                }
                // Restarted from zero.
                _ => value,
            }
        };
        self.total = self.total.saturating_add(added);
        self.last = value;
    }
}

#[derive(Debug, Default)]
struct Meter {
    rx: Counter,
    tx: Counter,
    generation: Option<u64>,
    /// A counter moved in this session (nonzero in a from-zero reading, or changed).
    moved: bool,
    /// (time, total rx, total tx), oldest first.
    samples: VecDeque<(f64, u64, u64)>,
}

impl Meter {
    fn observe(&mut self, now: f64, r: TrafficReading) {
        if self.generation == Some(r.generation) {
            let before = (self.rx.last, self.tx.last);
            self.rx.step(r.rx, r.width);
            self.tx.step(r.tx, r.width);
            self.moved |= before != (r.rx, r.tx);
        } else {
            self.generation = Some(r.generation);
            self.rx.start(r.rx, r.from_zero);
            self.tx.start(r.tx, r.from_zero);
            self.moved |= r.from_zero && (r.rx > 0 || r.tx > 0);
        }
        // A clock that went back: the readings start again (the totals stay).
        if self.samples.back().is_some_and(|s| s.0 > now) {
            self.samples.clear();
        }
        self.samples.push_back((now, self.rx.total, self.tx.total));
        while self.samples.front().is_some_and(|s| s.0 < now - KEEP) && self.samples.len() > 1 {
            self.samples.pop_front();
        }
    }

    fn traffic(&self, now: f64) -> Option<Traffic> {
        if !self.moved {
            return None;
        }
        let &(t1, rx1, tx1) = self.samples.back()?;
        // The anchor: the newest reading at least a window before the newest one, else the oldest kept.
        let anchor = self.samples.iter().rev().find(|s| s.0 <= t1 - RATE_WINDOW).or(self.samples.front());
        let rate = match anchor {
            Some(&(t0, rx0, tx0)) if t1 - t0 >= MIN_SPAN && now - t1 <= STALE_AFTER => {
                let span = t1 - t0;
                Some(((rx1.saturating_sub(rx0)) as f64 / span, (tx1.saturating_sub(tx0)) as f64 / span))
            }
            _ => None,
        };
        Some(Traffic { rx: rx1, tx: tx1, rx_rate: rate.map(|r| r.0), tx_rate: rate.map(|r| r.1) })
    }
}

/// The sessions by connection key (a managed connection's UUID string, a system VPN's service ID).
#[derive(Debug, Default)]
pub struct TrafficBook {
    meters: HashMap<String, Meter>,
    sampled_at: Option<f64>,
}

impl TrafficBook {
    /// A reading of the key's tunnel at `now` (Unix seconds).
    pub fn observe(&mut self, key: &str, now: f64, reading: TrafficReading) {
        self.meters.entry(key.to_string()).or_default().observe(now, reading);
    }

    /// A fresh user connect: the key's totals start again.
    pub fn restart(&mut self, key: &str) {
        self.meters.remove(key);
    }

    /// Keeps only these keys' sessions (the others are gone or down for good).
    pub fn retain(&mut self, keys: &[&str]) {
        self.meters.retain(|k, _| keys.contains(&k.as_str()));
    }

    /// The key's traffic at `now`; `None`: nothing known (no reading, or counters that never moved).
    pub fn get(&self, key: &str, now: f64) -> Option<Traffic> {
        self.meters.get(key)?.traffic(now)
    }

    /// A round of readings is due: none in the last `gap` seconds (two windows reading at once share one round).
    pub fn due(&self, now: f64, gap: f64) -> bool {
        self.sampled_at.is_none_or(|t| now - t >= gap || now < t)
    }

    /// A round of readings was taken at `now`.
    pub fn sampled(&mut self, now: f64) {
        self.sampled_at = Some(now);
    }
}

// MARK: - Texts

const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];

/// `value` with one decimal in the language's separator.
fn one_decimal(value: f64, language: AppLanguage) -> String {
    let s = format!("{value:.1}");
    match language {
        AppLanguage::Hu => s.replace('.', ","),
        AppLanguage::En => s,
    }
}

/// An amount of bytes (`bytes` ≥ 0, whole) in SI units.
fn amount(bytes: f64, language: AppLanguage) -> String {
    if bytes < 1000.0 {
        return format!("{} B", bytes.round().max(0.0) as u64);
    }
    let mut unit = 0;
    let mut value = bytes;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    // Rounding may reach the next step: 99.96 → "100", 999.6 → "1.0" of the next unit.
    if value < 99.95 {
        return format!("{} {}", one_decimal(value, language), UNITS[unit]);
    }
    let whole = value.round();
    if whole >= 1000.0 && unit < UNITS.len() - 1 {
        return format!("{} {}", one_decimal(whole / 1000.0, language), UNITS[unit + 1]);
    }
    format!("{} {}", whole as u64, UNITS[unit])
}

/// A total ("12.4 MB"; Hungarian "12,4 MB").
pub fn format_bytes(bytes: u64, language: AppLanguage) -> String {
    amount(bytes as f64, language)
}

/// A rate ("350 kB/s"); below one byte per second (or negative) "0 B/s".
pub fn format_rate(bytes_per_second: f64, language: AppLanguage) -> String {
    let v = if bytes_per_second.is_finite() { bytes_per_second.max(0.0) } else { 0.0 };
    l10n::tr_in(language, "%@/s", &[Arg::Str(&amount(v, language))])
}

/// What the rows show of a session's traffic, in the current language.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TrafficText {
    /// "↓ 12.4 MB  ↑ 1.2 MB".
    pub totals: String,
    /// "↓ 350 kB/s  ↑ 20.0 kB/s"; `None` until a rate is known.
    pub rates: Option<String>,
    /// The whole in words (the tooltip and the accessible label).
    pub tooltip: String,
}

/// The texts of `t` in the current language.
pub fn texts(t: &Traffic) -> TrafficText {
    let language = AppLanguage::current();
    let rx = format_bytes(t.rx, language);
    let tx = format_bytes(t.tx, language);
    let totals = l10n::tr_in(language, "↓ %@  ↑ %@", &[Arg::Str(&rx), Arg::Str(&tx)]);
    let since = l10n::tr_in(language, "Since connecting: %@ down, %@ up", &[Arg::Str(&rx), Arg::Str(&tx)]);
    match (t.rx_rate, t.tx_rate) {
        (Some(down), Some(up)) => {
            let (down, up) = (format_rate(down, language), format_rate(up, language));
            let now = l10n::tr_in(language, "Now: %@ down, %@ up", &[Arg::Str(&down), Arg::Str(&up)]);
            TrafficText {
                totals,
                rates: Some(l10n::tr_in(language, "↓ %@  ↑ %@", &[Arg::Str(&down), Arg::Str(&up)])),
                tooltip: format!("{since} · {now}"),
            }
        }
        _ => TrafficText { totals, rates: None, tooltip: since },
    }
}
