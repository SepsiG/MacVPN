//! `Date` with Swift Foundation semantics: a `Double` number of seconds since 2001-01-01T00:00:00Z, written as
//! ISO 8601 the way `JSONEncoder.dateEncodingStrategy = .iso8601` does (`2026-10-16T17:55:00Z`, seconds floored).

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds between 1970-01-01 and 2001-01-01 (Swift `Date.timeIntervalBetween1970AndReferenceDate`).
pub const REFERENCE_DATE_UNIX: f64 = 978_307_200.0;

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default)]
pub struct Date {
    since_reference: f64,
}

impl Date {
    pub fn from_time_interval_since_1970(seconds: f64) -> Date {
        Date { since_reference: seconds - REFERENCE_DATE_UNIX }
    }

    pub fn from_time_interval_since_reference_date(seconds: f64) -> Date {
        Date { since_reference: seconds }
    }

    pub fn now() -> Date {
        let unix = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs_f64(),
            Err(e) => -e.duration().as_secs_f64(),
        };
        Date::from_time_interval_since_1970(unix)
    }

    pub fn time_interval_since_1970(self) -> f64 {
        self.since_reference + REFERENCE_DATE_UNIX
    }

    pub fn time_interval_since_reference_date(self) -> f64 {
        self.since_reference
    }

    /// `self.timeIntervalSince(other)`.
    pub fn time_interval_since(self, other: Date) -> f64 {
        self.since_reference - other.since_reference
    }

    /// `self + interval` (`addingTimeInterval`).
    pub fn adding(self, interval: f64) -> Date {
        Date { since_reference: self.since_reference + interval }
    }

    /// `max(a, b)` as Swift's `Comparable` max (returns `b` when equal).
    pub fn max(a: Date, b: Date) -> Date {
        if b >= a { b } else { a }
    }

    /// ISO 8601 in UTC, whole seconds (floored), e.g. `2026-10-16T17:55:00Z`.
    pub fn iso8601(self) -> String {
        let total = self.time_interval_since_1970().floor() as i64;
        let days = total.div_euclid(86_400);
        let secs = total.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, secs / 3600, secs % 3600 / 60, secs % 60)
    }

    /// Parses what `JSONDecoder.dateDecodingStrategy = .iso8601` accepts in practice:
    /// `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH|±HHMM|±HH:MM)`, optionally followed by spaces.
    /// The day may overflow the month (`02-30` is March 2), as in Foundation.
    pub fn parse_iso8601(s: &str) -> Option<Date> {
        let b = s.trim_end_matches(' ').as_bytes();
        let num = |range: std::ops::Range<usize>| -> Option<i64> {
            let part = b.get(range)?;
            if part.iter().all(u8::is_ascii_digit) { std::str::from_utf8(part).ok()?.parse().ok() } else { None }
        };
        if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
            return None;
        }
        let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
        let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 24 || minute > 59 || second > 60 {
            return None;
        }
        let mut i = 19;
        let mut fraction = 0.0;
        if b[i] == b'.' {
            let start = i + 1;
            let mut end = start;
            while end < b.len() && b[end].is_ascii_digit() {
                end += 1;
            }
            if end == start {
                return None;
            }
            fraction = format!("0.{}", std::str::from_utf8(&b[start..end]).ok()?).parse().ok()?;
            i = end;
        }
        let offset = match b.get(i)? {
            b'Z' if i + 1 == b.len() => 0,
            sign @ (b'+' | b'-') => {
                let rest = &b[i + 1..];
                let (h, m) = match rest.len() {
                    2 => (num(i + 1..i + 3)?, 0),
                    4 => (num(i + 1..i + 3)?, num(i + 3..i + 5)?),
                    5 if rest[2] == b':' => (num(i + 1..i + 3)?, num(i + 4..i + 6)?),
                    _ => return None,
                };
                if h > 18 || m > 59 {
                    return None;
                }
                let o = h * 3600 + m * 60;
                if *sign == b'-' { -o } else { o }
            }
            _ => return None,
        };
        let days = days_from_civil(year, month, 1) + day - 1;
        let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset;
        Some(Date::from_time_interval_since_1970(seconds as f64 + fraction))
    }
}

impl Date {
    /// `ISO8601DateFormatter().date(from:)` (internet date-time; the GitHub API's `published_at`). Foundation's
    /// formatter is lenient: numeric fields of any length, whitespace before the fields and the time zone, a
    /// missing date separator after whitespace, `GMT`/`UTC`, `±h`, `±hhmm`, `±hh:mm(:ss)`, anything after the time
    /// zone ignored; no fractional seconds.
    pub fn parse_iso8601_formatter(s: &str) -> Option<Date> {
        let chars: Vec<char> = s.chars().collect();
        let mut i = 0;
        let skip_ws = |i: &mut usize| {
            while *i < chars.len() && chars[*i].is_whitespace() {
                *i += 1;
            }
        };
        let number = |i: &mut usize| -> Option<i64> {
            let start = *i;
            while *i < chars.len() && chars[*i].is_ascii_digit() {
                *i += 1;
            }
            if *i == start || *i - start > 18 {
                return None;
            }
            chars[start..*i].iter().collect::<String>().parse().ok()
        };
        let expect = |i: &mut usize, c: char| -> Option<()> {
            if chars.get(*i) == Some(&c) {
                *i += 1;
                Some(())
            } else {
                None
            }
        };
        skip_ws(&mut i);
        let year = number(&mut i)?;
        expect(&mut i, '-')?;
        skip_ws(&mut i);
        let month = number(&mut i)?;
        skip_ws(&mut i);
        if chars.get(i) == Some(&'-') {
            i += 1;
            skip_ws(&mut i);
        }
        let day = number(&mut i)?;
        expect(&mut i, 'T')?;
        let hour = number(&mut i)?;
        expect(&mut i, ':')?;
        let minute = number(&mut i)?;
        expect(&mut i, ':')?;
        let second = number(&mut i)?;
        skip_ws(&mut i);
        let rest: String = chars[i..].iter().collect();
        let offset = if rest.starts_with('Z') || rest.starts_with("GMT") || rest.starts_with("UTC") {
            0
        } else {
            let sign = rest.chars().next().filter(|c| *c == '+' || *c == '-')?;
            i += 1;
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let digits: String = chars[start..i].iter().collect();
            let (h, mut m) = match digits.len() {
                1 | 2 => (digits.parse::<i64>().ok()?, 0),
                4 => (digits[..2].parse::<i64>().ok()?, digits[2..].parse::<i64>().ok()?),
                _ => return None,
            };
            if digits.len() <= 2 && chars.get(i) == Some(&':') {
                let start = i + 1;
                let mut j = start;
                while j < chars.len() && chars[j].is_ascii_digit() {
                    j += 1;
                }
                if j - start == 2 {
                    m = chars[start..j].iter().collect::<String>().parse().ok()?;
                }
            }
            if h > 18 || m > 59 {
                return None;
            }
            let o = h * 3600 + m * 60;
            if sign == '-' { -o } else { o }
        };
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 24 || minute > 59 || second > 60 {
            return None;
        }
        let days = days_from_civil(year, month, 1) + day - 1;
        let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset;
        Some(Date::from_time_interval_since_1970(seconds as f64))
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix(s: &str) -> Option<f64> {
        Date::parse_iso8601(s).map(Date::time_interval_since_1970)
    }

    /// Values printed by Swift's `JSONDecoder` (`.iso8601`) on macOS 27.
    #[test]
    fn parses_like_foundation() {
        assert_eq!(unix("2026-10-16T17:55:00Z"), Some(1_792_173_300.0));
        assert_eq!(unix("2026-10-16T17:55:00-00:00"), Some(1_792_173_300.0));
        assert_eq!(unix("2026-10-16T17:55:00+00"), Some(1_792_173_300.0));
        assert_eq!(unix("2026-10-16T17:55:60Z"), Some(1_792_173_360.0));
        assert_eq!(unix("2026-10-16T24:00:00Z"), Some(1_792_195_200.0));
        assert_eq!(unix("2026-02-30T00:00:00Z"), Some(1_772_409_600.0));
        assert_eq!(unix("2026-13-01T00:00:00Z"), None);
        assert_eq!(unix("2026-10-16T17:55:00.Z"), None);
        assert_eq!(unix("2026-10-16T17:55:00,5Z"), None);
        assert_eq!(unix(" 2026-10-16T17:55:00Z"), None);
        assert_eq!(unix("2026-10-16T17:55:00Z "), Some(1_792_173_300.0));
        assert_eq!(unix("2026-10-16T17:55:00+14:00"), Some(1_792_122_900.0));
        assert_eq!(unix("2026-10-16T17:55:00+25:00"), None);
        assert_eq!(unix("2026-10-16T17:55:00+02:30"), Some(1_792_164_300.0));
        assert_eq!(unix("2026-10-16T17:55:00+0200"), Some(1_792_166_100.0));
        assert_eq!(unix("2026-10-16T17:55:00+02"), Some(1_792_166_100.0));
        assert_eq!(unix("2026-10-16T17:55:00.999999Z"), Some(1_792_173_300.999999));
        assert_eq!(unix("1969-12-31T23:59:59.5Z"), Some(-0.5));
        assert_eq!(unix("-2026-10-16T17:55:00Z"), None);
        assert_eq!(unix("+2026-10-16T17:55:00Z"), None);
        assert_eq!(unix("2026-10-16t17:55:00z"), None);
        assert_eq!(unix("2026-10-16 17:55:00Z"), None);
        assert_eq!(unix("2026-10-16T17:55:00"), None);
        assert_eq!(unix("2026-10-16T17:55Z"), None);
        assert_eq!(unix("20261016T175500Z"), None);
    }

    /// Strings written by Swift's `JSONEncoder` (`.iso8601`) on macOS 27.
    #[test]
    fn formats_like_foundation() {
        let f = |t: f64| Date::from_time_interval_since_1970(t).iso8601();
        assert_eq!(f(1.7), "1970-01-01T00:00:01Z");
        assert_eq!(f(-0.5), "1969-12-31T23:59:59Z");
        assert_eq!(f(-1.0), "1969-12-31T23:59:59Z");
        assert_eq!(f(1e10), "2286-11-20T17:46:40Z");
        assert_eq!(f(1.999999), "1970-01-01T00:00:01Z");
        assert_eq!(f(253_402_300_800.0), "10000-01-01T00:00:00Z");
        assert_eq!(f(1_792_173_300.0), "2026-10-16T17:55:00Z");
        assert_eq!(f(951_868_799.0), "2000-02-29T23:59:59Z");
    }

    #[test]
    fn reference_date_arithmetic() {
        let t0 = Date::from_time_interval_since_1970(1_800_000_000.0);
        assert_eq!(t0.time_interval_since_reference_date(), 1_800_000_000.0 - 978_307_200.0);
        assert_eq!(t0.adding(86_400.0).time_interval_since(t0), 86_400.0);
        assert_eq!(Date::parse_iso8601(&t0.iso8601()), Some(t0));
    }
}
