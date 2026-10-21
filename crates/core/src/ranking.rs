//! Port of `ConnectionRanking.swift` (spec 10e): pinned connections first in the user's order; below them the
//! others by use (1 point per successful connection, decaying with a 14-day half-life), ties by name. The key is
//! the managed connection's UUID string or the system VPN's scutil service ID. A pure value: the caller passes
//! the clock.

use crate::collation;
use crate::date::Date;
use crate::models::DecodeError;
use crate::store::{ensure_private_parent, write_private};
use crate::swift_json;
use serde_json::{Map, Number, Value};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UsageStats {
    /// The score at `last_updated`.
    pub score: f64,
    pub last_updated: Date,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct ConnectionRanking {
    pinned: Vec<String>,
    usage: HashMap<String, UsageStats>,
}

pub const HALF_LIFE: f64 = 14.0 * 24.0 * 60.0 * 60.0;

impl ConnectionRanking {
    pub fn new(pinned: Vec<String>, usage: HashMap<String, UsageStats>) -> Self {
        ConnectionRanking { pinned, usage }
    }

    /// Pinned keys, in display order.
    pub fn pinned(&self) -> &[String] {
        &self.pinned
    }

    pub fn usage(&self) -> &HashMap<String, UsageStats> {
        &self.usage
    }

    /// `score` decayed from `from` to `to`. Does not grow when the clock goes backwards (`to < from`).
    pub fn decayed(score: f64, from: Date, to: Date) -> f64 {
        let elapsed = f64::max(0.0, to.time_interval_since(from));
        score * 0.5f64.powf(elapsed / HALF_LIFE)
    }

    pub fn score(&self, id: &str, now: Date) -> f64 {
        match self.usage.get(id) {
            None => 0.0,
            Some(stats) => Self::decayed(stats.score, stats.last_updated, now),
        }
    }

    /// A successful connection: the score decayed to `now`, then +1.
    pub fn record_success(&mut self, id: &str, now: Date) {
        let last = self.usage.get(id).map_or(now, |s| s.last_updated);
        let stats = UsageStats { score: self.score(id, now) + 1.0, last_updated: Date::max(now, last) };
        self.usage.insert(id.to_string(), stats);
    }

    pub fn is_pinned(&self, id: &str) -> bool {
        self.pinned.iter().any(|p| p == id)
    }

    /// Appended to the pinned ones; no change if already pinned.
    pub fn pin(&mut self, id: &str) {
        if !self.is_pinned(id) {
            self.pinned.push(id.to_string());
        }
    }

    pub fn unpin(&mut self, id: &str) {
        self.pinned.retain(|p| p != id);
    }

    /// Drag in the visible pinned list (SwiftUI `onMove` parameters). `visible` is the currently visible order of
    /// the pinned keys; pinned keys that are not visible (e.g. a system VPN not listed now) stay at the end.
    pub fn move_pinned(&mut self, visible: &[String], source: &BTreeSet<usize>, destination: usize) {
        let mut moved: Vec<String> = visible.to_vec();
        let items: Vec<String> = source.iter().filter(|&&i| i < moved.len()).map(|&i| moved[i].clone()).collect();
        let insert_at = destination as isize - source.iter().filter(|&&i| i < destination).count() as isize;
        for &index in source.iter().rev() {
            if index < moved.len() {
                moved.remove(index);
            }
        }
        let at = insert_at.clamp(0, moved.len() as isize) as usize;
        moved.splice(at..at, items);
        let rest: Vec<String> = self.pinned.iter().filter(|p| !moved.contains(p)).cloned().collect();
        let mut pinned: Vec<String> = moved.into_iter().filter(|m| self.pinned.contains(m)).collect();
        pinned.extend(rest);
        self.pinned = pinned;
    }

    /// Removes the entries of connections that no longer exist. `true`: changed.
    pub fn prune(&mut self, keeping: &HashSet<String>) -> bool {
        let before = self.clone();
        self.pinned.retain(|p| keeping.contains(p));
        self.usage.retain(|k, _| keeping.contains(k));
        before != *self
    }

    /// The order: the pinned ones (in `pinned` order) first, then the others by decreasing score, then by name
    /// (case-insensitive, by the language's rules), finally by key (stable).
    pub fn order_with(
        ids: &[String],
        pinned: &[String],
        score: impl Fn(&str) -> f64,
        name: impl Fn(&str) -> String,
    ) -> Vec<String> {
        let present: HashSet<&str> = ids.iter().map(String::as_str).collect();
        let mut seen: HashSet<&str> = HashSet::new();
        let mut top: Vec<String> = Vec::new();
        for p in pinned {
            if present.contains(p.as_str()) && seen.insert(p.as_str()) {
                top.push(p.clone());
            }
        }
        let rest: Vec<&String> = ids.iter().filter(|i| !seen.contains(i.as_str())).collect();
        let mut scores: HashMap<&str, f64> = HashMap::new();
        for r in &rest {
            scores.entry(r.as_str()).or_insert_with(|| score(r));
        }
        let mut sorted = rest;
        sorted.sort_by(|a, b| {
            let (sa, sb) = (scores[a.as_str()], scores[b.as_str()]);
            if sa != sb {
                return if sa > sb { Ordering::Less } else { Ordering::Greater };
            }
            match collation::localized_case_insensitive_compare(&name(a), &name(b)) {
                Ordering::Equal => crate::swift_str::cmp(a, b),
                other => other,
            }
        });
        top.extend(sorted.into_iter().cloned());
        top
    }

    /// [`Self::order_with`] with the stored pins and scores.
    pub fn order(&self, ids: &[String], now: Date, name: impl Fn(&str) -> String) -> Vec<String> {
        Self::order_with(ids, &self.pinned, |id| self.score(id, now), name)
    }

    /// Synthesized `Decodable` (`.iso8601` dates): `pinned` and `usage` are both required.
    pub fn from_json(value: &Value) -> Result<ConnectionRanking, DecodeError> {
        let err = |m: &str| DecodeError(m.to_string());
        let obj = value.as_object().ok_or_else(|| err("ranking"))?;
        let pinned = obj
            .get("pinned")
            .and_then(Value::as_array)
            .ok_or_else(|| err("pinned"))?
            .iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| err("pinned"))?;
        let mut usage = HashMap::new();
        for (key, v) in obj.get("usage").and_then(Value::as_object).ok_or_else(|| err("usage"))? {
            let entry = v.as_object().ok_or_else(|| err("usage entry"))?;
            let score = entry.get("score").and_then(Value::as_f64).ok_or_else(|| err("score"))?;
            let last_updated = entry
                .get("lastUpdated")
                .and_then(Value::as_str)
                .and_then(Date::parse_iso8601)
                .ok_or_else(|| err("lastUpdated"))?;
            usage.insert(key.clone(), UsageStats { score, last_updated });
        }
        Ok(ConnectionRanking { pinned, usage })
    }

    pub fn to_json(&self) -> Result<Value, String> {
        let mut usage = Map::new();
        for (key, stats) in &self.usage {
            let mut m = Map::new();
            let score = Number::from_f64(stats.score).ok_or("Unable to encode a non-finite score")?;
            m.insert("score".into(), Value::Number(score));
            m.insert("lastUpdated".into(), Value::String(stats.last_updated.iso8601()));
            usage.insert(key.clone(), Value::Object(m));
        }
        let mut m = Map::new();
        m.insert("pinned".into(), Value::Array(self.pinned.iter().cloned().map(Value::String).collect()));
        m.insert("usage".into(), Value::Object(usage));
        Ok(Value::Object(m))
    }
}

/// `connection-order.json` in the app's data directory (`Product::data_dir`); 0600, atomic write. Not secret, not
/// exported.
#[derive(Debug, Clone)]
pub struct ConnectionRankingStore {
    pub path: PathBuf,
}

impl ConnectionRankingStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        ConnectionRankingStore { path: path.into() }
    }

    /// `<application support>/connection-order.json`.
    pub fn default_path(application_support: &Path) -> PathBuf {
        application_support.join("connection-order.json")
    }

    /// A missing or invalid file: empty order (nothing worth keeping from it).
    pub fn load(&self) -> ConnectionRanking {
        std::fs::read(&self.path)
            .ok()
            .and_then(|data| swift_json::parse(&data).ok())
            .and_then(|v| ConnectionRanking::from_json(&v).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, ranking: &ConnectionRanking) -> io::Result<()> {
        ensure_private_parent(&self.path)?;
        let json = ranking.to_json().and_then(|v| swift_json::to_pretty_sorted(&v)).map_err(io::Error::other)?;
        write_private(json.as_bytes(), &self.path)
    }
}
