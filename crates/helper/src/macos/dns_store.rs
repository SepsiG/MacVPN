//! The SystemConfiguration dynamic store as the DNS manager sees it (root layer 15): a small value tree for the
//! property lists it reads and writes, the batch operations the manager applies, and the [`Store`] trait with its
//! three implementations:
//!
//! - [`ScStore`]: the real dynamic store (`sc_store`), only as root;
//! - [`MemStore`]: in memory, for the unit tests (it can stand in for configd's IPMonitor, see
//!   [`MemStore::ipmonitor`]);
//! - [`FileStore`]: one JSON file per key in a directory, for test mode (`MVPN_DYNSTORE=<dir>`), so
//!   `scripts/test-root.sh` can seed the network's keys and read the results with `cat`.
//!
//! Test mode without `MVPN_DYNSTORE` has no store at all: the DNS manager then changes nothing.

use crate::macos::paths::Settings;
use crate::macos::sc_store;
use regex::Regex;
#[cfg(test)]
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The property-list values the DNS entries use: strings, integers, booleans, arrays and dictionaries. Anything
/// else read back from the store (a date, data, a real) is not represented: the reader drops it (strict).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    Array(Vec<Value>),
    Dict(Dict),
}

/// A dictionary value (keys sorted, so equal dictionaries compare and render equal).
pub type Dict = BTreeMap<String, Value>;

/// One change of a batch: set a key to a dictionary, or remove it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Set(String, Dict),
    Remove(String),
}

/// A string array value.
pub fn strings(v: &[String]) -> Value {
    Value::Array(v.iter().cloned().map(Value::Str).collect())
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&Dict> {
        match self {
            Value::Dict(d) => Some(d),
            _ => None,
        }
    }

    /// The strings of an array value; the non-string items are skipped. `None` for a non-array.
    pub fn as_strings(&self) -> Option<Vec<String>> {
        match self {
            Value::Array(a) => Some(a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()),
            _ => None,
        }
    }
}

/// `d[key]` as a list of strings (empty when absent or not an array).
pub fn list_of(d: &Dict, key: &str) -> Vec<String> {
    d.get(key).and_then(Value::as_strings).unwrap_or_default()
}

/// The dynamic store's operations the DNS manager needs.
pub trait Store {
    /// The value of `key`; `None` when absent (or not representable).
    fn get(&self, key: &str) -> Option<Value>;
    /// The keys matching the regular expression `pattern` (the manager anchors its patterns with `^…$`); empty when
    /// they cannot be listed.
    fn keys(&self, pattern: &str) -> Vec<String>;
    /// One batch: all sets and removes together (`SCDynamicStoreSetMultiple`); the error text on failure (logged
    /// by the caller).
    fn apply(&self, ops: &[Op]) -> Result<(), String>;

    /// `get` as a dictionary.
    fn dict(&self, key: &str) -> Option<Dict> {
        match self.get(key)? {
            Value::Dict(d) => Some(d),
            _ => None,
        }
    }
}

/// The real dynamic store (as root).
pub struct ScStore(sc_store::Session);

impl ScStore {
    pub fn open() -> Result<ScStore, String> {
        sc_store::open("mvpn").map(ScStore)
    }
}

impl Store for ScStore {
    fn get(&self, key: &str) -> Option<Value> {
        self.0.get(key)
    }

    fn keys(&self, pattern: &str) -> Vec<String> {
        self.0.keys(pattern).unwrap_or_default()
    }

    fn apply(&self, ops: &[Op]) -> Result<(), String> {
        self.0.apply(ops)
    }
}

/// The store for this invocation: the real one as root; in test mode the file store, only with `MVPN_DYNSTORE`.
pub fn store(s: &Settings) -> Option<Box<dyn Store>> {
    if s.test_mode {
        return s.dynstore.as_ref().map(|d| Box::new(FileStore::new(d)) as Box<dyn Store>);
    }
    ScStore::open().ok().map(|st| Box::new(st) as Box<dyn Store>)
}

/// A regular expression the manager built (a fixed shape plus a UUID or a service ID); an invalid one matches
/// nothing.
fn matcher(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

/// In memory (unit tests). Counts `get` calls (the energy guard of the reconcile) and can stand in for IPMonitor.
#[cfg(test)]
#[derive(Default)]
pub struct MemStore {
    pub map: RefCell<BTreeMap<String, Value>>,
    pub gets: Cell<usize>,
    /// After every batch, writes `State:/Network/Global/DNS` `ServerAddresses` from the primary service's `Setup:`
    /// DNS (over its `State:` DNS), as configd's IPMonitor merges them.
    pub ipmonitor: bool,
    /// Fail every batch (the error path).
    pub fail: Cell<bool>,
}

#[cfg(test)]
impl MemStore {
    pub fn set(&self, key: &str, d: Dict) {
        self.map.borrow_mut().insert(key.to_string(), Value::Dict(d));
    }

    /// The network of a test: `sid` primary and the only ordered service, its DHCP DNS `servers` and `domain`, and
    /// its IPv4 address `addr`/24.
    pub fn seed_primary(&self, sid: &str, servers: &[&str], domain: Option<&str>, addr: &str) {
        let s = |v: &[&str]| strings(&v.iter().map(|x| x.to_string()).collect::<Vec<_>>());
        self.set("State:/Network/Global/IPv4", Dict::from([("PrimaryService".into(), Value::Str(sid.into()))]));
        self.set("Setup:/Network/Global/IPv4", Dict::from([("ServiceOrder".into(), s(&[sid]))]));
        let mut dns = Dict::from([("ServerAddresses".to_string(), s(servers))]);
        if let Some(d) = domain {
            dns.insert("DomainName".into(), Value::Str(d.into()));
        }
        self.set(&format!("State:/Network/Service/{sid}/DNS"), dns);
        self.set(
            &format!("State:/Network/Service/{sid}/IPv4"),
            Dict::from([
                ("Addresses".to_string(), s(&[addr])),
                ("SubnetMasks".to_string(), s(&["255.255.255.0"])),
                ("InterfaceName".to_string(), Value::Str("en0".into())),
            ]),
        );
    }

    fn merge_global(&self) {
        let mut m = self.map.borrow_mut();
        let sid = m
            .get("State:/Network/Global/IPv4")
            .and_then(Value::as_dict)
            .and_then(|d| d.get("PrimaryService"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let Some(sid) = sid else { return };
        let servers = |k: String| m.get(&k).and_then(Value::as_dict).and_then(|d| d.get("ServerAddresses")).cloned();
        let v = servers(format!("Setup:/Network/Service/{sid}/DNS"))
            .or_else(|| servers(format!("State:/Network/Service/{sid}/DNS")));
        match v {
            Some(v) => {
                m.insert("State:/Network/Global/DNS".into(), Value::Dict(Dict::from([("ServerAddresses".into(), v)])))
            }
            None => m.remove("State:/Network/Global/DNS"),
        };
    }
}

#[cfg(test)]
impl Store for MemStore {
    fn get(&self, key: &str) -> Option<Value> {
        self.gets.set(self.gets.get() + 1);
        self.map.borrow().get(key).cloned()
    }

    fn keys(&self, pattern: &str) -> Vec<String> {
        let Some(re) = matcher(pattern) else { return Vec::new() };
        self.map.borrow().keys().filter(|k| re.is_match(k)).cloned().collect()
    }

    fn apply(&self, ops: &[Op]) -> Result<(), String> {
        if self.fail.get() {
            return Err("SCDynamicStoreSetMultiple: failed (test)".into());
        }
        {
            let mut m = self.map.borrow_mut();
            for op in ops {
                match op {
                    Op::Set(k, d) => m.insert(k.clone(), Value::Dict(d.clone())),
                    Op::Remove(k) => m.remove(k),
                };
            }
        }
        if self.ipmonitor {
            self.merge_global();
        }
        Ok(())
    }
}

/// Test mode: one file per key in `dir` (the key percent-encoded), the value as JSON.
pub struct FileStore {
    dir: PathBuf,
}

/// Letters, digits, `-`, `_` and `.` stay; every other byte becomes `%XX` (so `/` and `:` never reach the path).
pub fn encode_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len() * 2);
    for b in key.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The reverse of [`encode_key`]; `None` for a name it did not write.
pub fn decode_key(name: &str) -> Option<String> {
    let b = name.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Str(s) => serde_json::Value::String(s.clone()),
        Value::Int(i) => serde_json::Value::from(*i),
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Array(a) => serde_json::Value::Array(a.iter().map(to_json).collect()),
        Value::Dict(d) => serde_json::Value::Object(d.iter().map(|(k, v)| (k.clone(), to_json(v))).collect()),
    }
}

fn from_json(v: &serde_json::Value) -> Option<Value> {
    Some(match v {
        serde_json::Value::String(s) => Value::Str(s.clone()),
        serde_json::Value::Number(n) => Value::Int(n.as_i64()?),
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Array(a) => Value::Array(a.iter().filter_map(from_json).collect()),
        serde_json::Value::Object(o) => {
            Value::Dict(o.iter().filter_map(|(k, v)| Some((k.clone(), from_json(v)?))).collect())
        }
        serde_json::Value::Null => return None,
    })
}

impl FileStore {
    pub fn new(dir: &Path) -> FileStore {
        FileStore { dir: dir.to_path_buf() }
    }

    fn path(&self, key: &str) -> PathBuf {
        self.dir.join(encode_key(key))
    }
}

impl Store for FileStore {
    fn get(&self, key: &str) -> Option<Value> {
        let text = std::fs::read_to_string(self.path(key)).ok()?;
        from_json(&serde_json::from_str(&text).ok()?)
    }

    fn keys(&self, pattern: &str) -> Vec<String> {
        let Some(re) = matcher(pattern) else { return Vec::new() };
        let Ok(rd) = std::fs::read_dir(&self.dir) else { return Vec::new() };
        let mut keys: Vec<String> = rd
            .flatten()
            .filter_map(|e| decode_key(&e.file_name().to_string_lossy()))
            .filter(|k| re.is_match(k))
            .collect();
        keys.sort();
        keys
    }

    fn apply(&self, ops: &[Op]) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        for op in ops {
            match op {
                Op::Set(k, d) => {
                    let text = serde_json::to_string(&to_json(&Value::Dict(d.clone()))).map_err(|e| e.to_string())?;
                    std::fs::write(self.path(k), text + "\n").map_err(|e| e.to_string())?;
                }
                Op::Remove(k) => match std::fs::remove_file(self.path(k)) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
                    _ => {}
                },
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(pairs: &[(&str, Value)]) -> Dict {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn mem_store_batches_and_patterns() {
        let m = MemStore::default();
        m.apply(&[
            Op::Set("State:/Network/Service/macvpn-A/DNS".into(), d(&[("x", Value::Int(1))])),
            Op::Set("State:/Network/Service/macvpn-A-local/DNS".into(), Dict::new()),
            Op::Set("State:/Network/Service/S1/DNS".into(), Dict::new()),
        ])
        .unwrap();
        let ours = m.keys("^State:/Network/Service/macvpn-[^/]+/DNS$");
        assert_eq!(ours.len(), 2);
        m.apply(&[Op::Remove("State:/Network/Service/macvpn-A/DNS".into()), Op::Remove("absent".into())]).unwrap();
        assert_eq!(m.keys("^State:/Network/Service/macvpn-").len(), 1);
        assert_eq!(m.dict("State:/Network/Service/S1/DNS"), Some(Dict::new()));
        m.fail.set(true);
        assert!(m.apply(&[]).is_err());
        assert!(m.keys("(").is_empty(), "an invalid pattern matches nothing");
    }

    #[test]
    fn mem_store_ipmonitor_merges_setup_over_state() {
        let m = MemStore { ipmonitor: true, ..Default::default() };
        m.seed_primary("S1", &["192.168.1.1"], Some("lan"), "192.168.1.20");
        m.apply(&[]).unwrap();
        let global = |m: &MemStore| m.dict("State:/Network/Global/DNS").unwrap()["ServerAddresses"].clone();
        assert_eq!(global(&m), strings(&["192.168.1.1".into()]));
        m.apply(&[Op::Set(
            "Setup:/Network/Service/S1/DNS".into(),
            d(&[("ServerAddresses", strings(&["10.8.0.1".into()]))]),
        )])
        .unwrap();
        assert_eq!(global(&m), strings(&["10.8.0.1".into()]));
    }

    #[test]
    fn file_store_round_trips_values_and_escapes_keys() {
        let dir = std::env::temp_dir().join(format!("mvpn-filestore-{}", uuid::Uuid::new_v4()));
        let f = FileStore::new(&dir);
        let v = d(&[
            ("ServerAddresses", strings(&["10.8.0.1".into(), "fd00::1".into()])),
            ("SearchOrder", Value::Int(100)),
            ("Flag", Value::Bool(true)),
            ("Nested", Value::Dict(d(&[("a", Value::Str("b".into()))]))),
        ]);
        let key = "Setup:/Network/Service/S1/DNS";
        f.apply(&[Op::Set(key.into(), v.clone())]).unwrap();
        assert!(dir.join("Setup%3A%2FNetwork%2FService%2FS1%2FDNS").is_file());
        assert_eq!(f.dict(key), Some(v));
        assert_eq!(f.keys("^Setup:/Network/Service/[^/]+/DNS$"), [key]);
        f.apply(&[Op::Remove(key.into()), Op::Remove(key.into())]).unwrap();
        assert_eq!(f.get(key), None);
        assert_eq!(decode_key(&encode_key("a/b:c%d")), Some("a/b:c%d".into()));
        assert_eq!(decode_key("%Z1"), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
