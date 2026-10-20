//! JSON for secret-bearing documents (the backup payload, the catalog payload and header, the subscription
//! string): the `serde_json::Value` trees are wiped before they are dropped ([`WipedValue`]), the serialized text
//! goes into a `Zeroizing` buffer of exactly the right size ([`to_wiped_vec`]), and [`parse_strict`] refuses
//! duplicate object keys (which `serde_json::Value` would silently resolve to the last one).
//!
//! The callers keep secret values base64 inside the JSON, so the parser never copies them into its unescaping
//! scratch buffer.

use serde_json::Value;
use std::collections::HashSet;
use std::io;
use zeroize::{Zeroize, Zeroizing};

/// A JSON tree whose strings are wiped when it is dropped.
pub(crate) struct WipedValue(pub(crate) Value);

impl Drop for WipedValue {
    fn drop(&mut self) {
        fn wipe(v: &mut Value) {
            match v {
                Value::String(s) => s.zeroize(),
                Value::Array(items) => items.iter_mut().for_each(wipe),
                Value::Object(map) => map.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

/// Counts the bytes a serialization would take, so the real one goes into a buffer that never reallocates (a
/// reallocation would leave an unwiped copy behind).
pub(crate) struct Counter(pub(crate) usize);

impl io::Write for Counter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Compact JSON in a `Zeroizing` buffer of exactly the serialized size.
pub(crate) fn to_wiped_vec(value: &Value) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)?;
    let mut out = Zeroizing::new(Vec::with_capacity(counter.0));
    serde_json::to_writer(&mut *out, value)?;
    Ok(out)
}

/// Parses JSON (serde_json's strict grammar) and refuses any object with a duplicate key, at any depth (keys are
/// compared after unescaping). `None` for invalid JSON or a duplicate.
pub(crate) fn parse_strict(bytes: &[u8]) -> Option<WipedValue> {
    let value = WipedValue(serde_json::from_slice(bytes).ok()?);
    (!has_duplicate_keys(bytes)).then_some(value)
}

/// One open container while scanning: an object (its keys so far, and whether a key comes next) or an array.
enum Frame {
    Object { keys: HashSet<Vec<u8>>, key_next: bool },
    Array,
}

/// Scans JSON that `serde_json` has already accepted, so the grammar is known to be valid: only the string
/// boundaries, the containers and the commas matter. String values are skipped without being copied; only keys are
/// kept (schema names, never secrets).
fn has_duplicate_keys(b: &[u8]) -> bool {
    let mut stack: Vec<Frame> = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'{' => stack.push(Frame::Object { keys: HashSet::new(), key_next: true }),
            b'[' => stack.push(Frame::Array),
            b'}' | b']' => {
                stack.pop();
            }
            b',' => {
                if let Some(Frame::Object { key_next, .. }) = stack.last_mut() {
                    *key_next = true;
                }
            }
            b'"' => {
                let start = i;
                i += 1;
                let mut escaped = false;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        escaped = true;
                        i += 1;
                    }
                    i += 1;
                }
                if let Some(Frame::Object { keys, key_next }) = stack.last_mut()
                    && *key_next
                {
                    *key_next = false;
                    let raw = &b[start..(i + 1).min(b.len())];
                    let key = if escaped {
                        match serde_json::from_slice::<String>(raw) {
                            Ok(k) => k.into_bytes(),
                            Err(_) => return true,
                        }
                    } else {
                        raw[1..raw.len().saturating_sub(1).max(1)].to_vec()
                    };
                    if !keys.insert(key) {
                        return true;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicates_are_found_at_any_depth() {
        assert!(parse_strict(br#"{"a":1,"b":2}"#).is_some());
        assert!(parse_strict(br#"{"a":1,"a":2}"#).is_none());
        assert!(parse_strict(br#"{"x":[{"a":1},{"a":2}]}"#).is_some());
        assert!(parse_strict(br#"{"x":[{"a":1,"b":{"c":1,"c":1}}]}"#).is_none());
        assert!(parse_strict(br#"{"a":"a","a":2}"#).is_none());
        assert!(parse_strict(br#"{"a\"b":1,"a\"b":2}"#).is_none());
        assert!(parse_strict(br#"{"a":"b","b":"a"}"#).is_some());
        assert!(parse_strict(br#"{"a":{"a":{"a":1}}}"#).is_some());
        assert!(parse_strict(br#"{"":1,"":2}"#).is_none());
        assert!(parse_strict(br#"{"a":["x","a"],"b":1}"#).is_some());
        assert!(parse_strict(b"{\"a\":1,}").is_none());
    }

    #[test]
    fn serialization_is_exactly_sized() {
        let v: Value = serde_json::from_str(r#"{"k":"value","n":[1,2,3]}"#).unwrap();
        let out = to_wiped_vec(&v).unwrap();
        assert_eq!(out.len(), out.capacity());
        assert_eq!(&out[..], br#"{"k":"value","n":[1,2,3]}"#);
    }
}
