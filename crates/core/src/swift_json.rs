//! JSON the way Swift's `JSONDecoder` reads and `JSONEncoder([.prettyPrinted, .sortedKeys])` writes it.
//!
//! Reading: see [`parse`] (Foundation's lazy validation, first duplicate key wins, trailing commas). Writing: `"key" : value`, two-space indentation, keys sorted, `/` escaped as `\/`, empty
//! containers as `[\n\n<indent>]`, and numbers formatted like Swift's `Double.description` without a trailing
//! `.0`. The output is byte-for-byte what MacVPN 0.4.0 writes (see the Swift-written fixtures).

use serde_json::{Map, Number, Value};

/// Parses JSON bytes like `JSONDecoder`.
///
/// Foundation checks the structure strictly but only validates a string or a number when it is decoded: a value
/// of a key the type does not read may have raw control characters, bad escapes or `01`. Such a value becomes
/// [`invalid_value`], which every typed accessor rejects (an array holding `null`), so decoding it fails exactly
/// where Swift's would. Also as in Foundation: a leading UTF-8 BOM is skipped, one trailing comma is allowed in
/// objects and arrays, the first of duplicate keys wins, nesting is limited to 512 levels.
pub fn parse(bytes: &[u8]) -> Result<Value, ParseError> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let mut p = Parser { b: bytes, i: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return Err(ParseError("trailing data"));
    }
    Ok(v)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub &'static str);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid JSON: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// The stand-in for a string or number Foundation would reject when decoding it.
pub fn invalid_value() -> Value {
    Value::Array(vec![Value::Null])
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

const MAX_DEPTH: usize = 512;

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError("too deep"));
        }
        match self.peek().ok_or(ParseError("unexpected end"))? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => {
                let raw = self.raw_string()?;
                Ok(decode_string(raw).map(Value::String).unwrap_or_else(invalid_value))
            }
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            c if c == b'-' || c.is_ascii_digit() => {
                let start = self.i;
                while self.i < self.b.len() && matches!(self.b[self.i], b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
                {
                    self.i += 1;
                }
                Ok(decode_number(&self.b[start..self.i]).unwrap_or_else(invalid_value))
            }
            _ => Err(ParseError("unexpected character")),
        }
    }

    fn literal(&mut self, word: &[u8], v: Value) -> Result<Value, ParseError> {
        if self.b[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(ParseError("invalid literal"))
        }
    }

    /// The raw bytes between the quotes (escapes not decoded).
    fn raw_string(&mut self) -> Result<&[u8], ParseError> {
        self.i += 1;
        let start = self.i;
        while self.i < self.b.len() {
            match self.b[self.i] {
                b'"' => {
                    let raw = &self.b[start..self.i];
                    self.i += 1;
                    return Ok(raw);
                }
                b'\\' => self.i += 2,
                _ => self.i += 1,
            }
        }
        Err(ParseError("unterminated string"))
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.i += 1;
        let mut map = Map::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(ParseError("expected key"));
            }
            let raw = self.raw_string()?;
            let key = decode_string(raw).ok_or(ParseError("invalid key"))?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(ParseError("expected colon"));
            }
            self.i += 1;
            self.ws();
            let value = self.value(depth + 1)?;
            map.entry(key).or_insert(value);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                    self.ws();
                    if self.peek() == Some(b'}') {
                        self.i += 1;
                        return Ok(Value::Object(map));
                    }
                }
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Value::Object(map));
                }
                _ => return Err(ParseError("expected , or }")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.i += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                    self.ws();
                    if self.peek() == Some(b']') {
                        self.i += 1;
                        return Ok(Value::Array(items));
                    }
                }
                Some(b']') => {
                    self.i += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(ParseError("expected , or ]")),
            }
        }
    }
}

/// A JSON string's content, strictly (no raw control character, valid escapes and surrogate pairs, UTF-8).
fn decode_string(raw: &[u8]) -> Option<String> {
    let mut out: Vec<u8> = Vec::with_capacity(raw.len());
    let mut i = 0;
    let hex4 =
        |i: usize| -> Option<u32> { u32::from_str_radix(std::str::from_utf8(raw.get(i..i + 4)?).ok()?, 16).ok() };
    while i < raw.len() {
        let c = raw[i];
        if c < 0x20 {
            return None;
        }
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        let e = *raw.get(i + 1)?;
        i += 2;
        let ch = match e {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{C}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let hi = hex4(i)?;
                i += 4;
                if (0xD800..0xDC00).contains(&hi) {
                    if raw.get(i) != Some(&b'\\') || raw.get(i + 1) != Some(&b'u') {
                        return None;
                    }
                    let lo = hex4(i + 2)?;
                    if !(0xDC00..0xE000).contains(&lo) {
                        return None;
                    }
                    i += 6;
                    char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))?
                } else {
                    char::from_u32(hi)?
                }
            }
            _ => return None,
        };
        let mut buf = [0u8; 4];
        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
    }
    String::from_utf8(out).ok()
}

/// A JSON number, strictly (`-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?`, finite).
fn decode_number(raw: &[u8]) -> Option<Value> {
    let s = std::str::from_utf8(raw).ok()?;
    let b = s.as_bytes();
    let mut i = 0;
    if b.get(i) == Some(&b'-') {
        i += 1;
    }
    match b.get(i)? {
        b'0' => i += 1,
        b'1'..=b'9' => {
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        _ => return None,
    }
    let mut integer = true;
    if b.get(i) == Some(&b'.') {
        integer = false;
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return None;
        }
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        integer = false;
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return None;
        }
    }
    if i != b.len() {
        return None;
    }
    if integer {
        if let Ok(n) = s.parse::<i64>() {
            return Some(Value::Number(n.into()));
        }
        if let Ok(n) = s.parse::<u64>() {
            return Some(Value::Number(n.into()));
        }
    }
    let f: f64 = s.parse().ok()?;
    Number::from_f64(f).map(Value::Number)
}

/// Swift `JSONEncoder` with `[.prettyPrinted, .sortedKeys]`. Fails on non-finite numbers (as Swift does).
pub fn to_pretty_sorted(value: &Value) -> Result<String, String> {
    let mut out = String::new();
    write_value(&mut out, value, 0)?;
    Ok(out)
}

/// Swift `JSONEncoder` with `.sortedKeys` only (compact). Fails on non-finite numbers (as Swift does).
pub fn to_compact_sorted(value: &Value) -> Result<String, String> {
    let mut out = String::new();
    write_compact(&mut out, value)?;
    Ok(out)
}

fn write_compact(out: &mut String, value: &Value) -> Result<(), String> {
    match value {
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_compact(out, item)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_compact(out, &map[key.as_str()])?;
            }
            out.push('}');
        }
        other => write_value(out, other, 0)?,
    }
    Ok(())
}

fn indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

fn write_value(out: &mut String, value: &Value, level: usize) -> Result<(), String> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&format_number(n)?),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push_str("[\n");
            if items.is_empty() {
                out.push('\n');
            }
            for (i, item) in items.iter().enumerate() {
                indent(out, level + 1);
                write_value(out, item, level + 1)?;
                if i + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(out, level);
            out.push(']');
        }
        Value::Object(map) => {
            out.push_str("{\n");
            if map.is_empty() {
                out.push('\n');
            }
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            for (i, key) in keys.iter().enumerate() {
                indent(out, level + 1);
                write_string(out, key);
                out.push_str(" : ");
                write_value(out, &map[key.as_str()], level + 1)?;
                if i + 1 < keys.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            indent(out, level);
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' => out.push_str("\\/"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn format_number(n: &Number) -> Result<String, String> {
    if let Some(i) = n.as_i64() {
        return Ok(i.to_string());
    }
    if let Some(u) = n.as_u64() {
        return Ok(u.to_string());
    }
    let f = n.as_f64().ok_or("invalid number")?;
    format_double(f)
}

/// Swift `JSONEncoder` for a `Double`: `Double.description` without a trailing `.0` (`1`, `0.1`, `1e-07`,
/// `1e+16`, `1.7976931348623157e+308`). Shortest round-trip digits; exponent form below 1e-4 or from 1e16.
pub fn format_double(f: f64) -> Result<String, String> {
    if !f.is_finite() {
        return Err(format!("Unable to encode {f} directly in JSON."));
    }
    if f == 0.0 {
        return Ok(if f.is_sign_negative() { "-0".into() } else { "0".into() });
    }
    // `{:e}` gives the shortest round-trip digits: "1.2345678901234568e17", "1e-7".
    let sci = format!("{f:e}");
    let (mantissa, exp) = sci.split_once('e').ok_or("format")?;
    let exp: i32 = exp.parse().map_err(|_| "format")?;
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if (-4..16).contains(&exp) {
        if exp < 0 {
            out.push_str("0.");
            for _ in 0..(-exp - 1) {
                out.push('0');
            }
            out.push_str(&digits);
        } else {
            let int_len = exp as usize + 1;
            if digits.len() <= int_len {
                out.push_str(&digits);
                for _ in digits.len()..int_len {
                    out.push('0');
                }
            } else {
                out.push_str(&digits[..int_len]);
                out.push('.');
                out.push_str(&digits[int_len..]);
            }
        }
    } else {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if exp < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}", exp.abs()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Values printed by Swift's `JSONEncoder` on macOS 27.
    #[test]
    fn doubles_like_swift() {
        let cases = [
            (1.0, "1"),
            (2.5, "2.5"),
            (1e20, "1e+20"),
            (1e21, "1e+21"),
            (1.7071067811865475, "1.7071067811865475"),
            (0.00001, "1e-05"),
            (123_456_789_012_345_678.0, "1.2345678901234568e+17"),
            (1e16, "1e+16"),
            (5e-324, "5e-324"),
            (0.1, "0.1"),
            (1e-7, "1e-07"),
            (1.5e-7, "1.5e-07"),
            (0.0001, "0.0001"),
            (1e15, "1000000000000000"),
            (0.0, "0"),
            (-0.0, "-0"),
            (2.5e-308, "2.5e-308"),
            (1.797_693_134_862_315_7e308, "1.7976931348623157e+308"),
            (0.1 + 0.2, "0.30000000000000004"),
            (12_345_678.9, "12345678.9"),
            (9_007_199_254_740_992.0, "9007199254740992"),
            (-1.5, "-1.5"),
            (100.0, "100"),
        ];
        for (v, s) in cases {
            assert_eq!(format_double(v).unwrap(), s, "{v}");
        }
        assert!(format_double(f64::NAN).is_err());
        assert!(format_double(f64::INFINITY).is_err());
    }

    #[test]
    fn first_duplicate_key_wins_and_bom_is_skipped() {
        let v = parse(br#"{"a":1,"a":2,"b":{"c":true,"c":false}}"#).unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(v["b"]["c"], true);
        assert_eq!(parse(b"\xEF\xBB\xBF[1]").unwrap(), serde_json::json!([1]));
        assert!(parse(b"{nope").is_err());
        assert!(parse(b"[1] x").is_err());
        // Foundation only rejects these when the value is decoded.
        assert_eq!(parse(b"[1e400]").unwrap(), serde_json::json!([invalid_value()]));
        assert_eq!(
            parse(b"{\"z\":\"x\x01y\",\"a\":01}").unwrap(),
            serde_json::json!({"z": invalid_value(), "a": invalid_value()})
        );
        assert_eq!(parse(b"{\"a\":[1,2,],}").unwrap(), serde_json::json!({"a": [1, 2]}));
        assert!(parse(b"{\"a\":1,,}").is_err());
        assert!(parse(b"{,}").is_err());
        assert!(parse(b"{\"z\":tru}").is_err());
        assert!(parse(b"{\"a\":\"x\"}\x00").is_err());
        assert_eq!(parse(b"\"\\ud83c\\udded\"").unwrap(), serde_json::json!("\u{1F1ED}"));
        assert_eq!(parse(b"\"\\ud800\"").unwrap(), invalid_value());
    }

    #[test]
    fn pretty_sorted_layout() {
        let v = serde_json::json!({"b": [], "a": {}, "c": ["x/y"], "d": {"z": 1, "y": null}});
        assert_eq!(
            to_pretty_sorted(&v).unwrap(),
            "{\n  \"a\" : {\n\n  },\n  \"b\" : [\n\n  ],\n  \"c\" : [\n    \"x\\/y\"\n  ],\n  \"d\" : {\n    \"y\" : null,\n    \"z\" : 1\n  }\n}"
        );
    }
}
