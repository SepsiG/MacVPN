//! Base64 the way Swift's `Data(base64Encoded:)` / `base64EncodedString()` handle it (macOS 27 Foundation).
//!
//! Encoding is standard (padded, no line breaks). Decoding is more lenient than RFC 4648 in a few places, and the
//! port keeps exactly that behaviour (fitted to and checked against Foundation over every string up to 9
//! characters of `A`, `/`, `=` and by differential tests):
//! - an empty string is empty data;
//! - any number of `=` may follow a complete final group (`Ym9i=`, `AAAA====`);
//! - a final group may be `xx=x`: the middle byte is skipped (`AA=/` decodes to `00 3f`);
//! - a string of four or more `=` only decodes to one zero byte;
//! - non-zero trailing bits are ignored (`Ym9=` decodes like `Ym8=`);
//! - any other character (whitespace, line break, URL-safe alphabet) is an error.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// `data.base64EncodedString()`.
pub fn encode(data: &[u8]) -> String {
    STANDARD.encode(data)
}

fn value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn quad(q: &[u8]) -> Option<[u8; 3]> {
    let mut v = [0u32; 4];
    for (i, &c) in q.iter().enumerate() {
        v[i] = if c == b'=' { 0 } else { value(c)? };
    }
    let n = (v[0] << 18) | (v[1] << 12) | (v[2] << 6) | v[3];
    Some([(n >> 16) as u8, (n >> 8) as u8, n as u8])
}

/// `Data(base64Encoded: s)`.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.is_empty() {
        return Some(Vec::new());
    }
    if b.iter().all(|&c| c == b'=') {
        return if b.len() >= 4 { Some(vec![0]) } else { None };
    }
    let core_len = b.len() - b.iter().rev().take_while(|&&c| c == b'=').count();
    let pad = b.len() - core_len;
    let core = &b[..core_len];
    // `xx=x` final group: `=` only at the third position of the last group.
    let (body, tail) = if core.len() >= 4
        && core.len().is_multiple_of(4)
        && core[core.len() - 2] == b'='
        && !core[..core.len() - 2].contains(&b'=')
    {
        (&core[..core.len() - 4], Some(&core[core.len() - 4..]))
    } else {
        (core, None)
    };
    if body.contains(&b'=') {
        return None;
    }
    let rest = body.len() % 4;
    if rest == 1 {
        return None;
    }
    let full = body.len() - rest;
    let mut out = Vec::with_capacity(body.len() / 4 * 3 + 2);
    for q in body[..full].chunks(4) {
        out.extend_from_slice(&quad(q)?);
    }
    if let Some(t) = tail {
        if rest != 0 {
            return None;
        }
        let bytes = quad(t)?;
        out.push(bytes[0]);
        out.push(bytes[2]);
    } else if rest == 2 {
        if pad < 2 {
            return None;
        }
        out.push(quad(&[body[full], body[full + 1], b'A', b'A'])?[0]);
    } else if rest == 3 {
        if pad < 1 {
            return None;
        }
        let bytes = quad(&[body[full], body[full + 1], body[full + 2], b'A'])?;
        out.extend_from_slice(&bytes[..2]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Option<String> {
        decode(s).map(|d| d.iter().map(|b| format!("{b:02x}")).collect())
    }

    /// Values printed by Foundation on macOS 27.
    #[test]
    fn decodes_like_foundation() {
        let cases: &[(&str, Option<&str>)] = &[
            ("", Some("")),
            ("Ym9i", Some("626f62")),
            ("Ym9", None),
            ("Ym8=", Some("626f")),
            ("Ym9=", Some("626f")),
            ("Ym8", None),
            ("Ym==", Some("62")),
            ("YR==", Some("61")),
            ("Y===", None),
            ("====", Some("00")),
            ("=====", Some("00")),
            ("=", None),
            ("===", None),
            ("Ym8=Ym8=", None),
            ("Ym 9i", None),
            ("Ym9i\n", None),
            ("YQ=", None),
            ("YQ", None),
            ("Ym9i=", Some("626f62")),
            ("-_8=", None),
            ("Zm9vYmFy", Some("666f6f626172")),
            ("Zm9vYmF=", Some("666f6f6261")),
            ("AA=/", Some("003f")),
            ("A/=/", Some("033f")),
            ("A=AA", None),
            ("AAAA====", Some("000000")),
            ("AA=A====", Some("0000")),
            ("xx=x=", Some("c731")),
        ];
        for (s, expected) in cases {
            assert_eq!(hex(s).as_deref(), *expected, "{s:?}");
        }
        assert_eq!(encode(b"bob"), "Ym9i");
        assert_eq!(encode(b"bo"), "Ym8=");
    }
}
