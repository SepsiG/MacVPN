//! The answer of `mvpn respond openvpn <id>` (stdin: `kind=crv1|static|webauth-ack|cancel` and
//! `response=<value>`): the pure parser. The backend reads stdin and hands the answer to the bridge.

use zeroize::Zeroizing;

/// The longest input that can still be valid (two lines of 300 bytes and their line ends).
pub const STDIN_MAX: u64 = 604;

/// The localized message of a [`parse`] rejection.
pub fn message(key: &'static str) -> String {
    crate::shared::l10n::tr(key, &[])
}

/// The parsed answer; `Err(key)` is the message of the rejection.
pub fn parse(data: &[u8]) -> Result<(String, Zeroizing<Vec<u8>>), &'static str> {
    const INVALID: &str = "Invalid response";
    if data.len() as u64 > STDIN_MAX {
        return Err(INVALID);
    }
    let mut kind: Option<Vec<u8>> = None;
    let mut response = Zeroizing::new(Vec::new());
    // `while IFS= read -r line || [ -n "$line" ]`: every line, a final one without line end too; NULs dropped.
    let body = data.strip_suffix(b"\n").unwrap_or(data);
    if !data.is_empty() {
        for (n, raw) in body.split(|&b| b == b'\n').enumerate() {
            let line: Zeroizing<Vec<u8>> = Zeroizing::new(raw.iter().copied().filter(|&b| b != 0).collect());
            if n >= 2 || line.len() > 300 {
                return Err(INVALID);
            }
            if let Some(k) = line.strip_prefix(b"kind=") {
                kind = Some(k.to_vec());
            } else if let Some(r) = line.strip_prefix(b"response=") {
                response = Zeroizing::new(r.to_vec());
            } else {
                return Err(INVALID);
            }
        }
    }
    let kind = String::from_utf8(kind.unwrap_or_default()).unwrap_or_default();
    match kind.as_str() {
        "crv1" | "static" => {}
        "webauth-ack" | "cancel" => response = Zeroizing::new(Vec::new()),
        _ => return Err("Invalid response kind"),
    }
    if response.len() > 256 {
        return Err("The response is too long (256 bytes at most)");
    }
    if response.iter().any(|&b| b < 0x20 || b == 0x7F) {
        return Err("The response must not contain control characters");
    }
    Ok((kind, response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_answers() {
        let (k, r) = parse(b"kind=crv1\nresponse=123456\n").unwrap();
        assert_eq!((k.as_str(), r.as_slice()), ("crv1", &b"123456"[..]));
        let (k, r) = parse(b"kind=webauth-ack\nresponse=ignored\n").unwrap();
        assert_eq!((k.as_str(), r.as_slice()), ("webauth-ack", &b""[..]));
        assert!(parse(b"response=1\nkind=static").is_ok());
        assert!(parse(b"kind=cancel\n").is_ok());
    }

    #[test]
    fn rejected_answers() {
        let long = format!("kind=crv1\nresponse={}\n", "x".repeat(257));
        for bad in [
            &b"kind=password\nresponse=x\n"[..],
            b"kind=hold\nresponse=release\n",
            b"kind=raw\nresponse=signal SIGTERM\n",
            b"kind=CRV1\nresponse=1\n",
            b"kind=crv1\nresponse=12\x013\n",
            b"kind=crv1\nresponse=12\x7f3\n",
            long.as_bytes(),
            b"kind=crv1\nresponse=1\nextra=1\n",
            b"kind=crv1\nresponse=1\nkind=crv1\n",
            b"response=1\n",
            b"",
            b"kind=crv1 \nresponse=1\n",
            b"kind=crv1\n\n",
        ] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }
}
