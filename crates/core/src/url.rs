//! The parts of Foundation's `URL(string:)` / `URLComponents` that the update and MFA code depend on.
//!
//! Foundation (macOS 14+) parses RFC 3986 and percent-encodes invalid characters in the path, query, fragment and
//! user info instead of failing; it fails on an invalid host or port. `URL.host` is percent-decoded and drops the
//! IPv6 brackets; a port that does not fit an `Int` is `nil` (the URL itself stays valid); the user info is
//! everything before the last `@`. Only what the callers read is modelled: scheme, user, password, host, port,
//! percent-encoded path, query and fragment.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundationUrl {
    /// `None` for a relative reference (`URL(string:)` accepts those too).
    pub scheme: Option<String>,
    /// The authority as written (`//…`), if any.
    pub authority: Option<String>,
    /// The authority without the `:port` part.
    pub authority_without_port: Option<String>,
    /// The string as given.
    pub original: String,
    /// The path as written.
    pub raw_path: String,
    pub user: Option<String>,
    pub password: Option<String>,
    /// `URL.host`: percent-decoded, without IPv6 brackets.
    pub host: Option<String>,
    pub port: Option<i64>,
    /// `URLComponents.percentEncodedPath`.
    pub percent_encoded_path: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
}

fn is_unreserved(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~')
}

fn is_sub_delim(c: u8) -> bool {
    matches!(c, b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=')
}

fn is_pct(b: &[u8], i: usize) -> bool {
    b[i] == b'%' && b.get(i + 1).is_some_and(u8::is_ascii_hexdigit) && b.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
}

/// A component (path, or with `query` a query / fragment) as Foundation stores it: unchanged if every character is
/// allowed there (valid `%XX` escapes included); otherwise every disallowed character and every `%` is
/// percent-encoded. The flag says whether it was re-encoded.
fn encode(part: &str, query: bool) -> (String, bool) {
    let b = part.as_bytes();
    let allowed = |i: usize, percent_ok: bool| {
        let c = b[i];
        is_unreserved(c)
            || is_sub_delim(c)
            || matches!(c, b':' | b'@' | b'/')
            || (query && c == b'?')
            || (percent_ok && c == b'%' && is_pct(b, i))
    };
    if (0..b.len()).all(|i| allowed(i, true)) {
        return (part.to_string(), false);
    }
    let mut out = String::with_capacity(part.len() + 8);
    for (i, &c) in b.iter().enumerate() {
        if allowed(i, false) {
            out.push(c as char);
        } else {
            out.push_str(&format!("%{c:02X}"));
        }
    }
    (out, true)
}

fn encode_path(path: &str) -> String {
    encode(path, false).0
}

impl FoundationUrl {
    /// `URL.absoluteString` of a URL made with `URL(string:)`. If a component had to be re-encoded, Foundation
    /// rebuilds the string (and writes the port as a number: `:0443` becomes `:443`).
    pub fn absolute_string(&self) -> String {
        let path_changed = self.percent_encoded_path != self.raw_path;
        let query = self.query.as_deref().map(|q| encode(q, true));
        let fragment = self.fragment.as_deref().map(|f| encode(f, true));
        let rebuilt = path_changed || query.as_ref().is_some_and(|q| q.1) || fragment.as_ref().is_some_and(|f| f.1);
        if !rebuilt {
            return self.original.clone();
        }
        let mut out = String::new();
        if let Some(scheme) = &self.scheme {
            out.push_str(scheme);
            out.push(':');
        }
        if let Some(authority) = &self.authority {
            out.push_str("//");
            match (&self.authority_without_port, self.port) {
                (Some(host), Some(port)) => {
                    out.push_str(host);
                    out.push_str(&format!(":{port}"));
                }
                (Some(host), None) => out.push_str(host),
                _ => out.push_str(authority),
            }
        }
        out.push_str(&self.percent_encoded_path);
        if let Some((q, _)) = query {
            out.push('?');
            out.push_str(&q);
        }
        if let Some((f, _)) = fragment {
            out.push('#');
            out.push_str(&f);
        }
        out
    }
}

fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
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

/// `URL(string:)` (and `URLComponents(url:resolvingAgainstBaseURL: false)`); `None` where Foundation gives `nil`.
pub fn parse(s: &str) -> Option<FoundationUrl> {
    // A scheme is the part before a `:` that comes before any `/`, `?`, `#`; a first segment with a `:` but no valid
    // scheme is invalid (RFC 3986 path-noscheme).
    let (scheme, mut rest) = match s.find([':', '/', '?', '#']) {
        Some(i) if s.as_bytes()[i] == b':' => {
            let scheme = &s[..i];
            let sb = scheme.as_bytes();
            if sb.is_empty()
                || !sb[0].is_ascii_alphabetic()
                || !sb.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
            {
                return None;
            }
            (Some(scheme.to_string()), &s[i + 1..])
        }
        _ => (None, s),
    };
    let (mut user, mut password, mut host, mut port, mut authority_text) = (None, None, None, None, None);
    let mut authority_without_port = None;
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        let authority = &after[..end];
        authority_text = Some(authority.to_string());
        rest = &after[end..];
        let hostport = match authority.rfind('@') {
            Some(at) => {
                let info = &authority[..at];
                match info.find(':') {
                    Some(c) => {
                        user = Some(info[..c].to_string());
                        password = Some(info[c + 1..].to_string());
                    }
                    None => user = Some(info.to_string()),
                }
                &authority[at + 1..]
            }
            None => authority,
        };
        let (h, p) = if hostport.starts_with('[') {
            let close = hostport.find(']')?;
            let after = &hostport[close + 1..];
            let p = match after {
                "" => None,
                _ => Some(after.strip_prefix(':')?),
            };
            (&hostport[1..close], p)
        } else {
            match hostport.rfind(':') {
                Some(c) => (&hostport[..c], Some(&hostport[c + 1..])),
                None => (hostport, None),
            }
        };
        // A non-ASCII host goes through IDNA (UTS #46, non-transitional), like Foundation; an ASCII host keeps its
        // case and is only percent-decoded.
        let idna_host;
        let h = if !hostport.starts_with('[') && !h.is_ascii() {
            idna_host = idna::domain_to_ascii(h).ok()?;
            idna_host.as_str()
        } else {
            h
        };
        if !hostport.starts_with('[') {
            let hb = h.as_bytes();
            for i in 0..hb.len() {
                let c = hb[i];
                if !(is_unreserved(c) || is_sub_delim(c) || (c == b'%' && is_pct(hb, i))) {
                    return None;
                }
            }
        }
        authority_without_port = Some(match p {
            Some(p) => authority[..authority.len() - p.len() - 1].to_string(),
            None => authority.to_string(),
        });
        if let Some(p) = p {
            if !p.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            port = if p.is_empty() { None } else { p.parse::<i64>().ok() };
        }
        host = Some(if hostport.starts_with('[') { h.to_string() } else { percent_decode(h)? });
    }
    let (before_fragment, fragment) = match rest.find('#') {
        Some(i) => (&rest[..i], Some(rest[i + 1..].to_string())),
        None => (rest, None),
    };
    let (path, query) = match before_fragment.find('?') {
        Some(i) => (&before_fragment[..i], Some(before_fragment[i + 1..].to_string())),
        None => (before_fragment, None),
    };
    Some(FoundationUrl {
        scheme,
        authority: authority_text,
        authority_without_port,
        original: s.to_string(),
        raw_path: path.to_string(),
        user,
        password,
        host,
        port,
        percent_encoded_path: encode_path(path),
        query,
        fragment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Results printed by Foundation on macOS 27.
    #[test]
    fn parses_like_foundation() {
        let u = parse("https://github%2Ecom/x").unwrap();
        assert_eq!(u.host.as_deref(), Some("github.com"));
        assert!(parse("https://git hub.com/x").is_none());
        assert!(parse("https://github.com:443:1/x").is_none());
        assert!(parse("https://sso.example.com:+443/x").is_none());
        assert!(parse(" https://github.com/x").is_none());
        assert!(parse("https://gith%zzub.com/").is_none());
        assert!(parse("https://[::1]x/").is_none());
        assert_eq!(parse("https://github.com/%zz").unwrap().percent_encoded_path, "/%25zz");
        assert_eq!(parse("https://github.com/a b/c").unwrap().percent_encoded_path, "/a%20b/c");
        assert_eq!(parse("https://github.com/x#a#b").unwrap().fragment.as_deref(), Some("a#b"));
        assert_eq!(parse("https://github.com/x?").unwrap().query.as_deref(), Some(""));
        assert_eq!(parse("https://GitHub.com:0443/x").unwrap().port, Some(443));
        assert_eq!(parse("https://github.com:/x").unwrap().port, None);
        assert_eq!(parse("https://github.com:99999999999999999999/x").unwrap().port, None);
        assert_eq!(parse("https://a@b@github.com/x").unwrap().user.as_deref(), Some("a@b"));
        let empty = parse("https://:@github.com/x").unwrap();
        assert_eq!((empty.user.as_deref(), empty.password.as_deref()), (Some(""), Some("")));
        assert_eq!(parse("https://[::1]:8443/x").unwrap().host.as_deref(), Some("::1"));
        assert_eq!(parse("https://[zz]/").unwrap().host.as_deref(), Some("zz"));
        assert_eq!(parse("https://git%41hub.com/").unwrap().host.as_deref(), Some("gitAhub.com"));
        assert_eq!(parse("https://github.com%3A443/x").unwrap().host.as_deref(), Some("github.com:443"));
        assert_eq!(parse("https://github.com").unwrap().percent_encoded_path, "");
        assert_eq!(parse("https:github.com/x").unwrap().host, None);
        // Foundation's IDNA handling of non-ASCII hosts.
        let host = |h: &str| parse(&format!("https://{h}/x")).map(|u| u.host.unwrap_or_default());
        for (h, expected) in [
            ("gi\u{ad}thub.com", Some("github.com")),
            ("gi\u{feff}thub.com", Some("github.com")),
            ("gi\u{200b}thub.com", Some("github.com")),
            ("git\u{200d}hub.com", None),
            ("ＧＩＴＨＵＢ.com", Some("github.com")),
            ("GİTHUB.com", Some("xn--github-qyd.com")),
            ("gitнub.com", Some("xn--gitub-fye.com")),
            ("github.com\u{3002}", Some("github.com.")),
            ("github\u{3002}com", Some("github.com")),
            ("Github.Com", Some("Github.Com")),
            ("gıthub.com", Some("xn--gthub-n4a.com")),
            ("github.cοm", Some("github.xn--cm-jbc")),
            ("git%C2%ADhub.com", Some("git\u{ad}hub.com")),
            ("github.com\u{301}", Some("github.xn--co-1ws")),
            ("ß.com", Some("xn--zca.com")),
            ("\u{1}github.com", None),
        ] {
            assert_eq!(host(h).as_deref(), expected, "{h:?}");
        }
        assert_eq!(parse("https-/github.com/x").unwrap().scheme, None);
        assert!(parse("a b:x").is_none());
        assert_eq!(
            parse("https://sso.example.com/a[b]?x[1]#y#z").unwrap().absolute_string(),
            "https://sso.example.com/a%5Bb%5D?x%5B1%5D#y%23z"
        );
        // Results printed by Foundation: a re-encoded component encodes `%` too, and the port is rewritten.
        for (s, abs) in [
            ("https://a.b/p%2E?x[", "https://a.b/p%2E?x%5B"),
            ("https://a.b/p%2E[?x%2E", "https://a.b/p%252E%5B?x%2E"),
            ("https://a.b:0443/p?x%2E#f[", "https://a.b:443/p?x%2E#f%5B"),
            ("https://a.b:0443/p", "https://a.b:0443/p"),
            ("https://A.B:0443/p[", "https://A.B:443/p%5B"),
            ("https://a.b/p#x%2E[", "https://a.b/p#x%252E%5B"),
            ("https://a.b/[?q#f", "https://a.b/%5B?q#f"),
            ("https://a.b/p?q%zz", "https://a.b/p?q%25zz"),
        ] {
            assert_eq!(parse(s).unwrap().absolute_string(), abs, "{s}");
        }
        assert_eq!(parse("https://github.com/[x]").unwrap().percent_encoded_path, "/%5Bx%5D");
    }
}
