//! **Trust This CA in Windows…** (WinVPN 2c Task 12), the pure part: the first certificate of a PEM text (an SSTP
//! config's `<ca>` block, or a PEM file the user picked for IKEv2) read for the confirmation an administrator sees
//! before the computer trusts it: the subject, the validity and the SHA-256 fingerprint, plus the SHA-1 thumbprint
//! Windows' certificate stores are searched by. Only a CA certificate (basicConstraints `cA = TRUE`) that is valid
//! now is accepted.
//!
//! The PEM is untrusted text (a team catalog or an imported file can carry it): the DER reader is strict and
//! bounded (definite lengths of at most four bytes, every element inside its parent, nothing after the
//! certificate), and every text taken from it is cut and freed of control characters; invisible format characters
//! (bidi controls, zero-width characters) are shown escaped. Nothing here decides trust: Windows checks the
//! certificate itself when the elevated step (`win::admin_steps`) adds it and whenever a VPN uses it.

use macvpn_core::l10n;
use macvpn_platform_api::CaSummary;

/// A CA certificate ready to be trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaCert {
    /// The certificate (DER), exactly as the elevated step adds it.
    pub der: Vec<u8>,
    pub summary: CaSummary,
    /// The SHA-1 thumbprint (Windows' `CERT_SHA1_HASH_PROP_ID`): the key the store check searches by. Not a
    /// security decision: a match only says the store holds this exact certificate.
    pub sha1: [u8; 20],
}

/// The largest PEM text read (the editors' limit for a config).
const MAX_PEM_BYTES: usize = 1_048_576;
/// The largest certificate accepted (real CA certificates are a few kilobytes).
const MAX_DER_BYTES: usize = 64 * 1024;
/// The subject is cut at this many characters.
const MAX_SUBJECT_CHARACTERS: usize = 512;

const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";

/// The warning of the confirmation. WinVPN adds the CA for server and client authentication only (M-1 of the 2.0.0
/// security review): never for code signing.
pub fn warning() -> String {
    l10n::tr(
        "Every program on this PC will trust server and client certificates from this CA (not software it signs).",
        &[],
    )
}

fn no_certificate() -> String {
    l10n::tr("The text contains no readable certificate.", &[])
}

fn not_a_ca() -> String {
    l10n::tr("This certificate is not a CA certificate.", &[])
}

fn not_valid_now() -> String {
    l10n::tr("This CA certificate has expired or is not valid yet.", &[])
}

/// The first certificate of `pem` as a CA certificate valid at `now` (Unix seconds), or why it cannot be trusted.
pub fn read(pem: &str, now: i64) -> Result<CaCert, String> {
    if pem.len() > MAX_PEM_BYTES {
        return Err(no_certificate());
    }
    let der = first_der(pem).ok_or_else(no_certificate)?;
    read_der(&der, now)
}

/// The certificate `der` as a CA certificate valid at `now` (Unix seconds), or why it cannot be trusted: the checks
/// of [`read`], again in the elevated step on the file WinVPN staged.
pub fn read_der(der: &[u8], now: i64) -> Result<CaCert, String> {
    if der.is_empty() || der.len() > MAX_DER_BYTES {
        return Err(no_certificate());
    }
    let der = der.to_vec();
    let cert = parse(&der).ok_or_else(no_certificate)?;
    if !cert.ca {
        return Err(not_a_ca());
    }
    if now < cert.not_before || now > cert.not_after {
        return Err(not_valid_now());
    }
    let sha256 = macvpn_core::update::sha256_hex(&der)
        .as_bytes()
        .chunks(2)
        .map(|pair| String::from_utf8_lossy(pair).to_uppercase())
        .collect::<Vec<_>>()
        .join(":");
    let sha1 = sha1(&der);
    Ok(CaCert {
        summary: CaSummary { subject: cert.subject, not_before: cert.not_before, not_after: cert.not_after, sha256 },
        sha1,
        der,
    })
}

/// The DER of the first `BEGIN CERTIFICATE` … `END CERTIFICATE` block (whitespace in the base64 body ignored).
fn first_der(pem: &str) -> Option<Vec<u8>> {
    let start = pem.find(BEGIN)? + BEGIN.len();
    let end = start + pem[start..].find(END)?;
    let body: String = pem[start..end].chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if body.is_empty() || body.len() > MAX_DER_BYTES * 4 / 3 + 4 {
        return None;
    }
    macvpn_core::swift_base64::decode(&body).filter(|d| !d.is_empty() && d.len() <= MAX_DER_BYTES)
}

// MARK: - DER

/// A strict DER reader over one level of elements.
struct Der<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(data: &'a [u8]) -> Self {
        Der { data, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// The next element's tag and value. Low tag numbers only; definite lengths in the shortest form.
    fn read(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = *self.data.get(self.pos)?;
        if tag & 0x1F == 0x1F {
            return None;
        }
        let first = *self.data.get(self.pos + 1)?;
        let (len, header) = if first < 0x80 {
            (usize::from(first), 2)
        } else {
            let n = usize::from(first & 0x7F);
            if n == 0 || n > 4 {
                return None;
            }
            let mut len = 0usize;
            for i in 0..n {
                len = len.checked_mul(256)?.checked_add(usize::from(*self.data.get(self.pos + 2 + i)?))?;
            }
            if len < 0x80 || (n > 1 && len < 1 << (8 * (n - 1))) {
                return None;
            }
            (len, 2 + n)
        };
        let start = self.pos.checked_add(header)?;
        let end = start.checked_add(len)?;
        let value = self.data.get(start..end)?;
        self.pos = end;
        Some((tag, value))
    }

    fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        let (t, value) = self.read()?;
        (t == tag).then_some(value)
    }
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const BOOLEAN: u8 = 0x01;
const OID: u8 = 0x06;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
/// `[0] EXPLICIT Version` and `[3] EXPLICIT Extensions` of a `TBSCertificate`.
const VERSION_TAG: u8 = 0xA0;
const EXTENSIONS_TAG: u8 = 0xA3;
/// id-ce-basicConstraints (2.5.29.19).
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];

struct Parsed {
    subject: String,
    not_before: i64,
    not_after: i64,
    ca: bool,
}

/// RFC 5280 `Certificate`: the parts the confirmation shows and the CA flag.
fn parse(der: &[u8]) -> Option<Parsed> {
    let mut outer = Der::new(der);
    let certificate = outer.expect(SEQUENCE)?;
    if !outer.is_empty() {
        return None;
    }
    let mut c = Der::new(certificate);
    let tbs = c.expect(SEQUENCE)?;
    c.expect(SEQUENCE)?; // signatureAlgorithm
    c.expect(BIT_STRING)?; // signatureValue
    if !c.is_empty() {
        return None;
    }
    let mut t = Der::new(tbs);
    let mut version = 0u8;
    if t.peek_tag() == Some(VERSION_TAG) {
        let mut v = Der::new(t.expect(VERSION_TAG)?);
        let n = v.expect(INTEGER)?;
        version = match n {
            [n] if *n <= 2 => *n,
            _ => return None,
        };
    }
    t.expect(INTEGER)?; // serialNumber
    t.expect(SEQUENCE)?; // signature
    t.expect(SEQUENCE)?; // issuer
    let mut validity = Der::new(t.expect(SEQUENCE)?);
    let not_before = time(validity.read()?)?;
    let not_after = time(validity.read()?)?;
    if !validity.is_empty() {
        return None;
    }
    let subject = name(t.expect(SEQUENCE)?)?;
    t.expect(SEQUENCE)?; // subjectPublicKeyInfo
    let mut ca = false;
    while !t.is_empty() {
        let (tag, value) = t.read()?;
        if tag == EXTENSIONS_TAG {
            if version != 2 {
                return None;
            }
            ca = basic_constraints_ca(value)?;
        }
    }
    Some(Parsed { subject, not_before, not_after, ca })
}

/// `cA` of the basicConstraints extension (`false` when it is absent).
fn basic_constraints_ca(extensions: &[u8]) -> Option<bool> {
    let mut wrapper = Der::new(extensions);
    let mut list = Der::new(wrapper.expect(SEQUENCE)?);
    let mut ca = false;
    while !list.is_empty() {
        let mut ext = Der::new(list.expect(SEQUENCE)?);
        let oid = ext.expect(OID)?;
        if ext.peek_tag() == Some(BOOLEAN) {
            ext.expect(BOOLEAN)?; // critical
        }
        let value = ext.expect(OCTET_STRING)?;
        if oid == BASIC_CONSTRAINTS {
            let mut bc = Der::new(value);
            let mut seq = Der::new(bc.expect(SEQUENCE)?);
            if seq.peek_tag() == Some(BOOLEAN) {
                ca = seq.expect(BOOLEAN)? == [0xFF];
            }
        }
    }
    Some(ca)
}

/// `UTCTime` (`YYMMDDHHMMSSZ`, years 1950–2049) or `GeneralizedTime` (`YYYYMMDDHHMMSSZ`) as Unix seconds.
fn time((tag, value): (u8, &[u8])) -> Option<i64> {
    let digits = |s: &[u8]| -> Option<i64> {
        s.iter().try_fold(0i64, |n, &b| b.is_ascii_digit().then(|| n * 10 + i64::from(b - b'0')))
    };
    let (year, rest) = match (tag, value.len()) {
        (UTC_TIME, 13) => {
            let yy = digits(&value[..2])?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &value[2..])
        }
        (GENERALIZED_TIME, 15) => (digits(&value[..4])?, &value[4..]),
        _ => return None,
    };
    if rest.last() != Some(&b'Z') {
        return None;
    }
    let field = |i: usize| digits(&rest[i..i + 2]);
    let (month, day, hour, minute, second) = (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A `Name` as Windows shows it: the most specific part first (`CN=…, OU=…, O=…, C=…`).
fn name(value: &[u8]) -> Option<String> {
    let mut parts = Vec::new();
    let mut rdns = Der::new(value);
    while !rdns.is_empty() {
        let mut set = Der::new(rdns.expect(SET)?);
        while !set.is_empty() {
            let mut atv = Der::new(set.expect(SEQUENCE)?);
            let oid = atv.expect(OID)?;
            let (tag, text) = atv.read()?;
            parts.push(format!("{}={}", attribute_name(oid)?, string_value(tag, text)));
        }
    }
    parts.reverse();
    let joined = parts.join(", ");
    let mut subject: String = joined.chars().take(MAX_SUBJECT_CHARACTERS).collect();
    if joined.chars().count() > MAX_SUBJECT_CHARACTERS {
        subject.push('…');
    }
    Some(subject)
}

/// The short names Windows' certificate dialog uses; any other attribute as its dotted OID.
fn attribute_name(oid: &[u8]) -> Option<String> {
    Some(match oid {
        [0x55, 0x04, 0x03] => "CN".into(),
        [0x55, 0x04, 0x05] => "SERIALNUMBER".into(),
        [0x55, 0x04, 0x06] => "C".into(),
        [0x55, 0x04, 0x07] => "L".into(),
        [0x55, 0x04, 0x08] => "S".into(),
        [0x55, 0x04, 0x0A] => "O".into(),
        [0x55, 0x04, 0x0B] => "OU".into(),
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01] => "E".into(),
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19] => "DC".into(),
        _ => dotted(oid)?,
    })
}

fn dotted(oid: &[u8]) -> Option<String> {
    let (&first, rest) = oid.split_first()?;
    let mut arcs = vec![u64::from(first / 40).min(2), u64::from(first) - u64::from(first / 40).min(2) * 40];
    let mut n = 0u64;
    for &b in rest {
        n = n.checked_mul(128)? | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            arcs.push(n);
            n = 0;
        }
    }
    (n == 0 && oid.len() <= 32).then(|| arcs.iter().map(u64::to_string).collect::<Vec<_>>().join("."))
}

/// A directory string as text: UTF-8, the single-byte strings as Latin-1, BMP (UTF-16BE) and Universal (UTF-32BE)
/// strings; anything else as `#<hex>`. Control characters become `?`, invisible ones `\\u{…}` ([`shown`]).
fn string_value(tag: u8, bytes: &[u8]) -> String {
    let text = match tag {
        0x0C => String::from_utf8_lossy(bytes).into_owned(),
        0x13 | 0x14 | 0x16 => bytes.iter().map(|&b| char::from(b)).collect(),
        0x1E => char::decode_utf16(bytes.chunks(2).map(|p| u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)])))
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect(),
        0x1C => bytes
            .chunks(4)
            .map(|q| {
                let mut b = [0u8; 4];
                b[..q.len()].copy_from_slice(q);
                char::from_u32(u32::from_be_bytes(b)).unwrap_or(char::REPLACEMENT_CHARACTER)
            })
            .collect(),
        _ => format!("#{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()),
    };
    shown(&text)
}

/// The text as the confirmation may show it: a control character becomes `?`; an invisible character that changes
/// how the text around it reads ([`is_invisible`]) becomes `\u{…}`, so a subject cannot pose as another name.
fn shown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() {
            out.push('?');
        } else if is_invisible(c) {
            out.push_str(&format!("\\u{{{:X}}}", u32::from(c)));
        } else {
            out.push(c);
        }
    }
    out
}

/// Unicode's format characters (general category Cf, Unicode 16: bidi embeddings, overrides and isolates, the
/// zero-width space, joiners and marks, the BOM, the soft hyphen, tag characters, …), the line and paragraph
/// separators (Zl, Zp) and the Hangul fillers that render as blanks.
fn is_invisible(c: char) -> bool {
    matches!(
        u32::from(c),
        0xAD | 0x600..=0x605
            | 0x61C
            | 0x6DD
            | 0x70F
            | 0x890..=0x891
            | 0x8E2
            | 0x115F..=0x1160
            | 0x180E
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0x3164
            | 0xFEFF
            | 0xFFA0
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    )
}

// MARK: - SHA-1

/// SHA-1 (FIPS 180-4) of `data`: only the thumbprint Windows' certificate stores are searched by (no crate in the
/// workspace has it, and the store lookup is not a security decision).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let mut message = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    let (blocks, _) = message.as_chunks::<64>();
    for block in blocks {
        let mut w = [0u32; 80];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *chunk = word.to_be_bytes();
    }
    out
}
