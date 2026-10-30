//! The framed stdin of `up` and `validate`: the config, then the secrets (root layer 8).
//!
//! ```text
//! config <len>\n          <len>: ASCII decimal, 1–7 digits, no sign, no leading zero, 1 ≤ len ≤ SRC_MAX (1 MB)
//! <exactly len bytes>     the config: UTF-8, no NUL byte (it may hold private keys: zeroed on drop)
//! username=<v>\n          then only complete lines of these keys, each at most once, in any order
//! password=<v>\n          (`validate` takes none: anything after the body is refused)
//! psk=<v>\n
//! keypass=<v>\n
//! otp=<v>\n               the MFA code, only for masking (it is already part of the password)
//! challenge=packed\n      OpenVPN static challenge: the password is already in SCRV1 / concat form
//! x509=<base64>\n          root layer 12, strongSwan: an imported client certificate (DER) …
//! private=<base64>\n       … and its private key (one PEM block), or
//! pkcs12=<base64>\n        … a PKCS#12 file (see `macos::strongswan::stage_client_cert`)
//! ```
//!
//! Errors (see [`FrameError::message`]): no `config` header at the start → `Config not provided`; a malformed
//! header, a line after the body that is not one of the keys above, an unterminated last line, a non-UTF-8
//! config → `Invalid input`; `len` above 1 MB → `The config is too large (1 MB at most)`, refused before the
//! body is read; fewer than `len` bytes → `The config is incomplete`; a NUL byte → `The config must not contain
//! NUL bytes`. A `len` shorter than the real config leaves config lines where only secret lines may stand, so a
//! length mismatch ends as `Invalid input` (or `The config is incomplete` when `len` is longer than the stream).
//! The whole stdin is at most `SRC_MAX + SECRETS_MAX + 16` bytes.
//!
//! The root layer opens no user file: the config exists only in this process's memory and in the copy written
//! into the root-only run directory. The secrets stay in memory (zeroed on drop): never in an argument list
//! (except the documented sstpc `--password`), never in an environment, never in the log (every non-empty one is
//! masked).

use crate::shared::l10n::tr;
use crate::shared::limits::{SECRETS_MAX, SRC_MAX, STDIN_MAX};
use crate::shared::mask::Masker;
use std::io::Read;
use zeroize::Zeroizing;

/// `config ` + 7 digits + `\n`.
const HEADER_MAX: usize = 15;
// `read_framed` reads at most the header, the body and `SECRETS_MAX + 1` more bytes.
const _: () = assert!(HEADER_MAX as u64 + SRC_MAX + SECRETS_MAX + 1 == STDIN_MAX);

#[derive(Default)]
pub struct Secrets {
    pub user: Zeroizing<Vec<u8>>,
    pub pass: Zeroizing<Vec<u8>>,
    pub psk: Zeroizing<Vec<u8>>,
    pub keypass: Zeroizing<Vec<u8>>,
    /// The MFA code: only for masking (it is already part of the password).
    pub otp: Zeroizing<Vec<u8>>,
    /// OpenVPN static challenge: the password is already in SCRV1 / concat form.
    pub packed: bool,
    /// Root layer 12: an imported client certificate, still base64 (`x509=`, `private=`, `pkcs12=`).
    pub x509: Zeroizing<Vec<u8>>,
    pub private: Zeroizing<Vec<u8>>,
    pub pkcs12: Zeroizing<Vec<u8>>,
}

/// Why a framed stdin was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// No `config` header at the start (nothing on stdin, a terminal, or anything else first).
    Missing,
    /// A malformed header or secrets section (also a length mismatch), or a non-UTF-8 config.
    Invalid,
    /// `len` above `SRC_MAX`.
    TooLarge,
    /// Fewer than `len` bytes followed the header.
    Incomplete,
    /// A NUL byte in the config.
    Nul,
}

impl FrameError {
    /// The localized message.
    pub fn message(self) -> String {
        match self {
            FrameError::Missing => tr("Config not provided", &[]),
            FrameError::Invalid => tr("Invalid input", &[]),
            FrameError::TooLarge => tr("The config is too large (1 MB at most)", &[]),
            FrameError::Incomplete => tr("The config is incomplete", &[]),
            FrameError::Nul => tr("The config must not contain NUL bytes", &[]),
        }
    }
}

/// The config and the secrets of a framed stdin.
pub type Framed = (Zeroizing<Vec<u8>>, Secrets);

/// The header line (`data` starts with it): the config length and the header's own length.
fn parse_header(data: &[u8]) -> Result<(usize, usize), FrameError> {
    let Some(after) = data.strip_prefix(b"config") else { return Err(FrameError::Missing) };
    let Some(after) = after.strip_prefix(b" ") else { return Err(FrameError::Invalid) };
    let n = after.iter().take(8).take_while(|b| b.is_ascii_digit()).count();
    let digits = &after[..n];
    if digits.is_empty() || digits.len() > 7 || digits[0] == b'0' || after.get(n) != Some(&b'\n') {
        return Err(FrameError::Invalid);
    }
    let len = digits.iter().fold(0usize, |v, d| v * 10 + usize::from(d - b'0'));
    if len as u64 > SRC_MAX {
        return Err(FrameError::TooLarge);
    }
    Ok((len, "config ".len() + n + 1))
}

/// The pure parser of a whole framed stdin; `secrets`: whether secret lines may follow the config.
pub fn parse_framed(data: &[u8], secrets: bool) -> Result<Framed, FrameError> {
    let (len, header) = parse_header(data)?;
    let rest = &data[header..];
    if rest.len() < len {
        return Err(FrameError::Incomplete);
    }
    let (body, tail) = rest.split_at(len);
    if body.contains(&0) {
        return Err(FrameError::Nul);
    }
    if std::str::from_utf8(body).is_err() || tail.len() as u64 > SECRETS_MAX || (!secrets && !tail.is_empty()) {
        return Err(FrameError::Invalid);
    }
    let s = Secrets::parse_lines(tail).ok_or(FrameError::Invalid)?;
    Ok((Zeroizing::new(body.to_vec()), s))
}

/// Reads the raw frame from `r`: the header first (a byte at a time, so a refused header consumes nothing more),
/// then, into one buffer allocated at its final size, exactly the announced body and the bounded secrets section.
fn read_frame_bytes(r: &mut impl Read) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    let mut header = [0u8; HEADER_MAX];
    let mut n = 0;
    while n < HEADER_MAX && (n == 0 || header[n - 1] != b'\n') {
        match r.read(&mut header[n..=n]) {
            Ok(1) => n += 1,
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let (len, _) = parse_header(&header[..n])?;
    let rest = len as u64 + SECRETS_MAX + 1;
    let mut data = Zeroizing::new(Vec::with_capacity(HEADER_MAX + rest as usize));
    data.extend_from_slice(&header[..n]);
    // At most `rest` bytes: they fit the spare capacity, so the buffer never grows (and is never copied).
    let _ = r.by_ref().take(rest).read_to_end(&mut data);
    Ok(data)
}

/// Reads a framed stdin from `r` ([`read_frame_bytes`]); then [`parse_framed`] decides. The macOS backend reads
/// fd 0 directly (`macos::read_framed_stdin`).
pub fn read_framed(r: &mut impl Read, secrets: bool) -> Result<Framed, FrameError> {
    parse_framed(&read_frame_bytes(r)?, secrets)
}

impl Secrets {
    /// The secrets section: complete lines of the known keys, each at most once; `None` for anything else.
    fn parse_lines(tail: &[u8]) -> Option<Secrets> {
        let mut s = Secrets::default();
        if tail.is_empty() {
            return Some(s);
        }
        let body = tail.strip_suffix(b"\n")?;
        let mut seen = [false; 9];
        for line in body.split(|&b| b == b'\n') {
            if line.contains(&0) {
                return None;
            }
            let value = |prefix: &[u8]| line.strip_prefix(prefix).map(|v| Zeroizing::new(v.to_vec()));
            let slot = if let Some(v) = value(b"username=") {
                s.user = v;
                0
            } else if let Some(v) = value(b"password=") {
                s.pass = v;
                1
            } else if let Some(v) = value(b"psk=") {
                s.psk = v;
                2
            } else if let Some(v) = value(b"keypass=") {
                s.keypass = v;
                3
            } else if let Some(v) = value(b"otp=") {
                s.otp = v;
                4
            } else if line == b"challenge=packed" {
                s.packed = true;
                5
            } else if let Some(v) = value(b"x509=") {
                s.x509 = v;
                6
            } else if let Some(v) = value(b"private=") {
                s.private = v;
                7
            } else {
                s.pkcs12 = value(b"pkcs12=")?;
                8
            };
            if std::mem::replace(&mut seen[slot], true) {
                return None;
            }
        }
        Some(s)
    }

    /// The bash `mask`: password, PSK, key password and code.
    pub fn masker(&self) -> Masker {
        Masker::new([self.pass.as_slice(), self.psk.as_slice(), self.keypass.as_slice(), self.otp.as_slice()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(config: &[u8], rest: &[u8]) -> Vec<u8> {
        let mut v = format!("config {}\n", config.len()).into_bytes();
        v.extend_from_slice(config);
        v.extend_from_slice(rest);
        v
    }

    fn err(data: &[u8], secrets: bool) -> FrameError {
        match parse_framed(data, secrets) {
            Ok(_) => panic!("accepted: {:?}", String::from_utf8_lossy(data)),
            Err(e) => e,
        }
    }

    #[test]
    fn parses_the_config_and_every_secret_line() {
        let data = frame(
            b"client\nremote a 1\n",
            b"username=bob\npassword=a=b\npsk=k\nkeypass=kp\notp=123\nchallenge=packed\n",
        );
        let (config, s) = parse_framed(&data, true).unwrap();
        assert_eq!(config.as_slice(), b"client\nremote a 1\n");
        assert_eq!(s.user.as_slice(), b"bob");
        assert_eq!(s.pass.as_slice(), b"a=b");
        assert_eq!(s.psk.as_slice(), b"k");
        assert_eq!(s.keypass.as_slice(), b"kp");
        assert_eq!(s.otp.as_slice(), b"123");
        assert!(s.packed);
        let (config, s) = parse_framed(&frame(b"x", b""), true).unwrap();
        assert_eq!(config.as_slice(), b"x");
        assert!(s.user.is_empty() && s.pass.is_empty() && !s.packed);
        let (_, s) = parse_framed(&frame(b"x", b"password=\n"), true).unwrap();
        assert!(s.pass.is_empty());
    }

    #[test]
    fn the_client_certificate_lines_of_root_layer_12() {
        let (_, s) = parse_framed(&frame(b"x", b"keypass=kp\nx509=QUJD\nprivate=REVG\n"), true).unwrap();
        assert_eq!(
            (s.x509.as_slice(), s.private.as_slice(), s.pkcs12.as_slice()),
            (&b"QUJD"[..], &b"REVG"[..], &b""[..])
        );
        let (_, s) = parse_framed(&frame(b"x", b"pkcs12=UDEy\n"), true).unwrap();
        assert_eq!(s.pkcs12.as_slice(), b"UDEy");
        // Each at most once; never after `validate`'s config.
        assert_eq!(err(&frame(b"x", b"x509=QQ==\nx509=QQ==\n"), true), FrameError::Invalid);
        assert_eq!(err(&frame(b"x", b"pkcs12=QQ==\n"), false), FrameError::Invalid);
        assert_eq!(err(&frame(b"x", b"x509\n"), true), FrameError::Invalid);
    }

    #[test]
    fn secret_like_lines_inside_the_config_stay_config() {
        let config = b"server=a.example\nuser=bob\npassword=FromConfig\nusername=eve\n";
        let (c, s) = parse_framed(&frame(config, b"password=Real\n"), true).unwrap();
        assert_eq!(c.as_slice(), config);
        assert_eq!(s.pass.as_slice(), b"Real");
        assert!(s.user.is_empty());
        // Without a body terminator too: the length alone decides.
        let (c, s) = parse_framed(&frame(b"password=x", b""), true).unwrap();
        assert_eq!(c.as_slice(), b"password=x");
        assert!(s.pass.is_empty());
    }

    #[test]
    fn a_missing_header_is_config_not_provided() {
        assert_eq!(err(b"", true), FrameError::Missing);
        assert_eq!(err(b"username=bob\npassword=x\n", true), FrameError::Missing);
        assert_eq!(err(b"username=bob\nconfig 1\nx", true), FrameError::Missing);
        assert_eq!(err(b"garbage config 1\nx", true), FrameError::Missing);
        assert_eq!(err(b"\nconfig 1\nx", true), FrameError::Missing);
    }

    #[test]
    fn a_bad_header_is_invalid_input() {
        for bad in [
            &b"config -1\nx"[..],
            b"config +1\nx",
            b"config 01\nx",
            b"config 0\n",
            b"config 1x\nx",
            b"config 1",
            b"config",
            b"config\n1\nx",
            b"config  1\nx",
            b"config 1 \nx",
            b"config 1\r\nx",
            b"Config 1\nx",
            b"configx 1\nx",
            b"config 12345678\n",
            b"config 99999999999999999999\n",
            b"config \n",
        ] {
            let e = err(bad, true);
            // `Config 1` does not start with the header word at all.
            if bad.starts_with(b"Config") {
                assert_eq!(e, FrameError::Missing, "{:?}", String::from_utf8_lossy(bad));
            } else {
                assert_eq!(e, FrameError::Invalid, "{:?}", String::from_utf8_lossy(bad));
            }
        }
    }

    #[test]
    fn the_size_limit_is_checked_on_the_header() {
        assert_eq!(err(b"config 1048577\n", true), FrameError::TooLarge);
        assert_eq!(err(b"config 9999999\n", true), FrameError::TooLarge);
        let max = vec![b'#'; SRC_MAX as usize];
        assert!(parse_framed(&frame(&max, b""), true).is_ok());
    }

    #[test]
    fn a_short_body_is_incomplete() {
        let mut data = b"config 100\n".to_vec();
        data.extend_from_slice(&[b'#'; 50]);
        assert_eq!(err(&data, true), FrameError::Incomplete);
        assert_eq!(err(b"config 1\n", true), FrameError::Incomplete);
        // A length longer than everything sent.
        let mut data = b"config 30\nclient\n".to_vec();
        data.extend_from_slice(b"password=x\n");
        assert_eq!(err(&data, true), FrameError::Incomplete);
    }

    #[test]
    fn a_nul_byte_in_the_config_is_refused() {
        assert_eq!(err(&frame(b"client\n\0remote a\n", b""), true), FrameError::Nul);
        assert_eq!(err(&frame(b"\0", b"password=x\n"), true), FrameError::Nul);
    }

    #[test]
    fn the_config_must_be_utf8() {
        assert_eq!(err(&frame(b"client \xff\n", b""), true), FrameError::Invalid);
        assert!(parse_framed(&frame("szerver = árvíztűrő\n".as_bytes(), b""), true).is_ok());
    }

    #[test]
    fn a_length_mismatch_is_caught_by_the_strict_secret_lines() {
        let config = b"client\ndev tun\nremote vpn.example.com 1194\n";
        // Shorter: the config's tail arrives as "secret lines".
        let mut data = format!("config {}\n", config.len() - 10).into_bytes();
        data.extend_from_slice(config);
        data.extend_from_slice(b"password=x\n");
        assert_eq!(err(&data, true), FrameError::Invalid);
        // Longer (but within the stream): the body eats part of a secret line.
        let mut data = format!("config {}\n", config.len() + 5).into_bytes();
        data.extend_from_slice(config);
        data.extend_from_slice(b"username=bob\npassword=x\n");
        assert_eq!(err(&data, true), FrameError::Invalid);
    }

    #[test]
    fn the_secret_lines_are_strict() {
        for rest in [
            &b"x=y\n"[..],
            b"password=unterminated",
            b"username=bob\npassword",
            b"\n",
            b"username=bob\n\n",
            b"Password=x\n",
            b" password=x\n",
            b"challenge=packed2\n",
            b"challenge=\n",
            b"password=a\0b\n",
            b"config 1\nx\n",
            b"password=1\npassword=2\n",
        ] {
            assert_eq!(err(&frame(b"x", rest), true), FrameError::Invalid, "{:?}", String::from_utf8_lossy(rest));
        }
        let long = format!("password={}\n", "x".repeat(SECRETS_MAX as usize));
        assert_eq!(err(&frame(b"x", long.as_bytes()), true), FrameError::Invalid);
    }

    #[test]
    fn validate_takes_no_secret_lines() {
        assert!(parse_framed(&frame(b"x\n", b""), false).is_ok());
        assert_eq!(err(&frame(b"x\n", b"password=x\n"), false), FrameError::Invalid);
        assert_eq!(err(&frame(b"x\n", b"\n"), false), FrameError::Invalid);
    }

    #[test]
    fn reading_refuses_an_oversize_header_before_the_body() {
        // The reader would hand out the body forever: only the header may be consumed.
        let mut src = std::io::Cursor::new(b"config 1048577\n".to_vec()).chain(std::io::repeat(b'#'));
        assert_eq!(read_framed(&mut src, true).err(), Some(FrameError::TooLarge));
        let mut rest = [0u8; 4];
        src.read_exact(&mut rest).unwrap();
        assert_eq!(&rest, b"####");
    }

    #[test]
    fn the_read_buffer_is_allocated_once() {
        // The config is never copied into a grown (and then freed, not zeroed) buffer.
        let config = vec![b'#'; 200_000];
        let mut data = frame(&config, b"username=bob\npassword=pw\n");
        let raw = read_frame_bytes(&mut data.as_slice()).unwrap();
        assert_eq!(raw.as_slice(), data.as_slice());
        assert_eq!(raw.capacity(), HEADER_MAX + config.len() + SECRETS_MAX as usize + 1);
        data.extend(std::iter::repeat_n(b'x', SECRETS_MAX as usize * 2));
        let raw = read_frame_bytes(&mut data.as_slice()).unwrap();
        assert_eq!(raw.capacity(), HEADER_MAX + config.len() + SECRETS_MAX as usize + 1);
    }

    #[test]
    fn reading_matches_the_pure_parser() {
        let ok = frame(b"client\n", b"username=bob\npassword=pw\n");
        let (c, s) = read_framed(&mut ok.as_slice(), true).unwrap();
        assert_eq!((c.as_slice(), s.user.as_slice(), s.pass.as_slice()), (&b"client\n"[..], &b"bob"[..], &b"pw"[..]));
        for bad in [&b""[..], b"username=bob\n", b"config 01\nx", b"config 9\nx", b"config 2\n\0x", b"config 1\nxjunk"]
        {
            assert_eq!(
                read_framed(&mut &bad[..], true).err(),
                parse_framed(bad, true).err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        // Everything after the secrets limit is refused, not silently cut.
        let mut big = frame(b"x", b"");
        big.extend(std::iter::repeat_n(b'#', SECRETS_MAX as usize + 10));
        assert_eq!(read_framed(&mut big.as_slice(), true).err(), Some(FrameError::Invalid));
    }

    #[test]
    fn masks_all_but_the_user_name() {
        let (_, s) =
            parse_framed(&frame(b"x", b"username=bobby\npassword=pw1pw\npsk=psk99\nkeypass=kp77k\notp=135790\n"), true)
                .unwrap();
        assert_eq!(s.masker().line(b"bobby pw1pw psk99 kp77k 135790"), b"bobby *** *** *** ***".to_vec());
    }
}
