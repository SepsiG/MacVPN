//! The pipe between WinVPN and the WinVPN Service (`\\.\pipe\WinVPN`): one request per connection, length-
//! delimited, strict. The body of an `up` is the root layer 8 frame (`config <len>\n…` and the secret lines), of a
//! `respond` the answer lines; the service parses them with the helper's shared code. A pipe has no half-close, so
//! the envelope carries the body's length where the macOS root layer reads stdin to its end.
//!
//! ```text
//! request:  winvpn 1\n args <n>\n <arg>\n × n  body <len>\n <len bytes>
//! response: winvpn 1\n exit <code>\n stdout <len>\n <bytes> stderr <len>\n <bytes>
//! ```
//!
//! Numbers are ASCII decimal without sign (the exit code may have a `-`) or leading zero; an argument is 1–4096
//! bytes of `[A-Za-z0-9,._=-]`, 1–16 of them (the first is the command); the body is at most [`BODY_MAX`] bytes (refused before it is
//! read), each output at most [`OUTPUT_MAX`]. Platform-independent: no I/O but the given reader and writer.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

/// The service's endpoint.
pub const PIPE_NAME: &str = r"\\.\pipe\WinVPN";
/// The protocol and service version: the app requires exactly this one (the MSI installs both together).
pub const SERVICE_VERSION: u32 = 1;
pub const MAGIC: &[u8] = b"winvpn 1\n";
pub const ARG_MAX: usize = 4096;
pub const MAX_ARGS: usize = 16;
/// The helper's `STDIN_MAX` (1 MiB config + 64 KiB secrets + 16); the helper asserts the two are equal.
pub const BODY_MAX: u64 = 1_048_576 + 65_536 + 16;
pub const OUTPUT_MAX: u64 = 2 * 1024 * 1024;
/// The longest `engine` answer.
pub const FACTS_MAX: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoError {
    /// Not this protocol, a malformed line or number, or bytes where none may be.
    Invalid,
    /// A length above its limit (nothing more was read).
    TooLarge,
    /// The stream ended early or failed.
    Io(io::ErrorKind),
}

impl From<io::Error> for ProtoError {
    fn from(e: io::Error) -> Self {
        ProtoError::Io(e.kind())
    }
}

/// A request as the service receives it. The body may hold secrets: zeroed on drop, never in `Debug`.
pub struct Request {
    pub args: Vec<String>,
    pub body: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("args", &self.args)
            .field("body", &format_args!("<{} bytes redacted>", self.body.len()))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Response {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Response {
    pub fn ok(stdout: impl Into<Vec<u8>>) -> Response {
        Response { code: 0, stdout: stdout.into(), stderr: Vec::new() }
    }

    /// `code` with `message` and a line end on stderr (the `mvpn` `die`).
    pub fn fail(code: i32, message: &str) -> Response {
        Response { code, stdout: Vec::new(), stderr: format!("{message}\n").into_bytes() }
    }
}

pub fn is_valid_arg(a: &str) -> bool {
    !a.is_empty()
        && a.len() <= ARG_MAX
        && a.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b',' | b'.' | b'_' | b'=' | b'-'))
}

fn invalid_input() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "not a valid service request")
}

pub fn write_request(w: &mut impl Write, args: &[&str], body: &[u8]) -> io::Result<()> {
    if args.is_empty() || args.len() > MAX_ARGS || !args.iter().all(|a| is_valid_arg(a)) || body.len() as u64 > BODY_MAX
    {
        return Err(invalid_input());
    }
    let mut head = Vec::with_capacity(64 + args.iter().map(|a| a.len() + 1).sum::<usize>());
    head.extend_from_slice(MAGIC);
    head.extend_from_slice(format!("args {}\n", args.len()).as_bytes());
    for a in args {
        head.extend_from_slice(a.as_bytes());
        head.push(b'\n');
    }
    head.extend_from_slice(format!("body {}\n", body.len()).as_bytes());
    w.write_all(&head)?;
    w.write_all(body)?;
    w.flush()
}

pub fn write_response(w: &mut impl Write, r: &Response) -> io::Result<()> {
    if r.stdout.len() as u64 > OUTPUT_MAX || r.stderr.len() as u64 > OUTPUT_MAX {
        return Err(invalid_input());
    }
    w.write_all(MAGIC)?;
    w.write_all(format!("exit {}\nstdout {}\n", r.code, r.stdout.len()).as_bytes())?;
    w.write_all(&r.stdout)?;
    w.write_all(format!("stderr {}\n", r.stderr.len()).as_bytes())?;
    w.write_all(&r.stderr)?;
    w.flush()
}

/// One line of at most `max` bytes before its `\n`, read a byte at a time (nothing after the line is consumed).
fn read_line(r: &mut impl Read, max: usize) -> Result<Vec<u8>, ProtoError> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => return Err(ProtoError::Io(io::ErrorKind::UnexpectedEof)),
            Ok(_) if byte[0] == b'\n' => return Ok(line),
            Ok(_) if line.len() == max => return Err(ProtoError::Invalid),
            Ok(_) => line.push(byte[0]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// `<word> <number>`: digits only, no leading zero (but `0` itself), at most 12 digits.
fn number_line(line: &[u8], word: &str, signed: bool) -> Result<i64, ProtoError> {
    let rest = line.strip_prefix(word.as_bytes()).and_then(|r| r.strip_prefix(b" ")).ok_or(ProtoError::Invalid)?;
    let (negative, digits) = match rest.strip_prefix(b"-") {
        Some(d) if signed => (true, d),
        Some(_) => return Err(ProtoError::Invalid),
        None => (false, rest),
    };
    let ok = !digits.is_empty()
        && digits.len() <= 12
        && digits.iter().all(u8::is_ascii_digit)
        && (digits.len() == 1 || digits[0] != b'0');
    if !ok {
        return Err(ProtoError::Invalid);
    }
    let v = digits.iter().fold(0i64, |v, d| v * 10 + i64::from(d - b'0'));
    Ok(if negative { -v } else { v })
}

fn expect_magic(r: &mut impl Read) -> Result<(), ProtoError> {
    let mut magic = [0u8; MAGIC.len()];
    r.read_exact(&mut magic)?;
    if magic != MAGIC { Err(ProtoError::Invalid) } else { Ok(()) }
}

/// Exactly `len` bytes into one buffer allocated at its final size (never grown, so never copied unzeroed).
fn read_exact_zeroizing(r: &mut impl Read, len: usize) -> Result<Zeroizing<Vec<u8>>, ProtoError> {
    let mut buf = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn read_request(r: &mut impl Read) -> Result<Request, ProtoError> {
    expect_magic(r)?;
    let n = number_line(&read_line(r, 16)?, "args", false)?;
    if n == 0 || n as usize > MAX_ARGS {
        return Err(ProtoError::Invalid);
    }
    let mut args = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let line = read_line(r, ARG_MAX)?;
        let arg = String::from_utf8(line).map_err(|_| ProtoError::Invalid)?;
        if !is_valid_arg(&arg) {
            return Err(ProtoError::Invalid);
        }
        args.push(arg);
    }
    let len = number_line(&read_line(r, 24)?, "body", false)?;
    if len as u64 > BODY_MAX {
        return Err(ProtoError::TooLarge);
    }
    let body = read_exact_zeroizing(r, len as usize)?;
    Ok(Request { args, body })
}

pub fn read_response(r: &mut impl Read) -> Result<Response, ProtoError> {
    expect_magic(r)?;
    let code = number_line(&read_line(r, 24)?, "exit", true)?;
    let code = i32::try_from(code).map_err(|_| ProtoError::Invalid)?;
    let mut part = |word: &str| -> Result<Vec<u8>, ProtoError> {
        let len = number_line(&read_line(r, 24)?, word, false)?;
        if len as u64 > OUTPUT_MAX {
            return Err(ProtoError::TooLarge);
        }
        let mut buf = vec![0u8; len as usize];
        r.read_exact(&mut buf)?;
        Ok(buf)
    };
    let stdout = part("stdout")?;
    let stderr = part("stderr")?;
    Ok(Response { code, stdout, stderr })
}

// MARK: - `engine`

/// What the service knows about its engines (System Status; the `engine` command's stdout, JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EngineFacts {
    pub service_version: u32,
    /// The service cannot connect anything (its data directory is unsafe): the localized reason.
    pub problem: Option<String>,
    pub openvpn: OpenVpnFacts,
    pub wireguard: WireGuardFacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OpenVpnFacts {
    /// `major.minor.patch` of `openvpn.exe`; `None`: not installed.
    pub version: Option<String>,
    pub path: Option<String>,
    /// The version of each data-channel driver; `None`: not installed (decision 4: both are installed; OpenVPN 2.7
    /// has no Wintun, and the service never uses it).
    pub dco: Option<String>,
    pub tap_windows6: Option<String>,
    /// Why OpenVPN cannot be used (localized); `None`: usable.
    pub problem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireGuardFacts {
    /// The bundled `wireguard.dll`'s version once loaded and verified.
    pub dll_version: Option<String>,
    pub problem: Option<String>,
}

// MARK: - engine updates (2b plan, "As built (fix4)")

/// `wireguard-check`: the service asks the official wireguard-nt listing (answers are reused for a minute) whether a
/// newer `wireguard.dll` than the loaded one exists. Exit 0 with [`EngineUpdate`]; any failure (no answer, an
/// unexpected listing) is exit 1 with the reason, which the app treats as "unknown". An older service answers the
/// usage error (exit 2): also "unknown". Nothing of the request is used but the command.
pub const WIREGUARD_CHECK: &str = "wireguard-check";
/// `wireguard-update`: the service downloads, verifies and loads the newest wireguard-nt itself. Exit 0 with
/// [`EngineUpdate`] (`installed` = the version now loaded, `available` = none); [`UPDATE_BUSY`] when a WireGuard
/// connection is up (the DLL holds the driver) or another update runs; exit 1 with the reason otherwise.
pub const WIREGUARD_UPDATE: &str = "wireguard-update";
/// The exit code of an engine update that cannot run now (the message says why).
pub const UPDATE_BUSY: i32 = 3;

/// An engine's installed and available version (`wireguard-check`, `wireguard-update`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EngineUpdate {
    /// The loaded version (`1.1.0`); `None`: nothing is loaded.
    pub installed: Option<String>,
    /// A newer version upstream (`1.2.0`); `None`: nothing newer.
    pub available: Option<String>,
}

impl EngineUpdate {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("plain data serializes")
    }

    /// At most [`FACTS_MAX`] bytes of exactly this shape; each version at most 32 bytes of digits and dots.
    pub fn parse(data: &[u8]) -> Option<EngineUpdate> {
        if data.len() > FACTS_MAX {
            return None;
        }
        let u: EngineUpdate = serde_json::from_slice(data).ok()?;
        let plain = |v: &Option<String>| {
            v.as_deref()
                .is_none_or(|s| !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
        };
        (plain(&u.installed) && plain(&u.available)).then_some(u)
    }
}

impl EngineFacts {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("plain data serializes")
    }

    /// At most [`FACTS_MAX`] bytes of exactly this shape.
    pub fn parse(data: &[u8]) -> Option<EngineFacts> {
        if data.len() > FACTS_MAX {
            return None;
        }
        serde_json::from_slice(data).ok()
    }
}

impl OpenVpnFacts {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("plain data serializes")
    }

    /// At most [`FACTS_MAX`] bytes of exactly this shape (the service's debug `console-detect` prints it).
    pub fn parse(data: &[u8]) -> Option<OpenVpnFacts> {
        if data.len() > FACTS_MAX {
            return None;
        }
        serde_json::from_slice(data).ok()
    }
}

// MARK: - `log`

/// A slice of a connection's log (`log <id> <offset>`): `generation` changes when the log file is replaced (the
/// counterpart of the inode check), `size` is the file's size, `data` the bytes from `start` (at most 1 MiB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSlice {
    pub generation: u64,
    pub size: u64,
    pub start: u64,
    pub data: Vec<u8>,
}

impl LogSlice {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = format!("{} {} {}\n", self.generation, self.size, self.start).into_bytes();
        out.extend_from_slice(&self.data);
        out
    }

    /// `start + data.len() <= size`, numbers without leading zeros.
    pub fn parse(bytes: &[u8]) -> Option<LogSlice> {
        let nl = bytes.iter().position(|&b| b == b'\n')?;
        let head = std::str::from_utf8(&bytes[..nl]).ok()?;
        let mut parts = head.split(' ');
        let mut num = || -> Option<u64> {
            let p = parts.next()?;
            let ok = !p.is_empty() && p.len() <= 20 && p.bytes().all(|b| b.is_ascii_digit());
            (ok && (p.len() == 1 || !p.starts_with('0'))).then(|| p.parse().ok()).flatten()
        };
        let (generation, size, start) = (num()?, num()?, num()?);
        if parts.next().is_some() {
            return None;
        }
        let data = bytes[nl + 1..].to_vec();
        (start.checked_add(data.len() as u64)? <= size).then_some(LogSlice { generation, size, start, data })
    }
}

// MARK: - versions

/// `major.minor.patch` (OpenVPN's version policy; the service and the app compare versions with this type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub u16, pub u16, pub u16);

impl Version {
    /// Exactly three dot-separated decimal parts, each 1–5 ASCII digits fitting a `u16`.
    pub fn parse(s: &str) -> Option<Version> {
        let parts = s
            .split('.')
            .map(|p| {
                if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) {
                    p.parse().ok()
                } else {
                    None
                }
            })
            .collect::<Option<Vec<u16>>>()?;
        match parts.as_slice() {
            [a, b, c] => Some(Version(*a, *b, *c)),
            _ => None,
        }
    }

    /// A file version resource's `major.minor.build.revision` (`openvpn.exe` 2.6.23 is `2.6.23.0`).
    pub fn from_file_version(v: (u16, u16, u16, u16)) -> Version {
        Version(v.0, v.1, v.2)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}
