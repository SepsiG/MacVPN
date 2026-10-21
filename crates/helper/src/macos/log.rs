//! The connection log (`/var/log/macvpn/<id>.log`, the user's, 0600) and the rules for the root-only tool logs.
//!
//! Decisions (connected, authentication failure, interface, address, DNS) are never taken from the user's log,
//! only from the root-only `openvpn.log` / `pppd.log` in the run directory. Their content is copied into the user's
//! log masked, without OpenVPN management command lines that may carry an MFA code.

use crate::macos::fsx;
use crate::shared::mask::{self, Masker};
use regex::bytes::Regex;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// The user's connection log. Without a path (before `open`) every write is a no-op.
#[derive(Debug, Clone, Default)]
pub struct Log {
    path: Option<PathBuf>,
}

impl Log {
    pub fn none() -> Log {
        Log { path: None }
    }

    pub fn at(path: PathBuf) -> Log {
        Log { path: Some(path) }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn bytes(&self, data: &[u8]) {
        if let Some(p) = &self.path
            && !data.is_empty()
        {
            let _ = fsx::append(p, data);
        }
    }

    /// `printf '%s\n' "$*" >>"$LOG"`
    pub fn line(&self, s: &str) {
        self.bytes(format!("{s}\n").as_bytes());
    }

    /// `▶ [mvpn] …`
    pub fn step(&self, s: &str) {
        self.line(&format!("▶ [mvpn] {s}"));
    }

    /// `$ <command line>`
    pub fn cmd(&self, s: &str) {
        self.line(&format!("$ {s}"));
    }

    /// The log opened for an append by a child process (`>>"$LOG"`).
    pub fn file(&self) -> Option<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        let p = self.path.as_ref()?;
        std::fs::OpenOptions::new().append(true).create(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(p).ok()
    }
}

/// `open_log`: the log directory (755), a symlink in place of the log removed, rotation at `up`, the file the
/// user's (root) and 0600.
pub fn open(log_base: &Path, id: &str, rotate_max: Option<u64>, owner: Option<u32>) -> Log {
    let _ = std::fs::create_dir_all(log_base);
    let _ = fsx::chmod(log_base, 0o755);
    let path = log_base.join(format!("{id}.log"));
    if crate::macos::paths::is_symlink(&path) {
        fsx::remove_file(&path);
    }
    if let Some(max) = rotate_max {
        rotate(&path, max, owner);
    }
    let _ = fsx::append(&path, b"");
    if let Some(uid) = owner {
        let _ = std::os::unix::fs::lchown(&path, Some(uid), None);
    }
    let _ = fsx::chmod(&path, 0o600);
    Log::at(path)
}

/// Above `max` bytes the log becomes `<log>.1` (one copy kept). Nothing follows a symlink.
pub fn rotate(path: &Path, max: u64, owner: Option<u32>) {
    let Ok(m) = std::fs::symlink_metadata(path) else { return };
    if !m.file_type().is_file() || m.len() <= max {
        return;
    }
    let old = PathBuf::from(format!("{}.1", path.display()));
    fsx::remove_rf(&old);
    if std::fs::rename(path, &old).is_err() {
        return;
    }
    if let Some(uid) = owner {
        let _ = std::os::unix::fs::lchown(&old, Some(uid), None);
    }
    let _ = fsx::chmod(&old, 0o600);
}

/// The bash `log_safe`: lines that may carry an MFA code never reach the user's log. `CR_RESPONSE,` lines are
/// dropped, and of the `MANAGEMENT: CMD '…'` lines only `state`, `hold` and `version` are kept.
pub fn log_safe(line: &[u8]) -> bool {
    if mask::find(line, b"CR_RESPONSE,").is_some() {
        return false;
    }
    const CMD: &[u8] = b"MANAGEMENT: CMD '";
    match mask::find(line, CMD) {
        None => true,
        Some(p) => management_kept(&line[p + CMD.len()..]),
    }
}

/// `^(state|hold|version)( [^']*)?'`
fn management_kept(rest: &[u8]) -> bool {
    for word in [&b"state"[..], b"hold", b"version"] {
        if let Some(after) = rest.strip_prefix(word) {
            if after.first() == Some(&b'\'') {
                return true;
            }
            if after.first() == Some(&b' ') && after.contains(&b'\'') {
                return true;
            }
        }
    }
    false
}

static ECHO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?-u)(^|[ :])ECHO(-PULL)?:").expect("valid"));

/// The anchored completion line: a timestamp (plain, with ` us=` above verb 4, or `--machine-readable-output`), then
/// exactly `Initialization Sequence Completed` (possibly `With Errors …`).
pub const OVPN_DONE_RE: &str = r"^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}( us=[0-9]+)? |[0-9]+[.][0-9]+ [0-9A-Fa-f]+ )?Initialization Sequence Completed( With Errors.*)?$";

static DONE: LazyLock<Regex> = LazyLock::new(|| Regex::new(&format!("(?-u){OVPN_DONE_RE}")).expect("valid"));
static AUTH_NOT_FINAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?-u)AUTH_FAILED,(CRV1:|TEMP)").expect("valid"));

/// `ovpn_log_real`: OpenVPN's own lines (no `ECHO:` / `ECHO-PULL:`), through [`log_safe`].
pub fn ovpn_real_lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    mask::lines(data).filter(|l| !ECHO.is_match(l) && log_safe(l))
}

/// The root-only openvpn.log says the connection is up.
pub fn ovpn_done(data: &[u8]) -> bool {
    ovpn_real_lines(data).any(|l| DONE.is_match(l))
}

#[cfg(test)]
/// A final `AUTH_FAILED` (not `AUTH_FAILED,CRV1:` – a dynamic challenge – and not `AUTH_FAILED,TEMP`).
pub fn ovpn_auth_failed(data: &[u8]) -> bool {
    ovpn_real_lines(data).any(|l| mask::find(l, b"AUTH_FAILED").is_some() && !AUTH_NOT_FINAL.is_match(l))
}

#[cfg(test)]
/// The last non-blank real line (for the "openvpn exited:" message).
pub fn ovpn_last_line(data: &[u8]) -> Vec<u8> {
    ovpn_real_lines(data).filter(|l| !is_blank(l)).last().map(<[u8]>::to_vec).unwrap_or_default()
}

/// `[Pp][Aa][Ss][Ss]|[Aa][Uu][Tt][Hh]`
fn mentions_secret(line: &[u8]) -> bool {
    let lower = line.to_ascii_lowercase();
    mask::find(&lower, b"pass").is_some() || mask::find(&lower, b"auth").is_some()
}

/// `flush_root_log`: the part of a root-only tool log not yet copied (offset in `<file>.off`) goes to the user's
/// log, filtered with [`log_safe`], prefixed and masked. `nosecrets`: the caller does not know the secrets
/// (status), so every password- or authentication-like line is left out instead.
pub fn flush_root_log(log: &Log, f: &Path, prefix: &str, nosecrets: bool, masker: &Masker) {
    if log.path().is_none() || !crate::macos::paths::is_file(f) || crate::macos::paths::is_symlink(f) {
        return;
    }
    let off_path = PathBuf::from(format!("{}.off", f.display()));
    let off: u64 = fsx::read_trim(&off_path)
        .filter(|s| crate::macos::testmode::is_digits(s))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let Some(size) = fsx::size(f) else { return };
    if size <= off {
        return;
    }
    let Some(chunk) = read_range(f, off, size - off) else { return };
    let mut out = Vec::new();
    for l in mask::lines(&chunk) {
        if (nosecrets && mentions_secret(l)) || !log_safe(l) {
            continue;
        }
        let mut line = prefix.as_bytes().to_vec();
        line.extend_from_slice(l);
        out.extend_from_slice(&masker.line(&line));
        out.push(b'\n');
    }
    log.bytes(&out);
    let _ = fsx::write_line(&off_path, &size.to_string());
}

/// `tail -c +<off+1> f | head -c <len>`
pub fn read_range(f: &Path, off: u64, len: u64) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(f).ok()?;
    file.seek(SeekFrom::Start(off)).ok()?;
    let mut data = Vec::new();
    file.take(len).read_to_end(&mut data).ok()?;
    Some(data)
}

/// Streams the lines of a root-only log (`None` if it is missing or a symlink); `f` returns `true` to stop.
/// Returns whether `f` stopped the scan.
pub fn scan_root_log(path: &Path, mut f: impl FnMut(&[u8]) -> bool) -> bool {
    use std::io::BufRead;
    if crate::macos::paths::is_symlink(path) {
        return false;
    }
    let Ok(file) = std::fs::File::open(path) else { return false };
    let mut reader = std::io::BufReader::new(file);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => return false,
            Ok(_) => {
                if buf.last() == Some(&b'\n') {
                    buf.pop();
                }
                if f(&buf) {
                    return true;
                }
            }
        }
    }
}

/// [`ovpn_done`] on a file, without reading it into memory.
pub fn ovpn_done_file(path: &Path) -> bool {
    scan_root_log(path, |l| !ECHO.is_match(l) && log_safe(l) && DONE.is_match(l))
}

/// [`ovpn_auth_failed`] on a file.
pub fn ovpn_auth_failed_file(path: &Path) -> bool {
    scan_root_log(path, |l| {
        !ECHO.is_match(l) && log_safe(l) && mask::find(l, b"AUTH_FAILED").is_some() && !AUTH_NOT_FINAL.is_match(l)
    })
}

/// [`ovpn_last_line`] on a file.
pub fn ovpn_last_line_file(path: &Path) -> Vec<u8> {
    let mut last = Vec::new();
    scan_root_log(path, |l| {
        if !ECHO.is_match(l) && log_safe(l) && !is_blank(l) {
            last = l.to_vec();
        }
        false
    });
    last
}

fn is_blank(l: &[u8]) -> bool {
    l.iter().all(|&b| matches!(b, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_pattern() {
        for l in [
            "2026-10-18 15:22:48 Initialization Sequence Completed",
            "2026-10-18 15:42:51 us=411817 Initialization Sequence Completed",
            "Initialization Sequence Completed",
            "1792330971.453131 32000004 Initialization Sequence Completed",
            "2026-10-18 15:42:51 us=5 Initialization Sequence Completed With Errors ( see http://openvpn.net/faq.html#dhcpclientserv )",
        ] {
            assert!(ovpn_done(l.as_bytes()), "{l}");
        }
        for l in [
            "2026-10-18 15:22:48 ECHO:msg x Initialization Sequence Completed",
            "2026-10-18 15:22:48 PUSH: Received control message: 'PUSH_REPLY,echo msg Initialization Sequence Completed'",
            "2026-10-18 15:22:48 us=abc Initialization Sequence Completed",
            "2026-10-17 00:00:00 ECHO:msg Initialization Sequence Completed",
            "2026-10-17 00:00:02 ECHO-PULL:msg Initialization Sequence Completed",
            "Initialization Sequence Completed\r",
        ] {
            assert!(!ovpn_done(l.as_bytes()), "{l}");
        }
    }

    #[test]
    fn management_lines_filtered() {
        assert!(log_safe(b"x MANAGEMENT: CMD 'state on'"));
        assert!(log_safe(b"x MANAGEMENT: CMD 'hold release'"));
        assert!(log_safe(b"x MANAGEMENT: CMD 'version 3'"));
        assert!(log_safe(b"x MANAGEMENT: CMD 'state'"));
        assert!(!log_safe(b"x MANAGEMENT: CMD 'statex'"));
        assert!(!log_safe(b"x MANAGEMENT: CMD 'username \"Auth\" bob'"));
        assert!(!log_safe(b"x MANAGEMENT: CMD 'cr-response MTEy'"));
        assert!(!log_safe(b"x MANAGEMENT: CMD 'state on"));
        assert!(!log_safe(b"x SENT CONTROL [v]: 'CR_RESPONSE,MTEy' (status=1)"));
        assert!(log_safe(b"plain line"));
    }

    #[test]
    fn auth_failed_rules() {
        assert!(ovpn_auth_failed(b"2026 AUTH: Received control message: AUTH_FAILED\n"));
        assert!(!ovpn_auth_failed(b"x AUTH_FAILED,CRV1:R:st:Ym9i:PIN\n"));
        assert!(!ovpn_auth_failed(b"x AUTH_FAILED,TEMP[backoff 2]:busy\n"));
        assert!(!ovpn_auth_failed(b"2026 ECHO:msg AUTH_FAILED\n"));
    }

    #[test]
    fn last_line_skips_blank_and_filtered() {
        let data = b"2026 KEEPLINE\n2026 MANAGEMENT: CMD 'cr-response MTEy'\n  \n";
        assert_eq!(ovpn_last_line(data), b"2026 KEEPLINE".to_vec());
    }

    #[test]
    fn secret_like_lines() {
        assert!(mentions_secret(b"x Password: y"));
        assert!(mentions_secret(b"AUTH: x"));
        assert!(mentions_secret(b"passwd"));
        assert!(!mentions_secret(b"KEEPMARKER"));
    }
}
