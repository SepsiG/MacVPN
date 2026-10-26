//! The connection log (`/var/log/macvpn/<id>.log`, the user's, 0600) and the rules for the root-only tool logs.
//!
//! Decisions (connected, authentication failure, interface, address, DNS) are never taken from the user's log,
//! only from the root-only `openvpn.log` / `pppd.log` in the run directory. Their content is copied into the user's
//! log masked, without OpenVPN management command lines that may carry an MFA code.
//!
//! Size limits (a 29-hour session once wrote 30 GB): the user's log is at most [`LOG_MAX`] plus one rotated
//! generation `<id>.log.1` of at most [`LOG_MAX`], enforced on every write of `mvpn` ([`Log::bytes`]), by `mask-stream`
//! (SSTP) on every line, and by `status` and the OpenVPN management bridge for the writers outside `mvpn` (child
//! processes appending to the same file). A full log is rolled in place: its newest part becomes `.1`, the live
//! file is truncated, so every `O_APPEND` writer keeps writing into the live file. The engines' own logs in the run
//! directory are cut to their newest [`ROOT_LOG_KEEP`] above [`ROOT_LOG_MAX`] ([`trim_root_log`]), keeping the
//! lines decisions are taken from. One flush copies at most [`FLUSH_MAX`] into the user's log.

use crate::macos::fsx;
pub use crate::macos::paths::LOG_MAX;
use crate::shared::mask::{self, Masker};
pub use crate::shared::ovpn_log::ovpn_done;
use crate::shared::ovpn_log::{AUTH_NOT_FINAL, DONE, ECHO, is_blank, log_safe, mentions_secret};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// The cap of an engine's root-only log in the run directory (`openvpn.log`, `pppd.log`).
pub const ROOT_LOG_MAX: u64 = 5 * 1024 * 1024;
/// What is kept of an engine's log when it is cut: its newest bytes (from a line start).
pub const ROOT_LOG_KEEP: u64 = 1024 * 1024;
/// The most one flush copies from an engine's log into the user's log; an older backlog is skipped (with a note).
pub const FLUSH_MAX: u64 = 1024 * 1024;
/// How many decision lines of a cut part are kept at the start of the cut engine log.
const DECISION_LINES: usize = 16;

/// The user's connection log. Without a path (before `open`) every write is a no-op.
#[derive(Debug, Clone)]
pub struct Log {
    path: Option<PathBuf>,
    max: u64,
}

impl Default for Log {
    fn default() -> Log {
        Log::none()
    }
}

impl Log {
    pub fn none() -> Log {
        Log { path: None, max: LOG_MAX }
    }

    pub fn at(path: PathBuf) -> Log {
        Log::capped(path, LOG_MAX)
    }

    /// A log rolled above `max` bytes (the test mode's `MVPN_LOG_MAX`).
    pub fn capped(path: PathBuf, max: u64) -> Log {
        Log { path: Some(path), max: max.max(1) }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Appends `data`; the log is rolled first when it would grow over the cap. More than the cap at once keeps only
    /// its newest part.
    pub fn bytes(&self, data: &[u8]) {
        if let Some(p) = &self.path
            && !data.is_empty()
        {
            let data = newest_lines(data, self.max);
            make_room(p, self.max, data.len() as u64);
            let _ = fsx::append(p, data);
        }
    }

    /// Rolls the log if it is over the cap (what writers outside `mvpn` appended).
    pub fn enforce_cap(&self) {
        if let Some(p) = &self.path {
            make_room(p, self.max, 0);
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
        let p = self.path.as_ref()?;
        std::fs::OpenOptions::new().append(true).create(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(p).ok()
    }
}

/// `open_log`: the log directory (755), a symlink in place of the log removed, rotation at `up`, the file the
/// user's (root) and 0600. A live log or a rotated generation over `max` (an older version's) is cut to `max`.
pub fn open(log_base: &Path, id: &str, max: u64, rotate_at_up: bool, owner: Option<u32>) -> Log {
    let _ = std::fs::create_dir_all(log_base);
    let _ = fsx::chmod(log_base, 0o755);
    let path = log_base.join(format!("{id}.log"));
    if crate::macos::paths::is_symlink(&path) {
        fsx::remove_file(&path);
    }
    if rotate_at_up {
        rotate(&path, max, owner);
    }
    trim_file(&rotated(&path), max);
    make_room(&path, max, 0);
    let _ = fsx::append(&path, b"");
    if let Some(uid) = owner {
        let _ = std::os::unix::fs::lchown(&path, Some(uid), None);
    }
    let _ = fsx::chmod(&path, 0o600);
    Log::capped(path, max)
}

/// `<log>.1`
fn rotated(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.1", path.display()))
}

/// Above `max` bytes the log becomes `<log>.1` (one copy kept). Nothing follows a symlink.
pub fn rotate(path: &Path, max: u64, owner: Option<u32>) {
    let Ok(m) = std::fs::symlink_metadata(path) else { return };
    if !m.file_type().is_file() || m.len() <= max {
        return;
    }
    let old = rotated(path);
    fsx::remove_rf(&old);
    if std::fs::rename(path, &old).is_err() {
        return;
    }
    if let Some(uid) = owner {
        let _ = std::os::unix::fs::lchown(&old, Some(uid), None);
    }
    let _ = fsx::chmod(&old, 0o600);
}

/// The newest at most `max` bytes of `data`, from a line start when the cut falls inside a line.
fn newest_lines(data: &[u8], max: u64) -> &[u8] {
    let max = usize::try_from(max).unwrap_or(usize::MAX);
    if data.len() <= max {
        return data;
    }
    let cut = data.len() - max;
    let tail = &data[cut..];
    if data[cut - 1] == b'\n' { tail } else { &tail[line_start(tail)..] }
}

/// Where the first complete line of a chunk cut out of a file starts: after its first newline (0 without one, so a
/// chunk of one long line is kept whole).
fn line_start(chunk: &[u8]) -> usize {
    match chunk.iter().position(|&b| b == b'\n') {
        Some(nl) if nl + 1 < chunk.len() => nl + 1,
        _ => 0,
    }
}

/// The newest at most `max` bytes of a regular file (not through a symlink), from a line start.
fn read_tail(p: &Path, max: u64) -> Option<(Vec<u8>, u32)> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::MetadataExt;
    let mut f =
        std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(p).ok()?;
    let m = f.metadata().ok()?;
    if !m.file_type().is_file() {
        return None;
    }
    // One byte before the cut too: a cut right after a newline keeps that whole line.
    let start = m.len().saturating_sub(max).saturating_sub(1);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut data = Vec::new();
    (&mut f).take(max + 1).read_to_end(&mut data).ok()?;
    if start > 0 || m.len() > max {
        data.drain(..line_start(&data).max(1));
    }
    Some((data, m.uid()))
}

/// Replaces `p` with `data` (a new 0600 file of `uid`, renamed over it).
fn replace(p: &Path, data: &[u8], uid: u32) -> bool {
    let tmp = PathBuf::from(format!("{}.tmp{}", p.display(), std::process::id()));
    fsx::remove_file(&tmp);
    if fsx::create_new(&tmp, data, 0o600).is_err() {
        return false;
    }
    let _ = std::os::unix::fs::lchown(&tmp, Some(uid), None);
    if std::fs::rename(&tmp, p).is_err() {
        fsx::remove_file(&tmp);
        return false;
    }
    true
}

/// A regular file over `max` bytes is cut to its newest `max` bytes (from a line start); the owner is kept.
pub fn trim_file(p: &Path, max: u64) {
    if !std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file() && m.len() > max) {
        return;
    }
    if let Some((tail, uid)) = read_tail(p, max) {
        replace(p, &tail, uid);
    }
}

/// When `incoming` more bytes would take the log over `max`, it is rolled: its newest `max` bytes become `<log>.1`
/// and the live file is truncated in place (writers holding it open with `O_APPEND` continue at its new end).
pub fn make_room(p: &Path, max: u64, incoming: u64) {
    let Ok(m) = std::fs::symlink_metadata(p) else { return };
    if !m.file_type().is_file() || m.len().saturating_add(incoming) <= max || m.len() == 0 {
        return;
    }
    if let Some((tail, uid)) = read_tail(p, max) {
        replace(&rotated(p), &tail, uid);
    }
    // Even when `.1` could not be written the live file is cut: the bound comes before the history.
    if let Ok(f) = std::fs::OpenOptions::new().write(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(p)
        && f.metadata().is_ok_and(|m| m.file_type().is_file())
    {
        let _ = f.set_len(0);
    }
}

/// A line of an engine's log that a decision is taken from (completion, a final authentication failure, pppd's
/// interface / address / DNS lines): a cut keeps the newest of them.
fn decision_line(l: &[u8]) -> bool {
    if ECHO.is_match(l) || !log_safe(l) {
        return false;
    }
    DONE.is_match(l)
        || (mask::find(l, b"AUTH_FAILED").is_some() && !AUTH_NOT_FINAL.is_match(l))
        || [&b"Using interface "[..], b"IP address ", b"DNS address "].iter().any(|m| mask::find(l, m).is_some())
}

/// `<file>.off`: how much of an engine log is already in the user's log.
fn off_path(f: &Path) -> PathBuf {
    PathBuf::from(format!("{}.off", f.display()))
}

fn read_off(f: &Path) -> u64 {
    fsx::read_trim(&off_path(f))
        .filter(|s| crate::macos::testmode::is_digits(s))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// An engine's root-only log over `max` bytes is cut in place to its newest `keep` bytes (from a line start), after
/// the newest decision lines of the cut part; its copy offset follows. The engine appends with `O_APPEND`, so it
/// continues at the new end (a line written during the cut itself may be lost or land before the kept part).
pub fn trim_root_log(f: &Path, max: u64, keep: u64) {
    use std::io::{BufRead, Read, Seek, SeekFrom, Write};
    let Ok(mut file) =
        std::fs::OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(f)
    else {
        return;
    };
    let Ok(m) = file.metadata() else { return };
    if !m.file_type().is_file() || m.len() <= max {
        return;
    }
    // From one byte before the kept part: a cut right after a newline keeps that whole line.
    let mut start = m.len() - keep.min(m.len()).saturating_add(1).min(m.len());
    let mut tail = Vec::new();
    if file.seek(SeekFrom::Start(start)).is_err() || (&mut file).take(keep + max).read_to_end(&mut tail).is_err() {
        return;
    }
    let cut = line_start(&tail).max(1).min(tail.len());
    start += cut as u64;
    tail.drain(..cut);
    let mut decisions = std::collections::VecDeque::new();
    if file.seek(SeekFrom::Start(0)).is_ok() {
        let mut reader = std::io::BufReader::new((&mut file).take(start));
        let mut line = Vec::new();
        while reader.read_until(b'\n', &mut line).is_ok_and(|n| n > 0) {
            let l = line.strip_suffix(b"\n").unwrap_or(&line);
            if decision_line(l) {
                if decisions.len() == DECISION_LINES {
                    decisions.pop_front();
                }
                let mut l = l.to_vec();
                l.push(b'\n');
                decisions.push_back(l);
            }
            line.clear();
        }
    }
    let prefix: Vec<u8> = decisions.into_iter().flatten().collect();
    let off = read_off(f);
    if file.set_len(0).is_err() {
        return;
    }
    let Ok(mut out) = std::fs::OpenOptions::new().append(true).custom_flags(libc::O_NOFOLLOW).open(f) else { return };
    let _ = out.write_all(&prefix).and_then(|_| out.write_all(&tail));
    let p = prefix.len() as u64;
    let new_off = if off <= start { p } else { (p + (off - start)).min(p + tail.len() as u64) };
    let _ = fsx::write_line(&off_path(f), &new_off.to_string());
}

/// `flush_root_log`: the part of a root-only tool log not yet copied (offset in `<file>.off`) goes to the user's
/// log, filtered with [`log_safe`], prefixed and masked. `nosecrets`: the caller does not know the secrets
/// (status), so every password- or authentication-like line is left out instead. At most [`FLUSH_MAX`] is copied
/// (the newest part, with a note on what was left out); then the tool log is cut to its cap ([`trim_root_log`]).
pub fn flush_root_log(log: &Log, f: &Path, prefix: &str, nosecrets: bool, masker: &Masker) {
    if log.path().is_none() || !crate::macos::paths::is_file(f) || crate::macos::paths::is_symlink(f) {
        return;
    }
    let Some(size) = fsx::size(f) else { return };
    let mut off = read_off(f);
    if off > size {
        // The tool log was cut without its offset (an older version): copy from its start.
        off = 0;
    }
    if size > off {
        // A skip starts one byte early: a cut right after a newline keeps that whole line.
        let start = off.max(size.saturating_sub(FLUSH_MAX).saturating_sub(1));
        let Some(mut chunk) = read_range(f, start, size - start) else { return };
        let mut out = Vec::new();
        if start > off {
            let cut = line_start(&chunk).max(1).min(chunk.len());
            let skipped = start - off + cut as u64;
            chunk.drain(..cut);
            let note = crate::shared::l10n::tr(
                "%@ bytes of the engine log were left out (log size limit)",
                &[&skipped.to_string()],
            );
            out.extend_from_slice(format!("▶ [mvpn] {note}\n").as_bytes());
        }
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
        let _ = fsx::write_line(&off_path(f), &size.to_string());
    }
    trim_root_log(f, ROOT_LOG_MAX, ROOT_LOG_KEEP);
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

/// [`ovpn_auth_failed`](crate::shared::ovpn_log::ovpn_auth_failed) on a file.
pub fn ovpn_auth_failed_file(path: &Path) -> bool {
    scan_root_log(path, |l| {
        !ECHO.is_match(l) && log_safe(l) && mask::find(l, b"AUTH_FAILED").is_some() && !AUTH_NOT_FINAL.is_match(l)
    })
}

/// [`ovpn_last_line`](crate::shared::ovpn_log::ovpn_last_line) on a file.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("mvpn-log-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn lines(from: usize, to: usize) -> Vec<u8> {
        (from..to).flat_map(|i| format!("line {i:05}\n").into_bytes()).collect()
    }

    fn len(p: &Path) -> u64 {
        std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
    }

    #[test]
    fn a_line_cut_keeps_whole_lines() {
        assert_eq!(newest_lines(b"aa\nbb\ncc\n", 6), b"bb\ncc\n");
        assert_eq!(newest_lines(b"aa\nbb\ncc\n", 7), b"bb\ncc\n");
        assert_eq!(newest_lines(b"aa\nbb\ncc\n", 5), b"cc\n");
        assert_eq!(newest_lines(b"aa\nbb\n", 99), b"aa\nbb\n");
        assert_eq!(newest_lines(b"abcdefgh", 3), b"fgh", "one long line is kept as its tail");
        assert_eq!(line_start(b"\nab\n"), 1);
        assert_eq!(line_start(b"ab"), 0);
    }

    #[test]
    fn the_user_log_never_grows_over_its_cap_in_a_session() {
        let d = dir();
        let p = d.join("x.log");
        let log = Log::capped(p.clone(), 1000);
        for i in 0..500 {
            log.line(&format!("write UDPv4: Network is unreachable (fd=5,code=51) #{i}"));
            assert!(len(&p) <= 1000, "live {} after {i}", len(&p));
            assert!(len(&rotated(&p)) <= 1000);
        }
        let live = std::fs::read_to_string(&p).unwrap();
        assert!(live.ends_with("#499\n"), "the newest line is in the live log");
        let old = std::fs::read_to_string(rotated(&p)).unwrap();
        assert!(old.starts_with("write UDPv4") && old.ends_with('\n'), "whole lines in .1");
        // One write larger than the cap keeps its newest lines only.
        log.bytes(&lines(0, 1000));
        assert!(len(&p) <= 1000 && std::fs::read_to_string(&p).unwrap().ends_with("line 00999\n"));
        fsx::remove_rf(&d);
    }

    #[test]
    fn an_outside_append_writer_continues_in_the_cut_live_log() {
        let d = dir();
        let p = d.join("x.log");
        let log = Log::capped(p.clone(), 500);
        let mut child = log.file().unwrap();
        std::io::Write::write_all(&mut child, &lines(0, 200)).unwrap();
        assert!(len(&p) > 500);
        log.enforce_cap();
        assert_eq!(len(&p), 0);
        assert!(len(&rotated(&p)) <= 500);
        assert!(std::fs::read_to_string(rotated(&p)).unwrap().ends_with("line 00199\n"));
        std::io::Write::write_all(&mut child, b"after\n").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"after\n", "O_APPEND continues at the new end, no hole");
        fsx::remove_rf(&d);
    }

    #[test]
    fn opening_cuts_an_oversized_log_and_generation() {
        let d = dir();
        let id = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
        let p = d.join(format!("{id}.log"));
        std::fs::write(&p, lines(0, 3000)).unwrap();
        std::fs::write(rotated(&p), lines(5000, 9000)).unwrap();
        // `down` / `respond` (no rotation): the live log is rolled, the old `.1` replaced by its newest part.
        let log = open(&d, id, 2000, false, None);
        assert_eq!(log.path(), Some(p.as_path()));
        assert!(len(&p) <= 2000 && len(&rotated(&p)) <= 2000);
        assert!(std::fs::read_to_string(rotated(&p)).unwrap().ends_with("line 02999\n"));
        // An `.1` alone over the cap (an older version's) is cut to its newest lines at the next run.
        std::fs::write(rotated(&p), lines(5000, 9000)).unwrap();
        open(&d, id, 2000, true, None);
        let old = std::fs::read_to_string(rotated(&p)).unwrap();
        assert!(len(&rotated(&p)) <= 2000 && old.starts_with("line ") && old.ends_with("line 08999\n"));
        fsx::remove_rf(&d);
    }

    #[test]
    fn a_cut_engine_log_keeps_its_decisions_and_offset() {
        let d = dir();
        let f = d.join("openvpn.log");
        let mut data = b"2026-10-22 16:24:01 Initialization Sequence Completed\n".to_vec();
        data.extend(b"2026-10-22 16:24:00 ECHO:Initialization Sequence Completed\n");
        for i in 0..400 {
            data.extend(
                format!("2026-10-22 17:00:00 write UDPv4: Network is unreachable (fd=5,code=51) {i}\n").bytes(),
            );
        }
        std::fs::write(&f, &data).unwrap();
        let size = data.len() as u64;
        fsx::write_line(&off_path(&f), &(size - 100).to_string()).unwrap();
        trim_root_log(&f, 4000, 2000);
        let after = std::fs::read(&f).unwrap();
        assert!(after.len() < 2200, "{}", after.len());
        assert!(after.starts_with(b"2026-10-22 16:24:01 Initialization Sequence Completed\n"));
        assert!(!mask::find(&after, b"ECHO:").is_some(), "an echo is not a decision");
        assert!(after.ends_with(b"code=51) 399\n"));
        assert!(ovpn_done_file(&f), "status still sees the completed connection");
        // The 100 uncopied bytes stay uncopied.
        assert_eq!(read_off(&f), after.len() as u64 - 100);
        // Under the cap nothing changes.
        trim_root_log(&f, 4000, 2000);
        assert_eq!(std::fs::read(&f).unwrap(), after);
        fsx::remove_rf(&d);
    }

    #[test]
    fn a_flush_copies_a_bounded_newest_part_then_cuts_the_engine_log() {
        let d = dir();
        let f = d.join("openvpn.log");
        let user = Log::capped(d.join("u.log"), 4 * FLUSH_MAX);
        let line = b"2026-10-23 21:45:00 write UDPv4: Network is unreachable (fd=5,code=51)\n";
        let n = (ROOT_LOG_MAX as usize * 2) / line.len();
        std::fs::write(&f, line.repeat(n)).unwrap();
        flush_root_log(&user, &f, "", false, &Masker::default());
        let copied = std::fs::read(d.join("u.log")).unwrap();
        assert!(copied.len() as u64 <= FLUSH_MAX + 200, "{}", copied.len());
        assert!(copied.starts_with("▶ [mvpn] ".as_bytes()), "the skip is noted");
        assert!(copied.ends_with(line));
        assert!(len(&f) <= ROOT_LOG_KEEP, "the engine log is cut");
        assert_eq!(read_off(&f), len(&f), "everything left is already copied");
        // A newer line is copied once.
        fsx::append(&f, b"tail line\n").unwrap();
        flush_root_log(&user, &f, "", false, &Masker::default());
        let again = std::fs::read(d.join("u.log")).unwrap();
        assert_eq!(&again[copied.len()..], b"tail line\n");
        // An offset beyond the file (cut by someone else) starts over instead of stopping forever.
        fsx::write_line(&off_path(&f), "999999999").unwrap();
        flush_root_log(&user, &f, "", false, &Masker::default());
        assert!(len(&d.join("u.log")) > again.len() as u64);
        fsx::remove_rf(&d);
    }
}
