//! Small file helpers with the root layer's rules: never follow a symlink when creating or reading a private
//! file, bounded reads, `rm -rf` that never follows links.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// Upper bound for the small state files of a run directory (`kind`, `pid`, `iface`, …).
const SMALL_MAX: u64 = 64 * 1024;

/// The bash `$(cat f 2>/dev/null)`: the content with trailing newlines removed; `None` if unreadable.
/// Only for small files (at most 64 KB are read).
pub fn read_trim(p: &Path) -> Option<String> {
    let f = File::open(p).ok()?;
    let mut data = Vec::new();
    f.take(SMALL_MAX).read_to_end(&mut data).ok()?;
    while data.last() == Some(&b'\n') {
        data.pop();
    }
    Some(String::from_utf8_lossy(&data).into_owned())
}

/// Like [`read_trim`], empty when unreadable.
pub fn cat(p: &Path) -> String {
    read_trim(p).unwrap_or_default()
}

/// A regular file (not a symlink, not following one), at most `max` bytes, read whole.
pub fn read_private(p: &Path, max: u64) -> Option<Vec<u8>> {
    let mut f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(p).ok()?;
    let meta = f.metadata().ok()?;
    if !meta.file_type().is_file() || meta.len() > max {
        return None;
    }
    let mut data = Vec::with_capacity(meta.len() as usize);
    (&mut f).take(max + 1).read_to_end(&mut data).ok()?;
    (data.len() as u64 <= max).then_some(data)
}

/// Creates or truncates a file without following a symlink, with `mode` for a new file (umask applies).
pub fn write_file(p: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let mut f =
        OpenOptions::new().write(true).create(true).truncate(true).mode(mode).custom_flags(libc::O_NOFOLLOW).open(p)?;
    f.write_all(data)
}

/// Creates a new file (`O_EXCL`, so never through a symlink or over an existing file) with `mode` and `data`.
pub fn create_new(p: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).mode(mode).custom_flags(libc::O_NOFOLLOW).open(p)?;
    f.write_all(data)
}

/// `printf '%s\n' value >file`
pub fn write_line(p: &Path, value: &str) -> std::io::Result<()> {
    write_file(p, format!("{value}\n").as_bytes(), 0o600)
}

/// Appends without following a symlink (creating the file 0600 if needed).
pub fn append(p: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new().append(true).create(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(p)?;
    f.write_all(data)
}

/// The bash `rm -rf`: a symlink or file is unlinked, a directory removed recursively (links inside are not
/// followed). Errors are ignored.
pub fn remove_rf(p: &Path) {
    match fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_dir() => {
            let _ = fs::remove_dir_all(p);
        }
        Ok(_) => {
            let _ = fs::remove_file(p);
        }
        Err(_) => {}
    }
}

/// The bash `rm -f`.
pub fn remove_file(p: &Path) {
    if fs::symlink_metadata(p).is_ok_and(|m| !m.file_type().is_dir()) {
        let _ = fs::remove_file(p);
    }
}

/// `stat -f %z` (no symlink followed).
pub fn size(p: &Path) -> Option<u64> {
    fs::symlink_metadata(p).ok().map(|m| m.len())
}

/// `chmod` of a path that is known not to be a symlink (checked again here).
pub fn chmod(p: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let m = fs::symlink_metadata(p)?;
    if m.file_type().is_symlink() {
        return Err(std::io::Error::other("symlink"));
    }
    fs::set_permissions(p, fs::Permissions::from_mode(mode))
}

/// The modification time in nanoseconds since the epoch (no symlink followed).
pub fn mtime_ns(p: &Path) -> Option<i128> {
    fs::symlink_metadata(p).ok().map(|m| i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()))
}

/// The modification time in whole seconds (`stat -f %m`, which follows a symlink).
pub fn mtime_secs(p: &Path) -> Option<i64> {
    fs::metadata(p).ok().map(|m| m.mtime())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("mvpn-fsx-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&d).unwrap();
        d
    }

    #[test]
    fn read_trim_strips_trailing_newlines_only() {
        let d = tmp();
        fs::write(d.join("a"), "x y\n\n").unwrap();
        assert_eq!(read_trim(&d.join("a")).as_deref(), Some("x y"));
        assert_eq!(read_trim(&d.join("missing")), None);
        remove_rf(&d);
    }

    #[test]
    fn private_files_refuse_symlinks() {
        let d = tmp();
        fs::write(d.join("target"), "secret").unwrap();
        std::os::unix::fs::symlink(d.join("target"), d.join("link")).unwrap();
        assert!(read_private(&d.join("link"), 100).is_none());
        assert!(write_file(&d.join("link"), b"x", 0o600).is_err());
        assert_eq!(fs::read(d.join("target")).unwrap(), b"secret");
        assert_eq!(read_private(&d.join("target"), 100).unwrap(), b"secret");
        assert!(read_private(&d.join("target"), 3).is_none());
        remove_rf(&d.join("link"));
        assert!(d.join("target").exists());
        remove_rf(&d);
        assert!(!d.exists());
    }
}
