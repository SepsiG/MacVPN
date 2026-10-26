//! `fsx` on Unix: the exact calls the call sites made before (plan Task 4's table).

use super::{Access, Follow, OpenFor, Stat, not_regular_file};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(super) type OwnerId = u32;
pub(super) type FileIdent = (u64, u64);
/// Unix needs nothing beyond the metadata.
pub(super) type Extra = ();

/// `fstat`.
pub(super) fn stat(file: &File) -> io::Result<Stat> {
    Ok(Stat { meta: file.metadata()?, extra: () })
}

/// `lstat` ([`Follow::No`]) or `stat` ([`Follow::Yes`]).
pub(super) fn stat_path(path: &Path, follow: Follow) -> io::Result<Stat> {
    let meta = match follow {
        Follow::No => fs::symlink_metadata(path)?,
        Follow::Yes => fs::metadata(path)?,
    };
    Ok(Stat { meta, extra: () })
}

fn file_mode(access: Access) -> u32 {
    match access {
        Access::Private => 0o600,
        Access::Shared => 0o644,
    }
}

fn dir_mode(access: Access) -> u32 {
    match access {
        Access::Private => 0o700,
        Access::Shared => 0o755,
    }
}

pub(super) fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    create_missing_private_dirs(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

pub(super) fn create_missing_private_dirs(dir: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(dir)
}

pub(super) fn ensure_private_dir(dir: &Path) -> io::Result<OwnerId> {
    if let Some(parent) = dir.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let not_a_dir = || io::Error::new(ErrorKind::NotADirectory, format!("{} is not a real directory", dir.display()));
    if !fs::symlink_metadata(dir)?.file_type().is_dir() {
        return Err(not_a_dir());
    }
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(dir)
        .map_err(|e| if e.raw_os_error() == Some(libc::ELOOP) { not_a_dir() } else { e })?;
    let meta = handle.metadata()?;
    if !meta.file_type().is_dir() {
        return Err(not_a_dir());
    }
    if meta.mode() & 0o7777 != 0o700 {
        handle.set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    Ok(meta.uid())
}

pub(super) fn create_new(path: &Path, access: Access, read: bool) -> io::Result<File> {
    OpenOptions::new()
        .read(read)
        .write(true)
        .create_new(true)
        .mode(file_mode(access))
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

pub(super) fn open_regular(path: &Path, open: OpenFor, follow: Follow, noctty: bool) -> io::Result<(File, Stat)> {
    let mut flags = libc::O_NONBLOCK;
    if follow == Follow::No {
        flags |= libc::O_NOFOLLOW;
    }
    if noctty {
        flags |= libc::O_NOCTTY;
    }
    let mut options = OpenOptions::new();
    match open {
        OpenFor::Read => options.read(true),
        OpenFor::Write => options.write(true),
    };
    let file = options.custom_flags(flags).open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(not_regular_file());
    }
    Ok((clear_nonblocking(file)?, Stat { meta, extra: () }))
}

/// Switches an open descriptor back to blocking I/O. Core has no `unsafe` (no `fcntl`): the descriptor is wrapped
/// for a moment in a `UnixStream`, whose `set_nonblocking` (`ioctl(FIONBIO)`) clears `O_NONBLOCK` on any
/// descriptor, a regular file included, and then unwrapped again.
fn clear_nonblocking(file: File) -> io::Result<File> {
    use std::os::fd::OwnedFd;
    let stream = std::os::unix::net::UnixStream::from(OwnedFd::from(file));
    stream.set_nonblocking(false)?;
    Ok(File::from(OwnedFd::from(stream)))
}

pub(super) fn open_append(path: &Path, access: Access) -> io::Result<File> {
    OpenOptions::new().append(true).create(true).mode(file_mode(access)).custom_flags(libc::O_NOFOLLOW).open(path)
}

pub(super) fn set_access(file: &File, access: Access) -> io::Result<()> {
    file.set_permissions(fs::Permissions::from_mode(file_mode(access)))
}

pub(super) fn has_access(stat: &Stat, access: Access) -> bool {
    let want = if stat.meta.is_dir() { dir_mode(access) } else { file_mode(access) };
    stat.meta.mode() & 0o7777 == want
}

pub(super) fn owner(stat: &Stat) -> io::Result<OwnerId> {
    Ok(stat.meta.uid())
}

pub(super) fn file_id(stat: &Stat) -> Option<FileIdent> {
    Some((stat.meta.dev(), stat.meta.ino()))
}

pub(super) fn hard_links(stat: &Stat) -> u64 {
    stat.meta.nlink()
}

pub(super) fn sync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

/// The errnos that mean "the source cannot be reached right now" (catalog spike decision B2).
pub(super) fn is_unavailable(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(
            libc::ENOENT
                | libc::ENOTDIR
                | libc::ENXIO
                | libc::EIO
                | libc::EHOSTDOWN
                | libc::EHOSTUNREACH
                | libc::ENETDOWN
                | libc::ENETUNREACH
                | libc::ENETRESET
                | libc::ECONNABORTED
                | libc::ECONNRESET
                | libc::ECONNREFUSED
                | libc::ENOTCONN
                | libc::ETIMEDOUT
                | libc::ESTALE
                | libc::EDEADLK
                | libc::EAGAIN
        )
    )
}

pub(super) fn is_symlink_refused(e: &io::Error) -> bool {
    e.raw_os_error() == Some(libc::ELOOP)
}

pub(super) fn is_separator(c: char) -> bool {
    c == '/'
}

pub(super) fn names_a_stream(_path: &Path) -> bool {
    false
}

pub(super) fn join_reference(base: &Path, reference: &str) -> Option<PathBuf> {
    if crate::swift_str::has_prefix(reference, "/") {
        return Some(PathBuf::from(reference));
    }
    // Not `Path::join`: a reference that starts with `/` plus a combining mark is relative for Swift (one Character),
    // and `join` would make it absolute.
    let mut joined = base.as_os_str().to_owned();
    joined.push("/");
    joined.push(reference);
    Some(PathBuf::from(joined))
}

/// `realpath`, as 1.5.0 (see `fsx::canonicalize_reference` for why a symlink is followed here).
pub(super) fn canonicalize_reference(_base: &Path, joined: &Path) -> io::Result<PathBuf> {
    fs::canonicalize(joined)
}

pub(super) fn is_outside_base(_e: &io::Error) -> bool {
    false
}
