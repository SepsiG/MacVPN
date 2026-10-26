//! The safe file operations: the only module of core with an OS `cfg` (spec 3). This file holds the portable types
//! and the steps that are the same everywhere; `unix.rs` and `windows.rs` hold the OS calls.
//!
//! On Unix every function does exactly what its call sites did before (the flags, the order of the checks and the
//! error kinds). On Windows the owner, the private and shared DACLs, the identity and the link count are read from
//! the open handle through `macvpn-winsys`; a check that cannot be completed fails closed.

use crate::models::uuid_string;
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as imp;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as imp;

/// Who may read a file or directory we create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Only the owner. Unix: files 0600, directories 0700.
    Private,
    /// Everyone may read. Unix: files 0644, directories 0755.
    Shared,
}

/// Whether the last path component may be a symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Follow {
    /// The last component is never a symlink (`O_NOFOLLOW`; Windows: no symlink or junction).
    No,
    Yes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFor {
    Read,
    Write,
}

/// Opaque owner identity (Unix: the uid; Windows: the SID string).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOwner(imp::OwnerId);

impl FileOwner {
    /// The owner with this uid (the platform layer knows the process's uid; core has no `getuid`).
    #[cfg(unix)]
    pub fn from_uid(uid: u32) -> FileOwner {
        FileOwner(uid)
    }

    /// The owner with this SID string (`S-1-5-21-…`).
    #[cfg(windows)]
    pub fn from_sid(sid: String) -> FileOwner {
        FileOwner(sid)
    }

    /// The user this process runs as (Windows knows it without the platform layer).
    #[cfg(windows)]
    pub fn current_user() -> io::Result<FileOwner> {
        macvpn_winsys::sid::Sid::current_user().map(|s| FileOwner(s.to_string()))
    }
}

/// Opaque file identity (Unix: (dev, ino); Windows: the volume serial number and the 128-bit file id).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId(imp::FileIdent);

/// Creates `dir` and its missing parents 0700, then sets `dir` itself to 0700 (an existing leaf is tightened; an
/// existing parent is left alone). `ConnectionStore::save`.
pub fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    imp::create_private_dir_all(dir)
}

/// Creates `dir` and its missing parents 0700; an existing directory keeps its mode (`ensure_private_parent`, the
/// app's vault directory).
pub fn create_missing_private_dirs(dir: &Path) -> io::Result<()> {
    imp::create_missing_private_dirs(dir)
}

/// Creates `dir` (0700) if missing (its parents with the default mode), refuses anything but a real directory (a
/// symlink included: `NotADirectory`), tightens its mode to 0700 through the open handle, and returns its owner.
pub fn ensure_private_dir(dir: &Path) -> io::Result<FileOwner> {
    imp::ensure_private_dir(dir).map(FileOwner)
}

/// A new file for writing: `create_new` (never an existing file or a symlink at the path), with `access`.
pub fn create_new(path: &Path, access: Access) -> io::Result<File> {
    imp::create_new(path, access, false)
}

/// [`create_new`] for reading and writing (the vault database).
pub fn create_new_rw(path: &Path, access: Access) -> io::Result<File> {
    imp::create_new(path, access, true)
}

/// What the system says about a file: its [`Metadata`] (`Stat` derefs to it) plus, where the platform reads them
/// from an open handle (Windows), the owner, the access shape, the identity and the link count.
#[derive(Debug, Clone)]
pub struct Stat {
    meta: Metadata,
    /// Unix: `()` (the metadata says it all). Windows: what the open handle says (`None` when it could not be
    /// read: every check then fails closed).
    #[cfg_attr(unix, allow(dead_code))]
    extra: imp::Extra,
}

impl std::ops::Deref for Stat {
    type Target = Metadata;
    fn deref(&self) -> &Metadata {
        &self.meta
    }
}

/// The open file's [`Stat`] (Unix: `fstat`).
pub fn stat(file: &File) -> io::Result<Stat> {
    imp::stat(file)
}

/// The [`Stat`] of the file at `path` (Unix: `lstat` for [`Follow::No`], `stat` for [`Follow::Yes`]).
pub fn stat_path(path: &Path, follow: Follow) -> io::Result<Stat> {
    imp::stat_path(path, follow)
}

/// Opens with `O_NONBLOCK` (never hangs on a FIFO), checks the open descriptor (`fstat`) and refuses anything but
/// a regular file ([`not_regular_file`]), then clears `O_NONBLOCK`. `follow`: [`Follow::No`] refuses a symlink as
/// the last component ([`is_symlink_refused`]). `noctty`: also `O_NOCTTY` (a swapped-in terminal never becomes
/// the controlling one). Returns the file and its [`Stat`].
pub fn open_regular(path: &Path, open: OpenFor, follow: Follow, noctty: bool) -> io::Result<(File, Stat)> {
    imp::open_regular(path, open, follow, noctty)
}

/// Opens for appending, creating the file with `access` if missing; never through a symlink.
pub fn open_append(path: &Path, access: Access) -> io::Result<File> {
    imp::open_append(path, access)
}

/// Sets the access of an open file (on the descriptor, never by path). Windows: the handle needs `WRITE_DAC`, which
/// the handles of [`create_new`], [`create_new_rw`] and [`open_append`] have.
pub fn set_access(file: &File, access: Access) -> io::Result<()> {
    imp::set_access(file, access)
}

/// Whether the permissions are exactly `access` (Unix: `mode & 0o7777` is 0600 / 0644 for a file, 0700 / 0755 for
/// a directory; Windows: the DACL shape, see `macvpn_winsys::file::Protection`).
pub fn has_access(stat: &Stat, access: Access) -> bool {
    imp::has_access(stat, access)
}

/// The owner of a file.
pub fn owner(stat: &Stat) -> io::Result<FileOwner> {
    imp::owner(stat).map(FileOwner)
}

/// The identity of a file; `None` where the platform cannot tell.
pub fn file_id(stat: &Stat) -> Option<FileId> {
    imp::file_id(stat).map(FileId)
}

/// The number of hard links, never less than the real one: where the platform cannot tell it is `u64::MAX`, so a
/// caller that acts only on a single link (`store::shred_file`) fails closed.
pub fn hard_links(stat: &Stat) -> u64 {
    imp::hard_links(stat)
}

/// Makes a rename in `dir` durable (an fsync of the directory). Best effort: errors are ignored.
pub fn sync_dir(dir: &Path) {
    imp::sync_dir(dir);
}

/// Writes `data` to `path` atomically: a temp file in the same directory ([`create_new`] with `access`), the data,
/// an fsync, a rename over `path` and [`sync_dir`]. The temp file is removed on any error. Never a state with wider
/// permissions, and no empty or truncated file after a power loss.
pub fn atomic_write(path: &Path, data: &[u8], access: Access) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(".tmp-{}", uuid_string(&Uuid::new_v4())));
    let result = (|| {
        let mut file = create_new(&tmp, access)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // Durability of the rename; if the directory cannot be opened, the write still succeeded.
    sync_dir(dir);
    Ok(())
}

/// The refusal of anything but a regular file: `InvalidInput`, "not a regular file".
pub fn not_regular_file() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, NotRegularFile)
}

/// Whether `e` is [`not_regular_file`]'s error (from [`open_regular`]).
pub fn is_not_regular_file(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<NotRegularFile>())
}

/// Whether `e` means "the file cannot be reached right now" (a missing file, a share or server that went away),
/// as opposed to a refusal.
pub fn is_unavailable(e: &io::Error) -> bool {
    imp::is_unavailable(e)
}

/// Whether `e` is the refusal of a symlink by [`Follow::No`] (Unix: `ELOOP`).
pub fn is_symlink_refused(e: &io::Error) -> bool {
    imp::is_symlink_refused(e)
}

/// Whether `c` separates path components in a path a user typed (Unix: `/`; Windows: `/` and `\`).
pub fn is_separator(c: char) -> bool {
    imp::is_separator(c)
}

/// Whether a referenced path names an alternate data stream (Windows: a component with `:` after the drive).
/// Always `false` on Unix, where `:` is an ordinary file name character.
pub fn names_a_stream(path: &Path) -> bool {
    imp::names_a_stream(path)
}

/// The path that `reference` (a file named in an imported config) stands for, relative to `base` (a canonical
/// directory), ready for `canonicalize`; `None` for a form that is refused before the file system is asked.
///
/// Unix: an absolute reference (Swift's Character-wise `hasPrefix("/")`) as it is, anything else `base/reference`
/// as text: exactly the string 1.5.0 handed to `realpath`.
///
/// Windows: only a drive with a root (`C:\…`, `C:/…`) is absolute. UNC (`\\server\share`), device (`\\.\…`),
/// verbatim (`\\?\…`), NT (`\??\…`), rooted (`\x`) and drive-relative (`C:x`) forms are `None`: no SMB
/// connection (which would send the user's credentials to the server) and no device is ever opened. The path is
/// built lexically in the verbatim form (`\\?\C:\…`; `.` is dropped and `..` removes the component before it,
/// as Win32's own path normalization does), so no reserved device name (`CON`, `NUL`, …) and no trimming of
/// trailing dots applies: every name is taken literally.
pub fn join_reference(base: &Path, reference: &str) -> Option<PathBuf> {
    imp::join_reference(base, reference)
}

/// The canonical path of `joined` (from [`join_reference`]), for the caller's containment check below `base` (a
/// canonical directory).
///
/// Unix: `realpath(joined)`, exactly as 1.5.0. A symlink inside the folder is followed: one that points at an
/// autofs or network mount (`/net/…`, `/Volumes/share`) reaches a share that is already mounted or mounts it with
/// the credentials macOS already holds; no new credentials are sent to a server named by the config.
///
/// Windows: refused ([`is_outside_base`]) before the file system is asked when `joined` is not lexically below
/// `base` (components compared case-insensitively). Then every name below `base` is opened as itself, one at a
/// time, and a name-surrogate reparse point (a symlink, a junction, a mount point) is refused the same way,
/// whatever its target: canonicalizing would follow it, and a target on a UNC path (`\\attacker\s\x`, say from a
/// mounted VHDX) would open an SMB session that sends the user's NTLM credentials before any containment check
/// runs. Other reparse points (Cloud Files placeholders, dedup) are walked through. Only then is the path
/// canonicalized.
pub fn canonicalize_reference(base: &Path, joined: &Path) -> io::Result<PathBuf> {
    imp::canonicalize_reference(base, joined)
}

/// Whether `e` is [`canonicalize_reference`]'s refusal of a path outside `base` or through a reparse point
/// (always `false` on Unix, where it is never refused).
pub fn is_outside_base(e: &io::Error) -> bool {
    imp::is_outside_base(e)
}

/// The marker inside [`not_regular_file`]'s error; it displays (and debug-prints) as the plain message did.
struct NotRegularFile;

impl fmt::Display for NotRegularFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a regular file")
    }
}

impl fmt::Debug for NotRegularFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt("not a regular file", f)
    }
}

impl std::error::Error for NotRegularFile {}
