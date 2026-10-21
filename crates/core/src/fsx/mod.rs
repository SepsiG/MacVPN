//! The safe file operations: the only module of core with an OS `cfg` (spec 3). This file holds the portable types
//! and the steps that are the same everywhere; `unix.rs` and `windows.rs` hold the OS calls.
//!
//! On Unix every function does exactly what its call sites did before (the flags, the order of the checks and the
//! error kinds). On Windows (phase 1) opening without following reparse points, the atomic replace and the
//! "unavailable" errors are real; anything that needs an owner check or an owner-only ACL fails closed with
//! [`io::ErrorKind::Unsupported`] until the platform layer provides it (phase 2).

use crate::models::uuid_string;
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Write};
use std::path::Path;
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
    /// The last component is never a symlink (`O_NOFOLLOW`; Windows: no reparse point).
    No,
    Yes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFor {
    Read,
    Write,
}

/// Opaque owner identity (Unix: the uid).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOwner(imp::OwnerId);

impl FileOwner {
    /// The owner with this uid (the platform layer knows the process's uid; core has no `getuid`).
    #[cfg(unix)]
    pub fn from_uid(uid: u32) -> FileOwner {
        FileOwner(uid)
    }
}

/// Opaque file identity (Unix: (dev, ino)).
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

/// Opens with `O_NONBLOCK` (never hangs on a FIFO), checks the open descriptor (`fstat`) and refuses anything but
/// a regular file ([`not_regular_file`]), then clears `O_NONBLOCK`. `follow`: [`Follow::No`] refuses a symlink as
/// the last component ([`is_symlink_refused`]). `noctty`: also `O_NOCTTY` (a swapped-in terminal never becomes
/// the controlling one). Returns the file and the metadata of the open descriptor.
pub fn open_regular(path: &Path, open: OpenFor, follow: Follow, noctty: bool) -> io::Result<(File, Metadata)> {
    imp::open_regular(path, open, follow, noctty)
}

/// Opens for appending, creating the file with `access` if missing; never through a symlink.
pub fn open_append(path: &Path, access: Access) -> io::Result<File> {
    imp::open_append(path, access)
}

/// Sets the access of an open file (on the descriptor, never by path).
pub fn set_access(file: &File, access: Access) -> io::Result<()> {
    imp::set_access(file, access)
}

/// Whether the permissions are exactly `access` (Unix: `mode & 0o7777` is 0600 / 0644 for a file, 0700 / 0755 for
/// a directory).
pub fn has_access(meta: &Metadata, access: Access) -> bool {
    imp::has_access(meta, access)
}

/// The owner of a file.
pub fn owner(meta: &Metadata) -> io::Result<FileOwner> {
    imp::owner(meta).map(FileOwner)
}

/// The identity of a file; `None` where the platform cannot tell (Windows in phase 1).
pub fn file_id(meta: &Metadata) -> Option<FileId> {
    imp::file_id(meta).map(FileId)
}

/// The number of hard links, never less than the real one: where the platform cannot tell (Windows in phase 1) it
/// is `u64::MAX`, so a caller that acts only on a single link (`store::shred_file`) fails closed.
pub fn hard_links(meta: &Metadata) -> u64 {
    imp::hard_links(meta)
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
