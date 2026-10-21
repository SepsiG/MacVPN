//! `fsx` on Windows, phase 1 (compiled and clippy-checked on the Windows targets from Task 16 on; no `unsafe`).
//!
//! Real: opening without following a reparse point (`FILE_FLAG_OPEN_REPARSE_POINT`, then a handle whose attributes
//! say it is a reparse point is refused), `create_new`, `open_append`, the atomic replace (`rename` replaces the
//! target), the "unavailable" errors. Fail closed (`Unsupported`) wherever an owner or an owner-only ACL is needed:
//! `Access::Private`, `owner`, `has_access(Private)`, the private directories. Stable std has no file index, so
//! `file_id` is `None` and callers that compare identities refuse. Phase 2 replaces the fail-closed parts through the
//! platform layer.

use super::{Access, Follow, OpenFor, not_regular_file};
use std::convert::Infallible;
use std::fmt;
use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// No owner can be read in phase 1, so no value exists.
pub(super) type OwnerId = Infallible;
/// No file identity can be read in phase 1, so no value exists.
pub(super) type FileIdent = Infallible;

/// `FILE_FLAG_OPEN_REPARSE_POINT`: open the reparse point (a symlink, a junction) itself, never its target.
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

// The Win32 errors that mean "the file or its share cannot be reached right now" (the counterparts of the Unix
// errno list).
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PATH_NOT_FOUND: i32 = 3;
const ERROR_NOT_READY: i32 = 21;
const ERROR_BAD_NETPATH: i32 = 53;
const ERROR_NETNAME_DELETED: i32 = 64;
const ERROR_BAD_NET_NAME: i32 = 67;
const ERROR_SEM_TIMEOUT: i32 = 121;
const ERROR_NETWORK_UNREACHABLE: i32 = 1231;

fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "private files on Windows need the platform layer (phase 2)")
}

/// Refuses `Access::Private` (it needs an owner-only ACL).
fn require_shared(access: Access) -> io::Result<()> {
    match access {
        Access::Private => Err(unsupported()),
        Access::Shared => Ok(()),
    }
}

/// The refusal of a reparse point by `Follow::No` (recognized by [`is_symlink_refused`]).
struct SymlinkRefused;

impl fmt::Display for SymlinkRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the path is a symbolic link or another reparse point")
    }
}

impl fmt::Debug for SymlinkRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for SymlinkRefused {}

fn symlink_refused() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, SymlinkRefused)
}

fn is_reparse_point(meta: &Metadata) -> bool {
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

pub(super) fn create_private_dir_all(_dir: &Path) -> io::Result<()> {
    Err(unsupported())
}

pub(super) fn create_missing_private_dirs(_dir: &Path) -> io::Result<()> {
    Err(unsupported())
}

pub(super) fn ensure_private_dir(_dir: &Path) -> io::Result<OwnerId> {
    Err(unsupported())
}

pub(super) fn create_new(path: &Path, access: Access, read: bool) -> io::Result<File> {
    require_shared(access)?;
    OpenOptions::new().read(read).write(true).create_new(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path)
}

pub(super) fn open_regular(path: &Path, open: OpenFor, follow: Follow, _noctty: bool) -> io::Result<(File, Metadata)> {
    let mut options = OpenOptions::new();
    match open {
        OpenFor::Read => options.read(true),
        OpenFor::Write => options.write(true),
    };
    if follow == Follow::No {
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    if follow == Follow::No && is_reparse_point(&meta) {
        return Err(symlink_refused());
    }
    if !meta.file_type().is_file() {
        return Err(not_regular_file());
    }
    Ok((file, meta))
}

pub(super) fn open_append(path: &Path, access: Access) -> io::Result<File> {
    require_shared(access)?;
    let file = OpenOptions::new().append(true).create(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path)?;
    let meta = file.metadata()?;
    if is_reparse_point(&meta) {
        return Err(symlink_refused());
    }
    if !meta.file_type().is_file() {
        return Err(not_regular_file());
    }
    Ok(file)
}

pub(super) fn set_access(_file: &File, access: Access) -> io::Result<()> {
    require_shared(access)
}

pub(super) fn has_access(_meta: &Metadata, access: Access) -> bool {
    // Fail closed: a private file cannot be confirmed without reading its ACL.
    access == Access::Shared
}

pub(super) fn owner(_meta: &Metadata) -> io::Result<OwnerId> {
    Err(unsupported())
}

pub(super) fn file_id(_meta: &Metadata) -> Option<FileIdent> {
    None
}

/// Stable std has no link count on Windows (`nNumberOfLinks` needs `GetFileInformationByHandle`), so the count is
/// unknown. Fail closed: `u64::MAX` means "maybe shared", so `store::shred_file` only unlinks and never zeroes data
/// that another NTFS hard link may still name, the same as Unix does for `nlink > 1`. Phase 2 reads the real count
/// through the platform layer.
pub(super) fn hard_links(_meta: &Metadata) -> u64 {
    u64::MAX
}

pub(super) fn sync_dir(_dir: &Path) {}

pub(super) fn is_unavailable(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(
            ERROR_FILE_NOT_FOUND
                | ERROR_PATH_NOT_FOUND
                | ERROR_NOT_READY
                | ERROR_BAD_NETPATH
                | ERROR_NETNAME_DELETED
                | ERROR_BAD_NET_NAME
                | ERROR_SEM_TIMEOUT
                | ERROR_NETWORK_UNREACHABLE
        )
    )
}

pub(super) fn is_symlink_refused(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<SymlinkRefused>())
}
