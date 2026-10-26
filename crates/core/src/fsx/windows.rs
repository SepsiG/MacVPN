//! `fsx` on Windows. The owner (a SID string), the DACL shape, the 128-bit file id and the link count come from the
//! open handle through `macvpn-winsys` (core holds no `unsafe`). `Access::Private` is the protected DACL "this user
//! and SYSTEM" with the owner set to this user, `Access::Shared` adds read for `BUILTIN\Users`
//! (`macvpn_winsys::file::Protection`); directories carry the same ACEs inheritable to files and subdirectories.
//!
//! Reparse points: `Follow::No` refuses name surrogates (symlinks, junctions); other reparse points (Cloud Files
//! placeholders, dedup) are the file itself and are reopened normally, checked to be the same file. `Follow::Yes`
//! leaves following to the system: a symlink is followed; a junction a standard user made is refused by Windows 11's
//! redirection guard (`ERROR_UNTRUSTED_MOUNT_POINT`, 448), and that error is returned as it is (refused, never
//! assumed safe). Whatever cannot be read fails closed: no owner, no access, no identity, `u64::MAX` links.

use super::{Access, Follow, OpenFor, Stat, not_regular_file};
use macvpn_winsys::file::{self as wfile, Disposition, Info, Open, Protection};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf, Prefix};

/// The owner's SID in its string form (`S-1-5-21-…`).
pub(super) type OwnerId = String;
/// The volume serial number and the 128-bit file id.
pub(super) type FileIdent = (u64, [u8; 16]);
/// What the handle said (`None`: it could not be read; every check then fails closed).
pub(super) type Extra = Option<Info>;

/// `FILE_FLAG_OPEN_REPARSE_POINT`: open the reparse point (a symlink, a junction) itself, never its target.
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const ERROR_ACCESS_DENIED: i32 = 5;

// The Win32 errors that mean "the file or its share cannot be reached right now" (the counterparts of the Unix
// errno list); the Cloud Files ones come from `macvpn_winsys::file::is_cloud_unavailable`.
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PATH_NOT_FOUND: i32 = 3;
const ERROR_NOT_READY: i32 = 21;
const ERROR_BAD_NETPATH: i32 = 53;
const ERROR_NETNAME_DELETED: i32 = 64;
const ERROR_BAD_NET_NAME: i32 = 67;
const ERROR_SEM_TIMEOUT: i32 = 121;
const ERROR_NETWORK_UNREACHABLE: i32 = 1231;

fn protection(access: Access) -> Protection {
    match access {
        Access::Private => Protection::Private,
        Access::Shared => Protection::Shared,
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

fn not_a_dir(dir: &Path) -> io::Error {
    io::Error::new(io::ErrorKind::NotADirectory, format!("{} is not a real directory", dir.display()))
}

pub(super) fn stat(file: &File) -> io::Result<Stat> {
    Ok(Stat { meta: file.metadata()?, extra: wfile::info(file).ok() })
}

pub(super) fn stat_path(path: &Path, follow: Follow) -> io::Result<Stat> {
    match wfile::open_metadata(path, follow == Follow::Yes) {
        Ok(handle) => Ok(Stat { meta: handle.metadata()?, extra: wfile::info(&handle).ok() }),
        // No `READ_CONTROL` on someone else's file: its metadata as std reads it (as before), with nothing for the
        // checks (no owner, no access, no identity).
        Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
            let meta = match follow {
                Follow::No => fs::symlink_metadata(path)?,
                Follow::Yes => fs::metadata(path)?,
            };
            Ok(Stat { meta, extra: None })
        }
        Err(e) => Err(e),
    }
}

pub(super) fn create_missing_private_dirs(dir: &Path) -> io::Result<()> {
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        create_missing_private_dirs(parent)?;
    }
    match wfile::create_dir(dir, Some(Protection::Private)) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => Ok(()),
        other => other,
    }
}

pub(super) fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    create_missing_private_dirs(dir)?;
    let handle = wfile::open_dir(dir, true)?;
    wfile::set_protection(&handle, Protection::Private, true)
}

pub(super) fn ensure_private_dir(dir: &Path) -> io::Result<OwnerId> {
    if let Some(parent) = dir.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    match wfile::create_dir(dir, Some(Protection::Private)) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let handle = wfile::open_dir(dir, false).map_err(|e| {
        // A file (not a directory) at the name may answer ERROR_ACCESS_DENIED here.
        if fs::symlink_metadata(dir).is_ok_and(|m| !m.is_dir()) { not_a_dir(dir) } else { e }
    })?;
    let info = wfile::info(&handle)?;
    if info.reparse_tag.is_some() || info.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(not_a_dir(dir));
    }
    if info.protection != Some(Protection::Private) {
        wfile::set_protection(&handle, Protection::Private, true)?;
    }
    Ok(info.owner.to_string())
}

pub(super) fn create_new(path: &Path, access: Access, read: bool) -> io::Result<File> {
    wfile::open(
        path,
        Open {
            read,
            write: true,
            append: false,
            disposition: Disposition::CreateNew,
            protection: Some(protection(access)),
            no_follow: true,
        },
    )
}

pub(super) fn open_regular(path: &Path, open: OpenFor, follow: Follow, _noctty: bool) -> io::Result<(File, Stat)> {
    let options = |reparse: bool| {
        let mut o = OpenOptions::new();
        match open {
            OpenFor::Read => o.read(true),
            OpenFor::Write => o.write(true),
        };
        if reparse {
            o.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        o
    };
    let file = options(follow == Follow::No).open(path).map_err(|e| {
        // A directory (or a directory junction opened as itself) cannot be opened as a file (ERROR_ACCESS_DENIED):
        // the Unix "not a regular file" and "symlink refused".
        if e.raw_os_error() != Some(ERROR_ACCESS_DENIED) {
            return e;
        }
        match fs::symlink_metadata(path) {
            Ok(m) if follow == Follow::No && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                symlink_refused()
            }
            Ok(m) if m.is_dir() => not_regular_file(),
            _ => e,
        }
    })?;
    let (file, info) = match wfile::info(&file) {
        Ok(info) => match info.reparse_tag {
            Some(tag) if follow == Follow::No && wfile::is_name_surrogate(tag) => return Err(symlink_refused()),
            Some(_) if follow == Follow::No => {
                // A placeholder (or another non-surrogate reparse point) is the file itself: open it normally
                // (which hydrates a placeholder) and make sure it is still the same file.
                let again = options(false).open(path)?;
                let again_info = wfile::info(&again)?;
                if (again_info.volume, again_info.id) != (info.volume, info.id) {
                    return Err(symlink_refused());
                }
                (again, Some(again_info))
            }
            _ => (file, Some(info)),
        },
        // The handle's security or identity cannot be read (a file system without them): the file can still be
        // read, but no reparse point passes `Follow::No`, and every owner, access and identity check fails closed.
        Err(_) => {
            if follow == Follow::No && file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(symlink_refused());
            }
            (file, None)
        }
    };
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(not_regular_file());
    }
    Ok((file, Stat { meta, extra: info }))
}

pub(super) fn open_append(path: &Path, access: Access) -> io::Result<File> {
    let file = wfile::open(
        path,
        Open {
            read: false,
            write: false,
            append: true,
            disposition: Disposition::OpenOrCreate,
            protection: Some(protection(access)),
            no_follow: true,
        },
    )?;
    let info = wfile::info(&file)?;
    if info.reparse_tag.is_some_and(wfile::is_name_surrogate) {
        return Err(symlink_refused());
    }
    if !file.metadata()?.file_type().is_file() {
        return Err(not_regular_file());
    }
    Ok(file)
}

pub(super) fn set_access(file: &File, access: Access) -> io::Result<()> {
    wfile::set_protection(file, protection(access), file.metadata()?.is_dir())
}

pub(super) fn has_access(stat: &Stat, access: Access) -> bool {
    stat.extra.as_ref().is_some_and(|i| i.protection == Some(protection(access)))
}

pub(super) fn owner(stat: &Stat) -> io::Result<OwnerId> {
    stat.extra
        .as_ref()
        .map(|i| i.owner.to_string())
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "the file's owner could not be read"))
}

pub(super) fn file_id(stat: &Stat) -> Option<FileIdent> {
    stat.extra.as_ref().map(|i| (i.volume, i.id))
}

/// `u64::MAX` when unknown: `store::shred_file` then only unlinks (fail closed).
pub(super) fn hard_links(stat: &Stat) -> u64 {
    stat.extra.as_ref().map_or(u64::MAX, |i| u64::from(i.links))
}

/// NTFS journals the rename's metadata; flushing a directory handle needs write access to it and gives nothing
/// more.
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
    ) || e.raw_os_error().is_some_and(wfile::is_cloud_unavailable)
}

pub(super) fn is_symlink_refused(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<SymlinkRefused>())
}

pub(super) fn is_separator(c: char) -> bool {
    c == '/' || c == '\\'
}

/// A `Normal` component with a `:` (the drive is a `Prefix` component, so `C:\x` is not a stream).
pub(super) fn names_a_stream(path: &Path) -> bool {
    path.components().any(|c| matches!(c, Component::Normal(name) if name.to_string_lossy().contains(':')))
}

pub(super) fn join_reference(base: &Path, reference: &str) -> Option<PathBuf> {
    let mut components = Path::new(reference).components().peekable();
    let mut joined = match components.peek() {
        Some(Component::Prefix(prefix)) => {
            let Prefix::Disk(drive) = prefix.kind() else { return None };
            components.next();
            if components.next() != Some(Component::RootDir) {
                return None;
            }
            PathBuf::from(format!(r"\\?\{}:\", char::from(drive)))
        }
        Some(Component::RootDir) => return None,
        _ => base.to_path_buf(),
    };
    for component in components {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                joined.pop();
            }
            Component::Normal(name) => joined.push(name),
            Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    Some(joined)
}

/// The refusal of `canonicalize_reference`: outside the base, or through a reparse point.
struct OutsideBase;

impl fmt::Display for OutsideBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the path is not below the folder, or leads through a symbolic link or junction")
    }
}

impl fmt::Debug for OutsideBase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for OutsideBase {}

fn outside_base() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, OutsideBase)
}

pub(super) fn is_outside_base(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<OutsideBase>())
}

/// The names of `joined` below `base`, compared lexically (no file system call): `None` unless `joined` starts with
/// every component of `base` (the prefix and the names compared case-insensitively, as NTFS does) and has at least
/// one plain name more. A component that is not UTF-8 never matches.
pub(super) fn names_below<'a>(base: &Path, joined: &'a Path) -> Option<Vec<&'a std::ffi::OsStr>> {
    let same = |a: Component<'_>, b: Component<'_>| match (a.as_os_str().to_str(), b.as_os_str().to_str()) {
        (Some(a), Some(b)) => a.to_lowercase() == b.to_lowercase(),
        _ => false,
    };
    let mut rest = joined.components();
    for b in base.components() {
        if !same(b, rest.next()?) {
            return None;
        }
    }
    let names: Vec<_> = rest
        .map(|c| match c {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect::<Option<_>>()?;
    (!names.is_empty()).then_some(names)
}

pub(super) fn canonicalize_reference(base: &Path, joined: &Path) -> io::Result<PathBuf> {
    let names = names_below(base, joined).ok_or_else(outside_base)?;
    let mut path = base.to_path_buf();
    for name in names {
        path.push(name);
        if wfile::reparse_tag_at(&path)?.is_some_and(wfile::is_name_surrogate) {
            return Err(outside_base());
        }
    }
    fs::canonicalize(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lexical step decides without the file system: another drive, the base itself, a sibling with the base's
    /// name as a prefix and a path above the base are refused; case does not matter.
    #[test]
    fn names_below_is_lexical_and_case_insensitive() {
        let base = Path::new(r"\\?\C:\Users\me\vpn");
        let below = |p: &str| names_below(base, Path::new(p)).map(|n| n.len());
        assert_eq!(below(r"\\?\C:\Users\me\vpn\ca.crt"), Some(1));
        assert_eq!(below(r"\\?\c:\USERS\Me\VPN\sub\ca.crt"), Some(2));
        for outside in [
            r"\\?\C:\other\x",
            r"C:\other\x",
            r"\\?\D:\Users\me\vpn\ca.crt",
            r"\\?\C:\Users\me\vpn",
            r"\\?\C:\Users\me\vpn2\ca.crt",
            r"\\?\C:\Users\me",
            r"\\?\UNC\127.0.0.1\nonexistent\x",
            r"\\127.0.0.1\nonexistent\x",
        ] {
            assert_eq!(below(outside), None, "{outside}");
        }
        // `canonicalize_reference` refuses it with the marker before anything is opened (the path does not exist:
        // a file system call would say NotFound).
        let err = canonicalize_reference(base, Path::new(r"\\?\C:\other\x")).unwrap_err();
        assert!(is_outside_base(&err), "{err}");
        assert!(!is_outside_base(&io::Error::from(io::ErrorKind::NotFound)));
    }
}
