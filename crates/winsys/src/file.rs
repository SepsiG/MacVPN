//! Files and directories with an explicit owner and DACL, and what an open handle says about its file.

use crate::security::{Ace, Acl, Descriptor};
use crate::sid::Sid;
use crate::util::{LocalBox, check, wide_path};
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT, SE_KERNEL_OBJECT, SetSecurityInfo};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorControl,
    INHERITED_ACE, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS, FILE_APPEND_DATA,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_INFO,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
    FileAttributeTagInfo, FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx, OPEN_ALWAYS,
    OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE, WRITE_DAC,
};

/// The DACL shapes MacVPN creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// Protected (nothing inherited): the owner and SYSTEM, full access; nobody else (Unix 0600 / 0700).
    Private,
    /// Protected: the owner and SYSTEM full access, `BUILTIN\Users` read (Unix 0644 / 0755).
    Shared,
    /// Protected: SYSTEM and `BUILTIN\Administrators` full access, nobody else, whoever the owner is (the WinVPN
    /// Service's `C:\ProgramData\WinVPN`; created as SYSTEM, the owner is SYSTEM).
    Admins,
    /// Protected: the owner and SYSTEM full access, `BUILTIN\Administrators` read and write (`FILE_GENERIC_READ |
    /// FILE_GENERIC_WRITE`: never `DELETE`, `WRITE_DAC` or `WRITE_OWNER`), nobody else. A file of this user that an
    /// elevated step must write (msiexec's update log): with over-the-shoulder UAC a standard user's prompt asks
    /// for an administrator's credentials, and the elevated program runs as *that* account, which [`Private`]
    /// leaves out. Files only; the folder above can stay private (every account has "Bypass traverse checking").
    ///
    /// [`Private`]: Protection::Private
    AdminsReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Fails with `AlreadyExists` when anything (a file, a link) has the name.
    CreateNew,
    OpenOrCreate,
    OpenExisting,
}

/// How [`open`] opens or creates a file.
#[derive(Debug, Clone, Copy)]
pub struct Open {
    pub read: bool,
    pub write: bool,
    /// Writes always go to the end (`FILE_APPEND_DATA` without `FILE_WRITE_DATA`).
    pub append: bool,
    pub disposition: Disposition,
    /// The DACL of a newly created file (owner = this user); `None`: the folder's inherited permissions. Not
    /// applied to a file that already exists.
    pub protection: Option<Protection>,
    /// Open a reparse point itself, never its target.
    pub no_follow: bool,
}

impl Open {
    /// Write, create new, private, never through a reparse point: `fsx::create_new`'s defaults.
    pub fn create_new() -> Open {
        Open {
            read: false,
            write: true,
            append: false,
            disposition: Disposition::CreateNew,
            protection: Some(Protection::Private),
            no_follow: true,
        }
    }
}

/// What an open handle says about its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub owner: Sid,
    /// The DACL's shape: one of MacVPN's, or `None` (inherited or anything else).
    pub protection: Option<Protection>,
    pub volume: u64,
    /// The 128-bit file id (ReFS needs all of it; NTFS uses the low 64 bits).
    pub id: [u8; 16],
    pub links: u32,
    pub attributes: u32,
    /// The reparse tag when the handle is a reparse point (opened with `no_follow`).
    pub reparse_tag: Option<u32>,
}

/// `BUILTIN\Users`' rights in [`Protection::Shared`].
const USERS_READ: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
/// `BUILTIN\Administrators`' rights in [`Protection::AdminsReadWrite`]: read, write, append, attributes; no delete,
/// no `WRITE_DAC`, no `WRITE_OWNER`.
const ADMINS_READ_WRITE: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE;

fn descriptor(protection: Protection, dir: bool) -> io::Result<Box<Descriptor>> {
    descriptor_owned(Sid::current_user()?, protection, dir)
}

fn descriptor_owned(owner: Sid, protection: Protection, dir: bool) -> io::Result<Box<Descriptor>> {
    let system = Sid::local_system();
    let flags = if dir { OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE } else { 0 };
    let acl = match protection {
        Protection::Private => {
            Acl::new(&[Ace::Allow(&owner, FILE_ALL_ACCESS), Ace::Allow(&system, FILE_ALL_ACCESS)], flags)?
        }
        Protection::Shared => {
            let users = Sid::builtin_users();
            Acl::new(
                &[
                    Ace::Allow(&owner, FILE_ALL_ACCESS),
                    Ace::Allow(&system, FILE_ALL_ACCESS),
                    Ace::Allow(&users, USERS_READ),
                ],
                flags,
            )?
        }
        Protection::Admins => {
            let admins = Sid::builtin_administrators();
            Acl::new(&[Ace::Allow(&system, FILE_ALL_ACCESS), Ace::Allow(&admins, FILE_ALL_ACCESS)], flags)?
        }
        Protection::AdminsReadWrite => {
            let admins = Sid::builtin_administrators();
            Acl::new(
                &[
                    Ace::Allow(&owner, FILE_ALL_ACCESS),
                    Ace::Allow(&system, FILE_ALL_ACCESS),
                    Ace::Allow(&admins, ADMINS_READ_WRITE),
                ],
                flags,
            )?
        }
    };
    Descriptor::new(owner, acl)
}

fn handle_to_file(handle: HANDLE) -> io::Result<File> {
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a valid handle that CreateFileW just returned and nobody else owns; the File closes it on drop.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(handle) }))
}

const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

/// Opens or creates `path` as `o` says. Every handle also has `READ_CONTROL` and `FILE_READ_ATTRIBUTES` (for
/// [`info`]) and, for a writable one, `WRITE_DAC` (for [`set_protection`]). Sharing as std's default (read, write,
/// delete), so renames over the file keep working.
pub fn open(path: &Path, o: Open) -> io::Result<File> {
    let name = wide_path(path)?;
    let mut access = READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    if o.read {
        access |= FILE_GENERIC_READ;
    }
    if o.append {
        access |= FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | WRITE_DAC;
    } else if o.write {
        access |= FILE_GENERIC_WRITE | WRITE_DAC;
    }
    let disposition = match o.disposition {
        Disposition::CreateNew => CREATE_NEW,
        Disposition::OpenOrCreate => OPEN_ALWAYS,
        Disposition::OpenExisting => OPEN_EXISTING,
    };
    let flags = FILE_ATTRIBUTE_NORMAL | if o.no_follow { FILE_FLAG_OPEN_REPARSE_POINT } else { 0 };
    let sd = o.protection.map(|p| descriptor(p, false)).transpose()?;
    let sa = sd.as_ref().map_or(std::ptr::null(), |d| d.attributes());
    // SAFETY: `name` is NUL-terminated; `sa` is null or points into `sd`, which lives across the call.
    let handle = unsafe { CreateFileW(name.as_ptr(), access, SHARE_ALL, sa, disposition, flags, std::ptr::null_mut()) };
    handle_to_file(handle)
}

/// Creates one directory (not its parents) with `protection` (inheritable to what is created inside), or with
/// the parent's inherited permissions for `None`.
pub fn create_dir(path: &Path, protection: Option<Protection>) -> io::Result<()> {
    let name = wide_path(path)?;
    let sd = protection.map(|p| descriptor(p, true)).transpose()?;
    let sa = sd.as_ref().map_or(std::ptr::null(), |d| d.attributes());
    // SAFETY: `name` is NUL-terminated; `sa` is null or points into `sd`, which lives across the call.
    check(unsafe { CreateDirectoryW(name.as_ptr(), sa) })
}

/// [`create_dir`] with `protection` and `owner` as the folder's owner instead of this user. An elevated
/// administrator passes `BUILTIN\Administrators`: an owner has implicit `READ_CONTROL | WRITE_DAC`, so a folder
/// owned by the user would let the same user's unelevated processes rewrite its DACL. The token must allow `owner`
/// as an owner (else `ERROR_INVALID_OWNER`).
pub fn create_dir_owned(path: &Path, protection: Protection, owner: &Sid) -> io::Result<()> {
    let name = wide_path(path)?;
    let sd = descriptor_owned(owner.clone(), protection, true)?;
    // SAFETY: `name` is NUL-terminated; the attributes point into `sd`, which lives across the call.
    check(unsafe { CreateDirectoryW(name.as_ptr(), sd.attributes()) })
}

/// A new file (`CREATE_NEW`: never over an existing file or link, never through a reparse point) opened for
/// reading and writing, with `protection` and `owner` as its owner (see [`create_dir_owned`]). Shared for reading
/// only while this handle is open.
pub fn create_new_owned(path: &Path, protection: Protection, owner: &Sid) -> io::Result<File> {
    let name = wide_path(path)?;
    let access = READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE | FILE_GENERIC_READ | FILE_GENERIC_WRITE;
    let sd = descriptor_owned(owner.clone(), protection, false)?;
    // SAFETY: `name` is NUL-terminated; the attributes point into `sd`, which lives across the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ,
            sd.attributes(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    handle_to_file(handle)
}

/// Opens a directory (or any file) for its metadata and DACL: `READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES`,
/// with backup semantics (needed for directories; no privilege is used). `follow`: `false` opens a reparse point
/// itself.
pub fn open_dir(path: &Path, follow: bool) -> io::Result<File> {
    open_for_metadata(path, follow, READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
}

/// Like [`open_dir`] without `WRITE_DAC`: for reading only (`fsx::stat_path`).
pub fn open_metadata(path: &Path, follow: bool) -> io::Result<File> {
    open_for_metadata(path, follow, READ_CONTROL | FILE_READ_ATTRIBUTES)
}

/// The reparse tag of the file or directory at `path` itself (`None`: no reparse point). The name is opened with
/// `FILE_READ_ATTRIBUTES` only (no content, no DACL needed) and `FILE_FLAG_OPEN_REPARSE_POINT`: a symlink or
/// junction is never followed, so its target (a UNC path, and with it an SMB session) is never touched.
pub fn reparse_tag_at(path: &Path) -> io::Result<Option<u32>> {
    let file = open_for_metadata(path, false, FILE_READ_ATTRIBUTES)?;
    // SAFETY: plain data (integers); all zero is valid.
    let mut tag: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open (borrowed from `file`); `tag` is valid for writes of the size passed, the size of
    // the class's structure.
    check(unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast::<c_void>(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    })?;
    Ok((tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0).then_some(tag.ReparseTag))
}

/// Tests only: turns the empty directory `link` into a junction whose target is the NT path `target` as given
/// (`\??\C:\dir`, or a target `mklink /J` refuses, such as `\??\UNC\server\share`), with
/// `FSCTL_SET_REPARSE_POINT`. Needs no privilege on a directory the user owns.
#[doc(hidden)]
pub fn make_junction_for_tests(link: &Path, target: &str) -> io::Result<()> {
    const FSCTL_SET_REPARSE_POINT: u32 = 0x0009_00A4;
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
    let file = open_for_metadata(link, false, FILE_GENERIC_WRITE)?;
    let substitute: Vec<u16> = target.encode_utf16().collect();
    let name_bytes = u16::try_from(substitute.len() * 2).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // The mount point layout of REPARSE_DATA_BUFFER: the substitute name, NUL, an empty print name, NUL.
    let mut path_buffer = substitute;
    path_buffer.extend([0, 0]);
    let mut data = Vec::new();
    data.extend(0u16.to_le_bytes()); // SubstituteNameOffset
    data.extend(name_bytes.to_le_bytes()); // SubstituteNameLength
    data.extend((name_bytes + 2).to_le_bytes()); // PrintNameOffset
    data.extend(0u16.to_le_bytes()); // PrintNameLength
    data.extend(path_buffer.iter().flat_map(|c| c.to_le_bytes()));
    let mut buffer = Vec::new();
    buffer.extend(IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buffer.extend(u16::try_from(data.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?.to_le_bytes());
    buffer.extend(0u16.to_le_bytes()); // Reserved
    buffer.extend(data);
    let mut returned = 0u32;
    // SAFETY: the handle is open (borrowed from `file`); the input buffer is valid for reads of its length; no output
    // buffer; synchronous (no OVERLAPPED).
    check(unsafe {
        windows_sys::Win32::System::IO::DeviceIoControl(
            file.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            buffer.as_ptr().cast::<c_void>(),
            buffer.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    })
}

fn open_for_metadata(path: &Path, follow: bool, access: u32) -> io::Result<File> {
    let name = wide_path(path)?;
    let flags = FILE_FLAG_BACKUP_SEMANTICS | if follow { 0 } else { FILE_FLAG_OPEN_REPARSE_POINT };
    // SAFETY: `name` is NUL-terminated; no security attributes (nothing is created).
    let handle = unsafe {
        CreateFileW(name.as_ptr(), access, SHARE_ALL, std::ptr::null(), OPEN_EXISTING, flags, std::ptr::null_mut())
    };
    handle_to_file(handle)
}

/// Owner, DACL shape, identity, link count, attributes and reparse tag of an open file. The handle needs
/// `READ_CONTROL` and `FILE_READ_ATTRIBUTES` (every handle std opens for reading or writing has them). Any part
/// that cannot be read is an error, never a default.
pub fn info(file: &File) -> io::Result<Info> {
    let h = file.as_raw_handle();
    let (owner, protection) = owner_and_protection(h)?;
    // SAFETY: plain data (integers); all zero is valid and the call below fills it in.
    let mut basic: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `h` is an open handle (borrowed from `file`); `basic` is a valid out pointer of the right type.
    check(unsafe { GetFileInformationByHandle(h, &mut basic) })?;
    // SAFETY: plain data (integers and a byte array); all zero is valid.
    let mut id_info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: `id_info` is valid for writes of the size passed, the size of the class's structure.
    let have_id = unsafe {
        GetFileInformationByHandleEx(
            h,
            FileIdInfo,
            (&mut id_info as *mut FILE_ID_INFO).cast::<c_void>(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } != 0;
    let (volume, id) = if have_id {
        (id_info.VolumeSerialNumber, id_info.FileId.Identifier)
    } else {
        // FAT and some network file systems have no 128-bit id: the 64-bit index of the basic information.
        let mut id = [0u8; 16];
        let index = (u64::from(basic.nFileIndexHigh) << 32) | u64::from(basic.nFileIndexLow);
        id[..8].copy_from_slice(&index.to_le_bytes());
        (u64::from(basic.dwVolumeSerialNumber), id)
    };
    let reparse_tag = if basic.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        // SAFETY: plain data (integers); all zero is valid.
        let mut tag: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: `tag` is valid for writes of the size passed, the size of the class's structure.
        check(unsafe {
            GetFileInformationByHandleEx(
                h,
                FileAttributeTagInfo,
                (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast::<c_void>(),
                size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        })?;
        Some(tag.ReparseTag)
    } else {
        None
    };
    Ok(Info {
        owner,
        protection,
        volume,
        id,
        links: basic.nNumberOfLinks,
        attributes: basic.dwFileAttributes,
        reparse_tag,
    })
}

/// Whether the file has a DACL and every ACE of it is an allow ACE for its owner or SYSTEM (inherited ones
/// included): the test for files that others (SQLite) create inside a private directory. A null DACL (everyone
/// allowed) or any other ACE (a deny, an object ACE, another SID) is `false`.
pub fn grants_only_owner_and_system(file: &File) -> io::Result<bool> {
    with_security(file.as_raw_handle(), false, |owner, dacl, _control| {
        let Some(aces) = dacl else { return Ok(false) };
        let system = Sid::local_system();
        Ok(aces.iter().all(|a| a.allow && a.sid.as_ref().is_some_and(|s| s == owner || *s == system)))
    })
}

/// Sets the DACL of an open file or directory to `protection` (protected, nothing inherited). The handle needs
/// `WRITE_DAC` (files from [`open`] with write or append; directories from [`open_dir`]). The owner is not changed.
pub fn set_protection(file: &File, protection: Protection, dir: bool) -> io::Result<()> {
    let d = descriptor(protection, dir)?;
    // SAFETY: the handle is open (borrowed from `file`); the ACL lives in `d` across the call; owner, group and
    // SACL are not set (null).
    let err = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            d.acl(),
            std::ptr::null(),
        )
    };
    if err != 0 { Err(io::Error::from_raw_os_error(err as i32)) } else { Ok(()) }
}

/// Name-surrogate reparse points point at another name (symlinks, junctions, mount points); the others (Cloud Files
/// placeholders, dedup, WOF compression) are the file itself. `IsReparseTagNameSurrogate` (winnt.h).
pub fn is_name_surrogate(tag: u32) -> bool {
    tag & 0x2000_0000 != 0
}

/// The Cloud Files (OneDrive placeholder) errors that mean "cannot be reached right now".
pub fn is_cloud_unavailable(code: i32) -> bool {
    use windows_sys::Win32::Foundation::{
        ERROR_CLOUD_FILE_IN_USE, ERROR_CLOUD_FILE_NETWORK_UNAVAILABLE, ERROR_CLOUD_FILE_PROVIDER_NOT_RUNNING,
        ERROR_CLOUD_FILE_PROVIDER_TERMINATED, ERROR_CLOUD_FILE_REQUEST_TIMEOUT, ERROR_CLOUD_FILE_UNSUCCESSFUL,
    };
    [
        ERROR_CLOUD_FILE_PROVIDER_NOT_RUNNING,
        ERROR_CLOUD_FILE_NETWORK_UNAVAILABLE,
        ERROR_CLOUD_FILE_UNSUCCESSFUL,
        ERROR_CLOUD_FILE_REQUEST_TIMEOUT,
        ERROR_CLOUD_FILE_PROVIDER_TERMINATED,
        ERROR_CLOUD_FILE_IN_USE,
    ]
    .iter()
    .any(|&c| c as i32 == code)
}

/// One ACE of a DACL as far as MacVPN's checks need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AceEntry {
    /// `ACCESS_ALLOWED_ACE_TYPE`; every other type counts as "not an allow".
    pub(crate) allow: bool,
    /// The SID of an allow or deny ACE; `None` for every other type (not parsed).
    pub(crate) sid: Option<Sid>,
    pub(crate) mask: u32,
    pub(crate) flags: u8,
}

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// One ACE as the tests, the security review and the trust checks see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AceSummary {
    /// An access-allowed ACE; every other type (deny, audit, object ACEs) is `false`.
    pub allow: bool,
    /// The SID's string form for an allow or deny ACE; empty for every other type (not parsed).
    pub sid: String,
    pub mask: u32,
    /// `ACE_HEADER.AceFlags` (`INHERITED_ACE`, `INHERIT_ONLY_ACE`, …).
    pub flags: u8,
}

impl From<&AceEntry> for AceSummary {
    fn from(a: &AceEntry) -> AceSummary {
        AceSummary {
            allow: a.allow,
            sid: a.sid.as_ref().map(Sid::to_string).unwrap_or_default(),
            mask: a.mask,
            flags: a.flags,
        }
    }
}

/// Every ACE of the handle's DACL, in order. A null DACL is an error (it grants everyone everything). The handle
/// needs `READ_CONTROL`. `kernel_object`: the handle is a kernel object (a named pipe), not a file.
pub(crate) fn dacl_aces(h: HANDLE, kernel_object: bool) -> io::Result<Vec<AceSummary>> {
    with_security(h, kernel_object, |_owner, dacl, _control| {
        let aces = dacl.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "a null DACL"))?;
        Ok(aces.iter().map(AceSummary::from).collect())
    })
}

/// Every ACE of a descriptor's DACL (tests: the descriptor before any object carries it).
#[cfg(test)]
pub(crate) fn descriptor_aces(d: &Descriptor) -> io::Result<Vec<AceSummary>> {
    // SAFETY: the descriptor's ACL was built by `Acl::new` and lives as long as `d`, across the call.
    Ok(unsafe { aces(d.acl())? }.iter().map(AceSummary::from).collect())
}

/// Every ACE of the handle's DACL as (allow, SID string), in order; an ACE of another type is `(false, "")`. A
/// null DACL is an error. `kernel_object`: the handle is a kernel object (a named pipe), not a file.
pub(crate) fn dacl_entries(h: HANDLE, kernel_object: bool) -> io::Result<Vec<(bool, String)>> {
    Ok(dacl_aces(h, kernel_object)?.into_iter().map(|a| (a.allow, a.sid)).collect())
}

/// Runs `f` with the owner, the DACL's ACEs (`None` for a null DACL) and the control bits of `h`'s security
/// descriptor. Fails when any of them cannot be read. `kernel_object`: read it as a kernel object
/// (`SE_KERNEL_OBJECT`: named pipes) instead of a file (`SE_FILE_OBJECT`).
fn with_security<T>(
    h: HANDLE,
    kernel_object: bool,
    f: impl FnOnce(&Sid, Option<&[AceEntry]>, u16) -> io::Result<T>,
) -> io::Result<T> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: valid out pointers; on success `sd` is LocalAlloc'ed and `owner`/`dacl` point into it.
    let err = unsafe {
        GetSecurityInfo(
            h,
            if kernel_object { SE_KERNEL_OBJECT } else { SE_FILE_OBJECT },
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if err != 0 {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    // Freed on every path below.
    let _sd = LocalBox(sd);
    if sd.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no security descriptor"));
    }
    // SAFETY: `owner` is null or points into `sd`, alive until `_sd` drops at the end of this function.
    let owner = unsafe { Sid::from_psid(owner)? };
    let (mut control, mut revision) = (0u16, 0u32);
    // SAFETY: `sd` is a valid descriptor; valid out pointers.
    check(unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) })?;
    // SAFETY: `dacl` is null or a valid ACL inside `sd`, alive until `_sd` drops.
    let aces = if dacl.is_null() { None } else { Some(unsafe { aces(dacl)? }) };
    f(&owner, aces.as_deref(), control)
}

/// The owner of a kernel object (a mutex, a named pipe) from its security descriptor; the handle needs
/// `READ_CONTROL`. Any failure to read it is an error, never a default.
pub fn kernel_object_owner(h: BorrowedHandle<'_>) -> io::Result<Sid> {
    with_security(h.as_raw_handle(), true, |owner, _dacl, _control| Ok(owner.clone()))
}

/// The owner and every ACE of an open file's DACL (`None`: a null DACL, which grants everyone everything), for
/// [`crate::acl_check`]. The handle needs `READ_CONTROL`.
pub(crate) fn owner_and_aces(file: &File) -> io::Result<(Sid, Option<Vec<AceEntry>>)> {
    with_security(file.as_raw_handle(), false, |owner, dacl, _control| {
        Ok((owner.clone(), dacl.map(|aces| aces.iter().map(AceEntry::clone).collect())))
    })
}

/// Whether the open file or directory has exactly `protection`: a protected DACL of only explicit allow ACEs, each
/// of them one of the shape's entries and each entry present, every ACE inheritable to files and folders inside
/// (`OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`, nothing else) for a directory, with no flag for a file. Unlike
/// [`Info::protection`] it names the shape to test, so a DACL that fits two shapes (owned by Administrators:
/// [`Protection::Private`] and [`Protection::Admins`]) is never misread. The handle needs `READ_CONTROL`.
pub fn has_protection(file: &File, protection: Protection, dir: bool) -> io::Result<bool> {
    with_security(file.as_raw_handle(), false, |owner, dacl, control| {
        let Some(aces) = dacl else { return Ok(false) };
        let flags = if dir { (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8 } else { 0 };
        let protected = control & SE_DACL_PROTECTED != 0;
        Ok(fits(protection, owner, protected, aces) && aces.iter().all(|a| a.flags == flags))
    })
}

/// The rights another account would be granted to the open file: `user` with exactly the enabled `groups` (nothing
/// is looked up and nothing of this process' token is used), as the system's access check computes them
/// (`AuthzAccessCheck` with `MAXIMUM_ALLOWED`: the DACL, and the owner's implicit `READ_CONTROL | WRITE_DAC` only
/// when `user` owns the file). It proves who may open a file without signing in as them: an elevated administrator
/// other than the file's owner (over-the-shoulder UAC) is `user` = any other SID, `groups` = Administrators, Users,
/// Everyone, Authenticated Users, INTERACTIVE. Privileges (backup, restore) are not modelled. The handle needs
/// `READ_CONTROL`.
pub fn access_for(file: &File, user: &Sid, groups: &[Sid]) -> io::Result<u32> {
    use windows_sys::Win32::Foundation::LUID;
    use windows_sys::Win32::Security::Authorization::{
        AUTHZ_ACCESS_REPLY, AUTHZ_ACCESS_REQUEST, AUTHZ_CLIENT_CONTEXT_HANDLE, AUTHZ_RESOURCE_MANAGER_HANDLE,
        AUTHZ_RM_FLAG_NO_AUDIT, AUTHZ_SKIP_TOKEN_GROUPS, AuthzAccessCheck, AuthzAddSidsToContext, AuthzFreeContext,
        AuthzFreeResourceManager, AuthzInitializeContextFromSid, AuthzInitializeResourceManager,
    };
    use windows_sys::Win32::Security::{GROUP_SECURITY_INFORMATION, SID_AND_ATTRIBUTES};
    // winnt.h; not in the windows-sys features this crate enables.
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const SE_GROUP_ENABLED: u32 = 0x0000_0004;

    /// The Authz handles, freed on every path.
    struct Handles {
        rm: AUTHZ_RESOURCE_MANAGER_HANDLE,
        contexts: Vec<AUTHZ_CLIENT_CONTEXT_HANDLE>,
    }
    impl Drop for Handles {
        fn drop(&mut self) {
            for &c in &self.contexts {
                // SAFETY: a context AuthzInitializeContextFromSid / AuthzAddSidsToContext returned; freed once.
                unsafe { AuthzFreeContext(c) };
            }
            if !self.rm.is_null() {
                // SAFETY: the resource manager AuthzInitializeResourceManager returned; freed once, after its contexts.
                unsafe { AuthzFreeResourceManager(self.rm) };
            }
        }
    }

    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: the handle is open (borrowed from `file`); valid out pointer; on success `sd` is LocalAlloc'ed.
    let err = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if err != 0 {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    let _sd = LocalBox(sd);
    let mut h = Handles { rm: std::ptr::null_mut(), contexts: Vec::new() };
    // SAFETY: no callbacks, no name; valid out pointer.
    check(unsafe {
        AuthzInitializeResourceManager(AUTHZ_RM_FLAG_NO_AUDIT, None, None, None, std::ptr::null(), &mut h.rm)
    })?;
    let mut base: AUTHZ_CLIENT_CONTEXT_HANDLE = std::ptr::null_mut();
    // SAFETY: `user` is a valid SID alive across the call; `rm` is valid; no expiration, no dynamic groups; valid out
    // pointer. AUTHZ_SKIP_TOKEN_GROUPS: the SID's groups are not looked up (only `groups` below count).
    check(unsafe {
        AuthzInitializeContextFromSid(
            AUTHZ_SKIP_TOKEN_GROUPS,
            user.as_psid(),
            h.rm,
            std::ptr::null(),
            LUID { LowPart: 0, HighPart: 0 },
            std::ptr::null(),
            &mut base,
        )
    })?;
    h.contexts.push(base);
    let sids: Vec<SID_AND_ATTRIBUTES> =
        groups.iter().map(|g| SID_AND_ATTRIBUTES { Sid: g.as_psid(), Attributes: SE_GROUP_ENABLED }).collect();
    let mut context: AUTHZ_CLIENT_CONTEXT_HANDLE = std::ptr::null_mut();
    // SAFETY: `base` is valid; `sids` and the SIDs it points to (in `groups`) live across the call; no restricted
    // SIDs; valid out pointer.
    check(unsafe { AuthzAddSidsToContext(base, sids.as_ptr(), sids.len() as u32, std::ptr::null(), 0, &mut context) })?;
    h.contexts.push(context);
    let request = AUTHZ_ACCESS_REQUEST {
        DesiredAccess: MAXIMUM_ALLOWED,
        PrincipalSelfSid: std::ptr::null_mut(),
        ObjectTypeList: std::ptr::null_mut(),
        ObjectTypeListLength: 0,
        OptionalArguments: std::ptr::null_mut(),
    };
    let (mut granted, mut error) = (0u32, 0u32);
    let mut reply = AUTHZ_ACCESS_REPLY {
        ResultListLength: 1,
        GrantedAccessMask: &mut granted,
        SaclEvaluationResults: std::ptr::null_mut(),
        Error: &mut error,
    };
    // SAFETY: `context` is valid; `request` and `reply` (and the two u32 it points to) live across the call; `sd` is
    // the descriptor GetSecurityInfo returned (owner, group and DACL), alive until `_sd` drops; no extra descriptors,
    // no audit event, no results handle.
    check(unsafe {
        AuthzAccessCheck(
            0,
            context,
            &request,
            std::ptr::null_mut(),
            sd,
            std::ptr::null(),
            0,
            &mut reply,
            std::ptr::null_mut(),
        )
    })?;
    // `error` is ERROR_ACCESS_DENIED when nothing at all is granted: the answer is then no rights.
    Ok(if error == 0 { granted } else { 0 })
}

fn owner_and_protection(h: HANDLE) -> io::Result<(Sid, Option<Protection>)> {
    with_security(h, false, |owner, dacl, control| {
        let protected = control & SE_DACL_PROTECTED != 0;
        Ok((owner.clone(), dacl.and_then(|aces| shape(owner, protected, aces))))
    })
}

/// One of MacVPN's DACL shapes, exactly: protected, only explicit allow ACEs, and exactly the owner + SYSTEM
/// (+ `BUILTIN\Users` read, or + `BUILTIN\Administrators` read and write) entries, or SYSTEM + Administrators, each
/// ACE matching one of them and each of them present. A DACL that fits two shapes is reported as the first of
/// Private, Shared, Admins, AdminsReadWrite.
fn shape(owner: &Sid, protected: bool, aces: &[AceEntry]) -> Option<Protection> {
    [Protection::Private, Protection::Shared, Protection::Admins, Protection::AdminsReadWrite]
        .into_iter()
        .find(|&p| fits(p, owner, protected, aces))
}

/// Whether `aces` (of a DACL owned by `owner`) are exactly `protection`'s entries (the flags are not looked at but
/// for `INHERITED_ACE`, which no shape has).
fn fits(protection: Protection, owner: &Sid, protected: bool, aces: &[AceEntry]) -> bool {
    if !protected || !aces.iter().all(|a| a.allow && u32::from(a.flags) & INHERITED_ACE == 0) {
        return false;
    }
    let system = Sid::local_system();
    let (users, admins) = (Sid::builtin_users(), Sid::builtin_administrators());
    let expected: &[(&Sid, u32)] = match protection {
        Protection::Private => &[(owner, FILE_ALL_ACCESS), (&system, FILE_ALL_ACCESS)],
        Protection::Shared => &[(owner, FILE_ALL_ACCESS), (&system, FILE_ALL_ACCESS), (&users, USERS_READ)],
        Protection::Admins => &[(&system, FILE_ALL_ACCESS), (&admins, FILE_ALL_ACCESS)],
        Protection::AdminsReadWrite => {
            &[(owner, FILE_ALL_ACCESS), (&system, FILE_ALL_ACCESS), (&admins, ADMINS_READ_WRITE)]
        }
    };
    let is = |a: &AceEntry, sid: &Sid, mask: u32| a.sid.as_ref() == Some(sid) && a.mask == mask;
    aces.len() == expected.len()
        && aces.iter().all(|a| expected.iter().any(|&(s, m)| is(a, s, m)))
        && expected.iter().all(|&(s, m)| aces.iter().any(|a| is(a, s, m)))
}

/// Every ACE of a DACL. The SID is parsed only from allow and deny ACEs (whose layout is known), and only from
/// within the ACE's own bytes, which must lie within the ACL.
///
/// # Safety
/// `dacl` is a valid ACL (as the system returned it) that stays alive during the call.
unsafe fn aces(dacl: *const ACL) -> io::Result<Vec<AceEntry>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "a malformed ACL");
    // SAFETY: by the contract, `dacl` points to an ACL header.
    let (count, acl_size) = unsafe { ((*dacl).AceCount, usize::from((*dacl).AclSize)) };
    let mut out = Vec::with_capacity(usize::from(count));
    for i in 0..u32::from(count) {
        let mut ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: by the contract; GetAce checks the index against AceCount; `ace` is a valid out pointer.
        check(unsafe { GetAce(dacl, i, &mut ace) })?;
        let offset = (ace as usize).checked_sub(dacl as usize).ok_or_else(invalid)?;
        if ace.is_null() || offset + size_of::<ACE_HEADER>() > acl_size {
            return Err(invalid());
        }
        // SAFETY: the header lies within the ACL (checked above); ACEs are 4-byte aligned in an ACL.
        let header = unsafe { std::ptr::read_unaligned(ace as *const ACE_HEADER) };
        let ace_size = usize::from(header.AceSize);
        if ace_size < size_of::<ACE_HEADER>() + 4 || offset + ace_size > acl_size {
            return Err(invalid());
        }
        // SAFETY: the ACE's `ace_size` bytes lie within the ACL (checked above), alive by the contract.
        let bytes = unsafe { std::slice::from_raw_parts(ace as *const u8, ace_size) };
        let mask = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let sid = match header.AceType {
            // ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE: header, mask, then the SID up to the ACE's end.
            ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE => Some(sid_prefix(&bytes[8..]).ok_or_else(invalid)?),
            _ => None,
        };
        out.push(AceEntry { allow: header.AceType == ACCESS_ALLOWED_ACE_TYPE, sid, mask, flags: header.AceFlags });
    }
    Ok(out)
}

/// The SID at the start of `b` (its length from its sub-authority count), if it fits.
fn sid_prefix(b: &[u8]) -> Option<Sid> {
    let n = usize::from(*b.get(1)?);
    b.get(..8 + 4 * n).and_then(|s| Sid::from_bytes(s).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(acl: &Acl) -> Vec<AceEntry> {
        // SAFETY: an ACL built by Acl::new, alive during the call.
        unsafe { aces(acl.as_ptr()).unwrap() }
    }

    #[test]
    fn the_ace_parser_reads_allow_and_deny_aces() {
        let (me, system, users) = (Sid::current_user().unwrap(), Sid::local_system(), Sid::builtin_users());
        let acl = Acl::new(&[Ace::Deny(&users, FILE_GENERIC_READ), Ace::Allow(&me, FILE_ALL_ACCESS)], 0).unwrap();
        let parsed = parse(&acl);
        assert_eq!(
            parsed,
            [
                AceEntry { allow: false, sid: Some(users.clone()), mask: FILE_GENERIC_READ, flags: 0 },
                AceEntry { allow: true, sid: Some(me.clone()), mask: FILE_ALL_ACCESS, flags: 0 },
            ]
        );
        // A deny ACE is never part of a shape, nor "only owner and system".
        assert_eq!(shape(&me, true, &parsed), None);
        let private = Acl::new(&[Ace::Allow(&me, FILE_ALL_ACCESS), Ace::Allow(&system, FILE_ALL_ACCESS)], 0).unwrap();
        assert_eq!(shape(&me, true, &parse(&private)), Some(Protection::Private));
        assert_eq!(shape(&me, false, &parse(&private)), None);
        assert_eq!(shape(&users, true, &parse(&private)), None);
        // Owned by SYSTEM: both entries must be SYSTEM's; another SID in the second one is no shape.
        assert_eq!(shape(&system, true, &parse(&private)), None);
        let system_twice =
            Acl::new(&[Ace::Allow(&system, FILE_ALL_ACCESS), Ace::Allow(&system, FILE_ALL_ACCESS)], 0).unwrap();
        assert_eq!(shape(&system, true, &parse(&system_twice)), Some(Protection::Private));
    }

    #[test]
    fn a_shape_needs_exact_rights_and_no_extra_entry() {
        let (me, system, users) = (Sid::current_user().unwrap(), Sid::local_system(), Sid::builtin_users());
        let shared = Acl::new(
            &[Ace::Allow(&me, FILE_ALL_ACCESS), Ace::Allow(&system, FILE_ALL_ACCESS), Ace::Allow(&users, USERS_READ)],
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        )
        .unwrap();
        assert_eq!(shape(&me, true, &parse(&shared)), Some(Protection::Shared));
        let users_write = Acl::new(
            &[
                Ace::Allow(&me, FILE_ALL_ACCESS),
                Ace::Allow(&system, FILE_ALL_ACCESS),
                Ace::Allow(&users, FILE_ALL_ACCESS),
            ],
            0,
        )
        .unwrap();
        assert_eq!(shape(&me, true, &parse(&users_write)), None);
        let inherited =
            Acl::new(&[Ace::Allow(&me, FILE_ALL_ACCESS), Ace::Allow(&system, FILE_ALL_ACCESS)], INHERITED_ACE).unwrap();
        assert_eq!(shape(&me, true, &parse(&inherited)), None);
        let empty = Acl::new(&[], 0).unwrap();
        assert_eq!(shape(&me, true, &parse(&empty)), None);
    }

    #[test]
    fn the_admins_shape_is_system_and_administrators_whoever_owns_it() {
        let (me, system, admins) = (Sid::current_user().unwrap(), Sid::local_system(), Sid::builtin_administrators());
        let dir_flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
        let acl =
            Acl::new(&[Ace::Allow(&system, FILE_ALL_ACCESS), Ace::Allow(&admins, FILE_ALL_ACCESS)], dir_flags).unwrap();
        let parsed = parse(&acl);
        assert!(fits(Protection::Admins, &system, true, &parsed));
        assert!(fits(Protection::Admins, &me, true, &parsed));
        assert_eq!(shape(&system, true, &parsed), Some(Protection::Admins));
        // Owned by Administrators the same DACL is also Private's (owner + SYSTEM): `has_protection` names the shape.
        assert_eq!(shape(&admins, true, &parsed), Some(Protection::Private));
        assert!(fits(Protection::Admins, &admins, true, &parsed));
        assert!(!fits(Protection::Admins, &system, false, &parsed), "not protected");
        // An extra entry (Users read), a missing one, a weaker mask or an inherited ACE: not the shape.
        let users = Sid::builtin_users();
        let extra = Acl::new(
            &[
                Ace::Allow(&system, FILE_ALL_ACCESS),
                Ace::Allow(&admins, FILE_ALL_ACCESS),
                Ace::Allow(&users, USERS_READ),
            ],
            dir_flags,
        )
        .unwrap();
        assert!(!fits(Protection::Admins, &system, true, &parse(&extra)));
        let missing = Acl::new(&[Ace::Allow(&system, FILE_ALL_ACCESS)], dir_flags).unwrap();
        assert!(!fits(Protection::Admins, &system, true, &parse(&missing)));
        let weaker =
            Acl::new(&[Ace::Allow(&system, FILE_ALL_ACCESS), Ace::Allow(&admins, FILE_GENERIC_READ)], dir_flags)
                .unwrap();
        assert!(!fits(Protection::Admins, &system, true, &parse(&weaker)));
        let inherited =
            Acl::new(&[Ace::Allow(&system, FILE_ALL_ACCESS), Ace::Allow(&admins, FILE_ALL_ACCESS)], INHERITED_ACE)
                .unwrap();
        assert!(!fits(Protection::Admins, &system, true, &parse(&inherited)));
        let deny = Acl::new(
            &[
                Ace::Deny(&users, FILE_ALL_ACCESS),
                Ace::Allow(&system, FILE_ALL_ACCESS),
                Ace::Allow(&admins, FILE_ALL_ACCESS),
            ],
            dir_flags,
        )
        .unwrap();
        assert!(!fits(Protection::Admins, &system, true, &parse(&deny)));
    }

    #[test]
    fn the_admins_read_write_shape_is_the_owner_system_and_administrators_without_delete_or_dac() {
        let (me, system, admins, users) =
            (Sid::current_user().unwrap(), Sid::local_system(), Sid::builtin_administrators(), Sid::builtin_users());
        let acl = |admins_mask: u32| {
            Acl::new(
                &[
                    Ace::Allow(&me, FILE_ALL_ACCESS),
                    Ace::Allow(&system, FILE_ALL_ACCESS),
                    Ace::Allow(&admins, admins_mask),
                ],
                0,
            )
            .unwrap()
        };
        let exact = parse(&acl(ADMINS_READ_WRITE));
        assert_eq!(shape(&me, true, &exact), Some(Protection::AdminsReadWrite));
        assert!(fits(Protection::AdminsReadWrite, &me, true, &exact));
        assert!(!fits(Protection::AdminsReadWrite, &me, false, &exact), "not protected");
        assert!(!fits(Protection::AdminsReadWrite, &users, true, &exact), "another owner");
        // The rights the elevated step needs (msiexec truncates and writes its log) and nothing to take the file
        // over: no delete, no DACL or owner change.
        use windows_sys::Win32::Storage::FileSystem::{DELETE, FILE_APPEND_DATA, FILE_WRITE_DATA, WRITE_OWNER};
        assert_eq!(ADMINS_READ_WRITE & (FILE_WRITE_DATA | FILE_APPEND_DATA), FILE_WRITE_DATA | FILE_APPEND_DATA);
        assert_eq!(ADMINS_READ_WRITE & (DELETE | WRITE_DAC | WRITE_OWNER), 0);
        // Full control for Administrators, read only, or an extra Users entry: not the shape.
        assert_eq!(shape(&me, true, &parse(&acl(FILE_ALL_ACCESS))), None);
        assert_eq!(shape(&me, true, &parse(&acl(FILE_GENERIC_READ))), None);
        let extra = Acl::new(
            &[
                Ace::Allow(&me, FILE_ALL_ACCESS),
                Ace::Allow(&system, FILE_ALL_ACCESS),
                Ace::Allow(&admins, ADMINS_READ_WRITE),
                Ace::Allow(&users, USERS_READ),
            ],
            0,
        )
        .unwrap();
        assert_eq!(shape(&me, true, &parse(&extra)), None);
        // Private and Shared are never read as it (and it as neither).
        let private = Acl::new(&[Ace::Allow(&me, FILE_ALL_ACCESS), Ace::Allow(&system, FILE_ALL_ACCESS)], 0).unwrap();
        assert!(!fits(Protection::AdminsReadWrite, &me, true, &parse(&private)));
        assert!(!fits(Protection::Private, &me, true, &exact));
        assert!(!fits(Protection::Shared, &me, true, &exact));
        // The descriptor this crate builds is exactly the shape.
        let d = descriptor_owned(me.clone(), Protection::AdminsReadWrite, false).unwrap();
        let built = descriptor_aces(&d).unwrap();
        assert_eq!(built.len(), 3);
        assert!(built.iter().any(|a| a.sid == admins.to_string() && a.mask == ADMINS_READ_WRITE && a.flags == 0));
    }

    #[test]
    fn a_sid_must_fit_its_ace() {
        let me = Sid::current_user().unwrap();
        let acl = Acl::new(&[Ace::Allow(&me, FILE_ALL_ACCESS)], 0).unwrap();
        let entry = &parse(&acl)[0];
        assert_eq!(entry.sid.as_ref(), Some(&me));
        assert_eq!(sid_prefix(&[1, 2, 0, 0, 0, 0, 0, 5, 1, 0, 0, 0]), None);
        assert_eq!(sid_prefix(&[1, 0, 0, 0, 0, 0, 0, 5]).map(|s| s.to_string()).as_deref(), Some("S-1-5"));
        assert_eq!(sid_prefix(&[2, 0, 0, 0, 0, 0, 0, 5]), None);
        assert_eq!(sid_prefix(&[1]), None);
    }
}
