//! Thin, audited wrappers around the libc calls `std` does not offer (the user database, `mkdtemp`, `poll`,
//! `fcntl`, `kill`, `access`, `confstr`, `getentropy`, `getxattr`, `getifaddrs`, and the close-on-exec sweep for children).
//!
//! Every function here is a direct call with plain integer arguments or with buffers whose length is passed
//! alongside; none of them keeps a pointer past the call. Everything else in the crate is safe Rust.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString, OsString};
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// A user database entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub home: PathBuf,
}

/// `getxattr(path, name, NULL, 0, 0, options)`: whether the extended attribute exists (its size is asked for,
/// nothing is read). `follow`: `false` adds `XATTR_NOFOLLOW` (a symlink's own attributes). `Ok(false)`: no such
/// attribute (`ENOATTR`), or the file system has none (`ENOTSUP`).
pub fn has_xattr(path: &Path, name: &CStr, follow: bool) -> io::Result<bool> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let options = if follow { 0 } else { libc::XATTR_NOFOLLOW };
    // SAFETY: `c` and `name` are NUL-terminated strings alive for the call; a null value buffer with size 0 only
    // asks for the attribute's size (nothing is written).
    let rc = unsafe { libc::getxattr(c.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0, 0, options) };
    if rc >= 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::ENOATTR) | Some(libc::ENOTSUP) => Ok(false),
        _ => Err(e),
    }
}

/// `getuid()`.
pub fn getuid() -> u32 {
    // SAFETY: no arguments, cannot fail.
    unsafe { libc::getuid() }
}

/// `getentropy(2)` over the whole buffer, in chunks of at most 256 bytes (the call's limit). Fails rather than
/// leaving any part unfilled.
pub fn getentropy(buf: &mut [u8]) -> io::Result<()> {
    for chunk in buf.chunks_mut(256) {
        // SAFETY: `chunk` is a valid writable buffer of `chunk.len()` (≤ 256) bytes for the duration of the call.
        let rc = unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// `getpwuid_r(uid)`.
pub fn user_by_uid(uid: u32) -> Option<User> {
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: a zeroed `passwd` is a valid out-parameter (null pointers, zero integers).
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the duration of the call; the buffer length is passed.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
        return None;
    }
    // SAFETY: `pw_name` / `pw_dir` point into `buf` (alive here) and are NUL terminated.
    let name = unsafe { CStr::from_ptr(pwd.pw_name) }.to_str().ok()?.to_string();
    let home = if pwd.pw_dir.is_null() {
        PathBuf::new()
    } else {
        // SAFETY: as above.
        PathBuf::from(OsString::from_vec(unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes().to_vec()))
    };
    Some(User { name, uid: pwd.pw_uid, home })
}

/// `mkdtemp(3)` on `template` (which must end in `X`s). The created path is read back from the buffer itself.
pub fn mkdtemp(template: &Path) -> io::Result<PathBuf> {
    let c = CString::new(template.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut buffer = c.into_bytes_with_nul();
    // SAFETY: `buffer` is a writable, NUL-terminated byte string; mkdtemp only rewrites the trailing X's in place.
    let rc = unsafe { libc::mkdtemp(buffer.as_mut_ptr().cast()) };
    if rc.is_null() {
        return Err(io::Error::last_os_error());
    }
    buffer.pop();
    Ok(PathBuf::from(OsString::from_vec(buffer)))
}

/// `confstr(_CS_DARWIN_USER_TEMP_DIR)`: the per-user temporary directory Foundation's `temporaryDirectory`
/// returns (`/var/folders/…/T/`). `None` if it is not available.
pub fn darwin_user_temp_dir() -> Option<PathBuf> {
    // SAFETY: size query with a null buffer of length 0.
    let size = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, std::ptr::null_mut(), 0) };
    if size == 0 {
        return None;
    }
    let mut buffer = vec![0u8; size];
    // SAFETY: `buffer` has `size` bytes, its length is passed; confstr writes at most that, NUL terminated.
    let written = unsafe { libc::confstr(libc::_CS_DARWIN_USER_TEMP_DIR, buffer.as_mut_ptr().cast(), buffer.len()) };
    if written == 0 || written > buffer.len() {
        return None;
    }
    let end = buffer.iter().position(|&b| b == 0)?;
    buffer.truncate(end);
    let path = PathBuf::from(OsString::from_vec(buffer));
    path.is_absolute().then_some(path)
}

/// `access(path, W_OK) == 0` (Foundation `isWritableFile(atPath:)`).
pub fn is_writable(path: &Path) -> bool {
    let Ok(c) = CString::new(path.as_os_str().as_bytes()) else { return false };
    // SAFETY: a valid NUL-terminated path and an integer mode.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

/// `access(path, X_OK) == 0` on a regular file (Foundation `isExecutableFile(atPath:)`).
pub fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else { return false };
    if meta.is_dir() {
        return false;
    }
    let Ok(c) = CString::new(path.as_os_str().as_bytes()) else { return false };
    // SAFETY: a valid NUL-terminated path and an integer mode.
    unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
}

/// Sets `O_NONBLOCK` on `fd`.
pub fn set_nonblocking(fd: i32) -> io::Result<()> {
    // SAFETY: plain integer arguments; an invalid fd only yields EBADF.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `F_SETNOSIGPIPE`: a write to a closed pipe returns EPIPE instead of raising SIGPIPE.
pub fn set_nosigpipe(fd: i32) {
    // SAFETY: plain integer arguments.
    unsafe {
        libc::fcntl(fd, libc::F_SETNOSIGPIPE, 1);
    }
}

pub const POLLIN: i16 = libc::POLLIN;
pub const POLLOUT: i16 = libc::POLLOUT;

/// `poll(2)` on `(fd, events)` pairs; returns the `revents` per entry. EINTR counts as "nothing ready".
pub fn poll(fds: &[(i32, i16)], timeout_ms: i32) -> io::Result<Vec<i16>> {
    let mut pfds: Vec<libc::pollfd> = fds.iter().map(|&(fd, events)| libc::pollfd { fd, events, revents: 0 }).collect();
    // SAFETY: `pfds` is a valid array whose length is passed.
    let rc = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, timeout_ms) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINTR) {
            return Ok(vec![0; fds.len()]);
        }
        return Err(e);
    }
    Ok(pfds.iter().map(|p| p.revents).collect())
}

pub const SIGTERM: i32 = libc::SIGTERM;
pub const SIGKILL: i32 = libc::SIGKILL;

/// `kill(pid, sig)` for a positive pid (never a process group).
pub fn kill(pid: i32, sig: i32) {
    if pid > 0 {
        // SAFETY: plain integer arguments.
        unsafe {
            libc::kill(pid, sig);
        }
    }
}

/// Children must not inherit the app's open file descriptors (Foundation's `Process` spawns with
/// `POSIX_SPAWN_CLOEXEC_DEFAULT`; `std::process::Command` does not). Marks every descriptor from 3 up to
/// `getdtablesize()` close-on-exec in the child, after the standard streams are set up and right before `exec`.
/// Use it on every [`std::process::Command`] of this crate.
pub fn close_inherited_fds(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: plain getter, called in the parent (before fork).
    let max = unsafe { libc::getdtablesize() }.max(3);
    // SAFETY: the closure runs in the forked child between fork and exec. It only calls `fcntl` (async-signal-
    // safe), allocates nothing, takes no lock and touches no Rust state; an fd that is not open just returns EBADF.
    unsafe {
        command.pre_exec(move || {
            for fd in 3..max {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags >= 0 && flags & libc::FD_CLOEXEC == 0 {
                    libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
                }
            }
            Ok(())
        });
    }
}

/// `localtime_r(t)`: (year, month, day, hour, minute, second) in the local time zone.
pub fn local_time(t: i64) -> Option<(i32, u32, u32, u32, u32, u32)> {
    let time: libc::time_t = t;
    // SAFETY: a zeroed `tm` is a valid out-parameter.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call; `localtime_r` is the thread-safe variant.
    let result = unsafe { libc::localtime_r(&time, &mut tm) };
    if result.is_null() {
        return None;
    }
    Some((
        tm.tm_year + 1900,
        (tm.tm_mon + 1) as u32,
        tm.tm_mday as u32,
        tm.tm_hour as u32,
        tm.tm_min as u32,
        tm.tm_sec as u32,
    ))
}

/// The leading one bits of `mask` (the bytes from the netmask's address offset; missing bytes count as zero): the
/// prefix length of a contiguous netmask; a non-contiguous one stops at its first zero bit.
fn mask_len(mask: &[u8], width: usize) -> u8 {
    let mut len = 0u8;
    for i in 0..width {
        let ones = mask.get(i).copied().unwrap_or(0).leading_ones() as u8;
        len += ones;
        if ones < 8 {
            break;
        }
    }
    len
}

/// The `sa_len` bytes of a `sockaddr` (BSD trims netmasks to their significant bytes).
///
/// # Safety
/// `sa` is non-null and points to a `sockaddr` whose first `sa_len` bytes are readable for `'a`.
unsafe fn sockaddr_bytes<'a>(sa: *const libc::sockaddr) -> &'a [u8] {
    // SAFETY: (caller) `sa` is a readable sockaddr; `sa_len` is its first byte, read without a reference to the
    // whole struct (it may be shorter than `sockaddr`).
    let len = usize::from(unsafe { std::ptr::read(sa.cast::<u8>()) });
    // SAFETY: (caller) the first `len` bytes are readable for `'a`.
    unsafe { std::slice::from_raw_parts(sa.cast::<u8>(), len) }
}

/// `getifaddrs`: the IPv4 and IPv6 prefixes of the interfaces that are up and not loopback, with their interface
/// names (`en0`, `utun4`, …). An address without a netmask, or with an empty one, is left out. Read-only.
pub fn interface_prefixes() -> Vec<(String, macvpn_core::netaddr::IpPrefix)> {
    use macvpn_core::netaddr::IpPrefix;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is a valid out pointer; on success the list is ours until `freeifaddrs` below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: a non-null node of the list `getifaddrs` returned, alive until `freeifaddrs`.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        let flags = entry.ifa_flags as i32;
        if flags & libc::IFF_UP == 0
            || flags & libc::IFF_LOOPBACK != 0
            || entry.ifa_name.is_null()
            || entry.ifa_addr.is_null()
            || entry.ifa_netmask.is_null()
        {
            continue;
        }
        // SAFETY: non-null, NUL-terminated, alive until `freeifaddrs`.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) }.to_string_lossy().into_owned();
        // SAFETY: both are non-null sockaddrs of the list, `sa_len` bytes each, alive until `freeifaddrs` (the
        // slices are not used past this iteration).
        let (addr, mask) = unsafe { (sockaddr_bytes(entry.ifa_addr), sockaddr_bytes(entry.ifa_netmask)) };
        // The address's family decides (a netmask's own `sa_family` may be 0); `[sa_len, sa_family, …]`.
        let prefix = match addr.get(1).map(|f| i32::from(*f)) {
            Some(libc::AF_INET) if addr.len() >= 8 && mask.len() > 4 => {
                let ip = Ipv4Addr::new(addr[4], addr[5], addr[6], addr[7]);
                IpPrefix::new(IpAddr::V4(ip), mask_len(&mask[4..], 4))
            }
            Some(libc::AF_INET6) if addr.len() >= 24 && mask.len() > 8 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&addr[8..24]);
                IpPrefix::new(IpAddr::V6(Ipv6Addr::from(octets)), mask_len(&mask[8..], 16))
            }
            _ => None,
        };
        if let Some(prefix) = prefix.filter(|p| p.len > 0) {
            out.push((name, prefix));
        }
    }
    // SAFETY: the list `getifaddrs` returned, freed once; no reference into it outlives this point.
    unsafe { libc::freeifaddrs(head) };
    out
}
