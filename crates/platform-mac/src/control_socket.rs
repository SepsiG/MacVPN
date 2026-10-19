//! The local control API's Unix socket (spec section 4): the private `control/` directory, binding
//! `macvpn.sock` (single instance through `macvpn.lock`, stale socket, modes), the peer's identity, and a random
//! source for tokens.
//!
//! Audit note: the `unsafe` blocks here are direct libc calls (`umask`, `flock`, `getpeereid`, `getsockopt`,
//! `proc_pidpath`, `getentropy`) with plain integer arguments or with out-parameters / buffers that live on
//! the stack for the duration of the call and whose length is passed alongside. No pointer is kept past a call.
//!
//! Close-on-exec: `std` creates every socket close-on-exec on macOS (`socket`, `accept` and `socketpair` are
//! followed by `FIOCLEX`), so the listener and every accepted stream are close-on-exec; the tests check it. The
//! lock file is opened with `O_CLOEXEC`. There is a short window inside `std` between `accept` and `FIOCLEX`: a
//! child forked by another thread in that window would inherit the stream. Only spawns that go through
//! [`crate::sys::close_inherited_fds`] are covered against that (it marks every fd ≥ 3 close-on-exec in the child),
//! so the app must spawn child processes only through that path while the control server runs.
#![allow(unsafe_code)]

use crate::sys;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// The socket's file name inside the control directory.
pub const SOCKET_NAME: &str = "macvpn.sock";

/// The single-instance lock file's name inside the control directory.
pub const LOCK_NAME: &str = "macvpn.lock";

/// `sizeof(((struct sockaddr_un *)0)->sun_path)`: `char sun_path[104]` in `<sys/un.h>`. The path plus its NUL
/// terminator must fit.
const SUN_PATH_LEN: usize = 104;

/// The socket path inside `dir`.
pub fn socket_path(dir: &Path) -> PathBuf {
    dir.join(SOCKET_NAME)
}

fn error(kind: ErrorKind, message: String) -> io::Error {
    io::Error::new(kind, message)
}

/// Creates `dir` with mode 0700 if it is missing (its parent with default modes), then checks it without
/// following a symlink: it must be a real directory owned by `getuid()`. A looser mode is tightened to 0700; a
/// symlink, a non-directory or a foreign owner is an error.
///
/// The check and the `chmod` act on one descriptor opened with `O_NOFOLLOW | O_DIRECTORY` (`fstat` +
/// `fchmod`), so nothing can swap the path between them.
pub fn prepare_dir(dir: &Path) -> io::Result<()> {
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
    let not_a_dir = || error(ErrorKind::NotADirectory, format!("{} is not a real directory", dir.display()));
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
    if meta.uid() != sys::getuid() {
        return Err(error(
            ErrorKind::PermissionDenied,
            format!("{} is owned by uid {}, not by this user", dir.display(), meta.uid()),
        ));
    }
    if meta.mode() & 0o7777 != 0o700 {
        handle.set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// A bound control socket together with the single-instance lock, held for the listener's whole life. Dereferences
/// to the [`UnixListener`]. Fields drop in order: the socket closes before the lock is released.
#[derive(Debug)]
pub struct ControlListener {
    listener: UnixListener,
    _lock: File,
}

impl ControlListener {
    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }
}

impl std::ops::Deref for ControlListener {
    type Target = UnixListener;

    fn deref(&self) -> &UnixListener {
        &self.listener
    }
}

/// Prepares `dir` ([`prepare_dir`]) and binds `<dir>/macvpn.sock`:
/// - First takes an exclusive, non-blocking `flock` on `<dir>/macvpn.lock` (opened `O_CREAT | O_NOFOLLOW |
///   O_CLOEXEC`, mode 0600). If another instance holds it: `AddrInUse`. The lock lives as long as the returned
///   [`ControlListener`], so the stale-socket check, the unlink and the bind below never race another instance
///   (a `connect()` probe could not guarantee that, and on macOS a full backlog makes a live socket refuse).
/// - With the lock held, a leftover entry is removed only if `lstat` shows a socket owned by this user; anything
///   else is an error.
/// - The socket is bound with the umask set to 077 for just the bind (then restored) and `chmod`ed to 0600.
/// - A path that does not fit `sun_path` (104 bytes with the NUL) is an `InvalidInput` error.
pub fn bind(dir: &Path) -> io::Result<ControlListener> {
    prepare_dir(dir)?;
    let path = socket_path(dir);
    let length = path.as_os_str().as_bytes().len();
    if length >= SUN_PATH_LEN {
        return Err(error(
            ErrorKind::InvalidInput,
            format!(
                "control socket path is too long ({length} bytes, the limit is {}): {}",
                SUN_PATH_LEN - 1,
                path.display()
            ),
        ));
    }

    let lock = take_lock(dir)?;

    // With the lock held no other instance can serve here, so any socket left is stale.
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_socket() && meta.uid() == sys::getuid() => match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        },
        Ok(_) => {
            return Err(error(
                ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket owned by this user", path.display()),
            ));
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let listener = with_umask(0o077, || UnixListener::bind(&path))?;
    // `chmod` follows a symlink. Accepted: the path is in our 0700 directory, so only this same uid could swap
    // the socket for a link between the bind and here.
    if let Err(e) = fs::set_permissions(&path, fs::Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(&path);
        return Err(e);
    }
    Ok(ControlListener { listener, _lock: lock })
}

/// Opens `<dir>/macvpn.lock` (`O_CREAT | O_NOFOLLOW | O_CLOEXEC`, mode 0600; a symlink is refused) and takes
/// `flock(LOCK_EX | LOCK_NB)` on it (`File::try_lock` is newer than the MSRV). Already held (`EWOULDBLOCK`): `AddrInUse`.
fn take_lock(dir: &Path) -> io::Result<File> {
    let path = dir.join(LOCK_NAME);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() || meta.uid() != sys::getuid() {
        return Err(error(
            ErrorKind::AlreadyExists,
            format!("{} is not a regular file owned by this user", path.display()),
        ));
    }
    // SAFETY: an fd owned by `file` (alive here) and integer flags.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(error(
                ErrorKind::AddrInUse,
                format!("another instance is already serving in {}", dir.display()),
            ));
        }
        return Err(e);
    }
    Ok(file)
}

/// Runs `f` with the file mode creation mask set to `mask`, restoring the previous mask right after.
///
/// The umask is process-global: a file another thread creates during `f` also gets `mask` (077 here, i.e. it can
/// only come out narrower, never wider), and a concurrent `umask()` elsewhere could be overwritten by the
/// restore. Nothing else in the app changes the umask, and the window is a single `socket` + `bind` + `listen`.
/// The private 0700 directory is the primary protection either way; the umask only ensures the socket is never
/// briefly wider than 0600 before the `chmod` (the spec asks for both).
fn with_umask<T>(mask: libc::mode_t, f: impl FnOnce() -> T) -> T {
    // SAFETY: plain integer argument; `umask` cannot fail and returns the previous mask.
    let previous = unsafe { libc::umask(mask) };
    let result = f();
    // SAFETY: as above.
    unsafe {
        libc::umask(previous);
    }
    result
}

/// The process on the other end of a Unix socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    /// Effective uid (`getpeereid`).
    pub uid: u32,
    /// `LOCAL_PEERPID`: the pid of the process that last did I/O on the peer's socket (normally the one that
    /// connected, but a socket passed to or inherited by another process reports that one).
    pub pid: i32,
    /// Its executable path (`proc_pidpath`), `None` if unavailable (e.g. it already exited). A pid can be reused
    /// once the process exits, so this path is for pinning and the audit log, never the only check.
    pub executable: Option<PathBuf>,
}

/// The peer's identity: `getpeereid`, `getsockopt(SOL_LOCAL, LOCAL_PEERPID)` and `proc_pidpath`.
pub fn peer(stream: &UnixStream) -> io::Result<Peer> {
    let fd = stream.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: a socket fd and two out-parameters on the stack, valid for the call.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // `SOL_LOCAL` (0) and `LOCAL_PEERPID` (0x002) as in `<sys/un.h>`.
    let mut pid: libc::pid_t = 0;
    let mut length = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: the out-buffer is `pid` on the stack and its size is passed in `length`.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_LOCAL, libc::LOCAL_PEERPID, (&raw mut pid).cast(), &mut length) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<libc::pid_t>() {
        return Err(error(ErrorKind::InvalidData, format!("LOCAL_PEERPID returned {length} bytes")));
    }
    Ok(Peer { uid, pid, executable: executable_path(pid) })
}

/// `proc_pidpath(pid)` (buffer of `PROC_PIDPATHINFO_MAXSIZE`, `4 * MAXPATHLEN` in `<sys/proc_info.h>`).
fn executable_path(pid: i32) -> Option<PathBuf> {
    if pid <= 0 {
        return None;
    }
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buffer` is writable and its length is passed; the call writes at most that many bytes.
    let written = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if written <= 0 {
        return None;
    }
    buffer.truncate(written as usize);
    Some(PathBuf::from(OsString::from_vec(buffer)))
}

/// Whether `peer_uid` is this process's real uid.
pub fn same_user(peer_uid: u32) -> bool {
    peer_uid == sys::getuid()
}

/// 32 bytes from the kernel's CSPRNG (`getentropy`).
pub fn random_32() -> io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    // SAFETY: `bytes` is writable and its length (32, within getentropy's 256-byte limit) is passed.
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(bytes)
}
