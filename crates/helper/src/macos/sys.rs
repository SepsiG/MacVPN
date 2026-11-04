//! Thin, audited wrappers around the libc calls `std` does not offer. With `sc_prefs` (the SystemConfiguration
//! preferences of the DNS manager) the only modules with `unsafe` code.
//!
//! Every function here is a direct call with plain integer arguments or with buffers whose length is passed
//! alongside; none of them keeps a pointer past the call. Everything else in the crate is safe Rust.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicBool, Ordering};

/// Effective user id.
pub fn geteuid() -> u32 {
    // SAFETY: no arguments, cannot fail.
    unsafe { libc::geteuid() }
}

/// `flock(fd, LOCK_EX | LOCK_NB)`: `true` if the exclusive lock was taken (released when the file closes).
pub fn try_lock_exclusive(f: &std::fs::File) -> bool {
    use std::os::unix::io::AsRawFd;
    // SAFETY: a valid descriptor owned by `f` for the duration of the call.
    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

/// Sets the file mode creation mask (the bash `umask 077`).
pub fn umask(mask: u16) {
    // SAFETY: plain integer argument, cannot fail.
    unsafe {
        libc::umask(mask as libc::mode_t);
    }
}

/// `kill(pid, sig)`; `Ok(())` on success, the errno otherwise. `pid` must be positive (no process groups).
pub fn kill(pid: i32, sig: i32) -> Result<(), i32> {
    if pid <= 0 {
        return Err(libc::ESRCH);
    }
    // SAFETY: plain integer arguments.
    let rc = unsafe { libc::kill(pid, sig) };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::ESRCH)) }
}

/// `openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC [| O_DIRECTORY])`: one plain name (no `/`,
/// not `.` / `..`) in an open directory, never through a symlink (`ELOOP`).
pub fn open_at(dir: &std::fs::File, name: &std::ffi::OsStr, directory: bool) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let b = name.as_bytes();
    if b.is_empty() || b == b"." || b == b".." || b.contains(&b'/') {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    let cname = CString::new(b).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let mut flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
    if directory {
        flags |= libc::O_DIRECTORY;
    }
    // SAFETY: a valid descriptor owned by `dir` and a NUL-terminated name, both valid for the call.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), cname.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a new descriptor that nothing else owns.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// The entry names of an open directory (without `.` and `..`), read through a duplicate of its descriptor.
pub fn list_dir(dir: &std::fs::File) -> std::io::Result<Vec<std::ffi::OsString>> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: a valid descriptor owned by `dir`; the duplicate is owned by the DIR stream below.
    let fd = unsafe { libc::dup(dir.as_raw_fd()) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a valid directory descriptor; on success the stream owns it (closed by `closedir`).
    let d = unsafe { libc::fdopendir(fd) };
    if d.is_null() {
        let e = std::io::Error::last_os_error();
        // SAFETY: `fd` was not taken over by a stream.
        unsafe { libc::close(fd) };
        return Err(e);
    }
    // SAFETY: `d` is a valid stream; the shared offset is rewound so the listing is complete.
    unsafe { libc::rewinddir(d) };
    let mut names = Vec::new();
    loop {
        // SAFETY: `d` is a valid stream; the entry is copied before the next `readdir` / `closedir`.
        let e = unsafe { libc::readdir(d) };
        if e.is_null() {
            break;
        }
        // SAFETY: `d_name` of a returned entry is NUL terminated within the entry.
        let name = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) };
        let b = name.to_bytes();
        if b != b"." && b != b".." {
            names.push(std::ffi::OsStr::from_bytes(b).to_os_string());
        }
    }
    // SAFETY: `d` is a valid stream, closed once.
    unsafe { libc::closedir(d) };
    Ok(names)
}

/// `kill -0 <pid>` semantics including `0` (the caller's process group) the way bash passes it through.
pub fn kill0_raw(pid: i32) -> Result<(), i32> {
    // SAFETY: plain integer arguments; signal 0 only checks for existence / permission.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 { Ok(()) } else { Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::ESRCH)) }
}

pub const SIGTERM: i32 = libc::SIGTERM;
pub const SIGKILL: i32 = libc::SIGKILL;
pub const EPERM: i32 = libc::EPERM;

/// A user database entry.
#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

/// Copies a `passwd` record; `p` must be a valid pointer returned by `getpw*_r`.
fn user_from(p: &libc::passwd) -> Option<User> {
    if p.pw_name.is_null() {
        return None;
    }
    // SAFETY: `pw_name` points into the caller-owned buffer of the `getpw*_r` call, NUL terminated.
    let name = unsafe { CStr::from_ptr(p.pw_name) }.to_str().ok()?.to_string();
    Some(User { name, uid: p.pw_uid, gid: p.pw_gid })
}

/// `getpwnam_r`.
pub fn user_by_name(name: &str) -> Option<User> {
    let cname = CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: zeroed `passwd` is a valid out-parameter (all pointers null, integers zero).
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the duration of the call, the buffer length is passed.
    let rc = unsafe { libc::getpwnam_r(cname.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    user_from(&pwd)
}

/// `getpwuid_r`.
pub fn user_by_uid(uid: u32) -> Option<User> {
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: see `user_by_name`.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the duration of the call, the buffer length is passed.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return None;
    }
    user_from(&pwd)
}

/// fd 0 as an unbuffered `File` that is never closed (no `std::io::stdin()` buffer holding a copy of the input).
pub fn stdin_fd() -> std::mem::ManuallyDrop<std::fs::File> {
    use std::os::fd::FromRawFd;
    // SAFETY: fd 0 stays open for the whole process; `ManuallyDrop` keeps this `File` from closing it.
    std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(0) })
}

/// `isatty(0)` (the bash `[ -t 0 ]`).
pub fn stdin_is_tty() -> bool {
    // SAFETY: plain integer argument.
    unsafe { libc::isatty(0) == 1 }
}

static TERMINATED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigterm(_: libc::c_int) {
    // Async-signal-safe: a single atomic store.
    TERMINATED.store(true, Ordering::SeqCst);
}

/// Installs a SIGTERM handler that only records the signal (the bash `trap on_term TERM`); the main flow polls
/// [`terminated`] between steps, as bash runs a trap after the current foreground command.
pub fn install_sigterm_flag() {
    // SAFETY: zeroed `sigaction` is valid; the handler only touches an atomic. No SA_RESTART: sleeps return.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigterm as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

/// Whether SIGTERM arrived since [`install_sigterm_flag`].
pub fn terminated() -> bool {
    TERMINATED.load(Ordering::SeqCst)
}

/// Local time `YYYY-MM-DD HH:MM:SS` (the bash `date '+%Y-%m-%d %H:%M:%S'`).
pub fn local_timestamp(t: i64) -> String {
    let tt = t as libc::time_t;
    // SAFETY: zeroed `tm` is a valid out-parameter; `localtime_r` writes only into it.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call.
    let ok = unsafe { !libc::localtime_r(&tt, &mut tm).is_null() };
    if !ok {
        return String::from("1970-01-01 00:00:00");
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// The executable path a process was started from (`KERN_PROCARGS2`, the Swift bridge's `execPath`).
pub fn exec_path(pid: i32) -> Option<String> {
    if pid <= 0 {
        return None;
    }
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;
    // SAFETY: size query: null buffer, valid `size` out-parameter, `mib` length passed.
    let rc = unsafe { libc::sysctl(mib.as_mut_ptr(), 3, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0) };
    if rc != 0 || size <= 4 {
        return None;
    }
    let mut buf = vec![0u8; size];
    // SAFETY: `buf` has `size` bytes; the kernel writes at most `size` and updates it.
    let rc = unsafe { libc::sysctl(mib.as_mut_ptr(), 3, buf.as_mut_ptr().cast(), &mut size, std::ptr::null_mut(), 0) };
    if rc != 0 || size <= 4 {
        return None;
    }
    let rest = buf.get(4..size)?;
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    Some(String::from_utf8_lossy(&rest[..end]).into_owned())
}

/// `getpeereid`: the effective uid of the process on the other end of a connected Unix socket (`mvpn serve`'s peer
/// check). `None` if the kernel does not tell.
pub fn peer_uid(s: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let (mut uid, mut gid): (libc::uid_t, libc::gid_t) = (0, 0);
    // SAFETY: a valid descriptor owned by `s` and two valid out-parameters, all for the duration of the call.
    let rc = unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) };
    (rc == 0).then_some(uid)
}

/// `poll` for input on one descriptor: `true` once it is readable (for a listening socket: a connection is
/// waiting), `false` after `timeout` or on an error. A signal does not end the wait early: it goes on for the rest.
pub fn wait_readable(fd: &impl std::os::fd::AsRawFd, timeout: std::time::Duration) -> bool {
    let end = std::time::Instant::now() + timeout;
    loop {
        let left = end.saturating_duration_since(std::time::Instant::now());
        let ms = libc::c_int::try_from(left.as_millis()).unwrap_or(libc::c_int::MAX);
        let mut p = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid `pollfd` and its count, for the duration of the call.
        let rc = unsafe { libc::poll(&mut p, 1, ms) };
        if rc > 0 {
            return p.revents & libc::POLLIN != 0;
        }
        if rc == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return false;
        }
    }
}

// libSystem's launchd API (`<launch.h>`); no crate binds it.
unsafe extern "C" {
    fn launch_activate_socket(
        name: *const libc::c_char,
        fds: *mut *mut libc::c_int,
        cnt: *mut libc::size_t,
    ) -> libc::c_int;
}

/// `launch_activate_socket(name)`: the sockets launchd created for this job's `Sockets` entry `name` (socket
/// activation), each now owned by the caller. `Err(errno)`: not started by launchd, or no such entry.
pub fn launch_sockets(name: &str) -> Result<Vec<std::os::fd::OwnedFd>, i32> {
    use std::os::fd::FromRawFd;
    let cname = CString::new(name).map_err(|_| libc::EINVAL)?;
    let mut fds: *mut libc::c_int = std::ptr::null_mut();
    let mut cnt: libc::size_t = 0;
    // SAFETY: a NUL-terminated name and two valid out-parameters for the duration of the call.
    let rc = unsafe { launch_activate_socket(cname.as_ptr(), &mut fds, &mut cnt) };
    if rc != 0 {
        return Err(rc);
    }
    if fds.is_null() {
        return Ok(Vec::new());
    }
    // SAFETY: on success `fds` is a malloc'd array of `cnt` descriptors that launchd hands over to this process;
    // each is wrapped once (and so closed once), then the array itself is freed with `free`, as `launch.h` says.
    let owned = unsafe {
        let v = std::slice::from_raw_parts(fds, cnt).iter().map(|&fd| std::os::fd::OwnedFd::from_raw_fd(fd)).collect();
        libc::free(fds.cast());
        v
    };
    Ok(owned)
}

/// Children must not inherit mvpn's own open descriptors (sudo closes the app's, but mvpn's log files, pipes and
/// lock files would otherwise reach openvpn, the bridge, the hook and the tools). Marks every descriptor from 3 up
/// to `getdtablesize()` close-on-exec in the child, after its standard streams are set up, right before `exec`.
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

#[cfg(test)]
mod tests {
    use crate::macos::exec::{Cmd, EnvMode, capture_settled};
    use std::os::fd::AsRawFd;

    /// The reviewer's probe: an fd of this process without close-on-exec must not reach a child.
    #[test]
    fn children_do_not_inherit_our_descriptors() {
        let file = std::fs::File::open("/etc/hosts").unwrap();
        // SAFETY: duplicates a valid fd to the lowest free one ≥ 100; F_DUPFD clears close-on-exec on the copy.
        let leaked = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 100) };
        assert!(leaked >= 100);
        // `stat /dev/fd/N` succeeds only for an fd the child (bash, then stat) inherited; bash's own redirections are
        // done in the forked child, so they add nothing.
        let probe =
            "for i in $(/usr/bin/seq 3 255); do /usr/bin/stat /dev/fd/$i >/dev/null 2>&1 && echo $i; done; exit 0";
        let (ok, out) = capture_settled(&Cmd::new("/bin/bash").args(["-c", probe]), EnvMode::Minimal, 4096);
        // SAFETY: closes the fd made above, owned by this test only.
        unsafe { libc::close(leaked) };
        assert!(ok);
        assert_eq!(String::from_utf8_lossy(&out), "", "inherited descriptors");
    }
}
