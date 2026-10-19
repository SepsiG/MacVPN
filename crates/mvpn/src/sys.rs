//! The only module with `unsafe` code: thin, audited wrappers around the libc calls `std` does not offer.
//!
//! Every function here is a direct call with plain integer arguments or with buffers whose length is passed
//! alongside; none of them keeps a pointer past the call. Everything else in the crate is safe Rust.
#![allow(unsafe_code)]

use std::ffi::{CStr, CString, OsString};
use std::os::unix::ffi::OsStringExt;
use std::sync::atomic::{AtomicBool, Ordering};

/// Effective user id.
pub fn geteuid() -> u32 {
    // SAFETY: no arguments, cannot fail.
    unsafe { libc::geteuid() }
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
    pub home: OsString,
}

/// Copies a `passwd` record; `p` must be a valid pointer returned by `getpw*_r`.
fn user_from(p: &libc::passwd) -> Option<User> {
    if p.pw_name.is_null() {
        return None;
    }
    // SAFETY: `pw_name` / `pw_dir` point into the caller-owned buffer of the `getpw*_r` call, NUL terminated.
    let name = unsafe { CStr::from_ptr(p.pw_name) }.to_str().ok()?.to_string();
    let home = if p.pw_dir.is_null() {
        OsString::new()
    } else {
        // SAFETY: as above.
        OsString::from_vec(unsafe { CStr::from_ptr(p.pw_dir) }.to_bytes().to_vec())
    };
    Some(User { name, uid: p.pw_uid, gid: p.pw_gid, home })
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
    use crate::exec::{Cmd, EnvMode, capture_settled};
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
