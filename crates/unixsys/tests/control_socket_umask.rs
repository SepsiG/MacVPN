//! `control_socket::bind` sets the process-global umask to 077 for the bind only and restores it. One test
//! only, in its own binary (process), so no parallel test changes the umask meanwhile.
#![cfg(unix)]
#![allow(unsafe_code)]

mod common;

use common::short_scratch;
use macvpn_unixsys::control_socket::bind;

/// The current umask (set and put back; nothing else in this process runs concurrently).
fn current_umask() -> libc::mode_t {
    // SAFETY: plain integer arguments; the previous value is restored at once.
    unsafe {
        let m = libc::umask(0o022);
        libc::umask(m);
        m
    }
}

#[test]
fn bind_restores_the_umask() {
    let scratch = short_scratch();
    let dir = scratch.join("control");
    for mask in [0o022, 0o002] {
        // SAFETY: plain integer argument.
        let original = unsafe { libc::umask(mask) };
        let listener = bind(&dir).unwrap();
        assert_eq!(current_umask(), mask);
        drop(listener);
        // SAFETY: as above.
        unsafe { libc::umask(original) };
    }
}
