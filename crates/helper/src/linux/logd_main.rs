//! `linvpn-logd` (`/usr/libexec/linvpn/linvpn-logd`, L-b Task 18): socket-activated by `linvpn-logd.socket`, the
//! accepted connection on stdin. Linux only; elsewhere it exits 2.

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(macvpn_helper::linux::logd::main())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("linvpn-logd is LinVPN's (Linux)");
    std::process::exit(2)
}
