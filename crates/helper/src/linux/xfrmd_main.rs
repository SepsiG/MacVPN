//! `linvpn-xfrmd` (`/usr/libexec/linvpn/linvpn-xfrmd`): socket-activated by `linvpn-xfrmd.socket`, the accepted
//! connection on stdin. Linux only; elsewhere it exits 2.

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(macvpn_helper::linux::xfrmd::main())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("linvpn-xfrmd is LinVPN's (Linux)");
    std::process::exit(2)
}
