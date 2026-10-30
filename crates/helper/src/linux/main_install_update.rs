//! The root update step's binary (`/usr/libexec/linvpn/linvpn-install-update`). Linux only; elsewhere it exits 2.

#[cfg(target_os = "linux")]
fn main() {
    std::process::exit(macvpn_helper::linux::install_update::main())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("linvpn-install-update is LinVPN's (Linux)");
    std::process::exit(2)
}
