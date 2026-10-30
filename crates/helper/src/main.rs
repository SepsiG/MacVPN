//! `mvpn`, the helper binary: runs the backend of the operating system it was built for (see the library).
//! Installed on macOS as `/usr/local/libexec/macvpn/mvpn`.

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(macvpn_helper::macos::main())
}

#[cfg(windows)]
fn main() {
    std::process::exit(macvpn_helper::windows::main())
}

/// Linux runs no `mvpn` (LinVPN drives NetworkManager; its only root step is `linvpn-install-update`).
#[cfg(not(any(target_os = "macos", windows)))]
fn main() {
    eprintln!("mvpn is not used on this operating system");
    std::process::exit(2)
}
