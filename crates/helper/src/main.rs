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

/// Linux comes with phase 4: until then, as on Windows.
#[cfg(not(any(target_os = "macos", windows)))]
fn main() {
    std::process::exit(macvpn_helper::windows::main())
}
