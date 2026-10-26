//! The WinVPN Service (`mvpn.exe` on Windows, installed as `WinVPNService.exe`) links the Visual C++ runtime
//! statically and the Universal CRT dynamically, as WinVPN.exe does (tauri-build's `static_vcruntime`): Windows
//! ships the UCRT, but not `vcruntime140.dll`, so a dynamically linked service would not start on a machine without
//! the Visual C++ Redistributable, and the MSI's ServiceControl would fail the install. The same linker arguments as
//! the `static_vcruntime` crate (3.0.0, already in Cargo.lock through tauri-build), for the `mvpn` binary only; no
//! effect on any other target (the macOS helper is unchanged). `scripts/build-msi.sh` pins the service's imports
//! (no `vcruntime140.dll`).
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }
    for lib in [
        "libvcruntimed.lib",
        "vcruntime.lib",
        "vcruntimed.lib",
        "libcmtd.lib",
        "msvcrt.lib",
        "msvcrtd.lib",
        "libucrt.lib",
        "libucrtd.lib",
    ] {
        println!("cargo:rustc-link-arg-bin=mvpn=/NODEFAULTLIB:{lib}");
    }
    for lib in ["libcmt.lib", "libvcruntime.lib", "ucrt.lib"] {
        println!("cargo:rustc-link-arg-bin=mvpn=/DEFAULTLIB:{lib}");
    }
}
