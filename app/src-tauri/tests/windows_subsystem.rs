//! A release WinVPN.exe is a GUI program (PE subsystem 2): no console window opens with it. Reads the sources only;
//! `scripts/build-msi.sh` checks the built binary (`scripts/pe-imports.mjs --subsystem`).

use std::path::Path;

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The crate attribute, before any item (not an OS `cfg`: `windows_subsystem` has no effect on macOS). Debug builds
/// keep the console (the logs of `cargo run`).
#[test]
fn release_builds_use_the_windows_gui_subsystem() {
    let main = read("src/main.rs");
    let attribute = "#![cfg_attr(not(debug_assertions), windows_subsystem = \"windows\")]";
    let first_code = main.lines().find(|l| !l.starts_with("//") && !l.trim().is_empty()).unwrap();
    assert_eq!(first_code, attribute);
}

#[test]
fn the_msi_build_checks_the_subsystem_of_the_binary() {
    let script = read("../../scripts/build-msi.sh");
    // In the gates on an exe, which run on the WinVPN.exe unpacked from the MSI (what ships).
    assert!(script.contains("node scripts/pe-imports.mjs --subsystem \"$1\""));
    assert!(script.contains("[ \"$SUBSYSTEM\" = 2 ]"));
    assert!(script.contains("gate_exe \"$EXTRACT/$EXE_IN_MSI\" \"$arch\""));
    let pe = read("../../scripts/pe-imports.mjs");
    assert!(pe.contains("--subsystem"));
}

/// L-5 of the 2.0.0 security review: the DLL search is restricted to System32 before anything else runs in `main`,
/// also in the elevated step (`--winvpn-openvpn-step`, `--winvpn-trust-ca-step`) and the relauncher.
#[test]
fn main_restricts_the_dll_search_before_anything_else() {
    let main = read("src/main.rs");
    let body = main.split_once("\nfn main() {\n").expect("fn main").1;
    let first_code = body.lines().map(str::trim).find(|l| !l.starts_with("//") && !l.is_empty()).unwrap();
    assert_eq!(first_code, "platform::harden_dll_search();");
    let windows = read("src/platform/windows.rs");
    assert!(windows.contains("pub fn harden_dll_search() {\n    macvpn_platform_win::harden_dll_search();\n}"));
    let platform_win = read("../../crates/platform-win/src/lib.rs");
    assert!(platform_win.contains("pub fn harden_dll_search() {\n    macvpn_winsys::dll::harden_process_search();\n}"));
}
