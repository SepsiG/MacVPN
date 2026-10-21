//! `TargetOs`: the operating system a build targets (the per-OS OpenVPN tier and the l10n variants).

use macvpn_core::target_os::TargetOs;

#[test]
fn host_is_the_compile_target() {
    let expected = match std::env::consts::OS {
        "macos" => TargetOs::MacOs,
        "windows" => TargetOs::Windows,
        _ => TargetOs::Linux,
    };
    assert_eq!(TargetOs::host(), expected);
    if cfg!(target_os = "macos") {
        assert_eq!(TargetOs::host(), TargetOs::MacOs);
    }
}

#[test]
fn as_str_and_parse_round_trip() {
    assert_eq!(TargetOs::ALL, [TargetOs::MacOs, TargetOs::Windows, TargetOs::Linux]);
    assert_eq!(TargetOs::ALL.map(TargetOs::as_str), ["macos", "windows", "linux"]);
    for os in TargetOs::ALL {
        assert_eq!(TargetOs::parse(os.as_str()), Some(os));
    }
}

#[test]
fn parse_is_exact() {
    for s in ["Windows", "MACOS", "macOS", "darwin", "win", "", " linux", "linux "] {
        assert_eq!(TargetOs::parse(s), None, "{s:?}");
    }
}
