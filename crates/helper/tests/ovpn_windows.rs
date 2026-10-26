//! OpenVPN on Windows, the pure parts (Task 10 of the 2b plan): the fixed `openvpn.exe` command line, the driver
//! choice per connection, the DCO-incompatibility log line, versions and the pinned installer.

use macvpn_helper::windows::ovpn_args::{self, Driver, Version};
use macvpn_helper::windows::ovpn_pins::{self, PINS};
use std::path::Path;

#[test]
fn the_argv_is_fixed_and_contains_nothing_from_the_request() {
    let run = Path::new(r"C:\ProgramData\WinVPN\run\0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0");
    let argv = ovpn_args::argv(run, 51234, Driver::Dco, false, true, false);
    let s: Vec<String> = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    assert_eq!(
        s,
        [
            "--config",
            r"C:\ProgramData\WinVPN\run\0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0\config.ovpn",
            "--script-security",
            "1",
            "--verb",
            "3",
            "--mute",
            "20",
            "--management",
            "127.0.0.1",
            "51234",
            r"C:\ProgramData\WinVPN\run\0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0\mgmt.pw",
            "--management-hold",
            "--management-query-passwords",
            "--auth-retry",
            "interact",
            "--setenv",
            "IV_SSO",
            "openurl,webauth,crtext",
            "--auth-user-pass",
        ]
    );
    let debug_keypass = ovpn_args::argv(run, 51234, Driver::TapWindows6, true, false, true);
    let s: Vec<String> = debug_keypass.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    assert!(s.windows(2).any(|w| w == ["--verb", "5"]));
    assert!(s.windows(2).any(|w| w[0] == "--askpass" && w[1].ends_with(r"\askpass")));
    assert!(!s.contains(&"--auth-user-pass".to_string()));
    // OpenVPN 2.7 ignores --windows-driver: TAP-Windows6 is chosen by disabling DCO (the same in 2.6).
    assert!(s.windows(3).any(|w| w == ["1", "--disable-dco", "--verb"]));
    assert!(!s.iter().any(|a| a == "--windows-driver"));
}

#[test]
fn the_driver_follows_the_validated_config() {
    let base = "client\ndev tun\nremote vpn.example.com 1194\n";
    let d = |extra: &str| ovpn_args::choose_driver(&format!("{base}{extra}"));
    assert_eq!(d(""), Driver::Dco);
    assert_eq!(d("data-ciphers AES-256-GCM:CHACHA20-POLY1305\n"), Driver::Dco);
    assert_eq!(d("data-ciphers ?chacha20-poly1305:AES-128-GCM\n"), Driver::Dco, "optional marker, any case");
    assert_eq!(d("compress migrate\n"), Driver::Dco, "no compression context");
    assert_eq!(d("allow-compression no\n"), Driver::Dco);
    // OpenVPN 2.7.8 (dco.c, dco_check_option / dco_check_option_ce / dco_check_startup_option; the same client rules
    // as 2.6.23): any compression context, even `compress stub-v2`, any `allow-compression` but `no` (2.7 turns `yes`
    // into `asym`), a data cipher outside DCO's AEAD list, `fragment`, a proxy, no TLS (a static `secret`) disable
    // DCO: TAP-Windows6 (no Wintun in 2.7).
    for no_dco in [
        "comp-lzo\n",
        "comp-lzo no\n",
        "compress\n",
        "compress stub-v2\n",
        "compress lz4-v2\n",
        "allow-compression asym\n",
        "allow-compression yes\n",
        "cipher AES-256-CBC\ndata-ciphers AES-256-CBC\n",
        "data-ciphers AES-256-GCM:AES-256-CBC\n",
        "data-ciphers-fallback BF-CBC\n",
        "fragment 1300\n",
        "secret [inline]\n",
        "disable-dco\n",
        "http-proxy proxy.example.com 8080\n",
        "socks-proxy proxy.example.com 1080\n",
    ] {
        assert_eq!(d(no_dco), Driver::TapWindows6, "{no_dco}");
    }
    for tap in ["dev tap\n", "dev tap0\n", "dev-type tap\n"] {
        assert_eq!(
            ovpn_args::choose_driver(&format!("client\n{tap}remote vpn.example.com 1194\n")),
            Driver::TapWindows6,
            "{tap}"
        );
    }
    assert_eq!(
        ovpn_args::choose_driver("client\ndev tap\ncomp-lzo\nremote vpn.example.com 1194\n"),
        Driver::TapWindows6,
        "layer 2 wins"
    );
    // Inside a <connection> block and through `setenv opt` too; comments and inline blocks are ignored.
    assert_eq!(d("<connection>\nremote b 1\nfragment 1300\n</connection>\n"), Driver::TapWindows6);
    assert_eq!(d("setenv opt fragment 1300\n"), Driver::TapWindows6);
    assert_eq!(d("# comp-lzo\n; fragment 1300\n<key>\ncomp-lzo\n</key>\n"), Driver::Dco);
    assert_eq!(d("windows-driver tap-windows6\n"), Driver::Dco, "never read from the config");
    assert_eq!(Driver::Dco.args(), [] as [&str; 0]);
    assert_eq!(Driver::TapWindows6.args(), ["--disable-dco"]);
    assert_eq!((Driver::Dco.name(), Driver::TapWindows6.name()), ("OpenVPN DCO", "TAP-Windows6"));
}

#[test]
fn the_dco_incompatibility_line_is_recognized() {
    use macvpn_helper::shared::ovpn_log::dco_incompatible;
    // OpenVPN 2.7.8's exact wording (the same as 2.6.23) for a pushed option DCO cannot run (comp.c check_compression_settings_valid,
    // init.c do_deferred_options / dco.c dco_check_pull_options, ssl.c init_key_ctx_bi with DCO).
    assert!(dco_incompatible(
        b"2026-10-22 10:00:00 Compression or compression stub framing is not allowed since data-channel offloading is enabled."
    ));
    assert!(dco_incompatible(
        b"2026-10-22 10:00:00 OPTIONS ERROR: pushed options are incompatible with data channel offload. Use --disable-dco to connect to this server"
    ));
    assert!(dco_incompatible(b"2026-10-22 10:00:00 FATAL: DCO does not support --auth"));
    assert!(!dco_incompatible(b"2026-10-22 10:00:00 Initialization Sequence Completed"));
    // Startup notes are not failures: OpenVPN falls back to TAP-Windows6 itself.
    assert!(!dco_incompatible(b"2026-10-22 10:00:00 Note: --fragment disables data channel offload."));
    // A pushed line echoed by the server is not OpenVPN's own message.
    assert!(!dco_incompatible(b"2026-10-22 10:00:00 ECHO: pushed options are incompatible with data channel offload"));
}

#[test]
fn versions_compare_and_parse() {
    assert_eq!(Version::parse("2.6.14"), Some(Version(2, 6, 14)));
    assert_eq!(Version::from_file_version((2, 6, 14, 0)), Version(2, 6, 14));
    assert!(Version(2, 6, 0) <= Version(2, 6, 14) && Version(2, 5, 9) < Version(2, 6, 0));
    assert_eq!(Version::parse("2.6"), None);
    assert_eq!(Version::parse("2.6.x"), None);
    assert_eq!(Version::parse("2.6.1.0"), None);
    assert_eq!(Version::parse("2.6.+1"), None);
    assert_eq!(Version::parse("2.6.999999"), None);
    assert_eq!(Version(2, 6, 23).to_string(), "2.6.23");
}

#[test]
fn the_pins_parse_strictly() {
    let text =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/pins/openvpn.txt")).unwrap();
    assert!(ovpn_pins::parse(&text).is_ok());
    let without_signer: String =
        text.lines().filter(|l| !l.starts_with("signer\t")).map(|l| format!("{l}\n")).collect();
    assert!(ovpn_pins::parse(&without_signer).is_err(), "every key is required");
    assert!(ovpn_pins::parse(&format!("{text}signer\tSomeone Else\n")).is_err(), "every key exactly once");
    assert!(ovpn_pins::parse(&format!("{text}extra\tvalue\n")).is_err(), "unknown keys refused");
    assert!(ovpn_pins::parse(&text.replacen("signer\t", "signer ", 1)).is_err(), "tab-separated");
    assert!(ovpn_pins::parse(&text.replacen("min_version\t2.6.0", "min_version\t", 1)).is_err(), "no empty value");
}

#[test]
fn the_pins_are_complete_and_the_app_copy_is_current() {
    let text =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/pins/openvpn.txt")).unwrap();
    let pins = ovpn_pins::parse(&text).unwrap();
    assert_eq!(pins, *PINS);
    assert!(Version::parse(&pins.version).unwrap() >= Version::parse(&pins.min_version).unwrap());
    for (url, sha, arch) in
        [(&pins.msi_x64_url, &pins.msi_x64_sha256, "amd64"), (&pins.msi_arm64_url, &pins.msi_arm64_sha256, "arm64")]
    {
        assert!(url.starts_with("https://swupdate.openvpn.org/community/releases/OpenVPN-"), "{url}");
        assert!(
            url.starts_with(&format!("https://swupdate.openvpn.org/community/releases/OpenVPN-{}-I", pins.version))
        );
        assert!(url.ends_with(&format!("-{arch}.msi")), "{url}");
        assert!(sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "{sha}");
    }
    assert!(!pins.signer.is_empty());
    // M-1 of the 2.0.0 security review: the signer's issuing CA key (DigiCert Trusted G4 Code Signing RSA4096
    // SHA384 2021 CA1; OpenVPN Inc.'s certificates of 2.6.0 to 2.7.8 all chain to it).
    assert_eq!(pins.signer_cas(), ["4448d301cce6845000da99faf2b70baf3637601e9e1f940137943fe811a9ab32"]);
    let key = "signer_ca_spki_sha256\t4448d301cce6845000da99faf2b70baf3637601e9e1f940137943fe811a9ab32";
    assert!(text.contains(&format!("{key}\n")));
    for bad in [String::new(), format!("{key},"), key.to_uppercase(), key[..key.len() - 1].to_owned()] {
        let changed = text.replacen(&format!("{key}\n"), &format!("{bad}\n"), 1);
        assert!(ovpn_pins::parse(&changed).is_err(), "{bad:?}");
    }
    // A plain service name: Task 17 disables this service after its own install.
    assert!(pins.interactive_service.bytes().all(|b| b.is_ascii_alphanumeric()), "{}", pins.interactive_service);
    // Decision 4 (amended 2026-10-22): openvpn.exe, DCO and TAP-Windows6; never Wintun (OpenVPN 2.7 has none), the
    // GUI or the OpenVPN.Service feature.
    for features in [&pins.msi_x64_features, &pins.msi_arm64_features] {
        let list: Vec<&str> = features.split(',').collect();
        for needed in ["OpenVPN", "Drivers", "Drivers.OvpnDco", "Drivers.TAPWindows6"] {
            assert!(list.contains(&needed), "{features}");
        }
        assert!(!list.iter().any(|f| f.starts_with("OpenVPN.") || f.is_empty()), "{features}");
        assert!(!list.iter().any(|f| f.to_ascii_lowercase().contains("wintun")), "{features}");
    }
    // The app's copy (platform-win/src/pure/openvpn_pins.rs) is generated from the same file.
    let generated = ovpn_pins::render_rust(&pins);
    let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../platform-win/src/pure/openvpn_pins.rs");
    if std::env::var_os("WINVPN_WRITE_PINS").is_some() {
        std::fs::write(&app, &generated).unwrap();
    }
    assert_eq!(std::fs::read_to_string(&app).unwrap(), generated, "run with WINVPN_WRITE_PINS=1");
}
