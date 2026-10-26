//! The VPN test lab's OpenVPN profiles (`scripts/vpn-lab/profiles.sh`) take the Windows data-channel driver they
//! are named for: `openvpn-tun-dco.ovpn` and `openvpn-static-challenge.ovpn` run on DCO, `openvpn-tun-cbc.ovpn`
//! (AES-256-CBC) and `openvpn-tap-l2.ovpn` (`dev tap`) on TAP-Windows6.
//!
//! Runs only when `MVPN_LAB_CLIENT_DIR` names a generated `client` folder (`scripts/test-vpn-lab.sh` sets it).

use macvpn_helper::windows::ovpn_args::{self, Driver};
use std::path::Path;

#[test]
fn the_lab_openvpn_profiles_choose_their_windows_driver() {
    let Some(dir) = std::env::var_os("MVPN_LAB_CLIENT_DIR") else {
        eprintln!("MVPN_LAB_CLIENT_DIR is not set: nothing to check (scripts/test-vpn-lab.sh sets it)");
        return;
    };
    let windows = Path::new(&dir).join("windows");
    for (name, driver) in [
        ("openvpn-tun-dco.ovpn", Driver::Dco),
        ("openvpn-static-challenge.ovpn", Driver::Dco),
        ("openvpn-tun-cbc.ovpn", Driver::TapWindows6),
        ("openvpn-tap-l2.ovpn", Driver::TapWindows6),
    ] {
        let text = std::fs::read_to_string(windows.join(name)).expect("profile");
        assert_eq!(ovpn_args::choose_driver(&text), driver, "{name}");
    }
}
