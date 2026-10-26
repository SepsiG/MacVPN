//! An adapter up and down through the console service, with real wireguard-nt (an administrator, not SYSTEM: the
//! console refuses SYSTEM). CI's windows-admin job and the maintainer (elevated Git Bash) run it, after
//! `scripts/fetch-wireguard-nt.sh`.
#![cfg(all(windows, debug_assertions))]

mod common;

use common::console::{Console, framed, wireguard_dll};
use macvpn_helper::windows::wg_nt;

const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
const CONF: &str = "[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.199.0.2/32\nDNS = 10.199.0.1\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 10.199.0.0/24\nEndpoint = 127.0.0.1:51820\n";

fn netsh(args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(r"C:\Windows\System32\netsh.exe").args(args).output().unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
#[ignore = "admin: creates a WireGuard adapter"]
fn admin_a_wireguard_adapter_comes_up_with_its_address_and_goes_away() {
    let iface = wg_nt::adapter_name(ID).unwrap();
    let dll = wireguard_dll();
    let c = Console::start_with(&["--wireguard-dll", dll.to_str().unwrap()]);
    let r = c.call(&["up", "wireguard", ID, "--lang", "en"], &framed(CONF));
    assert_eq!(r.code, 0, "{}", String::from_utf8_lossy(&r.stderr));
    let st = String::from_utf8(c.call(&["status"], b"").stdout).unwrap();
    assert!(st.contains(&iface) && st.contains("10.199.0.2") && st.contains("\"connected\""), "{st}");
    let name = format!("name={iface}");
    assert!(netsh(&["interface", "ipv4", "show", "addresses", &name]).1.contains("10.199.0.2"));
    assert!(netsh(&["interface", "ipv4", "show", "dnsservers", &name]).1.contains("10.199.0.1"));
    let routes = std::process::Command::new(r"C:\Windows\System32\route.exe")
        .args(["print", "-4", "10.199.0.0"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&routes.stdout).contains("10.199.0.0"));
    assert_eq!(c.call(&["down", "wireguard", ID], b"").code, 0);
    assert!(!netsh(&["interface", "show", "interface", &name]).0, "the adapter is gone");
}
