//! WireGuard on Windows, the pure parts (Task 9 of the 2b plan): the IP plan read from a validated config and the
//! exact bytes wireguard-nt's `WireGuardSetConfiguration` takes. Tested on every OS.

use macvpn_helper::windows::wg_nt::{self, ALLOWED_IP_SIZE, INTERFACE_SIZE, PEER_SIZE};
use macvpn_helper::windows::wg_plan::{self, Endpoint, Prefix};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

const KEY_A: &str = "bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=";
const KEY_B: &str = "bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=";

fn conf(extra_iface: &str, extra_peer: &str) -> String {
    format!(
        "[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2/32, fd00::2/128\nDNS = 10.0.0.1, corp.example\n{extra_iface}\n[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 192.0.2.10:51820\nPersistentKeepalive = 25\n{extra_peer}"
    )
}

#[test]
fn the_plan_reads_every_supported_key() {
    let p = wg_plan::parse(&conf(
        "MTU = 1380\nListenPort = 51000\n",
        "PresharedKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\n",
    ))
    .unwrap();
    assert_eq!(p.addresses, [Prefix::parse("10.0.0.2/32").unwrap(), Prefix::parse("fd00::2/128").unwrap()]);
    assert_eq!(p.dns_servers, [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
    assert_eq!(p.dns_search, ["corp.example"]);
    assert_eq!((p.mtu, p.listen_port, p.routes_enabled), (Some(1380), Some(51000), true));
    assert_eq!(p.peers.len(), 1);
    assert_eq!(p.peers[0].endpoint, Some(Endpoint::Addr(SocketAddr::from(([192, 0, 2, 10], 51820)))));
    assert_eq!(p.peers[0].keepalive, Some(25));
    assert!(p.peers[0].preshared_key.is_some());
    assert_eq!(p.routes(), [Prefix::parse("0.0.0.0/0").unwrap(), Prefix::parse("::/0").unwrap()]);
    let off = wg_plan::parse(&conf("Table = off\n", "")).unwrap();
    assert!(off.routes().is_empty());
}

#[test]
fn host_endpoints_are_kept_for_resolution() {
    let p = wg_plan::parse(&conf("", "").replace("192.0.2.10:51820", "vpn.example.com:51820")).unwrap();
    assert_eq!(p.peers[0].endpoint, Some(Endpoint::Host("vpn.example.com".into(), 51820)));
    let p = wg_plan::parse(&conf("", "").replace("192.0.2.10:51820", "[2001:db8::1]:51820")).unwrap();
    assert!(matches!(p.peers[0].endpoint, Some(Endpoint::Addr(SocketAddr::V6(_)))));
}

#[test]
fn bad_keys_and_prefixes_are_refused() {
    assert!(wg_plan::parse(&conf("", "").replace(KEY_A, "c2hvcnQ=")).is_err());
    assert!(wg_plan::parse(&conf("", "").replace("10.0.0.2/32", "10.0.0.2/33")).is_err());
    assert!(!Prefix::parse("10.0.0.1/24").unwrap().is_canonical());
}

#[test]
fn the_layout_matches_wireguard_h() {
    // Checked against wireguard-nt 1.1's wireguard.h with MSVC (Task 14, Step 1): ALIGNED(8) structs.
    assert_eq!((INTERFACE_SIZE, PEER_SIZE, ALLOWED_IP_SIZE), (80, 136, 24));
}

#[test]
fn the_configuration_bytes_are_exact() {
    let p = wg_plan::parse(&conf("ListenPort = 51000\n", "")).unwrap();
    let resolved = vec![Some(SocketAddr::from(([192, 0, 2, 10], 51820)))];
    let bytes = wg_nt::encode(&p, &resolved).unwrap();
    assert_eq!(bytes.len(), INTERFACE_SIZE + PEER_SIZE + 2 * ALLOWED_IP_SIZE);
    // Interface: flags HAS_PRIVATE_KEY | HAS_LISTEN_PORT | REPLACE_PEERS, the port, the key, one peer.
    assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 0b1110);
    assert_eq!(u16::from_le_bytes(bytes[4..6].try_into().unwrap()), 51000);
    assert_eq!(&bytes[6..38], wg_plan::decode_key(KEY_A).unwrap().as_slice());
    assert_eq!(u32::from_le_bytes(bytes[72..76].try_into().unwrap()), 1);
    // Peer: flags HAS_PUBLIC_KEY | HAS_PERSISTENT_KEEPALIVE | HAS_ENDPOINT | REPLACE_ALLOWED_IPS.
    let peer = &bytes[INTERFACE_SIZE..INTERFACE_SIZE + PEER_SIZE];
    assert_eq!(u32::from_le_bytes(peer[0..4].try_into().unwrap()), 0b10_1101);
    assert_eq!(&peer[8..40], wg_plan::decode_key(KEY_B).unwrap().as_slice());
    assert_eq!(u16::from_le_bytes(peer[72..74].try_into().unwrap()), 25);
    // SOCKADDR_INET for 192.0.2.10:51820: AF_INET (2), the port big-endian, the address.
    assert_eq!(&peer[76..84], &[2, 0, 0xCA, 0x6C, 192, 0, 2, 10]);
    assert_eq!(u32::from_le_bytes(peer[128..132].try_into().unwrap()), 2);
    // The first allowed IP: 0.0.0.0/0, AF_INET.
    let ip = &bytes[INTERFACE_SIZE + PEER_SIZE..];
    assert_eq!(&ip[0..4], &[0, 0, 0, 0]);
    assert_eq!(u16::from_le_bytes(ip[16..18].try_into().unwrap()), 2);
    assert_eq!(ip[18], 0);
    // The second: ::/0, AF_INET6 (23).
    assert_eq!(u16::from_le_bytes(ip[ALLOWED_IP_SIZE + 16..ALLOWED_IP_SIZE + 18].try_into().unwrap()), 23);
}

// The checks below go beyond the plan's listing: what the parser and the encoder refuse (fail closed).

#[test]
fn the_preshared_key_and_an_ipv6_endpoint_are_encoded() {
    let text = conf("", &format!("PresharedKey = {KEY_A}\n")).replace("192.0.2.10:51820", "[2001:db8::1]:51820");
    let p = wg_plan::parse(&text).unwrap();
    let v6 = SocketAddr::V6(SocketAddrV6::new("2001:db8::1".parse::<Ipv6Addr>().unwrap(), 51820, 0, 0));
    let bytes = wg_nt::encode(&p, &[Some(v6)]).unwrap();
    // No ListenPort: HAS_PRIVATE_KEY | REPLACE_PEERS, port 0.
    assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 0b1010);
    assert_eq!(&bytes[4..6], &[0, 0]);
    let peer = &bytes[INTERFACE_SIZE..INTERFACE_SIZE + PEER_SIZE];
    assert_eq!(u32::from_le_bytes(peer[0..4].try_into().unwrap()), 0b10_1111);
    assert_eq!(&peer[40..72], wg_plan::decode_key(KEY_A).unwrap().as_slice());
    // SOCKADDR_IN6: AF_INET6 (23), the port big-endian, flowinfo 0, the address, scope 0.
    assert_eq!(&peer[76..80], &[23, 0, 0xCA, 0x6C]);
    assert_eq!(&peer[80..84], &[0; 4]);
    assert_eq!(&peer[84..100], &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
    assert_eq!(&peer[100..104], &[0; 4]);
    // The reserved field and the statistics stay zero.
    assert_eq!(&peer[4..8], &[0; 4]);
    assert_eq!(&peer[104..128], &[0; 24]);
}

#[test]
fn the_resolved_endpoints_must_fit_the_plan() {
    let p = wg_plan::parse(&conf("", "")).unwrap();
    let addr = SocketAddr::from(([192, 0, 2, 10], 51820));
    // One entry per peer; an endpoint exactly where the config has one; an address endpoint unchanged.
    assert!(wg_nt::encode(&p, &[]).is_err());
    assert!(wg_nt::encode(&p, &[Some(addr), None]).is_err());
    assert!(wg_nt::encode(&p, &[None]).is_err());
    assert!(wg_nt::encode(&p, &[Some(SocketAddr::from(([192, 0, 2, 11], 51820)))]).is_err());
    let host = wg_plan::parse(&conf("", "").replace("192.0.2.10:51820", "vpn.example.com:51820")).unwrap();
    assert!(wg_nt::encode(&host, &[Some(SocketAddr::from(([198, 51, 100, 7], 51820)))]).is_ok());
    assert!(wg_nt::encode(&host, &[Some(SocketAddr::from(([198, 51, 100, 7], 51821)))]).is_err());
    let none = wg_plan::parse(&conf("", "").replace("Endpoint = 192.0.2.10:51820\n", "")).unwrap();
    assert_eq!(none.peers[0].endpoint, None);
    assert!(wg_nt::encode(&none, &[Some(addr)]).is_err());
    let bytes = wg_nt::encode(&none, &[None]).unwrap();
    let peer = &bytes[INTERFACE_SIZE..INTERFACE_SIZE + PEER_SIZE];
    assert_eq!(u32::from_le_bytes(peer[0..4].try_into().unwrap()), 0b10_0101);
    assert_eq!(&peer[76..104], &[0; 28]);
}

#[test]
fn what_windows_cannot_represent_is_refused() {
    let base = conf("", "");
    for bad in [
        base.replace("[Interface]\n", "[Interface]\nFwMark = 51820\n"),
        base.replace("[Interface]\n", "[Interface]\nTable = 1234\n"),
        base.replace("[Interface]\n", "[Interface]\nPostUp = calc.exe\n"),
        base.replace("[Interface]\n", &format!("[Interface]\nPrivateKey = {KEY_B}\n")),
        base.replace("Endpoint = 192.0.2.10:51820", "Endpoint = 192.0.2.10"),
        base.replace("Endpoint = 192.0.2.10:51820", "Endpoint = 192.0.2.10:0"),
        // Hosts a resolver would read as an IPv4 number (inet_aton forms).
        base.replace("192.0.2.10:51820", "010.0.0.1:51820"),
        base.replace("192.0.2.10:51820", "3221225994:51820"),
        base.replace("192.0.2.10:51820", "vpn.0x7f:51820"),
        base.replace("10.0.0.2/32", "010.0.0.2/32"),
        base.replace("DNS = 10.0.0.1", "DNS = 1.2.3"),
        format!("{base}\n[Peer]\nAllowedIPs = 10.0.0.0/8\n"),
        base.replace("PersistentKeepalive = 25", "PersistentKeepalive = 70000"),
        base.replace("[Peer]\n", &format!("[Peer]\nPublicKey = {KEY_A}\n")),
        base.replace("[Peer]", "[Other]"),
        base.replace("[Peer]\n", "[Peer]\nnonsense\n"),
        format!("{base}\n[Interface]\nPrivateKey = {KEY_A}\n"),
        base.replace(&format!("PublicKey = {KEY_B}\n"), ""),
        base.replace(&format!("PrivateKey = {KEY_A}\n"), ""),
        base.replace("\n[Peer]", "\nAllowedIPs = 10.0.0.0/8\n[Peer]"),
        base.replace("PrivateKey = ", "PrivateKey = \u{7}"),
        format!("{base}\n#{}", "x".repeat(1_048_576)),
    ] {
        assert!(wg_plan::parse(&bad).is_err(), "{bad:.300}");
    }
    // The same text with the forms Windows does represent.
    for good in [
        base.replace("[Interface]\n", "[Interface]\nTable = auto\n"),
        base.replace("PersistentKeepalive = 25", "PersistentKeepalive = off"),
        base.replace("[Interface]", "[interface] # comment"),
        base.replace("AllowedIPs = 0.0.0.0/0, ::/0", "allowedips=0.0.0.0/0\nAllowedIPs = ::/0"),
    ] {
        assert!(wg_plan::parse(&good).is_ok(), "{good}");
    }
    let off = wg_plan::parse(&base.replace("PersistentKeepalive = 25", "PersistentKeepalive = 0")).unwrap();
    assert_eq!(off.peers[0].keepalive, None);
    let random = wg_plan::parse(&conf("ListenPort = 0\n", "")).unwrap();
    assert_eq!(random.listen_port, None);
}

#[test]
fn routes_are_canonical_and_unique() {
    let text = conf("", "")
        .replace("AllowedIPs = 0.0.0.0/0, ::/0", "AllowedIPs = 10.1.2.3/16, 10.1.0.0/16, 192.0.2.1, fd00::1/64")
        + &format!("\n[Peer]\nPublicKey = {KEY_A}\nAllowedIPs = 10.1.9.9/16, 172.16.0.0/12\n");
    let p = wg_plan::parse(&text).unwrap();
    let want: Vec<Prefix> = ["10.1.0.0/16", "192.0.2.1/32", "fd00::/64", "172.16.0.0/12"]
        .iter()
        .map(|s| Prefix::parse(s).unwrap())
        .collect();
    assert_eq!(p.routes(), want);
    assert!(p.routes().iter().all(Prefix::is_canonical));
    assert_eq!(p.peers[1].endpoint, None);
    // The allowed IPs go to wireguard-nt canonical as well.
    let bytes = wg_nt::encode(&p, &[Some(SocketAddr::from(([192, 0, 2, 10], 51820))), None]).unwrap();
    let ip = &bytes[INTERFACE_SIZE + PEER_SIZE..];
    assert_eq!(&ip[0..4], &[10, 1, 0, 0]);
    assert_eq!(ip[18], 16);
    // As written (wireguard-nt merges duplicates itself): the second is 10.1.0.0/16 again, then 192.0.2.1/32.
    assert_eq!(&ip[ALLOWED_IP_SIZE..ALLOWED_IP_SIZE + 4], &[10, 1, 0, 0]);
    assert_eq!(&ip[2 * ALLOWED_IP_SIZE..2 * ALLOWED_IP_SIZE + 4], &[192, 0, 2, 1]);
    assert_eq!(ip[2 * ALLOWED_IP_SIZE + 18], 32);
    assert_eq!(bytes.len(), INTERFACE_SIZE + 2 * PEER_SIZE + 6 * ALLOWED_IP_SIZE);
    assert_eq!(u32::from_le_bytes(bytes[72..76].try_into().unwrap()), 2);
}

#[test]
fn prefixes_and_keys_parse_strictly() {
    assert_eq!(Prefix::parse("192.0.2.1").unwrap(), Prefix::parse("192.0.2.1/32").unwrap());
    assert_eq!(Prefix::parse("fd00::1").unwrap().prefix_len(), 128);
    assert_eq!(Prefix::parse("10.0.0.0/08").unwrap(), Prefix::parse("10.0.0.0/8").unwrap());
    for bad in ["10.0.0.0/", "10.0.0.0/-1", "::/129", "10.0.0.0/8/8", "x/8", "", "fe80::1%3/64"] {
        assert!(Prefix::parse(bad).is_err(), "{bad}");
    }
    assert_eq!(Prefix::parse("10.1.2.3/8").unwrap().masked(), Prefix::parse("10.0.0.0/8").unwrap());
    assert_eq!(Prefix::parse("10.1.2.3/8").unwrap().addr(), IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
    assert_eq!(wg_plan::decode_key(KEY_A).unwrap().as_slice(), b"macvpn-test-private-key-32bytes!");
    // No padding, URL-safe characters, non-zero trailing bits, 33 bytes: refused.
    for bad in [
        KEY_A.trim_end_matches('='),
        "bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE_",
        "bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyF=",
        "bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyEh",
    ] {
        assert!(wg_plan::decode_key(bad).is_err(), "{bad}");
    }
}

#[test]
fn debug_output_never_shows_a_key() {
    let p = wg_plan::parse(&conf("", &format!("PresharedKey = {KEY_A}\n"))).unwrap();
    let shown = format!("{p:?}");
    let raw = wg_plan::decode_key(KEY_A).unwrap();
    assert!(!shown.contains(KEY_A), "{shown}");
    assert!(!shown.contains(&format!("{:?}", raw.as_slice())), "{shown}");
    assert!(shown.contains("redacted"), "{shown}");
}

// Task 14: the pins, the adapter's identity and the DNS lists.

use macvpn_helper::windows::wg_pins;

#[test]
fn the_wireguard_nt_pins_parse_strictly() {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/pins/wireguard-nt.txt")).unwrap();
    let pins = wg_pins::parse(&text).unwrap();
    assert_eq!((pins.version.as_str(), pins.signer.as_str()), ("1.1", "WireGuard LLC"));
    assert_eq!(pins, *wg_pins::PINS, "the compiled-in pins are the file's");
    for hash in [&pins.zip_sha256, &pins.dll_amd64_sha256, &pins.dll_arm64_sha256] {
        assert!(hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')), "{hash}");
    }
    assert!(wg_pins::parse(&text.replacen("signer\tWireGuard LLC\n", "", 1)).is_err(), "every key is required");
    assert!(wg_pins::parse(&format!("{text}version\t1.1\n")).is_err(), "every key exactly once");
    assert!(wg_pins::parse(&format!("{text}extra\tvalue\n")).is_err(), "unknown keys refused");
    let upper = text.replacen(&pins.dll_amd64_sha256, &pins.dll_amd64_sha256.to_uppercase(), 1);
    assert!(wg_pins::parse(&upper).is_err(), "hashes are 64 lower-case hex digits");
    let short = text.replacen(&pins.dll_arm64_sha256, &pins.dll_arm64_sha256[1..], 1);
    assert!(wg_pins::parse(&short).is_err(), "hashes are 64 lower-case hex digits");
    assert!(
        wg_pins::parse(&text.replacen("zip_url\thttps://download.wireguard.com/", "zip_url\thttp://example.com/", 1))
            .is_err()
    );
    // M-1 of the 2.0.0 security review: the signer's issuing CA key (Sectigo Public Code Signing CA EV R36), a
    // comma-separated set of SPKI SHA-256 hashes, at least one.
    assert_eq!(pins.signer_cas(), ["4c2655992d5a342a1082d3c3f0ba8ade37dfb425d15d3f4a3c091609af60c112"]);
    let key = "signer_ca_spki_sha256\t4c2655992d5a342a1082d3c3f0ba8ade37dfb425d15d3f4a3c091609af60c112";
    assert!(text.contains(&format!("{key}\n")));
    let two = wg_pins::parse(&text.replacen(key, &format!("{key},{}", "0".repeat(64)), 1)).unwrap();
    assert_eq!(two.signer_cas().len(), 2);
    for bad in [
        String::new(),
        format!("{key},"),
        format!("{key}, {}", "0".repeat(64)),
        key.to_uppercase(),
        key[..key.len() - 1].to_owned(),
    ] {
        let changed = text.replacen(&format!("{key}\n"), &format!("{bad}\n"), 1);
        assert!(wg_pins::parse(&changed).is_err(), "{bad:?}");
    }
    assert_eq!(wg_pins::dll_sha256("x86_64"), Some(pins.dll_amd64_sha256.as_str()));
    assert_eq!(wg_pins::dll_sha256("aarch64"), Some(pins.dll_arm64_sha256.as_str()));
    assert_eq!(wg_pins::dll_sha256("x86"), None, "no 32-bit service");
    assert_eq!(wg_pins::dll_sha256("arm"), None);
}

#[test]
fn the_adapter_identity_is_derived_from_the_id_only() {
    let id = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
    let name = wg_nt::adapter_name(id).unwrap();
    let guid = wg_nt::adapter_guid(id).unwrap();
    // Deterministic (Windows keeps one network profile per adapter GUID), letters and digits only.
    assert_eq!(wg_nt::adapter_name(id).unwrap(), name);
    assert_eq!(wg_nt::adapter_guid(id).unwrap(), guid);
    assert!(name.len() == 14 && name.starts_with("WinVPN") && name[6..].bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(name[6..].bytes().all(|b| !b.is_ascii_uppercase()));
    // Neither is the ID itself: a caller cannot pick the GUID of an existing adapter (or a name) by choosing an ID.
    assert_ne!(&name[6..], "0f1e2d3c");
    assert_ne!(guid.to_vec(), uuid::Uuid::parse_str(id).unwrap().as_bytes().to_vec());
    // A version 4-shaped GUID (RFC 9562 variant).
    assert_eq!((guid[6] >> 4, guid[8] >> 6), (4, 0b10));
    // Another ID, another adapter; the same ID in lower case is the same one (the service passes upper case).
    assert_ne!(wg_nt::adapter_guid("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F1").unwrap(), guid);
    assert_ne!(wg_nt::adapter_name("1F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0").unwrap(), name);
    assert_eq!(wg_nt::adapter_guid(&id.to_lowercase()).unwrap(), guid);
    // Not a UUID: nothing.
    for bad in ["", "WinVPN", "0F1E2D3C4B5A69788796A5B4C3D2E1F0", "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0\0", "../x"] {
        assert_eq!(wg_nt::adapter_name(bad), None, "{bad:?}");
        assert_eq!(wg_nt::adapter_guid(bad), None, "{bad:?}");
    }
}

#[test]
fn the_dns_lists_are_built_from_parsed_values() {
    let p = wg_plan::parse(
        &conf("", "")
            .replace("DNS = 10.0.0.1, corp.example", "DNS = 10.0.0.1, fd00::1, 10.0.0.53, corp.example, lab.example."),
    )
    .unwrap();
    let dns = wg_nt::dns_lists(&p);
    assert_eq!(dns.v4.as_deref(), Some("10.0.0.1,10.0.0.53"));
    assert_eq!(dns.v6.as_deref(), Some("fd00::1"));
    assert_eq!(dns.search, "corp.example,lab.example.");
    let none = wg_plan::parse(&conf("", "").replace("DNS = 10.0.0.1, corp.example\n", "")).unwrap();
    let dns = wg_nt::dns_lists(&none);
    assert_eq!((dns.v4, dns.v6, dns.search.as_str()), (None, None, ""));
    // Search domains without a server: nothing is set (Windows would use them with the system's servers).
    let only_search = wg_plan::parse(&conf("", "").replace("10.0.0.1, ", "")).unwrap();
    let dns = wg_nt::dns_lists(&only_search);
    assert_eq!((dns.v4, dns.v6), (None, None));
}

#[test]
fn every_up_sets_or_clears_both_families_and_the_search_list() {
    use wg_nt::DnsCall;
    let call = |ipv6: bool, servers: &str, search: Option<&str>| DnsCall {
        ipv6,
        servers: servers.to_string(),
        search: search.map(str::to_string),
    };
    let full =
        wg_nt::DnsLists { v4: Some("10.0.0.1".into()), v6: Some("fd00::1".into()), search: "corp.example".into() };
    assert_eq!(wg_nt::dns_calls(&full), [call(false, "10.0.0.1", Some("corp.example")), call(true, "fd00::1", None)]);
    // A config without DNS (or a server of one family only) clears what an earlier session left under the GUID.
    let none = wg_nt::DnsLists { v4: None, v6: None, search: String::new() };
    assert_eq!(wg_nt::dns_calls(&none), [call(false, "", Some("")), call(true, "", None)]);
    let v4 = wg_nt::DnsLists { v4: Some("10.0.0.1".into()), v6: None, search: String::new() };
    assert_eq!(wg_nt::dns_calls(&v4), [call(false, "10.0.0.1", Some("")), call(true, "", None)]);
}

#[test]
fn versions_read_as_windows_reports_them() {
    assert_eq!(wg_nt::version_string((0, 10, 1, 0)), "0.10.1");
    assert_eq!(wg_nt::version_string((1, 1, 0, 0)), "1.1.0");
    assert_eq!(wg_nt::version_string((1, 2, 3, 4)), "1.2.3.4");
}

#[test]
fn allowed_ips_are_added_never_removed() {
    // wireguard-nt 1.1: `WIREGUARD_ALLOWED_IP.Flags` (offset 20) is 0 = add; `WIREGUARD_ALLOWED_IP_REMOVE` never set,
    // nor is `WIREGUARD_PEER_UPDATE_ONLY` (bit 7) on a peer.
    let p = wg_plan::parse(&conf("", "")).unwrap();
    let block = wg_nt::encode(&p, &[Some(SocketAddr::from(([192, 0, 2, 10], 51820)))]).unwrap();
    let peer = INTERFACE_SIZE;
    let flags = u32::from_le_bytes(block[peer..peer + 4].try_into().unwrap());
    assert_eq!(flags & wg_nt::PEER_UPDATE_ONLY, 0);
    for i in 0..p.peers[0].allowed.len() {
        let at = peer + PEER_SIZE + i * ALLOWED_IP_SIZE;
        assert_eq!(block[at + 20..at + 24], wg_nt::ALLOWED_IP_ADD.to_le_bytes());
        assert_eq!(block[at + 19], 0, "padding");
    }
}
