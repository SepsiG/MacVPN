//! IP Helper on the service's own WireGuard adapter: addresses, on-link routes, the interface metric and MTU, DNS.
//! Every call names the adapter by the LUID (or the GUID derived from it) that wireguard-nt returned for the adapter
//! the service just created, never by a name or index from a request. Everything set here belongs to that adapter
//! and goes away with it (`WireGuardCloseAdapter` deletes the adapter). Each function returns the Win32 error.

use crate::windows::wg_plan::Prefix;
use std::io;
use std::net::IpAddr;
use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR, WIN32_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToGuid, CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS,
    DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, DNS_SETTING_SEARCHLIST,
    GetIpInterfaceEntry, InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetInterfaceDnsSettings, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IpDadStatePreferred, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_INET,
};
use windows_sys::core::GUID;

fn check(code: WIN32_ERROR) -> io::Result<()> {
    if code == NO_ERROR { Ok(()) } else { Err(io::Error::from_raw_os_error(code as i32)) }
}

pub fn family(ip: &IpAddr) -> ADDRESS_FAMILY {
    if ip.is_ipv4() { AF_INET } else { AF_INET6 }
}

/// A `SOCKADDR_INET` with port 0 (an address, not an endpoint).
fn sockaddr(ip: &IpAddr) -> SOCKADDR_INET {
    match ip {
        IpAddr::V4(a) => SOCKADDR_INET {
            Ipv4: SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: 0,
                sin_addr: IN_ADDR { S_un: IN_ADDR_0 { S_addr: u32::from_ne_bytes(a.octets()) } },
                sin_zero: [0; 8],
            },
        },
        IpAddr::V6(a) => SOCKADDR_INET {
            Ipv6: SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR { u: IN6_ADDR_0 { Byte: a.octets() } },
                ..Default::default()
            },
        },
    }
}

/// The adapter's address with its on-link prefix (`10.0.0.2/24`).
pub fn add_address(luid: NET_LUID_LH, prefix: &Prefix) -> io::Result<()> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: `row` is a valid, writable MIB_UNICASTIPADDRESS_ROW.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.Address = sockaddr(&prefix.addr());
    row.OnLinkPrefixLength = prefix.prefix_len();
    row.DadState = IpDadStatePreferred;
    // SAFETY: `row` is initialized above and lives across the call.
    check(unsafe { CreateUnicastIpAddressEntry(&row) })
}

/// An on-link route (next hop: the family's unspecified address) through the adapter, route metric 0 (the interface
/// metric decides). `prefix` is canonical (no host bits: `Plan::routes`). A route that already exists on this adapter
/// counts as added: `add_address` makes Windows create the address's on-link subnet route itself, so an AllowedIPs
/// entry equal to the Address subnet (`Address = 10.0.0.2/24`, `AllowedIPs = 10.0.0.0/24`) would otherwise fail with
/// ERROR_OBJECT_ALREADY_EXISTS (5010). Only this adapter's own routes can match: the row names its LUID.
pub fn add_route(luid: NET_LUID_LH, prefix: &Prefix) -> io::Result<()> {
    match add_route_row(luid, prefix) {
        Err(e) if e.raw_os_error() == Some(ERROR_OBJECT_ALREADY_EXISTS as i32) => Ok(()),
        other => other,
    }
}

fn add_route_row(luid: NET_LUID_LH, prefix: &Prefix) -> io::Result<()> {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: `row` is a valid, writable MIB_IPFORWARD_ROW2.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.DestinationPrefix.Prefix = sockaddr(&prefix.addr());
    row.DestinationPrefix.PrefixLength = prefix.prefix_len();
    let unspecified: IpAddr = if prefix.addr().is_ipv4() { [0u8; 4].into() } else { [0u8; 16].into() };
    row.NextHop = sockaddr(&unspecified);
    row.Metric = 0;
    // SAFETY: `row` is initialized above and lives across the call.
    check(unsafe { CreateIpForwardEntry2(&row) })
}

/// The adapter's interface metric (not automatic) and, when given, its MTU, for one address family.
pub fn set_interface(luid: NET_LUID_LH, family: ADDRESS_FAMILY, metric: u32, mtu: Option<u32>) -> io::Result<()> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    // SAFETY: `row` is a valid, writable MIB_IPINTERFACE_ROW.
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = family;
    row.InterfaceLuid = luid;
    // SAFETY: as above; `Family` and `InterfaceLuid` select the row to read.
    check(unsafe { GetIpInterfaceEntry(&mut row) })?;
    row.UseAutomaticMetric = false;
    row.Metric = metric;
    if let Some(mtu) = mtu {
        row.NlMtu = mtu;
    }
    // SetIpInterfaceEntry refuses an IPv4 row whose SitePrefixLength is not 0.
    row.SitePrefixLength = 0;
    // SAFETY: `row` was read above and lives across the call.
    check(unsafe { SetIpInterfaceEntry(&mut row) })
}

/// The interface GUID of the adapter's LUID (what `SetInterfaceDnsSettings` takes).
pub fn guid_of(luid: NET_LUID_LH) -> io::Result<GUID> {
    let mut guid = GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] };
    // SAFETY: both pointers are valid for the call.
    check(unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) })?;
    Ok(guid)
}

/// NUL-terminated UTF-16.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The adapter's DNS servers of one family (`servers`: comma-separated addresses, empty clears them) and, when
/// `Some`, its search list (comma-separated domains, empty clears it). Both come from `wg_nt::dns_calls` (parsed
/// addresses, validated names).
pub fn set_dns(guid: GUID, ipv6: bool, servers: &str, search: Option<&str>) -> io::Result<()> {
    let mut name_server = wide(servers);
    let mut search_list = wide(search.unwrap_or_default());
    let mut settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(DNS_SETTING_NAMESERVER),
        NameServer: name_server.as_mut_ptr(),
        ..Default::default()
    };
    if search.is_some() {
        settings.Flags |= u64::from(DNS_SETTING_SEARCHLIST);
        settings.SearchList = search_list.as_mut_ptr();
    }
    if ipv6 {
        settings.Flags |= u64::from(DNS_SETTING_IPV6);
    }
    // SAFETY: `settings` and the two strings it points to live across the call; the API only reads them.
    check(unsafe { SetInterfaceDnsSettings(guid, &settings) })
}
