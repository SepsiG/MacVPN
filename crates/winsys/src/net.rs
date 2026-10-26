//! The network reads auto-reconnect needs, behind safe functions. All of them only read; none needs administrator
//! rights.
//!
//! - [`adapters`]: every adapter with its unicast prefixes (`GetAdaptersAddresses`), its interface GUID
//!   (`ConvertInterfaceLuidToGuid`) and its best default route with the route metric plus the interface metric
//!   (`GetIpForwardTable2`).
//! - [`neighbor_mac`]: the gateway's MAC (`ResolveIpNetEntry2`, which sends ARP / NDP itself when the neighbour is
//!   not cached; it may block for a few seconds when nobody answers).
//! - [`wlan_ssid`]: the Wi-Fi SSID (`WlanQueryInterface`, `wlan_intf_opcode_current_connection`). `wlanapi.dll` is
//!   loaded from System32 at the call (not imported: a Windows without it still starts the app); a missing DLL or
//!   WLAN service, a non-Wi-Fi interface, no connection, and access denied (Windows 11 24H2 without location
//!   permission) are all "unknown".
//! - [`watch`]: a change watch (`NotifyIpInterfaceChange` + `NotifyRouteChange2`).
//!
//! Every `unsafe` block says why it is sound.

use crate::dll::Library;
use std::ffi::c_void;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use windows_sys::Win32::Foundation::{
    ERROR_BAD_NET_NAME, ERROR_BUFFER_OVERFLOW, ERROR_HOST_UNREACHABLE, ERROR_NETWORK_UNREACHABLE, ERROR_NO_DATA,
    ERROR_NOT_FOUND, HANDLE, NO_ERROR, WIN32_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, ConvertInterfaceLuidToGuid, FreeMibTable, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetIpForwardTable2, IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_IPNET_ROW2, MIB_NOTIFICATION_TYPE, NotifyIpInterfaceChange,
    NotifyRouteChange2, ResolveIpNetEntry2,
};
use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows_sys::Win32::NetworkManagement::WiFi::{
    WLAN_CONNECTION_ATTRIBUTES, WLAN_INTF_OPCODE, WLAN_OPCODE_VALUE_TYPE, wlan_interface_state_connected,
    wlan_intf_opcode_current_connection,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, NlnsIncomplete, NlnsUnreachable, SOCKADDR,
    SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
};
use windows_sys::core::GUID;

/// What [`adapters`] reads of one adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAdapter {
    /// The friendly name ("Wi-Fi", "Ethernet 2").
    pub alias: String,
    /// `IF_TYPE_*`.
    pub if_type: u32,
    pub description: String,
    /// The operational status is up.
    pub up: bool,
    /// The next hop of the adapter's best default route (`0.0.0.0` / `::` for an on-link one), if it has one.
    pub gateway: Option<IpAddr>,
    /// That route's metric plus the adapter's interface metric of its family; `u32::MAX` without a default route.
    pub route_metric: u32,
    /// (address, on-link prefix length) of each unicast address.
    pub unicast: Vec<(IpAddr, u8)>,
    pub luid: u64,
    /// The interface GUID in its in-memory layout (what `WlanQueryInterface` takes); zero when it cannot be read.
    pub guid: [u8; 16],
}

fn check(code: WIN32_ERROR) -> io::Result<()> {
    if code == NO_ERROR { Ok(()) } else { Err(io::Error::from_raw_os_error(code as i32)) }
}

fn guid_bytes(g: &GUID) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&g.data1.to_le_bytes());
    out[4..6].copy_from_slice(&g.data2.to_le_bytes());
    out[6..8].copy_from_slice(&g.data3.to_le_bytes());
    out[8..].copy_from_slice(&g.data4);
    out
}

fn guid_from(b: [u8; 16]) -> GUID {
    GUID {
        data1: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        data2: u16::from_le_bytes([b[4], b[5]]),
        data3: u16::from_le_bytes([b[6], b[7]]),
        data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
    }
}

/// The address in a `SOCKADDR_INET` (`None`: another family).
fn ip_of_inet(a: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: every member of the union starts with the family; the member read is the one the family names.
    unsafe {
        match a.si_family {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(a.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(a.Ipv6.sin6_addr.u.Byte))),
            _ => None,
        }
    }
}

/// The address a `SOCKADDR` pointer of `len` bytes holds (`None`: null, too short or another family).
///
/// # Safety
/// `sa`, when not null, points to at least `len` readable bytes.
unsafe fn ip_of_sockaddr(sa: *const SOCKADDR, len: i32) -> Option<IpAddr> {
    if sa.is_null() || (len as usize) < std::mem::size_of::<SOCKADDR>() {
        return None;
    }
    // SAFETY: at least a SOCKADDR's bytes are readable (checked above; the caller's contract); the cast members are
    // read only when the length covers them. `read_unaligned`: the system's buffers are aligned, but cheap to not
    // rely on it.
    unsafe {
        match (*sa).sa_family {
            AF_INET if len as usize >= std::mem::size_of::<SOCKADDR_IN>() => {
                let v4 = sa.cast::<SOCKADDR_IN>().read_unaligned();
                Some(IpAddr::V4(Ipv4Addr::from(v4.sin_addr.S_un.S_addr.to_ne_bytes())))
            }
            AF_INET6 if len as usize >= std::mem::size_of::<SOCKADDR_IN6>() => {
                let v6 = sa.cast::<SOCKADDR_IN6>().read_unaligned();
                Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.u.Byte)))
            }
            _ => None,
        }
    }
}

/// A `SOCKADDR_INET` with port 0.
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

/// A NUL-terminated wide string from the system (`None` for null).
///
/// # Safety
/// `p`, when not null, points to a NUL-terminated UTF-16 string.
unsafe fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: the string is NUL-terminated (the caller's contract): every index up to the NUL is readable.
    unsafe {
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// One default route: (next hop, route metric).
struct DefaultRoute {
    luid: u64,
    next_hop: IpAddr,
    metric: u32,
}

/// Every default route (`0.0.0.0/0`, `::/0`) of the system's forwarding table.
fn default_routes() -> io::Result<Vec<DefaultRoute>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: `table` is a valid out pointer; on success the system allocated the table, freed below.
    check(unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) })?;
    let mut out = Vec::new();
    // SAFETY: the table holds `NumEntries` rows starting at `Table` (a variable-length array); it is freed exactly
    // once, after the last read.
    unsafe {
        let rows: &[MIB_IPFORWARD_ROW2] =
            std::slice::from_raw_parts((&raw const (*table).Table).cast(), (*table).NumEntries as usize);
        for row in rows {
            if row.DestinationPrefix.PrefixLength != 0 {
                continue;
            }
            if let Some(next_hop) = ip_of_inet(&row.NextHop) {
                out.push(DefaultRoute { luid: row.InterfaceLuid.Value, next_hop, metric: row.Metric });
            }
        }
        FreeMibTable(table.cast());
    }
    Ok(out)
}

/// Every adapter (`AF_UNSPEC`); the buffer grows on `ERROR_BUFFER_OVERFLOW` (at most 3 tries). An adapter's default
/// route is the best of its own: one through a real next hop before an on-link one, IPv4 before IPv6 (the IPv6
/// router's address may change with router advertisements; IPv4's is the stable identity), then the lowest metric.
pub fn adapters() -> io::Result<Vec<RawAdapter>> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let Some(buf) = adapter_buffer(flags)? else { return Ok(Vec::new()) };
    let routes = default_routes()?;

    let mut out = Vec::new();
    let mut p = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !p.is_null() {
        // SAFETY: `p` is the first entry or a `Next` link of the list GetAdaptersAddresses wrote into `buf`, which
        // lives until the end of this function; every pointer inside points into `buf` or is null.
        let a = unsafe { &*p };
        // SAFETY: `a` is an entry of `buf` (above).
        let unicast = unsafe { unicast_of(a) };
        // SAFETY: plain value of a union of a u64 and its bit fields.
        let luid = unsafe { a.Luid.Value };
        let mut guid = GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] };
        // SAFETY: both pointers are valid for the call.
        let guid = match unsafe { ConvertInterfaceLuidToGuid(&a.Luid, &mut guid) } {
            NO_ERROR => guid_bytes(&guid),
            _ => [0; 16],
        };
        let best = routes
            .iter()
            .filter(|r| r.luid == luid)
            .map(|r| {
                let if_metric = if r.next_hop.is_ipv4() { a.Ipv4Metric } else { a.Ipv6Metric };
                (r, r.metric.saturating_add(if_metric))
            })
            .min_by_key(|(r, total)| (r.next_hop.is_unspecified(), r.next_hop.is_ipv6(), *total));
        out.push(RawAdapter {
            // SAFETY: the system's NUL-terminated strings inside `buf` (or null).
            alias: unsafe { from_wide(a.FriendlyName) },
            if_type: a.IfType,
            // SAFETY: as above.
            description: unsafe { from_wide(a.Description) },
            up: a.OperStatus == IfOperStatusUp,
            gateway: best.map(|(r, _)| r.next_hop),
            route_metric: best.map_or(u32::MAX, |(_, total)| total),
            unicast,
            luid,
            guid,
        });
        p = a.Next;
    }
    Ok(out)
}

/// The unicast addresses of one adapter entry.
///
/// # Safety
/// `a` is an entry of a list `GetAdaptersAddresses` wrote into a buffer that outlives the call.
unsafe fn unicast_of(a: &IP_ADAPTER_ADDRESSES_LH) -> Vec<(IpAddr, u8)> {
    let mut unicast = Vec::new();
    let mut u = a.FirstUnicastAddress;
    while !u.is_null() {
        // SAFETY: a link of the unicast list inside the caller's buffer (the contract).
        let entry = unsafe { &*u };
        // SAFETY: the system's SOCKET_ADDRESS: `lpSockaddr` points to `iSockaddrLength` bytes inside the buffer.
        if let Some(ip) = unsafe { ip_of_sockaddr(entry.Address.lpSockaddr, entry.Address.iSockaddrLength) } {
            unicast.push((ip, entry.OnLinkPrefixLength));
        }
        u = entry.Next;
    }
    unicast
}

/// `GetAdaptersAddresses(AF_UNSPEC, flags)` into an aligned buffer that grows on `ERROR_BUFFER_OVERFLOW` (at most 3
/// tries); `None`: no adapter (`ERROR_NO_DATA`).
fn adapter_buffer(flags: u32) -> io::Result<Option<Vec<u64>>> {
    // u64 words: the buffer is aligned for IP_ADAPTER_ADDRESSES_LH.
    let mut size: u32 = 16 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    let mut code = ERROR_BUFFER_OVERFLOW;
    for _ in 0..3 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        size = (buf.len() * 8) as u32;
        // SAFETY: `buf` is writable for `size` bytes and aligned; `size` is updated to the needed size on overflow.
        code = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                std::ptr::null(),
                buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut size,
            )
        };
        if code != ERROR_BUFFER_OVERFLOW {
            break;
        }
    }
    if code == ERROR_NO_DATA {
        return Ok(None);
    }
    check(code)?;
    Ok(Some(buf))
}

/// The neighbour's MAC on `luid`; `Ok(None)` when it does not answer (unreachable, not Ethernet-like).
pub fn neighbor_mac(luid: u64, ip: IpAddr) -> io::Result<Option<[u8; 6]>> {
    let mut row =
        MIB_IPNET_ROW2 { Address: sockaddr(&ip), InterfaceLuid: NET_LUID_LH { Value: luid }, ..Default::default() };
    // SAFETY: `row` is a valid, writable MIB_IPNET_ROW2 with the address and interface set; no source address.
    let code = unsafe { ResolveIpNetEntry2(&mut row, std::ptr::null()) };
    match code {
        NO_ERROR => {}
        ERROR_BAD_NET_NAME | ERROR_NOT_FOUND | ERROR_NETWORK_UNREACHABLE | ERROR_HOST_UNREACHABLE => return Ok(None),
        _ => return Err(io::Error::from_raw_os_error(code as i32)),
    }
    if row.PhysicalAddressLength != 6 || row.State == NlnsUnreachable || row.State == NlnsIncomplete {
        return Ok(None);
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&row.PhysicalAddress[..6]);
    Ok((mac != [0; 6]).then_some(mac))
}

type WlanOpenHandle = unsafe extern "system" fn(u32, *const c_void, *mut u32, *mut HANDLE) -> u32;
type WlanCloseHandle = unsafe extern "system" fn(HANDLE, *const c_void) -> u32;
type WlanFreeMemory = unsafe extern "system" fn(*const c_void);
type WlanQueryInterface = unsafe extern "system" fn(
    HANDLE,
    *const GUID,
    WLAN_INTF_OPCODE,
    *const c_void,
    *mut u32,
    *mut *mut c_void,
    *mut WLAN_OPCODE_VALUE_TYPE,
) -> u32;

/// The SSID the Wi-Fi interface `guid` is connected to; `Ok(None)` when not connected, not readable or denied
/// (location permission), when the interface is not a Wi-Fi one, and on a Windows without the WLAN service.
pub fn wlan_ssid(guid: [u8; 16]) -> io::Result<Option<String>> {
    let Ok(dir) = crate::known::system32() else { return Ok(None) };
    let Ok(lib) = Library::load(&dir.join("wlanapi.dll")) else { return Ok(None) };
    // SAFETY: each address is the named export of wlanapi.dll, whose documented signature the type spells; `lib`
    // outlives every call below.
    let (open, close, free, query) = unsafe {
        (
            std::mem::transmute::<*const c_void, WlanOpenHandle>(lib.symbol(c"WlanOpenHandle")?),
            std::mem::transmute::<*const c_void, WlanCloseHandle>(lib.symbol(c"WlanCloseHandle")?),
            std::mem::transmute::<*const c_void, WlanFreeMemory>(lib.symbol(c"WlanFreeMemory")?),
            std::mem::transmute::<*const c_void, WlanQueryInterface>(lib.symbol(c"WlanQueryInterface")?),
        )
    };
    let mut version = 0u32;
    let mut handle: HANDLE = std::ptr::null_mut();
    // SAFETY: client version 2 (Vista and later); valid out pointers. A failure (no WLAN service) is "unknown".
    if unsafe { open(2, std::ptr::null(), &mut version, &mut handle) } != NO_ERROR {
        return Ok(None);
    }
    let guid = guid_from(guid);
    let mut size = 0u32;
    let mut data: *mut c_void = std::ptr::null_mut();
    // SAFETY: an open handle; `guid` and the out pointers live across the call; the value type is not needed.
    let code = unsafe {
        query(
            handle,
            &guid,
            wlan_intf_opcode_current_connection,
            std::ptr::null(),
            &mut size,
            &mut data,
            std::ptr::null_mut(),
        )
    };
    let mut ssid = None;
    if code == NO_ERROR && !data.is_null() && size as usize >= std::mem::size_of::<WLAN_CONNECTION_ATTRIBUTES>() {
        // SAFETY: the system returned a WLAN_CONNECTION_ATTRIBUTES of `size` bytes at `data` (checked above); it
        // is read before WlanFreeMemory.
        let attrs = unsafe { data.cast::<WLAN_CONNECTION_ATTRIBUTES>().read_unaligned() };
        let raw = attrs.wlanAssociationAttributes.dot11Ssid;
        let len = (raw.uSSIDLength as usize).min(raw.ucSSID.len());
        if attrs.isState == wlan_interface_state_connected && len > 0 {
            ssid = Some(String::from_utf8_lossy(&raw.ucSSID[..len]).into_owned());
        }
    }
    // Every other answer is "unknown": access denied (no location permission), not connected
    // (ERROR_INVALID_STATE), not a Wi-Fi interface (ERROR_NOT_FOUND / ERROR_INVALID_PARAMETER).
    // SAFETY: `data` came from WlanQueryInterface (freed once, here, when set); the handle is closed exactly once.
    unsafe {
        if !data.is_null() {
            free(data);
        }
        close(handle, std::ptr::null());
    }
    Ok(ssid)
}

type Callback = Box<dyn Fn() + Send + Sync>;

/// Calls `on_change` from the system's notification threads on any interface or route change; dropping it cancels
/// both registrations (`CancelMibChangeNotify2`, which waits for running callbacks) and frees the callback after.
/// Never drop it from inside the callback (the cancel would wait for itself).
pub struct NetWatch {
    interface: HANDLE,
    route: HANDLE,
    callback: *mut Callback,
}

// SAFETY: the two notification handles may be cancelled from any thread; the callback box is `Send + Sync` and is
// only reclaimed in `drop`, after both registrations are gone.
unsafe impl Send for NetWatch {}

unsafe extern "system" fn on_interface(
    context: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _t: MIB_NOTIFICATION_TYPE,
) {
    // SAFETY: `context` is the `*mut Callback` registered by `watch`, alive until both registrations are cancelled.
    unsafe { call(context) }
}

unsafe extern "system" fn on_route(context: *const c_void, _row: *const MIB_IPFORWARD_ROW2, _t: MIB_NOTIFICATION_TYPE) {
    // SAFETY: as in `on_interface`.
    unsafe { call(context) }
}

/// # Safety
/// `context` is a live `*mut Callback`.
unsafe fn call(context: *const c_void) {
    // SAFETY: the caller's contract; the callback is only borrowed.
    let f = unsafe { &*context.cast::<Callback>() };
    // A panic must not unwind into the system's thread.
    let _ = catch_unwind(AssertUnwindSafe(f));
}

pub fn watch(on_change: Box<dyn Fn() + Send + Sync>) -> io::Result<NetWatch> {
    let callback: *mut Callback = Box::into_raw(Box::new(on_change));
    let mut interface: HANDLE = std::ptr::null_mut();
    // SAFETY: a callback with the documented signature; the context outlives the registration (reclaimed only
    // after the cancel); no initial notification.
    let code = unsafe {
        NotifyIpInterfaceChange(AF_UNSPEC, Some(on_interface), callback as *const c_void, false, &mut interface)
    };
    if code != NO_ERROR {
        // SAFETY: never registered: the box is reclaimed once, here.
        drop(unsafe { Box::from_raw(callback) });
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let mut route: HANDLE = std::ptr::null_mut();
    // SAFETY: as above.
    let code = unsafe { NotifyRouteChange2(AF_UNSPEC, Some(on_route), callback as *const c_void, false, &mut route) };
    if code != NO_ERROR {
        // SAFETY: the first registration is cancelled (waiting for its running callbacks) before the box goes.
        unsafe {
            CancelMibChangeNotify2(interface);
            drop(Box::from_raw(callback));
        }
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    Ok(NetWatch { interface, route, callback })
}

impl Drop for NetWatch {
    fn drop(&mut self) {
        // SAFETY: both handles came from successful registrations and are cancelled once; CancelMibChangeNotify2
        // returns after running callbacks finished, so the box is unused when it is reclaimed (once, here).
        unsafe {
            CancelMibChangeNotify2(self.interface);
            CancelMibChangeNotify2(self.route);
            drop(Box::from_raw(self.callback));
        }
    }
}

// MARK: - The WinVPN Service's debug diagnostics (WinVPN 2c, G-6): read-only, like everything above.

/// One route of the system's IPv4 forwarding table (`GetIpForwardTable2(AF_INET)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRoute {
    pub destination: IpAddr,
    pub prefix_len: u8,
    /// `0.0.0.0` for an on-link route.
    pub next_hop: IpAddr,
    pub luid: u64,
    /// The route's own metric (Windows adds the interface's: [`AdapterDiag::ipv4_metric`]).
    pub metric: u32,
}

/// Every IPv4 route.
pub fn ipv4_routes() -> io::Result<Vec<RawRoute>> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: `table` is a valid out pointer; on success the system allocated the table, freed below.
    check(unsafe { GetIpForwardTable2(AF_INET, &mut table) })?;
    let mut out = Vec::new();
    // SAFETY: the table holds `NumEntries` rows starting at `Table` (a variable-length array); it is freed exactly
    // once, after the last read.
    unsafe {
        let rows: &[MIB_IPFORWARD_ROW2] =
            std::slice::from_raw_parts((&raw const (*table).Table).cast(), (*table).NumEntries as usize);
        for row in rows {
            if let (Some(destination), Some(next_hop)) =
                (ip_of_inet(&row.DestinationPrefix.Prefix), ip_of_inet(&row.NextHop))
            {
                out.push(RawRoute {
                    destination,
                    prefix_len: row.DestinationPrefix.PrefixLength,
                    next_hop,
                    luid: row.InterfaceLuid.Value,
                    metric: row.Metric,
                });
            }
        }
        FreeMibTable(table.cast());
    }
    Ok(out)
}

/// What the diagnostics read of one adapter (`GetAdaptersAddresses` with its DNS servers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterDiag {
    pub luid: u64,
    /// The friendly name ("Wi-Fi", "Ethernet 2").
    pub alias: String,
    pub up: bool,
    /// (address, on-link prefix length) of each unicast address.
    pub unicast: Vec<(IpAddr, u8)>,
    pub dns: Vec<IpAddr>,
    pub ipv4_metric: u32,
}

/// Every adapter with its addresses and DNS servers.
pub fn adapters_with_dns() -> io::Result<Vec<AdapterDiag>> {
    let Some(buf) = adapter_buffer(GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST)? else { return Ok(Vec::new()) };
    let mut out = Vec::new();
    let mut p = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !p.is_null() {
        // SAFETY: `p` is the first entry or a `Next` link of the list GetAdaptersAddresses wrote into `buf`, which
        // lives until the end of this function; every pointer inside points into `buf` or is null.
        let a = unsafe { &*p };
        let mut dns = Vec::new();
        let mut d = a.FirstDnsServerAddress;
        while !d.is_null() {
            // SAFETY: a link of the DNS server list inside `buf`.
            let entry = unsafe { &*d };
            // SAFETY: the system's SOCKET_ADDRESS: `lpSockaddr` points to `iSockaddrLength` bytes inside `buf`.
            if let Some(ip) = unsafe { ip_of_sockaddr(entry.Address.lpSockaddr, entry.Address.iSockaddrLength) } {
                dns.push(ip);
            }
            d = entry.Next;
        }
        out.push(AdapterDiag {
            // SAFETY: plain value of a union of a u64 and its bit fields.
            luid: unsafe { a.Luid.Value },
            // SAFETY: the system's NUL-terminated string inside `buf` (or null).
            alias: unsafe { from_wide(a.FriendlyName) },
            up: a.OperStatus == IfOperStatusUp,
            // SAFETY: `a` is an entry of `buf` (above).
            unicast: unsafe { unicast_of(a) },
            dns,
            ipv4_metric: a.Ipv4Metric,
        });
        p = a.Next;
    }
    Ok(out)
}
