//! Which Windows network adapter is a VPN's or otherwise virtual, from what `GetAdaptersAddresses` reports (pure).
//! WinVPN's app uses it to find the physical network (auto-reconnect), its service to find the physical network's
//! own DNS (the names that stay local while a VPN holds DNS).

/// `IF_TYPE_*` of interfaces that are never the physical network: PPP (RAS), software loopback, proprietary virtual
/// (WireGuard, OpenVPN DCO, Wintun), tunnel.
const VIRTUAL_TYPES: &[u32] = &[23, 24, 53, 131];
/// VPN adapters that present themselves as Ethernet (TAP-Windows) or might.
const VPN_DESCRIPTIONS: &[&str] = &["TAP-Windows", "OpenVPN Data Channel Offload", "WireGuard", "Wintun"];

/// A virtual interface type, or a known VPN adapter by its description.
///
/// ```
/// use macvpn_core::win_adapters::is_virtual;
/// assert!(is_virtual(6, "TAP-Windows Adapter V9"));
/// assert!(!is_virtual(71, "Intel(R) Wi-Fi 6 AX201 160MHz"));
/// ```
pub fn is_virtual(if_type: u32, description: &str) -> bool {
    VIRTUAL_TYPES.contains(&if_type) || VPN_DESCRIPTIONS.iter().any(|d| description.contains(d))
}
