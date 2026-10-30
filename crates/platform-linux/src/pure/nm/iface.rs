//! Which interface is a tunnel (`/sys/class/net/<if>/type`), and which interface names may be read at all.

pub const ARPHRD_PPP: u32 = 512;
pub const ARPHRD_NONE: u32 = 65534;

/// tun and WireGuard (`ARPHRD_NONE`) and PPP (resolved point 16); never ethernet, loopback or anything else.
pub fn is_tunnel_type(arphrd: u32) -> bool {
    matches!(arphrd, ARPHRD_PPP | ARPHRD_NONE)
}

/// charon-nm's XFRM interface (strongSwan 6: `nm-xfrm-<random id>`, cut at 15 characters), the interface NM gets as
/// an IKEv2 connection's tunnel device. An older charon-nm (policy-based, no interface) has none.
pub const CHARON_NM_XFRM_PREFIX: &str = "nm-xfrm-";

/// `name` is a charon-nm XFRM interface: the prefix and a plain interface name.
pub fn is_charon_nm_xfrm(name: &str) -> bool {
    valid_iface_name(name) && name.len() > CHARON_NM_XFRM_PREFIX.len() && name.starts_with(CHARON_NM_XFRM_PREFIX)
}

/// `^[A-Za-z0-9_.-]{1,15}$` and not `.` or `..`: one plain path component of `/sys/class/net` (the kernel's
/// `IFNAMSIZ` − 1), checked before any path is built from it.
pub fn valid_iface_name(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && name != "."
        && name != ".."
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}
