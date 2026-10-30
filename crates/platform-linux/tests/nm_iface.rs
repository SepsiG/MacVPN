use macvpn_platform_linux::pure::nm::iface::{
    ARPHRD_NONE, ARPHRD_PPP, is_charon_nm_xfrm, is_tunnel_type, valid_iface_name,
};

#[test]
fn only_tun_wireguard_and_ppp_are_tunnels() {
    assert!(is_tunnel_type(ARPHRD_PPP) && is_tunnel_type(512));
    assert!(is_tunnel_type(ARPHRD_NONE) && is_tunnel_type(65534));
    assert!(!is_tunnel_type(1), "ethernet");
    assert!(!is_tunnel_type(772), "loopback");
    assert!(!is_tunnel_type(0));
}

#[test]
fn an_interface_name_is_one_short_plain_component() {
    for ok in ["lo", "wg0", "tun-linvpn", "enp1s0", "a.b_c-d", "123456789012345"] {
        assert!(valid_iface_name(ok), "{ok}");
    }
    for bad in ["", "1234567890123456", "../etc", "..", ".", "a/b", "/", "a b", "wg0\n", "é", "a\0b"] {
        assert!(!valid_iface_name(bad), "{bad:?}");
    }
}

#[test]
fn charon_nms_xfrm_interface_is_recognised_by_its_name() {
    for ok in ["nm-xfrm-1804289", "nm-xfrm-1", "nm-xfrm-1234567"] {
        assert!(is_charon_nm_xfrm(ok), "{ok}");
    }
    for bad in ["nm-xfrm-", "nm-xfrm", "xfrm0", "ppp0", "lo", "tun0", "nm-xfrm-1/../x", "nm-xfrm-12345678"] {
        assert!(!is_charon_nm_xfrm(bad), "{bad}");
    }
}
