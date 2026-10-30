//! OpenVPN's "Send all traffic over VPN" lives in the config (resolved point 4).
use macvpn_core::openvpn_routing::{Routing, read, write};

const BASE: &str = "client\nremote vpn.example.com 1194\ndev tun\n<ca>\nX\n</ca>\n";

#[test]
fn the_profile_decides_what_it_says() {
    assert_eq!(read(BASE), Routing::ServerDecides);
    assert_eq!(read(&format!("{BASE}redirect-gateway def1\n")), Routing::Always);
    assert_eq!(read(&format!("{BASE}redirect-gateway def1 bypass-dhcp\n")), Routing::Always);
    assert_eq!(
        read(&format!("{BASE}redirect-gateway ipv6 !ipv4\n")),
        Routing::ServerDecides,
        "!ipv4 is not 'all traffic'"
    );
    assert_eq!(read(&format!("{BASE}pull-filter ignore \"redirect-gateway\"\n")), Routing::Never);
    assert_eq!(read(&format!("{BASE}route-nopull\n")), Routing::Never);
}

#[test]
fn writing_replaces_only_the_routing_lines_and_round_trips() {
    let always = write(BASE, Routing::Always);
    assert_eq!(always, format!("{BASE}redirect-gateway def1\n"));
    assert_eq!(read(&always), Routing::Always);
    let never = write(&always, Routing::Never);
    assert!(!never.contains("redirect-gateway def1"));
    assert!(never.ends_with("pull-filter ignore \"redirect-gateway\"\n"));
    assert_eq!(write(&never, Routing::ServerDecides), BASE);
}

#[test]
fn ipv6_in_the_profile_is_kept_by_always() {
    let t = format!("{BASE}redirect-gateway def1 ipv6\n");
    assert_eq!(write(&write(&t, Routing::Never), Routing::Always), format!("{BASE}redirect-gateway def1\n"));
    assert_eq!(write(&t, Routing::Always), t, "already Always: unchanged");
}

#[test]
fn lines_inside_blocks_and_comments_are_never_touched() {
    let t = "client\n# redirect-gateway def1\n<connection>\nremote a 1\n</connection>\n";
    assert_eq!(read(t), Routing::ServerDecides);
    assert_eq!(write(t, Routing::ServerDecides), t);
}

#[test]
fn the_last_routing_line_wins_and_writing_removes_every_one() {
    let t = format!("{BASE}route-nopull\nredirect-gateway def1 ipv6\n");
    assert_eq!(read(&t), Routing::Always);
    assert_eq!(write(&t, Routing::ServerDecides), BASE);
    assert_eq!(write(&t, Routing::Never), format!("{BASE}pull-filter ignore \"redirect-gateway\"\n"));
    // Only `ignore` of exactly "redirect-gateway" means Never; other filters are left alone.
    let other = format!("{BASE}pull-filter ignore \"route\"\npull-filter accept \"redirect-gateway\"\n");
    assert_eq!(read(&other), Routing::ServerDecides);
    assert_eq!(write(&other, Routing::Always), format!("{other}redirect-gateway def1\n"));
}

#[test]
fn crlf_text_and_a_missing_final_newline_are_handled() {
    let crlf = "client\r\nremote a 1\r\nredirect-gateway def1\r\n";
    assert_eq!(write(crlf, Routing::Never), "client\r\nremote a 1\r\npull-filter ignore \"redirect-gateway\"\r\n");
    assert_eq!(write("client\nremote a 1", Routing::Always), "client\nremote a 1\nredirect-gateway def1\n");
    assert_eq!(read("client\n  --REDIRECT-GATEWAY def1"), Routing::Always, "case and -- as OpenVPN reads them");
}
