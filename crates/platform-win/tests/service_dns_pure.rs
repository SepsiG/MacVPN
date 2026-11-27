//! The app's side of the WinVPN Service's DNS (service version 2): the `up` body, the answers of `version`,
//! `dns-check` and `dns-apply`, and SSTP's `dns-apply` request (pure, tested on every OS).

use macvpn_core::dns_policy::Tunnel;
use macvpn_core::dns_settings::{DnsMode, DnsRequest};
use macvpn_core::helper_args::up_stdin;
use macvpn_core::models::Secrets;
use macvpn_core::status::DnsState;
use macvpn_platform_win::pure::engine::{dns_answer, service_up_body, sstp_dns_apply, takes_dns};

#[test]
fn the_up_body_carries_the_dns_lines_after_the_secrets_and_the_default_when_none() {
    let secrets = Secrets { password: Some("pw".into()), ..Secrets::default() };
    let config = b"client\n";
    let mut expected = up_stdin(config, &secrets).to_vec();
    expected.extend_from_slice(b"dns-mode=automatic\n");
    assert_eq!(service_up_body(config, &secrets, None).to_vec(), expected);
    let targeted = DnsRequest {
        mode: DnsMode::Targeted,
        servers: vec!["10.0.0.53".into()],
        domains: vec!["corp.example".into()],
        override_vpn: true,
    };
    let mut expected = up_stdin(config, &secrets).to_vec();
    expected.extend_from_slice(targeted.frame_lines().as_bytes());
    assert_eq!(service_up_body(config, &secrets, Some(&targeted)).to_vec(), expected);
}

#[test]
fn a_service_of_version_2_takes_the_dns_settings() {
    assert!(takes_dns(0, b"2\n"));
    assert!(takes_dns(0, b"3\n"));
    assert!(!takes_dns(0, b"1\n"));
    assert!(!takes_dns(1, b"2\n"));
    assert!(!takes_dns(0, b"two\n"));
}

#[test]
fn a_dns_answer_gives_the_state_and_the_log_lines() {
    assert_eq!(
        dns_answer(0, b"fallback\n", b"DNS mode: automatic\nonly the VPN's domains\n"),
        (Some(DnsState::Fallback), vec!["DNS mode: automatic".to_string(), "only the VPN's domains".to_string()])
    );
    assert_eq!(dns_answer(1, b"", b""), (None, Vec::<String>::new()));
    assert_eq!(dns_answer(0, b"sometimes\n", b"").0, None);
}

#[test]
fn sstps_dns_apply_names_the_adapter_and_the_tunnel() {
    let full = sstp_dns_apply(b"server=vpn.example.com\nuser=alice\nroute_all=yes\n", None, 42).unwrap();
    assert_eq!((full.luid, full.tunnel, full.request), (42, Tunnel::Full, DnsRequest::default()));
    let strict = DnsRequest { mode: DnsMode::Strict, ..DnsRequest::default() };
    let split = sstp_dns_apply(b"server=vpn.example.com\nuser=alice\nroute_all=no\n", Some(&strict), 7).unwrap();
    assert_eq!((split.tunnel, split.request), (Tunnel::Split, strict));
}

/// "Use the server's DNS" off: the server's DNS is never put into effect. Only the connection's own servers apply
/// (as "use these instead"); without any there is nothing to apply.
#[test]
fn sstp_without_the_servers_dns_applies_only_its_own() {
    let config = b"server=vpn.example.com\nuser=alice\nroute_all=yes\npeer_dns=no\n";
    assert_eq!(sstp_dns_apply(config, None, 42), None);
    let own = DnsRequest { servers: vec!["10.0.0.53".into()], ..DnsRequest::default() };
    let applied = sstp_dns_apply(config, Some(&own), 42).unwrap();
    assert_eq!(applied.request, DnsRequest { override_vpn: true, ..own });
}
