//! The framed stdin of `up`: the DNS lines of root layer 15 follow the secrets; without a request nothing changes.
use macvpn_core::dns_settings::{DnsMode, DnsRequest};
use macvpn_core::helper_args::{up_stdin, up_stdin_with_dns};
use macvpn_core::models::Secrets;

fn secrets() -> Secrets {
    Secrets { username: Some("u".into()), password: Some("p".into()), ..Secrets::default() }
}

#[test]
fn up_stdin_appends_dns_lines_after_the_secrets() {
    let dns = DnsRequest { mode: DnsMode::Full, servers: vec!["10.0.0.53".into()], ..Default::default() };
    let out = up_stdin_with_dns(b"client\n", &secrets(), Some(&dns));
    let text = String::from_utf8(out.to_vec()).unwrap();
    assert_eq!(text, "config 7\nclient\nusername=u\npassword=p\ndns-mode=full\ndns-servers=10.0.0.53\n");
}

#[test]
fn no_request_no_lines() {
    assert_eq!(up_stdin_with_dns(b"x", &secrets(), None).to_vec(), up_stdin(b"x", &secrets()).to_vec());
    assert_eq!(up_stdin(b"x", &Secrets::default()).to_vec(), b"config 1\nx".to_vec());
}
