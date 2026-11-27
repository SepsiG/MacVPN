//! The NM DNS keys per DNS mode (LinVPN, spec "Linux").

use macvpn_core::dns_settings::{DnsMode, DnsSetting};
use macvpn_core::nm_plan::NmValue;
use macvpn_core::nm_plan::dns::{DEFAULT_PRIORITY, STRICT_PRIORITY, merge_into, section_extras};
use std::collections::BTreeMap;

fn setting(mode: DnsMode, servers: &[&str], domains: &[&str], override_vpn: bool) -> DnsSetting {
    DnsSetting {
        mode,
        servers: servers.iter().map(|s| s.to_string()).collect(),
        domains: domains.iter().map(|s| s.to_string()).collect(),
        override_vpn,
    }
}

fn search(m: &BTreeMap<String, NmValue>) -> Vec<String> {
    match m.get("dns-search") {
        Some(NmValue::StrList(v)) => v.clone(),
        _ => vec![],
    }
}

fn prio(m: &BTreeMap<String, NmValue>) -> i32 {
    match m.get("dns-priority") {
        Some(NmValue::I32(p)) => *p,
        other => panic!("{other:?}"),
    }
}

const V4: bool = true;

#[test]
fn automatic_and_full_take_every_name_but_keep_local_names() {
    for mode in [DnsMode::Automatic, DnsMode::Full] {
        let m =
            section_extras(false, &["corp.example".into()], Some(&setting(mode, &[], &["intra.example"], false)), V4);
        assert_eq!(search(&m), ["corp.example", "~intra.example", "~."]);
        assert_eq!(prio(&m), DEFAULT_PRIORITY);
    }
}

#[test]
fn strict_is_exclusive() {
    let m = section_extras(true, &["corp.example".into()], Some(&setting(DnsMode::Strict, &[], &[], false)), V4);
    assert_eq!(search(&m), ["corp.example", "~."]);
    assert_eq!(prio(&m), STRICT_PRIORITY);
}

#[test]
fn targeted_routes_only_the_vpn_domains_on_a_split_tunnel() {
    let m = section_extras(
        false,
        &["corp.example".into()],
        Some(&setting(DnsMode::Targeted, &[], &["portal.example"], false)),
        V4,
    );
    assert_eq!(search(&m), ["~corp.example", "~portal.example"]);
    assert_eq!(prio(&m), DEFAULT_PRIORITY);
}

#[test]
fn targeted_on_a_full_tunnel_acts_as_automatic() {
    let m = section_extras(true, &[], Some(&setting(DnsMode::Targeted, &[], &[], false)), V4);
    assert_eq!(search(&m), ["~."]);
    assert_eq!(prio(&m), DEFAULT_PRIORITY);
}

#[test]
fn domains_are_deduplicated_case_insensitively() {
    let m = section_extras(
        false,
        &["Corp.Example".into(), "~corp.example".into()],
        Some(&setting(DnsMode::Targeted, &[], &["CORP.example", "b.example"], false)),
        V4,
    );
    assert_eq!(search(&m), ["~Corp.Example", "~b.example"]);
}

#[test]
fn own_servers_per_family_and_override() {
    let s = setting(DnsMode::Automatic, &["10.0.0.53", "fd00::53"], &[], true);
    let v4 = section_extras(false, &[], Some(&s), true);
    assert_eq!(v4.get("dns-data"), Some(&NmValue::StrList(vec!["10.0.0.53".into()])));
    assert_eq!(v4.get("ignore-auto-dns"), Some(&NmValue::Bool(true)));
    let v6 = section_extras(false, &[], Some(&s), false);
    assert_eq!(v6.get("dns-data"), Some(&NmValue::StrList(vec!["fd00::53".into()])));
    assert_eq!(v6.get("ignore-auto-dns"), Some(&NmValue::Bool(true)));
}

#[test]
fn override_drops_the_vpns_dns_only_in_a_family_with_own_servers() {
    let s = setting(DnsMode::Automatic, &["10.0.0.53"], &[], true);
    let v4 = section_extras(false, &[], Some(&s), true);
    assert_eq!(v4.get("ignore-auto-dns"), Some(&NmValue::Bool(true)));
    let v6 = section_extras(false, &[], Some(&s), false);
    assert_eq!(v6.get("ignore-auto-dns"), None, "IPv6 keeps the VPN's pushed DNS");
    assert_eq!(v6.get("dns-data"), None);
}

#[test]
fn own_servers_without_override_add_to_the_vpns() {
    let s = setting(DnsMode::Automatic, &["10.0.0.53"], &[], false);
    let extras = section_extras(false, &[], Some(&s), V4);
    assert_eq!(extras.get("ignore-auto-dns"), None);
    let mut section = BTreeMap::new();
    section.insert("dns-data".to_string(), NmValue::StrList(vec!["10.8.0.1".into(), "10.0.0.53".into()]));
    merge_into(&mut section, extras);
    assert_eq!(section.get("dns-data"), Some(&NmValue::StrList(vec!["10.8.0.1".into(), "10.0.0.53".into()])));
}

#[test]
fn override_replaces_the_configs_servers() {
    let s = setting(DnsMode::Automatic, &["10.0.0.53"], &[], true);
    let mut section = BTreeMap::new();
    section.insert("dns-data".to_string(), NmValue::StrList(vec!["10.8.0.1".into()]));
    merge_into(&mut section, section_extras(false, &[], Some(&s), V4));
    assert_eq!(section.get("dns-data"), Some(&NmValue::StrList(vec!["10.0.0.53".into()])));
}

#[test]
fn kinds_without_dns_settings_keep_todays_keys() {
    let m = section_extras(true, &[], None, V4);
    assert_eq!(search(&m), ["~."]);
    assert_eq!(prio(&m), STRICT_PRIORITY);
    let m = section_extras(false, &["a.example".into()], None, V4);
    assert_eq!(search(&m), ["~a.example"]);
    assert_eq!(prio(&m), DEFAULT_PRIORITY);
}
