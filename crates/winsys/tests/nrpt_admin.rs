//! NRPT rules in the registry, as an administrator (CI's `windows-admin` job, or the maintainer in an elevated Git
//! Bash; listed in `scripts/ignored-everywhere.txt`): rules are written, listed and deleted by prefix under a
//! throw-away key in `HKLM\SOFTWARE`, never under the real `DnsPolicyConfig`.

#![cfg(windows)]

use macvpn_winsys::{nrpt, random};

fn test_base() -> String {
    let mut id = [0u8; 16];
    random::fill(&mut id).unwrap();
    let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
    format!(r"SOFTWARE\WinVPN-test-{hex}")
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

#[test]
#[ignore = "admin: writes under HKLM\\SOFTWARE"]
fn admin_nrpt_rules_are_written_listed_and_deleted_by_prefix() {
    let base = test_base();
    assert!(nrpt::rule_keys(&base).unwrap().is_empty(), "a missing base has no rules");
    nrpt::write_rule(&base, "WinVPN-a-0", &s(&["."]), &s(&["10.99.0.53", "fd00::53"])).unwrap();
    nrpt::write_rule(&base, "WinVPN-a-1", &s(&[".home.lan", ".lab.test"]), &s(&["192.168.1.1"])).unwrap();
    nrpt::write_rule(&base, "WinVPN-b-0", &s(&[".corp.example"]), &s(&["10.0.0.1"])).unwrap();
    // Writing a rule again overwrites it.
    nrpt::write_rule(&base, "WinVPN-a-0", &s(&["."]), &s(&["10.99.0.53"])).unwrap();
    let mut keys = nrpt::rule_keys(&base).unwrap();
    keys.sort();
    let deleted = nrpt::delete_rules(&base, "WinVPN-a-");
    let left = nrpt::rule_keys(&base);
    let empty = nrpt::delete_rules(&base, "WinVPN-");
    let cleanup = nrpt::delete_rules("SOFTWARE", base.trim_start_matches(r"SOFTWARE\"));
    assert_eq!(keys, ["WinVPN-a-0", "WinVPN-a-1", "WinVPN-b-0"]);
    assert_eq!(deleted.unwrap(), 2);
    assert_eq!(left.unwrap(), ["WinVPN-b-0"]);
    assert_eq!(empty.unwrap(), 1);
    assert_eq!(cleanup.unwrap(), 1);
}

#[test]
#[ignore = "admin: tells the DNS client to re-read its policy"]
fn admin_the_dns_policy_refresh_is_accepted() {
    nrpt::apply().unwrap();
}
