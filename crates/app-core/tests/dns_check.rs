//! The dns-check schedule (macOS root layer 15).
use macvpn_app_core::dns_check::{Connected, DNS_CHECK_INTERVAL, DNS_SWITCH_DELAY, DnsSchedule};
use macvpn_core::status::DnsState;

fn c(key: &str, state: Option<DnsState>, switched_at: Option<f64>) -> Connected {
    Connected { key: key.into(), state, switched_at }
}

#[test]
fn due_every_5_minutes_when_probing_state() {
    let mut s = DnsSchedule::default();
    let list = [c("a", Some(DnsState::Vpn), None), c("b", Some(DnsState::Fallback), None)];
    assert!(s.due(1000.0, true, &list).is_empty(), "the connect's own probe just ran");
    assert!(s.due(1000.0 + DNS_CHECK_INTERVAL - 1.0, true, &list).is_empty());
    let due = s.due(1000.0 + DNS_CHECK_INTERVAL, true, &list);
    assert_eq!(due, ["a", "b"]);
    s.done("a", 1300.0);
    s.done("b", 1300.0);
    assert!(s.due(1301.0, true, &list).is_empty());
    assert_eq!(s.due(1300.0 + DNS_CHECK_INTERVAL, true, &list).len(), 2);
}

#[test]
fn due_15s_after_network_switch() {
    let mut s = DnsSchedule::default();
    assert!(s.due(1000.0, true, &[c("a", Some(DnsState::Vpn), None)]).is_empty());
    let switched = [c("a", Some(DnsState::Vpn), Some(1010.0))];
    assert!(s.due(1010.0 + DNS_SWITCH_DELAY - 1.0, true, &switched).is_empty());
    assert_eq!(s.due(1010.0 + DNS_SWITCH_DELAY, true, &switched), ["a"]);
    s.done("a", 1026.0);
    assert!(s.due(1040.0, true, &switched).is_empty(), "one switch, one check");
}

#[test]
fn never_when_asleep_offline_or_targeted_or_none() {
    let mut s = DnsSchedule::default();
    let list = [
        c("t", Some(DnsState::Targeted), None),
        c("n", Some(DnsState::None), None),
        c("u", None, None),
        c("v", Some(DnsState::Vpn), None),
    ];
    s.due(0.0, true, &list);
    assert_eq!(s.due(DNS_CHECK_INTERVAL, false, &list), Vec::<String>::new(), "the gate is closed");
    assert_eq!(s.due(DNS_CHECK_INTERVAL, true, &list), ["v"]);
}

#[test]
fn one_check_in_flight_per_connection() {
    let mut s = DnsSchedule::default();
    let list = [c("a", Some(DnsState::Failing), None)];
    s.due(0.0, true, &list);
    assert_eq!(s.due(DNS_CHECK_INTERVAL, true, &list), ["a"]);
    assert!(s.due(DNS_CHECK_INTERVAL * 2.0, true, &list).is_empty(), "still in flight");
    // A disconnected connection is forgotten.
    assert!(s.due(DNS_CHECK_INTERVAL * 2.0, true, &[]).is_empty());
    s.due(DNS_CHECK_INTERVAL * 2.0, true, &list);
    assert!(s.due(DNS_CHECK_INTERVAL * 2.5, true, &list).is_empty(), "seen again: due an interval later");
}
