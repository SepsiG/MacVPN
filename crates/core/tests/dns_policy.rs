//! The shared DNS mode logic (`dns_policy`): the decision, the merge of the VPN's DNS with the connection's own, the
//! probe-count rule and the state the app shows.

use macvpn_core::dns_policy::*;
use macvpn_core::dns_settings::{DnsMode, DnsRequest, MAX_DOMAINS};
use macvpn_core::dns_zones::MAX_ZONES;
use macvpn_core::netaddr::IpPrefix;
use macvpn_core::status::DnsState;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

#[test]
fn no_servers_is_none_with_hint() {
    for m in DnsMode::ALL {
        for t in [Tunnel::Full, Tunnel::Split, Tunnel::Unknown] {
            let d = decide(m, t, false, true, Probe::Ok);
            assert_eq!(d, Decision { layout: Layout::None, warn: Some(Warn::NoDns), probes: false });
        }
    }
}

#[test]
fn automatic_ok_or_not_yet_is_vpn_with_local() {
    for p in [Probe::Ok, Probe::NotRun] {
        for t in [Tunnel::Full, Tunnel::Split] {
            let d = decide(DnsMode::Automatic, t, true, false, p);
            assert_eq!(d, Decision { layout: Layout::Vpn { local: true }, warn: None, probes: true });
        }
    }
}

#[test]
fn automatic_failed_is_fallback_on_split_and_full() {
    let d = decide(DnsMode::Automatic, Tunnel::Split, true, true, Probe::Failed);
    assert_eq!(d.layout, Layout::Fallback);
    assert_eq!(d.warn, Some(Warn::Fallback { full_tunnel: false }));
    assert!(d.probes, "recovery needs the probe");
    let d = decide(DnsMode::Automatic, Tunnel::Full, true, true, Probe::Failed);
    assert_eq!(d.layout, Layout::Fallback);
    assert_eq!(d.warn, Some(Warn::Fallback { full_tunnel: true }));
}

#[test]
fn strict_never_falls_back() {
    let d = decide(DnsMode::Strict, Tunnel::Full, true, true, Probe::Failed);
    assert_eq!(d, Decision { layout: Layout::Vpn { local: false }, warn: Some(Warn::Failing), probes: true });
    assert_eq!(decide(DnsMode::Strict, Tunnel::Split, true, true, Probe::Ok).layout, Layout::Vpn { local: false });
}

#[test]
fn full_failed_keeps_vpn_with_local_and_warns() {
    let d = decide(DnsMode::Full, Tunnel::Split, true, true, Probe::Failed);
    assert_eq!(d, Decision { layout: Layout::Vpn { local: true }, warn: Some(Warn::Failing), probes: true });
}

#[test]
fn targeted_split_is_split_and_needs_no_probe() {
    for t in [Tunnel::Split, Tunnel::Unknown] {
        let d = decide(DnsMode::Targeted, t, true, true, Probe::NotRun);
        assert_eq!(d, Decision { layout: Layout::Split, warn: None, probes: false });
    }
}

#[test]
fn targeted_on_full_tunnel_acts_as_automatic() {
    let d = decide(DnsMode::Targeted, Tunnel::Full, true, true, Probe::Ok);
    assert_eq!(
        d,
        Decision { layout: Layout::Vpn { local: true }, warn: Some(Warn::TargetedOnFullTunnel), probes: true }
    );
    let d = decide(DnsMode::Targeted, Tunnel::Full, true, true, Probe::Failed);
    assert_eq!(d.layout, Layout::Fallback);
    assert_eq!(d.warn, Some(Warn::Fallback { full_tunnel: true }), "the notice wins over the log hint");
}

#[test]
fn targeted_without_domains_warns() {
    let d = decide(DnsMode::Targeted, Tunnel::Split, true, false, Probe::NotRun);
    assert_eq!(d.layout, Layout::Split);
    assert_eq!(d.warn, Some(Warn::TargetedNoDomains));
}

#[test]
fn raw_values_round_trip() {
    for l in [Layout::None, Layout::Vpn { local: true }, Layout::Vpn { local: false }, Layout::Split, Layout::Fallback]
    {
        assert_eq!(Layout::from_raw(l.raw()), Some(l));
    }
    for w in [Warn::NoDns, Warn::Fallback { full_tunnel: true }, Warn::Failing, Warn::TargetedNoDomains] {
        assert_eq!(Warn::from_raw(w.raw()), Some(w));
    }
    assert_eq!(Tunnel::from_raw("full"), Some(Tunnel::Full));
    assert_eq!(Probe::from_raw("failed"), Some(Probe::Failed));
    assert_eq!(Probe::from_raw("x"), None);
}

#[test]
fn effective_dns_merge() {
    let pushed = Pushed {
        servers: s(&["10.8.0.1"]),
        search: s(&["corp.example"]),
        resolve: s(&["svc.example"]),
        routes: vec![IpPrefix::parse("10.1.0.0/16").unwrap(), IpPrefix::parse("8.8.8.0/24").unwrap()],
    };
    let own = DnsRequest { servers: s(&["10.0.0.53"]), domains: s(&["portal.example"]), ..Default::default() };
    let e = effective(&pushed, &own);
    assert_eq!(e.servers, ["10.8.0.1"], "the VPN's servers win");
    assert_eq!(e.search, ["corp.example"]);
    assert_eq!(e.resolve, ["svc.example", "portal.example"], "own domains are always matched");
    assert_eq!(e.zones, ["1.10.in-addr.arpa"], "only private routes");

    let none = Pushed::default();
    let e = effective(&none, &own);
    assert_eq!(e.servers, ["10.0.0.53"], "own servers when the VPN sent none");
    assert_eq!(e.search, ["portal.example"], "own domains searched when the VPN sent none");
    assert!(e.resolve.is_empty());

    let over = DnsRequest { override_vpn: true, ..own.clone() };
    let e = effective(&pushed, &over);
    assert_eq!(e.servers, ["10.0.0.53"]);
    assert_eq!(e.search, ["portal.example"]);
    assert_eq!(e.resolve, ["svc.example"]);
    assert!(e.has_match());
    assert!(
        !effective(&Pushed { servers: s(&["10.8.0.1"]), ..Default::default() }, &DnsRequest::default()).has_match()
    );
}

#[test]
fn effective_lists_are_capped() {
    let many: Vec<String> = (0..100).map(|i| format!("d{i}.example")).collect();
    let pushed = Pushed { servers: s(&["10.8.0.1"]), search: many.clone(), resolve: many.clone(), routes: vec![] };
    let e = effective(&pushed, &DnsRequest { domains: many.clone(), ..Default::default() });
    assert_eq!(e.search.len(), MAX_DOMAINS);
    assert!(e.resolve.len() <= MAX_ZONES);
    let routes: Vec<IpPrefix> = (0..100).map(|i| IpPrefix::parse(&format!("10.{i}.0.0/16")).unwrap()).collect();
    let e = effective(&Pushed { routes, ..pushed }, &DnsRequest::default());
    assert_eq!(e.zones.len(), MAX_ZONES);
}

#[test]
fn dedup_keeps_order_ignores_case_and_caps() {
    assert_eq!(dedup(s(&["A.example", "b.example", "a.EXAMPLE", "c.example"]), 2), ["A.example", "b.example"]);
}

#[test]
fn all_matches_lists_search_resolve_and_zones() {
    let e = Effective {
        servers: s(&["10.8.0.1"]),
        search: s(&["corp.example"]),
        resolve: s(&["svc.example"]),
        zones: s(&["10.in-addr.arpa"]),
    };
    assert_eq!(e.all_matches(), ["corp.example", "svc.example", "10.in-addr.arpa"]);
}

#[test]
fn one_failure_keeps_the_layout_two_fall_back_one_success_returns() {
    assert_eq!(next_probe(Probe::Ok, 0, Probe::Failed), (Probe::Ok, 1));
    assert_eq!(next_probe(Probe::Ok, 1, Probe::Failed), (Probe::Failed, 2));
    assert_eq!(next_probe(Probe::Failed, 2, Probe::Failed), (Probe::Failed, 3));
    assert_eq!(next_probe(Probe::Failed, 3, Probe::Ok), (Probe::Ok, 0));
    assert_eq!(next_probe(Probe::Failed, 3, Probe::NotRun), (Probe::Failed, 3));
}

#[test]
fn states_follow_the_layout() {
    assert_eq!(state_of(Layout::None, Some(Warn::NoDns)), DnsState::None);
    assert_eq!(state_of(Layout::Split, None), DnsState::Targeted);
    assert_eq!(state_of(Layout::Fallback, Some(Warn::Fallback { full_tunnel: true })), DnsState::FallbackFullTunnel);
    assert_eq!(state_of(Layout::Fallback, Some(Warn::Fallback { full_tunnel: false })), DnsState::Fallback);
    assert_eq!(state_of(Layout::Vpn { local: true }, Some(Warn::Failing)), DnsState::Failing);
    assert_eq!(state_of(Layout::Vpn { local: false }, None), DnsState::Vpn);
}

#[test]
fn probe_of_no_servers_is_not_run() {
    assert_eq!(probe(&[]).0, Probe::NotRun);
}
