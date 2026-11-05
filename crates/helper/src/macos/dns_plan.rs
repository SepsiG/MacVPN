//! The DNS mode decision and the dynamic-store entries it leads to (root layer 15). Pure: the manager (`dns`)
//! gathers the facts (the VPN-sent DNS, the connection's request, the tunnel, the probe, the network services) and
//! applies the operations returned here; nothing here reads or writes the store.
//!
//! **Layouts.** `Vpn` puts the VPN's DNS in the default role: every ordered network service's `Setup:` DNS is
//! overridden **in the dynamic store** (never in the persistent preferences) with the VPN's servers, which configd
//! merges over the service's own DNS, so the resolver's default goes to the VPN. `Split` and `Fallback` leave the
//! services alone and add supplemental resolvers for the VPN's domains only. `None` writes nothing.
//!
//! **Entries (R3a of the plan).** Every entry carries `MacVPNOwner = <id>`, so drift and foreign changes are told
//! apart from ours:
//!
//! - `State:/Network/Service/macvpn-<id>/DNS`: the VPN's search domains on the VPN's servers (`SearchOrder` 100).
//!   In `Vpn` `SupplementalMatchDomainsNoSearch = 1`, because the override already puts them in the search list;
//!   in `Split` / `Fallback` without it, so they are appended to the search list.
//! - `…macvpn-<id>-match/DNS`: match-only names on the VPN's servers (`resolve-domains`, the connection's own
//!   domains that are not search domains, the reverse zones of the routed private networks), never searched (101).
//! - `…macvpn-<id>-local/DNS`: in `Vpn{local}` (Automatic, Full) the local network's own domain and reverse zone on
//!   the network's original DNS (200), minus anything a VPN domain or zone covers (the VPN wins an overlap).
//! - `Setup:/Network/Service/<sid>/DNS`: the override (see [`override_ops`]).
//!
//! NXDOMAIN and timeouts from the chosen resolver are final on macOS (no fall-through), which is why the fallback
//! takes the VPN's DNS out of the default role instead of adding the original DNS "after" it.

use crate::macos::dns_store::{Dict, Op, Value, list_of, strings};
use macvpn_core::dns_settings::{DnsMode, DnsRequest, MAX_DOMAINS, MAX_SERVERS};
use macvpn_core::dns_zones::{MAX_ZONES, covered_by, is_private, reverse_zones};
use macvpn_core::netaddr::IpPrefix;
use std::net::{IpAddr, Ipv4Addr};

/// The marker key in every value MacVPN writes.
pub const OWNER_KEY: &str = "MacVPNOwner";
const ORDER_VPN: i64 = 100;
const ORDER_MATCH: i64 = 101;
const ORDER_LOCAL: i64 = 200;
/// The suffixes of a connection's own entries (`macvpn-<id><suffix>`).
pub const ENTRY_SUFFIXES: [&str; 3] = ["", "-match", "-local"];

/// A connection's own entry key.
pub fn entry_key(id: &str, suffix: &str) -> String {
    format!("State:/Network/Service/macvpn-{id}{suffix}/DNS")
}

/// A network service's `Setup:` DNS key (the override).
pub fn setup_key(sid: &str) -> String {
    format!("Setup:/Network/Service/{sid}/DNS")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tunnel {
    Full,
    Split,
    /// Before the routes are in (the hook): counts as split for Targeted, irrelevant otherwise.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    NotRun,
    Ok,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    None,
    /// The VPN's DNS in the default role; `local`: the local network's own names stay on its DNS.
    Vpn {
        local: bool,
    },
    /// Targeted: only the VPN's domains on the VPN's DNS.
    Split,
    /// Automatic after failed probes: as `Split`, every other name on the network's original DNS.
    Fallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warn {
    NoDns,
    Fallback { full_tunnel: bool },
    Failing,
    TargetedOnFullTunnel,
    TargetedNoDomains,
}

/// `raw()` / `from_raw()` over a fixed list of values (the `<run>/dns-session` file's words).
macro_rules! raw_enum {
    ($t:ty, [$($v:expr),+ $(,)?], $raw:expr) => {
        impl $t {
            pub fn raw(self) -> &'static str {
                let f: fn($t) -> &'static str = $raw;
                f(self)
            }
            pub fn from_raw(s: &str) -> Option<Self> {
                [$($v),+].into_iter().find(|v| v.raw() == s)
            }
        }
    };
}

raw_enum!(Tunnel, [Tunnel::Full, Tunnel::Split, Tunnel::Unknown], |t| match t {
    Tunnel::Full => "full",
    Tunnel::Split => "split",
    Tunnel::Unknown => "unknown",
});
raw_enum!(Probe, [Probe::NotRun, Probe::Ok, Probe::Failed], |p| match p {
    Probe::NotRun => "not-run",
    Probe::Ok => "ok",
    Probe::Failed => "failed",
});
raw_enum!(
    Layout,
    [Layout::None, Layout::Vpn { local: true }, Layout::Vpn { local: false }, Layout::Split, Layout::Fallback],
    |l| match l {
        Layout::None => "none",
        Layout::Vpn { local: true } => "vpn-local",
        Layout::Vpn { local: false } => "vpn",
        Layout::Split => "split",
        Layout::Fallback => "fallback",
    }
);
raw_enum!(
    Warn,
    [
        Warn::NoDns,
        Warn::Fallback { full_tunnel: false },
        Warn::Fallback { full_tunnel: true },
        Warn::Failing,
        Warn::TargetedOnFullTunnel,
        Warn::TargetedNoDomains,
    ],
    |w| match w {
        Warn::NoDns => "no-dns",
        Warn::Fallback { full_tunnel: false } => "fallback",
        Warn::Fallback { full_tunnel: true } => "fallback-full",
        Warn::Failing => "failing",
        Warn::TargetedOnFullTunnel => "targeted-full",
        Warn::TargetedNoDomains => "targeted-no-domains",
    }
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub layout: Layout,
    pub warn: Option<Warn>,
    /// The session is probed again later (`dns-check`).
    pub probes: bool,
}

/// The whole mode logic. `Tunnel::Unknown` (before the routes are in, i.e. in the hook) counts as split for
/// Targeted and is otherwise irrelevant; the after-connect pass decides again with the real tunnel.
pub fn decide(mode: DnsMode, tunnel: Tunnel, has_servers: bool, has_match: bool, probe: Probe) -> Decision {
    use {DnsMode::*, Layout::*};
    if !has_servers {
        return Decision { layout: None, warn: Some(Warn::NoDns), probes: false };
    }
    let full = tunnel == Tunnel::Full;
    let (mode, note) = match mode {
        Targeted if full => (Automatic, Some(Warn::TargetedOnFullTunnel)),
        m => (m, Option::None),
    };
    let d = |layout, warn: Option<Warn>, probes| Decision { layout, warn: warn.or(note), probes };
    match (mode, probe) {
        (Targeted, _) => d(Split, (!has_match).then_some(Warn::TargetedNoDomains), false),
        (Automatic, Probe::Failed) => d(Fallback, Some(Warn::Fallback { full_tunnel: full }), true),
        (Automatic, _) => d(Vpn { local: true }, Option::None, true),
        (Full, Probe::Failed) => d(Vpn { local: true }, Some(Warn::Failing), true),
        (Full, _) => d(Vpn { local: true }, Option::None, true),
        (Strict, Probe::Failed) => d(Vpn { local: false }, Some(Warn::Failing), true),
        (Strict, _) => d(Vpn { local: false }, Option::None, true),
    }
}

/// What the VPN sent: OpenVPN's pushed options (or `--dns`), WireGuard's `DNS =`, pppd's peer DNS; and the routed
/// networks (for the reverse zones).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pushed {
    pub servers: Vec<String>,
    pub search: Vec<String>,
    /// OpenVPN 2.7 `dns server … resolve-domains`: match-only.
    pub resolve: Vec<String>,
    pub routes: Vec<IpPrefix>,
}

/// The DNS a connection puts into effect: the VPN-sent DNS merged with the connection's own request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Effective {
    pub servers: Vec<String>,
    /// Search domains, also matched.
    pub search: Vec<String>,
    /// Match-only domains (never searched).
    pub resolve: Vec<String>,
    /// Reverse zones of the routed private networks (match-only).
    pub zones: Vec<String>,
}

impl Effective {
    /// Any name the VPN's DNS is asked for in a split layout (reverse zones do not make Targeted useful alone).
    pub fn has_match(&self) -> bool {
        !self.search.is_empty() || !self.resolve.is_empty()
    }

    /// Every match domain and zone of the VPN (the overlap rule's "VPN side").
    fn all_matches(&self) -> Vec<String> {
        self.search.iter().chain(&self.resolve).chain(&self.zones).cloned().collect()
    }
}

/// Order-keeping, case-insensitive dedup, at most `cap` items.
fn dedup(items: impl IntoIterator<Item = String>, cap: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for i in items {
        if out.len() < cap && !out.iter().any(|o| o.eq_ignore_ascii_case(&i)) {
            out.push(i);
        }
    }
    out
}

/// VPN-sent DNS merged with the connection's request:
/// - the VPN's servers win, unless there are none or `override` is set (then the own servers);
/// - own domains are always matched; they become search domains only when the VPN sent none or with `override`,
///   otherwise they are match-only;
/// - the private routed networks give the reverse zones.
pub fn effective(p: &Pushed, req: &DnsRequest) -> Effective {
    let servers = if req.override_vpn || p.servers.is_empty() { &req.servers } else { &p.servers };
    let own_search = (req.override_vpn || p.search.is_empty()) && !req.domains.is_empty();
    let search = dedup(if own_search { req.domains.clone() } else { p.search.clone() }, MAX_DOMAINS);
    let resolve = dedup(
        p.resolve.iter().chain(&req.domains).filter(|d| !search.iter().any(|s| s.eq_ignore_ascii_case(d))).cloned(),
        MAX_ZONES,
    );
    let zones = dedup(p.routes.iter().filter(|r| is_private(r)).flat_map(reverse_zones), MAX_ZONES);
    Effective { servers: dedup(servers.iter().cloned(), MAX_SERVERS), search, resolve, zones }
}

/// A network service's `Setup:` DNS before MacVPN (from the volatile ledger).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Original {
    pub sid: String,
    /// The key existed (a service with manual DNS); otherwise the restore removes it.
    pub present: bool,
    pub dict: Dict,
}

/// The primary network service as the local entry needs it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Primary {
    pub sid: String,
    /// Its original DNS servers.
    pub servers: Vec<String>,
    /// Its own domain(s): the original search domains and the DHCP domain name.
    pub local_domains: Vec<String>,
    /// The reverse zones of its private subnets.
    pub local_zones: Vec<String>,
}

/// The "original search" of a service: its original `Setup:` `SearchDomains`, else its `State:` `SearchDomains`,
/// else `[State: DomainName]`. `State:` is never written by MacVPN, so it stays readable while overridden.
pub fn original_search(orig: Option<&Original>, state: Option<&Dict>) -> Vec<String> {
    let setup = orig.filter(|o| o.present).map(|o| list_of(&o.dict, "SearchDomains")).unwrap_or_default();
    if !setup.is_empty() {
        return setup;
    }
    let state_search = state.map(|d| list_of(d, "SearchDomains")).unwrap_or_default();
    if !state_search.is_empty() {
        return state_search;
    }
    state.and_then(|d| d.get("DomainName")).and_then(Value::as_str).map(|d| vec![d.to_string()]).unwrap_or_default()
}

/// The facts of the primary service: original servers (`Setup:` if it had manual DNS, else `State:`), its domains
/// and the reverse zones of its private subnets (IPv4 `Addresses` + `SubnetMasks`, IPv6 `Addresses` +
/// `PrefixLength`).
pub fn primary(
    sid: &str,
    orig: Option<&Original>,
    state: Option<&Dict>,
    ipv4: Option<&Dict>,
    ipv6: Option<&Dict>,
) -> Primary {
    let setup_servers = orig.filter(|o| o.present).map(|o| list_of(&o.dict, "ServerAddresses")).unwrap_or_default();
    let servers = if setup_servers.is_empty() {
        state.map(|d| list_of(d, "ServerAddresses")).unwrap_or_default()
    } else {
        setup_servers
    };
    let mut domains = original_search(orig, state);
    if let Some(d) = state.and_then(|d| d.get("DomainName")).and_then(Value::as_str) {
        domains.push(d.to_string());
    }
    let domains = dedup(
        domains
            .into_iter()
            .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| macvpn_core::dns_settings::is_dns_domain(d) && d != "local" && !d.ends_with(".local")),
        MAX_ZONES,
    );
    let mut prefixes = Vec::new();
    if let Some(v4) = ipv4 {
        for (a, m) in list_of(v4, "Addresses").iter().zip(list_of(v4, "SubnetMasks")) {
            if let (Ok(a), Ok(m)) = (a.parse::<Ipv4Addr>(), m.parse::<Ipv4Addr>()) {
                prefixes.extend(IpPrefix::from_mask(a, m));
            }
        }
    }
    if let Some(v6) = ipv6 {
        let lens = v6.get("PrefixLength").and_then(|v| match v {
            Value::Array(a) => Some(a.iter().map(|x| x.as_int()).collect::<Vec<_>>()),
            _ => None,
        });
        for (i, a) in list_of(v6, "Addresses").iter().enumerate() {
            let len = lens.as_ref().and_then(|l| l.get(i).copied().flatten());
            if let (Ok(a), Some(len)) = (a.parse::<IpAddr>(), len.and_then(|l| u8::try_from(l).ok())) {
                prefixes.extend(IpPrefix::new(a, len));
            }
        }
    }
    let zones = dedup(prefixes.iter().filter(|p| is_private(p)).flat_map(reverse_zones), MAX_ZONES);
    Primary { sid: sid.to_string(), servers: dedup(servers, MAX_SERVERS), local_domains: domains, local_zones: zones }
}

/// A supplemental resolver entry on `servers` for `domains`.
fn vpn_entry(id: &str, servers: &[String], domains: &[String], no_search: bool, order: i64) -> Dict {
    let mut d = Dict::new();
    d.insert("ServerAddresses".into(), strings(servers));
    d.insert("SupplementalMatchDomains".into(), strings(domains));
    d.insert("SearchOrder".into(), Value::Int(order));
    if no_search {
        d.insert("SupplementalMatchDomainsNoSearch".into(), Value::Int(1));
    }
    d.insert(OWNER_KEY.into(), Value::Str(id.into()));
    d
}

/// The local network's names that stay on its DNS (minus what the VPN covers), as the `-local` entry lists them.
pub fn local_matches(e: &Effective, p: &Primary) -> Vec<String> {
    let vpn = e.all_matches();
    dedup(p.local_domains.iter().chain(&p.local_zones).filter(|d| !covered_by(d, &vpn)).cloned(), MAX_ZONES)
}

/// The dynamic-store operations that bring this connection's own entries to `layout` (R3a), without the
/// overrides. An entry with nothing to match is removed rather than written empty.
pub fn own_entries(id: &str, layout: Layout, e: &Effective, primary: Option<&Primary>) -> Vec<Op> {
    let set_or_remove = |suffix: &str, d: Option<Dict>| match d {
        Some(d) => Op::Set(entry_key(id, suffix), d),
        None => Op::Remove(entry_key(id, suffix)),
    };
    let (vpn, local) = match layout {
        Layout::None => return ENTRY_SUFFIXES.iter().map(|s| set_or_remove(s, None)).collect(),
        Layout::Vpn { local } => (true, local),
        Layout::Split | Layout::Fallback => (false, false),
    };
    let matches = dedup(e.resolve.iter().chain(&e.zones).cloned(), MAX_ZONES);
    let main = (!e.search.is_empty()).then(|| vpn_entry(id, &e.servers, &e.search, vpn, ORDER_VPN));
    let only = (!matches.is_empty()).then(|| vpn_entry(id, &e.servers, &matches, true, ORDER_MATCH));
    let local_entry = primary.filter(|p| local && !p.servers.is_empty()).and_then(|p| {
        let m = local_matches(e, p);
        (!m.is_empty()).then(|| vpn_entry(id, &p.servers, &m, true, ORDER_LOCAL))
    });
    vec![set_or_remove("", main), set_or_remove("-match", only), set_or_remove("-local", local_entry)]
}

/// A network service in `Setup:/Network/Global/IPv4` `ServiceOrder`, as the override needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub sid: String,
    /// The current `Setup:` DNS value in the dynamic store.
    pub setup: Option<Dict>,
    /// Its `State:` DNS (DHCP).
    pub state: Option<Dict>,
    /// A tunnel interface (`utun*`, `ppp*`, `ipsec*`): another VPN's service, never overridden.
    pub vpn_like: bool,
}

/// `value` was written by MacVPN.
pub fn is_ours(value: Option<&Dict>) -> bool {
    value.is_some_and(|d| d.contains_key(OWNER_KEY))
}

/// The override of one service: its original `Setup:` DNS with the VPN's servers and search list and the marker.
fn override_of(id: &str, original: &Dict, servers: &[String], search: &[String]) -> Dict {
    let mut d = original.clone();
    d.insert("ServerAddresses".into(), strings(servers));
    if search.is_empty() {
        d.remove("SearchDomains");
    } else {
        d.insert("SearchDomains".into(), strings(search));
    }
    d.insert(OWNER_KEY.into(), Value::Str(id.into()));
    d
}

/// The overrides for the newest `Vpn`-layout owner `id` over every non-VPN service: its servers, and its search
/// domains followed (with `local`) by the service's own original search domains. Only the services whose current
/// value differs get an operation. `originals` must hold every listed service (the manager captures them first).
pub fn override_ops(id: &str, e: &Effective, local: bool, originals: &[Original], services: &[Service]) -> Vec<Op> {
    let mut ops = Vec::new();
    for s in services.iter().filter(|s| !s.vpn_like) {
        let orig = originals.iter().find(|o| o.sid == s.sid);
        let base = orig.filter(|o| o.present).map(|o| o.dict.clone()).unwrap_or_default();
        let own = if local { original_search(orig, s.state.as_ref()) } else { Vec::new() };
        let search = dedup(e.search.iter().cloned().chain(own), MAX_DOMAINS);
        let want = override_of(id, &base, &e.servers, &search);
        if s.setup.as_ref() != Some(&want) {
            ops.push(Op::Set(setup_key(&s.sid), want));
        }
    }
    ops
}

/// The restore of every override: where the current `Setup:` value is still ours, the original comes back (or the
/// key goes, when there was none). Values changed by the system meanwhile are left as they are and listed.
pub fn restore_ops(originals: &[Original], current: &dyn Fn(&str) -> Option<Dict>) -> (Vec<Op>, Vec<String>) {
    let mut ops = Vec::new();
    let mut changed = Vec::new();
    for o in originals {
        let now = current(&o.sid);
        if is_ours(now.as_ref()) {
            ops.push(if o.present {
                Op::Set(setup_key(&o.sid), o.dict.clone())
            } else {
                Op::Remove(setup_key(&o.sid))
            });
        } else if now.as_ref() != o.present.then_some(&o.dict) {
            changed.push(o.sid.clone());
        }
    }
    (ops, changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn eff(servers: &[&str], search: &[&str]) -> Effective {
        Effective { servers: s(servers), search: s(search), ..Default::default() }
    }

    fn dict(pairs: &[(&str, Value)]) -> Dict {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    fn strs(v: &[&str]) -> Value {
        strings(&s(v))
    }

    fn get<'a>(ops: &'a [Op], key: &str) -> Option<&'a Dict> {
        ops.iter().find_map(|o| match o {
            Op::Set(k, d) if k == key => Some(d),
            _ => None,
        })
    }

    fn removed(ops: &[Op], key: &str) -> bool {
        ops.iter().any(|o| matches!(o, Op::Remove(k) if k == key))
    }

    const ID: &str = "11111111-2222-3333-4444-555555555555";

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
        for l in
            [Layout::None, Layout::Vpn { local: true }, Layout::Vpn { local: false }, Layout::Split, Layout::Fallback]
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

    fn home() -> Primary {
        Primary {
            sid: "S1".into(),
            servers: s(&["192.168.1.1"]),
            local_domains: s(&["lan"]),
            local_zones: s(&["1.168.192.in-addr.arpa"]),
        }
    }

    #[test]
    fn entries_vpn_layout() {
        let e = Effective {
            resolve: s(&["svc.example"]),
            zones: s(&["10.in-addr.arpa"]),
            ..eff(&["10.8.0.1"], &["corp.example"])
        };
        let ops = own_entries(ID, Layout::Vpn { local: true }, &e, Some(&home()));
        let main = get(&ops, &entry_key(ID, "")).unwrap();
        assert_eq!(
            main,
            &dict(&[
                ("ServerAddresses", strs(&["10.8.0.1"])),
                ("SupplementalMatchDomains", strs(&["corp.example"])),
                ("SearchOrder", Value::Int(100)),
                ("SupplementalMatchDomainsNoSearch", Value::Int(1)),
                (OWNER_KEY, Value::Str(ID.into())),
            ])
        );
        let m = get(&ops, &entry_key(ID, "-match")).unwrap();
        assert_eq!(m["SupplementalMatchDomains"], strs(&["svc.example", "10.in-addr.arpa"]));
        assert_eq!(m["SupplementalMatchDomainsNoSearch"], Value::Int(1));
        assert_eq!(m["SearchOrder"], Value::Int(101));
        let l = get(&ops, &entry_key(ID, "-local")).unwrap();
        assert_eq!(l["ServerAddresses"], strs(&["192.168.1.1"]));
        assert_eq!(l["SupplementalMatchDomains"], strs(&["lan", "1.168.192.in-addr.arpa"]));
        assert_eq!(l["SupplementalMatchDomainsNoSearch"], Value::Int(1));
        assert_eq!(l["SearchOrder"], Value::Int(200));

        // The override: the VPN's search list followed by the service's own original search domains.
        let state = dict(&[("ServerAddresses", strs(&["192.168.1.1"])), ("DomainName", Value::Str("lan".into()))]);
        let services = [Service { sid: "S1".into(), setup: None, state: Some(state), vpn_like: false }];
        let originals = [Original { sid: "S1".into(), present: false, dict: Dict::new() }];
        let ops = override_ops(ID, &e, true, &originals, &services);
        assert_eq!(
            get(&ops, &setup_key("S1")).unwrap(),
            &dict(&[
                ("ServerAddresses", strs(&["10.8.0.1"])),
                ("SearchDomains", strs(&["corp.example", "lan"])),
                (OWNER_KEY, Value::Str(ID.into())),
            ])
        );
        // Already in place: no operation.
        let now = get(&ops, &setup_key("S1")).cloned();
        let services = [Service { setup: now, ..services[0].clone() }];
        assert!(override_ops(ID, &e, true, &originals, &services).is_empty());
    }

    #[test]
    fn entries_split_layout_has_no_override_and_search_entry_without_nosearch() {
        let e = eff(&["10.8.0.1"], &["corp.example"]);
        for layout in [Layout::Split, Layout::Fallback] {
            let ops = own_entries(ID, layout, &e, Some(&home()));
            let main = get(&ops, &entry_key(ID, "")).unwrap();
            assert!(!main.contains_key("SupplementalMatchDomainsNoSearch"));
            assert!(removed(&ops, &entry_key(ID, "-match")), "nothing match-only");
            assert!(removed(&ops, &entry_key(ID, "-local")), "the default already is the local DNS");
            assert!(ops.iter().all(|o| !matches!(o, Op::Set(k, _) if k.starts_with("Setup:"))));
        }
    }

    #[test]
    fn local_entry_drops_overlaps() {
        let e = Effective { zones: s(&["168.192.in-addr.arpa"]), ..eff(&["10.8.0.1"], &["lan", "corp.example"]) };
        let p = Primary { local_domains: s(&["lan", "home.example"]), ..home() };
        assert_eq!(local_matches(&e, &p), ["home.example"]);
        // A local parent of a VPN domain stays.
        let p = Primary { local_domains: s(&["example"]), local_zones: vec![], ..home() };
        assert_eq!(local_matches(&eff(&["10.8.0.1"], &["corp.example"]), &p), ["example"]);
        // Nothing left: no local entry.
        let p = Primary { local_domains: s(&["lan"]), local_zones: vec![], ..home() };
        let ops = own_entries(ID, Layout::Vpn { local: true }, &e, Some(&p));
        assert!(removed(&ops, &entry_key(ID, "-local")));
    }

    #[test]
    fn strict_has_no_local_entry() {
        let e = eff(&["10.8.0.1"], &["corp.example"]);
        let ops = own_entries(ID, Layout::Vpn { local: false }, &e, Some(&home()));
        assert!(removed(&ops, &entry_key(ID, "-local")));
        let services = [Service {
            sid: "S1".into(),
            setup: None,
            state: Some(dict(&[("DomainName", Value::Str("lan".into()))])),
            vpn_like: false,
        }];
        let originals = [Original { sid: "S1".into(), present: false, dict: Dict::new() }];
        let ops = override_ops(ID, &e, false, &originals, &services);
        assert_eq!(get(&ops, &setup_key("S1")).unwrap()["SearchDomains"], strs(&["corp.example"]), "no local search");
    }

    #[test]
    fn none_removes_every_own_entry() {
        let ops = own_entries(ID, Layout::None, &Effective::default(), None);
        assert_eq!(ops.len(), 3);
        assert!(ENTRY_SUFFIXES.iter().all(|x| removed(&ops, &entry_key(ID, x))));
    }

    #[test]
    fn override_skips_vpn_like_services() {
        let e = eff(&["10.8.0.1"], &[]);
        let services = [
            Service { sid: "S1".into(), setup: None, state: None, vpn_like: false },
            Service { sid: "T1".into(), setup: None, state: None, vpn_like: true },
        ];
        let manual = dict(&[("ServerAddresses", strs(&["1.1.1.1"])), ("SearchDomains", strs(&["x.example"]))]);
        let originals = [Original { sid: "S1".into(), present: true, dict: manual }];
        let ops = override_ops(ID, &e, true, &originals, &services);
        assert_eq!(ops.len(), 1);
        let d = get(&ops, &setup_key("S1")).unwrap();
        assert_eq!(d["ServerAddresses"], strs(&["10.8.0.1"]));
        assert_eq!(d["SearchDomains"], strs(&["x.example"]), "the manual search list stays (local)");
    }

    #[test]
    fn restore_puts_back_only_our_values() {
        let manual = dict(&[("ServerAddresses", strs(&["1.1.1.1"]))]);
        let originals = [
            Original { sid: "S1".into(), present: true, dict: manual.clone() },
            Original { sid: "S2".into(), present: false, dict: Dict::new() },
            Original { sid: "S3".into(), present: false, dict: Dict::new() },
            Original { sid: "S4".into(), present: false, dict: Dict::new() },
        ];
        let ours = dict(&[(OWNER_KEY, Value::Str(ID.into()))]);
        let foreign = dict(&[("ServerAddresses", strs(&["9.9.9.9"]))]);
        let current = |sid: &str| match sid {
            "S1" | "S2" => Some(ours.clone()),
            "S3" => Some(foreign.clone()),
            _ => None,
        };
        let (ops, changed) = restore_ops(&originals, &current);
        assert_eq!(ops, [Op::Set(setup_key("S1"), manual), Op::Remove(setup_key("S2"))]);
        assert_eq!(changed, ["S3"], "S4 is already as it was");
    }

    #[test]
    fn entries_are_capped() {
        let many: Vec<String> = (0..100).map(|i| format!("d{i}.example")).collect();
        let pushed = Pushed { servers: s(&["10.8.0.1"]), search: many.clone(), resolve: many.clone(), routes: vec![] };
        let e = effective(&pushed, &DnsRequest { domains: many.clone(), ..Default::default() });
        assert_eq!(e.search.len(), MAX_DOMAINS);
        assert!(e.resolve.len() <= MAX_ZONES);
        let routes: Vec<IpPrefix> = (0..100).map(|i| IpPrefix::parse(&format!("10.{i}.0.0/16")).unwrap()).collect();
        let e = effective(&Pushed { routes, ..pushed }, &DnsRequest::default());
        assert_eq!(e.zones.len(), MAX_ZONES);
        let ops = own_entries(ID, Layout::Vpn { local: true }, &e, None);
        let m = get(&ops, &entry_key(ID, "-match")).unwrap();
        assert!(m["SupplementalMatchDomains"].as_strings().unwrap().len() <= MAX_ZONES);
    }

    #[test]
    fn primary_facts() {
        let state = dict(&[("ServerAddresses", strs(&["192.168.1.1"])), ("DomainName", Value::Str("Lan.".into()))]);
        let v4 = dict(&[("Addresses", strs(&["192.168.1.20"])), ("SubnetMasks", strs(&["255.255.255.0"]))]);
        let v6 = dict(&[
            ("Addresses", strs(&["fd12:3456:789a:1::20", "2001:db8::1"])),
            ("PrefixLength", Value::Array(vec![Value::Int(64), Value::Int(64)])),
        ]);
        let p = primary("S1", None, Some(&state), Some(&v4), Some(&v6));
        assert_eq!(p.servers, ["192.168.1.1"]);
        assert_eq!(p.local_domains, ["lan"]);
        assert_eq!(p.local_zones[0], "1.168.192.in-addr.arpa");
        assert_eq!(p.local_zones.len(), 2, "the ULA /64, not the global one");
        // Manual DNS wins over DHCP.
        let manual =
            Original { sid: "S1".into(), present: true, dict: dict(&[("ServerAddresses", strs(&["1.1.1.1"]))]) };
        assert_eq!(primary("S1", Some(&manual), Some(&state), None, None).servers, ["1.1.1.1"]);
    }
}
