//! The DNS mode logic shared by MacVPN, WinVPN and LinVPN (moved from the macOS root helper, root layer 20). Pure:
//! each platform gathers the facts (the VPN-sent DNS, the connection's request, the tunnel, the probe) and applies
//! the layout decided here with its own mechanism.
//!
//! **Layouts.** `Vpn` puts the VPN's DNS in the default role (with `local`, the local network's own names stay on
//! its DNS). `Split` and `Fallback` send only the VPN's domains to the VPN's DNS. `None` changes nothing.
//!
//! **The probe** ([`probe`]) asks the VPN's DNS for an internet name; two failed checks in a row make the
//! Automatic mode fall back ([`next_probe`]), one good one returns.

use crate::dns_settings::{DnsMode, DnsRequest, MAX_DOMAINS, MAX_SERVERS};
use crate::dns_zones::{MAX_ZONES, is_private, reverse_zones};
use crate::netaddr::IpPrefix;
use crate::status::DnsState;

pub mod nrpt;
pub mod probe;
pub mod push_reply;

pub use probe::probe;

/// The connection's tunnel: everything through the VPN (`Full`) or only its routes (`Split`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tunnel {
    Full,
    Split,
    /// Before the routes are in (the hook): counts as split for Targeted, irrelevant otherwise.
    Unknown,
}

/// The probe's result as the decision uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    NotRun,
    Ok,
    Failed,
}

/// Where names are resolved while the connection is up.
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

/// The warning (notice or log hint) that goes with a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warn {
    NoDns,
    Fallback { full_tunnel: bool },
    Failing,
    TargetedOnFullTunnel,
    TargetedNoDomains,
}

/// `raw()` / `from_raw()` over a fixed list of values (the words of a platform's session record).
macro_rules! raw_enum {
    ($t:ty, [$($v:expr),+ $(,)?], $raw:expr) => {
        impl $t {
            /// The value's word.
            pub fn raw(self) -> &'static str {
                let f: fn($t) -> &'static str = $raw;
                f(self)
            }
            /// The value of a word, `None` for an unknown one.
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

/// The outcome of [`decide`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Where names are resolved.
    pub layout: Layout,
    /// The notice or log hint, if any.
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
    /// The DNS servers (IP literals).
    pub servers: Vec<String>,
    /// The search domains.
    pub search: Vec<String>,
    /// OpenVPN 2.7 `dns server … resolve-domains`: match-only.
    pub resolve: Vec<String>,
    /// The routed networks.
    pub routes: Vec<IpPrefix>,
}

/// The DNS a connection puts into effect: the VPN-sent DNS merged with the connection's own request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Effective {
    /// The DNS servers (IP literals).
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
    pub fn all_matches(&self) -> Vec<String> {
        self.search.iter().chain(&self.resolve).chain(&self.zones).cloned().collect()
    }
}

/// Order-keeping, case-insensitive dedup, at most `cap` items.
pub fn dedup(items: impl IntoIterator<Item = String>, cap: usize) -> Vec<String> {
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

/// Consecutive failed checks before the Automatic mode falls back (each check already sends twice).
pub const FAILS_TO_FALL_BACK: u32 = 2;

/// A check's probe result folded into the session's probe and failure count: one failure keeps the current
/// layout (no flapping), the second in a row decides; one success returns. `NotRun` changes nothing.
///
/// ```
/// use macvpn_core::dns_policy::{Probe, next_probe};
/// assert_eq!(next_probe(Probe::Ok, 0, Probe::Failed), (Probe::Ok, 1));
/// assert_eq!(next_probe(Probe::Ok, 1, Probe::Failed), (Probe::Failed, 2));
/// ```
pub fn next_probe(prev: Probe, prev_fails: u32, result: Probe) -> (Probe, u32) {
    match result {
        Probe::NotRun => (prev, prev_fails),
        Probe::Ok => (Probe::Ok, 0),
        Probe::Failed => {
            let fails = prev_fails.saturating_add(1);
            let keep = if prev == Probe::Failed { Probe::Failed } else { Probe::Ok };
            (if fails >= FAILS_TO_FALL_BACK { Probe::Failed } else { keep }, fails)
        }
    }
}

/// The state the app shows for a layout and its warning.
pub fn state_of(layout: Layout, warn: Option<Warn>) -> DnsState {
    match (layout, warn) {
        (Layout::None, _) => DnsState::None,
        (Layout::Split, _) => DnsState::Targeted,
        (Layout::Fallback, Some(Warn::Fallback { full_tunnel: true })) => DnsState::FallbackFullTunnel,
        (Layout::Fallback, _) => DnsState::Fallback,
        (Layout::Vpn { .. }, Some(Warn::Failing)) => DnsState::Failing,
        (Layout::Vpn { .. }, _) => DnsState::Vpn,
    }
}
