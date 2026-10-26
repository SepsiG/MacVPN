//! SSTP (MS-CHAP v2) from the `.sstp` config.

use super::{Auth, DefaultRoute, Needs, RasEntryPlan, Strategy, Unsupported, config_text};
use crate::l10n;
use crate::validators::sstp::DEFAULT_PORT;
use crate::validators::{CertMode, ConfigValidator, SSTPConfig, SSTPValidator};
use std::net::Ipv6Addr;

/// The interface metric that makes Windows prefer the physical adapter's DNS (`peer_dns = no`).
pub const NO_PEER_DNS_METRIC: u32 = 9000;

/// The plan of an SSTP config. The validator runs first: an invalid config is its error, not a Windows reason.
pub fn plan_sstp(config: &[u8]) -> Result<RasEntryPlan, Unsupported> {
    let text = config_text(config)?;
    let issues = SSTPValidator.validate(&text);
    if !issues.is_empty() {
        return Err(Unsupported::from_issues(&issues));
    }
    let c = SSTPConfig::parse(&text);
    if super::server_has_control(&c.server) {
        return Err(Unsupported::invalid(vec![super::server_control_reason()]));
    }
    if c.cert == CertMode::Insecure {
        return Err(Unsupported::windows(vec![l10n::tr(
            "Windows always checks the SSTP server's certificate. Choose System CA or Custom CA file.",
            &[],
        )]));
    }
    let server = if c.port == DEFAULT_PORT {
        c.server.clone()
    } else if c.server.parse::<Ipv6Addr>().is_ok() {
        format!("[{}]:{}", c.server, c.port)
    } else {
        format!("{}:{}", c.server, c.port)
    };
    Ok(RasEntryPlan {
        strategy: Strategy::Sstp,
        server,
        auth: Auth::MsChapV2 { psk: false },
        default_route: if c.route_all { DefaultRoute::Both } else { DefaultRoute::None },
        ts_as_routes: false,
        ike_fragmentation: false,
        interface_metric: (!c.peer_dns).then_some(NO_PEER_DNS_METRIC),
        policy: None,
        user: c.user,
        needs: Needs { user: false, password: true, psk: false },
        warnings: Vec::new(),
    })
}
