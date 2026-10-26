//! L2TP/IPsec (PSK + MS-CHAP v2) from the native settings; Cisco IPsec has no Windows client (option A).

use super::{Auth, DefaultRoute, Needs, RasEntryPlan, Strategy, Unsupported};
use crate::l10n;
use crate::models::{Connection, VPNKind};

/// The reason a Cisco IPsec connection cannot connect on Windows (the maintainer's option A, 2026-10-25). One
/// constant, so Task 12 can switch it.
pub const CISCO_UNSUPPORTED: &str = "Cisco IPsec is not supported by Windows. Ask your VPN administrator for L2TP/IPsec or IKEv2 access, or make an L2TP/IPsec copy of this connection.";

/// The plan of an L2TP connection; a Cisco IPsec connection is not supported on Windows. Server and account are
/// required (the editor refuses empty ones; a connection without them is invalid, not a Windows limit).
pub fn plan_native(connection: &Connection) -> Result<RasEntryPlan, Unsupported> {
    match connection.kind {
        VPNKind::L2tp => {}
        VPNKind::Cisco => {
            let key = CISCO_UNSUPPORTED;
            return Err(Unsupported::windows(vec![l10n::tr(key, &[])]));
        }
        _ => return Err(Unsupported::invalid(vec![l10n::tr("Server and account name are required", &[])])),
    }
    let settings = connection.native.as_ref();
    let server = settings.map_or("", |s| s.server.trim());
    let account = settings.map_or("", |s| s.account.trim());
    let Some(settings) = settings.filter(|_| !server.is_empty() && !account.is_empty()) else {
        return Err(Unsupported::invalid(vec![l10n::tr("Server and account name are required", &[])]));
    };
    if super::server_has_control(server) {
        return Err(Unsupported::invalid(vec![super::server_control_reason()]));
    }
    Ok(RasEntryPlan {
        strategy: Strategy::L2tp,
        server: server.to_string(),
        auth: Auth::MsChapV2 { psk: true },
        default_route: if settings.send_all_traffic { DefaultRoute::Both } else { DefaultRoute::None },
        ts_as_routes: false,
        ike_fragmentation: false,
        interface_metric: None,
        policy: None,
        user: account.to_string(),
        needs: Needs { user: true, password: true, psk: true },
        warnings: Vec::new(),
    })
}
