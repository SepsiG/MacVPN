//! Cisco IPsec on Windows: the maintainer's option A of the 2c plan (2026-10-25). Windows has no IKEv1-XAUTH
//! client and no maintained, redistributable engine exists, so a Cisco IPsec connection stays editable, exportable,
//! backed up and shared through catalogs, but cannot connect: its row is greyed with [`unsupported`], **New →
//! Cisco IPsec** is hidden (the kind gate: [`unsupported_kinds`] in the setup report), and its editor offers
//! **Make an L2TP/IPsec Copy** (app-core `editor::l2tp_copy_of`).

use macvpn_core::l10n;
use macvpn_core::models::{Connection, VPNKind};
use macvpn_platform_api::NativeSupport;

/// Why a Cisco IPsec connection cannot connect on Windows (the text of core's `ras::CISCO_UNSUPPORTED`, which the
/// RAS plans give too).
pub fn unsupported() -> String {
    l10n::tr(
        "Cisco IPsec is not supported by Windows. Ask your VPN administrator for L2TP/IPsec or IKEv2 access, or make an L2TP/IPsec copy of this connection.",
        &[],
    )
}

/// The setup report's `ras_unsupported_kinds`: Cisco IPsec with [`unsupported`].
pub fn unsupported_kinds() -> Vec<(VPNKind, String)> {
    vec![(VPNKind::Cisco, unsupported())]
}

/// The editor's button that makes the L2TP/IPsec copy.
pub fn copy_label() -> String {
    l10n::tr("Make an L2TP/IPsec Copy", &[])
}

/// A Cisco IPsec connection is never supported; every other connection is. The platform's `native_support` is the
/// RAS engine (2c Task 8), which gives the same Cisco reason from the connection's plan (`ras_connect`'s tests pin
/// it) and the IKEv2 / SSTP reasons too.
pub struct CiscoSupport;

impl NativeSupport for CiscoSupport {
    fn unsupported_reason(&self, connection: &Connection, _config: &[u8]) -> Option<String> {
        (connection.kind == VPNKind::Cisco).then(unsupported)
    }
}
