//! Cisco IPsec (IKEv1 XAUTH, group PSK) through NetworkManager (LinVPN L-b, Task 8): `network-manager-vpnc`
//! (Ubuntu 26.04 ships 1.4.0; keys pinned against its `shared/nm-service-defines.h`). Cisco works on Linux, unlike
//! Windows (spec 4). The group secret and the XAUTH password are secret items, never in `vpn.data`. The proposal is
//! fixed to what macOS's client sends: NAT-T, Cisco vendor, DH group 2, PFS as the server says.

use super::l2tp::{assemble, checked, secret};
use super::{Input, NmPlan, Unsupported};
use crate::l10n;
use crate::models::SecretField;
use std::collections::BTreeMap;

/// The plan of a Cisco IPsec connection. The group name is required (as for the macOS profile).
pub fn plan(input: &Input) -> Result<NmPlan, Unsupported> {
    let native = checked(input)?;
    if native.group.is_empty() {
        return Err(Unsupported::invalid(vec![l10n::tr("Cisco IPsec requires a group name", &[])]));
    }
    let flags = input.caps.secret_mode.flags().to_string();
    let mut data = BTreeMap::new();
    for (key, value) in [
        ("IPSec gateway", native.server.as_str()),
        ("IPSec ID", native.group.as_str()),
        ("Xauth username", native.account.as_str()),
        ("IPSec secret-flags", flags.as_str()),
        ("Xauth password-flags", flags.as_str()),
        ("NAT Traversal Mode", "natt"),
        ("Vendor", "cisco"),
        ("Perfect Forward Secrecy", "server"),
        ("IKE DH Group", "dh2"),
    ] {
        data.insert(key.to_string(), value.to_string());
    }
    let secrets = vec![secret("IPSec secret", SecretField::Psk), secret("Xauth password", SecretField::Password)];
    let summary = l10n::tr("On Linux: NetworkManager vpnc (Cisco IPsec)", &[]);
    Ok(assemble(input, &native, super::SERVICE_VPNC, data, secrets, summary))
}
