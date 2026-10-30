//! L2TP/IPsec through NetworkManager (LinVPN L-b, Task 8): `network-manager-l2tp` (Ubuntu 26.04 ships 1.52.0;
//! keys pinned against its `shared/nm-service-defines.h`). PSK + MS-CHAPv2 only, as macOS: PAP, CHAP, MS-CHAP and
//! EAP refused, no MPPE requirement (macOS asks for none). The PSK and the password are secret items (since 1.2.16
//! `ipsec-psk` is a secret with `ipsec-psk-flags`), never in `vpn.data`.
//!
//! The parts both native kinds share (the checks of [`NativeSettings`], the `connection`/`vpn`/`ipv4`/`ipv6`
//! sections) live here too; `vpnc` uses them.

use super::{Input, NmPlan, NmValue, SecretItem, SecretKey, SecretValue, Settings, Unsupported};
use crate::l10n;
use crate::models::{NativeSettings, SecretField};
use std::collections::BTreeMap;

/// The plan of an L2TP/IPsec connection.
pub fn plan(input: &Input) -> Result<NmPlan, Unsupported> {
    let native = checked(input)?;
    let flags = input.caps.secret_mode.flags().to_string();
    let mut data = BTreeMap::new();
    data.insert("gateway".to_string(), native.server.clone());
    data.insert("user".to_string(), native.account.clone());
    data.insert("ipsec-enabled".to_string(), "yes".to_string());
    for refused in ["refuse-pap", "refuse-chap", "refuse-mschap", "refuse-eap"] {
        data.insert(refused.to_string(), "yes".to_string());
    }
    data.insert("password-flags".to_string(), flags.clone());
    data.insert("ipsec-psk-flags".to_string(), flags);
    let secrets = vec![secret("password", SecretField::Password), secret("ipsec-psk", SecretField::Psk)];
    let summary = l10n::tr("On Linux: NetworkManager L2TP/IPsec (MS-CHAPv2)", &[]);
    let mut plan = assemble(input, &native, super::SERVICE_L2TP, data, secrets, summary);
    if !native.send_all_traffic {
        // The split tunnel's class-based route (Windows' and macOS' PPP), added by the dispatcher script.
        plan.settings.insert("user".into(), super::classful_route_section());
    }
    Ok(plan)
}

/// Server and account of a native connection, trimmed and checked.
pub(super) struct Native {
    pub server: String,
    pub account: String,
    pub group: String,
    pub send_all_traffic: bool,
}

/// The checks `ras::l2tp::plan_native` makes, plus control characters in the account and the group (they go into
/// the plugins' generated configs, where a line break would add options), and Cisco's required group.
pub(super) fn checked(input: &Input) -> Result<Native, Unsupported> {
    let required = || Unsupported::invalid(vec![l10n::tr("Server and account name are required", &[])]);
    let settings: &NativeSettings = input.connection.native.as_ref().ok_or_else(required)?;
    let server = settings.server.trim();
    let account = settings.account.trim();
    if server.is_empty() || account.is_empty() {
        return Err(required());
    }
    if crate::ras::server_has_control(server) {
        return Err(Unsupported::invalid(vec![crate::ras::server_control_reason()]));
    }
    let group = settings.group_name.trim();
    if crate::mfa::has_control(account) || crate::mfa::has_control(group) {
        return Err(Unsupported::invalid(vec![l10n::tr("Control character not allowed", &[])]));
    }
    Ok(Native {
        server: server.to_string(),
        account: account.to_string(),
        group: group.to_string(),
        send_all_traffic: settings.send_all_traffic,
    })
}

/// A `vpn.secrets[key]` item answered from a vault field.
pub(super) fn secret(key: &str, field: SecretField) -> SecretItem {
    SecretItem { setting: "vpn", key: SecretKey::Plain(key.into()), value: SecretValue::Field(field) }
}

/// The plan of a plugin connection: private `connection`, the `vpn` section, `ipv4`/`ipv6` by the DNS rule and
/// `never-default = !send_all_traffic` (the plugins' PPP / XAUTH configuration pushes the routes).
pub(super) fn assemble(
    input: &Input,
    native: &Native,
    service: &'static str,
    data: BTreeMap<String, String>,
    secrets: Vec<SecretItem>,
    summary: String,
) -> NmPlan {
    let c = input.connection;
    let full = native.send_all_traffic;
    let mut settings = Settings::new();
    settings.insert("connection".into(), super::connection_section(c, input.uid, input.user, "vpn", None));
    settings.insert("vpn".into(), super::vpn_section(service, Some(&native.account), data));
    for family in ["ipv4", "ipv6"] {
        let mut s = super::dns::section_extras(full, &[]);
        s.insert("method".into(), NmValue::Str("auto".into()));
        s.insert("never-default".into(), NmValue::Bool(!full));
        settings.insert(family.into(), s);
    }
    NmPlan {
        kind: c.kind,
        service_type: Some(service),
        settings,
        secrets,
        files: Vec::new(),
        iface: None,
        summary: Some(summary),
        warnings: Vec::new(),
    }
}
