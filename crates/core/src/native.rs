//! Native VPN start options (port of `NativeKind` and `NativeStartOptions` in `NativeVPN.swift`). The platform
//! layer turns them into the `SCNetworkConnectionStart` user-options dictionary.

use crate::models::{Secrets, VPNKind};
use std::collections::BTreeMap;

/// The native service types whose secrets can be passed when starting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeKind {
    L2tp,
    CiscoIPSec,
}

impl NativeKind {
    pub fn from_kind(kind: VPNKind) -> Option<NativeKind> {
        match kind {
            VPNKind::L2tp => Some(NativeKind::L2tp),
            VPNKind::Cisco => Some(NativeKind::CiscoIPSec),
            _ => None,
        }
    }

    /// `SystemVPNService.typeLabel`.
    pub fn from_type_label(label: &str) -> Option<NativeKind> {
        match label {
            "L2TP" => Some(NativeKind::L2tp),
            "Cisco IPsec" => Some(NativeKind::CiscoIPSec),
            _ => None,
        }
    }
}

/// `kSCEntNetIPSec`.
pub const ENT_IPSEC: &str = "IPSec";
/// `kSCEntNetPPP`.
pub const ENT_PPP: &str = "PPP";
/// `kSCPropNetIPSecSharedSecret`.
pub const IPSEC_SHARED_SECRET: &str = "SharedSecret";
/// `kSCPropNetIPSecXAuthName`.
pub const IPSEC_XAUTH_NAME: &str = "XAuthName";
/// `kSCPropNetIPSecXAuthPassword`.
pub const IPSEC_XAUTH_PASSWORD: &str = "XAuthPassword";
/// `kSCPropNetPPPAuthName`.
pub const PPP_AUTH_NAME: &str = "AuthName";
/// `kSCPropNetPPPAuthPassword`.
pub const PPP_AUTH_PASSWORD: &str = "AuthPassword";

/// User options for `SCNetworkConnectionStart`: `entity -> (property -> value)`. They override the service's
/// stored configuration for this start, so a PSK pppd/racoon cannot read from the System keychain is still used.
/// Never logged, never put into argv.
pub type NativeStartOptions = BTreeMap<&'static str, BTreeMap<&'static str, String>>;

/// `None`: no secret given, the stored configuration is used as it is.
pub fn start_options(kind: NativeKind, secrets: &Secrets) -> Option<NativeStartOptions> {
    let value = |s: &Option<String>| s.clone().filter(|v| !v.is_empty());
    let mut ipsec = BTreeMap::new();
    let mut ppp = BTreeMap::new();
    if let Some(psk) = value(&secrets.psk) {
        ipsec.insert(IPSEC_SHARED_SECRET, psk);
    }
    match kind {
        NativeKind::L2tp => {
            if let Some(name) = value(&secrets.username) {
                ppp.insert(PPP_AUTH_NAME, name);
            }
            if let Some(password) = value(&secrets.password) {
                ppp.insert(PPP_AUTH_PASSWORD, password);
            }
        }
        NativeKind::CiscoIPSec => {
            if let Some(name) = value(&secrets.username) {
                ipsec.insert(IPSEC_XAUTH_NAME, name);
            }
            if let Some(password) = value(&secrets.password) {
                ipsec.insert(IPSEC_XAUTH_PASSWORD, password);
            }
        }
    }
    let mut options = NativeStartOptions::new();
    if !ipsec.is_empty() {
        options.insert(ENT_IPSEC, ipsec);
    }
    if !ppp.is_empty() {
        options.insert(ENT_PPP, ppp);
    }
    (!options.is_empty()).then_some(options)
}
