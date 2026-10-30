//! The NM VPN plugins per kind, their packages, and the rows they make (resolved point 17): System Status'
//! NetworkManager rows from the facts `lin::nm::plugins::facts` reads, and the only package names
//! `lin::nm::packagekit::install` ever asks PackageKit for.

use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::VPNKind;
use macvpn_core::nm_plan::{SERVICE_L2TP, SERVICE_OPENVPN_STOCK, SERVICE_SSTP, SERVICE_STRONGSWAN, SERVICE_VPNC};
use macvpn_platform_api::{EngineRow, NmReport};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    pub nm_version: Option<String>,
    /// The service names of the installed `.name` files.
    pub services: Vec<String>,
    /// LinVPN's own OpenVPN service files are all there.
    pub linvpn_openvpn: bool,
    /// `openvpn --version`'s `2.7.0`.
    pub openvpn_version: Option<String>,
    /// strongSwan's EAP-MSCHAPv2 plugin is installed.
    pub eap_mschapv2: bool,
    /// strongSwan's EAP-Identity plugin is installed (a server with `eap_id = %any` asks for the EAP identity).
    pub eap_identity: bool,
}

/// `AddAndActivateConnection2` (NM 1.36).
const NM_MINIMUM: (u32, u32) = (1, 36);
/// NM's built-in WireGuard.
const NM_WIREGUARD: (u32, u32) = (1, 16);
/// OpenVPN exports `route_redirect_gateway_ipv4/6` to `--up` (decision 8).
const OPENVPN_PUSH_VISIBLE: (u32, u32) = (2, 7);

const OPENVPN: &str = "network-manager-openvpn";
const L2TP: &str = "network-manager-l2tp";
const STRONGSWAN: &str = "network-manager-strongswan";
/// strongSwan's EAP-MSCHAPv2 plugin (IKEv2 with a user name and password).
const EAP: &str = "libcharon-extauth-plugins";
/// strongSwan's EAP-Identity plugin (`libstrongswan-eap-identity.so`): without it charon-nm answers a server's
/// EAP-Identity request (`eap_id = %any`, the common setting) with EAP-NAK.
const EAP_IDENTITY: &str = "libcharon-extra-plugins";
const VPNC: &str = "network-manager-vpnc";
const SSTP: &str = "network-manager-sstp";

/// Every package LinVPN may ask PackageKit to install, and nothing else.
pub const PACKAGES: [&str; 7] = [OPENVPN, L2TP, STRONGSWAN, EAP, EAP_IDENTITY, VPNC, SSTP];

/// The packages a kind needs (WireGuard: none, built into NM).
pub fn packages(kind: VPNKind) -> &'static [&'static str] {
    match kind {
        VPNKind::Wireguard => &[],
        VPNKind::Openvpn => &[OPENVPN],
        VPNKind::L2tp => &[L2TP],
        VPNKind::Strongswan => &[STRONGSWAN, EAP, EAP_IDENTITY],
        VPNKind::Cisco => &[VPNC],
        VPNKind::Sstp => &[SSTP],
    }
}

/// `name` is one of [`PACKAGES`] (exactly).
pub fn is_installable(name: &str) -> bool {
    PACKAGES.contains(&name)
}

/// The `service=` value of a `.name` file (`[VPN Connection]`), if it is a D-Bus name.
pub fn service_of(name_file: &str) -> Option<String> {
    name_file.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        if key.trim() != "service" {
            return None;
        }
        let value = value.trim();
        let bus_name = !value.is_empty()
            && value.len() <= 255
            && value.contains('.')
            && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        bus_name.then(|| value.to_string())
    })
}

/// The version of `openvpn --version`'s first line (`OpenVPN 2.7.0 x86_64-pc-linux-gnu …` → `2.7.0`).
pub fn openvpn_version(stdout: &str) -> Option<String> {
    let rest = stdout.lines().next()?.strip_prefix("OpenVPN ")?;
    let version = rest.split_whitespace().next()?;
    let plain = version.starts_with(|c: char| c.is_ascii_digit())
        && version.len() <= 32
        && version.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    plain.then(|| version.to_string())
}

/// `major.minor` of a version string (`1.55.1-dev` → `(1, 55)`); `None`: not a version.
fn major_minor(version: &str) -> Option<(u32, u32)> {
    let mut parts = version.split(['.', '-', '_']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn at_least(version: &str, minimum: (u32, u32)) -> bool {
    major_minor(version).is_some_and(|v| v >= minimum)
}

fn row(ok: bool, usable: bool, detail: String, action: Option<&'static str>) -> EngineRow {
    EngineRow { ok, usable, detail, action }
}

fn not_installed(missing: &[&str]) -> String {
    l10n::tr("Not installed: %@", &[Arg::Str(&missing.join(", "))])
}

/// A plugin row: green when its service is there, else red with Install and its packages.
fn plugin_row(facts: &Facts, service: &str, kind: VPNKind) -> (EngineRow, String) {
    let all = packages(kind);
    if facts.services.iter().any(|s| s == service) {
        return (row(true, true, l10n::tr("Installed", &[]), None), all.join(" "));
    }
    (row(false, false, not_installed(all), Some("install")), all.join(" "))
}

fn openvpn_row(facts: &Facts) -> (EngineRow, String) {
    let package = OPENVPN.to_string();
    if !facts.linvpn_openvpn {
        let detail = l10n::tr("LinVPN's OpenVPN service is missing: reinstall LinVPN.", &[]);
        return (row(false, false, detail, None), package);
    }
    let stock = facts.services.iter().any(|s| s == SERVICE_OPENVPN_STOCK);
    let Some(version) = facts.openvpn_version.as_deref().filter(|_| stock) else {
        return (row(false, false, not_installed(&[OPENVPN]), Some("install")), package);
    };
    let detail = if at_least(version, OPENVPN_PUSH_VISIBLE) {
        l10n::tr("OpenVPN %@ · follows the server's redirect-gateway", &[Arg::Str(version)])
    } else {
        l10n::tr(
            "OpenVPN %@ · split tunnel unless set to Always (needs 2.7 to follow the server)",
            &[Arg::Str(version)],
        )
    };
    (row(true, true, detail, None), package)
}

fn strongswan_row(facts: &Facts) -> (EngineRow, String) {
    let eap_missing: Vec<&str> = [(EAP, facts.eap_mschapv2), (EAP_IDENTITY, facts.eap_identity)]
        .into_iter()
        .filter_map(|(package, there)| (!there).then_some(package))
        .collect();
    if !facts.services.iter().any(|s| s == SERVICE_STRONGSWAN) {
        let missing: Vec<&str> = std::iter::once(STRONGSWAN).chain(eap_missing).collect();
        return (row(false, false, not_installed(&missing), Some("install")), missing.join(" "));
    }
    if !eap_missing.is_empty() {
        // IKEv2 with certificates or a PSK works; only EAP (user name and password) needs the plugins.
        let detail = l10n::tr("EAP needs %@", &[Arg::Str(&eap_missing.join(", "))]);
        return (row(true, true, detail, Some("install")), eap_missing.join(" "));
    }
    (row(true, true, l10n::tr("Installed", &[]), None), packages(VPNKind::Strongswan).join(" "))
}

/// System Status' NetworkManager rows: NetworkManager itself, then one row per kind (WireGuard, OpenVPN, L2TP/IPsec,
/// IKEv2, Cisco IPsec, SSTP) with the packages its Install button asks for. Without a usable NetworkManager no
/// kind's row is usable.
pub fn report(facts: &Facts) -> NmReport {
    let networkmanager = match facts.nm_version.as_deref() {
        None => row(false, false, l10n::tr("NetworkManager is not running.", &[]), None),
        Some(v) if !at_least(v, NM_MINIMUM) => {
            row(false, false, l10n::tr("NetworkManager 1.36 or later is needed.", &[]), None)
        }
        Some(v) => row(true, true, format!("NetworkManager {v}"), None),
    };
    let wireguard = match facts.nm_version.as_deref() {
        Some(v) if at_least(v, NM_WIREGUARD) => row(true, true, l10n::tr("Built into NetworkManager", &[]), None),
        _ => row(false, false, networkmanager.detail.clone(), None),
    };
    let (openvpn, openvpn_packages) = openvpn_row(facts);
    let (l2tp, l2tp_packages) = plugin_row(facts, SERVICE_L2TP, VPNKind::L2tp);
    let (strongswan, strongswan_packages) = strongswan_row(facts);
    let (cisco, cisco_packages) = plugin_row(facts, SERVICE_VPNC, VPNKind::Cisco);
    let (sstp, sstp_packages) = plugin_row(facts, SERVICE_SSTP, VPNKind::Sstp);
    let mut kinds = vec![
        (VPNKind::Wireguard, wireguard, String::new()),
        (VPNKind::Openvpn, openvpn, openvpn_packages),
        (VPNKind::L2tp, l2tp, l2tp_packages),
        (VPNKind::Strongswan, strongswan, strongswan_packages),
        (VPNKind::Cisco, cisco, cisco_packages),
        (VPNKind::Sstp, sstp, sstp_packages),
    ];
    if !networkmanager.usable {
        for (_, r, _) in &mut kinds {
            r.usable = false;
        }
    }
    let openvpn_push_visible = facts.openvpn_version.as_deref().is_some_and(|v| at_least(v, OPENVPN_PUSH_VISIBLE));
    NmReport { networkmanager, kinds, openvpn_push_visible }
}
