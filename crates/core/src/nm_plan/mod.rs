//! LinVPN (L-b): how a connection becomes a NetworkManager connection. Pure: no OS call, no I/O; compiled and
//! tested on every OS (the counterpart of `ras` for Windows).
//!
//! [`plan`] dispatches by kind to one module per NM backend (spec section 4): `wireguard` (NM built-in),
//! `openvpn` (LinVPN's own service `org.freedesktop.NetworkManager.linvpn-openvpn`, decision 8), `l2tp`
//! (network-manager-l2tp), `strongswan` (IKEv2, network-manager-strongswan), `vpnc` (Cisco IPsec), `sstp`. A
//! [`NmPlan`] holds no secret in [`NmPlan::settings`]: the secrets are [`SecretItem`]s the agent answers (or, with
//! [`SecretMode::Inline`], the engine puts into the in-memory connection right before adding it), and inline
//! certificates and keys are [`RuntimeFile`]s the engine writes into the 0700 runtime directory. `Debug` never
//! shows a secret or a file's content.
//!
//! [`Unsupported`] carries the precise reasons Linux cannot run a connection (the connection is kept and still
//! runs on macOS and Windows; `NativeSupport` greys its row with them).

pub mod dns;
pub mod l2tp;
pub mod names;
pub mod openvpn;
pub mod sstp;
pub mod strongswan;
pub mod vpnc;
pub mod wireguard;

use crate::models::{Connection, SecretField, VPNKind};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// One NM setting value, as the D-Bus signature needs it (`lin::nm::value` converts it to a `zvariant`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NmValue {
    Str(String),
    Bool(bool),
    U32(u32),
    I32(i32),
    I64(i64),
    /// `as`
    StrList(Vec<String>),
    /// `a{ss}`: `vpn.data` (never `vpn.secrets`).
    StrDict(BTreeMap<String, String>),
    /// `aa{sv}` `address-data`
    Addresses(Vec<NmAddress>),
    /// `aa{sv}` `route-data`
    Routes(Vec<NmRoute>),
    /// `aa{sv}` `wireguard.peers`, without preshared keys
    WgPeers(Vec<NmWgPeer>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmAddress {
    pub address: String,
    pub prefix: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmRoute {
    pub dest: String,
    pub prefix: u32,
    /// `None`: no next hop (OpenVPN's `vpn_gateway` routes: into the tunnel).
    pub next_hop: Option<String>,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmWgPeer {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: u32,
    /// The peer has a preshared key: `preshared-key-flags` is set and the key is a [`SecretItem`].
    pub has_preshared_key: bool,
}

/// `setting name → key → value`.
pub type Settings = BTreeMap<String, BTreeMap<String, NmValue>>;

/// NM's secret flags (`NMSettingSecretFlags`).
pub const FLAG_NONE: u32 = 0;
pub const FLAG_AGENT_OWNED: u32 = 1;
pub const FLAG_NOT_SAVED: u32 = 2;
pub const FLAG_NOT_REQUIRED: u32 = 4;

/// Where a secret's value comes from at connect time.
pub enum SecretValue {
    /// A vault field (the `Secrets` app-core prepared: password with the code appended or packed, PSK, …).
    Field(SecretField),
    /// A value of the config itself (WireGuard's `PrivateKey`, a peer's `PresharedKey`).
    Literal(Zeroizing<String>),
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretValue::Field(field) => write!(f, "Field({field:?})"),
            SecretValue::Literal(_) => f.write_str("Literal(***)"),
        }
    }
}

/// Which secret key of which setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretKey {
    /// `vpn.secrets[<key>]` or `wireguard.<key>`.
    Plain(String),
    /// `wireguard.peers[public-key = …].preshared-key`.
    WgPeerPsk { public_key: String },
}

#[derive(Debug)]
pub struct SecretItem {
    /// `"vpn"` or `"wireguard"`.
    pub setting: &'static str,
    pub key: SecretKey,
    pub value: SecretValue,
}

/// An inline certificate or key the engine writes as `<runtime dir>/<name>` (0600) before connecting.
pub struct RuntimeFile {
    pub name: String,
    pub data: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for RuntimeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RuntimeFile({}, {} bytes)", self.name, self.data.len())
    }
}

/// How the engine delivers static secrets (resolved point 8; spike L0-4 sets the default).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SecretMode {
    /// `*-flags = 1`: LinVPN's agent answers.
    #[default]
    Agent,
    /// `*-flags = 0`: the values go into the volatile in-memory connection before it is added.
    Inline,
}

impl SecretMode {
    pub fn flags(self) -> u32 {
        match self {
            SecretMode::Agent => FLAG_AGENT_OWNED,
            SecretMode::Inline => FLAG_NONE,
        }
    }
}

/// What the system offers (read by the engine before planning; never a secret).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Caps {
    /// OpenVPN ≥ 2.7: the server's `redirect-gateway` reaches LinVPN's service (decision 8).
    pub openvpn_push_visible: bool,
    pub secret_mode: SecretMode,
    /// LinVPN's strongSwan credential folder (`$XDG_DATA_HOME/LinVPN/swanctl`), resolved point 18.
    pub swanctl_dir: Option<PathBuf>,
    /// The file names in `<swanctl_dir>/x509ca` (sorted).
    pub swanctl_ca_files: Vec<String>,
    /// The installed network-manager-strongswan knows `remote-ts` (split IKEv2 tunnels).
    pub strongswan_remote_ts: bool,
}

/// A path NetworkManager reads on the Linux host: `dir` and `parts` joined with `/` whatever OS builds the plan
/// (the plan is pure and tested on every OS; `Path::join` would write `\` on Windows).
pub fn linux_path(dir: &Path, parts: &[&str]) -> String {
    let mut s = dir.to_string_lossy().into_owned();
    for p in parts {
        if !s.ends_with('/') {
            s.push('/');
        }
        s.push_str(p);
    }
    s
}

/// Everything a plan reads. `config`: the stored config (empty for L2TP and Cisco); `user`: the login name for
/// `permissions`; `runtime_dir`: this connection's 0700 directory (`$XDG_RUNTIME_DIR/linvpn/nm/<nm uuid>`);
/// `client_cert`: the IKEv2 client certificate imported in the app (other kinds ignore it).
pub struct Input<'a> {
    pub connection: &'a Connection,
    pub config: &'a [u8],
    pub user: &'a str,
    pub uid: u32,
    pub runtime_dir: &'a Path,
    pub caps: &'a Caps,
    pub client_cert: ImportedCert<'a>,
}

/// The IKEv2 client certificate imported in the app (the vault's `SecretField::ClientCert`, client credential audit
/// G4). Only the connect reads its content; the editor's notes and the row's reason know only whether one is
/// imported and its form (no secret is read for them).
#[derive(Debug, Clone, Copy, Default)]
pub enum ImportedCert<'a> {
    /// None is imported.
    #[default]
    None,
    /// One is imported in this form (its content is not read here).
    Known(crate::client_cert::Form),
    /// The certificate and its key (the connect): written as runtime files.
    Cert(&'a crate::client_cert::ClientCert),
}

impl ImportedCert<'_> {
    pub fn form(&self) -> Option<crate::client_cert::Form> {
        match self {
            ImportedCert::None => None,
            ImportedCert::Known(form) => Some(*form),
            ImportedCert::Cert(cert) => Some(cert.form()),
        }
    }
}

#[derive(Debug)]
pub struct NmPlan {
    pub kind: VPNKind,
    /// `vpn.service-type`; `None` for WireGuard (`connection.type = wireguard`).
    pub service_type: Option<&'static str>,
    pub settings: Settings,
    pub secrets: Vec<SecretItem>,
    pub files: Vec<RuntimeFile>,
    /// The tunnel interface LinVPN chose (WireGuard, OpenVPN); `None`: NM or the plugin picks it.
    pub iface: Option<String>,
    /// One line for the editor ("On Linux: …"), localized.
    pub summary: Option<String>,
    /// Settings NetworkManager ignores; the connection still runs (grey editor notes, the log).
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported {
    pub reasons: Vec<String>,
    /// The config itself is invalid (the validator's messages, not a Linux limit).
    pub invalid_config: bool,
}

impl Unsupported {
    pub fn linux(reasons: Vec<String>) -> Unsupported {
        Unsupported { reasons, invalid_config: false }
    }

    pub fn invalid(reasons: Vec<String>) -> Unsupported {
        Unsupported { reasons, invalid_config: true }
    }
}

impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reasons.join("\n"))
    }
}

impl std::error::Error for Unsupported {}

/// The service types (spec 4; decision 8 for OpenVPN).
pub const SERVICE_OPENVPN: &str = "org.freedesktop.NetworkManager.linvpn-openvpn";
pub const SERVICE_OPENVPN_STOCK: &str = "org.freedesktop.NetworkManager.openvpn";
pub const SERVICE_L2TP: &str = "org.freedesktop.NetworkManager.l2tp";
pub const SERVICE_STRONGSWAN: &str = "org.freedesktop.NetworkManager.strongswan";
pub const SERVICE_VPNC: &str = "org.freedesktop.NetworkManager.vpnc";
pub const SERVICE_SSTP: &str = "org.freedesktop.NetworkManager.sstp";

/// The plan of any kind.
pub fn plan(input: &Input) -> Result<NmPlan, Unsupported> {
    match input.connection.kind {
        VPNKind::Wireguard => wireguard::plan(input),
        VPNKind::Openvpn => openvpn::plan(input),
        VPNKind::L2tp => l2tp::plan(input),
        VPNKind::Cisco => vpnc::plan(input),
        VPNKind::Strongswan => strongswan::plan(input),
        VPNKind::Sstp => sstp::plan(input),
    }
}

/// The `connection` section every plan starts with: private to `user`, never autoconnecting, the derived UUID.
pub fn connection_section(
    c: &Connection,
    uid: u32,
    user: &str,
    nm_type: &str,
    iface: Option<&str>,
) -> BTreeMap<String, NmValue> {
    let mut s = BTreeMap::new();
    s.insert("id".into(), NmValue::Str(c.name.trim().to_string()));
    s.insert("uuid".into(), NmValue::Str(names::nm_uuid(uid, &c.id).to_string()));
    s.insert("type".into(), NmValue::Str(nm_type.into()));
    s.insert("autoconnect".into(), NmValue::Bool(false));
    s.insert("permissions".into(), NmValue::StrList(vec![format!("user:{user}")]));
    if let Some(iface) = iface {
        s.insert("interface-name".into(), NmValue::Str(iface.into()));
    }
    s
}

/// The `vpn` section of a plugin connection: its service type, `persistent = false` (LinVPN's planner alone
/// reconnects), the user name, `data`.
/// The `user.data` key that asks LinVPN's NetworkManager dispatcher script (`90-linvpn-route`) for the class-based
/// route of the VPN address (SSTP and L2TP split tunnels, as Windows and macOS PPP); NM hands it to the script as
/// `CONNECTION_USER_LINVPN__CLASSFUL`.
pub const CLASSFUL_ROUTE_KEY: &str = "linvpn.classful";

/// The `user` section that marks a PPP split tunnel for the class-based route ([`CLASSFUL_ROUTE_KEY`]).
pub fn classful_route_section() -> BTreeMap<String, NmValue> {
    let data = BTreeMap::from([(CLASSFUL_ROUTE_KEY.to_string(), "1".to_string())]);
    BTreeMap::from([("data".to_string(), NmValue::StrDict(data))])
}

pub fn vpn_section(
    service: &str,
    user_name: Option<&str>,
    data: BTreeMap<String, String>,
) -> BTreeMap<String, NmValue> {
    let mut s = BTreeMap::new();
    s.insert("service-type".into(), NmValue::Str(service.into()));
    s.insert("persistent".into(), NmValue::Bool(false));
    if let Some(u) = user_name.filter(|u| !u.is_empty()) {
        s.insert("user-name".into(), NmValue::Str(u.into()));
    }
    s.insert("data".into(), NmValue::StrDict(data));
    s
}
