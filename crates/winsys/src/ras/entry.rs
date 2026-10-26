//! Phonebook entries: write (`RasSetEntryPropertiesW` + the EAP data + the policy keys), read, delete, list,
//! validate a name.

use super::ini::{self, IpsecPolicy};
use super::{Error, Result, field_text, fill, guid_bytes, rc};
use crate::util::{plain_absolute, wide, wide_path};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use windows_sys::Win32::NetworkManagement::Rras::{
    ET_Optional, ET_Require, RASENTRYNAMEW, RASENTRYW, RASEO_RemoteDefaultGateway, RASEO_RequireDataEncryption,
    RASEO_RequireEAP, RASEO_RequireEncryptedPw, RASEO_RequireMsCHAP2, RASEO_RequireMsEncryptedPw,
    RASEO2_DontNegotiateMultilink, RASEO2_IPv4ExplicitMetric, RASEO2_IPv6ExplicitMetric,
    RASEO2_IPv6RemoteDefaultGateway, RASEO2_PlumbIKEv2TSAsRoutes, RASEO2_ReconnectIfDropped,
    RASEO2_RequireMachineCertificates, RASEO2_UsePreSharedKey, RASET_Vpn, RASFP_Ppp, RASNP_Ip, RASNP_Ipv6,
    RasDeleteEntryW, RasEnumEntriesW, RasGetEntryPropertiesW, RasSetCustomAuthDataW, RasSetEntryPropertiesW,
    RasValidateEntryNameW, VS_Ikev2Only, VS_L2tpOnly, VS_SstpOnly,
};
use windows_sys::core::PCWSTR;

/// `ERROR_BUFFER_TOO_SMALL`: the size dance's first answer.
const ERROR_BUFFER_TOO_SMALL: u32 = 603;
/// `ERROR_CANNOT_OPEN_PHONEBOOK`
const ERROR_CANNOT_OPEN_PHONEBOOK: u32 = 615;
/// `REN_AllUsers` in `RASENTRYNAMEW.dwFlags`.
const REN_ALL_USERS: u32 = 1;
/// At most this many entries are listed from one call.
const MAX_ENTRIES: usize = 4096;
/// `RAS_MaxEntryName` + 1, `RAS_MaxPhoneNumber` + 1 (ras.h).
const ENTRY_NAME_CAP: usize = 257;
const PHONE_NUMBER_CAP: usize = 129;
/// The EAP type of EAP-MSCHAPv2 (`dwCustomAuthKey`) and the configuration Windows writes for it
/// (`Add-VpnConnection -AuthenticationMethod Eap`): `RasSetCustomAuthDataW` wraps these 8 bytes in its own header
/// (`1DBC`, the type, the length) and terminator, giving exactly the reference's `CustomAuthData`.
const EAP_MSCHAPV2: u32 = 26;
const EAP_MSCHAPV2_DATA: [u8; 8] = [1, 0, 0, 0, 0, 0, 0, 0];
/// `dwNetworkOutageTime` of Microsoft's IKEv2 entries (seconds IKEv2 mobility waits for the network to return).
const IKEV2_NETWORK_OUTAGE_SECS: u32 = 1800;
/// `dwRedialCount` / `dwRedialPause` of Microsoft's entries.
const REDIAL_COUNT: u32 = 3;
const REDIAL_PAUSE_SECS: u32 = 60;
/// MS-CHAP v2 with encrypted passwords (the PPP authentication of L2TP and SSTP).
const PPP_MSCHAPV2: u32 = RASEO_RequireMsCHAP2 | RASEO_RequireMsEncryptedPw | RASEO_RequireEncryptedPw;

/// A phonebook file: a private one ([`Phonebook::at`]) or the system's default phonebooks ([`Phonebook::system`],
/// for reading and listing only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phonebook {
    path: Option<(PathBuf, Vec<u16>)>,
}

impl Phonebook {
    /// The phonebook file at `path`: a plain absolute path (`X:\…`). The caller owns the folder (it must exist
    /// before the first write) and its ACL; the file inherits it.
    pub fn at(path: impl Into<PathBuf>) -> Result<Phonebook> {
        let path = path.into();
        plain_absolute(&path).map_err(|e| Error::invalid(e.to_string()))?;
        let w = wide_path(&path).map_err(|e| Error::invalid(e.to_string()))?;
        Ok(Phonebook { path: Some((path, w)) })
    }

    /// The default phonebooks (`lpszPhonebook = NULL`): the current user's and the all-users phonebook. Reading
    /// and listing only: every write, delete, credential and policy-key call refuses it.
    pub fn system() -> Phonebook {
        Phonebook { path: None }
    }

    /// The file's path (`None` for [`Phonebook::system`]).
    pub fn path(&self) -> Option<&Path> {
        self.path.as_ref().map(|(p, _)| p.as_path())
    }

    /// The `lpszPhonebook` argument: the NUL-terminated path, or NULL. Valid while `self` lives.
    pub(crate) fn as_pcwstr(&self) -> PCWSTR {
        self.path.as_ref().map_or(std::ptr::null(), |(_, w)| w.as_ptr())
    }

    /// The path of a private phonebook; the system phonebooks are refused.
    pub(crate) fn private_path(&self) -> Result<&Path> {
        self.path().ok_or_else(|| Error::invalid("the system phonebooks are read-only here"))
    }

    /// Writes `entry` (creating or replacing it whole), then its EAP data (EAP entries) and the policy keys
    /// (`NumCustomPolicy` always, `CustomIPSecPolicies` with a policy): a rewrite keeps whatever keys were there,
    /// so they are written every time. Private phonebooks only.
    pub fn write(&self, entry: &Entry) -> Result<()> {
        self.private_path()?;
        let name = entry_name(&entry.name)?;
        let e = entry.encode()?;
        let size = std::mem::size_of::<RASENTRYW>() as u32;
        // SAFETY: the phonebook path and `name` are NUL-terminated and alive across the call; `e` is a complete
        // RASENTRYW with `dwSize` = its size; no device-specific data (null, 0).
        let code = unsafe { RasSetEntryPropertiesW(self.as_pcwstr(), name.as_ptr(), &*e, size, std::ptr::null(), 0) };
        rc("RasSetEntryPropertiesW", code)?;
        if matches!(entry.auth, Auth::EapMsChapV2) {
            // SAFETY: as above; the data pointer and its length describe `EAP_MSCHAPV2_DATA`.
            let code = unsafe {
                RasSetCustomAuthDataW(
                    self.as_pcwstr(),
                    name.as_ptr(),
                    EAP_MSCHAPV2_DATA.as_ptr(),
                    EAP_MSCHAPV2_DATA.len() as u32,
                )
            };
            rc("RasSetCustomAuthDataW", code)?;
        } else {
            // An entry that was EAP before keeps its EAP type and data otherwise: RasSetEntryPropertiesW does not
            // reset `CustomAuthKey` when `dwCustomAuthKey` is 0 (seen on Windows 11 26H2).
            ini::set_key(self, &entry.name, "CustomAuthKey", Some("0"))?;
            ini::set_key(self, &entry.name, "CustomAuthData", None)?;
        }
        ini::set_custom_policy(self, &entry.name, entry.policy.as_ref())
    }

    /// Reads the entry `name` (`Error::Call` with 623 when there is none). The policy keys are read from a
    /// private phonebook's file (a value it cannot decode reads as no policy: [`ini::custom_policy`] reports it).
    pub fn read(&self, name: &str) -> Result<Entry> {
        let wname = entry_name(name)?;
        let mut size: u32 = 0;
        // SAFETY: the size query: no entry buffer (null), `size` receives the needed size; no device data.
        let code = unsafe {
            RasGetEntryPropertiesW(
                self.as_pcwstr(),
                wname.as_ptr(),
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if code != ERROR_BUFFER_TOO_SMALL {
            rc("RasGetEntryPropertiesW", code)?;
        }
        let struct_size = std::mem::size_of::<RASENTRYW>();
        let size = (size as usize).max(struct_size);
        // u64 storage: aligned for RASENTRYW (whose largest member alignment is 4); the alternate phone numbers
        // Windows may append after the structure fit in the rest.
        let mut buf = vec![0u64; size.div_ceil(8)];
        let mut size = (buf.len() * 8) as u32;
        let first = buf.as_mut_ptr().cast::<RASENTRYW>();
        // SAFETY: `buf` holds at least one zeroed RASENTRYW, suitably aligned; only `dwSize` is set.
        unsafe { (*first).dwSize = struct_size as u32 };
        // SAFETY: `buf` is `size` bytes, writable; the strings are NUL-terminated and alive across the call.
        let code = unsafe {
            RasGetEntryPropertiesW(
                self.as_pcwstr(),
                wname.as_ptr(),
                first,
                &mut size,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        rc("RasGetEntryPropertiesW", code)?;
        // SAFETY: the call filled the structure at the start of `buf` (aligned, initialised: zeroed before).
        let e: &RASENTRYW = unsafe { &*first };
        let policy = match self.path() {
            Some(_) => ini::custom_policy(self, name).ok().flatten(),
            None => None,
        };
        Ok(Entry::decode(name, e, policy))
    }

    /// Deletes the entry `name` (`RasDeleteEntryW`). Windows deletes the phonebook file with its last entry.
    /// Private phonebooks only. A PSK in the RAS credential store is the caller's to clear first ([`clear_psk`]).
    ///
    /// [`clear_psk`]: super::clear_psk
    pub fn delete(&self, name: &str) -> Result<()> {
        self.private_path()?;
        let wname = entry_name(name)?;
        // SAFETY: both strings NUL-terminated and alive across the call.
        rc("RasDeleteEntryW", unsafe { RasDeleteEntryW(self.as_pcwstr(), wname.as_ptr()) })
    }

    /// The entries of this phonebook (`RasEnumEntriesW`; the system phonebooks: the user's and the all-users
    /// one). A private phonebook whose file does not exist has none.
    pub fn entries(&self) -> Result<Vec<EntryName>> {
        let item = std::mem::size_of::<RASENTRYNAMEW>();
        let mut buf: Vec<RASENTRYNAMEW> = vec![RASENTRYNAMEW::default(); 16];
        loop {
            buf[0].dwSize = item as u32;
            let mut bytes = (buf.len() * item) as u32;
            let mut count: u32 = 0;
            // SAFETY: `buf` is `bytes` bytes of RASENTRYNAMEW with the first `dwSize` set; reserved = null.
            let code = unsafe {
                RasEnumEntriesW(std::ptr::null(), self.as_pcwstr(), buf.as_mut_ptr(), &mut bytes, &mut count)
            };
            if code == ERROR_BUFFER_TOO_SMALL {
                let needed = (bytes as usize).div_ceil(item);
                if needed <= buf.len() || needed > MAX_ENTRIES {
                    return Err(Error::Call { call: "RasEnumEntriesW", code });
                }
                buf = vec![RASENTRYNAMEW::default(); needed];
                continue;
            }
            if code == ERROR_CANNOT_OPEN_PHONEBOOK && self.path().is_some_and(|p| !p.exists()) {
                return Ok(Vec::new());
            }
            rc("RasEnumEntriesW", code)?;
            let count = (count as usize).min(buf.len());
            return Ok(buf[..count]
                .iter()
                .map(|n| EntryName {
                    name: field_text(&n.szEntryName),
                    phonebook: PathBuf::from(field_text(&n.szPhonebookPath)),
                    all_users: n.dwFlags & REN_ALL_USERS != 0,
                })
                .collect());
        }
    }

    /// The entry names of this phonebook ([`Phonebook::entries`]).
    pub fn names(&self) -> Result<Vec<String>> {
        Ok(self.entries()?.into_iter().map(|e| e.name).collect())
    }
}

/// The entries of the system's default phonebooks, each with its phonebook's path.
pub fn system_entries() -> Result<Vec<EntryName>> {
    Phonebook::system().entries()
}

/// Whether Windows accepts `name` as an entry name of `book` (`RasValidateEntryNameW`): `Ok` for a new name and
/// for an existing entry's name (`ERROR_ALREADY_EXISTS`); an empty name or one with `]`, a line break or NUL is
/// refused before the call.
pub fn validate_name(book: &Phonebook, name: &str) -> Result<()> {
    let wname = entry_name(name)?;
    // SAFETY: both strings NUL-terminated (or a null phonebook) and alive across the call.
    let code = unsafe { RasValidateEntryNameW(book.as_pcwstr(), wname.as_ptr()) };
    if code == super::ERROR_ALREADY_EXISTS { Ok(()) } else { rc("RasValidateEntryNameW", code) }
}

/// One entry of a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryName {
    pub name: String,
    /// The phonebook file it is in.
    pub phonebook: PathBuf,
    /// In the all-users phonebook (`REN_AllUsers`).
    pub all_users: bool,
}

/// The VPN protocol (`dwVpnStrategy`): one protocol only, never "automatic".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Strategy {
    /// `VS_L2tpOnly`
    #[default]
    L2tp,
    /// `VS_SstpOnly`
    Sstp,
    /// `VS_Ikev2Only`
    Ikev2,
    /// Read only: any other `dwVpnStrategy` (an entry someone else wrote: automatic, PPTP, …).
    Other(u32),
}

/// How the client authenticates. L2TP and SSTP take [`Auth::MsChapV2`] (SSTP without a PSK), IKEv2 [`Auth::EapMsChapV2`]
/// or [`Auth::MachineCertificate`]. (An IKEv2 pre-shared key has no entry form Windows dials with: the RAS spike.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Auth {
    /// PPP MS-CHAP v2; `psk`: L2TP's IPsec pre-shared key from the RAS credential store (`RASEO2_UsePreSharedKey`).
    MsChapV2 { psk: bool },
    /// IKEv2 EAP-MSCHAPv2 (`RASEO_RequireEAP`, EAP type 26): the user name and password at dial time.
    EapMsChapV2,
    /// IKEv2 with a certificate from the computer's Personal store (`RASEO2_RequireMachineCertificates`).
    MachineCertificate,
}

impl Default for Auth {
    fn default() -> Auth {
        Auth::MsChapV2 { psk: false }
    }
}

/// A VPN phonebook entry: what [`Phonebook::write`] encodes, and what [`Phonebook::read`] decodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub strategy: Strategy,
    /// `szLocalPhoneNumber`: a host name or address (SSTP: `host:port` for another port than 443).
    pub server: String,
    pub auth: Auth,
    /// The IPv4 default route over the VPN (`RASEO_RemoteDefaultGateway`).
    pub default_gateway_v4: bool,
    /// The IPv6 default route over the VPN (`RASEO2_IPv6RemoteDefaultGateway`).
    pub default_gateway_v6: bool,
    /// IKEv2: the negotiated traffic selectors become routes (`RASEO2_PlumbIKEv2TSAsRoutes`).
    pub ts_as_routes: bool,
    /// IKEv2 fragmentation (`fDisableIKEv2Fragmentation` when `false`); always `true` for L2TP and SSTP.
    pub ike_fragmentation: bool,
    /// The explicit IPv4 and IPv6 interface metric (`RASEO2_IPv4ExplicitMetric` / `IPv6ExplicitMetric`).
    pub interface_metric: Option<u32>,
    /// IKEv2: the custom IPsec policy (the phonebook keys `NumCustomPolicy` / `CustomIPSecPolicies`).
    pub policy: Option<IpsecPolicy>,
    /// Read only (ignored by `write`): the entry's `guidId`, in RFC 4122 byte order.
    pub guid: Option<[u8; 16]>,
}

impl Default for Entry {
    fn default() -> Entry {
        Entry {
            name: String::new(),
            strategy: Strategy::default(),
            server: String::new(),
            auth: Auth::default(),
            default_gateway_v4: false,
            default_gateway_v6: false,
            ts_as_routes: false,
            ike_fragmentation: true,
            interface_metric: None,
            policy: None,
            guid: None,
        }
    }
}

impl Entry {
    /// The `RASENTRYW` of this entry (Microsoft's reference entries without the dialler-UI bits; never
    /// `RASEO2_CacheCredentials`).
    fn encode(&self) -> Result<Box<RASENTRYW>> {
        let mut e = Box::<RASENTRYW>::default();
        e.dwSize = std::mem::size_of::<RASENTRYW>() as u32;
        e.dwType = RASET_Vpn;
        e.dwFramingProtocol = RASFP_Ppp;
        e.dwfNetProtocols = RASNP_Ip | RASNP_Ipv6;
        // An empty device name: Windows picks the WAN Miniport of the strategy itself.
        // SAFETY: the field is 17 units; "vpn" fits.
        unsafe { fill(e.szDeviceType.as_mut_ptr(), e.szDeviceType.len(), "vpn", "the device type")? };
        if self.server.is_empty() {
            return Err(Error::invalid("the server is empty"));
        }
        // It becomes the phonebook's `PhoneNumber=` line: no control character (C0, DEL, C1, U+2028/U+2029; CR/LF
        // would add keys to the section), whatever the caller checked (security review L-8).
        if self
            .server
            .chars()
            .any(|c| c < ' ' || ('\u{7f}'..='\u{9f}').contains(&c) || matches!(c, '\u{2028}' | '\u{2029}'))
        {
            return Err(Error::invalid("the server has a control character"));
        }
        // SAFETY: `fill` writes at most the field's length.
        unsafe { fill(e.szLocalPhoneNumber.as_mut_ptr(), PHONE_NUMBER_CAP, &self.server, "the server")? };
        e.dwDialMode = 0;
        e.dwRedialCount = REDIAL_COUNT;
        e.dwRedialPause = REDIAL_PAUSE_SECS;
        let mut options = 0u32;
        let mut options2 = RASEO2_DontNegotiateMultilink | RASEO2_ReconnectIfDropped;
        if self.default_gateway_v4 {
            options |= RASEO_RemoteDefaultGateway;
        }
        if self.default_gateway_v6 {
            options2 |= RASEO2_IPv6RemoteDefaultGateway;
        }
        let ikev2 = self.strategy == Strategy::Ikev2;
        if !ikev2 && (self.ts_as_routes || !self.ike_fragmentation || self.policy.is_some()) {
            return Err(Error::invalid(
                "traffic-selector routes, IKE fragmentation and an IPsec policy are IKEv2 only",
            ));
        }
        match (self.strategy, self.auth) {
            (Strategy::L2tp, Auth::MsChapV2 { psk }) => {
                e.dwVpnStrategy = VS_L2tpOnly;
                options |= PPP_MSCHAPV2 | RASEO_RequireDataEncryption;
                e.dwEncryptionType = ET_Require;
                if psk {
                    options2 |= RASEO2_UsePreSharedKey;
                }
            }
            (Strategy::Sstp, Auth::MsChapV2 { psk: false }) => {
                // TLS protects SSTP: Microsoft's entries leave the PPP data encryption optional.
                e.dwVpnStrategy = VS_SstpOnly;
                options |= PPP_MSCHAPV2;
                e.dwEncryptionType = ET_Optional;
            }
            (Strategy::Ikev2, Auth::EapMsChapV2) => {
                // Never RASEO_RequireMsCHAP2 / RequireMsEncryptedPw on IKEv2: ERROR_INVALID_PARAMETER.
                e.dwVpnStrategy = VS_Ikev2Only;
                options |= RASEO_RequireEAP;
                e.dwCustomAuthKey = EAP_MSCHAPV2;
                e.dwEncryptionType = ET_Optional;
                e.dwNetworkOutageTime = IKEV2_NETWORK_OUTAGE_SECS;
            }
            (Strategy::Ikev2, Auth::MachineCertificate) => {
                e.dwVpnStrategy = VS_Ikev2Only;
                options2 |= RASEO2_RequireMachineCertificates;
                e.dwEncryptionType = ET_Optional;
                e.dwNetworkOutageTime = IKEV2_NETWORK_OUTAGE_SECS;
            }
            (strategy, auth) => {
                return Err(Error::invalid(format!("{auth:?} is not an authentication of {strategy:?}")));
            }
        }
        if self.ts_as_routes {
            options2 |= RASEO2_PlumbIKEv2TSAsRoutes;
        }
        if ikev2 && !self.ike_fragmentation {
            e.fDisableIKEv2Fragmentation = 1;
        }
        if let Some(metric) = self.interface_metric {
            options2 |= RASEO2_IPv4ExplicitMetric | RASEO2_IPv6ExplicitMetric;
            e.dwIPv4InterfaceMetric = metric;
            e.dwIPv6InterfaceMetric = metric;
        }
        e.dwfOptions = options;
        e.dwfOptions2 = options2;
        Ok(e)
    }

    fn decode(name: &str, e: &RASENTRYW, policy: Option<IpsecPolicy>) -> Entry {
        let strategy = match e.dwVpnStrategy {
            s if s == VS_L2tpOnly => Strategy::L2tp,
            s if s == VS_SstpOnly => Strategy::Sstp,
            s if s == VS_Ikev2Only => Strategy::Ikev2,
            other => Strategy::Other(other),
        };
        let auth = if e.dwfOptions & RASEO_RequireEAP != 0 {
            Auth::EapMsChapV2
        } else if e.dwfOptions2 & RASEO2_RequireMachineCertificates != 0 {
            Auth::MachineCertificate
        } else {
            Auth::MsChapV2 { psk: e.dwfOptions2 & RASEO2_UsePreSharedKey != 0 }
        };
        let explicit = RASEO2_IPv4ExplicitMetric | RASEO2_IPv6ExplicitMetric;
        Entry {
            name: name.to_string(),
            strategy,
            server: field_text(&e.szLocalPhoneNumber),
            auth,
            default_gateway_v4: e.dwfOptions & RASEO_RemoteDefaultGateway != 0,
            default_gateway_v6: e.dwfOptions2 & RASEO2_IPv6RemoteDefaultGateway != 0,
            ts_as_routes: e.dwfOptions2 & RASEO2_PlumbIKEv2TSAsRoutes != 0,
            ike_fragmentation: e.fDisableIKEv2Fragmentation == 0,
            interface_metric: (e.dwfOptions2 & explicit != 0).then_some(e.dwIPv4InterfaceMetric),
            policy,
            guid: Some(guid_bytes(&e.guidId)).filter(|g| *g != [0; 16]),
        }
    }
}

/// An entry name as `lpszEntry`: not empty, at most `RAS_MaxEntryName` units, and no `]`, line break or NUL (the
/// name is also an INI section name: [`ini`]).
pub(crate) fn entry_name(name: &str) -> Result<Vec<u16>> {
    if name.is_empty() {
        return Err(Error::invalid("an entry name is empty"));
    }
    if name.contains([']', '\r', '\n']) {
        return Err(Error::invalid("an entry name contains ']' or a line break"));
    }
    let w = wide(OsStr::new(name)).map_err(|e| Error::invalid(e.to_string()))?;
    if w.len() > ENTRY_NAME_CAP {
        return Err(Error::invalid("an entry name is longer than 256 UTF-16 units"));
    }
    Ok(w)
}
