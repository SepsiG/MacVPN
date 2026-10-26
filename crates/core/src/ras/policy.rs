//! The IKEv2 IPsec policy: strongSwan proposals translated to the one IKE + ESP combination Windows offers.
//!
//! Windows' custom IPsec policy (`Set-VpnConnectionIPsecConfiguration`, `ROUTER_CUSTOM_IKEv2_POLICY0`) is a single
//! choice per field; a strongSwan proposal (`aes256-sha256-modp2048`) accepts any combination of its algorithms,
//! and a list of proposals (`,`-separated) is tried in order. So the first proposal that has a Windows algorithm
//! of every needed type wins, with the first Windows algorithm of each type in it. Weak algorithms (MD5,
//! DH group 1) are never chosen.
//!
//! The types name algorithms, not numbers: the DWORD values of `CustomIPSecPolicies` (and their order) are pinned
//! by the RAS spike's reference entries (Task 2, Step 2.6) and encoded in `winsys::ras` (Task 5).

use crate::l10n::{self, Arg};
use crate::swift_str::ascii_lowercased;

/// IKE encryption (`EncryptionMethod`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IkeCipher {
    Aes128,
    Aes192,
    Aes256,
    TripleDes,
    Aes128Gcm16,
    Aes256Gcm16,
}

/// IKE integrity, also Windows' PRF (`IntegrityCheckMethod`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IkeIntegrity {
    Sha1,
    Sha256,
    Sha384,
}

/// A Diffie-Hellman group: the IKE DH group (`DHGroup`) and the ESP PFS group (`PfsGroup`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DhGroup {
    /// MODP 1024 (group 2)
    Group2,
    /// MODP 2048 (group 14)
    Group14,
    /// MODP 2048 with a 256-bit subgroup (group 24)
    Group24,
    /// ECP 256 (group 19)
    Ecp256,
    /// ECP 384 (group 20)
    Ecp384,
}

/// ESP encryption (`CipherTransformConstants`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EspCipher {
    Aes128,
    Aes192,
    Aes256,
    TripleDes,
    Aes128Gcm16,
    Aes192Gcm16,
    Aes256Gcm16,
}

/// ESP integrity (`AuthenticationTransformConstants`). GCM ciphers carry their own tag: the matching `Gcm*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EspIntegrity {
    /// HMAC-SHA1-96
    Sha196,
    /// HMAC-SHA-256-128
    Sha256128,
    Gcm128,
    Gcm192,
    Gcm256,
}

/// The custom IPsec policy of an IKEv2 entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WindowsPolicy {
    pub ike_cipher: IkeCipher,
    pub ike_integrity: IkeIntegrity,
    pub dh_group: DhGroup,
    pub esp_cipher: EspCipher,
    pub esp_integrity: EspIntegrity,
    /// PFS for the CHILD SA (the ESP proposal's DH group), `None`: no PFS.
    pub pfs: Option<DhGroup>,
}

/// The policy for a strongSwan config without `proposals` / `esp_proposals`: AES-256-CBC / SHA-256 / DH group 14
/// for IKE, AES-256-CBC / SHA-256-128 / no PFS for ESP (strongSwan's defaults no longer accept Windows' built-in
/// DH group 2 offer; these are Microsoft's recommendation for Windows clients).
pub const WINDOWS_DEFAULT_FOR_STRONGSWAN: WindowsPolicy = WindowsPolicy {
    ike_cipher: IkeCipher::Aes256,
    ike_integrity: IkeIntegrity::Sha256,
    dh_group: DhGroup::Group14,
    esp_cipher: EspCipher::Aes256,
    esp_integrity: EspIntegrity::Sha256128,
    pfs: None,
};

/// The IKE half of a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IkeChoice {
    pub cipher: IkeCipher,
    pub integrity: IkeIntegrity,
    pub dh_group: DhGroup,
}

/// The ESP half of a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EspChoice {
    pub cipher: EspCipher,
    pub integrity: EspIntegrity,
    pub pfs: Option<DhGroup>,
}

impl WindowsPolicy {
    pub fn from_choices(ike: IkeChoice, esp: EspChoice) -> WindowsPolicy {
        WindowsPolicy {
            ike_cipher: ike.cipher,
            ike_integrity: ike.integrity,
            dh_group: ike.dh_group,
            esp_cipher: esp.cipher,
            esp_integrity: esp.integrity,
            pfs: esp.pfs,
        }
    }

    pub fn ike(&self) -> IkeChoice {
        IkeChoice { cipher: self.ike_cipher, integrity: self.ike_integrity, dh_group: self.dh_group }
    }

    pub fn esp(&self) -> EspChoice {
        EspChoice { cipher: self.esp_cipher, integrity: self.esp_integrity, pfs: self.pfs }
    }

    /// For the log and the editor: "AES-256, SHA-256, DH group 14; ESP AES-256, SHA-256" (GCM: "ESP AES-256-GCM";
    /// with PFS: ", PFS group 14").
    pub fn describe(&self) -> String {
        let dh = l10n::tr("DH group %@", &[Arg::Str(self.dh_group.number())]);
        let mut esp = vec![self.esp_cipher.label().to_string()];
        if let Some(integrity) = self.esp_integrity.label() {
            esp.push(integrity.to_string());
        }
        if let Some(pfs) = self.pfs {
            esp.push(l10n::tr("PFS group %@", &[Arg::Str(pfs.number())]));
        }
        format!("{}, {}, {dh}; ESP {}", self.ike_cipher.label(), self.ike_integrity.label(), esp.join(", "))
    }
}

impl IkeCipher {
    pub fn label(self) -> &'static str {
        match self {
            IkeCipher::Aes128 => "AES-128",
            IkeCipher::Aes192 => "AES-192",
            IkeCipher::Aes256 => "AES-256",
            IkeCipher::TripleDes => "3DES",
            IkeCipher::Aes128Gcm16 => "AES-128-GCM",
            IkeCipher::Aes256Gcm16 => "AES-256-GCM",
        }
    }

    fn is_aead(self) -> bool {
        matches!(self, IkeCipher::Aes128Gcm16 | IkeCipher::Aes256Gcm16)
    }
}

impl IkeIntegrity {
    pub fn label(self) -> &'static str {
        match self {
            IkeIntegrity::Sha1 => "SHA-1",
            IkeIntegrity::Sha256 => "SHA-256",
            IkeIntegrity::Sha384 => "SHA-384",
        }
    }
}

impl DhGroup {
    /// The IANA group number.
    pub fn number(self) -> &'static str {
        match self {
            DhGroup::Group2 => "2",
            DhGroup::Group14 => "14",
            DhGroup::Group24 => "24",
            DhGroup::Ecp256 => "19",
            DhGroup::Ecp384 => "20",
        }
    }
}

impl EspCipher {
    pub fn label(self) -> &'static str {
        match self {
            EspCipher::Aes128 => "AES-128",
            EspCipher::Aes192 => "AES-192",
            EspCipher::Aes256 => "AES-256",
            EspCipher::TripleDes => "3DES",
            EspCipher::Aes128Gcm16 => "AES-128-GCM",
            EspCipher::Aes192Gcm16 => "AES-192-GCM",
            EspCipher::Aes256Gcm16 => "AES-256-GCM",
        }
    }

    /// The integrity a GCM cipher brings along.
    fn gcm_integrity(self) -> Option<EspIntegrity> {
        match self {
            EspCipher::Aes128Gcm16 => Some(EspIntegrity::Gcm128),
            EspCipher::Aes192Gcm16 => Some(EspIntegrity::Gcm192),
            EspCipher::Aes256Gcm16 => Some(EspIntegrity::Gcm256),
            EspCipher::Aes128 | EspCipher::Aes192 | EspCipher::Aes256 | EspCipher::TripleDes => None,
        }
    }
}

impl EspIntegrity {
    /// `None` for GCM (the cipher's label says it).
    pub fn label(self) -> Option<&'static str> {
        match self {
            EspIntegrity::Sha196 => Some("SHA-1"),
            EspIntegrity::Sha256128 => Some("SHA-256"),
            EspIntegrity::Gcm128 | EspIntegrity::Gcm192 | EspIntegrity::Gcm256 => None,
        }
    }
}

// strongSwan algorithm keywords (`strongswan.org` → IKEv2 Cipher Suites), Windows-capable ones only.

fn ike_cipher(token: &str) -> Option<IkeCipher> {
    Some(match token {
        "aes128" => IkeCipher::Aes128,
        "aes192" => IkeCipher::Aes192,
        "aes256" => IkeCipher::Aes256,
        "3des" => IkeCipher::TripleDes,
        "aes128gcm16" | "aes128gcm" => IkeCipher::Aes128Gcm16,
        "aes256gcm16" | "aes256gcm" => IkeCipher::Aes256Gcm16,
        _ => return None,
    })
}

/// An integrity keyword (`sha256`) or, with `prf`, a PRF keyword (`prfsha256`), as the Windows hash.
fn hash(token: &str, prf: bool) -> Option<IkeIntegrity> {
    let name = if prf { token.strip_prefix("prf")? } else { token };
    Some(match name {
        "sha1" | "sha" => IkeIntegrity::Sha1,
        "sha256" | "sha2_256" => IkeIntegrity::Sha256,
        "sha384" | "sha2_384" => IkeIntegrity::Sha384,
        _ => return None,
    })
}

fn dh_group(token: &str) -> Option<DhGroup> {
    Some(match token {
        "modp1024" => DhGroup::Group2,
        "modp2048" => DhGroup::Group14,
        "modp2048s256" => DhGroup::Group24,
        "ecp256" => DhGroup::Ecp256,
        "ecp384" => DhGroup::Ecp384,
        _ => return None,
    })
}

fn esp_cipher(token: &str) -> Option<EspCipher> {
    Some(match token {
        "aes128" => EspCipher::Aes128,
        "aes192" => EspCipher::Aes192,
        "aes256" => EspCipher::Aes256,
        "3des" => EspCipher::TripleDes,
        "aes128gcm16" | "aes128gcm" => EspCipher::Aes128Gcm16,
        "aes192gcm16" | "aes192gcm" => EspCipher::Aes192Gcm16,
        "aes256gcm16" | "aes256gcm" => EspCipher::Aes256Gcm16,
        _ => return None,
    })
}

fn esp_integrity(token: &str) -> Option<EspIntegrity> {
    Some(match token {
        "sha1" | "sha" => EspIntegrity::Sha196,
        "sha256" | "sha2_256" => EspIntegrity::Sha256128,
        _ => return None,
    })
}

/// The proposals of a `proposals` / `esp_proposals` value (its items joined): `,`-separated, trimmed, lower case.
pub fn split_proposals(value: &str) -> Vec<String> {
    value.split(',').map(|p| ascii_lowercased(p.trim())).filter(|p| !p.is_empty()).collect()
}

/// The IKE choice for a list of proposals: the first Windows-capable one; `default` is
/// [`WINDOWS_DEFAULT_FOR_STRONGSWAN`]. `None`: Windows supports none of them.
pub fn ike_from_proposals(proposals: &[String]) -> Option<IkeChoice> {
    proposals.iter().find_map(|p| ike_from_proposal(p))
}

fn ike_from_proposal(proposal: &str) -> Option<IkeChoice> {
    if proposal == "default" {
        return Some(WINDOWS_DEFAULT_FOR_STRONGSWAN.ike());
    }
    let tokens: Vec<&str> = proposal.split('-').collect();
    let cipher = tokens.iter().find_map(|t| ike_cipher(t))?;
    let prfs: Vec<IkeIntegrity> = tokens.iter().filter_map(|t| hash(t, true)).collect();
    let has_prf = tokens.iter().any(|t| t.starts_with("prf"));
    let integrity = if cipher.is_aead() {
        // An AEAD proposal has no integrity: Windows' integrity (its PRF) comes from the PRF list.
        prfs.first().copied()?
    } else {
        // Windows uses the integrity hash as the PRF: with a PRF list it must be in it.
        tokens.iter().filter_map(|t| hash(t, false)).find(|h| !has_prf || prfs.contains(h))?
    };
    let dh_group = tokens.iter().find_map(|t| dh_group(t))?;
    Some(IkeChoice { cipher, integrity, dh_group })
}

/// The ESP choice for a list of proposals, like [`ike_from_proposals`]. A DH group in the proposal is the PFS
/// group. A proposal that requires extended sequence numbers (`esn` without `noesn`) is skipped.
pub fn esp_from_proposals(proposals: &[String]) -> Option<EspChoice> {
    proposals.iter().find_map(|p| esp_from_proposal(p))
}

fn esp_from_proposal(proposal: &str) -> Option<EspChoice> {
    if proposal == "default" {
        return Some(WINDOWS_DEFAULT_FOR_STRONGSWAN.esp());
    }
    let tokens: Vec<&str> = proposal.split('-').collect();
    if tokens.contains(&"esn") && !tokens.contains(&"noesn") {
        return None;
    }
    let cipher = tokens.iter().find_map(|t| esp_cipher(t))?;
    let integrity = match cipher.gcm_integrity() {
        Some(gcm) => gcm,
        None => tokens.iter().find_map(|t| esp_integrity(t))?,
    };
    let pfs = tokens.iter().find_map(|t| dh_group(t));
    Some(EspChoice { cipher, integrity, pfs })
}

/// What Windows offers for IKE, in strongSwan's keywords (for the "none of these proposals" reason).
pub const IKE_OFFER: &str = "aes128/aes192/aes256/3des - sha1/sha256/sha384 - modp1024/modp2048/modp2048s256/ecp256/ecp384, aes128gcm16/aes256gcm16 - prfsha1/prfsha256/prfsha384 - modp1024/modp2048/modp2048s256/ecp256/ecp384";
/// What Windows offers for ESP, in strongSwan's keywords (the DH group, for PFS, is optional).
pub const ESP_OFFER: &str = "aes128/aes192/aes256/3des - sha1/sha256 [- modp1024/modp2048/modp2048s256/ecp256/ecp384], aes128gcm16/aes192gcm16/aes256gcm16 [- modp1024/modp2048/modp2048s256/ecp256/ecp384]";
