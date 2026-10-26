//! The IKEv2 custom IPsec policy of a phonebook entry: the keys `NumCustomPolicy` and `CustomIPSecPolicies` that
//! Windows itself writes for `Set-VpnConnectionIPsecConfiguration` (`RASENTRYW` has no field for them), read and
//! written with `GetPrivateProfileStringW` / `WritePrivateProfileStringW` in the entry's section of a private
//! phonebook.
//!
//! `CustomIPSecPolicies` is 24 bytes in hexadecimal: six little-endian DWORDs in the order integrity, encryption,
//! DH group, cipher transform, auth transform, PFS group, numbered as the VpnClient module's enums (the RAS spike's
//! three reference policies, `tests/fixtures/ras/ikev2_policy*.pbk`).

use super::entry::entry_name;
use super::{Error, Phonebook, Result};
use crate::util::wide;
use std::ffi::OsStr;
use windows_sys::Win32::NetworkManagement::Rras::RasValidateEntryNameW;
use windows_sys::Win32::System::WindowsProgramming::{GetPrivateProfileStringW, WritePrivateProfileStringW};

const NUM_KEY: &str = "NumCustomPolicy";
const POLICY_KEY: &str = "CustomIPSecPolicies";

macro_rules! dword_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $variant:ident = $value:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vdoc])* $variant),+
        }

        impl $name {
            /// The DWORD Windows stores.
            pub fn dword(self) -> u32 {
                match self {
                    $($name::$variant => $value),+
                }
            }

            /// The value of a stored DWORD (`None`: not a value of this field).
            pub fn from_dword(value: u32) -> Option<$name> {
                match value {
                    $($value => Some($name::$variant),)+
                    _ => None,
                }
            }
        }
    };
}

dword_enum!(
    /// IKE integrity, also the PRF (`IntegrityCheckMethod`).
    Integrity { Md5 = 0, Sha1 = 1, Sha256 = 2, Sha384 = 3 }
);
dword_enum!(
    /// IKE encryption (`EncryptionMethod`; there is no GCM-AES-192).
    Encryption { Des = 0, Des3 = 1, Aes128 = 2, Aes192 = 3, Aes256 = 4, GcmAes128 = 5, GcmAes256 = 6 }
);
dword_enum!(
    /// The IKE Diffie-Hellman group (`DHGroup`).
    DhGroup {
        None = 0,
        /// MODP 768
        Group1 = 1,
        /// MODP 1024
        Group2 = 2,
        /// MODP 2048
        Group14 = 3,
        /// ECP 256 (IANA 19)
        Ecp256 = 4,
        /// ECP 384 (IANA 20)
        Ecp384 = 5,
        /// MODP 2048 with a 256-bit subgroup
        Group24 = 6,
    }
);
dword_enum!(
    /// ESP encryption (`CipherTransformConstants`).
    CipherTransform {
        Des = 1,
        Des3 = 2,
        Aes128 = 3,
        Aes192 = 4,
        Aes256 = 5,
        GcmAes128 = 6,
        GcmAes192 = 7,
        GcmAes256 = 8,
    }
);
dword_enum!(
    /// ESP integrity (`AuthenticationTransformConstants`); a GCM cipher takes the GCM value of its size.
    AuthTransform { Md596 = 0, Sha196 = 1, Sha256128 = 2, GcmAes128 = 3, GcmAes192 = 4, GcmAes256 = 5 }
);
dword_enum!(
    /// PFS for the child SA (`PfsGroup`).
    PfsGroup {
        None = 0,
        Pfs1 = 1,
        /// MODP 1024
        Pfs2 = 2,
        /// MODP 2048 (group 14)
        Pfs2048 = 3,
        Ecp256 = 4,
        Ecp384 = 5,
        /// The IKE DH group
        PfsMm = 6,
        /// group 24
        Pfs24 = 7,
    }
);

/// One IKEv2 custom IPsec policy (Windows takes exactly one IKE and one ESP combination).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpsecPolicy {
    pub integrity: Integrity,
    pub encryption: Encryption,
    pub dh_group: DhGroup,
    pub cipher_transform: CipherTransform,
    pub auth_transform: AuthTransform,
    pub pfs_group: PfsGroup,
}

impl IpsecPolicy {
    /// The six DWORDs in the stored order.
    pub fn dwords(&self) -> [u32; 6] {
        [
            self.integrity.dword(),
            self.encryption.dword(),
            self.dh_group.dword(),
            self.cipher_transform.dword(),
            self.auth_transform.dword(),
            self.pfs_group.dword(),
        ]
    }

    pub fn from_dwords(d: [u32; 6]) -> Option<IpsecPolicy> {
        Some(IpsecPolicy {
            integrity: Integrity::from_dword(d[0])?,
            encryption: Encryption::from_dword(d[1])?,
            dh_group: DhGroup::from_dword(d[2])?,
            cipher_transform: CipherTransform::from_dword(d[3])?,
            auth_transform: AuthTransform::from_dword(d[4])?,
            pfs_group: PfsGroup::from_dword(d[5])?,
        })
    }

    /// The `CustomIPSecPolicies` value: 48 upper-case hex digits.
    pub fn to_hex(&self) -> String {
        self.dwords().iter().flat_map(|d| d.to_le_bytes()).map(|b| format!("{b:02X}")).collect()
    }

    /// Decodes a `CustomIPSecPolicies` value (either letter case).
    pub fn from_hex(hex: &str) -> Option<IpsecPolicy> {
        let hex = hex.trim();
        if hex.len() != 48 || !hex.is_ascii() {
            return None;
        }
        let mut bytes = [0u8; 24];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
        }
        let mut d = [0u32; 6];
        for (i, v) in d.iter_mut().enumerate() {
            *v = u32::from_le_bytes([bytes[4 * i], bytes[4 * i + 1], bytes[4 * i + 2], bytes[4 * i + 3]]);
        }
        IpsecPolicy::from_dwords(d)
    }
}

/// The custom policy of entry `name` (`None`: `NumCustomPolicy` absent or 0). A value it cannot decode is an
/// `Error::Invalid`. Private phonebooks only.
pub fn custom_policy(book: &Phonebook, name: &str) -> Result<Option<IpsecPolicy>> {
    let file = file_of(book)?;
    let section = entry_name(name)?;
    match get(&file, &section, NUM_KEY)?.trim() {
        "" | "0" => Ok(None),
        "1" => {
            let hex = get(&file, &section, POLICY_KEY)?;
            IpsecPolicy::from_hex(&hex)
                .map(Some)
                .ok_or_else(|| Error::invalid(format!("{POLICY_KEY} cannot be decoded: {hex:?}")))
        }
        other => Err(Error::invalid(format!("{NUM_KEY} = {other:?} (WinVPN writes at most one policy)"))),
    }
}

/// Writes the policy keys of the existing entry `name`: `NumCustomPolicy=1` and `CustomIPSecPolicies`, or
/// `NumCustomPolicy=0` and no `CustomIPSecPolicies`; then reads them back. Call it after every
/// `RasSetEntryPropertiesW` ([`Phonebook::write`] does): a rewrite keeps whatever keys were there. Private
/// phonebooks only; refused for an entry that does not exist (the write would create a stray section).
pub fn set_custom_policy(book: &Phonebook, name: &str, policy: Option<&IpsecPolicy>) -> Result<()> {
    let file = file_of(book)?;
    let section = existing_section(book, name)?;
    match policy {
        Some(p) => {
            put(&file, &section, NUM_KEY, Some("1"))?;
            put(&file, &section, POLICY_KEY, Some(&p.to_hex()))?;
        }
        None => {
            put(&file, &section, NUM_KEY, Some("0"))?;
            put(&file, &section, POLICY_KEY, None)?;
        }
    }
    let back = custom_policy(book, name)?;
    if back.as_ref() != policy {
        return Err(Error::invalid(format!("the policy keys read back as {back:?}")));
    }
    if policy.is_none() && !get(&file, &section, POLICY_KEY)?.is_empty() {
        return Err(Error::invalid(format!("{POLICY_KEY} is still there")));
    }
    Ok(())
}

/// Writes `key = value` in the existing entry `name`'s section, or removes the key (`None`; nothing when absent).
pub(crate) fn set_key(book: &Phonebook, name: &str, key: &str, value: Option<&str>) -> Result<()> {
    let file = file_of(book)?;
    let section = existing_section(book, name)?;
    put(&file, &section, key, value)
}

fn file_of(book: &Phonebook) -> Result<Vec<u16>> {
    wide(book.private_path()?.as_os_str()).map_err(|e| Error::invalid(e.to_string()))
}

/// The section name of an entry that exists (`RasValidateEntryNameW` answers `ERROR_ALREADY_EXISTS`).
fn existing_section(book: &Phonebook, name: &str) -> Result<Vec<u16>> {
    let section = entry_name(name)?;
    // SAFETY: both strings NUL-terminated and alive across the call.
    let code = unsafe { RasValidateEntryNameW(book.as_pcwstr(), section.as_ptr()) };
    if code != super::ERROR_ALREADY_EXISTS {
        return Err(Error::Call { call: "RasValidateEntryNameW", code: super::ERROR_CANNOT_FIND_PHONEBOOK_ENTRY });
    }
    Ok(section)
}

fn get(file: &[u16], section: &[u16], key: &str) -> Result<String> {
    let key = wide(OsStr::new(key)).map_err(|e| Error::invalid(e.to_string()))?;
    let empty = [0u16];
    let mut buf = [0u16; 256];
    // SAFETY: every string is NUL-terminated and alive across the call; `buf` is writable for its length, which is
    // passed; the result is NUL-terminated within it.
    let n = unsafe {
        GetPrivateProfileStringW(
            section.as_ptr(),
            key.as_ptr(),
            empty.as_ptr(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            file.as_ptr(),
        )
    } as usize;
    Ok(String::from_utf16_lossy(&buf[..n.min(buf.len())]))
}

/// Writes `key = value`, or removes the key (`None`).
fn put(file: &[u16], section: &[u16], key: &str, value: Option<&str>) -> Result<()> {
    let key = wide(OsStr::new(key)).map_err(|e| Error::invalid(e.to_string()))?;
    let value = value.map(|v| wide(OsStr::new(v))).transpose().map_err(|e| Error::invalid(e.to_string()))?;
    // SAFETY: every string is NUL-terminated and alive across the call; a null value removes the key.
    let ok = unsafe {
        WritePrivateProfileStringW(
            section.as_ptr(),
            key.as_ptr(),
            value.as_ref().map_or(std::ptr::null(), |v| v.as_ptr()),
            file.as_ptr(),
        )
    };
    if ok == 0 {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        return Err(Error::Call { call: "WritePrivateProfileStringW", code });
    }
    Ok(())
}
