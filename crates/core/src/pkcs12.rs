//! A PKCS#12 (`.p12`, OpenVPN `<pkcs12>`) read without decrypting anything (client-credential audit G3 and G6):
//! the certificates stored unencrypted, how many parts are encrypted, and whether the file opens without a
//! password. OpenVPN tries an empty password before it asks (`askpass`), so the connect prompt asks for the
//! "Private key password" only when the file's MAC does not verify with an empty one.
//!
//! The file is untrusted input (an imported config or a team catalog carries it): the DER reader of [`crate::x509`]
//! is strict and bounded (BER, which some Windows and Java tools write, is not read: the file then counts as
//! unreadable), the number of bags is capped, and the MAC's iteration count is capped
//! ([`MAX_MAC_ITERATIONS`]) so a crafted file cannot make the check spin. The MAC check is no security decision
//! (OpenVPN checks the file itself); it only decides whether to ask for a password.

use crate::x509::{self, CONTEXT_0, Certificate, Der, INTEGER, NULL, OCTET_STRING, OID, SEQUENCE};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// The largest PKCS#12 read (the editors' limit for a whole config).
pub const MAX_PKCS12_BYTES: usize = 1_048_576;
/// More MAC iterations than this: the check is not done (the password is asked for). OpenSSL writes 2048.
pub const MAX_MAC_ITERATIONS: u32 = 100_000;
/// At most this many safe bags are looked at.
const MAX_BAGS: usize = 64;

/// pkcs7-data (1.2.840.113549.1.7.1).
const DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
/// pkcs7-encryptedData (1.2.840.113549.1.7.6).
const ENCRYPTED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06];
/// pkcs-12 bag types (1.2.840.113549.1.12.10.1.x).
const BAG_PREFIX: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x0C, 0x0A, 0x01];
const KEY_BAG: u8 = 1;
const SHROUDED_KEY_BAG: u8 = 2;
const CERT_BAG: u8 = 3;
/// x509Certificate (1.2.840.113549.1.9.22.1).
const X509_CERTIFICATE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x16, 0x01];

/// Whether the file opens without a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Password {
    /// The MAC verifies with an empty password (or there is neither a MAC nor anything encrypted).
    NotNeeded,
    /// The MAC does not verify with an empty password.
    Needed,
    /// Not checked: an unknown MAC algorithm, too many iterations, or no MAC over encrypted parts.
    Unknown,
}

/// What a PKCS#12 shows without its password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// The certificates stored unencrypted, in file order.
    pub certificates: Vec<Certificate>,
    /// Encrypted parts (an `encryptedData` content or a shrouded key bag): their certificates need the password.
    pub encrypted_parts: usize,
    pub password: Password,
}

impl Summary {
    /// The connect needs the "Private key password" (OpenVPN would ask for one).
    pub fn needs_password(&self) -> bool {
        self.password != Password::NotNeeded
    }
}

/// The PKCS#12 in base64 (an OpenVPN `<pkcs12>` block; whitespace ignored). `None`: not a readable PKCS#12.
pub fn read_base64(text: &str) -> Option<Summary> {
    if text.len() > MAX_PKCS12_BYTES * 4 / 3 + 4096 {
        return None;
    }
    let body: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let der = crate::swift_base64::decode(&body)?;
    read(&der)
}

/// The PKCS#12 `der` (RFC 7292 `PFX`). `None`: not a readable PKCS#12.
pub fn read(der: &[u8]) -> Option<Summary> {
    if der.is_empty() || der.len() > MAX_PKCS12_BYTES {
        return None;
    }
    let mut outer = Der::new(der);
    let pfx = outer.expect(SEQUENCE)?;
    if !outer.is_empty() {
        return None;
    }
    let mut p = Der::new(pfx);
    if p.expect(INTEGER)? != [3] {
        return None;
    }
    let auth_safe = data_content(p.expect(SEQUENCE)?)?;
    let mac = if p.is_empty() { None } else { Some(p.expect(SEQUENCE)?) };
    if !p.is_empty() {
        return None;
    }
    let mut certificates = Vec::new();
    let mut encrypted_parts = 0;
    let mut bags = 0;
    let mut contents = Der::new(auth_safe);
    let mut list = Der::new(contents.expect(SEQUENCE)?);
    if !contents.is_empty() {
        return None;
    }
    while !list.is_empty() {
        let info = list.expect(SEQUENCE)?;
        let mut i = Der::new(info);
        let kind = i.expect(OID)?;
        if kind == ENCRYPTED_DATA {
            encrypted_parts += 1;
            continue;
        }
        if kind != DATA {
            return None;
        }
        let safe_contents = data_content(info)?;
        let mut sc = Der::new(safe_contents);
        let mut safe_bags = Der::new(sc.expect(SEQUENCE)?);
        while !safe_bags.is_empty() {
            bags += 1;
            if bags > MAX_BAGS {
                return None;
            }
            let mut bag = Der::new(safe_bags.expect(SEQUENCE)?);
            let bag_id = bag.expect(OID)?;
            let value = bag.expect(CONTEXT_0)?;
            match bag_id.strip_prefix(BAG_PREFIX) {
                Some([CERT_BAG]) => {
                    if let Some(c) = cert_bag(value).and_then(|der| x509::parse_der(&der))
                        && certificates.len() < x509::MAX_CERTIFICATES
                    {
                        certificates.push(c);
                    }
                }
                Some([SHROUDED_KEY_BAG]) => encrypted_parts += 1,
                Some([KEY_BAG]) => {}
                _ => {}
            }
        }
    }
    let password = match mac {
        Some(mac) => mac_password(mac, auth_safe),
        None if encrypted_parts == 0 => Password::NotNeeded,
        None => Password::Unknown,
    };
    Some(Summary { certificates, encrypted_parts, password })
}

/// The `OCTET STRING` of a pkcs7-data `ContentInfo` (`SEQUENCE { data, [0] EXPLICIT OCTET STRING }`).
fn data_content(info: &[u8]) -> Option<&[u8]> {
    let mut i = Der::new(info);
    if i.expect(OID)? != DATA {
        return None;
    }
    let mut explicit = Der::new(i.expect(CONTEXT_0)?);
    let content = explicit.expect(OCTET_STRING)?;
    (explicit.is_empty() && i.is_empty()).then_some(content)
}

/// The certificate of a `CertBag` (`SEQUENCE { x509Certificate, [0] EXPLICIT OCTET STRING }`).
fn cert_bag(value: &[u8]) -> Option<Vec<u8>> {
    let mut v = Der::new(value);
    let mut bag = Der::new(v.expect(SEQUENCE)?);
    if bag.expect(OID)? != X509_CERTIFICATE {
        return None;
    }
    let mut explicit = Der::new(bag.expect(CONTEXT_0)?);
    Some(explicit.expect(OCTET_STRING)?.to_vec())
}

// MARK: - MAC

#[derive(Clone, Copy)]
enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn from_oid(oid: &[u8]) -> Option<Hash> {
        match oid {
            [0x2B, 0x0E, 0x03, 0x02, 0x1A] => Some(Hash::Sha1),
            [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, n] => match n {
                0x01 => Some(Hash::Sha256),
                0x02 => Some(Hash::Sha384),
                0x03 => Some(Hash::Sha512),
                _ => None,
            },
            _ => None,
        }
    }

    fn output_len(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }

    fn block_len(self) -> usize {
        match self {
            Hash::Sha1 | Hash::Sha256 => 64,
            Hash::Sha384 | Hash::Sha512 => 128,
        }
    }

    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            for part in parts {
                d.update(part);
            }
            d.finalize().to_vec()
        }
        match self {
            Hash::Sha1 => x509::sha1(&parts.concat()).to_vec(),
            Hash::Sha256 => run::<Sha256>(parts),
            Hash::Sha384 => run::<Sha384>(parts),
            Hash::Sha512 => run::<Sha512>(parts),
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let block = self.block_len();
        let mut k = if key.len() > block { self.digest(&[key]) } else { key.to_vec() };
        k.resize(block, 0);
        let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5C).collect();
        let inner = self.digest(&[&ipad, data]);
        self.digest(&[&opad, &inner])
    }
}

/// RFC 7292 appendix B.2: the PKCS#12 key derivation (`id` 3: the MAC key) of `n` bytes.
fn derive(hash: Hash, password: &[u8], salt: &[u8], id: u8, iterations: u32, n: usize) -> Vec<u8> {
    let (u, v) = (hash.output_len(), hash.block_len());
    let d = vec![id; v];
    let fill = |x: &[u8]| -> Vec<u8> {
        if x.is_empty() { Vec::new() } else { x.iter().cycle().take(v * x.len().div_ceil(v)).copied().collect() }
    };
    let mut i = [fill(salt), fill(password)].concat();
    let mut out = Vec::with_capacity(n + u);
    loop {
        let mut a = hash.digest(&[&d, &i]);
        for _ in 1..iterations {
            a = hash.digest(&[&a]);
        }
        out.extend_from_slice(&a);
        if out.len() >= n {
            out.truncate(n);
            return out;
        }
        let b: Vec<u8> = a.iter().cycle().take(v).copied().collect();
        for chunk in i.chunks_mut(v) {
            let mut carry = 1u16;
            for k in (0..v).rev() {
                let sum = u16::from(chunk[k]) + u16::from(b[k]) + carry;
                chunk[k] = sum as u8;
                carry = sum >> 8;
            }
        }
    }
}

/// `MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations INTEGER DEFAULT 1 }`, checked with
/// the two forms an empty password takes (OpenSSL's `PKCS12_parse` tries both): no password bytes at all, and the
/// empty BMPString with its terminator.
fn mac_password(mac: &[u8], auth_safe: &[u8]) -> Password {
    let check = || -> Option<Password> {
        let mut m = Der::new(mac);
        let mut digest_info = Der::new(m.expect(SEQUENCE)?);
        let mut algorithm = Der::new(digest_info.expect(SEQUENCE)?);
        let hash = Hash::from_oid(algorithm.expect(OID)?);
        if !algorithm.is_empty() {
            algorithm.expect(NULL)?;
        }
        let expected = digest_info.expect(OCTET_STRING)?;
        let salt = m.expect(OCTET_STRING)?;
        let iterations = if m.is_empty() { 1 } else { small_integer(m.expect(INTEGER)?)? };
        let Some(hash) = hash else { return Some(Password::Unknown) };
        if iterations == 0 || iterations > MAX_MAC_ITERATIONS || expected.len() != hash.output_len() {
            return Some(Password::Unknown);
        }
        for password in [&[][..], &[0, 0][..]] {
            let key = derive(hash, password, salt, 3, iterations, hash.output_len());
            if hash.hmac(&key, auth_safe) == expected {
                return Some(Password::NotNeeded);
            }
        }
        Some(Password::Needed)
    };
    check().unwrap_or(Password::Unknown)
}

/// A positive `INTEGER` of at most four bytes.
fn small_integer(bytes: &[u8]) -> Option<u32> {
    let bytes = match bytes {
        [0, rest @ ..] if !rest.is_empty() => rest,
        [first, ..] if first & 0x80 != 0 => return None,
        _ => bytes,
    };
    if bytes.is_empty() || bytes.len() > 4 {
        return None;
    }
    Some(bytes.iter().fold(0u32, |n, &b| (n << 8) | u32::from(b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn element(tag: u8, body: &[u8]) -> Vec<u8> {
        assert!(body.len() < 0x80);
        [vec![tag, body.len() as u8], body.to_vec()].concat()
    }

    /// `MacData` with SHA-256, `digest`, an 8-byte salt and `iterations` (big-endian bytes of the INTEGER).
    fn mac_data(digest: &[u8], iterations: &[u8]) -> Vec<u8> {
        let algorithm =
            [element(OID, &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]), element(NULL, &[])].concat();
        let digest_info = [element(SEQUENCE, &algorithm), element(OCTET_STRING, digest)].concat();
        [element(SEQUENCE, &digest_info), element(OCTET_STRING, &[7; 8]), element(INTEGER, iterations)].concat()
    }

    #[test]
    fn the_mac_check_verifies_an_empty_password_and_caps_the_iterations() {
        let content = b"auth safe";
        let key = derive(Hash::Sha256, &[0, 0], &[7; 8], 3, 2, 32);
        let good = Hash::Sha256.hmac(&key, content);
        assert_eq!(mac_password(&mac_data(&good, &[2]), content), Password::NotNeeded);
        assert_eq!(mac_password(&mac_data(&[0; 32], &[2]), content), Password::Needed);
        // Too many iterations: not checked at all.
        assert_eq!(mac_password(&mac_data(&good, &[0x7F, 0xFF, 0, 0]), content), Password::Unknown);
        assert_eq!(mac_password(&mac_data(&good, &[0]), content), Password::Unknown);
        // A digest of the wrong length, a negative or oversized INTEGER, garbage.
        assert_eq!(mac_password(&mac_data(&[0; 20], &[2]), content), Password::Unknown);
        assert_eq!(mac_password(&mac_data(&good, &[0x80]), content), Password::Unknown);
        assert_eq!(mac_password(&mac_data(&good, &[1, 0, 0, 0, 0]), content), Password::Unknown);
        assert_eq!(mac_password(&[0x30, 0x00], content), Password::Unknown);
    }

    #[test]
    fn hmac_matches_rfc_4231_and_rfc_2202() {
        // RFC 4231 test case 2 (HMAC-SHA-256) and RFC 2202 test case 2 (HMAC-SHA-1).
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(&Hash::Sha256.hmac(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex(&Hash::Sha1.hmac(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }
}
