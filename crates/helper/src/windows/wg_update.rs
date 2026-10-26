//! wireguard-nt updates at runtime (2b plan, decision 6 as amended 2026-10-24, "As built (fix4)"), the pure parts:
//! the newest version from the official SDK listing, the zip's one member WinVPN uses, the PE checks of the DLL,
//! which DLL the service loads, the curl argv and the check cache. Nothing here does I/O; `sys/wg_update.rs` does.
//!
//! **Source.** `https://download.wireguard.com/wireguard-nt/` lists the SDK zips (`wireguard-nt-<version>.zip`, the
//! newest only; older ones stay downloadable). Upstream publishes no signature or manifest for these zips (no
//! `.sig`, `.asc`, `.minisig`, `SHA256SUMS` or `LATEST`, checked 2026-10-24; the signify-signed `latest.sig` of
//! `download.wireguard.com/windows-client/` covers only the WireGuard for Windows MSIs). So the trust is the DLL's
//! own Authenticode signature (Valid, signer `WireGuard LLC`), checked by the service before it is kept and again
//! at every load (the maintainer's choice, 2026-10-24).
//!
//! **The zip** is read only for one member, `wireguard-nt/bin/<amd64|arm64>/wireguard.dll`, by its exact name: no
//! member's name ever becomes a path (no traversal is possible); the archive is refused when it is not a plain,
//! single-disk, unencrypted zip, when that name appears more than once, when its local header disagrees with the
//! central directory, when it is larger than the limit, or when the inflated bytes' CRC-32 or size differ.

use std::fmt;

/// The official SDK listing.
pub const LISTING_URL: &str = "https://download.wireguard.com/wireguard-nt/";
/// The largest listing read (it is about 2 KB).
pub const LISTING_MAX_BYTES: u64 = 256 << 10;
/// The largest SDK zip downloaded (1.1's is about 2 MB).
pub const ZIP_MAX_BYTES: u64 = 32 << 20;
/// The largest `wireguard.dll` taken from it (1.1's amd64 DLL is about 1.4 MB).
pub const DLL_MAX_BYTES: u64 = 8 << 20;
/// curl's `--max-time` for the listing and for the zip, in seconds.
pub const LISTING_MAX_TIME: u64 = 30;
pub const ZIP_MAX_TIME: u64 = 120;
/// How long a check's answer is reused (System Status asks when it opens and on "Check Again"; several users'
/// windows must not make the service ask upstream each time).
pub const CHECK_CACHE_SECS: u64 = 60;

/// A wireguard-nt version: 1 to 4 dot-separated numbers (`1.1`, `0.10.1`), compared numerically with missing parts
/// as 0 (`1.1` = `1.1.0.0`, the DLL's file version).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NtVersion(pub [u16; 4]);

impl NtVersion {
    /// 1–4 parts of 1–5 ASCII digits each, fitting a `u16`; nothing else.
    pub fn parse(s: &str) -> Option<NtVersion> {
        let mut parts = [0u16; 4];
        for (n, p) in s.split('.').enumerate() {
            if n == 4 || p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            parts[n] = p.parse().ok()?;
        }
        Some(NtVersion(parts))
    }

    /// A file version resource's `major.minor.build.revision`.
    pub fn from_file_version((a, b, c, d): (u16, u16, u16, u16)) -> NtVersion {
        NtVersion([a, b, c, d])
    }
}

/// `major.minor.build`, and `.revision` when it is not 0 (`wg_nt::version_string`, as System Status shows it).
impl fmt::Display for NtVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.0;
        if d == 0 { write!(f, "{a}.{b}.{c}") } else { write!(f, "{a}.{b}.{c}.{d}") }
    }
}

/// A listed version's text, exactly as the listing writes it (`1.1`): it names the zip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub text: String,
    pub version: NtVersion,
}

/// The newest `wireguard-nt-<version>.zip` the listing links to (`href="wireguard-nt-1.1.zip"`, relative, as the
/// page has it); `None` when there is none. Only links of exactly that form count.
pub fn parse_listing(html: &str) -> Option<Listed> {
    const PREFIX: &str = "href=\"wireguard-nt-";
    const SUFFIX: &str = ".zip\"";
    let mut best: Option<Listed> = None;
    let mut rest = html;
    while let Some(at) = rest.find(PREFIX) {
        rest = &rest[at + PREFIX.len()..];
        let Some(end) = rest.find(SUFFIX) else { break };
        let text = &rest[..end];
        if let Some(version) = NtVersion::parse(text)
            && best.as_ref().is_none_or(|b| version > b.version)
        {
            best = Some(Listed { text: text.to_string(), version });
        }
    }
    best
}

/// The zip of a listed version (built only from the parsed version's digits and dots).
pub fn zip_url(listed: &Listed) -> Option<String> {
    NtVersion::parse(&listed.text).map(|_| format!("{LISTING_URL}wireguard-nt-{}.zip", listed.text))
}

/// The zip member of `wireguard.dll` for a Rust architecture name (`std::env::consts::ARCH`).
pub fn dll_member(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("wireguard-nt/bin/amd64/wireguard.dll"),
        "aarch64" => Some("wireguard-nt/bin/arm64/wireguard.dll"),
        _ => None,
    }
}

/// `IMAGE_FILE_MACHINE_*` of a Rust architecture name: AMD64 `0x8664`, ARM64 `0xAA64`.
pub fn machine_of(arch: &str) -> Option<u16> {
    match arch {
        "x86_64" => Some(0x8664),
        "aarch64" => Some(0xAA64),
        _ => None,
    }
}

/// The PE image's machine when it is a DLL (`MZ`, `e_lfanew` → `PE\0\0`, `IMAGE_FILE_HEADER.Machine`, and
/// `Characteristics` with `IMAGE_FILE_DLL`); `None` for anything else.
pub fn pe_dll_machine(bytes: &[u8]) -> Option<u16> {
    let u16_at = |at: usize| bytes.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |at: usize| bytes.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    if bytes.get(..2)? != b"MZ" {
        return None;
    }
    let pe = usize::try_from(u32_at(0x3C)?).ok()?;
    if bytes.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let machine = u16_at(pe + 4)?;
    let characteristics = u16_at(pe + 22)?;
    const IMAGE_FILE_DLL: u16 = 0x2000;
    (characteristics & IMAGE_FILE_DLL != 0).then_some(machine)
}

/// The DLL's file version matches the listed version it came as: every part the listing names is equal (`1.1`
/// matches `1.1.x.y`).
pub fn matches_listed(file: NtVersion, listed: &Listed) -> bool {
    let parts = listed.text.split('.').count();
    file.0[..parts] == listed.version.0[..parts]
}

/// Which `wireguard.dll` the service loads: the downloaded one only when its version is above the bundled one
/// (the bundled DLL stays the fallback; a downloaded DLL that is not newer, e.g. after a WinVPN update brought a
/// newer one, is not used).
pub fn use_downloaded(bundled: NtVersion, downloaded: Option<NtVersion>) -> bool {
    downloaded.is_some_and(|d| d > bundled)
}

/// An update is worth downloading only when the listed version is above every DLL the service has.
pub fn is_newer(listed: NtVersion, have: &[NtVersion]) -> bool {
    have.iter().all(|h| listed > *h)
}

/// The curl argv of one download into `output` (the service's fixed URLs only): HTTPS only (also for redirects,
/// which curl does not follow: `--max-redirs 0`, a 3xx is a failure), TLS 1.2+, no config file, no globbing, no
/// cookies, Schannel's revocation check best effort, the size and time caps, the HTTP status on stdout.
pub fn curl_args(url: &str, output: &str, max_bytes: u64, max_time: u64) -> Vec<String> {
    let mut args: Vec<String> = [
        "-q",
        "--globoff",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--max-redirs",
        "0",
        "--ssl-revoke-best-effort",
        "--connect-timeout",
        "30",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend(["--max-time".into(), max_time.to_string()]);
    args.extend(["--max-filesize".into(), max_bytes.to_string()]);
    args.extend(["--user-agent".into(), format!("WinVPN-Service/{}", env!("CARGO_PKG_VERSION"))]);
    args.extend(["--write-out".into(), "%{http_code}".into()]);
    args.extend(["--output".into(), output.to_string()]);
    args.extend(["--".into(), url.to_string()]);
    args
}

/// A check's answer kept for [`CHECK_CACHE_SECS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckCache<T> {
    pub at: u64,
    pub answer: T,
}

impl<T: Clone> CheckCache<T> {
    /// The cached answer when it is younger than the limit at `now` (Unix seconds; a clock that went back is no
    /// hit).
    pub fn fresh(cache: &Option<CheckCache<T>>, now: u64) -> Option<T> {
        cache.as_ref().filter(|c| now >= c.at && now - c.at < CHECK_CACHE_SECS).map(|c| c.answer.clone())
    }
}

// MARK: - The zip

/// Why a zip was refused (fixed words for the service log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZipError {
    /// No end of central directory, a record out of bounds, a multi-disk or ZIP64 archive.
    Malformed,
    /// The member is not in the archive.
    Missing,
    /// The member's name appears more than once.
    Duplicate,
    /// Encrypted, or a compression method other than stored or deflate.
    Unsupported,
    /// The local header names another file, or its sizes disagree with the central directory.
    Inconsistent,
    /// The member is larger than allowed.
    TooLarge,
    /// The inflated bytes are not the member's size or CRC-32.
    Corrupt,
}

impl fmt::Display for ZipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ZipError::Malformed => "the zip is malformed",
            ZipError::Missing => "the zip has no wireguard.dll for this architecture",
            ZipError::Duplicate => "the zip names wireguard.dll twice",
            ZipError::Unsupported => "the zip uses an unsupported method",
            ZipError::Inconsistent => "the zip's headers disagree",
            ZipError::TooLarge => "the zip's wireguard.dll is too large",
            ZipError::Corrupt => "the zip's wireguard.dll is corrupt",
        })
    }
}

fn le16(b: &[u8], at: usize) -> Result<u16, ZipError> {
    b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or(ZipError::Malformed)
}

fn le32(b: &[u8], at: usize) -> Result<u32, ZipError> {
    b.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or(ZipError::Malformed)
}

fn offset(v: u32) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// One member's bytes, by its exact name, at most `max` bytes. `inflate(data, limit)` is raw deflate (the service
/// passes `miniz_oxide`), `None` on any error or above `limit`.
pub fn extract(
    zip: &[u8],
    name: &str,
    max: u64,
    inflate: impl Fn(&[u8], usize) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, ZipError> {
    const EOCD: u32 = 0x0605_4b50;
    const CENTRAL: u32 = 0x0201_4b50;
    const LOCAL: u32 = 0x0403_4b50;
    // The end of central directory record: 22 bytes plus a comment of at most 65535, searched from the end.
    let min = zip.len().checked_sub(22).ok_or(ZipError::Malformed)?;
    let lowest = min.saturating_sub(0xFFFF);
    let eocd = (lowest..=min).rev().find(|&i| le32(zip, i) == Ok(EOCD)).ok_or(ZipError::Malformed)?;
    let (disk, cd_disk) = (le16(zip, eocd + 4)?, le16(zip, eocd + 6)?);
    let (entries_here, entries) = (le16(zip, eocd + 8)?, le16(zip, eocd + 10)?);
    let (cd_size, cd_offset) = (le32(zip, eocd + 12)?, le32(zip, eocd + 16)?);
    if disk != 0 || cd_disk != 0 || entries_here != entries || entries == 0xFFFF || cd_offset == 0xFFFF_FFFF {
        return Err(ZipError::Malformed);
    }
    let cd_end = offset(cd_offset).checked_add(offset(cd_size)).ok_or(ZipError::Malformed)?;
    if cd_end > eocd {
        return Err(ZipError::Malformed);
    }
    let mut at = offset(cd_offset);
    let mut found = None;
    for _ in 0..entries {
        if le32(zip, at)? != CENTRAL {
            return Err(ZipError::Malformed);
        }
        let flags = le16(zip, at + 8)?;
        let method = le16(zip, at + 10)?;
        let crc = le32(zip, at + 16)?;
        let (packed, size) = (le32(zip, at + 20)?, le32(zip, at + 24)?);
        let (name_len, extra_len, comment_len) =
            (usize::from(le16(zip, at + 28)?), usize::from(le16(zip, at + 30)?), usize::from(le16(zip, at + 32)?));
        let local = le32(zip, at + 42)?;
        let entry_name = zip.get(at + 46..at + 46 + name_len).ok_or(ZipError::Malformed)?;
        if entry_name == name.as_bytes() {
            if found.is_some() {
                return Err(ZipError::Duplicate);
            }
            found = Some((flags, method, crc, packed, size, local));
        }
        at = at + 46 + name_len + extra_len + comment_len;
        if at > cd_end {
            return Err(ZipError::Malformed);
        }
    }
    let (flags, method, crc, packed, size, local) = found.ok_or(ZipError::Missing)?;
    // Bit 0: encrypted; bit 6: strong encryption. ZIP64 sizes (0xFFFFFFFF) are not taken.
    if flags & 0x41 != 0 || !matches!(method, 0 | 8) {
        return Err(ZipError::Unsupported);
    }
    if packed == 0xFFFF_FFFF || size == 0xFFFF_FFFF || local == 0xFFFF_FFFF {
        return Err(ZipError::Malformed);
    }
    if u64::from(size) > max {
        return Err(ZipError::TooLarge);
    }
    let local = offset(local);
    if le32(zip, local)? != LOCAL {
        return Err(ZipError::Malformed);
    }
    let (l_flags, l_method) = (le16(zip, local + 6)?, le16(zip, local + 8)?);
    let (l_name_len, l_extra_len) = (usize::from(le16(zip, local + 26)?), usize::from(le16(zip, local + 28)?));
    let l_name = zip.get(local + 30..local + 30 + l_name_len).ok_or(ZipError::Malformed)?;
    // Bit 3: the sizes follow the data (then the local header's are 0 and the central directory's count).
    let data_descriptor = l_flags & 0x08 != 0;
    let (l_crc, l_packed, l_size) = (le32(zip, local + 14)?, le32(zip, local + 18)?, le32(zip, local + 22)?);
    if l_name != name.as_bytes()
        || l_method != method
        || l_flags & 0x41 != 0
        || (!data_descriptor && (l_crc, l_packed, l_size) != (crc, packed, size))
    {
        return Err(ZipError::Inconsistent);
    }
    let start = local + 30 + l_name_len + l_extra_len;
    let end = start.checked_add(offset(packed)).ok_or(ZipError::Malformed)?;
    if end > offset(cd_offset) {
        return Err(ZipError::Malformed);
    }
    let data = zip.get(start..end).ok_or(ZipError::Malformed)?;
    let size = offset(size);
    let bytes = match method {
        0 => data.to_vec(),
        _ => inflate(data, size).ok_or(ZipError::Corrupt)?,
    };
    if bytes.len() != size || crc32(&bytes) != crc {
        return Err(ZipError::Corrupt);
    }
    Ok(bytes)
}

/// CRC-32 (IEEE 802.3, reflected, as zip uses it).
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
        *slot = c;
    }
    !bytes.iter().fold(!0u32, |c, &b| table[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8))
}
