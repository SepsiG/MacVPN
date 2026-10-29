//! WireGuard keys for the connection editor: a new private key (`wg genkey`), its public key (`wg pubkey`), a new
//! preshared key (`wg genpsk`), and the key lines of a config text read and replaced.
//!
//! - **Private key:** 32 bytes from the OS CSPRNG (the caller's `fill`: the platform's `Entropy`), clamped as
//!   `wg genkey` does (`k[0] &= 248; k[31] = (k[31] & 127) | 64`), standard base64 with padding (44 characters).
//! - **Public key:** X25519 of the private key with the base point (`curve25519-dalek`'s
//!   `MontgomeryPoint::mul_base_clamped`, which clamps first, as `wg pubkey` does for an unclamped key).
//! - **Preshared key:** 32 random bytes, base64.
//!
//! A key is accepted only in `wg`'s own form: 43 base64 characters and `=`, canonical (the unused low bits of the
//! last character zero), exactly what the validator's `PrivateKey` / `PublicKey` / `PresharedKey` rule allows.
//! Nothing here logs or formats key material; secrets are returned in [`Zeroizing`] buffers.
//!
//! The config text functions follow the validator's reading (`validators::wireguard`): a comment from `#`, keys
//! and section headers case-insensitive, space and tab trimmed. A replaced line keeps its indentation, its key's
//! spelling and its comment; the text's other lines and its line endings stay as they are.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use curve25519_dalek::montgomery::MontgomeryPoint;
use std::io;
use zeroize::Zeroizing;

/// The length of a WireGuard key in bytes.
pub const KEY_LEN: usize = 32;
/// The length of a WireGuard key in base64 (with the one `=`).
pub const KEY_BASE64_LEN: usize = 44;

/// `wg genkey`'s clamping of an X25519 private key.
pub fn clamp(key: &mut [u8; KEY_LEN]) {
    key[0] &= 248;
    key[31] = (key[31] & 127) | 64;
}

/// Standard base64 of a key (44 characters).
fn encode(key: &[u8; KEY_LEN]) -> Zeroizing<String> {
    Zeroizing::new(STANDARD.encode(key))
}

/// 32 bytes from `fill` (the OS CSPRNG in the app). A failed fill is an error, never a weak key.
fn random(fill: impl FnOnce(&mut [u8]) -> io::Result<()>) -> io::Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
    fill(bytes.as_mut_slice())?;
    Ok(bytes)
}

/// The private key `wg genkey` would make of these random bytes (clamped, base64).
pub fn private_key_from_random(random: &[u8; KEY_LEN]) -> Zeroizing<String> {
    let mut key = Zeroizing::new(*random);
    clamp(&mut key);
    encode(&key)
}

/// A new private key (`wg genkey`) from `fill`.
pub fn generate_private_key(fill: impl FnOnce(&mut [u8]) -> io::Result<()>) -> io::Result<Zeroizing<String>> {
    Ok(private_key_from_random(&*random(fill)?))
}

/// A new preshared key (`wg genpsk`: 32 random bytes, base64) from `fill`.
pub fn generate_preshared_key(fill: impl FnOnce(&mut [u8]) -> io::Result<()>) -> io::Result<Zeroizing<String>> {
    Ok(encode(&*random(fill)?))
}

/// The 32 bytes of a key in `wg`'s form (43 base64 characters, `=`, canonical); `None` for anything else.
pub fn decode_key(text: &str) -> Option<Zeroizing<[u8; KEY_LEN]>> {
    let bytes = text.as_bytes();
    if bytes.len() != KEY_BASE64_LEN
        || bytes[KEY_BASE64_LEN - 1] != b'='
        || !bytes[..KEY_BASE64_LEN - 1].iter().all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
    {
        return None;
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    // The standard engine refuses non-zero trailing bits (a non-canonical last character), as `wg` does.
    match STANDARD.decode_slice(bytes, key.as_mut_slice()) {
        Ok(KEY_LEN) => Some(key),
        _ => None,
    }
}

/// The public key of a private key (`wg pubkey`); `None` if `private_key` is not a key in `wg`'s form.
pub fn public_key(private_key: &str) -> Option<String> {
    let private = decode_key(private_key)?;
    let public = MontgomeryPoint::mul_base_clamped(*private);
    Some(STANDARD.encode(public.to_bytes()))
}

// MARK: - The key lines of a config text

/// Which key line of the config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLine {
    /// `[Interface] PrivateKey`.
    PrivateKey,
    /// `[Peer] PresharedKey` of the config's only peer.
    PresharedKey,
}

/// A line of the config, as the validator reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Line<'a> {
    /// Empty or a comment.
    Other,
    /// `[interface]`, `[peer]` or another header (lower-cased, trimmed).
    Header(&'a str),
    /// `key = value`: the key (trimmed, as written) and the value (trimmed, without the comment).
    KeyValue { key: &'a str, value: &'a str },
}

fn trim(s: &str) -> &str {
    s.trim_matches([' ', '\t'])
}

/// A line without its line ending.
fn parse(line: &str) -> Line<'_> {
    let before_comment = line.split('#').next().unwrap_or("");
    let content = trim(before_comment);
    if content.is_empty() {
        return Line::Other;
    }
    if content.starts_with('[') && content.ends_with(']') {
        return Line::Header(content);
    }
    match content.split_once('=') {
        Some((key, value)) => Line::KeyValue { key: trim(key), value: trim(value) },
        None => Line::Other,
    }
}

/// The section a header starts: `Some(true)` `[Interface]`, `Some(false)` `[Peer]`, `None` another one.
fn section_of(header: &str) -> Option<bool> {
    if header.eq_ignore_ascii_case("[interface]") {
        Some(true)
    } else if header.eq_ignore_ascii_case("[peer]") {
        Some(false)
    } else {
        None
    }
}

/// The text's lines with their line endings (`\n` or `\r\n`; the last one may have none).
fn lines(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

/// A line without its ending, and the ending.
fn split_ending(line: &str) -> (&str, &str) {
    if let Some(body) = line.strip_suffix("\r\n") {
        (body, "\r\n")
    } else if let Some(body) = line.strip_suffix('\n') {
        (body, "\n")
    } else {
        (line, "")
    }
}

/// The text's line ending (`\r\n` if it has any).
fn ending_of(text: &str) -> &'static str {
    if text.contains("\r\n") { "\r\n" } else { "\n" }
}

/// Where each line is: the section (`Some(true)` interface, `Some(false)` peer, `None` outside or unknown), the
/// index of the peer it belongs to, and the parsed line.
fn walk(text: &str) -> Vec<(Option<bool>, usize, Line<'_>)> {
    let mut section = None;
    let mut peer = 0usize;
    let mut out = Vec::new();
    for raw in lines(text) {
        let line = parse(split_ending(raw).0);
        if let Line::Header(h) = line {
            section = section_of(h);
            if section == Some(false) {
                peer += 1;
            }
        }
        out.push((section, peer, line));
    }
    out
}

/// What the editor shows of a config's keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigKeys {
    /// The `[Interface] PrivateKey` value (the last one, as `wg` uses it); `None`: no line or an empty value.
    pub private_key: Option<Zeroizing<String>>,
    /// The number of `[Peer]` sections.
    pub peers: usize,
    /// The only peer's `PresharedKey` (the last one); `None`: no line, an empty value, or not exactly one peer.
    pub preshared_key: Option<Zeroizing<String>>,
}

/// The keys of a config text.
pub fn read(text: &str) -> ConfigKeys {
    let mut keys = ConfigKeys::default();
    let walked = walk(text);
    keys.peers = walked.last().map_or(0, |(_, peer, _)| *peer);
    for (section, _, line) in walked {
        let Line::KeyValue { key, value } = line else { continue };
        let value = (!value.is_empty()).then(|| Zeroizing::new(value.to_string()));
        match section {
            Some(true) if key.eq_ignore_ascii_case("privatekey") => keys.private_key = value,
            Some(false) if keys.peers == 1 && key.eq_ignore_ascii_case("presharedkey") => keys.preshared_key = value,
            _ => {}
        }
    }
    keys
}

/// `line` with its value replaced by `value` (indentation, key spelling, comment and line ending kept).
fn replaced(raw: &str, key: &str, value: &str) -> String {
    let (body, ending) = split_ending(raw);
    let indent = &body[..body.len() - body.trim_start_matches([' ', '\t']).len()];
    let comment = body.find('#').map(|i| format!(" {}", &body[i..])).unwrap_or_default();
    format!("{indent}{key} = {value}{comment}{ending}")
}

/// The text with `which`'s value set to `value`: every such line of the section replaced, or, without one, a new
/// line after the section's header (a preshared key after the peer's `PublicKey` line). A private key without an
/// `[Interface]` section gets one at the top. `None`: a preshared key in a config without exactly one `[Peer]`.
pub fn set(text: &str, which: KeyLine, value: &str) -> Option<String> {
    let walked = walk(text);
    let peers = walked.last().map_or(0, |(_, peer, _)| *peer);
    let (wanted, name) = match which {
        KeyLine::PrivateKey => (true, "PrivateKey"),
        KeyLine::PresharedKey => {
            if peers != 1 {
                return None;
            }
            (false, "PresharedKey")
        }
    };
    let raw = lines(text);
    let mut out: Vec<String> = Vec::with_capacity(raw.len() + 1);
    let mut replaced_any = false;
    // Where a new line goes: after the section's first header, or (preshared key) after the peer's public key.
    let mut insert_after: Option<usize> = None;
    let mut header_seen = false;
    for (i, (section, _, line)) in walked.iter().enumerate() {
        let in_section = *section == Some(wanted);
        match line {
            Line::Header(_) if in_section && !header_seen => {
                header_seen = true;
                insert_after = Some(i);
            }
            Line::KeyValue { key, .. } if in_section && key.eq_ignore_ascii_case(name) => {
                out.push(replaced(raw[i], key, value));
                replaced_any = true;
                continue;
            }
            Line::KeyValue { key, .. }
                if in_section && which == KeyLine::PresharedKey && key.eq_ignore_ascii_case("publickey") =>
            {
                insert_after = Some(i);
            }
            _ => {}
        }
        out.push(raw[i].to_string());
    }
    if replaced_any {
        return Some(out.concat());
    }
    let eol = ending_of(text);
    let new_line = format!("{name} = {value}{eol}");
    match insert_after {
        Some(i) => {
            if split_ending(&out[i]).1.is_empty() {
                out[i].push_str(eol);
            }
            out.insert(i + 1, new_line);
            Some(out.concat())
        }
        // No `[Interface]` (a preshared key always has its peer's header).
        None if text.trim().is_empty() => Some(format!("[Interface]{eol}{new_line}")),
        None => Some(format!("[Interface]{eol}{new_line}{eol}{text}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7748, section 6.1 (Alice and Bob), as `wg pubkey` prints them.
    const ALICE_PRIVATE: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";
    const ALICE_PUBLIC: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
    const BOB_PRIVATE: &str = "XasIfmJKikt54X+Lg4AO5m87sSkmGLb9HC+LJ/+I4Os=";
    const BOB_PUBLIC: &str = "3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=";

    fn hex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn the_rfc_7748_vectors_give_their_public_keys() {
        // The RFC's hex keys are the base64 ones above.
        assert_eq!(
            STANDARD.encode(hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")),
            ALICE_PRIVATE
        );
        assert_eq!(
            STANDARD.encode(hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")),
            ALICE_PUBLIC
        );
        assert_eq!(
            STANDARD.encode(hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")),
            BOB_PUBLIC
        );
        assert_eq!(public_key(ALICE_PRIVATE).as_deref(), Some(ALICE_PUBLIC));
        assert_eq!(public_key(BOB_PRIVATE).as_deref(), Some(BOB_PUBLIC));
    }

    #[test]
    fn an_unclamped_key_is_clamped_first_as_wg_pubkey_does() {
        // `printf '%s' "$key" | wg pubkey` for 32 0xff bytes and for the same bytes clamped.
        let unclamped = "//////////////////////////////////////////8=";
        let clamped = "+P///////////////////////////////////////38=";
        assert_eq!(private_key_from_random(&[0xff; 32]).as_str(), clamped);
        let expected = "hHwNLDdSNPNl5mCVUYejc1oPdhPRYJ06ak2MU66qWiI=";
        assert_eq!(public_key(unclamped).as_deref(), Some(expected));
        assert_eq!(public_key(clamped).as_deref(), Some(expected));
        // The all-zero key, as `wg pubkey` prints it.
        let zero = STANDARD.encode([0u8; 32]);
        assert_eq!(public_key(&zero).as_deref(), Some("L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q="));
    }

    #[test]
    fn a_generated_private_key_is_clamped_base64_of_32_random_bytes() {
        let mut calls = 0;
        let key = generate_private_key(|buf| {
            calls += 1;
            assert_eq!(buf.len(), 32);
            buf.fill(0xa5);
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(key.len(), KEY_BASE64_LEN);
        assert!(key.ends_with('='));
        let bytes = decode_key(&key).unwrap();
        assert_eq!(bytes[0], 0xa5 & 248);
        assert_eq!(bytes[31], (0xa5 & 127) | 64);
        assert!(bytes[1..31].iter().all(|b| *b == 0xa5));
        assert!(public_key(&key).is_some());
        // The validator accepts it.
        assert!(crate::validators::wireguard::is_valid_value("privatekey", &key));
    }

    #[test]
    fn a_generated_preshared_key_is_base64_of_32_unchanged_bytes() {
        let psk = generate_preshared_key(|buf| {
            buf.fill(0xff);
            Ok(())
        })
        .unwrap();
        assert_eq!(psk.as_str(), "//////////////////////////////////////////8=");
        assert!(crate::validators::wireguard::is_valid_value("presharedkey", &psk));
    }

    #[test]
    fn a_failed_fill_makes_no_key() {
        let failing = |_: &mut [u8]| Err(io::Error::other("no entropy"));
        assert!(generate_private_key(failing).is_err());
        assert!(generate_preshared_key(failing).is_err());
    }

    #[test]
    fn each_key_comes_from_its_own_fill() {
        // A stand-in CSPRNG for the test (the app passes the platform's): the bytes differ per call.
        let mut n = 0u8;
        let mut fill = |buf: &mut [u8]| {
            n += 1;
            buf.iter_mut().enumerate().for_each(|(i, b)| *b = (i as u8).wrapping_mul(31) ^ n);
            Ok(())
        };
        let a = generate_private_key(&mut fill).unwrap();
        let b = generate_private_key(&mut fill).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn only_keys_in_wg_form_decode() {
        assert!(decode_key(ALICE_PRIVATE).is_some());
        for bad in [
            "",
            "abc",
            &ALICE_PRIVATE[..43],                            // no padding
            "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo==", // too long
            "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCp=",  // non-canonical last character
            "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LC-=",  // URL-safe alphabet
            " dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo",
        ] {
            assert!(decode_key(bad).is_none(), "{bad:?}");
            assert!(public_key(bad).is_none(), "{bad:?}");
        }
    }

    const TEMPLATE: &str =
        "[Interface]\nPrivateKey =\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey =\nAllowedIPs = 0.0.0.0/0\n";

    #[test]
    fn reads_the_interface_private_key_and_the_only_peers_preshared_key() {
        let text = "# c\n[Interface]\n  privatekey = AAA # mine\n[Peer]\nPublicKey = B\nPresharedKey = P\n";
        let keys = read(text);
        assert_eq!(keys.private_key.as_deref().map(String::as_str), Some("AAA"));
        assert_eq!(keys.peers, 1);
        assert_eq!(keys.preshared_key.as_deref().map(String::as_str), Some("P"));
        // An empty value is no key; a PrivateKey in a peer is not the interface's.
        let keys = read(TEMPLATE);
        assert_eq!(keys.private_key, None);
        assert_eq!(read("[Peer]\nPrivateKey = X\n").private_key, None);
        // Two peers: no single preshared key.
        let two = "[Interface]\nPrivateKey = A\n[Peer]\nPresharedKey = P\n[Peer]\nPresharedKey = Q\n";
        assert_eq!(read(two).peers, 2);
        assert_eq!(read(two).preshared_key, None);
        assert_eq!(read("").peers, 0);
    }

    #[test]
    fn sets_the_private_key_in_place() {
        let text = set(TEMPLATE, KeyLine::PrivateKey, ALICE_PRIVATE).unwrap();
        assert_eq!(text, TEMPLATE.replace("PrivateKey =\n", &format!("PrivateKey = {ALICE_PRIVATE}\n")));
        // Indentation, spelling and comment kept; CRLF kept; other lines untouched.
        let text = "[Interface]\r\n\tprivatekey=old # mine\r\nAddress = 10.0.0.2/32\r\n";
        assert_eq!(
            set(text, KeyLine::PrivateKey, "NEW").unwrap(),
            "[Interface]\r\n\tprivatekey = NEW # mine\r\nAddress = 10.0.0.2/32\r\n"
        );
        // The peer's lines are never touched.
        let text = "[Peer]\nPrivateKey = keep\n[Interface]\nPrivateKey = old\n";
        assert_eq!(
            set(text, KeyLine::PrivateKey, "N").unwrap(),
            "[Peer]\nPrivateKey = keep\n[Interface]\nPrivateKey = N\n"
        );
    }

    #[test]
    fn adds_a_missing_private_key_line_or_section() {
        let text = "[Interface] # main\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = B\n";
        assert_eq!(
            set(text, KeyLine::PrivateKey, "N").unwrap(),
            "[Interface] # main\nPrivateKey = N\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = B\n"
        );
        assert_eq!(set("[Interface]", KeyLine::PrivateKey, "N").unwrap(), "[Interface]\nPrivateKey = N\n");
        assert_eq!(set("[interface]\r\n", KeyLine::PrivateKey, "N").unwrap(), "[interface]\r\nPrivateKey = N\r\n");
        assert_eq!(set("", KeyLine::PrivateKey, "N").unwrap(), "[Interface]\nPrivateKey = N\n");
        assert_eq!(
            set("[Peer]\nPublicKey = B\n", KeyLine::PrivateKey, "N").unwrap(),
            "[Interface]\nPrivateKey = N\n\n[Peer]\nPublicKey = B\n"
        );
    }

    #[test]
    fn sets_the_only_peers_preshared_key() {
        let text = set(TEMPLATE, KeyLine::PresharedKey, "P").unwrap();
        assert_eq!(text, TEMPLATE.replace("PublicKey =\n", "PublicKey =\nPresharedKey = P\n"));
        assert_eq!(read(&text).preshared_key.as_deref().map(String::as_str), Some("P"));
        let text = "[Interface]\n[Peer]\nPresharedKey = old\nPublicKey = B";
        assert_eq!(
            set(text, KeyLine::PresharedKey, "P").unwrap(),
            "[Interface]\n[Peer]\nPresharedKey = P\nPublicKey = B"
        );
        // After the header when the peer has no public key; a last line without an ending gets one.
        assert_eq!(set("[Peer]", KeyLine::PresharedKey, "P").unwrap(), "[Peer]\nPresharedKey = P\n");
        // Not exactly one peer: nothing to set.
        assert_eq!(set("[Interface]\n", KeyLine::PresharedKey, "P"), None);
        assert_eq!(set("[Peer]\n[Peer]\n", KeyLine::PresharedKey, "P"), None);
    }

    #[test]
    fn a_generated_key_pair_validates_in_the_template() {
        let key = generate_private_key(|b| {
            b.fill(7);
            Ok(())
        })
        .unwrap();
        let text = set(TEMPLATE, KeyLine::PrivateKey, &key).unwrap();
        let text = text.replace("PublicKey =", &format!("PublicKey = {BOB_PUBLIC}"));
        let text = format!("{text}Endpoint = vpn.example.com:51820\n");
        use crate::validators::ConfigValidator;
        assert!(crate::validators::wireguard::WireGuardValidator.validate(&text).is_empty());
        assert_eq!(read(&text).private_key.as_deref().map(String::as_str), Some(key.as_str()));
    }
}
