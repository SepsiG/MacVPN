//! Crockford base32 for key text (the recovery key, spec 2.2, and the team key of a catalog, catalog spec 3):
//! alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, big-endian bit order, case-insensitive on input, `O` read as `0`,
//! `I` and `L` as `1`, `-` and white space ignored.
//!
//! Every buffer that holds key symbols or key bytes is a `Zeroizing` one, sized up front so it never reallocates.

use zeroize::Zeroizing;

pub(crate) const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Why typed key text was not accepted. Carries no part of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CrockfordError {
    /// A character outside the alphabet (also `U`), after the look-alike substitutions.
    InvalidCharacter,
}

/// The value (0..32) of one symbol, with the parse rules: case-insensitive, `O` → `0`, `I`/`L` → `1`.
pub(crate) fn symbol_value(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        other => other,
    };
    if !c.is_ascii() {
        return None;
    }
    ALPHABET.iter().position(|&a| a == c as u8).map(|p| p as u8)
}

/// The symbol values of typed text: `-` and white space skipped, every other character through [`symbol_value`].
pub(crate) fn normalize(input: &str) -> Result<Zeroizing<Vec<u8>>, CrockfordError> {
    // At most one value per input byte: the buffer never grows.
    let mut values = Zeroizing::new(Vec::with_capacity(input.len()));
    for c in input.chars() {
        if c == '-' || c.is_whitespace() {
            continue;
        }
        values.push(symbol_value(c).ok_or(CrockfordError::InvalidCharacter)?);
    }
    Ok(values)
}

/// The first `symbols × 5` bits of `bytes` as `symbols` symbols, big-endian, without separators. Missing bits at
/// the end (when `bytes` holds fewer) are zero.
pub(crate) fn encode(bytes: &[u8], symbols: usize) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(symbols));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut input = bytes.iter();
    while text.len() < symbols {
        if bits < 5 {
            acc = (acc << 8) | u32::from(input.next().copied().unwrap_or(0));
            bits += 8;
        }
        bits -= 5;
        text.push(char::from(ALPHABET[((acc >> bits) & 0x1F) as usize]));
        acc &= (1 << bits) - 1;
    }
    text
}

/// Symbol values (each below 32) → `len × 5 / 8` bytes, big-endian. `None` when a value is out of range or the
/// left-over bits at the end (`len × 5 mod 8` of them) are not zero: only the canonical text decodes.
pub(crate) fn decode(values: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(values.len() * 5 / 8));
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &v in values {
        if v >= 32 {
            return None;
        }
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0).then_some(bytes)
}

/// `text` split into groups of `size` characters joined by `-`.
pub(crate) fn grouped(text: &str, size: usize) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len() + text.len() / size.max(1)));
    for (i, c) in text.chars().enumerate() {
        if i > 0 && i.is_multiple_of(size) {
            out.push('-');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_and_decode_are_inverse() {
        let bytes: Vec<u8> = (0u8..32).map(|b| b.wrapping_mul(37)).collect();
        let text = encode(&bytes, 52);
        let values = normalize(&text).unwrap();
        assert_eq!(&decode(&values).unwrap()[..], &bytes[..]);
    }

    #[test]
    fn padding_bits_must_be_zero() {
        // 2 symbols = 10 bits = 1 byte + 2 left-over bits.
        assert_eq!(&decode(&[0b11111, 0b11100]).unwrap()[..], &[0xFF]);
        assert!(decode(&[0b11111, 0b11101]).is_none());
        assert!(decode(&[32]).is_none());
    }

    #[test]
    fn encode_truncates_and_pads() {
        assert_eq!(&*encode(&[0xFF, 0xFF, 0xFF], 4), "ZZZZ");
        assert_eq!(&*encode(&[0xFF], 2), "ZW");
        assert_eq!(&*encode(&[], 3), "000");
    }

    #[test]
    fn grouping() {
        assert_eq!(&*grouped("ABCDEFGH", 4), "ABCD-EFGH");
        assert_eq!(&*grouped("ABCDE", 4), "ABCD-E");
        assert_eq!(&*grouped("", 4), "");
    }
}
