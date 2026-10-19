// The recovery key as the user types it: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` in Crockford base32 (spec 2.2). Case does
// not matter, `O` reads as `0` and `I` / `L` as `1`, spaces and dashes are ignored, as in the backend's
// `RecoveryKey::parse` (which checks it again).

export const KEY_SYMBOLS = 24;
export const GROUP_SYMBOLS = 4;
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
/// The key's shape, as the field's placeholder (not a text: the same in every language).
export const KEY_PLACEHOLDER = Array(KEY_SYMBOLS / GROUP_SYMBOLS).fill('XXXX').join('-');

/// The symbols of `input`: upper case, the look-alikes mapped, separators dropped (other characters are kept, so
/// the key is reported invalid rather than silently changed).
export function normalizeRecoveryKey(input: string): string {
  return input
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
}

/// The field's text while typing: the normalized symbols in groups of four, at most 24 symbols.
export function formatRecoveryInput(input: string): string {
  const symbols = normalizeRecoveryKey(input).slice(0, KEY_SYMBOLS);
  return (symbols.match(/.{1,4}/g) ?? []).join('-');
}

/// 24 symbols of the alphabet.
export function isCompleteKey(input: string): boolean {
  const symbols = normalizeRecoveryKey(input);
  return symbols.length === KEY_SYMBOLS && [...symbols].every((c) => ALPHABET.includes(c));
}

/// One group typed for the "retype group N" check: the normalized symbols, at most four.
export function formatGroupInput(input: string): string {
  return normalizeRecoveryKey(input).slice(0, GROUP_SYMBOLS);
}
