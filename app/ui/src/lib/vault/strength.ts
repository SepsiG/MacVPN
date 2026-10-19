// The master password's strength hint (spec 2.2: shown, never blocking beyond the 10-character minimum). A rough
// estimate from the length and the kinds of characters, lowered for repeats and runs; the backend checks only the
// minimum (`check_password_rules`, counted in grapheme clusters as here).

export const MIN_PASSWORD_CHARS = 10;

export type Strength = 'weak' | 'fair' | 'strong';

/// The number of user-perceived characters (grapheme clusters), as the backend counts them.
export function characterCount(text: string): number {
  if (typeof Intl !== 'undefined' && 'Segmenter' in Intl) {
    let n = 0;
    for (const _ of new Intl.Segmenter(undefined, { granularity: 'grapheme' }).segment(text)) n += 1;
    return n;
  }
  return [...text].length;
}

/// At least [`MIN_PASSWORD_CHARS`] characters.
export function meetsMinimum(password: string): boolean {
  return characterCount(password) >= MIN_PASSWORD_CHARS;
}

/// The hint for `password`; `null` while it is empty.
export function strength(password: string): Strength | null {
  if (password === '') return null;
  const chars = [...password];
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 33;
  // Repeats and runs (aaaa, 1234, abcd) add little.
  let effective = 0;
  for (let i = 0; i < chars.length; i += 1) {
    const prev = i > 0 ? chars[i - 1].codePointAt(0)! : -10;
    const code = chars[i].codePointAt(0)!;
    const step = code - prev;
    effective += step === 0 || step === 1 || step === -1 ? 0.25 : 1;
  }
  const unique = new Set(chars).size;
  const bits = Math.min(effective, unique * 2) * Math.log2(Math.max(pool, 2));
  if (!meetsMinimum(password) || bits < 50) return 'weak';
  return bits < 75 ? 'fair' : 'strong';
}

/// Both fields filled in the same way and long enough: the strength does not matter (the hint only advises).
export function passwordsReady(password: string, again: string): boolean {
  return meetsMinimum(password) && password === again;
}
