// The backup and restore windows' rules, pure (the backend checks everything again).

/// The backup password's minimum, in characters (the master password's rule).
export const MIN_PASSWORD_CHARS = 10;

/// User-perceived characters (grapheme clusters), as the backend counts them.
export function characters(text: string): number {
  if (typeof Intl !== 'undefined' && 'Segmenter' in Intl) {
    return [...new Intl.Segmenter(undefined, { granularity: 'grapheme' }).segment(text)].length;
  }
  return [...text].length;
}

export type Strength = 'weak' | 'fair' | 'strong';

/// A hint only (it never blocks): length and the kinds of characters used.
export function passwordStrength(password: string): Strength {
  const length = characters(password);
  const kinds = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  if (length < MIN_PASSWORD_CHARS) return 'weak';
  if (length >= 16 && kinds >= 2) return 'strong';
  if (length >= 12 && kinds >= 3) return 'strong';
  return kinds >= 2 || length >= 14 ? 'fair' : 'weak';
}

export type PasswordProblem = 'short' | 'mismatch' | 'empty' | 'master' | null;

/// Why "Back Up…" is not available yet: an own password needs the minimum and the repeat, and the master password
/// is always needed too (the backend checks it against the vault; with `useMaster` it is `password` itself).
export function passwordProblem(password: string, repeat: string, useMaster: boolean, master = ''): PasswordProblem {
  if (password === '') return 'empty';
  if (useMaster) return null;
  if (characters(password) < MIN_PASSWORD_CHARS) return 'short';
  if (password !== repeat) return 'mismatch';
  if (master === '') return 'master';
  return null;
}

/// The keys of the ticked preference rows, in order.
export function tickedKeys<K extends string>(rows: readonly { key: K }[], ticked: Record<string, boolean>): K[] {
  return rows.filter((r) => ticked[r.key]).map((r) => r.key);
}

/// The preference rows' starting ticks (as the backend suggests them: never the control API).
export function initialTicks(rows: readonly { key: string; ticked: boolean }[]): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const r of rows) out[r.key] = r.key === 'controlApi' ? false : r.ticked;
  return out;
}

/// The local date of a backup (`YYYY-MM-DD`).
export function backupDate(unixSeconds: number): string {
  const d = new Date(unixSeconds * 1000);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/// The backup window's steps.
export type BackupStep = 'form' | 'confirmMaster' | 'saving' | 'done';
