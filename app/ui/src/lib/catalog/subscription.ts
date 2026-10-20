// The "Add team catalog…" dialog's rules (spec 5, plan Task 16), pure so `node --test` checks them: the paste
// detection of a subscription string, the fingerprint and team key formatting while typing, when "Check" may run,
// and what is wiped once the secrets were sent. There is no path without a fingerprint: it is typed by the user or
// comes from the administrator's subscription string, never from a downloaded file.

export const SUBSCRIPTION_PREFIX = 'macvpn-sub:';
export const TEAM_KEY_PREFIX = 'TEAM-';
/// The team key: 13 groups of key symbols and one check group, 4 symbols each.
export const TEAM_KEY_SYMBOLS = 56;
/// The publisher fingerprint: 8 groups of 4 hex digits.
export const FINGERPRINT_DIGITS = 32;

/// A pasted or typed text is a subscription string (`macvpn-sub:…`; outer white space ignored, as the backend).
export function isSubscriptionString(text: string): boolean {
  return text.trim().startsWith(SUBSCRIPTION_PREFIX);
}

/// What the paste field got: a subscription string to hand off, nothing, or some other text (refused; the field is
/// cleared either way, so a secret pasted by mistake does not stay in the page).
export function pastedKind(text: string): 'subscription' | 'empty' | 'other' {
  if (isSubscriptionString(text)) return 'subscription';
  return text.trim() === '' ? 'empty' : 'other';
}

function grouped(symbols: string, size = 4): string {
  return (symbols.match(new RegExp(`.{1,${size}}`, 'g')) ?? []).join('-');
}

/// The fingerprint as typed, shown as upper-case groups of 4 (`ABCD-1234-…`, at most 8 groups). Spaces, dashes and
/// anything that is not a hex digit are dropped.
export function formatFingerprint(input: string): string {
  const digits = input.toUpperCase().replace(/[^0-9A-F]/g, '').slice(0, FINGERPRINT_DIGITS);
  return grouped(digits);
}

export function fingerprintComplete(input: string): boolean {
  return input.toUpperCase().replace(/[^0-9A-F]/g, '').length === FINGERPRINT_DIGITS && !/[^0-9A-Fa-f\s-]/.test(input);
}

/// The Crockford base32 symbols of a typed team key (`O` → `0`, `I` / `L` → `1`, case, spaces and dashes ignored;
/// other characters dropped), without the `TEAM-` prefix.
function teamKeySymbols(input: string): string {
  let text = input.trim().toUpperCase();
  const prefixed = /^TEAM[-\s]/.test(text);
  text = text
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1')
    .replace(/[^0-9A-HJKMNP-TV-Z]/g, '');
  // The prefix letters are symbols too: dropped when written as a prefix, or when they make the key one group long.
  if (prefixed || (text.length === TEAM_KEY_SYMBOLS + 4 && text.startsWith('TEAM'))) text = text.slice(4);
  return text.slice(0, TEAM_KEY_SYMBOLS);
}

/// The team key as typed, shown as `TEAM-` and groups of 4 (empty stays empty).
export function formatTeamKey(input: string): string {
  const symbols = teamKeySymbols(input);
  return symbols === '' ? '' : TEAM_KEY_PREFIX + grouped(symbols);
}

/// All 14 groups are there (the backend checks the check group).
export function teamKeyComplete(input: string): boolean {
  return teamKeySymbols(input).length === TEAM_KEY_SYMBOLS;
}

/// What the add dialog holds while the user enters it. The pasted string, the team key and the token live only here
/// (in memory, never in storage) until "Check" sent them.
export interface AddForm {
  /// A subscription string that the backend parsed (kept for "Check"; never shown again).
  subscription: string | null;
  /// What the parse showed: the source and the fingerprint the administrator sent.
  parsed: { kind: 'https' | 'file'; source: string; fingerprint: string } | null;
  sourceKind: 'https' | 'file';
  url: string;
  /// The chosen file's name (the path stays in the backend).
  fileName: string | null;
  teamKey: string;
  fingerprint: string;
  token: string;
}

export function emptyForm(): AddForm {
  return { subscription: null, parsed: null, sourceKind: 'https', url: '', fileName: null, teamKey: '', fingerprint: '', token: '' };
}

/// The dialog for a team catalog file opened from Finder: the file source with that file (its name; the path stays
/// in the backend). The team key and the fingerprint are still the user's to enter.
export function openedFileForm(fileName: string): AddForm {
  return { ...emptyForm(), sourceKind: 'file', fileName };
}

/// "Check" can run: a parsed subscription string, or a source with a complete team key and fingerprint.
export function canCheck(form: AddForm): boolean {
  if (form.subscription !== null && form.parsed !== null) return true;
  const source = form.sourceKind === 'https' ? form.url.trim() !== '' : form.fileName !== null;
  return source && teamKeyComplete(form.teamKey) && fingerprintComplete(form.fingerprint);
}

/// The command's input for "Check".
export function previewInput(form: AddForm): {
  subscription: string | null;
  url: string | null;
  chosenFile: boolean;
  teamKey: string | null;
  fingerprint: string | null;
  token: string | null;
} {
  const token = form.token.trim() === '' ? null : form.token.trim();
  if (form.subscription !== null) {
    return { subscription: form.subscription, url: null, chosenFile: false, teamKey: null, fingerprint: null, token };
  }
  return {
    subscription: null,
    url: form.sourceKind === 'https' ? form.url.trim() : null,
    chosenFile: form.sourceKind === 'file',
    teamKey: form.teamKey,
    fingerprint: form.fingerprint,
    token,
  };
}

/// Once "Check" sent them: the pasted string (with what was read from it), the team key and the token are wiped
/// from the form. The typed source and fingerprint stay (they are not secret), so "Back" only asks for the key again.
export function withoutSecrets(form: AddForm): AddForm {
  return { ...form, subscription: null, parsed: null, teamKey: '', token: '' };
}

/// "Check" ended: if the dialog was closed meanwhile, the verified download (it holds the team key) is dropped in
/// the backend at once and nothing is shown (`null`); otherwise the result is kept for "Subscribe".
export async function afterCheck<T extends { pendingId: string }>(
  result: T,
  closed: () => boolean,
  discard: (pendingId: string) => Promise<unknown>,
): Promise<T | null> {
  if (!closed()) return result;
  await discard(result.pendingId).catch(console.error);
  return null;
}

/// The fields' example values (formats, not texts: the same in every language).
export const EXAMPLES = {
  subscription: `${SUBSCRIPTION_PREFIX}…`,
  url: 'https://vpn.example.com/team.macvpncatalog',
  teamKey: `${TEAM_KEY_PREFIX}XXXX-XXXX-…`,
  fingerprint: Array(8).fill('XXXX').join('-'),
};
