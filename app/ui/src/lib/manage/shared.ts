// Shared credentials in the Connections window (spec 3a): the pure rules of the Credentials section, the editors'
// selector and "Create from connection…" (tested by node --test). The backend never sends a password; a credential
// is listed with its name, user name, whether a password is stored, and how many connections use it.
import type { CredentialItem, Kind, Row } from '../api';

/// The selector's value for "Own username and password".
export const OWN = '';

/// The managed kinds whose editor has a user name or a password.
const KINDS_WITH_CREDENTIALS: readonly Kind[] = ['openvpn', 'strongswan', 'l2tp', 'cisco', 'sstp'];

/// The row's editor has a user name / password (a managed kind above, or an L2TP / Cisco IPsec system VPN whose
/// secrets MacVPN keeps).
export function hasCredentialFields(row: Pick<Row, 'managed' | 'kind' | 'storedSecrets'>): boolean {
  return row.managed ? row.kind !== null && KINDS_WITH_CREDENTIALS.includes(row.kind) : row.storedSecrets;
}

/// The connections "Create from connection…" can start from, by name.
export function sourceRows(rows: readonly Row[]): Row[] {
  return rows.filter(hasCredentialFields).sort((a, b) => a.name.localeCompare(b.name));
}

/// The selector's value: the linked credential's id (matched by its unique name), or [`OWN`]. A linked name that
/// is not listed (a locked vault) keeps its own value, so the selector still shows it as linked.
export function selectorValue(linked: string | null, items: readonly CredentialItem[]): string {
  if (linked === null) return OWN;
  return items.find((c) => c.name === linked)?.id ?? `linked:${linked}`;
}

/// The add / edit form can be saved: a name (1–64 characters after trimming) and, for a rename, a changed one.
export function canSaveForm(mode: 'add' | 'edit' | 'rename', name: string, original: string | null): boolean {
  const trimmed = name.trim();
  if (trimmed === '' || [...trimmed].length > 64) return false;
  return mode !== 'rename' || trimmed !== original;
}

/// The ticked matches of "Create from connection…" (all ticked at first; the user unticks).
export function tickedItems(matches: readonly { item: string }[], unticked: ReadonlySet<string>): string[] {
  return matches.map((m) => m.item).filter((item) => !unticked.has(item));
}
