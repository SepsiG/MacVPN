// The "Team catalogs" section's texts and rules (spec 6, plan Task 16), pure so `node --test` checks them: a
// subscription's status as text and severity, a refresh's outcome as the line under "Refresh now", the short form
// of a fingerprint, the times, and which rows and folders belong to a catalog.
import type { FolderTreeRow, Row, TreeRow } from '../api';
import { tr } from '../l10n.svelte';
import type { RefreshView, SubscriptionView } from './catalogApi';

export type Severity = 'ok' | 'warn' | 'error' | 'muted';

export interface StatusLine {
  text: string;
  severity: Severity;
}

/// A subscription's status (`SubscriptionView.status`) as the list and the detail show it.
export function statusOf(sub: Pick<SubscriptionView, 'status'>): StatusLine {
  switch (sub.status) {
    case 'ok':
    case 'notModified':
      return { text: tr('Up to date'), severity: 'ok' };
    case 'unavailable':
      return { text: tr('Source unavailable'), severity: 'warn' };
    case 'rollbackRefused':
      return { text: tr('Older version refused'), severity: 'error' };
    case 'teamKeyChanged':
      return { text: tr('Team key changed'), severity: 'error' };
    case 'failed':
      return { text: tr('Refresh failed'), severity: 'error' };
    default:
      return { text: tr('Not checked yet'), severity: 'muted' };
  }
}

/// The changes of an applied version, only the non-zero parts ("2 added, 1 removed").
export function changesText(applied: { added: number; changed: number; removed: number }): string {
  const parts: string[] = [];
  if (applied.added > 0) parts.push(tr('%lld added', applied.added));
  if (applied.changed > 0) parts.push(tr('%lld changed', applied.changed));
  if (applied.removed > 0) parts.push(tr('%lld removed', applied.removed));
  return parts.join(', ');
}

/// What "Refresh now" reports under the button.
export function refreshLine(result: RefreshView): StatusLine {
  switch (result.outcome) {
    case 'applied': {
      const applied = result.applied ?? { added: 0, changed: 0, removed: 0, deferred: 0 };
      const changes = changesText(applied);
      const text = changes === '' ? tr('Updated to the new version.') : tr('Updated: %@', changes);
      return {
        text: applied.deferred > 0 ? `${text} ${tr('Connections that are up stay until you disconnect them.')}` : text,
        severity: 'ok',
      };
    }
    case 'notModified':
    case 'unchanged':
      return { text: tr('No new version.'), severity: 'ok' };
    case 'locked':
      return { text: result.error ?? tr('Refresh failed'), severity: 'warn' };
    default:
      return { text: result.error ?? tr('Refresh failed'), severity: 'error' };
  }
}

/// The fingerprint's short form for the list (`ABCD…EF56`, its first and last group); the detail shows all 8.
export function shortFingerprint(fingerprint: string): string {
  const groups = fingerprint.split('-').filter((g) => g !== '');
  return groups.length < 3 ? fingerprint : `${groups[0]}…${groups[groups.length - 1]}`;
}

/// A Unix time (seconds) in the window's language; `null`: "Never".
export function when(seconds: number | null, language: 'en' | 'hu'): string {
  if (seconds === null) return tr('Never');
  return new Date(seconds * 1000).toLocaleString(language === 'hu' ? 'hu-HU' : 'en-US', { dateStyle: 'medium', timeStyle: 'short' });
}

const ACTIVE = new Set(['connected', 'connecting', 'awaitingAuth', 'disconnecting']);

/// The catalog's connections (rows with its badge).
export function catalogRows(rows: readonly Row[], catalogId: string): Row[] {
  return rows.filter((r) => r.catalog?.catalogId === catalogId);
}

/// Of those, the ones that are up (or on their way): unsubscribing disconnects them first.
export function activeRows(rows: readonly Row[], catalogId: string): Row[] {
  return catalogRows(rows, catalogId).filter((r) => ACTIVE.has(r.state));
}

/// The catalog a folder belongs to (`teamFolders`), or null for the user's own.
export function teamOf(teamFolders: Record<string, string> | undefined, folderId: string | null): string | null {
  return (folderId !== null && teamFolders?.[folderId]) || null;
}

/// A catalog's root folder (named after the catalog): a team folder whose parent is not one. It carries the badge.
export function isTeamRoot(teamFolders: Record<string, string> | undefined, folder: Pick<FolderTreeRow, 'id' | 'parent'>): boolean {
  return teamOf(teamFolders, folder.id) !== null && teamOf(teamFolders, folder.parent) === null;
}

/// A tree row the catalog manages: an item with the badge, or a team folder. Such rows are never dragged, and
/// nothing is dropped into a team folder.
export function isTeamRow(row: TreeRow, rows: readonly Row[], teamFolders: Record<string, string> | undefined): boolean {
  if (row.type === 'folder') return teamOf(teamFolders, row.id) !== null;
  return !!rows.find((r) => r.id === row.id)?.catalog;
}
