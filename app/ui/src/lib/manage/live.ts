// The live system VPN list in the Connections window: the rows follow the view model; a selected system VPN
// that macOS removed stays shown (read-only) while the backend says so (`selectedRemoved`).
import type { EditorView, Row } from '../api';

/// The row the detail shows: the selected row of the list, or – once it is gone from the list and the backend
/// marks the selection removed – the last row seen for it.
export function shownRow(rows: Row[], selected: string | null, selectedRemoved: boolean, last: Row | null): Row | null {
  if (selected === null) return null;
  const row = rows.find((r) => r.id === selected);
  if (row) return row;
  return selectedRemoved && last?.id === selected ? last : null;
}

/// The kept row of a removed VPN: no switch, no live state (macOS no longer has the service).
export function removedRow(row: Row): Row {
  const { id, name, typeLabel, managed, kind, storedSecrets, pinned, available, heldBy } = row;
  return { id, name, typeLabel, managed, kind, storedSecrets, pinned, available, heldBy, switchOn: false, switchEnabled: false, state: 'disconnected' };
}

/// "Forget saved secrets": deleting is not editing, so a removed VPN can forget what it has stored; otherwise
/// the button also resets unsaved typing.
export function forgetDisabled(removed: boolean, view: Pick<EditorView, 'hasStored' | 'dirty'> | null): boolean {
  if (removed) return !view?.hasStored;
  return !view?.hasStored && !view?.dirty;
}
