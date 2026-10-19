// Test data for the folder tests (not shipped: only the tests import it).
import type { FolderTreeRow, ItemTreeRow, Row } from '../api.ts';

export function folder(id: string, parent: string | null, depth: number, extra: Partial<FolderTreeRow> = {}): FolderTreeRow {
  return {
    type: 'folder', id, name: id, parent, depth, color: null, colorSource: 'none', ownColor: null, collapsed: false,
    activeCount: 0, hasConnected: false, connectionCount: 0, itemCount: 0, folderCount: 0, ...extra,
  };
}

export function item(id: string, parent: string | null, depth: number, extra: Partial<ItemTreeRow> = {}): ItemTreeRow {
  return { type: 'item', id, parent, depth, color: null, colorSource: 'none', ownColor: null, ...extra };
}

export function row(id: string, pinned = false): Row {
  return {
    id, name: id, typeLabel: 'OpenVPN', managed: true, kind: 'openvpn', storedSecrets: false, pinned, available: true,
    switchOn: false, switchEnabled: true, heldBy: [], state: 'disconnected',
  };
}

/// Work/ { Clients/ { Deep/ { d1 } c1 } w1(pinned) w2(pinned) w3 }  Archive/ {}  r1(pinned) r2
export const TREE = [
  folder('Work', null, 0),
  folder('Clients', 'Work', 1),
  folder('Deep', 'Clients', 2),
  item('d1', 'Deep', 3),
  item('c1', 'Clients', 2),
  item('w1', 'Work', 1),
  item('w2', 'Work', 1),
  item('w3', 'Work', 1),
  folder('Archive', null, 0),
  item('r1', null, 0),
  item('r2', null, 0),
];

export const ROWS = [row('w1', true), row('r1', true), row('w2', true), row('d1'), row('c1'), row('w3'), row('r2')];
