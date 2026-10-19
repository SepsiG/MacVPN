// Drag and drop in the Connections window's tree (spec 3, plan B "Resolved"): folders are moved and reordered,
// pinned items are reordered among the pinned items of their folder, and dropping any other item only moves it
// into another folder (items have no manual order). A drop that would put a folder into itself or one of its
// subfolders is refused here, before the backend is asked; so is a drop that changes nothing.
import type { Row, TreeRow } from '../api.ts';
import { childFolders, descendantFolders, pinnedOrder } from './tree.ts';

export type Dragged = { type: 'folder'; id: string } | { type: 'item'; id: string };

/// Where the pointer is: over a row (its top, middle or bottom part), over the list's empty space (the top
/// level), or outside the list.
export type Hover = { rowId: string; zone: Zone } | { root: true } | null;
export type Zone = 'top' | 'middle' | 'bottom';

export type DropAction =
  | { type: 'folderMove'; id: string; parent: string | null; position: number }
  | { type: 'itemMove'; key: string; folder: string | null }
  | { type: 'pinMove'; from: number[]; to: number };

/// What the view draws: a line before or after a row, or a highlighted folder (`rowId` null: the top level).
export interface Indicator {
  rowId: string | null;
  where: 'before' | 'after' | 'into';
}

export interface Drop {
  action: DropAction;
  indicator: Indicator;
}

/// The part of a row under the pointer (`fraction`: 0 at its top edge, 1 at its bottom edge). A folder has a
/// middle part (drop into it); an item only halves.
export function zoneOf(fraction: number, isFolder: boolean): Zone {
  if (!isFolder) return fraction < 0.5 ? 'top' : 'bottom';
  if (fraction < 0.28) return 'top';
  if (fraction > 0.72) return 'bottom';
  return 'middle';
}

function into(folder: string | null): Indicator {
  return { rowId: folder, where: 'into' };
}

/// A folder moved under `parent` at `position` among its subfolders (counted without it); null when that is where
/// it already is.
function folderMove(tree: readonly TreeRow[], id: string, parent: string | null, position: number, indicator: Indicator): Drop | null {
  const self = tree.find((r) => r.type === 'folder' && r.id === id);
  if (!self) return null;
  const siblings = childFolders(tree, parent).filter((f) => f.id !== id);
  const clamped = Math.max(0, Math.min(position, siblings.length));
  if (self.parent === parent) {
    const current = childFolders(tree, parent).findIndex((f) => f.id === id);
    if (current === clamped) return null;
  }
  return { action: { type: 'folderMove', id, parent, position: clamped }, indicator };
}

function itemMove(tree: readonly TreeRow[], key: string, folder: string | null): Drop | null {
  const self = tree.find((r) => r.type === 'item' && r.id === key);
  if (!self || self.parent === folder) return null;
  return { action: { type: 'itemMove', key, folder }, indicator: into(folder) };
}

/// The drop for the dragged row over `hover`, or null (refused, or nothing would change).
export function dropTarget(tree: readonly TreeRow[], rows: readonly Row[], dragged: Dragged, hover: Hover): Drop | null {
  if (hover === null) return null;
  if ('root' in hover) {
    if (dragged.type === 'item') return itemMove(tree, dragged.id, null);
    return folderMove(tree, dragged.id, null, childFolders(tree, null).length, into(null));
  }
  const target = tree.find((r) => r.id === hover.rowId);
  if (!target) return null;

  if (dragged.type === 'folder') {
    // Never into itself or below itself.
    const banned = descendantFolders(tree, dragged.id);
    banned.add(dragged.id);
    if (target.type === 'item') {
      // Folders come before items: over an item, the folder goes into that item's folder (at the end).
      if (target.parent !== null && banned.has(target.parent)) return null;
      return folderMove(tree, dragged.id, target.parent, childFolders(tree, target.parent).length, into(target.parent));
    }
    if (banned.has(target.id)) return null;
    const hasChildren = tree.some((r) => r.parent === target.id);
    if (hover.zone === 'middle' || (hover.zone === 'bottom' && hasChildren && !target.collapsed)) {
      // Into the folder: at the end, or first when dropped on the line right above its open contents.
      const position = hover.zone === 'middle' ? childFolders(tree, target.id).length : 0;
      return folderMove(tree, dragged.id, target.id, position, hover.zone === 'middle' ? into(target.id) : { rowId: target.id, where: 'after' });
    }
    const siblings = childFolders(tree, target.parent).filter((f) => f.id !== dragged.id);
    const index = siblings.findIndex((f) => f.id === target.id);
    const position = hover.zone === 'top' ? index : index + 1;
    return folderMove(tree, dragged.id, target.parent, position, { rowId: target.id, where: hover.zone === 'top' ? 'before' : 'after' });
  }

  // An item.
  const self = tree.find((r) => r.type === 'item' && r.id === dragged.id);
  if (!self) return null;
  if (target.type === 'folder') return itemMove(tree, dragged.id, target.id);
  if (target.id === dragged.id) return null;
  const pinned = pinnedOrder(rows);
  if (pinned.includes(dragged.id) && pinned.includes(target.id) && target.parent === self.parent) {
    // Reordering the pins (SwiftUI onMove: the destination is the gap in the list before the move). The pin order
    // is one list across the folders: a drop that leaves this folder's pins in their order changes nothing.
    const after = hover.zone === 'bottom' ? 1 : 0;
    const local = pinned.filter((id) => tree.some((r) => r.id === id && r.parent === self.parent));
    const localFrom = local.indexOf(dragged.id);
    const localTo = local.indexOf(target.id) + after;
    if (localTo === localFrom || localTo === localFrom + 1) return null;
    const from = pinned.indexOf(dragged.id);
    const to = pinned.indexOf(target.id) + after;
    return { action: { type: 'pinMove', from: [from], to }, indicator: { rowId: target.id, where: hover.zone === 'bottom' ? 'after' : 'before' } };
  }
  return itemMove(tree, dragged.id, target.parent);
}
