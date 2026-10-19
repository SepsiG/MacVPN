// The folder tree's view rules (spec 3), pure so `node --test` checks them: the indentation cap, which rows a
// collapsed folder hides, the folder badge (active count and the green dot), subtrees, and the colour tokens.
import type { FolderColor, FolderTreeRow, Row, TreeRow } from '../api.ts';

/// Nesting is shown with indentation up to this many levels; deeper levels still work, drawn at this indent.
export const MAX_INDENT_LEVELS = 3;

/// The indentation level of a row at `depth` (0 at the top level).
export function indentLevel(depth: number): number {
  return Math.min(Math.max(0, Math.floor(depth)), MAX_INDENT_LEVELS);
}

/// The tree to show: the backend's, or (an older view model without one) the rows at the top level.
export function treeOf(vm: { tree?: TreeRow[]; rows: Row[] }): TreeRow[] {
  if (vm.tree && (vm.tree.length > 0 || vm.rows.length === 0)) return vm.tree;
  return vm.rows.map((r) => ({ type: 'item', id: r.id, parent: null, depth: 0, color: null, colorSource: 'none', ownColor: null }));
}

/// The rows left once the contents of collapsed folders are hidden (a collapsed folder itself stays).
/// `collapsed` decides per folder (the backend's state, or the view's own while a change is on its way).
export function visibleRows(tree: readonly TreeRow[], collapsed: (folder: FolderTreeRow) => boolean = (f) => f.collapsed): TreeRow[] {
  const out: TreeRow[] = [];
  let hiddenBelow: number | null = null;
  for (const row of tree) {
    if (hiddenBelow !== null && row.depth > hiddenBelow) continue;
    hiddenBelow = null;
    out.push(row);
    if (row.type === 'folder' && collapsed(row)) hiddenBelow = row.depth;
  }
  return out;
}

/// What a folder row shows on the right: the number of active connections inside (null: none) and a dot – green
/// when one of them is connected (also, and especially, while the folder is collapsed), amber while they are only
/// connecting.
export function folderBadge(folder: Pick<FolderTreeRow, 'activeCount' | 'hasConnected'>): { count: number | null; dot: 'on' | 'busy' | null } {
  if (folder.activeCount <= 0) return { count: null, dot: folder.hasConnected ? 'on' : null };
  return { count: folder.activeCount, dot: folder.hasConnected ? 'on' : 'busy' };
}

/// The rows inside a folder (all depths), in display order.
export function subtree(tree: readonly TreeRow[], folderId: string): TreeRow[] {
  const start = tree.findIndex((r) => r.type === 'folder' && r.id === folderId);
  if (start < 0) return [];
  const depth = tree[start].depth;
  const out: TreeRow[] = [];
  for (let i = start + 1; i < tree.length && tree[i].depth > depth; i += 1) out.push(tree[i]);
  return out;
}

/// The ids of the folders below a folder (not itself).
export function descendantFolders(tree: readonly TreeRow[], folderId: string): Set<string> {
  return new Set(subtree(tree, folderId).filter((r) => r.type === 'folder').map((r) => r.id));
}

/// The subfolders of `parent` (null: the top level), in order.
export function childFolders(tree: readonly TreeRow[], parent: string | null): FolderTreeRow[] {
  return tree.filter((r): r is FolderTreeRow => r.type === 'folder' && r.parent === parent);
}

/// The CSS colour of a palette colour (null: none).
export function colorToken(color: FolderColor | null | undefined): string | null {
  return color ? `var(--folder-${color})` : null;
}

/// The pinned items' ids in pin order (the rows are in ranking order: pinned first, in pin order).
export function pinnedOrder(rows: readonly Row[]): string[] {
  return rows.filter((r) => r.pinned).map((r) => r.id);
}

export type DeleteMode = 'moveUp' | 'deleteContents';

/// After the delete dialog's first step: delete now, or ask once more – deleting connections always needs a
/// second confirmation that names how many.
export function deleteStep(mode: DeleteMode, connectionCount: number): 'delete' | 'confirm' {
  return mode === 'deleteContents' && connectionCount > 0 ? 'confirm' : 'delete';
}

/// The folder holds nothing (no item, no subfolder): deleting it asks no question about its contents.
export function isEmptyFolder(folder: Pick<FolderTreeRow, 'itemCount' | 'folderCount'>): boolean {
  return folder.itemCount === 0 && folder.folderCount === 0;
}
