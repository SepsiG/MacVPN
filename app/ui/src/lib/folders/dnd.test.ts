// node --test: the Connections tree's drop targets (folders moved and reordered, pins reordered, items moved into
// folders) and the refusals (into itself or a subfolder, or a drop that changes nothing).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dropTarget, zoneOf, type Dragged } from './dnd.ts';
import { ROWS, TREE } from './fixtures.ts';

const folderDrag = (id: string): Dragged => ({ type: 'folder', id });
const itemDrag = (id: string): Dragged => ({ type: 'item', id });
const over = (rowId: string, zone: 'top' | 'middle' | 'bottom') => ({ rowId, zone });

test('zones: a folder has a middle part, an item only halves', () => {
  assert.equal(zoneOf(0.1, true), 'top');
  assert.equal(zoneOf(0.5, true), 'middle');
  assert.equal(zoneOf(0.9, true), 'bottom');
  assert.equal(zoneOf(0.4, false), 'top');
  assert.equal(zoneOf(0.6, false), 'bottom');
});

test('a folder is never dropped into itself or one of its subfolders', () => {
  for (const target of ['Work', 'Clients', 'Deep']) {
    for (const zone of ['top', 'middle', 'bottom'] as const) {
      if (target === 'Work' && zone !== 'middle') continue; // before / after itself: a no-op, null as well
      assert.equal(dropTarget(TREE, ROWS, folderDrag('Work'), over(target, zone)), null, `${target} ${zone}`);
    }
  }
  // Over an item inside it: that item's folder is inside it too.
  for (const target of ['d1', 'c1', 'w1']) assert.equal(dropTarget(TREE, ROWS, folderDrag('Work'), over(target, 'top')), null, target);
  assert.equal(dropTarget(TREE, ROWS, folderDrag('Clients'), over('d1', 'top')), null);
});

test('folders move into a folder, before or after a sibling, and to the top level', () => {
  assert.deepEqual(dropTarget(TREE, ROWS, folderDrag('Archive'), over('Clients', 'middle')), {
    action: { type: 'folderMove', id: 'Archive', parent: 'Clients', position: 1 },
    indicator: { rowId: 'Clients', where: 'into' },
  });
  assert.deepEqual(dropTarget(TREE, ROWS, folderDrag('Archive'), over('Work', 'top')), {
    action: { type: 'folderMove', id: 'Archive', parent: null, position: 0 },
    indicator: { rowId: 'Work', where: 'before' },
  });
  // Right below an open folder with contents: first inside it.
  assert.deepEqual(dropTarget(TREE, ROWS, folderDrag('Archive'), over('Work', 'bottom')), {
    action: { type: 'folderMove', id: 'Archive', parent: 'Work', position: 0 },
    indicator: { rowId: 'Work', where: 'after' },
  });
  // Below a collapsed one: after it.
  const collapsed = TREE.map((r) => (r.id === 'Work' ? { ...r, collapsed: true } : r));
  assert.equal(dropTarget(collapsed, ROWS, folderDrag('Archive'), over('Work', 'bottom')), null, 'already right after Work');
  assert.deepEqual(dropTarget(TREE, ROWS, folderDrag('Deep'), { root: true }), {
    action: { type: 'folderMove', id: 'Deep', parent: null, position: 2 },
    indicator: { rowId: null, where: 'into' },
  });
  // Over an item: into that item's folder, after its subfolders.
  assert.deepEqual(dropTarget(TREE, ROWS, folderDrag('Archive'), over('w2', 'bottom'))?.action, {
    type: 'folderMove', id: 'Archive', parent: 'Work', position: 1,
  });
});

test('a drop that changes nothing is no drop', () => {
  assert.equal(dropTarget(TREE, ROWS, folderDrag('Archive'), over('Archive', 'top')), null);
  assert.equal(dropTarget(TREE, ROWS, folderDrag('Deep'), over('Clients', 'middle')), null, 'already in Clients, the last subfolder');
  assert.equal(dropTarget(TREE, ROWS, itemDrag('c1'), over('Clients', 'middle')), null, 'already in Clients');
  assert.equal(dropTarget(TREE, ROWS, itemDrag('r2'), { root: true }), null, 'already at the top level');
  assert.equal(dropTarget(TREE, ROWS, itemDrag('w3'), over('w1', 'top')), null, 'items have no manual order');
  assert.equal(dropTarget(TREE, ROWS, itemDrag('w1'), null), null);
});

test('items only change their folder', () => {
  assert.deepEqual(dropTarget(TREE, ROWS, itemDrag('r2'), over('Deep', 'top')), {
    action: { type: 'itemMove', key: 'r2', folder: 'Deep' },
    indicator: { rowId: 'Deep', where: 'into' },
  });
  // Over an item elsewhere: into that item's folder.
  assert.deepEqual(dropTarget(TREE, ROWS, itemDrag('r2'), over('c1', 'bottom'))?.action, { type: 'itemMove', key: 'r2', folder: 'Clients' });
  assert.deepEqual(dropTarget(TREE, ROWS, itemDrag('d1'), { root: true }), {
    action: { type: 'itemMove', key: 'd1', folder: null },
    indicator: { rowId: null, where: 'into' },
  });
});

test('pinned items are reordered among the pins of their folder', () => {
  // Pin order: w1, r1, w2. Dragging w2 above w1 (same folder): from 2 to the gap 0.
  assert.deepEqual(dropTarget(TREE, ROWS, itemDrag('w2'), over('w1', 'top')), {
    action: { type: 'pinMove', from: [2], to: 0 },
    indicator: { rowId: 'w1', where: 'before' },
  });
  assert.deepEqual(dropTarget(TREE, ROWS, itemDrag('w1'), over('w2', 'bottom'))?.action, { type: 'pinMove', from: [0], to: 3 });
  // Its own gaps: nothing.
  assert.equal(dropTarget(TREE, ROWS, itemDrag('w1'), over('w2', 'top')), null, 'w1 is already before w2 (r1 sits between them in another folder)');
  // A pin over a pin of another folder: moved there instead.
  assert.deepEqual(dropTarget(TREE, ROWS, itemDrag('r1'), over('w1', 'top'))?.action, { type: 'itemMove', key: 'r1', folder: 'Work' });
});
