// node --test: the folder tree's view rules (indentation cap, collapsed folders, the badge's count and green dot)
// and the palette's contrast on the card surface in both modes (spec 3: text-safe colours, at least 4.5:1).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { colorToken, descendantFolders, folderBadge, indentLevel, MAX_INDENT_LEVELS, subtree, treeOf, visibleRows } from './tree.ts';
import { folder, item, row, TREE } from './fixtures.ts';

test('the indentation is capped at three levels', () => {
  assert.equal(MAX_INDENT_LEVELS, 3);
  assert.deepEqual([0, 1, 2, 3, 4, 9].map(indentLevel), [0, 1, 2, 3, 3, 3]);
  assert.equal(indentLevel(-1), 0);
});

test('a collapsed folder hides its contents at every depth, and only them', () => {
  const ids = (rows: { id: string }[]) => rows.map((r) => r.id);
  assert.deepEqual(ids(visibleRows(TREE)), ids(TREE));
  const collapsedClients = TREE.map((r) => (r.id === 'Clients' ? { ...r, collapsed: true } : r));
  assert.deepEqual(ids(visibleRows(collapsedClients)), ['Work', 'Clients', 'w1', 'w2', 'w3', 'Archive', 'r1', 'r2']);
  const collapsedWork = TREE.map((r) => (r.id === 'Work' ? { ...r, collapsed: true } : r));
  assert.deepEqual(ids(visibleRows(collapsedWork)), ['Work', 'Archive', 'r1', 'r2']);
  // The view's own state wins (a toggle on its way to the backend).
  assert.deepEqual(ids(visibleRows(TREE, (f) => f.id === 'Deep')), ['Work', 'Clients', 'Deep', 'c1', 'w1', 'w2', 'w3', 'Archive', 'r1', 'r2']);
});

test('the folder badge: the active count, a green dot when something inside is connected', () => {
  assert.deepEqual(folderBadge({ activeCount: 0, hasConnected: false }), { count: null, dot: null });
  assert.deepEqual(folderBadge({ activeCount: 2, hasConnected: true }), { count: 2, dot: 'on' });
  assert.deepEqual(folderBadge({ activeCount: 1, hasConnected: false }), { count: 1, dot: 'busy' });
  // Collapsed or not, the badge is the same: the connected item inside stays visible on the folder row.
  const f = folder('X', null, 0, { activeCount: 1, hasConnected: true, collapsed: true });
  assert.deepEqual(folderBadge(f), { count: 1, dot: 'on' });
});

test('subtrees and descendants', () => {
  assert.deepEqual(subtree(TREE, 'Clients').map((r) => r.id), ['Deep', 'd1', 'c1']);
  assert.deepEqual([...descendantFolders(TREE, 'Work')], ['Clients', 'Deep']);
  assert.deepEqual(subtree(TREE, 'Archive'), []);
  assert.deepEqual(subtree(TREE, 'nope'), []);
});

test('an older view model without a tree shows the rows at the top level', () => {
  const rows = [row('a'), row('b')];
  assert.deepEqual(treeOf({ rows }).map((r) => [r.id, r.depth, r.type]), [['a', 0, 'item'], ['b', 0, 'item']]);
  assert.deepEqual(treeOf({ rows, tree: [item('a', null, 0)] }).length, 1);
  assert.equal(colorToken('teal'), 'var(--folder-teal)');
  assert.equal(colorToken(null), null);
});

// MARK: - Contrast

const css = readFileSync(new URL('../../app.css', import.meta.url), 'utf8');
const PALETTE = ['red', 'orange', 'amber', 'yellow', 'lime', 'green', 'teal', 'cyan', 'blue', 'indigo', 'purple', 'pink'];

function block(dark: boolean): string {
  const media = css.indexOf('@media (prefers-color-scheme: dark)');
  return dark ? css.slice(media) : css.slice(0, media);
}

function token(name: string, dark: boolean): string {
  const m = block(dark).match(new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})\\s*;`));
  assert.ok(m, `--${name} (${dark ? 'dark' : 'light'}) is a #rrggbb value`);
  return m[1];
}

function luminance(hex: string): number {
  const channel = (i: number) => {
    const c = Number.parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

test('every palette colour keeps 4.5:1 on the card surface, light and dark', () => {
  for (const dark of [false, true]) {
    const surface = token('surface', dark);
    for (const name of PALETTE) {
      const ratio = contrast(token(`folder-${name}`, dark), surface);
      assert.ok(ratio >= 4.5, `${name} ${dark ? 'dark' : 'light'}: ${ratio.toFixed(2)}:1 on ${surface}`);
    }
  }
});

test('the palette tokens match the backend palette, distinct per mode', () => {
  for (const dark of [false, true]) {
    const values = PALETTE.map((n) => token(`folder-${n}`, dark).toLowerCase());
    assert.equal(new Set(values).size, 12);
  }
  const rust = readFileSync(new URL('../../../../../crates/core/src/vault/color.rs', import.meta.url), 'utf8');
  for (const name of PALETTE) assert.match(rust, new RegExp(`=> "${name}"`));
});
