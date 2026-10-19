// node --test src/lib/ : popovers and context menus stay inside the window.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { placePopover, pointAnchor, POPOVER_MARGIN } from './popover.ts';

const viewport = { width: 800, height: 600 };
const menu = { width: 260, height: 300 };
const inside = (p: { left: number; top: number }, size = menu, view = viewport) =>
  p.left >= POPOVER_MARGIN &&
  p.top >= POPOVER_MARGIN &&
  p.left + size.width <= view.width - POPOVER_MARGIN &&
  p.top + size.height <= view.height - POPOVER_MARGIN;

test('a menu right-aligned under a button at the left edge stays inside the window', () => {
  // The New button in a 250 pt sidebar: right-aligned, the menu would start at -22. It takes the button's left
  // edge instead when that fits, else it is clamped to the margin.
  const button = { left: 150, top: 12, right: 238, bottom: 38 };
  const p = placePopover(button, menu, viewport, { align: 'end', gap: 6 });
  assert.deepEqual(p, { left: 150, top: 44, flipped: false });
  assert.ok(inside(p));
  const small = { width: 380, height: 600 };
  const q = placePopover(button, menu, small, { align: 'end', gap: 6 });
  assert.equal(q.left, POPOVER_MARGIN);
  assert.ok(inside(q, menu, small));
  // Room on the left: right-aligned as asked.
  assert.equal(placePopover({ left: 500, top: 12, right: 588, bottom: 38 }, menu, viewport, { align: 'end' }).left, 588 - menu.width);
});

test('a context menu at the right edge opens to the left of the pointer', () => {
  const p = placePopover(pointAnchor(790, 100), menu, viewport);
  assert.equal(p.left, 790 - menu.width);
  assert.equal(p.top, 100);
  assert.ok(inside(p));
});

test('a context menu at the left edge stays at the pointer, inside the margin', () => {
  assert.deepEqual(placePopover(pointAnchor(20, 50), menu, viewport), { left: 20, top: 50, flipped: false });
  assert.equal(placePopover(pointAnchor(2, 50), menu, viewport).left, POPOVER_MARGIN);
});

test('no room below: shown above the anchor', () => {
  const p = placePopover(pointAnchor(100, 550), menu, viewport);
  assert.equal(p.flipped, true);
  assert.equal(p.top, 550 - menu.height);
  assert.ok(inside(p));
  const button = { left: 100, top: 500, right: 200, bottom: 520 };
  const q = placePopover(button, menu, viewport, { gap: 6 });
  assert.equal(q.flipped, true);
  assert.equal(q.top, 500 - 6 - menu.height);
});

test('no room on either side: the roomier side, clamped inside the window', () => {
  const tall = { width: 200, height: 500 };
  const p = placePopover(pointAnchor(100, 400), tall, viewport);
  assert.equal(p.flipped, true);
  assert.equal(p.top, POPOVER_MARGIN);
  assert.ok(inside(p, tall));
  const q = placePopover(pointAnchor(100, 150), tall, viewport);
  assert.equal(q.flipped, false);
  assert.equal(q.top, viewport.height - POPOVER_MARGIN - tall.height);
});

test('a viewport narrower than the popover: it starts at the margin', () => {
  const narrow = { width: 200, height: 600 };
  const p = placePopover(pointAnchor(150, 20), menu, narrow);
  assert.equal(p.left, POPOVER_MARGIN);
  const q = placePopover({ left: 100, top: 10, right: 190, bottom: 30 }, menu, narrow, { align: 'end' });
  assert.equal(q.left, POPOVER_MARGIN);
  // The action caps the width at the viewport less the margins: that size then fits exactly.
  const capped = { width: narrow.width - 2 * POPOVER_MARGIN, height: 100 };
  assert.ok(inside(placePopover(pointAnchor(150, 20), capped, narrow), capped, narrow));
});

test('every popover and context menu is placed by the shared action', () => {
  const read = (name: string) => readFileSync(new URL(name, import.meta.url), 'utf8');
  assert.match(read('./manage/Sidebar.svelte'), /class="menu"[^>]*use:popover=/);
  assert.match(read('./folders/FolderTree.svelte'), /class="menu"[^>]*use:popover=/);
  assert.match(read('./folders/ColorPicker.svelte'), /class="picker"[^>]*use:popover=/);
});
