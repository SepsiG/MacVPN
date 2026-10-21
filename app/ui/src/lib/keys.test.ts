// node --test src/lib/ : the primary-modifier shortcut rule (Cmd on macOS, Ctrl on Windows and Linux).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isPrimaryShortcut, type ShortcutEvent } from './keys.ts';

const press = (key: string, mods: Partial<ShortcutEvent> = {}): ShortcutEvent => ({
  key,
  metaKey: false,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  ...mods,
});

test('Cmd+S on macOS', () => {
  assert.ok(isPrimaryShortcut(press('s', { metaKey: true }), 's', 'macos'));
  assert.ok(isPrimaryShortcut(press('S', { metaKey: true }), 's', 'macos'));
  assert.ok(!isPrimaryShortcut(press('s', { ctrlKey: true }), 's', 'macos'));
  assert.ok(!isPrimaryShortcut(press('s', { metaKey: true, ctrlKey: true }), 's', 'macos'));
  assert.ok(!isPrimaryShortcut(press('s'), 's', 'macos'));
  assert.ok(!isPrimaryShortcut(press('f', { metaKey: true }), 's', 'macos'));
});

test('Ctrl+S on Windows and Linux', () => {
  for (const os of ['windows', 'linux'] as const) {
    assert.ok(isPrimaryShortcut(press('s', { ctrlKey: true }), 's', os));
    assert.ok(!isPrimaryShortcut(press('s', { metaKey: true }), 's', os));
    assert.ok(!isPrimaryShortcut(press('s', { ctrlKey: true, metaKey: true }), 's', os));
  }
});

test('never with Alt or Shift', () => {
  assert.ok(!isPrimaryShortcut(press('f', { metaKey: true, altKey: true }), 'f', 'macos'));
  assert.ok(!isPrimaryShortcut(press('f', { metaKey: true, shiftKey: true }), 'f', 'macos'));
  assert.ok(!isPrimaryShortcut(press('f', { ctrlKey: true, altKey: true }), 'f', 'windows'));
  assert.ok(!isPrimaryShortcut(press('f', { ctrlKey: true, shiftKey: true }), 'f', 'windows'));
});
