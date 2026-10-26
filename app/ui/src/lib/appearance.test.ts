// node --test src/lib/ : the Appearance setting (one dark-mode mechanism, the three modes in the settings).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const css = readFileSync(new URL('../app.css', import.meta.url), 'utf8');
const menu = readFileSync(new URL('./Menu.svelte', import.meta.url), 'utf8');

test('dark mode has one source: prefers-color-scheme (the native theme drives it)', () => {
  assert.equal(css.match(/@media \(prefers-color-scheme: dark\)/g)?.length, 1);
  assert.match(css, /color-scheme: light dark;/);
  assert.doesNotMatch(css, /data-theme/);
});

test('the settings offer the three appearance modes', () => {
  for (const key of ["tr('Appearance')", "tr('Match System')", "tr('Light')", "tr('Dark')", 'api.setAppearance(']) {
    assert.ok(menu.includes(key), key);
  }
});
