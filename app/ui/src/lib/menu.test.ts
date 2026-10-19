// node --test src/lib/ : the menu's version line (the backend's version, never one of the UI's own).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { versionLabel } from './format.ts';

const menu = readFileSync(new URL('./Menu.svelte', import.meta.url), 'utf8');
const markup = menu.slice(menu.indexOf('</script>'), menu.indexOf('<style>'));

test('the version label is "MacVPN <version>"', () => {
  assert.equal(versionLabel('1.1.0'), 'MacVPN 1.1.0');
  assert.equal(versionLabel('2.0.0-beta.1'), 'MacVPN 2.0.0-beta.1');
});

test('the menu renders the view model version under the debug hint', () => {
  const hint = markup.indexOf("tr('Option-click a switch: debug mode')");
  const version = markup.indexOf('<p class="version">{versionLabel(vm.appVersion)}</p>');
  assert.ok(hint > 0, 'the debug hint is in the menu');
  assert.ok(version > hint, 'the version line follows the hint');
  // Inside the main menu branch, after the footer: not in the notice or the quit question.
  assert.ok(version > markup.indexOf('{:else}'));
  assert.ok(version < markup.lastIndexOf('{/if}\n</main>'));
});

test('the UI never hard-codes a version', () => {
  assert.doesNotMatch(markup, /MacVPN \d/);
  assert.doesNotMatch(readFileSync(new URL('./format.ts', import.meta.url), 'utf8'), /\d+\.\d+\.\d+/);
});

test('the measured list height includes its padding (the window cap would clip the bottom otherwise)', () => {
  const styles = menu.slice(menu.indexOf('<style>'));
  const list = styles.slice(styles.indexOf('  .list {'), styles.indexOf('}', styles.indexOf('  .list {')));
  assert.match(list, /box-sizing: border-box;/);
});

test('the page background fills the rounded popover to its edges', () => {
  const css = readFileSync(new URL('../app.css', import.meta.url), 'utf8');
  const base = css.slice(css.indexOf('html,\nbody {'), css.indexOf('}', css.indexOf('html,\nbody {')));
  assert.match(base, /margin: 0;/);
  assert.match(base, /background: var\(--background\);/);
});
