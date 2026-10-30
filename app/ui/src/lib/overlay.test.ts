// node --test src/lib/ : the card panel's overlay (Linux only; macOS and Windows keep their popover window).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { OVERLAY_CLASS, cardRect, usesOverlay } from './overlay.ts';

test('only the menu window on Linux is the overlay', () => {
  assert.equal(usesOverlay('linux', 'menu'), true);
  assert.equal(usesOverlay('macos', 'menu'), false);
  assert.equal(usesOverlay('windows', 'menu'), false);
  for (const label of ['manage', 'setup', 'update', 'vault-unlock', 'prompt-1']) {
    assert.equal(usesOverlay('linux', label), false, label);
  }
});

test('the card rectangle is what the page laid out', () => {
  const rect = { left: 875, top: 8, width: 330, height: 412.5, right: 1205, bottom: 420.5, x: 875, y: 8 };
  assert.deepEqual(cardRect(rect), { left: 875, top: 8, width: 330, height: 412.5 });
});

test('the class is set before the first render, from the platform reply', () => {
  const main = readFileSync(new URL('../main.ts', import.meta.url), 'utf8');
  const set = main.indexOf('classList.add(OVERLAY_CLASS)');
  assert.ok(set > 0 && set < main.indexOf('mount(App'));
  assert.match(main, /usesOverlay\(i18n\.platform\.os, getCurrentWindow\(\)\.label\)/);
});

test('the overlay draws only the card at the top-right, on a transparent page', () => {
  const css = readFileSync(new URL('../app.css', import.meta.url), 'utf8');
  assert.match(css, new RegExp(`html\\.${OVERLAY_CLASS},\\s*html\\.${OVERLAY_CLASS} body \\{\\s*background: transparent;`));
  const menu = readFileSync(new URL('./Menu.svelte', import.meta.url), 'utf8');
  const style = menu.slice(menu.indexOf('<style>'));
  const rule = style.slice(style.indexOf(`:global(html.${OVERLAY_CLASS}) main {`));
  assert.ok(rule.length < style.length, 'the overlay rule');
  for (const line of ['position: absolute;', 'top: 8px;', 'right: 8px;', 'width: 330px;']) {
    assert.ok(rule.slice(0, rule.indexOf('}')).includes(line), line);
  }
  // The menu reports the card (not a window height) in the overlay, also when the window itself resizes.
  const script = menu.slice(0, menu.indexOf('</script>'));
  assert.match(script, /api\.setMenuCard\(/);
  assert.match(script, /addEventListener\('resize', measure\)/);
});
