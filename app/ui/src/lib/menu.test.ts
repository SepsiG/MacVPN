// node --test src/lib/ : the menu's version line (the backend's version, never one of the UI's own).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { engineLink, idleLine, versionLabel } from './format.ts';

const menu = readFileSync(new URL('./Menu.svelte', import.meta.url), 'utf8');
const markup = menu.slice(menu.indexOf('</script>'), menu.indexOf('<style>'));

test('the version label is "MacVPN <version>"', () => {
  assert.equal(versionLabel('1.1.0'), 'MacVPN 1.1.0');
  assert.equal(versionLabel('2.0.0-beta.1'), 'MacVPN 2.0.0-beta.1');
  assert.equal(versionLabel('1.5.0', 'MacVPN'), 'MacVPN 1.5.0');
});

test('the version label names the running product (WinVPN on Windows)', () => {
  assert.equal(versionLabel('1.5.0', 'WinVPN'), 'WinVPN 1.5.0');
  // Both places that show it (the menu's footer and the locked menu) pass the platform's product.
  const calls = markup.match(/versionLabel\([^)]*\)/g) ?? [];
  assert.equal(calls.length, 2);
  for (const call of calls) assert.equal(call, 'versionLabel(vm.appVersion, i18n.platform.product)');
});

test('the menu renders the view model version under the debug hint', () => {
  const hint = markup.indexOf("tr('Option-click a switch: debug mode')");
  const version = markup.indexOf('<p class="version">{versionLabel(vm.appVersion, i18n.platform.product)}</p>');
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

test('an idle row shows its reason, or only its type until the setup check gave one (never "Missing tool")', () => {
  assert.deepEqual(idleLine({ available: true, typeLabel: 'OpenVPN' }), { type: 'OpenVPN', status: null });
  // Before the first setup check the backend has no reason yet: a neutral line, not a guess.
  assert.deepEqual(idleLine({ available: false, typeLabel: 'OpenVPN' }), { type: 'OpenVPN', status: null });
  assert.deepEqual(idleLine({ available: false, typeLabel: 'L2TP', unavailableReason: 'Later.' }), {
    type: 'L2TP',
    status: 'Later.',
  });
  // The 1.x fallback is gone from the sources (its key stays in the table only for the frozen 1.4.0 baseline).
  for (const file of ['./status.ts', './format.ts']) {
    const source = readFileSync(new URL(file, import.meta.url), 'utf8');
    assert.ok(!source.includes('Missing tool'), file);
  }
});

test('an unavailable row links System Status when its engine can be installed', () => {
  const row = { available: false, typeLabel: 'OpenVPN', unavailableReason: 'Not installed: OpenVPN', setupLink: true };
  assert.deepEqual(idleLine(row), { type: 'OpenVPN', status: 'Not installed: OpenVPN' });
  assert.equal(engineLink(row), true);
  assert.equal(engineLink({ ...row, setupLink: undefined }), false);
  assert.equal(engineLink({ ...row, available: true }), false);
});

test('rows and the detail render the System Status link', () => {
  // The popover's cards, the Connections list's rows (the folder tree) and the detail header.
  for (const file of ['./MenuRow.svelte', './folders/FolderTree.svelte', './manage/Detail.svelte']) {
    const src = readFileSync(new URL(file, import.meta.url), 'utf8');
    assert.ok(src.includes('engineLink(') && src.includes("openWindow('setup')"), file);
  }
});

test('the "New" menu shows the note and System Status when no kind can be added', () => {
  const sidebar = readFileSync(new URL('./manage/Sidebar.svelte', import.meta.url), 'utf8');
  assert.ok(sidebar.includes('kinds.length === 0 && kindsNote'));
  assert.ok(sidebar.includes('<p class="note">{kindsNote}</p>'));
  assert.ok(sidebar.includes("tr('System Status…')") && sidebar.includes("openWindow('setup')"));
  const manage = readFileSync(new URL('./manage/Manage.svelte', import.meta.url), 'utf8');
  assert.ok(manage.includes('kindsNote={vm?.manage.kindsNote'));
});

test('the settings have the connection notifications switch', () => {
  assert.ok(menu.includes("tr('Connection Notifications')"));
  assert.ok(menu.includes('api.setConnectionNotifications('));
});
