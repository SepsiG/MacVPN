// node --test src/lib/ : System Status' engine rows (WinVPN): none on macOS, three in order on Windows.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { engineRows, rasRow, uninstallTexts } from './setup.ts';
import { readFileSync } from 'node:fs';

const row = (ok: boolean, detail: string) => ({ ok, detail });

test('no engine rows without an engine (macOS)', () => {
  assert.deepEqual(engineRows({}, (key) => key), []);
});

test('the service, OpenVPN and WireGuard rows in order, with their titles', () => {
  const engine = {
    service: row(true, 'Running'),
    openvpn: row(false, 'Not installed'),
    wireguard: row(true, 'wireguard-nt 0.10.1'),
    openvpnAction: 'install' as const,
    laterNote: 'Later.',
  };
  const rows = engineRows({ engine }, (key) => `<${key}>`);
  assert.deepEqual(
    rows.map((r) => [r.id, r.title, r.row]),
    [
      ['service', '<WinVPN Service>', engine.service],
      ['openvpn', '<OpenVPN Community>', engine.openvpn],
      ['wireguard', '<WireGuard>', engine.wireguard],
    ],
  );
});

test('the uninstall area: MacVPN\'s own uninstall without an account clean-up (macOS)', () => {
  const texts = uninstallTexts({}, (key) => key);
  assert.equal(texts.button, 'Uninstall MacVPN…');
  assert.equal(texts.title, 'Uninstall MacVPN');
  assert.equal(texts.confirm, 'Uninstall');
  assert.ok(texts.message.startsWith('After you enter an admin password'));
  assert.deepEqual(uninstallTexts({ accountCleanup: false }, (key) => key), texts);
});

test('the uninstall area: "Remove WinVPN from This Account…" where the platform offers the clean-up (WinVPN)', () => {
  const texts = uninstallTexts({ accountCleanup: true }, (key) => `<${key}>`);
  assert.equal(texts.button, '<Remove WinVPN from This Account…>');
  assert.equal(texts.title, '<Remove WinVPN from This Account>');
  assert.equal(texts.confirm, '<Remove>');
  assert.ok(texts.message.includes('Your own Windows VPNs are kept.'));
  assert.ok(texts.caption.startsWith('<Before you uninstall'));
});

test('the Windows VPN client row: none on macOS, its title and row on Windows (WinVPN 2c)', () => {
  assert.equal(rasRow({}, (key) => key), null);
  const ras = row(true, 'Built into Windows');
  assert.deepEqual(rasRow({ ras }, (key) => `<${key}>`), { id: 'ras', title: '<Windows VPN client>', row: ras });
  // Shown under the engine rows and under the engine note (the native VPNs need no WinVPN Service); the note that
  // the native VPNs come later is gone (the backend sends no `laterNote` text any more).
  const page = readFileSync(new URL('./Setup.svelte', import.meta.url), 'utf8');
  const noteBranch = page.slice(page.indexOf('{#if setup?.engineNote}'), page.indexOf('{:else if setup?.engine}'));
  const engineBranch = page.slice(page.indexOf('{:else if setup?.engine}'), page.indexOf('{:else if setup?.homebrew'));
  assert.ok(noteBranch.includes('{@render windowsVpnClient()}'), noteBranch);
  assert.ok(engineBranch.includes('{@render windowsVpnClient()}'), engineBranch);
});
