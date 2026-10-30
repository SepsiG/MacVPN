// node --test src/lib/ : System Status' engine rows (WinVPN): none on macOS, three in order on Windows.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { engineRows, nmRows, opensInstalledApps, rasRow, uninstallTexts } from './setup.ts';
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

test('no uninstall area under the engine note (LinVPN in L-a: the app installed nothing of its own)', () => {
  const page = readFileSync(new URL('./Setup.svelte', import.meta.url), 'utf8');
  const danger = page.lastIndexOf('{#if', page.indexOf('<div class="card danger">'));
  const condition = page.slice(danger, page.indexOf('}', danger) + 1);
  assert.equal(condition, '{#if !setup?.engineNote && (!setup?.systemUninstall || setup.accountCleanup)}');
});

test('LinVPN: the system uninstall note alone, no "Open Installed Apps…" and no uninstall area', () => {
  // The backend's note (`apt remove linvpn`) replaces the uninstall area: `systemUninstall` without `accountCleanup`.
  assert.equal(opensInstalledApps('linux'), false);
  assert.equal(opensInstalledApps('windows'), true);
  const page = readFileSync(new URL('./Setup.svelte', import.meta.url), 'utf8');
  const card = page.slice(page.indexOf('{#if setup?.systemUninstall}'), page.indexOf('<div class="card danger">'));
  assert.ok(card.includes('<div class="card system-uninstall">'), card);
  const button = card.indexOf("tr('Open Installed Apps…')");
  assert.ok(button > card.indexOf('{#if opensInstalledApps(i18n.platform.os)}'), card);
  assert.ok(button < card.indexOf('{/if}'), 'the button only inside the platform check');
});

test('no NetworkManager rows without them (macOS, Windows)', () => {
  assert.deepEqual(nmRows({}, (key) => key), []);
});

test('the NetworkManager rows (LinVPN): NetworkManager, then the kinds in a fixed order, Install where a package is missing', () => {
  const nm = {
    networkmanager: row(true, 'NetworkManager 1.54.3'),
    // The platform's order differs from the window's.
    kinds: [
      { kind: 'sstp', row: row(false, 'Not installed'), packages: 'network-manager-sstp', action: 'install' as const },
      { kind: 'cisco', row: row(true, 'Installed'), packages: 'network-manager-vpnc' },
      { kind: 'strongswan', row: row(true, 'EAP needs libcharon-extauth-plugins'), packages: 'libcharon-extauth-plugins', action: 'install' as const },
      { kind: 'l2tp', row: row(true, 'Installed'), packages: 'network-manager-l2tp' },
      { kind: 'openvpn', row: row(true, 'OpenVPN 2.7.0'), packages: 'network-manager-openvpn' },
      { kind: 'wireguard', row: row(true, 'Built in'), packages: '' },
    ],
  };
  const rows = nmRows({ nm }, (key) => `<${key}>`);
  assert.deepEqual(
    rows.map((r) => r.title),
    ['<NetworkManager>', 'WireGuard', 'OpenVPN', 'L2TP/IPsec', 'IKEv2', 'Cisco IPsec', 'SSTP'],
  );
  assert.deepEqual(rows[0], { id: 'networkmanager', title: '<NetworkManager>', row: nm.networkmanager });
  assert.deepEqual(
    rows.map((r) => r.install ?? null),
    [null, null, null, null, { buttonId: 'nm-install-strongswan', kind: 'strongswan' }, null, { buttonId: 'nm-install-sstp', kind: 'sstp' }],
  );
  assert.equal(rows[6].id, 'nm-sstp');
  assert.equal(rows[6].row, nm.kinds[0].row);
});

test('the NetworkManager rows are rendered where the engine rows are, with the Install button', () => {
  const page = readFileSync(new URL('./Setup.svelte', import.meta.url), 'utf8');
  const nmBranch = page.slice(page.indexOf('{:else if setup && nmItems.length > 0}'), page.indexOf('{:else if setup?.homebrew'));
  assert.ok(nmBranch.includes('{#each nmItems as item'), nmBranch);
  assert.ok(nmBranch.includes('id={item.install.buttonId}'), nmBranch);
  assert.ok(nmBranch.includes('runNmInstall(install.kind)'), nmBranch);
});
