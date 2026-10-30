// node --test: the Windows parts of the native VPN editors and the failure banner (WinVPN 2c Task 11). Without the
// platform flags (macOS) every text is macOS' own; the Svelte files use these helpers and render the platform notes
// only when the backend sends them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { EditorPlatformView } from '../api';
import { adminActionLabel, caConfirmMessage, nativeSaveLabel, nativeSaveNote, nativeSavedText } from './ras.ts';

const tr = (key: string, ...args: (string | number)[]) => (args.length ? `<${key}|${args.join('|')}>` : `<${key}>`);

const windows: EditorPlatformView = {
  reasons: [],
  summary: null,
  warnings: [],
  insecureCert: null,
  trustCa: false,
  caTrusted: null,
  l2tpCopy: false,
  noInstallStep: true,
  pskNote: null,
};

const source = (name: string) => readFileSync(new URL(`./${name}`, import.meta.url), 'utf8');

test('the L2TP form saves without a profile step on Windows and keeps the macOS texts otherwise', () => {
  assert.equal(nativeSaveLabel(windows, tr), '<Save>');
  assert.equal(nativeSaveLabel(undefined, tr), '<Save and Install Profile>');
  assert.equal(nativeSavedText(windows, tr), '<Saved>');
  assert.equal(nativeSavedText(undefined, tr), '<Profile opened, approve it in System Settings.>');
  assert.ok(nativeSaveNote(windows, tr).startsWith('<Saving writes the Windows VPN entry'));
  assert.ok(nativeSaveNote(undefined, tr).startsWith('<Saving creates and opens a configuration profile.'));
  const form = source('NativeForm.svelte');
  for (const call of ['nativeSaveLabel(platform, tr)', 'nativeSavedText(platform, tr)', 'nativeSaveNote(platform, tr)']) {
    assert.ok(form.includes(call), call);
  }
});

test('the L2TP form\'s save note on Linux is its own variant, not the Windows text (LinVPN L-b)', async () => {
  const { translate } = await import('../l10n-core.ts');
  const table = JSON.parse(readFileSync(new URL('../../../../../crates/core/l10n/strings.json', import.meta.url), 'utf8')).strings;
  const linux = { os: 'linux' as const, product: 'LinVPN' };
  const note = (language: 'en' | 'hu', os: typeof linux | { os: 'windows'; product: string }) =>
    nativeSaveNote(windows, (key) => translate(table, language, os, key, []));
  assert.equal(
    note('en', linux),
    "Saving stores this connection's settings in LinVPN at once; there is nothing to approve. LinVPN creates its NetworkManager connection only when connecting, and passes the password then.",
  );
  assert.equal(
    note('hu', linux),
    'Mentéskor a LinVPN azonnal eltárolja a kapcsolat beállításait, nincs mit jóváhagyni. A NetworkManager-kapcsolatot csak csatlakozáskor hozza létre, és a jelszót is akkor adja át.',
  );
  // Windows keeps its text (the product name replaced as before).
  assert.equal(
    note('en', { os: 'windows', product: 'WinVPN' }),
    'Saving writes the Windows VPN entry of this connection at once; there is nothing to approve. The password is not in it: WinVPN passes it when connecting.',
  );
});

test('the error banner names the administrator step', () => {
  assert.equal(adminActionLabel('allow-l2tp-behind-nat', tr), '<Allow L2TP Behind NAT…>');
  assert.equal(adminActionLabel('trust-ca-in-windows', tr), '<Trust This CA in Windows…>');
  const detail = source('Detail.svelte');
  const banner = detail.slice(detail.indexOf("{#if row.state === 'failed'}"), detail.indexOf("{:else if row.state === 'awaitingAuth'}"));
  assert.ok(banner.includes('row.adminAction'), 'the button only with the backend’s action');
  assert.ok(banner.includes('<AdminActionButton'), banner);
});

test('the CA confirmation shows the subject, the validity, the fingerprint and the warning', () => {
  const message = caConfirmMessage(
    { subject: 'CN=Lab CA', notBefore: 1_700_000_000, notAfter: 2_000_000_000, sha256: 'AB:CD', warning: 'Every program…' },
    'en',
    tr,
  );
  assert.deepEqual(message.split('\n'), [
    '<Subject: %@|CN=Lab CA>',
    '<Valid from %@ to %@|Nov 14, 2023|May 18, 2033>',
    '<SHA-256 fingerprint: %@|AB:CD>',
    'Every program…',
  ]);
});

test('the platform notes are rendered only when the backend sends them', () => {
  // The yellow reasons above the form and the grey summary and warnings under it come from `PlatformNotes`, which
  // renders nothing without `platform`.
  const notes = source('PlatformNotes.svelte');
  assert.ok(notes.includes('{#if platform'), notes);
  for (const name of ['NativeForm.svelte', 'SstpForm.svelte', 'TextEditor.svelte']) {
    const form = source(name);
    assert.ok(form.includes('<PlatformNotes'), name);
  }
  // SSTP: "No verification" is disabled with Windows' reason; the CA can be trusted, or is shown as trusted.
  const sstp = source('SstpForm.svelte');
  assert.ok(sstp.includes('disabled={platform?.insecureCert'), 'the option is disabled only with the reason');
  assert.ok(sstp.includes('<TrustCa'), sstp);
  // IKEv2 picks the PEM file; SSTP uses its own CA.
  assert.ok(source('TextEditor.svelte').includes('pick={true}'));
  assert.ok(sstp.includes('pick={false}'));
  // Cisco: the copy button, only with the flag.
  assert.ok(source('NativeForm.svelte').includes('platform?.l2tpCopy'));
  // The system VPN's PSK note.
  assert.ok(source('SystemDetail.svelte').includes('view?.platform?.pskNote'));
});
