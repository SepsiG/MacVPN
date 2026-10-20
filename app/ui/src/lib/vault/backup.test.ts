// node --test: the backup and restore windows' rules, and their views rendered through Svelte's server renderer
// (compiled on the fly by the module hooks below, as in credentials.test.ts): the warning text, the strength hint,
// "Back Up…" only for a valid password, the "Use my master password" confirmation step, the risky connections
// listed before the choice, the replace confirmation naming the count, and the preferences step with the control
// API never ticked at first.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';
import { compile, compileModule } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';
import { backupDate, characters, initialTicks, passwordProblem, passwordStrength, tickedKeys } from './backup.ts';
import type { RestoreOutcome, RestoreSummary } from './backupApi.ts';

registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith('.') && !/\.(ts|js|json)$/.test(specifier)) {
      for (const candidate of [specifier, `${specifier}.ts`]) {
        try {
          return next(candidate, context);
        } catch {
          // The next candidate.
        }
      }
    }
    return next(specifier, context);
  },
  load(url, context, next) {
    if (url.endsWith('.svelte')) {
      const file = fileURLToPath(url);
      const { js } = compile(readFileSync(file, 'utf8'), { filename: file, generate: 'server', css: 'injected' });
      return { format: 'module', source: js.code, shortCircuit: true };
    }
    if (url.endsWith('.svelte.ts')) {
      const file = fileURLToPath(url);
      const { js } = compileModule(stripTypeScriptTypes(readFileSync(file, 'utf8')), { filename: file, generate: 'server' });
      return { format: 'module', source: js.code, shortCircuit: true };
    }
    if (url.endsWith('.json')) {
      return { format: 'module', source: `export default ${readFileSync(fileURLToPath(url), 'utf8')};`, shortCircuit: true };
    }
    return next(url, context);
  },
});

const table = JSON.parse(readFileSync(new URL('../../../../../crates/core/l10n/strings.json', import.meta.url), 'utf8')).strings;

async function renderView(name: string, props: Record<string, unknown>, language: 'en' | 'hu' = 'en'): Promise<string> {
  const { setLanguage } = (await import('../l10n.svelte')) as { setLanguage: (l: string) => void };
  setLanguage(language);
  const { default: View } = (await import(`./${name}.svelte`)) as { default: Component<Record<string, unknown>> };
  return render(View, { props }).body;
}

const noop = () => {};

function backupProps(extra: Record<string, unknown> = {}) {
  return { step: 'form', onsave: noop, onaskmaster: noop, onconfirmmaster: noop, oncancel: noop, ondone: noop, ...extra };
}

/// The `<button>` with this class, as rendered.
function button(html: string, cls: string): string {
  const m = new RegExp(`<button[^>]*class="[^"]*\\b${cls}\\b[^"]*"[^>]*>`).exec(html);
  assert.ok(m, `no ${cls} button in ${html}`);
  return m[0];
}

const WARNING = 'Anyone with this file and its password can read all your VPN credentials.';

test('characters and the strength hint (never a block)', () => {
  assert.equal(characters('👍🏽 ok'), 4);
  assert.equal(passwordStrength('abc'), 'weak');
  assert.equal(passwordStrength('abcdefghij'), 'weak');
  assert.equal(passwordStrength('abcdefghi1'), 'fair');
  assert.equal(passwordStrength('Abcdefgh1!xy'), 'strong');
  assert.equal(passwordStrength('correct horse battery'), 'strong');
});

test('the password rule: 10 characters and the same twice; the master password only needs a value', () => {
  assert.equal(passwordProblem('', '', false), 'empty');
  assert.equal(passwordProblem('short', 'short', false), 'short');
  assert.equal(passwordProblem('long enough!', 'long enough', false), 'mismatch');
  assert.equal(passwordProblem('long enough!', 'long enough!', false), 'master');
  assert.equal(passwordProblem('long enough!', 'long enough!', false, 'the master'), null);
  assert.equal(passwordProblem('x', '', true), null);
  assert.equal(passwordProblem('', '', true), 'empty');
});

test('preference ticks: as suggested, never the control API; only the ticked keys are sent', () => {
  const rows = [
    { key: 'autoCheck', ticked: true },
    { key: 'controlApi', ticked: true },
    { key: 'autoUnlock', ticked: false },
  ];
  const ticks = initialTicks(rows);
  assert.deepEqual(ticks, { autoCheck: true, controlApi: false, autoUnlock: false });
  assert.deepEqual(tickedKeys(rows, ticks), ['autoCheck']);
  assert.deepEqual(tickedKeys(rows, { ...ticks, controlApi: true }), ['autoCheck', 'controlApi']);
  assert.match(backupDate(1_792_400_000), /^\d{4}-\d{2}-\d{2}$/);
});

test('the backup window shows the warning (EN and HU)', async () => {
  const en = await renderView('BackupView', backupProps());
  assert.ok(en.includes(WARNING), en);
  const hu = await renderView('BackupView', backupProps(), 'hu');
  assert.ok(hu.includes(table[WARNING].hu), hu);
  assert.ok(!hu.includes(WARNING));
});

test('Back Up… needs a valid password; no form, no default button', async () => {
  for (const [password, repeat, enabled] of [
    ['', '', false],
    ['short', 'short', false],
    ['long enough!', 'long enough?', false],
    ['long enough!', 'long enough!', true],
  ] as const) {
    const html = await renderView('BackupView', backupProps({ password, repeat, master: 'the master pw' }));
    assert.equal(!/disabled/.test(button(html, 'save')), enabled, `${password} / ${repeat}`);
    assert.doesNotMatch(html, /<form|type="submit"|autofocus/);
  }
  // Without the master password: not yet.
  const noMaster = await renderView('BackupView', backupProps({ password: 'long enough!', repeat: 'long enough!' }));
  assert.match(button(noMaster, 'save'), /disabled/);
  const weak = await renderView('BackupView', backupProps({ password: 'abc' }));
  assert.match(weak, /class="meter weak"/);
});

test('"Use my master password" needs its own confirmation step, then asks for the master password once', async () => {
  const form = await renderView('BackupView', backupProps());
  button(form, 'use-master');
  assert.doesNotMatch(form, /role="alertdialog"/);
  assert.match(form, /data-field="password"/);
  assert.match(form, /data-field="repeat"/);
  // The master password is always asked too (the backend checks it before every backup).
  assert.match(form, /data-field="current-master"/);
  assert.doesNotMatch(form, /data-field="master"/);

  const asking = await renderView('BackupView', backupProps({ step: 'confirmMaster' }));
  assert.match(asking, /role="alertdialog"/);
  assert.ok(asking.includes('Use your master password for this backup?'));
  button(asking, 'confirm-master');
  button(asking, 'cancel-master');
  // Still the own password until it is confirmed.
  assert.doesNotMatch(asking, /data-field="master"/);

  const master = await renderView('BackupView', backupProps({ useMaster: true, password: 'x' }));
  assert.match(master, /data-field="master"/);
  assert.doesNotMatch(master, /data-field="repeat"/);
  assert.ok(!/disabled/.test(button(master, 'save')));
  button(master, 'separate');
});

test('saving shows the progress and disables everything; done names the file', async () => {
  const saving = await renderView('BackupView', backupProps({ step: 'saving', password: 'long enough!', repeat: 'long enough!' }));
  assert.match(saving, /class="spinner"/);
  assert.match(button(saving, 'save'), /disabled/);
  assert.match(button(saving, 'cancel'), /disabled/);
  const done = await renderView('BackupView', backupProps({ step: 'done', savedName: 'MacVPN-backup-2026-10-19.macvpnbackup' }));
  assert.ok(done.includes('MacVPN-backup-2026-10-19.macvpnbackup'));
  button(done, 'done');
});

const summary: RestoreSummary = {
  created: 1_792_400_000,
  appVersion: '1.2.0',
  connections: 12,
  folders: 3,
  credentials: 2,
  added: 4,
  conflicts: 13,
  lostOnReplace: 5,
  lostSubscriptions: [],
  lostAdminKeys: [],
  lostPublications: [],
  lostTotal: 5,
  acknowledgedRisky: ['Office up-script'],
  nativeProfiles: 1,
  fresh: false,
};

function planProps(extra: Record<string, unknown> = {}) {
  return { summary, onrestore: noop, onconfirm: noop, oncancelconfirm: noop, onbackupfirst: noop, onback: noop, ...extra };
}

test('the plan lists the risky connections before the choice, with the numbers', async () => {
  const html = await renderView('RestorePlanView', planProps());
  const risky = html.indexOf('Office up-script');
  assert.ok(risky > 0);
  assert.ok(risky < html.indexOf('name="restore-mode"'), 'the risky list comes first');
  assert.ok(html.includes('Adds what is missing here: 4 new items. Already here: 13.'));
  assert.ok(html.includes('Not in the backup, deleted: 5 items.'));
  // The single conflict question, with the three answers.
  assert.equal((html.match(/name="conflict"/g) ?? []).length, 3);
  assert.doesNotMatch(html, /role="alertdialog"/);
});

test('replace asks again, naming the count, and offers a backup first', async () => {
  const html = await renderView('RestorePlanView', planProps({ choice: 'replace', confirming: true }));
  assert.match(html, /role="alertdialog"/);
  assert.ok(html.includes('are deleted: 5 items.'));
  button(html, 'backup-first');
  button(html, 'confirm-replace');
  const hu = await renderView('RestorePlanView', planProps({ choice: 'replace', confirming: true }), 'hu');
  assert.ok(hu.includes('5 elem'), hu);
});

test('replace names the team catalogs, admin keys and publications it takes', async () => {
  const catalogs = { ...summary, lostSubscriptions: ['Acme VPN'], lostAdminKeys: ['primary'], lostPublications: ['Published'], lostTotal: 8 };
  for (const confirming of [false, true]) {
    const html = await renderView('RestorePlanView', planProps({ summary: catalogs, choice: 'replace', confirming }));
    assert.ok(html.includes('Team catalog subscriptions removed: Acme VPN'), html);
    assert.ok(html.includes('Admin keys replaced by the backup’s: 1'));
    assert.ok(html.includes('Publications replaced by the backup’s: Published'));
    assert.ok(html.includes('Admin keys and publications the backup does not have stay on this Mac.'));
  }
  const hu = await renderView('RestorePlanView', planProps({ summary: catalogs, choice: 'replace', confirming: true }), 'hu');
  assert.ok(hu.includes('Acme VPN') && hu.includes('Published'), hu);
  assert.doesNotMatch(hu, /Team catalog subscriptions removed/);
  // Nothing of it: no lines.
  const plain = await renderView('RestorePlanView', planProps({ choice: 'replace', confirming: true }));
  assert.doesNotMatch(plain, /Team catalog subscriptions removed|replaced by the backup/);
  // The confirmation sends the whole count.
  const restore = readFileSync(fileURLToPath(new URL('./Restore.svelte', import.meta.url)), 'utf8');
  assert.match(restore, /backupApi\.replace\(summary!\.lostTotal\)/);
});

test('a fresh restore shows the numbers and the risky list, no merge question', async () => {
  const html = await renderView('RestorePlanView', planProps({ summary: { ...summary, fresh: true, conflicts: 0, lostOnReplace: 0 } }));
  assert.ok(html.includes('Office up-script'));
  assert.doesNotMatch(html, /name="restore-mode"/);
  assert.ok(html.includes('Continue'));
});

const outcome: RestoreOutcome = {
  preferences: [
    { key: 'autoCheck', backedUp: false, current: true, ticked: true },
    { key: 'launchAtLogin', backedUp: true, current: true, ticked: false },
    { key: 'controlApi', backedUp: true, current: false, ticked: false },
  ],
  nativeProfiles: [{ id: '11111111-2222-4333-8444-555555555555', name: 'Branch L2TP', installed: false }],
  skippedCatalogItems: [],
};

test('a merge names the team catalog items it did not restore', async () => {
  const plain = await renderView('RestoreAfterView', afterProps());
  assert.doesNotMatch(plain, /skipped-catalog/);
  const skipped = await renderView('RestoreAfterView', afterProps({ outcome: { ...outcome, skippedCatalogItems: ['Team folder', 'Team Two'] } }));
  assert.ok(skipped.includes('A team catalog provides these, so the backup’s copies were not restored: Team folder, Team Two'), skipped);
  const hu = await renderView('RestoreAfterView', afterProps({ outcome: { ...outcome, skippedCatalogItems: ['Team Two'] } }), 'hu');
  assert.ok(hu.includes('Team Two') && !hu.includes('A team catalog provides these'), hu);
});

function afterProps(extra: Record<string, unknown> = {}) {
  return { outcome, ticks: initialTicks(outcome.preferences), onapply: noop, onreinstall: noop, ondone: noop, ...extra };
}

/// The checkbox of a preference row, as rendered.
function preferenceBox(html: string, key: string): string {
  const row = html.slice(html.indexOf(`data-preference="${key}"`));
  const m = /<input[^>]*type="checkbox"[^>]*>/.exec(row);
  assert.ok(m, `no checkbox for ${key}`);
  return m[0];
}

test('each preference has its own checkbox; the control API is not ticked; nothing is applied silently', async () => {
  const html = await renderView('RestoreAfterView', afterProps());
  assert.match(preferenceBox(html, 'autoCheck'), /checked/);
  assert.doesNotMatch(preferenceBox(html, 'controlApi'), /checked/);
  assert.doesNotMatch(preferenceBox(html, 'controlApi'), /disabled/);
  // The same value here: nothing to apply.
  assert.match(preferenceBox(html, 'launchAtLogin'), /disabled/);
  button(html, 'apply');
  assert.match(html, /Reinstall 1 Native Profile(?!s)/, 'one profile: the singular');
  assert.ok(html.includes('Branch L2TP'));
  const applied = await renderView('RestoreAfterView', afterProps({ applied: [] }));
  assert.ok(applied.includes('The selected preferences were applied.'));
  assert.match(preferenceBox(applied, 'autoCheck'), /disabled/);
});
