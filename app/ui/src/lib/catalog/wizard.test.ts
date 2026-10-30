// node --test: the publish wizard's rules (wizard.ts) and the publishing views rendered through Svelte's server
// renderer (compiled on the fly by the module hooks below, as in vault.test.ts): the wizard's steps, the subtree
// selection, the inline-key tick gating, the team key shown once and gone after "I Saved It", the rotate dialog's
// revoke text, and the copy of the subscription string that never shows the string or echoes the password.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';
import { compile, compileModule } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';
import { folder, item, row, TREE, ROWS } from '../folders/fixtures.ts';
import type { PublicationView, PublishPreview } from './publishApi.ts';
import {
  closeReveal,
  covered,
  defaultSlots,
  droppedSuccessorIn,
  fieldKey,
  firstStep,
  fromSelection,
  groupMatches,
  isPicked,
  nextStep,
  NO_TICKS,
  NOTHING,
  offered,
  pickGroup,
  pickedConnections,
  previousStep,
  reveal,
  reviewBlockers,
  rotateNeedsReview,
  savedIt,
  selectionOf,
  stepsOf,
  teamKeyGroups,
  toggle,
  withTick,
} from './wizard.ts';

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

const KEY = 'TEAM-7K3Q-M9XA-2PZD-F4TR-8VBN-H6WC-0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ';
const noop = () => {};

async function html(path: string, props: Record<string, unknown>): Promise<string> {
  const { default: view } = (await import(path)) as { default: Component<Record<string, unknown>> };
  return render(view, { props }).body;
}

function button(out: string, cls: string): string {
  const m = new RegExp(`<button[^>]*class="[^"]*\\b${cls}\\b[^"]*"[^>]*>`).exec(out);
  assert.ok(m, `no ${cls} button`);
  return m[0];
}

const preview = (extra: Partial<PublishPreview> = {}): PublishPreview => ({
  counts: { folders: 1, connections: 2, slots: 0, secrets: 0 },
  personal: [],
  inlineSecrets: [],
  availableSecrets: [],
  availableSlots: [],
  refused: [],
  successorDroppedIn: [],
  ...extra,
});

const publication: PublicationView = {
  id: 'P1',
  name: 'Acme VPN',
  version: 3,
  lastPublished: 1_760_000_000,
  fileName: 'Acme VPN.macvpncatalog',
  changed: 0,
  selection: { folders: ['Work'], connections: ['r1'], secrets: [], slots: [], inlineSecrets: [] },
};

// MARK: - wizard.ts

test('the steps of each flow', () => {
  assert.deepEqual(stepsOf('new'), ['select', 'review', 'name', 'done']);
  assert.deepEqual(stepsOf('again'), ['select', 'review', 'done']);
  assert.deepEqual(stepsOf('rotate'), ['review', 'done'], 'a rotation reviews before it saves');
  assert.equal(firstStep('new'), 'select');
  assert.equal(firstStep('again'), 'review');
  assert.equal(firstStep('rotate'), 'review');
  assert.equal(nextStep('new', 'select'), 'review');
  assert.equal(nextStep('new', 'review'), 'name');
  assert.equal(nextStep('again', 'review'), 'done');
  assert.equal(nextStep('new', 'done'), null);
  assert.equal(previousStep('new', 'name'), 'review');
  assert.equal(previousStep('again', 'review'), 'select');
  assert.equal(previousStep('rotate', 'review'), null);
  assert.equal(previousStep('new', 'done'), null, 'nothing goes back from the result');
});

test('a ticked folder brings its subtree, which then cannot be unticked one by one', () => {
  let picked = toggle(TREE, NOTHING, TREE[5], true); // w1
  picked = toggle(TREE, picked, TREE[4], true); // c1
  picked = toggle(TREE, picked, TREE[0], true); // Work
  assert.deepEqual([...picked.folders], ['Work']);
  assert.deepEqual([...picked.connections], [], 'the rows inside the folder go with it');
  for (const r of TREE.slice(1, 8)) {
    assert.ok(isPicked(TREE, picked, r), r.id);
    assert.ok(covered(TREE, picked, r.id), r.id);
  }
  assert.ok(!isPicked(TREE, picked, TREE[9]), 'r1 is outside');
  assert.equal(toggle(TREE, picked, TREE[3], false), picked, 'a covered row does not change');
  assert.equal(pickedConnections(TREE, TREE, picked), 5);
  const withRoot = toggle(TREE, picked, TREE[9], true);
  assert.deepEqual(selectionOf(TREE, withRoot, NO_TICKS, null), { folders: ['Work'], connections: ['r1'], secrets: [], slots: [], inlineSecrets: [] });
  assert.deepEqual([...toggle(TREE, picked, TREE[0], false).folders], []);
});

test('system VPNs, team catalog connections and team folders are not offered', () => {
  const tree = [folder('Team', null, 0), item('t1', 'Team', 1), folder('Mine', null, 0), item('m1', 'Mine', 1), item('sys', null, 0), item('cat', null, 0)];
  const rows = [row('t1'), row('m1'), { ...row('sys'), managed: false }, { ...row('cat'), catalog: { catalogId: 'C', name: 'Team', pendingRemoval: false, profileOutdated: false } }];
  assert.deepEqual(
    offered(tree, rows, { Team: 'C' }).map((r) => r.id),
    ['Mine', 'm1'],
  );
  assert.equal(offered(TREE, ROWS).length, TREE.length);
});

test('every inline key needs its own tick before the review goes on; refusals block', () => {
  const wg = { item: 'w1', field: 'wireguardPrivateKey' };
  const ta = { item: 'c1', field: 'tlsAuth' };
  const p = preview({ inlineSecrets: [wg, ta] });
  assert.deepEqual(reviewBlockers(p, NO_TICKS), ['inline']);
  const one = { ...NO_TICKS, inline: withTick(NO_TICKS.inline, fieldKey(wg), true) };
  assert.deepEqual(reviewBlockers(p, one), ['inline'], 'the WireGuard acknowledgement alone is not enough');
  const both = { ...one, inline: withTick(one.inline, fieldKey(ta), true) };
  assert.deepEqual(reviewBlockers(p, both), []);
  assert.deepEqual(reviewBlockers(preview({ refused: [{ item: 'r1', field: 'inlineCredentials' }] }), NO_TICKS), ['refused']);
  assert.deepEqual(reviewBlockers(null, NO_TICKS), ['empty']);
  // Only the offered ticks are sent.
  const stale = { ...both, inline: withTick(both.inline, 'gone|tlsCrypt', true) };
  assert.deepEqual(selectionOf(TREE, NOTHING, stale, p).inlineSecrets, [
    { item: 'c1', secret: 'tlsAuth' },
    { item: 'w1', secret: 'wireguardPrivateKey' },
  ]);
});

test('slots are ticked by default, secrets are not; a saved selection keeps its ticks', () => {
  const p = preview({ availableSlots: [{ id: 'S1', name: 'Office AD', connections: 2 }], availableSecrets: [{ item: 'r1', field: 'psk' }] });
  const seen = new Set<string>();
  const ticks = defaultSlots(NO_TICKS, p, seen, true);
  assert.deepEqual([...ticks.slots], ['S1']);
  assert.deepEqual(selectionOf(TREE, NOTHING, ticks, p).secrets, []);
  const unticked = { ...ticks, slots: withTick(ticks.slots, 'S1', false) };
  assert.deepEqual([...defaultSlots(unticked, p, seen, true).slots], [], 'an unticked slot stays unticked');
  const saved = fromSelection({ folders: [], connections: ['r1'], secrets: [{ item: 'r1', field: 'psk' }], slots: [], inlineSecrets: [] });
  assert.deepEqual([...defaultSlots(saved.ticks, p, new Set(), false).slots], []);
  assert.deepEqual(selectionOf(TREE, saved.picked, saved.ticks, p).secrets, [{ item: 'r1', field: 'psk' }]);
});

test('the successor warning and the rotation that needs a review first', () => {
  assert.deepEqual(droppedSuccessorIn(preview()), []);
  assert.deepEqual(droppedSuccessorIn(preview({ successorDroppedIn: ['Acme VPN'] })), ['Acme VPN']);
  assert.deepEqual(droppedSuccessorIn({ ...preview(), successorDroppedIn: undefined }), [], 'an older backend');
  assert.ok(!rotateNeedsReview({ changed: 0 }));
  assert.ok(rotateNeedsReview({ changed: 2 }));
});

test('the team key: its groups, the retyped group, the reveal that keeps nothing', () => {
  const groups = teamKeyGroups(KEY);
  assert.equal(groups.length, 14);
  assert.equal(groups[0], '7K3Q');
  assert.equal(pickGroup(14, () => 0), 0);
  assert.equal(pickGroup(14, () => 0.9999), 13);
  assert.ok(groupMatches('2PZD', '2pzd'));
  assert.ok(groupMatches('0123', 'o12-3'), 'O reads as 0, like the recovery key');
  assert.ok(!groupMatches('2PZD', '2PZE'));
  assert.ok(!groupMatches(null, ''));
  const shown = reveal(KEY);
  assert.equal(shown.key, KEY);
  const asked = savedIt(shown, () => 0.2);
  assert.equal(asked.step, 'confirm');
  assert.equal(asked.key, null, 'the key is gone after "I Saved It"');
  assert.equal(asked.expected, groups[asked.group!]);
  assert.deepEqual(closeReveal(), { step: 'closed', key: null, group: null, expected: null });
});

// MARK: - views

test('the wizard: step 1 ticks a folder and locks its contents; Next waits for a selection', async () => {
  const props = { mode: 'new', rows: ROWS, tree: TREE, onclose: noop };
  const empty = await html('./PublishWizard.svelte', props);
  assert.match(empty, /Step 1 of 4: Connections/);
  assert.match(button(empty, 'next'), /disabled/);
  assert.doesNotMatch(empty, /class="[^"]*\bback\b/, 'no Back on the first step');
  const picked = await html('./PublishWizard.svelte', { ...props, initialPicked: { folders: new Set(['Work']), connections: new Set() } });
  assert.doesNotMatch(button(picked, 'next'), /disabled/);
  assert.match(picked, /data-pick="Work"[^>]*checked/);
  assert.match(picked, /data-pick="d1"[^>]*checked[^>]*disabled|data-pick="d1"[^>]*disabled[^>]*checked/);
  assert.match(picked, /5 connections selected/);
});

test('the wizard: the review gates on every inline tick and explains the fields', async () => {
  const p = preview({
    inlineSecrets: [{ item: 'w1', field: 'wireguardPrivateKey' }],
    personal: [{ item: 'w1', field: 'wireguardPrivateKey' }, { item: 'c1', field: 'nativeAccount' }],
    availableSecrets: [{ item: 'r1', field: 'psk' }],
    availableSlots: [{ id: 'S1', name: 'Office AD', connections: 2 }],
    refused: [],
  });
  const props = { mode: 'new', rows: ROWS, tree: TREE, onclose: noop, initialStep: 'review', initialPreview: p };
  const unticked = await html('./PublishWizard.svelte', props);
  assert.match(unticked, /Step 2 of 4: Review/);
  assert.match(unticked, /Everyone with this catalog uses the same WireGuard key/);
  assert.match(unticked, /Account name: never published/);
  assert.match(unticked, /without user names or passwords/);
  assert.match(button(unticked, 'next'), /disabled/);
  assert.match(unticked, /Tick every key inside the configs/);
  assert.doesNotMatch(unticked, /Everyone with the team key can read this secret/, 'shown only once a secret is ticked');
  const ticked = await html('./PublishWizard.svelte', {
    ...props,
    initialTicks: { secrets: new Set(['r1|psk']), inline: new Set(['w1|wireguardPrivateKey']), slots: new Set(['S1']) },
  });
  assert.doesNotMatch(button(ticked, 'next'), /disabled/);
  assert.match(ticked, /Everyone with the team key can read this secret/);
  const refused = await html('./PublishWizard.svelte', { ...props, initialPreview: preview({ refused: [{ item: 'r1', field: 'config' }] }) });
  assert.match(refused, /cannot be published/);
  assert.match(refused, /The config has errors/);
  assert.match(button(refused, 'next'), /disabled/);
  const dropped = await html('./PublishWizard.svelte', { ...props, initialPreview: preview({ successorDroppedIn: ['Acme VPN'] }) });
  assert.match(dropped, /The last version of Acme VPN announced a backup admin key/);
});

test('the wizard: the name step, the rotation review, the result with the key shown once', async () => {
  const base = { rows: ROWS, tree: TREE, onclose: noop };
  const name = await html('./PublishWizard.svelte', { ...base, mode: 'new', initialStep: 'name', initialPreview: preview() });
  assert.match(name, /MacVPN does not upload anything/);
  assert.match(button(name, 'next'), /disabled/, 'a name is needed');
  const named = await html('./PublishWizard.svelte', { ...base, mode: 'new', initialStep: 'name', initialName: 'Acme VPN' });
  assert.doesNotMatch(button(named, 'next'), /disabled/);
  assert.match(named, /class="primary next"[^>]*>Publish…</);
  const rotate = await html('./PublishWizard.svelte', { ...base, mode: 'rotate', publication, initialPreview: preview() });
  assert.match(rotate, /Step 1 of 2: Review/);
  assert.match(rotate, /only way to revoke access/);
  assert.match(rotate, /class="primary next"[^>]*>Rotate and Save…</);
  const result = { catalogId: 'P1', version: 4, fingerprint: '0123-4567-89AB-CDEF-0123-4567-89AB-CDEF', fileName: 'Acme VPN.macvpncatalog', teamKey: KEY };
  const done = await html('./PublishWizard.svelte', { ...base, mode: 'rotate', publication, initialStep: 'done', initialResult: result });
  assert.match(done, /Version 4 was written to Acme VPN.macvpncatalog/);
  assert.match(done, /0123-4567-89AB-CDEF-0123-4567-89AB-CDEF/);
  assert.equal(done.split(KEY).length - 1, 1, 'the key once');
  assert.match(button(done, 'finish'), /disabled/, 'Done waits for the reveal');
  const plain = await html('./PublishWizard.svelte', { ...base, mode: 'again', publication, initialStep: 'done', initialResult: { ...result, teamKey: null } });
  assert.doesNotMatch(plain, /TEAM-/);
  assert.doesNotMatch(plain, /team-key-reveal/);
});

test('TeamKeyReveal: the key once, gone after "I Saved It", the group check', async () => {
  const shown = await html('./TeamKeyReveal.svelte', { teamKey: KEY, onclose: noop });
  assert.match(shown, new RegExp(KEY));
  assert.match(shown, /shown only now/);
  assert.ok(button(shown, 'saved-it'));
  assert.ok(button(shown, 'copy-key'));
  const asked = savedIt(reveal(KEY), () => 0.5);
  const confirm = await html('./TeamKeyReveal.svelte', { teamKey: KEY, initial: asked, onclose: noop });
  assert.doesNotMatch(confirm, /TEAM-/);
  for (const group of teamKeyGroups(KEY)) assert.doesNotMatch(confirm, new RegExp(group), group);
  assert.match(confirm, new RegExp(`Type group ${asked.group! + 1} of the team key`));
  assert.match(button(confirm, 'confirm-group'), /disabled/);
  const typed = await html('./TeamKeyReveal.svelte', { teamKey: KEY, initial: asked, typed: asked.expected!.toLowerCase(), onclose: noop });
  assert.doesNotMatch(button(typed, 'confirm-group'), /disabled/);
  const wrong = await html('./TeamKeyReveal.svelte', { teamKey: KEY, initial: asked, typed: 'ZZZZ', onclose: noop });
  assert.match(wrong, /role="alert"[^>]*>This is not group/);
  const closed = await html('./TeamKeyReveal.svelte', { teamKey: KEY, initial: closeReveal(), onclose: noop });
  assert.doesNotMatch(closed, /TEAM-|7K3Q/);
});

test('the rotate dialog says rotation is the only way to revoke access; a changed catalog publishes first', async () => {
  const props = { publications: [publication], canPublish: true, onagain: noop, onrotate: noop, oncopy: noop };
  const list = await html('./Publications.svelte', props);
  assert.match(list, /Version 3/);
  assert.match(list, /File: Acme VPN.macvpncatalog/);
  assert.match(list, /Up to date/);
  for (const cls of ['again', 'rotate', 'copy-subscription', 'forget']) assert.ok(button(list, cls));
  const asking = await html('./Publications.svelte', { ...props, rotating: publication });
  assert.match(asking, /Rotate the Team Key of “Acme VPN”\?/);
  assert.match(asking, /the only way to revoke access to a catalog someone already has/);
  const changed = { ...publication, changed: 2, successorDropped: true };
  const review = await html('./Publications.svelte', { ...props, publications: [changed], rotating: changed });
  assert.match(review, /2 changed since the last publish/);
  assert.match(review, /Publish the catalog and review the changes first/);
  assert.match(review, /announced a backup admin key as the successor/);
});

test('the copy of the subscription string never shows it and never echoes the password', async () => {
  const form = await html('./CopySubscription.svelte', { catalogId: 'P1', name: 'Acme VPN', onclose: noop });
  const master = /<input[^>]*data-field="master"[^>]*>/.exec(form)?.[0];
  assert.ok(master);
  assert.doesNotMatch(master, /value=/, 'the password field is bound to nothing');
  assert.match(button(form, 'copy-string'), /disabled/);
  const copied = await html('./CopySubscription.svelte', { catalogId: 'P1', name: 'Acme VPN', copied: true, onclose: noop });
  assert.match(copied, /on the clipboard/);
  assert.doesNotMatch(copied, /macvpn-sub:|TEAM-/);
  assert.doesNotMatch(copied, /data-field="master"/);
  const file = await html('./CopySubscription.svelte', { catalogId: 'P1', name: 'Acme VPN', source: 'file', fileName: 'team.macvpncatalog', onclose: noop });
  assert.match(file, /team.macvpncatalog/);
});

test('the admin key page: the offline backup key, the successor note', async () => {
  const keys = [
    { role: 'primary', fingerprint: '0123-4567-89AB-CDEF-0123-4567-89AB-CDEF', created: 1_760_000_000, offline: false },
    { role: 'backup', fingerprint: 'FEDC-BA98-7654-3210-FEDC-BA98-7654-3210', created: 1_760_000_000, offline: true },
  ];
  const out = await html('./AdminKeys.svelte', { keys });
  assert.match(out, /Offline: only in the exported file/);
  assert.match(button(out, 'promote-key'), /disabled/);
  assert.match(button(out, 'export-key'), /disabled/);
  assert.match(out, /not recovery from a compromise/);
  assert.match(out, /Full backups made before the export still contain the backup key/);
  const none = await html('./AdminKeys.svelte', { keys: [] });
  assert.ok(button(none, 'generate-primary'));
  assert.match(button(none, 'generate-backup'), /disabled/);
  const exporting = await html('./AdminKeys.svelte', { keys: [keys[0], { ...keys[1], offline: false }], dialog: 'export' });
  assert.match(exporting, /Remove the backup key from this Mac after export/);
  assert.equal((exporting.match(/type="password"/g) ?? []).length, 2, 'the password twice');
});

test('the row badge: published in a catalog, changed since', async () => {
  const out = await html('./PublishedBadges.svelte', { published: [{ catalogId: 'P1', name: 'Acme VPN', version: 12, changed: true }] });
  assert.match(out, /Published in “Acme VPN” \(v12\)/);
  assert.match(out, /changed since the last publish/);
  assert.doesNotMatch(await html('./PublishedBadges.svelte', {}), /published/);
});

test('no secret goes through the web view clipboard: the backend copies keys and strings concealed', async () => {
  const { readdirSync } = await import('node:fs');
  const lib = fileURLToPath(new URL('..', import.meta.url));
  const files = (readdirSync(lib, { recursive: true }) as string[]).filter((f) => /\.(svelte|ts)$/.test(f) && !f.endsWith('.test.ts'));
  const writers = files.filter((f) => /navigator\.clipboard|execCommand\(\s*'copy'/.test(readFileSync(`${lib}/${f}`, 'utf8')));
  assert.deepEqual(
    writers.map((f) => f.split(/[\\/]/).pop()).sort(),
    ['Certificates.svelte', 'Fingerprint.svelte', 'WireGuardKeys.svelte'],
    'only the public fingerprint, the WireGuard public key and certificates',
  );
  // Certificates (G3 of the client-credential audit): only the fingerprint and the certificate's PEM, both public.
  const certs = readFileSync(`${lib}/manage/Certificates.svelte`, 'utf8');
  assert.deepEqual(certs.match(/navigator\.clipboard\.writeText\([^)]*\)/g), ['navigator.clipboard.writeText(text)']);
  assert.deepEqual(certs.match(/copy\(i, '[a-z]+', [^)]*\)/g), ["copy(i, 'fingerprint', c.sha256)", "copy(i, 'pem', c.pem)"]);
  // WireGuard: the web view writes only the public key; the private and preshared keys go through the backend.
  const wg = readFileSync(`${lib}/manage/WireGuardKeys.svelte`, 'utf8');
  assert.deepEqual(wg.match(/navigator\.clipboard\.writeText\([^)]*\)/g), ['navigator.clipboard.writeText(key)']);
  assert.match(wg, /async function copyPublic\(key: string\) \{\s*error = null;\s*try \{\s*await navigator\.clipboard\.writeText\(key\)/);
  assert.match(wg, /copyPublic\(pub\.key\)/);
  assert.match(readFileSync(`${lib}/manage/session.svelte.ts`, 'utf8'), /api\.editorWireguardCopy\(this\.id, key\)/);
  const reveal = readFileSync(`${lib}/catalog/TeamKeyReveal.svelte`, 'utf8');
  assert.match(reveal, /publishApi\.copyTeamKey\(key\)/);
  assert.match(readFileSync(`${lib}/vault/copy.ts`, 'utf8'), /api\.vaultCopyRecoveryKey\(key\)/);
});

test('a vault lock takes the catalog sections down: the team key on show leaves the page', async () => {
  const open = await html('./fixtures/LockedReveal.svelte', { vaultState: 'unlocked', teamKey: KEY });
  assert.match(open, new RegExp(KEY));
  for (const state of ['locked', 'notCreated', 'legacyReadOnly']) {
    const locked = await html('./fixtures/LockedReveal.svelte', { vaultState: state, teamKey: KEY });
    assert.doesNotMatch(locked, /TEAM-|team-key-reveal/, state);
  }
  const manage = readFileSync(fileURLToPath(new URL('../manage/Manage.svelte', import.meta.url)), 'utf8');
  assert.match(manage, /<CatalogGate vaultState=\{vm\.vault\.state\}>\s*<TeamCatalogs/);
  assert.match(manage, /<CatalogGate vaultState=\{vm\.vault\.state\}>\s*<Publishing/);
  assert.match(manage, /lockedSection\(/, 'a lock leaves the catalog sections');
});
