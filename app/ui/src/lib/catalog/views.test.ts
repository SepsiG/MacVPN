// node --test: the team catalog views rendered through Svelte's server renderer (compiled on the fly, as in
// folders/views.test.ts), and the status texts: the add dialog's flow (no "Check" without a fingerprint, the pasted
// string and the team key never rendered, the preview's fingerprint comparison gating "Subscribe"), the read-only
// editor (the note, the disabled fields, the risky checkbox still active), the "Team" badges and the pending removal,
// the detail (no token, the slots) and the unsubscribe question.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';
import { compile, compileModule } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';

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

async function html(path: string, props: Record<string, unknown>): Promise<string> {
  const { default: view } = (await import(path)) as { default: Component<Record<string, unknown>> };
  return render(view, { props }).body;
}

const noop = () => {};
const FINGERPRINT = 'ABCD-1234-EF56-7890-ABCD-1234-EF56-7890';
const TEAM_KEY = 'TEAM-0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ-0123-4567-89AB-CDEF-GHJK-MNPQ';
const TOKEN = 'smoke-bearer-token-4711';
const SUBSCRIPTION = 'macvpn-sub:eyJ2IjoxLCJ0ZWFtS2V5IjoiVEVBTS1TRUNSRVQifQ';
const { emptyForm, withoutSecrets } = await import('./subscription.ts');
const { statusOf, refreshLine, shortFingerprint, isTeamRoot, activeRows } = await import('./status.ts');

const dialog = (props: Record<string, unknown>) =>
  html('./AddCatalogView.svelte', {
    step: 'enter',
    form: emptyForm(),
    onpaste: noop,
    onclearpaste: noop,
    onchoosefile: noop,
    oncheck: noop,
    onback: noop,
    oncompared: noop,
    onsubscribe: noop,
    oncancel: noop,
    ...props,
  });
const checkButton = (out: string) => out.match(/<button[^>]*class="primary check"[^>]*>/)?.[0] ?? '';
const subscribeButton = (out: string) => out.match(/<button[^>]*class="primary subscribe"[^>]*>/)?.[0] ?? '';

test('each subscription status has its text and severity', () => {
  assert.deepEqual(statusOf({ status: 'ok' }), { text: 'Up to date', severity: 'ok' });
  assert.deepEqual(statusOf({ status: 'notModified' }), { text: 'Up to date', severity: 'ok' });
  assert.deepEqual(statusOf({ status: 'unavailable' }), { text: 'Source unavailable', severity: 'warn' });
  assert.deepEqual(statusOf({ status: 'failed' }), { text: 'Refresh failed', severity: 'error' });
  assert.deepEqual(statusOf({ status: 'rollbackRefused' }), { text: 'Older version refused', severity: 'error' });
  assert.deepEqual(statusOf({ status: 'teamKeyChanged' }), { text: 'Team key changed', severity: 'error' });
  assert.equal(statusOf({ status: 'something new' }).severity, 'muted');
});

test('"Refresh now" reports only the non-zero changes, or the reason', () => {
  const applied = refreshLine({ id: 'a', outcome: 'applied', applied: { added: 2, changed: 0, removed: 1, deferred: 0 }, error: null });
  assert.deepEqual(applied, { text: 'Updated: 2 added, 1 removed', severity: 'ok' });
  const deferred = refreshLine({ id: 'a', outcome: 'applied', applied: { added: 0, changed: 0, removed: 1, deferred: 1 }, error: null });
  assert.match(deferred.text, /^Updated: 1 removed Connections that are up stay until you disconnect them\.$/);
  assert.deepEqual(refreshLine({ id: 'a', outcome: 'notModified', applied: null, error: null }), { text: 'No new version.', severity: 'ok' });
  assert.deepEqual(refreshLine({ id: 'a', outcome: 'refused', applied: null, error: 'Bad' }), { text: 'Bad', severity: 'error' });
  assert.equal(shortFingerprint(FINGERPRINT), 'ABCD…7890');
});

test('the root of a team catalog carries the badge, its subfolders and personal folders do not', () => {
  const team = { root: 'cat', sub: 'cat' };
  assert.ok(isTeamRoot(team, { id: 'root', parent: null }));
  assert.ok(!isTeamRoot(team, { id: 'sub', parent: 'root' }));
  assert.ok(!isTeamRoot(team, { id: 'mine', parent: null }));
  assert.ok(!isTeamRoot(undefined, { id: 'root', parent: null }));
});

test('the add dialog cannot check without a fingerprint', async () => {
  const typed = { ...emptyForm(), url: 'https://vpn.example.com/team.macvpncatalog', teamKey: TEAM_KEY };
  const without = await dialog({ form: typed });
  assert.match(checkButton(without), /disabled/);
  assert.match(without, /The fingerprint is required/);
  const partial = await dialog({ form: { ...typed, fingerprint: 'ABCD-1234' } });
  assert.match(checkButton(partial), /disabled/);
  const complete = await dialog({ form: { ...typed, fingerprint: FINGERPRINT } });
  assert.doesNotMatch(checkButton(complete), /disabled/);
  // The fingerprint field is never prefilled: it starts empty.
  assert.match(await dialog({}), /class="fingerprint mono"[^>]*value=""/);
});

test('a parsed subscription string shows the source and the fingerprint, never the string or the key', async () => {
  const form = {
    ...emptyForm(),
    subscription: SUBSCRIPTION,
    parsed: { kind: 'file', source: 'team.macvpncatalog', fingerprint: FINGERPRINT },
  };
  const out = await dialog({ form });
  assert.match(out, /Subscription string read/);
  assert.match(out, /team\.macvpncatalog/);
  assert.match(out, new RegExp(FINGERPRINT));
  assert.match(out, /The team key was checked and stays hidden\./);
  assert.ok(!out.includes(SUBSCRIPTION) && !out.includes('eyJ2'), 'the pasted string is not in the DOM');
  assert.doesNotMatch(out, /class="team-key/, 'no team key field');
  assert.doesNotMatch(checkButton(out), /disabled/);
});

test('the preview: the fingerprint to compare, the counts, and "Subscribe" only after the comparison', async () => {
  const preview = {
    pendingId: 'P', catalogId: 'C', name: 'Acme VPN', version: 3, fingerprint: FINGERPRINT, connections: 2, folders: 1,
    slots: ['Office AD'], risky: 1, teamSecrets: 1,
  };
  // The form as it is after "Check" (withoutSecrets); even with the secrets left in it, the preview shows none.
  const sent = { ...emptyForm(), url: 'https://vpn.example.com/c', teamKey: TEAM_KEY, fingerprint: FINGERPRINT, token: TOKEN, subscription: SUBSCRIPTION };
  for (const form of [withoutSecrets(sent), sent]) {
    const out = await dialog({ step: 'preview', form, preview });
    assert.match(out, /Acme VPN/);
    assert.match(out, /Version 3/);
    assert.match(out, new RegExp(FINGERPRINT));
    assert.match(out, /Compare it with what your administrator sent you/);
    assert.match(out, /2 connections/);
    assert.match(out, /1 folder/);
    assert.match(out, /Credential slots: Office AD/);
    assert.match(out, /Connections with risky settings: 1/);
    assert.match(out, /Team secrets included: 1/);
    assert.match(subscribeButton(out), /disabled/, 'not compared yet');
    for (const secret of [TEAM_KEY, TOKEN, SUBSCRIPTION, 'TEAM-0123']) assert.ok(!out.includes(secret), `shown: ${secret}`);
  }
  const compared = await dialog({ step: 'preview', form: withoutSecrets(sent), preview, compared: true });
  assert.doesNotMatch(subscribeButton(compared), /disabled/);
});

test('the edit dialogs never show a stored token, and say why a token was dropped', async () => {
  const base = { name: 'Acme VPN', onchoosefile: noop, onsave: noop, oncancel: noop };
  const token = await html('./EditDialog.svelte', { ...base, mode: 'token', hasToken: true });
  assert.match(token, /Change Access Token of Acme VPN/);
  assert.match(token, /class="token"[^>]*value=""/);
  assert.match(token, /Remove the stored access token/);
  const dropped = await html('./EditDialog.svelte', { ...base, mode: 'token', tokenDropped: true });
  assert.match(dropped, /The access token is not sent to a new address\. Enter the token for it, if it needs one\./);
  const key = await html('./EditDialog.svelte', { ...base, mode: 'teamKey' });
  assert.match(key, /class="team-key mono"[^>]*value=""/);
  assert.match(key, /<button[^>]*class="primary save"[^>]*disabled/);
});

const sub = {
  id: 'C1', name: 'Acme VPN', source: 'vpn.example.com/team.macvpncatalog', fingerprint: FINGERPRINT, version: 4, status: 'teamKeyChanged',
  lastRefresh: 1_800_000_000, lastSuccess: null, error: 'The team key does not open this catalog (it is wrong or was rotated).', hasToken: true,
  slots: [
    { name: 'Office AD', filled: true, credentialName: 'Office AD' },
    { name: 'Lab', filled: false, credentialName: 'Lab (Acme VPN)' },
  ],
};

test('the list and the detail: status, fingerprint, error, slots, and never a token', async () => {
  const list = await html('./CatalogList.svelte', { catalogs: [sub], language: 'en', onadd: noop, onrefreshall: noop, onselect: noop });
  assert.match(list, /Acme VPN/);
  assert.match(list, /Team key changed/);
  assert.match(list, /ABCD…7890/);
  assert.match(list, /v4/);
  assert.match(list, /The team key does not open this catalog/);
  assert.match(list, /Add team catalog…/);
  const detail = await html('./CatalogDetail.svelte', {
    sub, connections: 2, language: 'en', result: { text: 'No new version.', severity: 'ok' },
    onback: noop, onrefresh: noop, onedit: noop, onunsubscribe: noop, oncredentials: noop,
  });
  for (const text of ['Refresh now', 'Edit source…', 'Change team key…', 'Change access token…', 'Unsubscribe…', 'No new version.', FINGERPRINT, 'Stored in the vault', 'Never']) {
    assert.ok(detail.includes(text), `missing: ${text}`);
  }
  assert.match(detail, /Office AD<\/strong>\s*<span class="caption[^"]*filled[^"]*">Filled in/);
  assert.match(detail, /Lab<\/strong>\s*<span class="caption[^"]*">You will be asked when you connect/);
  assert.equal((detail.match(/Edit in Credentials/g) ?? []).length, 2);
});

test('unsubscribing names the catalog, the count and the active connections', async () => {
  const rows = [
    { id: 'a', name: 'Office', state: 'connected', catalog: { catalogId: 'C1' } },
    { id: 'b', name: 'Lab', state: 'disconnected', catalog: { catalogId: 'C1' } },
    { id: 'c', name: 'Mine', state: 'connected', catalog: null },
    { id: 'd', name: 'Lab 2', state: 'waitingForNetwork', catalog: { catalogId: 'C1' } },
  ] as never[];
  // A connection waiting for network (the network loss rule) is still up: it is disconnected first too.
  assert.deepEqual(activeRows(rows, 'C1').map((r: { name: string }) => r.name), ['Office', 'Lab 2']);
  const active = activeRows(rows.slice(0, 3), 'C1').map((r: { name: string }) => r.name);
  const out = await html('./UnsubscribeDialog.svelte', { name: 'Acme VPN', connections: 2, active, onconfirm: noop, oncancel: noop });
  assert.match(out, /Unsubscribe from Acme VPN\?/);
  assert.match(out, /Its 2 connections and folders are removed/);
  assert.match(out, /These connections are up and are disconnected first:/);
  assert.match(out, /<li>Office<\/li>/);
  assert.match(out, /Credential slots you filled in are kept/);
});

const badge = { catalogId: 'C1', name: 'Acme VPN', pendingRemoval: true, profileOutdated: false };
const menuRow = {
  id: 'r', name: 'Office', typeLabel: 'OpenVPN', managed: true, kind: 'openvpn', storedSecrets: false, pinned: false, available: true,
  switchOn: true, switchEnabled: true, heldBy: [], state: 'connected', ip: null, since: null, catalog: badge,
};

test('the Team badge and the pending removal, in the menu and in the folder rows', async () => {
  const row = await html('../MenuRow.svelte', { row: menuRow, now: 0, onToggle: noop });
  assert.match(row, /class="team-badge[^"]*"[^>]*>Team</);
  assert.match(row, /Removed from the team catalog — disappears after you disconnect/);
  const own = await html('../MenuRow.svelte', { row: { ...menuRow, catalog: null }, now: 0, onToggle: noop });
  assert.doesNotMatch(own, /team-badge|Removed from the team catalog/);
  const folder = {
    type: 'folder', id: 'f', name: 'Acme VPN', parent: null, depth: 0, color: null, colorSource: 'none', ownColor: null, collapsed: false,
    activeCount: 0, hasConnected: false, connectionCount: 1, itemCount: 1, folderCount: 0,
  };
  assert.match(await html('../folders/FolderRow.svelte', { folder, collapsed: false, team: true, ontoggle: noop }), />Team</);
  assert.doesNotMatch(await html('../folders/FolderRow.svelte', { folder, collapsed: false, ontoggle: noop }), /team-badge/);
  const bar = await html('./TeamConnectionBar.svelte', { id: 'r', name: 'Office', badge: { ...badge, profileOutdated: true }, native: true });
  assert.match(bar, /title="Managed by the team catalog “Acme VPN”"[^>]*>Team</);
  assert.match(bar, /class="managed[^"]*">Acme VPN</);
  assert.match(bar, /Duplicate as personal connection…/);
  assert.match(bar, /Install profile/);
  assert.match(bar, /The team catalog changed this connection: reinstall its profile/);
  assert.match(bar, /I installed it/);
});

/// An editor session as the editors use it (fields, view, save, open), without a backend.
function session(view: Record<string, unknown>) {
  return { id: 'r', fields: structuredClone(view.fields), view, save: async () => {}, open: async () => {} };
}

const textView = {
  id: 'r', kind: 'openvpn', dirty: false, issues: [], error: null, saved: false, savedAt: null,
  risky: [{ line: 3, directive: 'up', reason: 'runs a script as root' }], acknowledgesRisk: false, staticChallenge: false, certCount: 0,
  passwordRule: null, importError: null, hasStored: false, hasStoredSecret: { password: false, psk: false, keyPassword: false }, removed: false,
  credential: null, readOnly: 'Managed by the team catalog “Acme VPN”',
  fields: {
    type: 'text', name: 'Office', text: 'client\nuser nobody\n', username: '', password: null, psk: null, keyPassword: null, acknowledged: [],
    otp: { enabled: false, separator: 'none' },
  },
};

test('a read-only editor: the note, every field disabled, only the risky checkbox active', async () => {
  const out = await html('../manage/TextEditor.svelte', { session: session(textView), kind: 'openvpn' });
  assert.match(out, /class="readonly-note"[^>]*>.*Managed by the team catalog “Acme VPN”/s);
  // The name and the config are disabled, the authentication sits in a disabled group.
  assert.match(out, /<input class="wide"[^>]*disabled/);
  assert.match(out, /<textarea[^>]*class="config[^"]*"[^>]*disabled/);
  assert.equal((out.match(/<fieldset class="lock" disabled/g) ?? []).length, 1);
  // The risky panel lies outside the disabled group: its checkbox stays active.
  const panel = out.indexOf('class="risky');
  assert.ok(panel > 0 && panel < out.indexOf('<fieldset class="lock" disabled'), 'the risky checkbox stays active');
  assert.match(out.slice(panel), /I acknowledge these settings/);
  assert.doesNotMatch(out.slice(panel).match(/<input type="checkbox"[^>]*>/)?.[0] ?? 'disabled', /disabled/);
  assert.doesNotMatch(out.match(/<button[^>]*class="primary"[^>]*>/)?.[0] ?? '', /disabled/, 'Save stores the acknowledgement');

  const own = await html('../manage/TextEditor.svelte', { session: session({ ...textView, readOnly: null }), kind: 'openvpn' });
  assert.doesNotMatch(own, /readonly-note|<fieldset class="lock" disabled|<input class="wide"[^>]*disabled/);

  const native = {
    ...textView, kind: 'l2tp', risky: [],
    fields: { type: 'native', name: 'L', server: 's', account: '', groupName: '', sendAllTraffic: true, password: null, psk: null, otp: { enabled: false, separator: 'none' } },
  };
  const form = await html('../manage/NativeForm.svelte', { session: session(native), kind: 'l2tp' });
  assert.match(form, /Managed by the team catalog “Acme VPN”/);
  assert.match(form, /<fieldset class="lock" disabled/);
  assert.match(form.match(/<button[^>]*class="primary"[^>]*>/)?.[0] ?? '', /disabled/, 'nothing to save');
});
