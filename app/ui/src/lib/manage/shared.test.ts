// node --test: shared credentials in the Connections window (spec 3a). The pure rules (which editors have a
// selector, the selector's value, the forms, the ticked matches), and the views rendered through Svelte's server
// renderer (compiled on the fly by the module hooks below, as in credentials.test.ts): the Credentials cards (name,
// user name, "used by N", never a password), the locked state, the delete question naming the connections that use
// the credential with "Copy into each connection" or Cancel, and the editors' selector.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';
import { compile, compileModule } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';
import type { CredentialItem, CredentialsView, Row } from '../api.ts';
import { OWN, canSaveForm, hasCredentialFields, selectorValue, sourceRows, tickedItems } from './shared.ts';

// `.svelte` components and `.svelte.ts` modules compile for the server; the l10n table (a JSON import) loads as a
// module; extensionless imports resolve like the bundler does (`./l10n.svelte` → `./l10n.svelte.ts`).
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

const office: CredentialItem = { id: '11111111-2222-4333-8444-555555555555', name: 'Office AD', username: 'alice', hasPassword: true, usedBy: 2 };
const lab: CredentialItem = { id: '21111111-2222-4333-8444-555555555555', name: 'Lab', username: '', hasPassword: false, usedBy: 0 };

function row(partial: Partial<Row>): Row {
  return {
    id: '31111111-2222-4333-8444-555555555555',
    name: 'Row',
    typeLabel: 'OpenVPN',
    managed: true,
    kind: 'openvpn',
    storedSecrets: false,
    pinned: false,
    available: true,
    heldBy: [],
    switchOn: false,
    switchEnabled: true,
    state: 'disconnected',
    ...partial,
  } as Row;
}

async function component(file: string, props: Record<string, unknown>): Promise<string> {
  const { default: C } = (await import(file)) as { default: Component<Record<string, unknown>> };
  return render(C, { props }).body;
}

const noop = () => {};

async function list(view: CredentialsView, extra: Record<string, unknown> = {}): Promise<string> {
  return component('./CredentialList.svelte', { view, onadd: noop, onfrom: noop, onedit: noop, onrename: noop, ondelete: noop, ...extra });
}

test('the editors with a user name or password get the selector', () => {
  for (const kind of ['openvpn', 'strongswan', 'l2tp', 'cisco', 'sstp'] as const) {
    assert.equal(hasCredentialFields(row({ kind })), true, kind);
  }
  assert.equal(hasCredentialFields(row({ kind: 'wireguard' })), false);
  assert.equal(hasCredentialFields(row({ managed: false, kind: null, storedSecrets: true })), true);
  assert.equal(hasCredentialFields(row({ managed: false, kind: null, storedSecrets: false })), false);
  const rows = [row({ id: 'b', name: 'Beta' }), row({ id: 'w', name: 'Wire', kind: 'wireguard' }), row({ id: 'a', name: 'Alpha' })];
  assert.deepEqual(sourceRows(rows).map((r) => r.id), ['a', 'b']);
});

test("the selector's value follows the linked credential's name", () => {
  assert.equal(selectorValue(null, [office]), OWN);
  assert.equal(selectorValue('Office AD', [lab, office]), office.id);
  // Not listed (the vault is locked): still shown as linked, never as the own fields.
  assert.notEqual(selectorValue('Office AD', []), OWN);
});

test('the forms and the ticked matches', () => {
  assert.equal(canSaveForm('add', '  ', null), false);
  assert.equal(canSaveForm('add', 'Office AD', null), true);
  assert.equal(canSaveForm('add', 'x'.repeat(65), null), false);
  assert.equal(canSaveForm('rename', 'Office AD ', 'Office AD'), false);
  assert.equal(canSaveForm('rename', 'Office', 'Office AD'), true);
  const matches = [{ item: 'a' }, { item: 'b' }, { item: 'c' }];
  assert.deepEqual(tickedItems(matches, new Set()), ['a', 'b', 'c']);
  assert.deepEqual(tickedItems(matches, new Set(['b'])), ['a', 'c']);
});

test('the cards show the name, the user name and the use count, never a password', async () => {
  const html = await list({ available: true, message: null, items: [office, lab] });
  assert.match(html, /<strong class="name[^"]*">Office AD<\/strong>/);
  assert.match(html, /<span class="user[^"]*">alice<\/span>/);
  assert.match(html, /Used by 2 connections/);
  assert.match(html, /Used by 0 connections/);
  assert.match(html, /Password saved/);
  assert.match(html, /No password saved: asked when connecting/);
  assert.match(html, /No user name/);
  assert.doesNotMatch(html, /type="password"/);
  assert.equal((html.match(/data-credential=/g) ?? []).length, 2);
  assert.match(html, /<button[^>]*class="add[^"]*"(?![^>]*disabled)/);
});

test('a locked vault shows why, and nothing can be added', async () => {
  const html = await list({ available: false, message: 'The vault is locked. Unlock it and try again.', items: [] });
  assert.match(html, /The vault is locked\. Unlock it and try again\./);
  assert.match(html, /<button[^>]*class="add[^"]*"[^>]*disabled/);
  assert.match(html, /<button[^>]*class="from[^"]*"[^>]*disabled/);
  assert.doesNotMatch(html, /No shared credentials yet/);
});

test('deleting a credential in use asks "Copy into each connection" or Cancel and names the connections', async () => {
  const html = await component('./CredentialDeleteQuestion.svelte', {
    name: 'Office AD',
    connections: ['Office VPN', 'Office L2TP'],
    oncopy: noop,
    oncancel: noop,
  });
  assert.match(html, /Delete Office AD\?/);
  assert.deepEqual([...html.matchAll(/<li[^>]*>([^<]*)<\/li>/g)].map((m) => m[1]), ['Office VPN', 'Office L2TP']);
  const buttons = [...html.matchAll(/<button class="([^" ]*)[^"]*"[^>]*>([^<]*)<\/button>/g)].map((m) => [m[1], m[2]]);
  assert.deepEqual(buttons, [
    ['cancel', 'Cancel'],
    ['destructive', 'Copy into Each Connection'],
  ]);
});

test("the editors' selector: own fields by default, a credential by name", async () => {
  const own = await component('./CredentialSelector.svelte', { item: office.id, credential: null, items: [office, lab], onchanged: async () => {} });
  assert.match(own, /<option value="" selected[^>]*>Own username and password<\/option>/);
  assert.match(own, /<option value="11111111-2222-4333-8444-555555555555"[^>]*>Use credential: Office AD<\/option>/);
  assert.doesNotMatch(own, /come from the shared credential/);
  const linked = await component('./CredentialSelector.svelte', { item: office.id, credential: 'Office AD', items: [office, lab], onchanged: async () => {} });
  assert.match(linked, /<option value="11111111-2222-4333-8444-555555555555" selected[^>]*>Use credential: Office AD<\/option>/);
  assert.match(linked, /The user name and password come from the shared credential Office AD\./);
  const sstp = await component('./CredentialSelector.svelte', {
    item: office.id,
    credential: 'Office AD',
    items: [office],
    passwordOnly: true,
    onchanged: async () => {},
  });
  assert.match(sstp, /The password comes from the shared credential Office AD\./);
});

test('the section title in Hungarian', async () => {
  const { setLanguage } = await import('../l10n.svelte.ts');
  setLanguage('hu');
  try {
    const html = await component('./Credentials.svelte', { view: { available: true, message: null, items: [office] }, rows: [] });
    assert.match(html, /<h1[^>]*>Hitelesítő adatok<\/h1>/);
    assert.match(html, /2 kapcsolat használja/);
  } finally {
    setLanguage('en');
  }
});
