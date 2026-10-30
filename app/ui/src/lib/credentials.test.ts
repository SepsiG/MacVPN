// node --test: the credential window's rules, and its view rendered through Svelte's server renderer (compiled on
// the fly by the module hooks below, as in pairing.test.ts): only the asked fields are shown, the user name is
// pre-filled, "Connect" stays disabled until the input lock passed and every field has a value, and there is no
// form submit and no autofocus (no default button, no focus steal).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';
import { compile, compileModule } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';
import type { CredentialPromptView } from './api.ts';
import { answerValues, canConnect, credentialIdOfLabel, isSecretField, orderedFields } from './credentials.ts';

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

const base: CredentialPromptView = {
  id: 4,
  connectionId: '11111111-2222-4333-8444-555555555555',
  connectionName: 'Office',
  fields: ['username', 'password'],
  username: 'alice',
  message: null,
  deadline: 0,
  credentialName: null,
  usedBy: null,
  team: null,
  teamSource: null,
  server: null,
};

async function view(props: Record<string, unknown>, prompt: Partial<CredentialPromptView> = {}): Promise<string> {
  const { default: CredentialViewComponent } = (await import('./CredentialView.svelte')) as {
    default: Component<Record<string, unknown>>;
  };
  return render(CredentialViewComponent, {
    props: { prompt: { ...base, ...prompt }, left: 90, onconnect: () => {}, oncancel: () => {}, ...props },
  }).body;
}

/// The `<button>` with this class, as rendered.
function button(html: string, cls: string): string {
  const m = new RegExp(`<button[^>]*class="${cls}[^"]*"[^>]*>`).exec(html);
  assert.ok(m, `no ${cls} button in ${html}`);
  return m[0];
}

test('labels', () => {
  assert.equal(credentialIdOfLabel('cred-12'), 12);
  for (const bad of ['cred-', 'cred-x', 'prompt-1', 'pair-1', 'cred-1 ', 'cred-1234567890123456']) {
    assert.equal(credentialIdOfLabel(bad), null, bad);
  }
});

test('field order and labels', () => {
  assert.deepEqual(orderedFields(['keyPassword', 'password', 'other', 'username', 'psk']), ['username', 'password', 'psk', 'keyPassword']);
  assert.equal(isSecretField('username'), false);
  assert.equal(isSecretField('keyPassword'), true);
});

test('Connect needs the lock passed and every field', () => {
  assert.equal(canConnect(['username', 'password'], { username: 'a' }, true), false);
  assert.equal(canConnect(['username', 'password'], { username: 'a', password: '' }, true), false);
  assert.equal(canConnect(['username', 'password'], { username: 'a', password: 'b' }, false), false);
  assert.equal(canConnect(['username', 'password'], { username: 'a', password: 'b' }, true), true);
  assert.equal(canConnect([], {}, true), false);
  // Only the asked fields go into the answer.
  assert.deepEqual(answerValues(['password'], { username: 'a', password: 'b', psk: 'c' }), { password: 'b' });
});

test('the view shows only the asked fields, the user name pre-filled', async () => {
  const html = await view({ values: { username: 'alice' }, armed: true });
  assert.match(html, /Credentials needed/);
  assert.match(html, /<p class="name[^"]*">Office<\/p>/);
  assert.equal((html.match(/data-field=/g) ?? []).length, 2);
  assert.match(html, /<input[^>]*data-field="username"[^>]*type="text"[^>]*value="alice"/);
  assert.match(html, /<input[^>]*data-field="password"[^>]*type="password"/);
  assert.doesNotMatch(html, /data-field="psk"|data-field="keyPassword"/);
  assert.doesNotMatch(html, /Sign-in failed/);
  // "Save in vault" is ticked by default, with the vault hint (1.2: no Keychain).
  assert.match(html, /<input type="checkbox"[^>]*checked/);
  assert.match(html, /Save in vault/);
  assert.match(html, /MacVPN vault/);
  assert.doesNotMatch(html, /Keychain/);

  const psk = await view({ values: {}, armed: true }, { fields: ['psk'], username: null });
  assert.equal((psk.match(/data-field=/g) ?? []).length, 1);
  assert.match(psk, /Shared secret \(PSK\)/);
});

test('a typed secret can be shown (G6); a user name or an empty field offers nothing', async () => {
  const typed = await view({ values: { username: 'alice', password: 'x' }, armed: true });
  assert.equal((typed.match(/<button class="show[^"]*" type="button" aria-pressed="false"[^>]*>Show<\/button>/g) ?? []).length, 1);
  const empty = await view({ values: { username: 'alice' }, armed: true });
  assert.doesNotMatch(empty, /class="show/);
});

test('the re-prompt shows the message', async () => {
  const html = await view({ values: {}, armed: true }, { message: 'Sign-in failed — check the username and password' });
  assert.match(html, /role="alert"[^>]*>.*Sign-in failed — check the username and password/s);
});

test('Connect stays disabled until every field has a value and the lock passed; no default button', async () => {
  assert.match(button(await view({ values: { username: 'alice' }, armed: true }), 'connect'), /disabled/);
  assert.match(button(await view({ values: { username: 'alice', password: 'x' }, armed: false }), 'connect'), /disabled/);
  assert.doesNotMatch(button(await view({ values: { username: 'alice', password: 'x' }, armed: true }), 'connect'), /disabled/);
  const html = await view({ values: {}, armed: false });
  assert.doesNotMatch(button(html, 'cancel'), /disabled/, 'Cancel always works');
  assert.match(html, /<input[^>]*data-field="username"[^>]*disabled/, 'input locked');
  assert.doesNotMatch(html, /type="submit"/);
  assert.doesNotMatch(html, /<form/);
  assert.doesNotMatch(html, /autofocus/);
  assert.doesNotMatch(html, /class="[^"]*primary/);
});

test('a refused answer is shown, not silently ignored', async () => {
  assert.doesNotMatch(await view({ values: {}, armed: true }), /role="alert"/);
  assert.match(await view({ values: {}, armed: true, error: 'tooEarly' }), /role="alert"[^>]*>\s*Not ready yet/);
  assert.match(await view({ values: {}, armed: true, error: 'rejected' }), /role="alert"[^>]*>\s*MacVPN did not accept/);
});

test('a team catalog slot is named with its catalog', async () => {
  const both = await view(
    { values: {}, armed: true },
    { fields: ['username', 'password'], credentialName: 'Office AD', usedBy: 2, team: 'Acme VPN' },
  );
  assert.match(both, /<p class="caption shared[^"]*">\s*Office AD \(team catalog “Acme VPN”\) — enter your user name and password\s*<\/p>/);
  assert.doesNotMatch(both, /used by/);
  const password = await view(
    { values: {}, armed: true },
    { fields: ['password'], credentialName: 'Office AD', usedBy: 2, team: 'Acme VPN' },
  );
  assert.match(password, /Office AD \(team catalog “Acme VPN”\) — enter your password/);
});

test('a team slot shows its catalog source and the server the password goes to', async () => {
  const html = await view(
    { values: {}, armed: true },
    {
      credentialName: 'Office AD',
      usedBy: 2,
      team: 'Acme VPN',
      teamSource: 'catalogs.example.org',
      server: 'vpn.example.com',
    },
  );
  assert.match(html, /<p class="caption origin[^"]*">[^<]*Server: vpn\.example\.com[^<]*Catalog source: catalogs\.example\.org/);
  // A personal credential has no origin line.
  assert.doesNotMatch(await view({ values: {}, armed: true }, { credentialName: 'Office AD', usedBy: 2 }), /origin/);
});

test('a shared credential is named with its use count', async () => {
  const own = await view({ values: {}, armed: true }, { fields: ['password'] });
  assert.doesNotMatch(own, /used by/);
  const shared = await view({ values: {}, armed: true }, { fields: ['password'], credentialName: 'Office AD', usedBy: 4 });
  assert.match(shared, /<p class="caption shared[^"]*">\s*Password for Office AD — used by 4 connections\s*<\/p>/);
  const one = await view({ values: {}, armed: true }, { fields: ['password'], credentialName: 'Office AD', usedBy: 1 });
  assert.match(one, /Password for Office AD — used by 1 connection\b/);
});
