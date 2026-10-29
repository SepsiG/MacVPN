// node --test: the WireGuard key panel's rules (wgkeys.ts) and the panel as rendered (Svelte's server renderer,
// compiled on the fly as in search.views.test.ts), in English and Hungarian: the private key masked with Show and
// Copy, the public key read-only in monospace with Copy, "Invalid private key", "Generate Key Pair" (disabled in a
// team catalog's read-only editor), and the peer's preshared key only for a config with exactly one peer.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';
import { compile, compileModule } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';
import type { WireGuardKeysView } from '../api.ts';

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

// After the hooks: wgkeys.ts imports the Svelte l10n module.
const { offersPresharedKey, publicKeyLine, replaceQuestion } = await import('./wgkeys.ts');

const PRIVATE = 'dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=';
const PUBLIC = 'hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=';
const PSK = '//////////////////////////////////////////8=';

const keys = (over: Partial<WireGuardKeysView> = {}): WireGuardKeysView => ({
  privateKey: PRIVATE,
  publicKey: PUBLIC,
  peers: 1,
  presharedKey: null,
  ...over,
});

async function html(props: Record<string, unknown>): Promise<string> {
  const { default: view } = (await import('./WireGuardKeys.svelte')) as { default: Component<Record<string, unknown>> };
  const done = async () => {};
  return render(view, { props: { ongenerate: done, oncopy: done, ...props } })
    .body.replace(/<!--[^>]*-->/g, '')
    .replace(/ class="svelte-[a-z0-9]+"/g, '')
    .replace(/ svelte-[a-z0-9]+/g, '');
}

test('the public key row: the key, invalid, or none yet', () => {
  assert.deepEqual(publicKeyLine(keys()), { state: 'key', key: PUBLIC });
  assert.deepEqual(publicKeyLine(keys({ privateKey: 'not-a-key', publicKey: null })), { state: 'invalid' });
  assert.deepEqual(publicKeyLine(keys({ privateKey: null, publicKey: null })), { state: 'none' });
});

test('generating asks first only when it replaces a key', () => {
  assert.equal(replaceQuestion(keys({ privateKey: null, publicKey: null }), 'privateKey'), null);
  const question = replaceQuestion(keys(), 'privateKey');
  assert.equal(question?.title, 'Replace the private key?');
  assert.equal(question?.message, 'The other side must be updated with the new public key.');
  // An invalid key is replaced only after the question too.
  assert.ok(replaceQuestion(keys({ privateKey: 'x', publicKey: null }), 'privateKey'));
  assert.equal(replaceQuestion(keys(), 'presharedKey'), null);
  assert.equal(replaceQuestion(keys({ presharedKey: PSK }), 'presharedKey')?.title, 'Replace the preshared key?');
});

test('the preshared key is offered for exactly one peer', () => {
  assert.equal(offersPresharedKey(keys({ peers: 0 })), false);
  assert.equal(offersPresharedKey(keys({ peers: 1 })), true);
  assert.equal(offersPresharedKey(keys({ peers: 2 })), false);
});

test('the panel: masked private key, the public key with Copy, Generate Key Pair', async () => {
  const out = await html({ keys: keys({ presharedKey: PSK }) });
  // The private key is in a read-only password field (masked) with Show and Copy.
  assert.match(out, /<input class="key privateKey" type="password" readonly[^>]*value="dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="/);
  assert.match(out, /class="show-key"[^>]*>Show<\/button>/);
  assert.match(out, /class="copy-key"[^>]*>.*?Copy<\/button>/);
  // The public key: read-only text in monospace, its own Copy.
  assert.match(out, new RegExp(`<code class="key public-key" data-public-key="">${PUBLIC.replace(/[+/]/g, '\\$&')}</code>`));
  assert.match(out, /class="copy-public"/);
  assert.match(out, /<button class="generate-key-pair" type="button"><svg[\s\S]*?Generate Key Pair<\/button>/);
  // One peer: its preshared key, masked, and Generate Preshared Key.
  assert.match(out, /<input class="key presharedKey" type="password" readonly/);
  assert.match(out, /class="generate-psk"[\s\S]*?Generate Preshared Key/);
  assert.doesNotMatch(out, /Invalid private key/);
});

test('an invalid private key, no key yet, and a read-only editor', async () => {
  const invalid = await html({ keys: keys({ privateKey: 'not-a-key', publicKey: null, peers: 2 }) });
  assert.match(invalid, /<span class="key-state invalid-key" role="alert">Invalid private key<\/span>/);
  assert.doesNotMatch(invalid, /public-key|copy-public/);
  assert.doesNotMatch(invalid, /generate-psk|presharedKey/, 'two peers: no preshared key row');

  const none = await html({ keys: keys({ privateKey: null, publicKey: null }) });
  assert.match(none, /class="key-state no-key">Generate a key pair, or paste a private key into the config\.</);
  // Nothing to show or copy yet.
  assert.match(none, /<button class="show-key" type="button" disabled/);
  assert.match(none, /<button class="copy-key" type="button" disabled/);

  const readOnly = await html({ keys: keys(), readOnly: true });
  assert.match(readOnly, /<button class="generate-key-pair" type="button" disabled/);
  assert.match(readOnly, /class="copy-public"/, 'the public key can still be copied');
});

test('the panel in Hungarian', async () => {
  const { setLanguage } = await import('../l10n.svelte.ts');
  try {
    setLanguage('hu');
    const out = await html({ keys: keys() });
    assert.match(out, /Kulcspár generálása<\/button>/);
    assert.match(out, />Publikus kulcs</);
    assert.match(out, />Privát kulcs</);
    assert.match(out, />Megjelenítés<\/button>/);
    assert.match(out, /Másolás<\/button>/);
    const invalid = await html({ keys: keys({ privateKey: 'x', publicKey: null }) });
    assert.match(invalid, /Érvénytelen privát kulcs/);
    assert.equal(replaceQuestion(keys(), 'privateKey')?.title, 'Lecseréled a privát kulcsot?');
  } finally {
    setLanguage('en');
  }
});
