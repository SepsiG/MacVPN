// node --test: the IKEv2 client certificate panel's rules (clientcert.ts) and the panel as rendered (Svelte's
// server renderer, compiled on the fly as in wgkeys.test.ts), in English and Hungarian: "Private key password" for
// an IKEv2 config that signs with a key, "Import Client Certificate…", the imported form and SHA-256 fingerprint,
// "Remove", the notes, and a team catalog's read-only editor.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';
import { compile, compileModule } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';
import type { ClientCertView } from '../api.ts';

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

// After the hooks: clientcert.ts imports the Svelte l10n module.
const { formLabel, notes, showsKeyPassword, showsPanel } = await import('./clientcert.ts');

const SHA = 'AB:CD:' + '00:'.repeat(29) + 'EF';

const view = (over: Partial<ClientCertView> = {}): ClientCertView => ({
  pubkey: true,
  imported: null,
  ignored: 0,
  import: true,
  ...over,
});

async function html(props: Record<string, unknown>): Promise<string> {
  const { default: panel } = (await import('./ClientCert.svelte')) as { default: Component<Record<string, unknown>> };
  const done = async () => {};
  return render(panel, { props: { onimport: done, onremove: done, ...props } })
    .body.replace(/<!--[^>]*-->/g, '')
    .replace(/ class="svelte-[a-z0-9]+"/g, '')
    .replace(/ svelte-[a-z0-9]+/g, '');
}

test('the key password field: OpenVPN, and IKEv2 signing with a key where MacVPN loads it', () => {
  assert.equal(showsKeyPassword('openvpn', undefined), true);
  assert.equal(showsKeyPassword('strongswan', view()), true);
  assert.equal(showsKeyPassword('strongswan', view({ pubkey: false })), false, 'EAP');
  assert.equal(showsKeyPassword('strongswan', view({ import: false })), false, "Windows' certificate store");
  assert.equal(showsKeyPassword('strongswan', undefined), false);
  assert.equal(showsKeyPassword('wireguard', view()), false);
});

test('the panel: IKEv2 with a key, or with an imported certificate to remove', () => {
  assert.equal(showsPanel('strongswan', view()), true);
  assert.equal(showsPanel('strongswan', view({ pubkey: false })), false);
  assert.equal(showsPanel('strongswan', view({ pubkey: false, imported: { form: 'pem', sha256: SHA, needsPassword: false } })), true);
  assert.equal(showsPanel('strongswan', view({ import: false })), false);
  assert.equal(showsPanel('openvpn', view()), false);
});

test('the notes: unused, password, left-out certificates', () => {
  assert.deepEqual(notes(view()), []);
  const p12 = view({ imported: { form: 'pkcs12', sha256: SHA, needsPassword: true }, ignored: 2 });
  assert.deepEqual(notes(p12), [
    'The key is protected by a password: save it below, or MacVPN asks for it when connecting.',
    '2 other certificates in the files (the CA, the chain) were not imported.',
  ]);
  assert.match(notes(view({ pubkey: false, imported: { form: 'pem', sha256: SHA, needsPassword: false } }))[0], /is not used/);
  assert.equal(formLabel({ form: 'pkcs12', sha256: SHA, needsPassword: true }), 'PKCS#12 file');
  assert.equal(formLabel({ form: 'pem', sha256: SHA, needsPassword: false }), 'PEM certificate and key');
});

test('the panel rendered: import, the fingerprint, remove, read-only', async () => {
  const none = await html({ cert: view() });
  assert.match(none, /<button class="import-cert" type="button"><svg[\s\S]*?Import Client Certificate…<\/button>/);
  assert.match(none, /class="note no-cert"/);
  assert.doesNotMatch(none, /remove-cert|fingerprint/);

  const pem = await html({ cert: view({ imported: { form: 'pem', sha256: SHA, needsPassword: false } }) });
  assert.match(pem, /<span class="cert-form">PEM certificate and key<\/span>/);
  assert.ok(pem.includes(`>${SHA}</code>`), pem);
  assert.match(pem, /<button class="remove-cert" type="button">Remove<\/button>/);
  // Never anything that looks like key material.
  assert.doesNotMatch(pem, /BEGIN|PRIVATE/);

  const readOnly = await html({ cert: view({ imported: { form: 'pem', sha256: SHA, needsPassword: false } }), readOnly: true });
  assert.match(readOnly, /<button class="import-cert" type="button" disabled/);
  assert.match(readOnly, /<button class="remove-cert" type="button" disabled/);
});

test('the panel in Hungarian', async () => {
  const { setLanguage } = await import('../l10n.svelte.ts');
  try {
    setLanguage('hu');
    const out = await html({ cert: view({ imported: { form: 'pkcs12', sha256: SHA, needsPassword: true } }) });
    assert.match(out, /Klienstanúsítvány importálása…<\/button>/);
    assert.match(out, />PKCS#12 fájl</);
    assert.match(out, />Eltávolítás<\/button>/);
  } finally {
    setLanguage('en');
  }
});
