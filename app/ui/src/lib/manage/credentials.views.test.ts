// node --test: the client-credential fixes in the editors (audit G1, G3, G6) as rendered (Svelte's server renderer,
// compiled on the fly as in wgkeys.test.ts), in English and Hungarian: the config text masked read-only with "Show
// secrets" (the real text only in the editable, bound textarea), the certificates with their details and expiry
// note, the "Private key password" field only when the key needs one, the per-field remove labels, one PSK name,
// and "Show" only for typed text.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';
import { compile, compileModule } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';
import type { CertificateView, EditorView, TextFields } from '../api.ts';

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

const { canShowTyped } = await import('./secret.ts');
const { certificateDate, noteTone, roleTitle } = await import('./certs.ts');
const { setLanguage } = await import('../l10n.svelte.ts');

function clean(body: string): string {
  return body
    .replace(/<!--[^>]*-->/g, '')
    .replace(/ class="svelte-[a-z0-9]+"/g, '')
    .replace(/ svelte-[a-z0-9]+/g, '');
}

async function component(name: string, props: Record<string, unknown>): Promise<string> {
  const { default: view } = (await import(`./${name}`)) as { default: Component<Record<string, unknown>> };
  return clean(render(view, { props }).body);
}

const MASK = '\u2022'.repeat(16);
const CONFIG = 'client\nremote vpn.example.com 1194\n<key>\nKEYDATA\n</key>\n';
const MASKED = `client\nremote vpn.example.com 1194\n<key>\n${MASK}\n</key>\n`;

const certificate = (over: Partial<CertificateView> = {}): CertificateView => ({
  role: 'client',
  source: '<cert>',
  subject: 'CN=client one, OU=Lab, O=Example',
  issuer: 'CN=Cred Test CA, O=Example, C=HU',
  serial: '12:34:AB:CD',
  notBefore: 1_793_314_120,
  notAfter: 2_108_674_120,
  sha256: 'BF:09:5F:E2',
  keyType: 'RSA 2048',
  pem: '-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n',
  status: 'valid',
  note: null,
  ...over,
});

function textView(over: Partial<EditorView> = {}, fields: Partial<TextFields> = {}): { fields: TextFields; view: EditorView } {
  const f: TextFields = {
    type: 'text',
    name: 'Office',
    text: CONFIG,
    username: '',
    password: null,
    psk: null,
    keyPassword: null,
    acknowledged: [],
    otp: { enabled: false, separator: 'none' },
    ...fields,
  } as TextFields;
  const view = {
    id: 'id-1',
    kind: 'openvpn',
    fields: f,
    dirty: false,
    issues: [],
    error: null,
    saved: false,
    savedAt: null,
    risky: [],
    acknowledgesRisk: false,
    staticChallenge: false,
    certCount: 0,
    passwordRule: null,
    importError: null,
    hasStored: false,
    hasStoredSecret: { password: false, psk: false, keyPassword: false },
    removed: false,
    credential: null,
    readOnly: null,
    keyPasswordUsed: false,
    maskedText: MASKED,
    ...over,
  } as EditorView;
  return { fields: f, view };
}

async function editor(kind: string, over: Partial<EditorView> = {}, fields: Partial<TextFields> = {}): Promise<string> {
  const { fields: f, view } = textView(over, fields);
  const session = { id: 'id-1', fields: f, view, save: async () => {}, open: async () => {} };
  return component('TextEditor.svelte', { session, kind });
}

test('the config is masked read-only by default; the real text is only in the editable textarea', async () => {
  const out = await editor('openvpn');
  const areas = out.match(/<textarea[^>]*>[\s\S]*?<\/textarea>/g) ?? [];
  assert.equal(areas.length, 1);
  assert.match(areas[0], /class="config masked"/);
  assert.match(areas[0], /readonly/);
  assert.ok(areas[0].includes(MASK));
  assert.doesNotMatch(out, /KEYDATA/, 'the secret is nowhere in the page');
  assert.match(out, /Secrets in the config are hidden\. Tick Show secrets to edit the config\./);
  assert.match(out, /<input type="checkbox"[^>]*>Show secrets<\/label>/);
  assert.doesNotMatch(out, /<input type="checkbox" checked[^>]*>Show secrets/);
});

test('nothing to mask: the editable textarea, no toggle', async () => {
  const out = await editor('openvpn', { maskedText: undefined }, { text: 'client\n' });
  const areas = out.match(/<textarea[^>]*>/g) ?? [];
  assert.equal(areas.length, 1);
  assert.doesNotMatch(areas[0], /readonly|masked/);
  assert.doesNotMatch(out, /Show secrets/);
});

test('the key password only when the key needs one, with its own remove label; one PSK name', async () => {
  const without = await editor('openvpn');
  assert.doesNotMatch(without, /Private key password/);
  const stored = await editor('openvpn', { keyPasswordUsed: true, hasStoredSecret: { password: false, psk: false, keyPassword: true } });
  assert.match(stored, /aria-label="Private key password"/);
  assert.match(stored, /<button class="remove" type="button">Remove saved key password<\/button>/);
  const ike = await editor('strongswan', { kind: 'strongswan', maskedText: undefined, hasStoredSecret: { password: false, psk: true, keyPassword: false } }, { text: 'connections {}\n' });
  assert.match(ike, /aria-label="Shared secret \(PSK\)"/);
  assert.match(ike, /Remove saved PSK<\/button>/);
  assert.doesNotMatch(ike, /Pre-shared key|Private key password/);
});

test('the certificates: role, subject, details, fingerprint copy and the expiry note', async () => {
  const out = await editor('openvpn', {
    certificates: {
      certificates: [certificate({ status: 'expiresSoon', note: 'Expires in 10 days' }), certificate({ role: 'ca', source: '<ca>', subject: 'CN=Cred Test CA' })],
      pkcs12Encrypted: false,
    },
  });
  assert.match(out, /<legend>Certificates<\/legend>/);
  assert.match(out, /<details class="certificate" open=""><summary><span class="role">Client certificate<\/span>/);
  assert.match(out, /<span class="cert-note warn" role="note">[\s\S]*?Expires in 10 days<\/span>/);
  assert.match(out, /<dt>Issuer<\/dt>\s*<dd>CN=Cred Test CA, O=Example, C=HU<\/dd>/);
  assert.match(out, /<dt>Key type<\/dt>\s*<dd>RSA 2048<\/dd>/);
  assert.match(out, /<dt>SHA-256 fingerprint<\/dt>/);
  assert.match(out, /class="copy-fingerprint"/);
  assert.match(out, /class="copy-pem"[^>]*>[\s\S]*?Copy PEM<\/button>/);
  // A valid CA is shown closed.
  assert.match(out, /<details class="certificate"><summary><span class="role">CA certificate<\/span>/);
  const locked = await component('Certificates.svelte', { certificates: { certificates: [], pkcs12Encrypted: true } });
  assert.match(locked, /The certificates in the PKCS#12 file are encrypted with its password/);
});

test('the certificate helpers', () => {
  assert.equal(roleTitle('client'), 'Client certificate');
  assert.equal(roleTitle('chain'), 'Intermediate certificate');
  assert.equal(noteTone('expired'), 'error');
  assert.equal(noteTone('notYetValid'), 'error');
  assert.equal(noteTone('expiresSoon'), 'warn');
  assert.equal(noteTone('valid'), null);
  assert.ok(certificateDate(2_108_674_120, 'en').includes('2036'));
  assert.ok(certificateDate(2_108_674_120, 'hu').startsWith('2036.'));
});

test('Show is offered for typed text only, never for a stored value', async () => {
  assert.equal(canShowTyped(null), false);
  assert.equal(canShowTyped(''), false);
  assert.equal(canShowTyped('x'), true);
  const typed = await component('SecretField.svelte', { value: 'typed', stored: true, label: 'Password' });
  assert.match(typed, /<input type="password"[^>]*value="typed"/);
  assert.match(typed, /<button class="show" type="button" aria-pressed="false">Show<\/button>/);
  const kept = await component('SecretField.svelte', { value: null, stored: true, label: 'Password' });
  assert.doesNotMatch(kept, /class="show"/);
  assert.match(kept, /placeholder="Saved — type to replace"/);
  assert.match(kept, /Remove saved password<\/button>/);
  const psk = await component('SecretField.svelte', { value: null, stored: true, label: 'PSK', removeLabel: 'Remove saved PSK' });
  assert.match(psk, />Remove saved PSK<\/button>/);
});

test('in Hungarian', async () => {
  try {
    setLanguage('hu');
    const out = await editor('openvpn', {
      keyPasswordUsed: true,
      hasStoredSecret: { password: false, psk: false, keyPassword: true },
      certificates: { certificates: [certificate({ status: 'expired', note: 'Lejárt' })], pkcs12Encrypted: false },
    });
    assert.match(out, />Titkok megjelenítése<\/label>/);
    assert.match(out, /A config titkai rejtve vannak\./);
    assert.match(out, /Mentett kulcsjelszó törlése<\/button>/);
    assert.match(out, /<legend>Tanúsítványok<\/legend>/);
    assert.match(out, /Klienstanúsítvány/);
    assert.match(out, /<span class="cert-note error" role="alert">[\s\S]*?Lejárt<\/span>/);
    assert.match(out, /<dt>Kibocsátó<\/dt>/);
    assert.match(out, /PEM másolása/);
    const typed = await component('SecretField.svelte', { value: 'x', stored: false, label: 'Jelszó' });
    assert.match(typed, />Megjelenítés<\/button>/);
  } finally {
    setLanguage('en');
  }
});
