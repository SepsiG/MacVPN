// node --test: the live system VPN list in the Connections window, and the removed VPN's read-only detail
// rendered through Svelte's server renderer (as in pairing.test.ts).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';
import { compile, compileModule } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';
import type { Row } from '../api.ts';
import { forgetDisabled, removedRow, shownRow } from './live.ts';

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

async function rendered(path: string, props: Record<string, unknown>): Promise<string> {
  const { default: component } = (await import(path)) as { default: Component<Record<string, unknown>> };
  return render(component, { props }).body;
}

const row = (id: string, name = id): Row => ({
  id,
  name,
  typeLabel: 'L2TP',
  managed: false,
  kind: null,
  storedSecrets: true,
  pinned: false,
  available: true,
  switchOn: false,
  switchEnabled: true,
  heldBy: [],
  state: 'disconnected',
});

test('the selected row comes from the list while it is there', () => {
  const rows = [row('a'), row('b', 'B new name')];
  assert.equal(shownRow(rows, 'b', false, row('b', 'old')), rows[1]);
  assert.equal(shownRow(rows, null, false, rows[0]), null);
  assert.equal(shownRow(rows, 'x', false, null), null);
});

test('a removed selection keeps its last row only while the backend marks it removed', () => {
  const last = row('gone');
  const rows = [row('a')];
  assert.equal(shownRow(rows, 'gone', true, last), last);
  assert.equal(shownRow(rows, 'gone', false, last), null);
  assert.equal(shownRow(rows, 'gone', true, row('other')), null);
  assert.equal(shownRow(rows, 'gone', true, null), null);
});

test('a list update keeps the selection and the other rows', () => {
  const before = [row('a'), row('b'), row('c')];
  const after = [row('a'), row('c'), row('d')];
  assert.equal(shownRow(after, 'c', false, before[2])?.id, 'c');
  assert.deepEqual(after.map((r) => r.id), ['a', 'c', 'd']);
});

test('the kept row of a removed VPN has no switch and no live state', () => {
  const connected: Row = { ...row('gone'), state: 'connected', ip: '10.0.0.2', since: 1, switchOn: true };
  const kept = removedRow(connected);
  assert.equal(kept.state, 'disconnected');
  assert.equal(kept.switchOn, false);
  assert.equal(kept.switchEnabled, false);
  assert.equal(kept.name, 'gone');
  assert.equal('ip' in kept, false);
});

test('a removed VPN shows the banner and cannot be connected', async () => {
  const gone = removedRow({ ...row('gone', 'Office VPN'), storedSecrets: false });
  const html = await rendered('./SystemDetail.svelte', { row: gone, epoch: 0, selectedRemoved: true });
  assert.match(html, /class="removed[^"]*"[^>]*>[\s\S]*This VPN was removed from macOS/);
  const connect = /<button[^>]*>\s*Connect\s*<\/button>/.exec(html);
  assert.ok(connect && /\bdisabled\b/.test(connect[0]), html);
  const shown = await rendered('./SystemDetail.svelte', { row: row('here'), epoch: 0, selectedRemoved: false });
  assert.doesNotMatch(shown, /This VPN was removed from macOS/);
});

test('the read-only editor disables its inputs', async () => {
  const secret = await rendered('./SecretField.svelte', { value: null, stored: true, label: 'PSK', disabled: true });
  for (const control of secret.match(/<(input|button)[^>]*>/g) ?? []) assert.match(control, /\bdisabled\b/, control);
  assert.equal((secret.match(/<(input|button)[^>]*>/g) ?? []).length, 2);
  const otp = await rendered('./OtpFields.svelte', { otp: { enabled: true, separator: 'none' }, disabled: true });
  const controls = otp.match(/<(input|select)[^>]*>/g) ?? [];
  assert.equal(controls.length, 2);
  for (const control of controls) assert.match(control, /\bdisabled\b/, control);
  const editable = await rendered('./SecretField.svelte', { value: null, stored: true, label: 'PSK' });
  assert.doesNotMatch(editable, /\bdisabled\b/);
});

test('a removed VPN can still forget its stored secrets', () => {
  assert.equal(forgetDisabled(true, { hasStored: true, dirty: false }), false);
  assert.equal(forgetDisabled(true, { hasStored: false, dirty: true }), true, 'nothing stored: nothing to forget');
  assert.equal(forgetDisabled(true, null), true);
  assert.equal(forgetDisabled(false, { hasStored: false, dirty: true }), false);
  assert.equal(forgetDisabled(false, { hasStored: false, dirty: false }), true);
});
