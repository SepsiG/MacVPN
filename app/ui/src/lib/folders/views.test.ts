// node --test: the folder views rendered through Svelte's server renderer (compiled on the fly, as in
// credentials.test.ts): the colour picker (12 swatches, "None" on a folder, "Use folder colour" only on an item with
// its own colour), the delete dialog's two steps (the contents question with "move up" as the default, then the
// confirmation that names how many connections go), the menu's folder row (count and green dot), and the
// coloured connection card.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';
import { compile, compileModule } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';
import { deleteStep, isEmptyFolder } from './tree.ts';
import { folder, row } from './fixtures.ts';

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

const PALETTE = ['red', 'orange', 'amber', 'yellow', 'lime', 'green', 'teal', 'cyan', 'blue', 'indigo', 'purple', 'pink'];
const noop = () => {};

test('the colour picker: 12 swatches, the own colour marked, None on a folder', async () => {
  const out = await html('./ColorPicker.svelte', { palette: PALETTE, value: 'teal', target: 'folder', onpick: noop, onclose: noop });
  assert.equal((out.match(/class="swatch[\s"]/g) ?? []).length, 12);
  assert.match(out, /aria-label="Teal"[^>]*aria-pressed="true"/);
  assert.equal((out.match(/aria-pressed="true"/g) ?? []).length, 1);
  assert.match(out, />\s*None\s*</);
  assert.doesNotMatch(out, /Use folder colour/);
  assert.match(out, /--sw: var\(--folder-pink\)/);
});

test('the colour picker on an item: "Use folder colour" only with an own colour, never None', async () => {
  const own = await html('./ColorPicker.svelte', { palette: PALETTE, value: 'red', target: 'item', inherited: 'blue', onpick: noop, onclose: noop });
  assert.match(own, /Use folder colour/);
  assert.match(own, /--sw: var\(--folder-blue\)/, 'the folder colour shown on the option');
  assert.doesNotMatch(own, />\s*None\s*</);
  const inherits = await html('./ColorPicker.svelte', { palette: PALETTE, value: null, target: 'item', onpick: noop, onclose: noop });
  assert.doesNotMatch(inherits, /Use folder colour/);
  assert.doesNotMatch(inherits, /aria-pressed="true"/);
});

test('the delete dialog asks about the contents first, moving them up by default', async () => {
  const work = folder('Work', null, 0, { name: 'Work', connectionCount: 3, itemCount: 4, folderCount: 1 });
  const out = await html('./DeleteFolderDialog.svelte', { folder: work, ondelete: noop, oncancel: noop });
  assert.match(out, /Delete Work\?/);
  assert.match(out, /What should happen to its contents\?/);
  assert.match(out, /value="moveUp"[^>]*checked/);
  assert.doesNotMatch(out, /value="deleteContents"[^>]*checked/);
  assert.match(out, /Move its contents to the top level/);
  assert.match(out, /System VPNs are moved to the top level\./, 'one item is a system VPN');
  // A nested folder: "the parent folder".
  const nested = await html('./DeleteFolderDialog.svelte', { folder: { ...work, parent: 'X', depth: 1 }, ondelete: noop, oncancel: noop });
  assert.match(nested, /Move its contents to the parent folder/);
  // The default button is not destructive while "move up" is chosen.
  assert.match(out, /<button class="primary[^"]*"[^>]*>Delete<\/button>/);
});

test('deleting the connections too needs a second confirmation that names how many', async () => {
  assert.equal(deleteStep('moveUp', 3), 'delete');
  assert.equal(deleteStep('deleteContents', 3), 'confirm');
  assert.equal(deleteStep('deleteContents', 0), 'delete', 'only system VPNs: nothing is deleted');
  const work = folder('Work', null, 0, { name: 'Work', connectionCount: 3, itemCount: 3 });
  const out = await html('./DeleteFolderDialog.svelte', { folder: work, step: 'confirm', mode: 'deleteContents', ondelete: noop, oncancel: noop });
  assert.match(out, /Delete 3 connections\?/);
  assert.match(out, /The connections in Work and its subfolders are deleted with their saved passwords\./);
  assert.match(out, /<button class="destructive[^"]*"[^>]*>Delete Connections<\/button>/);
  assert.match(out, /<button class="cancel[^"]*"[^>]*>Cancel<\/button>/);
  assert.doesNotMatch(out, /type="radio"/);
});

test('an empty folder is only confirmed', async () => {
  const empty = folder('Old', null, 0, { name: 'Old' });
  assert.ok(isEmptyFolder(empty));
  const out = await html('./DeleteFolderDialog.svelte', { folder: empty, ondelete: noop, oncancel: noop });
  assert.match(out, /Delete Old\?/);
  assert.doesNotMatch(out, /type="radio"/);
});

test('the menu folder row: chevron state, the colour, the count with the green dot', async () => {
  const work = folder('Work', null, 0, { name: 'Work', color: 'teal', activeCount: 2, hasConnected: true });
  const out = await html('./FolderRow.svelte', { folder: work, collapsed: true, ontoggle: noop });
  assert.match(out, /aria-expanded="false"/);
  assert.match(out, /--fc: var\(--folder-teal\)/);
  assert.match(out, /class="badge on[^"]*"[^>]*aria-label="2 active"/);
  assert.match(out, /class="dot/);
  const idle = await html('./FolderRow.svelte', { folder: { ...work, activeCount: 0, hasConnected: false, color: null }, collapsed: false, ontoggle: noop });
  assert.match(idle, /aria-expanded="true"/);
  assert.doesNotMatch(idle, /class="badge/);
  assert.match(idle, /--fc: var\(--vpn-system\)/);
});

test('a connection card shows its folder colour as the left bar, none without one', async () => {
  const coloured = await html('../MenuRow.svelte', { row: row('a'), now: 0, onToggle: noop, color: 'purple' });
  assert.match(coloured, /class="card [^"]*tinted/);
  assert.match(coloured, /--tint: var\(--folder-purple\)/);
  const plain = await html('../MenuRow.svelte', { row: row('a'), now: 0, onToggle: noop });
  assert.doesNotMatch(plain, /tinted/);
});

// The network loss rule (2026-10-28): a connection without a physical network under it says so, never "connected".
test('a connection card waiting for network says so in the busy tone', async () => {
  const { statusLine } = await import('../status.ts');
  const waiting = { ...row('a'), state: 'waitingForNetwork' } as never;
  assert.equal(statusLine(waiting, 0).status, 'Waiting for network…');
  assert.equal(statusLine(waiting, 0).tone, 'busy');
  const card = await html('../MenuRow.svelte', { row: waiting, now: 0, onToggle: noop });
  assert.match(card, /Waiting for network…/);
  assert.match(card, /class="bubble [^"]*"[\s\S]*busy/);
});

// Dead-tunnel detection (2026-10-28): OpenVPN restarting itself is "Reconnecting…" (busy, never connected); a tunnel
// found dead and disconnected is "Not responding" (the failure tone).
test('a reconnecting or not responding connection card says so in its tone', async () => {
  const { statusLine } = await import('../status.ts');
  const reconnecting = { ...row('a'), state: 'reconnecting' } as never;
  assert.equal(statusLine(reconnecting, 0).status, 'Reconnecting…');
  assert.equal(statusLine(reconnecting, 0).tone, 'busy');
  const card = await html('../MenuRow.svelte', { row: reconnecting, now: 0, onToggle: noop });
  assert.match(card, /Reconnecting…/);
  assert.match(card, /class="bubble [^"]*"[\s\S]*busy/);
  const dead = { ...row('a'), state: 'notResponding' } as never;
  assert.equal(statusLine(dead, 0).status, 'Not responding');
  assert.equal(statusLine(dead, 0).tone, 'fail');
  const card2 = await html('../MenuRow.svelte', { row: dead, now: 0, onToggle: noop });
  assert.match(card2, /Not responding/);
  assert.match(card2, /class="bubble [^"]*"[\s\S]*fail/);
});

// The slow tier (2026-10-28): a down connection that is tried again later says when, in whole minutes.
test('a connection the slow tier retries shows the minutes to its next attempt', async () => {
  const { statusLine } = await import('../status.ts');
  const retrying = { ...row('a'), state: 'retrying', at: 1000 + 4 * 60 - 10 } as never;
  assert.equal(statusLine(retrying, 1000 * 1000).status, 'Retrying in 4 min');
  assert.equal(statusLine(retrying, 1000 * 1000).tone, 'busy');
  assert.equal(statusLine(retrying, (1000 + 300) * 1000).status, 'Retrying in 1 min');
  const card = await html('../MenuRow.svelte', { row: retrying, now: 1000 * 1000, onToggle: noop });
  assert.match(card, /Retrying in 4 min/);
});
