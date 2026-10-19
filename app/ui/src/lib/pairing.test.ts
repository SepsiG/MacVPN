// node --test: the pairing window's rules, and its view rendered through Svelte's server renderer (the component
// is compiled on the fly by the module hooks below, the way Vite would): the executable path is shown in full, and
// "Allow" stays disabled until the input lock passed and a connection is ticked.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';
import { compile, compileModule } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';
import type { PairingView } from './api.ts';
import { allowedKeys, canAllow, pairingIdOfLabel } from './pairing.ts';

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

const pairing: PairingView = {
  id: 3,
  name: 'Remote Desktop',
  executable: '/Applications/Remote Desktop.app/Contents/MacOS/Remote Desktop',
  items: [
    { id: '11111111-2222-4333-8444-555555555555', name: 'Office' },
    { id: '21111111-2222-4333-8444-555555555555', name: 'Lab' },
  ],
  deadline: 0,
};

async function view(props: { ticked: string[]; armed: boolean; expired?: boolean }): Promise<string> {
  const { default: PairingViewComponent } = (await import('./PairingView.svelte')) as { default: Component<Record<string, unknown>> };
  return render(PairingViewComponent, { props: { pairing, left: 90, onallow: () => {}, ondeny: () => {}, ...props } }).body;
}

/// The `<button>` with this class, as rendered.
function button(html: string, cls: string): string {
  const m = new RegExp(`<button[^>]*class="${cls}[^"]*"[^>]*>`).exec(html);
  assert.ok(m, `no ${cls} button in ${html}`);
  return m[0];
}

test('labels and keys', () => {
  assert.equal(pairingIdOfLabel('pair-7'), 7);
  for (const bad of ['pair-', 'pair-x', 'prompt-7', 'pair-7 ', 'pair-1234567890123456']) assert.equal(pairingIdOfLabel(bad), null, bad);
  const [a, b] = pairing.items.map((i) => i.id);
  assert.deepEqual(allowedKeys(pairing.items, [b, 'other', a]), [a, b]);
  assert.equal(canAllow(pairing.items, [], true), false);
  assert.equal(canAllow(pairing.items, ['other'], true), false);
  assert.equal(canAllow(pairing.items, [a], false), false);
  assert.equal(canAllow(pairing.items, [a], true), true);
});

test('the pairing view shows the name as self-reported and the full path', async () => {
  const html = await view({ ticked: [], armed: true });
  assert.match(html, /Name \(self-reported\)/);
  assert.match(html, /<p class="name[^"]*">Remote Desktop<\/p>/);
  assert.match(html, /<p class="path[^"]*">\/Applications\/Remote Desktop\.app\/Contents\/MacOS\/Remote Desktop<\/p>/);
  // Both connections offered, none ticked.
  assert.equal((html.match(/type="checkbox"/g) ?? []).length, 2);
  assert.doesNotMatch(html, /checked/);
});

test('Allow stays disabled until a connection is ticked (and the lock passed)', async () => {
  const a = pairing.items[0].id;
  assert.match(button(await view({ ticked: [], armed: true }), 'allow'), /disabled/);
  assert.match(button(await view({ ticked: [a], armed: false }), 'allow'), /disabled/);
  assert.doesNotMatch(button(await view({ ticked: [a], armed: true }), 'allow'), /disabled/);
  // Deny always works, and nothing is the default button.
  const html = await view({ ticked: [], armed: false });
  assert.doesNotMatch(button(html, 'deny'), /disabled/);
  assert.doesNotMatch(html, /class="[^"]*primary/);
  assert.doesNotMatch(html, /autofocus/);
});

test('after the two minutes both buttons are disabled (the backend times out)', async () => {
  const a = pairing.items[0].id;
  const html = await view({ ticked: [a], armed: true, expired: true });
  assert.match(button(html, 'allow'), /disabled/);
  assert.match(button(html, 'deny'), /disabled/);
});
