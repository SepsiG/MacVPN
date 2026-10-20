// node --test: the Connections window's search as rendered (Svelte's server renderer, compiled on the fly as in
// folders/views.test.ts): the field in the sidebar with its placeholder (EN, HU), the filtered tree (only the matches
// and their folders, every folder open whatever its stored state, the matched part marked, the keyboard's result
// highlighted), the footer's sections still there, and the empty result with its Clear button.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';
import { compile, compileModule } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';
import { folder, item, row } from '../folders/fixtures.ts';
import { searchTree } from './search.ts';
import type { Row, TreeRow } from '../api.ts';

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
  // Without Svelte's hydration comments and scoping classes, so the markup reads as written.
  return render(view, { props })
    .body.replace(/<!--[^>]*-->/g, '')
    .replace(/ class="svelte-[a-z0-9]+"/g, '')
    .replace(/ svelte-[a-z0-9]+/g, '');
}

const noop = () => {};
const named = (id: string, name: string): Row => ({ ...row(id), name });
// Iroda/ (collapsed) { Győr VPN, Pécs } Archív/ (collapsed) { Régi } Otthon
const TREE: TreeRow[] = [
  folder('f1', null, 0, { name: 'Iroda', collapsed: true, itemCount: 2 }),
  item('gyor', 'f1', 1),
  item('pecs', 'f1', 1),
  folder('f2', null, 0, { name: 'Archív', collapsed: true, itemCount: 1 }),
  item('regi', 'f2', 1),
  item('home', null, 0),
];
const ROWS = [named('gyor', 'Győr VPN'), named('pecs', 'Pécs'), named('regi', 'Régi'), named('home', 'Otthon')];
const sidebar = (query: string) => ({
  rows: ROWS, tree: TREE, foldersEnabled: true, selected: null, kinds: [], onselect: noop, onimport: noop, onpaired: noop, query,
});

/// The ids of the rendered tree rows, in order.
const rendered = (out: string) => [...out.matchAll(/data-tree-row[^>]*data-id="([^"]+)"/g)].map((m) => m[1]);

test('the sidebar has the search field, in both languages', async () => {
  const { setLanguage } = await import('../l10n.svelte.ts');
  try {
    const en = await html('./Sidebar.svelte', sidebar(''));
    assert.match(en, /<input[^>]*class="query[^"]*"[^>]*role="searchbox"[^>]*placeholder="Search connections"/);
    assert.doesNotMatch(en, /class="clear[\s"]/, 'no clear button while empty');
    setLanguage('hu');
    const hu = await html('./Sidebar.svelte', sidebar(''));
    assert.match(hu, /placeholder="Kapcsolatok keresése"/);
  } finally {
    setLanguage('en');
  }
});

test('a search shows only the matches and their folders, open, with the footer still there', async () => {
  const out = await html('./Sidebar.svelte', sidebar('gyor'));
  assert.deepEqual(rendered(out), ['f1', 'gyor']);
  assert.match(out, /data-id="f1"[^>]*aria-expanded="true"/, 'the collapsed folder is shown open');
  assert.match(out, /<mark>Győr<\/mark> VPN/);
  assert.match(out, /class="clear[\s"]/);
  for (const link of ['credentials', 'paired', 'team-catalogs', 'publishing']) assert.match(out, new RegExp(`link-${link}`));
  // Without a search the stored state rules again.
  const all = await html('./Sidebar.svelte', sidebar(''));
  assert.deepEqual(rendered(all), ['f1', 'f2', 'home']);
  assert.doesNotMatch(all, /<mark>/);
});

test('a folder name match keeps its contents; the first result is highlighted', async () => {
  const out = await html('./Sidebar.svelte', sidebar('archiv'));
  assert.deepEqual(rendered(out), ['f2', 'regi']);
  assert.match(out, /<mark>Archív<\/mark>/);
  assert.match(out, /<button class="row item active">[\s\S]*?Régi/);
});

test('the tree marks the keyboard result and never the stored collapsed state while filtering', async () => {
  const filtered = searchTree(TREE, ROWS, 'PECS');
  assert.deepEqual(filtered?.items, ['pecs']);
  const out = await html('../folders/FolderTree.svelte', {
    rows: ROWS, tree: TREE, selected: null, enabled: true, palette: [], onselect: noop, query: 'PECS', filtered, active: 'pecs',
  });
  assert.deepEqual(rendered(out), ['f1', 'pecs']);
  assert.match(out, /class="tree filtering"/);
  assert.match(out, /data-id="f1"[^>]*aria-expanded="true"/, 'stored collapsed, shown open');
  assert.match(out, /<button class="row item active">[\s\S]*?<mark>Pécs<\/mark>/);
  assert.equal(TREE[0].type === 'folder' && TREE[0].collapsed, true, 'the stored state is untouched');
  // Without a search: the stored state, no marks, nothing active.
  const plain = await html('../folders/FolderTree.svelte', { rows: ROWS, tree: TREE, selected: null, enabled: true, palette: [], onselect: noop });
  assert.deepEqual(rendered(plain), ['f1', 'f2', 'home']);
  assert.doesNotMatch(plain, /<mark>|filtering|\bactive\b/);
});

test('no match: the message names the query, with a Clear button (EN, HU)', async () => {
  const { setLanguage } = await import('../l10n.svelte.ts');
  try {
    const en = await html('./Sidebar.svelte', sidebar('  zzz '));
    assert.deepEqual(rendered(en), []);
    assert.match(en, /role="status"[^>]*>\s*<p>No connections match “zzz”<\/p>/);
    assert.match(en, /<button class="clear-search[^"]*"[^>]*>Clear Search<\/button>/);
    setLanguage('hu');
    const hu = await html('./Sidebar.svelte', sidebar('zzz'));
    assert.match(hu, /Egy kapcsolat sem felel meg ennek: „zzz”/);
    assert.match(hu, />Keresés törlése<\/button>/);
  } finally {
    setLanguage('en');
  }
});
