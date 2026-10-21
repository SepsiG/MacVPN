// node --test src/lib/ : the language rule and format port, and the l10n coverage of the UI sources.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MACOS, format, platformOf, resolveLanguage, translate, type Platform, type Table } from './l10n-core.ts';
import { uptime } from './format.ts';

const root = new URL('../../../../', import.meta.url);
const table: Table = JSON.parse(readFileSync(new URL('crates/core/l10n/strings.json', root), 'utf8')).strings;

test('language rule matches the core', () => {
  assert.equal(resolveLanguage([]), 'en');
  assert.equal(resolveLanguage(['de-DE', 'hu-HU', 'en']), 'hu');
  assert.equal(resolveLanguage(['en-GB', 'hu']), 'en');
  assert.equal(resolveLanguage(['HU_hu']), 'hu');
  assert.equal(resolveLanguage(['hungarian']), 'en');
  assert.equal(resolveLanguage(['fr', 'de']), 'en');
});

test('format subset', () => {
  assert.equal(format('%@ · %@', ['a', 'b']), 'a · b');
  assert.equal(format('%2$@ %1$@', ['a', 'b']), 'b a');
  assert.equal(format('%d%% of %lld', [5, 7]), '5% of 7');
  assert.equal(format('%x %@', ['a']), '%x a');
});

test('translate uses the app scope only', () => {
  assert.equal(translate(table, 'hu', MACOS, 'Quit MacVPN', []), table['Quit MacVPN'].hu);
  assert.equal(translate(table, 'en', MACOS, 'Quit MacVPN', []), 'Quit MacVPN');
  assert.equal(translate(table, 'hu', MACOS, '%@ · Missing tool', ['OpenVPN']), `OpenVPN · ${table['%@ · Missing tool'].hu.slice(5)}`);
  assert.equal(translate(table, 'hu', MACOS, 'not a key', []), 'not a key');
});

const WINDOWS: Platform = { os: 'windows', product: 'WinVPN' };

/// The macOS wording is the 1.4.0 text for every `app` key (the frozen baseline of Task 1).
test('macOS texts equal the 1.4.0 baseline', () => {
  const baseline: Record<string, { en: string; hu: string }> = JSON.parse(
    readFileSync(new URL('scripts/bundle-baseline/1.4.0/l10n-macos.json', root), 'utf8'),
  );
  let checked = 0;
  for (const [key, texts] of Object.entries(baseline)) {
    if (table[key]?.scope !== 'app') continue;
    checked += 1;
    assert.equal(translate(table, 'en', MACOS, key, []), texts.en, key);
    assert.equal(translate(table, 'hu', MACOS, key, []), texts.hu, key);
  }
  assert.ok(checked > 500, `${checked}`);
});

test('a windows variant is used on Windows in both languages', () => {
  const key = 'Enter the master password. Its key is then kept in the macOS Keychain, and MacVPN opens without asking.';
  assert.equal(
    translate(table, 'en', WINDOWS, key, []),
    'Enter the master password. Its key is then kept in the Windows Credential Manager, and WinVPN opens without asking.',
  );
  assert.equal(
    translate(table, 'hu', WINDOWS, key, []),
    'Add meg a mesterjelszót. A széf kulcsa ezután a Windows Hitelesítőadat-kezelőjében marad, és a WinVPN kérdés nélkül megnyílik.',
  );
  assert.equal(translate(table, 'hu', WINDOWS, 'On this Mac', []), 'Ezen a számítógépen');
  assert.equal(translate(table, 'en', WINDOWS, 'Option-click a switch: debug mode', []), 'Alt-click a switch: debug mode');
  // Linux has no variant yet: the base text.
  assert.equal(translate(table, 'en', { os: 'linux', product: 'MacVPN' }, 'On this Mac', []), 'On this Mac');
});

test('without a variant the product name is replaced', () => {
  assert.equal(translate(table, 'en', WINDOWS, 'Quit MacVPN', []), 'Quit WinVPN');
  assert.equal(translate(table, 'hu', WINDOWS, 'MacVPN is locked', []), 'A WinVPN zárolva van');
  // Arguments are not rewritten.
  assert.equal(translate(table, 'en', WINDOWS, '%@ (personal)', ['MacVPN']), 'MacVPN (personal)');
});

test('a macOS-only text is never substituted', () => {
  const key = 'MacVPN uses the VPN tools from Homebrew (openvpn, wireguard-tools, strongswan, sstp-client, bash). You can install the missing ones here.';
  assert.deepEqual(table[key].only, ['macos']);
  assert.equal(translate(table, 'en', WINDOWS, key, []), key);
  assert.equal(translate(table, 'hu', WINDOWS, key, []), table[key].hu);
});

test('the platform comes from the get_platform reply', () => {
  assert.deepEqual(platformOf({ os: 'macos', productName: 'MacVPN' }), MACOS);
  const windows = platformOf({ os: 'windows', productName: 'WinVPN' });
  assert.deepEqual(windows, WINDOWS);
  assert.equal(translate(table, 'en', windows, 'Quit MacVPN', []), 'Quit WinVPN');
  assert.deepEqual(platformOf({ os: 'linux', productName: 'LinVPN' }), { os: 'linux', product: 'LinVPN' });
});

test('an unknown or malformed get_platform reply keeps macOS', () => {
  for (const reply of [
    { os: 'beos', productName: 'WinVPN' },
    { os: 'Windows', productName: 'WinVPN' },
    { os: 'windows' },
    { os: 'windows', productName: '' },
    { os: 'windows', productName: 7 },
    { product: 'WinVPN' },
    'windows',
    null,
    undefined,
  ]) {
    assert.deepEqual(platformOf(reply), MACOS, JSON.stringify(reply));
  }
  // A fresh copy: changing it never changes the default.
  assert.notEqual(platformOf(null), MACOS);
});

test('uptime', () => {
  assert.equal(uptime(100, 165_000), '1:05');
  assert.equal(uptime(0, 3_723_000), '1:02:03');
  assert.equal(uptime(10, 0), '0:00');
});

/// Every literal tr('…') / tr("…") key in the UI sources is an `app` entry with a Hungarian text.
test('UI texts are in the table', () => {
  const dir = new URL('../', import.meta.url);
  const files: string[] = [];
  const walk = (path: string) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const full = join(path, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (/\.(svelte|ts)$/.test(entry.name) && !entry.name.endsWith('.test.ts')) files.push(full);
    }
  };
  walk(fileURLToPath(dir));
  const keys = new Set<string>();
  // The JS string escapes of a literal (`\n` is a line break, `\'` a quote).
  const unescape = (literal: string) => literal.replace(/\\(.)/g, (_, c: string) => (c === 'n' ? '\n' : c === 't' ? '\t' : c));
  for (const file of files) {
    const source = readFileSync(file, 'utf8');
    for (const m of source.matchAll(/\btr\(\s*'((?:[^'\\]|\\.)*)'/g)) keys.add(unescape(m[1]));
    for (const m of source.matchAll(/\btr\(\s*"((?:[^"\\]|\\.)*)"/g)) keys.add(unescape(m[1]));
  }
  assert.ok(keys.size >= 10, `found ${keys.size} keys`);
  for (const key of keys) {
    const entry = table[key];
    assert.ok(entry !== undefined, `missing from strings.json: ${key}`);
    assert.equal(entry.scope, 'app', `not an app text: ${key}`);
    assert.ok(entry.hu.length > 0, `no Hungarian text: ${key}`);
  }
});

/// The UI sources (`.svelte`, `.ts` but the tests), as [path, text].
function uiSources(): [string, string][] {
  const files: [string, string][] = [];
  const walk = (path: string) => {
    for (const entry of readdirSync(path, { withFileTypes: true })) {
      const full = join(path, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (/\.(svelte|ts)$/.test(entry.name) && !entry.name.endsWith('.test.ts')) files.push([full, readFileSync(full, 'utf8')]);
    }
  };
  walk(fileURLToPath(new URL('../', import.meta.url)));
  return files;
}

/// `tr` only ever gets a literal key (so the coverage test above sees every key), never a variable or template.
test('tr is only called with a literal key', () => {
  let calls = 0;
  for (const [file, source] of uiSources()) {
    for (const m of source.matchAll(/\btr\(\s*(.)/g)) {
      if (/export function tr\($/.test(source.slice(0, (m.index ?? 0) + 3))) continue;
      calls += 1;
      assert.ok(m[1] === "'" || m[1] === '"', `${file}: tr( with a non-literal key`);
    }
  }
  assert.ok(calls >= 100, `found ${calls} calls`);
});

/// What a .svelte file shows without `tr`: the markup's text nodes and the literal values of the attributes and
/// props that hold text. Scripts, styles, comments and `{…}` expressions are removed first.
function untranslatedMarkup(source: string): string[] {
  let markup = source
    .replace(/<script[\s\S]*?<\/script>/g, '')
    .replace(/<style[\s\S]*?<\/style>/g, '')
    .replace(/<!--[\s\S]*?-->/g, '');
  // Expressions, innermost first (they nest: `{tr('a', {x})}`).
  for (let previous = ''; previous !== markup; ) {
    previous = markup;
    markup = markup.replace(/\{[^{}]*\}/g, ' ');
  }
  const found: string[] = [];
  const attribute = /\s(title|placeholder|aria-label|alt|label|message|text|caption)\s*=\s*"([^"]*)"/g;
  for (const m of markup.matchAll(attribute)) {
    if (/[A-Za-zÀ-ɏ]/.test(m[2])) found.push(`${m[1]}="${m[2]}"`);
  }
  const text = markup.replace(/<[^>]*>/g, '\n');
  for (const line of text.split('\n')) {
    const t = line.trim();
    if (/[A-Za-zÀ-ɏ]{2,}/.test(t)) found.push(t);
  }
  return found;
}

/// Literal text in the markup that is not a user-facing string (an example value, a brand name).
const MARKUP_ALLOWED = new Set(['placeholder="vpn.example.com"']);

test('no hard-coded text in the Svelte markup', () => {
  // The check itself: text nodes and text attributes are found, expressions and scripts are not.
  assert.deepEqual(
    untranslatedMarkup('<script>const a = "Hidden";</script><p title="Tip">Hello {tr("x")} <b>{n}</b></p><i>{tr(\'a\', {b})}</i>'),
    ['title="Tip"', 'Hello'],
  );
  const found: string[] = [];
  for (const [file, source] of uiSources()) {
    if (!file.endsWith('.svelte')) continue;
    for (const text of untranslatedMarkup(source)) {
      if (!MARKUP_ALLOWED.has(text)) found.push(`${file}: ${text}`);
    }
  }
  assert.deepEqual(found, []);
});

/// Text given to the UI in TypeScript objects goes through `tr` too (no `title: 'Import'`).
test('no hard-coded text in TypeScript objects', () => {
  const found: string[] = [];
  for (const [file, source] of uiSources()) {
    const scripts = file.endsWith('.svelte') ? [...source.matchAll(/<script[\s\S]*?<\/script>/g)].map((m) => m[0]).join('\n') : source;
    for (const m of scripts.matchAll(/\b(title|message|label|text|caption|placeholder|detail|subtitle)\s*:\s*(['"`])[A-Za-z]/g)) {
      found.push(`${file}: ${m[0]}`);
    }
  }
  assert.deepEqual(found, []);
});
