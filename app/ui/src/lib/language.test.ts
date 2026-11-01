// node --test src/lib/ : the Language setting (the menu's choice and the first render's language).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { LANGUAGE_SETTINGS, isLanguageSetting, languageLabel, languageOf } from './language.ts';

const menu = readFileSync(new URL('./Menu.svelte', import.meta.url), 'utf8');
const main = readFileSync(new URL('../main.ts', import.meta.url), 'utf8');

test('System first, then the languages under their own names', () => {
  assert.deepEqual(LANGUAGE_SETTINGS, ['system', 'en', 'hu']);
  assert.deepEqual(
    LANGUAGE_SETTINGS.map((s) => languageLabel(s, 'Rendszer szerint')),
    ['Rendszer szerint', 'English', 'Magyar'],
  );
  // The names do not change with the UI language; only System is translated.
  assert.equal(languageLabel('hu', 'Match System'), 'Magyar');
  assert.equal(languageLabel('system', 'Match System'), 'Match System');
});

test('only the three values are settings', () => {
  for (const s of LANGUAGE_SETTINGS) assert.ok(isLanguageSetting(s), s);
  for (const bad of ['', 'HU', 'de', 'English', null, undefined, 1]) assert.ok(!isLanguageSetting(bad), String(bad));
});

test('a new window renders first in the language the platform reply names', () => {
  assert.equal(languageOf({ os: 'macos', productName: 'MacVPN', language: 'hu' }), 'hu');
  assert.equal(languageOf({ os: 'linux', productName: 'LinVPN', language: 'en' }), 'en');
  for (const reply of [null, 'hu', {}, { language: 'de' }, { language: 2 }]) assert.equal(languageOf(reply), null);
  assert.match(main, /languageOf\(reply\)/);
});

test('the settings offer the language choice and switch through the backend', () => {
  for (const key of ["tr('Language')", "tr('Match System')", 'LANGUAGE_SETTINGS', 'api.setLanguageSetting(', 'vm.languageSetting']) {
    assert.ok(menu.includes(key), key);
  }
  // One radio group: the checked choice is the view model's setting.
  assert.match(menu, /aria-checked=\{vm\.languageSetting === setting\}/);
});
