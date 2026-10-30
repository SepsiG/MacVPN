// Tests scripts/l10n-merge.mjs on a temporary table: entries are appended in fragment order, an identical
// duplicate is accepted once, a conflicting duplicate fails, fragments are deleted only after success.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { merge } from './l10n-merge.mjs';

function setup(fragments) {
  const dir = mkdtempSync(join(tmpdir(), 'l10n-merge-'));
  const table = join(dir, 'strings.json');
  writeFileSync(table, JSON.stringify({ comment: 'c', sourceLanguage: 'en', strings: { A: { hu: 'a', scope: 'app' } } }, null, 2) + '\n');
  mkdirSync(join(dir, 'lb'));
  for (const [name, strings] of Object.entries(fragments)) writeFileSync(join(dir, 'lb', name), JSON.stringify({ strings }));
  return { dir, table };
}

test('appends in fragment order and deletes the fragments', () => {
  const { dir, table } = setup({ '13.json': { B: { hu: 'b', scope: 'app', only: ['linux'] } }, '5.json': { C: { hu: 'c', scope: 'core' } } });
  merge(table, join(dir, 'lb'));
  const keys = Object.keys(JSON.parse(readFileSync(table, 'utf8')).strings);
  assert.deepEqual(keys, ['A', 'C', 'B']);
  assert.equal(existsSync(join(dir, 'lb', '13.json')), false);
});

test('a conflicting duplicate fails and changes nothing', () => {
  const { dir, table } = setup({ '5.json': { A: { hu: 'más', scope: 'app' } } });
  const before = readFileSync(table, 'utf8');
  assert.throws(() => merge(table, join(dir, 'lb')), /A/);
  assert.equal(readFileSync(table, 'utf8'), before);
  assert.equal(existsSync(join(dir, 'lb', '5.json')), true);
});
