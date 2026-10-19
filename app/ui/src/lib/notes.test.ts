import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inlineSegments } from './notes.ts';
import { countdown, isValidCode, promptIdOfLabel } from './prompt.ts';

const flat = (notes: string) =>
  inlineSegments(notes).map((s) => `${s.bold ? 'B' : ''}${s.italic ? 'I' : ''}${s.strike ? 'S' : ''}${s.code ? 'C' : ''}:${s.text}`);

test('inline emphasis, code and link texts', () => {
  assert.deepEqual(flat('**Fixes** and *more*'), ['B:Fixes', ': and ', 'I:more']);
  assert.deepEqual(flat('use `mvpn status` now'), [':use ', 'C:mvpn status', ': now']);
  assert.deepEqual(flat('~~old~~ new'), ['S:old', ': new']);
  assert.deepEqual(flat('[the guide](https://example.com) here'), [':the guide here']);
  assert.deepEqual(flat('**bold _and italic_**'), ['B:bold ', 'BI:and italic']);
  assert.deepEqual(flat('snake_case_name and 2*3*4'), [':snake_case_name and 2', 'I:3', ':4']);
  assert.deepEqual(flat('\\*not italic\\*'), [':*not italic*']);
  assert.deepEqual(flat('a * b * c'), [':a * b * c']);
});

test('markup is text, whitespace is kept', () => {
  const html = '<script>alert(1)</script>\n<img src=x onerror="x()">';
  assert.deepEqual(flat(html), [`:${html}`]);
  assert.deepEqual(flat('line 1\n\n  - item'), [':line 1\n\n  - item']);
  assert.deepEqual(flat('unclosed **bold and `code'), [':unclosed **bold and `code']);
});

test('prompt code rule, countdown and labels', () => {
  assert.ok(isValidCode('123456'));
  assert.ok(isValidCode('ő'.repeat(128)));
  assert.ok(!isValidCode('ő'.repeat(129)));
  assert.ok(!isValidCode(''));
  for (const bad of ['1\n2', '\u0000', '\u007f', '\u0085', ' ']) assert.ok(!isValidCode(bad), JSON.stringify(bad));
  assert.equal(countdown(125), '2:05');
  assert.equal(countdown(-3), '0:00');
  assert.equal(promptIdOfLabel('prompt-12'), 12);
  assert.equal(promptIdOfLabel('prompt-'), null);
  assert.equal(promptIdOfLabel('menu'), null);
});
