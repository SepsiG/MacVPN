// node --test: the Log tab's display rules (the backend's app-core `logs` has the same).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyChunk, MAX_LINES, visibleLines } from './logview.ts';
import type { LogLineView } from './api.ts';

const line = (text: string, kind: LogLineView['kind'] = 'output'): LogLineView => ({ text, kind });

test('chunks append, reset and keep the last 5000 lines', () => {
  const a = applyChunk([], true, [line('a')]);
  assert.deepEqual(a.map((l) => l.text), ['a']);
  const b = applyChunk(a, false, [line('b')]);
  assert.deepEqual(b.map((l) => l.text), ['a', 'b']);
  assert.deepEqual(applyChunk(b, true, [line('c')]).map((l) => l.text), ['c']);
  const many = Array.from({ length: MAX_LINES + 3 }, (_, i) => line(String(i)));
  const capped = applyChunk([], false, many);
  assert.equal(capped.length, MAX_LINES);
  assert.equal(capped[0].text, '3');
});

test('filter and search', () => {
  const lines = [line('═══ x ═══', 'header'), line('▶ [mvpn] s', 'step'), line('$ cmd', 'command'), line('AUTH_FAILED', 'error'), line('Plain')];
  assert.deepEqual(visibleLines(lines, 'errors', '').map((l) => l.text), ['AUTH_FAILED']);
  assert.equal(visibleLines(lines, 'commands', '').length, 3);
  assert.deepEqual(visibleLines(lines, 'all', 'plain').map((l) => l.text), ['Plain']);
  assert.deepEqual(visibleLines(lines, 'commands', 'CMD').map((l) => l.text), ['$ cmd']);
});
