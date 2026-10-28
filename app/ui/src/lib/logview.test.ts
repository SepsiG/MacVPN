// node --test: the Log tab's display rules (the backend's app-core `logs` has the same).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyChunk, civilSeconds, inputSeconds, MAX_LINES, presetRange, customRange, visibleLines, type TimeRange } from './logview.ts';
import type { LogLineView } from './api.ts';

const line = (text: string, kind: LogLineView['kind'] = 'output', time: number | null = null): LogLineView => ({ text, kind, time });

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

// The backend's line times are local wall-clock seconds (app-core `logs::civil_seconds`): 2026-10-28 10:00:00 is
// days_from_civil(2026, 10, 28) * 86400 + 36000.
const at = (h: number, m: number, s = 0) => Date.UTC(2026, 9, 28, h, m, s) / 1000;

test('local wall-clock seconds match the backend', () => {
  assert.equal(at(0, 0), 1_793_145_600);
  assert.equal(civilSeconds(new Date(2026, 9, 28, 10, 0, 5)), at(10, 0, 5));
  assert.equal(inputSeconds('2026-10-28T10:30'), at(10, 30));
  assert.equal(inputSeconds('2026-10-28T10:30:15'), at(10, 30, 15));
  for (const bad of ['', '2026-10-28', '2026-13-28T10:30', '2026-10-28T25:00', 'x']) assert.equal(inputSeconds(bad), null, bad);
});

test('the time presets', () => {
  const now = new Date(2026, 9, 28, 14, 3, 5);
  assert.deepEqual(presetRange('any', now), { from: null, to: null });
  assert.deepEqual(presetRange('5m', now), { from: at(13, 58, 5), to: null });
  assert.deepEqual(presetRange('15m', now), { from: at(13, 48, 5), to: null });
  assert.deepEqual(presetRange('1h', now), { from: at(13, 3, 5), to: null });
  assert.deepEqual(presetRange('today', now), { from: at(0, 0), to: null });
  // Custom: either end may be empty; "To" takes its whole minute.
  assert.deepEqual(customRange('2026-10-28T10:00', ''), { from: at(10, 0), to: null });
  assert.deepEqual(customRange('', '2026-10-28T10:30'), { from: null, to: at(10, 30, 59) });
  assert.deepEqual(customRange('', ''), { from: null, to: null });
});

test('the time range combines with the filter and the search', () => {
  const lines = [
    line('no time'),
    line('═══ 2026-10-28 10:00:00 up ═══', 'header', at(10, 0)),
    line('2026-10-28 10:00:01 AUTH_FAILED early', 'error', at(10, 0, 1)),
    line('2026-10-28 10:30:00 middle', 'output', at(10, 30)),
    line('continued middle', 'output', at(10, 30)),
    line('2026-10-28 11:00:00 AUTH_FAILED late', 'error', at(11, 0)),
  ];
  const any: TimeRange = { from: null, to: null };
  assert.equal(visibleLines(lines, 'all', '', any).length, 6);
  assert.equal(visibleLines(lines, 'all', '').length, 6, 'no range: every line');
  const from: TimeRange = { from: at(10, 15), to: null };
  assert.deepEqual(visibleLines(lines, 'all', '', from).map((l) => l.text), ['2026-10-28 10:30:00 middle', 'continued middle', '2026-10-28 11:00:00 AUTH_FAILED late']);
  const to: TimeRange = { from: null, to: at(10, 30) };
  assert.equal(visibleLines(lines, 'all', '', to).length, 4, 'inclusive; a line without a time is outside');
  const both: TimeRange = { from: at(10, 0), to: at(10, 59, 59) };
  assert.deepEqual(visibleLines(lines, 'errors', '', both).map((l) => l.text), ['2026-10-28 10:00:01 AUTH_FAILED early']);
  assert.deepEqual(visibleLines(lines, 'all', 'CONTINUED', both).map((l) => l.text), ['continued middle']);
});
