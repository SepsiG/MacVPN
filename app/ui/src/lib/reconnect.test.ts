import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const detail = readFileSync(new URL('./manage/Detail.svelte', import.meta.url), 'utf8');

test('the detail has the per-connection reconnect switch', () => {
  assert.ok(detail.includes("tr('Reconnect Automatically')"));
  assert.ok(detail.includes('api.setAutoReconnect('));
  assert.ok(detail.includes('row.autoReconnect !== undefined'));
});
