import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { TRAFFIC_INTERVAL, pollTraffic, type TrafficDeps, type TrafficMap } from './traffic.ts';

function fake(answer: TrafficMap) {
  const state = { visible: true, calls: 0, ticks: [] as (() => void)[], vis: [] as (() => void)[], cleared: false, ms: 0 };
  const deps: TrafficDeps = {
    fetch: () => {
      state.calls++;
      return Promise.resolve(answer);
    },
    visible: () => state.visible,
    setInterval: (f, ms) => {
      state.ticks.push(f);
      state.ms = ms;
      return 1;
    },
    clearInterval: () => (state.cleared = true),
    onVisibility: (f) => {
      state.vis.push(f);
      return () => (state.vis = []);
    },
  };
  return { state, deps };
}

const flush = () => new Promise((r) => setTimeout(r, 0));
const ROW = { A: { totals: '↓ 1.0 kB  ↑ 2.0 kB', rates: null, tooltip: 't' } };

test('a visible window with a connected row reads once a second', async () => {
  const { state, deps } = fake(ROW);
  const got: TrafficMap[] = [];
  const stop = pollTraffic(() => true, (t) => got.push(t), deps);
  await flush();
  assert.equal(state.ms, TRAFFIC_INTERVAL);
  assert.equal(TRAFFIC_INTERVAL, 1000);
  assert.equal(state.calls, 1, 'at once');
  state.ticks[0]();
  await flush();
  assert.equal(state.calls, 2);
  assert.deepEqual(got.at(-1), ROW);
  stop();
  assert.ok(state.cleared);
  state.ticks[0]();
  await flush();
  assert.equal(state.calls, 2, 'nothing after the stop');
});

test('a hidden window reads nothing, and reads at once when shown again', async () => {
  const { state, deps } = fake(ROW);
  state.visible = false;
  pollTraffic(() => true, () => {}, deps);
  state.ticks[0]();
  await flush();
  assert.equal(state.calls, 0);
  state.visible = true;
  state.vis[0]();
  await flush();
  assert.equal(state.calls, 1);
});

test('without a connected row nothing is read and the lines go', async () => {
  const { state, deps } = fake(ROW);
  const got: TrafficMap[] = [];
  pollTraffic(() => false, (t) => got.push(t), deps);
  await flush();
  assert.equal(state.calls, 0);
  assert.deepEqual(got, [{}]);
});

test('the menu card, the detail and the system VPN detail show the traffic line', () => {
  for (const file of ['./MenuRow.svelte', './manage/Detail.svelte', './manage/SystemDetail.svelte']) {
    const src = readFileSync(new URL(file, import.meta.url), 'utf8');
    assert.ok(src.includes('<TrafficLine'), file);
  }
  for (const file of ['./Menu.svelte', './manage/Manage.svelte']) {
    const src = readFileSync(new URL(file, import.meta.url), 'utf8');
    assert.ok(src.includes('pollTraffic('), file);
  }
});
