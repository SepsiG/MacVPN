// node --test: the pinned list's drag rules.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dropIndex, isMove } from './reorder.ts';

test('the gap under the pointer', () => {
  const mids = [10, 30, 50];
  assert.equal(dropIndex(mids, 0), 0);
  assert.equal(dropIndex(mids, 20), 1);
  assert.equal(dropIndex(mids, 45), 2);
  assert.equal(dropIndex(mids, 99), 3);
  assert.equal(dropIndex([], 5), 0);
});

test('a drop next to the row itself is no move', () => {
  assert.equal(isMove(1, 1), false);
  assert.equal(isMove(1, 2), false);
  assert.equal(isMove(1, 0), true);
  assert.equal(isMove(0, 2), true);
  assert.equal(isMove(0, 3), true);
});
