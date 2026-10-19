import { test } from 'node:test';
import assert from 'node:assert/strict';
import { secretFromInput } from './secret.ts';

test('typing stores, emptying keeps the stored secret, only Remove deletes it', () => {
  assert.equal(secretFromInput('abc', false), 'abc');
  assert.equal(secretFromInput('', false), null);
  assert.equal(secretFromInput('', true), '');
  assert.equal(secretFromInput('x', true), 'x');
});
