// node --test src/lib/ : the prompt windows fit their content (no fixed 100vh box that scrolls or clips).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fitHeight } from './fit.ts';

const read = (name: string) => readFileSync(new URL(name, import.meta.url), 'utf8');

test('the asked height is the content height in whole points', () => {
  assert.equal(fitHeight(431.2), 432);
  assert.equal(fitHeight(300), 300);
  assert.equal(fitHeight(0), null);
  assert.equal(fitHeight(-4), null);
  assert.equal(fitHeight(Number.NaN), null);
  assert.equal(fitHeight(Number.POSITIVE_INFINITY), null);
});

test('every prompt window measures its content and asks for its height', () => {
  for (const name of ['./Prompt.svelte', './CredentialPrompt.svelte', './Pairing.svelte']) {
    const source = read(name);
    assert.match(source, /fitToContent\(document\.getElementById\('app'\), api\.fitWindow\)/, name);
    assert.match(source, /unfit\(\);/, name);
  }
});

test('the prompt views take their natural height (the window follows it)', () => {
  for (const name of ['./Prompt.svelte', './CredentialView.svelte', './PairingView.svelte']) {
    const styles = read(name).slice(read(name).indexOf('<style>'));
    assert.doesNotMatch(styles, /100vh/, name);
  }
  // The pairing window's connection list scrolls inside its own box.
  const pairing = read('./PairingView.svelte');
  const items = pairing.slice(pairing.indexOf('  .items {'), pairing.indexOf('}', pairing.indexOf('  .items {')));
  assert.match(items, /max-height: \d+px;/);
  assert.match(items, /overflow: auto;/);
});
