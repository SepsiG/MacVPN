// node --test: the delete confirmation of a managed connection (G-3, WinVPN 2c). macOS: a native connection's
// profile is removed by the user in the Profiles pane that opens; WinVPN (`nativeDeleteRemovesProfile`) deletes its
// Windows VPN entry itself, so the text says so; without the flag (absent on macOS) nothing changes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const detail = readFileSync(new URL('./Detail.svelte', import.meta.url), 'utf8');

test('the delete confirmation names the Windows VPN entry only with the flag set', () => {
  const start = detail.indexOf('message={');
  const message = detail.slice(start, detail.indexOf('buttons={', start));
  const flagged = message.indexOf('native && manage.nativeDeleteRemovesProfile');
  const windows = message.indexOf("tr('The config and the saved passwords will be deleted, and its Windows VPN entry too.')");
  const profiles = message.indexOf("tr('You have to remove the installed profile yourself in the Profiles pane that opens.')");
  const plain = message.indexOf("tr('The config and the saved passwords will be deleted.')");
  assert.ok(flagged >= 0 && flagged < windows, 'the Windows text only behind the flag');
  assert.ok(windows < profiles && profiles < plain, 'without the flag: the macOS texts, unchanged');
});
