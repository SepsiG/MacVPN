// node --test: the add dialog's rules (subscription.ts): the paste detection, the fingerprint and team key formatting
// while typing, when "Check" may run (never without a fingerprint), and what is wiped once the secrets were sent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  afterCheck,
  canCheck,
  emptyForm,
  fingerprintComplete,
  formatFingerprint,
  formatTeamKey,
  isSubscriptionString,
  pastedKind,
  previewInput,
  teamKeyComplete,
  withoutSecrets,
} from './subscription.ts';

const KEY_SYMBOLS = '0123456789ABCDEFGHJKMNPQRSTVWXYZ0123456789ABCDEFGHJKMNPQ'; // 56 Crockford symbols
const FINGERPRINT = 'ABCD-1234-EF56-7890-ABCD-1234-EF56-7890';

test('a pasted subscription string is detected by its prefix only', () => {
  assert.ok(isSubscriptionString('macvpn-sub:eyJ2IjoxfQ'));
  assert.ok(isSubscriptionString('  macvpn-sub:eyJ2IjoxfQ\n'));
  assert.ok(!isSubscriptionString('MACVPN-SUB:eyJ2IjoxfQ'), 'the prefix is case-sensitive, as in the backend');
  assert.ok(!isSubscriptionString('https://vpn.example.com/team.macvpncatalog'));
  assert.ok(!isSubscriptionString(''));
});

test('the fingerprint is formatted as 8 groups while typing', () => {
  assert.equal(formatFingerprint('abcd'), 'ABCD');
  assert.equal(formatFingerprint('abcd1'), 'ABCD-1');
  assert.equal(formatFingerprint('ab cd-12 34'), 'ABCD-1234');
  assert.equal(formatFingerprint('abcd1234ef567890abcd1234ef567890'), FINGERPRINT);
  assert.equal(formatFingerprint(`${FINGERPRINT}FFFF`), FINGERPRINT, 'at most 8 groups');
  assert.equal(formatFingerprint('xyz!'), '', 'not hex: dropped');
  assert.ok(fingerprintComplete(FINGERPRINT));
  assert.ok(fingerprintComplete(FINGERPRINT.toLowerCase().replace(/-/g, ' ')));
  assert.ok(!fingerprintComplete(FINGERPRINT.slice(0, -1)));
  assert.ok(!fingerprintComplete(`${FINGERPRINT}Z`), 'a stray character is not ignored');
});

test('the team key is formatted as TEAM- and groups of 4', () => {
  assert.equal(formatTeamKey(''), '');
  assert.equal(formatTeamKey('abcd'), 'TEAM-ABCD');
  assert.equal(formatTeamKey('team-abcd efgh'), 'TEAM-ABCD-EFGH');
  // Crockford: O is 0, I and L are 1; U is not a symbol.
  assert.equal(formatTeamKey('TEAM-OILU'), 'TEAM-011');
  const full = formatTeamKey(KEY_SYMBOLS);
  assert.equal(full.split('-').length, 15, 'TEAM + 14 groups');
  assert.ok(full.startsWith('TEAM-0123-4567-'));
  assert.ok(teamKeyComplete(full));
  assert.ok(teamKeyComplete(KEY_SYMBOLS.toLowerCase()));
  // Without the dash, the prefix letters are dropped only when they make the key one group too long.
  assert.ok(teamKeyComplete(`TEAM${KEY_SYMBOLS}`));
  assert.equal(formatTeamKey(`${KEY_SYMBOLS}ZZZZ`), full, 'at most 14 groups');
  assert.ok(!teamKeyComplete(KEY_SYMBOLS.slice(4)));
});

test('"Check" needs a fingerprint: there is no trust on first use', () => {
  const form = { ...emptyForm(), url: 'https://vpn.example.com/team.macvpncatalog', teamKey: KEY_SYMBOLS };
  assert.ok(!canCheck(form), 'no fingerprint');
  assert.ok(!canCheck({ ...form, fingerprint: FINGERPRINT.slice(0, 20) }), 'an incomplete fingerprint');
  assert.ok(canCheck({ ...form, fingerprint: FINGERPRINT }));
  assert.ok(!canCheck({ ...form, fingerprint: FINGERPRINT, teamKey: 'TEAM-ABCD' }), 'an incomplete team key');
  assert.ok(!canCheck({ ...form, fingerprint: FINGERPRINT, url: ' ' }), 'no source');
  const file = { ...form, fingerprint: FINGERPRINT, sourceKind: 'file' as const };
  assert.ok(!canCheck(file), 'no file chosen');
  assert.ok(canCheck({ ...file, fileName: 'team.macvpncatalog' }));
  // A parsed subscription string carries the administrator's fingerprint.
  const pasted = { ...emptyForm(), subscription: 'macvpn-sub:x', parsed: { kind: 'file' as const, source: 'team.macvpncatalog', fingerprint: FINGERPRINT } };
  assert.ok(canCheck(pasted));
  assert.ok(!canCheck({ ...pasted, parsed: null }), 'not parsed (refused): no check');
});

test('the preview input sends either the string or the fields', () => {
  const pasted = previewInput({ ...emptyForm(), subscription: 'macvpn-sub:x', parsed: { kind: 'https', source: 's', fingerprint: FINGERPRINT }, token: ' tok ' });
  assert.deepEqual(pasted, { subscription: 'macvpn-sub:x', url: null, chosenFile: false, teamKey: null, fingerprint: null, token: 'tok' });
  const fields = previewInput({ ...emptyForm(), sourceKind: 'file', fileName: 'f', teamKey: 'TEAM-K', fingerprint: FINGERPRINT });
  assert.deepEqual(fields, { subscription: null, url: null, chosenFile: true, teamKey: 'TEAM-K', fingerprint: FINGERPRINT, token: null });
});

test('once sent, the string, the team key and the token are wiped', () => {
  const form = {
    ...emptyForm(),
    subscription: 'macvpn-sub:secret',
    parsed: { kind: 'https' as const, source: 'https://vpn.example.com/c', fingerprint: FINGERPRINT },
    url: 'https://vpn.example.com/c',
    teamKey: 'TEAM-SECRET',
    fingerprint: FINGERPRINT,
    token: 'bearer-secret',
  };
  const wiped = withoutSecrets(form);
  assert.equal(wiped.subscription, null);
  assert.equal(wiped.parsed, null);
  assert.equal(wiped.teamKey, '');
  assert.equal(wiped.token, '');
  assert.equal(wiped.fingerprint, FINGERPRINT, 'not secret: kept for "Back"');
  assert.ok(!JSON.stringify(wiped).includes('SECRET') && !JSON.stringify(wiped).includes('secret'));
});

test('a dialog closed during "Check" drops the verified download at once', async () => {
  const dropped: string[] = [];
  const discard = async (id: string) => void dropped.push(id);
  const result = { pendingId: 'P1', name: 'Acme VPN' };
  assert.equal(await afterCheck(result, () => false, discard), result, 'still open: kept for "Subscribe"');
  assert.deepEqual(dropped, []);
  assert.equal(await afterCheck(result, () => true, discard), null, 'closed: nothing is shown');
  assert.deepEqual(dropped, ['P1']);
  // A failed discard is logged, never thrown into the closed dialog.
  assert.equal(await afterCheck(result, () => true, async () => Promise.reject(new Error('gone'))), null);
});

test('the paste field: a string is handed off, anything else is refused, the field is always cleared', async () => {
  assert.equal(pastedKind('macvpn-sub:AAAA'), 'subscription');
  assert.equal(pastedKind('  \n'), 'empty');
  for (const other of ['TEAM-7K3Q', 'https://vpn.example.com/x', 'hello']) assert.equal(pastedKind(other), 'other', other);
  const { readFileSync } = await import('node:fs');
  const view = readFileSync(new URL('./AddCatalogView.svelte', import.meta.url), 'utf8');
  assert.match(view, /const text = e\.currentTarget\.value;\s*e\.currentTarget\.value = '';\s*onpaste\(text\);/, 'cleared before the hand-off');
  const dialog = readFileSync(new URL('./AddCatalog.svelte', import.meta.url), 'utf8');
  assert.match(dialog, /tr\('This is not a subscription string\.'\)/);
});
