// node --test: the vault windows' rules (the strength hint, the recovery key while typing) and their views rendered
// through Svelte's server renderer (compiled on the fly by the module hooks below, as in pairing.test.ts): the
// recovery key is shown once and is gone after "I saved it", nothing is a form or autofocused (no default button,
// no focus steal), the buttons wait for the input lock, and a wrong attempt's countdown holds the unlock.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
import { fileURLToPath } from 'node:url';
import { compile, compileModule } from 'svelte/compiler';
import { render } from 'svelte/server';
import type { Component } from 'svelte';
import type { VaultSetupView } from '../api.ts';
import { formatGroupInput, formatRecoveryInput, isCompleteKey, normalizeRecoveryKey } from './recovery.ts';
import { characterCount, meetsMinimum, passwordsReady, strength } from './strength.ts';

registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith('.') && !/\.(ts|js|json)$/.test(specifier)) {
      for (const candidate of [specifier, `${specifier}.ts`]) {
        try {
          return next(candidate, context);
        } catch {
          // The next candidate.
        }
      }
    }
    return next(specifier, context);
  },
  load(url, context, next) {
    if (url.endsWith('.svelte')) {
      const file = fileURLToPath(url);
      const { js } = compile(readFileSync(file, 'utf8'), { filename: file, generate: 'server', css: 'injected' });
      return { format: 'module', source: js.code, shortCircuit: true };
    }
    if (url.endsWith('.svelte.ts')) {
      const file = fileURLToPath(url);
      const { js } = compileModule(stripTypeScriptTypes(readFileSync(file, 'utf8')), { filename: file, generate: 'server' });
      return { format: 'module', source: js.code, shortCircuit: true };
    }
    if (url.endsWith('.json')) {
      return { format: 'module', source: `export default ${readFileSync(fileURLToPath(url), 'utf8')};`, shortCircuit: true };
    }
    return next(url, context);
  },
});

const KEY = '7K3Q-M9XA-2PZD-F4TR-8VBN-H6WC';
const noop = () => {};

const setupBase: VaultSetupView = {
  step: 'intro',
  migrating: false,
  keychainItems: 0,
  group: null,
  message: null,
  connections: 0,
  secrets: 0,
  skipped: 0,
  canRestore: false,
  restoring: false,
  resumed: false,
  vaultRemoved: false,
};

async function component(file: string): Promise<Component<Record<string, unknown>>> {
  return ((await import(file)) as { default: Component<Record<string, unknown>> }).default;
}

async function create(setup: Partial<VaultSetupView>, props: Record<string, unknown> = {}): Promise<string> {
  const View = await component('./CreateVaultView.svelte');
  const handlers = Object.fromEntries(
    ['oncontinue', 'onback', 'oncreate', 'oncopy', 'onsaved', 'onconfirm', 'onretry', 'onfinish', 'onclose', 'onrestore'].map(
      (k) => [k, noop],
    ),
  );
  return render(View, { props: { setup: { ...setupBase, ...setup }, armed: true, ...handlers, ...props } }).body;
}

async function unlock(props: Record<string, unknown>): Promise<string> {
  const View = await component('./UnlockView.svelte');
  return render(View, { props: { mode: 'password', armed: true, onunlock: noop, onrecover: noop, onmode: noop, ...props } })
    .body;
}

/// The `<button>` with this class, as rendered.
function button(html: string, cls: string): string {
  const m = new RegExp(`<button[^>]*class="[^"]*\\b${cls}\\b[^"]*"[^>]*>`).exec(html);
  assert.ok(m, `no ${cls} button in ${html}`);
  return m[0];
}

test('strength: weak, fair and strong, and the minimum alone decides', () => {
  assert.equal(strength(''), null);
  for (const weak of ['abc', 'password12', 'aaaaaaaaaaaa', '1234567890', 'qwertyuiop']) assert.equal(strength(weak), 'weak', weak);
  assert.equal(strength('tulipriver42'), 'fair');
  assert.equal(strength('correct horse battery staple'), 'strong');
  assert.equal(strength('G7#kq!Lw2@Zp9$x'), 'strong');
  // A weak password of 10 characters is still accepted (the hint only advises).
  assert.ok(passwordsReady('password12', 'password12'));
  assert.ok(!passwordsReady('short', 'short'));
  assert.ok(!passwordsReady('password12', 'password13'));
  // Counted in user-perceived characters, as the backend does.
  assert.equal(characterCount('ééééééééé👍🏽'), 10);
  assert.ok(meetsMinimum('ééééééééé👍🏽'));
});

test('recovery key: formatting while typing and normalisation', () => {
  assert.equal(formatRecoveryInput('7k3qm9'), '7K3Q-M9');
  assert.equal(formatRecoveryInput(' 7k3q - m9xa 2pzd'), '7K3Q-M9XA-2PZD');
  assert.equal(formatRecoveryInput(`${KEY}EXTRA`), KEY);
  assert.equal(normalizeRecoveryKey('oIl-0'), '0110');
  assert.ok(isCompleteKey(KEY.toLowerCase()));
  assert.ok(isCompleteKey(KEY.replace(/-/g, ' ')));
  assert.ok(!isCompleteKey(KEY.slice(0, -1)));
  assert.ok(!isCompleteKey(KEY.replace('7', 'U')), 'U is not in the alphabet');
  assert.equal(formatGroupInput('m9-xa1'), 'M9XA');
});

test('the intro names the Keychain prompts in migration mode', async () => {
  const fresh = await create({});
  assert.doesNotMatch(fresh, /Keychain/);
  assert.doesNotMatch(fresh, /Restore from backup/);
  const migrating = await create({ migrating: true, keychainItems: 7, canRestore: true });
  assert.match(migrating, /up to 7 times/);
  assert.match(migrating, /Always Allow/);
  assert.match(migrating, /Restore from backup/);
});

test('the password step waits for two equal passwords of 10 characters', async () => {
  const empty = await create({ step: 'password' });
  assert.match(button(empty, 'create-vault'), /disabled/);
  assert.match(empty, /<input type="checkbox"[^>]*checked/, 'auto-unlock is on by default');
  const weak = await create({ step: 'password' }, { password: 'password12', again: 'password12' });
  assert.doesNotMatch(button(weak, 'create-vault'), /disabled/, 'a weak password is not blocked');
  assert.match(weak, /data-strength="weak"/);
  const mismatch = await create({ step: 'password' }, { password: 'password12', again: 'password13' });
  assert.match(mismatch, /not the same/);
  assert.match(button(mismatch, 'create-vault'), /disabled/);
  const locked = await create({ step: 'password' }, { password: 'password12', again: 'password12', armed: false });
  assert.match(button(locked, 'create-vault'), /disabled/, 'the input lock');
});

test('the recovery key is shown once and is gone after "I saved it"', async () => {
  const shown = await create({ step: 'recoveryKey' }, { recoveryKey: KEY });
  assert.match(shown, new RegExp(KEY));
  assert.match(shown, /shown only now/);
  // The next step, even with the key still passed in: not in the page.
  const confirm = await create({ step: 'confirm', group: 2 }, { recoveryKey: KEY });
  assert.doesNotMatch(confirm, new RegExp(KEY));
  for (const group of KEY.split('-')) assert.doesNotMatch(confirm, new RegExp(group));
  assert.match(confirm, /Type group 3 of your recovery key/);
  assert.match(button(confirm, 'confirm'), /disabled/);
  const typed = await create({ step: 'confirm', group: 2 }, { typed: '2PZD' });
  assert.doesNotMatch(button(typed, 'confirm'), /disabled/);
  const wrong = await create({ step: 'confirm', group: 2, message: 'This is not group 3 of your recovery key' });
  assert.match(wrong, /role="alert"[^>]*>This is not group 3/);
});

test('the migration steps', async () => {
  assert.match(await create({ step: 'migrating', migrating: true, keychainItems: 2 }), /Always Allow/);
  const verified = await create({ step: 'verified', migrating: true, connections: 5, secrets: 3, skipped: 1 });
  assert.match(verified, /5 connections and 3 saved secrets/);
  assert.match(verified, /1 item could not be read and was left/);
  // The reminder offers the backup right there.
  assert.match(verified, /class="left backup"[^>]*>Back Up Everything…</);
  assert.match(await create({ step: 'verified', migrating: true, skipped: 3 }), /3 items could not be read/);
  const failed = await create({ step: 'failed', migrating: true, vaultRemoved: true, message: 'the migration failed (read)' });
  assert.match(failed, /Nothing was deleted/);
  assert.match(failed, /the migration failed \(read\)/);
  assert.ok(button(failed, 'retry'));
  // A run that kept the vault (an earlier run's deletion, a refusal) never says the vault was removed.
  const kept = await create({ step: 'failed', migrating: true, resumed: true, vaultRemoved: false, message: 'x' });
  assert.doesNotMatch(kept, /new vault was removed/);
  assert.match(kept, /Your vault and its data were kept/);
});

test('no form, no autofocus, no default button', async () => {
  const pages = [
    await create({ step: 'password' }, { password: 'password12', again: 'password12' }),
    await create({ step: 'confirm', group: 0 }),
    await unlock({ password: 'x' }),
    await unlock({ mode: 'recovery' }),
  ];
  for (const html of pages) {
    assert.doesNotMatch(html, /<form/);
    assert.doesNotMatch(html, /autofocus/);
    assert.doesNotMatch(html, /type="submit"/);
  }
});

test('the unlock window: the countdown holds the button, the recovery form needs a whole key', async () => {
  const ready = await unlock({ password: 'secret' });
  assert.doesNotMatch(button(ready, 'unlock-button'), /disabled/);
  const waiting = await unlock({ password: 'secret', wait: 4, error: 'Wrong password or recovery key' });
  assert.match(button(waiting, 'unlock-button'), /disabled/);
  assert.match(waiting, /Try again in 4 s/);
  assert.match(waiting, /Wrong password or recovery key/);
  assert.ok(button(waiting, 'use-recovery'));
  const partial = await unlock({ mode: 'recovery', recoveryKey: KEY.slice(0, 9), newPassword: 'new password 1', newAgain: 'new password 1' });
  assert.match(button(partial, 'recover-button'), /disabled/);
  const whole = await unlock({ mode: 'recovery', recoveryKey: KEY, newPassword: 'new password 1', newAgain: 'new password 1' });
  assert.doesNotMatch(button(whole, 'recover-button'), /disabled/);
  assert.ok(button(whole, 'use-password'));
});

const vaultBase = {
  state: 'locked',
  autoUnlock: false,
  showLockNow: false,
  showLockNowPref: false,
  activeCount: 0,
  legacyError: null,
  passwordMode: null,
};

test('the locked menu: one Unlock row, the active count, Quit; no name, no switch', async () => {
  const View = await component('./LockedMenu.svelte');
  const render_ = (vault: Record<string, unknown>) =>
    render(View, { props: { vault: { ...vaultBase, ...vault }, version: 'MacVPN 1.2.0', onunlock: noop, onquit: noop } }).body;
  const locked = render_({ activeCount: 2 });
  assert.match(locked, /Unlock…/);
  assert.match(locked, /2 connections active/);
  assert.match(locked, /Quit MacVPN/);
  assert.doesNotMatch(locked, /type="checkbox"|role="switch"/);
  assert.doesNotMatch(locked, /Office|Seeded|Settings/);
  assert.match(render_({ activeCount: 1 }), /1 connection active/);
  assert.doesNotMatch(render_({}), /connections? active/);
  assert.match(render_({ state: 'notCreated' }), /Set Up the Vault…/);
});

test('the password window: change and confirm', async () => {
  const View = await component('./PasswordView.svelte');
  const page = (props: Record<string, unknown>) =>
    render(View, { props: { mode: 'change', armed: true, onsubmit: noop, oncancel: noop, ...props } }).body;
  const empty = page({});
  assert.equal((empty.match(/data-field=/g) ?? []).length, 3);
  assert.match(button(empty, 'submit'), /disabled/);
  const ready = page({ current: 'old password 1', newPassword: 'new password 22', newAgain: 'new password 22' });
  assert.doesNotMatch(button(ready, 'submit'), /disabled/);
  const short = page({ current: 'old password 1', newPassword: 'short', newAgain: 'short' });
  assert.match(button(short, 'submit'), /disabled/);
  const waiting = page({ current: 'x', newPassword: 'new password 22', newAgain: 'new password 22', wait: 3, error: 'Wrong password or recovery key' });
  assert.match(button(waiting, 'submit'), /disabled/);
  assert.match(waiting, /Try again in 3 s/);
  assert.match(page({ done: true }), /The master password was changed/);
  const confirm = page({ mode: 'confirm', current: 'x' });
  assert.equal((confirm.match(/data-field=/g) ?? []).length, 1);
  assert.match(confirm, /Turn on automatic unlock/);
  assert.doesNotMatch(button(confirm, 'submit'), /disabled/);
  for (const html of [empty, confirm]) assert.doesNotMatch(html, /<form|autofocus/);
});

test('the new recovery key: shown once, gone at the check', async () => {
  const View = await component('./NewKeyView.svelte');
  const handlers = { onsubmit: noop, oncopy: noop, onsaved: noop, onconfirm: noop, oncancel: noop };
  const page = (props: Record<string, unknown>) => render(View, { props: { step: 'password', armed: true, ...handlers, ...props } }).body;
  assert.match(page({}), /old key stops working/);
  assert.match(button(page({}), 'submit'), /disabled/);
  assert.match(page({ step: 'key', recoveryKey: KEY }), new RegExp(KEY));
  const check = page({ step: 'confirm', recoveryKey: KEY, group: 4 });
  assert.doesNotMatch(check, new RegExp(KEY));
  assert.match(check, /Type group 5 of your recovery key/);
  assert.match(page({ step: 'done' }), /The old recovery key no longer works/);
});
