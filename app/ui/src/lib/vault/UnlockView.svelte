<script lang="ts">
  // The unlock window as it shows it (the window's logic is in Unlock.svelte): the master password, or – after
  // "Use recovery key" – the recovery key with a new master password twice. A wrong attempt delays the next one
  // (1 s, doubling, at most 30 s): the countdown shows, and the button waits. No form, no default button.
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import { KEY_PLACEHOLDER, formatRecoveryInput, isCompleteKey } from './recovery';
  import { meetsMinimum, passwordsReady, strength } from './strength';
  import StrengthHint from './StrengthHint.svelte';

  let {
    mode,
    armed,
    busy = false,
    wait = 0,
    password = $bindable(''),
    recoveryKey = $bindable(''),
    newPassword = $bindable(''),
    newAgain = $bindable(''),
    error = null,
    onunlock,
    onrecover,
    onmode,
  }: {
    mode: 'password' | 'recovery';
    armed: boolean;
    busy?: boolean;
    /// Seconds until the next attempt is taken (0: now).
    wait?: number;
    password?: string;
    recoveryKey?: string;
    newPassword?: string;
    newAgain?: string;
    error?: string | null;
    onunlock: () => void;
    onrecover: () => void;
    onmode: (mode: 'password' | 'recovery') => void;
  } = $props();

  const canUnlock = $derived(armed && !busy && wait === 0 && password !== '');
  const mismatch = $derived(newAgain !== '' && newPassword !== newAgain);
  const canRecover = $derived(
    armed && !busy && wait === 0 && isCompleteKey(recoveryKey) && passwordsReady(newPassword, newAgain),
  );
</script>

<div class="vault manage unlock">
  {#if mode === 'password'}
    <h1><span class="bubble" aria-hidden="true"><Icon name="lock" /></span>{tr('MacVPN is locked')}</h1>
    <p>{tr('Enter the master password to open the vault.')}</p>
    <div class="card">
      <label class="field">
        <span class="caption">{tr('Master password')}</span>
        <input data-field="password" type="password" autocomplete="current-password" spellcheck="false" disabled={!armed || busy} bind:value={password} />
      </label>
      {#if error}<p class="refused" role="alert">{error}</p>{/if}
      {#if wait > 0}<p class="caption wait" aria-live="polite">{tr('Try again in %lld s', wait)}</p>{/if}
    </div>
    <button type="button" class="link use-recovery" disabled={busy} onclick={() => onmode('recovery')}>{tr('Use recovery key')}</button>
    <div class="buttons">
      <button type="button" class="primary unlock-button" disabled={!canUnlock} onclick={() => canUnlock && onunlock()}>
        {busy ? tr('Unlocking…') : tr('Unlock')}
      </button>
    </div>
  {:else}
    <h1><span class="bubble warn" aria-hidden="true"><Icon name="key" /></span>{tr('Reset the master password')}</h1>
    <p>{tr('Enter your recovery key and choose a new master password. Your connections stay as they are.')}</p>
    <div class="card">
      <label class="field">
        <span class="caption">{tr('Recovery key')}</span>
        <input
          data-field="recovery"
          class="key"
          type="text"
          autocomplete="off"
          autocapitalize="characters"
          spellcheck="false"
          placeholder={KEY_PLACEHOLDER}
          disabled={!armed || busy}
          value={recoveryKey}
          oninput={(e) => {
            recoveryKey = formatRecoveryInput(e.currentTarget.value);
            e.currentTarget.value = recoveryKey;
          }}
        />
      </label>
      <label class="field">
        <span class="caption">{tr('New master password')}</span>
        <input data-field="new" type="password" autocomplete="new-password" spellcheck="false" disabled={!armed || busy} bind:value={newPassword} />
      </label>
      <StrengthHint strength={strength(newPassword)} short={newPassword !== '' && !meetsMinimum(newPassword)} />
      <label class="field">
        <span class="caption">{tr('Repeat the new master password')}</span>
        <input data-field="again" type="password" autocomplete="new-password" spellcheck="false" disabled={!armed || busy} bind:value={newAgain} />
      </label>
      {#if mismatch}<p class="refused" role="alert">{tr('The two passwords are not the same')}</p>{/if}
      {#if error}<p class="refused" role="alert">{error}</p>{/if}
      {#if wait > 0}<p class="caption wait" aria-live="polite">{tr('Try again in %lld s', wait)}</p>{/if}
    </div>
    <button type="button" class="link use-password" disabled={busy} onclick={() => onmode('password')}>{tr('Use the master password')}</button>
    <div class="buttons">
      <button type="button" class="primary recover-button" disabled={!canRecover} onclick={() => canRecover && onrecover()}>
        {busy ? tr('Unlocking…') : tr('Reset and Unlock')}
      </button>
    </div>
  {/if}
</div>

<style>
  .key {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    letter-spacing: 0.03em;
  }
  .wait {
    color: var(--state-busy-text);
  }
</style>
