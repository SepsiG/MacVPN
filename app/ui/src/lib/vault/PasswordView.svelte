<script lang="ts">
  // The master password window as it shows it (the window's logic is in PasswordWindow.svelte). `change`: the
  // current password and a new one twice (with the strength hint), then "changed". `confirm`: the master password
  // once, to turn "Unlock Automatically" on. A wrong password delays the next attempt (the countdown). No form, no
  // default button.
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import { meetsMinimum, passwordsReady, strength } from './strength';
  import StrengthHint from './StrengthHint.svelte';

  let {
    mode,
    armed,
    busy = false,
    done = false,
    wait = 0,
    current = $bindable(''),
    newPassword = $bindable(''),
    newAgain = $bindable(''),
    error = null,
    onsubmit,
    oncancel,
  }: {
    mode: 'change' | 'confirm';
    armed: boolean;
    busy?: boolean;
    /// `change` finished.
    done?: boolean;
    wait?: number;
    current?: string;
    newPassword?: string;
    newAgain?: string;
    error?: string | null;
    onsubmit: () => void;
    oncancel: () => void;
  } = $props();

  const mismatch = $derived(newAgain !== '' && newPassword !== newAgain);
  const ready = $derived(
    armed && !busy && wait === 0 && current !== '' && (mode === 'confirm' || passwordsReady(newPassword, newAgain)),
  );
</script>

<div class="vault manage password">
  {#if done}
    <h1><span class="bubble ok" aria-hidden="true"><Icon name="check" /></span>{tr('The master password was changed')}</h1>
    <p>{tr('Use the new master password from now on. Your recovery key stays the same.')}</p>
    <div class="buttons">
      <button type="button" class="primary close" onclick={oncancel}>{tr('Done')}</button>
    </div>
  {:else}
    <h1>
      <span class="bubble" aria-hidden="true"><Icon name="lock" /></span>
      {mode === 'change' ? tr('Change the master password') : tr('Turn on automatic unlock')}
    </h1>
    <p>
      {mode === 'change'
        ? tr('Enter the current master password, then the new one twice.')
        : tr('Enter the master password. Its key is then kept in the macOS Keychain, and MacVPN opens without asking.')}
    </p>
    <div class="card">
      <label class="field">
        <span class="caption">{mode === 'change' ? tr('Current master password') : tr('Master password')}</span>
        <input data-field="current" type="password" autocomplete="current-password" spellcheck="false" disabled={!armed || busy} bind:value={current} />
      </label>
      {#if mode === 'change'}
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
      {/if}
      {#if error}<p class="refused" role="alert">{error}</p>{/if}
      {#if wait > 0}<p class="caption wait" aria-live="polite">{tr('Try again in %lld s', wait)}</p>{/if}
    </div>
    <div class="buttons">
      <button type="button" class="cancel" disabled={busy} onclick={oncancel}>{tr('Cancel')}</button>
      <button type="button" class="primary submit" disabled={!ready} onclick={() => ready && onsubmit()}>
        {mode === 'change' ? tr('Change Password') : tr('Turn On')}
      </button>
    </div>
  {/if}
</div>

<style>
  .wait {
    color: var(--state-busy-text);
  }
</style>
