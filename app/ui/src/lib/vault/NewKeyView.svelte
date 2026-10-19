<script lang="ts">
  // The new recovery key window as it shows it (the window's logic is in NewKey.svelte): the master password, then
  // the new key shown once (Copy, "I saved it"), then one group retyped, then done. The old key stops working as
  // soon as the new one is made. No form, no default button.
  import Icon from '../Icon.svelte';
  import { tr } from '../l10n.svelte';
  import { formatGroupInput } from './recovery';

  let {
    step,
    armed,
    busy = false,
    wait = 0,
    password = $bindable(''),
    recoveryKey = null,
    group = 0,
    typed = $bindable(''),
    error = null,
    copied = false,
    onsubmit,
    oncopy,
    onsaved,
    onconfirm,
    oncancel,
  }: {
    step: 'password' | 'key' | 'confirm' | 'done';
    armed: boolean;
    busy?: boolean;
    wait?: number;
    password?: string;
    recoveryKey?: string | null;
    group?: number;
    typed?: string;
    error?: string | null;
    copied?: boolean;
    onsubmit: () => void;
    oncopy: () => void;
    onsaved: () => void;
    onconfirm: () => void;
    oncancel: () => void;
  } = $props();

  const ready = $derived(armed && !busy && wait === 0 && password !== '');
  const canConfirm = $derived(armed && !busy && typed.length === 4);
</script>

<div class="vault manage new-key">
  {#if step === 'password'}
    <h1><span class="bubble warn" aria-hidden="true"><Icon name="key" /></span>{tr('Make a new recovery key')}</h1>
    <p>{tr('The new key replaces the old one: the old key stops working at once. Enter the master password to go on.')}</p>
    <div class="card">
      <label class="field">
        <span class="caption">{tr('Master password')}</span>
        <input data-field="password" type="password" autocomplete="current-password" spellcheck="false" disabled={!armed || busy} bind:value={password} />
      </label>
      {#if error}<p class="refused" role="alert">{error}</p>{/if}
      {#if wait > 0}<p class="caption wait" aria-live="polite">{tr('Try again in %lld s', wait)}</p>{/if}
    </div>
    <div class="buttons">
      <button type="button" class="cancel" disabled={busy} onclick={oncancel}>{tr('Cancel')}</button>
      <button type="button" class="primary submit" disabled={!ready} onclick={() => ready && onsubmit()}>{tr('Make New Key')}</button>
    </div>
  {:else if step === 'key'}
    <h1><span class="bubble warn" aria-hidden="true"><Icon name="key" /></span>{tr('Your recovery key')}</h1>
    <p>{tr('If you forget the master password, this key is the only way back into the vault. Write it down or keep it in a password manager. It is shown only now.')}</p>
    <div class="card key-card">
      <code class="recovery-key" data-recovery-key>{recoveryKey ?? ''}</code>
      <button type="button" class="copy" disabled={!armed || !recoveryKey} onclick={oncopy}>
        <Icon name="copy" />{copied ? tr('Copied') : tr('Copy')}
      </button>
    </div>
    <div class="buttons">
      <button type="button" class="primary saved" disabled={!armed} onclick={onsaved}>{tr('I Saved It')}</button>
    </div>
  {:else if step === 'confirm'}
    <h1><span class="bubble warn" aria-hidden="true"><Icon name="key" /></span>{tr('Check your recovery key')}</h1>
    <p>{tr('Type group %lld of your recovery key, counting from the left.', group + 1)}</p>
    <div class="card">
      <label class="field">
        <span class="caption">{tr('Group %lld', group + 1)}</span>
        <input
          data-field="group"
          type="text"
          class="group"
          maxlength="4"
          autocomplete="off"
          autocapitalize="characters"
          spellcheck="false"
          disabled={!armed || busy}
          value={typed}
          oninput={(e) => {
            typed = formatGroupInput(e.currentTarget.value);
            e.currentTarget.value = typed;
          }}
        />
      </label>
      {#if error}<p class="refused" role="alert">{error}</p>{/if}
    </div>
    <div class="buttons">
      <button type="button" class="primary confirm" disabled={!canConfirm} onclick={() => canConfirm && onconfirm()}>{tr('Confirm')}</button>
    </div>
  {:else}
    <h1><span class="bubble ok" aria-hidden="true"><Icon name="check" /></span>{tr('The new recovery key is ready')}</h1>
    <p>{tr('The old recovery key no longer works. Keep the new one safe.')}</p>
    <div class="buttons">
      <button type="button" class="primary close" onclick={oncancel}>{tr('Done')}</button>
    </div>
  {/if}
</div>

<style>
  .recovery-key {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    font-size: 15px;
    letter-spacing: 0.04em;
    -webkit-user-select: text;
    user-select: text;
  }
  .group {
    font-family: ui-monospace, 'SF Mono', Menlo, monospace;
    text-transform: uppercase;
    width: 9ch;
  }
  .wait {
    color: var(--state-busy-text);
  }
</style>
