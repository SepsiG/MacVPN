<script lang="ts">
  // A password / PSK field over a vault value the web view never sees: empty with "Saved — type to replace"
  // while a value is stored, a typed text replaces it, the remove button ("Remove saved password", "Remove saved
  // PSK", "Remove saved key password") deletes it on save. "Show" reveals only the text being typed: a stored
  // value never reaches the web view, so there is nothing else to show.
  import type { SecretInput } from '../api';
  import { tr } from '../l10n.svelte';
  import { canShowTyped, secretFromInput } from './secret';

  let {
    value = $bindable(),
    stored,
    label,
    placeholder = '',
    disabled = false,
    removeLabel,
  }: {
    value: SecretInput;
    stored: boolean;
    label: string;
    placeholder?: string;
    disabled?: boolean;
    /// The remove button's text (default "Remove saved password").
    removeLabel?: string;
  } = $props();

  let removed = $state(false);
  let shown = $state(false);
  // Back to "keep" (a save, a reload): a later Remove starts over, and nothing typed is shown any more.
  $effect(() => {
    if (value === null) removed = false;
  });
  $effect(() => {
    if (!canShowTyped(value)) shown = false;
  });

  const hint = $derived(stored && value === null && !removed ? tr('Saved — type to replace') : placeholder);

  function input(event: Event) {
    value = secretFromInput((event.currentTarget as HTMLInputElement).value, removed);
  }

  function remove() {
    removed = true;
    value = '';
  }
</script>

<span class="secret">
  <input
    type={shown && canShowTyped(value) ? 'text' : 'password'}
    autocomplete="off"
    autocapitalize="off"
    spellcheck="false"
    aria-label={label}
    placeholder={hint}
    value={value ?? ''}
    oninput={input}
    {disabled}
  />
  {#if canShowTyped(value)}
    <button class="show" type="button" aria-pressed={shown} onclick={() => (shown = !shown)} {disabled}>{shown ? tr('Hide') : tr('Show')}</button>
  {/if}
  {#if stored && value === null && !removed}
    <button class="remove" type="button" onclick={remove} {disabled}>{removeLabel ?? tr('Remove saved password')}</button>
  {/if}
</span>

<style>
  .secret {
    display: flex;
    gap: 6px;
    align-items: center;
    min-width: 0;
  }
  .secret input {
    flex: 1;
    min-width: 0;
  }
  .remove,
  .show {
    flex: none;
    min-height: 24px;
    padding: 2px 10px;
    border-radius: var(--radius-pill);
    font-size: var(--text-sm);
  }
</style>
