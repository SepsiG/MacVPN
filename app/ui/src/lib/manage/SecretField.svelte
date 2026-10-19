<script lang="ts">
  // A password / PSK field over a Keychain value the web view never sees: empty with "Saved — type to replace"
  // while a value is stored, a typed text replaces it, "Remove saved password" deletes it on save.
  import type { SecretInput } from '../api';
  import { tr } from '../l10n.svelte';
  import { secretFromInput } from './secret';

  let {
    value = $bindable(),
    stored,
    label,
    placeholder = '',
    disabled = false,
  }: { value: SecretInput; stored: boolean; label: string; placeholder?: string; disabled?: boolean } = $props();

  let removed = $state(false);
  // Back to "keep" (a save, a reload): a later Remove starts over.
  $effect(() => {
    if (value === null) removed = false;
  });

  const shown = $derived(stored && value === null && !removed ? tr('Saved — type to replace') : placeholder);

  function input(event: Event) {
    value = secretFromInput((event.currentTarget as HTMLInputElement).value, removed);
  }

  function remove() {
    removed = true;
    value = '';
  }
</script>

<span class="secret">
  <input type="password" autocomplete="off" aria-label={label} placeholder={shown} value={value ?? ''} oninput={input} {disabled} />
  {#if stored && value === null && !removed}
    <button class="remove" type="button" onclick={remove} {disabled}>{tr('Remove saved password')}</button>
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
  .remove {
    flex: none;
    min-height: 24px;
    padding: 2px 10px;
    border-radius: var(--radius-pill);
    font-size: var(--text-sm);
  }
</style>
